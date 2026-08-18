"""TLS, mTLS and Retry-After handling (issue #3, finding 9 and retry gap)."""

from __future__ import annotations

import ssl
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from clever_cloud import ApiTokenCredentials, CleverCloudClient, RateLimitError
from clever_cloud.client import _retry_after_seconds
from conftest import BASE_URL


class RecordingContext:
    """Stand-in capturing what would be loaded into the SSL context."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


@pytest.fixture
def recorded_cert_chain(monkeypatch: pytest.MonkeyPatch) -> RecordingContext:
    recorder = RecordingContext()

    def fake_load(self: ssl.SSLContext, **kwargs: object) -> None:
        recorder(**kwargs)

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", fake_load)
    return recorder


class TestClientCertificate:
    def test_single_file_certificate(
        self, token_auth: ApiTokenCredentials, recorded_cert_chain: RecordingContext
    ) -> None:
        client = CleverCloudClient(
            token_auth, base_url=BASE_URL, client_cert="/etc/pki/client.pem"
        )
        client._build_ssl_context()
        assert recorded_cert_chain.calls == [{"certfile": "/etc/pki/client.pem"}]

    def test_certificate_and_key_pair(
        self, token_auth: ApiTokenCredentials, recorded_cert_chain: RecordingContext
    ) -> None:
        client = CleverCloudClient(
            token_auth, base_url=BASE_URL, client_cert=("/c.crt", "/c.key")
        )
        client._build_ssl_context()
        assert recorded_cert_chain.calls == [
            {"certfile": "/c.crt", "keyfile": "/c.key"}
        ]

    def test_certificate_key_and_password(
        self, token_auth: ApiTokenCredentials, recorded_cert_chain: RecordingContext
    ) -> None:
        client = CleverCloudClient(
            token_auth, base_url=BASE_URL, client_cert=("/c.crt", "/c.key", "pw")
        )
        client._build_ssl_context()
        assert recorded_cert_chain.calls == [
            {"certfile": "/c.crt", "keyfile": "/c.key", "password": "pw"}
        ]

    def test_client_cert_without_verification_still_builds_a_context(
        self, token_auth: ApiTokenCredentials, recorded_cert_chain: RecordingContext
    ) -> None:
        """verify_ssl=False must not silently drop the client certificate."""
        client = CleverCloudClient(
            token_auth,
            base_url=BASE_URL,
            client_cert=("/c.crt", "/c.key"),
            verify_ssl=False,
        )
        context = client._build_ssl_context()
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode is ssl.CERT_NONE
        assert context.check_hostname is False
        assert recorded_cert_chain.calls


class TestCaBundle:
    def test_missing_ca_bundle_is_reported(
        self, token_auth: ApiTokenCredentials
    ) -> None:
        client = CleverCloudClient(
            token_auth, base_url=BASE_URL, ca_bundle="/does/not/exist.pem"
        )
        with pytest.raises(FileNotFoundError):
            client._build_ssl_context()

    def test_ca_bundle_is_loaded(
        self, token_auth: ApiTokenCredentials, tmp_path: object
    ) -> None:
        """A real PEM file is loaded without any deprecation warning."""
        import warnings
        from pathlib import Path

        # Reuse the system trust store contents as a valid PEM bundle.
        default_paths = ssl.get_default_verify_paths()
        source = default_paths.cafile
        if not source or not Path(source).exists():
            pytest.skip("no system CA bundle available to reuse")

        client = CleverCloudClient(token_auth, base_url=BASE_URL, ca_bundle=source)
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            context = client._build_ssl_context()
        assert isinstance(context, ssl.SSLContext)
        assert context.get_ca_certs()


class TestRetryAfterParsing:
    def test_delta_seconds(self) -> None:
        response = httpx.Response(429, headers={"retry-after": "30"})
        assert _retry_after_seconds(response) == 30.0

    def test_http_date(self) -> None:
        future = datetime.now(tz=UTC) + timedelta(seconds=60)
        stamp = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        response = httpx.Response(429, headers={"retry-after": stamp})
        value = _retry_after_seconds(response)
        assert value is not None
        assert 30 <= value <= 61

    def test_past_http_date_is_clamped_to_zero(self) -> None:
        past = datetime.now(tz=UTC) - timedelta(hours=1)
        stamp = past.strftime("%a, %d %b %Y %H:%M:%S GMT")
        response = httpx.Response(429, headers={"retry-after": stamp})
        assert _retry_after_seconds(response) == 0.0

    def test_absent_header(self) -> None:
        assert _retry_after_seconds(httpx.Response(429)) is None

    def test_negative_value_is_clamped(self) -> None:
        response = httpx.Response(429, headers={"retry-after": "-5"})
        assert _retry_after_seconds(response) == 0.0

    async def test_retry_after_is_capped_by_max_retry_wait(
        self, token_auth: ApiTokenCredentials, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A hostile Retry-After must not park the client for hours."""
        import asyncio

        waits: list[float] = []

        async def fake_sleep(delay: float) -> None:
            waits.append(delay)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            if len(calls) == 1:
                return httpx.Response(503, headers={"retry-after": "86400"})
            return httpx.Response(200, json={"id": "u", "email": "e@x.test"})

        client = CleverCloudClient(
            token_auth,
            base_url=BASE_URL,
            max_retries=1,
            max_retry_wait=5,
            transport=httpx.MockTransport(handler),
        )
        async with client:
            await client.get_profile()
        assert waits == [5.0]

    async def test_rate_limit_error_carries_a_date_based_retry_after(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        future = datetime.now(tz=UTC) + timedelta(seconds=45)
        stamp = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        client = make_client(
            lambda r: httpx.Response(429, headers={"retry-after": stamp})
        )
        async with client:
            with pytest.raises(RateLimitError) as excinfo:
                await client.get_profile()
        assert excinfo.value.retry_after is not None


class TestMalformedRetryAfter:
    """A server-controlled header must never escape the error hierarchy."""

    @pytest.mark.parametrize(
        "value", ["bogus", "Mon, 32 Foo 2026 99:99:99 GMT", "", "   ", "NaN", "1e999"]
    )
    def test_malformed_value_is_treated_as_absent(self, value: str) -> None:
        response = httpx.Response(429, headers={"retry-after": value})
        assert _retry_after_seconds(response) is None

    async def test_malformed_value_does_not_cancel_the_retry(
        self, token_auth: ApiTokenCredentials
    ) -> None:
        """A 503 with `Retry-After: bogus` used to raise ValueError instead."""
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            if len(calls) == 1:
                return httpx.Response(503, headers={"retry-after": "bogus"})
            return httpx.Response(200, json={"id": "u", "email": "e@x.test"})

        client = CleverCloudClient(
            token_auth,
            base_url=BASE_URL,
            max_retries=1,
            max_retry_wait=0,
            transport=httpx.MockTransport(handler),
        )
        async with client:
            profile = await client.get_profile()
        assert profile.id == "u"
        assert len(calls) == 2

    async def test_malformed_value_on_429_still_raises_the_sdk_error(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(
            lambda r: httpx.Response(429, headers={"retry-after": "bogus"})
        )
        async with client:
            with pytest.raises(RateLimitError) as excinfo:
                await client.get_profile()
        assert excinfo.value.retry_after is None
