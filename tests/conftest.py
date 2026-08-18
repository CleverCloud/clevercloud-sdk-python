"""Shared fixtures: fake credentials and an HTTP layer backed by MockTransport.

No test performs a real network call — every request is served by a handler
declared in the test itself.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from clever_cloud import ApiTokenCredentials, CleverCloudClient, OAuthCredentials

Handler = Callable[[httpx.Request], httpx.Response]

BASE_URL = "https://api.example.test"


@pytest.fixture
def token_auth() -> ApiTokenCredentials:
    return ApiTokenCredentials(token="test-bearer-token", base_url=BASE_URL)


@pytest.fixture
def oauth_auth() -> OAuthCredentials:
    return OAuthCredentials(
        consumer_key="consumer-key",
        consumer_secret="consumer-secret",
        token="access-token",
        secret="access-secret",
        base_url=BASE_URL,
    )


@pytest.fixture
def make_client(
    token_auth: ApiTokenCredentials,
) -> Callable[..., CleverCloudClient]:
    """Build a client whose transport is a caller-supplied request handler."""

    def factory(handler: Handler, **kwargs: object) -> CleverCloudClient:
        kwargs.setdefault("auth", token_auth)
        kwargs.setdefault("base_url", BASE_URL)
        kwargs.setdefault("max_retries", 0)
        auth = kwargs.pop("auth")
        return CleverCloudClient(
            auth,  # type: ignore[arg-type]
            transport=httpx.MockTransport(handler),
            **kwargs,  # type: ignore[arg-type]
        )

    return factory


@pytest.fixture
def record_requests() -> tuple[list[httpx.Request], Callable[..., Handler]]:
    """Capture requests while returning a canned response."""
    seen: list[httpx.Request] = []

    def handler_factory(
        status_code: int = 200,
        json: object = None,
        *,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> Handler:
        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if content is not None:
                return httpx.Response(status_code, content=content, headers=headers)
            return httpx.Response(status_code, json=json, headers=headers)

        return handler

    return seen, handler_factory
