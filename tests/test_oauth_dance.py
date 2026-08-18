"""Tests for the OAuth dance (issue #3, findings 1, 2 and 8)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import parse_qsl

import httpx
import pytest

from clever_cloud import OAuthConsumer, OAuthDance, OAuthError, RequestToken, SignatureMethod

API_URL = "https://api.example.test"
CONSUMER = OAuthConsumer(key="consumer-key", secret="consumer-secret")

Handler = Callable[[httpx.Request], httpx.Response]


def make_dance(handler: Handler, **kwargs: object) -> OAuthDance:
    return OAuthDance(
        CONSUMER,
        api_url=API_URL,
        transport=httpx.MockTransport(handler),
        **kwargs,  # type: ignore[arg-type]
    )


def form(response_text: str) -> dict[str, str]:
    return dict(parse_qsl(response_text))


def request_token_response(**extra: str) -> str:
    params = {
        "oauth_token": "req-token",
        "oauth_token_secret": "req-secret",
        "oauth_callback_confirmed": "true",
        **extra,
    }
    return "&".join(f"{k}={v}" for k, v in params.items())


class TestRequestTokenSigning:
    """Finding 1: the exchange omitted timestamp, nonce and version."""

    def test_body_carries_every_oauth_parameter(self) -> None:
        seen: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(dict(parse_qsl(request.content.decode())))
            return httpx.Response(200, text=request_token_response())

        with make_dance(handler) as dance:
            dance.get_request_token()

        body = seen[0]
        assert body["oauth_consumer_key"] == "consumer-key"
        assert body["oauth_signature_method"] == "HMAC-SHA512"
        assert body["oauth_version"] == "1.0"
        assert body["oauth_nonce"]
        assert body["oauth_timestamp"].isdigit()
        assert body["oauth_signature"]
        assert body["oauth_callback"] == "oob"

    def test_signature_does_not_expose_the_consumer_secret(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.content.decode())
            return httpx.Response(200, text=request_token_response())

        with make_dance(handler) as dance:
            dance.get_request_token()
        assert "consumer-secret" not in seen[0]

    def test_two_dances_produce_different_nonces(self) -> None:
        nonces: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonces.append(dict(parse_qsl(request.content.decode()))["oauth_nonce"])
            return httpx.Response(200, text=request_token_response())

        with make_dance(handler) as dance:
            dance.get_request_token()
            dance.get_request_token()
        assert nonces[0] != nonces[1]

    def test_plaintext_mode_still_carries_the_secret_by_design(self) -> None:
        seen: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(dict(parse_qsl(request.content.decode())))
            return httpx.Response(200, text=request_token_response())

        with make_dance(handler, signature_method=SignatureMethod.PLAINTEXT) as dance:
            dance.get_request_token()
        assert seen[0]["oauth_signature_method"] == "PLAINTEXT"
        assert seen[0]["oauth_signature"] == "consumer-secret&"

    def test_returns_the_token(self) -> None:
        with make_dance(lambda r: httpx.Response(200, text=request_token_response())) as dance:
            token = dance.get_request_token()
        assert token.token == "req-token"
        assert token.secret == "req-secret"
        assert token.callback_confirmed is True

    def test_http_error_is_reported_with_its_step(self) -> None:
        with make_dance(lambda r: httpx.Response(500, text="boom")) as dance:
            with pytest.raises(OAuthError) as excinfo:
                dance.get_request_token()
        assert excinfo.value.step == "request_token"

    def test_incomplete_response_is_rejected(self) -> None:
        with make_dance(lambda r: httpx.Response(200, text="oauth_token=only")) as dance:
            with pytest.raises(OAuthError, match="Invalid request token"):
                dance.get_request_token()

    def test_network_failure_becomes_an_oauth_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        with make_dance(handler) as dance:
            with pytest.raises(OAuthError, match="Network failure"):
                dance.get_request_token()


class TestCallbackConfirmation:
    """Finding 8: oauth_callback_confirmed was ignored."""

    def test_unconfirmed_callback_is_refused(self) -> None:
        text = request_token_response(oauth_callback_confirmed="false")
        with make_dance(
            lambda r: httpx.Response(200, text=text),
            callback_url="https://app.example.test/cb",
        ) as dance:
            with pytest.raises(OAuthError, match="did not confirm"):
                dance.get_request_token()

    def test_missing_confirmation_is_refused_for_a_real_callback(self) -> None:
        text = "oauth_token=t&oauth_token_secret=s"
        with make_dance(
            lambda r: httpx.Response(200, text=text),
            callback_url="https://app.example.test/cb",
        ) as dance:
            with pytest.raises(OAuthError, match="did not confirm"):
                dance.get_request_token()

    def test_out_of_band_flow_does_not_require_confirmation(self) -> None:
        text = "oauth_token=t&oauth_token_secret=s"
        with make_dance(lambda r: httpx.Response(200, text=text)) as dance:
            token = dance.get_request_token()
        assert token.callback_confirmed is False


class TestCallbackValidation:
    """Finding 8: the callback token was never compared to the request token."""

    @pytest.fixture
    def token(self) -> RequestToken:
        return RequestToken(token="req-token", secret="req-secret")

    def test_valid_callback_returns_the_verifier(self, token: RequestToken) -> None:
        with make_dance(lambda r: httpx.Response(200)) as dance:
            verifier = dance.parse_callback_url(
                "https://app.example.test/cb?oauth_token=req-token&oauth_verifier=v-123",
                token,
            )
        assert verifier == "v-123"

    def test_mismatched_token_is_refused(self, token: RequestToken) -> None:
        with make_dance(lambda r: httpx.Response(200)) as dance:
            with pytest.raises(OAuthError, match="does not match"):
                dance.parse_callback_url(
                    "https://app.example.test/cb?oauth_token=other&oauth_verifier=v",
                    token,
                )

    def test_absent_token_is_refused(self, token: RequestToken) -> None:
        with make_dance(lambda r: httpx.Response(200)) as dance:
            with pytest.raises(OAuthError, match="does not match"):
                dance.parse_callback_url(
                    "https://app.example.test/cb?oauth_verifier=v", token
                )

    def test_missing_verifier_is_refused(self, token: RequestToken) -> None:
        with make_dance(lambda r: httpx.Response(200)) as dance:
            with pytest.raises(OAuthError, match="missing oauth_verifier"):
                dance.parse_callback_url(
                    "https://app.example.test/cb?oauth_token=req-token", token
                )

    def test_authorization_url(self, token: RequestToken) -> None:
        with make_dance(lambda r: httpx.Response(200)) as dance:
            url = dance.get_authorization_url(token)
        assert url == f"{API_URL}/v2/oauth/authorize?oauth_token=req-token"


class TestAccessToken:
    @pytest.fixture
    def token(self) -> RequestToken:
        return RequestToken(token="req-token", secret="req-secret")

    def test_exchange_is_fully_signed(self, token: RequestToken) -> None:
        seen: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(dict(parse_qsl(request.content.decode())))
            return httpx.Response(
                200, text="oauth_token=access&oauth_token_secret=access-secret"
            )

        with make_dance(handler) as dance:
            dance.get_access_token(token, "verifier-1")

        body = seen[0]
        assert body["oauth_token"] == "req-token"
        assert body["oauth_verifier"] == "verifier-1"
        assert body["oauth_signature_method"] == "HMAC-SHA512"
        assert body["oauth_nonce"]
        assert body["oauth_timestamp"].isdigit()
        assert body["oauth_version"] == "1.0"
        assert "consumer-secret" not in request_body_text(seen[0])

    def test_returns_usable_credentials(self, token: RequestToken) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text="oauth_token=access&oauth_token_secret=access-secret"
            )

        with make_dance(handler) as dance:
            credentials = dance.get_access_token(token, "v")

        assert credentials.token == "access"
        assert credentials.secret == "access-secret"
        assert credentials.consumer_key == "consumer-key"
        assert credentials.signature_method is SignatureMethod.HMAC_SHA512
        # The credentials can immediately sign a request.
        assert credentials.get_authorization_header("GET", "https://x.test/v2/self")

    def test_expiration_date_is_kept(self, token: RequestToken) -> None:
        """Finding 8: the returned expiration_date was discarded."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text=(
                    "oauth_token=access&oauth_token_secret=s"
                    "&expiration_date=2030-01-01T00%3A00%3A00Z"
                ),
            )

        with make_dance(handler) as dance:
            credentials = dance.get_access_token(token, "v")
        assert credentials.expiration_date == datetime(2030, 1, 1, tzinfo=UTC)
        assert credentials.is_expired() is False

    def test_epoch_expiration_is_parsed(self, token: RequestToken) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text="oauth_token=a&oauth_token_secret=s&expiration_date=1700000000"
            )

        with make_dance(handler) as dance:
            credentials = dance.get_access_token(token, "v")
        assert credentials.expiration_date == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)

    def test_absent_expiration_is_none(self, token: RequestToken) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="oauth_token=a&oauth_token_secret=s")

        with make_dance(handler) as dance:
            credentials = dance.get_access_token(token, "v")
        assert credentials.expiration_date is None

    def test_incomplete_response_is_rejected(self, token: RequestToken) -> None:
        with make_dance(lambda r: httpx.Response(200, text="oauth_token=a")) as dance:
            with pytest.raises(OAuthError, match="Invalid access token"):
                dance.get_access_token(token, "v")


def request_body_text(body: dict[str, str]) -> str:
    return "&".join(f"{k}={v}" for k, v in body.items())


class TestLogin:
    """The password-driven shortcut, kept for browser-less automation."""

    @pytest.fixture
    def token(self) -> RequestToken:
        return RequestToken(token="req-token", secret="req-secret")

    def test_successful_login_returns_the_verifier(self, token: RequestToken) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v2/sessions/login":
                return httpx.Response(303, headers={"location": "/"})
            return httpx.Response(
                302,
                headers={
                    "location": "https://app.test/cb?oauth_token=req-token&oauth_verifier=v-9"
                },
            )

        with make_dance(handler) as dance:
            assert dance.login(token, email="a@b.test", password="pw") == "v-9"

    def test_verifier_from_a_foreign_token_is_refused(self, token: RequestToken) -> None:
        """A redirect for another authorization must not be accepted."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v2/sessions/login":
                return httpx.Response(303, headers={"location": "/"})
            return httpx.Response(
                302,
                headers={
                    "location": "https://app.test/cb?oauth_token=someone-else&oauth_verifier=v"
                },
            )

        with make_dance(handler) as dance:
            with pytest.raises(OAuthError, match="does not match"):
                dance.login(token, email="a@b.test", password="pw")

    def test_invalid_credentials(self, token: RequestToken) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="bad")

        with make_dance(handler) as dance:
            with pytest.raises(OAuthError, match="Invalid credentials"):
                dance.login(token, email="a@b.test", password="pw")

    def test_mfa_required_without_code(self, token: RequestToken) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<mfa form>")

        with make_dance(handler) as dance:
            with pytest.raises(OAuthError, match="MFA code required"):
                dance.login(token, email="a@b.test", password="pw")

    def test_mfa_kind_is_configurable(self, token: RequestToken) -> None:
        """The MFA kind used to be hard-coded to TOTP."""
        seen: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v2/sessions/login":
                return httpx.Response(200, text="<mfa form>")
            if request.url.path == "/v2/sessions/mfa_login":
                seen.append(dict(parse_qsl(request.content.decode())))
                return httpx.Response(303, headers={"location": "/"})
            return httpx.Response(
                302,
                headers={
                    "location": "https://app.test/cb?oauth_token=req-token&oauth_verifier=v"
                },
            )

        with make_dance(handler) as dance:
            dance.login(
                token, email="a@b.test", password="pw", mfa_code="123456", mfa_kind="WEBAUTHN"
            )
        assert seen[0]["mfa_kind"] == "WEBAUTHN"

    def test_invalid_mfa_code(self, token: RequestToken) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v2/sessions/login":
                return httpx.Response(200, text="<mfa form>")
            return httpx.Response(401, text="bad code")

        with make_dance(handler) as dance:
            with pytest.raises(OAuthError, match="Invalid MFA code"):
                dance.login(token, email="a@b.test", password="pw", mfa_code="000000")

    def test_consent_screen_is_approved(self, token: RequestToken) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v2/sessions/login":
                return httpx.Response(303, headers={"location": "/"})
            if request.method == "GET":
                return httpx.Response(200, text="<consent form>")
            return httpx.Response(
                303,
                headers={
                    "location": "https://app.test/cb?oauth_token=req-token&oauth_verifier=v-c"
                },
            )

        with make_dance(handler) as dance:
            assert dance.login(token, email="a@b.test", password="pw") == "v-c"


class TestDanceRedaction:
    """Finding 2: dance credentials leaked through repr()."""

    def test_consumer_secret_is_hidden(self) -> None:
        text = repr(OAuthConsumer(key="KEY", secret="CONSUMER_SECRET"))
        assert "CONSUMER_SECRET" not in text
        assert "KEY" in text

    def test_request_token_secret_is_hidden(self) -> None:
        text = repr(RequestToken(token="TOKEN", secret="TOKEN_SECRET"))
        assert "TOKEN_SECRET" not in text
        assert "TOKEN" in text

    def test_oauth_error_details_are_truncated(self) -> None:
        error = OAuthError("failed", step="login", details="x" * 100_000)
        assert error.details is not None
        assert len(error.details) < 3000


class TestLoginTransportErrors:
    """Every dance call must translate a network failure into an OAuthError."""

    @pytest.fixture
    def token(self) -> RequestToken:
        return RequestToken(token="req-token", secret="req-secret")

    def _failing_at(self, failing_path: str) -> Handler:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == failing_path:
                raise httpx.ConnectError("connection refused")
            if request.url.path == "/v2/sessions/login":
                return httpx.Response(200, text="<mfa form>")
            if request.url.path == "/v2/sessions/mfa_login":
                return httpx.Response(303, headers={"location": "/"})
            return httpx.Response(200, text="<consent form>")

        return handler

    def test_login_network_failure(self, token: RequestToken) -> None:
        with make_dance(self._failing_at("/v2/sessions/login")) as dance:
            with pytest.raises(OAuthError) as excinfo:
                dance.login(token, email="a@b.test", password="pw")
        assert excinfo.value.step == "login"
        assert "ConnectError" in excinfo.value.message

    def test_mfa_network_failure(self, token: RequestToken) -> None:
        with make_dance(self._failing_at("/v2/sessions/mfa_login")) as dance:
            with pytest.raises(OAuthError) as excinfo:
                dance.login(token, email="a@b.test", password="pw", mfa_code="123456")
        assert excinfo.value.step == "mfa_login"

    def test_authorize_network_failure(self, token: RequestToken) -> None:
        with make_dance(self._failing_at("/v2/oauth/authorize")) as dance:
            with pytest.raises(OAuthError) as excinfo:
                dance.login(token, email="a@b.test", password="pw", mfa_code="123456")
        assert excinfo.value.step == "authorize"

    def test_approve_network_failure(self, token: RequestToken) -> None:
        """The consent POST is the fourth call and was unguarded too."""
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(f"{request.method} {request.url.path}")
            if request.url.path == "/v2/sessions/login":
                return httpx.Response(303, headers={"location": "/"})
            if request.method == "GET":
                return httpx.Response(200, text="<consent form>")
            raise httpx.ReadTimeout("timeout")

        with make_dance(handler) as dance:
            with pytest.raises(OAuthError) as excinfo:
                dance.login(token, email="a@b.test", password="pw")
        assert excinfo.value.step == "authorize"

    def test_no_raw_httpx_error_escapes(self, token: RequestToken) -> None:
        """Nothing outside the SDK hierarchy reaches the caller."""
        from clever_cloud import CleverCloudError

        with make_dance(self._failing_at("/v2/sessions/login")) as dance:
            with pytest.raises(CleverCloudError):
                dance.login(token, email="a@b.test", password="pw")


class TestCredentialsTargetTheIssuingApi:
    """Credentials must keep addressing the deployment that issued them."""

    @pytest.fixture
    def token(self) -> RequestToken:
        return RequestToken(token="req-token", secret="req-secret")

    def _access_token_handler(self) -> Handler:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="oauth_token=access&oauth_token_secret=s")

        return handler

    def test_custom_api_root_is_preserved(self, token: RequestToken) -> None:
        with make_dance(self._access_token_handler()) as dance:
            credentials = dance.get_access_token(token, "v")
        assert credentials.base_url == API_URL
        assert credentials.get_base_url() == API_URL

    def test_default_api_root_is_unchanged(self, token: RequestToken) -> None:
        dance = OAuthDance(
            CONSUMER, transport=httpx.MockTransport(self._access_token_handler())
        )
        with dance:
            credentials = dance.get_access_token(token, "v")
        assert credentials.get_base_url() == "https://api.clever-cloud.com"

    async def test_client_handoff_targets_the_private_deployment(
        self, token: RequestToken
    ) -> None:
        """The full flow: dance on a private root, then use the credentials."""
        from clever_cloud import CleverCloudClient

        with make_dance(self._access_token_handler()) as dance:
            credentials = dance.get_access_token(token, "v")

        seen: list[httpx.Request] = []

        def api_handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"id": "u_1", "email": "u@example.test"})

        # No base_url passed: the client must follow the credentials.
        async with CleverCloudClient(
            credentials, transport=httpx.MockTransport(api_handler)
        ) as client:
            await client.get_profile()

        assert str(seen[0].url).startswith(API_URL)
        assert "api.clever-cloud.com" not in str(seen[0].url)
