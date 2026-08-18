"""OAuth 1.0a dance to obtain access credentials.

Flow: ``get_request_token()`` -> browser authorization (or ``login()``)
-> ``get_access_token()``.
"""

from __future__ import annotations

import base64
import hmac
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Self
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit

import httpx

from clever_cloud.auth import (
    HASH_ALGORITHMS,
    OAUTH_VERSION,
    OAuthCredentials,
    SignatureMethod,
    build_signature_base_string,
    percent_encode,
    redact,
)
from clever_cloud.exceptions import OAuthError

_FORM_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/x-www-form-urlencoded",
}
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True, slots=True, repr=False)
class OAuthConsumer:
    """OAuth consumer credentials from the Clever Cloud console."""

    key: str
    secret: str = field(repr=False)

    def __repr__(self) -> str:
        return f"OAuthConsumer(key={self.key!r}, secret={redact(self.secret)})"


@dataclass(frozen=True, slots=True, repr=False)
class RequestToken:
    """Temporary token used during the OAuth dance."""

    token: str
    secret: str = field(repr=False)
    callback_confirmed: bool = False

    def __repr__(self) -> str:
        return (
            f"RequestToken(token={self.token!r}, secret={redact(self.secret)}, "
            f"callback_confirmed={self.callback_confirmed!r})"
        )


class OAuthDance:
    """Performs the OAuth 1.0a dance to obtain :class:`OAuthCredentials`.

    Example:
        with OAuthDance(OAuthConsumer(key="...", secret="...")) as dance:
            request_token = dance.get_request_token()
            webbrowser.open(dance.get_authorization_url(request_token))
            verifier = dance.parse_callback_url(callback_url, request_token)
            credentials = dance.get_access_token(request_token, verifier)
    """

    API_URL = "https://api.clever-cloud.com"

    def __init__(
        self,
        consumer: OAuthConsumer,
        *,
        callback_url: str = "oob",
        timeout: float = 30.0,
        signature_method: SignatureMethod = SignatureMethod.HMAC_SHA512,
        api_url: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Create a dance.

        Args:
            consumer: Consumer key/secret issued by the Clever Cloud console.
            callback_url: Callback the API redirects to, or ``"oob"`` for
                out-of-band (the verifier is then shown to the user).
            timeout: Per-request timeout, in seconds.
            signature_method: Signature method; HMAC-SHA512 by default.
                ``PLAINTEXT`` is a legacy compatibility mode.
            api_url: Override the API root (testing, private deployments).
            transport: Custom transport, mainly useful for tests.
        """
        self._consumer = consumer
        self._callback_url = callback_url
        self._signature_method = signature_method
        self._api_url = (api_url or self.API_URL).rstrip("/")
        self._client = httpx.Client(
            base_url=self._api_url, timeout=timeout, transport=transport
        )

    def close(self) -> None:
        """Close the underlying HTTP client. Called on context-manager exit."""
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _signed_params(
        self,
        url: str,
        extra: dict[str, str],
        *,
        token_secret: str = "",
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> dict[str, str]:
        """Build the fully signed OAuth parameters for a dance request.

        Every request carries a signature method, timestamp, nonce and version,
        so it cannot be replayed — the legacy format omitted all four.
        """
        params = {
            "oauth_consumer_key": self._consumer.key,
            "oauth_signature_method": self._signature_method.value,
            "oauth_timestamp": str(timestamp if timestamp is not None else int(time.time())),
            "oauth_nonce": nonce or secrets.token_hex(16),
            "oauth_version": OAUTH_VERSION,
            **extra,
        }
        key = f"{percent_encode(self._consumer.secret)}&{percent_encode(token_secret)}"
        if self._signature_method is SignatureMethod.PLAINTEXT:
            signature = key
        else:
            base_string = build_signature_base_string("POST", url, params.items())
            digest = hmac.new(
                key.encode("utf-8"),
                base_string.encode("utf-8"),
                HASH_ALGORITHMS[self._signature_method],
            ).digest()
            signature = base64.b64encode(digest).decode("ascii")
        return {**params, "oauth_signature": signature}

    def _post_form(self, path: str, body: dict[str, str], *, step: str) -> dict[str, str]:
        try:
            response = self._client.post(path, data=body, headers=_FORM_HEADERS)
        except httpx.TransportError as exc:
            msg = f"Network failure during {step}: {type(exc).__name__}: {exc}"
            raise OAuthError(msg, step=step) from exc

        if response.status_code != 200:
            raise OAuthError(
                f"Step {step} failed with HTTP {response.status_code}",
                step=step,
                details=response.text,
            )
        return dict(parse_qsl(response.text, keep_blank_values=True))

    def get_request_token(self) -> RequestToken:
        """Step 1: get a temporary request token.

        Returns:
            The request token to pass to :meth:`get_authorization_url`, then to
            :meth:`get_access_token`. Keep it for the whole dance: its secret
            signs the final exchange, and its token validates the callback.

        Raises:
            OAuthError: If the API rejects the request, answers an incomplete
                body, does not confirm the callback, or is unreachable. Check
                ``.step`` to see which stage failed.
        """
        url = f"{self._api_url}/v2/oauth/request_token"
        body = self._signed_params(url, {"oauth_callback": self._callback_url})
        params = self._post_form("/v2/oauth/request_token", body, step="request_token")

        token = params.get("oauth_token", "")
        secret = params.get("oauth_token_secret", "")
        if not token or not secret:
            raise OAuthError(
                "Invalid request token response",
                step="request_token",
                details=str(params),
            )

        # RFC 5849 §2.1: the server must confirm it recorded the callback.
        confirmed = params.get("oauth_callback_confirmed", "").lower() == "true"
        if not confirmed and self._callback_url != "oob":
            raise OAuthError(
                "Server did not confirm the OAuth callback "
                "(oauth_callback_confirmed is not 'true'); the authorization "
                "could be redirected to an address you did not request",
                step="request_token",
                details=str(params),
            )

        return RequestToken(token=token, secret=secret, callback_confirmed=confirmed)

    def get_authorization_url(self, request_token: RequestToken) -> str:
        """Get the URL to send the user to for authorization.

        Args:
            request_token: Token from :meth:`get_request_token`.

        Returns:
            The URL to open in a browser. Once the user approves, the API
            redirects to the callback given to the constructor; pass that
            callback URL to :meth:`parse_callback_url`.
        """
        params = urlencode({"oauth_token": request_token.token})
        return f"{self._api_url}/v2/oauth/authorize?{params}"

    def parse_callback_url(self, callback_url: str, request_token: RequestToken) -> str:
        """Extract and validate the verifier from the URL the callback received.

        Verifies that the callback carries the very token this dance requested,
        so a verifier obtained for another authorization cannot be injected.

        Args:
            callback_url: The full URL your callback received, query included.
            request_token: The token returned by :meth:`get_request_token`.

        Returns:
            The verifier to pass to :meth:`get_access_token`.

        Raises:
            OAuthError: If the token does not match or the verifier is missing.
        """
        params = parse_qs(urlsplit(callback_url).query)
        returned_token = params.get("oauth_token", [""])[0]
        verifier = params.get("oauth_verifier", [""])[0]

        if not hmac.compare_digest(returned_token, request_token.token):
            raise OAuthError(
                "Callback oauth_token does not match the request token",
                step="callback",
            )
        if not verifier:
            raise OAuthError("Callback is missing oauth_verifier", step="callback")
        return verifier

    def _verifier_from_redirect(
        self, response: httpx.Response, request_token: RequestToken
    ) -> str | None:
        if response.status_code not in _REDIRECT_STATUSES:
            return None
        location = response.headers.get("Location", "")
        if "oauth_verifier=" not in location:
            return None
        return self.parse_callback_url(location, request_token)

    def login(
        self,
        request_token: RequestToken,
        *,
        email: str,
        password: str,
        mfa_code: str | None = None,
        mfa_kind: str = "TOTP",
    ) -> str:
        """Step 2 (non-interactive): log in and return the OAuth verifier.

        Warning:
            This drives the console's internal session endpoints with the
            account password, which is not a supported OAuth flow: prefer
            :meth:`get_authorization_url` plus :meth:`parse_callback_url` and let
            the user authorize in a browser. It is kept for automation contexts
            where no browser is available.

        Args:
            request_token: Token returned by :meth:`get_request_token`.
            email: Account email.
            password: Account password.
            mfa_code: One-time code, when the account has MFA enabled.
            mfa_kind: MFA kind expected by the API (``"TOTP"`` by default).

        Returns:
            The OAuth verifier, to pass to :meth:`get_access_token`.

        Raises:
            OAuthError: If the credentials or the MFA code are rejected, if MFA
                is required but no code was given, or if no verifier could be
                obtained. ``.step`` names the stage that failed.
        """
        # Session cookies are kept by the HTTPX client itself: passing them
        # per-request is deprecated and makes persistence ambiguous.
        login_response = self._client.post(
            "/v2/sessions/login",
            data={"email": email, "pass": password, "from_authorize": "true"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )

        # A 200 means the MFA form was returned instead of a session redirect.
        if login_response.status_code == 200:
            if mfa_code is None:
                raise OAuthError(
                    "MFA code required",
                    step="login",
                    details="Please provide the mfa_code parameter",
                )
            mfa_response = self._client.post(
                "/v2/sessions/mfa_login",
                data={
                    "mfa_attempt": mfa_code,
                    "mfa_kind": mfa_kind,
                    "email": email,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=False,
            )
            if mfa_response.status_code == 401:
                raise OAuthError(
                    "Invalid MFA code", step="mfa_login", details=mfa_response.text
                )
            if mfa_response.status_code != 303:
                raise OAuthError(
                    f"MFA login failed with HTTP {mfa_response.status_code}",
                    step="mfa_login",
                    details=mfa_response.text,
                )
        elif login_response.status_code == 401:
            raise OAuthError(
                "Invalid credentials", step="login", details=login_response.text
            )
        elif login_response.status_code == 303:
            pass  # Session cookie recorded on the client by HTTPX.
        else:
            raise OAuthError(
                f"Login failed with HTTP {login_response.status_code}",
                step="login",
                details=login_response.text,
            )

        auth_response = self._client.get(
            "/v2/oauth/authorize",
            params={"oauth_token": request_token.token},
            follow_redirects=False,
        )
        verifier = self._verifier_from_redirect(auth_response, request_token)
        if verifier:
            return verifier

        # HTTP 200 means the consent screen was returned: approve it explicitly.
        if auth_response.status_code == 200:
            approve_response = self._client.post(
                "/v2/oauth/authorize",
                data={"oauth_token": request_token.token},
                follow_redirects=False,
            )
            verifier = self._verifier_from_redirect(approve_response, request_token)
            if verifier:
                return verifier

        raise OAuthError(
            "Failed to get OAuth verifier", step="authorize", details=auth_response.text
        )

    def get_access_token(
        self,
        request_token: RequestToken,
        verifier: str,
    ) -> OAuthCredentials:
        """Step 3: exchange the request token and verifier for credentials.

        Args:
            request_token: Token from :meth:`get_request_token`.
            verifier: Verifier from :meth:`parse_callback_url` or
                :meth:`login`.

        Returns:
            Long-lived credentials, ready to be passed to
            :class:`CleverCloudClient`. Store all four values: the consumer
            pair is needed to sign requests, not only the access token.

        Raises:
            OAuthError: If the exchange is rejected — commonly an expired
                request token or a verifier already used — or if the response
                is incomplete.
        """
        url = f"{self._api_url}/v2/oauth/access_token"
        body = self._signed_params(
            url,
            {"oauth_token": request_token.token, "oauth_verifier": verifier},
            token_secret=request_token.secret,
        )
        params = self._post_form("/v2/oauth/access_token", body, step="access_token")

        token = params.get("oauth_token", "")
        secret = params.get("oauth_token_secret", "")
        if not token or not secret:
            raise OAuthError(
                "Invalid access token response",
                step="access_token",
                details=str(params),
            )

        return OAuthCredentials(
            consumer_key=self._consumer.key,
            consumer_secret=self._consumer.secret,
            token=token,
            secret=secret,
            signature_method=self._signature_method,
            expiration_date=_parse_expiration(params.get("expiration_date")),
        )


def _parse_expiration(raw: Any) -> datetime | None:
    """Parse the ``expiration_date`` the API returns with access tokens."""
    if raw is None or raw == "":
        return None
    text = str(raw)
    if text.isdigit():
        value = int(text)
        # Values are seconds or milliseconds depending on the endpoint.
        if value > 10_000_000_000:
            value //= 1000
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
