"""OAuth 1.0 dance to obtain access credentials.

Flow: get_request_token() -> login() or browser auth -> get_access_token()
"""

from dataclasses import dataclass
from typing import Self
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from clever_cloud.auth import OAuthCredentials
from clever_cloud.exceptions import OAuthError


@dataclass(frozen=True, slots=True)
class OAuthConsumer:
    """OAuth consumer credentials from Clever Cloud console."""

    key: str
    secret: str


@dataclass(frozen=True, slots=True)
class RequestToken:
    """Temporary token used during OAuth dance."""

    token: str
    secret: str


class OAuthDance:
    """Performs OAuth 1.0 dance to obtain OAuthCredentials.

    Example:
        with OAuthDance(OAuthConsumer(key="...", secret="...")) as dance:
            request_token = dance.get_request_token()
            verifier = dance.login(request_token, email="...", password="...")
            credentials = dance.get_access_token(request_token, verifier)
    """

    API_URL = "https://api.clever-cloud.com"

    def __init__(
        self,
        consumer: OAuthConsumer,
        *,
        callback_url: str = "oob",
        timeout: float = 30.0,
    ) -> None:
        self._consumer = consumer
        self._callback_url = callback_url
        self._client = httpx.Client(base_url=self.API_URL, timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _get_oauth_signature(self, token_secret: str = "") -> str:
        return f"{self._consumer.secret}&{token_secret}"

    def get_request_token(self) -> RequestToken:
        """Step 1: Get temporary request token."""
        body = {
            "oauth_consumer_key": self._consumer.key,
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": self._get_oauth_signature(),
            "oauth_callback": self._callback_url,
        }

        response = self._client.post(
            "/v2/oauth/request_token",
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/x-www-form-urlencoded",
            },
        )

        if response.status_code != 200:
            raise OAuthError(
                f"Failed to get request token: {response.text}",
                step="request_token",
                details=response.text,
            )

        # Parse the response (format: oauth_token=...&oauth_token_secret=...)
        params = parse_qs(response.text)
        token = params.get("oauth_token", [""])[0]
        secret = params.get("oauth_token_secret", [""])[0]

        if not token or not secret:
            raise OAuthError(
                "Invalid request token response",
                step="request_token",
                details=response.text,
            )

        return RequestToken(token=token, secret=secret)

    def get_authorization_url(self, request_token: RequestToken) -> str:
        """Get URL for browser-based authorization."""
        params = urlencode({"oauth_token": request_token.token})
        return f"{self.API_URL}/v2/oauth/authorize?{params}"

    def login(
        self,
        request_token: RequestToken,
        *,
        email: str,
        password: str,
        mfa_code: str | None = None,
    ) -> str:
        """Step 2: Login with email/password and return OAuth verifier."""
        # First, login to create a session
        login_body: dict[str, str] = {
            "email": email,
            "pass": password,
            "from_authorize": "true",
        }

        login_response = self._client.post(
            "/v2/sessions/login",
            data=login_body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
            follow_redirects=False,
        )

        # Check for MFA requirement (status 200 means MFA form returned)
        if login_response.status_code == 200:
            if mfa_code is None:
                raise OAuthError(
                    "MFA code required",
                    step="login",
                    details="Please provide mfa_code parameter",
                )
            # Submit MFA code
            mfa_response = self._client.post(
                "/v2/sessions/mfa_login",
                data={
                    "mfa_attempt": mfa_code,
                    "mfa_kind": "TOTP",
                    "email": email,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                cookies=login_response.cookies,
                follow_redirects=False,
            )
            if mfa_response.status_code == 401:
                raise OAuthError(
                    "Invalid MFA code",
                    step="mfa_login",
                    details=mfa_response.text,
                )
            if mfa_response.status_code != 303:
                raise OAuthError(
                    f"MFA login failed: {mfa_response.text}",
                    step="mfa_login",
                    details=mfa_response.text,
                )
            session_cookies = mfa_response.cookies
        elif login_response.status_code == 401:
            raise OAuthError(
                "Invalid credentials",
                step="login",
                details=login_response.text,
            )
        elif login_response.status_code == 303:
            # Login successful, got session cookie
            session_cookies = login_response.cookies
        else:
            raise OAuthError(
                f"Login failed: {login_response.text}",
                step="login",
                details=login_response.text,
            )

        # Now authorize the OAuth application
        auth_response = self._client.get(
            "/v2/oauth/authorize",
            params={"oauth_token": request_token.token},
            cookies=session_cookies,
            follow_redirects=False,
        )

        # The response should redirect with oauth_verifier
        if auth_response.status_code in (301, 302, 303, 307, 308):
            location = auth_response.headers.get("Location", "")
            if "oauth_verifier=" in location:
                # Extract verifier from redirect URL
                parsed = urlparse(location)
                params = parse_qs(parsed.query)
                verifier = params.get("oauth_verifier", [""])[0]
                if verifier:
                    return verifier

        # If we get 200, user needs to approve OAuth rights
        if auth_response.status_code == 200:
            # Auto-approve by posting to authorize
            approve_response = self._client.post(
                "/v2/oauth/authorize",
                data={"oauth_token": request_token.token},
                cookies=session_cookies,
                follow_redirects=False,
            )
            if approve_response.status_code in (301, 302, 303, 307, 308):
                location = approve_response.headers.get("Location", "")
                if "oauth_verifier=" in location:
                    parsed = urlparse(location)
                    params = parse_qs(parsed.query)
                    verifier = params.get("oauth_verifier", [""])[0]
                    if verifier:
                        return verifier

        raise OAuthError(
            "Failed to get OAuth verifier",
            step="authorize",
            details=auth_response.text,
        )

    def get_access_token(
        self,
        request_token: RequestToken,
        verifier: str,
    ) -> OAuthCredentials:
        """Step 3: Exchange request token + verifier for final credentials."""
        body = {
            "oauth_consumer_key": self._consumer.key,
            "oauth_signature_method": "PLAINTEXT",
            "oauth_signature": self._get_oauth_signature(request_token.secret),
            "oauth_token": request_token.token,
            "oauth_verifier": verifier,
        }

        response = self._client.post(
            "/v2/oauth/access_token",
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/x-www-form-urlencoded",
            },
        )

        if response.status_code != 200:
            raise OAuthError(
                f"Failed to get access token: {response.text}",
                step="access_token",
                details=response.text,
            )

        # Parse the response
        params = parse_qs(response.text)
        token = params.get("oauth_token", [""])[0]
        secret = params.get("oauth_token_secret", [""])[0]

        if not token or not secret:
            raise OAuthError(
                "Invalid access token response",
                step="access_token",
                details=response.text,
            )

        return OAuthCredentials(
            consumer_key=self._consumer.key,
            consumer_secret=self._consumer.secret,
            token=token,
            secret=secret,
        )
