"""Authentication strategies: OAuth 1.0a signed requests and API Token."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from urllib.parse import parse_qsl, quote, urlsplit

import httpx

OAUTH_VERSION = "1.0"

_DEFAULT_PORTS = {"http": 80, "https": 443}
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


class SignatureMethod(str, Enum):
    """OAuth 1.0a signature methods supported by this SDK.

    ``HMAC-SHA512`` is the method recommended by Clever Cloud for production.
    ``PLAINTEXT`` is a legacy compatibility mode: it sends the secrets in the
    header and produces a static, replayable ``Authorization`` value, so it must
    be selected explicitly.
    """

    HMAC_SHA512 = "HMAC-SHA512"
    HMAC_SHA256 = "HMAC-SHA256"
    PLAINTEXT = "PLAINTEXT"


HASH_ALGORITHMS = {
    SignatureMethod.HMAC_SHA512: hashlib.sha512,
    SignatureMethod.HMAC_SHA256: hashlib.sha256,
}


def percent_encode(value: str) -> str:
    """Percent-encode a value per RFC 5849 §3.6 (only unreserved chars survive)."""
    return quote(str(value), safe="~")


def normalize_url(url: str) -> str:
    """Return the signature base URL: no query, no fragment, no default port."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    netloc = host
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return f"{scheme}://{netloc}{path}"


def normalize_parameters(params: Iterable[tuple[str, str]]) -> str:
    """Encode, sort and join request parameters per RFC 5849 §3.4.1.3.2."""
    encoded = sorted(
        (percent_encode(key), percent_encode(value)) for key, value in params
    )
    return "&".join(f"{key}={value}" for key, value in encoded)


def build_signature_base_string(
    method: str,
    url: str,
    params: Iterable[tuple[str, str]],
) -> str:
    """Build the OAuth 1.0a signature base string (RFC 5849 §3.4.1.1)."""
    return "&".join(
        (
            method.upper(),
            percent_encode(normalize_url(url)),
            percent_encode(normalize_parameters(params)),
        )
    )


def _signing_key(consumer_secret: str, token_secret: str) -> str:
    return f"{percent_encode(consumer_secret)}&{percent_encode(token_secret)}"


def redact(value: str | None) -> str:
    """Represent a secret without disclosing it, keeping length as a hint."""
    if value is None:
        return "None"
    return f"'***redacted ({len(value)} chars)***'" if value else "''"


class Auth(ABC):
    """Base class for authentication strategies."""

    @abstractmethod
    def get_authorization_header(
        self,
        method: str,
        url: str,
        *,
        body_params: Sequence[tuple[str, str]] = (),
    ) -> str:
        """Build the ``Authorization`` header value for one specific request.

        Args:
            method: HTTP method, e.g. ``"GET"``.
            url: Absolute request URL, including its query string.
            body_params: Form-encoded body parameters, which take part in the
                OAuth signature when the body is ``x-www-form-urlencoded``.
        """

    @abstractmethod
    def get_base_url(self) -> str:
        """Return the default API base URL for this credential kind."""

    def apply_to_request(self, request: httpx.Request) -> httpx.Request:
        """Sign ``request`` in place and return it."""
        request.headers["Authorization"] = self.get_authorization_header(
            request.method,
            str(request.url),
            body_params=_form_body_params(request),
        )
        return request


def _form_body_params(request: httpx.Request) -> list[tuple[str, str]]:
    """Extract form-encoded body parameters, which must be signed."""
    content_type = request.headers.get("content-type", "")
    if not content_type.startswith(_FORM_CONTENT_TYPE):
        return []
    try:
        body = request.content.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return parse_qsl(body, keep_blank_values=True)


@dataclass(frozen=True, slots=True, repr=False)
class OAuthCredentials(Auth):
    """OAuth 1.0a credentials (4 tokens from the OAuth dance or clever-tools).

    Every request is signed with HMAC-SHA512 by default, including a timestamp,
    a nonce and the OAuth version, so the ``Authorization`` header cannot be
    replayed. Select ``SignatureMethod.PLAINTEXT`` only to talk to a server that
    requires the legacy format.
    """

    consumer_key: str
    consumer_secret: str = field(repr=False)
    token: str
    secret: str = field(repr=False)
    base_url: str | None = None
    signature_method: SignatureMethod = SignatureMethod.HMAC_SHA512
    expiration_date: datetime | None = None
    """When the access token expires, as reported by the API, if it says so."""

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"consumer_key={self.consumer_key!r}, "
            f"consumer_secret={redact(self.consumer_secret)}, "
            f"token={self.token!r}, "
            f"secret={redact(self.secret)}, "
            f"base_url={self.base_url!r}, "
            f"signature_method={self.signature_method!r}, "
            f"expiration_date={self.expiration_date!r})"
        )

    def get_authorization_header(
        self,
        method: str,
        url: str,
        *,
        body_params: Sequence[tuple[str, str]] = (),
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> str:
        """Build a fully signed OAuth 1.0a ``Authorization`` header.

        ``timestamp`` and ``nonce`` are generated per call; they are only
        accepted as arguments to make signatures reproducible in tests.
        """
        oauth_params = {
            "oauth_consumer_key": self.consumer_key,
            "oauth_token": self.token,
            "oauth_signature_method": self.signature_method.value,
            "oauth_timestamp": str(timestamp if timestamp is not None else int(time.time())),
            "oauth_nonce": nonce or secrets.token_hex(16),
            "oauth_version": OAUTH_VERSION,
        }
        signature = self._sign(method, url, oauth_params, body_params)
        parts = [
            f'{percent_encode(key)}="{percent_encode(value)}"'
            for key, value in sorted({**oauth_params, "oauth_signature": signature}.items())
        ]
        return f"OAuth {', '.join(parts)}"

    def _sign(
        self,
        method: str,
        url: str,
        oauth_params: Mapping[str, str],
        body_params: Sequence[tuple[str, str]],
    ) -> str:
        key = _signing_key(self.consumer_secret, self.secret)
        if self.signature_method is SignatureMethod.PLAINTEXT:
            return key
        params: list[tuple[str, str]] = [
            *parse_qsl(urlsplit(url).query, keep_blank_values=True),
            *body_params,
            *oauth_params.items(),
        ]
        base_string = build_signature_base_string(method, url, params)
        digest = hmac.new(
            key.encode("utf-8"),
            base_string.encode("utf-8"),
            HASH_ALGORITHMS[self.signature_method],
        ).digest()
        return base64.b64encode(digest).decode("ascii")

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """Whether the access token is past its expiration date, if known."""
        if self.expiration_date is None:
            return False
        return (now or datetime.now(tz=UTC)) >= self.expiration_date

    def get_base_url(self) -> str:
        return self.base_url or "https://api.clever-cloud.com"


@dataclass(frozen=True, slots=True, repr=False)
class ApiTokenCredentials(Auth):
    """API Token for the Clever Cloud API Bridge."""

    token: str = field(repr=False)
    base_url: str | None = None

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"token={redact(self.token)}, base_url={self.base_url!r})"
        )

    def get_authorization_header(
        self,
        method: str = "",
        url: str = "",
        *,
        body_params: Sequence[tuple[str, str]] = (),
    ) -> str:
        return f"Bearer {self.token}"

    def get_base_url(self) -> str:
        return self.base_url or "https://api-bridge.clever-cloud.com"
