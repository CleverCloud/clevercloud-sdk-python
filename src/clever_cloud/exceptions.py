"""Exception hierarchy for Clever Cloud SDK."""

MAX_BODY_LENGTH = 2048
"""Maximum number of characters of a response body kept in an exception."""


def truncate_body(body: str, *, limit: int = MAX_BODY_LENGTH) -> str:
    """Truncate a response body so exceptions never carry unbounded payloads."""
    if len(body) <= limit:
        return body
    return f"{body[:limit]}... [truncated, {len(body)} characters total]"


class CleverCloudError(Exception):
    """Base exception for all SDK errors."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class TransportError(CleverCloudError):
    """Network-level failure (connection, timeout, TLS) raised by the transport."""


class InvalidResponseError(CleverCloudError):
    """The server returned a response the SDK cannot interpret.

    Raised for undecodable JSON bodies, unexpected redirections, or payloads
    whose shape does not match what the endpoint is documented to return.
    """

    def __init__(self, message: str, *, response_body: str = "") -> None:
        super().__init__(message)
        self.response_body = truncate_body(response_body)


class HttpError(CleverCloudError):
    """HTTP error with status code and (truncated) response body."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        response_body: str,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = truncate_body(response_body)


class AuthenticationError(HttpError):
    """Authentication failure (HTTP 401): credentials missing or invalid."""


class AuthorizationError(HttpError):
    """Authorization failure (HTTP 403): credentials valid but access denied."""


class NotFoundError(HttpError):
    """The requested resource does not exist (HTTP 404)."""


class RateLimitError(HttpError):
    """The API rejected the request for rate limiting (HTTP 429)."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        response_body: str,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(
            message, status_code=status_code, response_body=response_body
        )
        self.retry_after = retry_after


class OAuthError(CleverCloudError):
    """OAuth dance failure with step information."""

    def __init__(
        self,
        message: str,
        *,
        step: str,
        details: str | None = None,
    ) -> None:
        super().__init__(message)
        self.step = step
        self.details = truncate_body(details) if details is not None else None
