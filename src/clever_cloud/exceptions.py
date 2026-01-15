"""Exception hierarchy for Clever Cloud SDK."""


class CleverCloudError(Exception):
    """Base exception for all SDK errors."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class HttpError(CleverCloudError):
    """HTTP error with status code and response body."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        response_body: str,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class AuthenticationError(HttpError):
    """Authentication failure (HTTP 401/403)."""


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
        self.details = details
