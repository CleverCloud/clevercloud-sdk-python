"""Authentication: OAuth v1 PLAINTEXT and API Token."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import quote

import httpx


class Auth(ABC):
    """Base class for authentication strategies."""

    @abstractmethod
    def get_authorization_header(self) -> str: ...

    @abstractmethod
    def get_base_url(self) -> str: ...

    def apply_to_request(self, request: httpx.Request) -> httpx.Request:
        request.headers["Authorization"] = self.get_authorization_header()
        return request


@dataclass(frozen=True, slots=True)
class OAuthCredentials(Auth):
    """OAuth v1 PLAINTEXT credentials (4 tokens from OAuth dance or clever-tools)."""

    consumer_key: str
    consumer_secret: str
    token: str
    secret: str

    def get_authorization_header(self) -> str:
        """OAuth header with PLAINTEXT signature: consumerSecret%26tokenSecret."""
        signature = f"{quote(self.consumer_secret, safe='')}%26{quote(self.secret, safe='')}"
        parts = [
            f'oauth_consumer_key="{self.consumer_key}"',
            f'oauth_token="{self.token}"',
            f'oauth_signature="{signature}"',
        ]
        return f"OAuth {', '.join(parts)}"

    def get_base_url(self) -> str:
        return "https://api.clever-cloud.com"


@dataclass(frozen=True, slots=True)
class ApiTokenCredentials(Auth):
    """API Token for the Clever Cloud API Bridge."""

    token: str

    def get_authorization_header(self) -> str:
        return f"Bearer {self.token}"

    def get_base_url(self) -> str:
        return "https://api-bridge.clever-cloud.com"
