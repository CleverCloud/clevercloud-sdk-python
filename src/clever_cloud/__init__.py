"""Clever Cloud Python SDK.

Example with API Token (simplest):
    from clever_cloud import CleverCloudClient, ApiTokenCredentials

    async with CleverCloudClient(ApiTokenCredentials(token="...")) as client:
        profile = await client.get_profile()
        print(f"Hello, {profile.name}!")

Example with OAuth (full access):
    from clever_cloud import CleverCloudClient, OAuthCredentials

    credentials = OAuthCredentials(
        consumer_key="...", consumer_secret="...",
        token="...", secret="...",
    )
    async with CleverCloudClient(credentials) as client:
        app = await client.create_application(owner_id="...", name="my-app", instance_slug="node")
"""

from clever_cloud.auth import (
    ApiTokenCredentials,
    Auth,
    OAuthCredentials,
    SignatureMethod,
)
from clever_cloud.client import CleverCloudClient
from clever_cloud.exceptions import (
    AuthenticationError,
    AuthorizationError,
    CleverCloudError,
    HttpError,
    InvalidResponseError,
    NotFoundError,
    OAuthError,
    RateLimitError,
    TransportError,
)
from clever_cloud.models import (
    Application,
    Domain,
    MemberKind,
    NetworkGroup,
    NetworkGroupMember,
    NetworkGroupPeer,
    PeerCreated,
    PeerKind,
    PeerRole,
    Profile,
    TcpRedirection,
    WireguardEndpoint,
)
from clever_cloud.oauth_dance import OAuthConsumer, OAuthDance, RequestToken

__version__ = "0.2.0"

__all__ = [
    "ApiTokenCredentials",
    "Application",
    "Auth",
    "AuthenticationError",
    "AuthorizationError",
    "CleverCloudClient",
    "CleverCloudError",
    "Domain",
    "HttpError",
    "InvalidResponseError",
    "MemberKind",
    "NetworkGroup",
    "NetworkGroupMember",
    "NetworkGroupPeer",
    "NotFoundError",
    "OAuthConsumer",
    "OAuthCredentials",
    "OAuthDance",
    "OAuthError",
    "PeerCreated",
    "PeerKind",
    "PeerRole",
    "Profile",
    "RateLimitError",
    "RequestToken",
    "SignatureMethod",
    "TcpRedirection",
    "TransportError",
    "WireguardEndpoint",
]
