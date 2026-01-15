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

from clever_cloud.auth import ApiTokenCredentials, OAuthCredentials
from clever_cloud.client import CleverCloudClient
from clever_cloud.exceptions import (
    AuthenticationError,
    CleverCloudError,
    HttpError,
    OAuthError,
)
from clever_cloud.models import Application, Domain, Profile, TcpRedirection
from clever_cloud.oauth_dance import OAuthConsumer, OAuthDance, RequestToken

__version__ = "0.1.0"

__all__ = [
    "CleverCloudClient",
    "OAuthCredentials",
    "ApiTokenCredentials",
    "Application",
    "Domain",
    "Profile",
    "TcpRedirection",
    "OAuthDance",
    "OAuthConsumer",
    "RequestToken",
    "CleverCloudError",
    "AuthenticationError",
    "HttpError",
    "OAuthError",
]
