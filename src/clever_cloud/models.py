"""Data models for Clever Cloud API responses."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Self


def _parse_date(raw: Any) -> datetime:
    """Parse API date (timestamp in ms or ISO string)."""
    if isinstance(raw, int):
        return datetime.fromtimestamp(raw / 1000, tz=UTC)
    if isinstance(raw, str) and raw:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return datetime.now(tz=UTC)


@dataclass(frozen=True, slots=True)
class Profile:
    """User profile from GET /v2/self."""

    id: str
    email: str
    name: str
    phone: str
    address: str
    city: str
    zipcode: str
    country: str
    avatar: str
    creation_date: datetime
    lang: str
    email_validated: bool
    is_linked_to_github: bool
    admin: bool
    can_pay: bool
    preferred_mfa: str | None
    has_password: bool
    partner_id: str | None
    partner_name: str | None
    partner_console_url: str | None

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> Self:
        oauth_apps = data.get("oauthApps", [])
        is_linked_to_github = isinstance(oauth_apps, list) and "github" in oauth_apps

        return cls(
            id=data.get("id", ""),
            email=data.get("email", ""),
            name=data.get("name", ""),
            phone=data.get("phone", ""),
            address=data.get("address", ""),
            city=data.get("city", ""),
            zipcode=data.get("zipcode", ""),
            country=data.get("country", ""),
            avatar=data.get("avatar", ""),
            creation_date=_parse_date(data.get("creationDate", "")),
            lang=data.get("lang", ""),
            email_validated=data.get("emailValidated", False),
            is_linked_to_github=is_linked_to_github,
            admin=data.get("admin", False),
            can_pay=data.get("canPay", False),
            preferred_mfa=data.get("preferredMFA"),
            has_password=data.get("hasPassword", False),
            partner_id=data.get("partnerId"),
            partner_name=data.get("partnerName"),
            partner_console_url=data.get("partnerConsoleUrl"),
        )


@dataclass(frozen=True, slots=True)
class Domain:
    """Domain (vhost) for an application."""

    domain: str
    is_primary: bool

    @classmethod
    def from_api_response(
        cls, data: dict[str, Any], *, is_primary: bool = False
    ) -> Self:
        fqdn = data.get("fqdn", "").rstrip("/")
        return cls(
            domain=fqdn,
            is_primary=is_primary,
        )


@dataclass(frozen=True, slots=True)
class TcpRedirection:
    """TCP redirection for an application."""

    namespace: str
    port: int

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> Self:
        return cls(
            namespace=data.get("namespace", "default"),
            port=data.get("port", 0),
        )


@dataclass(frozen=True, slots=True)
class Application:
    """Application from the Clever Cloud API."""

    id: str
    name: str
    description: str
    zone: str
    instance_type: str
    instance_version: str
    instance_variant: str
    min_instances: int
    max_instances: int
    min_flavor: str
    max_flavor: str
    deploy_url: str
    creation_date: datetime
    state: str

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> Self:
        instance = data.get("instance", {})
        variant = instance.get("variant", {})

        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            zone=data.get("zone", ""),
            instance_type=instance.get("type", data.get("instanceType", "")),
            instance_version=instance.get("version", data.get("instanceVersion", "")),
            instance_variant=variant.get("id", data.get("instanceVariant", "")),
            min_instances=data.get("minInstances", 1),
            max_instances=data.get("maxInstances", 1),
            min_flavor=data.get("minFlavor", ""),
            max_flavor=data.get("maxFlavor", ""),
            deploy_url=data.get("deployUrl", ""),
            creation_date=_parse_date(data.get("creationDate", "")),
            state=data.get("state", ""),
        )
