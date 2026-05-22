"""Data models for Clever Cloud API responses."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
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


class MemberKind(str, Enum):
    """Kind of a NetworkGroup member."""

    ADDON = "ADDON"
    APPLICATION = "APPLICATION"
    EXTERNAL = "EXTERNAL"
    LOADBALANCER = "LOADBALANCER"


class PeerRole(str, Enum):
    """Role of a NetworkGroup peer."""

    CLIENT = "CLIENT"
    SERVER = "SERVER"


class PeerKind(str, Enum):
    """Kind of a NetworkGroup peer."""

    CLEVER = "CLEVER"
    EXTERNAL = "EXTERNAL"


@dataclass(frozen=True, slots=True)
class NetworkGroupMember:
    """Member of a NetworkGroup (GET .../members/{memberId})."""

    id: str
    domain_name: str
    kind: MemberKind
    label: str

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> Self:
        return cls(
            id=data.get("id", ""),
            domain_name=data.get("domainName", ""),
            kind=MemberKind(data.get("kind", "EXTERNAL")),
            label=data.get("label", ""),
        )


@dataclass(frozen=True, slots=True)
class WireguardEndpoint:
    """Wireguard endpoint (private/public address pair)."""

    private_address: str
    public_address: str

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> Self:
        return cls(
            private_address=str(data.get("privateAddress", "")),
            public_address=str(data.get("publicAddress", "")),
        )


@dataclass(frozen=True, slots=True)
class NetworkGroupPeer:
    """Peer of a NetworkGroup (CleverPeer or ExternalPeer flattened)."""

    id: str
    public_key: str
    parent_member: str
    endpoint: WireguardEndpoint | None
    hostname: str
    label: str
    kind: PeerKind
    hv: str | None

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> Self:
        endpoint_data = data.get("endpoint")
        endpoint = (
            WireguardEndpoint.from_api_response(endpoint_data)
            if isinstance(endpoint_data, dict)
            else None
        )
        # CleverPeer has "hv" field; ExternalPeer does not.
        hv = data.get("hv")
        kind = PeerKind.CLEVER if hv is not None else PeerKind.EXTERNAL
        return cls(
            id=data.get("id", ""),
            public_key=data.get("publicKey", ""),
            parent_member=data.get("parentMember", ""),
            endpoint=endpoint,
            hostname=data.get("hostname", ""),
            label=data.get("label", ""),
            kind=kind,
            hv=hv,
        )


@dataclass(frozen=True, slots=True)
class NetworkGroup:
    """NetworkGroup from GET .../networkgroups/{networkGroupId}."""

    id: str
    owner_id: str
    label: str
    description: str
    dns_sanitized_label: str
    network_ip: str
    last_allocated_ip: str
    version: int
    members: list[NetworkGroupMember] = field(default_factory=list)
    peers: list[NetworkGroupPeer] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> Self:
        return cls(
            id=data.get("id", ""),
            owner_id=data.get("ownerId", ""),
            label=data.get("label", ""),
            description=data.get("description", ""),
            dns_sanitized_label=data.get("dnsSanitizedLabel", ""),
            network_ip=data.get("networkIp", ""),
            last_allocated_ip=data.get("lastAllocatedIp", ""),
            version=data.get("version", 0),
            members=[
                NetworkGroupMember.from_api_response(m)
                for m in data.get("members") or []
            ],
            peers=[
                NetworkGroupPeer.from_api_response(p) for p in data.get("peers") or []
            ],
            tags=list(data.get("tags") or []),
        )


@dataclass(frozen=True, slots=True)
class PeerCreated:
    """Response of POST .../peers and .../external-peers."""

    peer_id: str
    raw: dict[str, Any]

    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> Self:
        return cls(
            peer_id=data.get("id", data.get("peerId", "")),
            raw=data,
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
