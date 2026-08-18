"""Data models for Clever Cloud API responses.

Parsing is strict on purpose: a payload that does not carry the fields an
endpoint is documented to return raises :class:`InvalidResponseError` instead of
producing a model filled with empty strings, zeroes or a fabricated timestamp.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Self, TypeVar

from clever_cloud.exceptions import InvalidResponseError


def _parse_date(raw: Any, *, model: str, key: str) -> datetime | None:
    """Parse an API date into a timezone-aware UTC datetime.

    Accepts a millisecond epoch integer or an ISO-8601 string. An absent date
    yields ``None`` — it is never replaced with the current time. A present but
    unparsable date is an error, not a silent fallback.
    """
    if raw is None or raw == "":
        return None
    if isinstance(raw, bool):
        msg = f"{model}.{key}: expected a date, got a boolean"
        raise InvalidResponseError(msg)
    if isinstance(raw, int):
        try:
            return datetime.fromtimestamp(raw / 1000, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            msg = f"{model}.{key}: invalid epoch timestamp {raw!r}"
            raise InvalidResponseError(msg) from exc
    if isinstance(raw, str):
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            msg = f"{model}.{key}: invalid ISO-8601 date {raw!r}"
            raise InvalidResponseError(msg) from exc
        # Normalize: a date without offset is interpreted as UTC, and any other
        # offset is converted, so every model exposes UTC-aware datetimes.
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    msg = f"{model}.{key}: unsupported date type {type(raw).__name__}"
    raise InvalidResponseError(msg)


def _mapping(data: Any, *, model: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        msg = f"{model}: expected a JSON object, got {type(data).__name__}"
        raise InvalidResponseError(msg)
    return data


def _require_str(data: Mapping[str, Any], key: str, *, model: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        msg = f"{model}: missing or invalid required field {key!r}"
        raise InvalidResponseError(msg)
    return value


def _require_int(data: Mapping[str, Any], key: str, *, model: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{model}: missing or invalid required field {key!r}"
        raise InvalidResponseError(msg)
    return value


def _optional_str(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    return value if isinstance(value, str) and value else None


def _optional_int(data: Mapping[str, Any], key: str) -> int | None:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _flag(data: Mapping[str, Any], key: str) -> bool:
    return bool(data.get(key, False))


@dataclass(frozen=True, slots=True)
class Profile:
    """User profile from ``GET /v2/self``."""

    id: str
    email: str
    name: str | None = None
    phone: str | None = None
    address: str | None = None
    city: str | None = None
    zipcode: str | None = None
    country: str | None = None
    avatar: str | None = None
    creation_date: datetime | None = None
    lang: str | None = None
    email_validated: bool = False
    is_linked_to_github: bool = False
    admin: bool = False
    can_pay: bool = False
    preferred_mfa: str | None = None
    has_password: bool = False
    partner_id: str | None = None
    partner_name: str | None = None
    partner_console_url: str | None = None

    @classmethod
    def from_api_response(cls, data: Any) -> Self:
        data = _mapping(data, model="Profile")
        oauth_apps = data.get("oauthApps", [])
        is_linked_to_github = isinstance(oauth_apps, list) and "github" in oauth_apps

        return cls(
            id=_require_str(data, "id", model="Profile"),
            email=_require_str(data, "email", model="Profile"),
            name=_optional_str(data, "name"),
            phone=_optional_str(data, "phone"),
            address=_optional_str(data, "address"),
            city=_optional_str(data, "city"),
            zipcode=_optional_str(data, "zipcode"),
            country=_optional_str(data, "country"),
            avatar=_optional_str(data, "avatar"),
            creation_date=_parse_date(
                data.get("creationDate"), model="Profile", key="creationDate"
            ),
            lang=_optional_str(data, "lang"),
            email_validated=_flag(data, "emailValidated"),
            is_linked_to_github=is_linked_to_github,
            admin=_flag(data, "admin"),
            can_pay=_flag(data, "canPay"),
            preferred_mfa=_optional_str(data, "preferredMFA"),
            has_password=_flag(data, "hasPassword"),
            partner_id=_optional_str(data, "partnerId"),
            partner_name=_optional_str(data, "partnerName"),
            partner_console_url=_optional_str(data, "partnerConsoleUrl"),
        )


@dataclass(frozen=True, slots=True)
class Domain:
    """Domain (vhost) for an application."""

    domain: str
    is_primary: bool

    @classmethod
    def from_api_response(cls, data: Any, *, is_primary: bool = False) -> Self:
        data = _mapping(data, model="Domain")
        return cls(
            domain=_require_str(data, "fqdn", model="Domain").rstrip("/"),
            is_primary=is_primary,
        )


@dataclass(frozen=True, slots=True)
class TcpRedirection:
    """TCP redirection for an application."""

    namespace: str
    port: int

    @classmethod
    def from_api_response(cls, data: Any) -> Self:
        data = _mapping(data, model="TcpRedirection")
        return cls(
            namespace=_require_str(data, "namespace", model="TcpRedirection"),
            port=_require_int(data, "port", model="TcpRedirection"),
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


_E = TypeVar("_E", bound=Enum)


def _parse_enum(enum_cls: type[_E], raw: Any, *, model: str, key: str) -> _E:
    try:
        return enum_cls(raw)
    except ValueError as exc:
        msg = f"{model}.{key}: unknown value {raw!r}"
        raise InvalidResponseError(msg) from exc


@dataclass(frozen=True, slots=True)
class NetworkGroupMember:
    """Member of a NetworkGroup (``GET .../members/{memberId}``)."""

    id: str
    domain_name: str
    kind: MemberKind
    label: str | None = None

    @classmethod
    def from_api_response(cls, data: Any) -> Self:
        data = _mapping(data, model="NetworkGroupMember")
        return cls(
            id=_require_str(data, "id", model="NetworkGroupMember"),
            domain_name=_require_str(data, "domainName", model="NetworkGroupMember"),
            kind=_parse_enum(
                MemberKind,
                _require_str(data, "kind", model="NetworkGroupMember"),
                model="NetworkGroupMember",
                key="kind",
            ),
            label=_optional_str(data, "label"),
        )


@dataclass(frozen=True, slots=True)
class WireguardEndpoint:
    """Wireguard endpoint (private/public address pair)."""

    private_address: str | None = None
    public_address: str | None = None

    @classmethod
    def from_api_response(cls, data: Any) -> Self:
        data = _mapping(data, model="WireguardEndpoint")
        return cls(
            private_address=_optional_str(data, "privateAddress"),
            public_address=_optional_str(data, "publicAddress"),
        )


@dataclass(frozen=True, slots=True)
class NetworkGroupPeer:
    """Peer of a NetworkGroup (CleverPeer or ExternalPeer flattened)."""

    id: str
    parent_member: str
    kind: PeerKind
    public_key: str | None = None
    endpoint: WireguardEndpoint | None = None
    hostname: str | None = None
    label: str | None = None
    hv: str | None = None

    @classmethod
    def from_api_response(cls, data: Any) -> Self:
        data = _mapping(data, model="NetworkGroupPeer")
        endpoint_data = data.get("endpoint")
        endpoint = (
            WireguardEndpoint.from_api_response(endpoint_data)
            if isinstance(endpoint_data, Mapping)
            else None
        )
        # CleverPeer carries an "hv" field; ExternalPeer does not.
        hv = _optional_str(data, "hv")
        return cls(
            id=_require_str(data, "id", model="NetworkGroupPeer"),
            parent_member=_require_str(data, "parentMember", model="NetworkGroupPeer"),
            kind=PeerKind.CLEVER if hv is not None else PeerKind.EXTERNAL,
            public_key=_optional_str(data, "publicKey"),
            endpoint=endpoint,
            hostname=_optional_str(data, "hostname"),
            label=_optional_str(data, "label"),
            hv=hv,
        )


@dataclass(frozen=True, slots=True)
class NetworkGroup:
    """NetworkGroup from ``GET .../networkgroups/{networkGroupId}``.

    Collections are exposed as tuples so the model is deeply immutable, as
    ``frozen=True`` advertises.
    """

    id: str
    owner_id: str
    label: str
    version: int
    description: str | None = None
    dns_sanitized_label: str | None = None
    network_ip: str | None = None
    last_allocated_ip: str | None = None
    members: tuple[NetworkGroupMember, ...] = ()
    peers: tuple[NetworkGroupPeer, ...] = ()
    tags: tuple[str, ...] = ()

    @classmethod
    def from_api_response(cls, data: Any) -> Self:
        data = _mapping(data, model="NetworkGroup")
        return cls(
            id=_require_str(data, "id", model="NetworkGroup"),
            owner_id=_require_str(data, "ownerId", model="NetworkGroup"),
            label=_require_str(data, "label", model="NetworkGroup"),
            version=_require_int(data, "version", model="NetworkGroup"),
            description=_optional_str(data, "description"),
            dns_sanitized_label=_optional_str(data, "dnsSanitizedLabel"),
            network_ip=_optional_str(data, "networkIp"),
            last_allocated_ip=_optional_str(data, "lastAllocatedIp"),
            members=tuple(
                NetworkGroupMember.from_api_response(m)
                for m in data.get("members") or ()
            ),
            peers=tuple(
                NetworkGroupPeer.from_api_response(p) for p in data.get("peers") or ()
            ),
            tags=tuple(str(tag) for tag in data.get("tags") or ()),
        )


@dataclass(frozen=True, slots=True)
class PeerCreated:
    """Response of ``POST .../peers`` and ``.../external-peers``."""

    peer_id: str
    raw: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def from_api_response(cls, data: Any) -> Self:
        data = _mapping(data, model="PeerCreated")
        peer_id = data.get("id") or data.get("peerId")
        if not isinstance(peer_id, str) or not peer_id:
            msg = "PeerCreated: missing or invalid required field 'id'"
            raise InvalidResponseError(msg)
        return cls(peer_id=peer_id, raw=MappingProxyType(dict(data)))


@dataclass(frozen=True, slots=True)
class Application:
    """Application from the Clever Cloud API."""

    id: str
    name: str
    zone: str | None = None
    description: str | None = None
    instance_type: str | None = None
    instance_version: str | None = None
    instance_variant: str | None = None
    min_instances: int | None = None
    max_instances: int | None = None
    min_flavor: str | None = None
    max_flavor: str | None = None
    deploy_url: str | None = None
    creation_date: datetime | None = None
    state: str | None = None

    @classmethod
    def from_api_response(cls, data: Any) -> Self:
        data = _mapping(data, model="Application")
        instance = data.get("instance")
        instance = instance if isinstance(instance, Mapping) else {}
        variant = instance.get("variant")
        variant = variant if isinstance(variant, Mapping) else {}

        return cls(
            id=_require_str(data, "id", model="Application"),
            name=_require_str(data, "name", model="Application"),
            zone=_optional_str(data, "zone"),
            description=_optional_str(data, "description"),
            instance_type=_optional_str(instance, "type")
            or _optional_str(data, "instanceType"),
            instance_version=_optional_str(instance, "version")
            or _optional_str(data, "instanceVersion"),
            instance_variant=_optional_str(variant, "id")
            or _optional_str(data, "instanceVariant"),
            min_instances=_optional_int(data, "minInstances"),
            max_instances=_optional_int(data, "maxInstances"),
            min_flavor=_optional_str(data, "minFlavor"),
            max_flavor=_optional_str(data, "maxFlavor"),
            deploy_url=_optional_str(data, "deployUrl"),
            creation_date=_parse_date(
                data.get("creationDate"), model="Application", key="creationDate"
            ),
            state=_optional_str(data, "state"),
        )
