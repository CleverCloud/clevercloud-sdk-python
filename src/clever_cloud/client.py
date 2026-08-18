"""Clever Cloud async API client."""

from __future__ import annotations

import asyncio
import email.utils
import random
import re
import ssl
from datetime import UTC, datetime
from typing import Any, Self
from urllib.parse import quote, urlsplit

import httpx

from clever_cloud.auth import Auth
from clever_cloud.exceptions import (
    AuthenticationError,
    AuthorizationError,
    HttpError,
    InvalidResponseError,
    NotFoundError,
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
    PeerRole,
    Profile,
    TcpRedirection,
)

#: Methods that can safely be retried after a transient failure.
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})

#: Status codes worth retrying for an idempotent request.
RETRYABLE_STATUS_CODES = frozenset({429, 502, 503, 504})

_VERSION_PART = re.compile(r"(\d+)|([^\d]+)")

# Sorts above any run, so a bare version outranks the same version with a suffix.
_VERSION_END: tuple[int, str] = (2, "")


def encode_path_segment(value: object, *, name: str) -> str:
    """Percent-encode one path segment so it cannot alter the request route.

    Identifiers received from callers are interpolated into URLs; without
    encoding, values such as ``../self``, ``x?override=1`` or ``x/y`` would
    change which endpoint is reached on the authenticated host.

    Raises:
        ValueError: If the value is empty or is a relative path element.
    """
    if not isinstance(value, str) or not value:
        msg = f"{name} must be a non-empty string, got {value!r}"
        raise ValueError(msg)
    if value in {".", ".."}:
        msg = f"{name} must not be a relative path element, got {value!r}"
        raise ValueError(msg)
    return quote(value, safe="")


def _version_sort_key(version: object) -> tuple[tuple[int, int | str], ...]:
    """Order versions naturally, so ``10`` sorts above ``9``.

    Splits a version into numeric and non-numeric runs; numeric runs compare as
    integers, so ``10`` sorts above ``9`` where a string comparison did not. A
    trailing end-marker sorts above any run, which keeps a pre-release suffix
    such as ``1.0-beta`` below the bare ``1.0``.
    """
    text = str(version)
    key: list[tuple[int, int | str]] = []
    for digits, rest in _VERSION_PART.findall(text):
        key.append((1, int(digits)) if digits else (0, rest))
    key.append(_VERSION_END)
    return tuple(key)


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Parse a ``Retry-After`` header, in delta-seconds or HTTP-date form."""
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    raw = raw.strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    parsed = email.utils.parsedate_to_datetime(raw)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0.0, (parsed - datetime.now(tz=UTC)).total_seconds())


class CleverCloudClient:
    """Async client for the Clever Cloud API.

    Example:
        credentials = OAuthCredentials(
            consumer_key="...", consumer_secret="...",
            token="...", secret="...",
        )

        async with CleverCloudClient(credentials) as client:
            profile = await client.get_profile()
            app = await client.create_application(...)
    """

    def __init__(
        self,
        auth: Auth,
        *,
        base_url: str | None = None,
        timeout: float = 30.0,
        ca_bundle: str | None = None,
        client_cert: str | tuple[str, str] | tuple[str, str, str] | None = None,
        verify_ssl: bool = True,
        allow_insecure_http: bool = False,
        max_retries: int = 2,
        max_retry_wait: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Create a client.

        Args:
            auth: Credentials used to sign every request.
            base_url: Override the API base URL. Must be HTTPS unless
                ``allow_insecure_http`` is set.
            timeout: Per-request timeout, in seconds.
            ca_bundle: Path to a CA bundle used to verify the server certificate.
            client_cert: Client certificate for mTLS: a path, ``(cert, key)`` or
                ``(cert, key, password)``.
            verify_ssl: Set to ``False`` to disable certificate verification
                entirely (local testing only).
            allow_insecure_http: Allow a clear-text ``http://`` base URL. Off by
                default, because credentials would travel unencrypted.
            max_retries: Extra attempts for idempotent requests hitting a
                transient failure (429/502/503/504 or a network error).
            max_retry_wait: Upper bound, in seconds, for a single backoff wait.
            transport: Custom transport, mainly useful for tests.
        """
        self._auth = auth
        self._base_url = base_url or auth.get_base_url()
        self._validate_base_url(allow_insecure_http=allow_insecure_http)
        self._timeout = timeout
        self._ca_bundle = ca_bundle
        self._client_cert = client_cert
        self._verify_ssl = verify_ssl
        self._max_retries = max(0, max_retries)
        self._max_retry_wait = max_retry_wait
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._instances_cache: list[dict[str, Any]] | None = None

    def _validate_base_url(self, *, allow_insecure_http: bool) -> None:
        scheme = urlsplit(self._base_url).scheme.lower()
        if scheme == "https":
            return
        if scheme == "http" and allow_insecure_http:
            return
        msg = (
            f"Refusing to use base URL {self._base_url!r}: credentials must be sent "
            "over HTTPS. Pass allow_insecure_http=True to override in development."
        )
        raise ValueError(msg)

    def _build_ssl_context(self) -> ssl.SSLContext | bool:
        """Build the TLS configuration as an :class:`ssl.SSLContext`.

        HTTPX deprecated passing file paths to ``verify=`` and the ``cert=``
        argument, so certificates are loaded into an explicit context instead.
        """
        if not self._verify_ssl:
            if self._client_cert is None:
                return False
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context = ssl.create_default_context(cafile=self._ca_bundle)

        cert = self._client_cert
        if cert is not None:
            if isinstance(cert, str):
                context.load_cert_chain(certfile=cert)
            elif len(cert) == 2:
                context.load_cert_chain(certfile=cert[0], keyfile=cert[1])
            else:
                context.load_cert_chain(
                    certfile=cert[0], keyfile=cert[1], password=cert[2]
                )
        return context

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                # Only Accept is set globally: the Content-Type must follow the
                # body actually sent, which HTTPX derives from json=/data=.
                headers={"Accept": "*/*"},
                verify=self._build_ssl_context(),
                transport=self._transport,
                follow_redirects=False,
            )
        return self._client

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _handle_response(self, response: httpx.Response) -> Any:
        status = response.status_code
        body = response.text

        if status == 401:
            raise AuthenticationError(
                "Authentication failed", status_code=status, response_body=body
            )
        if status == 403:
            raise AuthorizationError(
                "Access forbidden", status_code=status, response_body=body
            )
        if status == 404:
            raise NotFoundError(
                "Resource not found", status_code=status, response_body=body
            )
        if status == 429:
            raise RateLimitError(
                "Rate limited",
                status_code=status,
                response_body=body,
                retry_after=_retry_after_seconds(response),
            )
        if status >= 400:
            raise HttpError(
                f"HTTP {status}", status_code=status, response_body=body
            )
        if 300 <= status < 400:
            # Redirections are not followed: silently treating one as success
            # would return the body of a page the caller never asked for.
            location = response.headers.get("location", "")
            msg = f"Unexpected redirection (HTTP {status}) to {location!r}"
            raise InvalidResponseError(msg, response_body=body)

        # Any successful status may come without a body (204, but also 202 for
        # accepted NetworkGroup operations, or 200 on some endpoints).
        if not response.content:
            return None

        content_type = response.headers.get("content-type", "")
        if "json" in content_type:
            try:
                return response.json()
            except ValueError as exc:
                msg = f"Server returned an undecodable JSON body: {exc}"
                raise InvalidResponseError(msg, response_body=body) from exc
        return body

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        client = self._get_client()
        attempts = 1 + (self._max_retries if method.upper() in IDEMPOTENT_METHODS else 0)

        last_error: Exception | None = None
        for attempt in range(attempts):
            # Rebuilt and re-signed on every attempt: an OAuth signature carries
            # a nonce and a timestamp that must not be reused.
            request = client.build_request(
                method=method,
                url=path,
                json=json,
                data=data,
                params=params,
                headers=headers,
            )
            request = self._auth.apply_to_request(request)

            wait: float | None = None
            try:
                response = await client.send(request)
            except httpx.TransportError as exc:
                last_error = TransportError(f"{type(exc).__name__}: {exc}")
                last_error.__cause__ = exc
                wait = self._backoff(attempt, None)
            else:
                if (
                    response.status_code in RETRYABLE_STATUS_CODES
                    and attempt < attempts - 1
                ):
                    wait = self._backoff(attempt, _retry_after_seconds(response))
                else:
                    return self._handle_response(response)

            if attempt == attempts - 1:
                break
            await asyncio.sleep(wait or 0.0)

        if last_error is not None:
            raise last_error
        # Unreachable: the loop either returns, sleeps, or records an error.
        msg = "Request failed without a response"
        raise TransportError(msg)

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        """Exponential backoff with jitter, capped, honouring ``Retry-After``."""
        if retry_after is not None:
            return min(retry_after, self._max_retry_wait)
        base = min(2.0**attempt, self._max_retry_wait)
        return base * (0.5 + random.random() / 2)  # noqa: S311 - jitter, not crypto

    async def get_profile(self) -> Profile:
        """Get the authenticated user's profile."""
        data = await self._request("GET", "/v2/self")
        return Profile.from_api_response(data)

    async def list_instances(self, *, refresh: bool = False) -> list[dict[str, Any]]:
        """List available instance types (runtimes).

        The catalogue is cached for the lifetime of the client, since it changes
        rarely and every ``instance_slug`` resolution would otherwise re-download
        it. Pass ``refresh=True`` to force a new fetch.
        """
        if self._instances_cache is None or refresh:
            data = await self._request("GET", "/v2/products/instances")
            if not isinstance(data, list):
                msg = f"Expected a list of instances, got {type(data).__name__}"
                raise InvalidResponseError(msg)
            self._instances_cache = data
        return self._instances_cache

    async def resolve_instance_slug(self, slug: str) -> tuple[str, str, str]:
        """Resolve an instance slug to ``(type, version, variant_id)``.

        Args:
            slug: Instance slug like "static", "node", "python", etc.

        Returns:
            Tuple of (instance_type, version, variant_id)

        Raises:
            ValueError: If the slug cannot be resolved
        """
        instances = await self.list_instances()
        matching = [
            i
            for i in instances
            if isinstance(i, dict)
            and i.get("enabled")
            and (i.get("variant") or {}).get("slug") == slug
        ]
        if not matching:
            available = sorted(
                {
                    candidate
                    for i in instances
                    if isinstance(i, dict) and i.get("enabled")
                    for candidate in [(i.get("variant") or {}).get("slug")]
                    if isinstance(candidate, str)
                }
            )
            msg = f"Unknown instance slug: {slug}. Available: {available}"
            raise ValueError(msg)
        # Natural version ordering, so "10" is newer than "9".
        matching.sort(
            key=lambda x: _version_sort_key(x.get("version", "")), reverse=True
        )
        best = matching[0]
        try:
            return best["type"], best["version"], best["variant"]["id"]
        except (KeyError, TypeError) as exc:
            msg = f"Incomplete instance entry for slug {slug!r}: {exc}"
            raise InvalidResponseError(msg) from exc

    async def create_application(
        self,
        owner_id: str,
        name: str,
        *,
        instance_slug: str | None = None,
        instance_type: str | None = None,
        instance_version: str | None = None,
        instance_variant: str | None = None,
        deploy: str = "git",
        branch: str = "master",
        min_flavor: str = "XS",
        max_flavor: str = "XS",
        min_instances: int = 1,
        max_instances: int = 1,
        build_flavor: str | None = None,
        description: str | None = None,
        zone: str = "par",
        environment: list[dict[str, str]] | None = None,
        public_git_repository_url: str | None = None,
    ) -> Application:
        """Create a new application.

        Args:
            owner_id: Organisation or user ID that will own the application
            name: Application name
            instance_slug: Instance slug (e.g. "static", "node", "python").
                Automatically resolves to type/version/variant.
            instance_type: Instance type (if not using slug)
            instance_version: Instance version (if not using slug)
            instance_variant: Instance variant ID (if not using slug)
            deploy: "git" or "ftp"
            branch: Git branch to deploy
            min_flavor/max_flavor: Instance sizes (XS, S, M, L, XL...)
            min_instances/max_instances: Scaling limits
            build_flavor: Build instance size (enables separate build)
            description: Application description
            zone: Deployment zone (par, rbx, etc.)
            environment: Env vars as [{"name": "KEY", "value": "val"}]
            public_git_repository_url: Public git repo URL to deploy

        Either instance_slug OR (instance_type, instance_version, instance_variant)
        must be provided.
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        if instance_slug:
            (
                instance_type,
                instance_version,
                instance_variant,
            ) = await self.resolve_instance_slug(instance_slug)
        elif not (instance_type and instance_version and instance_variant):
            msg = (
                "Either instance_slug or "
                "(instance_type, instance_version, instance_variant) is required"
            )
            raise ValueError(msg)

        body: dict[str, Any] = {
            "name": name,
            "deploy": deploy,
            "branch": branch,
            "minFlavor": min_flavor,
            "maxFlavor": max_flavor,
            "minInstances": min_instances,
            "maxInstances": max_instances,
            "instanceType": instance_type,
            "instanceVersion": instance_version,
            "instanceVariant": instance_variant,
            "instance": {
                "type": instance_type,
                "version": instance_version,
                "variant": instance_variant,
            },
            "zone": zone,
        }
        if build_flavor:
            body["buildFlavor"] = build_flavor
            body["separateBuild"] = True
        if description:
            body["description"] = description
        if environment:
            # Convert [{name: "X", value: "Y"}] to {"X": "Y"}
            body["env"] = {var["name"]: var["value"] for var in environment}
        if public_git_repository_url:
            body["publicGitRepositoryUrl"] = public_git_repository_url

        data = await self._request(
            "POST", f"/v2/organisations/{owner}/applications", json=body
        )
        return Application.from_api_response(data)

    async def redeploy_application(
        self,
        owner_id: str,
        app_id: str,
        *,
        commit: str | None = None,
        use_cache: bool | None = None,
    ) -> None:
        """Trigger a redeployment of an application.

        Args:
            owner_id: Organisation or user ID that owns the application
            app_id: Application ID to redeploy
            commit: Specific commit to deploy (optional)
            use_cache: Whether to use build cache (optional)
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        app = encode_path_segment(app_id, name="app_id")
        params: dict[str, Any] = {}
        if commit is not None:
            params["commit"] = commit
        if use_cache is not None:
            params["useCache"] = "true" if use_cache else "false"

        await self._request(
            "POST",
            f"/v2/organisations/{owner}/applications/{app}/instances",
            params=params or None,
        )

    async def create_tcp_redirection(
        self,
        owner_id: str,
        app_id: str,
        *,
        namespace: str = "cleverapps",
    ) -> TcpRedirection:
        """Create a TCP redirection for an application.

        Args:
            owner_id: Organisation or user ID that owns the application
            app_id: Application ID to create redirection for
            namespace: TCP redirection namespace (default: "cleverapps")

        Returns:
            TcpRedirection with namespace and assigned port
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        app = encode_path_segment(app_id, name="app_id")
        data = await self._request(
            "POST",
            f"/v2/organisations/{owner}/applications/{app}/tcpRedirs",
            json={"namespace": namespace},
        )
        return TcpRedirection.from_api_response(data)

    async def list_domains(self, owner_id: str, app_id: str) -> list[Domain]:
        """List all domains (vhosts) for an application.

        Args:
            owner_id: Organisation or user ID that owns the application
            app_id: Application ID

        Returns:
            List of domains for the application

        Raises:
            NotFoundError: If the organisation or the application does not exist.
                An existing application with no domain returns an empty list.
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        app = encode_path_segment(app_id, name="app_id")
        data = await self._request(
            "GET", f"/v2/organisations/{owner}/applications/{app}/vhosts"
        )
        if not isinstance(data, list):
            msg = f"Expected a list of domains, got {type(data).__name__}"
            raise InvalidResponseError(msg)
        return [Domain.from_api_response(d) for d in data]

    async def get_primary_domain(self, owner_id: str, app_id: str) -> Domain | None:
        """Get the primary domain (vhost) for an application.

        Args:
            owner_id: Organisation or user ID that owns the application
            app_id: Application ID

        Returns:
            Domain with the primary vhost, or ``None`` if the API answered
            successfully with no content.

        Raises:
            NotFoundError: If the application has no primary domain, or does not
                exist. The API reports both with HTTP 404, so the caller decides
                how to treat it.
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        app = encode_path_segment(app_id, name="app_id")
        data = await self._request(
            "GET", f"/v2/organisations/{owner}/applications/{app}/vhosts/favourite"
        )
        if data is None:
            return None
        # Some deployments answer with a single-element list.
        if isinstance(data, list):
            if not data:
                return None
            data = data[0]
        return Domain.from_api_response(data, is_primary=True)

    async def create_networkgroup(
        self,
        owner_id: str,
        *,
        label: str,
        description: str | None = None,
        ng_id: str | None = None,
        tags: list[str] | None = None,
        members: list[dict[str, Any]] | None = None,
    ) -> None:
        """Create a NetworkGroup.

        POST /v4/networkgroups/organisations/{ownerId}/networkgroups
        Returns 202 with no body.

        Args:
            owner_id: Organisation ID (orga_*).
            label: NG label.
            description: Optional description.
            ng_id: Pre-defined NG id (server generates one if omitted).
            tags: Optional tags.
            members: Optional initial members (list of WannabeNetworkgroupMember
                dicts: {id, domainName, kind, label?}).
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        body: dict[str, Any] = {"label": label}
        if description is not None:
            body["description"] = description
        if ng_id is not None:
            body["id"] = ng_id
        if tags is not None:
            body["tags"] = tags
        if members is not None:
            body["members"] = members
        await self._request(
            "POST",
            f"/v4/networkgroups/organisations/{owner}/networkgroups",
            json=body,
        )

    async def get_networkgroup(self, owner_id: str, ng_id: str) -> NetworkGroup:
        """Get a NetworkGroup.

        GET /v4/networkgroups/organisations/{ownerId}/networkgroups/{networkGroupId}
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        data = await self._request(
            "GET", f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}"
        )
        return NetworkGroup.from_api_response(data)

    async def delete_networkgroup(self, owner_id: str, ng_id: str) -> None:
        """Delete a NetworkGroup.

        DELETE /v4/networkgroups/organisations/{ownerId}/networkgroups/{networkGroupId}
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        await self._request(
            "DELETE", f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}"
        )

    async def search_networkgroup_components(
        self,
        owner_id: str,
        *,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search NetworkGroup components (NGs, members, peers).

        GET /v4/networkgroups/organisations/{ownerId}/networkgroups/search

        Returns the raw component list — the response is a oneOf union
        (CleverPeer | ExternalPeer | Member | NetworkGroup) that callers
        typically discriminate by inspecting fields.
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        params = {"query": query} if query is not None else None
        data = await self._request(
            "GET",
            f"/v4/networkgroups/organisations/{owner}/networkgroups/search",
            params=params,
        )
        if data is None:
            return []
        if not isinstance(data, list):
            msg = f"Expected a list of components, got {type(data).__name__}"
            raise InvalidResponseError(msg)
        return data

    async def create_networkgroup_member(
        self,
        owner_id: str,
        ng_id: str,
        *,
        member_id: str,
        domain_name: str,
        kind: MemberKind | str,
        label: str | None = None,
    ) -> None:
        """Add a member to a NetworkGroup.

        POST /v4/networkgroups/organisations/{ownerId}/networkgroups/{networkGroupId}/members
        Returns 202 with no body.

        Args:
            owner_id: Organisation ID (orga_*).
            ng_id: NetworkGroup ID (ng_*).
            member_id: ID of the entity to add (app_*, addon_*, ...).
            domain_name: Internal domain name to assign to the member.
            kind: ADDON | APPLICATION | EXTERNAL | LOADBALANCER.
            label: Optional human-readable label.
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        body: dict[str, Any] = {
            "id": member_id,
            "domainName": domain_name,
            "kind": kind.value if isinstance(kind, MemberKind) else kind,
        }
        if label is not None:
            body["label"] = label
        await self._request(
            "POST",
            f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}/members",
            json=body,
        )

    async def get_networkgroup_member(
        self, owner_id: str, ng_id: str, member_id: str
    ) -> NetworkGroupMember:
        """Get a member of a NetworkGroup.

        GET .../networkgroups/{networkGroupId}/members/{memberId}
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        member = encode_path_segment(member_id, name="member_id")
        data = await self._request(
            "GET",
            f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}/members/{member}",
        )
        return NetworkGroupMember.from_api_response(data)

    async def delete_networkgroup_member(
        self, owner_id: str, ng_id: str, member_id: str
    ) -> None:
        """Remove a member from a NetworkGroup.

        DELETE .../networkgroups/{networkGroupId}/members/{memberId}
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        member = encode_path_segment(member_id, name="member_id")
        await self._request(
            "DELETE",
            f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}/members/{member}",
        )

    async def list_networkgroup_peers(
        self, owner_id: str, ng_id: str
    ) -> list[NetworkGroupPeer]:
        """List peers of a NetworkGroup.

        GET .../networkgroups/{networkGroupId}/peers
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        data = await self._request(
            "GET", f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}/peers"
        )
        if data is None:
            return []
        if not isinstance(data, list):
            msg = f"Expected a list of peers, got {type(data).__name__}"
            raise InvalidResponseError(msg)
        return [NetworkGroupPeer.from_api_response(p) for p in data]

    async def get_networkgroup_peer(
        self, owner_id: str, ng_id: str, peer_id: str
    ) -> NetworkGroupPeer:
        """Get a peer of a NetworkGroup.

        GET .../networkgroups/{networkGroupId}/peers/{peerId}
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        peer = encode_path_segment(peer_id, name="peer_id")
        data = await self._request(
            "GET",
            f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}/peers/{peer}",
        )
        return NetworkGroupPeer.from_api_response(data)

    async def create_networkgroup_peer(
        self,
        owner_id: str,
        ng_id: str,
        *,
        peer_id: str,
        parent_member: str,
        peer_role: PeerRole | str,
        peer_kind: str = "CLEVER",
        public_key: str | None = None,
        ip: str | None = None,
        port: int | None = None,
        hostname: str | None = None,
        label: str | None = None,
        hv: str | None = None,
        parent_event: str | None = None,
    ) -> PeerCreated:
        """Add a peer to a member of a NetworkGroup.

        POST .../networkgroups/{networkGroupId}/peers
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        body: dict[str, Any] = {
            "id": peer_id,
            "parentMember": parent_member,
            "peerRole": peer_role.value if isinstance(peer_role, PeerRole) else peer_role,
            "peerKind": peer_kind,
        }
        for key, value in (
            ("publicKey", public_key),
            ("ip", ip),
            ("port", port),
            ("hostname", hostname),
            ("label", label),
            ("hv", hv),
            ("parentEvent", parent_event),
        ):
            if value is not None:
                body[key] = value
        data = await self._request(
            "POST",
            f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}/peers",
            json=body,
        )
        return PeerCreated.from_api_response(data)

    async def delete_networkgroup_peer(
        self, owner_id: str, ng_id: str, peer_id: str
    ) -> None:
        """Delete a peer of a NetworkGroup.

        DELETE .../networkgroups/{networkGroupId}/peers/{peerId}
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        peer = encode_path_segment(peer_id, name="peer_id")
        await self._request(
            "DELETE",
            f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}/peers/{peer}",
        )

    async def create_networkgroup_external_peer(
        self,
        owner_id: str,
        ng_id: str,
        *,
        parent_member: str,
        peer_role: PeerRole | str,
        public_key: str,
        label: str,
        ip: str | None = None,
        port: int | None = None,
        hostname: str | None = None,
        parent_event: str | None = None,
    ) -> PeerCreated:
        """Add an external peer to a member of a NetworkGroup.

        POST .../networkgroups/{networkGroupId}/external-peers
        """
        owner = encode_path_segment(owner_id, name="owner_id")
        ng = encode_path_segment(ng_id, name="ng_id")
        body: dict[str, Any] = {
            "parentMember": parent_member,
            "peerRole": peer_role.value if isinstance(peer_role, PeerRole) else peer_role,
            "publicKey": public_key,
            "label": label,
        }
        for key, value in (
            ("ip", ip),
            ("port", port),
            ("hostname", hostname),
            ("parentEvent", parent_event),
        ):
            if value is not None:
                body[key] = value
        data = await self._request(
            "POST",
            f"/v4/networkgroups/organisations/{owner}/networkgroups/{ng}/external-peers",
            json=body,
        )
        return PeerCreated.from_api_response(data)
