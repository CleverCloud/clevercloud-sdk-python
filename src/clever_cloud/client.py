"""Clever Cloud async API client."""

from typing import Any, Self

import httpx

from clever_cloud.auth import Auth
from clever_cloud.exceptions import AuthenticationError, HttpError
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
    ) -> None:
        self._auth = auth
        self._base_url = base_url or auth.get_base_url()
        self._timeout = timeout
        self._ca_bundle = ca_bundle
        self._client_cert = client_cert
        self._verify_ssl = verify_ssl
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            # Prepare SSL verification
            # - ca_bundle: path to custom CA bundle file to verify server certificate
            # - verify_ssl: True (default CA), False (disable verification)
            verify: bool | str
            if self._ca_bundle:
                verify = self._ca_bundle
            else:
                verify = self._verify_ssl

            # Prepare client certificate for mTLS
            # - client_cert: path to cert file, or (cert, key), or (cert, key, password)
            cert = self._client_cert

            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                headers={
                    "Accept": "*/*",
                    "Content-Type": "application/json",
                },
                verify=verify,
                cert=cert,
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
        if response.status_code == 401:
            raise AuthenticationError(
                "Authentication failed", status_code=401, response_body=response.text
            )
        if response.status_code == 403:
            raise AuthenticationError(
                "Access forbidden", status_code=403, response_body=response.text
            )
        if response.status_code >= 400:
            raise HttpError(
                f"HTTP {response.status_code}: {response.text}",
                status_code=response.status_code,
                response_body=response.text,
            )
        if response.status_code == 204:
            return {}
        content_type = response.headers.get("content-type", "")
        if "json" in content_type:
            return response.json()
        return response.text

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        client = self._get_client()
        request = client.build_request(
            method=method,
            url=path,
            json=json,
            data=data,
            params=params,
            headers=headers,
        )
        request = self._auth.apply_to_request(request)
        response = await client.send(request)
        return self._handle_response(response)

    async def get_profile(self) -> Profile:
        """Get the authenticated user's profile."""
        data = await self._request("GET", "/v2/self")
        return Profile.from_api_response(data)

    async def list_instances(self) -> list[dict[str, Any]]:
        """List available instance types (runtimes)."""
        return await self._request("GET", "/v2/products/instances")

    async def resolve_instance_slug(self, slug: str) -> tuple[str, str, str]:
        """Resolve an instance slug to (type, version, variant_id).

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
            if i.get("enabled") and i.get("variant", {}).get("slug") == slug
        ]
        if not matching:
            available = sorted(
                {
                    i.get("variant", {}).get("slug")
                    for i in instances
                    if i.get("enabled")
                }
            )
            msg = f"Unknown instance slug: {slug}. Available: {available}"
            raise ValueError(msg)
        # Sort by version descending to get latest
        matching.sort(key=lambda x: x.get("version", ""), reverse=True)
        best = matching[0]
        return best["type"], best["version"], best["variant"]["id"]

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
        if instance_slug:
            (
                instance_type,
                instance_version,
                instance_variant,
            ) = await self.resolve_instance_slug(instance_slug)
        elif not (instance_type and instance_version and instance_variant):
            msg = "Either instance_slug or (instance_type, instance_version, instance_variant) required"
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
            "POST", f"/v2/organisations/{owner_id}/applications", json=body
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
        params: dict[str, Any] = {}
        if commit is not None:
            params["commit"] = commit
        if use_cache is not None:
            params["useCache"] = "true" if use_cache else "false"

        await self._request(
            "POST",
            f"/v2/organisations/{owner_id}/applications/{app_id}/instances",
            params=params if params else None,
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
        data = await self._request(
            "POST",
            f"/v2/organisations/{owner_id}/applications/{app_id}/tcpRedirs",
            json={"namespace": namespace},
        )
        return TcpRedirection.from_api_response(data)

    async def list_domains(
        self,
        owner_id: str,
        app_id: str,
    ) -> list[Domain]:
        """List all domains (vhosts) for an application.

        Args:
            owner_id: Organisation or user ID that owns the application
            app_id: Application ID

        Returns:
            List of domains for the application
        """
        try:
            data = await self._request(
                "GET",
                f"/v2/organisations/{owner_id}/applications/{app_id}/vhosts",
            )
            return [Domain.from_api_response(d) for d in data]
        except HttpError as e:
            if e.status_code == 404:
                return []
            raise

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
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups",
            json=body,
        )

    async def get_networkgroup(
        self,
        owner_id: str,
        ng_id: str,
    ) -> NetworkGroup:
        """Get a NetworkGroup.

        GET /v4/networkgroups/organisations/{ownerId}/networkgroups/{networkGroupId}
        """
        data = await self._request(
            "GET",
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}",
        )
        return NetworkGroup.from_api_response(data)

    async def delete_networkgroup(
        self,
        owner_id: str,
        ng_id: str,
    ) -> None:
        """Delete a NetworkGroup.

        DELETE /v4/networkgroups/organisations/{ownerId}/networkgroups/{networkGroupId}
        """
        await self._request(
            "DELETE",
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}",
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
        params = {"query": query} if query is not None else None
        return await self._request(
            "GET",
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/search",
            params=params,
        )

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
        body: dict[str, Any] = {
            "id": member_id,
            "domainName": domain_name,
            "kind": kind.value if isinstance(kind, MemberKind) else kind,
        }
        if label is not None:
            body["label"] = label
        await self._request(
            "POST",
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}/members",
            json=body,
        )

    async def get_networkgroup_member(
        self,
        owner_id: str,
        ng_id: str,
        member_id: str,
    ) -> NetworkGroupMember:
        """Get a member of a NetworkGroup.

        GET .../networkgroups/{networkGroupId}/members/{memberId}
        """
        data = await self._request(
            "GET",
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}/members/{member_id}",
        )
        return NetworkGroupMember.from_api_response(data)

    async def delete_networkgroup_member(
        self,
        owner_id: str,
        ng_id: str,
        member_id: str,
    ) -> None:
        """Remove a member from a NetworkGroup.

        DELETE .../networkgroups/{networkGroupId}/members/{memberId}
        """
        await self._request(
            "DELETE",
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}/members/{member_id}",
        )

    async def list_networkgroup_peers(
        self,
        owner_id: str,
        ng_id: str,
    ) -> list[NetworkGroupPeer]:
        """List peers of a NetworkGroup.

        GET .../networkgroups/{networkGroupId}/peers
        """
        data = await self._request(
            "GET",
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}/peers",
        )
        return [NetworkGroupPeer.from_api_response(p) for p in data or []]

    async def get_networkgroup_peer(
        self,
        owner_id: str,
        ng_id: str,
        peer_id: str,
    ) -> NetworkGroupPeer:
        """Get a peer of a NetworkGroup.

        GET .../networkgroups/{networkGroupId}/peers/{peerId}
        """
        data = await self._request(
            "GET",
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}/peers/{peer_id}",
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
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}/peers",
            json=body,
        )
        return PeerCreated.from_api_response(data or {})

    async def delete_networkgroup_peer(
        self,
        owner_id: str,
        ng_id: str,
        peer_id: str,
    ) -> None:
        """Delete a peer of a NetworkGroup.

        DELETE .../networkgroups/{networkGroupId}/peers/{peerId}
        """
        await self._request(
            "DELETE",
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}/peers/{peer_id}",
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
            f"/v4/networkgroups/organisations/{owner_id}/networkgroups/{ng_id}/external-peers",
            json=body,
        )
        return PeerCreated.from_api_response(data or {})

    async def get_primary_domain(
        self,
        owner_id: str,
        app_id: str,
    ) -> Domain | None:
        """Get the primary domain (vhost) for an application.

        Args:
            owner_id: Organisation or user ID that owns the application
            app_id: Application ID

        Returns:
            Domain with the primary vhost, or None if not set
        """
        try:
            data = await self._request(
                "GET",
                f"/v2/organisations/{owner_id}/applications/{app_id}/vhosts/favourite",
            )
            return Domain.from_api_response(data, is_primary=True)
        except HttpError as e:
            if e.status_code == 404:
                return None
            raise
