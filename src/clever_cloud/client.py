"""Clever Cloud async API client."""

from typing import Any, Self

import httpx

from clever_cloud.auth import Auth
from clever_cloud.exceptions import AuthenticationError, HttpError
from clever_cloud.models import Application, Domain, Profile, TcpRedirection


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
    ) -> None:
        self._auth = auth
        self._base_url = base_url or auth.get_base_url()
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=self._timeout,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
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
        return response.json()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        client = self._get_client()
        request = client.build_request(
            method=method, url=path, json=json, data=data, params=params
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
