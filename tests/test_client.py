"""Tests for the HTTP client (issue #3, findings 3, 4, 6, 7, 9)."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from clever_cloud import (
    ApiTokenCredentials,
    AuthenticationError,
    AuthorizationError,
    CleverCloudClient,
    HttpError,
    InvalidResponseError,
    NotFoundError,
    OAuthCredentials,
    RateLimitError,
    TransportError,
)
from clever_cloud.client import _version_sort_key, encode_path_segment
from conftest import BASE_URL

PROFILE = {"id": "user_1", "email": "user@example.test"}


class TestPathSegmentEncoding:
    """Finding 3: identifiers were interpolated raw into URLs."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("orga_1234", "orga_1234"),
            ("../self", "..%2Fself"),
            ("x?override=1", "x%3Foverride%3D1"),
            ("x/y", "x%2Fy"),
            ("x#frag", "x%23frag"),
            ("a b", "a%20b"),
            ("100%", "100%25"),
        ],
    )
    def test_encoding(self, raw: str, expected: str) -> None:
        assert encode_path_segment(raw, name="owner_id") == expected

    @pytest.mark.parametrize("bad", ["", ".", ".."])
    def test_rejected_values(self, bad: str) -> None:
        with pytest.raises(ValueError, match="owner_id"):
            encode_path_segment(bad, name="owner_id")

    def test_non_string_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"):
            encode_path_segment(None, name="owner_id")

    async def test_traversal_cannot_change_the_route(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(200, []))
        async with client:
            await client.list_domains("../self", "app_1")
        # raw_path is what actually goes on the wire; .path is the decoded view.
        assert seen[0].url.raw_path == (
            b"/v2/organisations/..%2Fself/applications/app_1/vhosts"
        )

    async def test_query_injection_cannot_add_parameters(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(200, []))
        async with client:
            await client.list_domains("x?override=1", "app_1")
        assert seen[0].url.params.get("override") is None
        assert "override" not in str(seen[0].url.query)

    async def test_extra_path_segment_cannot_be_injected(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(200, []))
        async with client:
            await client.list_domains("orga_1", "x/y")
        assert seen[0].url.raw_path == (
            b"/v2/organisations/orga_1/applications/x%2Fy/vhosts"
        )


class TestResponseHandling:
    """Finding 4: empty bodies, redirections and undecodable JSON."""

    @pytest.mark.parametrize("status", [200, 201, 202, 204, 205])
    async def test_empty_body_on_any_success_status(
        self, make_client: Callable[..., CleverCloudClient], status: int
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status, content=b"", headers={"content-type": "application/json"}
            )

        client = make_client(handler)
        async with client:
            # create_networkgroup is documented to answer 202 with no body.
            await client.create_networkgroup("orga_1", label="ng")

    async def test_json_content_type_with_empty_body_does_not_raise(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"", headers={"content-type": "application/json"})

        client = make_client(handler)
        async with client:
            assert await client.search_networkgroup_components("orga_1") == []

    async def test_undecodable_json_is_wrapped_in_a_domain_exception(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=b"{not json", headers={"content-type": "application/json"}
            )

        client = make_client(handler)
        async with client:
            with pytest.raises(InvalidResponseError, match="undecodable JSON"):
                await client.get_profile()

    async def test_plain_text_body_is_returned_as_text(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="hello", headers={"content-type": "text/plain"})

        client = make_client(handler)
        async with client:
            with pytest.raises(InvalidResponseError, match="expected a JSON object"):
                await client.get_profile()

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    async def test_unfollowed_redirection_is_not_a_success(
        self, make_client: Callable[..., CleverCloudClient], status: int
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, headers={"location": "https://evil.test/"}, text="body")

        client = make_client(handler)
        async with client:
            with pytest.raises(InvalidResponseError, match="Unexpected redirection"):
                await client.get_profile()

    async def test_successful_profile(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(200, json=PROFILE))
        async with client:
            profile = await client.get_profile()
        assert profile.id == "user_1"


class TestErrorClassification:
    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (401, AuthenticationError),
            (403, AuthorizationError),
            (404, NotFoundError),
            (429, RateLimitError),
            (400, HttpError),
            (500, HttpError),
        ],
    )
    async def test_status_maps_to_exception(
        self,
        make_client: Callable[..., CleverCloudClient],
        status: int,
        expected: type[Exception],
    ) -> None:
        client = make_client(lambda r: httpx.Response(status, text="boom"))
        async with client:
            with pytest.raises(expected) as excinfo:
                await client.get_profile()
        assert excinfo.value.status_code == status  # type: ignore[attr-defined]

    async def test_403_is_authorization_not_authentication(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        """403 used to be reported as an authentication failure."""
        client = make_client(lambda r: httpx.Response(403, text="nope"))
        async with client:
            with pytest.raises(AuthorizationError):
                await client.get_profile()
            assert not issubclass(AuthorizationError, AuthenticationError)

    async def test_large_error_body_is_truncated(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        big = "x" * 100_000
        client = make_client(lambda r: httpx.Response(500, text=big))
        async with client:
            with pytest.raises(HttpError) as excinfo:
                await client.get_profile()
        assert len(excinfo.value.response_body) < 3000
        assert "truncated" in excinfo.value.response_body

    async def test_error_message_does_not_embed_the_whole_body(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(500, text="secret-token-in-body"))
        async with client:
            with pytest.raises(HttpError) as excinfo:
                await client.get_profile()
        assert "secret-token-in-body" not in str(excinfo.value)

    async def test_rate_limit_exposes_retry_after(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(
            lambda r: httpx.Response(429, headers={"retry-after": "12"}, text="slow down")
        )
        async with client:
            with pytest.raises(RateLimitError) as excinfo:
                await client.get_profile()
        assert excinfo.value.retry_after == 12.0

    async def test_transport_error_is_wrapped_in_the_sdk_hierarchy(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        """A network failure used to escape CleverCloudError entirely."""
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        client = make_client(handler)
        async with client:
            with pytest.raises(TransportError, match="ConnectError"):
                await client.get_profile()


class TestRequestShape:
    """Finding 7: a JSON Content-Type was forced onto every request."""

    async def test_get_has_no_content_type(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(200, PROFILE))
        async with client:
            await client.get_profile()
        assert "content-type" not in seen[0].headers

    async def test_json_body_gets_a_json_content_type(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(202))
        async with client:
            await client.create_networkgroup("orga_1", label="ng")
        assert seen[0].headers["content-type"] == "application/json"

    async def test_form_body_gets_a_form_content_type(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        """data={"x": "y"} used to be sent form-encoded under a JSON Content-Type."""
        seen, factory = record_requests
        client = make_client(factory(200, PROFILE))
        async with client:
            await client._request("POST", "/v2/x", data={"x": "y"})
        assert seen[0].headers["content-type"] == "application/x-www-form-urlencoded"
        assert seen[0].content == b"x=y"

    async def test_authorization_header_is_applied(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
        oauth_auth: OAuthCredentials,
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(200, PROFILE), auth=oauth_auth)
        async with client:
            await client.get_profile()
        assert seen[0].headers["authorization"].startswith("OAuth ")


class TestRetries:
    @pytest.mark.parametrize("status", [429, 502, 503, 504])
    async def test_idempotent_request_is_retried(
        self, token_auth: ApiTokenCredentials, status: int
    ) -> None:
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            if len(calls) < 3:
                return httpx.Response(status, headers={"retry-after": "0"})
            return httpx.Response(200, json=PROFILE)

        client = CleverCloudClient(
            token_auth,
            base_url=BASE_URL,
            max_retries=2,
            transport=httpx.MockTransport(handler),
        )
        async with client:
            profile = await client.get_profile()
        assert profile.id == "user_1"
        assert len(calls) == 3

    async def test_non_idempotent_request_is_not_retried(
        self, token_auth: ApiTokenCredentials
    ) -> None:
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            return httpx.Response(503, headers={"retry-after": "0"})

        client = CleverCloudClient(
            token_auth,
            base_url=BASE_URL,
            max_retries=3,
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(HttpError):
                await client.create_networkgroup("orga_1", label="ng")
        assert len(calls) == 1

    async def test_retries_are_bounded(self, token_auth: ApiTokenCredentials) -> None:
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            return httpx.Response(503, headers={"retry-after": "0"})

        client = CleverCloudClient(
            token_auth,
            base_url=BASE_URL,
            max_retries=2,
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(HttpError):
                await client.get_profile()
        assert len(calls) == 3

    async def test_transport_error_is_retried_then_raised(
        self, token_auth: ApiTokenCredentials
    ) -> None:
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            raise httpx.ConnectTimeout("timeout")

        client = CleverCloudClient(
            token_auth,
            base_url=BASE_URL,
            max_retries=1,
            max_retry_wait=0,
            transport=httpx.MockTransport(handler),
        )
        async with client:
            with pytest.raises(TransportError):
                await client.get_profile()
        assert len(calls) == 2

    async def test_each_retry_is_signed_again(self, oauth_auth: OAuthCredentials) -> None:
        """An OAuth nonce must never be reused across attempts."""
        headers: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            headers.append(request.headers["authorization"])
            if len(headers) < 2:
                return httpx.Response(503, headers={"retry-after": "0"})
            return httpx.Response(200, json=PROFILE)

        client = CleverCloudClient(
            oauth_auth,
            base_url=BASE_URL,
            max_retries=1,
            transport=httpx.MockTransport(handler),
        )
        async with client:
            await client.get_profile()
        assert headers[0] != headers[1]


class TestVersionOrdering:
    """Finding 6: versions were compared as strings, so "9" beat "10"."""

    @pytest.mark.parametrize(
        ("lower", "higher"),
        [("9", "10"), ("1.9", "1.10"), ("8", "11"), ("3.9", "3.12"), ("1.0-beta", "1.0")],
    )
    def test_natural_ordering(self, lower: str, higher: str) -> None:
        assert _version_sort_key(lower) < _version_sort_key(higher)

    async def test_resolve_instance_slug_picks_the_highest_version(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        instances = [
            {"enabled": True, "type": "node", "version": "9",
             "variant": {"slug": "node", "id": "var_9"}},
            {"enabled": True, "type": "node", "version": "10",
             "variant": {"slug": "node", "id": "var_10"}},
        ]
        client = make_client(lambda r: httpx.Response(200, json=instances))
        async with client:
            resolved = await client.resolve_instance_slug("node")
        assert resolved == ("node", "10", "var_10")

    async def test_disabled_instances_are_ignored(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        instances = [
            {"enabled": False, "type": "node", "version": "20",
             "variant": {"slug": "node", "id": "var_20"}},
            {"enabled": True, "type": "node", "version": "18",
             "variant": {"slug": "node", "id": "var_18"}},
        ]
        client = make_client(lambda r: httpx.Response(200, json=instances))
        async with client:
            assert (await client.resolve_instance_slug("node"))[1] == "18"

    async def test_unknown_slug_lists_the_available_ones(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        instances = [
            {"enabled": True, "type": "node", "version": "20",
             "variant": {"slug": "node", "id": "v"}}
        ]
        client = make_client(lambda r: httpx.Response(200, json=instances))
        async with client:
            with pytest.raises(ValueError, match="Unknown instance slug: ruby"):
                await client.resolve_instance_slug("ruby")


class TestInstanceCatalogueCaching:
    async def test_catalogue_is_fetched_once_per_client(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        calls: list[int] = []
        instances = [
            {"enabled": True, "type": "node", "version": "20",
             "variant": {"slug": "node", "id": "var_20"}}
        ]

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v2/products/instances":
                calls.append(1)
                return httpx.Response(200, json=instances)
            return httpx.Response(200, json={"id": "app_1", "name": "n"})

        client = make_client(handler)
        async with client:
            await client.create_application("orga_1", "a", instance_slug="node")
            await client.create_application("orga_1", "b", instance_slug="node")
        assert len(calls) == 1

    async def test_refresh_forces_a_new_fetch(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            return httpx.Response(200, json=[])

        client = make_client(handler)
        async with client:
            await client.list_instances()
            await client.list_instances()
            await client.list_instances(refresh=True)
        assert len(calls) == 2


class TestTlsConfiguration:
    """Finding 9: deprecated HTTPX TLS APIs and clear-text base URLs."""

    def test_http_base_url_is_refused_by_default(
        self, token_auth: ApiTokenCredentials
    ) -> None:
        with pytest.raises(ValueError, match="must be sent over HTTPS"):
            CleverCloudClient(token_auth, base_url="http://api.example.test")

    def test_http_base_url_requires_an_explicit_override(
        self, token_auth: ApiTokenCredentials
    ) -> None:
        client = CleverCloudClient(
            token_auth, base_url="http://localhost:8080", allow_insecure_http=True
        )
        assert client._base_url == "http://localhost:8080"

    def test_credentials_default_base_url_is_https(
        self, token_auth: ApiTokenCredentials
    ) -> None:
        CleverCloudClient(ApiTokenCredentials(token="t"))

    def test_ca_bundle_builds_an_ssl_context_without_deprecation(
        self, token_auth: ApiTokenCredentials, tmp_path: object
    ) -> None:
        import ssl

        client = CleverCloudClient(token_auth, base_url=BASE_URL)
        context = client._build_ssl_context()
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode is ssl.CERT_REQUIRED

    def test_verify_ssl_false_disables_verification(
        self, token_auth: ApiTokenCredentials
    ) -> None:
        client = CleverCloudClient(token_auth, base_url=BASE_URL, verify_ssl=False)
        assert client._build_ssl_context() is False

    def test_no_deprecation_warning_when_creating_the_transport(
        self, token_auth: ApiTokenCredentials, recwarn: pytest.WarningsRecorder
    ) -> None:
        client = CleverCloudClient(token_auth, base_url=BASE_URL)
        client._get_client()
        assert [w for w in recwarn if issubclass(w.category, DeprecationWarning)] == []


class TestEndpoints:
    async def test_create_domain(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(200, {"fqdn": "app.example.test"}))
        async with client:
            domain = await client.create_domain(
                "orga_1", "app_1", domain="app.example.test"
            )
        assert domain.domain == "app.example.test"
        assert domain.is_primary is False
        assert seen[0].method == "PUT"
        assert seen[0].url.path.endswith("/vhosts/app.example.test")

    async def test_create_domain_accepts_an_empty_body(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        """Some deployments answer the PUT with no content."""
        client = make_client(lambda r: httpx.Response(200))
        async with client:
            domain = await client.create_domain(
                "orga_1", "app_1", domain="app.example.test/"
            )
        assert domain.domain == "app.example.test"

    async def test_create_domain_encodes_a_path_suffix(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        """A path suffix belongs to the vhost name, not to the request route."""
        seen, factory = record_requests
        client = make_client(factory(200))
        async with client:
            await client.create_domain("orga_1", "app_1", domain="example.test/api")
        assert seen[0].url.raw_path.endswith(b"/vhosts/example.test%2Fapi")

    async def test_create_domain_rejects_an_empty_name(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(200))
        async with client:
            with pytest.raises(ValueError, match="domain"):
                await client.create_domain("orga_1", "app_1", domain="/")

    async def test_list_domains(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(
            lambda r: httpx.Response(200, json=[{"fqdn": "a.test"}, {"fqdn": "b.test/"}])
        )
        async with client:
            domains = await client.list_domains("orga_1", "app_1")
        assert [d.domain for d in domains] == ["a.test", "b.test"]

    async def test_list_domains_no_longer_hides_a_missing_application(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        """A 404 used to be reported as "this application has no domain"."""
        client = make_client(lambda r: httpx.Response(404, text="app not found"))
        async with client:
            with pytest.raises(NotFoundError):
                await client.list_domains("orga_1", "unknown_app")

    async def test_get_primary_domain(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(200, json={"fqdn": "a.test"}))
        async with client:
            domain = await client.get_primary_domain("orga_1", "app_1")
        assert domain is not None
        assert domain.is_primary is True

    async def test_get_primary_domain_surfaces_404(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(404))
        async with client:
            with pytest.raises(NotFoundError):
                await client.get_primary_domain("orga_1", "app_1")

    async def test_create_tcp_redirection(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(200, {"namespace": "cleverapps", "port": 4242}))
        async with client:
            redir = await client.create_tcp_redirection("orga_1", "app_1")
        assert redir.port == 4242
        assert seen[0].url.path.endswith("/tcpRedirs")

    async def test_redeploy_sends_optional_parameters(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(200))
        async with client:
            await client.redeploy_application("orga_1", "app_1", commit="abc", use_cache=False)
        assert seen[0].url.params["commit"] == "abc"
        assert seen[0].url.params["useCache"] == "false"

    async def test_create_application_body(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        import json as jsonlib

        seen, factory = record_requests
        client = make_client(factory(200, {"id": "app_1", "name": "my-app"}))
        async with client:
            app = await client.create_application(
                "orga_1",
                "my-app",
                instance_type="node",
                instance_version="20",
                instance_variant="var_1",
                environment=[{"name": "K", "value": "V"}],
            )
        body = jsonlib.loads(seen[0].content)
        assert body["name"] == "my-app"
        assert body["env"] == {"K": "V"}
        assert app.id == "app_1"

    async def test_create_application_requires_instance_information(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(200, json={}))
        async with client:
            with pytest.raises(ValueError, match="instance_slug"):
                await client.create_application("orga_1", "my-app")

    async def test_networkgroup_roundtrip(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        ng = {"id": "ng_1", "ownerId": "orga_1", "label": "l", "version": 1}
        client = make_client(factory(200, ng))
        async with client:
            result = await client.get_networkgroup("orga_1", "ng_1")
        assert result.id == "ng_1"
        assert seen[0].url.path == (
            "/v4/networkgroups/organisations/orga_1/networkgroups/ng_1"
        )

    async def test_create_networkgroup_member_body(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        import json as jsonlib

        from clever_cloud import MemberKind

        seen, factory = record_requests
        client = make_client(factory(202))
        async with client:
            await client.create_networkgroup_member(
                "orga_1",
                "ng_1",
                member_id="app_1",
                domain_name="d.members",
                kind=MemberKind.APPLICATION,
                label="app",
            )
        body = jsonlib.loads(seen[0].content)
        assert body == {
            "id": "app_1",
            "domainName": "d.members",
            "kind": "APPLICATION",
            "label": "app",
        }

    async def test_list_networkgroup_peers_handles_a_null_body(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(200, json=None))
        async with client:
            assert await client.list_networkgroup_peers("orga_1", "ng_1") == []

    async def test_delete_networkgroup_peer_uses_the_delete_verb(
        self,
        make_client: Callable[..., CleverCloudClient],
        record_requests: tuple[list[httpx.Request], Callable[..., object]],
    ) -> None:
        seen, factory = record_requests
        client = make_client(factory(204))
        async with client:
            await client.delete_networkgroup_peer("orga_1", "ng_1", "peer_1")
        assert seen[0].method == "DELETE"
        assert seen[0].url.path.endswith("/peers/peer_1")


class TestClientLifecycle:
    async def test_close_is_idempotent(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(200, json=PROFILE))
        async with client:
            await client.get_profile()
        await client.close()

    async def test_client_is_reusable_after_close(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(200, json=PROFILE))
        async with client:
            await client.get_profile()
        async with client:
            assert (await client.get_profile()).id == "user_1"


class TestNoBodyRetentionThroughCause:
    """A truncated body must not stay reachable through the exception chain."""

    async def test_invalid_json_body_is_not_retained_by_the_cause(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        # A JSONDecodeError keeps the whole payload in its .doc attribute.
        big = "{" + "x" * 200_000
        client = make_client(
            lambda r: httpx.Response(
                200, content=big.encode(), headers={"content-type": "application/json"}
            )
        )
        async with client:
            with pytest.raises(InvalidResponseError) as excinfo:
                await client.get_profile()

        error = excinfo.value
        assert len(error.response_body) < 3000
        assert error.__cause__ is None
        assert error.__context__ is None or not hasattr(error.__context__, "doc")

    async def test_invalid_json_message_stays_informative(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        """Suppressing the cause must not cost the failure position."""
        client = make_client(
            lambda r: httpx.Response(
                200, content=b"{not json", headers={"content-type": "application/json"}
            )
        )
        async with client:
            with pytest.raises(InvalidResponseError, match="line 1 column"):
                await client.get_profile()

    async def test_secret_in_an_invalid_body_is_not_reachable_from_the_chain(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        payload = '{"token": "SUPER_SECRET_VALUE", ' + "x" * 5000
        client = make_client(
            lambda r: httpx.Response(
                200,
                content=payload.encode(),
                headers={"content-type": "application/json"},
            )
        )
        async with client:
            with pytest.raises(InvalidResponseError) as excinfo:
                await client.get_profile()
        assert "SUPER_SECRET_VALUE" not in str(excinfo.value)
        assert excinfo.value.__cause__ is None
