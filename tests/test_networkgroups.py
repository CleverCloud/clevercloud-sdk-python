"""Endpoint-level tests for the NetworkGroups API surface."""

from __future__ import annotations

import json as jsonlib
from collections.abc import Callable

import httpx
import pytest

from clever_cloud import (
    CleverCloudClient,
    InvalidResponseError,
    MemberKind,
    PeerKind,
    PeerRole,
)

NG_ROOT = "/v4/networkgroups/organisations/orga_1/networkgroups"


Handler = Callable[[httpx.Request], httpx.Response]


def capture(
    status: int = 200, payload: object = None
) -> tuple[list[httpx.Request], Handler]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if payload is None:
            return httpx.Response(status, content=b"")
        return httpx.Response(status, json=payload)

    return seen, handler


class TestCreateNetworkGroup:
    async def test_minimal_body(self, make_client: Callable[..., CleverCloudClient]) -> None:
        seen, handler = capture(202)
        client = make_client(handler)
        async with client:
            await client.create_networkgroup("orga_1", label="my-ng")
        assert seen[0].method == "POST"
        assert seen[0].url.path == NG_ROOT
        assert jsonlib.loads(seen[0].content) == {"label": "my-ng"}

    async def test_full_body(self, make_client: Callable[..., CleverCloudClient]) -> None:
        seen, handler = capture(202)
        client = make_client(handler)
        async with client:
            await client.create_networkgroup(
                "orga_1",
                label="my-ng",
                description="desc",
                ng_id="ng_custom",
                tags=["a"],
                members=[{"id": "app_1", "domainName": "d", "kind": "APPLICATION"}],
            )
        body = jsonlib.loads(seen[0].content)
        assert body["id"] == "ng_custom"
        assert body["description"] == "desc"
        assert body["tags"] == ["a"]
        assert body["members"][0]["id"] == "app_1"

    async def test_owner_id_is_encoded(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        seen, handler = capture(202)
        client = make_client(handler)
        async with client:
            await client.create_networkgroup("../orga_2", label="x")
        assert b"..%2Forga_2" in seen[0].url.raw_path


class TestDeleteNetworkGroup:
    async def test_delete(self, make_client: Callable[..., CleverCloudClient]) -> None:
        seen, handler = capture(204)
        client = make_client(handler)
        async with client:
            await client.delete_networkgroup("orga_1", "ng_1")
        assert seen[0].method == "DELETE"
        assert seen[0].url.path == f"{NG_ROOT}/ng_1"


class TestSearchComponents:
    async def test_query_is_sent(self, make_client: Callable[..., CleverCloudClient]) -> None:
        seen, handler = capture(200, [{"id": "ng_1"}])
        client = make_client(handler)
        async with client:
            result = await client.search_networkgroup_components("orga_1", query="ng")
        assert seen[0].url.params["query"] == "ng"
        assert result == [{"id": "ng_1"}]

    async def test_no_query(self, make_client: Callable[..., CleverCloudClient]) -> None:
        seen, handler = capture(200, [])
        client = make_client(handler)
        async with client:
            await client.search_networkgroup_components("orga_1")
        assert not seen[0].url.params

    async def test_unexpected_shape_is_rejected(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(200, json={"not": "a list"}))
        async with client:
            with pytest.raises(InvalidResponseError, match="Expected a list"):
                await client.search_networkgroup_components("orga_1")


class TestMembers:
    async def test_get_member(self, make_client: Callable[..., CleverCloudClient]) -> None:
        seen, handler = capture(
            200, {"id": "app_1", "domainName": "d.members", "kind": "APPLICATION"}
        )
        client = make_client(handler)
        async with client:
            member = await client.get_networkgroup_member("orga_1", "ng_1", "app_1")
        assert member.kind is MemberKind.APPLICATION
        assert seen[0].url.path == f"{NG_ROOT}/ng_1/members/app_1"

    async def test_delete_member(self, make_client: Callable[..., CleverCloudClient]) -> None:
        seen, handler = capture(204)
        client = make_client(handler)
        async with client:
            await client.delete_networkgroup_member("orga_1", "ng_1", "app_1")
        assert seen[0].method == "DELETE"
        assert seen[0].url.path == f"{NG_ROOT}/ng_1/members/app_1"

    async def test_kind_accepts_a_plain_string(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        seen, handler = capture(202)
        client = make_client(handler)
        async with client:
            await client.create_networkgroup_member(
                "orga_1", "ng_1", member_id="app_1", domain_name="d", kind="ADDON"
            )
        assert jsonlib.loads(seen[0].content)["kind"] == "ADDON"

    async def test_label_is_omitted_when_absent(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        seen, handler = capture(202)
        client = make_client(handler)
        async with client:
            await client.create_networkgroup_member(
                "orga_1", "ng_1", member_id="app_1", domain_name="d", kind=MemberKind.ADDON
            )
        assert "label" not in jsonlib.loads(seen[0].content)


class TestPeers:
    async def test_list_peers(self, make_client: Callable[..., CleverCloudClient]) -> None:
        seen, handler = capture(
            200, [{"id": "peer_1", "parentMember": "app_1", "hv": "hv1"}]
        )
        client = make_client(handler)
        async with client:
            peers = await client.list_networkgroup_peers("orga_1", "ng_1")
        assert peers[0].kind is PeerKind.CLEVER
        assert seen[0].url.path == f"{NG_ROOT}/ng_1/peers"

    async def test_list_peers_rejects_an_unexpected_shape(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        client = make_client(lambda r: httpx.Response(200, json={"x": 1}))
        async with client:
            with pytest.raises(InvalidResponseError, match="Expected a list of peers"):
                await client.list_networkgroup_peers("orga_1", "ng_1")

    async def test_get_peer(self, make_client: Callable[..., CleverCloudClient]) -> None:
        seen, handler = capture(200, {"id": "peer_1", "parentMember": "app_1"})
        client = make_client(handler)
        async with client:
            peer = await client.get_networkgroup_peer("orga_1", "ng_1", "peer_1")
        assert peer.id == "peer_1"
        assert seen[0].url.path == f"{NG_ROOT}/ng_1/peers/peer_1"

    async def test_create_peer_body(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        seen, handler = capture(200, {"id": "peer_1"})
        client = make_client(handler)
        async with client:
            created = await client.create_networkgroup_peer(
                "orga_1",
                "ng_1",
                peer_id="peer_1",
                parent_member="app_1",
                peer_role=PeerRole.SERVER,
                public_key="pk",
                ip="10.0.0.1",
                port=51820,
                hostname="h",
                label="l",
                hv="hv1",
                parent_event="evt",
            )
        body = jsonlib.loads(seen[0].content)
        assert body["peerRole"] == "SERVER"
        assert body["peerKind"] == "CLEVER"
        assert body["publicKey"] == "pk"
        assert body["port"] == 51820
        assert body["parentEvent"] == "evt"
        assert created.peer_id == "peer_1"

    async def test_create_peer_omits_absent_optional_fields(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        seen, handler = capture(200, {"id": "peer_1"})
        client = make_client(handler)
        async with client:
            await client.create_networkgroup_peer(
                "orga_1", "ng_1", peer_id="p", parent_member="m", peer_role="CLIENT"
            )
        body = jsonlib.loads(seen[0].content)
        assert set(body) == {"id", "parentMember", "peerRole", "peerKind"}

    async def test_create_external_peer(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        seen, handler = capture(200, {"id": "peer_ext"})
        client = make_client(handler)
        async with client:
            created = await client.create_networkgroup_external_peer(
                "orga_1",
                "ng_1",
                parent_member="m_1",
                peer_role=PeerRole.CLIENT,
                public_key="pk",
                label="laptop",
                ip="1.2.3.4",
                port=51820,
                hostname="host",
                parent_event="evt",
            )
        assert seen[0].url.path == f"{NG_ROOT}/ng_1/external-peers"
        body = jsonlib.loads(seen[0].content)
        assert body["peerRole"] == "CLIENT"
        assert body["label"] == "laptop"
        assert created.peer_id == "peer_ext"

    async def test_external_peer_omits_absent_optional_fields(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        seen, handler = capture(200, {"id": "p"})
        client = make_client(handler)
        async with client:
            await client.create_networkgroup_external_peer(
                "orga_1", "ng_1", parent_member="m", peer_role="CLIENT",
                public_key="pk", label="l",
            )
        body = jsonlib.loads(seen[0].content)
        assert set(body) == {"parentMember", "peerRole", "publicKey", "label"}

    async def test_peer_response_without_id_is_rejected(
        self, make_client: Callable[..., CleverCloudClient]
    ) -> None:
        """The old code accepted an empty body and returned an empty peer id."""
        client = make_client(lambda r: httpx.Response(200, content=b""))
        async with client:
            with pytest.raises(InvalidResponseError):
                await client.create_networkgroup_peer(
                    "orga_1", "ng_1", peer_id="p", parent_member="m", peer_role="CLIENT"
                )
