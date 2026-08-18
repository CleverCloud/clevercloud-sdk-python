"""Tests for response model parsing (issue #3, finding 5)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from clever_cloud import (
    Application,
    Domain,
    InvalidResponseError,
    MemberKind,
    NetworkGroup,
    NetworkGroupMember,
    NetworkGroupPeer,
    PeerCreated,
    PeerKind,
    Profile,
    TcpRedirection,
)

MINIMAL_PROFILE = {"id": "user_1", "email": "user@example.test"}


class TestDateParsing:
    """A missing date must never be replaced with the current time."""

    def test_missing_date_is_none_not_now(self) -> None:
        profile = Profile.from_api_response(MINIMAL_PROFILE)
        assert profile.creation_date is None

    def test_empty_string_date_is_none(self) -> None:
        profile = Profile.from_api_response({**MINIMAL_PROFILE, "creationDate": ""})
        assert profile.creation_date is None

    def test_epoch_milliseconds(self) -> None:
        profile = Profile.from_api_response(
            {**MINIMAL_PROFILE, "creationDate": 1700000000000}
        )
        assert profile.creation_date == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)

    def test_iso_string_with_offset_is_converted_to_utc(self) -> None:
        profile = Profile.from_api_response(
            {**MINIMAL_PROFILE, "creationDate": "2023-11-14T23:13:20+01:00"}
        )
        assert profile.creation_date == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)

    def test_iso_string_with_z_suffix(self) -> None:
        profile = Profile.from_api_response(
            {**MINIMAL_PROFILE, "creationDate": "2023-11-14T22:13:20Z"}
        )
        assert profile.creation_date == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)

    def test_naive_iso_string_is_assumed_utc_not_left_naive(self) -> None:
        """Integer and string dates used to produce inconsistent awareness."""
        profile = Profile.from_api_response(
            {**MINIMAL_PROFILE, "creationDate": "2023-11-14T22:13:20"}
        )
        assert profile.creation_date is not None
        assert profile.creation_date.tzinfo is not None
        assert profile.creation_date == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)

    def test_unparsable_date_is_rejected(self) -> None:
        with pytest.raises(InvalidResponseError, match="invalid ISO-8601"):
            Profile.from_api_response({**MINIMAL_PROFILE, "creationDate": "not-a-date"})

    def test_wrong_type_date_is_rejected(self) -> None:
        with pytest.raises(InvalidResponseError, match="unsupported date type"):
            Profile.from_api_response({**MINIMAL_PROFILE, "creationDate": ["x"]})


class TestProfile:
    def test_required_fields_are_enforced(self) -> None:
        with pytest.raises(InvalidResponseError, match="'id'"):
            Profile.from_api_response({"email": "a@b.test"})
        with pytest.raises(InvalidResponseError, match="'email'"):
            Profile.from_api_response({"id": "user_1"})

    def test_missing_optional_fields_are_none_not_empty_strings(self) -> None:
        profile = Profile.from_api_response(MINIMAL_PROFILE)
        assert profile.name is None
        assert profile.country is None
        assert profile.preferred_mfa is None

    def test_full_payload(self) -> None:
        profile = Profile.from_api_response(
            {
                "id": "user_1",
                "email": "user@example.test",
                "name": "Ada",
                "phone": "+33100000000",
                "country": "FR",
                "lang": "fr",
                "emailValidated": True,
                "admin": False,
                "canPay": True,
                "hasPassword": True,
                "preferredMFA": "TOTP",
                "oauthApps": ["github"],
            }
        )
        assert profile.name == "Ada"
        assert profile.email_validated is True
        assert profile.is_linked_to_github is True
        assert profile.preferred_mfa == "TOTP"

    def test_github_link_absent(self) -> None:
        profile = Profile.from_api_response({**MINIMAL_PROFILE, "oauthApps": []})
        assert profile.is_linked_to_github is False

    def test_non_object_payload_is_rejected(self) -> None:
        with pytest.raises(InvalidResponseError, match="expected a JSON object"):
            Profile.from_api_response(["not", "an", "object"])


class TestDomain:
    def test_parses_and_strips_trailing_slash(self) -> None:
        domain = Domain.from_api_response({"fqdn": "app.example.test/"})
        assert domain.domain == "app.example.test"
        assert domain.is_primary is False

    def test_primary_flag(self) -> None:
        domain = Domain.from_api_response({"fqdn": "a.test"}, is_primary=True)
        assert domain.is_primary is True

    def test_missing_fqdn_is_rejected(self) -> None:
        with pytest.raises(InvalidResponseError, match="'fqdn'"):
            Domain.from_api_response({})


class TestTcpRedirection:
    def test_parses_namespace_and_port(self) -> None:
        redir = TcpRedirection.from_api_response({"namespace": "cleverapps", "port": 4242})
        assert redir.namespace == "cleverapps"
        assert redir.port == 4242

    def test_missing_port_is_rejected_rather_than_defaulting_to_zero(self) -> None:
        with pytest.raises(InvalidResponseError, match="'port'"):
            TcpRedirection.from_api_response({"namespace": "cleverapps"})

    def test_boolean_is_not_accepted_as_a_port(self) -> None:
        with pytest.raises(InvalidResponseError, match="'port'"):
            TcpRedirection.from_api_response({"namespace": "n", "port": True})


class TestApplication:
    def test_reads_instance_from_the_nested_object(self) -> None:
        app = Application.from_api_response(
            {
                "id": "app_1",
                "name": "my-app",
                "zone": "par",
                "instance": {"type": "node", "version": "20", "variant": {"id": "var_1"}},
                "creationDate": 1700000000000,
            }
        )
        assert app.instance_type == "node"
        assert app.instance_version == "20"
        assert app.instance_variant == "var_1"

    def test_falls_back_to_the_flat_fields(self) -> None:
        app = Application.from_api_response(
            {
                "id": "app_1",
                "name": "my-app",
                "instanceType": "python",
                "instanceVersion": "3.12",
                "instanceVariant": "var_2",
            }
        )
        assert app.instance_type == "python"
        assert app.instance_variant == "var_2"

    def test_required_fields_are_enforced(self) -> None:
        with pytest.raises(InvalidResponseError, match="'id'"):
            Application.from_api_response({"name": "x"})
        with pytest.raises(InvalidResponseError, match="'name'"):
            Application.from_api_response({"id": "app_1"})

    def test_unknown_instance_shape_does_not_crash(self) -> None:
        app = Application.from_api_response(
            {"id": "app_1", "name": "x", "instance": "unexpected"}
        )
        assert app.instance_type is None


class TestNetworkGroupModels:
    def test_member_parsing(self) -> None:
        member = NetworkGroupMember.from_api_response(
            {"id": "app_1", "domainName": "a.members", "kind": "APPLICATION", "label": "app"}
        )
        assert member.kind is MemberKind.APPLICATION
        assert member.label == "app"

    def test_unknown_member_kind_is_rejected(self) -> None:
        """The old code silently coerced an unknown kind into EXTERNAL."""
        with pytest.raises(InvalidResponseError, match="unknown value"):
            NetworkGroupMember.from_api_response(
                {"id": "x", "domainName": "d", "kind": "SOMETHING_NEW"}
            )

    def test_missing_member_kind_is_rejected(self) -> None:
        with pytest.raises(InvalidResponseError, match="'kind'"):
            NetworkGroupMember.from_api_response({"id": "x", "domainName": "d"})

    def test_clever_peer_is_detected_by_its_hv_field(self) -> None:
        peer = NetworkGroupPeer.from_api_response(
            {
                "id": "peer_1",
                "parentMember": "app_1",
                "hv": "hv-1",
                "endpoint": {"privateAddress": "10.0.0.1", "publicAddress": "1.2.3.4"},
            }
        )
        assert peer.kind is PeerKind.CLEVER
        assert peer.endpoint is not None
        assert peer.endpoint.private_address == "10.0.0.1"

    def test_external_peer_has_no_hv(self) -> None:
        peer = NetworkGroupPeer.from_api_response(
            {"id": "peer_2", "parentMember": "m_1", "publicKey": "pk"}
        )
        assert peer.kind is PeerKind.EXTERNAL
        assert peer.endpoint is None

    def test_networkgroup_parsing(self) -> None:
        ng = NetworkGroup.from_api_response(
            {
                "id": "ng_1",
                "ownerId": "orga_1",
                "label": "my-ng",
                "version": 3,
                "members": [{"id": "app_1", "domainName": "d", "kind": "APPLICATION"}],
                "peers": [{"id": "peer_1", "parentMember": "app_1"}],
                "tags": ["a", "b"],
            }
        )
        assert ng.version == 3
        assert len(ng.members) == 1
        assert len(ng.peers) == 1
        assert ng.tags == ("a", "b")

    def test_collections_are_immutable(self) -> None:
        """frozen=True advertised an immutability the lists did not provide."""
        ng = NetworkGroup.from_api_response(
            {"id": "ng_1", "ownerId": "orga_1", "label": "l", "version": 1}
        )
        assert isinstance(ng.members, tuple)
        assert isinstance(ng.peers, tuple)
        assert isinstance(ng.tags, tuple)
        with pytest.raises(AttributeError):
            ng.tags.append("x")  # type: ignore[attr-defined]

    def test_null_collections_are_empty(self) -> None:
        ng = NetworkGroup.from_api_response(
            {"id": "ng_1", "ownerId": "orga_1", "label": "l", "version": 1,
             "members": None, "peers": None, "tags": None}
        )
        assert ng.members == ()

    def test_peer_created_requires_an_id(self) -> None:
        with pytest.raises(InvalidResponseError, match="'id'"):
            PeerCreated.from_api_response({})

    def test_peer_created_accepts_the_peer_id_alias(self) -> None:
        created = PeerCreated.from_api_response({"peerId": "peer_9"})
        assert created.peer_id == "peer_9"

    def test_peer_created_raw_mapping_is_read_only(self) -> None:
        created = PeerCreated.from_api_response({"id": "peer_1", "extra": 1})
        assert created.raw["extra"] == 1
        with pytest.raises(TypeError):
            created.raw["extra"] = 2  # type: ignore[index]
