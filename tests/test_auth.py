"""Tests for the authentication strategies (issue #3, findings 1 and 2)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from clever_cloud import ApiTokenCredentials, OAuthCredentials, SignatureMethod
from clever_cloud.auth import (
    build_signature_base_string,
    normalize_parameters,
    normalize_url,
    percent_encode,
)

HEADER_PARAM = re.compile(r'(\w+)="([^"]*)"')


def parse_header(header: str) -> dict[str, str]:
    assert header.startswith("OAuth ")
    return dict(HEADER_PARAM.findall(header))


class TestPercentEncoding:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("abcABC123", "abcABC123"),
            ("-._~", "-._~"),
            ("+", "%2B"),
            (" ", "%20"),
            ("/", "%2F"),
            ("=", "%3D"),
            ("&", "%26"),
            ("é", "%C3%A9"),
        ],
    )
    def test_only_unreserved_characters_survive(self, raw: str, expected: str) -> None:
        assert percent_encode(raw) == expected


class TestNormalizeUrl:
    def test_drops_query_and_fragment(self) -> None:
        url = "https://api.example.com/v2/self?a=1#frag"
        assert normalize_url(url) == "https://api.example.com/v2/self"

    def test_drops_default_port_and_lowercases_authority(self) -> None:
        assert normalize_url("HTTPS://API.Example.COM:443/v2/x") == (
            "https://api.example.com/v2/x"
        )

    def test_keeps_non_default_port(self) -> None:
        assert normalize_url("https://api.example.com:8443/v2/x") == (
            "https://api.example.com:8443/v2/x"
        )


class TestSignatureBaseString:
    def test_matches_the_rfc_5849_example(self) -> None:
        """The worked example from RFC 5849 section 3.4.1.1."""
        url = "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b"
        params = [
            ("b5", "=%3D"),
            ("a3", "a"),
            ("c@", ""),
            ("a2", "r b"),
            ("c2", ""),
            ("a3", "2 q"),
            ("oauth_consumer_key", "9djdj82h48djs9d2"),
            ("oauth_token", "kkk9d7dh3k39sjv7"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", "137131201"),
            ("oauth_nonce", "7d8f3e4a"),
        ]
        expected = (
            "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q"
            "%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_"
            "key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m"
            "ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk"
            "9d7dh3k39sjv7"
        )
        assert build_signature_base_string("POST", url, params) == expected

    def test_duplicate_keys_are_ordered_by_value(self) -> None:
        assert normalize_parameters([("a", "2"), ("a", "1")]) == "a=1&a=2"


class TestOAuthHeader:
    def test_carries_every_required_oauth_parameter(
        self, oauth_auth: OAuthCredentials
    ) -> None:
        """Finding 1: the legacy header omitted method, timestamp, nonce, version."""
        header = oauth_auth.get_authorization_header("GET", "https://api.example.test/v2/self")
        params = parse_header(header)
        assert params["oauth_consumer_key"] == "consumer-key"
        assert params["oauth_token"] == "access-token"
        assert params["oauth_signature_method"] == "HMAC-SHA512"
        assert params["oauth_version"] == "1.0"
        assert params["oauth_nonce"]
        assert params["oauth_timestamp"].isdigit()
        assert params["oauth_signature"]

    def test_signature_is_not_replayable(self, oauth_auth: OAuthCredentials) -> None:
        """Two calls for the same request must not produce the same header."""
        url = "https://api.example.test/v2/self"
        first = oauth_auth.get_authorization_header("GET", url)
        second = oauth_auth.get_authorization_header("GET", url)
        assert first != second
        assert parse_header(first)["oauth_nonce"] != parse_header(second)["oauth_nonce"]

    def test_signature_does_not_disclose_the_secrets(
        self, oauth_auth: OAuthCredentials
    ) -> None:
        header = oauth_auth.get_authorization_header("GET", "https://api.example.test/v2/self")
        assert "consumer-secret" not in header
        assert "access-secret" not in header

    def test_signature_binds_the_http_method(self, oauth_auth: OAuthCredentials) -> None:
        url = "https://api.example.test/v2/self"
        get = oauth_auth.get_authorization_header("GET", url, timestamp=1, nonce="n")
        post = oauth_auth.get_authorization_header("POST", url, timestamp=1, nonce="n")
        assert parse_header(get)["oauth_signature"] != parse_header(post)["oauth_signature"]

    def test_signature_binds_the_url(self, oauth_auth: OAuthCredentials) -> None:
        one = oauth_auth.get_authorization_header(
            "GET", "https://api.example.test/v2/self", timestamp=1, nonce="n"
        )
        two = oauth_auth.get_authorization_header(
            "GET", "https://api.example.test/v2/other", timestamp=1, nonce="n"
        )
        assert parse_header(one)["oauth_signature"] != parse_header(two)["oauth_signature"]

    def test_signature_binds_the_query_parameters(
        self, oauth_auth: OAuthCredentials
    ) -> None:
        one = oauth_auth.get_authorization_header(
            "GET", "https://api.example.test/v2/x?a=1", timestamp=1, nonce="n"
        )
        two = oauth_auth.get_authorization_header(
            "GET", "https://api.example.test/v2/x?a=2", timestamp=1, nonce="n"
        )
        assert parse_header(one)["oauth_signature"] != parse_header(two)["oauth_signature"]

    def test_signature_binds_a_form_encoded_body(
        self, oauth_auth: OAuthCredentials
    ) -> None:
        url = "https://api.example.test/v2/x"
        plain = oauth_auth.get_authorization_header("POST", url, timestamp=1, nonce="n")
        with_body = oauth_auth.get_authorization_header(
            "POST", url, body_params=[("a", "1")], timestamp=1, nonce="n"
        )
        assert parse_header(plain)["oauth_signature"] != parse_header(with_body)["oauth_signature"]

    def test_hmac_sha512_value_is_reproducible(self, oauth_auth: OAuthCredentials) -> None:
        """Recompute the signature independently and compare."""
        url = "https://api.example.test/v2/self"
        header = oauth_auth.get_authorization_header(
            method="GET", url=url, timestamp=1700000000, nonce="fixed-nonce"
        )
        params = parse_header(header)

        signed_params = [
            ("oauth_consumer_key", "consumer-key"),
            ("oauth_token", "access-token"),
            ("oauth_signature_method", "HMAC-SHA512"),
            ("oauth_timestamp", "1700000000"),
            ("oauth_nonce", "fixed-nonce"),
            ("oauth_version", "1.0"),
        ]
        base_string = build_signature_base_string("GET", url, signed_params)
        key = "consumer-secret&access-secret"
        expected = base64.b64encode(
            hmac.new(key.encode(), base_string.encode(), hashlib.sha512).digest()
        ).decode()

        # The header value is percent-encoded; compare against the encoded form.
        assert params["oauth_signature"] == percent_encode(expected)

    def test_hmac_sha256_is_selectable(self, oauth_auth: OAuthCredentials) -> None:
        creds = OAuthCredentials(
            consumer_key="k",
            consumer_secret="cs",
            token="t",
            secret="ts",
            signature_method=SignatureMethod.HMAC_SHA256,
        )
        params = parse_header(creds.get_authorization_header("GET", "https://x.test/a"))
        assert params["oauth_signature_method"] == "HMAC-SHA256"

    def test_plaintext_stays_available_as_an_explicit_compatibility_mode(self) -> None:
        creds = OAuthCredentials(
            consumer_key="k",
            consumer_secret="cs",
            token="t",
            secret="ts",
            signature_method=SignatureMethod.PLAINTEXT,
        )
        params = parse_header(creds.get_authorization_header("GET", "https://x.test/a"))
        assert params["oauth_signature_method"] == "PLAINTEXT"
        assert params["oauth_signature"] == percent_encode("cs&ts")
        # Even in legacy mode, the anti-replay parameters are present.
        assert params["oauth_nonce"]
        assert params["oauth_timestamp"]

    def test_default_method_is_hmac_sha512(self) -> None:
        creds = OAuthCredentials(consumer_key="k", consumer_secret="cs", token="t", secret="ts")
        assert creds.signature_method is SignatureMethod.HMAC_SHA512

    def test_secrets_needing_encoding_are_handled(self) -> None:
        creds = OAuthCredentials(
            consumer_key="k",
            consumer_secret="a b&c",
            token="t",
            secret="d/e",
            signature_method=SignatureMethod.PLAINTEXT,
        )
        params = parse_header(creds.get_authorization_header("GET", "https://x.test/a"))
        assert params["oauth_signature"] == percent_encode("a%20b%26c&d%2Fe")


class TestApplyToRequest:
    def test_signs_the_actual_request_url_and_method(
        self, oauth_auth: OAuthCredentials
    ) -> None:
        request = httpx.Request("GET", "https://api.example.test/v2/self?a=1")
        oauth_auth.apply_to_request(request)
        assert request.headers["Authorization"].startswith("OAuth ")

    def test_form_body_takes_part_in_the_signature(
        self, oauth_auth: OAuthCredentials
    ) -> None:
        url = "https://api.example.test/v2/oauth/x"
        with_body = httpx.Request("POST", url, data={"a": "1"})
        without_body = httpx.Request("POST", url)
        oauth_auth.apply_to_request(with_body)
        oauth_auth.apply_to_request(without_body)
        # Different signed material, so the two headers cannot be identical.
        assert with_body.headers["Authorization"] != without_body.headers["Authorization"]

    def test_json_body_is_not_treated_as_form_parameters(
        self, oauth_auth: OAuthCredentials
    ) -> None:
        request = httpx.Request("POST", "https://api.example.test/v2/x", json={"a": "1"})
        oauth_auth.apply_to_request(request)
        assert "OAuth" in request.headers["Authorization"]


class TestApiToken:
    def test_bearer_header(self, token_auth: ApiTokenCredentials) -> None:
        assert token_auth.get_authorization_header("GET", "https://x.test") == (
            "Bearer test-bearer-token"
        )

    def test_applies_to_request(self, token_auth: ApiTokenCredentials) -> None:
        request = httpx.Request("GET", "https://x.test/v2/self")
        token_auth.apply_to_request(request)
        assert request.headers["Authorization"] == "Bearer test-bearer-token"

    def test_default_base_url_is_the_api_bridge(self) -> None:
        assert ApiTokenCredentials(token="t").get_base_url() == (
            "https://api-bridge.clever-cloud.com"
        )


class TestCredentialRedaction:
    """Finding 2: secrets must not appear in a representation."""

    def test_api_token_repr_hides_the_token(self) -> None:
        creds = ApiTokenCredentials(token="BEARER_SECRET")
        assert "BEARER_SECRET" not in repr(creds)
        assert "redacted" in repr(creds)

    def test_oauth_repr_hides_both_secrets(self) -> None:
        creds = OAuthCredentials(
            consumer_key="KEY",
            consumer_secret="CONSUMER_SECRET",
            token="TOKEN",
            secret="TOKEN_SECRET",
        )
        text = repr(creds)
        assert "CONSUMER_SECRET" not in text
        assert "TOKEN_SECRET" not in text
        # Non-secret identifiers stay visible, so the repr is still useful.
        assert "KEY" in text
        assert "TOKEN" in text

    def test_str_and_format_also_hide_secrets(self) -> None:
        creds = OAuthCredentials(
            consumer_key="KEY",
            consumer_secret="CONSUMER_SECRET",
            token="TOKEN",
            secret="TOKEN_SECRET",
        )
        assert "CONSUMER_SECRET" not in str(creds)
        assert "CONSUMER_SECRET" not in f"{creds}"
        assert "CONSUMER_SECRET" not in f"{creds!r}"

    def test_secrets_do_not_leak_through_a_container_repr(self) -> None:
        """Structured logging often reprs a whole dict or list."""
        creds = ApiTokenCredentials(token="BEARER_SECRET")
        assert "BEARER_SECRET" not in repr({"auth": creds})
        assert "BEARER_SECRET" not in repr([creds])


class TestExpiration:
    def test_credentials_without_expiration_never_expire(self) -> None:
        creds = OAuthCredentials(consumer_key="k", consumer_secret="cs", token="t", secret="ts")
        assert creds.is_expired() is False

    def test_expired_credentials_are_reported(self) -> None:
        past = datetime.now(tz=UTC) - timedelta(hours=1)
        creds = OAuthCredentials(
            consumer_key="k", consumer_secret="cs", token="t", secret="ts",
            expiration_date=past,
        )
        assert creds.is_expired() is True

    def test_future_expiration_is_not_expired(self) -> None:
        future = datetime.now(tz=UTC) + timedelta(hours=1)
        creds = OAuthCredentials(
            consumer_key="k", consumer_secret="cs", token="t", secret="ts",
            expiration_date=future,
        )
        assert creds.is_expired() is False
