# Changelog

All notable changes to this project are documented in this file.

## 0.2.1

### Fixed

- A domain whose `fqdn` is only slashes no longer yields `Domain(domain="")`.
  `Domain.from_api_response()` validated the raw field and stripped the trailing
  slashes afterwards, so `{"fqdn": "/"}` passed validation. The stripped value is
  what gets validated now, and it raises the same `InvalidResponseError` as a
  missing field.

### Added

- `create_domain()` attaches a domain (vhost) to an application. The name is
  stripped of its trailing slash before being percent-encoded, so it round-trips
  with `Domain.domain` and a path suffix such as `example.com/api` stays part of
  the vhost name. Deployments that answer with an empty body are supported: the
  returned `Domain` then carries the requested name.

## 0.2.0

Addresses the security, correctness and design audit tracked in
[issue #3](https://github.com/CleverCloud/clevercloud-sdk-python/issues/3).

### Security

- **OAuth requests are now fully signed.** Every request carries
  `oauth_signature_method`, `oauth_timestamp`, `oauth_nonce` and `oauth_version`,
  and is signed with HMAC-SHA512 over its method, URL, query and form body. The
  previous header was static and could be replayed by anyone who observed it.
  `SignatureMethod.PLAINTEXT` remains available as an explicitly selected
  compatibility mode, and `SignatureMethod.HMAC_SHA256` is also supported.
- **Credentials no longer appear in representations.** `ApiTokenCredentials`,
  `OAuthCredentials`, `OAuthConsumer` and `RequestToken` redact their secrets in
  `repr()`, including when nested in a container that a logger reprs.
- **Path parameters are percent-encoded.** Identifiers such as `../self`,
  `x?override=1` or `x/y` can no longer change which endpoint a request reaches.
- **Clear-text base URLs are refused.** An `http://` base URL raises unless
  `allow_insecure_http=True` is passed explicitly.
- **The OAuth dance validates its callback.** `oauth_callback_confirmed` is
  checked, and the verifier is only accepted when the callback carries the very
  request token this dance obtained.
- Exception messages and attributes no longer copy an entire response body;
  bodies are truncated to 2 KiB.

### Fixed

- Successful responses with an empty body (202, 205, and 200 on some endpoints)
  no longer raise `JSONDecodeError`. Undecodable JSON now raises
  `InvalidResponseError`.
- Unfollowed 3xx responses are no longer treated as successful responses.
- Missing dates are no longer replaced with the current time, and every parsed
  date is normalized to a timezone-aware UTC datetime.
- Runtime versions are ordered naturally, so `resolve_instance_slug()` picks
  `10` over `9`.
- The JSON `Content-Type` is no longer forced onto every request; HTTPX derives
  it from the body actually sent. A GET carries no `Content-Type` at all, and a
  form body is correctly labelled `application/x-www-form-urlencoded`.
- TLS and mTLS are configured through an `ssl.SSLContext` instead of the HTTPX
  arguments deprecated in 0.28. Per-request cookies were removed from the OAuth
  dance for the same reason.
- HTTP 403 is reported as `AuthorizationError` rather than an authentication
  failure.
- Transport failures are wrapped in `TransportError`, inside the
  `CleverCloudError` hierarchy.

### Added

- Idempotent requests (GET, HEAD, OPTIONS, PUT, DELETE) retry on 429, 502, 503,
  504 and network errors, with exponential backoff, jitter and `Retry-After`
  support, capped by `max_retry_wait`. Each attempt is re-signed with a fresh
  nonce. Configure with `max_retries` (2 by default; `0` disables retries).
- The instance catalogue is cached per client, so repeated `instance_slug`
  resolutions no longer re-download it. `list_instances(refresh=True)` forces a
  new fetch.
- `NotFoundError` and `RateLimitError` (which exposes `retry_after`).
- `OAuthDance.parse_callback_url()` for the browser-based flow, and a
  configurable `mfa_kind` on `login()`.
- `OAuthCredentials.expiration_date` and `is_expired()`, populated from the
  access-token exchange.
- A `py.typed` marker, so the declared `Typing :: Typed` classifier is honoured.
- A test suite (217 tests, no network access) plus CI running lint, strict type
  checking and tests on Python 3.11, 3.12 and 3.13.

### Breaking changes

- `Auth.get_authorization_header()` now takes the request method and URL, since
  a signature is bound to them. Custom `Auth` subclasses must be updated.
- Response models are parsed strictly: a payload missing a required field raises
  `InvalidResponseError` instead of yielding a model filled with empty strings,
  zeroes or a fabricated date. Genuinely optional fields are now typed
  `| None` and default to `None` rather than `""`.
- `Profile.creation_date` and `Application.creation_date` are `datetime | None`.
- `NetworkGroup.members`, `.peers` and `.tags` are tuples, and
  `PeerCreated.raw` is a read-only mapping, so `frozen=True` means what it says.
- An unknown `MemberKind` is rejected instead of being coerced to `EXTERNAL`.
- `list_domains()` and `get_primary_domain()` no longer swallow HTTP 404. They
  raise `NotFoundError`, because the API reports "no such application" and "no
  domain" with the same status; the caller decides how to treat it.
- HTTP 403 raises `AuthorizationError`, which is *not* a subclass of
  `AuthenticationError`. Code catching `AuthenticationError` for 403 must be
  updated.
- Redirections raise `InvalidResponseError` instead of returning the redirect
  body.
- `httpx>=0.28` is now required.

## 0.1.0

- Initial public release.
