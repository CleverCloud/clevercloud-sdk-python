# Clever Cloud Python SDK

A Python SDK for [Clever Cloud](https://clever-cloud.com).

## Installation

You can add it to your project using `pip` or `uv`:

```bash
pip install clevercloud-sdk
uv add clevercloud-sdk
```

## Usage

```python
from clever_cloud import CleverCloudClient, ApiTokenCredentials

async with CleverCloudClient(ApiTokenCredentials(token="...")) as client:
    profile = await client.get_profile()
    print(f"Hello, {profile.name}!")
```

You can also use OAuth credentials:

```python
from clever_cloud import OAuthCredentials

credentials = OAuthCredentials(
    consumer_key="...",
    consumer_secret="...",
    token="...",
    secret="...",
)

async with CleverCloudClient(credentials) as client:
    ...
```

Every OAuth request is signed with HMAC-SHA512 over its method, URL, query
string and form body, with a timestamp, a nonce and the OAuth version, so an
intercepted `Authorization` header cannot be replayed. To talk to a deployment
that still requires the legacy format, select the compatibility mode explicitly:

```python
from clever_cloud import SignatureMethod

credentials = OAuthCredentials(..., signature_method=SignatureMethod.PLAINTEXT)
```

### Obtaining OAuth credentials

The browser flow is the supported way to obtain credentials:

```python
import webbrowser
from clever_cloud import OAuthConsumer, OAuthDance

with OAuthDance(OAuthConsumer(key="...", secret="..."),
                callback_url="https://my-app.example/callback") as dance:
    request_token = dance.get_request_token()
    webbrowser.open(dance.get_authorization_url(request_token))

    # ... your callback receives the redirect; pass its full URL back:
    verifier = dance.parse_callback_url(callback_url, request_token)
    credentials = dance.get_access_token(request_token, verifier)
```

`parse_callback_url()` checks that the callback carries the token this dance
requested before accepting the verifier. `OAuthDance.login()` remains available
for browser-less automation, but it drives the console's internal session
endpoints with the account password and is not a supported OAuth flow.

### Errors

All errors derive from `CleverCloudError`:

| Exception | Raised when |
| --- | --- |
| `AuthenticationError` | HTTP 401: credentials missing or invalid |
| `AuthorizationError` | HTTP 403: credentials valid, access denied |
| `NotFoundError` | HTTP 404 |
| `RateLimitError` | HTTP 429, exposes `retry_after` |
| `HttpError` | Any other HTTP error status |
| `TransportError` | Network, timeout or TLS failure |
| `InvalidResponseError` | Undecodable body, unexpected redirect, or a payload that does not match the endpoint's contract |
| `OAuthError` | Failure during the OAuth dance, with its `step` |

Response bodies attached to exceptions are truncated, so a large or sensitive
error payload does not end up whole in your logs.

### Retries

Idempotent requests (GET, HEAD, OPTIONS, PUT, DELETE) are retried on HTTP 429,
502, 503, 504 and on network errors, using exponential backoff with jitter and
honouring `Retry-After`. Each attempt is signed again with a fresh nonce.

```python
async with CleverCloudClient(credentials, max_retries=0) as client:  # opt out
    ...
```

### Custom CA bundle and mTLS

The client accepts a custom CA bundle and a client certificate for mutual TLS,
useful when targeting an API behind a private PKI or requiring client
authentication:

```python
async with CleverCloudClient(
    credentials,
    ca_bundle="/path/to/ca-bundle.pem",
    client_cert=("/path/to/client.crt", "/path/to/client.key"),
) as client:
    ...
```

Both are loaded into an `ssl.SSLContext`, so no deprecated HTTPX argument is
used. `verify_ssl=False` disables server certificate verification entirely (not
recommended outside of local testing).

A clear-text `http://` base URL is refused by default, because credentials
would travel unencrypted; pass `allow_insecure_http=True` to override it against
a local development server.

### Response models

Models are parsed strictly: a response missing a field the endpoint is
documented to return raises `InvalidResponseError` rather than producing a model
filled with empty strings, zeroes or a fabricated timestamp. Optional fields are
typed `| None`, dates are timezone-aware UTC datetimes, and collections are
tuples, so `frozen=True` models are immutable all the way down.

## Available features

This SDK is still a work in progress, but it already provides the following
features:

- Get user profile
- List instance types (cached per client)
- Create application
- Redeploy application
- Create TCP redirection
- List domains
- Get primary domain
- Custom CA bundle and mTLS client certificate support
- Automatic retries with backoff on transient failures
- NetworkGroups: create / get / delete / search, manage members, peers and external peers

### NetworkGroups example

Attach an application as a member of an existing NetworkGroup:

```python
from clever_cloud import MemberKind

await client.create_networkgroup_member(
    owner_id="orga_xxx",
    ng_id="ng_xxx",
    member_id="app_xxx",
    domain_name="my-app.m.ng_xxx.members",
    kind=MemberKind.APPLICATION,
    label="my-app",
)
```

## Development

```bash
uv sync --extra dev
uv run pytest          # test suite, no network access
uv run ruff check .    # lint
uv run mypy            # strict type checking
```

See [CHANGELOG.md](CHANGELOG.md) for release notes, including breaking changes.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
