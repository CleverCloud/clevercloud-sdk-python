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

### Custom CA bundle and mTLS

The client accepts a custom CA bundle and a client certificate for mutual TLS, useful when targeting an API behind a private PKI or requiring client authentication:

```python
async with CleverCloudClient(
    credentials,
    ca_bundle="/path/to/ca-bundle.pem",
    client_cert=("/path/to/client.crt", "/path/to/client.key"),
) as client:
    ...
```

`verify_ssl=False` disables server certificate verification entirely (not recommended outside of local testing).

## Available features

This SDK is still a work in progress, but it already provides the following features:

- Get user profile
- List instance types
- Create application
- Redeploy application
- Create TCP redirection
- List domains
- Get primary domain
- Custom CA bundle and mTLS client certificate support
- Tolerant response handling (non-JSON bodies, relaxed `Accept` header)
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

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
