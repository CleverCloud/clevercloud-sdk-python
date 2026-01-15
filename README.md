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

## Available features

This SDK is still a work in progress, but it already provides the following features:

- Get user profile
- List instance types
- Create application
- Redeploy application
- Create TCP redirection
- List domains
- Get primary domain

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
