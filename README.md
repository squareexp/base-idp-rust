# Base IdP Rust SDK

Rust SDK for Base identity integration in backend services and gateways.

## Install

Before publishing:

```toml
base-idp = { path = "../base/sdk/rust" }
```

After publishing, replace with crates.io version.

## Minimal Environment

```env
BASE_IDP_CLIENT_ID=<your-client-id>
BASE_IDP_CLIENT_SECRET=<your-client-secret-if-confidential>
```

That is enough for most services. Base resolves redirect URIs, scopes, audience, and auth methods from the client registration.
`BASE_IDP_SECRET` remains a backward-compatible alias in some SDKs, but `BASE_IDP_CLIENT_SECRET` is the preferred secret name.

## Fast Init

The TypeScript SDK ships with a bootstrap CLI that can generate the exact client-registration payload and env block used by Base:

```bash
npx base-idp init \
  --client-id console-gateway \
  --display-name "Base Console" \
  --product console \
  --app-domain console.cloud.squareexp.com \
  --redirect-uri http://localhost:3010/api/auth/callback \
  --allowed-redirect-uris http://localhost:3010/api/auth/callback \
  --allowed-origins http://localhost:3010 \
  --allowed-scopes "openid profile console:manage" \
  --allowed-auth-methods password,magic_link \
  --requested-claims email,profile
```

Use `--post --admin-token <token>` to register the client through the Base admin API.

## Verify Access Tokens

```rust
use base_idp::{bearer_token, Config, BaseIdPClient, VerifyOptions};

async fn verify(auth_header: Option<&str>) -> Result<(), base_idp::Error> {
    let client = BaseIdPClient::new(Config::from_env()?)?;
    let token = bearer_token(auth_header)?;

    let principal = client
        .verify_access_token(
            token,
            VerifyOptions {
                required_scope: Some("projects:read".to_string()),
                ..Default::default()
            },
        )
        .await?;

    println!("principal id={}", principal.id);
    Ok(())
}
```

## OAuth Code Exchange

```rust
let auth_url = client.authorize_url(Default::default())?;
let tokens = client
    .exchange_code(base_idp::TokenOptions {
        code,
        ..Default::default()
    })
    .await?;
```

## Verification Model

The SDK validates:
- PASETO `v4.public` signature (Ed25519)
- issuer and audience
- time-based claims
- `token_use=access`
- required scopes

Public keys are discovered from Base and cached by the async client.
