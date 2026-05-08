# Square Base IDP Rust SDK

Rust SDK for Base identity integration in backend services and gateways.

## Install

Before publishing:

```toml
square-idp-sdk = { path = "../base/sdk/rust" }
```

After publishing, replace with crates.io version.

## Required Environment

```env
BASE_IDP_ISSUER=https://authlayer.squareexp.com
BASE_IDP_CLIENT_ID=<your-client-id>
BASE_IDP_CLIENT_SECRET=<your-client-secret-if-confidential>
BASE_IDP_REDIRECT_URI=<exact-registered-callback-url>
BASE_IDP_SCOPES="openid profile <product>:read <product>:write"
BASE_IDP_AUDIENCE=square-experience
```

Get these values from Base client registration.

## Verify Access Tokens

```rust
use square_idp_sdk::{bearer_token, Config, SquareIdpClient, VerifyOptions};

async fn verify(auth_header: Option<&str>) -> Result<(), square_idp_sdk::Error> {
    let client = SquareIdpClient::new(Config::from_env()?)?;
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
    .exchange_code(square_idp_sdk::TokenOptions {
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
