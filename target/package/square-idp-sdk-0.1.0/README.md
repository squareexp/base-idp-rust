# Square IdP Rust SDK

Install from this workspace path until the crate is published:

```toml
square-idp-sdk = { path = "../base/sdk/rust" }
```

Create the application in Base before using this SDK. The Base registration returns the `client_id`, optional confidential `client_secret`, exact callback URLs, allowed scopes, and app metadata used for auth and delivery customization.

Gateway usage:

```rust
use square_idp_sdk::{bearer_token, Config, SquareIdpClient, VerifyOptions};

async fn verify(auth_header: Option<&str>) -> Result<(), square_idp_sdk::Error> {
    let client = SquareIdpClient::new(Config::from_env()?)?;
    let token = bearer_token(auth_header)?;
    let principal = client
        .verify_access_token(
            token,
            VerifyOptions {
                required_scope: Some("axiomdb:read".to_string()),
                ..Default::default()
            },
        )
        .await?;

    println!("base gid={}", principal.id);
    Ok(())
}
```

Authorization code flow:

```rust
let auth_url = client.authorize_url(Default::default())?;
let tokens = client
    .exchange_code(square_idp_sdk::TokenOptions {
        code,
        ..Default::default()
    })
    .await?;
```

Expected environment:

```env
BASE_IDP_ISSUER=https://authlayer.squareexp.com
BASE_IDP_CLIENT_ID=axiomdb-gateway
BASE_IDP_CLIENT_SECRET=...
BASE_IDP_REDIRECT_URI=https://gateway.squareexp.com/api/v1/auth/square/callback
BASE_IDP_SCOPES="openid profile axiomdb:read axiomdb:write"
BASE_IDP_AUDIENCE=square-experience
```

The verifier validates PASETO `v4.public`, Ed25519 signatures, issuer, audience, time bounds, `token_use=access`, and required scopes. Public keys are fetched from Base discovery and cached by the async client.
