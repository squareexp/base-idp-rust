use serde::{Deserialize, Serialize};

pub const DEFAULT_AUDIENCE: &str = "square-experience";
pub const DEFAULT_IMPLICIT_ASSERTION: &str = "square-experience:idp:access:v1";

#[derive(Clone, Debug)]
pub struct Config {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub audience: String,
    pub required_scope: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, crate::Error> {
        Ok(Self {
            issuer: required_env("BASE_IDP_ISSUER")?
                .trim_end_matches('/')
                .to_string(),
            client_id: required_env("BASE_IDP_CLIENT_ID")?,
            client_secret: std::env::var("BASE_IDP_CLIENT_SECRET")
                .ok()
                .filter(|value| !value.is_empty()),
            redirect_uri: required_env("BASE_IDP_REDIRECT_URI")?,
            scopes: split_scopes(
                &std::env::var("BASE_IDP_SCOPES").unwrap_or_else(|_| "openid profile".to_string()),
            ),
            audience: std::env::var("BASE_IDP_AUDIENCE")
                .unwrap_or_else(|_| DEFAULT_AUDIENCE.to_string()),
            required_scope: std::env::var("BASE_IDP_REQUIRED_SCOPE")
                .ok()
                .filter(|value| !value.is_empty()),
        })
    }

    pub fn normalized(mut self) -> Self {
        self.issuer = self.issuer.trim_end_matches('/').to_string();
        if self.audience.is_empty() {
            self.audience = DEFAULT_AUDIENCE.to_string();
        }
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct AuthorizeOptions {
    pub response_type: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub additional_parameters: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default)]
pub struct TokenOptions {
    pub code: String,
    pub code_verifier: Option<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RefreshOptions {
    pub refresh_token: String,
    pub scopes: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default)]
pub struct VerifyOptions {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub required_scope: Option<String>,
    pub max_clock_skew_seconds: i64,
    pub implicit_assertion: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub paseto_public_key_endpoint: String,
    pub token_format: String,
    pub paseto_purpose: String,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKey {
    pub kid: String,
    pub alg: String,
    pub kty: String,
    pub crv: String,
    pub public_key_base64: String,
    #[serde(default)]
    pub implicit_assertion: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeySet {
    pub keys: Vec<PublicKey>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token_expires_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AccountContext {
    pub kind: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: String,
    pub nbf: String,
    pub iat: String,
    pub jti: String,
    pub gid: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub token_use: String,
    pub sid: String,
    pub ctx: AccountContext,
    pub role: String,
    #[serde(default)]
    pub ent: Vec<String>,
    #[serde(default)]
    pub ev: Option<String>,
    pub aal: i64,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub scp: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub id: String,
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: String,
    pub scopes: Vec<String>,
    pub account_context: AccountContext,
    pub claims: AccessClaims,
}

pub fn split_scopes(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_string).collect()
}

pub fn join_scopes(scopes: &[String]) -> String {
    scopes.join(" ")
}

fn required_env(name: &str) -> Result<String, crate::Error> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| crate::Error::InvalidConfig(format!("{name} is required")))
}
