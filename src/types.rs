use serde::{Deserialize, Serialize};

pub const DEFAULT_AUDIENCE: &str = "square-experience";
pub const DEFAULT_ISSUER: &str = "https://authlayer.square.com";
pub const DEFAULT_LOCAL_ISSUER: &str = "http://localhost:8080";
pub const DEFAULT_IMPLICIT_ASSERTION: &str = "square-experience:idp:access:v1";

#[derive(Clone, Debug)]
pub struct Config {
    pub key: String,
    pub secret: Option<String>,
    pub issuer: String,

    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub audience: String,
    pub required_scope: Option<String>,
    pub confidential: bool,
    pub allowed_scopes: Vec<String>,
    pub resolved: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientConfigResponse {
    pub client_id: String,
    #[serde(default)]
    pub anon_key: String,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub app_domain: String,
    #[serde(default)]
    pub logo_url: Option<String>,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub paseto_public_key_endpoint: String,
    #[serde(default)]
    pub allowed_redirect_uris: Vec<String>,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub allowed_auth_methods: Vec<String>,
    #[serde(default)]
    pub requested_claims: Vec<String>,
    #[serde(default)]
    pub confidential: bool,
    #[serde(default)]
    pub status: String,
}

impl Config {
    pub fn from_env() -> Result<Self, crate::Error> {
        let client_id = required_env("BASE_IDP_CLIENT_ID")?;
        let issuer = resolve_issuer_from_env();
        Ok(Self {
            key: client_id.clone(),
            issuer,
            secret: std::env::var("BASE_IDP_CLIENT_SECRET")
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    std::env::var("BASE_IDP_SECRET")
                        .ok()
                        .filter(|value| !value.is_empty())
                }),
            client_id,
            redirect_uri: String::new(),
            scopes: Vec::new(),
            audience: String::new(),
            required_scope: None,
            confidential: false,
            allowed_scopes: Vec::new(),
            resolved: false,
        })
    }

    pub fn new(key: &str, issuer: &str) -> Self {
        Self {
            key: key.to_string(),
            issuer: issuer.trim_end_matches('/').to_string(),
            secret: None,
            client_id: String::new(),
            redirect_uri: String::new(),
            scopes: Vec::new(),
            audience: String::new(),
            required_scope: None,
            confidential: false,
            allowed_scopes: Vec::new(),
            resolved: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AuthorizeOptions {
    pub response_type: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub redirect_uri: Option<String>,
    pub auth_session_id: Option<String>,
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

pub fn resolve_issuer_from_env() -> String {
    if let Ok(value) = std::env::var("BASE_IDP_ISSUER") {
        if !value.trim().is_empty() {
            return value.trim_end_matches('/').to_string();
        }
    }
    let node_env = std::env::var("NODE_ENV").ok();
    let app_env = std::env::var("APP_ENV").ok();
    if matches_env(node_env.as_deref()) || matches_env(app_env.as_deref()) {
        DEFAULT_LOCAL_ISSUER.to_string()
    } else {
        DEFAULT_ISSUER.to_string()
    }
}

fn matches_env(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_lowercase()).as_deref(),
        Some("dev" | "development" | "local")
    )
}
