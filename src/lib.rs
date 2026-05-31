mod paseto;
mod types;

#[cfg(feature = "reqwest")]
mod client;

pub use paseto::{bearer_token, unsafe_footer_kid, verify_paseto_v4_public};
pub use types::*;

#[cfg(feature = "reqwest")]
pub use client::BaseIdPClient;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("base idp invalid config: {0}")]
    InvalidConfig(String),
    #[error("base idp config discovery failed: {0}")]
    ConfigDiscovery(String),
    #[error("base idp discovery failed: {0}")]
    Discovery(String),
    #[error("base idp key fetch failed: {0}")]
    KeyFetch(String),
    #[error("base idp token exchange failed: {0}")]
    TokenExchange(String),
    #[error("base idp missing bearer token")]
    MissingBearer,
    #[error("base idp invalid token: {0}")]
    InvalidToken(String),
    #[error("base idp insufficient scope: {0}")]
    InsufficientScope(String),
}

pub fn authorize_url(config: &Config, options: AuthorizeOptions) -> Result<String, Error> {
    if config.client_id.is_empty() {
        return Err(Error::InvalidConfig(
            "client is not resolved; call resolve_config".to_string(),
        ));
    }
    let mut url = url::Url::parse(&format!(
        "{}/oauth2/authorize",
        config.issuer.trim_end_matches('/')
    ))
    .map_err(|err| Error::InvalidConfig(err.to_string()))?;
    let scopes = options.scopes.unwrap_or_else(|| config.scopes.clone());
    {
        let mut query = url.query_pairs_mut();
        query.append_pair(
            "response_type",
            options.response_type.as_deref().unwrap_or("code"),
        );
        query.append_pair("client_id", &config.client_id);
        query.append_pair(
            "redirect_uri",
            options
                .redirect_uri
                .as_deref()
                .unwrap_or(&config.redirect_uri),
        );
        query.append_pair("scope", &join_scopes(&scopes));
        if let Some(state) = options.state {
            query.append_pair("state", &state);
        }
        if let Some(nonce) = options.nonce {
            query.append_pair("nonce", &nonce);
        }
        if let Some(auth_session_id) = options.auth_session_id {
            query.append_pair("auth_session_id", &auth_session_id);
        }
        if let Some(challenge) = options.code_challenge {
            query.append_pair("code_challenge", &challenge);
            query.append_pair(
                "code_challenge_method",
                options.code_challenge_method.as_deref().unwrap_or("S256"),
            );
        }
        for (key, value) in options.additional_parameters {
            if !key.is_empty() && !value.is_empty() {
                query.append_pair(&key, &value);
            }
        }
    }
    Ok(url.to_string())
}
