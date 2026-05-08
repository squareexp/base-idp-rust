use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::{
    authorize_url, verify_paseto_v4_public, AuthorizeOptions, Config, Error, Metadata, Principal,
    PublicKeySet, RefreshOptions, TokenOptions, TokenPair, VerifyOptions,
};

#[derive(Clone)]
pub struct SquareIdpClient {
    config: Config,
    http: reqwest::Client,
    metadata_cache: Arc<RwLock<Option<Metadata>>>,
    key_cache: Arc<RwLock<Option<(PublicKeySet, Instant)>>>,
    key_cache_ttl: Duration,
}

impl SquareIdpClient {
    pub fn new(config: Config) -> Result<Self, Error> {
        let config = config.normalized();
        if config.issuer.is_empty() || config.client_id.is_empty() || config.redirect_uri.is_empty()
        {
            return Err(Error::InvalidConfig(
                "issuer, client_id, and redirect_uri are required".to_string(),
            ));
        }
        Ok(Self {
            config,
            http: reqwest::Client::new(),
            metadata_cache: Arc::new(RwLock::new(None)),
            key_cache: Arc::new(RwLock::new(None)),
            key_cache_ttl: Duration::from_secs(300),
        })
    }

    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    pub fn with_key_cache_ttl(mut self, ttl: Duration) -> Self {
        self.key_cache_ttl = ttl;
        self
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn authorize_url(&self, options: AuthorizeOptions) -> Result<String, Error> {
        authorize_url(&self.config, options)
    }

    pub async fn discovery(&self, force: bool) -> Result<Metadata, Error> {
        if !force {
            if let Some(metadata) = self
                .metadata_cache
                .read()
                .ok()
                .and_then(|cache| cache.clone())
            {
                return Ok(metadata);
            }
        }

        let endpoint = format!(
            "{}/.well-known/square-identity",
            self.config.issuer.trim_end_matches('/')
        );
        let metadata = self
            .http
            .get(endpoint)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|err| Error::Discovery(err.to_string()))?
            .error_for_status()
            .map_err(|err| Error::Discovery(err.to_string()))?
            .json::<Metadata>()
            .await
            .map_err(|err| Error::Discovery(err.to_string()))?;

        if let Ok(mut cache) = self.metadata_cache.write() {
            *cache = Some(metadata.clone());
        }
        Ok(metadata)
    }

    pub async fn public_keys(&self, force: bool) -> Result<PublicKeySet, Error> {
        if !force {
            if let Some((keys, expires_at)) =
                self.key_cache.read().ok().and_then(|cache| cache.clone())
            {
                if Instant::now() < expires_at {
                    return Ok(keys);
                }
            }
        }

        let metadata = self.discovery(false).await?;
        let keys = self
            .http
            .get(metadata.paseto_public_key_endpoint)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|err| Error::KeyFetch(err.to_string()))?
            .error_for_status()
            .map_err(|err| Error::KeyFetch(err.to_string()))?
            .json::<PublicKeySet>()
            .await
            .map_err(|err| Error::KeyFetch(err.to_string()))?;

        if keys.keys.is_empty() {
            return Err(Error::KeyFetch(
                "Base returned an empty public key set".to_string(),
            ));
        }
        if let Ok(mut cache) = self.key_cache.write() {
            *cache = Some((keys.clone(), Instant::now() + self.key_cache_ttl));
        }
        Ok(keys)
    }

    pub async fn exchange_code(&self, options: TokenOptions) -> Result<TokenPair, Error> {
        if options.code.is_empty() {
            return Err(Error::TokenExchange(
                "authorization code is required".to_string(),
            ));
        }
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", options.code),
            ("client_id", self.config.client_id.clone()),
            (
                "redirect_uri",
                options
                    .redirect_uri
                    .unwrap_or_else(|| self.config.redirect_uri.clone()),
            ),
        ];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret.clone()));
        }
        if let Some(verifier) = options.code_verifier {
            form.push(("code_verifier", verifier));
        }
        self.post_token(form).await
    }

    pub async fn refresh(&self, options: RefreshOptions) -> Result<TokenPair, Error> {
        if options.refresh_token.is_empty() {
            return Err(Error::TokenExchange(
                "refresh token is required".to_string(),
            ));
        }
        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", options.refresh_token),
            ("client_id", self.config.client_id.clone()),
        ];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret.clone()));
        }
        if let Some(scopes) = options.scopes {
            form.push(("scope", scopes.join(" ")));
        }
        self.post_token(form).await
    }

    pub async fn verify_access_token(
        &self,
        token: &str,
        options: VerifyOptions,
    ) -> Result<Principal, Error> {
        let keys = self.public_keys(false).await?;
        verify_paseto_v4_public(token, &keys, &self.config, options)
    }

    async fn post_token(&self, form: Vec<(&str, String)>) -> Result<TokenPair, Error> {
        let metadata = self.discovery(false).await?;
        self.http
            .post(metadata.token_endpoint)
            .header("Accept", "application/json")
            .form(&form)
            .send()
            .await
            .map_err(|err| Error::TokenExchange(err.to_string()))?
            .error_for_status()
            .map_err(|err| Error::TokenExchange(err.to_string()))?
            .json::<TokenPair>()
            .await
            .map_err(|err| Error::TokenExchange(err.to_string()))
    }
}
