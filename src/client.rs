use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::{
    authorize_url, verify_paseto_v4_public, AuthorizeOptions, ClientConfigResponse, Config, Error,
    Metadata, Principal, PublicKeySet, RefreshOptions, TokenOptions, TokenPair, VerifyOptions,
};

#[derive(Clone)]
pub struct BaseIdPClient {
    config: Arc<RwLock<Config>>,
    http: reqwest::Client,
    metadata_cache: Arc<RwLock<Option<Metadata>>>,
    key_cache: Arc<RwLock<Option<(PublicKeySet, Instant)>>>,
    key_cache_ttl: Duration,
}

impl BaseIdPClient {
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.client_id.is_empty() && config.key.is_empty() {
            return Err(Error::InvalidConfig(
                "BASE_IDP_CLIENT_ID is required".to_string(),
            ));
        }
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
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

    pub async fn resolve_config(&self) -> Result<Config, Error> {
        let mut cfg = self
            .config
            .write()
            .map_err(|err| Error::InvalidConfig(format!("lock poisoned: {err}")))?;
        if cfg.resolved {
            return Ok(cfg.clone());
        }

        let issuer = if cfg.issuer.is_empty() {
            crate::types::resolve_issuer_from_env()
        } else {
            cfg.issuer.trim_end_matches('/').to_string()
        };

        let response: ClientConfigResponse = if !cfg.client_id.is_empty() {
            self.http
                .post(format!("{issuer}/v1/client-config"))
                .header("Accept", "application/json")
                .json(&serde_json::json!({
                    "client_id": cfg.client_id,
                    "secret": cfg.secret,
                }))
                .send()
                .await
                .map_err(|err| Error::ConfigDiscovery(err.to_string()))?
                .error_for_status()
                .map_err(|err| Error::ConfigDiscovery(err.to_string()))?
                .json()
                .await
                .map_err(|err| Error::ConfigDiscovery(err.to_string()))?
        } else {
            let url = format!("{issuer}/v1/client-config?key={}", urlencoding(&cfg.key));
            self.http
                .get(&url)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|err| Error::ConfigDiscovery(err.to_string()))?
                .error_for_status()
                .map_err(|err| Error::ConfigDiscovery(err.to_string()))?
                .json()
                .await
                .map_err(|err| Error::ConfigDiscovery(err.to_string()))?
        };

        cfg.issuer = response.issuer.trim_end_matches('/').to_string();
        if cfg.key.is_empty() {
            cfg.key = response.client_id.clone();
        }
        cfg.client_id = response.client_id;
        cfg.confidential = response.confidential;
        cfg.allowed_scopes = response.allowed_scopes.clone();
        if cfg.redirect_uri.is_empty() {
            cfg.redirect_uri = response
                .allowed_redirect_uris
                .first()
                .cloned()
                .unwrap_or_default();
        }
        if cfg.scopes.is_empty() {
            cfg.scopes = response.allowed_scopes;
        }
        if cfg.audience.is_empty() {
            cfg.audience = crate::DEFAULT_AUDIENCE.to_string();
        }
        cfg.resolved = true;

        Ok(cfg.clone())
    }

    pub fn authorize_url(&self, options: AuthorizeOptions) -> Result<String, Error> {
        let cfg = self
            .config
            .read()
            .map_err(|err| Error::InvalidConfig(format!("lock poisoned: {err}")))?;
        if !cfg.resolved {
            return Err(Error::InvalidConfig(
                "client not resolved; call resolve_config() first or use an async method"
                    .to_string(),
            ));
        }
        authorize_url(&cfg, options)
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

        let cfg = self
            .config
            .read()
            .map_err(|_| Error::InvalidConfig("lock poisoned".to_string()))?;
        let endpoint = format!(
            "{}/.well-known/square-identity",
            cfg.issuer.trim_end_matches('/')
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
        self.resolve_config().await?;
        if options.code.is_empty() {
            return Err(Error::TokenExchange(
                "authorization code is required".to_string(),
            ));
        }
        let cfg = self
            .config
            .read()
            .map_err(|_| Error::InvalidConfig("lock poisoned".to_string()))?;
        let mut form = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", options.code),
            ("client_id", cfg.client_id.clone()),
            (
                "redirect_uri",
                options
                    .redirect_uri
                    .unwrap_or_else(|| cfg.redirect_uri.clone()),
            ),
        ];
        if let Some(secret) = &cfg.secret {
            form.push(("client_secret", secret.clone()));
        }
        if let Some(verifier) = options.code_verifier {
            form.push(("code_verifier", verifier));
        }
        self.post_token(form).await
    }

    pub async fn refresh(&self, options: RefreshOptions) -> Result<TokenPair, Error> {
        self.resolve_config().await?;
        if options.refresh_token.is_empty() {
            return Err(Error::TokenExchange(
                "refresh token is required".to_string(),
            ));
        }
        let cfg = self
            .config
            .read()
            .map_err(|_| Error::InvalidConfig("lock poisoned".to_string()))?;
        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", options.refresh_token),
            ("client_id", cfg.client_id.clone()),
        ];
        if let Some(secret) = &cfg.secret {
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
        self.resolve_config().await?;
        let keys = self.public_keys(false).await?;
        let cfg = self
            .config
            .read()
            .map_err(|_| Error::InvalidConfig("lock poisoned".to_string()))?;
        verify_paseto_v4_public(token, &keys, &cfg, options)
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

fn urlencoding(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
