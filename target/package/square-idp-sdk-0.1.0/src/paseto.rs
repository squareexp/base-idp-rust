use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::{
    AccessClaims, Config, Error, Principal, PublicKeySet, VerifyOptions, DEFAULT_AUDIENCE,
    DEFAULT_IMPLICIT_ASSERTION,
};

const HEADER: &[u8] = b"v4.public.";

#[derive(Debug, Deserialize)]
struct Footer {
    kid: Option<String>,
    alg: Option<String>,
    typ: Option<String>,
}

pub fn unsafe_footer_kid(token: &str) -> Result<String, Error> {
    let footer = unsafe_footer(token)?;
    footer
        .kid
        .ok_or_else(|| Error::InvalidToken("footer is missing kid".to_string()))
}

pub fn bearer_token(header: Option<&str>) -> Result<&str, Error> {
    let header = header.ok_or(Error::MissingBearer)?;
    let mut parts = header.split_whitespace();
    let scheme = parts.next().ok_or(Error::MissingBearer)?;
    let token = parts.next().ok_or(Error::MissingBearer)?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || parts.next().is_some() {
        return Err(Error::MissingBearer);
    }
    Ok(token)
}

pub fn verify_paseto_v4_public(
    token: &str,
    key_set: &PublicKeySet,
    config: &Config,
    options: VerifyOptions,
) -> Result<Principal, Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 || parts[0] != "v4" || parts[1] != "public" {
        return Err(Error::InvalidToken(
            "token is not PASETO v4.public".to_string(),
        ));
    }

    let payload = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|err| Error::InvalidToken(format!("decode payload: {err}")))?;
    let footer_bytes = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|err| Error::InvalidToken(format!("decode footer: {err}")))?;
    if payload.len() <= 64 {
        return Err(Error::InvalidToken("payload is too short".to_string()));
    }

    let footer: Footer = serde_json::from_slice(&footer_bytes)
        .map_err(|err| Error::InvalidToken(format!("decode footer json: {err}")))?;
    let kid = footer
        .kid
        .ok_or_else(|| Error::InvalidToken("footer is missing kid".to_string()))?;
    if footer.alg.as_deref() != Some("v4.public") || footer.typ.as_deref() != Some("paseto") {
        return Err(Error::InvalidToken(
            "footer is not a Square v4.public footer".to_string(),
        ));
    }

    let public_key = key_set
        .keys
        .iter()
        .find(|key| key.kid == kid && key.alg == "v4.public" && key.crv == "Ed25519")
        .ok_or_else(|| {
            Error::InvalidToken(format!("key id {kid} is not present in the Base key set"))
        })?;
    let public_key_bytes = decode_base64_flexible(&public_key.public_key_base64)?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidToken("Ed25519 public key has invalid size".to_string()))?,
    )
    .map_err(|err| Error::InvalidToken(format!("invalid Ed25519 public key: {err}")))?;

    let (message, signature_bytes) = payload.split_at(payload.len() - 64);
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|err| Error::InvalidToken(format!("invalid signature bytes: {err}")))?;
    let implicit = options
        .implicit_assertion
        .as_deref()
        .unwrap_or(DEFAULT_IMPLICIT_ASSERTION);
    let pae = pre_auth_encode(&[HEADER, message, &footer_bytes, implicit.as_bytes()]);
    verifying_key
        .verify(&pae, &signature)
        .map_err(|_| Error::InvalidToken("signature verification failed".to_string()))?;

    let claims: AccessClaims = serde_json::from_slice(message)
        .map_err(|err| Error::InvalidToken(format!("decode claims: {err}")))?;
    validate_claims(&claims, config, &options)?;

    Ok(Principal {
        id: claims.gid.clone(),
        subject: claims.sub.clone(),
        email: claims.email.clone(),
        name: claims.name.clone(),
        role: claims.role.clone(),
        scopes: claims.scp.clone(),
        account_context: claims.ctx.clone(),
        claims,
    })
}

fn unsafe_footer(token: &str) -> Result<Footer, Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 || parts[0] != "v4" || parts[1] != "public" {
        return Err(Error::InvalidToken(
            "token is not PASETO v4.public".to_string(),
        ));
    }
    let footer_bytes = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|err| Error::InvalidToken(format!("decode footer: {err}")))?;
    serde_json::from_slice(&footer_bytes)
        .map_err(|err| Error::InvalidToken(format!("decode footer json: {err}")))
}

fn validate_claims(
    claims: &AccessClaims,
    config: &Config,
    options: &VerifyOptions,
) -> Result<(), Error> {
    let option_issuer = options
        .issuer
        .as_deref()
        .map(|value| value.trim_end_matches('/'));
    let issuer = option_issuer.unwrap_or_else(|| config.issuer.trim_end_matches('/'));
    let audience = options
        .audience
        .as_deref()
        .unwrap_or(if config.audience.is_empty() {
            DEFAULT_AUDIENCE
        } else {
            &config.audience
        });
    let required_scope = options
        .required_scope
        .as_deref()
        .or(config.required_scope.as_deref());
    let skew = if options.max_clock_skew_seconds > 0 {
        options.max_clock_skew_seconds
    } else {
        30
    };

    if claims.token_use != "access" {
        return Err(Error::InvalidToken("token_use must be access".to_string()));
    }
    if claims.iss != issuer || claims.aud != audience {
        return Err(Error::InvalidToken(
            "issuer or audience mismatch".to_string(),
        ));
    }
    if claims.gid.is_empty()
        || claims.sub.is_empty()
        || claims.sid.is_empty()
        || claims.role.is_empty()
        || claims.ctx.kind.is_empty()
    {
        return Err(Error::InvalidToken(
            "required identity claims are missing".to_string(),
        ));
    }

    let exp = DateTime::parse_from_rfc3339(&claims.exp)
        .map_err(|err| Error::InvalidToken(format!("invalid exp: {err}")))?
        .with_timezone(&Utc);
    let nbf = DateTime::parse_from_rfc3339(&claims.nbf)
        .map_err(|err| Error::InvalidToken(format!("invalid nbf: {err}")))?
        .with_timezone(&Utc);
    let now = Utc::now();
    if exp <= now - Duration::seconds(skew) {
        return Err(Error::InvalidToken("access token expired".to_string()));
    }
    if nbf > now + Duration::seconds(skew) {
        return Err(Error::InvalidToken(
            "access token is not valid yet".to_string(),
        ));
    }
    if let Some(scope) = required_scope {
        if !claims.scp.iter().any(|value| value == scope) {
            return Err(Error::InsufficientScope(scope.to_string()));
        }
    }
    Ok(())
}

fn pre_auth_encode(pieces: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + pieces.iter().map(|piece| piece.len() + 8).sum::<usize>());
    out.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        out.extend_from_slice(&(piece.len() as u64).to_le_bytes());
        out.extend_from_slice(piece);
    }
    out
}

fn decode_base64_flexible(value: &str) -> Result<Vec<u8>, Error> {
    for engine in [URL_SAFE_NO_PAD, URL_SAFE, STANDARD_NO_PAD, STANDARD] {
        if let Ok(decoded) = engine.decode(value) {
            return Ok(decoded);
        }
    }
    Err(Error::InvalidToken("decode public key failed".to_string()))
}
