// POST /oauth/token — Token endpoint

use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use mcpshield_db::AccessToken;

use crate::crypto::{random_base64url, sha256_hex, unix_timestamp_secs, verify_pkce};
use crate::handler::{extract_client_ip, AppState};

const CODE_VERIFIER_MIN_LEN: usize = 43;
const CODE_VERIFIER_MAX_LEN: usize = 128;
/// Argon2 long-input DoS cap — no legitimate credential exceeds 1 KiB
const MAX_SECRET_BYTES: usize = 1024;
/// client_id is generated as base64url(16 bytes) = 22 chars; 256 is a generous cap
const MAX_CLIENT_ID_BYTES: usize = 256;

#[derive(Debug, Deserialize, Default)]
pub struct TokenForm {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

fn token_error(status: StatusCode, error: &str) -> Response {
    let body = serde_json::json!({"error": error}).to_string();
    axum::http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .header("www-authenticate", "Basic realm=\"MCPShield\"")
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// Extract client_id and client_secret from Basic Authorization header.
fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded_str.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

pub async fn post_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let ip = extract_client_ip(&headers);
    let now_for_rate = unix_timestamp_secs();

    // 1. Extract client_id + client_secret (Basic takes priority)
    let (client_id, client_secret) = if let Some((id, secret)) = extract_basic_auth(&headers) {
        (id, secret)
    } else {
        match (form.client_id.clone(), form.client_secret.clone()) {
            (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => (id, secret),
            _ => {
                return token_error(StatusCode::UNAUTHORIZED, "invalid_client");
            }
        }
    };

    // 2. Cap credential lengths before any Argon2 or DB work
    if client_id.len() > MAX_CLIENT_ID_BYTES {
        return token_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    if client_secret.len() > MAX_SECRET_BYTES {
        return token_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }

    // Rate-limit per IP before any expensive work
    if !state.rate_limiter.allow(&ip, now_for_rate) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("content-type", "application/json"), ("retry-after", "60"), ("cache-control", "no-store")],
            r#"{"error":"too_many_requests"}"#,
        )
            .into_response();
    }

    // 3. Check grant_type
    let grant_type = form.grant_type.as_deref().unwrap_or("");
    if grant_type != "authorization_code" {
        return token_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }

    // 4. Extract and validate code_verifier — length (RFC 7636 §4.1) and character set
    let code_verifier = match form.code_verifier.as_deref() {
        Some(v)
            if v.len() >= CODE_VERIFIER_MIN_LEN
                && v.len() <= CODE_VERIFIER_MAX_LEN
                && v.bytes().all(|b| {
                    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
                }) =>
        {
            v.to_string()
        }
        _ => return token_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };

    // 5. Extract code
    let code = match form.code.as_deref() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return token_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };

    // 6. Extract redirect_uri
    let redirect_uri = match form.redirect_uri.as_deref() {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => return token_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };

    let now = unix_timestamp_secs();

    // 7. Look up the client (needed for secret_hash)
    let client_info = match state.db.get_client_auth_info(&client_id).await {
        Ok(Some(info)) => info,
        Ok(None) => return token_error(StatusCode::UNAUTHORIZED, "invalid_client"),
        Err(e) => {
            tracing::error!(err = %e, "token: db error looking up client");
            return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let stored_hash = client_info.client_secret_hash;

    // 8. Look up the auth code (validates client ownership, expiry, and single-use flag)
    let auth_code = match state.db.get_auth_code(&code, &client_id, now).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            state.rate_limiter.record_failure(&ip, now_for_rate);
            return token_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }
        Err(e) => {
            tracing::error!(err = %e, "token: db error looking up auth code");
            return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };
    let stored_redirect_uri = auth_code.redirect_uri;
    let code_challenge = auth_code.code_challenge;
    let code_agent_id = auth_code.agent_id;

    // 9. Validate redirect_uri before consuming the code
    if redirect_uri != stored_redirect_uri {
        state.rate_limiter.record_failure(&ip, now_for_rate);
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    // 10. Verify PKCE before consuming the code
    if !verify_pkce(&code_verifier, &code_challenge) {
        state.rate_limiter.record_failure(&ip, now_for_rate);
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    // 11. Atomic single-use gate — move this BEFORE Argon2 so a losing race is rejected
    // cheaply without burning server-side Argon2 CPU. A stolen code with the wrong
    // client_secret is still rejected in step 12; it just never triggers Argon2.
    match state.db.mark_auth_code_used(&code).await {
        Ok(true) => {}
        Ok(false) => {
            state.rate_limiter.record_failure(&ip, now_for_rate);
            return token_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }
        Err(e) => {
            tracing::error!(err = %e, "token: db error marking code used");
            return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    }

    // 12. Verify client_secret — Argon2 only runs after winning the single-use gate
    let parsed_hash = match PasswordHash::new(&stored_hash) {
        Ok(h) => h,
        Err(_) => return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    if Argon2::default()
        .verify_password(client_secret.as_bytes(), &parsed_hash)
        .is_err()
    {
        state.rate_limiter.record_failure(&ip, now_for_rate);
        return token_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    state.rate_limiter.record_success(&ip);

    // 13. Issue access token
    let token = random_base64url(32);
    let token_hash = sha256_hex(&token);
    let expires_at = now + 3600;

    if let Err(e) = state
        .db
        .insert_access_token(&AccessToken {
            token_hash: token_hash.clone(),
            client_id: client_id.clone(),
            agent_id: code_agent_id.clone(),
            expires_at,
            created_at: now,
        })
        .await
    {
        tracing::error!(err = %e, "token: db error inserting access token");
        return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    }

    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(axum::body::Body::from(
            serde_json::to_string(&TokenResponse {
                access_token: token,
                token_type: "Bearer".to_string(),
                expires_in: 3600,
            })
            .expect("TokenResponse is always serialisable"),
        ))
        .unwrap()
}
