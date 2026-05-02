// POST /oauth/register — Dynamic Client Registration (RFC 7591)

use std::sync::Arc;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use mcpshield_db::OAuthClient;

use mcpshield_db::StoreError;

use crate::admin::require_admin;
use crate::crypto::{random_base64url, unix_timestamp_secs};
use crate::handler::{AppState, PeerIp};

const CLIENT_NAME_MAX_LEN: usize = 256;
const MAX_REDIRECT_URIS: usize = 10;
const MAX_REDIRECT_URI_LEN: usize = 2048;

#[derive(Debug, Deserialize)]
pub struct DcrRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DcrResponse {
    pub client_id: String,
    pub client_secret: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub agent_id: String,
}

pub async fn post_register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Json(req): Json<DcrRequest>,
) -> Response {
    if let Err(resp) = require_admin(&state, &headers, peer_ip).await {
        return resp;
    }

    // Validate client_name length
    if req.client_name.trim().is_empty() || req.client_name.len() > CLIENT_NAME_MAX_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_client_metadata", "error_description": "client_name must be 1-256 characters"})),
        )
            .into_response();
    }

    // Validate redirect_uris
    if req.redirect_uris.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_redirect_uri", "error_description": "redirect_uris must not be empty"})),
        )
            .into_response();
    }
    if req.redirect_uris.len() > MAX_REDIRECT_URIS {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_redirect_uri", "error_description": "too many redirect_uris"})),
        )
            .into_response();
    }

    for uri in &req.redirect_uris {
        if uri.len() > MAX_REDIRECT_URI_LEN || !is_valid_redirect_uri(uri) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_redirect_uri",
                    "error_description": "redirect_uri must be https:// or http://localhost"
                })),
            )
                .into_response();
        }
    }

    // Generate credentials
    let client_id = random_base64url(16);
    let client_secret = random_base64url(32);
    let agent_id = Uuid::new_v4().to_string();

    // Hash client_secret with Argon2id
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let secret_hash = match argon2.hash_password(client_secret.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            tracing::error!(err = %e, "dcr: failed to hash client secret");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let now = unix_timestamp_secs();

    if let Err(e) = state
        .db
        .insert_oauth_client(&OAuthClient {
            client_id: client_id.clone(),
            agent_id: agent_id.clone(),
            client_secret_hash: secret_hash.clone(),
            client_name: req.client_name.clone(),
            redirect_uris: req.redirect_uris.clone(),
            created_at: now,
        })
        .await
    {
        if matches!(e, StoreError::Conflict(_)) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "client_already_exists"})),
            )
                .into_response();
        }
        tracing::error!(err = %e, "dcr: db error inserting client");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
    }

    (
        StatusCode::CREATED,
        Json(DcrResponse {
            client_id,
            client_secret,
            client_name: req.client_name,
            redirect_uris: req.redirect_uris,
            agent_id,
        }),
    )
        .into_response()
}

/// Validate that a redirect URI is https:// or http://localhost[/...]
/// and has no fragment (#).
pub fn is_valid_redirect_uri(uri: &str) -> bool {
    if uri.contains('#') {
        return false;
    }
    if uri.starts_with("https://") {
        return true;
    }
    if uri.starts_with("http://localhost") {
        // Must be http://localhost followed by end-of-string, path, port, or nothing
        // — reject bare '?' to avoid registering URIs with no path component
        let rest = &uri["http://localhost".len()..];
        return rest.is_empty() || rest.starts_with('/') || rest.starts_with(':');
    }
    false
}
