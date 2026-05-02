// Admin API — authenticated with Authorization: Basic admin:{password}

use std::net::IpAddr;
use std::sync::Arc;

/// Argon2 long-input DoS cap — no legitimate credential exceeds 1 KiB
const MAX_PASSWORD_BYTES: usize = 1024;
/// Reasonable cap to prevent oversized admin path parameters
const MAX_TOOL_NAME_BYTES: usize = 256;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use uuid::Uuid;

use mcpshield_db::PolicyRule;

use crate::crypto::unix_timestamp_secs;
use crate::handler::{extract_client_ip, AppState, PeerIp};

/// Verify admin Basic auth. Returns Ok(()) or an error Response.
pub async fn require_admin(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
) -> Result<(), Response> {
    let (username, password) = match extract_basic(headers) {
        Some(pair) => pair,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Basic realm=\"MCPShield Admin\"")],
                "Unauthorized",
            )
                .into_response());
        }
    };

    // Cap password length before Argon2 to prevent long-input DoS
    if password.len() > MAX_PASSWORD_BYTES {
        return Err((
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Basic realm=\"MCPShield Admin\"")],
            "Unauthorized",
        )
            .into_response());
    }

    let ip = extract_client_ip(peer_ip);
    let now = unix_timestamp_secs();

    // Rate-limit on the admin-specific limiter — separate from the OAuth limiter so
    // a successful OAuth flow cannot reset the admin failure counter.
    if !state.admin_rate_limiter.allow(&ip, now) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "60")],
            "Too many requests",
        )
            .into_response());
    }

    let stored_username = match state.db.get_setup_value("admin_username").await {
        Ok(Some(u)) => u,
        _ => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "setup incomplete").into_response());
        }
    };
    let stored_hash = match state.db.get_setup_value("admin_password_hash").await {
        Ok(Some(h)) => h,
        _ => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "setup incomplete").into_response());
        }
    };

    use sha2::{Digest, Sha256};
    let username_ok = constant_time_eq::constant_time_eq(
        Sha256::digest(username.as_bytes()).as_slice(),
        Sha256::digest(stored_username.as_bytes()).as_slice(),
    );

    // Record failure before the hash parse so a corrupted hash doesn't silently skip counting.
    let parsed_hash = match PasswordHash::new(&stored_hash) {
        Ok(h) => h,
        Err(_) => {
            state.admin_rate_limiter.record_failure(&ip, now);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "setup error").into_response());
        }
    };

    let password_ok = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    if !username_ok || !password_ok {
        state.admin_rate_limiter.record_failure(&ip, now);
        return Err((
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Basic realm=\"MCPShield Admin\"")],
            "Unauthorized",
        )
            .into_response());
    }

    state.admin_rate_limiter.record_success(&ip);
    Ok(())
}

fn extract_basic(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded_str.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

// GET /admin/agents
pub async fn list_agents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    let clients = match state.db.list_oauth_clients().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(err = %e, "admin: db error listing agents");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let agents: Vec<serde_json::Value> = clients
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "client_id": c.client_id,
                "agent_id": c.agent_id,
                "client_name": c.client_name,
                "redirect_uris": c.redirect_uris,
                "created_at": c.created_at
            })
        })
        .collect();

    Json(agents).into_response()
}

// DELETE /admin/agents/{agent_id}
pub async fn delete_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(agent_id): Path<String>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    if Uuid::parse_str(&agent_id).is_err() {
        return (StatusCode::BAD_REQUEST, "agent_id must be a UUID").into_response();
    }

    match state.db.delete_oauth_client(&agent_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error deleting agent");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// GET /admin/agents/{agent_id}/policy
pub async fn get_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(agent_id): Path<String>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    if Uuid::parse_str(&agent_id).is_err() {
        return (StatusCode::BAD_REQUEST, "agent_id must be a UUID").into_response();
    }

    let rules = match state.db.list_policy_rules(&agent_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(err = %e, "admin: db error listing policy rules");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let rules: Vec<serde_json::Value> = rules
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "agent_id": r.agent_id,
                "tool_name": r.tool_name,
                "allowed": r.allowed
            })
        })
        .collect();

    Json(rules).into_response()
}

#[derive(Deserialize)]
pub struct PolicyRuleRequest {
    pub tool_name: String,
    pub allowed: bool,
}

// POST /admin/agents/{agent_id}/policy
pub async fn set_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(agent_id): Path<String>,
    Json(body): Json<PolicyRuleRequest>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    if Uuid::parse_str(&agent_id).is_err() {
        return (StatusCode::BAD_REQUEST, "agent_id must be a UUID").into_response();
    }

    if body.tool_name.is_empty() || body.tool_name.len() > MAX_TOOL_NAME_BYTES {
        return (StatusCode::BAD_REQUEST, "tool_name must be 1–256 characters").into_response();
    }

    let now = unix_timestamp_secs();
    match state
        .db
        .upsert_policy_rule(&PolicyRule {
            agent_id: agent_id.clone(),
            tool_name: body.tool_name.clone(),
            allowed: body.allowed,
            created_at: now,
        })
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error setting policy");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// DELETE /admin/agents/{agent_id}/policy/{tool_name}
pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path((agent_id, tool_name)): Path<(String, String)>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    if Uuid::parse_str(&agent_id).is_err() {
        return (StatusCode::BAD_REQUEST, "agent_id must be a UUID").into_response();
    }

    if tool_name.is_empty() || tool_name.len() > MAX_TOOL_NAME_BYTES {
        return (StatusCode::BAD_REQUEST, "tool_name must be 1–256 characters").into_response();
    }

    match state.db.delete_policy_rule(&agent_id, &tool_name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error deleting policy");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}
