// Admin API — authenticated with Authorization: Basic admin:{password}

use std::net::IpAddr;
use std::sync::Arc;

/// Argon2 long-input DoS cap — no legitimate credential exceeds 1 KiB
const MAX_PASSWORD_BYTES: usize = 1024;
/// Reasonable cap to prevent oversized admin path parameters
const MAX_TOOL_NAME_BYTES: usize = 256;
/// Cap for outbound token endpoint responses — token responses are always tiny
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::STANDARD, Engine};
use mcpcondor_core::vault::VaultTokenData;
use mcpcondor_db::{AgentOverride, AgentOverrideKind, GlobalRule, Integration, Profile, ProfileRule};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto::unix_timestamp_secs;
use crate::downstream::DownstreamClient;
use crate::handler::{
    extract_client_ip, AppState, PeerIp, MAX_PENDING_INTEGRATION_ENTRIES,
    PENDING_INTEGRATION_TTL_SECS,
};

fn outbound_http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
}

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
                [("WWW-Authenticate", "Basic realm=\"MCPCondor Admin\"")],
                "Unauthorized",
            )
                .into_response());
        }
    };

    // Cap password length before Argon2 to prevent long-input DoS
    if password.len() > MAX_PASSWORD_BYTES {
        return Err((
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Basic realm=\"MCPCondor Admin\"")],
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
            [("WWW-Authenticate", "Basic realm=\"MCPCondor Admin\"")],
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
        Ok(true) => {
            state.bearer_cache.retain(|_, (aid, _, _)| aid.as_str() != agent_id.as_str());
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error deleting agent");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// DELETE /admin/agents/{agent_id}/tokens — revoke all active tokens without deleting the agent
pub async fn revoke_agent_tokens(
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

    match state.db.delete_agent_tokens(&agent_id).await {
        Ok(count) => {
            state.bearer_cache.retain(|_, (aid, _, _)| aid.as_str() != agent_id.as_str());
            Json(serde_json::json!({ "revoked": count })).into_response()
        }
        Err(e) => {
            tracing::error!(err = %e, "admin: db error revoking tokens");
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

    let overrides = match state.db.list_agent_overrides(&agent_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(err = %e, "admin: db error listing agent overrides");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let rules: Vec<serde_json::Value> = overrides
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
        .upsert_agent_override(&AgentOverride {
            agent_id: agent_id.clone(),
            tool_name: body.tool_name.clone(),
            allowed: body.allowed,
            kind: AgentOverrideKind::Static,
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

    match state.db.delete_agent_override(&agent_id, &tool_name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error deleting policy");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// ─── Profile Admin Handlers ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateProfileBody {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct SetRuleBody {
    pub tool_name: String,
    pub allowed: bool,
}

#[derive(Deserialize)]
pub struct BulkRuleBody {
    pub integration_slug: String,
    pub allowed: bool,
}

#[derive(Deserialize)]
pub struct SetGlobalRuleBody {
    pub tool_name: String,
    pub allowed: bool,
}

#[derive(Deserialize)]
pub struct SetOverrideBody {
    pub tool_name: String,
    pub allowed: bool,
    pub kind: String,
    pub expires_at: Option<i64>,
    pub remaining: Option<i64>,
}

#[derive(Deserialize)]
pub struct AssignProfileBody {
    pub profile_id: String,
}

// GET /admin/profiles
pub async fn list_profiles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    match state.db.list_profiles().await {
        Ok(profiles) => Json(profiles).into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error listing profiles");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// POST /admin/profiles
pub async fn create_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Json(body): Json<CreateProfileBody>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    if body.name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name must not be empty").into_response();
    }
    let id = Uuid::new_v4().to_string();
    let now = unix_timestamp_secs();
    let profile = Profile {
        id: id.clone(),
        name: body.name,
        description: body.description,
        is_default: false,
        created_at: now,
    };
    match state.db.insert_profile(&profile).await {
        Ok(()) => (StatusCode::CREATED, Json(profile)).into_response(),
        Err(mcpcondor_db::StoreError::Conflict(_)) => {
            (StatusCode::CONFLICT, "profile name already exists").into_response()
        }
        Err(e) => {
            tracing::error!(err = %e, "admin: db error creating profile");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// GET /admin/profiles/{id}
pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    match state.db.get_profile(&id).await {
        Ok(Some(p)) => Json(p).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error getting profile");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// PUT /admin/profiles/{id}
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
    Json(body): Json<CreateProfileBody>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    if body.name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name must not be empty").into_response();
    }
    match state.db.update_profile(&id, &body.name, body.description.as_deref()).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error updating profile");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// DELETE /admin/profiles/{id}
pub async fn delete_profile_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    // Check if it's the default profile
    match state.db.get_profile(&id).await {
        Ok(Some(p)) if p.is_default => {
            return (StatusCode::BAD_REQUEST, "cannot delete the default profile").into_response();
        }
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error looking up profile");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
        _ => {}
    }
    match state.db.delete_profile(&id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error deleting profile");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// POST /admin/profiles/{id}/rules
pub async fn set_profile_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
    Json(body): Json<SetRuleBody>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    if body.tool_name.is_empty() || body.tool_name.len() > MAX_TOOL_NAME_BYTES {
        return (StatusCode::BAD_REQUEST, "tool_name must be 1–256 characters").into_response();
    }
    let now = unix_timestamp_secs();
    let rule = ProfileRule {
        profile_id: id,
        tool_name: body.tool_name,
        allowed: body.allowed,
        created_at: now,
    };
    match state.db.upsert_profile_rule(&rule).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error setting profile rule");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// DELETE /admin/profiles/{id}/rules/{tool_name}
pub async fn delete_profile_rule_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path((id, tool_name)): Path<(String, String)>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    match state.db.delete_profile_rule(&id, &tool_name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error deleting profile rule");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// GET /admin/profiles/{id}/rules
pub async fn list_profile_rules_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    match state.db.list_profile_rules(&id).await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error listing profile rules");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// POST /admin/profiles/{id}/rules/bulk
pub async fn set_profile_rules_bulk(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
    Json(body): Json<BulkRuleBody>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    let slug = &body.integration_slug;
    let downstream = match state.downstreams.get(slug) {
        Some(d) => d.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let tools = downstream.list_tools().await;
    if tools.is_empty() {
        return (StatusCode::NOT_FOUND, "integration has no tools (not yet initialized)").into_response();
    }
    let tool_names: Vec<String> = tools
        .iter()
        .map(|t| format!("{}__{}", slug, t.name))
        .collect();
    let now = unix_timestamp_secs();
    match state.db.set_profile_rules_for_integration(&id, &tool_names, body.allowed, now).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error setting bulk profile rules");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// ─── Global Rules Handlers ─────────────────────────────────────────────────────

// GET /admin/global-rules
pub async fn list_global_rules_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    match state.db.list_global_rules().await {
        Ok(rules) => Json(rules).into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error listing global rules");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// POST /admin/global-rules
pub async fn set_global_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Json(body): Json<SetGlobalRuleBody>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    if body.tool_name.is_empty() || body.tool_name.len() > MAX_TOOL_NAME_BYTES {
        return (StatusCode::BAD_REQUEST, "tool_name must be 1–256 characters").into_response();
    }
    let now = unix_timestamp_secs();
    let rule = GlobalRule {
        tool_name: body.tool_name,
        allowed: body.allowed,
        created_at: now,
    };
    match state.db.upsert_global_rule(&rule).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error setting global rule");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// DELETE /admin/global-rules/{tool_name}
pub async fn delete_global_rule_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(tool_name): Path<String>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    match state.db.delete_global_rule(&tool_name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error deleting global rule");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// ─── Agent Override Handlers ───────────────────────────────────────────────────

// GET /admin/agents/{agent_id}/overrides
pub async fn list_agent_overrides_handler(
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
    match state.db.list_agent_overrides(&agent_id).await {
        Ok(overrides) => Json(overrides).into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error listing agent overrides");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// POST /admin/agents/{agent_id}/overrides
pub async fn set_agent_override(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(agent_id): Path<String>,
    Json(body): Json<SetOverrideBody>,
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
    let kind = match body.kind.as_str() {
        "static" => AgentOverrideKind::Static,
        "until" => match body.expires_at {
            Some(ea) => AgentOverrideKind::Until { expires_at: ea },
            None => return (StatusCode::BAD_REQUEST, "expires_at required for kind=until").into_response(),
        },
        "uses" => match body.remaining {
            Some(r) => AgentOverrideKind::Uses { remaining: r },
            None => return (StatusCode::BAD_REQUEST, "remaining required for kind=uses").into_response(),
        },
        _ => return (StatusCode::BAD_REQUEST, "kind must be 'static', 'until', or 'uses'").into_response(),
    };
    let now = unix_timestamp_secs();
    let override_ = AgentOverride {
        agent_id: agent_id.clone(),
        tool_name: body.tool_name,
        allowed: body.allowed,
        kind,
        created_at: now,
    };
    match state.db.upsert_agent_override(&override_).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error setting agent override");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// DELETE /admin/agents/{agent_id}/overrides/{tool_name}
pub async fn delete_agent_override_handler(
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
    match state.db.delete_agent_override(&agent_id, &tool_name).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error deleting agent override");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// POST /admin/agents/{agent_id}/profile
pub async fn assign_agent_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(agent_id): Path<String>,
    Json(body): Json<AssignProfileBody>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }
    if Uuid::parse_str(&agent_id).is_err() {
        return (StatusCode::BAD_REQUEST, "agent_id must be a UUID").into_response();
    }
    match state.db.set_agent_profile(&agent_id, Some(&body.profile_id)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error assigning agent profile");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// ─── Integration Admin Handlers ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateIntegrationRequest {
    pub slug: String,
    pub name: String,
    pub mcp_url: String,
    pub oauth_auth_url: Option<String>,
    pub oauth_token_url: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_scopes: Option<Vec<String>>,
}

fn validate_slug(slug: &str) -> Result<(), Response> {
    if slug.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "slug must not be empty").into_response());
    }
    if !slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err((StatusCode::BAD_REQUEST, "slug must contain only alphanumeric, '-', or '_'").into_response());
    }
    if slug.contains("__") {
        return Err((StatusCode::BAD_REQUEST, "slug must not contain '__'").into_response());
    }
    Ok(())
}

// GET /admin/integrations
pub async fn list_integrations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    match state.db.list_integrations().await {
        Ok(integrations) => {
            let body: Vec<serde_json::Value> = integrations
                .into_iter()
                .map(|i| serde_json::json!({
                    "id": i.id,
                    "slug": i.slug,
                    "name": i.name,
                    "mcp_url": i.mcp_url,
                    "oauth_auth_url": i.oauth_auth_url,
                    "oauth_token_url": i.oauth_token_url,
                    "oauth_client_id": i.oauth_client_id,
                    "oauth_scopes": i.oauth_scopes,
                    "connected": i.connected,
                    "created_at": i.created_at,
                }))
                .collect();
            Json(body).into_response()
        }
        Err(e) => {
            tracing::error!(err = %e, "admin: db error listing integrations");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// POST /admin/integrations
pub async fn create_integration(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Json(body): Json<CreateIntegrationRequest>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    if let Err(e) = validate_slug(&body.slug) {
        return e;
    }

    let id = Uuid::new_v4().to_string();
    let now = unix_timestamp_secs();

    let integration = Integration {
        id: id.clone(),
        slug: body.slug.clone(),
        name: body.name.clone(),
        mcp_url: body.mcp_url.clone(),
        oauth_auth_url: body.oauth_auth_url.clone(),
        oauth_token_url: body.oauth_token_url.clone(),
        oauth_client_id: body.oauth_client_id.clone(),
        oauth_scopes: body.oauth_scopes.clone(),
        connected: false,
        default_stance: false,
        created_at: now,
    };

    match state.db.insert_integration(&integration).await {
        Ok(()) => {}
        Err(mcpcondor_db::StoreError::Conflict(_)) => {
            return (StatusCode::CONFLICT, "slug already exists").into_response();
        }
        Err(e) => {
            tracing::error!(err = %e, "admin: db error creating integration");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    }

    // Create downstream client and try to connect (non-fatal)
    match DownstreamClient::new(body.mcp_url.clone(), body.slug.clone(), id.clone()) {
        Ok(client) => {
            let client = Arc::new(client);
            state.downstreams.insert(body.slug.clone(), Arc::clone(&client));
            let client_clone = Arc::clone(&client);
            tokio::spawn(async move {
                if let Err(e) = client_clone.initialize(None).await {
                    tracing::warn!(err = %e, "integration: downstream not reachable on create");
                }
            });
        }
        Err(e) => {
            tracing::warn!(err = %e, "admin: failed to build downstream client on create");
        }
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "slug": body.slug })),
    )
        .into_response()
}

// DELETE /admin/integrations/{id}
pub async fn delete_integration_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    // Look up slug before deleting so we can remove from downstreams map
    let integration = match state.db.get_integration(&id).await {
        Ok(Some(i)) => i,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error looking up integration");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    match state.db.delete_integration(&id).await {
        Ok(true) => {}
        Ok(false) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error deleting integration");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    }

    // Remove from in-memory maps
    state.downstreams.remove(&integration.slug);
    state.vault_cache.remove(&id);

    StatusCode::NO_CONTENT.into_response()
}

// POST /admin/integrations/{id}/refresh
pub async fn refresh_integration(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    let integration = match state.db.get_integration(&id).await {
        Ok(Some(i)) => i,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error looking up integration for refresh");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let downstream = match state.downstreams.get(&integration.slug) {
        Some(d) => d.clone(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, "downstream not connected").into_response(),
    };

    // Get vault token if available
    let auth_token = match state.vault.get_token(&id).await {
        Ok(Some(data)) => data.access_token,
        _ => None,
    };

    tokio::spawn(async move {
        if let Err(e) = downstream.initialize(auth_token.as_deref()).await {
            tracing::warn!(err = %e, "integration refresh: downstream error");
        }
    });

    StatusCode::ACCEPTED.into_response()
}

#[derive(Debug, Deserialize)]
pub struct ClientCredsRequest {
    pub client_id: String,
    pub client_secret: String,
    pub token_url: Option<String>,
    pub scopes: Option<Vec<String>>,
}

// POST /admin/integrations/{id}/connect/client-credentials
pub async fn connect_client_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
    Json(body): Json<ClientCredsRequest>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    let integration = match state.db.get_integration(&id).await {
        Ok(Some(i)) => i,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error looking up integration");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let token_url = body.token_url
        .as_deref()
        .or(integration.oauth_token_url.as_deref())
        .map(|s| s.to_string());

    let token_url = match token_url {
        Some(u) => u,
        None => {
            return (StatusCode::BAD_REQUEST, "token_url required: integration has no oauth_token_url").into_response();
        }
    };

    // Build form params for client_credentials grant
    let mut form_params = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", body.client_id.clone()),
        ("client_secret", body.client_secret.clone()),
    ];
    if let Some(scopes) = &body.scopes {
        if !scopes.is_empty() {
            form_params.push(("scope", scopes.join(" ")));
        }
    } else if let Some(scopes) = &integration.oauth_scopes {
        if !scopes.is_empty() {
            form_params.push(("scope", scopes.join(" ")));
        }
    }

    let http = match outbound_http_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(err = %e, "admin: failed to build http client");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    let token_resp = match http
        .post(&token_url)
        .form(&form_params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(err = %e, "admin: client_credentials token request failed");
            return (StatusCode::BAD_GATEWAY, "token endpoint request failed").into_response();
        }
    };

    if !token_resp.status().is_success() {
        let status = token_resp.status();
        tracing::warn!(status = %status, "admin: client_credentials token endpoint returned error");
        return (StatusCode::BAD_GATEWAY, "token endpoint returned error").into_response();
    }

    let body_bytes = match token_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(err = %e, "admin: failed to read token response");
            return (StatusCode::BAD_GATEWAY, "token endpoint read failed").into_response();
        }
    };
    if body_bytes.len() > MAX_TOKEN_RESPONSE_BYTES {
        return (StatusCode::BAD_GATEWAY, "token response too large").into_response();
    }
    let token_json: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(err = %e, "admin: failed to parse token response");
            return (StatusCode::BAD_GATEWAY, "invalid token response").into_response();
        }
    };

    let access_token = token_json["access_token"].as_str().map(|s| s.to_string());
    let token_type = token_json["token_type"].as_str().map(|s| s.to_string());
    let expires_in = token_json["expires_in"].as_i64();
    let now = unix_timestamp_secs();
    let expires_at = expires_in.map(|e| now + e);

    let vault_data = VaultTokenData {
        client_secret: Some(body.client_secret.clone()),
        access_token: access_token.clone(),
        refresh_token: None,
        token_type,
        expires_at,
    };

    if let Err(e) = state.vault.store_token(&id, &vault_data).await {
        tracing::error!(err = %e, "admin: failed to store vault token");
        return (StatusCode::INTERNAL_SERVER_ERROR, "failed to store credentials").into_response();
    }

    // Mark integration as connected
    if let Err(e) = state.db.update_integration_connected(&id, true).await {
        tracing::warn!(err = %e, "admin: failed to mark integration as connected");
    }

    // Evict stale vault cache entry
    state.vault_cache.remove(&id);

    (StatusCode::OK, Json(serde_json::json!({ "connected": true }))).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ConnectAuthorizeQuery {
    pub redirect_uri: Option<String>,
}

// POST /admin/integrations/{id}/connect/authorize — initiate auth code + PKCE flow
pub async fn connect_authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    PeerIp(peer_ip): PeerIp,
    Path(id): Path<String>,
    Query(query): Query<ConnectAuthorizeQuery>,
) -> Response {
    if let Err(e) = require_admin(&state, &headers, peer_ip).await {
        return e;
    }

    let integration = match state.db.get_integration(&id).await {
        Ok(Some(i)) => i,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "admin: db error looking up integration");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let auth_url = match &integration.oauth_auth_url {
        Some(u) => u.clone(),
        None => {
            return (StatusCode::BAD_REQUEST, "integration has no oauth_auth_url").into_response();
        }
    };

    let client_id = match &integration.oauth_client_id {
        Some(c) => c.clone(),
        None => {
            return (StatusCode::BAD_REQUEST, "integration has no oauth_client_id").into_response();
        }
    };

    // Generate PKCE pair and state nonce
    let code_verifier = crate::crypto::random_base64url(32);
    let code_challenge = crate::crypto::pkce_challenge(&code_verifier);
    let state_nonce = crate::crypto::random_base64url(16);
    let now = unix_timestamp_secs();

    let redirect_uri = query.redirect_uri.unwrap_or_else(|| {
        // Default redirect — caller must configure this at the downstream
        format!("/oauth/integrations/{id}/callback")
    });

    // H4: evict expired entries before inserting; reject if still at cap
    if state.pending_integration_auth.len() >= MAX_PENDING_INTEGRATION_ENTRIES {
        state.pending_integration_auth.retain(|_, v| now - v.created_at < PENDING_INTEGRATION_TTL_SECS);
        if state.pending_integration_auth.len() >= MAX_PENDING_INTEGRATION_ENTRIES {
            return (StatusCode::TOO_MANY_REQUESTS, "too many pending authorization flows").into_response();
        }
    }

    state.pending_integration_auth.insert(
        state_nonce.clone(),
        crate::handler::PendingIntegrationAuth {
            integration_id: id.clone(),
            state: state_nonce.clone(),
            code_verifier,
            created_at: now,
        },
    );

    // H2: build URL with proper percent-encoding so injected & in any value can't add parameters
    let mut parsed = match reqwest::Url::parse(&auth_url) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid oauth_auth_url").into_response(),
    };
    {
        let mut pairs = parsed.query_pairs_mut();
        pairs.append_pair("response_type", "code");
        pairs.append_pair("client_id", &client_id);
        pairs.append_pair("state", &state_nonce);
        pairs.append_pair("code_challenge", &code_challenge);
        pairs.append_pair("code_challenge_method", "S256");
        pairs.append_pair("redirect_uri", &redirect_uri);
        if let Some(scopes) = &integration.oauth_scopes {
            if !scopes.is_empty() {
                pairs.append_pair("scope", &scopes.join(" "));
            }
        }
    }

    Json(serde_json::json!({ "url": parsed.to_string() })).into_response()
}

// GET /oauth/integrations/{id}/callback — receive auth code callback
pub async fn integration_oauth_callback(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let code = match params.get("code") {
        Some(c) => c.clone(),
        None => {
            // Restrict to known OAuth error codes — never reflect arbitrary query param values
            let error = match params.get("error").map(|s| s.as_str()) {
                Some("access_denied") => "access_denied",
                Some("temporarily_unavailable") => "temporarily_unavailable",
                Some("server_error") => "server_error",
                _ => "authorization_failed",
            };
            return (StatusCode::BAD_REQUEST, format!("authorization denied: {error}")).into_response();
        }
    };

    let state_param = match params.get("state") {
        Some(s) => s.clone(),
        None => return (StatusCode::BAD_REQUEST, "missing state parameter").into_response(),
    };

    let pending = match state.pending_integration_auth.remove(&state_param) {
        Some((_, p)) => p,
        None => return (StatusCode::BAD_REQUEST, "invalid or expired state").into_response(),
    };

    if pending.integration_id != id {
        return (StatusCode::BAD_REQUEST, "state/integration mismatch").into_response();
    }

    let integration = match state.db.get_integration(&id).await {
        Ok(Some(i)) => i,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(err = %e, "callback: db error");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let token_url = match &integration.oauth_token_url {
        Some(u) => u.clone(),
        None => return (StatusCode::BAD_REQUEST, "integration has no oauth_token_url").into_response(),
    };

    let client_id = match &integration.oauth_client_id {
        Some(c) => c.clone(),
        None => return (StatusCode::BAD_REQUEST, "integration has no oauth_client_id").into_response(),
    };

    // Exchange code for tokens
    let http = match outbound_http_client() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(err = %e, "callback: failed to build http client");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    let token_resp = match http
        .post(&token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &client_id),
            ("code_verifier", &pending.code_verifier),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(err = %e, "callback: token exchange request failed");
            return (StatusCode::BAD_GATEWAY, "token exchange failed").into_response();
        }
    };

    if !token_resp.status().is_success() {
        return (StatusCode::BAD_GATEWAY, "token endpoint returned error").into_response();
    }

    let body_bytes = match token_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(err = %e, "callback: failed to read token response");
            return (StatusCode::BAD_GATEWAY, "token endpoint read failed").into_response();
        }
    };
    if body_bytes.len() > MAX_TOKEN_RESPONSE_BYTES {
        return (StatusCode::BAD_GATEWAY, "token response too large").into_response();
    }
    let token_json: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(err = %e, "callback: failed to parse token response");
            return (StatusCode::BAD_GATEWAY, "invalid token response").into_response();
        }
    };

    let access_token = token_json["access_token"].as_str().map(|s| s.to_string());
    let refresh_token = token_json["refresh_token"].as_str().map(|s| s.to_string());
    let token_type = token_json["token_type"].as_str().map(|s| s.to_string());
    let expires_in = token_json["expires_in"].as_i64();
    let now = unix_timestamp_secs();
    let expires_at = expires_in.map(|e| now + e);

    let vault_data = VaultTokenData {
        client_secret: None,
        access_token,
        refresh_token,
        token_type,
        expires_at,
    };

    if let Err(e) = state.vault.store_token(&id, &vault_data).await {
        tracing::error!(err = %e, "callback: failed to store vault token");
        return (StatusCode::INTERNAL_SERVER_ERROR, "failed to store credentials").into_response();
    }

    if let Err(e) = state.db.update_integration_connected(&id, true).await {
        tracing::warn!(err = %e, "callback: failed to mark integration as connected");
    }

    state.vault_cache.remove(&id);

    (StatusCode::OK, "Integration connected successfully").into_response()
}
