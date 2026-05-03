use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use chrono::Utc;
use dashmap::DashMap;
use mcpshield_core::audit::AuditSink;
use mcpshield_core::mcp::{
    error_response, InitializeParams, InitializeResult, JsonRpcError, JsonRpcOutcome,
    JsonRpcRequest, JsonRpcResponse, PeerInfo, RequestId, ToolsListResult, ERR_INTERNAL,
    ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, SUPPORTED_PROTOCOL_VERSION,
};
use mcpshield_core::policy::PolicyEngine;
use mcpshield_core::types::{AgentId, AuditEvent, AuditOutcome, IntegrationId, McpPrimitive};
use mcpshield_core::vault::{VaultBackend, VaultTokenData};
use mcpshield_db::Store;
use serde_json::json;
use uuid::Uuid;

use crate::crypto::unix_timestamp_secs;
use crate::downstream::DownstreamClient;
use crate::policy_cache::CachingPolicyEngine;
use crate::session::{create_session, get_session, SessionStore};

/// Maximum length for an Mcp-Session-Id header value. UUIDv4 is 36 chars; 128 is generous.
const MAX_SESSION_ID_BYTES: usize = 128;
/// Pending OAuth flows (inbound and outbound) expire after 10 minutes.
pub const PENDING_AUTH_TTL_SECS: i64 = 600;
pub const PENDING_INTEGRATION_TTL_SECS: i64 = 600;
/// Maximum concurrent pending outbound integration auth flows.
pub const MAX_PENDING_INTEGRATION_ENTRIES: usize = 100;

/// A pending authorization request stored in-memory until user submits credentials.
#[derive(Debug, Clone)]
pub struct PendingAuthRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: String,
    pub agent_id: String,
    pub created_at: i64,
    /// Failed credential attempts on this specific OAuth flow.
    pub attempts: u8,
}

pub type PendingAuthStore = Arc<DashMap<String, PendingAuthRequest>>;

pub fn new_pending_store() -> PendingAuthStore {
    Arc::new(DashMap::new())
}

/// Pending outbound OAuth state for connecting an integration.
#[derive(Debug, Clone)]
pub struct PendingIntegrationAuth {
    pub integration_id: String,
    pub state: String,
    pub code_verifier: String,
    pub created_at: i64,
}

pub type PendingIntegrationAuthStore = Arc<DashMap<String, PendingIntegrationAuth>>;

pub fn new_pending_integration_auth_store() -> PendingIntegrationAuthStore {
    Arc::new(DashMap::new())
}

/// Per-IP sliding-window rate limiter for credential-checking endpoints.
pub struct RateLimiter {
    failures: DashMap<String, Vec<i64>>,
}

const RATE_WINDOW_SECS: i64 = 60;
const RATE_MAX_FAILURES: usize = 10;
const RATE_MAX_ENTRIES: usize = 50_000;

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            failures: DashMap::new(),
        }
    }

    pub fn allow(&self, ip: &str, now: i64) -> bool {
        if let Some(entry) = self.failures.get(ip) {
            entry
                .iter()
                .filter(|&&ts| now - ts < RATE_WINDOW_SECS)
                .count()
                < RATE_MAX_FAILURES
        } else {
            true
        }
    }

    pub fn record_failure(&self, ip: &str, now: i64) {
        if self.failures.len() >= RATE_MAX_ENTRIES {
            self.failures
                .retain(|_, v| v.iter().any(|&ts| now - ts < RATE_WINDOW_SECS));
        }
        let mut entry = self.failures.entry(ip.to_string()).or_default();
        entry.retain(|&ts| now - ts < RATE_WINDOW_SECS);
        entry.push(now);
    }

    pub fn record_success(&self, ip: &str) {
        self.failures.remove(ip);
    }
}

pub type RateLimiterStore = Arc<RateLimiter>;

pub fn new_rate_limiter() -> RateLimiterStore {
    Arc::new(RateLimiter::new())
}

/// Extract the real peer IP from the ConnectInfo extension.
pub fn extract_client_ip(peer_ip: Option<IpAddr>) -> String {
    peer_ip.map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string())
}

#[derive(Debug, Clone)]
pub struct PeerIp(pub Option<IpAddr>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        Ok(PeerIp(ip))
    }
}

pub struct AppState {
    pub sessions: SessionStore,
    pub downstreams: Arc<DashMap<String, Arc<DownstreamClient>>>,
    pub policy: Arc<CachingPolicyEngine>,
    pub audit: Arc<dyn AuditSink>,
    pub db: Arc<dyn Store>,
    pub vault: Arc<dyn VaultBackend>,
    pub pending_auth: PendingAuthStore,
    pub pending_integration_auth: PendingIntegrationAuthStore,
    pub rate_limiter: RateLimiterStore,
    pub admin_rate_limiter: RateLimiterStore,
    pub setup_csrf_token: String,
    /// token_hash → (agent_id, client_id, expiry_unix_secs)
    pub bearer_cache: Arc<DashMap<String, (String, String, i64)>>,
    /// integration_id → (token_data, cached_at)
    pub vault_cache: Arc<DashMap<String, (VaultTokenData, Instant)>>,
}

pub fn new_setup_csrf_token() -> String {
    crate::crypto::random_base64url(32)
}

/// Authenticated agent extracted from a Bearer token.
#[derive(Debug, Clone)]
pub struct AuthenticatedAgent {
    pub agent_id: String,
    pub client_id: String,
}

/// Unauthenticated MCP handler — **test use only**.
pub async fn mcp_handler_no_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> Response {
    let is_notification = req.id.is_none();

    if req.jsonrpc != "2.0" {
        if is_notification {
            return notification_ack();
        }
        return error_json(error_response(
            req.id,
            ERR_INVALID_REQUEST,
            format!("unsupported jsonrpc version: {}", req.jsonrpc),
        ));
    }

    match req.method.as_str() {
        "initialize" => {
            if is_notification {
                return notification_ack();
            }
            handle_initialize(state, &headers, req).await
        }
        "notifications/initialized" => {
            let sid = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if get_session(&state.sessions, sid).is_none() {
                let safe_sid: String = sid
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                    .take(128)
                    .collect();
                tracing::warn!(session_id = %safe_sid, "notifications/initialized from unknown session");
            }
            notification_ack()
        }
        method => {
            let session_id = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .filter(|s| s.len() <= MAX_SESSION_ID_BYTES)
                .map(|s| s.to_string());

            let session_id = match session_id {
                Some(id) => id,
                None => {
                    if is_notification {
                        return notification_ack();
                    }
                    return error_json(error_response(
                        req.id.clone(),
                        ERR_INVALID_REQUEST,
                        "missing or oversized Mcp-Session-Id header",
                    ));
                }
            };

            let session = match get_session(&state.sessions, &session_id) {
                Some(s) => s,
                None => {
                    if is_notification {
                        return notification_ack();
                    }
                    return error_json(error_response(
                        req.id.clone(),
                        ERR_INVALID_REQUEST,
                        "unknown session",
                    ));
                }
            };

            match method {
                "tools/list" => handle_tools_list(state, req, session.agent_id).await,
                "tools/call" => handle_tools_call(state, req, session.agent_id).await,
                _ => {
                    if is_notification {
                        notification_ack()
                    } else {
                        error_json(error_response(
                            req.id,
                            ERR_METHOD_NOT_FOUND,
                            format!("method not found: {method}"),
                        ))
                    }
                }
            }
        }
    }
}

/// Authenticate the Bearer token from headers. Returns Ok(AuthenticatedAgent) or an HTTP error response.
pub async fn authenticate_bearer(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<AuthenticatedAgent, Response> {
    let token = match extract_bearer_token(headers) {
        Some(t) => t,
        None => {
            return Err(axum::http::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "application/json")
                .header("www-authenticate", "Bearer realm=\"MCPShield\"")
                .body(axum::body::Body::from(
                    r#"{"error":"unauthorized","error_description":"Bearer token required"}"#,
                ))
                .expect("valid static response"));
        }
    };

    let token_hash = crate::crypto::sha256_hex(&token);
    let now = unix_timestamp_secs();

    // Cache check
    if let Some(entry) = state.bearer_cache.get(&token_hash) {
        let (agent_id, client_id, expiry) = entry.clone();
        if now < expiry {
            return Ok(AuthenticatedAgent { agent_id, client_id });
        }
        drop(entry);
        state.bearer_cache.remove(&token_hash);
    }

    // DB fallback
    match state.db.get_token_by_hash(&token_hash, now).await {
        Ok(Some(lookup)) => {
            let cache_ttl = std::cmp::min(now + 30, lookup.expires_at);
            state.bearer_cache.insert(
                token_hash,
                (lookup.agent_id.clone(), lookup.client_id.clone(), cache_ttl),
            );
            Ok(AuthenticatedAgent {
                agent_id: lookup.agent_id,
                client_id: lookup.client_id,
            })
        }
        Ok(None) => Err(axum::http::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .header("www-authenticate", "Bearer realm=\"MCPShield\", error=\"invalid_token\"")
            .body(axum::body::Body::from(
                r#"{"error":"invalid_token","error_description":"Token invalid or expired"}"#,
            ))
            .expect("valid static response")),
        Err(e) => {
            tracing::error!(err = %e, "bearer auth: db error");
            Err(axum::http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"server_error","error_description":"internal server error"}"#,
                ))
                .expect("valid static response"))
        }
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

pub async fn mcp_handler_authenticated(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> Response {
    let agent = match authenticate_bearer(&state, &headers).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let is_notification = req.id.is_none();

    if req.jsonrpc != "2.0" {
        if is_notification {
            return notification_ack();
        }
        return error_json(error_response(
            req.id,
            ERR_INVALID_REQUEST,
            format!("unsupported jsonrpc version: {}", req.jsonrpc),
        ));
    }

    match req.method.as_str() {
        "initialize" => {
            if is_notification {
                return notification_ack();
            }
            handle_initialize_with_agent(state, &headers, req, agent.agent_id).await
        }
        "notifications/initialized" => {
            let sid = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if get_session(&state.sessions, sid).is_none() {
                let safe_sid: String = sid
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                    .take(128)
                    .collect();
                tracing::warn!(session_id = %safe_sid, "notifications/initialized from unknown session");
            }
            notification_ack()
        }
        method => {
            let session_id = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .filter(|s| s.len() <= MAX_SESSION_ID_BYTES)
                .map(|s| s.to_string());

            let session_id = match session_id {
                Some(id) => id,
                None => {
                    if is_notification {
                        return notification_ack();
                    }
                    return error_json(error_response(
                        req.id.clone(),
                        ERR_INVALID_REQUEST,
                        "missing or oversized Mcp-Session-Id header",
                    ));
                }
            };

            let session = match get_session(&state.sessions, &session_id) {
                Some(s) => s,
                None => {
                    if is_notification {
                        return notification_ack();
                    }
                    return error_json(error_response(
                        req.id.clone(),
                        ERR_INVALID_REQUEST,
                        "unknown session",
                    ));
                }
            };

            if session.agent_id != agent.agent_id {
                return error_json(error_response(
                    req.id,
                    ERR_INVALID_REQUEST,
                    "token does not match session",
                ));
            }

            match method {
                "tools/list" => handle_tools_list(state, req, session.agent_id).await,
                "tools/call" => handle_tools_call(state, req, session.agent_id).await,
                _ => {
                    if is_notification {
                        notification_ack()
                    } else {
                        error_json(error_response(
                            req.id,
                            ERR_METHOD_NOT_FOUND,
                            format!("method not found: {method}"),
                        ))
                    }
                }
            }
        }
    }
}

async fn handle_initialize(state: Arc<AppState>, headers: &HeaderMap, req: JsonRpcRequest) -> Response {
    handle_initialize_with_agent(state, headers, req, Uuid::nil().to_string()).await
}

async fn handle_initialize_with_agent(
    state: Arc<AppState>,
    headers: &HeaderMap,
    req: JsonRpcRequest,
    agent_id: String,
) -> Response {
    let req_id = match require_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if headers.contains_key("mcp-session-id") {
        return error_json(error_response(
            Some(req_id),
            ERR_INVALID_REQUEST,
            "Mcp-Session-Id must not be sent on initialize",
        ));
    }

    let params: InitializeParams = match req
        .params
        .as_ref()
        .and_then(|p| serde_json::from_value(p.clone()).ok())
    {
        Some(p) => p,
        None => {
            return error_json(error_response(
                Some(req_id),
                ERR_INVALID_REQUEST,
                "invalid initialize params",
            ));
        }
    };

    if params.protocol_version != SUPPORTED_PROTOCOL_VERSION {
        tracing::warn!(
            client_version = %params.protocol_version,
            server_version = %SUPPORTED_PROTOCOL_VERSION,
            "protocol version mismatch — responding with server version"
        );
    }

    // Aggregate capabilities from all downstreams (or provide default tools capability)
    let mut capabilities = json!({});
    for entry in state.downstreams.iter() {
        let downstream_caps = entry.value().capabilities().await;
        if let (Some(obj), Some(downstream_obj)) = (capabilities.as_object_mut(), downstream_caps.as_object()) {
            for (k, v) in downstream_obj {
                obj.entry(k).or_insert_with(|| v.clone());
            }
        }
    }
    if let Some(obj) = capabilities.as_object_mut() {
        obj.entry("tools").or_insert(json!({}));
    }

    let result = InitializeResult {
        protocol_version: SUPPORTED_PROTOCOL_VERSION.to_string(),
        capabilities,
        server_info: PeerInfo {
            name: "mcpshield".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };

    let result_value = match serde_json::to_value(&result) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(err = %e, "initialize: serialization error");
            return error_json(error_response(Some(req_id), ERR_INTERNAL, "internal error"));
        }
    };

    let resp = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req_id,
        result: result_value,
    };
    let body = serde_json::to_string(&resp).expect("JsonRpcResponse is always serialisable");

    let session_id = match create_session(&state.sessions, agent_id) {
        Ok(id) => id,
        Err(e) => {
            return error_json(error_response(Some(resp.id), ERR_INTERNAL, e));
        }
    };

    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("mcp-session-id", session_id)
        .body(axum::body::Body::from(body))
        .expect("valid response headers")
}

fn emit_audit(state: &Arc<AppState>, event: AuditEvent) {
    let audit = Arc::clone(&state.audit);
    tokio::spawn(async move {
        if let Err(e) = audit.log_boxed(event).await {
            tracing::warn!(err = %e, "audit: failed to log event");
        }
    });
}

fn tool_call_event(
    agent_id: &AgentId,
    integration_id: &IntegrationId,
    slug: &str,
    tool: &str,
    outcome: AuditOutcome,
    latency_ms: u64,
) -> AuditEvent {
    AuditEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        agent_id: agent_id.clone(),
        integration_id: Some(integration_id.clone()),
        primitive: McpPrimitive::Tool,
        operation_name: format!("{slug}__{tool}"),
        outcome,
        dlp_detections: vec![],
        latency_ms,
    }
}

async fn handle_tools_list(state: Arc<AppState>, req: JsonRpcRequest, agent_id: String) -> Response {
    let req_id = match require_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let parsed_agent_id = match Uuid::parse_str(&agent_id) {
        Ok(u) => AgentId(u),
        Err(_) => {
            return error_json(error_response(
                Some(req_id),
                ERR_INTERNAL,
                "invalid agent_id in session",
            ));
        }
    };
    let integration_id = IntegrationId(Uuid::nil());

    let mut namespaced = Vec::new();

    for entry in state.downstreams.iter() {
        let slug = entry.key().clone();
        let downstream = entry.value().clone();
        let raw_tools = downstream.list_tools().await;

        // Build namespaced tool names for the policy batch check
        let namespaced_names: Vec<String> = raw_tools
            .iter()
            .map(|t| format!("{slug}__{}", t.name))
            .collect();

        let allowed_names: HashSet<String> = match state
            .policy
            .list_allowed_boxed(&parsed_agent_id, &integration_id, &namespaced_names)
            .await
        {
            Ok(set) => set,
            Err(e) => {
                tracing::error!(err = %e, slug = %slug, "tools/list: policy evaluation error");
                return error_json(error_response(Some(req_id), ERR_INTERNAL, "internal error"));
            }
        };

        for t in raw_tools.iter() {
            let namespaced_name = format!("{slug}__{}", t.name);
            if allowed_names.contains(&namespaced_name) {
                let mut tool = t.clone();
                tool.name = namespaced_name;
                namespaced.push(tool);
            }
        }
    }

    let result = ToolsListResult {
        tools: namespaced,
        next_cursor: None,
    };

    let result_value = match serde_json::to_value(&result) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(err = %e, "tools/list: serialization error");
            return error_json(error_response(Some(req_id), ERR_INTERNAL, "internal error"));
        }
    };

    let resp = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req_id,
        result: result_value,
    };

    json_response(resp)
}

async fn handle_tools_call(state: Arc<AppState>, req: JsonRpcRequest, agent_id: String) -> Response {
    let req_id = match require_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let call_start = std::time::Instant::now();

    let params: mcpshield_core::mcp::ToolCallParams =
        match req.params.as_ref().and_then(|p| serde_json::from_value(p.clone()).ok()) {
            Some(p) => p,
            None => {
                return error_json(error_response(
                    Some(req_id),
                    ERR_INVALID_REQUEST,
                    "invalid tools/call params",
                ));
            }
        };

    let tool_name = &params.name;

    let (tool_slug, local_name) = match tool_name.split_once("__") {
        Some(parts) => parts,
        None => {
            return error_json(error_response(
                Some(req_id),
                ERR_METHOD_NOT_FOUND,
                format!("unknown tool: {tool_name}"),
            ));
        }
    };

    let downstream = match state.downstreams.get(tool_slug) {
        Some(d) => d.clone(),
        None => {
            return error_json(error_response(
                Some(req_id),
                ERR_METHOD_NOT_FOUND,
                format!("unknown integration: {tool_slug}"),
            ));
        }
    };

    let known_tools = downstream.list_tools().await;
    if !known_tools.iter().any(|t| t.name == local_name) {
        return error_json(error_response(
            Some(req_id),
            ERR_METHOD_NOT_FOUND,
            format!("unknown tool: {tool_name}"),
        ));
    }

    let parsed_agent_id = match Uuid::parse_str(&agent_id) {
        Ok(u) => AgentId(u),
        Err(_) => {
            return error_json(error_response(
                Some(req_id),
                ERR_INTERNAL,
                "invalid agent_id in session",
            ));
        }
    };
    let integration_id = IntegrationId(Uuid::nil());
    let call_params = params.arguments.clone().unwrap_or(serde_json::Value::Null);

    // Policy check uses the full namespaced name
    let decision = match state
        .policy
        .evaluate_boxed(&parsed_agent_id, &integration_id, tool_name, &call_params)
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(err = %e, "tools/call: policy evaluation error");
            return error_json(error_response(Some(req_id), ERR_INTERNAL, "internal error"));
        }
    };

    if !decision.allowed {
        let latency_ms = call_start.elapsed().as_millis() as u64;
        emit_audit(
            &state,
            tool_call_event(
                &parsed_agent_id,
                &integration_id,
                tool_slug,
                local_name,
                AuditOutcome::Denied { reason: "policy deny".to_string() },
                latency_ms,
            ),
        );
        return error_json(error_response(
            Some(req_id),
            ERR_INVALID_REQUEST,
            "tool not permitted",
        ));
    }

    // Get auth token from vault cache (non-fatal — None means no auth header)
    let auth_token = get_vault_token_cached(&state, &downstream.integration_id).await;

    match downstream.call_tool(local_name, params.arguments, auth_token.as_deref()).await {
        Ok(JsonRpcOutcome::Success(downstream_resp)) => {
            let latency_ms = call_start.elapsed().as_millis() as u64;
            emit_audit(
                &state,
                tool_call_event(
                    &parsed_agent_id,
                    &integration_id,
                    tool_slug,
                    local_name,
                    AuditOutcome::Allowed,
                    latency_ms,
                ),
            );
            let resp = JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req_id,
                result: downstream_resp.result,
            };
            json_response(resp)
        }
        Ok(JsonRpcOutcome::Error(downstream_err)) => {
            let latency_ms = call_start.elapsed().as_millis() as u64;
            emit_audit(
                &state,
                tool_call_event(
                    &parsed_agent_id,
                    &integration_id,
                    tool_slug,
                    local_name,
                    AuditOutcome::Allowed,
                    latency_ms,
                ),
            );
            error_json(JsonRpcError {
                jsonrpc: "2.0".to_string(),
                id: Some(req_id),
                error: downstream_err.error,
            })
        }
        Err(e) => {
            let latency_ms = call_start.elapsed().as_millis() as u64;
            tracing::error!(err = %e, "tools/call: downstream error");
            emit_audit(
                &state,
                tool_call_event(
                    &parsed_agent_id,
                    &integration_id,
                    tool_slug,
                    local_name,
                    AuditOutcome::Error { detail: "downstream unavailable".to_string() },
                    latency_ms,
                ),
            );
            error_json(error_response(Some(req_id), ERR_INTERNAL, "downstream unavailable"))
        }
    }
}

/// Look up a vault access_token for an integration. Returns None if no token stored or token expired.
async fn get_vault_token_cached(state: &Arc<AppState>, integration_id: &str) -> Option<String> {
    let now = unix_timestamp_secs();

    // Check cache
    if let Some(entry) = state.vault_cache.get(integration_id) {
        let (data, cached_at) = entry.value().clone();
        // Evict if cached more than 5 seconds ago, or if token itself is expired
        if cached_at.elapsed().as_secs() < 5 {
            if let Some(expires_at) = data.expires_at {
                if now < expires_at {
                    return data.access_token;
                }
                // Token expired — fall through to evict
            } else {
                return data.access_token;
            }
        }
        drop(entry);
        state.vault_cache.remove(integration_id);
    }

    // Fetch from vault
    match state.vault.get_token(integration_id).await {
        Ok(Some(data)) => {
            // Don't cache if already expired
            if let Some(expires_at) = data.expires_at {
                if now >= expires_at {
                    return None;
                }
            }
            let token = data.access_token.clone();
            state.vault_cache.insert(integration_id.to_string(), (data, Instant::now()));
            token
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(err = %e, integration_id = %integration_id, "vault: failed to get token");
            None
        }
    }
}

fn require_id(req: &JsonRpcRequest) -> Result<RequestId, Response> {
    req.id.clone().ok_or_else(|| {
        error_json(error_response(
            None,
            ERR_INVALID_REQUEST,
            "request must have an id",
        ))
    })
}

fn json_response(resp: JsonRpcResponse) -> Response {
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&resp).expect("JsonRpcResponse is always serialisable"),
        ))
        .expect("valid response headers")
}

pub fn error_json(err: JsonRpcError) -> Response {
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&err).expect("JsonRpcError is always serialisable"),
        ))
        .expect("valid response headers")
}

fn notification_ack() -> Response {
    axum::http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(axum::body::Body::empty())
        .expect("valid response headers")
}
