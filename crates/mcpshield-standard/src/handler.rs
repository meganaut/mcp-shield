use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use dashmap::DashMap;
use mcpshield_core::audit::AuditSink;
use mcpshield_core::mcp::{
    error_response, InitializeParams, InitializeResult, JsonRpcError, JsonRpcOutcome,
    JsonRpcRequest, JsonRpcResponse, PeerInfo, RequestId, ToolsListResult, ERR_INTERNAL,
    ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, SUPPORTED_PROTOCOL_VERSION,
};
use mcpshield_core::policy::PolicyEngine;
use mcpshield_core::types::{AgentId, IntegrationId};
use mcpshield_db::Store;
use serde_json::json;
use uuid::Uuid;

use crate::crypto::unix_timestamp_secs;
use crate::downstream::DownstreamClient;
use crate::session::{create_session, get_session, SessionStore};

/// A pending authorization request stored in-memory until user submits credentials.
#[derive(Debug, Clone)]
pub struct PendingAuthRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: String,
    pub agent_id: String,
    pub created_at: i64,
}

pub type PendingAuthStore = Arc<DashMap<String, PendingAuthRequest>>;

pub fn new_pending_store() -> PendingAuthStore {
    Arc::new(DashMap::new())
}

/// Per-IP sliding-window rate limiter for credential-checking endpoints.
/// Tracks timestamps of recent failures; rejects when the count in the window exceeds the cap.
pub struct RateLimiter {
    // IP -> list of failure timestamps within the window
    failures: DashMap<String, Vec<i64>>,
}

const RATE_WINDOW_SECS: i64 = 60;
const RATE_MAX_FAILURES: usize = 10;
/// Global cap on tracked IPs; evict all fully-stale entries when exceeded.
const RATE_MAX_ENTRIES: usize = 50_000;

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            failures: DashMap::new(),
        }
    }

    /// Return false if this IP has exceeded the failure limit in the current window.
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

    /// Record one failed attempt. Prunes stale entries from this IP.
    /// Also evicts fully-stale IPs when the global map exceeds RATE_MAX_ENTRIES.
    pub fn record_failure(&self, ip: &str, now: i64) {
        // Global eviction when the map is too large
        if self.failures.len() >= RATE_MAX_ENTRIES {
            self.failures
                .retain(|_, v| v.iter().any(|&ts| now - ts < RATE_WINDOW_SECS));
        }
        let mut entry = self.failures.entry(ip.to_string()).or_default();
        entry.retain(|&ts| now - ts < RATE_WINDOW_SECS);
        entry.push(now);
    }

    /// Clear failure history on successful auth.
    pub fn record_success(&self, ip: &str) {
        self.failures.remove(ip);
    }
}

pub type RateLimiterStore = Arc<RateLimiter>;

pub fn new_rate_limiter() -> RateLimiterStore {
    Arc::new(RateLimiter::new())
}

/// Extract the best-available client IP from headers (X-Forwarded-For or fallback).
pub fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub struct AppState {
    pub sessions: SessionStore,
    pub downstream: Arc<DownstreamClient>,
    /// Policy engine — M1: always-allow no-op. M2 wires in SqlPolicyEngine.
    pub policy: Arc<dyn PolicyEngine>,
    /// Audit sink — M1: no-op. M2 wires in structured JSON logger.
    pub audit: Arc<dyn AuditSink>,
    /// Database handle.
    pub db: Arc<dyn Store>,
    /// In-memory store of pending OAuth authorization requests.
    pub pending_auth: PendingAuthStore,
    /// Per-IP rate limiter for credential-checking endpoints.
    pub rate_limiter: RateLimiterStore,
    /// CSRF token for the setup wizard form — generated once at startup.
    pub setup_csrf_token: String,
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

pub async fn mcp_handler_no_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> Response {
    // Compute is_notification first — it governs whether we may send any response at all.
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
            // Notifications must not receive a meaningful response per spec.
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
                        "missing Mcp-Session-Id header",
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
                .unwrap());
        }
    };

    let token_hash = crate::crypto::sha256_hex(&token);
    let now = unix_timestamp_secs();

    match state.db.get_token_by_hash(&token_hash, now).await {
        Ok(Some(lookup)) => Ok(AuthenticatedAgent {
            agent_id: lookup.agent_id,
            client_id: lookup.client_id,
        }),
        Ok(None) => Err(axum::http::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .header("www-authenticate", "Bearer realm=\"MCPShield\", error=\"invalid_token\"")
            .body(axum::body::Body::from(
                r#"{"error":"invalid_token","error_description":"Token invalid or expired"}"#,
            ))
            .unwrap()),
        Err(e) => {
            tracing::error!(err = %e, "bearer auth: db error");
            Err(axum::http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"server_error","error_description":"internal server error"}"#,
                ))
                .unwrap())
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
    // Authenticate the bearer token
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
                        "missing Mcp-Session-Id header",
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

            // Verify the token's agent_id matches the session's agent_id
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
    // For the unauthenticated path (e.g. tests with NoopPolicy), use a nil agent_id
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
    let negotiated_version = SUPPORTED_PROTOCOL_VERSION;

    let mut capabilities = state.downstream.capabilities().await;
    if let Some(obj) = capabilities.as_object_mut() {
        obj.entry("tools").or_insert(json!({}));
    }

    let result = InitializeResult {
        protocol_version: negotiated_version.to_string(),
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
        .unwrap()
}

async fn handle_tools_list(state: Arc<AppState>, req: JsonRpcRequest, agent_id: String) -> Response {
    let req_id = match require_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let slug = state.downstream.slug();
    let raw_tools = state.downstream.list_tools().await;

    // Parse agent_id UUID for policy check
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
    for mut t in raw_tools {
        let local_name = t.name.clone();
        // Check policy for this tool
        let decision = state
            .policy
            .evaluate_boxed(
                &parsed_agent_id,
                &integration_id,
                &local_name,
                &serde_json::Value::Null,
            )
            .await;
        let allowed = match decision {
            Ok(d) => d.allowed,
            Err(_) => false,
        };
        if allowed {
            t.name = format!("{slug}__{}", local_name);
            namespaced.push(t);
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

    if tool_slug != state.downstream.slug() {
        return error_json(error_response(
            Some(req_id),
            ERR_METHOD_NOT_FOUND,
            format!("unknown integration: {tool_slug}"),
        ));
    }

    let known_tools = state.downstream.list_tools().await;
    if !known_tools.iter().any(|t| t.name == local_name) {
        return error_json(error_response(
            Some(req_id),
            ERR_METHOD_NOT_FOUND,
            format!("unknown tool: {tool_name}"),
        ));
    }

    // Policy check
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

    let decision = match state
        .policy
        .evaluate_boxed(&parsed_agent_id, &integration_id, local_name, &call_params)
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(err = %e, "tools/call: policy evaluation error");
            return error_json(error_response(Some(req_id), ERR_INTERNAL, "internal error"));
        }
    };

    if !decision.allowed {
        return error_json(error_response(
            Some(req_id),
            ERR_INVALID_REQUEST,
            "tool not permitted",
        ));
    }

    match state.downstream.call_tool(local_name, params.arguments).await {
        Ok(JsonRpcOutcome::Success(downstream_resp)) => {
            let resp = JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req_id,
                result: downstream_resp.result,
            };
            json_response(resp)
        }
        Ok(JsonRpcOutcome::Error(downstream_err)) => {
            error_json(JsonRpcError {
                jsonrpc: "2.0".to_string(),
                id: Some(req_id),
                error: downstream_err.error,
            })
        }
        Err(e) => {
            tracing::error!(err = %e, "tools/call: downstream error");
            error_json(error_response(Some(req_id), ERR_INTERNAL, "downstream unavailable"))
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
        .unwrap()
}

pub fn error_json(err: JsonRpcError) -> Response {
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&err).expect("JsonRpcError is always serialisable"),
        ))
        .unwrap()
}

fn notification_ack() -> Response {
    axum::http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(axum::body::Body::empty())
        .unwrap()
}
