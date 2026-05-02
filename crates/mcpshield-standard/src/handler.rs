use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use mcpshield_core::audit::AuditSink;
use mcpshield_core::mcp::{
    error_response, InitializeParams, InitializeResult, JsonRpcError, JsonRpcOutcome,
    JsonRpcRequest, JsonRpcResponse, PeerInfo, RequestId, ToolsListResult, ERR_INTERNAL,
    ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, SUPPORTED_PROTOCOL_VERSION,
};
use mcpshield_core::policy::PolicyEngine;
use serde_json::json;

use crate::downstream::DownstreamClient;
use crate::session::{create_session, get_session, SessionStore};

pub struct AppState {
    pub sessions: SessionStore,
    pub downstream: Arc<DownstreamClient>,
    /// Policy engine — M1: always-allow no-op. M2 wires in SqlPolicyStore.
    pub policy: Arc<dyn PolicyEngine>,
    /// Audit sink — M1: no-op. M2 wires in structured JSON logger.
    pub audit: Arc<dyn AuditSink>,
}

pub async fn mcp_handler(
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
            // Log unknown sessions for visibility but always respond 204.
            let sid = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if get_session(&state.sessions, sid).is_none() {
                // Sanitize before logging to prevent log injection in structured log formats.
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

            if get_session(&state.sessions, &session_id).is_none() {
                if is_notification {
                    return notification_ack();
                }
                return error_json(error_response(
                    req.id.clone(),
                    ERR_INVALID_REQUEST,
                    "unknown session",
                ));
            }

            match method {
                "tools/list" => handle_tools_list(state, req).await,
                "tools/call" => handle_tools_call(state, req).await,
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
    let req_id = match require_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // The spec requires that clients MUST NOT include Mcp-Session-Id on initialize.
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

    // If the client requests a version we don't support, respond with our supported
    // version per the spec negotiation semantics — the client then decides whether
    // to proceed or disconnect. Only hard-reject if the client sends something
    // unparseable (handled above by the params parse failure).
    if params.protocol_version != SUPPORTED_PROTOCOL_VERSION {
        tracing::warn!(
            client_version = %params.protocol_version,
            server_version = %SUPPORTED_PROTOCOL_VERSION,
            "protocol version mismatch — responding with server version"
        );
    }
    let negotiated_version = SUPPORTED_PROTOCOL_VERSION;

    // Start from downstream capabilities so we accurately reflect what the downstream
    // supports. Then ensure tools is always present — we always proxy tools.
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
            return error_json(error_response(
                Some(req_id),
                ERR_INTERNAL,
                format!("serialization error: {e}"),
            ));
        }
    };

    // Build the full response body before creating the session — avoids leaking a
    // session slot if serialization fails.
    let resp = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req_id,
        result: result_value,
    };
    let body = serde_json::to_string(&resp).expect("JsonRpcResponse is always serialisable");

    let session_id = match create_session(&state.sessions) {
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

async fn handle_tools_list(state: Arc<AppState>, req: JsonRpcRequest) -> Response {
    let req_id = match require_id(&req) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let slug = state.downstream.slug();
    let raw_tools = state.downstream.list_tools().await;

    let namespaced: Vec<_> = raw_tools
        .into_iter()
        .map(|mut t| {
            t.name = format!("{slug}__{}", t.name);
            t
        })
        .collect();

    let result = ToolsListResult {
        tools: namespaced,
        next_cursor: None,
    };

    let result_value = match serde_json::to_value(&result) {
        Ok(v) => v,
        Err(e) => {
            return error_json(error_response(
                Some(req_id),
                ERR_INTERNAL,
                format!("serialization error: {e}"),
            ));
        }
    };

    let resp = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req_id,
        result: result_value,
    };

    json_response(resp)
}

async fn handle_tools_call(state: Arc<AppState>, req: JsonRpcRequest) -> Response {
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
            // Forward the downstream JSON-RPC error to the upstream, replacing the
            // downstream's id with the upstream request's id.
            error_json(JsonRpcError {
                jsonrpc: "2.0".to_string(),
                id: Some(req_id),
                error: downstream_err.error,
            })
        }
        Err(e) => error_json(error_response(
            Some(req_id),
            ERR_INTERNAL,
            format!("downstream error: {e}"),
        )),
    }
}

/// Extract the request ID from a JSON-RPC request, returning an error response if absent.
/// Requests (as opposed to notifications) MUST have an id.
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

fn error_json(err: JsonRpcError) -> Response {
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
