use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use mcpshield_core::mcp::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestId, RpcError, Tool, ToolCallParams,
    ToolCallResult, ToolsListResult, ERR_METHOD_NOT_FOUND,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RecordedCall {
    pub tool_name: String,
    pub arguments: Option<Value>,
    pub session_id: Option<String>,
}

struct MockState {
    tools: Vec<Tool>,
    calls: Mutex<Vec<RecordedCall>>,
    session_id: String,
}

pub struct MockMcpServer {
    addr: SocketAddr,
    state: Arc<MockState>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MockMcpServer {
    pub async fn start(tools: Vec<Tool>) -> Self {
        let state = Arc::new(MockState {
            tools,
            calls: Mutex::new(Vec::new()),
            session_id: Uuid::new_v4().to_string(),
        });

        let app = Router::new()
            .route("/mcp", post(handle_mcp))
            .with_state(Arc::clone(&state));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .ok();
        });

        Self {
            addr,
            state,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub async fn calls(&self) -> Vec<RecordedCall> {
        self.state.calls.lock().await.clone()
    }

    pub fn session_id(&self) -> &str {
        &self.state.session_id
    }
}

impl Drop for MockMcpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn handle_mcp(
    State(state): State<Arc<MockState>>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    match req.method.as_str() {
        "initialize" => {
            let result = json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": { "name": "mock-mcp-server", "version": "0.1.0" }
            });
            let resp = JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id.unwrap_or(RequestId::Number(0)),
                result,
            };
            axum::http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .header("mcp-session-id", state.session_id.clone())
                .body(serde_json::to_string(&resp).unwrap())
                .unwrap()
        }
        "notifications/initialized" => axum::http::Response::builder()
            .status(202)
            .body("".to_string())
            .unwrap(),
        "tools/list" => {
            let result = ToolsListResult {
                tools: state.tools.clone(),
                next_cursor: None,
            };
            let resp = JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id.unwrap_or(RequestId::Number(0)),
                result: serde_json::to_value(&result).unwrap(),
            };
            json_response(serde_json::to_string(&resp).unwrap())
        }
        "tools/call" => {
            let params: ToolCallParams = serde_json::from_value(
                req.params.clone().unwrap_or(Value::Null),
            )
            .unwrap_or(ToolCallParams {
                name: String::new(),
                arguments: None,
            });

            let session_id = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            state.calls.lock().await.push(RecordedCall {
                tool_name: params.name.clone(),
                arguments: params.arguments.clone(),
                session_id,
            });

            let call_result = ToolCallResult {
                content: vec![json!({"type": "text", "text": "mock result"})],
                is_error: None,
            };
            let resp = JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id.unwrap_or(RequestId::Number(0)),
                result: serde_json::to_value(&call_result).unwrap(),
            };
            json_response(serde_json::to_string(&resp).unwrap())
        }
        _ => {
            let err = JsonRpcError {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                error: RpcError {
                    code: ERR_METHOD_NOT_FOUND,
                    message: "method not found".to_string(),
                    data: None,
                },
            };
            json_response(serde_json::to_string(&err).unwrap())
        }
    }
}

fn json_response(body: String) -> axum::http::Response<String> {
    axum::http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}
