use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::post;
use axum::Router;
use dashmap::DashMap;
use mcpcondor_core::mcp::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestId, Tool, SUPPORTED_PROTOCOL_VERSION,
};
use mcpcondor_db::Store;
use mcpcondor_standard::handler::{
    mcp_handler_no_auth, new_admin_session_key, new_pending_store, new_pending_integration_auth_store,
    new_rate_limiter, new_setup_csrf_token, AppState,
};
use mcpcondor_standard::noop::NoopAudit;
use mcpcondor_standard::policy_cache::CachingPolicyEngine;
use mcpcondor_standard::noop::NoopPolicy;
use mcpcondor_standard::session::new_store;
use mcpcondor_standard::downstream::DownstreamClient;
use mcpcondor_test_support::MockMcpServer;
use serde_json::json;
use tokio::net::TcpListener;

/// Create an in-memory SQLite DB with migrations applied.
async fn make_test_db() -> Arc<dyn mcpcondor_db::Store> {
    let store = mcpcondor_db_sqlite::SqliteStore::open(":memory:")
        .await
        .expect("open in-memory db");
    store.run_migrations().await.expect("run migrations");
    Arc::new(store) as Arc<dyn mcpcondor_db::Store>
}

// Minimal NoopVault for tests
struct NoopVault;
impl mcpcondor_core::vault::VaultBackend for NoopVault {
    fn store_token(
        &self, _: &str, _: &mcpcondor_core::vault::VaultTokenData,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), mcpcondor_core::error::CoreError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
    fn get_token(
        &self, _: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<mcpcondor_core::vault::VaultTokenData>, mcpcondor_core::error::CoreError>> + Send + '_>> {
        Box::pin(async { Ok(None) })
    }
    fn delete_token(
        &self, _: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), mcpcondor_core::error::CoreError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

async fn start_proxy(mock_url: String, slug: &str) -> (String, Arc<AppState>) {
    let integration_id = uuid::Uuid::new_v4().to_string();
    let downstream = Arc::new(
        DownstreamClient::new(mock_url, slug.to_string(), integration_id).expect("build downstream"),
    );
    downstream.initialize(None).await.expect("downstream init");

    let db = make_test_db().await;
    let downstreams = Arc::new(DashMap::new());
    downstreams.insert(slug.to_string(), Arc::clone(&downstream));

    let state = Arc::new(AppState {
        sessions: new_store(),
        downstreams,
        policy: Arc::new(CachingPolicyEngine::new(Arc::new(NoopPolicy))),
        audit: Arc::new(NoopAudit),
        db,
        vault: Arc::new(NoopVault),
        pending_auth: new_pending_store(),
        pending_integration_auth: new_pending_integration_auth_store(),
        rate_limiter: new_rate_limiter(),
        admin_rate_limiter: new_rate_limiter(),
        setup_csrf_token: new_setup_csrf_token(),
        admin_session_key: new_admin_session_key(),
        bearer_cache: Arc::new(DashMap::new()),
        vault_cache: Arc::new(DashMap::new()),
    });

    let app = Router::new()
        .route("/mcp", post(mcp_handler_no_auth))
        .with_state(Arc::clone(&state));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
    });

    (format!("http://{}", addr), state)
}

async fn send_request(url: &str, req: &JsonRpcRequest) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{url}/mcp"))
        .json(req)
        .send()
        .await
        .expect("send request")
}

async fn send_request_with_session(
    url: &str,
    req: &JsonRpcRequest,
    session_id: &str,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{url}/mcp"))
        .header("mcp-session-id", session_id)
        .json(req)
        .send()
        .await
        .expect("send request with session")
}

async fn do_initialize(url: &str) -> (JsonRpcResponse, String) {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(1)),
        method: "initialize".to_string(),
        params: Some(json!({
            "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.0.1" }
        })),
    };
    let resp = send_request(url, &req).await;
    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body: JsonRpcResponse = resp.json().await.expect("parse initialize response");
    (body, session_id)
}

#[tokio::test]
async fn test_initialize_accepted() {
    let mock = MockMcpServer::start(vec![]).await;
    let (proxy_url, _state) = start_proxy(mock.url(), "fs").await;

    let (resp, session_id) = do_initialize(&proxy_url).await;

    assert!(!session_id.is_empty(), "Mcp-Session-Id header must be set");
    let version = resp.result["protocolVersion"].as_str().unwrap();
    assert_eq!(version, SUPPORTED_PROTOCOL_VERSION);
}

#[tokio::test]
async fn test_initialize_version_negotiated() {
    let mock = MockMcpServer::start(vec![]).await;
    let (proxy_url, _state) = start_proxy(mock.url(), "fs").await;

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(1)),
        method: "initialize".to_string(),
        params: Some(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.0.1" }
        })),
    };

    let resp = send_request(&proxy_url, &req).await;
    let body: JsonRpcResponse = resp.json().await.expect("parse initialize response");
    assert_eq!(
        body.result["protocolVersion"].as_str().unwrap(),
        SUPPORTED_PROTOCOL_VERSION,
        "server must respond with its own supported version"
    );
}

#[tokio::test]
async fn test_tools_list_namespaced() {
    let tools = vec![
        Tool {
            name: "read_file".to_string(),
            description: None,
            input_schema: json!({"type": "object"}),
        },
        Tool {
            name: "write_file".to_string(),
            description: None,
            input_schema: json!({"type": "object"}),
        },
    ];
    let mock = MockMcpServer::start(tools).await;
    let (proxy_url, _state) = start_proxy(mock.url(), "fs").await;

    let (_init_resp, session_id) = do_initialize(&proxy_url).await;
    assert!(!session_id.is_empty());

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(2)),
        method: "tools/list".to_string(),
        params: None,
    };

    let resp = send_request_with_session(&proxy_url, &req, &session_id).await;
    let body: JsonRpcResponse = resp.json().await.expect("parse tools/list response");

    let tools_arr = body.result["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools_arr
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();

    assert!(names.contains(&"fs__read_file"), "expected fs__read_file, got {names:?}");
    assert!(names.contains(&"fs__write_file"), "expected fs__write_file, got {names:?}");
}

#[tokio::test]
async fn test_tools_call_routed() {
    let tools = vec![Tool {
        name: "read_file".to_string(),
        description: None,
        input_schema: json!({"type": "object"}),
    }];
    let mock = MockMcpServer::start(tools).await;
    let mock_url = mock.url();
    let (proxy_url, _state) = start_proxy(mock_url, "fs").await;

    let (_init_resp, session_id) = do_initialize(&proxy_url).await;

    let args = json!({"path": "/etc/hosts"});
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(3)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "fs__read_file",
            "arguments": args
        })),
    };

    let resp = send_request_with_session(&proxy_url, &req, &session_id).await;
    let body: JsonRpcResponse = resp.json().await.expect("parse tools/call response");
    let content = body.result["content"].as_array().expect("content array");
    assert!(!content.is_empty());

    let calls = mock.calls().await;
    assert_eq!(calls.len(), 1, "mock should have received one call");
    assert_eq!(calls[0].tool_name, "read_file");
    assert_eq!(calls[0].arguments, Some(args));
    assert_eq!(
        calls[0].session_id.as_deref(),
        Some(mock.session_id()),
        "proxy must forward downstream session ID on tool calls"
    );
}

#[tokio::test]
async fn test_tools_call_unknown_slug() {
    let mock = MockMcpServer::start(vec![]).await;
    let (proxy_url, _state) = start_proxy(mock.url(), "fs").await;

    let (_init_resp, session_id) = do_initialize(&proxy_url).await;

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(4)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "unknown__something",
            "arguments": null
        })),
    };

    let resp = send_request_with_session(&proxy_url, &req, &session_id).await;
    let body: JsonRpcError = resp.json().await.expect("parse error response");

    assert_eq!(body.error.code, -32601, "expected method-not-found error code");
}

#[tokio::test]
async fn test_tools_call_known_slug_unknown_tool() {
    let mock = MockMcpServer::start(vec![]).await;
    let (proxy_url, _state) = start_proxy(mock.url(), "fs").await;

    let (_init_resp, session_id) = do_initialize(&proxy_url).await;

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(4)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "fs__nonexistent",
            "arguments": null
        })),
    };

    let resp = send_request_with_session(&proxy_url, &req, &session_id).await;
    let body: JsonRpcError = resp.json().await.expect("parse error response");

    assert_eq!(body.error.code, -32601, "expected method-not-found for unknown local tool");
}

#[tokio::test]
async fn test_tools_call_no_namespace_separator() {
    let mock = MockMcpServer::start(vec![]).await;
    let (proxy_url, _state) = start_proxy(mock.url(), "fs").await;

    let (_init_resp, session_id) = do_initialize(&proxy_url).await;

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(4)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "read_file",
            "arguments": null
        })),
    };

    let resp = send_request_with_session(&proxy_url, &req, &session_id).await;
    let body: JsonRpcError = resp.json().await.expect("parse error response");

    assert_eq!(body.error.code, -32601, "expected method-not-found for non-namespaced tool");
}

#[tokio::test]
async fn test_notifications_initialized_valid_session() {
    let mock = MockMcpServer::start(vec![]).await;
    let (proxy_url, _state) = start_proxy(mock.url(), "fs").await;

    let (_init_resp, session_id) = do_initialize(&proxy_url).await;
    assert!(!session_id.is_empty());

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: None,
        method: "notifications/initialized".to_string(),
        params: None,
    };

    let resp = send_request_with_session(&proxy_url, &req, &session_id).await;
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_notifications_initialized_without_session_accepted_silently() {
    let mock = MockMcpServer::start(vec![]).await;
    let (proxy_url, _state) = start_proxy(mock.url(), "fs").await;

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: None,
        method: "notifications/initialized".to_string(),
        params: None,
    };

    let resp = send_request(&proxy_url, &req).await;
    assert_eq!(resp.status(), 204, "notifications must always get 204, never a meaningful error");
}
