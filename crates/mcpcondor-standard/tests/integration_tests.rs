use std::sync::Arc;

use axum::Router;
use axum::routing::post;
use dashmap::DashMap;
use mcpcondor_core::mcp::{JsonRpcRequest, JsonRpcResponse, RequestId, Tool, SUPPORTED_PROTOCOL_VERSION};
use mcpcondor_core::vault::{VaultBackend, VaultTokenData};
use mcpcondor_db::Store;
use mcpcondor_db_sqlite::SqliteStore;
use mcpcondor_policy_db::DbPolicyEngine;
use mcpcondor_standard::downstream::DownstreamClient;
use mcpcondor_standard::handler::{
    mcp_handler_no_auth, new_admin_session_key, new_pending_store, new_pending_integration_auth_store,
    new_rate_limiter, new_setup_csrf_token, AppState,
};
use mcpcondor_standard::noop::NoopAudit;
use mcpcondor_standard::policy_cache::CachingPolicyEngine;
use mcpcondor_standard::session::new_store;
use mcpcondor_standard::vault::SqliteVaultBackend;
use mcpcondor_test_support::MockMcpServer;
use serde_json::json;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use uuid::Uuid;

// ─── Shared helpers ───────────────────────────────────────────────────────────

async fn make_db() -> Arc<dyn mcpcondor_db::Store> {
    let store = SqliteStore::open(":memory:").await.expect("open db");
    store.run_migrations().await.expect("run migrations");
    Arc::new(store) as Arc<dyn mcpcondor_db::Store>
}

struct NoopVault;
impl mcpcondor_core::vault::VaultBackend for NoopVault {
    fn store_token(
        &self, _: &str, _: &VaultTokenData,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), mcpcondor_core::error::CoreError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
    fn get_token(
        &self, _: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<VaultTokenData>, mcpcondor_core::error::CoreError>> + Send + '_>> {
        Box::pin(async { Ok(None) })
    }
    fn delete_token(
        &self, _: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), mcpcondor_core::error::CoreError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

async fn send_request(url: &str, req: &JsonRpcRequest) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{url}/mcp"))
        .json(req)
        .send()
        .await
        .expect("send request")
}

async fn send_with_session(url: &str, req: &JsonRpcRequest, session_id: &str) -> reqwest::Response {
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
            "clientInfo": {"name": "test", "version": "0.1"}
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

// ─── Test 1: Multi-integration routing ───────────────────────────────────────

#[tokio::test]
async fn test_multi_integration_routing() {
    // Start two different mock MCP servers
    let tools_a = vec![Tool {
        name: "tool_alpha".to_string(),
        description: None,
        input_schema: json!({"type": "object"}),
    }];
    let tools_b = vec![Tool {
        name: "tool_beta".to_string(),
        description: None,
        input_schema: json!({"type": "object"}),
    }];

    let mock_a = MockMcpServer::start(tools_a).await;
    let mock_b = MockMcpServer::start(tools_b).await;

    let db = make_db().await;
    let downstreams = Arc::new(DashMap::new());

    let id_a = Uuid::new_v4().to_string();
    let id_b = Uuid::new_v4().to_string();

    let client_a = Arc::new(
        DownstreamClient::new(mock_a.url(), "svc_a".to_string(), id_a).expect("build svc_a"),
    );
    client_a.initialize(None).await.expect("init svc_a");
    downstreams.insert("svc_a".to_string(), Arc::clone(&client_a));

    let client_b = Arc::new(
        DownstreamClient::new(mock_b.url(), "svc_b".to_string(), id_b).expect("build svc_b"),
    );
    client_b.initialize(None).await.expect("init svc_b");
    downstreams.insert("svc_b".to_string(), Arc::clone(&client_b));

    let policy = Arc::new(CachingPolicyEngine::new(Arc::new(
        mcpcondor_standard::noop::NoopPolicy,
    )));

    let state = Arc::new(AppState {
        sessions: new_store(),
        downstreams,
        policy,
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
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
        drop(mock_a);
        drop(mock_b);
    });

    let (_, session_id) = do_initialize(&proxy_url).await;
    assert!(!session_id.is_empty());

    let list_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(2)),
        method: "tools/list".to_string(),
        params: None,
    };
    let list_resp: JsonRpcResponse = send_with_session(&proxy_url, &list_req, &session_id)
        .await
        .json()
        .await
        .expect("parse tools/list");

    let tools_arr = list_resp.result["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools_arr.iter().map(|t| t["name"].as_str().unwrap()).collect();

    assert!(
        names.contains(&"svc_a__tool_alpha"),
        "expected svc_a__tool_alpha in {names:?}"
    );
    assert!(
        names.contains(&"svc_b__tool_beta"),
        "expected svc_b__tool_beta in {names:?}"
    );

    // Verify routing: call svc_a__tool_alpha goes to mock_a
    let call_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(3)),
        method: "tools/call".to_string(),
        params: Some(json!({"name": "svc_a__tool_alpha", "arguments": null})),
    };
    let call_resp: JsonRpcResponse = send_with_session(&proxy_url, &call_req, &session_id)
        .await
        .json()
        .await
        .expect("parse tools/call response");
    assert!(
        call_resp.result.get("content").is_some(),
        "svc_a tool call should succeed: {:?}",
        call_resp.result
    );
}

// ─── Test 2: Policy uses namespaced names ─────────────────────────────────────

#[tokio::test]
async fn test_policy_namespaced_isolation() {
    let tools_a = vec![Tool {
        name: "my_tool".to_string(),
        description: None,
        input_schema: json!({"type": "object"}),
    }];
    let tools_b = vec![Tool {
        name: "my_tool".to_string(),
        description: None,
        input_schema: json!({"type": "object"}),
    }];

    let mock_a = MockMcpServer::start(tools_a).await;
    let mock_b = MockMcpServer::start(tools_b).await;

    let db = make_db().await;
    let downstreams = Arc::new(DashMap::new());

    let id_a = Uuid::new_v4().to_string();
    let id_b = Uuid::new_v4().to_string();

    let client_a = Arc::new(
        DownstreamClient::new(mock_a.url(), "myint".to_string(), id_a).expect("build myint"),
    );
    client_a.initialize(None).await.expect("init myint");
    downstreams.insert("myint".to_string(), Arc::clone(&client_a));

    let client_b = Arc::new(
        DownstreamClient::new(mock_b.url(), "otherint".to_string(), id_b).expect("build otherint"),
    );
    client_b.initialize(None).await.expect("init otherint");
    downstreams.insert("otherint".to_string(), Arc::clone(&client_b));

    let policy_engine = Arc::new(DbPolicyEngine::new(Arc::clone(&db)));
    let policy = Arc::new(CachingPolicyEngine::new(policy_engine));

    let agent_id = Uuid::nil();

    // Allow myint__my_tool but NOT otherint__my_tool
    db.upsert_policy_rule(&mcpcondor_db::PolicyRule {
        agent_id: agent_id.to_string(),
        tool_name: "myint__my_tool".to_string(),
        allowed: true,
        created_at: 0,
    })
    .await
    .expect("upsert policy rule");

    let state = Arc::new(AppState {
        sessions: new_store(),
        downstreams,
        policy,
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
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
        drop(mock_a);
        drop(mock_b);
    });

    // The agent_id in the session comes from initialize — use nil UUID
    let (_, session_id) = do_initialize(&proxy_url).await;

    // tools/list should contain myint__my_tool but not otherint__my_tool
    let list_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(2)),
        method: "tools/list".to_string(),
        params: None,
    };
    let list_resp: JsonRpcResponse = send_with_session(&proxy_url, &list_req, &session_id)
        .await
        .json()
        .await
        .expect("parse tools/list");

    let tools_arr = list_resp.result["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools_arr.iter().map(|t| t["name"].as_str().unwrap()).collect();

    assert!(
        names.contains(&"myint__my_tool"),
        "myint__my_tool should be visible, got {names:?}"
    );
    assert!(
        !names.contains(&"otherint__my_tool"),
        "otherint__my_tool should be denied, got {names:?}"
    );

    // tools/call for otherint__my_tool should be denied
    let call_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(3)),
        method: "tools/call".to_string(),
        params: Some(json!({"name": "otherint__my_tool", "arguments": null})),
    };
    let call_resp_raw = send_with_session(&proxy_url, &call_req, &session_id).await;
    let call_resp: serde_json::Value = call_resp_raw.json().await.unwrap();
    assert!(
        call_resp.get("error").is_some(),
        "otherint__my_tool call should return error: {call_resp:?}"
    );
}

// ─── Test 3: Vault round-trip ─────────────────────────────────────────────────

#[tokio::test]
async fn test_vault_round_trip() {
    let db = make_db().await;

    // Use a fixed 32-byte key
    let master_key = [0x42u8; 32];
    let vault = SqliteVaultBackend::new(Arc::clone(&db), master_key);

    let integration_id = Uuid::new_v4().to_string();

    // Insert a matching integration row so the FK constraint is satisfied
    db.insert_integration(&mcpcondor_db::Integration {
        id: integration_id.clone(),
        slug: "test-vault".to_string(),
        name: "Test Vault".to_string(),
        mcp_url: "http://localhost:9999".to_string(),
        oauth_auth_url: None,
        oauth_token_url: None,
        oauth_client_id: None,
        oauth_scopes: None,
        connected: false,
        default_stance: false,
        created_at: 0,
    })
    .await
    .expect("insert integration");

    let original = VaultTokenData {
        client_secret: Some("s3cr3t".to_string()),
        access_token: Some("tok_abc123".to_string()),
        refresh_token: Some("ref_xyz456".to_string()),
        token_type: Some("Bearer".to_string()),
        expires_at: Some(9999999999),
    };

    // Store
    vault
        .store_token(&integration_id, &original)
        .await
        .expect("store_token should succeed");

    // Retrieve
    let retrieved = vault
        .get_token(&integration_id)
        .await
        .expect("get_token should succeed")
        .expect("token should exist");

    assert_eq!(retrieved.client_secret, original.client_secret);
    assert_eq!(retrieved.access_token, original.access_token);
    assert_eq!(retrieved.refresh_token, original.refresh_token);
    assert_eq!(retrieved.token_type, original.token_type);
    assert_eq!(retrieved.expires_at, original.expires_at);

    // Overwrite with different data
    let updated = VaultTokenData {
        client_secret: None,
        access_token: Some("tok_new456".to_string()),
        refresh_token: None,
        token_type: Some("Bearer".to_string()),
        expires_at: None,
    };
    vault
        .store_token(&integration_id, &updated)
        .await
        .expect("second store_token should succeed");

    let retrieved2 = vault
        .get_token(&integration_id)
        .await
        .expect("get_token should succeed")
        .expect("token should exist after update");

    assert_eq!(retrieved2.access_token, updated.access_token);
    assert_eq!(retrieved2.client_secret, None);

    // Delete
    vault
        .delete_token(&integration_id)
        .await
        .expect("delete_token should succeed");

    let after_delete = vault
        .get_token(&integration_id)
        .await
        .expect("get_token should succeed after delete");

    assert!(after_delete.is_none(), "token should be gone after delete");

    // Attempt to decrypt with wrong key should fail gracefully
    let wrong_key = [0x99u8; 32];
    let vault_wrong = SqliteVaultBackend::new(Arc::clone(&db), wrong_key);

    // Re-store with original key so we can try wrong-key decryption
    vault
        .store_token(&integration_id, &original)
        .await
        .expect("re-store should succeed");

    let bad_decrypt = vault_wrong.get_token(&integration_id).await;
    assert!(
        bad_decrypt.is_err(),
        "wrong key should fail decryption, got: {bad_decrypt:?}"
    );
}
