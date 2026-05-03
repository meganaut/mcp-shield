use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, post};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::DashMap;
use mcpshield_core::mcp::{JsonRpcRequest, JsonRpcResponse, RequestId, Tool, SUPPORTED_PROTOCOL_VERSION};
use mcpshield_db::Store;
use mcpshield_db_sqlite::SqliteStore;
use mcpshield_policy_db::DbPolicyEngine;
use mcpshield_standard::admin::{delete_policy, get_policy, list_agents, set_policy};
use mcpshield_standard::downstream::DownstreamClient;
use mcpshield_standard::handler::{
    mcp_handler_authenticated, new_pending_store, new_pending_integration_auth_store,
    new_rate_limiter, new_setup_csrf_token, AppState,
};
use std::net::SocketAddr;
use mcpshield_standard::noop::NoopAudit;
use mcpshield_standard::oauth::authorize::{get_authorize, post_authorize};
use mcpshield_standard::oauth::dcr::post_register;
use mcpshield_standard::oauth::metadata::get_metadata;
use mcpshield_standard::oauth::token::post_token;
use mcpshield_standard::policy_cache::CachingPolicyEngine;
use mcpshield_standard::session::new_store;
use mcpshield_test_support::MockMcpServer;
use rand::RngCore;
use serde_json::json;
use tokio::net::TcpListener;

struct NoopVault;
impl mcpshield_core::vault::VaultBackend for NoopVault {
    fn store_token(
        &self, _: &str, _: &mcpshield_core::vault::VaultTokenData,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), mcpshield_core::error::CoreError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
    fn get_token(
        &self, _: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<mcpshield_core::vault::VaultTokenData>, mcpshield_core::error::CoreError>> + Send + '_>> {
        Box::pin(async { Ok(None) })
    }
    fn delete_token(
        &self, _: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), mcpshield_core::error::CoreError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

// ─── Test helpers ────────────────────────────────────────────────────────────

/// Create a fresh in-memory SQLite DB with migrations and setup completed.
async fn make_db(issuer_url: &str) -> Arc<dyn Store> {
    let store = SqliteStore::open(":memory:").await.expect("open db");
    store.run_migrations().await.expect("migrations");

    // Hash a known password "testpassword1234!" with argon2id for the admin
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(b"testpassword1234!", &salt)
        .unwrap()
        .to_string();

    store
        .complete_setup("admin", &hash, issuer_url)
        .await
        .expect("complete setup");

    Arc::new(store) as Arc<dyn Store>
}

/// Start a full gateway (with OAuth, admin, mcp routes) for testing.
/// Returns (gateway_base_url, db_arc).
async fn start_gateway(tools: Vec<Tool>) -> (String, Arc<dyn Store>) {
    let mock = MockMcpServer::start(tools).await;

    let db = make_db("http://localhost").await;

    let integration_id = uuid::Uuid::new_v4().to_string();
    let downstream = Arc::new(
        DownstreamClient::new(mock.url(), "fs".to_string(), integration_id).expect("build downstream"),
    );
    downstream.initialize(None).await.expect("downstream init");

    let downstreams = Arc::new(DashMap::new());
    downstreams.insert("fs".to_string(), Arc::clone(&downstream));

    let policy = Arc::new(CachingPolicyEngine::new(Arc::new(DbPolicyEngine::new(Arc::clone(&db)))));

    let state = Arc::new(AppState {
        sessions: new_store(),
        downstreams,
        policy,
        audit: Arc::new(NoopAudit),
        db: Arc::clone(&db),
        vault: Arc::new(NoopVault),
        pending_auth: new_pending_store(),
        pending_integration_auth: new_pending_integration_auth_store(),
        rate_limiter: new_rate_limiter(),
        admin_rate_limiter: new_rate_limiter(),
        setup_csrf_token: new_setup_csrf_token(),
        bearer_cache: Arc::new(DashMap::new()),
        vault_cache: Arc::new(DashMap::new()),
    });

    let app = Router::new()
        .route("/mcp", post(mcp_handler_authenticated))
        .route("/.well-known/oauth-authorization-server", get(get_metadata))
        .route("/oauth/register", post(post_register))
        .route("/oauth/authorize", get(get_authorize).post(post_authorize))
        .route("/oauth/token", post(post_token))
        .route("/admin/agents", get(list_agents))
        .route("/admin/agents/{agent_id}/policy", get(get_policy).post(set_policy))
        .route("/admin/agents/{agent_id}/policy/{tool_name}", delete(delete_policy))
        .with_state(Arc::clone(&state));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .ok();
        drop(mock); // Keep mock alive
    });

    (base_url, db)
}

fn pkce_pair() -> (String, String) {
    use sha2::Digest;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let verifier = URL_SAFE_NO_PAD.encode(&buf);
    let hash = sha2::Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash.as_slice());
    (verifier, challenge)
}

// ─── DCR Tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_dcr_registers_client() {
    let (base_url, _db) = start_gateway(vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base_url}/oauth/register"))
        .basic_auth("admin", Some("testpassword1234!"))
        .json(&json!({
            "client_name": "Test Agent",
            "redirect_uris": ["https://example.com/callback"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201, "DCR should return 201");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["client_id"].is_string(), "client_id must be present");
    assert!(body["client_secret"].is_string(), "client_secret must be present");
    assert!(body["agent_id"].is_string(), "agent_id must be present");
    assert_eq!(body["client_name"], "Test Agent");
    assert_eq!(body["redirect_uris"][0], "https://example.com/callback");
}

#[tokio::test]
async fn test_dcr_rejects_http_redirect() {
    let (base_url, _db) = start_gateway(vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base_url}/oauth/register"))
        .basic_auth("admin", Some("testpassword1234!"))
        .json(&json!({
            "client_name": "Bad Agent",
            "redirect_uris": ["http://evil.com/callback"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "Non-localhost http:// should be rejected");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_redirect_uri");
}

#[tokio::test]
async fn test_dcr_rejects_empty_redirect_uris() {
    let (base_url, _db) = start_gateway(vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base_url}/oauth/register"))
        .basic_auth("admin", Some("testpassword1234!"))
        .json(&json!({
            "client_name": "Empty Agent",
            "redirect_uris": []
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "Empty redirect_uris should be rejected");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_redirect_uri");
}

#[tokio::test]
async fn test_dcr_rejects_unauthenticated() {
    let (base_url, _db) = start_gateway(vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base_url}/oauth/register"))
        .json(&json!({
            "client_name": "Sneaky Agent",
            "redirect_uris": ["https://example.com/callback"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "Unauthenticated DCR must return 401");
}

// ─── Authorize Tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_authorize_rejects_bad_client_id() {
    let (base_url, _db) = start_gateway(vec![]).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{base_url}/oauth/authorize?response_type=code&client_id=nonexistent&redirect_uri=https://example.com/cb&code_challenge=abc&code_challenge_method=S256&state=xyz"
        ))
        .send()
        .await
        .unwrap();

    // Must return 400, not redirect
    assert_eq!(resp.status(), 400, "Unknown client_id must return 400 (not redirect)");
    // Must NOT have Location header (no redirect)
    assert!(
        resp.headers().get("location").is_none(),
        "Must not redirect on invalid client_id"
    );
}

#[tokio::test]
async fn test_authorize_rejects_plain_pkce() {
    let (base_url, _db) = start_gateway(vec![]).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // First register a client (admin auth required)
    let reg_resp: serde_json::Value = client
        .post(format!("{base_url}/oauth/register"))
        .basic_auth("admin", Some("testpassword1234!"))
        .json(&json!({
            "client_name": "PKCE Test",
            "redirect_uris": ["https://example.com/cb"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id = reg_resp["client_id"].as_str().unwrap();

    let resp = client
        .get(format!(
            "{base_url}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=https://example.com/cb&code_challenge=abc123&code_challenge_method=plain&state=xyz"
        ))
        .send()
        .await
        .unwrap();

    // Should redirect with error=invalid_request
    assert!(
        resp.status().is_redirection(),
        "Should redirect, got: {}",
        resp.status()
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.contains("error=invalid_request"),
        "Location must contain error=invalid_request, got: {location}"
    );
}

// ─── Full OAuth Flow ──────────────────────────────────────────────────────────

/// Perform DCR with admin credentials, extract client credentials.
async fn do_register(base_url: &str, client: &reqwest::Client) -> (String, String, String) {
    let resp: serde_json::Value = client
        .post(format!("{base_url}/oauth/register"))
        .basic_auth("admin", Some("testpassword1234!"))
        .json(&json!({
            "client_name": "Integration Test Agent",
            "redirect_uris": ["http://localhost/callback"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        resp["client_id"].as_str().unwrap().to_string(),
        resp["client_secret"].as_str().unwrap().to_string(),
        resp["agent_id"].as_str().unwrap().to_string(),
    )
}

/// Perform the authorize flow, returning the auth code.
async fn do_authorize(
    base_url: &str,
    client: &reqwest::Client,
    client_id: &str,
    code_challenge: &str,
    state_val: &str,
) -> String {
    // GET authorize — returns HTML form with request_id
    let form_resp = client
        .get(format!(
            "{base_url}/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=http://localhost/callback&code_challenge={code_challenge}&code_challenge_method=S256&state={state_val}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(form_resp.status(), 200, "authorize GET should return 200");
    let html = form_resp.text().await.unwrap();

    // Extract request_id from hidden input
    let request_id = html
        .lines()
        .find(|l| l.contains("name=\"request_id\""))
        .and_then(|l| {
            let start = l.find("value=\"")? + 7;
            let end = l[start..].find('"')? + start;
            Some(l[start..end].to_string())
        })
        .expect("request_id hidden input not found");

    // POST credentials — no-follow redirect client
    let no_follow = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let post_resp = no_follow
        .post(format!("{base_url}/oauth/authorize"))
        .form(&[
            ("request_id", request_id.as_str()),
            ("username", "admin"),
            ("password", "testpassword1234!"),
        ])
        .send()
        .await
        .unwrap();

    assert!(
        post_resp.status().is_redirection(),
        "POST authorize should redirect, got: {}",
        post_resp.status()
    );

    let location = post_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Extract code from Location: http://localhost/callback?code=XXX&state=YYY
    let code = location
        .split('?')
        .nth(1)
        .and_then(|qs| {
            qs.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == "code" { Some(v.to_string()) } else { None }
            })
        })
        .expect("code not found in Location header");

    code
}

/// Exchange code for token.
async fn do_token_exchange(
    base_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    code_verifier: &str,
) -> String {
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(format!("{base_url}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", "http://localhost/callback"),
            ("code_verifier", code_verifier),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    resp["access_token"]
        .as_str()
        .expect("access_token missing")
        .to_string()
}

#[tokio::test]
async fn test_full_oauth_flow() {
    let tools = vec![Tool {
        name: "ping".to_string(),
        description: None,
        input_schema: json!({"type": "object"}),
    }];
    let (base_url, _db) = start_gateway(tools).await;
    let client = reqwest::Client::new();

    // 1. Register
    let (client_id, client_secret, agent_id) = do_register(&base_url, &client).await;

    // 2. Authorize
    let (verifier, challenge) = pkce_pair();
    let code = do_authorize(&base_url, &client, &client_id, &challenge, "teststate").await;
    assert!(!code.is_empty(), "auth code must be non-empty");

    // 3. Token exchange
    let token = do_token_exchange(&base_url, &client_id, &client_secret, &code, &verifier).await;
    assert!(!token.is_empty(), "access token must be non-empty");

    // 4. Add allow policy for "fs__ping" tool via admin API (namespaced)
    let policy_resp = reqwest::Client::new()
        .post(format!("{base_url}/admin/agents/{agent_id}/policy"))
        .basic_auth("admin", Some("testpassword1234!"))
        .json(&json!({"tool_name": "fs__ping", "allowed": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(policy_resp.status(), 204, "admin policy set should return 204");

    // 5. Use token on /mcp initialize
    let init_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(1)),
        method: "initialize".to_string(),
        params: Some(json!({
            "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}
        })),
    };
    let init_resp = client
        .post(format!("{base_url}/mcp"))
        .bearer_auth(&token)
        .json(&init_req)
        .send()
        .await
        .unwrap();

    assert_eq!(init_resp.status(), 200);
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(!session_id.is_empty(), "must get session after initialize");

    let _: JsonRpcResponse = init_resp.json().await.unwrap();

    // 6. Call tools/list — should see ping (allowed)
    let list_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(2)),
        method: "tools/list".to_string(),
        params: None,
    };
    let list_resp: JsonRpcResponse = client
        .post(format!("{base_url}/mcp"))
        .bearer_auth(&token)
        .header("mcp-session-id", &session_id)
        .json(&list_req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let empty = vec![];
    let tool_names: Vec<&str> = list_resp.result["tools"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        tool_names.contains(&"fs__ping"),
        "ping should be visible, got: {tool_names:?}"
    );
}

// ─── Policy Tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_policy_deny_by_default() {
    let tools = vec![Tool {
        name: "secret_tool".to_string(),
        description: None,
        input_schema: json!({"type": "object"}),
    }];
    let (base_url, _db) = start_gateway(tools).await;
    let client = reqwest::Client::new();

    // Register + authorize + get token
    let (client_id, client_secret, _agent_id) = do_register(&base_url, &client).await;
    let (verifier, challenge) = pkce_pair();
    let code = do_authorize(&base_url, &client, &client_id, &challenge, "s1").await;
    let token = do_token_exchange(&base_url, &client_id, &client_secret, &code, &verifier).await;

    // Initialize
    let init_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(1)),
        method: "initialize".to_string(),
        params: Some(json!({
            "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}
        })),
    };
    let init_resp = client
        .post(format!("{base_url}/mcp"))
        .bearer_auth(&token)
        .json(&init_req)
        .send()
        .await
        .unwrap();
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // tools/list should be empty (no policy rules = deny all)
    let list_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(2)),
        method: "tools/list".to_string(),
        params: None,
    };
    let list_resp: JsonRpcResponse = client
        .post(format!("{base_url}/mcp"))
        .bearer_auth(&token)
        .header("mcp-session-id", &session_id)
        .json(&list_req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tools_arr = list_resp.result["tools"].as_array().unwrap();
    assert!(
        tools_arr.is_empty(),
        "No tools should be visible with no policy rules"
    );

    // tools/call should fail with "tool not permitted"
    let call_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(3)),
        method: "tools/call".to_string(),
        params: Some(json!({"name": "fs__secret_tool", "arguments": null})),
    };
    let call_resp_raw = client
        .post(format!("{base_url}/mcp"))
        .bearer_auth(&token)
        .header("mcp-session-id", &session_id)
        .json(&call_req)
        .send()
        .await
        .unwrap();
    let call_resp: serde_json::Value = call_resp_raw.json().await.unwrap();
    assert!(
        call_resp.get("error").is_some(),
        "tool call should return error: {call_resp:?}"
    );
    let msg = call_resp["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("not permitted"),
        "error message should say 'not permitted', got: {msg}"
    );
}

#[tokio::test]
async fn test_policy_allow_via_admin_api() {
    let tools = vec![Tool {
        name: "read_file".to_string(),
        description: None,
        input_schema: json!({"type": "object"}),
    }];
    let (base_url, _db) = start_gateway(tools).await;
    let client = reqwest::Client::new();

    let (client_id, client_secret, agent_id) = do_register(&base_url, &client).await;
    let (verifier, challenge) = pkce_pair();
    let code = do_authorize(&base_url, &client, &client_id, &challenge, "s2").await;
    let token = do_token_exchange(&base_url, &client_id, &client_secret, &code, &verifier).await;

    // Add allow rule via admin API (namespaced tool name)
    let admin_resp = client
        .post(format!("{base_url}/admin/agents/{agent_id}/policy"))
        .basic_auth("admin", Some("testpassword1234!"))
        .json(&json!({"tool_name": "fs__read_file", "allowed": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(admin_resp.status(), 204, "admin policy set should return 204");

    // Initialize
    let init_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(1)),
        method: "initialize".to_string(),
        params: Some(json!({
            "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}
        })),
    };
    let init_resp = client
        .post(format!("{base_url}/mcp"))
        .bearer_auth(&token)
        .json(&init_req)
        .send()
        .await
        .unwrap();
    let session_id = init_resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // tools/list should now show read_file
    let list_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(2)),
        method: "tools/list".to_string(),
        params: None,
    };
    let list_resp: JsonRpcResponse = client
        .post(format!("{base_url}/mcp"))
        .bearer_auth(&token)
        .header("mcp-session-id", &session_id)
        .json(&list_req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let empty2 = vec![];
    let tool_names: Vec<&str> = list_resp.result["tools"]
        .as_array()
        .unwrap_or(&empty2)
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        tool_names.contains(&"fs__read_file"),
        "read_file should be visible after allow rule, got: {tool_names:?}"
    );

    // tools/call should succeed
    let call_req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(3)),
        method: "tools/call".to_string(),
        params: Some(json!({"name": "fs__read_file", "arguments": {"path": "/test"}})),
    };
    let call_resp: JsonRpcResponse = client
        .post(format!("{base_url}/mcp"))
        .bearer_auth(&token)
        .header("mcp-session-id", &session_id)
        .json(&call_req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        call_resp.result.get("content").is_some(),
        "tool call should succeed with content: {:?}",
        call_resp.result
    );
}

// ─── Token single-use test ────────────────────────────────────────────────────

#[tokio::test]
async fn test_token_exchange_single_use() {
    let (base_url, _db) = start_gateway(vec![]).await;
    let client = reqwest::Client::new();

    let (client_id, client_secret, _agent_id) = do_register(&base_url, &client).await;
    let (verifier, challenge) = pkce_pair();
    let code = do_authorize(&base_url, &client, &client_id, &challenge, "s3").await;

    // Exchange same code concurrently — exactly one must succeed
    let (r1, r2) = tokio::join!(
        async {
            reqwest::Client::new()
                .post(format!("{base_url}/oauth/token"))
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", "http://localhost/callback"),
                    ("code_verifier", &verifier),
                    ("client_id", &client_id),
                    ("client_secret", &client_secret),
                ])
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        },
        async {
            reqwest::Client::new()
                .post(format!("{base_url}/oauth/token"))
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", "http://localhost/callback"),
                    ("code_verifier", &verifier),
                    ("client_id", &client_id),
                    ("client_secret", &client_secret),
                ])
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    );

    let success_count = [&r1, &r2]
        .iter()
        .filter(|r| r.get("access_token").is_some())
        .count();
    let error_count = [&r1, &r2]
        .iter()
        .filter(|r| r.get("error").is_some())
        .count();

    assert_eq!(
        success_count, 1,
        "Exactly one exchange should succeed (got {success_count} successes, {error_count} errors). r1={r1}, r2={r2}"
    );
    assert_eq!(error_count, 1, "Exactly one exchange should fail");
}
