use std::sync::Arc;

use anyhow::{Context, Result};
use mcpshield_core::mcp::{
    InitializeResult, JsonRpcOutcome, JsonRpcRequest, RequestId, Tool,
    ToolCallParams, ToolsListParams, ToolsListResult, SUPPORTED_PROTOCOL_VERSION,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

const MAX_PAGINATION_PAGES: usize = 100;
const MAX_TOTAL_TOOLS: usize = 10_000;
/// Cap downstream response bodies to prevent an OOM from a compromised upstream.
const MAX_DOWNSTREAM_BODY_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

pub struct DownstreamClient {
    http: reqwest::Client,
    url: String,
    slug: String,
    pub integration_id: String,
    next_id: AtomicU64,
    session_id: RwLock<Option<String>>,
    tools: RwLock<Arc<Vec<Tool>>>,
    capabilities: RwLock<serde_json::Value>,
}

impl DownstreamClient {
    pub fn new(url: String, slug: String, integration_id: String) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            url,
            slug,
            integration_id,
            next_id: AtomicU64::new(1),
            session_id: RwLock::new(None),
            tools: RwLock::new(Arc::new(Vec::new())),
            capabilities: RwLock::new(serde_json::Value::Object(Default::default())),
        })
    }

    fn next_id(&self) -> RequestId {
        RequestId::Number(self.next_id.fetch_add(1, Ordering::AcqRel) as i64)
    }

    pub async fn initialize(&self, auth_token: Option<&str>) -> Result<()> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(self.next_id()),
            method: "initialize".to_string(),
            params: Some(json!({
                "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "mcpshield", "version": "0.1.0" }
            })),
        };

        let builder = self.http.post(format!("{}/mcp", self.url)).json(&req);
        let response = self
            .add_auth(builder, auth_token)
            .send()
            .await
            .context("downstream initialize request failed")?;

        if !response.status().is_success() {
            anyhow::bail!("downstream initialize returned HTTP {}", response.status());
        }

        let session_id = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty() && s.bytes().all(|b| (0x20..0x7f).contains(&b)))
            .map(|s| s.to_string());

        let body = response
            .bytes()
            .await
            .context("downstream initialize response read failed")?;
        if body.len() > MAX_DOWNSTREAM_BODY_BYTES {
            anyhow::bail!("downstream initialize response exceeds size limit");
        }
        let outcome: JsonRpcOutcome = serde_json::from_slice(&body)
            .context("downstream initialize response parse failed")?;

        let init_result = match outcome {
            JsonRpcOutcome::Error(err) => anyhow::bail!(
                "downstream initialize failed: {} (code {})",
                err.error.message,
                err.error.code
            ),
            JsonRpcOutcome::Success(resp) => serde_json::from_value::<InitializeResult>(resp.result)
                .context("downstream initialize result parse failed")?,
        };

        *self.capabilities.write().await = init_result.capabilities;
        *self.session_id.write().await = session_id;

        self.send_initialized(auth_token).await?;
        self.refresh_tools(auth_token).await?;
        Ok(())
    }

    async fn send_initialized(&self, auth_token: Option<&str>) -> Result<()> {
        let notification = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: "notifications/initialized".to_string(),
            params: None,
        };

        let mut builder = self
            .http
            .post(format!("{}/mcp", self.url))
            .json(&notification);

        if let Some(sid) = self.session_id.read().await.as_ref() {
            builder = builder.header("mcp-session-id", sid.clone());
        }
        builder = self.add_auth(builder, auth_token);

        let resp = builder
            .send()
            .await
            .context("downstream notifications/initialized failed")?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "downstream notifications/initialized returned HTTP {}",
                resp.status()
            );
        }

        Ok(())
    }

    async fn refresh_tools(&self, auth_token: Option<&str>) -> Result<()> {
        let mut all_tools: Vec<Tool> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;

        loop {
            if pages >= MAX_PAGINATION_PAGES {
                anyhow::bail!(
                    "downstream tools/list exceeded {} pagination pages",
                    MAX_PAGINATION_PAGES
                );
            }
            pages += 1;

            let params = ToolsListParams {
                cursor: cursor.clone(),
            };
            let req = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(self.next_id()),
                method: "tools/list".to_string(),
                params: Some(serde_json::to_value(&params)?),
            };

            let mut builder = self
                .http
                .post(format!("{}/mcp", self.url))
                .json(&req);

            if let Some(sid) = self.session_id.read().await.as_ref() {
                builder = builder.header("mcp-session-id", sid.clone());
            }
            builder = self.add_auth(builder, auth_token);

            let resp = builder
                .send()
                .await
                .context("downstream tools/list request failed")?;

            if !resp.status().is_success() {
                anyhow::bail!("downstream tools/list returned HTTP {}", resp.status());
            }

            let body = resp
                .bytes()
                .await
                .context("downstream tools/list response read failed")?;
            if body.len() > MAX_DOWNSTREAM_BODY_BYTES {
                anyhow::bail!("downstream tools/list response exceeds size limit");
            }
            let outcome: JsonRpcOutcome = serde_json::from_slice(&body)
                .context("downstream tools/list response parse failed")?;

            let json_resp = match outcome {
                JsonRpcOutcome::Success(r) => r,
                JsonRpcOutcome::Error(e) => anyhow::bail!(
                    "downstream tools/list failed: {} (code {})",
                    e.error.message,
                    e.error.code
                ),
            };

            let list: ToolsListResult = serde_json::from_value(json_resp.result)
                .context("downstream tools/list result parse failed")?;

            all_tools.extend(list.tools);

            if all_tools.len() > MAX_TOTAL_TOOLS {
                anyhow::bail!(
                    "downstream tools/list exceeded {} total tools",
                    MAX_TOTAL_TOOLS
                );
            }

            match list.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }

        *self.tools.write().await = Arc::new(all_tools);
        Ok(())
    }

    pub async fn list_tools(&self) -> Arc<Vec<Tool>> {
        Arc::clone(&*self.tools.read().await)
    }

    pub fn slug(&self) -> &str {
        &self.slug
    }

    pub async fn capabilities(&self) -> serde_json::Value {
        self.capabilities.read().await.clone()
    }

    pub async fn downstream_session_id(&self) -> Option<String> {
        self.session_id.read().await.clone()
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Value>,
        auth_token: Option<&str>,
    ) -> Result<JsonRpcOutcome> {
        let params = ToolCallParams {
            name: name.to_string(),
            arguments,
        };
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(self.next_id()),
            method: "tools/call".to_string(),
            params: Some(serde_json::to_value(&params)?),
        };

        let mut builder = self
            .http
            .post(format!("{}/mcp", self.url))
            .json(&req);

        if let Some(sid) = self.session_id.read().await.as_ref() {
            builder = builder.header("mcp-session-id", sid.clone());
        }
        builder = self.add_auth(builder, auth_token);

        let resp = builder
            .send()
            .await
            .context("downstream tools/call request failed")?;

        if !resp.status().is_success() {
            anyhow::bail!("downstream tools/call returned HTTP {}", resp.status());
        }

        let body = resp
            .bytes()
            .await
            .context("downstream tools/call response read failed")?;
        if body.len() > MAX_DOWNSTREAM_BODY_BYTES {
            anyhow::bail!("downstream tools/call response exceeds size limit");
        }
        serde_json::from_slice::<JsonRpcOutcome>(&body)
            .context("downstream tools/call response parse failed")
    }

    fn add_auth(&self, builder: reqwest::RequestBuilder, auth_token: Option<&str>) -> reqwest::RequestBuilder {
        if let Some(token) = auth_token {
            builder.header("authorization", format!("Bearer {token}"))
        } else {
            builder
        }
    }
}
