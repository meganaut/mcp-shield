use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::types::{AgentId, IntegrationId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: Option<String>,
}

pub trait PolicyStore: Send + Sync {
    fn evaluate(
        &self,
        agent_id: &AgentId,
        integration_id: &IntegrationId,
        tool_name: &str,
        params: &serde_json::Value,
    ) -> impl Future<Output = Result<PolicyDecision, CoreError>> + Send;
}

/// Object-safe version of `PolicyStore` for use as `Arc<dyn PolicyEngine>`.
pub trait PolicyEngine: Send + Sync {
    fn evaluate_boxed<'a>(
        &'a self,
        agent_id: &'a AgentId,
        integration_id: &'a IntegrationId,
        tool_name: &'a str,
        params: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, CoreError>> + Send + 'a>>;

    /// Batch version of evaluate_boxed for tools/list: returns the set of allowed tool names.
    /// The default implementation calls evaluate_boxed for each tool (serial, one call per tool).
    /// Implementations backed by a database should override this to batch the query.
    fn list_allowed_boxed<'a>(
        &'a self,
        agent_id: &'a AgentId,
        integration_id: &'a IntegrationId,
        tool_names: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<HashSet<String>, CoreError>> + Send + 'a>> {
        Box::pin(async move {
            // 'static null so we can pass &'static Value to evaluate_boxed without lifetime issues
            static NULL: OnceLock<serde_json::Value> = OnceLock::new();
            let null = NULL.get_or_init(|| serde_json::Value::Null);

            let mut allowed = HashSet::new();
            for name in tool_names {
                match self.evaluate_boxed(agent_id, integration_id, name.as_str(), null).await {
                    Ok(d) if d.allowed => {
                        allowed.insert(name.clone());
                    }
                    _ => {}
                }
            }
            Ok(allowed)
        })
    }
}

impl<T: PolicyStore> PolicyEngine for T {
    fn evaluate_boxed<'a>(
        &'a self,
        agent_id: &'a AgentId,
        integration_id: &'a IntegrationId,
        tool_name: &'a str,
        params: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, CoreError>> + Send + 'a>> {
        Box::pin(self.evaluate(agent_id, integration_id, tool_name, params))
    }
}
