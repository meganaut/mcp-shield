use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use mcpshield_core::error::CoreError;
use mcpshield_core::policy::{PolicyDecision, PolicyEngine};
use mcpshield_core::types::{AgentId, IntegrationId};
use mcpshield_db::Store;

pub struct DbPolicyEngine {
    store: Arc<dyn Store>,
}

impl DbPolicyEngine {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }
}

impl PolicyEngine for DbPolicyEngine {
    fn evaluate_boxed<'a>(
        &'a self,
        agent_id: &'a AgentId,
        _integration_id: &'a IntegrationId,
        tool_name: &'a str,
        _params: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, CoreError>> + Send + 'a>> {
        Box::pin(async move {
            let agent_str = agent_id.0.to_string();
            let rule = self
                .store
                .get_policy_rule(&agent_str, tool_name)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;

            // deny by default — missing rule = deny
            let allowed = rule.map(|r| r.allowed).unwrap_or(false);
            Ok(PolicyDecision { allowed, reason: None })
        })
    }

    /// Batch override: fetch all policy rules for this agent in a single query.
    fn list_allowed_boxed<'a>(
        &'a self,
        agent_id: &'a AgentId,
        _integration_id: &'a IntegrationId,
        _tool_names: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<HashSet<String>, CoreError>> + Send + 'a>> {
        Box::pin(async move {
            let agent_str = agent_id.0.to_string();
            let rules = self
                .store
                .list_policy_rules(&agent_str)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;

            // Build the set of explicitly-allowed tool names; anything absent is denied.
            Ok(rules
                .into_iter()
                .filter(|r| r.allowed)
                .map(|r| r.tool_name)
                .collect())
        })
    }
}
