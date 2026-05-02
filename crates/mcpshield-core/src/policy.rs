use std::future::Future;
use std::pin::Pin;

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
