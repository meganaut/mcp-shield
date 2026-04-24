use std::future::Future;

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
