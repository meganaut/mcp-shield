use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::types::{AgentId, IntegrationId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub detector: String,
    pub location: DetectionLocation,
    pub confidence: DetectionConfidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionLocation {
    InboundParam { param: String },
    OutboundResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DlpAction {
    Redact,
    Block,
    Allow,
    Alert,
}

pub trait DlpScanner: Send + Sync {
    fn scan(
        &self,
        content: &str,
        location: DetectionLocation,
    ) -> impl Future<Output = Result<Vec<Detection>, CoreError>> + Send;
}

pub trait DlpActionResolver: Send + Sync {
    fn resolve(
        &self,
        agent_id: &AgentId,
        integration_id: &IntegrationId,
        tool_name: &str,
        detection: &Detection,
    ) -> impl Future<Output = Result<DlpAction, CoreError>> + Send;
}
