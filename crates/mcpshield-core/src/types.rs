use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::dlp::Detection;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AgentId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IntegrationId(pub Uuid);

/// The owner of a set of OAuth tokens. In desktop this is always the single
/// implicit owner. In enterprise this maps to a user account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SubjectId(pub Uuid);

/// Which MCP primitive the audit event relates to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpPrimitive {
    Tool,
    Resource,
    Prompt,
    Sampling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub agent_id: AgentId,
    pub integration_id: Option<IntegrationId>,
    /// The MCP primitive type being invoked.
    pub primitive: McpPrimitive,
    /// Namespaced operation name: `integration_slug__operation` for forwarded
    /// primitives, `mcpshield__operation` for internal meta-tools.
    pub operation_name: String,
    pub outcome: AuditOutcome,
    pub dlp_detections: Vec<Detection>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuditOutcome {
    Allowed,
    Denied { reason: String },
    Error { detail: String },
}
