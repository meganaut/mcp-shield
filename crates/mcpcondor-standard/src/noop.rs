use std::pin::Pin;
use std::future::Future;

use mcpcondor_core::audit::AuditSink;
use mcpcondor_core::error::CoreError;
use mcpcondor_core::policy::{PolicyDecision, PolicyEngine};
use mcpcondor_core::types::{AgentId, AuditEvent, IntegrationId};

pub struct NoopPolicy;
pub struct NoopAudit;

impl PolicyEngine for NoopPolicy {
    fn evaluate_boxed<'a>(
        &'a self,
        _agent_id: &'a AgentId,
        _integration_id: &'a IntegrationId,
        _tool_name: &'a str,
        _params: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, CoreError>> + Send + 'a>> {
        Box::pin(async { Ok(PolicyDecision { allowed: true, reason: None }) })
    }
}

impl AuditSink for NoopAudit {
    fn log_boxed(
        &self,
        _event: AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}
