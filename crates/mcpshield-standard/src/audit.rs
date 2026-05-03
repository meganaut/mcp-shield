use std::pin::Pin;
use std::future::Future;
use std::sync::Arc;

use mcpshield_core::audit::AuditSink;
use mcpshield_core::error::CoreError;
use mcpshield_core::types::{AuditEvent, AuditOutcome};
use mcpshield_db::{AuditEventRow, Store};

pub struct DbAuditSink {
    store: Arc<dyn Store>,
}

impl DbAuditSink {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }
}

impl AuditSink for DbAuditSink {
    fn log_boxed(
        &self,
        event: AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send + '_>> {
        Box::pin(async move {
            let outcome = match &event.outcome {
                AuditOutcome::Allowed => "allowed".to_string(),
                AuditOutcome::Denied { reason } => format!("denied:{reason}"),
                AuditOutcome::Error { detail } => format!("error:{detail}"),
            };
            let row = AuditEventRow {
                id: event.id.to_string(),
                timestamp_ms: event.timestamp.timestamp_millis(),
                agent_id: event.agent_id.0.to_string(),
                operation_name: event.operation_name,
                outcome,
                latency_ms: event.latency_ms as i64,
            };
            self.store
                .insert_audit_event(&row)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))
        })
    }
}
