use std::pin::Pin;
use std::future::Future;
use std::sync::Arc;

use mcpcondor_core::audit::AuditSink;
use mcpcondor_core::error::CoreError;
use mcpcondor_core::types::{AuditEvent, AuditOutcome};
use mcpcondor_db::{AuditEventRow, Store};

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
            let (outcome, deny_reason, error_message) = match &event.outcome {
                AuditOutcome::Allowed => ("allowed".to_string(), None, None),
                AuditOutcome::Denied { reason } => {
                    (format!("denied:{reason}"), Some(reason.clone()), None)
                }
                AuditOutcome::Error { detail } => {
                    (format!("error:{detail}"), None, Some(detail.clone()))
                }
            };

            let integration_slug = event.operation_name
                .split_once("__")
                .map(|(slug, _)| slug.to_string());

            let dlp_detections = if event.dlp_detections.is_empty() {
                None
            } else {
                serde_json::to_string(&event.dlp_detections).ok()
            };

            let row = AuditEventRow {
                id: event.id.to_string(),
                timestamp_ms: event.timestamp.timestamp_millis(),
                agent_id: event.agent_id.0.to_string(),
                operation_name: event.operation_name,
                outcome,
                latency_ms: event.latency_ms as i64,
                integration_slug,
                deny_reason,
                error_message,
                client_id: event.client_id,
                dlp_detections,
            };
            self.store
                .insert_audit_event(&row)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))
        })
    }
}
