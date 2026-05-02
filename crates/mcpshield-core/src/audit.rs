use std::future::Future;
use std::pin::Pin;

use crate::error::CoreError;
use crate::types::AuditEvent;

pub trait AuditLogger: Send + Sync {
    fn log(
        &self,
        event: AuditEvent,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
}

/// Object-safe version of `AuditLogger` for use as `Arc<dyn AuditSink>`.
pub trait AuditSink: Send + Sync {
    fn log_boxed(
        &self,
        event: AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send + '_>>;
}

impl<T: AuditLogger> AuditSink for T {
    fn log_boxed(
        &self,
        event: AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send + '_>> {
        Box::pin(self.log(event))
    }
}
