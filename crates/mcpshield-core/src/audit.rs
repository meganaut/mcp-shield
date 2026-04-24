use std::future::Future;

use crate::error::CoreError;
use crate::types::AuditEvent;

pub trait AuditLogger: Send + Sync {
    fn log(
        &self,
        event: AuditEvent,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
}
