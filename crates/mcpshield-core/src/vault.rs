use std::future::Future;

use crate::error::CoreError;
use crate::types::{IntegrationId, SubjectId};

#[derive(Debug, Clone)]
pub struct StoredToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub scopes: Vec<String>,
}

pub trait VaultBackend: Send + Sync {
    fn store_token(
        &self,
        subject_id: &SubjectId,
        integration_id: &IntegrationId,
        token: StoredToken,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;

    fn get_token(
        &self,
        subject_id: &SubjectId,
        integration_id: &IntegrationId,
    ) -> impl Future<Output = Result<Option<StoredToken>, CoreError>> + Send;

    fn delete_token(
        &self,
        subject_id: &SubjectId,
        integration_id: &IntegrationId,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;

    /// Delete all tokens owned by a subject — used when an account is deactivated.
    fn delete_all_tokens(
        &self,
        subject_id: &SubjectId,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;

    fn store_secret(
        &self,
        key: &str,
        value: &str,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;

    fn get_secret(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<String>, CoreError>> + Send;

    fn delete_secret(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
}
