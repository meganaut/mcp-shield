use std::future::Future;
use std::pin::Pin;

use crate::error::CoreError;

/// Plaintext token data stored per integration. All fields optional — the vault
/// stores whatever credentials were provided (client_secret, access_token,
/// refresh_token, or a combination depending on the auth flow used).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct VaultTokenData {
    pub client_secret: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_at: Option<i64>,
}

pub trait VaultBackend: Send + Sync {
    fn store_token(
        &self,
        integration_id: &str,
        data: &VaultTokenData,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send + '_>>;

    fn get_token(
        &self,
        integration_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<VaultTokenData>, CoreError>> + Send + '_>>;

    fn delete_token(
        &self,
        integration_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send + '_>>;
}
