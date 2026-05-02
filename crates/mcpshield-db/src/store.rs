use async_trait::async_trait;

use crate::error::StoreError;
use crate::types::*;

#[async_trait]
pub trait Store: Send + Sync {
    // --- Lifecycle ---
    async fn run_migrations(&self) -> Result<(), StoreError>;

    // --- Setup state ---
    async fn is_setup_complete(&self) -> Result<bool, StoreError>;
    async fn complete_setup(
        &self,
        admin_username: &str,
        admin_password_hash: &str,
        issuer_url: &str,
    ) -> Result<(), StoreError>;
    async fn get_setup_value(&self, key: &str) -> Result<Option<String>, StoreError>;

    // --- OAuth clients ---
    async fn insert_oauth_client(&self, client: &OAuthClient) -> Result<(), StoreError>;
    async fn get_client_auth_info(
        &self,
        client_id: &str,
    ) -> Result<Option<ClientAuthInfo>, StoreError>;
    async fn get_client_authorize_info(
        &self,
        client_id: &str,
    ) -> Result<Option<ClientAuthorizeInfo>, StoreError>;
    async fn get_client_name(&self, client_id: &str) -> Result<Option<String>, StoreError>;
    async fn list_oauth_clients(&self) -> Result<Vec<OAuthClient>, StoreError>;

    // --- Auth codes ---
    async fn insert_auth_code(&self, code: &AuthCode) -> Result<(), StoreError>;
    async fn get_auth_code(
        &self,
        code: &str,
        client_id: &str,
        now: i64,
    ) -> Result<Option<AuthCode>, StoreError>;
    /// Atomically marks the code used. Returns true if exactly one row was updated.
    async fn mark_auth_code_used(&self, code: &str) -> Result<bool, StoreError>;
    async fn delete_expired_auth_codes(&self, now: i64) -> Result<u64, StoreError>;

    // --- Access tokens ---
    async fn insert_access_token(&self, token: &AccessToken) -> Result<(), StoreError>;
    async fn get_token_by_hash(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<TokenLookup>, StoreError>;
    async fn delete_expired_access_tokens(&self, now: i64) -> Result<u64, StoreError>;

    // --- Policy rules ---
    async fn upsert_policy_rule(&self, rule: &PolicyRule) -> Result<(), StoreError>;
    async fn delete_policy_rule(
        &self,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<(), StoreError>;
    async fn list_policy_rules(&self, agent_id: &str) -> Result<Vec<PolicyRule>, StoreError>;
    async fn get_policy_rule(
        &self,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<Option<PolicyRule>, StoreError>;
}
