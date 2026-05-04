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
    /// Delete an OAuth client by agent_id, removing its auth codes and access tokens first.
    /// Returns true if the client existed and was deleted, false if not found.
    async fn delete_oauth_client(&self, agent_id: &str) -> Result<bool, StoreError>;

    // --- Auth codes ---
    async fn insert_auth_code(&self, code: &AuthCode) -> Result<(), StoreError>;
    async fn get_auth_code(
        &self,
        code: &str,
        client_id: &str,
        now: i64,
    ) -> Result<Option<AuthCode>, StoreError>;
    /// Atomically marks the code used; also checks expiry to close the cleanup-job TOCTOU.
    /// Returns true if exactly one row was updated.
    async fn mark_auth_code_used(&self, code: &str, now: i64) -> Result<bool, StoreError>;
    async fn delete_expired_auth_codes(&self, now: i64) -> Result<u64, StoreError>;

    // --- Access tokens ---
    async fn insert_access_token(&self, token: &AccessToken) -> Result<(), StoreError>;
    async fn get_token_by_hash(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<TokenLookup>, StoreError>;
    async fn delete_expired_access_tokens(&self, now: i64) -> Result<u64, StoreError>;

    // --- Access token revocation ---
    /// Delete all access tokens for an agent. Returns the number deleted.
    async fn delete_agent_tokens(&self, agent_id: &str) -> Result<u64, StoreError>;

    // --- Audit log ---
    async fn insert_audit_event(&self, event: &AuditEventRow) -> Result<(), StoreError>;
    async fn list_audit_events(
        &self,
        agent_id: &str,
        limit: i64,
    ) -> Result<Vec<AuditEventRow>, StoreError>;
    /// Delete audit events older than the given timestamp (milliseconds since epoch).
    /// Returns the number of rows deleted.
    async fn delete_old_audit_events(&self, before_ms: i64) -> Result<u64, StoreError>;
    /// List the most recent audit events across all agents.
    async fn list_all_audit_events(&self, limit: i64) -> Result<Vec<AuditEventRow>, StoreError>;
    /// Count tool calls since a timestamp (ms). Returns (total, denied).
    async fn count_audit_events_since(&self, since_ms: i64) -> Result<(u64, u64), StoreError>;

    // --- Integrations ---
    async fn insert_integration(&self, integration: &Integration) -> Result<(), StoreError>;
    async fn get_integration(&self, id: &str) -> Result<Option<Integration>, StoreError>;
    async fn get_integration_by_slug(&self, slug: &str) -> Result<Option<Integration>, StoreError>;
    async fn list_integrations(&self) -> Result<Vec<Integration>, StoreError>;
    async fn update_integration_connected(&self, id: &str, connected: bool) -> Result<(), StoreError>;
    async fn delete_integration(&self, id: &str) -> Result<bool, StoreError>;

    // --- Vault tokens ---
    async fn upsert_vault_token(&self, token: &VaultToken) -> Result<(), StoreError>;
    async fn get_vault_token(&self, integration_id: &str) -> Result<Option<VaultToken>, StoreError>;
    async fn delete_vault_token(&self, integration_id: &str) -> Result<bool, StoreError>;

    // --- Policy rules ---
    async fn upsert_policy_rule(&self, rule: &PolicyRule) -> Result<(), StoreError>;
    /// Delete a policy rule. Returns true if deleted, false if it did not exist.
    async fn delete_policy_rule(
        &self,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<bool, StoreError>;
    async fn list_policy_rules(&self, agent_id: &str) -> Result<Vec<PolicyRule>, StoreError>;
    async fn get_policy_rule(
        &self,
        agent_id: &str,
        tool_name: &str,
    ) -> Result<Option<PolicyRule>, StoreError>;

    // --- Profiles ---
    async fn insert_profile(&self, profile: &Profile) -> Result<(), StoreError>;
    async fn get_profile(&self, id: &str) -> Result<Option<Profile>, StoreError>;
    async fn list_profiles(&self) -> Result<Vec<Profile>, StoreError>;
    async fn update_profile(&self, id: &str, name: &str, description: Option<&str>) -> Result<(), StoreError>;
    async fn delete_profile(&self, id: &str) -> Result<bool, StoreError>;

    // --- Profile rules ---
    async fn upsert_profile_rule(&self, rule: &ProfileRule) -> Result<(), StoreError>;
    async fn delete_profile_rule(&self, profile_id: &str, tool_name: &str) -> Result<bool, StoreError>;
    async fn list_profile_rules(&self, profile_id: &str) -> Result<Vec<ProfileRule>, StoreError>;
    async fn get_profile_rule(&self, profile_id: &str, tool_name: &str) -> Result<Option<ProfileRule>, StoreError>;
    /// Set all rules for tools matching an integration slug prefix (slug__) to the given allowed value.
    /// Upserts one row per tool_name provided.
    async fn set_profile_rules_for_integration(
        &self,
        profile_id: &str,
        tool_names: &[String],
        allowed: bool,
        now: i64,
    ) -> Result<(), StoreError>;

    // --- Global rules ---
    async fn upsert_global_rule(&self, rule: &GlobalRule) -> Result<(), StoreError>;
    async fn delete_global_rule(&self, tool_name: &str) -> Result<bool, StoreError>;
    async fn list_global_rules(&self) -> Result<Vec<GlobalRule>, StoreError>;
    async fn get_global_rule(&self, tool_name: &str) -> Result<Option<GlobalRule>, StoreError>;

    // --- Agent overrides ---
    async fn upsert_agent_override(&self, override_: &AgentOverride) -> Result<(), StoreError>;
    async fn delete_agent_override(&self, agent_id: &str, tool_name: &str) -> Result<bool, StoreError>;
    async fn list_agent_overrides(&self, agent_id: &str) -> Result<Vec<AgentOverride>, StoreError>;
    async fn get_agent_override(&self, agent_id: &str, tool_name: &str) -> Result<Option<AgentOverride>, StoreError>;

    // --- Profile assignment ---
    async fn set_agent_profile(&self, agent_id: &str, profile_id: Option<&str>) -> Result<(), StoreError>;
    async fn get_agent_profile_id(&self, agent_id: &str) -> Result<Option<String>, StoreError>;
}
