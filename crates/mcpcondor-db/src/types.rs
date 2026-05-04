use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Integration {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub mcp_url: String,
    pub oauth_auth_url: Option<String>,
    pub oauth_token_url: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_scopes: Option<Vec<String>>,
    pub connected: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct VaultToken {
    pub id: String,
    pub integration_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub agent_id: String,
    pub client_secret_hash: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub agent_id: String,
    pub expires_at: i64,
    pub used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub token_hash: String,
    pub client_id: String,
    pub agent_id: String,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub agent_id: String,
    pub tool_name: String,
    pub allowed: bool,
    pub created_at: i64,
}

/// Projection returned by token bearer lookup.
#[derive(Debug, Clone)]
pub struct TokenLookup {
    pub agent_id: String,
    pub client_id: String,
    pub expires_at: i64,
}

/// Projection returned when authenticating a client at the token endpoint.
#[derive(Debug, Clone)]
pub struct ClientAuthInfo {
    pub client_secret_hash: String,
    pub agent_id: String,
}

/// Projection returned when validating an authorization request.
#[derive(Debug, Clone)]
pub struct ClientAuthorizeInfo {
    pub agent_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: String,
}

#[derive(Debug, Clone)]
pub struct AuditEventRow {
    pub id: String,
    pub timestamp_ms: i64,
    pub agent_id: String,
    pub operation_name: String,
    pub outcome: String,
    pub latency_ms: i64,
}
