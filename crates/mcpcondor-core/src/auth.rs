use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::types::{AgentId, IntegrationId, SubjectId};

/// The result of a successful inbound authentication.
/// Carries both the agent identity and the owner subject so the gateway
/// can enforce policy and resolve vault credentials in a single step.
#[derive(Debug, Clone)]
pub struct AuthenticatedAgent {
    pub agent_id: AgentId,
    pub subject_id: SubjectId,
}

/// Credentials MCPCondor holds for a downstream integration,
/// obtained either via manual entry or DCR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationCredentials {
    pub client_id: String,
    pub client_secret: String,
}

/// Inbound auth — validates tokens presented by agents connecting to MCPCondor
/// and issues tokens to agents after registration.
///
/// Desktop: client credentials (client_id + client_secret) → bearer token.
/// Enterprise: IDP-backed OIDC for humans, client credentials for agents.
pub trait AuthProvider: Send + Sync {
    fn authenticate(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<AuthenticatedAgent, CoreError>> + Send;

    fn issue_token(
        &self,
        agent_id: &AgentId,
        subject_id: &SubjectId,
    ) -> impl Future<Output = Result<String, CoreError>> + Send;
}

/// Outbound auth — how MCPCondor registers itself with a downstream MCP server
/// to obtain the credentials it needs to call that service on behalf of users.
///
/// Manual: admin provides client_id + client_secret directly.
/// DCR: MCPCondor registers itself dynamically with the integration's DCR endpoint.
pub trait IntegrationRegistrar: Send + Sync {
    fn register(
        &self,
        integration_id: &IntegrationId,
    ) -> impl Future<Output = Result<IntegrationCredentials, CoreError>> + Send;

    fn deregister(
        &self,
        integration_id: &IntegrationId,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
}
