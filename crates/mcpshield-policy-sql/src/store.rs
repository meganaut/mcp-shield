use std::future::Future;

use mcpshield_core::{
    error::CoreError,
    policy::{PolicyDecision, PolicyStore},
    types::{AgentId, IntegrationId},
};

use crate::constraints::{ToolEffect, ToolPermission};

#[derive(Default)]
pub struct SqlPolicyStore {
    // db pool will be added in milestone 2 when we wire up sqlx
}

impl SqlPolicyStore {
    async fn get_permissions(
        &self,
        _agent_id: &AgentId,
        _integration_id: &IntegrationId,
    ) -> Result<Vec<ToolPermission>, CoreError> {
        // placeholder — real impl queries the db
        Ok(vec![])
    }
}

impl PolicyStore for SqlPolicyStore {
    fn evaluate(
        &self,
        agent_id: &AgentId,
        integration_id: &IntegrationId,
        tool_name: &str,
        params: &serde_json::Value,
    ) -> impl Future<Output = Result<PolicyDecision, CoreError>> + Send {
        let agent_id = agent_id.clone();
        let integration_id = integration_id.clone();
        let tool_name = tool_name.to_string();
        let params = params.clone();

        async move {
            let permissions = self.get_permissions(&agent_id, &integration_id).await?;

            let matched = permissions
                .iter()
                .find(|p| p.tool_name == tool_name || p.tool_name == "*");

            match matched {
                Some(p) if p.effect == ToolEffect::Allow => {
                    for constraint in &p.constraints {
                        match constraint.evaluate(&params) {
                            Ok(true) => {}
                            Ok(false) => {
                                return Ok(PolicyDecision {
                                    allowed: false,
                                    reason: Some(format!(
                                        "parameter constraint violated on '{}'",
                                        constraint.param
                                    )),
                                });
                            }
                            Err(e) => {
                                return Ok(PolicyDecision {
                                    allowed: false,
                                    reason: Some(format!(
                                        "constraint evaluation error on '{}': {e}",
                                        constraint.param
                                    )),
                                });
                            }
                        }
                    }
                    Ok(PolicyDecision {
                        allowed: true,
                        reason: None,
                    })
                }
                Some(_) => Ok(PolicyDecision {
                    allowed: false,
                    reason: Some(format!("tool '{tool_name}' explicitly denied by policy")),
                }),
                None => Ok(PolicyDecision {
                    allowed: false,
                    reason: Some(format!(
                        "tool '{tool_name}' not permitted (deny by default)"
                    )),
                }),
            }
        }
    }
}
