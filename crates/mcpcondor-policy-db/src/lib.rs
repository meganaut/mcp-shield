use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use mcpcondor_core::error::CoreError;
use mcpcondor_core::policy::{PolicyDecision, PolicyEngine};
use mcpcondor_core::types::{AgentId, IntegrationId};
use mcpcondor_db::{AgentOverrideKind, Store};

pub struct DbPolicyEngine {
    store: Arc<dyn Store>,
}

impl DbPolicyEngine {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }
}

/// Extract the integration slug from a tool name (e.g. "gmail__send_email" → "gmail").
fn slug_from_tool_name(tool_name: &str) -> &str {
    tool_name.split("__").next().unwrap_or(tool_name)
}

/// Current unix timestamp in seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl PolicyEngine for DbPolicyEngine {
    fn evaluate_boxed<'a>(
        &'a self,
        agent_id: &'a AgentId,
        _integration_id: &'a IntegrationId,
        tool_name: &'a str,
        _params: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, CoreError>> + Send + 'a>> {
        Box::pin(async move {
            let agent_str = agent_id.0.to_string();
            let now = now_secs();

            // Layer 1 & 5: fetch global rule once
            let global_rule = self
                .store
                .get_global_rule(tool_name)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;

            // Layer 1: global hard deny
            if let Some(ref gr) = global_rule {
                if !gr.allowed {
                    return Ok(PolicyDecision { allowed: false, reason: Some("global hard deny".to_string()) });
                }
            }

            // Layer 2: agent override
            let agent_override = self
                .store
                .get_agent_override(&agent_str, tool_name)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;

            if let Some(ref ov) = agent_override {
                match &ov.kind {
                    AgentOverrideKind::Static => {
                        return Ok(PolicyDecision { allowed: ov.allowed, reason: Some("agent override (static)".to_string()) });
                    }
                    AgentOverrideKind::Until { expires_at } => {
                        if now < *expires_at {
                            return Ok(PolicyDecision { allowed: ov.allowed, reason: Some("agent override (until)".to_string()) });
                        }
                        // expired — fall through
                    }
                    AgentOverrideKind::Uses { remaining } => {
                        if *remaining > 0 {
                            return Ok(PolicyDecision { allowed: true, reason: Some("agent override (uses)".to_string()) });
                        }
                        // exhausted — fall through
                    }
                }
            }

            // Layer 3: profile rule
            let profile_id = self
                .store
                .get_agent_profile_id(&agent_str)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;

            if let Some(ref pid) = profile_id {
                let profile_rule = self
                    .store
                    .get_profile_rule(pid, tool_name)
                    .await
                    .map_err(|e| CoreError::Internal(e.to_string()))?;
                if let Some(pr) = profile_rule {
                    return Ok(PolicyDecision { allowed: pr.allowed, reason: Some("profile rule".to_string()) });
                }
            }

            // Layer 4: integration default stance
            let slug = slug_from_tool_name(tool_name);
            let integration = self
                .store
                .get_integration_by_slug(slug)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;

            if let Some(ref integ) = integration {
                if integ.default_stance {
                    return Ok(PolicyDecision { allowed: true, reason: Some("integration default allow".to_string()) });
                } else {
                    // default_stance=false means deny-all by integration default
                    // but only acts as a definitive deny after checking layer 5 global allow
                }
            }

            // Layer 5: global allow
            if let Some(ref gr) = global_rule {
                if gr.allowed {
                    return Ok(PolicyDecision { allowed: true, reason: Some("global allow".to_string()) });
                }
            }

            // Layer 6: default deny
            Ok(PolicyDecision { allowed: false, reason: Some("default deny".to_string()) })
        })
    }

    /// Batch override: evaluate all tool_names for the agent using a single set of DB reads.
    fn list_allowed_boxed<'a>(
        &'a self,
        agent_id: &'a AgentId,
        _integration_id: &'a IntegrationId,
        tool_names: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<HashSet<String>, CoreError>> + Send + 'a>> {
        Box::pin(async move {
            let agent_str = agent_id.0.to_string();
            let now = now_secs();

            // Fetch all needed data in parallel (sequentially here for simplicity)
            let global_rules = self
                .store
                .list_global_rules()
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;

            let global_deny: HashSet<&str> = global_rules
                .iter()
                .filter(|r| !r.allowed)
                .map(|r| r.tool_name.as_str())
                .collect();
            let global_allow: HashSet<&str> = global_rules
                .iter()
                .filter(|r| r.allowed)
                .map(|r| r.tool_name.as_str())
                .collect();

            let agent_overrides = self
                .store
                .list_agent_overrides(&agent_str)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;
            let override_map: HashMap<&str, &mcpcondor_db::AgentOverride> = agent_overrides
                .iter()
                .map(|o| (o.tool_name.as_str(), o))
                .collect();

            let profile_id = self
                .store
                .get_agent_profile_id(&agent_str)
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;

            let profile_rules = if let Some(ref pid) = profile_id {
                self.store
                    .list_profile_rules(pid)
                    .await
                    .map_err(|e| CoreError::Internal(e.to_string()))?
            } else {
                vec![]
            };
            let profile_rule_map: HashMap<&str, bool> = profile_rules
                .iter()
                .map(|r| (r.tool_name.as_str(), r.allowed))
                .collect();

            let integrations = self
                .store
                .list_integrations()
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))?;
            let integration_stance: HashMap<&str, bool> = integrations
                .iter()
                .map(|i| (i.slug.as_str(), i.default_stance))
                .collect();

            let mut allowed_set = HashSet::new();

            for tool_name in tool_names {
                let tn = tool_name.as_str();

                // Layer 1: global hard deny
                if global_deny.contains(tn) {
                    continue;
                }

                // Layer 2: agent override
                if let Some(ov) = override_map.get(tn) {
                    match &ov.kind {
                        AgentOverrideKind::Static => {
                            if ov.allowed {
                                allowed_set.insert(tool_name.clone());
                            }
                            continue;
                        }
                        AgentOverrideKind::Until { expires_at } => {
                            if now < *expires_at {
                                if ov.allowed {
                                    allowed_set.insert(tool_name.clone());
                                }
                                continue;
                            }
                            // expired — fall through
                        }
                        AgentOverrideKind::Uses { remaining } => {
                            if *remaining > 0 {
                                allowed_set.insert(tool_name.clone());
                                continue;
                            }
                            // exhausted — fall through
                        }
                    }
                }

                // Layer 3: profile rule
                if let Some(&pr_allowed) = profile_rule_map.get(tn) {
                    if pr_allowed {
                        allowed_set.insert(tool_name.clone());
                    }
                    continue;
                }

                // Layer 4: integration default
                let slug = slug_from_tool_name(tn);
                if let Some(&stance) = integration_stance.get(slug) {
                    if stance {
                        allowed_set.insert(tool_name.clone());
                        continue;
                    } else {
                        // integration default deny — check layer 5
                    }
                }

                // Layer 5: global allow
                if global_allow.contains(tn) {
                    allowed_set.insert(tool_name.clone());
                    continue;
                }

                // Layer 6: default deny — do nothing
            }

            Ok(allowed_set)
        })
    }
}
