use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use mcpshield_core::error::CoreError;
use mcpshield_core::policy::{PolicyDecision, PolicyEngine};
use mcpshield_core::types::{AgentId, IntegrationId};

const DEFAULT_TTL: Duration = Duration::from_secs(300);

pub struct CachingPolicyEngine {
    inner: Arc<dyn PolicyEngine>,
    cache: DashMap<(String, String), (bool, Instant)>,
    ttl: Duration,
}

impl CachingPolicyEngine {
    pub fn new(inner: Arc<dyn PolicyEngine>) -> Self {
        Self { inner, cache: DashMap::new(), ttl: DEFAULT_TTL }
    }

    pub fn invalidate_agent(&self, agent_id: &str) {
        self.cache.retain(|(aid, _), _| aid.as_str() != agent_id);
    }
}

impl PolicyEngine for CachingPolicyEngine {
    fn evaluate_boxed<'a>(
        &'a self,
        agent_id: &'a AgentId,
        integration_id: &'a IntegrationId,
        tool_name: &'a str,
        params: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<PolicyDecision, CoreError>> + Send + 'a>> {
        Box::pin(async move {
            let key = (agent_id.0.to_string(), tool_name.to_string());
            if let Some(entry) = self.cache.get(&key) {
                let (allowed, cached_at) = *entry;
                if cached_at.elapsed() < self.ttl {
                    return Ok(PolicyDecision { allowed, reason: None });
                }
                drop(entry);
                self.cache.remove(&key);
            }
            let decision = self.inner.evaluate_boxed(agent_id, integration_id, tool_name, params).await?;
            self.cache.insert(key, (decision.allowed, Instant::now()));
            Ok(decision)
        })
    }

    fn list_allowed_boxed<'a>(
        &'a self,
        agent_id: &'a AgentId,
        integration_id: &'a IntegrationId,
        tool_names: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<HashSet<String>, CoreError>> + Send + 'a>> {
        // Pass through — DbPolicyEngine already does this in one query and the result
        // set varies with the downstream tool catalogue, making it tricky to cache correctly.
        self.inner.list_allowed_boxed(agent_id, integration_id, tool_names)
    }
}
