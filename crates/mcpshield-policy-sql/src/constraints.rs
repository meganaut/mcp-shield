use serde::{Deserialize, Serialize};

/// Coarse-grained rule: applies to all tools in an integration for an agent.
/// Tool-level rules take precedence over this when both are present.
/// Evaluation order: tool-level → integration-level → default deny.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationPermission {
    pub effect: ToolEffect,
}

/// Fine-grained rule: applies to a specific tool within an integration.
/// Overrides any IntegrationPermission for the same (agent, integration) pair.
/// `tool_name` is the local name without the integration slug prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPermission {
    pub tool_name: String,
    pub effect: ToolEffect,
    pub constraints: Vec<ParameterConstraint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolEffect {
    /// Agent may call this tool. Appears in tools/list.
    Allow,
    /// Tool exists in the integration but is not enabled for this agent.
    /// Excluded from tools/list; surfaced via mcpshield__list_available_tools.
    /// Desktop does not use this variant — binary Allow/Deny only.
    Discoverable,
    /// Agent has no visibility of this tool. Silent absence from all responses.
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterConstraint {
    pub param: String,
    pub operator: ConstraintOperator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "value")]
pub enum ConstraintOperator {
    Max(serde_json::Number),
    Min(serde_json::Number),
    MaxLength(usize),
    Allowlist(Vec<String>),
    Denylist(Vec<String>),
    RegexMatch(String),
    RegexReject(String),
}

impl ParameterConstraint {
    pub fn evaluate(&self, params: &serde_json::Value) -> Result<bool, String> {
        let value = &params[&self.param];
        match &self.operator {
            ConstraintOperator::Max(max) => {
                let n = value.as_f64().ok_or("parameter is not a number")?;
                let m = max.as_f64().ok_or("max is not a number")?;
                Ok(n <= m)
            }
            ConstraintOperator::Min(min) => {
                let n = value.as_f64().ok_or("parameter is not a number")?;
                let m = min.as_f64().ok_or("min is not a number")?;
                Ok(n >= m)
            }
            ConstraintOperator::MaxLength(max) => {
                let s = value.as_str().ok_or("parameter is not a string")?;
                Ok(s.len() <= *max)
            }
            ConstraintOperator::Allowlist(list) => {
                let s = value.as_str().ok_or("parameter is not a string")?;
                Ok(list.iter().any(|v| v == s))
            }
            ConstraintOperator::Denylist(list) => {
                let s = value.as_str().ok_or("parameter is not a string")?;
                Ok(!list.iter().any(|v| v == s))
            }
            ConstraintOperator::RegexMatch(pattern) => {
                let s = value.as_str().ok_or("parameter is not a string")?;
                let re = regex::Regex::new(pattern).map_err(|e| e.to_string())?;
                Ok(re.is_match(s))
            }
            ConstraintOperator::RegexReject(pattern) => {
                let s = value.as_str().ok_or("parameter is not a string")?;
                let re = regex::Regex::new(pattern).map_err(|e| e.to_string())?;
                Ok(!re.is_match(s))
            }
        }
    }
}
