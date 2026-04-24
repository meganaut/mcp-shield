use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPermission {
    pub tool_name: String,
    pub effect: ToolEffect,
    pub constraints: Vec<ParameterConstraint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolEffect {
    Allow,
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
