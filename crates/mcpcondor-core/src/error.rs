use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("policy denied: {reason}")]
    PolicyDenied { reason: String },

    #[error("vault error: {0}")]
    Vault(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error("serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),
}
