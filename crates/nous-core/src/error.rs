use thiserror::Error;

/// Errors that can occur in nous-core operations.
#[derive(Debug, Error)]
pub enum NousError {
    #[error("event normalization failed: {0}")]
    Normalization(String),

    #[error("unsupported event class: {class_uid}")]
    UnsupportedClass { class_uid: u32 },

    #[error("context window generation failed: {0}")]
    ContextGeneration(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid severity id: {0}")]
    InvalidSeverity(u8),

    #[error("state error: {0}")]
    State(String),
}

pub type Result<T> = std::result::Result<T, NousError>;
