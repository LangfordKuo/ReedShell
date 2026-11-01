/// Errors produced by shared domain types.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid identifier")]
    InvalidId,
}
