/// Errors produced by the cryptography layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("random source unavailable")]
    Random,
    #[error("invalid input")]
    InvalidInput,
    #[error("invalid KDF parameters")]
    InvalidKdfParams,
    #[error("key derivation failed")]
    Kdf,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid recovery code")]
    InvalidRecoveryCode,
}
