use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Length of every symmetric key used by ReedShell.
pub const KEY_LEN: usize = 32;

/// A 32-byte secret that is wiped from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh key from the operating system CSPRNG.
    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::Random)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_keys_differ() {
        let first = SecretKey::random().expect("random source");
        let second = SecretKey::random().expect("random source");
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn debug_is_redacted() {
        let key = SecretKey::from_bytes([7u8; KEY_LEN]);
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("07"));
        assert!(rendered.contains("REDACTED"));
    }
}
