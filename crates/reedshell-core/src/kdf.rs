use serde::{Deserialize, Serialize};

/// Length of the password KDF salt.
pub const KDF_SALT_LEN: usize = 16;

/// Minimum Argon2id memory accepted from a client (32 MiB).
pub const MIN_MEMORY_KIB: u32 = 32 * 1024;

/// Maximum Argon2id memory accepted from a client (1 GiB).
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// Argon2id parameters negotiated per account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Default parameters for desktop devices (64 MiB, t=3, p=1).
    pub const DESKTOP: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Default parameters for mobile devices (32 MiB, t=3, p=1).
    pub const MOBILE: Self = Self {
        memory_kib: 32 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Enforce the protocol bounds for client-supplied parameters.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (1..=10).contains(&self.iterations)
            && (1..=8).contains(&self.parallelism)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert!(KdfParams::DESKTOP.is_valid());
        assert!(KdfParams::MOBILE.is_valid());
    }

    #[test]
    fn rejects_out_of_range_values() {
        assert!(
            !KdfParams {
                memory_kib: 1024,
                iterations: 1,
                parallelism: 1
            }
            .is_valid()
        );
        assert!(
            !KdfParams {
                memory_kib: MIN_MEMORY_KIB,
                iterations: 0,
                parallelism: 1
            }
            .is_valid()
        );
    }
}
