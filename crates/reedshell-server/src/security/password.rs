use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;

use crate::error::AppError;

/// Argon2id parameters for server-side hashing of the client-derived
/// authentication key. The input is already high entropy, so the server
/// only needs a moderate memory cost.
const SERVER_MEMORY_KIB: u32 = 19 * 1024;
const SERVER_ITERATIONS: u32 = 2;
const SERVER_PARALLELISM: u32 = 1;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

/// Salt and digest stored alongside an account.
#[derive(Clone, Debug)]
pub struct PasswordHash {
    pub salt: [u8; SALT_LEN],
    pub hash: [u8; HASH_LEN],
}

/// Hash a client-derived `auth_key` before storing it.
pub fn hash_auth_key(auth_key: &[u8; 32]) -> Result<PasswordHash, AppError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|error| AppError::internal(anyhow::anyhow!("random source: {error}")))?;

    let hash = argon2_hash(auth_key, &salt)?;
    Ok(PasswordHash { salt, hash })
}

/// Verify a client-derived `auth_key` in constant time.
pub fn verify_auth_key(
    auth_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    expected: &[u8; HASH_LEN],
) -> Result<bool, AppError> {
    let computed = argon2_hash(auth_key, salt)?;
    Ok(computed.ct_eq(expected).into())
}

fn argon2_hash(auth_key: &[u8; 32], salt: &[u8; SALT_LEN]) -> Result<[u8; HASH_LEN], AppError> {
    let params = Params::new(
        SERVER_MEMORY_KIB,
        SERVER_ITERATIONS,
        SERVER_PARALLELISM,
        Some(HASH_LEN),
    )
    .map_err(|error| AppError::internal(anyhow::anyhow!("invalid Argon2 params: {error}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; HASH_LEN];
    argon
        .hash_password_into(auth_key, salt, &mut output)
        .map_err(|error| AppError::internal(anyhow::anyhow!("Argon2 failure: {error}")))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_correct_key_and_rejects_wrong_key() {
        let auth_key = [3u8; 32];
        let hashed = hash_auth_key(&auth_key).expect("hash");
        assert!(verify_auth_key(&auth_key, &hashed.salt, &hashed.hash).expect("verify"));
        assert!(!verify_auth_key(&[4u8; 32], &hashed.salt, &hashed.hash).expect("verify"));
    }

    #[test]
    fn hashes_are_salted() {
        let auth_key = [3u8; 32];
        let first = hash_auth_key(&auth_key).expect("hash");
        let second = hash_auth_key(&auth_key).expect("hash");
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.hash, second.hash);
    }
}
