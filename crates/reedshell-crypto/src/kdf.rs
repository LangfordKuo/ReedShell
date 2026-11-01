use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;
use crate::secret::SecretKey;

pub use reedshell_core::kdf::{KDF_SALT_LEN, KdfParams, MAX_MEMORY_KIB, MIN_MEMORY_KIB};

/// Generate a fresh 16-byte KDF salt.
pub fn random_salt() -> Result<[u8; KDF_SALT_LEN], CryptoError> {
    let mut salt = [0u8; KDF_SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::Random)?;
    Ok(salt)
}

/// Derive the account root secret from the user's password.
pub fn derive_root(
    password: &[u8],
    salt: &[u8; KDF_SALT_LEN],
    params: KdfParams,
) -> Result<SecretKey, CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::InvalidInput);
    }
    if !params.is_valid() {
        return Err(CryptoError::InvalidKdfParams);
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| CryptoError::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut output = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(SecretKey::from_bytes(output))
}

/// Derive the authentication key sent to the server.
pub fn derive_auth_key(root: &SecretKey) -> Result<SecretKey, CryptoError> {
    expand(root, None, b"reedshell/auth/v1")
}

/// Derive the key-encryption key that wraps the master key.
pub fn derive_kek(root: &SecretKey, user_id: &str) -> Result<SecretKey, CryptoError> {
    expand(root, Some(user_id.as_bytes()), b"reedshell/enc/v1")
}

fn expand(input: &SecretKey, salt: Option<&[u8]>, info: &[u8]) -> Result<SecretKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(salt, input.as_bytes());
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::InvalidInput)?;
    Ok(SecretKey::from_bytes(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams {
            memory_kib: MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let salt = [3u8; KDF_SALT_LEN];
        let first =
            derive_root(b"correct horse battery staple", &salt, test_params()).expect("derive");
        let second =
            derive_root(b"correct horse battery staple", &salt, test_params()).expect("derive");
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn different_salt_changes_root() {
        let first = derive_root(b"password", &[1u8; 16], test_params()).expect("derive");
        let second = derive_root(b"password", &[2u8; 16], test_params()).expect("derive");
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn auth_key_and_kek_are_independent() {
        let root = derive_root(b"password", &[1u8; 16], test_params()).expect("derive");
        let auth = derive_auth_key(&root).expect("auth");
        let kek = derive_kek(&root, "user-1").expect("kek");
        assert_ne!(auth.as_bytes(), kek.as_bytes());
        assert_ne!(auth.as_bytes(), root.as_bytes());
    }

    #[test]
    fn rejects_weak_parameters() {
        let params = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        assert!(matches!(
            derive_root(b"password", &[0u8; 16], params),
            Err(CryptoError::InvalidKdfParams)
        ));
    }

    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").expect("hex");
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").expect("hex");
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        )
        .expect("hex");

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut output = [0u8; 42];
        hkdf.expand(&info, &mut output).expect("expand");
        assert_eq!(output.as_slice(), expected.as_slice());
    }
}
