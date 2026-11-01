use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::secret::SecretKey;

/// Length of an XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;

/// Length of the Poly1305 authentication tag appended to ciphertext.
pub const TAG_LEN: usize = 16;

/// An encrypted payload together with its nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedBlob {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    #[must_use]
    pub fn total_len(&self) -> usize {
        self.nonce.len() + self.ciphertext.len()
    }
}

/// Derive the per-record key from the master key.
pub fn item_key(master_key: &SecretKey, item_id: &str) -> Result<SecretKey, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(item_id.as_bytes()), master_key.as_bytes());
    let mut output = [0u8; 32];
    hkdf.expand(b"reedshell/item-key/v1", &mut output)
        .map_err(|_| CryptoError::InvalidInput)?;
    Ok(SecretKey::from_bytes(output))
}

/// Build the additional authenticated data for one vault record.
pub fn item_aad(user_id: &str, item_id: &str, version: u32) -> Result<Vec<u8>, CryptoError> {
    let mut aad = Vec::with_capacity(32 + user_id.len() + item_id.len() + 4);
    aad.extend_from_slice(b"reedshell/item/v1\0");
    push_len_prefixed(&mut aad, user_id.as_bytes())?;
    push_len_prefixed(&mut aad, item_id.as_bytes())?;
    aad.extend_from_slice(&version.to_be_bytes());
    Ok(aad)
}

/// Build the AAD used when wrapping or unwrapping the master key.
#[must_use]
pub fn wrap_aad(purpose: &str, user_id: &str) -> Vec<u8> {
    format!("reedshell/wrap/v1\0{purpose}\0{user_id}").into_bytes()
}

/// Encrypt one vault record with its derived item key.
pub fn encrypt_item(
    master_key: &SecretKey,
    user_id: &str,
    item_id: &str,
    version: u32,
    plaintext: &[u8],
) -> Result<EncryptedBlob, CryptoError> {
    let key = item_key(master_key, item_id)?;
    let aad = item_aad(user_id, item_id, version)?;
    encrypt_with_key(&key, plaintext, &aad)
}

/// Decrypt one vault record with its derived item key.
pub fn decrypt_item(
    master_key: &SecretKey,
    user_id: &str,
    item_id: &str,
    version: u32,
    blob: &EncryptedBlob,
) -> Result<Vec<u8>, CryptoError> {
    let key = item_key(master_key, item_id)?;
    let aad = item_aad(user_id, item_id, version)?;
    decrypt_with_key(&key, blob, &aad)
}

/// Encrypt a raw payload under a caller-supplied key.
pub fn encrypt_with_key(
    key: &SecretKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedBlob, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Random)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(EncryptedBlob { nonce, ciphertext })
}

/// Decrypt a raw payload under a caller-supplied key.
pub fn decrypt_with_key(
    key: &SecretKey,
    blob: &EncryptedBlob,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    cipher
        .decrypt(
            XNonce::from_slice(&blob.nonce),
            Payload {
                msg: &blob.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

/// Wrap a key (for example the master key) under another key.
pub fn wrap_key(
    wrapping_key: &SecretKey,
    key_to_wrap: &SecretKey,
    aad: &[u8],
) -> Result<EncryptedBlob, CryptoError> {
    encrypt_with_key(wrapping_key, key_to_wrap.as_bytes(), aad)
}

/// Unwrap a previously wrapped key.
pub fn unwrap_key(
    wrapping_key: &SecretKey,
    blob: &EncryptedBlob,
    aad: &[u8],
) -> Result<SecretKey, CryptoError> {
    let mut plaintext = decrypt_with_key(wrapping_key, blob, aad)?;
    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err(CryptoError::InvalidInput);
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(SecretKey::from_bytes(bytes))
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CryptoError> {
    let len = u16::try_from(bytes.len()).map_err(|_| CryptoError::InvalidInput)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_bytes([byte; 32])
    }

    #[test]
    fn item_round_trip() {
        let master = key(7);
        let plaintext = br#"{"kind":"host","host":"example.com"}"#;
        let blob = encrypt_item(&master, "user-1", "item-1", 3, plaintext).expect("encrypt");
        let decrypted = decrypt_item(&master, "user-1", "item-1", 3, &blob).expect("decrypt");
        assert_eq!(decrypted, plaintext);
        assert_ne!(blob.ciphertext, plaintext);
    }

    #[test]
    fn aad_binds_version_user_and_item() {
        let master = key(7);
        let blob = encrypt_item(&master, "user-1", "item-1", 3, b"secret").expect("encrypt");

        assert!(decrypt_item(&master, "user-1", "item-1", 4, &blob).is_err());
        assert!(decrypt_item(&master, "user-1", "item-2", 3, &blob).is_err());
        assert!(decrypt_item(&master, "user-2", "item-1", 3, &blob).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let master = key(9);
        let mut blob = encrypt_item(&master, "user-1", "item-1", 1, b"secret").expect("encrypt");
        blob.ciphertext[0] ^= 0xff;
        assert!(decrypt_item(&master, "user-1", "item-1", 1, &blob).is_err());
    }

    #[test]
    fn per_item_keys_are_isolated() {
        let master = key(11);
        let first = item_key(&master, "item-1").expect("key");
        let second = item_key(&master, "item-2").expect("key");
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn wraps_and_unwraps_master_key() {
        let wrapping = key(13);
        let master = key(17);
        let aad = wrap_aad("pw", "user-1");
        let blob = wrap_key(&wrapping, &master, &aad).expect("wrap");
        let unwrapped = unwrap_key(&wrapping, &blob, &aad).expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), master.as_bytes());
    }

    #[test]
    fn wrong_wrap_aad_fails() {
        let wrapping = key(13);
        let master = key(17);
        let blob = wrap_key(&wrapping, &master, &wrap_aad("pw", "user-1")).expect("wrap");
        assert!(unwrap_key(&wrapping, &blob, &wrap_aad("rc", "user-1")).is_err());
    }
}
