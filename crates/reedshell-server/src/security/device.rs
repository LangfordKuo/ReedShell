use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::AppError;

/// Verify a device proof-of-possession signature.
pub fn verify_device_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &str,
) -> Result<(), AppError> {
    let trimmed = signature.trim();
    let signature_bytes = STANDARD
        .decode(trimmed)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .map_err(|_| invalid_signature())?;

    let signature = Signature::from_slice(&signature_bytes).map_err(|_| invalid_signature())?;
    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|_| invalid_signature())?;
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| invalid_signature())?;
    Ok(())
}

fn invalid_signature() -> AppError {
    AppError::unauthorized("invalid_device_signature", "device signature is invalid")
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn keypair() -> (SigningKey, [u8; 32]) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing.verifying_key().to_bytes();
        (signing, public)
    }

    #[test]
    fn accepts_a_valid_signature() {
        let (signing, public) = keypair();
        let message = b"refresh|device|1700000000";
        let signature = STANDARD.encode(signing.sign(message).to_bytes());
        assert!(verify_device_signature(&public, message, &signature).is_ok());
    }

    #[test]
    fn rejects_a_tampered_message() {
        let (signing, public) = keypair();
        let signature = STANDARD.encode(signing.sign(b"original").to_bytes());
        assert!(verify_device_signature(&public, b"tampered", &signature).is_err());
    }

    #[test]
    fn rejects_malformed_signatures() {
        let (_signing, public) = keypair();
        assert!(verify_device_signature(&public, b"message", "not-base64!").is_err());
        assert!(verify_device_signature(&public, b"message", "").is_err());
    }
}
