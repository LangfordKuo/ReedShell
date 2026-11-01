use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use reedshell_core::id::{DeviceId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ulid::Ulid;

/// Access-token claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    /// User id.
    pub sub: String,
    /// Device id.
    pub did: String,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Expiry, Unix seconds.
    pub exp: i64,
    /// Unique token id.
    pub jti: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported token algorithm")]
    Algorithm,
    #[error("invalid token signature")]
    Signature,
    #[error("token expired")]
    Expired,
    #[error("invalid token claims")]
    Claims,
    #[error("token serialization failed")]
    Serialization,
}

#[derive(Serialize, Deserialize)]
struct TokenHeader {
    alg: String,
    typ: String,
}

/// Issues and verifies Ed25519 JWT-shaped access tokens.
pub struct TokenSigner {
    signing: SigningKey,
}

impl TokenSigner {
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Issue an access token for a user/device pair.
    pub fn issue_access(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        ttl_secs: i64,
    ) -> Result<String, TokenError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            sub: user_id.to_string(),
            did: device_id.to_string(),
            iat: now,
            exp: now.saturating_add(ttl_secs),
            jti: Ulid::new().to_string(),
        };

        let header = TokenHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
        };
        let header_b64 = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).map_err(|_| TokenError::Serialization)?);
        let payload_b64 = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).map_err(|_| TokenError::Serialization)?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = self.signing.sign(signing_input.as_bytes());

        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    /// Verify a token and return its claims.
    pub fn verify_access(&self, token: &str) -> Result<Claims, TokenError> {
        let mut parts = token.split('.');
        let header_b64 = parts.next().ok_or(TokenError::Malformed)?;
        let payload_b64 = parts.next().ok_or(TokenError::Malformed)?;
        let signature_b64 = parts.next().ok_or(TokenError::Malformed)?;
        if parts.next().is_some() {
            return Err(TokenError::Malformed);
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| TokenError::Malformed)?;
        let header: TokenHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| TokenError::Malformed)?;
        if header.alg != "EdDSA" || header.typ != "JWT" {
            return Err(TokenError::Algorithm);
        }

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| TokenError::Malformed)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| TokenError::Malformed)?;
        let signing_input = format!("{header_b64}.{payload_b64}");
        self.verifying_key()
            .verify_strict(signing_input.as_bytes(), &signature)
            .map_err(|_| TokenError::Signature)?;

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| TokenError::Malformed)?;
        let claims: Claims =
            serde_json::from_slice(&payload_bytes).map_err(|_| TokenError::Claims)?;

        if claims
            .sub
            .parse::<UserId>()
            .map_err(|_| TokenError::Claims)?
            .to_string()
            != claims.sub
            || claims
                .did
                .parse::<DeviceId>()
                .map_err(|_| TokenError::Claims)?
                .to_string()
                != claims.did
        {
            return Err(TokenError::Claims);
        }

        if claims.exp <= OffsetDateTime::now_utc().unix_timestamp() {
            return Err(TokenError::Expired);
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> TokenSigner {
        TokenSigner::from_seed([7u8; 32])
    }

    #[test]
    fn issues_and_verifies_tokens() {
        let signer = signer();
        let user = UserId::new();
        let device = DeviceId::new();
        let token = signer.issue_access(user, device, 60).expect("issue");
        let claims = signer.verify_access(&token).expect("verify");
        assert_eq!(claims.sub, user.to_string());
        assert_eq!(claims.did, device.to_string());
    }

    #[test]
    fn rejects_tampered_signature() {
        let signer = signer();
        let token = signer
            .issue_access(UserId::new(), DeviceId::new(), 60)
            .expect("issue");
        let mut chars: Vec<char> = token.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(matches!(
            signer.verify_access(&tampered),
            Err(TokenError::Signature | TokenError::Malformed)
        ));
    }

    #[test]
    fn rejects_expired_tokens() {
        let signer = signer();
        let token = signer
            .issue_access(UserId::new(), DeviceId::new(), -1)
            .expect("issue");
        assert!(matches!(
            signer.verify_access(&token),
            Err(TokenError::Expired)
        ));
    }

    #[test]
    fn rejects_tokens_from_another_key() {
        let token = signer()
            .issue_access(UserId::new(), DeviceId::new(), 60)
            .expect("issue");
        let other = TokenSigner::from_seed([8u8; 32]);
        assert!(matches!(
            other.verify_access(&token),
            Err(TokenError::Signature)
        ));
    }
}
