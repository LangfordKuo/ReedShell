use std::fmt;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::secret::SecretKey;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DATA_CHARS: usize = 30;
const CHECK_CHARS: usize = 2;
const TOTAL_CHARS: usize = DATA_CHARS + CHECK_CHARS;
const GROUP_SIZE: usize = 4;

/// A human-transcribable master-key recovery code.
///
/// The code carries 150 bits of entropy: 30 Crockford Base32 data
/// characters plus a 2-character checksum. It is shown to the user once
/// and never stored by the server.
#[derive(Clone)]
pub struct RecoveryCode {
    normalized: String,
}

impl RecoveryCode {
    /// Generate a fresh random recovery code.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut raw = [0u8; 19];
        getrandom::fill(&mut raw).map_err(|_| CryptoError::Random)?;
        let encoded = encode_base32(&raw);
        let data: String = encoded.chars().take(DATA_CHARS).collect();
        if data.len() != DATA_CHARS {
            return Err(CryptoError::InvalidRecoveryCode);
        }
        let checksum = checksum_for(&data);
        Ok(Self {
            normalized: format!("{data}{checksum}"),
        })
    }

    /// Parse and validate a user-supplied recovery code.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        let normalized = normalize(input)?;
        let (data, supplied_checksum) = normalized.split_at(DATA_CHARS);
        if checksum_for(data) != supplied_checksum {
            return Err(CryptoError::InvalidRecoveryCode);
        }
        Ok(Self { normalized })
    }

    /// Derive the key-encryption key that protects the master key.
    pub fn recovery_key(&self, user_id: &str) -> Result<SecretKey, CryptoError> {
        let digest = Sha256::digest(self.normalized.as_bytes());
        let hkdf = Hkdf::<Sha256>::new(Some(user_id.as_bytes()), digest.as_slice());
        let mut output = [0u8; 32];
        hkdf.expand(b"reedshell/recovery/v1", &mut output)
            .map_err(|_| CryptoError::InvalidInput)?;
        Ok(SecretKey::from_bytes(output))
    }

    /// The normalized code without separators. Treat as a secret.
    #[must_use]
    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    /// The display form, grouped as `XXXX-XXXX-...`.
    #[must_use]
    pub fn grouped(&self) -> String {
        self.normalized
            .as_bytes()
            .chunks(GROUP_SIZE)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.grouped())
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode([REDACTED])")
    }
}

impl Drop for RecoveryCode {
    fn drop(&mut self) {
        self.normalized.zeroize();
    }
}

fn normalize(input: &str) -> Result<String, CryptoError> {
    let mut normalized = String::with_capacity(TOTAL_CHARS);
    for character in input.chars() {
        let mut upper = character.to_ascii_uppercase();
        if upper == '-' || upper.is_ascii_whitespace() {
            continue;
        }
        upper = match upper {
            'I' | 'L' => '1',
            'O' => '0',
            'U' => 'V',
            other => other,
        };
        if !ALPHABET.contains(&(upper as u8)) {
            return Err(CryptoError::InvalidRecoveryCode);
        }
        normalized.push(upper);
    }
    if normalized.len() != TOTAL_CHARS {
        return Err(CryptoError::InvalidRecoveryCode);
    }
    Ok(normalized)
}

fn checksum_for(data: &str) -> String {
    let digest = Sha256::digest(data.as_bytes());
    let value = (u16::from(digest[0]) << 2) | (u16::from(digest[1]) >> 6);
    let high = ALPHABET[usize::from((value >> 5) & 0x1f)] as char;
    let low = ALPHABET[usize::from(value & 0x1f)] as char;
    format!("{high}{low}")
}

fn encode_base32(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::from(((buffer >> bits) & 0x1f) as u8);
            output.push(ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = usize::from(((buffer << (5 - bits)) & 0x1f) as u8);
        output.push(ALPHABET[index] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_round_trip() {
        for _ in 0..20 {
            let code = RecoveryCode::generate().expect("generate");
            let parsed = RecoveryCode::parse(&code.grouped()).expect("parse grouped");
            assert_eq!(code.normalized(), parsed.normalized());
            assert_eq!(code.grouped().len(), TOTAL_CHARS + 7);
        }
    }

    #[test]
    fn accepts_lowercase_and_spaces() {
        let code = RecoveryCode::generate().expect("generate");
        let messy = format!("  {}  ", code.grouped().to_lowercase());
        let parsed = RecoveryCode::parse(&messy).expect("parse messy");
        assert_eq!(code.normalized(), parsed.normalized());
    }

    #[test]
    fn rejects_bad_length() {
        assert!(RecoveryCode::parse("ABC").is_err());
    }

    #[test]
    fn rejects_invalid_alphabet() {
        let code = RecoveryCode::generate().expect("generate");
        let mut chars: Vec<char> = code.normalized().chars().collect();
        chars[0] = '!';
        let bad: String = chars.into_iter().collect();
        assert!(RecoveryCode::parse(&bad).is_err());
    }

    #[test]
    fn rejects_wrong_checksum() {
        let code = RecoveryCode::generate().expect("generate");
        let mut chars: Vec<char> = code.normalized().chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let bad: String = chars.into_iter().collect();
        assert!(RecoveryCode::parse(&bad).is_err());
    }

    #[test]
    fn recovery_key_is_deterministic_and_user_bound() {
        let code = RecoveryCode::generate().expect("generate");
        let first = code.recovery_key("user-1").expect("key");
        let second = code.recovery_key("user-1").expect("key");
        let other = code.recovery_key("user-2").expect("key");
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_ne!(first.as_bytes(), other.as_bytes());
    }
}
