use axum::http::{HeaderMap, header::AUTHORIZATION};
use reedshell_core::id::{DeviceId, UserId};

use crate::{
    error::AppError,
    security::token::{Claims, TokenSigner},
};

/// Extract and verify the bearer access token.
pub fn require_access(headers: &HeaderMap, signer: &TokenSigner) -> Result<Claims, AppError> {
    let raw = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(invalid_token)?;

    let (scheme, token) = raw.split_once(' ').ok_or_else(invalid_token)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(invalid_token());
    }

    signer
        .verify_access(token.trim())
        .map_err(|_| invalid_token())
}

/// Extract the authenticated user and the calling device.
pub fn require_identity(
    headers: &HeaderMap,
    signer: &TokenSigner,
) -> Result<(UserId, DeviceId), AppError> {
    let claims = require_access(headers, signer)?;
    let user_id = claims.sub.parse::<UserId>().map_err(|_| invalid_token())?;
    let device_id = claims
        .did
        .parse::<DeviceId>()
        .map_err(|_| invalid_token())?;
    Ok((user_id, device_id))
}

fn invalid_token() -> AppError {
    AppError::unauthorized("invalid_token", "access token is invalid or expired")
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use reedshell_core::id::{DeviceId, UserId};

    use super::*;

    #[test]
    fn accepts_a_valid_bearer_header() {
        let signer = TokenSigner::from_seed([3u8; 32]);
        let token = signer
            .issue_access(UserId::new(), DeviceId::new(), 60)
            .expect("issue");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );

        let claims = require_access(&headers, &signer).expect("claims");
        assert!(!claims.sub.is_empty());
    }

    #[test]
    fn rejects_missing_and_malformed_headers() {
        let signer = TokenSigner::from_seed([3u8; 32]);
        assert!(require_access(&HeaderMap::new(), &signer).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert!(require_access(&headers, &signer).is_err());
    }
}
