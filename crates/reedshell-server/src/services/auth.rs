use axum::http::HeaderMap;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use reedshell_core::{
    consts::{
        ACCESS_TOKEN_TTL_SECS, AEAD_NONCE_LEN, AUTH_KEY_LEN, MAX_APP_VERSION_LEN,
        MAX_DEVICE_NAME_LEN, MAX_EMAIL_LEN, MAX_OS_VERSION_LEN, MAX_PRO_DEVICES, PUBLIC_KEY_LEN,
        REFRESH_TOKEN_TTL_SECS, WRAPPED_MASTER_KEY_LEN,
    },
    id::{DeviceId, UserId},
    kdf::{KDF_SALT_LEN, KdfParams},
    model::{DevicePlatform, Plan, UserStatus},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use ulid::Ulid;

use crate::{
    error::AppError,
    repo::{NewDevice, NewUser, RefreshTokenRecord, RepoError, UserRepository},
    security::{
        device::verify_device_signature,
        password,
        rate_limit::RateLimiter,
        token::{Claims, TokenSigner},
    },
};

const WRAPPED_MK_LEN: usize = WRAPPED_MASTER_KEY_LEN;
const MAX_REFRESH_SKEW_SECS: i64 = 300;
const REGISTER_LIMIT: u32 = 3;
const REGISTER_WINDOW_SECS: u64 = 3600;
const LOGIN_ATTEMPT_LIMIT: u32 = 10;
const LOGIN_ATTEMPT_WINDOW_SECS: u64 = 60;
const LOGIN_FAILURE_LIMIT: u32 = 20;
const LOGIN_FAILURE_WINDOW_SECS: u64 = 3600;
const REFRESH_LIMIT: u32 = 60;
const REFRESH_WINDOW_SECS: u64 = 60;

/// Registration payload produced by a client after deriving its keys.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub auth_key: String,
    pub kdf_salt: String,
    pub kdf_params: KdfParams,
    pub wrapped_mk_by_pw: String,
    pub nonce_pw: String,
    pub wrapped_mk_by_rc: String,
    pub nonce_rc: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
}

/// Device metadata supplied during login.
#[derive(Debug, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    #[serde(default)]
    pub platform: DevicePlatform,
    pub os_version: Option<String>,
    pub app_version: Option<String>,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_key: String,
    pub device: DeviceInfo,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub refresh_expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub device_id: String,
    pub refresh_token: String,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub refresh_expires_in: i64,
}

/// Create an account from client-derived key material.
pub async fn register(
    repo: &dyn UserRepository,
    limiter: &dyn RateLimiter,
    request: RegisterRequest,
) -> Result<RegisterResponse, AppError> {
    let email = normalize_email(&request.email)?;
    enforce_limit(
        limiter,
        &format!("register:{email}"),
        REGISTER_LIMIT,
        REGISTER_WINDOW_SECS,
    )
    .await?;
    let auth_key = decode_fixed::<AUTH_KEY_LEN>(&request.auth_key, "auth_key")?;
    let kdf_salt = decode_fixed::<KDF_SALT_LEN>(&request.kdf_salt, "kdf_salt")?;
    if !request.kdf_params.is_valid() {
        return Err(AppError::bad_request(
            "invalid_kdf_params",
            "unsupported KDF parameters",
        ));
    }

    let wrapped_mk_by_pw = decode_wrapped_key(&request.wrapped_mk_by_pw, "wrapped_mk_by_pw")?;
    let nonce_pw = decode_fixed::<AEAD_NONCE_LEN>(&request.nonce_pw, "nonce_pw")?;
    let wrapped_mk_by_rc = decode_wrapped_key(&request.wrapped_mk_by_rc, "wrapped_mk_by_rc")?;
    let nonce_rc = decode_fixed::<AEAD_NONCE_LEN>(&request.nonce_rc, "nonce_rc")?;

    let password_hash = password::hash_auth_key(&auth_key)?;
    let user_id = UserId::new();

    repo.create_user(NewUser {
        id: user_id,
        email,
        auth_salt: password_hash.salt,
        auth_hash: password_hash.hash,
        kdf_salt,
        kdf_params: request.kdf_params,
        wrapped_mk_by_pw,
        nonce_pw,
        wrapped_mk_by_rc,
        nonce_rc,
        created_at: now_secs(),
    })
    .await
    .map_err(map_repo_error)?;

    Ok(RegisterResponse {
        user_id: user_id.to_string(),
    })
}

/// Authenticate a client and enroll its device.
pub async fn login(
    repo: &dyn UserRepository,
    tokens: &TokenSigner,
    limiter: &dyn RateLimiter,
    request: LoginRequest,
) -> Result<LoginResponse, AppError> {
    let email = normalize_email(&request.email)?;
    let failure_key = format!("login_fail:{email}");
    let failure_state = limiter
        .peek(&failure_key)
        .await
        .map_err(|_| rate_limiter_unavailable())?;
    if failure_state.count >= LOGIN_FAILURE_LIMIT {
        return Err(AppError::too_many_requests(
            "account_locked",
            "too many failed sign-in attempts; try again later",
            failure_state.retry_after_secs,
        ));
    }
    enforce_limit(
        limiter,
        &format!("login_attempt:{email}"),
        LOGIN_ATTEMPT_LIMIT,
        LOGIN_ATTEMPT_WINDOW_SECS,
    )
    .await?;

    let auth_key = decode_fixed::<AUTH_KEY_LEN>(&request.auth_key, "auth_key")?;
    let device = validate_device(request.device)?;

    let Some(user) = repo
        .find_user_by_email(&email)
        .await
        .map_err(map_repo_error)?
    else {
        verify_dummy(&auth_key)?;
        record_login_failure(limiter, &failure_key).await?;
        return Err(invalid_credentials());
    };

    if !password::verify_auth_key(&auth_key, &user.auth_salt, &user.auth_hash)? {
        record_login_failure(limiter, &failure_key).await?;
        return Err(invalid_credentials());
    }
    if user.status != UserStatus::Active {
        record_login_failure(limiter, &failure_key).await?;
        return Err(invalid_credentials());
    }
    limiter
        .reset(&failure_key)
        .await
        .map_err(|_| rate_limiter_unavailable())?;

    let device_limit = match user.plan {
        Plan::Pro => MAX_PRO_DEVICES,
        Plan::Free => 1,
    };
    let active_devices = repo
        .count_active_devices(user.id)
        .await
        .map_err(map_repo_error)?;
    if active_devices >= device_limit {
        return Err(AppError::conflict(
            "device_limit_reached",
            "the account has reached its device limit",
        ));
    }

    let now = now_secs();
    let device_id = DeviceId::new();
    repo.create_device(NewDevice {
        id: device_id,
        user_id: user.id,
        name: device.name,
        platform: device.platform,
        os_version: device.os_version,
        app_version: device.app_version,
        public_key: device.public_key,
        created_at: now,
    })
    .await
    .map_err(map_repo_error)?;

    let access_token = tokens
        .issue_access(user.id, device_id, ACCESS_TOKEN_TTL_SECS)
        .map_err(|error| AppError::internal(anyhow::anyhow!("token issuance failed: {error}")))?;
    let (refresh_token, refresh_hash) = random_refresh_token()?;

    repo.store_refresh_token(RefreshTokenRecord {
        id: Ulid::new().to_string(),
        user_id: user.id,
        device_id,
        token_hash: refresh_hash,
        expires_at: now.saturating_add(REFRESH_TOKEN_TTL_SECS),
        created_at: now,
        rotated_at: None,
        revoked_at: None,
    })
    .await
    .map_err(map_repo_error)?;

    Ok(LoginResponse {
        user_id: user.id.to_string(),
        device_id: device_id.to_string(),
        access_token,
        expires_in: ACCESS_TOKEN_TTL_SECS,
        refresh_token,
        refresh_expires_in: REFRESH_TOKEN_TTL_SECS,
    })
}

/// Rotate a refresh token and issue a new access token.
pub async fn refresh(
    repo: &dyn UserRepository,
    tokens: &TokenSigner,
    limiter: &dyn RateLimiter,
    request: RefreshRequest,
) -> Result<RefreshResponse, AppError> {
    let device_id = request
        .device_id
        .parse::<DeviceId>()
        .map_err(|_| invalid_refresh_token())?;
    enforce_limit(
        limiter,
        &format!("refresh:{device_id}"),
        REFRESH_LIMIT,
        REFRESH_WINDOW_SECS,
    )
    .await?;
    let token_hash = hash_refresh_token(request.refresh_token.trim());
    let now = now_secs();

    let Some(record) = repo
        .find_refresh_token(&token_hash)
        .await
        .map_err(map_repo_error)?
    else {
        return Err(invalid_refresh_token());
    };

    // A token that was already rotated being presented again means it leaked.
    if record.rotated_at.is_some() {
        repo.revoke_device_tokens(record.device_id, now)
            .await
            .map_err(map_repo_error)?;
        return Err(AppError::unauthorized(
            "refresh_token_reused",
            "refresh token reuse detected; device sessions revoked",
        ));
    }

    if record.revoked_at.is_some() || record.expires_at <= now {
        return Err(invalid_refresh_token());
    }
    if record.device_id != device_id {
        return Err(invalid_refresh_token());
    }

    let Some(device) = repo.find_device(device_id).await.map_err(map_repo_error)? else {
        return Err(invalid_refresh_token());
    };
    if device.revoked_at.is_some() || device.user_id != record.user_id {
        return Err(invalid_refresh_token());
    }

    if (now - request.timestamp).abs() > MAX_REFRESH_SKEW_SECS {
        return Err(AppError::unauthorized(
            "stale_request",
            "request timestamp is outside the allowed window",
        ));
    }
    let message = refresh_signature_message(&request.device_id, request.timestamp);
    verify_device_signature(&device.public_key, message.as_bytes(), &request.signature)?;

    let access_token = tokens
        .issue_access(device.user_id, device_id, ACCESS_TOKEN_TTL_SECS)
        .map_err(|error| AppError::internal(anyhow::anyhow!("token issuance failed: {error}")))?;
    let (refresh_token, refresh_hash) = random_refresh_token()?;

    repo.rotate_refresh_token(
        &record.id,
        RefreshTokenRecord {
            id: Ulid::new().to_string(),
            user_id: device.user_id,
            device_id,
            token_hash: refresh_hash,
            expires_at: now.saturating_add(REFRESH_TOKEN_TTL_SECS),
            created_at: now,
            rotated_at: None,
            revoked_at: None,
        },
        now,
    )
    .await
    .map_err(map_repo_error)?;

    Ok(RefreshResponse {
        access_token,
        expires_in: ACCESS_TOKEN_TTL_SECS,
        refresh_token,
        refresh_expires_in: REFRESH_TOKEN_TTL_SECS,
    })
}

/// Revoke every refresh token belonging to the calling device.
pub async fn logout(repo: &dyn UserRepository, claims: &Claims) -> Result<(), AppError> {
    let device_id = claims
        .did
        .parse::<DeviceId>()
        .map_err(|_| AppError::unauthorized("invalid_token", "access token is invalid"))?;
    repo.revoke_device_tokens(device_id, now_secs())
        .await
        .map_err(map_repo_error)
}

/// Authenticate a protected request and reject revoked devices immediately.
pub async fn authenticate(
    repo: &dyn UserRepository,
    tokens: &TokenSigner,
    headers: &HeaderMap,
) -> Result<(UserId, DeviceId), AppError> {
    let (user_id, device_id) = crate::security::bearer::require_identity(headers, tokens)?;
    let Some(device) = repo.find_device(device_id).await.map_err(map_repo_error)? else {
        return Err(AppError::unauthorized(
            "invalid_token",
            "device is not registered",
        ));
    };
    if device.user_id != user_id || device.revoked_at.is_some() {
        return Err(AppError::unauthorized(
            "device_revoked",
            "device has been revoked",
        ));
    }
    Ok((user_id, device_id))
}

/// The exact message a client signs when refreshing.
#[must_use]
pub fn refresh_signature_message(device_id: &str, timestamp: i64) -> String {
    format!("refresh|{device_id}|{timestamp}")
}

struct ValidatedDevice {
    name: String,
    platform: DevicePlatform,
    os_version: Option<String>,
    app_version: Option<String>,
    public_key: [u8; 32],
}

fn validate_device(device: DeviceInfo) -> Result<ValidatedDevice, AppError> {
    let name = device.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > MAX_DEVICE_NAME_LEN {
        return Err(AppError::bad_request(
            "invalid_device_name",
            format!("device.name must be 1..={MAX_DEVICE_NAME_LEN} characters"),
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "invalid_device_name",
            "device.name must not contain control characters",
        ));
    }

    let os_version = validate_optional_text(device.os_version, MAX_OS_VERSION_LEN, "os_version")?;
    let app_version =
        validate_optional_text(device.app_version, MAX_APP_VERSION_LEN, "app_version")?;
    let public_key = decode_fixed::<PUBLIC_KEY_LEN>(&device.public_key, "device.public_key")?;

    Ok(ValidatedDevice {
        name,
        platform: device.platform,
        os_version,
        app_version,
        public_key,
    })
}

fn validate_optional_text(
    value: Option<String>,
    max_len: usize,
    field: &'static str,
) -> Result<Option<String>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > max_len || trimmed.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "invalid_device_metadata",
            format!("{field} is invalid"),
        ));
    }
    Ok(Some(trimmed.to_owned()))
}

fn normalize_email(value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_EMAIL_LEN {
        return Err(AppError::bad_request("invalid_email", "email is invalid"));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(AppError::bad_request("invalid_email", "email is invalid"));
    }
    let Some((local, domain)) = trimmed.rsplit_once('@') else {
        return Err(AppError::bad_request("invalid_email", "email is invalid"));
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(AppError::bad_request("invalid_email", "email is invalid"));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn decode_b64(value: &str, field: &'static str) -> Result<Vec<u8>, AppError> {
    let trimmed = value.trim();
    STANDARD
        .decode(trimmed)
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .map_err(|_| {
            AppError::bad_request("invalid_base64", format!("{field} must be valid base64"))
        })
}

fn decode_fixed<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N], AppError> {
    let bytes = decode_b64(value, field)?;
    bytes.try_into().map_err(|_| {
        AppError::bad_request(
            "invalid_field_length",
            format!("{field} must decode to {N} bytes"),
        )
    })
}

fn decode_wrapped_key(value: &str, field: &'static str) -> Result<Vec<u8>, AppError> {
    let bytes = decode_b64(value, field)?;
    if bytes.len() != WRAPPED_MK_LEN {
        return Err(AppError::bad_request(
            "invalid_field_length",
            format!("{field} must decode to {WRAPPED_MK_LEN} bytes"),
        ));
    }
    Ok(bytes)
}

fn random_refresh_token() -> Result<(String, [u8; 32]), AppError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| AppError::internal(anyhow::anyhow!("random source: {error}")))?;
    let raw = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_refresh_token(&raw);
    Ok((raw, hash))
}

fn hash_refresh_token(raw: &str) -> [u8; 32] {
    let digest = Sha256::digest(raw.as_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

fn invalid_refresh_token() -> AppError {
    AppError::unauthorized(
        "invalid_refresh_token",
        "refresh token is invalid or expired",
    )
}

fn verify_dummy(auth_key: &[u8; 32]) -> Result<(), AppError> {
    const DUMMY_SALT: [u8; 16] = [0x5a; 16];
    const DUMMY_HASH: [u8; 32] = [0u8; 32];
    let _ = password::verify_auth_key(auth_key, &DUMMY_SALT, &DUMMY_HASH)?;
    Ok(())
}

fn invalid_credentials() -> AppError {
    AppError::unauthorized("invalid_credentials", "email or password is incorrect")
}

async fn enforce_limit(
    limiter: &dyn RateLimiter,
    key: &str,
    limit: u32,
    window_secs: u64,
) -> Result<(), AppError> {
    let decision = limiter
        .hit(key, limit, window_secs)
        .await
        .map_err(|_| rate_limiter_unavailable())?;
    if decision.allowed {
        return Ok(());
    }
    Err(AppError::too_many_requests(
        "rate_limited",
        "too many requests; try again later",
        decision.retry_after_secs,
    ))
}

async fn record_login_failure(limiter: &dyn RateLimiter, key: &str) -> Result<(), AppError> {
    limiter
        .hit(key, LOGIN_FAILURE_LIMIT, LOGIN_FAILURE_WINDOW_SECS)
        .await
        .map_err(|_| rate_limiter_unavailable())?;
    Ok(())
}

fn rate_limiter_unavailable() -> AppError {
    AppError::internal(anyhow::anyhow!("rate limiter unavailable"))
}

fn map_repo_error(error: RepoError) -> AppError {
    match error {
        RepoError::EmailExists => AppError::conflict("email_exists", "email is already registered"),
        RepoError::NotFound => AppError::internal(anyhow::anyhow!("repository record missing")),
        RepoError::Storage(message) => AppError::internal(anyhow::anyhow!(message)),
    }
}

fn now_secs() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
