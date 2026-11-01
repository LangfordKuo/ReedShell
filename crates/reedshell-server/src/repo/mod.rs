use async_trait::async_trait;
use reedshell_core::{
    id::{DeviceId, UserId},
    kdf::KdfParams,
    model::{DevicePlatform, Plan, UserStatus},
};

pub mod memory;
pub mod mysql;

/// An account as stored by the server.
#[derive(Clone, Debug)]
pub struct UserRecord {
    pub id: UserId,
    pub email: String,
    pub auth_salt: [u8; 16],
    pub auth_hash: [u8; 32],
    pub kdf_salt: [u8; 16],
    pub kdf_params: KdfParams,
    pub wrapped_mk_by_pw: Vec<u8>,
    pub nonce_pw: [u8; 24],
    pub wrapped_mk_by_rc: Vec<u8>,
    pub nonce_rc: [u8; 24],
    pub plan: Plan,
    pub status: UserStatus,
    pub created_at: i64,
}

/// Fields required to create an account.
#[derive(Clone, Debug)]
pub struct NewUser {
    pub id: UserId,
    pub email: String,
    pub auth_salt: [u8; 16],
    pub auth_hash: [u8; 32],
    pub kdf_salt: [u8; 16],
    pub kdf_params: KdfParams,
    pub wrapped_mk_by_pw: Vec<u8>,
    pub nonce_pw: [u8; 24],
    pub wrapped_mk_by_rc: Vec<u8>,
    pub nonce_rc: [u8; 24],
    pub created_at: i64,
}

/// A device enrolled by a signed-in client.
#[derive(Clone, Debug)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub platform: DevicePlatform,
    pub os_version: Option<String>,
    pub app_version: Option<String>,
    pub public_key: [u8; 32],
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

/// Fields required to enroll a device.
#[derive(Clone, Debug)]
pub struct NewDevice {
    pub id: DeviceId,
    pub user_id: UserId,
    pub name: String,
    pub platform: DevicePlatform,
    pub os_version: Option<String>,
    pub app_version: Option<String>,
    pub public_key: [u8; 32],
    pub created_at: i64,
}

/// A server-side refresh token record. Only the hash is stored.
#[derive(Clone, Debug)]
pub struct RefreshTokenRecord {
    pub id: String,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub token_hash: [u8; 32],
    pub expires_at: i64,
    pub created_at: i64,
    pub rotated_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("email already exists")]
    EmailExists,
    #[error("record not found")]
    NotFound,
    #[error("storage failure: {0}")]
    Storage(String),
}

/// Persistence boundary for accounts, devices, and refresh tokens.
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: NewUser) -> Result<UserRecord, RepoError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, RepoError>;
    async fn find_user_by_id(&self, id: UserId) -> Result<Option<UserRecord>, RepoError>;
    async fn create_device(&self, device: NewDevice) -> Result<DeviceRecord, RepoError>;
    async fn find_device(&self, id: DeviceId) -> Result<Option<DeviceRecord>, RepoError>;
    async fn list_devices(&self, user_id: UserId) -> Result<Vec<DeviceRecord>, RepoError>;
    async fn rename_device(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        name: &str,
    ) -> Result<DeviceRecord, RepoError>;
    async fn revoke_device(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        revoked_at: i64,
    ) -> Result<(), RepoError>;
    async fn count_active_devices(&self, user_id: UserId) -> Result<u32, RepoError>;
    async fn store_refresh_token(&self, token: RefreshTokenRecord) -> Result<(), RepoError>;
    async fn find_refresh_token(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<RefreshTokenRecord>, RepoError>;
    async fn rotate_refresh_token(
        &self,
        old_id: &str,
        new_token: RefreshTokenRecord,
        rotated_at: i64,
    ) -> Result<(), RepoError>;
    async fn revoke_device_tokens(
        &self,
        device_id: DeviceId,
        revoked_at: i64,
    ) -> Result<(), RepoError>;
}
