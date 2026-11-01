use async_trait::async_trait;
use reedshell_core::{
    id::{DeviceId, UserId},
    model::{Plan, UserStatus},
};
use sqlx::{MySqlPool, Row, mysql::MySqlRow};
use time::OffsetDateTime;

use super::{
    DeviceRecord, NewDevice, NewUser, RefreshTokenRecord, RepoError, UserRecord, UserRepository,
};

/// MySQL-backed repository used in production.
#[derive(Clone)]
pub struct MySqlUserRepository {
    pool: MySqlPool,
}

impl MySqlUserRepository {
    #[must_use]
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }
}

#[async_trait]
impl UserRepository for MySqlUserRepository {
    async fn create_user(&self, user: NewUser) -> Result<UserRecord, RepoError> {
        let params = serde_json::to_string(&user.kdf_params)
            .map_err(|error| RepoError::Storage(format!("invalid kdf_params: {error}")))?;
        let created_at = timestamp(user.created_at)?;

        let result = sqlx::query(
            "INSERT INTO users (
                id, email, auth_hash, kdf_salt, kdf_params, kdf_version,
                wrapped_mk_by_pw, nonce_pw, wrapped_mk_by_rc, nonce_rc,
                plan, status, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 'free', 'active', ?, ?)",
        )
        .bind(user.id.to_string())
        .bind(&user.email)
        .bind(user.auth_hash.as_slice())
        .bind(user.kdf_salt.as_slice())
        .bind(params)
        .bind(user.wrapped_mk_by_pw.as_slice())
        .bind(user.nonce_pw.as_slice())
        .bind(user.wrapped_mk_by_rc.as_slice())
        .bind(user.nonce_rc.as_slice())
        .bind(created_at)
        .bind(created_at)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(UserRecord {
                id: user.id,
                email: user.email,
                auth_salt: user.auth_salt,
                auth_hash: user.auth_hash,
                kdf_salt: user.kdf_salt,
                kdf_params: user.kdf_params,
                wrapped_mk_by_pw: user.wrapped_mk_by_pw,
                nonce_pw: user.nonce_pw,
                wrapped_mk_by_rc: user.wrapped_mk_by_rc,
                nonce_rc: user.nonce_rc,
                plan: Plan::Free,
                status: UserStatus::Active,
                created_at: user.created_at,
            }),
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("1062") => {
                Err(RepoError::EmailExists)
            }
            Err(error) => Err(storage(error)),
        }
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, RepoError> {
        let row = sqlx::query(
            "SELECT id, email, auth_salt, auth_hash, kdf_salt, kdf_params,
                    wrapped_mk_by_pw, nonce_pw, wrapped_mk_by_rc, nonce_rc,
                    plan, status, created_at
             FROM users WHERE email = ?",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;

        row.as_ref().map(user_from_row).transpose()
    }

    async fn find_user_by_id(&self, id: UserId) -> Result<Option<UserRecord>, RepoError> {
        let row = sqlx::query(
            "SELECT id, email, auth_salt, auth_hash, kdf_salt, kdf_params,
                    wrapped_mk_by_pw, nonce_pw, wrapped_mk_by_rc, nonce_rc,
                    plan, status, created_at
             FROM users WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;

        row.as_ref().map(user_from_row).transpose()
    }

    async fn create_device(&self, device: NewDevice) -> Result<DeviceRecord, RepoError> {
        sqlx::query(
            "INSERT INTO devices (
                id, user_id, name, platform, os_version, app_version, public_key, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(device.id.to_string())
        .bind(device.user_id.to_string())
        .bind(&device.name)
        .bind(device.platform.as_str())
        .bind(&device.os_version)
        .bind(&device.app_version)
        .bind(device.public_key.as_slice())
        .bind(timestamp(device.created_at)?)
        .execute(&self.pool)
        .await
        .map_err(storage)?;

        Ok(DeviceRecord {
            id: device.id,
            user_id: device.user_id,
            name: device.name,
            platform: device.platform,
            os_version: device.os_version,
            app_version: device.app_version,
            public_key: device.public_key,
            created_at: device.created_at,
            revoked_at: None,
        })
    }

    async fn find_device(&self, id: DeviceId) -> Result<Option<DeviceRecord>, RepoError> {
        let row = sqlx::query(
            "SELECT id, user_id, name, platform, os_version, app_version,
                    public_key, created_at, revoked_at
             FROM devices WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;

        row.as_ref().map(device_from_row).transpose()
    }

    async fn count_active_devices(&self, user_id: UserId) -> Result<u32, RepoError> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS count FROM devices
             WHERE user_id = ? AND revoked_at IS NULL",
        )
        .bind(user_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(storage)?;

        let count: i64 = row.try_get("count").map_err(storage)?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn store_refresh_token(&self, token: RefreshTokenRecord) -> Result<(), RepoError> {
        sqlx::query(
            "INSERT INTO refresh_tokens (
                id, user_id, device_id, token_hash, expires_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&token.id)
        .bind(token.user_id.to_string())
        .bind(token.device_id.to_string())
        .bind(token.token_hash.as_slice())
        .bind(timestamp(token.expires_at)?)
        .bind(timestamp(token.created_at)?)
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    async fn find_refresh_token(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<RefreshTokenRecord>, RepoError> {
        let row = sqlx::query(
            "SELECT id, user_id, device_id, token_hash, expires_at, created_at,
                    rotated_at, revoked_at
             FROM refresh_tokens WHERE token_hash = ?",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;

        row.as_ref().map(refresh_from_row).transpose()
    }

    async fn rotate_refresh_token(
        &self,
        old_id: &str,
        new_token: RefreshTokenRecord,
        rotated_at: i64,
    ) -> Result<(), RepoError> {
        let mut transaction = self.pool.begin().await.map_err(storage)?;

        let updated = sqlx::query(
            "UPDATE refresh_tokens SET rotated_at = ?, replaced_by = ?
             WHERE id = ? AND rotated_at IS NULL",
        )
        .bind(timestamp(rotated_at)?)
        .bind(&new_token.id)
        .bind(old_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;

        if updated.rows_affected() != 1 {
            return Err(RepoError::NotFound);
        }

        sqlx::query(
            "INSERT INTO refresh_tokens (
                id, user_id, device_id, token_hash, expires_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&new_token.id)
        .bind(new_token.user_id.to_string())
        .bind(new_token.device_id.to_string())
        .bind(new_token.token_hash.as_slice())
        .bind(timestamp(new_token.expires_at)?)
        .bind(timestamp(new_token.created_at)?)
        .execute(&mut *transaction)
        .await
        .map_err(storage)?;

        transaction.commit().await.map_err(storage)
    }

    async fn revoke_device_tokens(
        &self,
        device_id: DeviceId,
        revoked_at: i64,
    ) -> Result<(), RepoError> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ?
             WHERE device_id = ? AND revoked_at IS NULL",
        )
        .bind(timestamp(revoked_at)?)
        .bind(device_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }
}

fn user_from_row(row: &MySqlRow) -> Result<UserRecord, RepoError> {
    let id: String = row.try_get("id").map_err(storage)?;
    let plan: String = row.try_get("plan").map_err(storage)?;
    let status: String = row.try_get("status").map_err(storage)?;
    let kdf_params: serde_json::Value = row.try_get("kdf_params").map_err(storage)?;

    Ok(UserRecord {
        id: id
            .parse()
            .map_err(|_| RepoError::Storage("invalid user id".to_owned()))?,
        email: row.try_get("email").map_err(storage)?,
        auth_salt: array(row.try_get("auth_salt").map_err(storage)?, "auth_salt")?,
        auth_hash: array(row.try_get("auth_hash").map_err(storage)?, "auth_hash")?,
        kdf_salt: array(row.try_get("kdf_salt").map_err(storage)?, "kdf_salt")?,
        kdf_params: serde_json::from_value(kdf_params)
            .map_err(|error| RepoError::Storage(format!("invalid kdf_params: {error}")))?,
        wrapped_mk_by_pw: row.try_get("wrapped_mk_by_pw").map_err(storage)?,
        nonce_pw: array(row.try_get("nonce_pw").map_err(storage)?, "nonce_pw")?,
        wrapped_mk_by_rc: row.try_get("wrapped_mk_by_rc").map_err(storage)?,
        nonce_rc: array(row.try_get("nonce_rc").map_err(storage)?, "nonce_rc")?,
        plan: plan
            .parse()
            .map_err(|()| RepoError::Storage("invalid plan".to_owned()))?,
        status: status
            .parse()
            .map_err(|()| RepoError::Storage("invalid status".to_owned()))?,
        created_at: row
            .try_get::<OffsetDateTime, _>("created_at")
            .map_err(storage)?
            .unix_timestamp(),
    })
}

fn device_from_row(row: &MySqlRow) -> Result<DeviceRecord, RepoError> {
    let id: String = row.try_get("id").map_err(storage)?;
    let user_id: String = row.try_get("user_id").map_err(storage)?;
    let platform: String = row.try_get("platform").map_err(storage)?;
    let revoked_at: Option<OffsetDateTime> = row.try_get("revoked_at").map_err(storage)?;

    Ok(DeviceRecord {
        id: id
            .parse()
            .map_err(|_| RepoError::Storage("invalid device id".to_owned()))?,
        user_id: user_id
            .parse()
            .map_err(|_| RepoError::Storage("invalid user id".to_owned()))?,
        name: row.try_get("name").map_err(storage)?,
        platform: platform
            .parse()
            .map_err(|()| RepoError::Storage("invalid platform".to_owned()))?,
        os_version: row.try_get("os_version").map_err(storage)?,
        app_version: row.try_get("app_version").map_err(storage)?,
        public_key: array(row.try_get("public_key").map_err(storage)?, "public_key")?,
        created_at: row
            .try_get::<OffsetDateTime, _>("created_at")
            .map_err(storage)?
            .unix_timestamp(),
        revoked_at: revoked_at.map(|value| value.unix_timestamp()),
    })
}

fn refresh_from_row(row: &MySqlRow) -> Result<RefreshTokenRecord, RepoError> {
    let user_id: String = row.try_get("user_id").map_err(storage)?;
    let device_id: String = row.try_get("device_id").map_err(storage)?;
    let rotated_at: Option<OffsetDateTime> = row.try_get("rotated_at").map_err(storage)?;
    let revoked_at: Option<OffsetDateTime> = row.try_get("revoked_at").map_err(storage)?;

    Ok(RefreshTokenRecord {
        id: row.try_get("id").map_err(storage)?,
        user_id: user_id
            .parse()
            .map_err(|_| RepoError::Storage("invalid user id".to_owned()))?,
        device_id: device_id
            .parse()
            .map_err(|_| RepoError::Storage("invalid device id".to_owned()))?,
        token_hash: array(row.try_get("token_hash").map_err(storage)?, "token_hash")?,
        expires_at: row
            .try_get::<OffsetDateTime, _>("expires_at")
            .map_err(storage)?
            .unix_timestamp(),
        created_at: row
            .try_get::<OffsetDateTime, _>("created_at")
            .map_err(storage)?
            .unix_timestamp(),
        rotated_at: rotated_at.map(|value| value.unix_timestamp()),
        revoked_at: revoked_at.map(|value| value.unix_timestamp()),
    })
}

fn array<const N: usize>(bytes: Vec<u8>, field: &str) -> Result<[u8; N], RepoError> {
    bytes
        .try_into()
        .map_err(|_| RepoError::Storage(format!("invalid {field} length")))
}

fn timestamp(value: i64) -> Result<OffsetDateTime, RepoError> {
    OffsetDateTime::from_unix_timestamp(value)
        .map_err(|_| RepoError::Storage("invalid timestamp".to_owned()))
}

fn storage(error: sqlx::Error) -> RepoError {
    RepoError::Storage(error.to_string())
}
