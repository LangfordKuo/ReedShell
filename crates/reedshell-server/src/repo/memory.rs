use std::collections::HashMap;

use async_trait::async_trait;
use reedshell_core::id::UserId;
use reedshell_core::model::{Plan, UserStatus};
use time::OffsetDateTime;
use tokio::sync::RwLock;

use super::{
    DeviceRecord, NewDevice, NewUser, RefreshTokenRecord, RepoError, UserRecord, UserRepository,
};

#[derive(Default)]
struct MemoryStore {
    users: HashMap<UserId, UserRecord>,
    email_index: HashMap<String, UserId>,
    devices: Vec<DeviceRecord>,
    refresh_tokens: Vec<RefreshTokenRecord>,
}

/// In-memory repository for development and tests.
#[derive(Default)]
pub struct MemoryUserRepository {
    inner: RwLock<MemoryStore>,
}

impl MemoryUserRepository {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserRepository for MemoryUserRepository {
    async fn create_user(&self, user: NewUser) -> Result<UserRecord, RepoError> {
        let mut store = self.inner.write().await;
        if store.email_index.contains_key(&user.email) {
            return Err(RepoError::EmailExists);
        }

        let record = UserRecord {
            id: user.id,
            email: user.email.clone(),
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
        };

        store.email_index.insert(record.email.clone(), record.id);
        store.users.insert(record.id, record.clone());
        Ok(record)
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, RepoError> {
        let store = self.inner.read().await;
        let Some(user_id) = store.email_index.get(email) else {
            return Ok(None);
        };
        Ok(store.users.get(user_id).cloned())
    }

    async fn find_user_by_id(&self, id: UserId) -> Result<Option<UserRecord>, RepoError> {
        let store = self.inner.read().await;
        Ok(store.users.get(&id).cloned())
    }

    async fn create_device(&self, device: NewDevice) -> Result<DeviceRecord, RepoError> {
        let mut store = self.inner.write().await;
        if !store.users.contains_key(&device.user_id) {
            return Err(RepoError::NotFound);
        }

        let record = DeviceRecord {
            id: device.id,
            user_id: device.user_id,
            name: device.name,
            platform: device.platform,
            os_version: device.os_version,
            app_version: device.app_version,
            public_key: device.public_key,
            created_at: device.created_at,
        };
        store.devices.push(record.clone());
        Ok(record)
    }

    async fn count_active_devices(&self, user_id: UserId) -> Result<u32, RepoError> {
        let store = self.inner.read().await;
        let count = store
            .devices
            .iter()
            .filter(|device| device.user_id == user_id)
            .count();
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn store_refresh_token(&self, token: RefreshTokenRecord) -> Result<(), RepoError> {
        let mut store = self.inner.write().await;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        store
            .refresh_tokens
            .retain(|record| record.expires_at > now);
        store.refresh_tokens.push(token);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use reedshell_core::kdf::KdfParams;

    use super::*;

    fn new_user(email: &str) -> NewUser {
        NewUser {
            id: UserId::new(),
            email: email.to_owned(),
            auth_salt: [1u8; 16],
            auth_hash: [2u8; 32],
            kdf_salt: [3u8; 16],
            kdf_params: KdfParams::DESKTOP,
            wrapped_mk_by_pw: vec![4u8; 48],
            nonce_pw: [5u8; 24],
            wrapped_mk_by_rc: vec![6u8; 48],
            nonce_rc: [7u8; 24],
            created_at: 0,
        }
    }

    #[tokio::test]
    async fn rejects_duplicate_email() {
        let repo = MemoryUserRepository::new();
        repo.create_user(new_user("a@example.com"))
            .await
            .expect("create");
        let error = repo
            .create_user(new_user("a@example.com"))
            .await
            .expect_err("duplicate must fail");
        assert!(matches!(error, RepoError::EmailExists));
    }

    #[tokio::test]
    async fn finds_by_email_and_id() {
        let repo = MemoryUserRepository::new();
        let user = repo
            .create_user(new_user("a@example.com"))
            .await
            .expect("create");
        assert_eq!(
            repo.find_user_by_email("a@example.com")
                .await
                .expect("find")
                .expect("present")
                .id,
            user.id
        );
        assert_eq!(
            repo.find_user_by_id(user.id)
                .await
                .expect("find")
                .expect("present")
                .id,
            user.id
        );
        assert!(
            repo.find_user_by_email("missing@example.com")
                .await
                .expect("find")
                .is_none()
        );
    }
}
