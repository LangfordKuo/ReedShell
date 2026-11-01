use reedshell_core::{
    consts::MAX_DEVICE_NAME_LEN,
    id::{DeviceId, UserId},
    model::DevicePlatform,
};
use serde::Serialize;
use time::OffsetDateTime;

use crate::{
    error::AppError,
    repo::{DeviceRecord, RepoError, UserRepository},
};

#[derive(Debug, Serialize)]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub platform: DevicePlatform,
    pub os_version: Option<String>,
    pub app_version: Option<String>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub current: bool,
}

#[derive(Debug, Serialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceView>,
}

pub async fn list(
    repo: &dyn UserRepository,
    user_id: UserId,
    current_device: DeviceId,
) -> Result<DeviceListResponse, AppError> {
    let devices = repo.list_devices(user_id).await.map_err(map_repo_error)?;
    Ok(DeviceListResponse {
        devices: devices
            .into_iter()
            .map(|device| view(device, current_device))
            .collect(),
    })
}

pub async fn rename(
    repo: &dyn UserRepository,
    user_id: UserId,
    current_device: DeviceId,
    device_id: DeviceId,
    name: &str,
) -> Result<DeviceView, AppError> {
    let name = validate_name(name)?;
    let device = repo
        .rename_device(user_id, device_id, &name)
        .await
        .map_err(map_repo_error)?;
    Ok(view(device, current_device))
}

pub async fn revoke(
    repo: &dyn UserRepository,
    user_id: UserId,
    device_id: DeviceId,
) -> Result<(), AppError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    repo.revoke_device(user_id, device_id, now)
        .await
        .map_err(map_repo_error)?;
    repo.revoke_device_tokens(device_id, now)
        .await
        .map_err(map_repo_error)?;
    Ok(())
}

fn view(device: DeviceRecord, current_device: DeviceId) -> DeviceView {
    DeviceView {
        id: device.id.to_string(),
        name: device.name,
        platform: device.platform,
        os_version: device.os_version,
        app_version: device.app_version,
        created_at: device.created_at,
        revoked_at: device.revoked_at,
        current: device.id == current_device,
    }
}

fn validate_name(name: &str) -> Result<String, AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_DEVICE_NAME_LEN {
        return Err(AppError::bad_request(
            "invalid_device_name",
            format!("name must be 1..={MAX_DEVICE_NAME_LEN} characters"),
        ));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(AppError::bad_request(
            "invalid_device_name",
            "name must not contain control characters",
        ));
    }
    Ok(trimmed.to_owned())
}

fn map_repo_error(error: RepoError) -> AppError {
    match error {
        RepoError::EmailExists => AppError::internal(anyhow::anyhow!("unexpected email conflict")),
        RepoError::NotFound => AppError::not_found("device_not_found", "device not found"),
        RepoError::Storage(message) => AppError::internal(anyhow::anyhow!(message)),
    }
}
