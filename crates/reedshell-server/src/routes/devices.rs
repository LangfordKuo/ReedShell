use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use reedshell_core::id::DeviceId;
use serde::Deserialize;

use crate::{
    error::AppError,
    services::{
        auth,
        devices::{self, DeviceListResponse, DeviceView},
    },
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct RenameDeviceRequest {
    pub name: String,
}

/// List every device enrolled by the authenticated account.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<DeviceListResponse>, AppError> {
    let (user_id, current_device) =
        auth::authenticate(state.users.as_ref(), state.tokens.as_ref(), &headers).await?;
    Ok(Json(
        devices::list(state.users.as_ref(), user_id, current_device).await?,
    ))
}

/// Rename one of the authenticated account's devices.
pub async fn rename(
    State(state): State<AppState>,
    Path(device_id): Path<DeviceId>,
    headers: HeaderMap,
    Json(request): Json<RenameDeviceRequest>,
) -> Result<Json<DeviceView>, AppError> {
    let (user_id, current_device) =
        auth::authenticate(state.users.as_ref(), state.tokens.as_ref(), &headers).await?;
    Ok(Json(
        devices::rename(
            state.users.as_ref(),
            user_id,
            current_device,
            device_id,
            &request.name,
        )
        .await?,
    ))
}

/// Revoke one of the authenticated account's devices.
pub async fn revoke(
    State(state): State<AppState>,
    Path(device_id): Path<DeviceId>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let (user_id, _) =
        auth::authenticate(state.users.as_ref(), state.tokens.as_ref(), &headers).await?;
    devices::revoke(state.users.as_ref(), user_id, device_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
