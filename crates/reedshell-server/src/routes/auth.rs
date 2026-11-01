use axum::{Json, extract::State, http::StatusCode};

use crate::{
    error::AppError,
    services::auth::{LoginRequest, LoginResponse, RegisterRequest, RegisterResponse},
    state::AppState,
};

/// Register a new account.
pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    let response = crate::services::auth::register(state.users.as_ref(), request).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// Authenticate and enroll the calling device.
pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let response =
        crate::services::auth::login(state.users.as_ref(), state.tokens.as_ref(), request).await?;
    Ok(Json(response))
}
