use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};

use crate::{
    error::AppError,
    security::bearer,
    services::auth::{
        LoginRequest, LoginResponse, RefreshRequest, RefreshResponse, RegisterRequest,
        RegisterResponse,
    },
    state::AppState,
};

/// Register a new account.
pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    let response =
        crate::services::auth::register(state.users.as_ref(), state.limiter.as_ref(), request)
            .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// Authenticate and enroll the calling device.
pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let response = crate::services::auth::login(
        state.users.as_ref(),
        state.tokens.as_ref(),
        state.limiter.as_ref(),
        request,
    )
    .await?;
    Ok(Json(response))
}

/// Rotate a refresh token.
pub async fn refresh(
    State(state): State<AppState>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    let response = crate::services::auth::refresh(
        state.users.as_ref(),
        state.tokens.as_ref(),
        state.limiter.as_ref(),
        request,
    )
    .await?;
    Ok(Json(response))
}

/// Revoke all refresh tokens for the calling device.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let claims = bearer::require_access(&headers, state.tokens.as_ref())?;
    crate::services::auth::logout(state.users.as_ref(), &claims).await?;
    Ok(StatusCode::NO_CONTENT)
}
