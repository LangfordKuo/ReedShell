use axum::{Json, extract::State};
use serde::Serialize;

use crate::state::AppState;

/// Liveness probe.
pub async fn healthz() -> &'static str {
    "ok"
}

#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub repository: &'static str,
    pub database_configured: bool,
}

/// Readiness probe.
pub async fn readyz(State(state): State<AppState>) -> Json<ReadyResponse> {
    let repository = if state.config.database_url.is_some() {
        "mysql"
    } else {
        "memory"
    };
    Json(ReadyResponse {
        status: "ready",
        repository,
        database_configured: state.config.database_url.is_some(),
    })
}
