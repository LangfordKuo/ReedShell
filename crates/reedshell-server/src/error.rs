use axum::{
    Json,
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Errors returned by HTTP handlers.
#[derive(Debug)]
pub enum AppError {
    BadRequest {
        code: &'static str,
        detail: String,
    },
    Unauthorized {
        code: &'static str,
        detail: String,
    },
    Conflict {
        code: &'static str,
        detail: String,
    },
    NotFound {
        code: &'static str,
        detail: String,
    },
    TooManyRequests {
        code: &'static str,
        detail: String,
        retry_after_secs: u64,
    },
    Internal(anyhow::Error),
}

impl AppError {
    #[must_use]
    pub fn bad_request(code: &'static str, detail: impl Into<String>) -> Self {
        Self::BadRequest {
            code,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn unauthorized(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Unauthorized {
            code,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Conflict {
            code,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn not_found(code: &'static str, detail: impl Into<String>) -> Self {
        Self::NotFound {
            code,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn too_many_requests(
        code: &'static str,
        detail: impl Into<String>,
        retry_after_secs: u64,
    ) -> Self {
        Self::TooManyRequests {
            code,
            detail: detail.into(),
            retry_after_secs,
        }
    }

    #[must_use]
    pub fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self::Internal(error.into())
    }
}

#[derive(Debug, Serialize)]
struct ProblemDetails {
    #[serde(rename = "type")]
    type_uri: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
    detail: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, title, code, detail, retry_after) = match self {
            Self::BadRequest { code, detail } => (
                StatusCode::BAD_REQUEST,
                "Invalid request",
                code,
                detail,
                None,
            ),
            Self::Unauthorized { code, detail } => {
                (StatusCode::UNAUTHORIZED, "Unauthorized", code, detail, None)
            }
            Self::Conflict { code, detail } => {
                (StatusCode::CONFLICT, "Conflict", code, detail, None)
            }
            Self::NotFound { code, detail } => {
                (StatusCode::NOT_FOUND, "Not found", code, detail, None)
            }
            Self::TooManyRequests {
                code,
                detail,
                retry_after_secs,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests",
                code,
                detail,
                Some(retry_after_secs),
            ),
            Self::Internal(error) => {
                tracing::error!(error = %error, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal error",
                    "internal_error",
                    "An unexpected error occurred.".to_owned(),
                    None,
                )
            }
        };

        let body = ProblemDetails {
            type_uri: "about:blank",
            title,
            status: status.as_u16(),
            code,
            detail,
        };
        let mut response = (status, Json(body)).into_response();
        if let Some(seconds) = retry_after
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(RETRY_AFTER, value);
        }
        response
    }
}
