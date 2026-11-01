use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reedshell_server::{
    AppState,
    config::{Config, Environment},
    repo::memory::MemoryUserRepository,
    routes,
    security::token::TokenSigner,
};
use serde_json::{Value, json};
use tower::ServiceExt;

fn test_app() -> Router {
    let config = Arc::new(Config {
        bind_addr: "127.0.0.1:0".parse().expect("valid address"),
        environment: Environment::Development,
        database_url: None,
        redis_url: None,
        token_signing_key: [7u8; 32],
        allow_memory_repository: true,
    });
    let users = Arc::new(MemoryUserRepository::new());
    let tokens = Arc::new(TokenSigner::from_seed([7u8; 32]));

    routes::router(AppState {
        config,
        users,
        tokens,
    })
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn register_body(email: &str) -> Value {
    json!({
        "email": email,
        "auth_key": b64(&[1u8; 32]),
        "kdf_salt": b64(&[2u8; 16]),
        "kdf_params": {
            "memory_kib": 65_536,
            "iterations": 3,
            "parallelism": 1
        },
        "wrapped_mk_by_pw": b64(&[3u8; 48]),
        "nonce_pw": b64(&[4u8; 24]),
        "wrapped_mk_by_rc": b64(&[5u8; 48]),
        "nonce_rc": b64(&[6u8; 24])
    })
}

fn login_body(email: &str, auth_key_byte: u8, device_name: &str) -> Value {
    json!({
        "email": email,
        "auth_key": b64(&[auth_key_byte; 32]),
        "device": {
            "name": device_name,
            "platform": "windows",
            "os_version": "Windows 11",
            "app_version": "0.1.0",
            "public_key": b64(&[9u8; 32])
        }
    })
}

async fn post(app: &Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request");

    let response = app.clone().oneshot(request).await.expect("request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json body")
    };
    (status, value)
}

#[tokio::test]
async fn register_then_login() {
    let app = test_app();

    let (status, body) = post(
        &app,
        "/v1/auth/register",
        &register_body("user@example.com"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["user_id"].as_str().is_some());

    let (status, body) = post(
        &app,
        "/v1/auth/login",
        &login_body("user@example.com", 1, "desktop"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["expires_in"], 900);
    let access_token = body["access_token"].as_str().expect("access token");
    assert_eq!(access_token.split('.').count(), 3);
    assert!(
        !body["refresh_token"]
            .as_str()
            .expect("refresh token")
            .is_empty()
    );
}

#[tokio::test]
async fn duplicate_email_is_rejected() {
    let app = test_app();
    let (status, _) = post(&app, "/v1/auth/register", &register_body("dup@example.com")).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = post(&app, "/v1/auth/register", &register_body("dup@example.com")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "email_exists");
}

#[tokio::test]
async fn wrong_auth_key_is_rejected() {
    let app = test_app();
    let (status, _) = post(&app, "/v1/auth/register", &register_body("key@example.com")).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = post(
        &app,
        "/v1/auth/login",
        &login_body("key@example.com", 2, "desktop"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "invalid_credentials");
}

#[tokio::test]
async fn unknown_account_uses_the_same_error() {
    let app = test_app();
    let (status, body) = post(
        &app,
        "/v1/auth/login",
        &login_body("missing@example.com", 1, "desktop"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "invalid_credentials");
}

#[tokio::test]
async fn free_plan_limits_devices() {
    let app = test_app();
    let (status, _) = post(
        &app,
        "/v1/auth/register",
        &register_body("limit@example.com"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = post(
        &app,
        "/v1/auth/login",
        &login_body("limit@example.com", 1, "first"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post(
        &app,
        "/v1/auth/login",
        &login_body("limit@example.com", 1, "second"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "device_limit_reached");
}

#[tokio::test]
async fn invalid_base64_is_rejected() {
    let app = test_app();
    let mut body = register_body("bad@example.com");
    body["auth_key"] = Value::String("not-base64!".to_owned());

    let (status, body) = post(&app, "/v1/auth/register", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_base64");
}

#[tokio::test]
async fn health_endpoints_respond() {
    let app = test_app();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("health");
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("ready");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["repository"], "memory");
}
