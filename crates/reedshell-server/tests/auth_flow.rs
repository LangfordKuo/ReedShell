use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use reedshell_server::{
    AppState,
    config::{Config, Environment},
    repo::memory::MemoryUserRepository,
    routes,
    security::{rate_limit::MemoryRateLimiter, token::TokenSigner},
};
use serde_json::{Value, json};
use time::OffsetDateTime;
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
    let limiter = Arc::new(MemoryRateLimiter::new());

    routes::router(AppState {
        config,
        users,
        tokens,
        limiter,
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
    login_body_with_key(email, auth_key_byte, device_name, &b64(&[9u8; 32]))
}

fn login_body_with_key(
    email: &str,
    auth_key_byte: u8,
    device_name: &str,
    public_key: &str,
) -> Value {
    json!({
        "email": email,
        "auth_key": b64(&[auth_key_byte; 32]),
        "device": {
            "name": device_name,
            "platform": "windows",
            "os_version": "Windows 11",
            "app_version": "0.1.0",
            "public_key": public_key
        }
    })
}

fn device_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn device_public_key(signing: &SigningKey) -> String {
    b64(&signing.verifying_key().to_bytes())
}

fn refresh_signature(signing: &SigningKey, device_id: &str, timestamp: i64) -> String {
    let message = format!("refresh|{device_id}|{timestamp}");
    b64(&signing.sign(message.as_bytes()).to_bytes())
}

fn refresh_body(device_id: &str, refresh_token: &str, signature: &str, timestamp: i64) -> Value {
    json!({
        "device_id": device_id,
        "refresh_token": refresh_token,
        "timestamp": timestamp,
        "signature": signature
    })
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
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

async fn post(app: &Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("build request");
    send(app, request).await
}

async fn post_with_bearer(app: &Router, uri: &str, token: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request");
    send(app, request).await
}

async fn request_with_bearer(
    app: &Router,
    method: Method,
    uri: &str,
    token: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));

    let request = if let Some(body) = body {
        builder = builder.header("content-type", "application/json");
        builder
            .body(Body::from(body.to_string()))
            .expect("build request")
    } else {
        builder.body(Body::empty()).expect("build request")
    };
    send(app, request).await
}

async fn register_and_login(
    app: &Router,
    email: &str,
    device_name: &str,
    seed: u8,
) -> (SigningKey, Value) {
    let (status, _) = post(app, "/v1/auth/register", &register_body(email)).await;
    assert_eq!(status, StatusCode::CREATED);

    let signing = SigningKey::from_bytes(&[seed; 32]);
    let (status, body) = post(
        app,
        "/v1/auth/login",
        &login_body_with_key(email, 1, device_name, &device_public_key(&signing)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (signing, body)
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
async fn refresh_rotates_and_detects_reuse() {
    let app = test_app();
    let signing = device_signing_key();
    let email = "refresh@example.com";

    let (status, _) = post(&app, "/v1/auth/register", &register_body(email)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, login) = post(
        &app,
        "/v1/auth/login",
        &login_body_with_key(email, 1, "refresh-device", &device_public_key(&signing)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let device_id = login["device_id"].as_str().expect("device id").to_owned();
    let old_refresh = login["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let signature = refresh_signature(&signing, &device_id, timestamp);
    let body = refresh_body(&device_id, &old_refresh, &signature, timestamp);

    let (status, refreshed) = post(&app, "/v1/auth/refresh", &body).await;
    assert_eq!(status, StatusCode::OK);
    let new_refresh = refreshed["refresh_token"]
        .as_str()
        .expect("new refresh token")
        .to_owned();
    assert_ne!(new_refresh, old_refresh);
    assert_eq!(refreshed["expires_in"], 900);

    // Presenting the rotated token again revokes every token for the device.
    let (status, conflict) = post(&app, "/v1/auth/refresh", &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(conflict["code"], "refresh_token_reused");

    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let signature = refresh_signature(&signing, &device_id, timestamp);
    let body = refresh_body(&device_id, &new_refresh, &signature, timestamp);
    let (status, _) = post(&app, "/v1/auth/refresh", &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revokes_refresh_token() {
    let app = test_app();
    let signing = device_signing_key();
    let email = "logout@example.com";

    let (status, _) = post(&app, "/v1/auth/register", &register_body(email)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, login) = post(
        &app,
        "/v1/auth/login",
        &login_body_with_key(email, 1, "logout-device", &device_public_key(&signing)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let access_token = login["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();
    let device_id = login["device_id"].as_str().expect("device id").to_owned();
    let refresh_token = login["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    let (status, body) = post_with_bearer(&app, "/v1/auth/logout", &access_token).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(body, Value::Null);

    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let signature = refresh_signature(&signing, &device_id, timestamp);
    let body = refresh_body(&device_id, &refresh_token, &signature, timestamp);
    let (status, _) = post(&app, "/v1/auth/refresh", &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_rejects_signature_from_another_device() {
    let app = test_app();
    let signing = device_signing_key();
    let email = "bad-signature@example.com";

    let (status, _) = post(&app, "/v1/auth/register", &register_body(email)).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, login) = post(
        &app,
        "/v1/auth/login",
        &login_body_with_key(email, 1, "device", &device_public_key(&signing)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let device_id = login["device_id"].as_str().expect("device id").to_owned();
    let refresh_token = login["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    let impostor = SigningKey::from_bytes(&[43u8; 32]);
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let signature = refresh_signature(&impostor, &device_id, timestamp);
    let body = refresh_body(&device_id, &refresh_token, &signature, timestamp);

    let (status, error) = post(&app, "/v1/auth/refresh", &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error["code"], "invalid_device_signature");
}

#[tokio::test]
async fn register_rate_limits_repeated_attempts() {
    let app = test_app();
    let email = "rate@example.com";

    let (status, _) = post(&app, "/v1/auth/register", &register_body(email)).await;
    assert_eq!(status, StatusCode::CREATED);

    for _ in 0..2 {
        let (status, _) = post(&app, "/v1/auth/register", &register_body(email)).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    let (status, body) = post(&app, "/v1/auth/register", &register_body(email)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
}

#[tokio::test]
async fn devices_can_be_listed_renamed_and_revoked() {
    let app = test_app();
    let (signing, login) = register_and_login(&app, "devices@example.com", "original", 51).await;

    let access_token = login["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();
    let device_id = login["device_id"].as_str().expect("device id").to_owned();
    let refresh_token = login["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    let (status, body) =
        request_with_bearer(&app, Method::GET, "/v1/devices", &access_token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["devices"].as_array().expect("devices").len(), 1);
    assert_eq!(body["devices"][0]["id"], device_id);
    assert_eq!(body["devices"][0]["current"], true);

    let (status, body) = request_with_bearer(
        &app,
        Method::PATCH,
        &format!("/v1/devices/{device_id}"),
        &access_token,
        Some(&json!({ "name": "renamed" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "renamed");

    let (status, _) = request_with_bearer(
        &app,
        Method::DELETE,
        &format!("/v1/devices/{device_id}"),
        &access_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A revoked device's access token stops working immediately.
    let (status, body) =
        request_with_bearer(&app, Method::GET, "/v1/devices", &access_token, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "device_revoked");

    // The revoked device no longer counts against the Free plan limit.
    let replacement = SigningKey::from_bytes(&[52u8; 32]);
    let (status, second_login) = post(
        &app,
        "/v1/auth/login",
        &login_body_with_key(
            "devices@example.com",
            1,
            "replacement",
            &device_public_key(&replacement),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second_access = second_login["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();

    let (status, body) =
        request_with_bearer(&app, Method::GET, "/v1/devices", &second_access, None).await;
    assert_eq!(status, StatusCode::OK);
    let devices = body["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 2);
    let revoked = devices
        .iter()
        .find(|device| device["id"] == device_id)
        .expect("revoked device");
    assert!(revoked["revoked_at"].is_number());

    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let signature = refresh_signature(&signing, &device_id, timestamp);
    let body = refresh_body(&device_id, &refresh_token, &signature, timestamp);
    let (status, _) = post(&app, "/v1/auth/refresh", &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cannot_rename_another_users_device() {
    let app = test_app();
    let (_owner_signing, owner) = register_and_login(&app, "owner@example.com", "owner", 61).await;
    let owner_device = owner["device_id"].as_str().expect("device id").to_owned();

    let (_other_signing, other) = register_and_login(&app, "other@example.com", "other", 62).await;
    let other_access = other["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();

    let (status, body) = request_with_bearer(
        &app,
        Method::PATCH,
        &format!("/v1/devices/{owner_device}"),
        &other_access,
        Some(&json!({ "name": "hijacked" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "device_not_found");
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
