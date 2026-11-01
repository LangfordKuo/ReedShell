use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use reedshell_server::{
    AppState, Config, Environment,
    repo::mysql::MySqlUserRepository,
    routes,
    security::{rate_limit::MemoryRateLimiter, token::TokenSigner},
};
use serde_json::{Value, json};
use sqlx::mysql::MySqlPoolOptions;
use time::OffsetDateTime;
use tower::ServiceExt;
use ulid::Ulid;

async fn mysql_app() -> Option<(Router, sqlx::MySqlPool)> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .ok()?;
    sqlx::migrate!("./migrations").run(&pool).await.ok()?;

    let config = Arc::new(Config {
        bind_addr: "127.0.0.1:0".parse().ok()?,
        environment: Environment::Development,
        database_url: Some(database_url),
        redis_url: None,
        token_signing_key: [9u8; 32],
        allow_memory_repository: false,
    });
    let users = Arc::new(MySqlUserRepository::new(pool.clone()));
    let tokens = Arc::new(TokenSigner::from_seed([9u8; 32]));
    let limiter = Arc::new(MemoryRateLimiter::new());

    Some((
        routes::router(AppState {
            config,
            users,
            tokens,
            limiter,
        }),
        pool,
    ))
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
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
async fn mysql_register_login_refresh_flow() {
    let Some((app, pool)) = mysql_app().await else {
        eprintln!("skipping MySQL integration test: DATABASE_URL is not set");
        return;
    };

    let email = format!("mysql-test-{}@example.com", Ulid::new());
    let signing = SigningKey::from_bytes(&[21u8; 32]);
    let public_key = b64(&signing.verifying_key().to_bytes());

    let register = json!({
        "email": email,
        "auth_key": b64(&[22u8; 32]),
        "kdf_salt": b64(&[23u8; 16]),
        "kdf_params": {"memory_kib": 65_536, "iterations": 3, "parallelism": 1},
        "wrapped_mk_by_pw": b64(&[24u8; 48]),
        "nonce_pw": b64(&[25u8; 24]),
        "wrapped_mk_by_rc": b64(&[26u8; 48]),
        "nonce_rc": b64(&[27u8; 24])
    });
    let (status, body) = post(&app, "/v1/auth/register", &register).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let user_id = body["user_id"].as_str().expect("user id").to_owned();

    let login = json!({
        "email": email,
        "auth_key": b64(&[22u8; 32]),
        "device": {
            "name": "mysql-integration",
            "platform": "windows",
            "os_version": "Windows 11",
            "app_version": "0.1.0",
            "public_key": public_key
        }
    });
    let (status, body) = post(&app, "/v1/auth/login", &login).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let device_id = body["device_id"].as_str().expect("device id").to_owned();
    let refresh_token = body["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("count users");
    assert_eq!(count, 1);

    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let message = format!("refresh|{device_id}|{timestamp}");
    let signature = b64(&signing.sign(message.as_bytes()).to_bytes());
    let refresh = json!({
        "device_id": device_id,
        "refresh_token": refresh_token,
        "timestamp": timestamp,
        "signature": signature
    });

    let (status, body) = post(&app, "/v1/auth/refresh", &refresh).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rotated = body["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_owned();
    assert_ne!(rotated, refresh_token);

    let (status, body) = post(&app, "/v1/auth/refresh", &refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["code"], "refresh_token_reused");

    let _ = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
        .bind(&user_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM devices WHERE user_id = ?")
        .bind(&user_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&user_id)
        .execute(&pool)
        .await;
}
