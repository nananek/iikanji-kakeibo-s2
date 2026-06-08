//! 統合テスト共有ヘルパ (sync テストから利用)。`DATABASE_URL`(Postgres) が必要。
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use chrono::Utc;
use http_body_util::BodyExt;
use iikanji_crypto::TotpSecret;
use iikanji_server::{migrate, router, AppState};
use iikanji_types::{KeyBlobs, LoginVerifyRequest, SignupRequest};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

pub async fn test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for server tests");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    migrate(&pool).await.expect("migrate");
    pool
}

pub async fn test_app() -> Router {
    router(AppState::new(test_pool().await, b"test-secret".to_vec()))
}

/// 任意メソッド + 任意の Bearer トークン + 任意 JSON body でリクエストする。
pub async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

pub fn unique_email() -> String {
    format!("u{}@example.com", Uuid::new_v4().simple())
}

pub fn now() -> u64 {
    Utc::now().timestamp() as u64
}

pub fn signup_body(email: &str, auth_key: Vec<u8>) -> Value {
    serde_json::to_value(SignupRequest {
        email: email.to_string(),
        salt_pw: vec![1, 2, 3, 4],
        kdf_version: 1,
        auth_key,
        key_blobs: KeyBlobs {
            mk_pw: vec![10, 11],
            mk_recovery: vec![12, 13],
            dk_wrap: vec![14, 15],
        },
    })
    .unwrap()
}

pub fn verify_body(email: &str, auth_key: Vec<u8>) -> Value {
    serde_json::to_value(LoginVerifyRequest {
        email: email.to_string(),
        auth_key,
    })
    .unwrap()
}

pub fn secret_from_uri(uri: &str) -> TotpSecret {
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    TotpSecret::from_base32(b32).unwrap()
}

pub fn code_at(uri: &str, unix_time: u64) -> String {
    secret_from_uri(uri).code_at(unix_time).unwrap()
}

/// 完全な認証 ceremony (signup→confirm→login→2FA) を実行し session_token を返す。
pub async fn authenticate(app: &Router) -> String {
    let email = unique_email();
    let auth_key = vec![7u8; 32];
    let (_, body) = request(
        app,
        "POST",
        "/auth/signup",
        None,
        Some(&signup_body(&email, auth_key.clone())),
    )
    .await;
    let uri = body["totp_provisioning_uri"].as_str().unwrap().to_string();
    request(
        app,
        "POST",
        "/auth/totp/confirm",
        None,
        Some(&json!({ "email": email, "code": code_at(&uri, now()) })),
    )
    .await;
    let (_, lv) = request(
        app,
        "POST",
        "/auth/login/verify",
        None,
        Some(&verify_body(&email, auth_key)),
    )
    .await;
    let login_token = lv["login_token"].as_str().unwrap().to_string();
    // confirm と別 step を使う (replay 回避)。
    let (_, sess) = request(
        app,
        "POST",
        "/auth/2fa/totp",
        None,
        Some(&json!({ "login_token": login_token, "code": code_at(&uri, now() + 30) })),
    )
    .await;
    sess["session_token"].as_str().unwrap().to_string()
}
