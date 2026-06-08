//! 認証フローの統合テスト。`DATABASE_URL`(Postgres) が必要。
//! tower oneshot で TCP を立てずにルーターへ直接リクエストする。各テストは Uuid email で分離。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use http_body_util::BodyExt;
use iikanji_crypto::TotpSecret;
use iikanji_server::{migrate, router, AppState};
use iikanji_types::{KeyBlobs, LoginVerifyRequest, SignupRequest};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

async fn test_app() -> Router {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for server tests");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("connect");
    migrate(&pool).await.expect("migrate");
    router(AppState::new(pool, b"test-secret".to_vec()))
}

async fn call(app: &Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn unique_email() -> String {
    format!("u{}@example.com", Uuid::new_v4().simple())
}

fn signup_body(email: &str, auth_key: Vec<u8>) -> Value {
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

fn verify_body(email: &str, auth_key: Vec<u8>) -> Value {
    serde_json::to_value(LoginVerifyRequest {
        email: email.to_string(),
        auth_key,
    })
    .unwrap()
}

/// プロビジョニング URI から現在時刻の TOTP コードを作る (authenticator アプリの代用)。
fn code_from_uri(uri: &str) -> String {
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let secret = TotpSecret::from_base32(b32).unwrap();
    secret.code_at(Utc::now().timestamp() as u64).unwrap()
}

#[tokio::test]
async fn full_signup_confirm_login_flow() {
    let app = test_app().await;
    let email = unique_email();
    let auth_key = vec![7u8; 32];

    // signup → 201 + otpauth provisioning URI
    let (s, body) = call(&app, "/auth/signup", &signup_body(&email, auth_key.clone())).await;
    assert_eq!(s, StatusCode::CREATED);
    let uri = body["totp_provisioning_uri"].as_str().unwrap().to_string();
    assert!(uri.starts_with("otpauth://totp/"));

    // 重複 signup → 409
    let (s, _) = call(&app, "/auth/signup", &signup_body(&email, auth_key.clone())).await;
    assert_eq!(s, StatusCode::CONFLICT);

    // TOTP 確認前は login 不可 (パスワードが正しくても 403)
    let (s, _) = call(
        &app,
        "/auth/login/verify",
        &verify_body(&email, auth_key.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // 誤コード (長さ不正) で confirm → 401
    let (s, _) = call(
        &app,
        "/auth/totp/confirm",
        &json!({ "email": email, "code": "000" }),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // 正コードで confirm → 200 (active 化)
    let (s, _) = call(
        &app,
        "/auth/totp/confirm",
        &json!({ "email": email, "code": code_from_uri(&uri) }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // 二重 confirm → 409 (already confirmed)
    let (s, _) = call(
        &app,
        "/auth/totp/confirm",
        &json!({ "email": email, "code": code_from_uri(&uri) }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // login begin → 保存 salt
    let (s, lb) = call(&app, "/auth/login/begin", &json!({ "email": email })).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(lb["kdf_version"], 1);
    assert_eq!(
        STANDARD.decode(lb["salt_pw"].as_str().unwrap()).unwrap(),
        vec![1, 2, 3, 4]
    );

    // login verify (active) → 200 + totp factor + token
    let (s, lv) = call(
        &app,
        "/auth/login/verify",
        &verify_body(&email, auth_key.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!lv["login_token"].as_str().unwrap().is_empty());
    assert_eq!(lv["factors"][0], "totp");

    // 誤 authKey → 401
    let (s, _) = call(
        &app,
        "/auth/login/verify",
        &verify_body(&email, vec![8u8; 32]),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_begin_unknown_email_returns_deterministic_dummy_salt() {
    let app = test_app().await;
    let email = unique_email();
    let req = json!({ "email": email });

    let (s, body1) = call(&app, "/auth/login/begin", &req).await;
    assert_eq!(s, StatusCode::OK);
    let salt = STANDARD.decode(body1["salt_pw"].as_str().unwrap()).unwrap();
    assert_eq!(salt.len(), 16, "dummy salt is 16 bytes");

    let (_, body2) = call(&app, "/auth/login/begin", &req).await;
    assert_eq!(
        body1["salt_pw"], body2["salt_pw"],
        "deterministic dummy salt"
    );

    // 未登録ユーザーの verify は 401
    let (s, _) = call(
        &app,
        "/auth/login/verify",
        &verify_body(&email, vec![5u8; 32]),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signup_rejects_bad_auth_key_length() {
    let app = test_app().await;
    let (s, _) = call(
        &app,
        "/auth/signup",
        &signup_body(&unique_email(), vec![1, 2, 3]),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn health_ok() {
    let app = test_app().await;
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
