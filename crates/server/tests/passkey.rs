//! passkey (WebAuthn 第2要素) のガード / ライフサイクル統合テスト。`DATABASE_URL`(Postgres) が必要。
//!
//! ハッピーパス (実認証器の attestation/assertion を伴う登録→認証) は Playwright Chromium 仮想
//! 認証器の e2e (`tests/e2e/passkey.spec.ts`) が担保する。ここでは認証器を介さず検証できる
//! **ガード**を確認する: 登録の session gate・login_token 検証・factors 出し分け・不正入力拒否・
//! 2FA 不成立では session/blob を出さないこと。

mod common;

use axum::http::StatusCode;
use axum::Router;
use common::*;
use iikanji_crypto::hash_token;
use iikanji_server::{router, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;

/// signup→confirm→login/verify まで進め、passkey 未登録ユーザーの (まだ消費していない) login_token を返す。
/// あわせて factors が TOTP のみであることを確認する。
async fn login_token_no_passkey(app: &Router) -> String {
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
    // passkey 未登録なら factors は TOTP のみ。
    let factors = lv["factors"].as_array().unwrap();
    assert_eq!(factors.len(), 1, "factors={:?}", factors);
    assert_eq!(lv["factors"][0], "totp");
    lv["login_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn register_begin_requires_session() {
    let app = test_app().await;
    // Bearer 無 → 401。
    let (s, _) = request(&app, "POST", "/auth/passkey/register/begin", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // 不正トークン → 401。
    let (s, _) = request(
        &app,
        "POST",
        "/auth/passkey/register/begin",
        Some("not-a-real-token"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_begin_with_session_returns_challenge_and_no_blob() {
    let app = test_app().await;
    let token = authenticate(&app).await;
    let (s, body) = request(
        &app,
        "POST",
        "/auth/passkey/register/begin",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // CreationChallengeResponse は publicKey.challenge / user.id を持つ。
    assert!(
        body["publicKey"]["challenge"].as_str().is_some(),
        "challenge 欠如: {body}"
    );
    assert!(body["publicKey"]["user"]["id"].as_str().is_some());
    // 登録 challenge に MK/DK blob は含めない (blob は 2FA 通過後の SessionResponse でのみ返す)。
    assert!(body.get("mk_pw").is_none());
    assert!(body.get("dk_wrap").is_none());
    assert!(body.get("session_token").is_none());
}

#[tokio::test]
async fn register_finish_rejects_bogus_credential() {
    let app = test_app().await;
    let token = authenticate(&app).await;
    // 先に begin して reg_state を作る。
    let (s, _) = request(
        &app,
        "POST",
        "/auth/passkey/register/begin",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // 構造的に不正な credential → 4xx (Json 拒否 or attestation 検証失敗)。資格情報は保存されない。
    let bad = json!({
        "credential": { "id": "AAAA", "rawId": "AAAA", "type": "public-key", "response": {} }
    });
    let (s, _) = request(
        &app,
        "POST",
        "/auth/passkey/register/finish",
        Some(&token),
        Some(&bad),
    )
    .await;
    assert!(s.is_client_error(), "expected 4xx, got {s}");
}

#[tokio::test]
async fn auth_begin_rejects_invalid_login_token() {
    let app = test_app().await;
    let (s, _) = request(
        &app,
        "POST",
        "/auth/passkey/auth/begin",
        None,
        Some(&json!({ "login_token": "nonexistent" })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_begin_without_passkey_is_bad_request() {
    let app = test_app().await;
    let token = login_token_no_passkey(&app).await;
    // passkey 未登録ユーザーは passkey 認証を開始できない。
    let (s, _) = request(
        &app,
        "POST",
        "/auth/passkey/auth/begin",
        None,
        Some(&json!({ "login_token": token })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_finish_rejects_bogus_and_issues_no_session() {
    let app = test_app().await;
    let token = login_token_no_passkey(&app).await;
    // auth_state も無く credential も不正 → 4xx。SessionResponse (session/blob) は返さない。
    let bad = json!({
        "login_token": token,
        "credential": { "id": "AAAA", "rawId": "AAAA", "type": "public-key", "response": {} }
    });
    let (s, body): (StatusCode, Value) =
        request(&app, "POST", "/auth/passkey/auth/finish", None, Some(&bad)).await;
    assert!(s.is_client_error(), "expected 4xx, got {s}");
    assert!(
        body.get("session_token").is_none(),
        "blob/session を漏らした: {body}"
    );
    assert!(body.get("mk_pw").is_none());
}

// ===== 2FA ゲート (期限切れ / 試行超過) が passkey 経路にも効くこと =====
//
// pending_logins の expires_at / failed_attempts は TOTP と passkey で共通のゲート。passkey の
// begin / finish 双方がこのゲートを尊重することを、DB 行を直接操作して確認する。finish のゲートは
// Json デコード後・assertion 検証前に効くため、パース可能だが暗号的に無効な credential で到達させる。

/// pending_logins を直接操作するため pool 付きでアプリを構築する。
async fn app_with_pool() -> (Router, PgPool) {
    let pool = test_pool().await;
    let app = router(AppState::new(pool.clone(), b"test-secret".to_vec()));
    (app, pool)
}

/// login_token の pending_logins 行を期限切れにする。
async fn expire_login_token(pool: &PgPool, login_token: &str) {
    sqlx::query(
        "UPDATE pending_logins SET expires_at = now() - interval '1 hour' WHERE token_hash = $1",
    )
    .bind(hash_token(login_token.as_bytes()).to_vec())
    .execute(pool)
    .await
    .expect("expire login token");
}

/// login_token の 2FA 失敗回数を上限超過まで引き上げる。
/// 100 は MAX_2FA_ATTEMPTS (現在 5) を確実に超える値 (定数は server 内部 private のため直書き)。
async fn exhaust_login_attempts(pool: &PgPool, login_token: &str) {
    sqlx::query("UPDATE pending_logins SET failed_attempts = 100 WHERE token_hash = $1")
        .bind(hash_token(login_token.as_bytes()).to_vec())
        .execute(pool)
        .await
        .expect("set failed attempts");
}

/// パース可能だが暗号的に無効な assertion credential (finish のゲートに到達させる用)。
fn dummy_assertion() -> Value {
    json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "authenticatorData": "AAAA",
            "clientDataJSON": "AAAA",
            "signature": "AAAA"
        }
    })
}

#[tokio::test]
async fn auth_begin_rejects_expired_login_token() {
    let (app, pool) = app_with_pool().await;
    let token = login_token_no_passkey(&app).await;
    expire_login_token(&pool, &token).await;
    let (s, _) = request(
        &app,
        "POST",
        "/auth/passkey/auth/begin",
        None,
        Some(&json!({ "login_token": token })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_finish_rejects_expired_login_token_without_session() {
    let (app, pool) = app_with_pool().await;
    let token = login_token_no_passkey(&app).await;
    expire_login_token(&pool, &token).await;
    let (s, body): (StatusCode, Value) = request(
        &app,
        "POST",
        "/auth/passkey/auth/finish",
        None,
        Some(&json!({ "login_token": token, "credential": dummy_assertion() })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(body.get("session_token").is_none());
    assert!(body.get("mk_pw").is_none());
}

#[tokio::test]
async fn auth_begin_rejects_after_max_2fa_attempts() {
    let (app, pool) = app_with_pool().await;
    let token = login_token_no_passkey(&app).await;
    exhaust_login_attempts(&pool, &token).await;
    let (s, _) = request(
        &app,
        "POST",
        "/auth/passkey/auth/begin",
        None,
        Some(&json!({ "login_token": token })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_finish_rejects_after_max_2fa_attempts_without_session() {
    let (app, pool) = app_with_pool().await;
    let token = login_token_no_passkey(&app).await;
    exhaust_login_attempts(&pool, &token).await;
    let (s, body): (StatusCode, Value) = request(
        &app,
        "POST",
        "/auth/passkey/auth/finish",
        None,
        Some(&json!({ "login_token": token, "credential": dummy_assertion() })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // invariant 4: 期限切れ側と対称に、blob (session/MK) を返さないことを確認する。
    assert!(body.get("session_token").is_none());
    assert!(body.get("mk_pw").is_none());
}
