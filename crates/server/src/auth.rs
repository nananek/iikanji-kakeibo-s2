//! 認証ハンドラ (Bitwarden 方式 + TOTP)。signup → totp/confirm → login(begin/verify)。
//!
//! 不変条件: サーバーはパスワードを学習しない (受け取るのは authKey のみ)。TOTP 秘密は
//! at-rest 暗号して保持し、復号鍵としては使わない。ラップ blob は 2FA 通過後に返す (後続 PR)。

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use iikanji_crypto::{
    gen_opaque_token, hash_auth_key, hash_token, open_at_rest, seal_at_rest, server_dummy_salt,
    verify_auth_key, AuthKey, KdfParams, TotpSecret,
};
use iikanji_types::{
    Factor, LoginBeginRequest, LoginBeginResponse, LoginVerifyRequest, LoginVerifyResponse,
    SessionResponse, SignupRequest, SignupResponse, TotpConfirmRequest, TotpVerifyRequest,
};
use serde::Deserialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};

use crate::error::AppError;
use crate::session::AuthUser;
use crate::AppState;

const TOTP_ISSUER: &str = "いいかんじ家計簿";
/// TOTP confirm の失敗許容回数。超えるとアカウント単位でロック (ブルートフォース緩和)。
const MAX_TOTP_CONFIRM_ATTEMPTS: i32 = 10;
/// 2FA (login_token) の失敗許容回数。超えるとトークンを破棄し再 login を要求する。
const MAX_2FA_ATTEMPTS: i32 = 5;
/// セッションの有効期間 (日)。
const SESSION_DAYS: i64 = 30;

/// `users.status` の値 (typo 防止のため定数化)。
mod status {
    pub const ACTIVE: &str = "active";
}

fn auth_key_from(bytes: &[u8]) -> Result<AuthKey, AppError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("auth_key must be 32 bytes"))?;
    Ok(AuthKey::from_wire_bytes(arr))
}

/// TOTP 秘密 at-rest 暗号の AAD コンテキスト (user_id で束縛)。
fn totp_context(user_id: Uuid) -> Vec<u8> {
    let mut c = b"iikanji/totp-at-rest/v1/".to_vec();
    c.extend_from_slice(user_id.as_bytes());
    c
}

fn now_unix() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

pub async fn health() -> &'static str {
    "ok"
}

pub async fn signup(
    State(st): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Result<(StatusCode, Json<SignupResponse>), AppError> {
    if req.email.trim().is_empty() {
        return Err(AppError::BadRequest("email required"));
    }
    let auth_key = auth_key_from(&req.auth_key)?;
    let auth_hash = hash_auth_key(&auth_key, KdfParams::SERVER_V1)?;

    let mut tx = st.pool.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO users (email, status, salt_pw, kdf_version, auth_hash) \
         VALUES ($1, 'pending_totp', $2, $3, $4) RETURNING id",
    )
    .bind(&req.email)
    .bind(&req.salt_pw)
    .bind(req.kdf_version as i32)
    .bind(&auth_hash)
    .fetch_one(&mut *tx)
    .await;

    let user_id: Uuid = match inserted {
        Ok(row) => row.get("id"),
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            return Err(AppError::Conflict("email already registered"));
        }
        Err(e) => return Err(e.into()),
    };

    for (purpose, blob) in [
        ("mk-pw", &req.key_blobs.mk_pw),
        ("mk-recovery", &req.key_blobs.mk_recovery),
        ("dk-wrap", &req.key_blobs.dk_wrap),
    ] {
        sqlx::query("INSERT INTO key_blobs (user_id, purpose, blob) VALUES ($1, $2, $3)")
            .bind(user_id)
            .bind(purpose)
            .bind(blob)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("INSERT INTO user_seq (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // TOTP は必須。秘密を生成し at-rest 暗号して保存 (enabled=false → confirm で有効化)。
    let secret = TotpSecret::generate();
    let secret_enc = seal_at_rest(&st.totp_key, &totp_context(user_id), secret.as_bytes());
    sqlx::query("INSERT INTO totp_secrets (user_id, secret_enc, enabled) VALUES ($1, $2, false)")
        .bind(user_id)
        .bind(secret_enc)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let totp_provisioning_uri = secret.provisioning_uri(TOTP_ISSUER, &req.email)?;
    Ok((
        StatusCode::CREATED,
        Json(SignupResponse {
            totp_provisioning_uri,
        }),
    ))
}

pub async fn totp_confirm(
    State(st): State<AppState>,
    Json(req): Json<TotpConfirmRequest>,
) -> Result<StatusCode, AppError> {
    // 行ロックを取って SELECT→検証→UPDATE を 1 tx で行い、並行 confirm の TOCTOU を防ぐ。
    let mut tx = st.pool.begin().await?;
    let row = sqlx::query(
        "SELECT u.id, u.status, t.secret_enc, t.last_used_step, t.failed_attempts \
         FROM users u JOIN totp_secrets t ON t.user_id = u.id \
         WHERE u.email = $1 FOR UPDATE OF u, t",
    )
    .bind(&req.email)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;

    let user_id: Uuid = row.get("id");
    if row.get::<String, _>("status") == status::ACTIVE {
        return Err(AppError::Conflict("totp already confirmed"));
    }
    if row.get::<i32, _>("failed_attempts") >= MAX_TOTP_CONFIRM_ATTEMPTS {
        return Err(AppError::TooManyRequests);
    }
    let secret_enc: Vec<u8> = row.get("secret_enc");
    let last_used_step: Option<i64> = row.get("last_used_step");

    let secret = TotpSecret::from_bytes(open_at_rest(
        &st.totp_key,
        &totp_context(user_id),
        &secret_enc,
    )?);

    match secret.verify(&req.code, now_unix(), last_used_step.map(|s| s as u64))? {
        Some(step) => {
            sqlx::query(
                "UPDATE totp_secrets SET enabled = true, last_used_step = $2, failed_attempts = 0 \
                 WHERE user_id = $1",
            )
            .bind(user_id)
            .bind(step as i64)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE users SET status = 'active', updated_at = now() WHERE id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(StatusCode::OK)
        }
        None => {
            // 失敗回数を加算して commit (ロールバックで失われないように)。
            sqlx::query(
                "UPDATE totp_secrets SET failed_attempts = failed_attempts + 1 WHERE user_id = $1",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Err(AppError::Unauthorized)
        }
    }
}

pub async fn login_begin(
    State(st): State<AppState>,
    Json(req): Json<LoginBeginRequest>,
) -> Result<Json<LoginBeginResponse>, AppError> {
    let row = sqlx::query("SELECT salt_pw, kdf_version FROM users WHERE email = $1")
        .bind(&req.email)
        .fetch_optional(&st.pool)
        .await?;
    let resp = match row {
        Some(r) => LoginBeginResponse {
            salt_pw: r.get("salt_pw"),
            kdf_version: r.get::<i32, _>("kdf_version") as u8,
        },
        None => LoginBeginResponse {
            salt_pw: server_dummy_salt(&st.server_secret, &req.email).to_vec(),
            kdf_version: KdfParams::INTERACTIVE_V1.version().unwrap_or(1),
        },
    };
    Ok(Json(resp))
}

pub async fn login_verify(
    State(st): State<AppState>,
    Json(req): Json<LoginVerifyRequest>,
) -> Result<Json<LoginVerifyResponse>, AppError> {
    let auth_key = auth_key_from(&req.auth_key)?;
    let row = sqlx::query("SELECT id, status, auth_hash FROM users WHERE email = $1")
        .bind(&req.email)
        .fetch_optional(&st.pool)
        .await?;

    let user_id = match row {
        Some(r) => {
            let hash: String = r.get("auth_hash");
            // パスワード正 かつ active のときのみ成功。未確定/非 active も 401 に統一し、
            // status code からパスワードの正否が漏れないようにする (enumeration 対策)。
            if verify_auth_key(&auth_key, &hash).unwrap_or(false)
                && r.get::<String, _>("status") == status::ACTIVE
            {
                Some(r.get::<Uuid, _>("id"))
            } else {
                None
            }
        }
        None => {
            // timing 平準化: 未知ユーザーでも固定ダミー PHC に対して verify を回す。
            let _ = verify_auth_key(&auth_key, &st.dummy_phc);
            None
        }
    };
    let user_id = user_id.ok_or(AppError::Unauthorized)?;

    // 2FA-pending トークンを発行 (OsRng 由来・ハッシュのみ保存)。blob は 2FA 通過後にのみ返す。
    let token = gen_opaque_token();
    let expires = Utc::now() + Duration::minutes(5);
    sqlx::query("INSERT INTO pending_logins (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash_token(token.as_bytes()).to_vec())
        .bind(user_id)
        .bind(expires)
        .execute(&st.pool)
        .await?;

    // 利用可能な第2要素を提示する。TOTP は常時必須、passkey は登録済みなら代替として選べる。
    let passkey_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&st.pool)
            .await?;
    let mut factors = vec![Factor::Totp];
    if passkey_count > 0 {
        factors.push(Factor::Passkey);
    }

    Ok(Json(LoginVerifyResponse {
        login_token: token,
        factors,
    }))
}

/// 2FA (TOTP)。login_token を消費し、TOTP コードを検証して**セッションと MK/DK ラップ blob を返す**。
/// blob はここで初めて返す (2FA 通過後)。login_token はワンショット相当 (失敗を上限まで許容)。
pub async fn totp_2fa(
    State(st): State<AppState>,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<Json<SessionResponse>, AppError> {
    let token_hash = hash_token(req.login_token.as_bytes()).to_vec();

    let mut tx = st.pool.begin().await?;
    let pending = sqlx::query(
        "SELECT user_id, expires_at, failed_attempts FROM pending_logins \
         WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;

    let user_id: Uuid = pending.get("user_id");
    let expires_at: DateTime<Utc> = pending.get("expires_at");
    let attempts: i32 = pending.get("failed_attempts");

    // 期限切れ / 試行超過 → トークンを破棄して拒否。
    if expires_at < Utc::now() || attempts >= MAX_2FA_ATTEMPTS {
        consume_login_token(&mut tx, &token_hash).await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized);
    }

    let trow = sqlx::query(
        "SELECT secret_enc, last_used_step FROM totp_secrets WHERE user_id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;
    let secret_enc: Vec<u8> = trow.get("secret_enc");
    let last_used_step: Option<i64> = trow.get("last_used_step");

    let secret = TotpSecret::from_bytes(open_at_rest(
        &st.totp_key,
        &totp_context(user_id),
        &secret_enc,
    )?);

    let step = match secret.verify(&req.code, now_unix(), last_used_step.map(|s| s as u64))? {
        Some(step) => step,
        None => {
            sqlx::query(
                "UPDATE pending_logins SET failed_attempts = failed_attempts + 1 \
                 WHERE token_hash = $1",
            )
            .bind(&token_hash)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(AppError::Unauthorized);
        }
    };

    // 成功: replay step を前進、login_token を消費、セッション発行。
    sqlx::query("UPDATE totp_secrets SET last_used_step = $2 WHERE user_id = $1")
        .bind(user_id)
        .bind(step as i64)
        .execute(&mut *tx)
        .await?;
    consume_login_token(&mut tx, &token_hash).await?;

    // 2FA 通過後にのみ セッション + MK/DK ラップ blob を発行する (passkey 経路と共通)。
    let resp = issue_session(&mut tx, user_id).await?;
    tx.commit().await?;
    Ok(Json(resp))
}

/// login_token を消費する。pending_login と、同じ token_hash に紐づく passkey 認証途中状態
/// (`webauthn_auth_states`) の両方を削除する。後者は `passkey_auth_begin` 後に別経路 (TOTP) で
/// 2FA を通した場合に孤立しうるため、login_token を捨てる全経路でまとめて掃除する。
async fn consume_login_token(
    tx: &mut Transaction<'_, Postgres>,
    token_hash: &[u8],
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM pending_logins WHERE token_hash = $1")
        .bind(token_hash)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM webauthn_auth_states WHERE token_hash = $1")
        .bind(token_hash)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// 2FA 通過後の共通処理: セッションを発行し、MK/DK ラップ blob と sync_cursor を返す。
/// TOTP / passkey の両 2FA 経路から呼ぶ。**ここで初めて blob を返す** (2FA 通過後)。
///
/// sync_cursor の正統な源泉は `user_seq.next_seq` (per-user 単調カウンタ)。レコード 0 件なら
/// next_seq=1 → cursor=0。`MAX(enc_records.seq)` は seq の抜けでずれ得るうえ全スキャンになるため使わない。
async fn issue_session(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<SessionResponse, AppError> {
    let session_token = gen_opaque_token();
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash_token(session_token.as_bytes()).to_vec())
        .bind(user_id)
        .bind(Utc::now() + Duration::days(SESSION_DAYS))
        .execute(&mut **tx)
        .await?;
    let mk_pw: Vec<u8> =
        sqlx::query_scalar("SELECT blob FROM key_blobs WHERE user_id = $1 AND purpose = $2")
            .bind(user_id)
            .bind("mk-pw")
            .fetch_one(&mut **tx)
            .await?;
    let dk_wrap: Vec<u8> =
        sqlx::query_scalar("SELECT blob FROM key_blobs WHERE user_id = $1 AND purpose = $2")
            .bind(user_id)
            .bind("dk-wrap")
            .fetch_one(&mut **tx)
            .await?;
    let sync_cursor: i64 =
        sqlx::query_scalar("SELECT next_seq - 1 FROM user_seq WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut **tx)
            .await?;
    Ok(SessionResponse {
        session_token,
        mk_pw,
        dk_wrap,
        sync_cursor: sync_cursor as u64,
    })
}

// ===== WebAuthn (passkey) 第2要素 =====
//
// passkey は復号鍵ではなくセッション/blob 解放を gate するだけ (CLAUDE.md invariant 3)。
// 登録 (register) は AuthUser gate = TOTP 通過済みセッション必須。認証 (auth) は login_token
// (= パスワード検証済み) を要し、TOTP の代替として 2FA を通す。blob は auth 成功後にのみ返る。

/// `webauthn_credentials.public_key` に格納した直列化 Passkey 群を復元する。
async fn load_user_passkeys(pool: &PgPool, user_id: Uuid) -> Result<Vec<Passkey>, AppError> {
    let rows = sqlx::query("SELECT public_key FROM webauthn_credentials WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|r| {
            let bytes: Vec<u8> = r.get("public_key");
            serde_json::from_slice::<Passkey>(&bytes).map_err(|e| {
                tracing::error!(error = %e, "stored passkey deserialize failed");
                AppError::Internal
            })
        })
        .collect()
}

/// `POST /auth/passkey/register/begin` (AuthUser 必須)。登録 challenge を発行する。
pub async fn passkey_register_begin(
    State(st): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<CreationChallengeResponse>, AppError> {
    // 期限切れの登録途中状態を掃除する (opportunistic GC — abandoned ceremony の蓄積を防ぐ)。
    sqlx::query("DELETE FROM webauthn_reg_states WHERE expires_at < now()")
        .execute(&st.pool)
        .await?;
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&st.pool)
        .await?;
    // 既存資格情報を exclude し、同一認証器の二重登録を防ぐ。
    let existing = load_user_passkeys(&st.pool, user_id).await?;
    let exclude: Vec<_> = existing.iter().map(|pk| pk.cred_id().clone()).collect();
    let exclude = (!exclude.is_empty()).then_some(exclude);

    let (ccr, reg_state) = st
        .webauthn
        .start_passkey_registration(user_id, &email, &email, exclude)
        .map_err(|e| {
            tracing::error!(error = %e, "passkey register begin failed");
            AppError::Internal
        })?;

    let state_bytes = serde_json::to_vec(&reg_state).map_err(|_| AppError::Internal)?;
    sqlx::query(
        "INSERT INTO webauthn_reg_states (user_id, state, expires_at) VALUES ($1, $2, $3) \
         ON CONFLICT (user_id) DO UPDATE \
           SET state = EXCLUDED.state, created_at = now(), expires_at = EXCLUDED.expires_at",
    )
    .bind(user_id)
    .bind(state_bytes)
    .bind(Utc::now() + Duration::minutes(5))
    .execute(&st.pool)
    .await?;

    Ok(Json(ccr))
}

#[derive(Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    credential: RegisterPublicKeyCredential,
    #[serde(default)]
    nickname: Option<String>,
}

/// `POST /auth/passkey/register/finish` (AuthUser 必須)。attestation を検証して資格情報を保存する。
pub async fn passkey_register_finish(
    State(st): State<AppState>,
    AuthUser(user_id): AuthUser,
    Json(req): Json<PasskeyRegisterFinishRequest>,
) -> Result<StatusCode, AppError> {
    let mut tx = st.pool.begin().await?;
    let row = sqlx::query(
        "SELECT state, expires_at FROM webauthn_reg_states WHERE user_id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::BadRequest("no passkey registration in progress"))?;
    let expires_at: DateTime<Utc> = row.get("expires_at");
    if expires_at < Utc::now() {
        sqlx::query("DELETE FROM webauthn_reg_states WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(AppError::BadRequest("passkey registration expired"));
    }
    let state_bytes: Vec<u8> = row.get("state");
    let reg_state: PasskeyRegistration =
        serde_json::from_slice(&state_bytes).map_err(|_| AppError::Internal)?;

    let passkey = st
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            tracing::warn!(error = %e, "passkey register finish failed");
            AppError::BadRequest("passkey registration failed")
        })?;

    let cred_id = passkey.cred_id().as_ref().to_vec();
    let pk_bytes = serde_json::to_vec(&passkey).map_err(|_| AppError::Internal)?;
    let inserted = sqlx::query(
        "INSERT INTO webauthn_credentials (user_id, cred_id, public_key, nickname) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(&cred_id)
    .bind(&pk_bytes)
    .bind(req.nickname.as_deref())
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        // cred_id UNIQUE 衝突 = 同じ認証器の二重登録。
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            return Err(AppError::Conflict("passkey already registered"));
        }
        Err(e) => return Err(e.into()),
    }
    sqlx::query("DELETE FROM webauthn_reg_states WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct PasskeyAuthBeginRequest {
    login_token: String,
}

/// `POST /auth/passkey/auth/begin`。login_token を検証し、passkey 認証 challenge を発行する。
/// login_token は消費しない (finish で消費)。
pub async fn passkey_auth_begin(
    State(st): State<AppState>,
    Json(req): Json<PasskeyAuthBeginRequest>,
) -> Result<Json<RequestChallengeResponse>, AppError> {
    let token_hash = hash_token(req.login_token.as_bytes()).to_vec();
    // 期限切れの認証途中状態を掃除する (opportunistic GC — abandoned ceremony の蓄積を防ぐ)。
    sqlx::query("DELETE FROM webauthn_auth_states WHERE expires_at < now()")
        .execute(&st.pool)
        .await?;
    let mut tx = st.pool.begin().await?;
    let row = sqlx::query(
        "SELECT user_id, expires_at, failed_attempts FROM pending_logins WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;
    let user_id: Uuid = row.get("user_id");
    let expires_at: DateTime<Utc> = row.get("expires_at");
    let attempts: i32 = row.get("failed_attempts");
    if expires_at < Utc::now() || attempts >= MAX_2FA_ATTEMPTS {
        return Err(AppError::Unauthorized);
    }

    let passkeys = load_user_passkeys(&st.pool, user_id).await?;
    if passkeys.is_empty() {
        return Err(AppError::BadRequest("no passkey registered"));
    }
    let (rcr, auth_state) = st
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| {
            tracing::error!(error = %e, "passkey auth begin failed");
            AppError::Internal
        })?;

    let state_bytes = serde_json::to_vec(&auth_state).map_err(|_| AppError::Internal)?;
    sqlx::query(
        "INSERT INTO webauthn_auth_states (token_hash, user_id, state, expires_at) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (token_hash) DO UPDATE \
           SET state = EXCLUDED.state, user_id = EXCLUDED.user_id, \
               created_at = now(), expires_at = EXCLUDED.expires_at",
    )
    .bind(&token_hash)
    .bind(user_id)
    .bind(state_bytes)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(rcr))
}

#[derive(Deserialize)]
pub struct PasskeyAuthFinishRequest {
    login_token: String,
    credential: PublicKeyCredential,
}

/// `POST /auth/passkey/auth/finish`。assertion を検証し、成功で **セッション + MK/DK blob** を返す
/// (TOTP 2FA と同一)。sign_count 後退は webauthn-rs が finish で Err にする → 401。
pub async fn passkey_auth_finish(
    State(st): State<AppState>,
    Json(req): Json<PasskeyAuthFinishRequest>,
) -> Result<Json<SessionResponse>, AppError> {
    let token_hash = hash_token(req.login_token.as_bytes()).to_vec();
    let mut tx = st.pool.begin().await?;
    let row = sqlx::query(
        "SELECT user_id, expires_at, failed_attempts FROM pending_logins \
         WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;
    let user_id: Uuid = row.get("user_id");
    let expires_at: DateTime<Utc> = row.get("expires_at");
    let attempts: i32 = row.get("failed_attempts");
    if expires_at < Utc::now() || attempts >= MAX_2FA_ATTEMPTS {
        consume_login_token(&mut tx, &token_hash).await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized);
    }

    let astate =
        sqlx::query("SELECT state FROM webauthn_auth_states WHERE token_hash = $1 FOR UPDATE")
            .bind(&token_hash)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::BadRequest(
                "no passkey authentication in progress",
            ))?;
    let state_bytes: Vec<u8> = astate.get("state");
    let auth_state: PasskeyAuthentication =
        serde_json::from_slice(&state_bytes).map_err(|_| AppError::Internal)?;

    let auth_result = match st
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "passkey auth finish failed");
            // 失敗回数を加算 (TOTP と同様)。auth_state は残し再試行を許す。
            sqlx::query(
                "UPDATE pending_logins SET failed_attempts = failed_attempts + 1 \
                 WHERE token_hash = $1",
            )
            .bind(&token_hash)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(AppError::Unauthorized);
        }
    };

    // 認証された credential を cred_id (UNIQUE) で 1 行に絞って更新する。start_passkey_authentication
    // でこのユーザーの passkey 群を allowCredentials に渡しているため、該当行は必ず存在する。
    let cred_id = auth_result.cred_id().as_ref().to_vec();
    if auth_result.needs_update() {
        // counter を前進 (sign_count 後退は上の finish が Err にするためここは前進のみ)。
        let row = sqlx::query(
            "SELECT public_key FROM webauthn_credentials \
             WHERE user_id = $1 AND cred_id = $2 FOR UPDATE",
        )
        .bind(user_id)
        .bind(&cred_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(r) = row {
            let bytes: Vec<u8> = r.get("public_key");
            let mut pk: Passkey = serde_json::from_slice(&bytes).map_err(|_| AppError::Internal)?;
            pk.update_credential(&auth_result);
            let updated = serde_json::to_vec(&pk).map_err(|_| AppError::Internal)?;
            sqlx::query(
                "UPDATE webauthn_credentials \
                 SET public_key = $3, sign_count = $4, last_used_at = now() \
                 WHERE user_id = $1 AND cred_id = $2",
            )
            .bind(user_id)
            .bind(&cred_id)
            .bind(updated)
            .bind(i64::from(auth_result.counter()))
            .execute(&mut *tx)
            .await?;
        }
    } else {
        sqlx::query(
            "UPDATE webauthn_credentials SET last_used_at = now() \
             WHERE user_id = $1 AND cred_id = $2",
        )
        .bind(user_id)
        .bind(&cred_id)
        .execute(&mut *tx)
        .await?;
    }

    // login_token + auth_state を消費し、2FA 通過後のセッション + blob を発行する。
    consume_login_token(&mut tx, &token_hash).await?;
    let resp = issue_session(&mut tx, user_id).await?;
    tx.commit().await?;
    Ok(Json(resp))
}
