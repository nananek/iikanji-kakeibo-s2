//! 認証ハンドラ (Bitwarden 方式 + TOTP)。signup → totp/confirm → login(begin/verify)。
//!
//! 不変条件: サーバーはパスワードを学習しない (受け取るのは authKey のみ)。TOTP 秘密は
//! at-rest 暗号して保持し、復号鍵としては使わない。ラップ blob は 2FA 通過後に返す (後続 PR)。

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::{Duration, Utc};
use iikanji_crypto::{
    gen_opaque_token, hash_auth_key, hash_token, open_at_rest, seal_at_rest, server_dummy_salt,
    verify_auth_key, AuthKey, KdfParams, TotpSecret,
};
use iikanji_types::{
    Factor, LoginBeginRequest, LoginBeginResponse, LoginVerifyRequest, LoginVerifyResponse,
    SignupRequest, SignupResponse, TotpConfirmRequest,
};
use sqlx::Row;
use uuid::Uuid;

use crate::error::AppError;
use crate::AppState;

const TOTP_ISSUER: &str = "いいかんじ家計簿";
/// TOTP confirm の失敗許容回数。超えるとアカウント単位でロック (ブルートフォース緩和)。
const MAX_TOTP_CONFIRM_ATTEMPTS: i32 = 10;

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

    // 2FA-pending トークンを発行 (OsRng 由来・ハッシュのみ保存)。blob は 2FA 通過後 (後続 PR)。
    let token = gen_opaque_token();
    let expires = Utc::now() + Duration::minutes(5);
    sqlx::query("INSERT INTO pending_logins (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash_token(token.as_bytes()).to_vec())
        .bind(user_id)
        .bind(expires)
        .execute(&st.pool)
        .await?;

    Ok(Json(LoginVerifyResponse {
        login_token: token,
        factors: vec![Factor::Totp],
    }))
}
