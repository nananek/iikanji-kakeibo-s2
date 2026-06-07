//! 認証ハンドラ (Bitwarden 方式)。signup と login(begin/verify)。
//!
//! 不変条件: サーバーはパスワードを学習しない (受け取るのは authKey のみ)。ラップ blob は
//! signup 時に保存し、2FA 通過後にのみ返す (本 PR では login_verify までで、blob 返却は後続)。

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::{Duration, Utc};
use iikanji_crypto::{hash_auth_key, verify_auth_key, AuthKey, KdfParams};
use iikanji_types::{
    Factor, LoginBeginRequest, LoginBeginResponse, LoginVerifyRequest, LoginVerifyResponse,
    SignupRequest,
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::error::AppError;
use crate::AppState;

fn auth_key_from(bytes: &[u8]) -> Result<AuthKey, AppError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("auth_key must be 32 bytes"))?;
    Ok(AuthKey::from_wire_bytes(arr))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// email から決定的なダミー salt を導出する (未知ユーザーの enumeration 対策)。
fn dummy_salt(secret: &[u8], email: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(b"|salt-v1|");
    h.update(email.as_bytes());
    h.finalize()[..16].to_vec()
}

pub async fn health() -> &'static str {
    "ok"
}

pub async fn signup(
    State(st): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Result<StatusCode, AppError> {
    if req.email.trim().is_empty() {
        return Err(AppError::BadRequest("email required"));
    }
    let auth_key = auth_key_from(&req.auth_key)?;
    let auth_hash = hash_auth_key(&auth_key, KdfParams::SERVER_V1)?;

    let mut tx = st.pool.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO users (email, salt_pw, kdf_version, auth_hash) \
         VALUES ($1, $2, $3, $4) RETURNING id",
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
    tx.commit().await?;
    Ok(StatusCode::CREATED)
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
            salt_pw: dummy_salt(&st.server_secret, &req.email),
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
    let row = sqlx::query("SELECT id, auth_hash FROM users WHERE email = $1")
        .bind(&req.email)
        .fetch_optional(&st.pool)
        .await?;

    let user_id = match row {
        Some(r) => {
            let hash: String = r.get("auth_hash");
            if verify_auth_key(&auth_key, &hash).unwrap_or(false) {
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

    // 2FA-pending トークンを発行 (ハッシュのみ保存)。blob は 2FA 通過後 (後続 PR)。
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let expires = Utc::now() + Duration::minutes(5);
    sqlx::query("INSERT INTO pending_logins (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(sha256(token.as_bytes()))
        .bind(user_id)
        .bind(expires)
        .execute(&st.pool)
        .await?;

    Ok(Json(LoginVerifyResponse {
        login_token: token,
        factors: vec![Factor::Totp],
    }))
}
