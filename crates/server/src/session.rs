//! セッション認証エクストラクタ。`Authorization: Bearer <session_token>` を検証する。

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use iikanji_crypto::hash_token;
use sqlx::Row;
use uuid::Uuid;

use crate::error::AppError;
use crate::AppState;

/// 認証済みユーザー。ハンドラ引数に置くとセッション検証が走る。
pub struct AuthUser(pub Uuid);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or(AppError::Unauthorized)?;

        let row = sqlx::query(
            "SELECT user_id FROM sessions WHERE token_hash = $1 AND expires_at > now()",
        )
        .bind(hash_token(token.as_bytes()).to_vec())
        .fetch_optional(&state.pool)
        .await?;

        let user_id: Uuid = row.ok_or(AppError::Unauthorized)?.get("user_id");
        Ok(AuthUser(user_id))
    }
}
