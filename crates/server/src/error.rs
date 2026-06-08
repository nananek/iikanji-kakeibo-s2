//! HTTP エラー。内部詳細・機密はレスポンスに出さず、ログにのみ残す。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, *m),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, *m),
            AppError::Conflict(m) => (StatusCode::CONFLICT, *m),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        // sqlx エラーに財務 ciphertext は含まれない。クエリ/接続エラーのみ。
        tracing::error!(error = %e, "database error");
        AppError::Internal
    }
}

impl From<iikanji_crypto::CryptoError> for AppError {
    fn from(e: iikanji_crypto::CryptoError) -> Self {
        tracing::error!(error = %e, "crypto error");
        AppError::Internal
    }
}
