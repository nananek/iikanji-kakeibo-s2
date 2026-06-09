//! 証憑(添付)バイナリのアップロード/ダウンロード/削除。
//!
//! サーバーは**クライアントが暗号化済みの不透明 blob のみ**を S3 互換ストレージへ中継保存し、復号しない
//! (CLAUDE.md E2EE 不変条件)。オブジェクトキーは `"{user_id}/{attachment_id}"` で、ユーザー prefix により
//! 所有権が構造的に分離される (認証ユーザーの id からキーを組み立てるため、他人の blob には到達できない)。
//! メタ行 (`enc_attachments`) は存在確認・サイズ・GC 用で、財務平文は持たない。

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use object_store::path::Path as StorePath;
use object_store::{Error as StoreError, ObjectStoreExt, PutPayload};
use uuid::Uuid;

use crate::error::AppError;
use crate::session::AuthUser;
use crate::AppState;

/// ct_size のバケット幅 (sync と同様、漏洩緩和)。
const SIZE_BUCKET: usize = 256;

fn bucketed_ct_size(n: usize) -> i32 {
    let bucketed = n.div_ceil(SIZE_BUCKET).saturating_mul(SIZE_BUCKET);
    bucketed.min(i32::MAX as usize) as i32
}

/// 認証ユーザーの id から blob のオブジェクトキーを組み立てる (所有権を prefix で固定)。
fn object_key(user_id: Uuid, attachment_id: Uuid) -> StorePath {
    StorePath::from(format!("{user_id}/{attachment_id}"))
}

/// `PUT /attachments/{id}` — 暗号 blob を保存する (octet-stream)。サイズ上限超過は 413
/// (ルートの `DefaultBodyLimit` でも弾かれるが、明示チェックも行う)。
pub async fn put(
    State(st): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(attachment_id): Path<Uuid>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    if body.len() > st.max_attachment_bytes {
        return Err(AppError::PayloadTooLarge);
    }
    let ct_size = bucketed_ct_size(body.len());
    st.store
        .put(&object_key(user_id, attachment_id), PutPayload::from(body))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "attachment store put failed");
            AppError::Internal
        })?;
    sqlx::query(
        "INSERT INTO enc_attachments (user_id, attachment_id, ct_size) VALUES ($1, $2, $3) \
         ON CONFLICT (user_id, attachment_id) DO UPDATE SET ct_size = EXCLUDED.ct_size",
    )
    .bind(user_id)
    .bind(attachment_id)
    .bind(ct_size)
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::OK)
}

/// `GET /attachments/{id}` — 暗号 blob を返す (octet-stream)。当該ユーザーの行が無ければ 404。
pub async fn get(
    State(st): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(attachment_id): Path<Uuid>,
) -> Result<Bytes, AppError> {
    let exists: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM enc_attachments WHERE user_id = $1 AND attachment_id = $2",
    )
    .bind(user_id)
    .bind(attachment_id)
    .fetch_optional(&st.pool)
    .await?;
    if exists.is_none() {
        return Err(AppError::NotFound);
    }
    let res = st
        .store
        .get(&object_key(user_id, attachment_id))
        .await
        .map_err(|e| match e {
            StoreError::NotFound { .. } => AppError::NotFound,
            other => {
                tracing::error!(error = %other, "attachment store get failed");
                AppError::Internal
            }
        })?;
    let bytes = res.bytes().await.map_err(|e| {
        tracing::error!(error = %e, "attachment store read failed");
        AppError::Internal
    })?;
    Ok(bytes)
}

/// `DELETE /attachments/{id}` — メタ行と blob を削除する (証憑削除/tombstone 時に client が呼ぶ)。
/// 既に無い blob は無視 (冪等)。
pub async fn delete(
    State(st): State<AppState>,
    AuthUser(user_id): AuthUser,
    Path(attachment_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    sqlx::query("DELETE FROM enc_attachments WHERE user_id = $1 AND attachment_id = $2")
        .bind(user_id)
        .bind(attachment_id)
        .execute(&st.pool)
        .await?;
    match st.store.delete(&object_key(user_id, attachment_id)).await {
        Ok(()) | Err(StoreError::NotFound { .. }) => {}
        Err(e) => {
            tracing::error!(error = %e, "attachment store delete failed");
            return Err(AppError::Internal);
        }
    }
    Ok(StatusCode::NO_CONTENT)
}
