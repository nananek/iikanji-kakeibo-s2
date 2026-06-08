//! 同期エンドポイント。サーバーは ciphertext を**復号しない**。
//! push は per-record `version`(CAS) + per-user `seq`(user_seq) で楽観排他。pull は cursor 増分。

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use sqlx::postgres::PgRow;
use sqlx::Row;
use uuid::Uuid;

use iikanji_types::{
    CursorResponse, EncRecord, PullResponse, PushRequest, PushResponse, PushResult, PushStatus,
};

use crate::error::AppError;
use crate::session::AuthUser;
use crate::AppState;

const DEFAULT_PULL_LIMIT: i64 = 500;
const MAX_PULL_LIMIT: i64 = 1000;

fn row_to_record(row: &PgRow) -> EncRecord {
    EncRecord {
        record_id: row.get("record_id"),
        record_type: row.get::<i16, _>("record_type") as u16,
        version: row.get::<i32, _>("version") as u32,
        seq: row.get::<i64, _>("seq") as u64,
        tombstone: row.get("tombstone"),
        ciphertext: row.get::<Option<Vec<u8>>, _>("ciphertext"),
    }
}

/// push: 各変更を CAS で適用する。新規は `expected_version=0`、更新は現行 version と一致が条件。
pub async fn push(
    State(st): State<AppState>,
    user: AuthUser,
    Json(req): Json<PushRequest>,
) -> Result<Json<PushResponse>, AppError> {
    let user_id = user.0;
    let mut tx = st.pool.begin().await?;
    let mut results = Vec::with_capacity(req.changes.len());

    for change in req.changes {
        if !change.tombstone && change.ciphertext.is_none() {
            return Err(AppError::BadRequest(
                "non-tombstone change requires ciphertext",
            ));
        }
        let ct_size = change
            .ciphertext
            .as_ref()
            .map(|c| c.len() as i32)
            .unwrap_or(0);

        // 対象行をロックして現状を確認 (seq の無駄消費を避けるため CAS 判定を先に行う)。
        let current = sqlx::query(
            "SELECT record_id, record_type, version, seq, tombstone, ciphertext \
             FROM enc_records WHERE user_id = $1 AND record_id = $2 FOR UPDATE",
        )
        .bind(user_id)
        .bind(change.record_id)
        .fetch_optional(&mut *tx)
        .await?;

        match current {
            None => {
                if change.expected_version != 0 {
                    // クライアントは存在を期待したが無い (削除/GC 済み) → 衝突。
                    results.push(conflict(change.record_id, 0, 0, None));
                    continue;
                }
                let seq = alloc_seq(&mut tx, user_id).await?;
                sqlx::query(
                    "INSERT INTO enc_records \
                     (user_id, record_id, record_type, version, seq, tombstone, ciphertext, ct_size) \
                     VALUES ($1, $2, $3, 1, $4, $5, $6, $7)",
                )
                .bind(user_id)
                .bind(change.record_id)
                .bind(change.record_type as i16)
                .bind(seq)
                .bind(change.tombstone)
                .bind(change.ciphertext.as_deref())
                .bind(ct_size)
                .execute(&mut *tx)
                .await?;
                results.push(applied(change.record_id, 1, seq as u64));
            }
            Some(row) => {
                let cur_version = row.get::<i32, _>("version") as u32;
                if cur_version != change.expected_version {
                    let seq = row.get::<i64, _>("seq") as u64;
                    results.push(conflict(
                        change.record_id,
                        cur_version,
                        seq,
                        Some(row_to_record(&row)),
                    ));
                    continue;
                }
                let seq = alloc_seq(&mut tx, user_id).await?;
                let new_version = change.expected_version + 1;
                sqlx::query(
                    "UPDATE enc_records \
                     SET record_type = $3, version = $4, seq = $5, tombstone = $6, \
                         ciphertext = $7, ct_size = $8, updated_at = now() \
                     WHERE user_id = $1 AND record_id = $2",
                )
                .bind(user_id)
                .bind(change.record_id)
                .bind(change.record_type as i16)
                .bind(new_version as i32)
                .bind(seq)
                .bind(change.tombstone)
                .bind(change.ciphertext.as_deref())
                .bind(ct_size)
                .execute(&mut *tx)
                .await?;
                results.push(applied(change.record_id, new_version, seq as u64));
            }
        }
    }

    let new_cursor = current_cursor(&mut tx, user_id).await?;
    tx.commit().await?;
    Ok(Json(PushResponse {
        results,
        new_cursor,
    }))
}

#[derive(Deserialize)]
pub struct PullQuery {
    since: Option<i64>,
    limit: Option<i64>,
}

/// pull: `since` より大きい seq のレコードを昇順で返す (incremental)。
pub async fn pull(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<PullQuery>,
) -> Result<Json<PullResponse>, AppError> {
    let since = q.since.unwrap_or(0);
    let limit = q
        .limit
        .unwrap_or(DEFAULT_PULL_LIMIT)
        .clamp(1, MAX_PULL_LIMIT);

    let rows = sqlx::query(
        "SELECT record_id, record_type, version, seq, tombstone, ciphertext \
         FROM enc_records WHERE user_id = $1 AND seq > $2 ORDER BY seq ASC LIMIT $3",
    )
    .bind(user.0)
    .bind(since)
    .bind(limit + 1)
    .fetch_all(&st.pool)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let records: Vec<EncRecord> = rows
        .iter()
        .take(limit as usize)
        .map(row_to_record)
        .collect();
    let next_cursor = records.last().map(|r| r.seq).unwrap_or(since.max(0) as u64);
    Ok(Json(PullResponse {
        records,
        next_cursor,
        has_more,
    }))
}

/// cursor: per-user の現在カーソル (= 最新 seq)。
pub async fn cursor(
    State(st): State<AppState>,
    user: AuthUser,
) -> Result<Json<CursorResponse>, AppError> {
    let mut tx = st.pool.begin().await?;
    let cursor = current_cursor(&mut tx, user.0).await?;
    tx.commit().await?;
    Ok(Json(CursorResponse { cursor }))
}

/// per-user 単調 seq を 1 つ確保して返す (`user_seq.next_seq` をアトミックに前進)。
async fn alloc_seq(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<i64, AppError> {
    let seq: i64 = sqlx::query_scalar(
        "UPDATE user_seq SET next_seq = next_seq + 1 WHERE user_id = $1 RETURNING next_seq - 1",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(seq)
}

async fn current_cursor(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<u64, AppError> {
    let cursor: i64 = sqlx::query_scalar("SELECT next_seq - 1 FROM user_seq WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await?;
    Ok(cursor as u64)
}

fn applied(record_id: Uuid, new_version: u32, seq: u64) -> PushResult {
    PushResult {
        record_id,
        status: PushStatus::Applied,
        new_version,
        seq,
        server_record: None,
    }
}

fn conflict(
    record_id: Uuid,
    new_version: u32,
    seq: u64,
    server_record: Option<EncRecord>,
) -> PushResult {
    PushResult {
        record_id,
        status: PushStatus::Conflict,
        new_version,
        seq,
        server_record,
    }
}
