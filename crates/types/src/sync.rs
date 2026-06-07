//! 同期 push/pull の DTO。財務データは `ciphertext` (Envelope バイト列) としてのみ運ぶ。
//! サーバーは内容を復号せず、`version`(CAS) / `seq`(per-user カーソル) / `tombstone` のみ扱う。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// サーバーが保持/返却する 1 レコード (不透明 blob)。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct EncRecord {
    pub record_id: Uuid,
    pub record_type: u16,
    pub version: u32,
    pub seq: u64,
    pub tombstone: bool,
    /// tombstone のときは `None`。
    #[serde(with = "crate::b64_opt", default)]
    pub ciphertext: Option<Vec<u8>>,
}

/// クライアントからの 1 変更 (CAS push)。新規は `expected_version = 0`。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PushChange {
    pub record_id: Uuid,
    pub record_type: u16,
    pub expected_version: u32,
    pub tombstone: bool,
    #[serde(with = "crate::b64_opt", default)]
    pub ciphertext: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PushRequest {
    pub changes: Vec<PushChange>,
}

/// CAS の結果。
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PushStatus {
    /// 適用された。
    Applied,
    /// version 不一致で衝突 (`server_record` に現行を返す)。
    Conflict,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PushResult {
    pub record_id: Uuid,
    pub status: PushStatus,
    pub new_version: u32,
    pub seq: u64,
    /// 衝突時の現行レコード。
    pub server_record: Option<EncRecord>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PushResponse {
    pub results: Vec<PushResult>,
    pub new_cursor: u64,
}

/// `GET /sync/pull?since=<cursor>` の応答 (seq 昇順)。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PullResponse {
    pub records: Vec<EncRecord>,
    pub next_cursor: u64,
    pub has_more: bool,
}
