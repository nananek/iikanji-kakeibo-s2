//! レコード平文 DTO の CBOR (版管理) コーデック。`enc_records.ciphertext` の中身は
//! `Record` を CBOR 符号化したもの。`record_type`(SMALLINT) と payload variant を対応させる。
//!
//! `serde` feature 有効時のみ含まれる (client/server 連携)。サーバーはこれを復号しない。

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::chart::AccountInfo;
use crate::fiscal::FiscalClose;
use crate::journal::JournalEntry;
use crate::medical::MedicalExpense;

/// レコード平文のスキーマ版 (前方互換のため内部 `v` に持つ)。
pub const RECORD_SCHEMA_VERSION: u16 = 1;

/// `record_type` (enc_records.record_type) の値。
pub mod record_type {
    pub const JOURNAL_ENTRY: u16 = 1;
    pub const ACCOUNT: u16 = 2;
    pub const FISCAL_CLOSE: u16 = 3;
    pub const MEDICAL: u16 = 4;
    pub const VOUCHER_META: u16 = 5;
}

/// 証憑(添付)のメタデータ。暗号バイナリ本体は別ストア (chunked AEAD blob)、本型は仕訳との紐付けや
/// ファイル名等を持ち、他のレコードと同様 DK で暗号化されて同期される。**サーバーには平文で出ない**。
///
/// `attachment_id` / `linked_entry_id` は UUID を生バイト (`Uuid::into_bytes`) で持つ。domain を外部依存
/// ゼロに保つため `uuid` 型は使わない (client が変換する)。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoucherMeta {
    /// 添付バイナリの ID (ストレージのオブジェクトキー / `enc_attachments.attachment_id`)。
    pub attachment_id: [u8; 16],
    /// 紐付く仕訳レコードの record_id (この型ごと暗号化されるためサーバーには出ない)。
    pub linked_entry_id: [u8; 16],
    /// 元ファイル名 (ユーザー表示用)。
    pub filename: String,
    /// MIME タイプ (例 "image/jpeg")。
    pub mime: String,
    /// 平文の真サイズ (bytes)。chunked blob はゼロ詰めされるため open 後にこの値で切り詰める。
    pub size: u64,
    /// 平文の SHA-256 (ダウンロード後の整合性確認用)。
    pub content_hash: [u8; 32],
    /// 暗号化時のチャンク平文長 (bytes)。前方互換のため記録。
    pub chunk_size: u32,
}

/// レコード本体 (型別)。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordPayload {
    JournalEntry(JournalEntry),
    Account(AccountInfo),
    FiscalClose(FiscalClose),
    Medical(MedicalExpense),
    VoucherMeta(VoucherMeta),
}

impl RecordPayload {
    /// 対応する `record_type`。
    pub fn record_type(&self) -> u16 {
        match self {
            RecordPayload::JournalEntry(_) => record_type::JOURNAL_ENTRY,
            RecordPayload::Account(_) => record_type::ACCOUNT,
            RecordPayload::FiscalClose(_) => record_type::FISCAL_CLOSE,
            RecordPayload::Medical(_) => record_type::MEDICAL,
            RecordPayload::VoucherMeta(_) => record_type::VOUCHER_META,
        }
    }
}

/// 版管理されたレコード平文。`v` で前方互換、`payload` が本体。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub v: u16,
    pub payload: RecordPayload,
}

impl Record {
    /// 現行版でレコードを作る。
    pub fn new(payload: RecordPayload) -> Self {
        Self {
            v: RECORD_SCHEMA_VERSION,
            payload,
        }
    }
    pub fn record_type(&self) -> u16 {
        self.payload.record_type()
    }
}

/// CBOR コーデックのエラー。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    Encode,
    Decode,
    /// 既知より新しいスキーマ版 (このクライアントでは解釈不可)。
    UnsupportedVersion,
}

/// レコードを CBOR バイト列へ符号化する (暗号化前の平文)。
pub fn encode(record: &Record) -> Result<Vec<u8>, RecordError> {
    let mut buf = Vec::new();
    ciborium::into_writer(record, &mut buf).map_err(|_| RecordError::Encode)?;
    Ok(buf)
}

/// CBOR バイト列をレコードへ復号する。既知より新しい `v` は `UnsupportedVersion`。
pub fn decode(bytes: &[u8]) -> Result<Record, RecordError> {
    let record: Record = ciborium::from_reader(bytes).map_err(|_| RecordError::Decode)?;
    if record.v > RECORD_SCHEMA_VERSION {
        return Err(RecordError::UnsupportedVersion);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chart::Chart;
    use crate::{AccountCode, Date, EntryLine, Yen};

    #[test]
    fn journal_record_roundtrip() {
        let entry = JournalEntry {
            date: Date::new(2026, 6, 8).unwrap(),
            description: "昼食".into(),
            lines: vec![
                EntryLine::debit(AccountCode::from("5010"), Yen::new(1000)),
                EntryLine::credit(AccountCode::from("1010"), Yen::new(1000)),
            ],
        };
        let rec = Record::new(RecordPayload::JournalEntry(entry.clone()));
        assert_eq!(rec.record_type(), record_type::JOURNAL_ENTRY);
        assert_eq!(rec.v, RECORD_SCHEMA_VERSION);

        let bytes = encode(&rec).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back, rec);
        match back.payload {
            RecordPayload::JournalEntry(e) => assert_eq!(e, entry),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn all_record_types_roundtrip() {
        let account = Chart::standard()
            .get(&AccountCode::from("1010"))
            .unwrap()
            .clone();
        let medical = MedicalExpense {
            date: Date::new(2026, 1, 1).unwrap(),
            patient: "A".into(),
            hospital: "H".into(),
            treatment: "診察".into(),
            paid: Yen::new(5000),
            reimbursement: Yen::new(1000),
        };
        let records = [
            Record::new(RecordPayload::Account(account)),
            Record::new(RecordPayload::FiscalClose(FiscalClose::new(2026))),
            Record::new(RecordPayload::Medical(medical)),
        ];
        let expected_types = [
            record_type::ACCOUNT,
            record_type::FISCAL_CLOSE,
            record_type::MEDICAL,
        ];
        for (rec, ty) in records.iter().zip(expected_types) {
            assert_eq!(rec.record_type(), ty);
            let bytes = encode(rec).unwrap();
            assert_eq!(&decode(&bytes).unwrap(), rec);
        }
    }

    #[test]
    fn voucher_meta_roundtrip() {
        let meta = VoucherMeta {
            attachment_id: [1u8; 16],
            linked_entry_id: [2u8; 16],
            filename: "領収書.pdf".into(),
            mime: "application/pdf".into(),
            size: 123_456,
            content_hash: [9u8; 32],
            chunk_size: 65536,
        };
        let rec = Record::new(RecordPayload::VoucherMeta(meta.clone()));
        assert_eq!(rec.record_type(), record_type::VOUCHER_META);
        let bytes = encode(&rec).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back, rec);
        match back.payload {
            RecordPayload::VoucherMeta(m) => assert_eq!(m, meta),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn decode_garbage_errors() {
        assert_eq!(decode(&[0xff, 0xff, 0x01, 0x02]), Err(RecordError::Decode));
    }

    #[test]
    fn decode_rejects_future_version() {
        // 将来版 (v=2) のレコードを符号化 → 既知 (v=1) クライアントは UnsupportedVersion。
        let future = Record {
            v: RECORD_SCHEMA_VERSION + 1,
            payload: RecordPayload::FiscalClose(FiscalClose::new(2026)),
        };
        let bytes = encode(&future).unwrap();
        assert_eq!(decode(&bytes), Err(RecordError::UnsupportedVersion));
    }
}
