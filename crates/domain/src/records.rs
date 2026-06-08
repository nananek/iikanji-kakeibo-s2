//! レコード平文 DTO の CBOR (版管理) コーデック。`enc_records.ciphertext` の中身は
//! `Record` を CBOR 符号化したもの。`record_type`(SMALLINT) と payload variant を対応させる。
//!
//! `serde` feature 有効時のみ含まれる (client/server 連携)。サーバーはこれを復号しない。

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
}

/// レコード本体 (型別)。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordPayload {
    JournalEntry(JournalEntry),
    Account(AccountInfo),
    FiscalClose(FiscalClose),
    Medical(MedicalExpense),
}

impl RecordPayload {
    /// 対応する `record_type`。
    pub fn record_type(&self) -> u16 {
        match self {
            RecordPayload::JournalEntry(_) => record_type::JOURNAL_ENTRY,
            RecordPayload::Account(_) => record_type::ACCOUNT,
            RecordPayload::FiscalClose(_) => record_type::FISCAL_CLOSE,
            RecordPayload::Medical(_) => record_type::MEDICAL,
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
}

/// レコードを CBOR バイト列へ符号化する (暗号化前の平文)。
pub fn encode(record: &Record) -> Result<Vec<u8>, RecordError> {
    let mut buf = Vec::new();
    ciborium::into_writer(record, &mut buf).map_err(|_| RecordError::Encode)?;
    Ok(buf)
}

/// CBOR バイト列をレコードへ復号する。
pub fn decode(bytes: &[u8]) -> Result<Record, RecordError> {
    ciborium::from_reader(bytes).map_err(|_| RecordError::Decode)
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
    fn decode_garbage_errors() {
        assert_eq!(decode(&[0xff, 0xff, 0x01, 0x02]), Err(RecordError::Decode));
    }
}
