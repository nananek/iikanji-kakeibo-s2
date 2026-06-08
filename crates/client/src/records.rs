//! レコード ↔ ciphertext のブリッジ。Record を CBOR 化して DK で暗号化/復号する。
//! AAD は crypto 側で (record_type, record_id, version) に束縛されるため、メタ取り違えは復号失敗。

use iikanji_crypto::{decrypt_record, encrypt_record, CryptoError, DataKey};
use iikanji_domain::{decode, encode, Record, RecordError};
use uuid::Uuid;

/// ブリッジのエラー (CBOR / AEAD)。
#[derive(Debug)]
pub enum RecordCryptoError {
    Cbor(RecordError),
    Crypto(CryptoError),
}

/// Record を CBOR → DK で暗号化し ciphertext を返す (push 用)。
pub fn seal_record(
    dk: &DataKey,
    record_id: Uuid,
    version: u32,
    record: &Record,
) -> Result<Vec<u8>, RecordCryptoError> {
    let cbor = encode(record).map_err(RecordCryptoError::Cbor)?;
    Ok(encrypt_record(
        dk,
        record.record_type(),
        record_id.as_bytes(),
        u64::from(version),
        &cbor,
    ))
}

/// ciphertext を DK で復号 → CBOR デコードして Record を返す (pull 用)。
/// `record_type` / `record_id` / `version` は EncRecord のメタから渡す。
pub fn open_record(
    dk: &DataKey,
    record_id: Uuid,
    version: u32,
    record_type: u16,
    ciphertext: &[u8],
) -> Result<Record, RecordCryptoError> {
    let cbor = decrypt_record(
        dk,
        record_type,
        record_id.as_bytes(),
        u64::from(version),
        ciphertext,
    )
    .map_err(RecordCryptoError::Crypto)?;
    decode(&cbor).map_err(RecordCryptoError::Cbor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iikanji_domain::{FiscalClose, RecordPayload};

    #[test]
    fn seal_open_roundtrip_and_context_binding() {
        let dk = DataKey::generate();
        let id = Uuid::from_u128(7);
        let rec = Record::new(RecordPayload::FiscalClose(FiscalClose::new(2026)));

        let ct = seal_record(&dk, id, 1, &rec).unwrap();
        assert_eq!(
            open_record(&dk, id, 1, rec.record_type(), &ct).unwrap(),
            rec
        );

        // メタ取り違え (version / type / id) は AEAD 復号失敗。
        assert!(open_record(&dk, id, 2, rec.record_type(), &ct).is_err());
        assert!(open_record(&dk, id, 1, 99, &ct).is_err());
        assert!(open_record(&dk, Uuid::from_u128(8), 1, rec.record_type(), &ct).is_err());
        // 別 DK でも開けない。
        assert!(open_record(&DataKey::generate(), id, 1, rec.record_type(), &ct).is_err());
    }
}
