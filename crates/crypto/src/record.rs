//! 財務レコードの暗号化。DK で封緘し、AAD に `(record_type, record_id, version)` を束縛する。
//! これにより別レコード/別バージョンの ciphertext すり替えが復号時に検出される。

use crate::envelope::{self, context};
use crate::error::Result;
use crate::keys::DataKey;

/// レコード平文を DK で暗号化し Envelope バイト列を返す。
pub fn encrypt_record(
    dk: &DataKey,
    record_type: u16,
    record_id: &[u8; 16],
    version: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    envelope::seal(
        dk.as_bytes(),
        0,
        &context::record(record_type, record_id, version),
        plaintext,
    )
}

/// レコード Envelope を復号する。文脈不一致/改竄は [`crate::CryptoError::AeadOpen`]。
pub fn decrypt_record(
    dk: &DataKey,
    record_type: u16,
    record_id: &[u8; 16],
    version: u64,
    blob: &[u8],
) -> Result<Vec<u8>> {
    envelope::open(
        dk.as_bytes(),
        &context::record(record_type, record_id, version),
        blob,
    )
}
