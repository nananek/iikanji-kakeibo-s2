//! `iikanji-crypto` — E2EE の鍵階層・AEAD Envelope・リカバリコードのコア暗号 crate。
//!
//! 鍵ツリー (詳細は repo の `CLAUDE.md`「E2EE invariants」):
//! ```text
//! password ─Argon2id(salt)─► PMK
//!    ├─ HKDF "auth" ─► authKey  (login 証明として送信)
//!    └─ HKDF "wrap" ─► wrapKey  (非送出; MK をアンラップ)
//! MK (乱数) ── wraps ──► DK (乱数) ── encrypts ──► records/attachments
//! ```
//! 不変条件: MK/DK/wrapKey/recovery code はネットワークへ出さない。サーバーはレコードを復号しない。
//! passkey/TOTP はこの crate の責務外 (復号鍵ではない)。

#![forbid(unsafe_code)]

mod attachment;
mod auth;
mod envelope;
mod error;
mod kdf;
mod keys;
mod record;
mod recovery;
mod server;
mod totp;
mod wrap;

#[cfg(test)]
mod tests;

pub use attachment::{open_attachment, seal_attachment, ATTACHMENT_CHUNK_LEN};
pub use auth::{hash_auth_key, verify_auth_key};
pub use error::{CryptoError, Result};
pub use kdf::{argon2_hash, derive_pmk, generate_salt, pmk_from_hash, KdfParams, SALT_LEN};
pub use keys::{AuthKey, DataKey, MasterKey, Pmk, RecoveryKey, WrapKey};
pub use record::{decrypt_record, encrypt_record};
pub use recovery::RecoveryCode;
pub use server::{
    derive_server_key, gen_opaque_token, hash_token, open_at_rest, seal_at_rest, server_dummy_salt,
};
pub use totp::TotpSecret;
pub use wrap::{
    unwrap_data_key, unwrap_master_key_with_password, unwrap_master_key_with_recovery,
    wrap_data_key, wrap_master_key_with_password, wrap_master_key_with_recovery,
};

/// OS CSPRNG から `N` バイトを得る。鍵・nonce・salt は必ずこれ経由で生成する。
pub(crate) fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable");
    buf
}

/// データの SHA-256。添付ファイルの content hash (整合性確認) 等に使う汎用ハッシュ。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
