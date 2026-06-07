//! サーバー側の login 証明検証 (Bitwarden 方式)。
//!
//! クライアントは `authKey` (= HKDF(PMK)) を送る。サーバーは `Argon2id(authKey, salt_srv)`
//! の PHC 文字列を保存し、login 時に定数時間検証する。authKey は wrapKey/MK と独立なので、
//! DB 漏洩で authKey ハッシュを得ても、平文パスワードを得るには高コストな client Argon2id を
//! 総当りする必要があり、データ復号には到達できない。

use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Algorithm, Argon2, PasswordHasher, PasswordVerifier, Version};

use crate::error::{CryptoError, Result};
use crate::kdf::KdfParams;
use crate::keys::AuthKey;

/// `authKey` を `params` (推奨 [`KdfParams::SERVER_V1`]) でハッシュし、保存用 PHC 文字列を返す。
pub fn hash_auth_key(auth_key: &AuthKey, params: KdfParams) -> Result<String> {
    let salt_bytes = crate::random_array::<16>();
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| CryptoError::Auth("salt encode"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_argon2()?);
    let hash = argon
        .hash_password(auth_key.as_bytes(), salt.as_salt())
        .map_err(|_| CryptoError::Auth("hash"))?;
    Ok(hash.to_string())
}

/// 保存済み PHC 文字列に対して `authKey` を定数時間検証する。
pub fn verify_auth_key(auth_key: &AuthKey, phc: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc).map_err(|_| CryptoError::Auth("parse phc"))?;
    Ok(Argon2::default()
        .verify_password(auth_key.as_bytes(), &parsed)
        .is_ok())
}
