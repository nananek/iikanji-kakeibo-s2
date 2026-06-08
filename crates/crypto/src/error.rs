use thiserror::Error;

/// `iikanji-crypto` のエラー。エラーメッセージに鍵・平文を含めないこと。
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD のタグ検証失敗、または文脈 (AAD) 不一致。blob すり替えもここで検出される。
    #[error("AEAD open failed (authentication tag mismatch or wrong context)")]
    AeadOpen,
    /// Envelope のパース失敗 (magic/version/alg 不正、長さ不足など)。
    #[error("invalid envelope: {0}")]
    Envelope(&'static str),
    /// 鍵導出 (Argon2id/HKDF) の失敗。
    #[error("key derivation failed: {0}")]
    Kdf(&'static str),
    /// リカバリコードの形式・チェックサム不正。
    #[error("invalid recovery code: {0}")]
    Recovery(&'static str),
    /// サーバー側 auth ハッシュの生成・検証エラー。
    #[error("auth hash error: {0}")]
    Auth(&'static str),
    /// TOTP の生成・検証エラー。
    #[error("totp error: {0}")]
    Totp(&'static str),
}

pub type Result<T> = core::result::Result<T, CryptoError>;
