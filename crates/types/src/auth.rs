//! 認証 ceremony の DTO (Bitwarden 方式)。
//!
//! 不変条件 (CLAUDE.md): サーバーへ送るパスワード由来の値は `auth_key` のみ。MK/DK/wrapKey/
//! recovery code は送らない。ラップ blob (`KeyBlobs`) は ciphertext であり、2FA 通過後にのみ
//! クライアントへ返す (`SessionResponse`)。

use serde::{Deserialize, Serialize};

/// signup 時にクライアントが構築する 3 種のラップ blob (Envelope バイト列)。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct KeyBlobs {
    /// password 由来 wrapKey で MK を封緘したもの。
    #[serde(with = "crate::b64")]
    pub mk_pw: Vec<u8>,
    /// recovery 鍵で MK を封緘したもの。
    #[serde(with = "crate::b64")]
    pub mk_recovery: Vec<u8>,
    /// MK で DK を封緘したもの。
    #[serde(with = "crate::b64")]
    pub dk_wrap: Vec<u8>,
}

/// アカウント作成。`auth_key` は HKDF(PMK) の 32B。salt_srv とハッシュはサーバーが生成する。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SignupRequest {
    pub email: String,
    #[serde(with = "crate::b64")]
    pub salt_pw: Vec<u8>,
    pub kdf_version: u8,
    #[serde(with = "crate::b64")]
    pub auth_key: Vec<u8>,
    pub key_blobs: KeyBlobs,
}

/// login 第1段: salt と KDF パラメータを取得 (未知ユーザーには enumeration 対策のダミー)。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct LoginBeginRequest {
    pub email: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct LoginBeginResponse {
    #[serde(with = "crate::b64")]
    pub salt_pw: Vec<u8>,
    pub kdf_version: u8,
}

/// login 第2段: `auth_key` を提示。成功で 2FA-pending トークンを得る (blob はまだ渡さない)。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct LoginVerifyRequest {
    pub email: String,
    #[serde(with = "crate::b64")]
    pub auth_key: Vec<u8>,
}

/// 第2要素の種別。
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Factor {
    Totp,
    Passkey,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct LoginVerifyResponse {
    pub login_token: String,
    pub factors: Vec<Factor>,
}

/// TOTP による 2FA。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TotpVerifyRequest {
    pub login_token: String,
    pub code: String,
}

/// 2FA 通過後に発行されるセッション。**ここで初めて** MK/DK ラップ blob を渡す。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SessionResponse {
    pub session_token: String,
    #[serde(with = "crate::b64")]
    pub mk_pw: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub dk_wrap: Vec<u8>,
    pub sync_cursor: u64,
}
