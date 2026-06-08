//! 認証 ceremony の DTO (Bitwarden 方式)。
//!
//! 不変条件 (CLAUDE.md): サーバーへ送るパスワード由来の値は `auth_key` のみ。MK/DK/wrapKey/
//! recovery code は送らない。ラップ blob (`KeyBlobs`) は ciphertext であり、2FA 通過後にのみ
//! クライアントへ返す (`SessionResponse`)。
//!
//! 機密素材 (auth_key・ラップ blob・トークン・TOTP コード) を持つ型は `Debug` を手動実装で
//! redact し、リクエスト/エラーログへの漏洩を防ぐ。

use core::fmt;

use serde::{Deserialize, Serialize};

/// バイト長のみ出す redact 用ヘルパ。
struct RedactedBytes(usize);
impl fmt::Debug for RedactedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} bytes redacted]", self.0)
    }
}

/// 文字列トークン等を伏せる redact 用ヘルパ。
struct Redacted;
impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// signup 時にクライアントが構築する 3 種のラップ blob (Envelope バイト列)。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
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

impl fmt::Debug for KeyBlobs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBlobs")
            .field("mk_pw", &RedactedBytes(self.mk_pw.len()))
            .field("mk_recovery", &RedactedBytes(self.mk_recovery.len()))
            .field("dk_wrap", &RedactedBytes(self.dk_wrap.len()))
            .finish()
    }
}

/// signup 応答。`totp_provisioning_uri` は otpauth URI に TOTP secret を含むため Debug で伏せる。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignupResponse {
    pub totp_provisioning_uri: String,
}

impl fmt::Debug for SignupResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignupResponse")
            .field("totp_provisioning_uri", &Redacted)
            .finish()
    }
}

/// TOTP 登録の確認 (signup 直後)。`code` は短命 OTP のため Debug で伏せる。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TotpConfirmRequest {
    pub email: String,
    pub code: String,
}

impl fmt::Debug for TotpConfirmRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfirmRequest")
            .field("email", &self.email)
            .field("code", &Redacted)
            .finish()
    }
}

/// アカウント作成。`auth_key` は HKDF(PMK) の 32B。salt_srv とハッシュはサーバーが生成する。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignupRequest {
    pub email: String,
    #[serde(with = "crate::b64")]
    pub salt_pw: Vec<u8>,
    pub kdf_version: u8,
    #[serde(with = "crate::b64")]
    pub auth_key: Vec<u8>,
    pub key_blobs: KeyBlobs,
}

impl fmt::Debug for SignupRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignupRequest")
            .field("email", &self.email)
            .field("salt_pw", &RedactedBytes(self.salt_pw.len()))
            .field("kdf_version", &self.kdf_version)
            .field("auth_key", &RedactedBytes(self.auth_key.len()))
            .field("key_blobs", &self.key_blobs)
            .finish()
    }
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
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LoginVerifyRequest {
    pub email: String,
    #[serde(with = "crate::b64")]
    pub auth_key: Vec<u8>,
}

impl fmt::Debug for LoginVerifyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginVerifyRequest")
            .field("email", &self.email)
            .field("auth_key", &RedactedBytes(self.auth_key.len()))
            .finish()
    }
}

/// 第2要素の種別。
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Factor {
    Totp,
    Passkey,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LoginVerifyResponse {
    pub login_token: String,
    pub factors: Vec<Factor>,
}

impl fmt::Debug for LoginVerifyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginVerifyResponse")
            .field("login_token", &Redacted)
            .field("factors", &self.factors)
            .finish()
    }
}

/// TOTP による 2FA。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct TotpVerifyRequest {
    pub login_token: String,
    pub code: String,
}

impl fmt::Debug for TotpVerifyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpVerifyRequest")
            .field("login_token", &Redacted)
            .field("code", &Redacted)
            .finish()
    }
}

/// 2FA 通過後に発行されるセッション。**ここで初めて** MK/DK ラップ blob を渡す。
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SessionResponse {
    pub session_token: String,
    #[serde(with = "crate::b64")]
    pub mk_pw: Vec<u8>,
    #[serde(with = "crate::b64")]
    pub dk_wrap: Vec<u8>,
    pub sync_cursor: u64,
}

impl fmt::Debug for SessionResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionResponse")
            .field("session_token", &Redacted)
            .field("mk_pw", &RedactedBytes(self.mk_pw.len()))
            .field("dk_wrap", &RedactedBytes(self.dk_wrap.len()))
            .field("sync_cursor", &self.sync_cursor)
            .finish()
    }
}
