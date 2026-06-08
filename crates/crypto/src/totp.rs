//! TOTP (RFC 6238) — 第2要素。**復号鍵ではない**(セッション/アクセスを gate するのみ)。
//! 秘密はサーバーが at-rest 暗号して保持する ([`crate::seal_at_rest`])。

use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};

const STEP: u64 = 30;
const DIGITS: usize = 6;
const SKEW: u8 = 1;

/// 160-bit の TOTP 秘密。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TotpSecret {
    bytes: Vec<u8>,
}

impl core::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TotpSecret(<redacted>)")
    }
}

impl TotpSecret {
    /// OS CSPRNG から 160-bit 秘密を生成する。
    pub fn generate() -> Self {
        Self {
            bytes: crate::random_array::<20>().to_vec(),
        }
    }

    /// 生バイトから復元する (at-rest 復号後など)。
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// base32 文字列から復元する。
    pub fn from_base32(s: &str) -> Result<Self> {
        let bytes = Secret::Encoded(s.to_string())
            .to_bytes()
            .map_err(|_| CryptoError::Totp("invalid base32 secret"))?;
        Ok(Self { bytes })
    }

    /// at-rest 暗号用の生バイト。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn totp(&self, issuer: &str, account: &str) -> Result<TOTP> {
        TOTP::new(
            Algorithm::SHA1,
            DIGITS,
            SKEW,
            STEP,
            self.bytes.clone(),
            Some(issuer.to_string()),
            account.to_string(),
        )
        .map_err(|_| CryptoError::Totp("invalid totp parameters"))
    }

    /// otpauth:// プロビジョニング URI (authenticator アプリの QR 用)。
    pub fn provisioning_uri(&self, issuer: &str, account: &str) -> Result<String> {
        Ok(self.totp(issuer, account)?.get_url())
    }

    /// 指定 unix 時刻のコードを生成する (検証/テスト用)。
    pub fn code_at(&self, unix_time: u64) -> Result<String> {
        Ok(self.totp("i", "a")?.generate(unix_time))
    }

    /// コードを検証する。±1 step の skew を許容し、replay 防止のため `last_used_step` 以下の
    /// step は拒否する。成功で消費した step を返す (呼び出し側が `last_used_step` を更新する)。
    pub fn verify(
        &self,
        code: &str,
        unix_time: u64,
        last_used_step: Option<u64>,
    ) -> Result<Option<u64>> {
        let totp = self.totp("i", "a")?;
        let current = unix_time / STEP;
        for &step in &[current.saturating_sub(1), current, current + 1] {
            if let Some(last) = last_used_step {
                if step <= last {
                    continue;
                }
            }
            let expected = totp.generate(step * STEP);
            if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
                return Ok(Some(step));
            }
        }
        Ok(None)
    }
}
