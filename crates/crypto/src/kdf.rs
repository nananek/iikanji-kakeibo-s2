//! 鍵導出: Argon2id (password→PMK) と HKDF-SHA-256 (PMK→auth/wrap, recovery)。

use argon2::{Algorithm, Argon2, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{CryptoError, Result};
use crate::keys::{AuthKey, Pmk, WrapKey};

/// PMK 導出に使う salt のバイト長 (= サーバーが `users.salt_pw` に保持)。
pub const SALT_LEN: usize = 16;

/// Argon2id パラメータ。`kdf_version` でプロファイルを版管理する。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// メモリコスト (KiB)。
    pub m_cost: u32,
    /// 反復コスト。
    pub t_cost: u32,
    /// 並列度。
    pub p_cost: u32,
}

impl KdfParams {
    /// interactive (login / MK アンロック) プロファイル — WASM 単一スレッド前提: 64 MiB, t=3, p=1。
    pub const INTERACTIVE_V1: KdfParams = KdfParams {
        m_cost: 65_536,
        t_cost: 3,
        p_cost: 1,
    };
    /// モバイルフォールバック: 46 MiB, t=3, p=1。
    pub const MOBILE_V2: KdfParams = KdfParams {
        m_cost: 47_104,
        t_cost: 3,
        p_cost: 1,
    };
    /// サーバー側 second hash (高エントロピーな authKey に対して): 19 MiB, t=2, p=1。
    pub const SERVER_V1: KdfParams = KdfParams {
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
    };

    /// `kdf_version` (1=INTERACTIVE_V1, 2=MOBILE_V2) からパラメータを得る。
    pub fn from_version(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::INTERACTIVE_V1),
            2 => Ok(Self::MOBILE_V2),
            _ => Err(CryptoError::Kdf("unknown kdf_version")),
        }
    }

    /// 既知プロファイルなら `kdf_version` を返す。任意パラメータでは `None`。
    pub fn version(self) -> Option<u8> {
        if self == Self::INTERACTIVE_V1 {
            Some(1)
        } else if self == Self::MOBILE_V2 {
            Some(2)
        } else {
            None
        }
    }

    pub(crate) fn to_argon2(self) -> Result<argon2::Params> {
        argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, None)
            .map_err(|_| CryptoError::Kdf("invalid argon2 params"))
    }
}

/// password + salt から PMK (Password-derived Master Key) を導出する。
pub fn derive_pmk(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Pmk> {
    Ok(pmk_from_hash(argon2_raw(password, salt, params)?))
}

/// **Web Worker でメインスレッドを塞がずに** Argon2id を回すための公開 API。
/// 出力は PMK 材料 (= [`derive_pmk`] の Argon2id 部分そのもの)。同一オリジンの worker 内で用い、
/// 結果は [`pmk_from_hash`] で `Pmk` に戻す。**ネットワークへ出さない** (PMK 不変条件は不変)。
pub fn argon2_hash(password: &[u8], salt: &[u8], params: KdfParams) -> Result<[u8; 32]> {
    argon2_raw(password, salt, params)
}

/// [`argon2_hash`] が返した PMK 材料から `Pmk` を復元する (Web Worker パスのメインスレッド側)。
/// 恒等: `derive_pmk(pw, salt, p) == pmk_from_hash(argon2_hash(pw, salt, p))`。
pub fn pmk_from_hash(hash: [u8; 32]) -> Pmk {
    Pmk::from_bytes(hash)
}

/// 新しい password salt (16B) を OS CSPRNG から生成する (signup 時にクライアントが使う)。
pub fn generate_salt() -> [u8; SALT_LEN] {
    crate::random_array()
}

pub(crate) fn argon2_raw(password: &[u8], salt: &[u8], params: KdfParams) -> Result<[u8; 32]> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_argon2()?);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::Kdf("argon2 derivation failed"))?;
    Ok(out)
}

/// PMK (32B, 高エントロピー) を PRK とした HKDF-Expand。`info` でドメイン分離する。
pub(crate) fn hkdf_expand(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("PRK length 32 == HashLen");
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32-byte OKM is valid");
    okm
}

impl Pmk {
    /// authKey = HKDF-Expand(PMK, "iikanji/auth/v1")。login 証明としてサーバーへ送る。
    pub fn auth_key(&self) -> AuthKey {
        AuthKey::from_bytes(hkdf_expand(self.as_bytes(), b"iikanji/auth/v1"))
    }

    /// wrapKey = HKDF-Expand(PMK, "iikanji/wrap/v1")。非送出。MK をアンラップする。
    pub fn wrap_key(&self) -> WrapKey {
        WrapKey::from_bytes(hkdf_expand(self.as_bytes(), b"iikanji/wrap/v1"))
    }
}
