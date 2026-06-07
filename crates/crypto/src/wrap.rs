//! 鍵ラップ/アンラップ。`MK → DK → records` の間接参照を Envelope で実装する。
//! signup 時のラップ blob: `mk-pw` / `mk-recovery` / `dk-wrap`。

use crate::envelope::{self, context};
use crate::error::Result;
use crate::keys::{DataKey, MasterKey, RecoveryKey, WrapKey};

/// MK を wrapKey で封緘 (password-wrapped MK)。`kdf_version` をヘッダに刻む。
pub fn wrap_master_key_with_password(
    wrap_key: &WrapKey,
    mk: &MasterKey,
    kdf_version: u8,
) -> Vec<u8> {
    envelope::seal(
        wrap_key.as_bytes(),
        kdf_version,
        &context::mk_pw(),
        mk.as_bytes(),
    )
}

/// password-wrapped MK を開封する。誤パスワード/すり替えは [`crate::CryptoError::AeadOpen`]。
pub fn unwrap_master_key_with_password(wrap_key: &WrapKey, blob: &[u8]) -> Result<MasterKey> {
    let pt = envelope::open(wrap_key.as_bytes(), &context::mk_pw(), blob)?;
    MasterKey::try_from_slice(&pt)
}

/// MK を recoveryKey で封緘 (recovery-wrapped MK)。
pub fn wrap_master_key_with_recovery(recovery_key: &RecoveryKey, mk: &MasterKey) -> Vec<u8> {
    envelope::seal(
        recovery_key.as_bytes(),
        0,
        &context::mk_recovery(),
        mk.as_bytes(),
    )
}

/// recovery-wrapped MK を開封する。
pub fn unwrap_master_key_with_recovery(
    recovery_key: &RecoveryKey,
    blob: &[u8],
) -> Result<MasterKey> {
    let pt = envelope::open(recovery_key.as_bytes(), &context::mk_recovery(), blob)?;
    MasterKey::try_from_slice(&pt)
}

/// DK を MK で封緘 (dk-wrap)。
pub fn wrap_data_key(mk: &MasterKey, dk: &DataKey) -> Vec<u8> {
    envelope::seal(mk.as_bytes(), 0, &context::dk_wrap(), dk.as_bytes())
}

/// dk-wrap を開封する。
pub fn unwrap_data_key(mk: &MasterKey, blob: &[u8]) -> Result<DataKey> {
    let pt = envelope::open(mk.as_bytes(), &context::dk_wrap(), blob)?;
    DataKey::try_from_slice(&pt)
}
