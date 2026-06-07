//! 鍵型。すべて 32 バイトの対称鍵で、`Debug` は redact、drop 時に zeroize される。
//! 鍵バイトを外部へ晒すのは `AuthKey` (login 証明として送信) のみ。

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};

macro_rules! define_key {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        #[allow(dead_code)]
        impl $name {
            pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            pub(crate) fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            pub(crate) fn try_from_slice(slice: &[u8]) -> Result<Self> {
                if slice.len() != 32 {
                    return Err(CryptoError::Envelope("unexpected wrapped-key length"));
                }
                let mut b = [0u8; 32];
                b.copy_from_slice(slice);
                Ok(Self(b))
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}(<redacted>)", stringify!($name))
            }
        }
    };
}

define_key!(
    Pmk,
    "Password-derived master key (ephemeral; Argon2id 出力)。ネットワークへ出さない。"
);
define_key!(
    AuthKey,
    "認証鍵 (PMK の HKDF)。パスワード由来でネットワークへ出る唯一の値 (login 証明)。"
);
define_key!(
    WrapKey,
    "鍵ラップ鍵 (PMK の HKDF)。非送出。MK をアンラップする。"
);
define_key!(
    MasterKey,
    "Master Key (乱数)。間接参照層: DK をラップ。パスワード変更時は再ラップのみ (データ再暗号化不要)。"
);
define_key!(
    DataKey,
    "Data Key (乱数)。全財務レコード/添付を暗号化する。"
);
define_key!(
    RecoveryKey,
    "リカバリ鍵 (オフライン リカバリコード由来)。MK の 2 本目のラップを開く。"
);

impl MasterKey {
    /// OS CSPRNG から新しい Master Key を生成する (signup 時)。
    pub fn generate() -> Self {
        Self(crate::random_array())
    }
}

impl DataKey {
    /// OS CSPRNG から新しい Data Key を生成する (signup 時)。
    pub fn generate() -> Self {
        Self(crate::random_array())
    }
}

impl AuthKey {
    /// クライアントから受信した 32 バイトで再構築する (サーバー側)。
    pub fn from_wire_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// login 証明としてサーバーへ送るための生バイトを取り出す (クライアント側)。
    /// **意図的にバイトを晒す唯一の鍵**。MK/DK/wrapKey では決して提供しない。
    pub fn expose_bytes(&self) -> [u8; 32] {
        self.0
    }
}
