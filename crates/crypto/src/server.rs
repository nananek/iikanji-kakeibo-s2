//! サーバー側の補助関数 (不透明トークンの生成/ハッシュ・enumeration 対策のダミー salt)。
//!
//! AEAD ではないが「暗号は `crypto` crate の API 経由のみ」(CLAUDE.md) の方針に従い、
//! SHA-256 や OsRng を使うこれらの処理を server/handler から切り出してここへ集約する。

use std::fmt::Write;

use sha2::{Digest, Sha256};

/// OS CSPRNG から 32 バイトを生成し、hex 64 文字の不透明トークンにする。
pub fn gen_opaque_token() -> String {
    let bytes = crate::random_array::<32>();
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// トークン等の SHA-256 ハッシュ (保存用)。
pub fn hash_token(token: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(Sha256::digest(token).as_slice());
    out
}

/// `secret` と `email` から決定的なダミー salt (16B) を導出する (未知ユーザーの enumeration 対策)。
pub fn server_dummy_salt(secret: &[u8], email: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(b"|salt-v1|");
    h.update(email.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize()[..16]);
    out
}
