//! サーバー側の補助関数 (不透明トークンの生成/ハッシュ・enumeration 対策のダミー salt)。
//!
//! AEAD ではないが「暗号は `crypto` crate の API 経由のみ」(CLAUDE.md) の方針に従い、
//! SHA-256 や OsRng を使うこれらの処理を server/handler から切り出してここへ集約する。

use std::fmt::Write;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::error::Result;

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

/// サーバー設定秘密から用途別の 32B 鍵を HKDF で導出する (TOTP 秘密の at-rest 暗号等)。
pub fn derive_server_key(server_secret: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, server_secret);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("32-byte OKM is valid");
    out
}

/// サーバー側 at-rest 暗号 (TOTP 秘密など)。Envelope を server 鍵で用いる。E2EE 鍵ツリーとは別。
pub fn seal_at_rest(key: &[u8; 32], context: &[u8], plaintext: &[u8]) -> Vec<u8> {
    crate::envelope::seal(key, 0, context, plaintext)
}

/// [`seal_at_rest`] の復号。文脈/鍵不一致は [`CryptoError::AeadOpen`](crate::CryptoError::AeadOpen)。
pub fn open_at_rest(key: &[u8; 32], context: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    crate::envelope::open(key, context, blob)
}
