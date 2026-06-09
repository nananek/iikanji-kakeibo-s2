//! Envelope v1 — 唯一の AEAD ラッパ (XChaCha20-Poly1305)。
//!
//! ワイヤ形式 (binary, 版管理):
//! ```text
//!   magic(2)="K1" | version(1)=1 | alg(1)=1 | kdf_id(1) | flags(1) | nonce(24) | ciphertext(+16B tag)
//! ```
//! ヘッダ全体 (30B) と呼び出し側の **context** を AEAD の AAD に束縛する。
//! AAD は envelope に格納せず、open 時に呼び出し側が文脈から再構築する。これにより
//! サーバーが別用途の blob をすり替えても (purpose 不一致で) 復号が必ず失敗する。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::{CryptoError, Result};

pub(crate) const MAGIC: [u8; 2] = *b"K1";
pub(crate) const VERSION: u8 = 1;
pub(crate) const ALG_XCHACHA20POLY1305: u8 = 1;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const NONCE_OFFSET: usize = 6; // magic(2)+version(1)+alg(1)+kdf_id(1)+flags(1)
const HEADER_LEN: usize = NONCE_OFFSET + NONCE_LEN; // 30

/// `key` で `plaintext` を封緘する。`kdf_id` はヘッダに刻むメタ情報 (password-wrap blob では kdf_version)。
pub(crate) fn seal(key: &[u8; 32], kdf_id: u8, context: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce = crate::random_array::<NONCE_LEN>();
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(ALG_XCHACHA20POLY1305);
    out.push(kdf_id);
    out.push(0); // flags (reserved)
    out.extend_from_slice(&nonce);
    debug_assert_eq!(out.len(), HEADER_LEN);

    let aad = build_aad(&out[..HEADER_LEN], context);
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for valid inputs");
    out.extend_from_slice(&ciphertext);
    out
}

/// `key` と再構築した `context` で `envelope` を開封する。失敗時は [`CryptoError::AeadOpen`]。
pub(crate) fn open(key: &[u8; 32], context: &[u8], envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(CryptoError::Envelope("envelope too short"));
    }
    if envelope[0..2] != MAGIC {
        return Err(CryptoError::Envelope("bad magic"));
    }
    if envelope[2] != VERSION {
        return Err(CryptoError::Envelope("unsupported version"));
    }
    if envelope[3] != ALG_XCHACHA20POLY1305 {
        return Err(CryptoError::Envelope("unsupported alg"));
    }
    let header = &envelope[..HEADER_LEN];
    let nonce = &envelope[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN];
    let ciphertext = &envelope[HEADER_LEN..];

    let aad = build_aad(header, context);
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadOpen)
}

fn build_aad(header: &[u8], context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + context.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(context);
    aad
}

/// purpose 束縛コンテキスト。これが AAD に入り、blob の用途を暗号学的に固定する。
pub(crate) mod context {
    pub(crate) fn mk_pw() -> Vec<u8> {
        b"iikanji/v1/mk-pw".to_vec()
    }
    pub(crate) fn mk_recovery() -> Vec<u8> {
        b"iikanji/v1/mk-recovery".to_vec()
    }
    pub(crate) fn dk_wrap() -> Vec<u8> {
        b"iikanji/v1/dk-wrap".to_vec()
    }
    pub(crate) fn record(record_type: u16, record_id: &[u8; 16], version: u64) -> Vec<u8> {
        let mut c = Vec::with_capacity(15 + 2 + 16 + 8);
        c.extend_from_slice(b"iikanji/v1/rec/");
        c.extend_from_slice(&record_type.to_be_bytes());
        c.extend_from_slice(record_id);
        c.extend_from_slice(&version.to_be_bytes());
        c
    }

    /// 添付チャンクの束縛コンテキスト。`(attachment_id, chunk_index, total_chunks)` を AAD に固定し、
    /// チャンクの並べ替え・切り詰め・別添付とのすり替えを復号失敗として検出させる。
    pub(crate) fn attachment_chunk(attachment_id: &[u8; 16], index: u32, total: u32) -> Vec<u8> {
        let mut c = Vec::with_capacity(15 + 16 + 4 + 4);
        c.extend_from_slice(b"iikanji/v1/att/");
        c.extend_from_slice(attachment_id);
        c.extend_from_slice(&index.to_be_bytes());
        c.extend_from_slice(&total.to_be_bytes());
        c
    }
}
