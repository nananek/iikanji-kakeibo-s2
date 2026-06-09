//! 添付(証憑)ファイルの chunked AEAD。ファイルを 64KiB チャンクに分割し、各チャンクを Envelope v1 で
//! 封緘する。各チャンクの AAD に `(attachment_id, chunk_index, total_chunks)` を束縛するため、チャンクの
//! **並べ替え・切り詰め・別添付とのすり替え・改竄**はすべて復号失敗として検出される。
//!
//! blob 形式 (binary):
//! ```text
//!   total_chunks(u32 BE) | repeat[ frame_len(u32 BE) | Envelope(frame) ]
//! ```
//! 各チャンクは平文を 64KiB に**ゼロ詰め**して封緘するため、サーバーが観測できるサイズは 64KiB 粒度に
//! 丸まる (size パディング)。**真のファイルサイズは blob に入れず**、暗号レコード (VoucherMeta) 側に持つ。
//! そのため [`open_attachment`] は詰め済みバイト列を返し、呼び出し側が真サイズで切り詰める。

use crate::envelope::{self, context};
use crate::error::{CryptoError, Result};
use crate::keys::DataKey;

/// 1 チャンクの平文長 (64KiB)。最後のチャンクはゼロ詰めされる。
pub const ATTACHMENT_CHUNK_LEN: usize = 64 * 1024;

/// open 時の総チャンク数の上限 (DoS 緩和: 不正な total で巨大 alloc を防ぐ)。約 1GiB 相当。
const MAX_ATTACHMENT_CHUNKS: u32 = 16 * 1024;

fn total_chunks(plaintext_len: usize) -> u32 {
    // div_ceil。空ファイルは 0 チャンク (blob は total=0 のみ)。
    (plaintext_len.div_ceil(ATTACHMENT_CHUNK_LEN)) as u32
}

/// 添付ファイル平文を DK で chunked AEAD 暗号化し、不透明 blob を返す。
pub fn seal_attachment(dk: &DataKey, attachment_id: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let total = total_chunks(plaintext.len());
    let mut out = Vec::new();
    out.extend_from_slice(&total.to_be_bytes());
    // 64KiB の再利用バッファ。各チャンクはここへコピーし、最後の半端チャンクはゼロ詰め。
    let mut buf = vec![0u8; ATTACHMENT_CHUNK_LEN];
    for index in 0..total {
        let start = index as usize * ATTACHMENT_CHUNK_LEN;
        let end = core::cmp::min(start + ATTACHMENT_CHUNK_LEN, plaintext.len());
        let n = end - start;
        buf[..n].copy_from_slice(&plaintext[start..end]);
        if n < ATTACHMENT_CHUNK_LEN {
            buf[n..].fill(0); // 半端チャンクのゼロ詰め
        }
        let frame = envelope::seal(
            dk.as_bytes(),
            0,
            &context::attachment_chunk(attachment_id, index, total),
            &buf,
        );
        out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        out.extend_from_slice(&frame);
    }
    out
}

/// chunked AEAD blob を復号し、**ゼロ詰め済み**の平文を返す。呼び出し側は VoucherMeta の真サイズで
/// 切り詰めること。チャンクの並べ替え/切り詰め/すり替え/改竄は [`CryptoError::AeadOpen`]、
/// 構造異常は [`CryptoError::Envelope`]。
pub fn open_attachment(dk: &DataKey, attachment_id: &[u8; 16], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 4 {
        return Err(CryptoError::Envelope("attachment blob too short"));
    }
    let total = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if total > MAX_ATTACHMENT_CHUNKS {
        return Err(CryptoError::Envelope("attachment chunk count too large"));
    }
    let mut out = Vec::with_capacity(total as usize * ATTACHMENT_CHUNK_LEN);
    let mut pos = 4usize;
    for index in 0..total {
        if blob.len() < pos + 4 {
            return Err(CryptoError::Envelope("truncated frame length"));
        }
        let len =
            u32::from_be_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]) as usize;
        pos += 4;
        let frame_end = pos
            .checked_add(len)
            .ok_or(CryptoError::Envelope("frame length overflow"))?;
        if blob.len() < frame_end {
            return Err(CryptoError::Envelope("truncated frame"));
        }
        let plain = envelope::open(
            dk.as_bytes(),
            &context::attachment_chunk(attachment_id, index, total),
            &blob[pos..frame_end],
        )?;
        out.extend_from_slice(&plain);
        pos = frame_end;
    }
    if pos != blob.len() {
        return Err(CryptoError::Envelope(
            "trailing bytes after attachment chunks",
        ));
    }
    Ok(out)
}
