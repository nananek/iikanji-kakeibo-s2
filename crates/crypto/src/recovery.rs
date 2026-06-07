//! オフライン リカバリコード。160-bit エントロピーを Crockford Base32 +
//! チェックサムで人が読める形式に符号化し、Argon2id+HKDF で `RecoveryKey` を導出する。

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};
use crate::kdf::{self, KdfParams};
use crate::keys::RecoveryKey;

/// Crockford Base32 アルファベット (I, L, O, U を除外)。
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ENTROPY_BYTES: usize = 20; // 160-bit
const DATA_CHARS: usize = 32; // 20 bytes -> 32 base32 chars
const CHECK_CHARS: usize = 4;

/// 一度だけ表示してユーザーがオフライン保管するリカバリコード。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode {
    entropy: [u8; ENTROPY_BYTES],
}

impl core::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

impl RecoveryCode {
    /// OS CSPRNG から新しいリカバリコードを生成する。
    pub fn generate() -> Self {
        Self {
            entropy: crate::random_array(),
        }
    }

    /// 人が読める表示形式 (`XXXX-XXXX-...`、4 文字 9 グループ = データ32 + チェック4)。
    pub fn display(&self) -> String {
        let mut all = b32_encode(&self.entropy);
        all.push_str(&checksum(&self.entropy));
        all.as_bytes()
            .chunks(4)
            .map(|c| core::str::from_utf8(c).expect("ascii"))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// ユーザー入力をパースする。空白/ハイフン除去、大小・O→0・I/L→1 を正規化し、チェックサムを検証。
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        if cleaned.chars().count() != DATA_CHARS + CHECK_CHARS {
            return Err(CryptoError::Recovery("wrong length"));
        }
        let data: String = cleaned.chars().take(DATA_CHARS).collect();
        let check: String = cleaned.chars().skip(DATA_CHARS).collect();

        let decoded = b32_decode(&data)?;
        if decoded.len() != ENTROPY_BYTES {
            return Err(CryptoError::Recovery("decode length"));
        }
        let mut entropy = [0u8; ENTROPY_BYTES];
        entropy.copy_from_slice(&decoded);

        // 入力チェック文字を正規化し、期待値と一致するか比較 (タイポ検出)。
        let typed: String = check.chars().map(canon_char).collect::<Result<String>>()?;
        if typed != checksum(&entropy) {
            return Err(CryptoError::Recovery("checksum mismatch"));
        }
        Ok(Self { entropy })
    }

    /// `RecoveryKey = HKDF(Argon2id(canonical_code, salt), "iikanji/recovery/v1")`。
    pub fn derive_key(&self, salt: &[u8], params: KdfParams) -> Result<RecoveryKey> {
        let prk = kdf::argon2_raw(self.canonical_data().as_bytes(), salt, params)?;
        Ok(RecoveryKey::from_bytes(kdf::hkdf_expand(
            &prk,
            b"iikanji/recovery/v1",
        )))
    }

    /// 正規形 (ハイフン無し・大文字・チェックサム無しのデータ部 32 文字)。導出の決定性を担保する。
    fn canonical_data(&self) -> String {
        b32_encode(&self.entropy)
    }
}

fn checksum(entropy: &[u8]) -> String {
    let digest = Sha256::digest(entropy);
    let enc = b32_encode(digest.as_slice());
    enc[..CHECK_CHARS].to_string()
}

fn canon_char(c: char) -> Result<char> {
    let up = c.to_ascii_uppercase();
    let mapped = match up {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    if ALPHABET.iter().any(|&a| a as char == mapped) {
        Ok(mapped)
    } else {
        Err(CryptoError::Recovery("invalid character"))
    }
}

fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn b32_decode(s: &str) -> Result<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in s.chars() {
        let canon = canon_char(c)?;
        let val = ALPHABET
            .iter()
            .position(|&a| a as char == canon)
            .expect("canon in alphabet") as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}
