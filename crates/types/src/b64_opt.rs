//! `Option<Vec<u8>>` を base64 文字列 / null として (de)serialize する serde ヘルパ。
//! tombstone レコードは ciphertext が `None`。`#[serde(with = "crate::b64_opt")]` で使う。

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(crate) fn serialize<S: Serializer>(
    bytes: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match bytes {
        Some(b) => Some(STANDARD.encode(b)).serialize(serializer),
        None => None::<String>.serialize(serializer),
    }
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    match Option::<String>::deserialize(deserializer)? {
        Some(s) => STANDARD
            .decode(s.as_bytes())
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}
