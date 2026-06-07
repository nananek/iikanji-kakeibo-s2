//! `Vec<u8>` を base64 文字列として (de)serialize する serde ヘルパ。
//! `#[serde(with = "crate::b64")]` で使う。

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(bytes))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    STANDARD
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)
}
