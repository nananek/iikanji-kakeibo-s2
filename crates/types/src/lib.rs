//! `iikanji-types` — server/client 共有の serde DTO (wire + at-rest contract)。
//!
//! 財務平文は持たない。バイト列フィールド (salt・auth_key・ラップ blob・ciphertext) は JSON 上
//! base64 文字列として表現する。auth ceremony と sync push/pull の契約を定義する。

#![forbid(unsafe_code)]

mod b64;
mod b64_opt;

pub mod auth;
pub mod sync;

#[cfg(test)]
mod tests;

pub use auth::{
    Factor, KeyBlobs, LoginBeginRequest, LoginBeginResponse, LoginVerifyRequest,
    LoginVerifyResponse, SessionResponse, SignupRequest, SignupResponse, TotpConfirmRequest,
    TotpVerifyRequest,
};
pub use sync::{
    CursorResponse, EncRecord, PullResponse, PushChange, PushRequest, PushResponse, PushResult,
    PushStatus,
};
