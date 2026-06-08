//! `iikanji-client` — Leptos SPA のクライアントロジック (WASM target)。
//!
//! 本 PR の範囲: 鍵管理グルー (auth ceremony のクライアント半分)。
//! 後続: store(IndexedDB)・sync ループ(pull→merge→resolve→push)・crypto_glue の DOM 連携・
//! Leptos UI・AI 証憑仕訳 (ユーザー鍵で provider 直叩き)。
//!
//! 不変条件: DK/MK は IndexedDB に平文保存しない (メモリのみ)。サーバーへ送るパスワード由来
//! 値は authKey のみ。財務計算は `iikanji_domain` を共有して全てクライアント側で行う。

#![forbid(unsafe_code)]

mod crypto_glue;
mod records;
mod sync;

// Leptos UI シェルは wasm32 限定 (native ビルドには Leptos を持ち込まない)。
#[cfg(target_arch = "wasm32")]
mod app;

pub use crypto_glue::{build_signup, derive_login, unlock_data_key, LoginKeys, SignupOutput};
pub use records::{open_record, seal_record, RecordCryptoError};
pub use sync::{reconcile, resolve, RemoteRecord};

#[cfg(target_arch = "wasm32")]
pub use app::App;
