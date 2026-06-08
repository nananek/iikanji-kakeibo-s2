//! `iikanji-server` — 認証付き暗号 blob ストア (Axum + Postgres)。
//!
//! 不変条件 (CLAUDE.md): サーバーは財務の平文を持たず、`enc_records.ciphertext` を**復号しない**。
//! 受け取るパスワード由来値は authKey のみ。ラップ blob は 2FA 通過後にのみ返す。
//! TOTP/passkey はセッションを gate するだけで復号鍵ではない。

#![forbid(unsafe_code)]

mod auth;
pub mod config;
mod error;
mod session;
mod sync;

use axum::routing::{get, post};
use axum::Router;
use iikanji_crypto::{derive_server_key, hash_auth_key, AuthKey, KdfParams};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub use config::Config;
pub use error::AppError;

/// ハンドラ共有状態。
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub server_secret: Vec<u8>,
    /// TOTP 秘密の at-rest 暗号鍵 (server_secret 由来)。E2EE 鍵ツリーとは別。drop 時に zeroize。
    pub totp_key: zeroize::Zeroizing<[u8; 32]>,
    /// 未知ユーザーの login_verify で timing を平準化する固定ダミー PHC。
    pub dummy_phc: String,
}

impl AppState {
    pub fn new(pool: PgPool, server_secret: Vec<u8>) -> Self {
        let dummy = AuthKey::from_wire_bytes([0u8; 32]);
        let dummy_phc =
            hash_auth_key(&dummy, KdfParams::SERVER_V1).expect("dummy hash never fails");
        let totp_key =
            zeroize::Zeroizing::new(derive_server_key(&server_secret, b"totp-at-rest-v1"));
        Self {
            pool,
            server_secret,
            totp_key,
            dummy_phc,
        }
    }
}

/// ルーターを構築する (テストからも利用)。
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(auth::health))
        .route("/auth/signup", post(auth::signup))
        .route("/auth/totp/confirm", post(auth::totp_confirm))
        .route("/auth/login/begin", post(auth::login_begin))
        .route("/auth/login/verify", post(auth::login_verify))
        .route("/auth/2fa/totp", post(auth::totp_2fa))
        .route("/sync/push", post(sync::push))
        .route("/sync/pull", get(sync::pull))
        .route("/sync/cursor", get(sync::cursor))
        .with_state(state)
}

/// Postgres プールを作る。
pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    Ok(pool)
}

/// マイグレーションを適用する (冪等)。
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
