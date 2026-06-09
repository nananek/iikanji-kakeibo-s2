//! `iikanji-server` — 認証付き暗号 blob ストア (Axum + Postgres)。
//!
//! 不変条件 (CLAUDE.md): サーバーは財務の平文を持たず、`enc_records.ciphertext` を**復号しない**。
//! 受け取るパスワード由来値は authKey のみ。ラップ blob は 2FA 通過後にのみ返す。
//! TOTP/passkey はセッションを gate するだけで復号鍵ではない。

#![forbid(unsafe_code)]

mod attachments;
mod auth;
pub mod config;
mod error;
mod session;
mod sync;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use axum::Router;
use iikanji_crypto::{derive_server_key, hash_auth_key, AuthKey, KdfParams};
use object_store::aws::AmazonS3Builder;
use object_store::memory::InMemory;
use object_store::ObjectStore;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder};

pub use attachments::gc_orphaned_attachments;
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
    /// WebAuthn (passkey 第2要素)。セッションを gate するだけで E2EE 鍵ツリーとは無関係。
    pub webauthn: Arc<Webauthn>,
    /// 添付バイナリの S3 互換ストレージ。クライアント暗号済み blob のみを置き、復号しない。
    pub store: Arc<dyn ObjectStore>,
    /// アップロード可能な暗号 blob の上限 (bytes)。
    pub max_attachment_bytes: usize,
}

/// 添付ストレージを config から構築する。S3 設定があれば S3 互換 (versitygw 等)、無ければ
/// in-memory にフォールバックする (dev/test 用)。非 localhost http や設定不整合は起動失敗。
pub fn build_object_store(config: &Config) -> anyhow::Result<Arc<dyn ObjectStore>> {
    match (&config.s3_endpoint, &config.s3_bucket) {
        (Some(endpoint), Some(bucket)) => {
            let s3 = AmazonS3Builder::new()
                .with_endpoint(endpoint)
                .with_bucket_name(bucket)
                .with_region(&config.s3_region)
                .with_access_key_id(config.s3_access_key.clone().unwrap_or_default())
                .with_secret_access_key(config.s3_secret_key.clone().unwrap_or_default())
                .with_allow_http(endpoint.starts_with("http://"))
                // path-style (versitygw / MinIO)。
                .with_virtual_hosted_style_request(false)
                .build()?;
            Ok(Arc::new(s3))
        }
        _ => {
            tracing::warn!(
                "S3_ENDPOINT/S3_BUCKET 未設定 — 添付は in-memory ストアにフォールバック \
                 (再起動で消える。本番では versitygw 等の S3 を設定すること)"
            );
            Ok(Arc::new(InMemory::new()))
        }
    }
}

/// RP ID + origin から `Webauthn` を構築する。非 localhost の http origin 等の不正設定では
/// webauthn-rs がエラーを返す (= 起動失敗で fail-closed、CSP 導出と同方針)。
fn build_webauthn(rp_id: &str, origin: &str) -> anyhow::Result<Webauthn> {
    let url = Url::parse(origin)
        .map_err(|e| anyhow::anyhow!("WEBAUTHN_ORIGIN ({origin}) が不正な URL です: {e}"))?;
    let builder = WebauthnBuilder::new(rp_id, &url).map_err(|e| {
        anyhow::anyhow!("WebAuthn 構築に失敗 (rp_id={rp_id}, origin={origin}): {e}")
    })?;
    Ok(builder.rp_name("いいかんじ家計簿").build()?)
}

impl AppState {
    /// 既定 (localhost) の WebAuthn でアプリ状態を作る。テストはこちらを使う。
    pub fn new(pool: PgPool, server_secret: Vec<u8>) -> Self {
        Self::new_with_webauthn(pool, server_secret, "localhost", "http://localhost:8080")
            .expect("default localhost webauthn always builds")
    }

    /// RP ID + origin を指定してアプリ状態を作る (本番は config 値を渡す)。
    pub fn new_with_webauthn(
        pool: PgPool,
        server_secret: Vec<u8>,
        rp_id: &str,
        origin: &str,
    ) -> anyhow::Result<Self> {
        let dummy = AuthKey::from_wire_bytes([0u8; 32]);
        let dummy_phc =
            hash_auth_key(&dummy, KdfParams::SERVER_V1).expect("dummy hash never fails");
        let totp_key =
            zeroize::Zeroizing::new(derive_server_key(&server_secret, b"totp-at-rest-v1"));
        let webauthn = Arc::new(build_webauthn(rp_id, origin)?);
        Ok(Self {
            pool,
            server_secret,
            totp_key,
            dummy_phc,
            webauthn,
            // 既定は in-memory ストア (テスト用)。本番は main で config 由来の S3 に差し替える。
            store: Arc::new(InMemory::new()),
            max_attachment_bytes: config::DEFAULT_MAX_ATTACHMENT_BYTES,
        })
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
        // passkey 第2要素。register 系は AuthUser gate (TOTP 通過済みセッション)。
        // auth 系は login_token (= パスワード検証済み) を要し、TOTP の代替として 2FA を通す。
        .route(
            "/auth/passkey/register/begin",
            post(auth::passkey_register_begin),
        )
        .route(
            "/auth/passkey/register/finish",
            post(auth::passkey_register_finish),
        )
        .route("/auth/passkey/auth/begin", post(auth::passkey_auth_begin))
        .route("/auth/passkey/auth/finish", post(auth::passkey_auth_finish))
        .route("/sync/push", post(sync::push))
        .route("/sync/pull", get(sync::pull))
        .route("/sync/cursor", get(sync::cursor))
        // 添付は大きめの body を許す (既定 body limit は小さいので当該ルートだけ引き上げる)。
        .merge(
            Router::new()
                .route(
                    "/attachments/{id}",
                    put(attachments::put)
                        .get(attachments::get)
                        .delete(attachments::delete),
                )
                .layer(DefaultBodyLimit::max(state.max_attachment_bytes)),
        )
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
