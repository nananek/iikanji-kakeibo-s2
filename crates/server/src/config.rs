//! 環境変数からの設定。

use anyhow::Context;

const DEV_SECRET: &[u8] = b"dev-insecure-server-secret-change-me";

pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// enumeration 対策のダミー salt 導出と、将来の TOTP at-rest 暗号鍵の素。
    pub server_secret: Vec<u8>,
    /// 静的 SPA(Trunk dist) の配信元ディレクトリ。設定時のみ server が同一オリジンで配信する。
    /// 未設定なら API 専用 (テスト・別配信構成)。
    pub static_dir: Option<String>,
    /// WebAuthn の Relying Party ID (= effective domain)。passkey の scope を縛る。
    /// 本番は配信ドメイン (例 "kakeibo.example.com")。既定はローカル開発用 "localhost"。
    pub webauthn_rp_id: String,
    /// WebAuthn の origin (scheme + host + port)。RP ID は origin の登録可能サフィックスである必要がある。
    /// localhost / 127.0.0.1 以外は https 必須 (webauthn-rs が検証 → 不正なら起動失敗で fail-closed)。
    pub webauthn_origin: String,
    /// 添付バイナリの S3 互換ストレージ設定 (versitygw / MinIO / S3)。未設定なら in-memory に
    /// フォールバックする (dev/test 用、再起動で消える)。本番は必ず設定する。
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: String,
    pub s3_access_key: Option<String>,
    pub s3_secret_key: Option<String>,
    /// アップロード可能な暗号 blob の上限 (bytes)。
    pub max_attachment_bytes: usize,
    /// 孤立した添付 blob を掃除する GC の実行間隔 (秒)。0 で無効。
    pub attachment_gc_interval_secs: u64,
}

/// 添付暗号 blob の既定上限 (25 MiB)。
pub const DEFAULT_MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// 添付 GC の既定間隔 (1 時間)。
pub const DEFAULT_ATTACHMENT_GC_INTERVAL_SECS: u64 = 3600;

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let server_secret = std::env::var("SERVER_SECRET")
            .map(String::into_bytes)
            .unwrap_or_else(|_| DEV_SECRET.to_vec());
        // 未設定 / 既定 / プレースホルダ ("change-me...") の弱い値を検出して警告 (本番事故防止)。
        if server_secret == DEV_SECRET || server_secret.starts_with(b"change-me") {
            tracing::warn!(
                "SERVER_SECRET が未設定または既定/プレースホルダ値です。\
                 本番では固有のランダム値 (例: openssl rand -hex 32) を設定してください"
            );
        }
        let static_dir = std::env::var("STATIC_DIR").ok().filter(|s| !s.is_empty());
        let webauthn_rp_id =
            std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
        let webauthn_origin = std::env::var("WEBAUTHN_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());
        let s3_endpoint = std::env::var("S3_ENDPOINT").ok().filter(|s| !s.is_empty());
        let s3_bucket = std::env::var("S3_BUCKET").ok().filter(|s| !s.is_empty());
        let s3_region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let s3_access_key = std::env::var("S3_ACCESS_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        let s3_secret_key = std::env::var("S3_SECRET_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        let max_attachment_bytes = std::env::var("MAX_ATTACHMENT_BYTES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_ATTACHMENT_BYTES);
        let attachment_gc_interval_secs = std::env::var("ATTACHMENT_GC_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_ATTACHMENT_GC_INTERVAL_SECS);
        Ok(Config {
            database_url,
            bind_addr,
            server_secret,
            static_dir,
            webauthn_rp_id,
            webauthn_origin,
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_access_key,
            s3_secret_key,
            max_attachment_bytes,
            attachment_gc_interval_secs,
        })
    }
}
