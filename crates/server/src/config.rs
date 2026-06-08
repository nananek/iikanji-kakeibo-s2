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
}

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
        Ok(Config {
            database_url,
            bind_addr,
            server_secret,
            static_dir,
        })
    }
}
