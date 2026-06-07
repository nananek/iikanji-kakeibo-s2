//! 環境変数からの設定。

use anyhow::Context;

pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// enumeration 対策のダミー salt 導出と、将来の TOTP at-rest 暗号鍵の素。
    pub server_secret: Vec<u8>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let server_secret = std::env::var("SERVER_SECRET")
            .map(String::into_bytes)
            .unwrap_or_else(|_| b"dev-insecure-server-secret-change-me".to_vec());
        Ok(Config {
            database_url,
            bind_addr,
            server_secret,
        })
    }
}
