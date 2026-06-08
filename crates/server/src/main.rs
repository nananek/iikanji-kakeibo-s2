use std::path::Path;

use anyhow::Result;
use iikanji_server::{connect, migrate, router, AppState, Config};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    let pool = connect(&config.database_url).await?;
    migrate(&pool).await?;
    let state = AppState::new(pool, config.server_secret);

    // API ルーター。STATIC_DIR があれば SPA(dist) を同一オリジンで配信する
    // (API ルートに当たらないパスは static、未知パスは index.html へ SPA fallback)。
    let mut app = router(state);
    if let Some(dir) = &config.static_dir {
        let index = Path::new(dir).join("index.html");
        app = app.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)));
        tracing::info!(static_dir = %dir, "serving SPA from static dir");
    }

    let listener = TcpListener::bind(&config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "iikanji-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
