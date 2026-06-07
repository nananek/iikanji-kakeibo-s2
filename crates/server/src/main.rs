use anyhow::Result;
use iikanji_server::{connect, migrate, router, AppState, Config};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    let pool = connect(&config.database_url).await?;
    migrate(&pool).await?;
    let state = AppState::new(pool, config.server_secret);

    let listener = TcpListener::bind(&config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "iikanji-server listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
