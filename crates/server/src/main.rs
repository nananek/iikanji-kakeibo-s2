use std::path::Path;

use anyhow::Result;
use axum::http::{header, HeaderName, HeaderValue};
use base64::Engine as _;
use iikanji_server::{build_object_store, connect, migrate, router, AppState, Config};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

/// Trunk が index.html に埋め込むインライン `<script type="module">` 起動コードの SHA-256(base64)。
/// CSP `script-src 'sha256-...'` に使い、`'unsafe-inline'` 無しで inline 起動を許可する。
fn inline_script_sha256(index_html: &str) -> Option<String> {
    let open = "<script type=\"module\">";
    let start = index_html.find(open)? + open.len();
    let end = index_html[start..].find("</script>")? + start;
    let digest = Sha256::digest(&index_html.as_bytes()[start..end]);
    Some(base64::engine::general_purpose::STANDARD.encode(digest))
}

/// SPA 配信時のセキュリティヘッダ。CSP は inline 起動 script を hash 許可し、wasm を
/// `'wasm-unsafe-eval'`、Web Worker(Blob) を `worker-src blob:` で許可する。
/// COOP/COEP で cross-origin isolation を有効化する (将来の Argon2 p>1 = SharedArrayBuffer 前提)。
///
/// inline script hash を導出できない場合は **起動失敗** (fail-closed)。`'unsafe-inline'` への
/// サイレント劣化はしない — CSP は XSS でのクライアント鍵漏洩を防ぐ最後の砦のため。
fn build_csp(index_html: &str) -> Result<String> {
    let hash = inline_script_sha256(index_html).ok_or_else(|| {
        anyhow::anyhow!(
            "index.html の inline 起動 script の hash を導出できません。Trunk ビルド出力を確認してください"
        )
    })?;
    Ok(format!(
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'sha256-{hash}'; \
         worker-src 'self' blob:; connect-src 'self'; img-src 'self' data:; \
         style-src 'self'; object-src 'none'; base-uri 'self'; \
         form-action 'self'; frame-ancestors 'none'"
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    let pool = connect(&config.database_url).await?;
    migrate(&pool).await?;
    // 添付ストレージ (S3 互換 / 未設定なら in-memory) を config から構築する。config を move する前に。
    let store = build_object_store(&config)?;
    let max_attachment_bytes = config.max_attachment_bytes;
    // WebAuthn の RP ID / origin は config (env) から。非 localhost の http 等の不正設定は
    // ここで起動失敗にする (fail-closed)。
    let mut state = AppState::new_with_webauthn(
        pool,
        config.server_secret,
        &config.webauthn_rp_id,
        &config.webauthn_origin,
    )?;
    state.store = store;
    state.max_attachment_bytes = max_attachment_bytes;

    // API ルーター。STATIC_DIR があれば SPA(dist) を同一オリジンで配信する
    // (API ルートに当たらないパスは static、未知パスは index.html へ SPA fallback)。
    let mut app = router(state);
    if let Some(dir) = &config.static_dir {
        let index = Path::new(dir).join("index.html");
        let index_html = std::fs::read_to_string(&index)
            .map_err(|e| anyhow::anyhow!("STATIC_DIR の index.html を読めません: {e}"))?;
        let csp = HeaderValue::from_str(&build_csp(&index_html)?)?;
        app = app
            .fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)))
            // セキュリティヘッダ (全レスポンスに付与)。
            .layer(SetResponseHeaderLayer::overriding(
                header::CONTENT_SECURITY_POLICY,
                csp,
            ))
            .layer(SetResponseHeaderLayer::overriding(
                HeaderName::from_static("cross-origin-opener-policy"),
                HeaderValue::from_static("same-origin"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                HeaderName::from_static("cross-origin-embedder-policy"),
                HeaderValue::from_static("require-corp"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                HeaderName::from_static("cross-origin-resource-policy"),
                HeaderValue::from_static("same-origin"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ));
        tracing::info!(static_dir = %dir, "serving SPA from static dir with security headers");
    }

    let listener = TcpListener::bind(&config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "iikanji-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
