//! Trunk エントリポイント。
//!
//! wasm32 では Leptos アプリを `<body>` にマウントする。native ターゲット
//! (clippy/test/coverage の server lane) では Leptos を一切含めず空 `main` とし、
//! UI 依存をネイティブビルドへ持ち込まない。

#[cfg(target_arch = "wasm32")]
fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(iikanji_client::App);
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {}
