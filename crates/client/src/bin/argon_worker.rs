//! Argon2id Web Worker のエントリ (Trunk が `data-type="worker"` でビルドする)。**wasm32 限定**。
//! native ターゲット (server lane の clippy/test) では空 main。

#[cfg(target_arch = "wasm32")]
fn main() {
    use gloo_worker::Registrable;
    console_error_panic_hook::set_once();
    iikanji_client::ArgonWorker::registrar().register();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {}
