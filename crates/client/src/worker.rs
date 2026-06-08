//! Argon2id を Web Worker で実行するための gloo-worker oneshot。**wasm32 限定**。
//!
//! メインスレッドで Argon2id (64MiB) を回すと UI が数秒フリーズするため、重い Argon2id 部分だけを
//! worker に逃がす。worker は password+salt+kdf_version を受け取り PMK 材料 (32B) を返す
//! ([`iikanji_crypto::argon2_hash`])。メインスレッドは [`iikanji_crypto::pmk_from_hash`] +
//! `*_from_pmk` で残りの軽い鍵処理を行う。
//!
//! 不変条件: PMK 材料は**同一オリジンの worker** 内に留まり、ネットワークへ出さない。

use gloo_worker::oneshot::oneshot;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use iikanji_crypto::{argon2_hash, KdfParams};

/// worker への入力。`password` は鍵素材なので drop 時にゼロ化する (メイン側 input・worker 側
/// デシリアライズ結果の両方)。gloo-worker 内部の bincode/postMessage バッファは呼び出し側から
/// ゼロ化できない構造的制約がある (issue #12)。
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ArgonInput {
    pub password: Vec<u8>,
    pub salt: Vec<u8>,
    pub kdf_version: u8,
}

/// Argon2id を実行し PMK 材料 (32B) を返す。失敗は文字列で返す (worker 境界を越えるため)。
#[oneshot]
pub async fn ArgonWorker(input: ArgonInput) -> Result<[u8; 32], String> {
    let params = KdfParams::from_version(input.kdf_version).map_err(|e| e.to_string())?;
    argon2_hash(&input.password, &input.salt, params).map_err(|e| e.to_string())
}

/// Trunk が `data-type="worker"` で出力する worker JS のパス (ハッシュなし)。
const ARGON_WORKER_URL: &str = "/argon_worker.js";

/// メインスレッドから Argon2id を worker で実行する。新しい worker を 1 回だけ使い、結果を返す。
///
/// 返す `[u8; 32]` は PMK 材料 (高機密)。呼び出し元は [`iikanji_crypto::pmk_from_hash`] へ渡した後、
/// 速やかに `zeroize` すること (この値は worker→main の postMessage コピーでメインスレッドに載る)。
pub async fn argon_hash_in_worker(input: ArgonInput) -> Result<[u8; 32], String> {
    use gloo_worker::Spawnable;
    // Trunk の worker 出力は `--target no-modules` 形式なので as_module(false)。
    // gloo-worker が `importScripts(js); wasm_bindgen(wasm);` の loader shim を生成する。
    let mut bridge = ArgonWorker::spawner()
        .as_module(false)
        .spawn(ARGON_WORKER_URL);
    bridge.run(input).await
}
