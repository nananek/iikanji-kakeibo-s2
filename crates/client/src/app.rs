//! アプリシェル (Leptos CSR)。**wasm32 限定**。
//!
//! 本 PR はスキャフォルドのみ — 認証 (signup/login) UI・同期ループ・IndexedDB ストア・
//! Leptos ルーティングは後続 PR で追加する。財務計算は `iikanji_domain` を共有し全て
//! クライアント側で実行する (CLAUDE.md 不変条件)。
//!
//! ここから先で扱う鍵 (MK/DK) は IndexedDB に平文保存しない (メモリのみ)。

use leptos::prelude::*;

use crate::ui::SignupForm;

/// ルートコンポーネント。アプリシェル + 認証 UI (現状は signup ceremony)。
#[component]
pub fn App() -> impl IntoView {
    view! {
        <main class="app-shell">
            <h1>"いいかんじ™家計簿"</h1>
            <p class="tagline">"E2EE 複式簿記の家計簿"</p>
            <SignupForm />
        </main>
    }
}
