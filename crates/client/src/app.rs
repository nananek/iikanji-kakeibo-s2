//! アプリシェル (Leptos CSR)。**wasm32 限定**。
//!
//! 本 PR はスキャフォルドのみ — 認証 (signup/login) UI・同期ループ・IndexedDB ストア・
//! Leptos ルーティングは後続 PR で追加する。財務計算は `iikanji_domain` を共有し全て
//! クライアント側で実行する (CLAUDE.md 不変条件)。
//!
//! ここから先で扱う鍵 (MK/DK) は IndexedDB に平文保存しない (メモリのみ)。

use leptos::prelude::*;

use crate::ui::{LoginForm, SignupForm};

/// 認証 UI のモード。
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    Signup,
    Login,
}

/// ルートコンポーネント。アプリシェル + 認証 UI (signup / login)。
#[component]
pub fn App() -> impl IntoView {
    let mode = RwSignal::new(AuthMode::Signup);
    view! {
        <main class="app-shell">
            <h1>"いいかんじ™家計簿"</h1>
            <p class="tagline">"E2EE 複式簿記の家計簿"</p>
            <nav class="auth-tabs">
                <button
                    data-testid="tab-signup"
                    class:active=move || mode.get() == AuthMode::Signup
                    on:click=move |_| mode.set(AuthMode::Signup)
                >
                    "アカウント作成"
                </button>
                <button
                    data-testid="tab-login"
                    class:active=move || mode.get() == AuthMode::Login
                    on:click=move |_| mode.set(AuthMode::Login)
                >
                    "ログイン"
                </button>
            </nav>
            {move || match mode.get() {
                AuthMode::Signup => view! { <SignupForm /> }.into_any(),
                AuthMode::Login => view! { <LoginForm /> }.into_any(),
            }}
        </main>
    }
}
