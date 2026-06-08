//! アプリシェル (Leptos CSR)。**wasm32 限定**。
//!
//! 本 PR はスキャフォルドのみ — 認証 (signup/login) UI・同期ループ・IndexedDB ストア・
//! Leptos ルーティングは後続 PR で追加する。財務計算は `iikanji_domain` を共有し全て
//! クライアント側で実行する (CLAUDE.md 不変条件)。
//!
//! ここから先で扱う鍵 (MK/DK) は IndexedDB に平文保存しない (メモリのみ)。

use leptos::prelude::*;

use crate::ui::{LedgerShell, LoginForm, Session, SignupForm};

/// 認証 UI のモード。
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    Signup,
    Login,
}

/// ルートコンポーネント。未ログインは認証 UI、ログイン後は Ledger シェルを表示する。
/// 復元した DK を含む [`Session`] はメモリのみで保持する (IndexedDB 等へ永続化しない)。
#[component]
pub fn App() -> impl IntoView {
    // 非 Clone・機密の Session (DK + API クライアント) を StoredValue (Send+Copy) で保持。
    let session = StoredValue::new(None::<Session>);
    let logged_in = RwSignal::new(false);

    view! {
        <main class="app-shell">
            <h1>"いいかんじ™家計簿"</h1>
            <p class="tagline">"E2EE 複式簿記の家計簿"</p>
            {move || {
                if logged_in.get() {
                    view! { <LedgerShell session=session logged_in=logged_in /> }.into_any()
                } else {
                    view! { <AuthScreen session=session logged_in=logged_in /> }.into_any()
                }
            }}
        </main>
    }
}

/// 認証画面 (signup / login タブ)。login 成功で `logged_in` が立ち、App が Ledger へ切替える。
#[component]
fn AuthScreen(session: StoredValue<Option<Session>>, logged_in: RwSignal<bool>) -> impl IntoView {
    let mode = RwSignal::new(AuthMode::Signup);
    view! {
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
            AuthMode::Login => {
                view! { <LoginForm session=session logged_in=logged_in /> }.into_any()
            }
        }}
    }
}
