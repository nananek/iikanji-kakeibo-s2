//! 認証 UI (Leptos CSR)。**wasm32 限定**。
//!
//! - [`SignupForm`]: email+password → [`crate::crypto_glue::build_signup`] (Argon2id + 鍵生成・
//!   MK/DK ラップ) → [`crate::api::Client::signup`] → provisioning URI と recovery code 表示 → TOTP 確認。
//! - [`LoginForm`]: login_begin → [`crate::crypto_glue::derive_login`] → login_verify → TOTP 2FA →
//!   [`crate::crypto_glue::unlock_data_key`] で DK 復元 → 認証付き API (cursor) で疎通確認。
//!
//! 不変条件 (CLAUDE.md): サーバーへ出るのは authKey と ラップ blob のみ。MK/DK/wrapKey/
//! recovery code は送らない。ラップ blob (`SessionResponse`) は 2FA 通過後にのみ受領する。
//! 復元した `data_key` はメモリ保持 (アプリ状態への保持・利用は ledger UI で行う)。
//! Argon2id はメインスレッドで実行 — Web Worker 化は堅牢化フェーズ (issue #12)。

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api::Client;
use crate::crypto_glue::{build_signup, derive_login, unlock_data_key, LoginKeys};
use iikanji_crypto::DataKey;
use iikanji_types::auth::{
    LoginBeginRequest, LoginVerifyRequest, TotpConfirmRequest, TotpVerifyRequest,
};

/// signup ceremony の段階。
#[derive(Clone)]
enum Step {
    /// email/password 入力。
    Form,
    /// 登録成功 → TOTP 登録待ち。
    Totp {
        email: String,
        provisioning_uri: String,
        recovery_code: String,
    },
    /// TOTP 確認済み。
    Done,
}

/// signup フォーム + TOTP 登録。
#[component]
pub fn SignupForm() -> impl IntoView {
    let email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let totp_code = RwSignal::new(String::new());
    let step = RwSignal::new(Step::Form);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);

    // 段階1: 鍵生成 + signup。
    let on_signup = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get() {
            return;
        }
        let em = email.get();
        let pw = password.get();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            // Argon2id + MK/DK 生成 (CPU 重・メインスレッド。Web Worker 化は後続)。
            let out = match build_signup(&em, &pw, 1) {
                Ok(o) => o,
                Err(e) => {
                    error.set(Some(format!("鍵生成に失敗しました: {e}")));
                    busy.set(false);
                    return;
                }
            };
            // base_url="" = 同一オリジン (相対 URL)。
            let client = Client::new("");
            match client.signup(&out.request).await {
                Ok(resp) => {
                    step.set(Step::Totp {
                        email: em,
                        provisioning_uri: resp.totp_provisioning_uri,
                        recovery_code: out.recovery_code,
                    });
                }
                Err(e) => error.set(Some(format!("登録に失敗しました: {e}"))),
            }
            busy.set(false);
        });
    };

    // 段階2: TOTP 確認。
    let on_confirm = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get() {
            return;
        }
        let em = match step.get() {
            Step::Totp { email, .. } => email,
            _ => return,
        };
        let code = totp_code.get();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let client = Client::new("");
            match client
                .totp_confirm(&TotpConfirmRequest { email: em, code })
                .await
            {
                Ok(()) => step.set(Step::Done),
                Err(e) => error.set(Some(format!("TOTP 確認に失敗しました: {e}"))),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="auth">
            <h2>"アカウント作成"</h2>
            {move || {
                error
                    .get()
                    .map(|e| view! { <p class="error" role="alert">{e}</p> })
            }}
            {move || match step.get() {
                Step::Form => {
                    view! {
                        <form on:submit=on_signup>
                            <label>
                                "メール"
                                <input
                                    type="email"
                                    prop:value=move || email.get()
                                    on:input=move |ev| email.set(event_target_value(&ev))
                                    required
                                />
                            </label>
                            <label>
                                "パスワード"
                                <input
                                    type="password"
                                    prop:value=move || password.get()
                                    on:input=move |ev| password.set(event_target_value(&ev))
                                    required
                                />
                            </label>
                            <button type="submit" prop:disabled=move || busy.get()>
                                {move || if busy.get() { "処理中…" } else { "登録" }}
                            </button>
                        </form>
                    }
                        .into_any()
                }
                Step::Totp { provisioning_uri, recovery_code, .. } => {
                    view! {
                        <div class="totp-setup">
                            <p>"認証アプリに次の設定を登録してください:"</p>
                            <code data-testid="totp-uri" class="totp-uri">
                                {provisioning_uri}
                            </code>
                            <p class="recovery-note">"リカバリコード (この画面でのみ表示):"</p>
                            <code data-testid="recovery-code" class="recovery-code">
                                {recovery_code}
                            </code>
                            <form on:submit=on_confirm>
                                <label>
                                    "TOTP コード"
                                    <input
                                        type="text"
                                        inputmode="numeric"
                                        autocomplete="one-time-code"
                                        prop:value=move || totp_code.get()
                                        on:input=move |ev| totp_code.set(event_target_value(&ev))
                                        required
                                    />
                                </label>
                                <button type="submit" prop:disabled=move || busy.get()>
                                    "確認"
                                </button>
                            </form>
                        </div>
                    }
                        .into_any()
                }
                Step::Done => {
                    view! {
                        <p data-testid="signup-done" class="done">
                            "登録が完了しました。ログインできます。"
                        </p>
                    }
                        .into_any()
                }
            }}
        </section>
    }
}

/// login ceremony の段階。
#[derive(Clone)]
enum LoginStep {
    /// email/password 入力。
    Form,
    /// authKey 検証済み → TOTP 待ち。`login_token` は signal、`LoginKeys` は StoredValue 保持。
    Totp,
}

/// ログイン後のアプリセッション。復元した DK と、セッショントークンを持つ API クライアントを
/// アプリ状態として保持する。**メモリのみ** — IndexedDB 等へ永続化しない。drop で DK/トークンを
/// zeroize する (`DataKey` は ZeroizeOnDrop、`Client` の token は `Zeroizing`)。
pub struct Session {
    /// 復元した Data Key。財務レコードの seal/open に使う (利用は PR-3c2)。
    #[allow(dead_code)]
    pub dk: DataKey,
    /// セッショントークンを持つ API クライアント。sync push/pull に使う (利用は PR-3c2)。
    #[allow(dead_code)]
    pub client: Client,
    pub email: String,
    pub cursor: u64,
}

/// login フォーム + TOTP 2FA + DK アンロック。成功で `session` を確立し `logged_in` を立てる。
#[component]
pub fn LoginForm(
    session: StoredValue<Option<Session>>,
    logged_in: RwSignal<bool>,
) -> impl IntoView {
    let email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let totp_code = RwSignal::new(String::new());
    let step = RwSignal::new(LoginStep::Form);
    let login_token = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    // 非 Clone な LoginKeys (wrapKey 保持) を段階間で持ち越す。StoredValue ハンドルは Send+Copy
    // なので reactive クロージャ (Send 必須) に取り込める。LoginKeys は Send+Sync。
    let keys_store = StoredValue::new(None::<LoginKeys>);

    // 段階1: login_begin → derive_login (Argon2id) → login_verify。
    let on_login = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get() {
            return;
        }
        let em = email.get();
        let pw = password.get();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let client = Client::new("");
            // salt/kdf_version を取得 (未知ユーザーにはダミー salt が返る)。
            let begin = match client
                .login_begin(&LoginBeginRequest { email: em.clone() })
                .await
            {
                Ok(b) => b,
                Err(e) => {
                    error.set(Some(format!("ログイン開始に失敗しました: {e}")));
                    busy.set(false);
                    return;
                }
            };
            // authKey/wrapKey を導出 (Argon2id・メインスレッド)。
            let keys = match derive_login(&pw, &begin.salt_pw, begin.kdf_version) {
                Ok(k) => k,
                Err(e) => {
                    error.set(Some(format!("鍵導出に失敗しました: {e}")));
                    busy.set(false);
                    return;
                }
            };
            // authKey を提示 → 成功で login_token (blob はまだ受け取らない)。
            match client
                .login_verify(&LoginVerifyRequest {
                    email: em,
                    auth_key: keys.auth_key().to_vec(),
                })
                .await
            {
                Ok(resp) => {
                    login_token.set(resp.login_token);
                    keys_store.set_value(Some(keys));
                    step.set(LoginStep::Totp);
                }
                Err(e) => error.set(Some(format!("認証に失敗しました: {e}"))),
            }
            busy.set(false);
        });
    };

    // 段階2: totp_2fa → SessionResponse → wrapKey で DK をアンロック → 認証付き API で疎通確認。
    let on_totp = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get() {
            return;
        }
        let token = login_token.get();
        let code = totp_code.get();
        let em = email.get();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let mut client = Client::new("");
            // 2FA 通過で初めて MK/DK ラップ blob (SessionResponse) を受領。
            let session_resp = match client
                .totp_2fa(&TotpVerifyRequest {
                    login_token: token,
                    code,
                })
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    error.set(Some(format!("2FA に失敗しました: {e}")));
                    busy.set(false);
                    return;
                }
            };
            // 持ち越した LoginKeys を取り出す。
            let mut taken = None;
            keys_store.update_value(|slot| taken = slot.take());
            let keys = match taken {
                Some(k) => k,
                None => {
                    error.set(Some("内部エラー: 鍵が見つかりません".into()));
                    busy.set(false);
                    return;
                }
            };
            // wrapKey → MK → DK を復元 (E2EE unlock)。DK はアプリ Session として保持する。
            let dk = match unlock_data_key(&keys, &session_resp.mk_pw, &session_resp.dk_wrap) {
                Ok(dk) => dk,
                Err(e) => {
                    error.set(Some(format!("復号鍵のアンロックに失敗しました: {e}")));
                    busy.set(false);
                    return;
                }
            };
            // セッショントークンで認証付き API (cursor) を実行し、疎通確認 + 初期カーソル取得。
            client.set_session_token(session_resp.session_token);
            match client.cursor().await {
                Ok(c) => {
                    session.set_value(Some(Session {
                        dk,
                        client,
                        email: em,
                        cursor: c.cursor,
                    }));
                    logged_in.set(true);
                }
                Err(e) => error.set(Some(format!("セッション確認に失敗しました: {e}"))),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="auth">
            <h2>"ログイン"</h2>
            {move || {
                error
                    .get()
                    .map(|e| view! { <p class="error" role="alert">{e}</p> })
            }}
            {move || match step.get() {
                LoginStep::Form => {
                    view! {
                        <form on:submit=on_login.clone()>
                            <label>
                                "メール"
                                <input
                                    type="email"
                                    prop:value=move || email.get()
                                    on:input=move |ev| email.set(event_target_value(&ev))
                                    required
                                />
                            </label>
                            <label>
                                "パスワード"
                                <input
                                    type="password"
                                    prop:value=move || password.get()
                                    on:input=move |ev| password.set(event_target_value(&ev))
                                    required
                                />
                            </label>
                            <button type="submit" prop:disabled=move || busy.get()>
                                {move || if busy.get() { "処理中…" } else { "ログイン" }}
                            </button>
                        </form>
                    }
                        .into_any()
                }
                LoginStep::Totp => {
                    view! {
                        <form on:submit=on_totp.clone()>
                            <label>
                                "TOTP コード"
                                <input
                                    type="text"
                                    inputmode="numeric"
                                    autocomplete="one-time-code"
                                    prop:value=move || totp_code.get()
                                    on:input=move |ev| totp_code.set(event_target_value(&ev))
                                    required
                                />
                            </label>
                            <button type="submit" prop:disabled=move || busy.get()>
                                "確認"
                            </button>
                        </form>
                    }
                        .into_any()
                }
            }}
        </section>
    }
}

/// ログイン後のシェル。DK 保持中であることを示し、ログアウトで Session を破棄する。
/// 仕訳入力・残高/レポート・同期 UI は後続 PR でここに追加する。
#[component]
pub fn LedgerShell(
    session: StoredValue<Option<Session>>,
    logged_in: RwSignal<bool>,
) -> impl IntoView {
    // Session は logged_in=true の間は必ず Some。表示用に email/cursor を取り出す (静的)。
    let (email, cursor) = session
        .with_value(|s| s.as_ref().map(|s| (s.email.clone(), s.cursor)))
        .unwrap_or_default();

    let on_logout = move |_| {
        // DK + セッショントークンを破棄 (drop で zeroize)。
        session.set_value(None);
        logged_in.set(false);
    };

    view! {
        <section class="ledger" data-testid="ledger-shell">
            <p data-testid="ledger-welcome">{format!("ログイン中: {email}")}</p>
            <p class="muted">{format!("同期カーソル: {cursor}")}</p>
            <button data-testid="logout" on:click=on_logout>
                "ログアウト"
            </button>
            <p class="muted">"仕訳入力・残高表示は次の PR で追加します。"</p>
        </section>
    }
}
