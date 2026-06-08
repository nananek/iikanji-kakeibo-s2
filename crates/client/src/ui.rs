//! 認証 UI (Leptos CSR)。**wasm32 限定**。
//!
//! 本 PR は **signup ceremony** のみ: email+password → [`crate::crypto_glue::build_signup`]
//! (Argon2id + 鍵生成・MK/DK ラップ) → [`crate::api::Client::signup`] → provisioning URI と
//! recovery code を表示 → TOTP 確認。login は後続 PR。
//!
//! 不変条件 (CLAUDE.md): サーバーへ出るのは authKey と ラップ blob のみ。MK/DK/wrapKey/
//! recovery code は送らない。`build_signup` が返す `data_key` はメモリ保持 (本 PR では未使用、
//! login + 同期 UI で扱う)。Argon2id はメインスレッドで実行 — Web Worker 化は堅牢化フェーズ。

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api::Client;
use crate::crypto_glue::build_signup;
use iikanji_types::auth::TotpConfirmRequest;

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
