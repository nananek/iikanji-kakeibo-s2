//! 認証 UI (Leptos CSR)。**wasm32 限定**。
//!
//! - [`SignupForm`]: email+password → [`crate::crypto_glue::build_signup`] (Argon2id + 鍵生成・
//!   MK/DK ラップ) → [`crate::api::Client::signup`] → provisioning URI と recovery code 表示 → TOTP 確認。
//! - [`LoginForm`]: login_begin → [`crate::crypto_glue::derive_login`] → login_verify → TOTP 2FA →
//!   [`crate::crypto_glue::unlock_data_key`] で DK 復元 → 認証付き API (cursor) で疎通確認。
//!
//! 不変条件 (CLAUDE.md): サーバーへ出るのは authKey と ラップ blob のみ。MK/DK/wrapKey/
//! recovery code は送らない。ラップ blob (`SessionResponse`) は 2FA 通過後にのみ受領する。
//! 復元した `data_key` はメモリ保持。
//! 重い Argon2id は [`crate::worker`] (Web Worker) で実行し、メインスレッドを塞がない。

use std::collections::HashMap;

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;

use zeroize::Zeroize;

use crate::api::Client;
use crate::attachment_glue::{
    download_attachment, read_file, trigger_browser_download, upload_attachment,
};
use crate::crypto_glue::{build_signup_from_pmk, login_keys_from_pmk, unlock_data_key, LoginKeys};
use crate::migrate::{map_export, parse_export, MigrationPlan};
use crate::records::{open_record, seal_record};
use crate::webauthn_glue::{authenticate_passkey, register_passkey};
use crate::worker::{argon_hash_in_worker, ArgonInput};
use iikanji_crypto::{generate_salt, pmk_from_hash, sha256, DataKey, ATTACHMENT_CHUNK_LEN};
use iikanji_domain::{
    income_expense_summary, record_type, AccountCode, AccountInfo, Chart, Date, EntryLine,
    JournalEntry, Record, RecordPayload, VoucherMeta, Yen,
};
use iikanji_types::auth::{
    Factor, LoginBeginRequest, LoginVerifyRequest, SessionResponse, TotpConfirmRequest,
    TotpVerifyRequest,
};
use iikanji_types::sync::{EncRecord, PushChange, PushRequest};
use uuid::Uuid;

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
            // 重い Argon2id は Web Worker で実行し、メインスレッドを塞がない。
            let salt = generate_salt();
            let mut raw = match argon_hash_in_worker(ArgonInput {
                password: pw.into_bytes(),
                salt: salt.to_vec(),
                kdf_version: 1,
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    error.set(Some(format!("鍵生成に失敗しました: {e}")));
                    busy.set(false);
                    return;
                }
            };
            // PMK 材料 → Pmk → 残りの軽い処理 (MK/DK 生成・ラップ) はメインスレッド。
            let pmk = pmk_from_hash(raw);
            raw.zeroize();
            let out = match build_signup_from_pmk(&em, &pmk, salt.to_vec(), 1) {
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
    /// 復元した Data Key。財務レコードの seal/open に使う。
    pub(crate) dk: DataKey,
    /// セッショントークンを持つ API クライアント。sync push/pull に使う。
    pub(crate) client: Client,
    pub(crate) email: String,
    pub(crate) cursor: u64,
}

/// StoredValue から非 Clone な `LoginKeys` (wrapKey 保持) を取り出す。
fn take_keys(store: StoredValue<Option<LoginKeys>>) -> Option<LoginKeys> {
    let mut taken = None;
    store.update_value(|slot| taken = slot.take());
    taken
}

/// 2FA (TOTP / passkey いずれか) 通過後の共通処理。受領した `SessionResponse` の MK/DK ラップ blob を
/// **login 第1段 (パスワード) 由来の wrapKey** でアンロックして DK を復元し、セッショントークンで
/// 疎通確認 (cursor) してアプリ `Session` を確立する。passkey は鍵ツリーに一切触れない (invariant 3)。
async fn finalize_login(
    session_resp: SessionResponse,
    keys: LoginKeys,
    mut client: Client,
    email: String,
    session: StoredValue<Option<Session>>,
    logged_in: RwSignal<bool>,
    error: RwSignal<Option<String>>,
) {
    let dk = match unlock_data_key(&keys, &session_resp.mk_pw, &session_resp.dk_wrap) {
        Ok(dk) => dk,
        Err(e) => {
            error.set(Some(format!("復号鍵のアンロックに失敗しました: {e}")));
            return;
        }
    };
    drop(keys); // wrapKey を即破棄 (生存窓を最小化)。
    client.set_session_token(session_resp.session_token);
    match client.cursor().await {
        Ok(c) => {
            session.set_value(Some(Session {
                dk,
                client,
                email,
                cursor: c.cursor,
            }));
            logged_in.set(true);
        }
        Err(e) => error.set(Some(format!("セッション確認に失敗しました: {e}"))),
    }
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
    // login_verify が返す factors に passkey が含まれるか (Totp 段で「パスキーで認証」を出すか)。
    let has_passkey = RwSignal::new(false);
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
            // Argon2id は Web Worker で実行 (メインスレッドを塞がない)。
            let mut raw = match argon_hash_in_worker(ArgonInput {
                password: pw.into_bytes(),
                salt: begin.salt_pw.clone(),
                kdf_version: begin.kdf_version,
            })
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    error.set(Some(format!("鍵導出に失敗しました: {e}")));
                    busy.set(false);
                    return;
                }
            };
            // PMK 材料 → wrapKey/authKey 導出はメインスレッド (軽量)。
            let pmk = pmk_from_hash(raw);
            raw.zeroize();
            let keys = login_keys_from_pmk(&pmk);
            // authKey を提示 → 成功で login_token (blob はまだ受け取らない)。
            match client
                .login_verify(&LoginVerifyRequest {
                    email: em,
                    auth_key: keys.auth_key().to_vec(),
                })
                .await
            {
                Ok(resp) => {
                    has_passkey.set(resp.factors.contains(&Factor::Passkey));
                    login_token.set(resp.login_token);
                    keys_store.set_value(Some(keys));
                    step.set(LoginStep::Totp);
                }
                Err(e) => error.set(Some(format!("認証に失敗しました: {e}"))),
            }
            busy.set(false);
        });
    };

    // 段階2a: totp_2fa → SessionResponse → finalize_login (wrapKey で DK アンロック → Session 確立)。
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
            let client = Client::new("");
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
            let keys = match take_keys(keys_store) {
                Some(k) => k,
                None => {
                    error.set(Some("内部エラー: 鍵が見つかりません".into()));
                    busy.set(false);
                    return;
                }
            };
            finalize_login(session_resp, keys, client, em, session, logged_in, error).await;
            busy.set(false);
        });
    };

    // 段階2b (代替): passkey で 2FA。TOTP コードの代わりに認証器で assertion → 同じく SessionResponse。
    // wrapKey は段階1 (パスワード) 由来のまま使う — passkey は鍵ツリーに触れない (invariant 3)。
    let on_passkey = move |_| {
        if busy.get() {
            return;
        }
        let token = login_token.get();
        let em = email.get();
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let client = Client::new("");
            let session_resp = match authenticate_passkey(&client, &token).await {
                Ok(s) => s,
                Err(e) => {
                    error.set(Some(format!("パスキー認証に失敗しました: {e}")));
                    busy.set(false);
                    return;
                }
            };
            let keys = match take_keys(keys_store) {
                Some(k) => k,
                None => {
                    error.set(Some("内部エラー: 鍵が見つかりません".into()));
                    busy.set(false);
                    return;
                }
            };
            finalize_login(session_resp, keys, client, em, session, logged_in, error).await;
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
                        <form on:submit=on_login>
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
                        <form on:submit=on_totp>
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
                        {move || {
                            has_passkey
                                .get()
                                .then(|| {
                                    view! {
                                        <button
                                            type="button"
                                            data-testid="passkey-auth"
                                            on:click=on_passkey
                                            prop:disabled=move || busy.get()
                                        >
                                            "パスキーで認証"
                                        </button>
                                    }
                                })
                        }}
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
            <header class="ledger-header">
                <p data-testid="ledger-welcome">{format!("ログイン中: {email}")}</p>
                <p class="muted">{format!("同期カーソル: {cursor}")}</p>
                <button data-testid="logout" on:click=on_logout>
                    "ログアウト"
                </button>
            </header>
            <PasskeyRegister session=session />
            <LedgerView session=session />
            <MigrationImport session=session />
        </section>
    }
}

/// 旧 iikanji-kakeibo の export JSON を取り込む UI。ファイルをクライアントで解析・暗号化して
/// 同期する (平文はサーバーへ出さない)。証憑画像も chunked-AEAD で暗号化アップロードする。
#[component]
fn MigrationImport(session: StoredValue<Option<Session>>) -> impl IntoView {
    // 解析済みプラン (非 Clone 不要だが大きいので StoredValue で保持)。
    let plan_store = StoredValue::new(None::<MigrationPlan>);
    // サマリー (件数 + 警告)。None = 未選択。
    let summary = RwSignal::new(None::<ImportSummary>);
    let status = RwSignal::new(Option::<Result<String, String>>::None);
    let busy = RwSignal::new(false);

    // ファイル選択 → 解析 + 写像 → サマリー表示。
    let on_file = move |ev: leptos::ev::Event| {
        if busy.get() {
            return;
        }
        let input: web_sys::HtmlInputElement = event_target(&ev);
        let Some(file) = input.files().and_then(|f| f.get(0)) else {
            return;
        };
        busy.set(true);
        status.set(None);
        summary.set(None);
        spawn_local(async move {
            let bytes = match read_file(file).await {
                Ok(b) => b,
                Err(e) => {
                    status.set(Some(Err(e)));
                    busy.set(false);
                    return;
                }
            };
            let text = match String::from_utf8(bytes) {
                Ok(t) => t,
                Err(_) => {
                    status.set(Some(Err("ファイルが UTF-8 の JSON ではありません".into())));
                    busy.set(false);
                    return;
                }
            };
            match parse_export(&text).map(map_export) {
                Ok(plan) => {
                    summary.set(Some(ImportSummary::of(&plan)));
                    plan_store.set_value(Some(plan));
                }
                Err(e) => status.set(Some(Err(e.to_string()))),
            }
            busy.set(false);
        });
    };

    // 取込実行 → 暗号化 + 同期 + 証憑アップロード。
    let on_import = move |_| {
        if busy.get() {
            return;
        }
        let mut taken = None;
        plan_store.update_value(|s| taken = s.take());
        let Some(plan) = taken else {
            status.set(Some(Err("先に export ファイルを選択してください".into())));
            return;
        };
        let Some((client, dk)) =
            session.with_value(|s| s.as_ref().map(|s| (s.client.clone(), s.dk.clone())))
        else {
            return;
        };
        busy.set(true);
        status.set(None);
        summary.set(None);
        spawn_local(async move {
            match run_import(&client, &dk, plan).await {
                Ok(msg) => status.set(Some(Ok(msg))),
                Err(e) => status.set(Some(Err(e))),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="migration" data-testid="migration">
            <h3>"データ移植（旧 iikanji-kakeibo から）"</h3>
            <p class="muted">
                "旧アプリの export JSON を選ぶと、クライアントで暗号化してから取り込みます "
                "(平文はサーバーに渡りません)。"
            </p>
            <label>
                "export ファイル (.json)"
                <input
                    data-testid="migration-file"
                    type="file"
                    accept="application/json,.json"
                    on:change=on_file
                    prop:disabled=move || busy.get()
                />
            </label>
            {move || {
                summary
                    .get()
                    .map(|s| {
                        view! {
                            <div class="migration-summary" data-testid="migration-summary">
                                <p>
                                    {format!(
                                        "仕訳 {} / 科目 {} / 医療費 {} / 締め {} / 証憑 {} 件を取込みます。",
                                        s.entries,
                                        s.accounts,
                                        s.medical,
                                        s.fiscal,
                                        s.vouchers,
                                    )}
                                </p>
                                {(!s.warnings.is_empty())
                                    .then(|| {
                                        view! {
                                            <ul class="migration-warnings">
                                                {s
                                                    .warnings
                                                    .iter()
                                                    .map(|w| view! { <li>{w.clone()}</li> })
                                                    .collect::<Vec<_>>()}
                                            </ul>
                                        }
                                    })}
                                <button
                                    data-testid="migration-import"
                                    on:click=on_import
                                    prop:disabled=move || busy.get()
                                >
                                    {move || if busy.get() { "取込中…" } else { "取込実行" }}
                                </button>
                            </div>
                        }
                    })
            }}
            {move || {
                status
                    .get()
                    .map(|r| match r {
                        Ok(m) => {
                            view! {
                                <p class="ok" data-testid="migration-status" role="status">
                                    {m}
                                </p>
                            }
                                .into_any()
                        }
                        Err(m) => {
                            view! {
                                <p class="error" data-testid="migration-status" role="alert">
                                    {m}
                                </p>
                            }
                                .into_any()
                        }
                    })
            }}
        </section>
    }
}

/// 取込サマリー (件数 + 警告)。
#[derive(Clone)]
struct ImportSummary {
    entries: usize,
    accounts: usize,
    medical: usize,
    fiscal: usize,
    vouchers: usize,
    warnings: Vec<String>,
}

impl ImportSummary {
    fn of(plan: &MigrationPlan) -> Self {
        Self {
            entries: plan.journal_entries.len(),
            accounts: plan.accounts.len(),
            medical: plan.medical.len(),
            fiscal: plan.fiscal.len(),
            vouchers: plan.vouchers.len(),
            warnings: plan.warnings.clone(),
        }
    }
}

/// 一度の push に詰めるレコード数 (sync の body limit 内に収める)。
const IMPORT_BATCH: usize = 200;

/// レコードを DK で seal して PushChange を作る (新規 = expected_version 0)。
fn seal_change(dk: &DataKey, record: &Record) -> Result<PushChange, String> {
    let id = Uuid::new_v4();
    seal_change_with_id(dk, id, record)
}

fn seal_change_with_id(dk: &DataKey, id: Uuid, record: &Record) -> Result<PushChange, String> {
    let ct = seal_record(dk, id, 1, record).map_err(|e| format!("暗号化に失敗しました: {e}"))?;
    Ok(PushChange {
        record_id: id,
        record_type: record.record_type(),
        expected_version: 0,
        tombstone: false,
        ciphertext: Some(ct),
    })
}

/// 写像済みプランを暗号化 + 同期 + 証憑アップロードする。結果メッセージを返す。
async fn run_import(client: &Client, dk: &DataKey, plan: MigrationPlan) -> Result<String, String> {
    let mut changes: Vec<PushChange> = Vec::new();
    // 仕訳は key→新 UUID を控える (証憑の紐付けに使う)。
    let mut entry_uuid: HashMap<String, Uuid> = HashMap::new();

    for acc in plan.accounts {
        changes.push(seal_change(dk, &Record::new(RecordPayload::Account(acc)))?);
    }
    for (key, entry) in plan.journal_entries {
        let id = Uuid::new_v4();
        entry_uuid.insert(key, id);
        changes.push(seal_change_with_id(
            dk,
            id,
            &Record::new(RecordPayload::JournalEntry(entry)),
        )?);
    }
    for med in plan.medical {
        changes.push(seal_change(dk, &Record::new(RecordPayload::Medical(med)))?);
    }
    for fc in plan.fiscal {
        changes.push(seal_change(
            dk,
            &Record::new(RecordPayload::FiscalClose(fc)),
        )?);
    }

    let record_count = changes.len();
    // body limit を超えないよう分割 push。途中失敗時は何件まで同期したかを伝える
    // (再取込時の重複範囲をユーザーが把握できるように)。
    let mut synced = 0usize;
    let mut iter = changes.into_iter();
    loop {
        let chunk: Vec<PushChange> = iter.by_ref().take(IMPORT_BATCH).collect();
        if chunk.is_empty() {
            break;
        }
        let n = chunk.len();
        client
            .push(&PushRequest { changes: chunk })
            .await
            .map_err(|e| {
                format!("同期に失敗しました（{synced}/{record_count} 件まで同期済み）: {e}")
            })?;
        synced += n;
    }

    // 証憑: 暗号化アップロード + VoucherMeta レコード。紐付け先が無ければスキップ。
    let mut voucher_ok = 0usize;
    let mut voucher_skip = 0usize;
    for v in plan.vouchers {
        let Some(&entry_id) = v.entry_key.as_deref().and_then(|k| entry_uuid.get(k)) else {
            voucher_skip += 1;
            continue;
        };
        let attachment_id = Uuid::new_v4();
        let content_hash = sha256(&v.data);
        let size = u64::try_from(v.data.len()).unwrap_or(u64::MAX);
        upload_attachment(client, dk, attachment_id, &v.data)
            .await
            .map_err(|e| {
                format!("証憑アップロードに失敗しました（レコードは同期済み / 証憑 {voucher_ok} 件まで完了）: {e}")
            })?;
        let meta = VoucherMeta {
            attachment_id: *attachment_id.as_bytes(),
            linked_entry_id: *entry_id.as_bytes(),
            filename: v.filename,
            mime: v.mime,
            size,
            content_hash,
            chunk_size: ATTACHMENT_CHUNK_LEN as u32,
        };
        let change = seal_change(dk, &Record::new(RecordPayload::VoucherMeta(meta)))?;
        client
            .push(&PushRequest {
                changes: vec![change],
            })
            .await
            .map_err(|e| {
                format!("証憑メタの同期に失敗しました（レコードは同期済み / 証憑 {voucher_ok} 件まで完了）: {e}")
            })?;
        voucher_ok += 1;
    }

    Ok(format!(
        "取込完了: レコード {record_count} 件 / 証憑 {voucher_ok} 件\
         {}。上の「再読込」で反映されます。",
        if voucher_skip > 0 {
            format!(" (紐付け不可の証憑 {voucher_skip} 件はスキップ)")
        } else {
            String::new()
        }
    ))
}

/// passkey 登録 UI。ログイン済み (= TOTP gate 済み) セッションで認証器を登録する。
/// 登録した passkey は次回以降のログインで TOTP の代替として使える (TOTP 自体は引き続き必須)。
#[component]
fn PasskeyRegister(session: StoredValue<Option<Session>>) -> impl IntoView {
    let nickname = RwSignal::new(String::new());
    // 結果メッセージ: Ok=成功 / Err=失敗。
    let status = RwSignal::new(Option::<Result<String, String>>::None);
    let busy = RwSignal::new(false);

    let on_register = move |_| {
        if busy.get() {
            return;
        }
        // セッションの API クライアント (セッショントークン保持) をクローンして使う。
        let Some(client) = session.with_value(|s| s.as_ref().map(|s| s.client.clone())) else {
            return;
        };
        let nn = nickname.get();
        let nn = (!nn.trim().is_empty()).then(|| nn.trim().to_string());
        busy.set(true);
        status.set(None);
        spawn_local(async move {
            match register_passkey(&client, nn).await {
                Ok(()) => status.set(Some(Ok("パスキーを登録しました".into()))),
                Err(e) => status.set(Some(Err(format!("パスキー登録に失敗しました: {e}")))),
            }
            busy.set(false);
        });
    };

    view! {
        <section class="passkey" data-testid="passkey-settings">
            <h3>"パスキー"</h3>
            <p class="muted">
                "2回目以降のログインで TOTP の代わりにパスキーを使えます (TOTP も引き続き必要です)。"
            </p>
            <label>
                "名前 (任意)"
                <input
                    data-testid="passkey-nickname"
                    type="text"
                    prop:value=move || nickname.get()
                    on:input=move |ev| nickname.set(event_target_value(&ev))
                />
            </label>
            <button
                data-testid="passkey-register"
                on:click=on_register
                prop:disabled=move || busy.get()
            >
                {move || if busy.get() { "登録中…" } else { "パスキーを登録" }}
            </button>
            {move || {
                status
                    .get()
                    .map(|r| match r {
                        Ok(m) => {
                            view! {
                                <p class="ok" data-testid="passkey-status" role="status">
                                    {m}
                                </p>
                            }
                                .into_any()
                        }
                        Err(m) => {
                            view! {
                                <p class="error" data-testid="passkey-status" role="alert">
                                    {m}
                                </p>
                            }
                                .into_any()
                        }
                    })
            }}
        </section>
    }
}

/// フォーム入力から複式仕訳を組み立てる (借方=貸方の 2 行)。
fn build_entry(
    date: &str,
    description: &str,
    debit: &str,
    credit: &str,
    amount: &str,
) -> Result<JournalEntry, String> {
    let p: Vec<&str> = date.split('-').collect();
    if p.len() != 3 {
        return Err("日付は YYYY-MM-DD 形式で入力してください".into());
    }
    let y = p[0]
        .parse::<i32>()
        .map_err(|_| "年が不正です".to_string())?;
    let m = p[1].parse::<u8>().map_err(|_| "月が不正です".to_string())?;
    let d = p[2].parse::<u8>().map_err(|_| "日が不正です".to_string())?;
    let date = Date::new(y, m, d).map_err(|_| "日付が不正です".to_string())?;
    let amt = amount
        .trim()
        .parse::<i64>()
        .map_err(|_| "金額は整数 (円) で入力してください".to_string())?;
    if amt <= 0 {
        return Err("金額は正の整数で入力してください".into());
    }
    if debit.trim().is_empty() || credit.trim().is_empty() {
        return Err("借方・貸方の科目コードを入力してください".into());
    }
    Ok(JournalEntry {
        date,
        description: description.to_string(),
        lines: vec![
            EntryLine::debit(AccountCode::from(debit.trim()), Yen::new(amt)),
            EntryLine::credit(AccountCode::from(credit.trim()), Yen::new(amt)),
        ],
    })
}

/// pull した EncRecord 群を DK で復号し、仕訳のみ (id, JournalEntry) を取り出す。
fn decode_entries(session: &Option<Session>, records: &[EncRecord]) -> Vec<(Uuid, JournalEntry)> {
    let Some(sess) = session else {
        return Vec::new();
    };
    records
        .iter()
        .filter_map(|r| {
            let ct = r.ciphertext.as_ref()?;
            let rec = open_record(&sess.dk, r.record_id, r.version, r.record_type, ct).ok()?;
            match rec.payload {
                RecordPayload::JournalEntry(j) => Some((r.record_id, j)),
                _ => None,
            }
        })
        .collect()
}

/// pull した EncRecord 群を DK で復号し、証憑メタのみ (record_id, version, VoucherMeta) を取り出す。
/// tombstone 済み (ciphertext=None) は除外される。
fn decode_vouchers(
    session: &Option<Session>,
    records: &[EncRecord],
) -> Vec<(Uuid, u32, VoucherMeta)> {
    let Some(sess) = session else {
        return Vec::new();
    };
    records
        .iter()
        .filter_map(|r| {
            let ct = r.ciphertext.as_ref()?;
            let rec = open_record(&sess.dk, r.record_id, r.version, r.record_type, ct).ok()?;
            match rec.payload {
                RecordPayload::VoucherMeta(m) => Some((r.record_id, r.version, m)),
                _ => None,
            }
        })
        .collect()
}

/// 仕訳入力フォーム + 一覧。DK で seal/open し、API で push/pull する E2EE 同期ループ。
#[component]
pub fn LedgerView(session: StoredValue<Option<Session>>) -> impl IntoView {
    let entries = RwSignal::new(Vec::<(Uuid, JournalEntry)>::new());
    // 証憑メタ (record_id, version, meta)。version は tombstone(削除)時の CAS に使う。
    let vouchers = RwSignal::new(Vec::<(Uuid, u32, VoucherMeta)>::new());
    // 添付対象の仕訳 record_id (文字列)。
    let selected_entry = RwSignal::new(String::new());
    let error = RwSignal::new(Option::<String>::None);
    let busy = RwSignal::new(false);

    let date = RwSignal::new(String::new());
    let desc = RwSignal::new(String::new());
    let debit = RwSignal::new(String::new());
    let credit = RwSignal::new(String::new());
    let amount = RwSignal::new(String::new());

    // 標準科目カタログは一度だけ構築し、集計・科目ドロップダウン・名称解決で再利用する。
    let chart = StoredValue::new(Chart::standard());
    // ドロップダウン用 (code, "code 名称")。display_order 順。
    let account_opts: Vec<(String, String)> = chart.with_value(|c| {
        let mut accts: Vec<&AccountInfo> = c.iter().filter(|a| a.is_active).collect();
        accts.sort_by_key(|a| a.display_order);
        accts
            .into_iter()
            .map(|a| {
                (
                    a.code.as_str().to_string(),
                    format!("{} {}", a.code.as_str(), a.name),
                )
            })
            .collect()
    });

    // サーバーから全レコードを pull → DK で復号 → 一覧へ反映。
    let load = move || {
        let Some(client) = session.with_value(|s| s.as_ref().map(|s| s.client.clone())) else {
            return;
        };
        spawn_local(async move {
            match client.pull(0).await {
                Ok(resp) => {
                    let (decoded, vs) = session.with_value(|s| {
                        (
                            decode_entries(s, &resp.records),
                            decode_vouchers(s, &resp.records),
                        )
                    });
                    entries.set(decoded);
                    vouchers.set(vs);
                }
                Err(e) => error.set(Some(format!("読込に失敗しました: {e}"))),
            }
        });
    };
    // 初回ロード。
    load();

    let on_add = move |ev: SubmitEvent| {
        ev.prevent_default();
        if busy.get() {
            return;
        }
        let entry = match build_entry(
            &date.get(),
            &desc.get(),
            &debit.get(),
            &credit.get(),
            &amount.get(),
        ) {
            Ok(e) => e,
            Err(msg) => {
                error.set(Some(msg));
                return;
            }
        };
        let record = Record::new(RecordPayload::JournalEntry(entry));
        let id = Uuid::new_v4();
        let rtype = record.record_type();
        // DK で seal (同期。StoredValue 借用は await をまたがない)。
        let ct = match session
            .with_value(|s| s.as_ref().map(|sess| seal_record(&sess.dk, id, 1, &record)))
        {
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                error.set(Some(format!("暗号化に失敗しました: {e}")));
                return;
            }
            None => return,
        };
        let Some(client) = session.with_value(|s| s.as_ref().map(|s| s.client.clone())) else {
            return;
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let push = PushRequest {
                changes: vec![PushChange {
                    record_id: id,
                    record_type: rtype,
                    expected_version: 0,
                    tombstone: false,
                    ciphertext: Some(ct),
                }],
            };
            match client.push(&push).await {
                Ok(_) => {
                    date.set(String::new());
                    desc.set(String::new());
                    amount.set(String::new());
                    debit.set(String::new());
                    credit.set(String::new());
                    // サーバーから再読込 (pull+decrypt 経路で一覧へ反映)。
                    load();
                }
                Err(e) => error.set(Some(format!("保存に失敗しました: {e}"))),
            }
            busy.set(false);
        });
    };

    // 証憑を添付: ファイル選択時に 読込→暗号化アップロード→VoucherMeta レコード push→再読込。
    let on_file = move |ev: leptos::ev::Event| {
        if busy.get() {
            return;
        }
        let entry_id = match Uuid::parse_str(selected_entry.get().trim()) {
            Ok(id) => id,
            Err(_) => {
                error.set(Some("先に対象の仕訳を選んでください".into()));
                return;
            }
        };
        let input: web_sys::HtmlInputElement = event_target(&ev);
        let Some(file) = input.files().and_then(|f| f.get(0)) else {
            return;
        };
        let filename = file.name();
        let mime = file.type_();
        let Some((client, dk)) =
            session.with_value(|s| s.as_ref().map(|s| (s.client.clone(), s.dk.clone())))
        else {
            return;
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let bytes = match read_file(file).await {
                Ok(b) => b,
                Err(e) => {
                    error.set(Some(e));
                    busy.set(false);
                    return;
                }
            };
            let attachment_id = Uuid::new_v4();
            let content_hash = sha256(&bytes);
            let size = bytes.len() as u64;
            // 暗号 blob を先にアップロードする。
            if let Err(e) = upload_attachment(&client, &dk, attachment_id, &bytes).await {
                error.set(Some(format!("アップロードに失敗しました: {e}")));
                busy.set(false);
                return;
            }
            // VoucherMeta を暗号レコードとして push (仕訳との紐付けは ciphertext 内)。
            let meta = VoucherMeta {
                attachment_id: *attachment_id.as_bytes(),
                linked_entry_id: *entry_id.as_bytes(),
                filename,
                mime,
                size,
                content_hash,
                chunk_size: ATTACHMENT_CHUNK_LEN as u32,
            };
            let record = Record::new(RecordPayload::VoucherMeta(meta));
            let voucher_id = Uuid::new_v4();
            let ct = match seal_record(&dk, voucher_id, 1, &record) {
                Ok(c) => c,
                Err(e) => {
                    error.set(Some(format!("暗号化に失敗しました: {e}")));
                    busy.set(false);
                    return;
                }
            };
            let push = PushRequest {
                changes: vec![PushChange {
                    record_id: voucher_id,
                    record_type: record.record_type(),
                    expected_version: 0,
                    tombstone: false,
                    ciphertext: Some(ct),
                }],
            };
            match client.push(&push).await {
                Ok(_) => load(),
                Err(e) => error.set(Some(format!("保存に失敗しました: {e}"))),
            }
            busy.set(false);
        });
    };

    // 証憑をダウンロード: get→復号→真サイズ切り詰め→content hash 検証→ブラウザ保存。
    let on_download = move |meta: VoucherMeta| {
        if busy.get() {
            return;
        }
        let Some((client, dk)) =
            session.with_value(|s| s.as_ref().map(|s| (s.client.clone(), s.dk.clone())))
        else {
            return;
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let attachment_id = Uuid::from_bytes(meta.attachment_id);
            match download_attachment(
                &client,
                &dk,
                attachment_id,
                meta.size as usize,
                &meta.content_hash,
            )
            .await
            {
                Ok(bytes) => {
                    if let Err(e) = trigger_browser_download(&bytes, &meta.filename, &meta.mime) {
                        error.set(Some(e));
                    }
                }
                Err(e) => error.set(Some(format!("ダウンロードに失敗しました: {e}"))),
            }
            busy.set(false);
        });
    };

    // 証憑を削除: VoucherMeta を tombstone (CAS) + blob 削除 → 再読込。
    let on_delete = move |voucher_id: Uuid, version: u32, attachment_id: Uuid| {
        if busy.get() {
            return;
        }
        let Some(client) = session.with_value(|s| s.as_ref().map(|s| s.client.clone())) else {
            return;
        };
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let push = PushRequest {
                changes: vec![PushChange {
                    record_id: voucher_id,
                    record_type: record_type::VOUCHER_META,
                    expected_version: version,
                    tombstone: true,
                    ciphertext: None,
                }],
            };
            match client.push(&push).await {
                Ok(_) => {
                    // blob 本体も削除 (失敗してもメタは tombstone 済み)。
                    let _ = client.attachment_delete(attachment_id).await;
                    load();
                }
                Err(e) => error.set(Some(format!("削除に失敗しました: {e}"))),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="ledger-view">
            <section class="summary" data-testid="summary">
                <h3>"収支サマリー"</h3>
                {move || {
                    let v = entries.get();
                    let s = chart.with_value(|c| income_expense_summary(v.iter().map(|(_, e)| e), c));
                    view! {
                        <ul class="summary-list">
                            <li>
                                "収入 "
                                <span data-testid="sum-income">{s.income.to_string()}</span>
                                " 円"
                            </li>
                            <li>
                                "支出 "
                                <span data-testid="sum-expense">{s.expense.to_string()}</span>
                                " 円"
                            </li>
                            <li>
                                "収支 "
                                <span data-testid="sum-balance">{s.balance.to_string()}</span>
                                " 円"
                            </li>
                        </ul>
                    }
                }}
            </section>

            <h3>"仕訳入力"</h3>
            {move || error.get().map(|e| view! { <p class="error" role="alert">{e}</p> })}
            <form on:submit=on_add>
                <label>
                    "日付"
                    <input
                        data-testid="je-date"
                        type="text"
                        placeholder="2026-06-08"
                        prop:value=move || date.get()
                        on:input=move |ev| date.set(event_target_value(&ev))
                        required
                    />
                </label>
                <label>
                    "摘要"
                    <input
                        data-testid="je-desc"
                        type="text"
                        prop:value=move || desc.get()
                        on:input=move |ev| desc.set(event_target_value(&ev))
                        required
                    />
                </label>
                <label>
                    "借方科目"
                    <select
                        data-testid="je-debit"
                        prop:value=move || debit.get()
                        on:change=move |ev| debit.set(event_target_value(&ev))
                        required
                    >
                        <option value="">"-- 借方科目 --"</option>
                        {account_opts
                            .iter()
                            .map(|(code, label)| {
                                view! { <option value=code.clone()>{label.clone()}</option> }
                            })
                            .collect::<Vec<_>>()}
                    </select>
                </label>
                <label>
                    "貸方科目"
                    <select
                        data-testid="je-credit"
                        prop:value=move || credit.get()
                        on:change=move |ev| credit.set(event_target_value(&ev))
                        required
                    >
                        <option value="">"-- 貸方科目 --"</option>
                        {account_opts
                            .iter()
                            .map(|(code, label)| {
                                view! { <option value=code.clone()>{label.clone()}</option> }
                            })
                            .collect::<Vec<_>>()}
                    </select>
                </label>
                <label>
                    "金額(円)"
                    <input
                        data-testid="je-amount"
                        type="text"
                        inputmode="numeric"
                        prop:value=move || amount.get()
                        on:input=move |ev| amount.set(event_target_value(&ev))
                        required
                    />
                </label>
                <button type="submit" data-testid="je-submit" prop:disabled=move || busy.get()>
                    {move || if busy.get() { "保存中…" } else { "追加" }}
                </button>
            </form>

            <h3>"仕訳一覧"</h3>
            <button data-testid="reload" on:click=move |_| load()>
                "再読込"
            </button>
            <table data-testid="entries">
                <thead>
                    <tr>
                        <th>"日付"</th>
                        <th>"摘要"</th>
                        <th>"借方"</th>
                        <th>"貸方"</th>
                        <th>"金額"</th>
                    </tr>
                </thead>
                <tbody>
                    <For
                        each=move || entries.get()
                        key=|(id, _)| *id
                        children=move |(_id, e)| {
                            let total = e.total_debit();
                            let name = |code: Option<&AccountCode>| match code {
                                Some(c) => {
                                    chart
                                        .with_value(|ch| {
                                            ch.get(c)
                                                .map(|a| a.name.clone())
                                                .unwrap_or_else(|| c.as_str().to_string())
                                        })
                                }
                                None => String::new(),
                            };
                            let debit_acct = name(
                                e.lines.iter().find(|l| l.debit.is_positive()).map(|l| &l.account),
                            );
                            let credit_acct = name(
                                e.lines.iter().find(|l| l.credit.is_positive()).map(|l| &l.account),
                            );
                            view! {
                                <tr>
                                    <td>
                                        {format!(
                                            "{:04}-{:02}-{:02}",
                                            e.date.year(),
                                            e.date.month(),
                                            e.date.day(),
                                        )}
                                    </td>
                                    <td class="desc">{e.description.clone()}</td>
                                    <td class="debit-acct">{debit_acct}</td>
                                    <td class="credit-acct">{credit_acct}</td>
                                    <td class="amount">{total.to_string()}</td>
                                </tr>
                            }
                        }
                    />
                </tbody>
            </table>

            <section class="vouchers" data-testid="vouchers">
                <h3>"証憑(添付)"</h3>
                <p class="muted">
                    "ファイルはクライアントで暗号化してから保存されます (サーバーは復号できません)。"
                </p>
                <label>
                    "対象の仕訳"
                    <select
                        data-testid="voucher-entry"
                        prop:value=move || selected_entry.get()
                        on:change=move |ev| selected_entry.set(event_target_value(&ev))
                    >
                        <option value="">"-- 仕訳を選択 --"</option>
                        {move || {
                            entries
                                .get()
                                .into_iter()
                                .map(|(id, e)| {
                                    let label = format!(
                                        "{:04}-{:02}-{:02} {}",
                                        e.date.year(),
                                        e.date.month(),
                                        e.date.day(),
                                        e.description,
                                    );
                                    view! { <option value=id.to_string()>{label}</option> }
                                })
                                .collect::<Vec<_>>()
                        }}
                    </select>
                </label>
                <label>
                    "ファイル"
                    <input
                        data-testid="voucher-file"
                        type="file"
                        on:change=on_file
                        prop:disabled=move || busy.get()
                    />
                </label>

                <ul data-testid="voucher-list">
                    <For
                        each=move || vouchers.get()
                        key=|(id, ver, _)| (*id, *ver)
                        children=move |(rid, ver, meta)| {
                            let attachment_id = Uuid::from_bytes(meta.attachment_id);
                            let meta_dl = meta.clone();
                            view! {
                                <li class="voucher-item">
                                    <span class="voucher-name">{meta.filename.clone()}</span>
                                    {format!(" ({} bytes) ", meta.size)}
                                    <button
                                        data-testid="voucher-download"
                                        on:click=move |_| on_download(meta_dl.clone())
                                    >
                                        "ダウンロード"
                                    </button>
                                    <button
                                        data-testid="voucher-delete"
                                        on:click=move |_| on_delete(rid, ver, attachment_id)
                                    >
                                        "削除"
                                    </button>
                                </li>
                            }
                        }
                    />
                </ul>
            </section>
        </div>
    }
}
