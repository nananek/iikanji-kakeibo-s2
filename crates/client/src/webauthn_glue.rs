//! WebAuthn (passkey) のブラウザ glue。**wasm32 限定**。
//!
//! `navigator.credentials` を駆動し、proto 型 ↔ `web_sys` 型の変換 (webauthn-rs-proto の `wasm`
//! feature が提供する `From`) を仲介する。サーバーとの往復は [`crate::api::Client`] が担う。
//!
//! 不変条件 (CLAUDE.md): passkey は復号鍵ではなくセッション/blob 解放を gate するだけ。DK の
//! アンロックは login 第1段 (パスワード) 由来の wrapKey で行い、passkey は鍵ツリーに一切触れない。

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use webauthn_rs_proto::{PublicKeyCredential, RegisterPublicKeyCredential};

use iikanji_types::auth::SessionResponse;

use crate::api::Client;

/// `navigator.credentials` を取得する。
fn credentials() -> Result<web_sys::CredentialsContainer, String> {
    let win = web_sys::window().ok_or("window が利用できません")?;
    Ok(win.navigator().credentials())
}

/// 認証器を呼び、返ってきた資格情報を `web_sys::PublicKeyCredential` へダウンキャストする。
async fn await_credential(
    promise: js_sys::Promise,
) -> Result<web_sys::PublicKeyCredential, String> {
    let cred = JsFuture::from(promise)
        .await
        .map_err(|e| format!("認証器がキャンセル/失敗しました: {e:?}"))?;
    cred.dyn_into::<web_sys::PublicKeyCredential>()
        .map_err(|_| "PublicKeyCredential への変換に失敗しました".to_string())
}

/// passkey を登録する (要: ログイン済みセッション = TOTP gate 済み)。
pub async fn register_passkey(client: &Client, nickname: Option<String>) -> Result<(), String> {
    let ccr = client
        .passkey_register_begin()
        .await
        .map_err(|e| e.to_string())?;
    // proto challenge → ブラウザ API のオプション (webauthn-rs-proto wasm の From)。
    let options: web_sys::CredentialCreationOptions = ccr.into();
    let promise = credentials()?
        .create_with_options(&options)
        .map_err(|e| format!("認証器の呼び出しに失敗しました: {e:?}"))?;
    let pkc = await_credential(promise).await?;
    let reg: RegisterPublicKeyCredential = pkc.into();
    client
        .passkey_register_finish(&reg, nickname.as_deref())
        .await
        .map_err(|e| e.to_string())
}

/// passkey で 2FA を通し、`SessionResponse` (session_token + MK/DK ラップ blob) を得る。
/// 得た blob のアンロックは呼び出し側が login 第1段の wrapKey で行う (passkey は鍵に不介入)。
pub async fn authenticate_passkey(
    client: &Client,
    login_token: &str,
) -> Result<SessionResponse, String> {
    let rcr = client
        .passkey_auth_begin(login_token)
        .await
        .map_err(|e| e.to_string())?;
    let options: web_sys::CredentialRequestOptions = rcr.into();
    let promise = credentials()?
        .get_with_options(&options)
        .map_err(|e| format!("認証器の呼び出しに失敗しました: {e:?}"))?;
    let pkc = await_credential(promise).await?;
    let assertion: PublicKeyCredential = pkc.into();
    client
        .passkey_auth_finish(login_token, &assertion)
        .await
        .map_err(|e| e.to_string())
}
