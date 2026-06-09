//! サーバー API クライアント (auth ceremony + sync)。
//!
//! 設計: **純粋部** (リクエスト整形・レスポンス/エラー解釈) を transport 非依存にし native で
//! テストする。実際の fetch は **wasm32 限定**の [`Client`] (gloo-net = ブラウザ fetch) が担う。
//!
//! 不変条件 (CLAUDE.md): サーバーへ送るパスワード由来値は authKey のみ。MK/DK/wrapKey/
//! recovery code は送らない (これらは [`crate::crypto_glue`] でローカル処理する)。本モジュールは
//! `iikanji_types` の DTO をそのまま運ぶだけで、財務平文も鍵素材も新たに生成しない。

use serde::de::DeserializeOwned;
use serde::Serialize;

use iikanji_types::auth::{
    LoginBeginRequest, LoginVerifyRequest, SignupRequest, TotpConfirmRequest, TotpVerifyRequest,
};
use iikanji_types::sync::PushRequest;

/// HTTP メソッド (本 API は GET/POST のみ)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// transport 非依存のリクエスト仕様。base_url は [`Client`] が付与する。
///
/// `Debug` は手動実装で `body` を伏せる: 本体 JSON は base64 化された authKey 等を含むため、
/// `{:?}` ログに平文で出さない (path/クエリは機微でないので表示)。
#[derive(Clone, PartialEq, Eq)]
pub struct ApiRequest {
    pub method: Method,
    /// base_url からの相対パス (クエリを含む)。
    pub path: String,
    /// JSON 本体 (GET など本体なしは `None`)。
    pub body: Option<String>,
    /// `Authorization: Bearer <session_token>` を付与するか。
    pub needs_auth: bool,
}

/// `ApiRequest` の `body` を長さのみ出す redact 用ヘルパ。
struct RedactedBody(Option<usize>);
impl core::fmt::Debug for RedactedBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(n) => write!(f, "Some([{n} bytes redacted])"),
            None => f.write_str("None"),
        }
    }
}

impl core::fmt::Debug for ApiRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApiRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body", &RedactedBody(self.body.as_ref().map(|b| b.len())))
            .field("needs_auth", &self.needs_auth)
            .finish()
    }
}

/// API エラー。サーバー `error.rs` の `{"error": msg}` + HTTP status に対応。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiError {
    /// transport / ネットワーク失敗 (送信前のトークン欠如も含む)。
    Network(String),
    /// HTTP エラーステータス (サーバーの message 付き)。
    Status { code: u16, message: String },
    /// レスポンス JSON のデコード失敗。
    Decode(String),
    /// リクエスト JSON のエンコード失敗 (通常起きない)。
    Encode(String),
}

impl core::fmt::Display for ApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ApiError::Network(m) => write!(f, "network error: {m}"),
            ApiError::Status { code, message } => write!(f, "HTTP {code}: {message}"),
            ApiError::Decode(m) => write!(f, "response decode error: {m}"),
            ApiError::Encode(m) => write!(f, "request encode error: {m}"),
        }
    }
}

impl std::error::Error for ApiError {}

fn to_json<T: Serialize>(v: &T) -> Result<String, ApiError> {
    serde_json::to_string(v).map_err(|e| ApiError::Encode(e.to_string()))
}

fn post(path: &str, body: String) -> ApiRequest {
    ApiRequest {
        method: Method::Post,
        path: path.to_string(),
        body: Some(body),
        needs_auth: false,
    }
}

// ---- リクエストビルダ (純粋・transport 非依存) ----

/// `POST /auth/signup`。
pub fn signup_request(req: &SignupRequest) -> Result<ApiRequest, ApiError> {
    Ok(post("/auth/signup", to_json(req)?))
}

/// `POST /auth/totp/confirm` (本体応答なし)。
pub fn totp_confirm_request(req: &TotpConfirmRequest) -> Result<ApiRequest, ApiError> {
    Ok(post("/auth/totp/confirm", to_json(req)?))
}

/// `POST /auth/login/begin`。
pub fn login_begin_request(req: &LoginBeginRequest) -> Result<ApiRequest, ApiError> {
    Ok(post("/auth/login/begin", to_json(req)?))
}

/// `POST /auth/login/verify`。
pub fn login_verify_request(req: &LoginVerifyRequest) -> Result<ApiRequest, ApiError> {
    Ok(post("/auth/login/verify", to_json(req)?))
}

/// `POST /auth/2fa/totp` (成功で `SessionResponse` = ラップ blob を受領)。
pub fn totp_2fa_request(req: &TotpVerifyRequest) -> Result<ApiRequest, ApiError> {
    Ok(post("/auth/2fa/totp", to_json(req)?))
}

/// `POST /sync/push` (要セッション)。
pub fn push_request(req: &PushRequest) -> Result<ApiRequest, ApiError> {
    Ok(ApiRequest {
        method: Method::Post,
        path: "/sync/push".to_string(),
        body: Some(to_json(req)?),
        needs_auth: true,
    })
}

/// `GET /sync/pull?since=<cursor>` (要セッション)。
pub fn pull_request(since: u64) -> ApiRequest {
    ApiRequest {
        method: Method::Get,
        path: format!("/sync/pull?since={since}"),
        body: None,
        needs_auth: true,
    }
}

/// `GET /sync/cursor` (要セッション)。
pub fn cursor_request() -> ApiRequest {
    ApiRequest {
        method: Method::Get,
        path: "/sync/cursor".to_string(),
        body: None,
        needs_auth: true,
    }
}

/// login_token のみを運ぶ本体 (passkey auth/begin・auth/finish 共通の先頭フィールド)。
#[derive(Serialize)]
struct LoginTokenBody<'a> {
    login_token: &'a str,
}

/// `POST /auth/passkey/register/begin` (要セッション = TOTP gate 済み。本体なし)。
pub fn passkey_register_begin_request() -> ApiRequest {
    ApiRequest {
        method: Method::Post,
        path: "/auth/passkey/register/begin".to_string(),
        body: None,
        needs_auth: true,
    }
}

/// `POST /auth/passkey/auth/begin` (login_token を提示、セッション不要)。
pub fn passkey_auth_begin_request(login_token: &str) -> Result<ApiRequest, ApiError> {
    Ok(ApiRequest {
        method: Method::Post,
        path: "/auth/passkey/auth/begin".to_string(),
        body: Some(to_json(&LoginTokenBody { login_token })?),
        needs_auth: false,
    })
}

// ---- レスポンス解釈 (純粋) ----

fn status_error(status: u16, body: &str) -> ApiError {
    // サーバーは {"error": "..."} を返す。読めなければ生ボディ (trim) を message に。
    let message = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| body.trim().to_string());
    ApiError::Status {
        code: status,
        message,
    }
}

/// 2xx を期待して JSON をデコードする。非 2xx は [`ApiError::Status`] へ写像。
pub fn parse_json<T: DeserializeOwned>(status: u16, body: &str) -> Result<T, ApiError> {
    if (200..300).contains(&status) {
        serde_json::from_str(body).map_err(|e| ApiError::Decode(e.to_string()))
    } else {
        Err(status_error(status, body))
    }
}

/// 本体を持たない応答 (例: totp/confirm)。2xx を `Ok(())` に、非 2xx を [`ApiError::Status`] に。
pub fn parse_empty(status: u16, body: &str) -> Result<(), ApiError> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(status_error(status, body))
    }
}

// ---- wasm32: ブラウザ fetch アダプタ ----

#[cfg(target_arch = "wasm32")]
mod wasm_client {
    use super::*;
    use gloo_net::http::Request;
    use iikanji_types::auth::{
        LoginBeginResponse, LoginVerifyResponse, SessionResponse, SignupResponse,
    };
    use iikanji_types::sync::{CursorResponse, PullResponse, PushResponse};
    use uuid::Uuid;
    use webauthn_rs_proto::{
        CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
        RequestChallengeResponse,
    };

    /// passkey 登録完了の本体 (server `PasskeyRegisterFinishRequest` に対応)。
    #[derive(Serialize)]
    struct RegisterFinishBody<'a> {
        credential: &'a RegisterPublicKeyCredential,
        nickname: Option<&'a str>,
    }

    /// passkey 認証完了の本体 (server `PasskeyAuthFinishRequest` に対応)。
    #[derive(Serialize)]
    struct AuthFinishBody<'a> {
        login_token: &'a str,
        credential: &'a PublicKeyCredential,
    }

    /// ブラウザ fetch によるサーバークライアント。session_token を保持する (メモリのみ)。
    ///
    /// session_token は MK/DK より秘匿度は低いが、なりすまし可能なアクセストークンのため
    /// `Zeroizing<String>` で保持し、置換/破棄/drop 時にヒープを zeroize する。
    ///
    /// `Clone` 可: `StoredValue` 保持の Session から非同期処理の前にクローンして取り出すため
    /// (借用を `.await` をまたいで保持しない)。クローンは `Zeroizing` ごとコピーされ drop で zeroize。
    #[derive(Clone)]
    pub struct Client {
        base_url: String,
        session_token: Option<zeroize::Zeroizing<String>>,
    }

    impl Client {
        /// 例: `Client::new("")` (同一オリジン) または `Client::new("http://127.0.0.1:3000")`。
        pub fn new(base_url: impl Into<String>) -> Self {
            Self {
                base_url: base_url.into(),
                session_token: None,
            }
        }

        /// 2FA 通過後のセッショントークンを設定する。
        pub fn set_session_token(&mut self, token: String) {
            self.session_token = Some(zeroize::Zeroizing::new(token));
        }

        /// ログアウト等でセッションを破棄する (旧トークンは drop で zeroize)。
        pub fn clear_session_token(&mut self) {
            self.session_token = None;
        }

        async fn execute(&self, r: ApiRequest) -> Result<(u16, String), ApiError> {
            let url = format!("{}{}", self.base_url, r.path);
            let builder = match r.method {
                Method::Get => Request::get(&url),
                Method::Post => Request::post(&url),
            };
            let builder = if r.needs_auth {
                match &self.session_token {
                    Some(t) => builder.header("Authorization", &format!("Bearer {}", t.as_str())),
                    None => return Err(ApiError::Network("missing session token".into())),
                }
            } else {
                builder
            };
            let request = match r.body {
                Some(body) => builder
                    .header("Content-Type", "application/json")
                    .body(body)
                    .map_err(|e| ApiError::Network(e.to_string()))?,
                None => builder
                    .build()
                    .map_err(|e| ApiError::Network(e.to_string()))?,
            };
            let resp = request
                .send()
                .await
                .map_err(|e| ApiError::Network(e.to_string()))?;
            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| ApiError::Network(e.to_string()))?;
            Ok((status, text))
        }

        async fn send_json<T: DeserializeOwned>(&self, r: ApiRequest) -> Result<T, ApiError> {
            let (status, body) = self.execute(r).await?;
            parse_json(status, &body)
        }

        pub async fn signup(&self, req: &SignupRequest) -> Result<SignupResponse, ApiError> {
            self.send_json(signup_request(req)?).await
        }

        pub async fn totp_confirm(&self, req: &TotpConfirmRequest) -> Result<(), ApiError> {
            let (status, body) = self.execute(totp_confirm_request(req)?).await?;
            parse_empty(status, &body)
        }

        pub async fn login_begin(
            &self,
            req: &LoginBeginRequest,
        ) -> Result<LoginBeginResponse, ApiError> {
            self.send_json(login_begin_request(req)?).await
        }

        pub async fn login_verify(
            &self,
            req: &LoginVerifyRequest,
        ) -> Result<LoginVerifyResponse, ApiError> {
            self.send_json(login_verify_request(req)?).await
        }

        pub async fn totp_2fa(&self, req: &TotpVerifyRequest) -> Result<SessionResponse, ApiError> {
            self.send_json(totp_2fa_request(req)?).await
        }

        pub async fn push(&self, req: &PushRequest) -> Result<PushResponse, ApiError> {
            self.send_json(push_request(req)?).await
        }

        pub async fn pull(&self, since: u64) -> Result<PullResponse, ApiError> {
            self.send_json(pull_request(since)).await
        }

        pub async fn cursor(&self) -> Result<CursorResponse, ApiError> {
            self.send_json(cursor_request()).await
        }

        // ---- passkey 第2要素 (proto 型を直接授受) ----

        /// passkey 登録 challenge を得る (要セッション)。
        pub async fn passkey_register_begin(&self) -> Result<CreationChallengeResponse, ApiError> {
            self.send_json(passkey_register_begin_request()).await
        }

        /// attestation を提示して passkey 登録を完了する (要セッション)。
        pub async fn passkey_register_finish(
            &self,
            credential: &RegisterPublicKeyCredential,
            nickname: Option<&str>,
        ) -> Result<(), ApiError> {
            let req = ApiRequest {
                method: Method::Post,
                path: "/auth/passkey/register/finish".to_string(),
                body: Some(to_json(&RegisterFinishBody {
                    credential,
                    nickname,
                })?),
                needs_auth: true,
            };
            let (status, body) = self.execute(req).await?;
            parse_empty(status, &body)
        }

        /// passkey 認証 challenge を得る (login_token を提示、セッション不要)。
        pub async fn passkey_auth_begin(
            &self,
            login_token: &str,
        ) -> Result<RequestChallengeResponse, ApiError> {
            self.send_json(passkey_auth_begin_request(login_token)?)
                .await
        }

        /// assertion を提示して 2FA を通し、`SessionResponse` (session + MK/DK blob) を得る。
        pub async fn passkey_auth_finish(
            &self,
            login_token: &str,
            credential: &PublicKeyCredential,
        ) -> Result<SessionResponse, ApiError> {
            let req = ApiRequest {
                method: Method::Post,
                path: "/auth/passkey/auth/finish".to_string(),
                body: Some(to_json(&AuthFinishBody {
                    login_token,
                    credential,
                })?),
                needs_auth: false,
            };
            self.send_json(req).await
        }

        // ---- 添付 (octet-stream の生バイト授受) ----

        /// 添付暗号 blob をアップロードする (`PUT /attachments/{id}`)。
        pub async fn attachment_put(&self, id: Uuid, blob: Vec<u8>) -> Result<(), ApiError> {
            let token = self.bearer()?;
            let array = js_sys::Uint8Array::from(blob.as_slice());
            let resp = Request::put(&format!("{}/attachments/{}", self.base_url, id))
                .header("Authorization", &token)
                .header("Content-Type", "application/octet-stream")
                .body(array)
                .map_err(|e| ApiError::Network(e.to_string()))?
                .send()
                .await
                .map_err(|e| ApiError::Network(e.to_string()))?;
            self.expect_ok(resp).await
        }

        /// 添付暗号 blob をダウンロードする (`GET /attachments/{id}`)。
        pub async fn attachment_get(&self, id: Uuid) -> Result<Vec<u8>, ApiError> {
            let token = self.bearer()?;
            let resp = Request::get(&format!("{}/attachments/{}", self.base_url, id))
                .header("Authorization", &token)
                .send()
                .await
                .map_err(|e| ApiError::Network(e.to_string()))?;
            let status = resp.status();
            if (200..300).contains(&status) {
                resp.binary()
                    .await
                    .map_err(|e| ApiError::Network(e.to_string()))
            } else {
                Err(status_error(status, &resp.text().await.unwrap_or_default()))
            }
        }

        /// 添付を削除する (`DELETE /attachments/{id}`、メタ行 + blob)。
        pub async fn attachment_delete(&self, id: Uuid) -> Result<(), ApiError> {
            let token = self.bearer()?;
            let resp = Request::delete(&format!("{}/attachments/{}", self.base_url, id))
                .header("Authorization", &token)
                .send()
                .await
                .map_err(|e| ApiError::Network(e.to_string()))?;
            self.expect_ok(resp).await
        }

        /// `Authorization: Bearer <token>` 値を作る (セッション欠如は Network エラー)。
        fn bearer(&self) -> Result<String, ApiError> {
            let token = self
                .session_token
                .as_ref()
                .ok_or_else(|| ApiError::Network("missing session token".into()))?;
            Ok(format!("Bearer {}", token.as_str()))
        }

        /// 2xx を `Ok(())`、それ以外を `ApiError::Status` に写像する (本体なし応答)。
        async fn expect_ok(&self, resp: gloo_net::http::Response) -> Result<(), ApiError> {
            let status = resp.status();
            if (200..300).contains(&status) {
                Ok(())
            } else {
                Err(status_error(status, &resp.text().await.unwrap_or_default()))
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_client::Client;

#[cfg(test)]
mod tests {
    use super::*;
    use iikanji_types::auth::{KeyBlobs, SessionResponse};
    use iikanji_types::sync::{CursorResponse, PushChange, PushResponse};
    use uuid::Uuid;

    fn signup_dto() -> SignupRequest {
        SignupRequest {
            email: "a@example.com".into(),
            salt_pw: vec![1, 2, 3],
            kdf_version: 1,
            auth_key: vec![9; 32],
            key_blobs: KeyBlobs {
                mk_pw: vec![1; 10],
                mk_recovery: vec![2; 10],
                dk_wrap: vec![3; 10],
            },
        }
    }

    #[test]
    fn builders_set_method_path_and_auth() {
        let s = signup_request(&signup_dto()).unwrap();
        assert_eq!(s.method, Method::Post);
        assert_eq!(s.path, "/auth/signup");
        assert!(!s.needs_auth);
        assert!(s.body.is_some());

        let p = push_request(&PushRequest {
            changes: vec![PushChange {
                record_id: Uuid::from_u128(1),
                record_type: 1,
                expected_version: 0,
                tombstone: false,
                ciphertext: Some(vec![7, 7]),
            }],
        })
        .unwrap();
        assert_eq!(p.method, Method::Post);
        assert_eq!(p.path, "/sync/push");
        assert!(p.needs_auth);

        let pull = pull_request(42);
        assert_eq!(pull.method, Method::Get);
        assert_eq!(pull.path, "/sync/pull?since=42");
        assert!(pull.needs_auth);
        assert!(pull.body.is_none());

        let cur = cursor_request();
        assert_eq!(cur.path, "/sync/cursor");
        assert!(cur.needs_auth);
    }

    #[test]
    fn auth_builders_target_correct_unauthenticated_paths() {
        // 認証 ceremony はまだセッションが無いので needs_auth=false。
        let confirm = totp_confirm_request(&TotpConfirmRequest {
            email: "a@example.com".into(),
            code: "123456".into(),
        })
        .unwrap();
        assert_eq!(confirm.path, "/auth/totp/confirm");
        assert!(!confirm.needs_auth);

        let begin = login_begin_request(&LoginBeginRequest {
            email: "a@example.com".into(),
        })
        .unwrap();
        assert_eq!(begin.path, "/auth/login/begin");
        assert!(!begin.needs_auth);

        let verify = login_verify_request(&LoginVerifyRequest {
            email: "a@example.com".into(),
            auth_key: vec![9; 32],
        })
        .unwrap();
        assert_eq!(verify.path, "/auth/login/verify");
        // authKey は送るが Bearer トークンは不要 (設計上正しい)。
        assert!(!verify.needs_auth);

        let twofa = totp_2fa_request(&TotpVerifyRequest {
            login_token: "tok".into(),
            code: "123456".into(),
        })
        .unwrap();
        assert_eq!(twofa.path, "/auth/2fa/totp");
        assert!(!twofa.needs_auth);
    }

    #[test]
    fn passkey_begin_builders_target_correct_paths_and_auth() {
        // 登録 begin は要セッション (TOTP gate 済み) かつ本体なし。
        let reg = passkey_register_begin_request();
        assert_eq!(reg.method, Method::Post);
        assert_eq!(reg.path, "/auth/passkey/register/begin");
        assert!(reg.needs_auth);
        assert!(reg.body.is_none());

        // 認証 begin は login 途中なのでセッション不要、login_token を本体で運ぶ。
        let auth = passkey_auth_begin_request("tok").unwrap();
        assert_eq!(auth.method, Method::Post);
        assert_eq!(auth.path, "/auth/passkey/auth/begin");
        assert!(!auth.needs_auth);
        let body: serde_json::Value = serde_json::from_str(auth.body.as_ref().unwrap()).unwrap();
        assert_eq!(body["login_token"], "tok");
    }

    #[test]
    fn debug_redacts_request_body() {
        // body (authKey 等を含む JSON) は {:?} に平文で出さない。
        let dbg = format!("{:?}", signup_request(&signup_dto()).unwrap());
        assert!(
            dbg.contains("bytes redacted]"),
            "body should be redacted: {dbg}"
        );
        assert!(!dbg.contains("a@example.com"), "email leaked: {dbg}");
        assert!(
            dbg.contains("/auth/signup"),
            "path should be visible: {dbg}"
        );
        // 本体なしの GET は None と表示。
        assert!(format!("{:?}", cursor_request()).contains("body: None"));
    }

    #[test]
    fn request_body_is_valid_json_for_dto() {
        let req = signup_request(&signup_dto()).unwrap();
        let body = req.body.unwrap();
        // サーバーが受ける形 (base64 文字列フィールド) に往復できること。
        let back: SignupRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(back, signup_dto());
    }

    #[test]
    fn parse_json_decodes_2xx() {
        let dto = CursorResponse { cursor: 7 };
        let body = serde_json::to_string(&dto).unwrap();
        let got: CursorResponse = parse_json(200, &body).unwrap();
        assert_eq!(got, dto);
    }

    #[test]
    fn parse_json_session_response_roundtrip() {
        let dto = SessionResponse {
            session_token: "tok".into(),
            mk_pw: vec![1, 2, 3],
            dk_wrap: vec![4, 5, 6],
            sync_cursor: 3,
        };
        let body = serde_json::to_string(&dto).unwrap();
        let got: SessionResponse = parse_json(200, &body).unwrap();
        assert_eq!(got, dto);
    }

    #[test]
    fn parse_json_maps_error_status_with_server_message() {
        let err: Result<PushResponse, _> = parse_json(409, r#"{"error":"version conflict"}"#);
        assert_eq!(
            err.unwrap_err(),
            ApiError::Status {
                code: 409,
                message: "version conflict".into()
            }
        );
    }

    #[test]
    fn parse_json_error_falls_back_to_raw_body() {
        let err: Result<CursorResponse, _> = parse_json(502, "  bad gateway  ");
        assert_eq!(
            err.unwrap_err(),
            ApiError::Status {
                code: 502,
                message: "bad gateway".into()
            }
        );
    }

    #[test]
    fn parse_json_decode_failure_on_2xx() {
        let err: Result<CursorResponse, _> = parse_json(200, "not json");
        assert!(matches!(err.unwrap_err(), ApiError::Decode(_)));
    }

    #[test]
    fn parse_empty_ok_on_2xx_err_on_4xx() {
        assert_eq!(parse_empty(204, ""), Ok(()));
        assert_eq!(
            parse_empty(401, r#"{"error":"unauthorized"}"#).unwrap_err(),
            ApiError::Status {
                code: 401,
                message: "unauthorized".into()
            }
        );
    }

    #[test]
    fn api_error_display_is_readable() {
        assert_eq!(
            ApiError::Status {
                code: 409,
                message: "conflict".into()
            }
            .to_string(),
            "HTTP 409: conflict"
        );
        assert_eq!(
            ApiError::Network("boom".into()).to_string(),
            "network error: boom"
        );
    }
}
