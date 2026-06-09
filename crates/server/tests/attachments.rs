//! 証憑(添付)エンドポイントの統合テスト。`DATABASE_URL`(Postgres) が必要。ストレージは AppState の
//! 既定 in-memory backend を使う (versitygw は不要)。サーバーは blob を不透明に保存・返却するだけで
//! 復号しない — テストは暗号 bytes を put して同一 bytes が get できることを確認する。

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::*;
use http_body_util::BodyExt;
use iikanji_server::{router, AppState};
use tower::ServiceExt;
use uuid::Uuid;

/// raw bytes で PUT/GET/DELETE する (octet-stream)。`token=None` で Authorization 無し。
async fn raw_request(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let body = match body {
        Some(bytes) => {
            builder = builder.header("content-type", "application/octet-stream");
            Body::from(bytes)
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

fn uri(id: Uuid) -> String {
    format!("/attachments/{id}")
}

#[tokio::test]
async fn requires_session() {
    let app = test_app().await;
    let id = Uuid::new_v4();
    // Bearer 無し → 401。
    let (s, _) = raw_request(&app, "PUT", &uri(id), None, Some(b"blob".to_vec())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = raw_request(&app, "GET", &uri(id), None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // 不正トークン → 401。
    let (s, _) = raw_request(&app, "GET", &uri(id), Some("bad-token"), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn upload_download_roundtrip_preserves_bytes() {
    let app = test_app().await;
    let token = authenticate(&app).await;
    let id = Uuid::new_v4();
    // 暗号 blob 相当の任意 bytes (server は不透明に扱う)。
    let blob: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();

    let (s, _) = raw_request(&app, "PUT", &uri(id), Some(&token), Some(blob.clone())).await;
    assert_eq!(s, StatusCode::OK);

    let (s, body) = raw_request(&app, "GET", &uri(id), Some(&token), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, blob, "server は blob を一切改変せず返す");
}

#[tokio::test]
async fn download_missing_is_404() {
    let app = test_app().await;
    let token = authenticate(&app).await;
    let (s, _) = raw_request(&app, "GET", &uri(Uuid::new_v4()), Some(&token), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn other_users_attachment_is_404() {
    let app = test_app().await;
    let token_a = authenticate(&app).await;
    let token_b = authenticate(&app).await;
    let id = Uuid::new_v4();
    // A がアップロード。
    let (s, _) = raw_request(
        &app,
        "PUT",
        &uri(id),
        Some(&token_a),
        Some(b"a-secret".to_vec()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // B は同じ id を取得できない (キーは {user_id}/{id} で prefix 分離 → B には行が無い)。
    let (s, _) = raw_request(&app, "GET", &uri(id), Some(&token_b), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_then_download_is_404() {
    let app = test_app().await;
    let token = authenticate(&app).await;
    let id = Uuid::new_v4();
    raw_request(&app, "PUT", &uri(id), Some(&token), Some(b"blob".to_vec())).await;
    let (s, _) = raw_request(&app, "GET", &uri(id), Some(&token), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = raw_request(&app, "DELETE", &uri(id), Some(&token), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = raw_request(&app, "GET", &uri(id), Some(&token), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oversize_upload_is_413() {
    // 小さい上限のアプリを作り、超過 body が 413 になることを確認する。
    let mut st = AppState::new(test_pool().await, b"test-secret".to_vec());
    st.max_attachment_bytes = 64;
    let app = router(st);
    let token = authenticate(&app).await;
    let big = vec![0u8; 1024]; // 上限 64B を超過
    let (s, _) = raw_request(&app, "PUT", &uri(Uuid::new_v4()), Some(&token), Some(big)).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}
