//! 同期エンドポイントの統合テスト + E2EE 境界テスト。`DATABASE_URL`(Postgres) が必要。

mod common;

use axum::http::StatusCode;
use common::{authenticate, request, test_app, test_pool};
use iikanji_crypto::{decrypt_record, encrypt_record, DataKey};
use iikanji_types::{EncRecord, PushChange, PushRequest};
use serde_json::Value;
use uuid::Uuid;

fn push_body(changes: Vec<PushChange>) -> Value {
    serde_json::to_value(PushRequest { changes }).unwrap()
}

fn change(rid: Uuid, expected_version: u32, ciphertext: Vec<u8>) -> PushChange {
    PushChange {
        record_id: rid,
        record_type: 1,
        expected_version,
        tombstone: false,
        ciphertext: Some(ciphertext),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn sync_requires_auth() {
    let app = test_app().await;
    let (s, _) = request(&app, "POST", "/sync/push", None, Some(&push_body(vec![]))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = request(&app, "GET", "/sync/cursor", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = request(&app, "GET", "/sync/cursor", Some("bad-token"), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn push_pull_cas_roundtrip() {
    let app = test_app().await;
    let token = authenticate(&app).await;
    let rid = Uuid::from_u128(1);

    // 初期 cursor は 0
    let (s, c) = request(&app, "GET", "/sync/cursor", Some(&token), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(c["cursor"], 0);

    // 新規 push (expected_version 0) → applied v1 seq1
    let (s, r) = request(
        &app,
        "POST",
        "/sync/push",
        Some(&token),
        Some(&push_body(vec![change(rid, 0, vec![1, 2, 3])])),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["results"][0]["status"], "applied");
    assert_eq!(r["results"][0]["new_version"], 1);
    assert_eq!(r["results"][0]["seq"], 1);
    assert_eq!(r["new_cursor"], 1);

    // pull since 0 → 1 件
    let (s, p) = request(&app, "GET", "/sync/pull?since=0", Some(&token), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(p["records"].as_array().unwrap().len(), 1);
    assert_eq!(p["records"][0]["version"], 1);
    assert_eq!(p["has_more"], false);
    assert_eq!(p["next_cursor"], 1);

    // 更新 (expected_version 1) → applied v2 seq2
    let (_, r) = request(
        &app,
        "POST",
        "/sync/push",
        Some(&token),
        Some(&push_body(vec![change(rid, 1, vec![4, 5, 6])])),
    )
    .await;
    assert_eq!(r["results"][0]["status"], "applied");
    assert_eq!(r["results"][0]["new_version"], 2);
    assert_eq!(r["results"][0]["seq"], 2);

    // 古い expected_version → conflict + 現行 server_record
    let (_, r) = request(
        &app,
        "POST",
        "/sync/push",
        Some(&token),
        Some(&push_body(vec![change(rid, 1, vec![9, 9])])),
    )
    .await;
    assert_eq!(r["results"][0]["status"], "conflict");
    assert_eq!(r["results"][0]["new_version"], 2);
    assert_eq!(r["results"][0]["server_record"]["version"], 2);

    // conflict は seq を消費しない → cursor はまだ 2
    let (_, c) = request(&app, "GET", "/sync/cursor", Some(&token), None).await;
    assert_eq!(c["cursor"], 2);

    // pull since 1 → seq2 のみ
    let (_, p) = request(&app, "GET", "/sync/pull?since=1", Some(&token), None).await;
    assert_eq!(p["records"].as_array().unwrap().len(), 1);
    assert_eq!(p["records"][0]["seq"], 2);
    assert_eq!(p["records"][0]["version"], 2);
}

#[tokio::test]
async fn tombstone_push_and_pull() {
    let app = test_app().await;
    let token = authenticate(&app).await;
    let rid = Uuid::from_u128(42);

    // 作成 → v1
    let (_, r) = request(
        &app,
        "POST",
        "/sync/push",
        Some(&token),
        Some(&push_body(vec![change(rid, 0, vec![1, 2, 3])])),
    )
    .await;
    assert_eq!(r["results"][0]["new_version"], 1);

    // tombstone (expected_version 1, ciphertext なし) → v2
    let tomb = PushChange {
        record_id: rid,
        record_type: 1,
        expected_version: 1,
        tombstone: true,
        ciphertext: None,
    };
    let (_, r) = request(
        &app,
        "POST",
        "/sync/push",
        Some(&token),
        Some(&push_body(vec![tomb])),
    )
    .await;
    assert_eq!(r["results"][0]["status"], "applied");
    assert_eq!(r["results"][0]["new_version"], 2);

    // pull → tombstone=true, ciphertext=null
    let (_, p) = request(&app, "GET", "/sync/pull?since=0", Some(&token), None).await;
    assert_eq!(p["records"][0]["tombstone"], true);
    assert_eq!(p["records"][0]["ciphertext"], Value::Null);
}

#[tokio::test]
async fn e2ee_boundary_no_plaintext_reaches_db() {
    let app = test_app().await;
    let token = authenticate(&app).await;
    let pool = test_pool().await;

    // クライアントが暗号化したレコードを push する (サーバーは平文を一切受け取らない)。
    let dk = DataKey::generate();
    // record_id は per-user PK で大域一意ではない。直読みクエリのため run ごとに一意化する。
    let rid = Uuid::new_v4();
    let id = *rid.as_bytes();
    let plaintext = b"PATIENT:John Doe|amount:99999|date:2026-06-08";
    let ct = encrypt_record(&dk, 4, &id, 1, plaintext);

    let ch = PushChange {
        record_id: rid,
        record_type: 4,
        expected_version: 0,
        tombstone: false,
        ciphertext: Some(ct.clone()),
    };
    let (s, _) = request(
        &app,
        "POST",
        "/sync/push",
        Some(&token),
        Some(&push_body(vec![ch])),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // DB ダンプ: enc_records.ciphertext を直接読み、平文マーカーが現れないことを保証。
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT ciphertext FROM enc_records WHERE record_id = $1")
            .bind(rid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, ct, "server stores ciphertext verbatim");
    assert!(
        !contains(&stored, b"PATIENT"),
        "plaintext marker must not appear in DB"
    );
    assert!(!contains(&stored, b"John"));
    assert!(!contains(&stored, b"99999"));

    // pull で取り出した ciphertext をクライアント鍵で復号できる (E2EE 往復)。
    let (_, p) = request(&app, "GET", "/sync/pull?since=0", Some(&token), None).await;
    let rec: EncRecord = serde_json::from_value(p["records"][0].clone()).unwrap();
    let decrypted = decrypt_record(&dk, 4, &id, 1, rec.ciphertext.as_ref().unwrap()).unwrap();
    assert_eq!(decrypted, plaintext);
}
