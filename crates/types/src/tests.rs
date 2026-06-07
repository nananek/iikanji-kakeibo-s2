//! serde ラウンドトリップと base64 表現の検証。

use crate::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

fn roundtrip<T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug>(value: &T) -> String {
    let json = serde_json::to_string(value).unwrap();
    let back: T = serde_json::from_str(&json).unwrap();
    assert_eq!(*value, back, "round-trip mismatch");
    json
}

#[test]
fn signup_request_roundtrip_uses_base64() {
    let req = SignupRequest {
        email: "a@example.com".into(),
        salt_pw: vec![1, 2, 3, 250, 251, 255],
        kdf_version: 1,
        auth_key: vec![9; 32],
        key_blobs: KeyBlobs {
            mk_pw: vec![0x4B, 0x31, 1, 2],
            mk_recovery: vec![5, 6, 7],
            dk_wrap: vec![8, 9, 10],
        },
    };
    let json = roundtrip(&req);
    // バイト列は base64 文字列 (JSON 配列ではない)。
    assert!(json.contains("\"salt_pw\":\""));
    assert!(!json.contains("[1,2,3"));
}

#[test]
fn login_dtos_roundtrip() {
    roundtrip(&LoginBeginRequest {
        email: "x@y.z".into(),
    });
    roundtrip(&LoginBeginResponse {
        salt_pw: vec![1, 2, 3, 4],
        kdf_version: 2,
    });
    roundtrip(&LoginVerifyRequest {
        email: "x@y.z".into(),
        auth_key: vec![7; 32],
    });
    let resp = LoginVerifyResponse {
        login_token: "tok".into(),
        factors: vec![Factor::Totp, Factor::Passkey],
    };
    let json = roundtrip(&resp);
    assert!(json.contains("\"totp\""));
    assert!(json.contains("\"passkey\""));

    roundtrip(&TotpVerifyRequest {
        login_token: "tok".into(),
        code: "123456".into(),
    });
    roundtrip(&SessionResponse {
        session_token: "s".into(),
        mk_pw: vec![1, 2],
        dk_wrap: vec![3, 4],
        sync_cursor: 42,
    });
}

#[test]
fn debug_redacts_secrets() {
    // auth_key 等の機密はログに出さない (バイト長のみ)。
    let req = LoginVerifyRequest {
        email: "a@b.c".into(),
        auth_key: vec![0xAB; 32],
    };
    let s = format!("{req:?}");
    assert!(s.contains("redacted"), "auth_key must be redacted: {s}");
    assert!(s.contains("a@b.c"), "non-secret email shown");
    assert!(!s.contains("171"), "raw byte value must not appear"); // 0xAB

    // session_token / blob も伏せる、sync_cursor は出す。
    let sess = SessionResponse {
        session_token: "supersecrettoken".into(),
        mk_pw: vec![1, 2, 3],
        dk_wrap: vec![4, 5],
        sync_cursor: 7,
    };
    let s = format!("{sess:?}");
    assert!(!s.contains("supersecrettoken"), "token must not leak: {s}");
    assert!(s.contains("redacted"));
    assert!(s.contains('7'), "sync_cursor shown");

    // KeyBlobs 単体も redact。
    let blobs = KeyBlobs {
        mk_pw: vec![9; 60],
        mk_recovery: vec![8; 60],
        dk_wrap: vec![7; 60],
    };
    assert!(format!("{blobs:?}").contains("redacted"));
}

#[test]
fn enc_record_tombstone_has_null_ciphertext() {
    let live = EncRecord {
        record_id: Uuid::from_u128(1),
        record_type: 1,
        version: 3,
        seq: 100,
        tombstone: false,
        ciphertext: Some(vec![0x4B, 0x31, 1]),
    };
    let json = roundtrip(&live);
    assert!(json.contains("\"ciphertext\":\""));

    let dead = EncRecord {
        record_id: Uuid::from_u128(2),
        record_type: 1,
        version: 4,
        seq: 101,
        tombstone: true,
        ciphertext: None,
    };
    let json = roundtrip(&dead);
    assert!(json.contains("\"ciphertext\":null"));
}

#[test]
fn push_pull_dtos_roundtrip() {
    let push = PushRequest {
        changes: vec![
            PushChange {
                record_id: Uuid::from_u128(1),
                record_type: 1,
                expected_version: 0,
                tombstone: false,
                ciphertext: Some(vec![1, 2, 3]),
            },
            PushChange {
                record_id: Uuid::from_u128(2),
                record_type: 2,
                expected_version: 5,
                tombstone: true,
                ciphertext: None,
            },
        ],
    };
    roundtrip(&push);

    let resp = PushResponse {
        results: vec![
            PushResult {
                record_id: Uuid::from_u128(1),
                status: PushStatus::Applied,
                new_version: 1,
                seq: 10,
                server_record: None,
            },
            PushResult {
                record_id: Uuid::from_u128(2),
                status: PushStatus::Conflict,
                new_version: 5,
                seq: 9,
                server_record: Some(EncRecord {
                    record_id: Uuid::from_u128(2),
                    record_type: 2,
                    version: 5,
                    seq: 9,
                    tombstone: false,
                    ciphertext: Some(vec![9, 9]),
                }),
            },
        ],
        new_cursor: 10,
    };
    let json = roundtrip(&resp);
    assert!(json.contains("\"applied\""));
    assert!(json.contains("\"conflict\""));

    roundtrip(&PullResponse {
        records: vec![],
        next_cursor: 0,
        has_more: false,
    });
}
