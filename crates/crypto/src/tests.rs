//! KAT / ラウンドトリップ / 不変条件テスト。
//! 高コストな Argon2id を避けるため KDF 系は `fast()` パラメータを使う (本番は INTERACTIVE_V1)。

use crate::*;
// envelope は private モジュールだが、文脈束縛の単体テストのため明示的に参照する。
use crate::envelope;

/// テスト専用の高速 Argon2id パラメータ (16 KiB, t=1)。本番では使わない。
fn fast() -> KdfParams {
    KdfParams {
        m_cost: 16,
        t_cost: 1,
        p_cost: 1,
    }
}

#[test]
fn envelope_roundtrip_and_tamper_and_context() {
    let dk = DataKey::generate();
    let id = [7u8; 16];
    let blob = encrypt_record(&dk, 1, &id, 1, b"amount:1000");
    assert_eq!(
        decrypt_record(&dk, 1, &id, 1, &blob).unwrap(),
        b"amount:1000"
    );

    // ciphertext 改竄 -> AeadOpen
    let mut tampered = blob.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(matches!(
        decrypt_record(&dk, 1, &id, 1, &tampered),
        Err(CryptoError::AeadOpen)
    ));

    // 文脈不一致 (version / type / record_id) -> AeadOpen
    assert!(matches!(
        decrypt_record(&dk, 1, &id, 2, &blob),
        Err(CryptoError::AeadOpen)
    ));
    assert!(matches!(
        decrypt_record(&dk, 2, &id, 1, &blob),
        Err(CryptoError::AeadOpen)
    ));
    assert!(matches!(
        decrypt_record(&dk, 1, &[8u8; 16], 1, &blob),
        Err(CryptoError::AeadOpen)
    ));

    // ヘッダ改竄 (magic) -> Envelope
    let mut bad = blob.clone();
    bad[0] ^= 0x01;
    assert!(matches!(
        decrypt_record(&dk, 1, &id, 1, &bad),
        Err(CryptoError::Envelope(_))
    ));

    // 別の DK では開けない
    let other = DataKey::generate();
    assert!(decrypt_record(&other, 1, &id, 1, &blob).is_err());
}

#[test]
fn context_binding_with_identical_key() {
    // 鍵が同一でも purpose (context) が違えば開けない。サーバーの blob すり替え検出の核。
    let key = [4u8; 32];
    let blob = envelope::seal(&key, 0, &envelope::context::mk_pw(), b"secret");
    assert!(envelope::open(&key, &envelope::context::mk_recovery(), &blob).is_err());
    assert!(envelope::open(&key, &envelope::context::dk_wrap(), &blob).is_err());
    assert_eq!(
        envelope::open(&key, &envelope::context::mk_pw(), &blob).unwrap(),
        b"secret"
    );
}

#[test]
fn pmk_derivation_deterministic() {
    let salt = [1u8; 16];
    let a = derive_pmk(b"correct horse", &salt, fast()).unwrap();
    let b = derive_pmk(b"correct horse", &salt, fast()).unwrap();
    assert_eq!(a.auth_key().expose_bytes(), b.auth_key().expose_bytes());

    // salt が違えば authKey も違う
    let c = derive_pmk(b"correct horse", &[2u8; 16], fast()).unwrap();
    assert_ne!(a.auth_key().expose_bytes(), c.auth_key().expose_bytes());
    // password が違えば authKey も違う
    let d = derive_pmk(b"wrong", &salt, fast()).unwrap();
    assert_ne!(a.auth_key().expose_bytes(), d.auth_key().expose_bytes());
}

#[test]
fn full_signup_then_login_flow() {
    let salt_pw = [9u8; 16];

    // --- signup ---
    let pmk = derive_pmk(b"correct horse battery staple", &salt_pw, fast()).unwrap();
    let mk = MasterKey::generate();
    let dk = DataKey::generate();
    let mk_pw_blob = wrap_master_key_with_password(&pmk.wrap_key(), &mk, 1);
    let dk_blob = wrap_data_key(&mk, &dk);
    let id = [3u8; 16];
    let record = encrypt_record(&dk, 1, &id, 1, b"date:2026-06-07,amount:1234");

    // --- login (別セッション): password+salt から PMK を再導出して鍵を復元 ---
    let pmk2 = derive_pmk(b"correct horse battery staple", &salt_pw, fast()).unwrap();
    let mk2 = unwrap_master_key_with_password(&pmk2.wrap_key(), &mk_pw_blob).unwrap();
    let dk2 = unwrap_data_key(&mk2, &dk_blob).unwrap();
    assert_eq!(
        decrypt_record(&dk2, 1, &id, 1, &record).unwrap(),
        b"date:2026-06-07,amount:1234"
    );

    // 誤パスワードでは MK を開けない
    let bad = derive_pmk(b"WRONG", &salt_pw, fast()).unwrap();
    assert!(unwrap_master_key_with_password(&bad.wrap_key(), &mk_pw_blob).is_err());
}

#[test]
fn blob_swap_across_purposes_is_rejected() {
    let mk = MasterKey::generate();

    // password-wrapped MK
    let pmk = derive_pmk(b"pw", &[1u8; 16], fast()).unwrap();
    let pw_blob = wrap_master_key_with_password(&pmk.wrap_key(), &mk, 1);

    // recovery-wrapped MK
    let code = RecoveryCode::generate();
    let rkey = code.derive_key(&[5u8; 16], fast()).unwrap();
    let rec_blob = wrap_master_key_with_recovery(&rkey, &mk);

    // 用途を取り違えると (鍵 or 文脈の不一致で) 必ず失敗する
    assert!(unwrap_master_key_with_recovery(&rkey, &pw_blob).is_err());
    assert!(unwrap_master_key_with_password(&pmk.wrap_key(), &rec_blob).is_err());

    // 正しい用途なら同一 MK が得られる (DK ラップ往復で確認)
    let dk = DataKey::generate();
    let dk_blob = wrap_data_key(&mk, &dk);
    let mk_from_pw = unwrap_master_key_with_password(&pmk.wrap_key(), &pw_blob).unwrap();
    let mk_from_rec = unwrap_master_key_with_recovery(&rkey, &rec_blob).unwrap();
    assert!(unwrap_data_key(&mk_from_pw, &dk_blob).is_ok());
    assert!(unwrap_data_key(&mk_from_rec, &dk_blob).is_ok());
}

#[test]
fn recovery_code_roundtrip_and_normalization() {
    let code = RecoveryCode::generate();
    let shown = code.display();
    assert!(shown.contains('-'));
    assert_eq!(shown.chars().filter(|c| *c != '-').count(), 36);

    // 正確なパース
    assert!(RecoveryCode::parse(&shown).is_ok());

    // 正規化: 小文字 + ハイフン→空白
    let messy = shown.to_lowercase().replace('-', " ");
    let parsed = RecoveryCode::parse(&messy).unwrap();

    // 同じコードからは同じ RecoveryKey が導出される (MK ラップ往復で確認)
    let salt = [1u8; 16];
    let k1 = code.derive_key(&salt, fast()).unwrap();
    let k2 = parsed.derive_key(&salt, fast()).unwrap();
    let mk = MasterKey::generate();
    let blob = wrap_master_key_with_recovery(&k1, &mk);
    assert!(unwrap_master_key_with_recovery(&k2, &blob).is_ok());

    // チェックサム破壊 -> エラー
    let mut chars: Vec<char> = shown.chars().filter(|c| *c != '-').collect();
    let li = chars.len() - 1;
    chars[li] = if chars[li] == '0' { '1' } else { '0' };
    let corrupted: String = chars.into_iter().collect();
    assert!(RecoveryCode::parse(&corrupted).is_err());

    // 長さ不正 -> エラー
    assert!(RecoveryCode::parse("TOOSHORT").is_err());
}

#[test]
fn server_auth_hash_roundtrip() {
    let salt = [2u8; 16];
    let auth = derive_pmk(b"pw", &salt, fast()).unwrap().auth_key();
    let phc = hash_auth_key(&auth, fast()).unwrap();

    assert!(verify_auth_key(&auth, &phc).unwrap());

    // 別 authKey では検証失敗
    let other = derive_pmk(b"different", &salt, fast()).unwrap().auth_key();
    assert!(!verify_auth_key(&other, &phc).unwrap());

    // 壊れた PHC はエラー
    assert!(verify_auth_key(&auth, "not-a-phc-string").is_err());
}

#[test]
fn password_change_rewraps_mk_without_re_encrypting_data() {
    let salt_old = [1u8; 16];
    let salt_new = [2u8; 16];

    // 初期状態
    let pmk_old = derive_pmk(b"old-password", &salt_old, fast()).unwrap();
    let mk = MasterKey::generate();
    let dk = DataKey::generate();
    let dk_blob = wrap_data_key(&mk, &dk);
    let id = [1u8; 16];
    let record = encrypt_record(&dk, 1, &id, 1, b"sensitive");
    let _mk_pw_old = wrap_master_key_with_password(&pmk_old.wrap_key(), &mk, 1);

    // パスワード変更: MK を旧 wrapKey で開き、新 wrapKey で再ラップするだけ
    let pmk_new = derive_pmk(b"new-password", &salt_new, fast()).unwrap();
    let mk_pw_new = wrap_master_key_with_password(&pmk_new.wrap_key(), &mk, 1);

    // 新パスワードで login -> DK blob と record は無変更のまま復号できる
    let pmk_login = derive_pmk(b"new-password", &salt_new, fast()).unwrap();
    let mk_login = unwrap_master_key_with_password(&pmk_login.wrap_key(), &mk_pw_new).unwrap();
    let dk_login = unwrap_data_key(&mk_login, &dk_blob).unwrap();
    assert_eq!(
        decrypt_record(&dk_login, 1, &id, 1, &record).unwrap(),
        b"sensitive"
    );

    // 旧パスワードでは新 blob を開けない
    assert!(unwrap_master_key_with_password(&pmk_old.wrap_key(), &mk_pw_new).is_err());
}

#[test]
fn keys_debug_is_redacted() {
    let mk = MasterKey::generate();
    let s = format!("{mk:?}");
    assert!(s.contains("redacted"));
    assert!(!s.contains('['));
}

#[test]
fn server_helpers_token_hash_and_dummy_salt() {
    // 不透明トークン: 64 hex 文字、ランダム (2 回で異なる)。
    let t1 = gen_opaque_token();
    let t2 = gen_opaque_token();
    assert_eq!(t1.len(), 64);
    assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(t1, t2);

    // hash_token: 決定的 32B。
    assert_eq!(hash_token(b"abc"), hash_token(b"abc"));
    assert_ne!(hash_token(b"abc"), hash_token(b"abd"));

    // dummy salt: 16B・決定的・email/secret で変わる。
    let secret = b"secret";
    assert_eq!(server_dummy_salt(secret, "a@x").len(), 16);
    assert_eq!(
        server_dummy_salt(secret, "a@x"),
        server_dummy_salt(secret, "a@x")
    );
    assert_ne!(
        server_dummy_salt(secret, "a@x"),
        server_dummy_salt(secret, "b@x")
    );
    assert_ne!(
        server_dummy_salt(secret, "a@x"),
        server_dummy_salt(b"other", "a@x")
    );
}

#[test]
fn totp_verify_replay_and_uri() {
    let secret = TotpSecret::generate();
    let t = 1_700_000_000u64;
    let code = secret.code_at(t).unwrap();
    assert_eq!(code.len(), 6);

    // 正しいコード → 消費 step を返す
    let used = secret.verify(&code, t, None).unwrap().expect("valid code");
    assert_eq!(used, t / 30);

    // replay: 消費済み step 以下は拒否
    assert_eq!(secret.verify(&code, t, Some(used)).unwrap(), None);

    // 桁数不正 → 拒否 (定数時間比較で長さ不一致)
    assert_eq!(secret.verify("12345", t, None).unwrap(), None);

    // プロビジョニング URI
    let uri = secret
        .provisioning_uri("いいかんじ家計簿", "acct@example.com")
        .unwrap();
    assert!(uri.starts_with("otpauth://totp/"));
    assert!(uri.contains("secret="));

    // base32 ラウンドトリップ (URI から復元 → 同じコード)
    let b32 = uri
        .split("secret=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let restored = TotpSecret::from_base32(b32).unwrap();
    assert_eq!(restored.code_at(t).unwrap(), code);
}

#[test]
fn at_rest_roundtrip_and_binding() {
    let key = derive_server_key(b"server-secret", b"totp-at-rest-v1");
    assert_eq!(key, derive_server_key(b"server-secret", b"totp-at-rest-v1")); // 決定的
    assert_ne!(key, derive_server_key(b"server-secret", b"other-info"));

    let blob = seal_at_rest(&key, b"totp/user", b"secret-bytes");
    assert_eq!(
        open_at_rest(&key, b"totp/user", &blob).unwrap(),
        b"secret-bytes"
    );
    // 文脈不一致・別鍵は失敗
    assert!(open_at_rest(&key, b"totp/other", &blob).is_err());
    assert!(open_at_rest(&derive_server_key(b"x", b"y"), b"totp/user", &blob).is_err());
}
