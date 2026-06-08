//! クライアント側の鍵管理グルー (auth ceremony のクライアント半分)。
//!
//! 不変条件 (CLAUDE.md): MK/DK/wrapKey/recovery code はサーバーへ送らない。サーバーへ出るのは
//! `auth_key` のみ。DK はメモリ上にのみ保持する。暗号は `iikanji_crypto` 経由のみ。

use iikanji_crypto::{
    derive_pmk, generate_salt, unwrap_data_key, unwrap_master_key_with_password, wrap_data_key,
    wrap_master_key_with_password, wrap_master_key_with_recovery, DataKey, KdfParams, MasterKey,
    RecoveryCode, Result, WrapKey,
};
use iikanji_types::{KeyBlobs, SignupRequest};

/// recovery code 由来 Argon2id の salt。recovery code が 160-bit と高エントロピーのため
/// 固定 salt で許容する (Argon2 は belt-and-suspenders)。recovery エンドポイント実装時に
/// per-user salt 化を検討。
const RECOVERY_SALT: &[u8] = b"iikanji/recovery-salt/v1";

/// signup の成果物。`request` をサーバーへ送り、`recovery_code` を一度だけ表示、
/// `data_key` をメモリ保持する。
pub struct SignupOutput {
    pub request: SignupRequest,
    pub recovery_code: String,
    pub data_key: DataKey,
}

/// email + password から signup ペイロードを構築する。MK/DK/recovery を生成し、
/// password 鍵 / recovery 鍵で MK を二重ラップ、MK で DK をラップする。
pub fn build_signup(email: &str, password: &str, kdf_version: u8) -> Result<SignupOutput> {
    let params = KdfParams::from_version(kdf_version)?;
    let salt_pw = generate_salt();
    let pmk = derive_pmk(password.as_bytes(), &salt_pw, params)?;
    let auth_key = pmk.auth_key().expose_bytes().to_vec();
    let wrap_key = pmk.wrap_key();

    let mk = MasterKey::generate();
    let dk = DataKey::generate();

    let mk_pw = wrap_master_key_with_password(&wrap_key, &mk, kdf_version);
    let dk_wrap = wrap_data_key(&mk, &dk);

    let recovery = RecoveryCode::generate();
    let recovery_key = recovery.derive_key(RECOVERY_SALT, params)?;
    let mk_recovery = wrap_master_key_with_recovery(&recovery_key, &mk);

    Ok(SignupOutput {
        request: SignupRequest {
            email: email.to_string(),
            salt_pw: salt_pw.to_vec(),
            kdf_version,
            auth_key,
            key_blobs: KeyBlobs {
                mk_pw,
                mk_recovery,
                dk_wrap,
            },
        },
        recovery_code: recovery.display(),
        data_key: dk,
    })
}

/// login 第1段の鍵。`auth_key` をサーバーへ送り、`wrap_key` は 2FA 通過後の unlock 用に保持する。
pub struct LoginKeys {
    auth_key: Vec<u8>,
    wrap_key: WrapKey,
}

impl LoginKeys {
    /// サーバーへ送る login 証明 (HKDF(PMK))。
    pub fn auth_key(&self) -> &[u8] {
        &self.auth_key
    }
}

/// login 第1段: salt + kdf_version (login/begin で取得) から authKey と wrapKey を導出する。
pub fn derive_login(password: &str, salt_pw: &[u8], kdf_version: u8) -> Result<LoginKeys> {
    let params = KdfParams::from_version(kdf_version)?;
    let pmk = derive_pmk(password.as_bytes(), salt_pw, params)?;
    Ok(LoginKeys {
        auth_key: pmk.auth_key().expose_bytes().to_vec(),
        wrap_key: pmk.wrap_key(),
    })
}

/// 2FA 通過後: SessionResponse の `mk_pw` / `dk_wrap` blob から DK を復元する (メモリ保持)。
pub fn unlock_data_key(
    keys: &LoginKeys,
    mk_pw_blob: &[u8],
    dk_wrap_blob: &[u8],
) -> Result<DataKey> {
    let mk = unwrap_master_key_with_password(&keys.wrap_key, mk_pw_blob)?;
    unwrap_data_key(&mk, dk_wrap_blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iikanji_crypto::{decrypt_record, encrypt_record, hash_auth_key, verify_auth_key, AuthKey};

    fn arr(v: &[u8]) -> [u8; 32] {
        <[u8; 32]>::try_from(v).unwrap()
    }

    #[test]
    fn signup_login_unlock_roundtrip() {
        // signup (kdf_version=1 = INTERACTIVE_V1。版が round-trip する必要があるため fast 不可)。
        let out = build_signup("a@b.c", "correct horse", 1).unwrap();
        assert_eq!(out.request.auth_key.len(), 32);
        assert!(out.recovery_code.contains('-'));

        // クライアントが signup の DK で暗号化したレコード。
        let id = [1u8; 16];
        let ct = encrypt_record(&out.data_key, 1, &id, 1, b"date:2026,amount:1000");

        // サーバーが保存するもの: auth_hash + key_blobs。
        let auth_hash = hash_auth_key(
            &AuthKey::from_wire_bytes(arr(&out.request.auth_key)),
            KdfParams::SERVER_V1,
        )
        .unwrap();
        let blobs = &out.request.key_blobs;

        // login: 同じ password で authKey/wrapKey を再導出。
        let lk = derive_login(
            "correct horse",
            &out.request.salt_pw,
            out.request.kdf_version,
        )
        .unwrap();
        // サーバーが authKey を検証。
        assert!(
            verify_auth_key(&AuthKey::from_wire_bytes(arr(lk.auth_key())), &auth_hash).unwrap()
        );
        // 2FA 通過後、blob から DK を復元。
        let dk = unlock_data_key(&lk, &blobs.mk_pw, &blobs.dk_wrap).unwrap();
        // 復元した DK で signup 時の ciphertext を復号できる。
        assert_eq!(
            decrypt_record(&dk, 1, &id, 1, &ct).unwrap(),
            b"date:2026,amount:1000"
        );

        // 誤 password → authKey 不一致 + unlock 失敗。
        let bad = derive_login("wrong", &out.request.salt_pw, out.request.kdf_version).unwrap();
        assert!(
            !verify_auth_key(&AuthKey::from_wire_bytes(arr(bad.auth_key())), &auth_hash).unwrap()
        );
        assert!(unlock_data_key(&bad, &blobs.mk_pw, &blobs.dk_wrap).is_err());
    }

    #[test]
    fn recovery_code_unwraps_master_key() {
        // signup の mk_recovery blob が、表示された recovery code から復元できる。
        let out = build_signup("a@b.c", "pw", 1).unwrap();
        let parsed = RecoveryCode::parse(&out.recovery_code).unwrap();
        let rkey = parsed
            .derive_key(RECOVERY_SALT, KdfParams::from_version(1).unwrap())
            .unwrap();
        // recovery 鍵で MK を復元 → DK をアンラップできる。
        let mk = iikanji_crypto::unwrap_master_key_with_recovery(
            &rkey,
            &out.request.key_blobs.mk_recovery,
        )
        .unwrap();
        assert!(unwrap_data_key(&mk, &out.request.key_blobs.dk_wrap).is_ok());
    }
}
