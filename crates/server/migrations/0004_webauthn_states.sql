-- WebAuthn (passkey) を第2要素として配線するための ceremony 途中状態。
-- passkey は復号鍵ではなくセッション/blob 解放を gate するだけ (CLAUDE.md invariant 3)。
-- webauthn-rs の PasskeyRegistration / PasskeyAuthentication を serde_json バイト列にして短命保存する。
-- 資格情報そのものは既存 webauthn_credentials テーブルに格納する (0001_init.sql、alter 不要):
--   public_key … 直列化した Passkey (公開鍵 + メタ) の serde_json バイト列
--   cred_id    … 一意制約 + 登録時 exclude リスト用
--   sign_count … 監査用の冗長カウンタ (正は Passkey 内部値)

-- passkey 登録途中状態 (PasskeyRegistration)。認証済みユーザーに 1:1 で束縛 (TOTP gate 済みセッション)。
CREATE TABLE webauthn_reg_states (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    state      BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- passkey 認証途中状態 (PasskeyAuthentication)。login_token のハッシュに束縛 (2FA pending login と 1:1)。
CREATE TABLE webauthn_auth_states (
    token_hash BYTEA PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state      BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
