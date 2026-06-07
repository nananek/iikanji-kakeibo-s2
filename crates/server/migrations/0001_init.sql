-- 初期スキーマ。サーバーは財務平文を持たない: 業務データは enc_records.ciphertext のみ。
CREATE EXTENSION IF NOT EXISTS citext;

-- 認証 (Bitwarden 方式)。auth_hash は Argon2id(authKey) の PHC 文字列 (salt 内包)。
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       CITEXT UNIQUE NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    salt_pw     BYTEA NOT NULL,
    kdf_version INT  NOT NULL,
    auth_hash   TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- E2EE ラップ blob (ciphertext)。purpose = 'mk-pw' | 'mk-recovery' | 'dk-wrap'。
CREATE TABLE key_blobs (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL,
    blob       BYTEA NOT NULL,
    version    INT  NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, purpose)
);

-- per-user 単調カーソル (グローバル SERIAL は使わない)。
CREATE TABLE user_seq (
    user_id  UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    next_seq BIGINT NOT NULL DEFAULT 1
);

-- login 第2段の成功後に発行する 2FA-pending トークン (ハッシュのみ保存)。
CREATE TABLE pending_logins (
    token_hash BYTEA PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- TOTP 秘密 (server master 鍵で at-rest 暗号化)。復号鍵ではない。
CREATE TABLE totp_secrets (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc     BYTEA NOT NULL,
    enabled        BOOLEAN NOT NULL DEFAULT false,
    last_used_step BIGINT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- WebAuthn 資格情報 (第2要素)。公開鍵は秘密ではない。
CREATE TABLE webauthn_credentials (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cred_id      BYTEA UNIQUE NOT NULL,
    public_key   BYTEA NOT NULL,
    sign_count   BIGINT NOT NULL DEFAULT 0,
    nickname     TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

-- 全財務レコードを不透明 blob として単一テーブルに格納。
CREATE TABLE enc_records (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    record_id   UUID NOT NULL,
    record_type SMALLINT NOT NULL,
    version     INT  NOT NULL,
    seq         BIGINT NOT NULL,
    tombstone   BOOLEAN NOT NULL DEFAULT false,
    ciphertext  BYTEA,
    ct_size     INT  NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, record_id)
);
CREATE INDEX idx_enc_records_sync ON enc_records (user_id, seq);
