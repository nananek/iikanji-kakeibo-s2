-- 2FA 通過後に発行するセッション (トークンはハッシュのみ保存)。
CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions (user_id);

-- 2FA (login_token) のブルートフォース緩和: トークン単位の失敗回数。
ALTER TABLE pending_logins ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0;
