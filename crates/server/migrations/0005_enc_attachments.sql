-- 証憑(添付)バイナリのメタ行。バイナリ本体は S3 互換ストレージ (versitygw 等) に
-- 不透明な暗号 blob として置き、ここにはメタのみ持つ (CLAUDE.md: enc_attachments 行はメタのみ)。
-- 財務平文は持たない。所有権はオブジェクトキー "{user_id}/{attachment_id}" の prefix で構造的に分離する。
-- ct_size は 256B バケットへ丸めた blob サイズ (漏洩緩和)。chunked AEAD のゼロ詰めで真サイズは 64KiB 粒度。
CREATE TABLE enc_attachments (
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attachment_id UUID NOT NULL,
    ct_size       INT  NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, attachment_id)
);
