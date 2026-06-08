-- TOTP confirm のブルートフォース緩和: アカウント単位の失敗回数カウンタ。
-- 一定回数を超えたら confirm をロックする (短命な pending_totp ウィンドウでの総当りを防ぐ)。
ALTER TABLE totp_secrets ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0;
