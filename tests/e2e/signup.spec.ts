import { test, expect } from '@playwright/test';
import { authenticator } from 'otplib';

// otplib authenticator の既定 (SHA1 / 6 桁 / 30 秒) はサーバー crypto/totp.rs と一致。
function totpSecretFromUri(uri: string): string {
  const u = new URL(uri);
  const secret = u.searchParams.get('secret');
  if (!secret) throw new Error(`provisioning URI に secret がありません: ${uri}`);
  return secret;
}

// E2EE signup ceremony を実ブラウザ + 実サーバーで通す:
// email/password → Argon2id + 鍵生成 + signup → provisioning URI/recovery 表示 → TOTP 確認。
test('signup ceremony enrolls account + TOTP end-to-end', async ({ page }) => {
  await page.goto('/');

  // メールはユニークにして再実行/並列での衝突を避ける。
  const email = `e2e-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill('correct horse battery staple');
  await page.getByRole('button', { name: '登録' }).click();

  // Argon2id (64MiB) + signup 完了で provisioning URI が表示される。
  const uri = await page.getByTestId('totp-uri').textContent({ timeout: 30_000 });
  expect(uri ?? '').toContain('otpauth://');
  // recovery code も一度だけ表示される。
  await expect(page.getByTestId('recovery-code')).toBeVisible();

  // 認証アプリ相当: secret から TOTP コードを生成して確認する。
  const code = authenticator.generate(totpSecretFromUri(uri!));
  await page.getByLabel('TOTP コード').fill(code);
  await page.getByRole('button', { name: '確認' }).click();

  await expect(page.getByTestId('signup-done')).toBeVisible({ timeout: 15_000 });
});
