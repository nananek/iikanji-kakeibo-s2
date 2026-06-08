import { test, expect } from '@playwright/test';
import { authenticator } from 'otplib';

function secretFromUri(uri: string): string {
  const s = new URL(uri).searchParams.get('secret');
  if (!s) throw new Error(`provisioning URI に secret がありません: ${uri}`);
  return s;
}

// offsetMs 後の時刻で TOTP を生成する。signup 確認で消費した step を login 2FA で再利用すると
// サーバーの replay 防止 (last_used_step) に弾かれるため、login 側は +1 step (30s 先) を用いる。
function totpCode(secret: string, offsetMs = 0): string {
  authenticator.options = { epoch: Date.now() + offsetMs };
  const code = authenticator.generate(secret);
  authenticator.resetOptions();
  return code;
}

// signup → login の往復を実ブラウザ + 実サーバーで通す。login では
// derive_login → login_verify → totp_2fa → unlock_data_key (DK 復元) →
// セッショントークンで /sync/cursor を叩いて疎通確認、までを検証する。
test('login ceremony unlocks DK and authenticates a session', async ({ page }) => {
  await page.goto('/');
  const email = `e2e-login-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  const password = 'correct horse battery staple';

  // --- signup でアカウントを用意 ---
  await page.getByTestId('tab-signup').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.getByRole('button', { name: '登録' }).click();
  const uri = await page.getByTestId('totp-uri').textContent({ timeout: 30_000 });
  const secret = secretFromUri(uri!);
  await page.getByLabel('TOTP コード').fill(totpCode(secret));
  await page.getByRole('button', { name: '確認' }).click();
  await expect(page.getByTestId('signup-done')).toBeVisible({ timeout: 15_000 });

  // --- login で DK アンロック + セッション ---
  await page.getByTestId('tab-login').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  // 送信ボタン「ログイン」はタブ「ログイン」と名前が重複するため form に限定する。
  await page.locator('form').getByRole('button', { name: 'ログイン' }).click();
  // replay 回避のため +1 step。
  await page.getByLabel('TOTP コード').fill(totpCode(secret, 30_000));
  await page.getByRole('button', { name: '確認' }).click();

  const done = page.getByTestId('login-done');
  await expect(done).toBeVisible({ timeout: 30_000 });
  await expect(done).toContainText('同期カーソル');
});
