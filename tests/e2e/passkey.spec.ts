import { test, expect, type Page, type CDPSession } from '@playwright/test';
import { authenticator } from 'otplib';

// passkey (WebAuthn 第2要素) のハッピーパス e2e。**Chromium 限定** — Playwright の仮想認証器は
// CDP (Chromium) でのみ提供される。RP ID は IP リテラルだとブラウザが拒否するため、本 spec は
// localhost オリジン (playwright.config.ts の chromium プロジェクトの baseURL) で実行する。
//
// 検証する流れ: signup+login(TOTP) → パスキー登録 → ログアウト → 再ログイン (パスワード) →
// 2FA 段で「パスキーで認証」→ DK アンロック → Ledger 到達。passkey は鍵に触れず 2FA を通すだけ。

function secretFromUri(uri: string): string {
  const s = new URL(uri).searchParams.get('secret');
  if (!s) throw new Error(`provisioning URI に secret がありません: ${uri}`);
  return s;
}

function totpCode(secret: string, offsetMs = 0): string {
  authenticator.options = { epoch: Date.now() + offsetMs };
  const code = authenticator.generate(secret);
  authenticator.resetOptions();
  return code;
}

// CDP 仮想認証器を有効化する (ctap2 / internal / 常時 user-verified なプラットフォーム認証器)。
async function addVirtualAuthenticator(page: Page): Promise<CDPSession> {
  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return client;
}

test('register a passkey and use it as the second factor at login', async ({ page }) => {
  const email = `e2e-passkey-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  const password = 'correct horse battery staple';

  await page.goto('/');
  // 仮想認証器を登録 create() の前に有効化しておく。
  await addVirtualAuthenticator(page);

  // --- signup (TOTP 必須) ---
  await page.getByTestId('tab-signup').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.getByRole('button', { name: '登録' }).click();
  const uri = await page.getByTestId('totp-uri').textContent({ timeout: 30_000 });
  const secret = secretFromUri(uri!);
  await page.getByLabel('TOTP コード').fill(totpCode(secret));
  await page.getByRole('button', { name: '確認' }).click();
  await expect(page.getByTestId('signup-done')).toBeVisible({ timeout: 15_000 });

  // --- 初回ログインは TOTP で (replay 回避のため +1 step) ---
  await page.getByTestId('tab-login').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.locator('form').getByRole('button', { name: 'ログイン' }).click();
  await page.getByLabel('TOTP コード').fill(totpCode(secret, 30_000));
  await page.getByRole('button', { name: '確認' }).click();
  await expect(page.getByTestId('ledger-shell')).toBeVisible({ timeout: 30_000 });

  // --- パスキーを登録 (ログイン済み = TOTP gate 済み) ---
  await page.getByTestId('passkey-register').click();
  await expect(page.getByTestId('passkey-status')).toContainText('登録しました', {
    timeout: 30_000,
  });

  // --- ログアウト ---
  await page.getByTestId('logout').click();
  await expect(page.getByTestId('tab-login')).toBeVisible();

  // --- 再ログイン: パスワード → 2FA 段で「パスキーで認証」(TOTP コードは入力しない) ---
  await page.getByTestId('tab-login').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.locator('form').getByRole('button', { name: 'ログイン' }).click();
  // passkey 登録済みなので factors に passkey が含まれ、ボタンが出る。
  const passkeyBtn = page.getByTestId('passkey-auth');
  await expect(passkeyBtn).toBeVisible({ timeout: 30_000 });
  await passkeyBtn.click();

  // assertion 成功 → SessionResponse の blob を wrapKey でアンロック → Ledger 到達。
  await expect(page.getByTestId('ledger-shell')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId('ledger-welcome')).toContainText(email);
});
