import { test, expect, type Page, type CDPSession } from '@playwright/test';
import { authenticator } from 'otplib';

// passkey (WebAuthn 第2要素) のハッピーパス + 改竄拒否 e2e。**Chromium 限定** — Playwright の
// 仮想認証器は CDP (Chromium) でのみ提供される。RP ID は IP リテラルだとブラウザが拒否するため、
// 本 spec は localhost オリジン (playwright.config.ts の chromium プロジェクトの baseURL) で実行する。
//
// passkey は鍵に触れず 2FA を通すだけ。assertion が無効なら DK はアンロックされない。

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

// signup(TOTP) → 初回 TOTP ログイン → パスキー登録 → ログアウト まで進める。
// 戻り時はログイン画面で、当該アカウントにパスキーが 1 つ登録済みの状態。
async function signupLoginAndRegisterPasskey(
  page: Page,
  email: string,
  password: string,
): Promise<void> {
  await page.goto('/');
  // 登録 create() の前に仮想認証器を有効化しておく。
  await addVirtualAuthenticator(page);

  // signup (TOTP 必須)。
  await page.getByTestId('tab-signup').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.getByRole('button', { name: '登録' }).click();
  const uri = await page.getByTestId('totp-uri').textContent({ timeout: 30_000 });
  const secret = secretFromUri(uri!);
  await page.getByLabel('TOTP コード').fill(totpCode(secret));
  await page.getByRole('button', { name: '確認' }).click();
  await expect(page.getByTestId('signup-done')).toBeVisible({ timeout: 15_000 });

  // 初回ログインは TOTP で (replay 回避のため +1 step)。
  await page.getByTestId('tab-login').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.locator('form').getByRole('button', { name: 'ログイン' }).click();
  await page.getByLabel('TOTP コード').fill(totpCode(secret, 30_000));
  await page.getByRole('button', { name: '確認' }).click();
  await expect(page.getByTestId('ledger-shell')).toBeVisible({ timeout: 30_000 });

  // パスキーを登録 (ログイン済み = TOTP gate 済み) → ログアウト。
  await page.getByTestId('passkey-register').click();
  await expect(page.getByTestId('passkey-status')).toContainText('登録しました', {
    timeout: 30_000,
  });
  await page.getByTestId('logout').click();
  await expect(page.getByTestId('tab-login')).toBeVisible();
}

// パスワード入力 → 2FA 段まで進め、「パスキーで認証」ボタンを出す。
async function loginToSecondFactor(page: Page, email: string, password: string): Promise<void> {
  await page.getByTestId('tab-login').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.locator('form').getByRole('button', { name: 'ログイン' }).click();
  await expect(page.getByTestId('passkey-auth')).toBeVisible({ timeout: 30_000 });
}

const PASSWORD = 'correct horse battery staple';

test('register a passkey and use it as the second factor at login', async ({ page }) => {
  const email = `e2e-passkey-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  await signupLoginAndRegisterPasskey(page, email, PASSWORD);

  // 再ログイン: パスワード → 2FA 段で「パスキーで認証」(TOTP コードは入力しない)。
  await loginToSecondFactor(page, email, PASSWORD);
  await page.getByTestId('passkey-auth').click();

  // assertion 成功 → SessionResponse の blob を wrapKey でアンロック → Ledger 到達。
  await expect(page.getByTestId('ledger-shell')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId('ledger-welcome')).toContainText(email);
});

test('a tampered passkey assertion is rejected and does not unlock the DK', async ({ page }) => {
  const email = `e2e-passkey-bad-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  await signupLoginAndRegisterPasskey(page, email, PASSWORD);

  await loginToSecondFactor(page, email, PASSWORD);

  // auth/finish への assertion 署名を改竄する。サーバーの finish_passkey_authentication が
  // 検証に失敗し 401 を返す経路 (sign_count 後退もこの分岐) を実機で確認する。begin は素通し。
  await page.route('**/auth/passkey/auth/finish', async (route) => {
    const data = JSON.parse(route.request().postData() ?? '{}');
    if (data?.credential?.response) {
      data.credential.response.signature = 'AAAA'; // パース可だが無効な署名
    }
    await route.continue({ postData: JSON.stringify(data) });
  });

  await page.getByTestId('passkey-auth').click();

  // 認証失敗のエラーが出て、Ledger には到達しない (DK 未アンロック)。
  await expect(page.getByRole('alert')).toContainText('パスキー認証に失敗', { timeout: 30_000 });
  await expect(page.getByTestId('ledger-shell')).toHaveCount(0);
});
