import { test, expect, type Page } from '@playwright/test';
import { authenticator } from 'otplib';

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

// signup → login で認証済みセッション (Ledger シェル) まで到達する。
async function signupAndLogin(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/');
  await page.getByTestId('tab-signup').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.getByRole('button', { name: '登録' }).click();
  const uri = await page.getByTestId('totp-uri').textContent({ timeout: 30_000 });
  const secret = secretFromUri(uri!);
  await page.getByLabel('TOTP コード').fill(totpCode(secret));
  await page.getByRole('button', { name: '確認' }).click();
  await expect(page.getByTestId('signup-done')).toBeVisible({ timeout: 15_000 });

  await page.getByTestId('tab-login').click();
  await page.getByLabel('メール').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.locator('form').getByRole('button', { name: 'ログイン' }).click();
  await page.getByLabel('TOTP コード').fill(totpCode(secret, 30_000)); // +1 step (replay 回避)
  await page.getByRole('button', { name: '確認' }).click();
  await expect(page.getByTestId('ledger-shell')).toBeVisible({ timeout: 30_000 });
}

// 仕訳を作成 → DK で seal → push → 再 pull → DK で open → 一覧表示、までの E2EE 同期ループ。
test('create a journal entry and see it persisted via E2EE sync', async ({ page }) => {
  const email = `e2e-ledger-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  await signupAndLogin(page, email, 'correct horse battery staple');

  const memo = `ランチ-${Math.floor(Math.random() * 1e6)}`;
  await page.getByTestId('je-date').fill('2026-06-08');
  await page.getByTestId('je-desc').fill(memo);
  await page.getByTestId('je-debit').fill('5010');
  await page.getByTestId('je-credit').fill('1010');
  await page.getByTestId('je-amount').fill('1280');
  await page.getByTestId('je-submit').click();

  // push 成功後にサーバーから再読込 (pull+decrypt) されて一覧へ反映される。
  const table = page.getByTestId('entries');
  await expect(table).toContainText(memo, { timeout: 15_000 });
  await expect(table).toContainText('1280');

  // 明示的な再読込でも pull+open 経路で残ること (= サーバー側の暗号化永続を確認)。
  await page.getByTestId('reload').click();
  await expect(table).toContainText(memo);
});
