import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { authenticator } from 'otplib';

// 証憑(添付)の E2EE 往復を実ブラウザ + 実サーバーで検証する。クライアントでファイルを暗号化して
// アップロード → 再読込 (pull+復号でメタを一覧化) → ダウンロード (復号 + content hash 検証) →
// 元バイトと一致、を確認する。サーバーは暗号 blob を不透明に扱うだけ (in-memory backend で十分)。

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

test('attach an encrypted file to an entry, list it, and download it back', async ({ page }) => {
  const email = `e2e-att-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  await signupAndLogin(page, email, 'correct horse battery staple');

  // --- 添付先の仕訳を 1 件作る ---
  const memo = `証憑-${Math.floor(Math.random() * 1e6)}`;
  await page.getByTestId('je-date').fill('2026-06-09');
  await page.getByTestId('je-desc').fill(memo);
  await page.getByTestId('je-debit').selectOption('5010');
  await page.getByTestId('je-credit').selectOption('1010');
  await page.getByTestId('je-amount').fill('1000');
  await page.getByTestId('je-submit').click();
  await expect(page.getByTestId('entries')).toContainText(memo, { timeout: 15_000 });

  // --- 証憑を添付 (対象仕訳を選択 → ファイル選択で暗号化アップロード) ---
  const fileName = 'receipt.txt';
  const content = Buffer.from(`証憑テスト内容 / receipt body ${Math.random()}`, 'utf-8');
  await page.getByTestId('voucher-entry').selectOption({ index: 1 }); // 先頭 placeholder の次 = 作成した仕訳
  await page.getByTestId('voucher-file').setInputFiles({
    name: fileName,
    mimeType: 'text/plain',
    buffer: content,
  });

  // 一覧にファイル名が出る (アップロード + VoucherMeta push 完了)。
  const list = page.getByTestId('voucher-list');
  await expect(list).toContainText(fileName, { timeout: 30_000 });

  // 明示的に再読込 → pull + 復号で一覧化される経路 (= サーバー側の暗号化永続) を確認。
  await page.getByTestId('reload').click();
  await expect(list).toContainText(fileName, { timeout: 15_000 });

  // --- ダウンロード → 復号 + hash 検証 → 元バイトと一致 ---
  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('voucher-download').first().click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe(fileName);
  const path = await download.path();
  const got = readFileSync(path);
  expect(got.equals(content)).toBeTruthy();

  // --- 削除 → 一覧から消える (tombstone + blob 削除) ---
  await page.getByTestId('voucher-delete').first().click();
  await expect(list).not.toContainText(fileName, { timeout: 15_000 });
});
