import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { authenticator } from 'otplib';

// 旧 iikanji-kakeibo からのデータ移植を実ブラウザ + 実サーバーで検証する。
// 旧アプリの export JSON (仕訳 + 医療費 + 締め + base64 証憑) をクライアントへ読み込ませ、
// クライアントが暗号化して同期 → 再読込 (pull + 復号) で仕訳一覧・証憑一覧に反映され、
// 証憑が元バイトのままダウンロードできることを確認する。サーバーへ渡るのは暗号 blob のみ。

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

test('import a legacy export JSON: entries + voucher round-trip through E2EE sync', async ({ page }) => {
  const email = `e2e-migrate-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  await signupAndLogin(page, email, 'correct horse battery staple');

  // --- 旧アプリの export JSON を組み立てる (Python エクスポータが吐く形と同一) ---
  const memo = `移植-${Math.floor(Math.random() * 1e6)}`;
  const voucherName = 'legacy-receipt.txt';
  const voucherBody = Buffer.from(`旧証憑バイト / legacy receipt ${Math.random()}`, 'utf-8');
  const entryKey = '4242'; // 旧 journal_entry.id = 証憑との紐付け handle
  const exportJson = {
    format: 'iikanji-export',
    version: 1,
    exported_at: '2026-06-09T00:00:00+00:00',
    accounts: [],
    journal_entries: [
      {
        key: entryKey,
        date: '2026-03-14',
        description: memo,
        // 5010(食費)/1010(現金) は標準カタログにある → 名前解決される。借貸一致。
        lines: [
          { account_code: '5010', debit: 1280, credit: 0 },
          { account_code: '1010', debit: 0, credit: 1280 },
        ],
      },
    ],
    medical_expenses: [
      {
        date: '2026-01-05',
        patient: '本人',
        hospital: 'H医院',
        treatment: '診察',
        paid: 5000,
        reimbursement: 1000,
      },
    ],
    fiscal_closes: [{ year: 2026, closed_period: 6 }],
    vouchers: [
      {
        entry_key: entryKey,
        filename: voucherName,
        mime: 'text/plain',
        data: voucherBody.toString('base64'),
      },
    ],
  };

  // --- 移植セクションへ JSON を読み込ませる → サマリー表示 ---
  await page.getByTestId('migration-file').setInputFiles({
    name: 'export.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(exportJson), 'utf-8'),
  });
  const summary = page.getByTestId('migration-summary');
  await expect(summary).toBeVisible({ timeout: 15_000 });
  await expect(summary).toContainText('仕訳 1');
  await expect(summary).toContainText('証憑 1');

  // --- 取込実行 → 暗号化 + 同期 + 証憑アップロード ---
  await page.getByTestId('migration-import').click();
  await expect(page.getByTestId('migration-status')).toContainText('取込完了', { timeout: 60_000 });

  // --- 再読込 (pull + 復号) で仕訳一覧と証憑一覧へ反映される ---
  await page.getByTestId('reload').click();
  await expect(page.getByTestId('entries')).toContainText(memo, { timeout: 30_000 });
  const list = page.getByTestId('voucher-list');
  await expect(list).toContainText(voucherName, { timeout: 30_000 });

  // --- 証憑ダウンロード → 復号 + hash 検証 → 元バイトと一致 ---
  const downloadPromise = page.waitForEvent('download');
  await page.getByTestId('voucher-download').first().click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe(voucherName);
  const got = readFileSync(await download.path());
  expect(got.equals(voucherBody)).toBeTruthy();
});
