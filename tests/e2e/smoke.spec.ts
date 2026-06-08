import { test, expect } from '@playwright/test';

// スモーク: Leptos が wasm をロード/マウントしてアプリシェルを描画することを確認する。
// (UI 機能・認証・同期は後続 PR。ここではビルド成果物がブラウザで実際に動くことを担保。)
test('app shell mounts and renders the title', async ({ page }) => {
  await page.goto('/');

  // wasm のロード→マウント完了で <h1> が現れるまで待機。
  const heading = page.getByRole('heading', { level: 1 });
  await expect(heading).toHaveText('いいかんじ™家計簿');

  await expect(page.getByText('E2EE 複式簿記の家計簿')).toBeVisible();
});
