import { defineConfig, devices } from '@playwright/test';

// Trunk が生成した dist/ を静的配信し、ブラウザで Leptos SPA を検証する。
// dist/ は事前に `trunk build` (CI では --release) で生成しておく。
const PORT = 8080;
const BASE_URL = `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
  },
  projects: [{ name: 'firefox', use: { ...devices['Desktop Firefox'] } }],
  webServer: {
    // dist/ を静的配信 (http-server は devDependencies)。
    // クライアントルーティング導入時に index.html への SPA fallback を追加する (PR-3+)。
    command: `npx http-server dist -p ${PORT} -a 127.0.0.1 --silent`,
    url: BASE_URL,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
