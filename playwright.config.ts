import { defineConfig, devices } from '@playwright/test';

// E2E は本番と同じ**単一 server** (iikanji-server が API + SPA を同一オリジン配信 + セキュリティ
// ヘッダ付与) を相手にする。server バイナリは `cargo build -p iikanji-server`、dist は
// `trunk build --release` で事前生成しておく (CI のステップ参照)。Postgres も別途用意。
const PORT = 8080;
const BASE_URL = `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  // Argon2id (release wasm, Web Worker) + 実ブラウザのため既定 30s より緩める。
  timeout: 60_000,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
  },
  projects: [{ name: 'firefox', use: { ...devices['Desktop Firefox'] } }],
  webServer: {
    command: './target/debug/iikanji-server',
    url: `${BASE_URL}/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    env: {
      DATABASE_URL:
        process.env.DATABASE_URL ?? 'postgres://postgres:postgres@localhost:5432/iikanji_test',
      BIND_ADDR: `127.0.0.1:${PORT}`,
      STATIC_DIR: 'dist',
      SERVER_SECRET: 'e2e-not-a-real-secret',
    },
  },
});
