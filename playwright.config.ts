import { defineConfig, devices } from '@playwright/test';

// E2E 構成: Trunk dist/ を静的配信 (+ API を Rust サーバーへプロキシ) し、実ブラウザ +
// 実サーバー (Axum + Postgres) で検証する。dist/ は事前に `trunk build --release` で生成、
// サーバーバイナリは `cargo build -p iikanji-server` で生成しておく (CI のステップ参照)。
const PORT = 8080;
const SERVER_PORT = 3000;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const BACKEND_URL = `http://127.0.0.1:${SERVER_PORT}`;

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  // Argon2id (release wasm) + 実ブラウザのため既定 30s より少し緩める。
  timeout: 60_000,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
  },
  projects: [{ name: 'firefox', use: { ...devices['Desktop Firefox'] } }],
  webServer: [
    {
      // Rust API サーバー。Postgres は別途用意 (CI: service container、ローカル: docker)。
      // ローカルは既に起動済みのサーバーを再利用する (reuseExistingServer)。
      command: './target/debug/iikanji-server',
      url: `${BACKEND_URL}/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: {
        DATABASE_URL:
          process.env.DATABASE_URL ?? 'postgres://postgres:postgres@localhost:5432/iikanji_test',
        BIND_ADDR: `127.0.0.1:${SERVER_PORT}`,
      },
    },
    {
      // dist/ を静的配信し /auth,/sync,/health を Rust サーバーへプロキシ (同一オリジン化)。
      command: 'node tools/e2e-server.mjs',
      url: BASE_URL,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: {
        E2E_PORT: String(PORT),
        E2E_BACKEND: BACKEND_URL,
        E2E_DIST: 'dist',
      },
    },
  ],
});
