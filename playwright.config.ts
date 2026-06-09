import { defineConfig, devices } from '@playwright/test';

// E2E は本番と同じ**単一 server** (iikanji-server が API + SPA を同一オリジン配信 + セキュリティ
// ヘッダ付与) を相手にする。server バイナリは `cargo build -p iikanji-server`、dist は
// `trunk build --release` で事前生成しておく (CI のステップ参照)。Postgres も別途用意。
const PORT = 8080;
const BASE_URL = `http://127.0.0.1:${PORT}`;
// passkey spec (Chromium) は localhost オリジンで実行する。WebAuthn の RP ID は IP リテラルだと
// ブラウザに拒否されるため (127.0.0.1 不可)。server は 0.0.0.0 で待受け、localhost/127.0.0.1 双方から届く。
const WEBAUTHN_ORIGIN = `http://localhost:${PORT}`;

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
  projects: [
    // 既存スペック (signup/login/ledger) は Firefox。passkey spec は除外する。
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
      testIgnore: /passkey\.spec\.ts/,
    },
    // passkey spec は Chromium のみ (CDP 仮想認証器)。localhost オリジンで実行する。
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], baseURL: WEBAUTHN_ORIGIN },
      testMatch: /passkey\.spec\.ts/,
    },
  ],
  webServer: {
    command: './target/debug/iikanji-server',
    url: `${BASE_URL}/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    env: {
      DATABASE_URL:
        process.env.DATABASE_URL ?? 'postgres://postgres:postgres@localhost:5432/iikanji_test',
      // 0.0.0.0 で待受け、127.0.0.1 (firefox/health) と localhost (chromium/passkey) の双方に応答する。
      BIND_ADDR: `0.0.0.0:${PORT}`,
      STATIC_DIR: 'dist',
      SERVER_SECRET: 'e2e-not-a-real-secret',
      // passkey の RP ID / origin。localhost はブラウザが安全コンテキスト + 有効 RP ID として扱う。
      WEBAUTHN_RP_ID: 'localhost',
      WEBAUTHN_ORIGIN,
      // 添付ストレージ。S3_* が環境にあれば versitygw 等へ接続、無ければ空 → サーバーは in-memory に
      // フォールバックする (versitygw 無しのローカル e2e でも動く)。CI は versitygw を立てて設定する。
      S3_ENDPOINT: process.env.S3_ENDPOINT ?? '',
      S3_BUCKET: process.env.S3_BUCKET ?? '',
      S3_REGION: process.env.S3_REGION ?? 'us-east-1',
      S3_ACCESS_KEY: process.env.S3_ACCESS_KEY ?? '',
      S3_SECRET_KEY: process.env.S3_SECRET_KEY ?? '',
    },
  },
});
