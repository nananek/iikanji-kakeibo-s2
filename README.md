# いいかんじ™家計簿 (s2)

**E2EE（エンドツーエンド暗号化）の複式簿記家計簿。** サーバーは email・認証情報・2FA 秘密・
ラップ鍵 blob・不透明な同期メタデータ・暗号化添付のみを保持し、**財務の平文（日付・金額・科目名・
摘要・患者名等）を一切持たない**「認証付き暗号 blob ストア」に縮退している。会計計算はすべて
クライアント（Leptos → WASM）側で実行する。

> [`nananek/iikanji-kakeibo`](https://github.com/nananek/iikanji-kakeibo)（Python/Flask、財務データを
> サーバーに平文保持）の根本設計を改めたグリーンフィールド再構築。複式簿記の家計簿という本質と
> 医療費/確定申告集計は維持しつつ、E2EE + フル Rust 構成へ転換した。

設計の全文・暗号鍵階層・**絶対に破ってはならない E2EE 不変条件**は [`CLAUDE.md`](./CLAUDE.md) を参照。

## 特徴

- **E2EE** — サーバーは復号鍵を持たない。MK / DK / wrapKey / リカバリコードはネットワークへ出さない。
- **複式簿記中核** + 医療費 / 確定申告集計。
- **Rust サーバー（Axum + Postgres）+ フル Rust SPA（Leptos → WASM）**。会計ロジックは `domain` crate を
  サーバー / クライアントで共有。
- **認証は Bitwarden 方式** — 1 つのパスワードで login と E2EE マスター鍵アンロックの両方。
  **TOTP 必須**、**passkey（WebAuthn）は第2要素の代替**（passkey 追加後も TOTP 登録は必須）。
- **復旧はオフライン リカバリコード**（MK を password 鍵 / recovery 鍵で二重ラップ）。
- 金額は整数（円, `i64`）。float 厳禁。

## アーキテクチャ

```
crates/
├── domain/   純会計ロジック（no_std-friendly, I/O 無）。wasm32 と native 両対応。複式・StandardChart・
│             試算表・元帳・PL/BS・税/医療費集計・月次比較・着地予測・fiscal close。
├── crypto/   鍵階層 + AEAD + Envelope v1。derive/wrap/unwrap/recovery codec（RustCrypto に統一）。
├── types/    server/client 共有の serde DTO（auth ceremony / sync push-pull / レコード平文 schema）。
├── client/   Leptos SPA → WASM。鍵管理グルー・WebAuthn glue・同期・UI（財務計算は domain を共有）。
└── server/   Axum + sqlx(Postgres)。auth（signup/login/TOTP/passkey）・sync（push/pull）・静的 SPA 配信。
              ※ server は crypto を TOTP at-rest 暗号 + Envelope 検証にのみ使い、レコードは決して復号しない。
```

サーバーは全財務レコードを単一テーブル `enc_records` に不透明 blob として格納し、per-user 単調カーソル +
tombstone で多デバイス同期する。詳細は `CLAUDE.md`。

## 開発

### 前提ツール

- **Rust（stable）** + wasm ターゲット: `rustup target add wasm32-unknown-unknown`
- **Trunk**（SPA ビルド）, **wasm-bindgen-cli**（`Cargo.lock` の wasm-bindgen と**版一致必須**）,
  **wasm-opt**（binaryen）
- **PostgreSQL**（テスト / 実行用）
- **Node.js 22 + npm**（E2E: Playwright。Firefox + Chromium）

### アプリを動かす

最も手軽なのは Docker Compose（API + SPA + Postgres を一括起動）:

```sh
docker compose up --build
# ブラウザで http://localhost:8080 を開く（アカウント作成 → 認証アプリに TOTP 登録 → ログイン）
```

ソースから直接動かす場合（単一サーバーが API と SPA を同一オリジン配信する本番同等構成）:

```sh
trunk build --release                 # SPA を dist/ へ
DATABASE_URL=postgres://... \
STATIC_DIR=dist \
SERVER_SECRET=$(openssl rand -hex 32) \
  cargo run -p iikanji-server         # http://localhost:8080
```

> SPA だけを反復開発したいときは `trunk serve`（:8080）も使えるが、API は別途
> `iikanji-server` を動かす必要がある（クライアントは同一オリジンの相対 URL で API を叩く）。

### テスト

```sh
# 会計・暗号・認証/2FA/passkey・同期・E2EE 境界（Postgres 必須）
DATABASE_URL=postgres://... cargo test --workspace --all-features

# wasm ビルドが壊れていないこと
cargo build --target wasm32-unknown-unknown -p iikanji-client

# E2E（実ブラウザ + 実サーバー）。Firefox = 既存フロー / Chromium = passkey 仮想認証器
npm ci
npx playwright install --with-deps firefox chromium
DATABASE_URL=postgres://... npx playwright test
```

テスト方針（golden corpus・KAT・E2EE 境界・2FA リプレイ / passkey ゲート 等）の詳細は `CLAUDE.md`。

## データ移植（旧 iikanji-kakeibo から）

旧アプリ（Python/Flask + **平文** Postgres）から、勘定科目 / 仕訳 / 医療費 / 月次締め / 証憑画像を
移植できる。E2EE のため **移植はユーザーの手元で完結** させる ― 旧 DB の平文はあなたのマシン上だけで扱い、
新サーバーへ渡るのはクライアントで暗号化した blob のみ。

```sh
# 1) 旧 Postgres から移植 JSON を吐く（あなたのマシンで）
cd tools/legacy-export
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
# --storage-dir は証憑画像のルート（省略すると証憑なし）。
python export.py \
  --database-url postgres://user:pass@localhost:5432/iikanji \
  --user-email me@example.com \
  --storage-dir /path/to/legacy/voucher-storage \
  -o export.json

# 2) 新 SPA にログイン → 画面下部「データ移植」で export.json を選択 → サマリー確認 → 取込実行
#    クライアントが暗号化して同期する。完了後「再読込」で反映。
```

`export.json` は財務の平文を含む。**取込後は速やかに削除** すること。詳細・注意（proprietor 科目の扱い・
借貸不一致のスキップ・二重取込の重複）は `tools/legacy-export/README.md`。

## デプロイ

`iikanji-server` 単一イメージが API と SPA を同一オリジンで配信し、セキュリティヘッダ（CSP /
COOP / COEP 等）を付与する。GHCR に公開イメージ（`ghcr.io/nananek/iikanji-kakeibo-s2`）を発行。

**環境変数・TLS / passkey の要件・運用注意は [`docs/DEPLOY.md`](./docs/DEPLOY.md) を参照。**

## ライセンス

`LicenseRef-SUL-1.0`（`Cargo.toml` の `workspace.package.license`）。
