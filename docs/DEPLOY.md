# デプロイマニュアル

`iikanji-server` 単一イメージが **API と静的 SPA（Trunk の `dist`）を同一オリジンで配信**し、
セキュリティヘッダを付与する。状態は PostgreSQL に置く。サーバーは財務の平文も復号鍵も持たない
（[`CLAUDE.md`](../CLAUDE.md) の E2EE 不変条件）。

## 必要なもの

- **PostgreSQL**（16 以降を想定）。
- **TLS を終端するリバースプロキシ**（本番は https 必須 — passkey の要件、後述）。
- コンテナランタイム（Docker など）。自前ビルドも可。

## 環境変数

| 変数 | 必須 | 既定 | 説明 |
|---|---|---|---|
| `DATABASE_URL` | **必須** | — | `postgres://user:pass@host:5432/db`。**起動時に migration を自動適用**する。 |
| `SERVER_SECRET` | **本番必須** | dev 既定値 + 警告 | ダミー salt 導出（enumeration 対策）と **TOTP 秘密の at-rest 暗号鍵**の素。`openssl rand -hex 32` 等で固有のランダム値を設定する。未設定 / `change-me…` / dev 既定値は起動時に警告。 |
| `BIND_ADDR` | 任意 | `0.0.0.0:8080` | 待受アドレス。 |
| `STATIC_DIR` | 任意 | （未設定 = API 専用） | SPA（`dist`）の配信元ディレクトリ。**設定時のみ**セキュリティヘッダを付与する。配布イメージでは `/app/dist`。 |
| `WEBAUTHN_RP_ID` | 任意 | `localhost` | passkey の **Relying Party ID = 配信ドメイン**。本番は実ホスト名（例 `kakeibo.example.com`）。`WEBAUTHN_ORIGIN` の host の「登録可能サフィックス」である必要がある（IP リテラルは不可）。 |
| `WEBAUTHN_ORIGIN` | 任意 | `http://localhost:8080` | passkey の **origin（`scheme://host[:port]`）**。**本番は https 必須**。localhost / 127.0.0.1 以外で http だと webauthn-rs が拒否し、サーバーが**起動失敗**する（fail-closed）。 |
| `RUST_LOG` | 任意 | （イメージは `info`） | ログレベル（`tracing` の `EnvFilter`）。 |
| `S3_ENDPOINT` | 添付を使うなら必須 | （未設定 = in-memory） | 証憑バイナリの S3 互換ストレージ endpoint（例 `http://s3:7070`）。未設定だと in-memory にフォールバック（再起動で消える）。 |
| `S3_BUCKET` | 添付を使うなら必須 | — | バケット名（versitygw posix では事前に作成しておく）。 |
| `S3_REGION` | 任意 | `us-east-1` | 署名用リージョン（S3 互換実装は任意値で可）。 |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | 添付を使うなら必須 | — | S3 互換ストレージの認証情報。 |
| `MAX_ATTACHMENT_BYTES` | 任意 | `26214400`（25MiB） | アップロード可能な暗号 blob の上限（bytes）。 |

### ⚠️ passkey を本番ドメインで使うとき

`WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` は既定が `localhost` 向けのため、**設定し忘れると本番ドメインで
passkey の登録・認証が機能しない**（TOTP は影響を受けない）。必ず配信ドメインに合わせること:

```sh
WEBAUTHN_RP_ID=kakeibo.example.com
WEBAUTHN_ORIGIN=https://kakeibo.example.com
```

- `WEBAUTHN_ORIGIN` はブラウザが見る実オリジンと**完全一致**させる（scheme・host・必要ならポート）。
- `WEBAUTHN_RP_ID` は origin の host か、その登録可能な親ドメイン（例 host が `app.example.com` のとき
  `example.com` 可、別ドメインは不可）。

## ビルドと起動

### A. GHCR の公開イメージを使う

```sh
docker pull ghcr.io/nananek/iikanji-kakeibo-s2:main      # or :vX.Y.Z / :sha-xxxxxxx
docker run --rm -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@db:5432/iikanji \
  -e SERVER_SECRET=$(openssl rand -hex 32) \
  -e WEBAUTHN_RP_ID=kakeibo.example.com \
  -e WEBAUTHN_ORIGIN=https://kakeibo.example.com \
  ghcr.io/nananek/iikanji-kakeibo-s2:main
```

タグは `main`（main ブランチ）・`vX.Y.Z` / `X.Y`（`v*` タグ）・`sha-xxxxxxx`（コミット）を発行
（`.github/workflows/image.yml`）。

### B. 自前ビルド

```sh
docker build -t iikanji-kakeibo .
```

`Dockerfile` の builder が SPA（Trunk, wasm）と server（native release）を 1 イメージにまとめ、
slim runtime（`debian:bookworm-slim`）へ成果物を移す。フロントツール（Trunk / wasm-bindgen / binaryen）は
版 + SHA256 を固定して取得する（supply-chain 対策）。

### C. Docker Compose（ローカル / 小規模）

リポジトリ同梱の [`compose.yaml`](../compose.yaml) が `db`（Postgres）+ `app` を起動する:

```sh
docker compose up --build      # → http://localhost:8080
```

本番では `SERVER_SECRET` を固有値に、`WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` を配信ドメイン（https）に
変更すること。GHCR の公開イメージを使うなら `app.build` を消して `app.image` を有効化する。

## マイグレーション

起動時に `sqlx::migrate!("./migrations")` が**冪等に**適用される（手動操作は不要）。
マイグレーションは**前方向のみ**（down/ロールバックは未定義）。スキーマ変更は新しい連番ファイルを追加する。

## TLS / リバースプロキシ

- **passkey は secure context + https origin が必須**（localhost を除く）。プロキシで TLS を終端し、
  `WEBAUTHN_ORIGIN` を `https://<ドメイン>` に設定する。
- サーバーは `STATIC_DIR` 設定時に **CSP / COOP(`same-origin`) / COEP(`require-corp`) / CORP / `nosniff` /
  `no-referrer`** を全レスポンスへ付与する。**プロキシでこれらを除去・上書きしないこと**。
  COOP/COEP は将来の Argon2 `p>1`（`SharedArrayBuffer` = cross-origin isolation）に備えた設計。
- CSP は SPA の inline 起動 script を **hash 許可**する（`'unsafe-inline'` 不使用）。サーバーは
  配信する `index.html` から hash を計算して起動し、**導出できない場合は起動を中止**する（fail-closed）。
  そのため `dist/index.html` を改変したイメージでも CSP が壊れない。

## 証憑(添付)ストレージ

証憑バイナリは**クライアントが暗号化した不透明 blob** として S3 互換ストレージに置く。サーバーは
中継保存するだけで復号しない（メタ行 `enc_attachments` も財務平文を持たない）。同梱 `compose.yaml` は
**versitygw**（POSIX バックの S3 互換ゲートウェイ）を使う:

- バケットは versitygw posix では**トップレベルのディレクトリ**。`object_store` は CreateBucket を
  呼ばないため、バケット用ディレクトリを事前に作る（compose では `s3-init` サービスが mkdir する）。
- AWS S3 や MinIO 等、他の S3 互換ストレージでも `S3_*` を向ければ動く（path-style でアクセスする）。
- `S3_*` 未設定なら **in-memory ストアにフォールバック**する（プロセス内のみ・再起動で消える）。
  単一プロセスのデモや E2E では十分だが、**本番では必ず永続ストレージを設定する**。
- アップロード上限は `MAX_ATTACHMENT_BYTES`（既定 25MiB）。

## ヘルスチェック

`GET /health` → `ok`（200）。コンテナ / オーケストレータの liveness・readiness に使う
（`compose.yaml` の `app` 健全性や K8s probe など）。

## バックアップ / 運用上の注意

- **PostgreSQL を定期バックアップ**する。`enc_records` は暗号 blob で、復号鍵はサーバーに存在しない。
- **`SERVER_SECRET` は安全に保管し、原則ローテーションしない。** これを変えると保存済みの TOTP 秘密
  （at-rest 暗号）が復号できなくなり、全ユーザーが TOTP を再登録する必要が生じる
  （ダミー salt も変わるが、こちらは無害）。
- ユーザーの MK / DK はサーバーに無いため、**ユーザーがパスワードとリカバリコードの両方を失うと
  そのユーザーの財務データは復号不能**（E2EE の設計どおり）。
- **証憑バイナリ（S3 互換ストレージ）も定期バックアップ**する。中身は暗号 blob で復号鍵はサーバーに無い。

## 再現ビルド

- `Cargo.lock` をコミットして依存を固定。
- `Dockerfile` は Trunk / wasm-bindgen-cli / binaryen を**版 + SHA256 固定**で取得する。
  **`wasm-bindgen-cli` の版は `Cargo.lock` の `wasm-bindgen` と一致必須**（bump 時は `Dockerfile` の
  `WASM_BINDGEN_VERSION` と CI の固定値も更新する）。
