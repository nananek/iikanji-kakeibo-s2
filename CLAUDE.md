# いいかんじ™家計簿 (s2) — Claude Code ガイド

## プロジェクト概要

[`nananek/iikanji-kakeibo`](https://github.com/nananek/iikanji-kakeibo)（Python/Flask + PostgreSQL、
財務データをサーバーに**平文**保持）の**根本設計を改めたグリーンフィールド再構築**。
複式簿記の家計簿という本質は維持しつつ、以下へ転換する。

- **E2EE** — サーバーは email・認証情報・2FA秘密・ラップ鍵 blob・不透明な同期メタデータ・暗号化添付のみを保持し、
  **財務の平文（日付・金額・科目名・摘要・患者名等）を一切持たない**。
- **あくまで家計簿** — 複式簿記中核 + 医療費/確定申告集計を維持。**顧問(税理士)共有と平文前提のサーバー側 REST/OAuth API は廃止**。
- **Rust サーバー + Full Rust SPA (Leptos→WASM)** — 会計ロジックを `domain` crate に集約しクライアントで共有。
  全計算をクライアント側 WASM で実行 ⇒ **サーバーは「認証付き暗号 blob ストア」に縮退**。
- **TOTP 必須 + passkey は第2要素の代替**（passkey 追加時も TOTP 登録は必須）。
- **1パスワードで login と E2EE MK アンロックの両方**。MK 間接参照でパスワード変更を低コスト化。
- **復旧 = オフライン リカバリコード**（MK を password 鍵 / recovery 鍵で二重ラップ）。

設計の全文は承認済みプランを参照: `~/.claude/plans/zesty-drifting-sunbeam.md`
（リポジトリ外。本ファイルはその運用要約 + 不変条件）。

## ⚠️ 絶対に破ってはならない不変条件 (E2EE invariants)

1. **サーバーは財務の平文を絶対に受け取らない／保存しない**。`enc_records.ciphertext` の外に
   業務データ（日付・金額・科目名・摘要・患者名・取引先）を置かない。新カラム追加時は必ず「これは平文で漏れてよいか」を判断する。
2. **MK / DK / wrapKey / recovery code はサーバーへ送信しない**。サーバーが保持するのは ciphertext（ラップ blob）と認証材料のみ。
3. **passkey / TOTP は復号鍵ではない** — セッション/アカウントアクセスを gate するだけ。鍵ツリー（PMK→MK→DK）から厳格に分離する。
4. **2FA 通過前に wrapped-MK / DK blob・同期データを渡さない**。
5. **クライアントの計算結果（残高・レポート）をサーバーに送って保存しない**。BalanceCache はクライアント派生キャッシュのみ、同期しない。
6. **金額は整数（円, `i64` / checked Decimal）**。float 厳禁。
7. **暗号は `crypto` crate の API 経由のみ**。view/handler で直接 nonce や AEAD を組まない。Envelope の AAD 束縛を外さない。

## 確定済み設計判断

| 項目 | 決定 |
|---|---|
| フロントエンド | **Full Rust SPA (Leptos)**、`domain` crate を共有 |
| 認証方式 | **Bitwarden 方式**（client-derived authKey + server-side slow hash）。OPAQUE は v2 検討 |
| passkey/MK | **パスワード主・passkey は第2要素**。MK は password 鍵で1重ラップ、passkey は復号しない。TOTP 常時登録 |
| Data Key | **単一 DK**。ただし `MK → DK → records` の二重間接は維持 |
| 標準勘定科目 | `domain` にコンパイル同梱した版管理カタログ `StandardChart vN`。`enc_records` にはユーザー差分のみ |
| 復旧 | リカバリコード（オフライン）。MK を recovery 鍵でも二重ラップ |
| v1 スコープ | CSV/OFX/Web 取込 / クライアント側 AI 証憑仕訳 / 証憑画像の暗号化保存 / マルチデバイス同期 を含む |

## 暗号鍵階層（要約）

```
password ─Argon2id(salt_pw)─► PMK (ephemeral, zeroize)
   ├─ HKDF(PMK,"auth-v1") ─► authKey  → login 証明として送信。server は Argon2id(authKey,salt_srv) のみ保存
   └─ HKDF(PMK,"wrap-v1") ─► wrapKey  → 非送出。MK blob をアンラップ
MK (random 32B) ── wraps ──► DK (random 32B) ── encrypts ──► 全財務レコード/添付
signup 時のラップ blob: mk-pw(wrapKey) / mk-recovery(recoveryKey) / dk-wrap(MK)
```

**Primitives（RustCrypto に統一。libsodium/dryoc 不採用）**: `argon2`(Argon2id, interactive `m=64MiB,t=3,p=1`) /
`chacha20poly1305`(**XChaCha20-Poly1305**) / `hkdf`(HKDF-SHA-256, info でドメイン分離) / `sha2` / `getrandom`(OsRng) /
`totp-rs` / `webauthn-rs`(server) / `subtle` / `zeroize`。

**Envelope v1**（binary, 版管理）: `magic("K1")|version|alg|kdf_id|flags|nonce(24)|ciphertext(+16B tag)`。
AAD = ヘッダ(30B) + 呼び出し側 context(`purpose + record_id + version`)。**AAD は envelope に格納せず open 時に文脈から再構築**するため、blob すり替え（用途取り違え）は復号失敗として必ず検出される。version/alg/kdf_id バイトで将来の鍵ローテ・アルゴリズム更新に備える。実装は `crates/crypto/`（`iikanji-crypto`）。

## ワークスペース構成（予定 / 段階的に作成）

```
crates/
├── domain/   純会計ロジック（no_std-friendly, I/O無）。wasm32 と native 両対応。
│             chart/ journal/ ledger/ reports/ fiscal/ import/ money/
├── crypto/   鍵階層 + AEAD + Envelope v1。derive/wrap/unwrap/recovery codec
├── types/    共有 serde DTO（sync push/pull, auth ceremony, レコード平文 schema）
├── client/   Leptos SPA→WASM。app/ store/(IndexedDB・outbox・sync) crypto_glue/ ai/ sync/
└── server/   Axum + sqlx(Postgres) + S3。auth/ sync/ attachments/ db/(migrations)
              ※ server は crypto を TOTP at-rest 暗号 + Envelope 検証にのみ使用し、レコードは決して復号しない
xtask/        (任意) reproducible-build ハッシュ生成
```

`domain` は `#![no_std]`+`alloc` を目標（I/O・プラットフォーム依存を型で排除）。`std` 依存パーサは feature gate。
レコード平文 DTO は `ciborium`(CBOR) で版管理 serde（内部 `v` フィールド）。

## サーバーデータモデル（要点）

全財務レコードは**単一テーブル `enc_records(user_id, record_id, record_type, version, seq, tombstone, ciphertext, ct_size, ...)`**
に不透明 blob として格納。`record_type` は SMALLINT enum、内容は ciphertext。`user_seq.next_seq` で per-user 単調カーソル
（グローバル SERIAL 禁止）。添付バイナリは S3、`enc_attachments` 行はメタのみ。voucher→journal 紐付けは ciphertext 内。
`ct_size` は size バケットへパディングして漏洩緩和。

## マルチデバイス同期（要点）

per-record `version`(CAS) + per-user `seq` カーソル + tombstone。**型別マージ規則付き LWW**（汎用 CRDT 不採用）。
- journal entry: 実質 append-only、締め後変更は client 側 immutability 規則で拒否。
- fiscal-close: 前方向ラッチ ⇒ `closed_period = max(local, remote)` の**単調マージ**（素朴 LWW 禁止）。
- push は `expected_version` 同梱、server は `UPDATE ... WHERE version=$expected RETURNING seq`、0行で `409`。
- tombstone GC 地平より古いカーソルには `426 Resync Required` で full pull。
- client は **pull→merge→resolve→push** を収束までループ。**DK/MK は IndexedDB に平文保存しない**（メモリのみ）。

## ビルド・ツーリング

- **Trunk**（純 CSR SPA, v1）。SSR が要れば後日 `cargo-leptos`。`wasm-bindgen` + `wasm-opt -Oz`。
- **Argon2id は Web Worker で実行**（UI を塞がない）。`p>1` 化に備え COOP/COEP cross-origin-isolation ヘッダを設計。
- **Reproducible build**: `rust-toolchain.toml` 固定 + `Cargo.lock` + リリース毎に wasm/js の SHA-256 公開（SRI 用）。
- **CSP**: `script-src 'self'`, inline 禁止, Trusted Types。Web E2EE は配信ビルドを信頼する旨を文書化。

## 開発フェーズ（de-risk 順）

0. **Spikes** — Argon2id WASM 実機ベンチ / Leptos 重量グリッド試作 / `crypto` crate + Envelope を KAT 付き実装。
1. **認証 + 鍵階層 + 単一レコード同期スケルトン**（背骨）— signup/login(Bitwarden), TOTP 必須, MK/DK blob, `enc_records` + sync, 2デバイス E2EE 往復。WebAuthn 第2要素。
2. **`domain` 中核** — 複式モデル・仕訳・StandardChart + 科目差分・試算表/残高。旧 Python 出力を golden corpus に。
3. **レポート/計算** — 元帳・PL/BS・税区分集計・医療費ロールアップ・月次 pivot・着地予測。
4. **取込** — CSV/OFX/Web パーサ・出納帳→仕訳・fiscal-close 状態機械 + 多デバイス締め UX。
5. **添付** — chunked AEAD(64KiB)・presigned S3・voucher meta・size パディング。
6. **AI OCR** — クライアント側・ユーザー鍵・信頼境界の明示 UX。
7. **堅牢化** — PWA/オフライン・リカバリ再生成・パスワード変更・アカウント削除/crypto-shredding・セキュリティレビュー。

## テスト方針

- **会計**: `domain` を native で `cargo test`（複式不変条件 借方==貸方、残高、予測関数の property/golden test）+ `wasm32` build-check。
  旧 Python の `app/services/{accounting,fiscal,tax,balance_cache}.py` 出力を golden corpus とする。
- **暗号**: `crypto` の KAT（Envelope ラウンドトリップ、AAD 改竄検出、recovery codec）。
- **認証/2FA**: signup→TOTP 強制→login→add passkey(TOTP gate)→password 変更(再ラップのみ)→recovery→削除 の統合テスト。
  enumeration ダミー・レート制限・TOTP リプレイ(`last_used_step`)・WebAuthn `sign_count` 後退を検証。
- **E2EE 境界テスト**: DB ダンプに財務平文が一切現れないことを保証。
- **同期**: 2クライアント interleaving シミュレーション（CAS 競合・tombstone・`426 Resync`・fiscal-close 単調マージ・offline outbox drain）。

## 規約・注意

- 旧アプリ（参照のみ、移植元の振る舞い仕様）: https://github.com/nananek/iikanji-kakeibo
- ブランチ: `main`（既定）。リリース運用は追って定義。
- コミット/プッシュはユーザーが明示的に依頼したときのみ行う。
- 新しい暗号プリミティブやレコード型を足すときは、必ず上記「E2EE invariants」と鍵ツリーへの影響を先に確認する。
