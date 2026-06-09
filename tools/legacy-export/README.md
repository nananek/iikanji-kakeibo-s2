# 旧 iikanji-kakeibo データ移植エクスポータ

旧アプリ [`nananek/iikanji-kakeibo`](https://github.com/nananek/iikanji-kakeibo)（Python/Flask +
**平文** Postgres）から、新 E2EE 版へ移植するための JSON を吐き出す standalone スクリプト。

新アプリはサーバーに財務の平文を持たない（E2EE）。そのため移植は**ユーザー自身の手元で完結**させる:

```
旧 Postgres(平文) ──export.py──► 移植 JSON(平文) ──新クライアントで取込──► 暗号化して同期
                  （あなたのマシン）                （ブラウザ内で暗号化）
```

新サーバーへ渡るのは暗号化済み blob だけ。**移植 JSON は平文を含むので、取込後は速やかに削除**すること。

## 対象データ

勘定科目 / 仕訳（複式明細）/ 医療費 / 月次締め / 証憑画像。

## 使い方

```sh
cd tools/legacy-export
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# email でユーザー指定。証憑画像も含める場合は --storage-dir を渡す。
python export.py \
  --database-url postgres://user:pass@localhost:5432/iikanji \
  --user-email me@example.com \
  --storage-dir /path/to/legacy/voucher-storage \
  -o export.json
```

- `--database-url` … 旧アプリの Postgres（読み取りのみ）。
- `--user-email` / `--user-id` … 移植するユーザー（どちらか一方）。
- `--storage-dir` … 旧アプリの証憑画像ストレージのルート。`Voucher.image_key` を相対パスとして解決する。
  **S3 バックエンド**だった場合は事前にバケットをローカルへ同期し、そのディレクトリを指定する。
  省略すると証憑画像は出力されない。
- `-o` / `--output` … 出力先（省略で標準出力）。

## 取込（新アプリ側）

新 SPA にログインし、画面下部の「データ移植（旧 iikanji-kakeibo から）」で `export.json` を選択 →
サマリーを確認 → 「取込実行」。クライアントが暗号化して同期する。完了後「再読込」で反映。

## 注意

- スクリプトは旧 DB を **読み取り専用**で参照する（書き込まない）。
- 旧 `事業主(proprietor)` 科目の `system_role` は新設計で廃止のため、通常科目として取り込まれる。
- 借方=貸方が一致しない仕訳・日付不正・未知の科目区分は取込時にスキップされ、警告が表示される。
- 同じ JSON を二度取り込むと**重複**する（取込は一度だけ）。取込が途中で失敗した場合は
  エラーに「○件中○件まで同期済み」と表示されるので、再取込での重複範囲を把握できる。
- 出力 JSON とローカルに同期した証憑は、取込後に削除すること（平文を含む）。
