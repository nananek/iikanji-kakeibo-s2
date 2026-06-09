#!/usr/bin/env python3
"""旧 iikanji-kakeibo (Python/Flask + 平文 Postgres) から移植 JSON を吐き出す standalone スクリプト。

新 E2EE 版へのデータ移植用。**旧データの平文を扱うので、必ずユーザー自身の手元で実行**し、
出力 JSON は新クライアントで取り込んだら速やかに削除すること（新サーバーには渡らない）。

使い方:
    python export.py --database-url postgres://user:pass@localhost/iikanji \\
        --user-email me@example.com --storage-dir /path/to/voucher/storage -o export.json

`--storage-dir` は旧アプリの証憑画像ストレージのルート（`Voucher.image_key` を相対パスとして解決）。
S3 バックエンドだった場合は事前にバケットをローカルへ同期し、そのディレクトリを指定する。省略すると
証憑画像は出力されない。

出力は新クライアント (`crates/types/src/migrate.rs` の `LegacyExport`) が読む JSON。
"""

import argparse
import base64
import datetime
import json
import sys
from pathlib import Path

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    sys.exit("psycopg2 が必要です: pip install -r requirements.txt")

FORMAT = "iikanji-export"
VERSION = 1


def resolve_user_id(cur, args):
    if args.user_id is not None:
        return args.user_id
    cur.execute("SELECT id FROM users WHERE email = %s", (args.user_email,))
    row = cur.fetchone()
    if not row:
        sys.exit(f"ユーザーが見つかりません: {args.user_email}")
    return row["id"]


def fetch_accounts(cur, user_id):
    cur.execute(
        """
        SELECT a.code, t.code AS account_type, a.name, a.tax_category,
               a.cost_type, a.system_role, a.is_active, a.display_order
        FROM accounts a
        JOIN account_types t ON a.account_type_id = t.id
        WHERE a.user_id = %s
        ORDER BY a.display_order, a.code
        """,
        (user_id,),
    )
    return [
        {
            "code": r["code"],
            "account_type": r["account_type"],
            "name": r["name"],
            "tax_category": r["tax_category"],
            "cost_type": r["cost_type"],
            "system_role": r["system_role"],
            "is_active": bool(r["is_active"]),
            "display_order": int(r["display_order"] or 0),
        }
        for r in cur.fetchall()
    ]


def fetch_journal_entries(cur, user_id):
    cur.execute(
        """
        SELECT id, to_char(date, 'YYYY-MM-DD') AS date, description
        FROM journal_entries WHERE user_id = %s ORDER BY id
        """,
        (user_id,),
    )
    entries = {
        r["id"]: {
            "key": str(r["id"]),
            "date": r["date"],
            "description": r["description"] or "",
            "lines": [],
        }
        for r in cur.fetchall()
    }
    if entries:
        cur.execute(
            """
            SELECT l.journal_entry_id, l.account_code, l.debit_amount, l.credit_amount
            FROM journal_entry_lines l
            JOIN journal_entries e ON e.id = l.journal_entry_id
            WHERE e.user_id = %s
            ORDER BY l.id
            """,
            (user_id,),
        )
        for r in cur.fetchall():
            e = entries.get(r["journal_entry_id"])
            if e is not None:
                e["lines"].append(
                    {
                        "account_code": r["account_code"],
                        "debit": int(r["debit_amount"] or 0),
                        "credit": int(r["credit_amount"] or 0),
                    }
                )
    return list(entries.values())


def fetch_medical(cur, user_id):
    cur.execute(
        """
        SELECT to_char(date, 'YYYY-MM-DD') AS date, patient_name, hospital_name,
               treatment_description, amount_paid, insurance_reimbursement
        FROM medical_expenses WHERE user_id = %s ORDER BY date, id
        """,
        (user_id,),
    )
    return [
        {
            "date": r["date"],
            "patient": r["patient_name"] or "",
            "hospital": r["hospital_name"] or "",
            "treatment": r["treatment_description"] or "",
            "paid": int(r["amount_paid"]),
            "reimbursement": int(r["insurance_reimbursement"] or 0),
        }
        for r in cur.fetchall()
    ]


def fetch_fiscal(cur, user_id):
    cur.execute(
        "SELECT year, closed_period FROM fiscal_closes WHERE user_id = %s ORDER BY year",
        (user_id,),
    )
    return [
        {"year": int(r["year"]), "closed_period": int(r["closed_period"])}
        for r in cur.fetchall()
    ]


def fetch_vouchers(cur, user_id, storage_dir):
    if not storage_dir:
        return []
    root = Path(storage_dir).resolve()
    cur.execute(
        """
        SELECT journal_entry_id, image_key, image_mime, original_filename
        FROM vouchers WHERE user_id = %s ORDER BY id
        """,
        (user_id,),
    )
    out = []
    for r in cur.fetchall():
        # image_key は DB 由来。`../` 等で storage_dir 外を読まないよう解決後に内包を検証する。
        path = (root / r["image_key"]).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            print(f"  パス逸脱のためスキップ: {r['image_key']}", file=sys.stderr)
            continue
        if not path.is_file():
            print(f"  証憑画像が見つかりません (スキップ): {path}", file=sys.stderr)
            continue
        data = path.read_bytes()
        out.append(
            {
                "entry_key": (
                    str(r["journal_entry_id"])
                    if r["journal_entry_id"] is not None
                    else None
                ),
                "filename": r["original_filename"] or path.name,
                "mime": r["image_mime"] or "application/octet-stream",
                "data": base64.b64encode(data).decode("ascii"),
            }
        )
    return out


def main():
    ap = argparse.ArgumentParser(description="旧 iikanji-kakeibo から移植 JSON を出力する")
    ap.add_argument("--database-url", required=True, help="旧 Postgres の接続 URL")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--user-email", help="移植するユーザーの email")
    g.add_argument("--user-id", type=int, help="移植するユーザーの id")
    ap.add_argument("--storage-dir", help="証憑画像ストレージのルート (省略で証憑なし)")
    ap.add_argument("-o", "--output", help="出力先 (省略で stdout)")
    args = ap.parse_args()

    conn = psycopg2.connect(args.database_url)
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        user_id = resolve_user_id(cur, args)
        export = {
            "format": FORMAT,
            "version": VERSION,
            "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "accounts": fetch_accounts(cur, user_id),
            "journal_entries": fetch_journal_entries(cur, user_id),
            "medical_expenses": fetch_medical(cur, user_id),
            "fiscal_closes": fetch_fiscal(cur, user_id),
            "vouchers": fetch_vouchers(cur, user_id, args.storage_dir),
        }
    finally:
        conn.close()

    text = json.dumps(export, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(
            f"出力しました: {args.output}\n"
            f"  仕訳 {len(export['journal_entries'])} / 科目 {len(export['accounts'])} / "
            f"医療費 {len(export['medical_expenses'])} / 締め {len(export['fiscal_closes'])} / "
            f"証憑 {len(export['vouchers'])}",
            file=sys.stderr,
        )
    else:
        print(text)


if __name__ == "__main__":
    main()
