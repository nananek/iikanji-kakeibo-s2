//! 旧 iikanji-kakeibo からの移植 JSON (`iikanji-export` v1) の serde DTO。
//!
//! 旧アプリ（Python/Flask + 平文 Postgres）を `tools/legacy-export` の Python スクリプトで吸い出した
//! **中間形式**。client がこれを parse → domain レコードへ map → DK で暗号化 → 同期する。
//! **サーバーはこの平文を受け取らない**（移植はユーザーの手元で完結）。金額は整数（円）。

use core::fmt;

use serde::{Deserialize, Serialize};

/// 移植 JSON の `format` フィールドの期待値。
pub const EXPORT_FORMAT: &str = "iikanji-export";
/// 対応する移植 JSON の最大バージョン。
pub const EXPORT_VERSION: u32 = 1;

fn default_true() -> bool {
    true
}

/// 旧財務の平文 freetext（患者名・科目名・摘要等）を `Debug` に出さず文字数だけ示すラッパ。
/// 誤って `tracing` 等へ流れても内容が漏れないようにする（[`LegacyVoucher`] の画像バイトと同方針）。
struct Redacted<'a>(&'a str);

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} chars]", self.0.chars().count())
    }
}

/// 移植 JSON のルート。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyExport {
    pub format: String,
    pub version: u32,
    #[serde(default)]
    pub exported_at: String,
    #[serde(default)]
    pub accounts: Vec<LegacyAccount>,
    #[serde(default)]
    pub journal_entries: Vec<LegacyJournalEntry>,
    #[serde(default)]
    pub medical_expenses: Vec<LegacyMedical>,
    #[serde(default)]
    pub fiscal_closes: Vec<LegacyFiscalClose>,
    #[serde(default)]
    pub vouchers: Vec<LegacyVoucher>,
}

/// 旧 `accounts`(+`account_types.code`)。enum 系は文字列コード（client が enum へ写像する）。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyAccount {
    pub code: String,
    /// "asset" | "liability" | "equity" | "revenue" | "expense"。
    pub account_type: String,
    pub name: String,
    #[serde(default)]
    pub tax_category: Option<String>,
    #[serde(default)]
    pub cost_type: Option<String>,
    #[serde(default)]
    pub system_role: Option<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(default)]
    pub display_order: i32,
}

/// 旧 `journal_entries` + 明細。`key` は旧 entry id（証憑↔仕訳の紐付け handle）。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyJournalEntry {
    pub key: String,
    /// "YYYY-MM-DD"。
    pub date: String,
    #[serde(default)]
    pub description: String,
    pub lines: Vec<LegacyLine>,
}

/// 旧 `journal_entry_lines` の 1 行。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyLine {
    pub account_code: String,
    #[serde(default)]
    pub debit: i64,
    #[serde(default)]
    pub credit: i64,
}

/// 旧 `medical_expenses`。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyMedical {
    pub date: String,
    #[serde(default)]
    pub patient: String,
    #[serde(default)]
    pub hospital: String,
    #[serde(default)]
    pub treatment: String,
    pub paid: i64,
    #[serde(default)]
    pub reimbursement: i64,
}

/// 旧 `fiscal_closes`。`closed_period` が `-1` は未締め。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyFiscalClose {
    pub year: i32,
    pub closed_period: i32,
}

/// 旧 `vouchers` + 画像バイト。`data` は base64 で同梱（JSON 上は文字列、Rust 側は `Vec<u8>`）。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyVoucher {
    /// 紐付く旧 journal_entry の `key`（未紐付けは `None`）。
    #[serde(default)]
    pub entry_key: Option<String>,
    #[serde(default)]
    pub filename: String,
    pub mime: String,
    #[serde(with = "crate::b64")]
    pub data: Vec<u8>,
}

impl fmt::Debug for LegacyVoucher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 画像バイト（旧財務の平文相当）は Debug に出さず長さのみ。
        f.debug_struct("LegacyVoucher")
            .field("entry_key", &self.entry_key)
            .field("filename", &self.filename)
            .field("mime", &self.mime)
            .field("data", &format_args!("[{} bytes]", self.data.len()))
            .finish()
    }
}

// 以下 3 つは財務平文の freetext（科目名・摘要・患者名等）を `Debug` から伏せる。
// 構造把握用の code/date/金額は残し、内容文字列は文字数のみ示す。

impl fmt::Debug for LegacyAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyAccount")
            .field("code", &self.code)
            .field("account_type", &self.account_type)
            .field("name", &Redacted(&self.name))
            .field("tax_category", &self.tax_category)
            .field("cost_type", &self.cost_type)
            .field("system_role", &self.system_role)
            .field("is_active", &self.is_active)
            .field("display_order", &self.display_order)
            .finish()
    }
}

impl fmt::Debug for LegacyJournalEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyJournalEntry")
            .field("key", &self.key)
            .field("date", &self.date)
            .field("description", &Redacted(&self.description))
            .field("lines", &self.lines)
            .finish()
    }
}

impl fmt::Debug for LegacyMedical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyMedical")
            .field("date", &self.date)
            .field("patient", &Redacted(&self.patient))
            .field("hospital", &Redacted(&self.hospital))
            .field("treatment", &Redacted(&self.treatment))
            .field("paid", &self.paid)
            .field("reimbursement", &self.reimbursement)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_json_deserializes_with_defaults_and_b64_voucher() {
        // "AQID" = base64("\x01\x02\x03")。省略可能フィールドは default で埋まる。
        let json = r#"{
            "format": "iikanji-export",
            "version": 1,
            "accounts": [{"code":"5010","account_type":"expense","name":"食費","tax_category":null,"display_order":50}],
            "journal_entries": [{"key":"1","date":"2026-06-08","lines":[
                {"account_code":"5010","debit":1280},{"account_code":"1010","credit":1280}]}],
            "medical_expenses": [{"date":"2026-01-05","hospital":"H","paid":5000}],
            "fiscal_closes": [{"year":2026,"closed_period":6}],
            "vouchers": [{"entry_key":"1","filename":"r.jpg","mime":"image/jpeg","data":"AQID"}]
        }"#;
        let exp: LegacyExport = serde_json::from_str(json).unwrap();
        assert_eq!(exp.format, EXPORT_FORMAT);
        assert_eq!(exp.version, 1);
        assert_eq!(exp.accounts.len(), 1);
        assert!(exp.accounts[0].is_active); // default
        assert_eq!(exp.journal_entries[0].lines[1].credit, 1280);
        assert_eq!(exp.journal_entries[0].lines[1].debit, 0); // default
        assert_eq!(exp.medical_expenses[0].reimbursement, 0); // default
        assert_eq!(exp.vouchers[0].data, vec![1, 2, 3]); // base64 復号
        assert_eq!(exp.vouchers[0].entry_key.as_deref(), Some("1"));
    }

    #[test]
    fn debug_redacts_financial_freetext() {
        // 患者名・科目名・摘要・画像バイトは Debug に内容が出ない（[N chars]/[N bytes] のみ）。
        let med = LegacyMedical {
            date: "2026-01-05".into(),
            patient: "山田太郎".into(),
            hospital: "秘密病院".into(),
            treatment: "極秘治療".into(),
            paid: 5000,
            reimbursement: 0,
        };
        let acc = LegacyAccount {
            code: "5010".into(),
            account_type: "expense".into(),
            name: "内緒の科目".into(),
            tax_category: None,
            cost_type: None,
            system_role: None,
            is_active: true,
            display_order: 0,
        };
        let je = LegacyJournalEntry {
            key: "1".into(),
            date: "2026-06-08".into(),
            description: "ひみつの摘要".into(),
            lines: vec![],
        };
        for (dbg, secret) in [
            (format!("{med:?}"), "山田太郎"),
            (format!("{med:?}"), "秘密病院"),
            (format!("{acc:?}"), "内緒の科目"),
            (format!("{je:?}"), "ひみつの摘要"),
        ] {
            assert!(!dbg.contains(secret), "Debug leaked plaintext: {dbg}");
        }
        // 構造把握用フィールドは残る。
        assert!(format!("{med:?}").contains("paid: 5000"));
        assert!(format!("{acc:?}").contains("5010"));
    }
}
