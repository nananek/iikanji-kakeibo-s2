//! 旧 iikanji-kakeibo の移植 JSON を domain レコードへ写像する（**純粋部・native テスト可**）。
//!
//! 旧アプリの平文 export（[`iikanji_types::migrate`]）を parse し、勘定科目/仕訳/医療費/締めを domain 型へ
//! 変換する。文字列 enum は domain enum へ写像（未知は警告して None/スキップ）、借貸不一致の仕訳は
//! スキップして警告する。UUID 採番・暗号化・同期・証憑アップロードは呼び出し側（UI）が行う。

use iikanji_domain::{
    AccountCode, AccountInfo, AccountType, CostType, Date, EntryLine, FiscalClose, JournalEntry,
    MedicalExpense, SystemRole, TaxCategory, Yen,
};
use iikanji_types::migrate::{
    LegacyAccount, LegacyExport, LegacyFiscalClose, LegacyJournalEntry, LegacyMedical,
    LegacyVoucher, EXPORT_FORMAT, EXPORT_VERSION,
};

/// 移植 JSON のパース/検証エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrateError {
    /// JSON デコード失敗。
    Parse(String),
    /// `format` が `iikanji-export` でない。
    UnsupportedFormat(String),
    /// 既知より新しい `version`。
    UnsupportedVersion(u32),
}

impl core::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MigrateError::Parse(m) => write!(f, "JSON の解析に失敗しました: {m}"),
            MigrateError::UnsupportedFormat(g) => {
                write!(f, "移植ファイル形式が不正です (format={g})")
            }
            MigrateError::UnsupportedVersion(v) => {
                write!(f, "未対応の移植ファイル版です (version={v})")
            }
        }
    }
}

/// domain へ写像した移植計画。UUID 採番・暗号化・同期は呼び出し側が行う。
#[derive(Debug, Clone, Default)]
pub struct MigrationPlan {
    /// (旧 entry key, 仕訳)。key は証憑↔仕訳の紐付けに使う。
    pub journal_entries: Vec<(String, JournalEntry)>,
    pub accounts: Vec<AccountInfo>,
    pub medical: Vec<MedicalExpense>,
    pub fiscal: Vec<FiscalClose>,
    /// 証憑（画像バイト付き）。UI が seal_attachment → upload → VoucherMeta を行う。
    pub vouchers: Vec<LegacyVoucher>,
    /// スキップ/未知値などの警告（ユーザーに提示）。
    pub warnings: Vec<String>,
}

/// 移植 JSON を parse + 形式/版を検証する。
pub fn parse_export(json: &str) -> Result<LegacyExport, MigrateError> {
    let exp: LegacyExport =
        serde_json::from_str(json).map_err(|e| MigrateError::Parse(e.to_string()))?;
    if exp.format != EXPORT_FORMAT {
        return Err(MigrateError::UnsupportedFormat(exp.format));
    }
    if exp.version > EXPORT_VERSION {
        return Err(MigrateError::UnsupportedVersion(exp.version));
    }
    Ok(exp)
}

fn account_type_from(s: &str) -> Option<AccountType> {
    match s {
        "asset" => Some(AccountType::Asset),
        "liability" => Some(AccountType::Liability),
        "equity" => Some(AccountType::Equity),
        "revenue" => Some(AccountType::Revenue),
        "expense" => Some(AccountType::Expense),
        _ => None,
    }
}

fn tax_category_from(s: &str) -> Option<TaxCategory> {
    match s {
        "medical" => Some(TaxCategory::Medical),
        "social_insurance" => Some(TaxCategory::SocialInsurance),
        "life_insurance" => Some(TaxCategory::LifeInsurance),
        "earthquake_insurance" => Some(TaxCategory::EarthquakeInsurance),
        "donation" => Some(TaxCategory::Donation),
        "small_business_mutual_aid" => Some(TaxCategory::SmallBusinessMutualAid),
        "withholding_tax" => Some(TaxCategory::WithholdingTax),
        "resident_tax" => Some(TaxCategory::ResidentTax),
        _ => None,
    }
}

fn cost_type_from(s: &str) -> Option<CostType> {
    match s {
        "fixed" => Some(CostType::Fixed),
        "variable" => Some(CostType::Variable),
        "occasional" => Some(CostType::Occasional),
        _ => None,
    }
}

fn system_role_from(s: &str) -> Option<SystemRole> {
    match s {
        "capital" => Some(SystemRole::Capital),
        "retained_earnings" => Some(SystemRole::RetainedEarnings),
        // 旧 "proprietor"(事業主) は新設計で廃止 → 通常科目として取り込む (system_role なし)。
        _ => None,
    }
}

/// "YYYY-MM-DD" を [`Date`] へ。
fn parse_date(s: &str) -> Option<Date> {
    let mut it = s.split('-');
    let y = it.next()?.parse::<i32>().ok()?;
    let m = it.next()?.parse::<u8>().ok()?;
    let d = it.next()?.parse::<u8>().ok()?;
    if it.next().is_some() {
        return None;
    }
    Date::new(y, m, d).ok()
}

fn map_account(a: &LegacyAccount, warnings: &mut Vec<String>) -> Option<AccountInfo> {
    let Some(account_type) = account_type_from(&a.account_type) else {
        warnings.push(format!(
            "科目 {} ({}) の区分 \"{}\" が未知のためスキップしました",
            a.code, a.name, a.account_type
        ));
        return None;
    };
    let tax_category = a.tax_category.as_deref().and_then(tax_category_from);
    let cost_type = a.cost_type.as_deref().and_then(cost_type_from);
    let system_role = a.system_role.as_deref().and_then(system_role_from);
    // proprietor(事業主) は廃止 → 通常科目として取り込むが、サイレントだと気付けないので警告する。
    if a.system_role.as_deref() == Some("proprietor") {
        warnings.push(format!(
            "科目 {} ({}) の事業主区分は新設計で廃止のため通常科目として取り込みました",
            a.code, a.name
        ));
    }
    Some(AccountInfo {
        code: AccountCode::new(a.code.clone()),
        account_type,
        name: a.name.clone(),
        tax_category,
        cost_type,
        system_role,
        is_active: a.is_active,
        display_order: a.display_order,
    })
}

fn map_entry(e: &LegacyJournalEntry, warnings: &mut Vec<String>) -> Option<JournalEntry> {
    let Some(date) = parse_date(&e.date) else {
        warnings.push(format!(
            "仕訳 (date={}) の日付が不正でスキップしました",
            e.date
        ));
        return None;
    };
    let lines = e
        .lines
        .iter()
        .map(|l| EntryLine {
            account: AccountCode::new(l.account_code.clone()),
            debit: Yen::new(l.debit),
            credit: Yen::new(l.credit),
        })
        .collect::<Vec<_>>();
    let entry = JournalEntry {
        date,
        description: e.description.clone(),
        lines,
    };
    if entry.validate().is_err() {
        warnings.push(format!(
            "仕訳 (date={}, {}) が借貸不一致/空のためスキップしました",
            e.date, e.description
        ));
        return None;
    }
    Some(entry)
}

fn map_medical(m: &LegacyMedical, warnings: &mut Vec<String>) -> Option<MedicalExpense> {
    let Some(date) = parse_date(&m.date) else {
        warnings.push(format!(
            "医療費 (date={}) の日付が不正でスキップしました",
            m.date
        ));
        return None;
    };
    Some(MedicalExpense {
        date,
        patient: m.patient.clone(),
        hospital: m.hospital.clone(),
        treatment: m.treatment.clone(),
        paid: Yen::new(m.paid),
        reimbursement: Yen::new(m.reimbursement),
    })
}

fn map_fiscal(fc: &LegacyFiscalClose, warnings: &mut Vec<String>) -> Option<FiscalClose> {
    let close = FiscalClose::new(fc.year);
    if fc.closed_period < 0 {
        return Some(close); // 未締め
    }
    match u8::try_from(fc.closed_period)
        .ok()
        .and_then(|p| close.close_to(p).ok())
    {
        Some(c) => Some(c),
        None => {
            warnings.push(format!(
                "{}年の締め (closed_period={}) が不正でスキップしました",
                fc.year, fc.closed_period
            ));
            None
        }
    }
}

/// 検証済み export を domain レコードへ写像する。
pub fn map_export(exp: LegacyExport) -> MigrationPlan {
    let mut plan = MigrationPlan::default();
    for a in &exp.accounts {
        if let Some(acc) = map_account(a, &mut plan.warnings) {
            plan.accounts.push(acc);
        }
    }
    for e in &exp.journal_entries {
        if let Some(entry) = map_entry(e, &mut plan.warnings) {
            plan.journal_entries.push((e.key.clone(), entry));
        }
    }
    for m in &exp.medical_expenses {
        if let Some(med) = map_medical(m, &mut plan.warnings) {
            plan.medical.push(med);
        }
    }
    for fc in &exp.fiscal_closes {
        if let Some(f) = map_fiscal(fc, &mut plan.warnings) {
            plan.fiscal.push(f);
        }
    }
    plan.vouchers = exp.vouchers;
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "format":"iikanji-export","version":1,
        "accounts":[
            {"code":"5010","account_type":"expense","name":"食費","cost_type":"variable","display_order":50},
            {"code":"9999","account_type":"bogus","name":"不明区分"}
        ],
        "journal_entries":[
            {"key":"1","date":"2026-06-08","description":"昼食","lines":[
                {"account_code":"5010","debit":1280},{"account_code":"1010","credit":1280}]},
            {"key":"2","date":"2026-06-09","description":"不均衡","lines":[
                {"account_code":"5010","debit":100},{"account_code":"1010","credit":50}]}
        ],
        "medical_expenses":[{"date":"2026-01-05","hospital":"H","paid":5000,"reimbursement":1000}],
        "fiscal_closes":[{"year":2026,"closed_period":6},{"year":2025,"closed_period":-1}],
        "vouchers":[{"entry_key":"1","filename":"r.jpg","mime":"image/jpeg","data":"AQID"}]
    }"#;

    #[test]
    fn parse_rejects_bad_format_and_version() {
        assert!(matches!(
            parse_export(r#"{"format":"x","version":1}"#),
            Err(MigrateError::UnsupportedFormat(_))
        ));
        assert!(matches!(
            parse_export(r#"{"format":"iikanji-export","version":99}"#),
            Err(MigrateError::UnsupportedVersion(99))
        ));
        assert!(matches!(
            parse_export("not json"),
            Err(MigrateError::Parse(_))
        ));
    }

    #[test]
    fn map_converts_and_skips_with_warnings() {
        let exp = parse_export(SAMPLE).unwrap();
        let plan = map_export(exp);

        // 食費は取込、区分不明の 9999 はスキップ。
        assert_eq!(plan.accounts.len(), 1);
        assert_eq!(plan.accounts[0].code.as_str(), "5010");
        assert_eq!(plan.accounts[0].account_type, AccountType::Expense);
        assert_eq!(plan.accounts[0].cost_type, Some(CostType::Variable));

        // 均衡する仕訳 key=1 のみ。不均衡 key=2 はスキップ。
        assert_eq!(plan.journal_entries.len(), 1);
        assert_eq!(plan.journal_entries[0].0, "1");
        assert_eq!(plan.journal_entries[0].1.total_debit(), Yen::new(1280));

        assert_eq!(plan.medical.len(), 1);
        assert_eq!(plan.medical[0].paid, Yen::new(5000));

        // 2026 は締め6、2025 は未締め (両方取込)。
        assert_eq!(plan.fiscal.len(), 2);

        assert_eq!(plan.vouchers.len(), 1);
        assert_eq!(plan.vouchers[0].data, vec![1, 2, 3]);

        // 区分不明科目 + 不均衡仕訳の 2 警告。
        assert_eq!(plan.warnings.len(), 2, "warnings={:?}", plan.warnings);
    }

    #[test]
    fn proprietor_system_role_is_dropped() {
        let a = LegacyAccount {
            code: "3030".into(),
            account_type: "equity".into(),
            name: "事業主".into(),
            tax_category: None,
            cost_type: None,
            system_role: Some("proprietor".into()),
            is_active: true,
            display_order: 0,
        };
        let mut w = Vec::new();
        let acc = map_account(&a, &mut w).unwrap();
        assert_eq!(acc.system_role, None); // proprietor は廃止 → None
                                           // サイレントに落とさず、通常科目化を警告する。
        assert_eq!(w.len(), 1, "warnings={w:?}");
        assert!(w[0].contains("事業主区分"));
    }
}
