//! reports スライス (statements / tax / medical / general_ledger) のテスト。

use crate::*;

fn exp(date: Date, payment: &str, category: &str, amount: i64) -> JournalEntry {
    cashbook_to_entry(CashbookInput {
        date,
        kind: CashbookKind::Expense,
        payment_account: AccountCode::from(payment),
        category_account: AccountCode::from(category),
        amount: Yen::new(amount),
        description: "x".into(),
    })
    .unwrap()
}

fn inc(date: Date, payment: &str, category: &str, amount: i64) -> JournalEntry {
    cashbook_to_entry(CashbookInput {
        date,
        kind: CashbookKind::Income,
        payment_account: AccountCode::from(payment),
        category_account: AccountCode::from(category),
        amount: Yen::new(amount),
        description: "x".into(),
    })
    .unwrap()
}

fn d() -> Date {
    Date::new(2026, 6, 7).unwrap()
}

#[test]
fn income_statement_and_summary() {
    let chart = Chart::standard();
    let entries = vec![
        inc(d(), "1020", "4010", 300_000), // 給与
        exp(d(), "1010", "5010", 5_000),   // 食費
        exp(d(), "1020", "5020", 80_000),  // 住居費
    ];

    let is = income_statement(&entries, &chart);
    assert_eq!(is.total_revenue, Yen::new(300_000));
    assert_eq!(is.total_expense, Yen::new(85_000));
    assert_eq!(is.net_income, Yen::new(215_000));
    assert_eq!(is.revenues.len(), 1);
    assert_eq!(is.revenues[0].code.as_str(), "4010");
    assert_eq!(is.revenues[0].amount, Yen::new(300_000));
    assert_eq!(is.expenses.len(), 2); // 5010, 5020 (コード昇順)
    assert_eq!(is.expenses[0].code.as_str(), "5010");
    assert_eq!(is.expenses[1].code.as_str(), "5020");

    let summary = income_expense_summary(&entries, &chart);
    assert_eq!(summary.income, Yen::new(300_000));
    assert_eq!(summary.expense, Yen::new(85_000));
    assert_eq!(summary.balance, Yen::new(215_000));
}

#[test]
fn balance_sheet_identity_known() {
    let chart = Chart::standard();
    let entries = vec![
        inc(d(), "1020", "4010", 300_000),
        exp(d(), "1010", "5010", 5_000),
        exp(d(), "1020", "5020", 80_000),
    ];
    let bs = balance_sheet(&entries, &chart);

    // 普通預金 +220000, 現金 -5000 → 資産合計 215000
    assert_eq!(bs.total_assets, Yen::new(215_000));
    assert_eq!(bs.total_liabilities, Yen::ZERO);
    assert_eq!(bs.total_equity, Yen::ZERO);
    assert_eq!(bs.net_income, Yen::new(215_000));
    assert!(bs.is_balanced()); // 資産 == 負債 + 純資産 + 当期純利益
}

#[test]
fn balance_sheet_with_liability() {
    let chart = Chart::standard();
    // クレジットカードで食費 (負債計上): 借方 食費 / 貸方 クレカ
    let entries = vec![exp(d(), "2010", "5010", 12_000)];
    let bs = balance_sheet(&entries, &chart);
    // 負債 (クレカ) +12000、資産 0、純資産 0、当期純利益 = -12000 (費用のみ)
    assert_eq!(bs.total_liabilities, Yen::new(12_000));
    assert_eq!(bs.total_assets, Yen::ZERO);
    assert_eq!(bs.net_income, Yen::new(-12_000));
    assert!(bs.is_balanced()); // 0 == 12000 + 0 + (-12000)
}

#[test]
fn tax_summary_groups_by_category() {
    let chart = Chart::standard();
    let entries = vec![
        exp(d(), "1010", "6010", 10_000), // 医療費 (Medical)
        exp(d(), "1020", "6020", 20_000), // 健康保険料 (SocialInsurance)
        exp(d(), "1020", "6030", 5_000),  // 厚生年金 (SocialInsurance)
        exp(d(), "1010", "5010", 3_000),  // 食費 (税区分なし → 集計外)
    ];
    let summary = tax_summary(&entries, &chart);
    // 宣言順: Medical, SocialInsurance
    assert_eq!(summary.len(), 2);
    assert_eq!(summary[0].category, TaxCategory::Medical);
    assert_eq!(summary[0].total, Yen::new(10_000));
    assert_eq!(summary[1].category, TaxCategory::SocialInsurance);
    assert_eq!(summary[1].total, Yen::new(25_000));
    assert_eq!(summary[1].accounts.len(), 2); // 6020, 6030
}

#[test]
fn medical_summary_rollup() {
    let expenses = vec![
        MedicalExpense {
            date: d(),
            patient: "A".into(),
            hospital: "H1".into(),
            treatment: "診察".into(),
            paid: Yen::new(10_000),
            reimbursement: Yen::new(3_000),
        },
        MedicalExpense {
            date: d(),
            patient: "A".into(),
            hospital: "H1".into(),
            treatment: "薬".into(),
            paid: Yen::new(5_000),
            reimbursement: Yen::ZERO,
        },
        MedicalExpense {
            date: d(),
            patient: "B".into(),
            hospital: "H2".into(),
            treatment: "診察".into(),
            paid: Yen::new(8_000),
            reimbursement: Yen::new(2_000),
        },
    ];
    let s = medical_summary(&expenses);

    // 全体
    assert_eq!(s.totals.paid, Yen::new(23_000));
    assert_eq!(s.totals.reimbursement, Yen::new(5_000));
    assert_eq!(s.totals.net, Yen::new(18_000));

    // 受診者順: A, B
    assert_eq!(s.by_patient.len(), 2);
    let a = &s.by_patient[0];
    assert_eq!(a.patient, "A");
    assert_eq!(a.by_hospital.len(), 1);
    assert_eq!(a.by_hospital[0].hospital, "H1");
    assert_eq!(a.by_hospital[0].count, 2);
    assert_eq!(a.by_hospital[0].totals.net, Yen::new(12_000));
    assert_eq!(a.totals.net, Yen::new(12_000));

    let b = &s.by_patient[1];
    assert_eq!(b.patient, "B");
    assert_eq!(b.totals.net, Yen::new(6_000));
}

#[test]
fn general_ledger_running_balance() {
    let chart = Chart::standard();
    let normal = chart.normal_balance(&AccountCode::from("1020")).unwrap();
    // 入力順をバラして渡し、日付昇順で処理されることを確認する。
    let entries = vec![
        exp(Date::new(2026, 6, 5).unwrap(), "1020", "5020", 80_000), // 06-05 credit
        inc(Date::new(2026, 6, 1).unwrap(), "1020", "4010", 300_000), // 06-01 debit
        inc(Date::new(2026, 6, 3).unwrap(), "1020", "4030", 10_000), // 06-03 debit
    ];
    let lines = general_ledger(&entries, &AccountCode::from("1020"), normal);
    assert_eq!(lines.len(), 3);
    // 06-01: +300000, 06-03: +10000, 06-05: -80000
    assert_eq!(lines[0].balance, Yen::new(300_000));
    assert_eq!(lines[1].balance, Yen::new(310_000));
    assert_eq!(lines[2].balance, Yen::new(230_000));
    assert_eq!(lines[0].debit, Yen::new(300_000));
    assert_eq!(lines[2].credit, Yen::new(80_000));
}

// ---- 不変条件 (決定的ランダム): BS 恒等式 ----

struct R(u64);
impl R {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

#[test]
fn balance_sheet_identity_holds_over_random_entries() {
    let chart = Chart::standard();
    let mut rng = R(0xDEAD_BEEF_1234_5678);
    let payments = ["1010", "1020", "1040", "2010"];
    let expenses = ["5010", "5050", "5120", "6010", "6020"];
    let incomes = ["4010", "4020", "4050"];

    let mut entries = Vec::new();
    for _ in 0..1000 {
        let income = rng.next().is_multiple_of(2);
        let amount = 1 + (rng.next() % 500_000) as i64;
        let pay = payments[(rng.next() % payments.len() as u64) as usize];
        let entry = if income {
            let cat = incomes[(rng.next() % incomes.len() as u64) as usize];
            inc(d(), pay, cat, amount)
        } else {
            let cat = expenses[(rng.next() % expenses.len() as u64) as usize];
            exp(d(), pay, cat, amount)
        };
        entries.push(entry);
    }

    let bs = balance_sheet(&entries, &chart);
    assert!(
        bs.is_balanced(),
        "資産 == 負債 + 純資産 + 当期純利益 が任意の balanced 仕訳集合で成立する"
    );
}

// ---- monthly: 比較・着地予測 ----

#[test]
fn weekday_known_dates() {
    assert_eq!(Date::new(1970, 1, 1).unwrap().weekday(), 4); // 木曜
    assert_eq!(Date::new(2000, 1, 1).unwrap().weekday(), 6); // 土曜
    assert_eq!(Date::new(2024, 1, 1).unwrap().weekday(), 1); // 月曜
}

fn ymd(y: i32, m: u8, day: u8) -> Date {
    Date::new(y, m, day).unwrap()
}

#[test]
fn monthly_comparison_pivot() {
    let chart = Chart::standard();
    let entries = vec![
        exp(ymd(2026, 1, 10), "1020", "5020", 80_000), // 住居費(Fixed) 1月
        exp(ymd(2026, 1, 15), "1010", "5010", 30_000), // 食費(Variable) 1月
        exp(ymd(2026, 2, 10), "1020", "5020", 80_000), // 2月
        exp(ymd(2026, 2, 15), "1010", "5010", 25_000),
        inc(ymd(2026, 1, 25), "1020", "4010", 300_000), // 給与 1月
        exp(ymd(2025, 12, 1), "1010", "5010", 99_999),  // 別年 → 除外
    ];
    let mc = monthly_comparison(&entries, 2026, &chart);

    assert_eq!(mc.expense_rows.len(), 2); // 5010, 5020
    let food = &mc.expense_rows[0];
    assert_eq!(food.code.as_str(), "5010");
    assert_eq!(food.monthly[0], Yen::new(30_000));
    assert_eq!(food.monthly[1], Yen::new(25_000));
    assert_eq!(food.total, Yen::new(55_000));
    assert_eq!(food.cost_type, Some(CostType::Variable));

    assert_eq!(mc.expense_totals[0], Yen::new(110_000));
    assert_eq!(mc.expense_totals[1], Yen::new(105_000));
    assert_eq!(mc.fixed_totals[0], Yen::new(80_000));
    assert_eq!(mc.variable_totals[1], Yen::new(25_000));
    assert_eq!(mc.income_totals[0], Yen::new(300_000));
    assert_eq!(mc.income_rows.len(), 1);
}

fn find_proj(p: &MonthProjection, code: &str) -> AccountProjection {
    p.rows
        .iter()
        .find(|r| r.code.as_str() == code)
        .unwrap_or_else(|| panic!("missing {code}"))
        .clone()
}

#[test]
fn project_month_pro_rata_and_fixed() {
    let chart = Chart::standard();
    let entries = vec![
        // 変動費 5010: 6月 1/5/10 日に計 10000、経過 10/30 日
        exp(ymd(2026, 6, 1), "1010", "5010", 4_000),
        exp(ymd(2026, 6, 5), "1010", "5010", 3_000),
        exp(ymd(2026, 6, 10), "1010", "5010", 3_000),
        // 固定費 5020: 前月(5月)80000、当月(6月1日)80000
        exp(ymd(2026, 5, 20), "1020", "5020", 80_000),
        exp(ymd(2026, 6, 1), "1020", "5020", 80_000),
    ];
    let p = project_month(&entries, &chart, 2026, 6, 10, ProjectionMethod::ProRata);

    let food = find_proj(&p, "5010");
    assert_eq!(food.actual, Yen::new(10_000));
    assert_eq!(food.projected, Yen::new(30_000)); // 10000 * 30 / 10

    let rent = find_proj(&p, "5020");
    assert_eq!(rent.actual, Yen::new(80_000));
    assert_eq!(rent.projected, Yen::new(80_000)); // 固定費 → 前月総額
}

#[test]
fn project_month_rolling28_and_dow28() {
    let chart = Chart::standard();
    // 変動費 5010 を 6月 1〜28 日に毎日 1000 (計 28000)、as_of=28、dim=30
    let mut entries = Vec::new();
    for day in 1..=28u8 {
        entries.push(exp(ymd(2026, 6, day), "1010", "5010", 1_000));
    }

    let r = project_month(&entries, &chart, 2026, 6, 28, ProjectionMethod::Rolling28);
    let food_r = find_proj(&r, "5010");
    assert_eq!(food_r.actual, Yen::new(28_000));
    // 平均日額 1000 × 残 2 日 = 2000 → 30000
    assert_eq!(food_r.projected, Yen::new(30_000));

    let dw = project_month(&entries, &chart, 2026, 6, 28, ProjectionMethod::Dow28);
    let food_d = find_proj(&dw, "5010");
    // 各曜日平均 1000、残 2 日とも 1000 → 30000
    assert_eq!(food_d.projected, Yen::new(30_000));
}
