//! fiscal (月次確定状態機械・損益振替) のテスト。

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

fn d(month: u8) -> Date {
    Date::new(2026, month, 15).unwrap()
}

#[test]
fn close_state_machine_is_forward_only() {
    let fc = FiscalClose::new(2026);
    assert!(!fc.is_closed());
    assert_eq!(fc.closed_period(), NOT_CLOSED);
    assert!(!fc.is_period_locked(0));

    let fc6 = fc.close_to(6).unwrap();
    assert!(fc6.is_closed());
    assert_eq!(fc6.closed_period(), 6);
    for p in 0..=6u8 {
        assert!(fc6.is_period_locked(p), "period {p} should be locked");
    }
    for p in 7..=16u8 {
        assert!(!fc6.is_period_locked(p), "period {p} should be open");
    }

    // 前方向のみ
    assert_eq!(fc6.close_to(6), Err(FiscalError::NotForward));
    assert_eq!(fc6.close_to(3), Err(FiscalError::NotForward));
    assert_eq!(fc6.close_to(12).unwrap().closed_period(), 12);
    // 範囲外
    assert_eq!(fc6.close_to(17), Err(FiscalError::PeriodOutOfRange));

    assert!(FiscalClose::with_closed(2026, MAX_PERIOD as i8).is_ok());
    assert_eq!(
        FiscalClose::with_closed(2026, 17),
        Err(FiscalError::PeriodOutOfRange)
    );
    assert_eq!(
        FiscalClose::with_closed(2026, -2),
        Err(FiscalError::PeriodOutOfRange)
    );
}

#[test]
fn date_lock_and_modifiable_guard() {
    let fc = FiscalClose::new(2026).close_to(6).unwrap();
    assert!(fc.is_date_locked(Date::new(2026, 5, 10).unwrap())); // 5月 <= 6
    assert!(fc.is_date_locked(Date::new(2026, 6, 30).unwrap())); // 6月 == 6
    assert!(!fc.is_date_locked(Date::new(2026, 7, 1).unwrap())); // 7月 > 6
    assert!(!fc.is_date_locked(Date::new(2025, 5, 1).unwrap())); // 別年

    assert_eq!(
        fc.check_date_modifiable(Date::new(2026, 5, 1).unwrap()),
        Err(FiscalError::PeriodLocked)
    );
    assert!(fc
        .check_date_modifiable(Date::new(2026, 7, 1).unwrap())
        .is_ok());
}

#[test]
fn monotonic_merge_takes_max() {
    let a = FiscalClose::new(2026).close_to(3).unwrap();
    let b = FiscalClose::new(2026).close_to(8).unwrap();
    assert_eq!(a.merge(b).closed_period(), 8);
    assert_eq!(b.merge(a).closed_period(), 8); // 可換
    assert_eq!(FiscalClose::new(2026).merge(b).closed_period(), 8); // 未確定 + 8

    // 別年はマージしない (self を返す)
    let other_year = FiscalClose::new(2025).close_to(12).unwrap();
    assert_eq!(a.merge(other_year).closed_period(), 3);
}

#[test]
fn closing_entry_zeroes_pl_and_books_retained_earnings() {
    let chart = Chart::standard();
    let entries = vec![
        inc(d(1), "1020", "4010", 300_000), // 給与
        exp(d(2), "1010", "5010", 5_000),   // 食費
        exp(d(3), "1020", "5020", 80_000),  // 住居費
    ];
    let closing = generate_closing_entry(&entries, &chart, 2026)
        .unwrap()
        .unwrap();
    assert!(closing.is_balanced());
    assert_eq!(closing.date, Date::new(2026, 12, 31).unwrap());
    assert_eq!(closing.description, "損益振替");

    // 繰越利益 3020 に当期純利益 215000 が貸方計上。
    let re = closing
        .lines
        .iter()
        .find(|l| l.account.as_str() == "3020")
        .unwrap();
    assert_eq!(re.credit, Yen::new(215_000));
    assert_eq!(re.debit, Yen::ZERO);

    // 振替後: P&L が 0、純資産(繰越利益)に 215000。
    let mut combined = entries.clone();
    combined.push(closing);
    let is = income_statement(&combined, &chart);
    assert_eq!(is.total_revenue, Yen::ZERO);
    assert_eq!(is.total_expense, Yen::ZERO);
    assert_eq!(is.net_income, Yen::ZERO);
    let bs = balance_sheet(&combined, &chart);
    assert!(bs.is_balanced());
    assert_eq!(bs.total_equity, Yen::new(215_000));
}

#[test]
fn closing_entry_net_loss_debits_retained_earnings() {
    let chart = Chart::standard();
    let entries = vec![
        inc(d(1), "1020", "4010", 50_000),
        exp(d(2), "1020", "5020", 80_000),
    ];
    let closing = generate_closing_entry(&entries, &chart, 2026)
        .unwrap()
        .unwrap();
    let re = closing
        .lines
        .iter()
        .find(|l| l.account.as_str() == "3020")
        .unwrap();
    assert_eq!(re.debit, Yen::new(30_000)); // 純損失 30000 → 繰越利益の借方
    assert_eq!(re.credit, Yen::ZERO);
    assert!(closing.is_balanced());
}

#[test]
fn closing_entry_is_none_without_pl_activity() {
    let chart = Chart::standard();
    // 資産間振替のみ (P&L なし)
    let entries = vec![JournalEntry {
        date: d(1),
        description: "預入".into(),
        lines: vec![
            EntryLine::debit(AccountCode::from("1020"), Yen::new(10_000)),
            EntryLine::credit(AccountCode::from("1010"), Yen::new(10_000)),
        ],
    }];
    assert!(generate_closing_entry(&entries, &chart, 2026)
        .unwrap()
        .is_none());
    // 対象年にエントリが無ければ None
    assert!(generate_closing_entry(&entries, &chart, 2030)
        .unwrap()
        .is_none());
}
