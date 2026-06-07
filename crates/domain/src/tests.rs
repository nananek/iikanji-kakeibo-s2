//! domain の単体・golden・不変条件テスト。複式不変条件 (借方==貸方) を重点的に検証する。

use crate::*;
use std::collections::HashSet;

// ---- money ----

#[test]
fn yen_basic_arithmetic() {
    assert_eq!(Yen::ZERO.amount(), 0);
    assert_eq!(Yen::new(100).amount(), 100);
    assert_eq!((Yen::new(100) + Yen::new(50)).amount(), 150);
    assert_eq!((Yen::new(100) - Yen::new(150)).amount(), -50);
    assert_eq!((-Yen::new(30)).amount(), -30);
    assert_eq!(Yen::new(-7).abs().amount(), 7);
    assert!(Yen::new(-1).is_negative());
    assert!(Yen::new(1).is_positive());
    assert!(Yen::ZERO.is_zero());

    let sum: Yen = [Yen::new(1), Yen::new(2), Yen::new(3)].into_iter().sum();
    assert_eq!(sum.amount(), 6);

    assert_eq!(Yen::new(i64::MAX).checked_add(Yen::new(1)), None);
    assert_eq!(Yen::new(10).checked_sub(Yen::new(4)), Some(Yen::new(6)));
    assert!(Yen::new(5) > Yen::new(3));
}

// ---- chart ----

#[test]
fn standard_chart_is_well_formed() {
    let chart = standard_chart();
    // README のカタログを反映した件数。
    assert_eq!(chart.len(), 45);
    assert_eq!(STANDARD_CHART_VERSION, 1);

    // コード一意。
    let mut codes = HashSet::new();
    for d in chart {
        assert!(codes.insert(d.code), "duplicate code {}", d.code);
    }

    // normal_balance が区分どおり。
    for d in chart {
        let expected = match d.account_type {
            AccountType::Asset | AccountType::Expense => Side::Debit,
            AccountType::Liability | AccountType::Equity | AccountType::Revenue => Side::Credit,
        };
        assert_eq!(d.account_type.normal_balance(), expected, "code {}", d.code);
    }
}

#[test]
fn chart_standard_lookup() {
    let chart = Chart::standard();
    assert_eq!(chart.len(), 45);
    assert!(!chart.is_empty());

    let cash = AccountCode::from("1010");
    assert_eq!(chart.account_type(&cash), Some(AccountType::Asset));
    assert_eq!(chart.normal_balance(&cash), Some(Side::Debit));
    assert_eq!(chart.get(&cash).unwrap().name, "現金");

    // system_role / tax_category / cost_type
    assert_eq!(
        chart.get(&AccountCode::from("3010")).unwrap().system_role,
        Some(SystemRole::Capital)
    );
    assert_eq!(
        chart.get(&AccountCode::from("3020")).unwrap().system_role,
        Some(SystemRole::RetainedEarnings)
    );
    assert_eq!(
        chart.get(&AccountCode::from("6010")).unwrap().tax_category,
        Some(TaxCategory::Medical)
    );
    assert_eq!(
        chart.get(&AccountCode::from("5020")).unwrap().cost_type,
        Some(CostType::Fixed)
    );

    // 顧問用 "事業主/proprietor" は廃止 → 3030 は存在しない。
    assert!(chart.get(&AccountCode::from("3030")).is_none());
    // 未知科目。
    assert_eq!(chart.normal_balance(&AccountCode::from("9999")), None);
}

// ---- journal ----

#[test]
fn date_validation() {
    assert!(Date::new(2026, 6, 7).is_ok());
    assert_eq!(Date::new(2026, 13, 1), Err(JournalError::InvalidDate));
    assert_eq!(Date::new(2026, 0, 1), Err(JournalError::InvalidDate));
    assert_eq!(Date::new(2026, 6, 0), Err(JournalError::InvalidDate));
    assert_eq!(Date::new(2026, 6, 32), Err(JournalError::InvalidDate));
    let d = Date::new(2026, 6, 7).unwrap();
    assert_eq!((d.year(), d.month(), d.day()), (2026, 6, 7));
}

#[test]
fn journal_entry_balance_and_validation() {
    let d = Date::new(2026, 6, 7).unwrap();

    // balanced 2 行
    let ok = JournalEntry {
        date: d,
        description: "test".into(),
        lines: vec![
            EntryLine::debit(AccountCode::from("5010"), Yen::new(1000)),
            EntryLine::credit(AccountCode::from("1010"), Yen::new(1000)),
        ],
    };
    assert!(ok.is_balanced());
    assert_eq!(ok.total_debit(), Yen::new(1000));
    assert_eq!(ok.total_credit(), Yen::new(1000));
    assert!(ok.validate().is_ok());

    // unbalanced
    let unbalanced = JournalEntry {
        date: d,
        description: "x".into(),
        lines: vec![
            EntryLine::debit(AccountCode::from("5010"), Yen::new(1000)),
            EntryLine::credit(AccountCode::from("1010"), Yen::new(900)),
        ],
    };
    assert!(!unbalanced.is_balanced());
    assert_eq!(unbalanced.validate(), Err(JournalError::Unbalanced));

    // 1 行のみ
    let single = JournalEntry {
        date: d,
        description: "x".into(),
        lines: vec![EntryLine::debit(AccountCode::from("5010"), Yen::new(1))],
    };
    assert_eq!(single.validate(), Err(JournalError::EmptyEntry));

    // 両側正の行 (片側性違反)
    let two_sided = JournalEntry {
        date: d,
        description: "x".into(),
        lines: vec![
            EntryLine {
                account: AccountCode::from("5010"),
                debit: Yen::new(100),
                credit: Yen::new(100),
            },
            EntryLine::credit(AccountCode::from("1010"), Yen::new(100)),
        ],
    };
    assert_eq!(two_sided.validate(), Err(JournalError::InvalidLine));

    // 合計 0 (片側性は満たすが金額が無い → 片側性で弾かれる: debit=0,credit=0)
    let zero = JournalEntry {
        date: d,
        description: "x".into(),
        lines: vec![
            EntryLine {
                account: AccountCode::from("5010"),
                debit: Yen::ZERO,
                credit: Yen::ZERO,
            },
            EntryLine {
                account: AccountCode::from("1010"),
                debit: Yen::ZERO,
                credit: Yen::ZERO,
            },
        ],
    };
    assert_eq!(zero.validate(), Err(JournalError::InvalidLine));
}

#[test]
fn cashbook_generates_correct_double_entry() {
    let d = Date::new(2026, 6, 7).unwrap();

    // 出金: 食費 1500 を現金で
    let expense = cashbook_to_entry(CashbookInput {
        date: d,
        kind: CashbookKind::Expense,
        payment_account: AccountCode::from("1010"),
        category_account: AccountCode::from("5010"),
        amount: Yen::new(1500),
        description: "昼食".into(),
    })
    .unwrap();
    assert!(expense.is_balanced());
    // 借方=食費, 貸方=現金
    assert_eq!(
        expense.lines[0],
        EntryLine::debit(AccountCode::from("5010"), Yen::new(1500))
    );
    assert_eq!(
        expense.lines[1],
        EntryLine::credit(AccountCode::from("1010"), Yen::new(1500))
    );

    // 入金: 給与 300000 を普通預金で
    let income = cashbook_to_entry(CashbookInput {
        date: d,
        kind: CashbookKind::Income,
        payment_account: AccountCode::from("1020"),
        category_account: AccountCode::from("4010"),
        amount: Yen::new(300_000),
        description: "給与".into(),
    })
    .unwrap();
    assert!(income.is_balanced());
    // 借方=普通預金, 貸方=給与収入
    assert_eq!(
        income.lines[0],
        EntryLine::debit(AccountCode::from("1020"), Yen::new(300_000))
    );
    assert_eq!(
        income.lines[1],
        EntryLine::credit(AccountCode::from("4010"), Yen::new(300_000))
    );

    // 0 以下は拒否
    let bad = cashbook_to_entry(CashbookInput {
        date: d,
        kind: CashbookKind::Expense,
        payment_account: AccountCode::from("1010"),
        category_account: AccountCode::from("5010"),
        amount: Yen::ZERO,
        description: "x".into(),
    });
    assert_eq!(bad, Err(JournalError::NonPositiveAmount));
}

// ---- ledger ----

#[test]
fn trial_balance_known_scenario() {
    let d = Date::new(2026, 6, 7).unwrap();
    let entries = vec![
        // 給与 300000 → 普通預金
        cashbook_to_entry(CashbookInput {
            date: d,
            kind: CashbookKind::Income,
            payment_account: AccountCode::from("1020"),
            category_account: AccountCode::from("4010"),
            amount: Yen::new(300_000),
            description: "給与".into(),
        })
        .unwrap(),
        // 食費 5000 → 現金
        cashbook_to_entry(CashbookInput {
            date: d,
            kind: CashbookKind::Expense,
            payment_account: AccountCode::from("1010"),
            category_account: AccountCode::from("5010"),
            amount: Yen::new(5_000),
            description: "食費".into(),
        })
        .unwrap(),
    ];

    let tb = trial_balance(&entries);
    assert!(tb.is_balanced());
    assert_eq!(tb.total_debit, Yen::new(305_000));
    assert_eq!(tb.total_credit, Yen::new(305_000));

    let chart = Chart::standard();
    let find = |code: &str| {
        tb.rows
            .iter()
            .find(|r| r.code.as_str() == code)
            .unwrap_or_else(|| panic!("missing {code}"))
    };

    // 普通預金 (資産, 借方正常): +300000
    let fukotsu = find("1020");
    assert_eq!(
        fukotsu.net(chart.normal_balance(&AccountCode::from("1020")).unwrap()),
        Yen::new(300_000)
    );
    // 現金 (資産): -5000
    let cash = find("1010");
    assert_eq!(
        cash.net(chart.normal_balance(&AccountCode::from("1010")).unwrap()),
        Yen::new(-5_000)
    );
    // 給与収入 (収益, 貸方正常): +300000
    let salary = find("4010");
    assert_eq!(
        salary.net(chart.normal_balance(&AccountCode::from("4010")).unwrap()),
        Yen::new(300_000)
    );
    // 食費 (費用, 借方正常): +5000
    let food = find("5010");
    assert_eq!(
        food.net(chart.normal_balance(&AccountCode::from("5010")).unwrap()),
        Yen::new(5_000)
    );

    // rows はコード昇順
    let codes: Vec<&str> = tb.rows.iter().map(|r| r.code.as_str()).collect();
    let mut sorted = codes.clone();
    sorted.sort_unstable();
    assert_eq!(codes, sorted);
}

// ---- 不変条件 (決定的ランダム) ----

struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[(self.next_u64() % items.len() as u64) as usize]
    }
    fn amount(&mut self) -> Yen {
        Yen::new(1 + (self.next_u64() % 1_000_000) as i64)
    }
}

#[test]
fn double_entry_invariant_holds_over_random_entries() {
    let mut rng = Lcg(0x1234_5678_9abc_def0);
    let payments = ["1010", "1020", "1040", "2010"];
    let expenses = [
        "5010", "5020", "5030", "5040", "5050", "5060", "5070", "5080", "5090", "5100", "5110",
        "5120", "6010",
    ];
    let incomes = ["4010", "4020", "4030", "4040", "4050"];
    let d = Date::new(2026, 6, 7).unwrap();

    let mut entries = Vec::new();
    for _ in 0..2000 {
        let income = rng.next_u64().is_multiple_of(2);
        let kind = if income {
            CashbookKind::Income
        } else {
            CashbookKind::Expense
        };
        let category = if income {
            rng.pick(&incomes)
        } else {
            rng.pick(&expenses)
        };
        let entry = cashbook_to_entry(CashbookInput {
            date: d,
            kind,
            payment_account: AccountCode::from(rng.pick(&payments)),
            category_account: AccountCode::from(category),
            amount: rng.amount(),
            description: "rng".into(),
        })
        .unwrap();
        assert!(entry.is_balanced(), "every generated entry is balanced");
        entries.push(entry);
    }

    // 全体でも借方総計 == 貸方総計。
    let tb = trial_balance(&entries);
    assert!(tb.is_balanced());
    // account_balances の総和も一致。
    let (sum_d, sum_c) = account_balances(&entries)
        .values()
        .fold((Yen::ZERO, Yen::ZERO), |(ad, ac), (d, c)| {
            (ad + *d, ac + *c)
        });
    assert_eq!(sum_d, sum_c);
    assert_eq!(sum_d, tb.total_debit);
}
