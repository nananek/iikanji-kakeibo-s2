//! 月次比較 (固定/変動/随時 × 12ヶ月) と月末着地予測。
//!
//! 予測方針 (旧アプリ踏襲):
//! - 固定費 (Fixed): 前月の総額を再利用。
//! - 変動費 (Variable): 当月実績を手法で外挿。
//! - 随時費 (Occasional) / 区分なし (None): 当月実績をそのまま採用 (外挿しない)。

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::chart::{AccountCode, AccountType, Chart, CostType};
use crate::journal::{days_in_month, Date, JournalEntry};
use crate::money::Yen;

/// 科目 1 行の月次推移 (1 月 = index 0)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonthlyRow {
    pub code: AccountCode,
    pub cost_type: Option<CostType>,
    pub monthly: [Yen; 12],
    pub total: Yen,
}

/// 月次比較。費用は固定/変動/随時の小計も持つ。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonthlyComparison {
    pub expense_rows: Vec<MonthlyRow>,
    pub income_rows: Vec<MonthlyRow>,
    pub expense_totals: [Yen; 12],
    pub income_totals: [Yen; 12],
    pub fixed_totals: [Yen; 12],
    pub variable_totals: [Yen; 12],
    pub occasional_totals: [Yen; 12],
}

/// 指定年の月次比較を構築する (科目コード昇順)。
pub fn monthly_comparison<'a, I>(entries: I, year: i32, chart: &Chart) -> MonthlyComparison
where
    I: IntoIterator<Item = &'a JournalEntry>,
{
    let mut exp: BTreeMap<AccountCode, [Yen; 12]> = BTreeMap::new();
    let mut inc: BTreeMap<AccountCode, [Yen; 12]> = BTreeMap::new();
    for entry in entries {
        if entry.date.year() != year {
            continue;
        }
        let m = (entry.date.month() - 1) as usize;
        for line in &entry.lines {
            match chart.account_type(&line.account) {
                Some(AccountType::Expense) => {
                    exp.entry(line.account.clone()).or_insert([Yen::ZERO; 12])[m] +=
                        line.debit - line.credit;
                }
                Some(AccountType::Revenue) => {
                    inc.entry(line.account.clone()).or_insert([Yen::ZERO; 12])[m] +=
                        line.credit - line.debit;
                }
                _ => {}
            }
        }
    }

    let mut expense_rows = Vec::new();
    let mut expense_totals = [Yen::ZERO; 12];
    let mut fixed_totals = [Yen::ZERO; 12];
    let mut variable_totals = [Yen::ZERO; 12];
    let mut occasional_totals = [Yen::ZERO; 12];
    for (code, monthly) in exp {
        let cost_type = chart.get(&code).and_then(|i| i.cost_type);
        let mut total = Yen::ZERO;
        for (i, v) in monthly.iter().enumerate() {
            expense_totals[i] += *v;
            total += *v;
            match cost_type {
                Some(CostType::Fixed) => fixed_totals[i] += *v,
                Some(CostType::Variable) => variable_totals[i] += *v,
                Some(CostType::Occasional) => occasional_totals[i] += *v,
                None => {}
            }
        }
        expense_rows.push(MonthlyRow {
            code,
            cost_type,
            monthly,
            total,
        });
    }

    let mut income_rows = Vec::new();
    let mut income_totals = [Yen::ZERO; 12];
    for (code, monthly) in inc {
        let mut total = Yen::ZERO;
        for (i, v) in monthly.iter().enumerate() {
            income_totals[i] += *v;
            total += *v;
        }
        income_rows.push(MonthlyRow {
            code,
            cost_type: None,
            monthly,
            total,
        });
    }

    MonthlyComparison {
        expense_rows,
        income_rows,
        expense_totals,
        income_totals,
        fixed_totals,
        variable_totals,
        occasional_totals,
    }
}

/// 月末着地予測の手法。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionMethod {
    /// 当月実績を経過日数で線形外挿。
    ProRata,
    /// 直近 28 日の平均日額 × 残日数を加算。
    Rolling28,
    /// 直近 28 日の曜日別平均を残日それぞれの曜日に適用して加算。
    Dow28,
}

/// 科目 1 件の予測。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountProjection {
    pub code: AccountCode,
    pub cost_type: Option<CostType>,
    /// 月初〜as_of の実績。
    pub actual: Yen,
    /// 月末着地予測。
    pub projected: Yen,
}

/// 月末着地予測の全体 (費用科目)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonthProjection {
    pub rows: Vec<AccountProjection>,
    pub total_actual: Yen,
    pub total_projected: Yen,
}

/// 指定月 (year, month) の費用科目について、as_of_day 時点の実績から月末着地を予測する。
pub fn project_month<'a, I>(
    entries: I,
    chart: &Chart,
    year: i32,
    month: u8,
    as_of_day: u8,
    method: ProjectionMethod,
) -> MonthProjection
where
    I: IntoIterator<Item = &'a JournalEntry>,
{
    let dim = days_in_month(year, month);
    let as_of_day = as_of_day.clamp(1, dim);
    let as_of = Date::new(year, month, as_of_day).expect("clamped to a valid day");
    let (prev_year, prev_month) = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };

    let window_start = as_of.to_days() - 27;
    let as_of_days = as_of.to_days();

    let mut mtd: BTreeMap<AccountCode, Yen> = BTreeMap::new();
    let mut prev: BTreeMap<AccountCode, Yen> = BTreeMap::new();
    let mut trailing_total: BTreeMap<AccountCode, Yen> = BTreeMap::new();
    let mut trailing_dow: BTreeMap<AccountCode, [Yen; 7]> = BTreeMap::new();

    for entry in entries {
        let ed = entry.date;
        for line in &entry.lines {
            if chart.account_type(&line.account) != Some(AccountType::Expense) {
                continue;
            }
            let amount = line.debit - line.credit;
            if ed.year() == year && ed.month() == month && ed.day() <= as_of_day {
                *mtd.entry(line.account.clone()).or_insert(Yen::ZERO) += amount;
            }
            if ed.year() == prev_year && ed.month() == prev_month {
                *prev.entry(line.account.clone()).or_insert(Yen::ZERO) += amount;
            }
            let edd = ed.to_days();
            if edd >= window_start && edd <= as_of_days {
                *trailing_total
                    .entry(line.account.clone())
                    .or_insert(Yen::ZERO) += amount;
                trailing_dow
                    .entry(line.account.clone())
                    .or_insert([Yen::ZERO; 7])[ed.weekday() as usize] += amount;
            }
        }
    }

    let mut codes: BTreeSet<AccountCode> = BTreeSet::new();
    codes.extend(mtd.keys().cloned());
    codes.extend(prev.keys().cloned());

    let remaining = (dim - as_of_day) as i64;
    let mut rows = Vec::new();
    let mut total_actual = Yen::ZERO;
    let mut total_projected = Yen::ZERO;
    for code in codes {
        let actual = mtd.get(&code).copied().unwrap_or(Yen::ZERO);
        let cost_type = chart.get(&code).and_then(|i| i.cost_type);
        let projected = match cost_type {
            // 固定費: 前月総額を再利用 (前月実績が無ければ当月実績)。
            Some(CostType::Fixed) => prev.get(&code).copied().unwrap_or(actual),
            // 随時費・区分なし: 外挿しない。
            Some(CostType::Occasional) | None => actual,
            // 変動費: 手法で外挿。
            Some(CostType::Variable) => match method {
                ProjectionMethod::ProRata => {
                    Yen::new(actual.amount() * dim as i64 / as_of_day as i64)
                }
                ProjectionMethod::Rolling28 => {
                    let avg_daily = trailing_total
                        .get(&code)
                        .copied()
                        .unwrap_or(Yen::ZERO)
                        .amount()
                        / 28;
                    Yen::new(actual.amount() + avg_daily * remaining)
                }
                ProjectionMethod::Dow28 => {
                    let by = trailing_dow.get(&code).copied().unwrap_or([Yen::ZERO; 7]);
                    let mut add = 0i64;
                    for day in (as_of_day + 1)..=dim {
                        let wd = Date::new(year, month, day)
                            .expect("valid day in month")
                            .weekday() as usize;
                        // 28 日窓では各曜日が 4 回 → 平均 = 合計 / 4。
                        add += by[wd].amount() / 4;
                    }
                    Yen::new(actual.amount() + add)
                }
            },
        };
        total_actual += actual;
        total_projected += projected;
        rows.push(AccountProjection {
            code,
            cost_type,
            actual,
            projected,
        });
    }

    MonthProjection {
        rows,
        total_actual,
        total_projected,
    }
}
