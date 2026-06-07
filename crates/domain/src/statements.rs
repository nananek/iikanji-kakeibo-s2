//! 財務諸表: 損益計算書 (P&L)・貸借対照表 (BS)・収支サマリー。
//!
//! いずれも呼び出し側が対象期間の仕訳を渡す純関数。金額の符号は正常残高側を正とする
//! (収益=貸方-借方, 費用=借方-貸方, 資産=借方-貸方, 負債/純資産=貸方-借方)。

use alloc::vec::Vec;

use crate::chart::{AccountCode, AccountType, Chart};
use crate::journal::JournalEntry;
use crate::ledger::account_balances;
use crate::money::Yen;

/// 科目別の 1 行 (コード + 金額)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineItem {
    pub code: AccountCode,
    pub amount: Yen,
}

/// 損益計算書。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomeStatement {
    pub revenues: Vec<LineItem>,
    pub expenses: Vec<LineItem>,
    pub total_revenue: Yen,
    pub total_expense: Yen,
    /// 当期純利益 = 収益合計 − 費用合計。
    pub net_income: Yen,
}

/// 損益計算書を構築する (科目コード昇順)。
pub fn income_statement<'a, I>(entries: I, chart: &Chart) -> IncomeStatement
where
    I: IntoIterator<Item = &'a JournalEntry>,
{
    let balances = account_balances(entries);
    let mut revenues = Vec::new();
    let mut expenses = Vec::new();
    let mut total_revenue = Yen::ZERO;
    let mut total_expense = Yen::ZERO;
    for (code, &(debit, credit)) in &balances {
        match chart.account_type(code) {
            Some(AccountType::Revenue) => {
                let amount = credit - debit;
                total_revenue += amount;
                revenues.push(LineItem {
                    code: code.clone(),
                    amount,
                });
            }
            Some(AccountType::Expense) => {
                let amount = debit - credit;
                total_expense += amount;
                expenses.push(LineItem {
                    code: code.clone(),
                    amount,
                });
            }
            _ => {}
        }
    }
    IncomeStatement {
        revenues,
        expenses,
        total_revenue,
        total_expense,
        net_income: total_revenue - total_expense,
    }
}

/// 貸借対照表。`net_income` は当期純利益 (純資産に未振替の利益)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceSheet {
    pub assets: Vec<LineItem>,
    pub liabilities: Vec<LineItem>,
    pub equity: Vec<LineItem>,
    pub total_assets: Yen,
    pub total_liabilities: Yen,
    pub total_equity: Yen,
    pub net_income: Yen,
}

impl BalanceSheet {
    /// 会計恒等式: 資産 == 負債 + 純資産 + 当期純利益 (健全な仕訳集合なら必ず成立)。
    pub fn is_balanced(&self) -> bool {
        self.total_assets == self.total_liabilities + self.total_equity + self.net_income
    }
}

/// 貸借対照表を構築する (科目コード昇順)。
pub fn balance_sheet<'a, I>(entries: I, chart: &Chart) -> BalanceSheet
where
    I: IntoIterator<Item = &'a JournalEntry>,
{
    let balances = account_balances(entries);
    let mut assets = Vec::new();
    let mut liabilities = Vec::new();
    let mut equity = Vec::new();
    let mut total_assets = Yen::ZERO;
    let mut total_liabilities = Yen::ZERO;
    let mut total_equity = Yen::ZERO;
    let mut total_revenue = Yen::ZERO;
    let mut total_expense = Yen::ZERO;
    for (code, &(debit, credit)) in &balances {
        match chart.account_type(code) {
            Some(AccountType::Asset) => {
                let amount = debit - credit;
                total_assets += amount;
                assets.push(LineItem {
                    code: code.clone(),
                    amount,
                });
            }
            Some(AccountType::Liability) => {
                let amount = credit - debit;
                total_liabilities += amount;
                liabilities.push(LineItem {
                    code: code.clone(),
                    amount,
                });
            }
            Some(AccountType::Equity) => {
                let amount = credit - debit;
                total_equity += amount;
                equity.push(LineItem {
                    code: code.clone(),
                    amount,
                });
            }
            Some(AccountType::Revenue) => total_revenue += credit - debit,
            Some(AccountType::Expense) => total_expense += debit - credit,
            None => {}
        }
    }
    BalanceSheet {
        assets,
        liabilities,
        equity,
        total_assets,
        total_liabilities,
        total_equity,
        net_income: total_revenue - total_expense,
    }
}

/// 収支サマリー (収益・費用・差引)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncomeExpenseSummary {
    pub income: Yen,
    pub expense: Yen,
    pub balance: Yen,
}

/// 収益合計・費用合計・差引 (= 当期純利益) を返す。
pub fn income_expense_summary<'a, I>(entries: I, chart: &Chart) -> IncomeExpenseSummary
where
    I: IntoIterator<Item = &'a JournalEntry>,
{
    let is = income_statement(entries, chart);
    IncomeExpenseSummary {
        income: is.total_revenue,
        expense: is.total_expense,
        balance: is.net_income,
    }
}
