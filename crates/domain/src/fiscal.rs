//! 月次確定 (fiscal-close) の状態機械と損益振替仕訳の生成。
//!
//! `closed_period` は -1(未確定)..=16。会計期間は 0=期首 / 1-12=月 / 13-15=決算整理 / 16=損益振替。
//! 締めは**前方向にのみ進む**ラッチで、`period <= closed_period` の仕訳は immutable。
//! 多デバイスでは `closed_period = max(local, remote)` の**単調マージ**で収束させる (素朴 LWW 禁止)。

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::chart::{AccountType, Chart, SystemRole};
use crate::journal::{Date, EntryLine, JournalEntry};
use crate::ledger::account_balances;
use crate::money::Yen;

/// 未確定を表す `closed_period` 値。
pub const NOT_CLOSED: i8 = -1;
/// 期首期間。
pub const OPENING_PERIOD: u8 = 0;
/// 損益振替期間 (自動生成専用)。
pub const TRANSFER_PERIOD: u8 = 16;
/// `closed_period` の最大値。
pub const MAX_PERIOD: u8 = 16;

/// 会計ロジック (fiscal) のエラー。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FiscalError {
    /// period が 0..=16 の範囲外。
    PeriodOutOfRange,
    /// 締めを後退/同一 period へ進めようとした (前方向のみ許可)。
    NotForward,
    /// 確定済み期間の仕訳を変更しようとした。
    PeriodLocked,
    /// 繰越利益 (system_role=RetainedEarnings) 科目がカタログに無い。
    NoRetainedEarnings,
}

/// 1 年度の月次確定状態。`closed_period` は前方向にのみ進む。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FiscalClose {
    year: i32,
    closed_period: i8,
}

impl FiscalClose {
    /// 未確定の状態を作る。
    pub fn new(year: i32) -> Self {
        Self {
            year,
            closed_period: NOT_CLOSED,
        }
    }

    /// `closed_period` を指定して復元する (同期で受け取った状態など)。
    pub fn with_closed(year: i32, closed_period: i8) -> Result<Self, FiscalError> {
        if !(NOT_CLOSED..=(MAX_PERIOD as i8)).contains(&closed_period) {
            return Err(FiscalError::PeriodOutOfRange);
        }
        Ok(Self {
            year,
            closed_period,
        })
    }

    pub fn year(self) -> i32 {
        self.year
    }
    pub fn closed_period(self) -> i8 {
        self.closed_period
    }
    pub fn is_closed(self) -> bool {
        self.closed_period >= 0
    }

    /// period (0..=16) が確定済み (ロック) か。
    pub fn is_period_locked(self, period: u8) -> bool {
        (period as i8) <= self.closed_period
    }

    /// 通常仕訳 (period = 月) がロックされているか。別年は対象外。
    pub fn is_date_locked(self, date: Date) -> bool {
        date.year() == self.year && self.is_period_locked(date.month())
    }

    /// 指定 date の通常仕訳が変更可能かを判定する (ロック時 `PeriodLocked`)。
    pub fn check_date_modifiable(self, date: Date) -> Result<(), FiscalError> {
        if self.is_date_locked(date) {
            Err(FiscalError::PeriodLocked)
        } else {
            Ok(())
        }
    }

    /// `target` まで確定を進める。前方向のみ (target > 現在の closed_period)。
    pub fn close_to(self, target: u8) -> Result<Self, FiscalError> {
        if target > MAX_PERIOD {
            return Err(FiscalError::PeriodOutOfRange);
        }
        if (target as i8) <= self.closed_period {
            return Err(FiscalError::NotForward);
        }
        Ok(Self {
            year: self.year,
            closed_period: target as i8,
        })
    }

    /// 多デバイス単調マージ: `closed_period = max(local, remote)`。年が異なる場合は self を返す。
    pub fn merge(self, other: FiscalClose) -> Self {
        if self.year != other.year {
            return self;
        }
        Self {
            year: self.year,
            closed_period: self.closed_period.max(other.closed_period),
        }
    }
}

/// 指定年の損益振替 (決算) 仕訳を生成する。
///
/// 収益・費用の各科目を 0 にする行と、差額を繰越利益へ振り替える行を持つ均衡仕訳。
/// 対象 P&L 残高が無ければ `None`。日付は year-12-31、摘要は「損益振替」。
pub fn generate_closing_entry<'a, I>(
    entries: I,
    chart: &Chart,
    year: i32,
) -> Result<Option<JournalEntry>, FiscalError>
where
    I: IntoIterator<Item = &'a JournalEntry>,
{
    let retained = chart
        .iter()
        .find(|a| a.system_role == Some(SystemRole::RetainedEarnings))
        .map(|a| a.code.clone())
        .ok_or(FiscalError::NoRetainedEarnings)?;

    let year_entries: Vec<&JournalEntry> = entries
        .into_iter()
        .filter(|e| e.date.year() == year)
        .collect();
    let balances = account_balances(year_entries.iter().copied());

    let mut lines = Vec::new();
    let mut posted_debit = Yen::ZERO;
    let mut posted_credit = Yen::ZERO;
    for (code, &(debit, credit)) in &balances {
        match chart.account_type(code) {
            Some(AccountType::Revenue) | Some(AccountType::Expense) => {}
            _ => continue,
        }
        // 残高を反対側に振って 0 にする。
        let raw = debit - credit;
        if raw.is_positive() {
            lines.push(EntryLine::credit(code.clone(), raw));
            posted_credit += raw;
        } else if raw.is_negative() {
            let amount = -raw;
            lines.push(EntryLine::debit(code.clone(), amount));
            posted_debit += amount;
        }
    }

    if lines.is_empty() {
        return Ok(None);
    }

    // 差額を繰越利益で均衡させる。
    let diff = posted_debit - posted_credit;
    if diff.is_positive() {
        lines.push(EntryLine::credit(retained, diff));
    } else if diff.is_negative() {
        lines.push(EntryLine::debit(retained, -diff));
    }

    let entry = JournalEntry {
        date: Date::new(year, 12, 31).expect("Dec 31 is always valid"),
        description: "損益振替".to_string(),
        lines,
    };
    debug_assert!(entry.is_balanced(), "closing entry must balance");
    Ok(Some(entry))
}
