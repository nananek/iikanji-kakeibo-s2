//! 仕訳と出納帳→仕訳生成。複式不変条件 (借方合計 == 貸方合計) を担保する。

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::chart::AccountCode;
use crate::money::Yen;

/// 日付 (年/月/日)。完全な暦検証は後続で強化 (現状は範囲のみ)。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Date {
    year: i32,
    month: u8,
    day: u8,
}

impl Date {
    pub fn new(year: i32, month: u8, day: u8) -> Result<Date, JournalError> {
        if !(1..=12).contains(&month) {
            return Err(JournalError::InvalidDate);
        }
        if !(1..=days_in_month(year, month)).contains(&day) {
            return Err(JournalError::InvalidDate);
        }
        Ok(Date { year, month, day })
    }
    pub fn year(self) -> i32 {
        self.year
    }
    pub fn month(self) -> u8 {
        self.month
    }
    pub fn day(self) -> u8 {
        self.day
    }

    /// Unix epoch (1970-01-01) からの通日。日付差・曜日計算に使う (Howard Hinnant の算法)。
    pub fn to_days(self) -> i64 {
        let y0 = self.year as i64;
        let m = self.month as i64;
        let d = self.day as i64;
        let y = if m <= 2 { y0 - 1 } else { y0 };
        let era = (if y >= 0 { y } else { y - 399 }) / 400;
        let yoe = y - era * 400; // [0, 399]
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        era * 146097 + doe - 719468
    }

    /// 曜日 (0=日曜 .. 6=土曜)。
    pub fn weekday(self) -> u8 {
        (self.to_days() + 4).rem_euclid(7) as u8
    }

    /// その月の日数 (閏年考慮)。
    pub fn month_length(self) -> u8 {
        days_in_month(self.year, self.month)
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

pub(crate) fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// 仕訳明細行。借方・貸方のどちらか一方が正、もう一方は 0 (両方 0 や両方正は不正)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryLine {
    pub account: AccountCode,
    pub debit: Yen,
    pub credit: Yen,
}

impl EntryLine {
    /// 借方行。
    pub fn debit(account: AccountCode, amount: Yen) -> EntryLine {
        EntryLine {
            account,
            debit: amount,
            credit: Yen::ZERO,
        }
    }
    /// 貸方行。
    pub fn credit(account: AccountCode, amount: Yen) -> EntryLine {
        EntryLine {
            account,
            debit: Yen::ZERO,
            credit: amount,
        }
    }

    /// 片側のみ正・もう一方 0・負値なし。
    fn has_valid_sides(&self) -> bool {
        !self.debit.is_negative()
            && !self.credit.is_negative()
            && (self.debit.is_positive() ^ self.credit.is_positive())
    }
}

/// 仕訳。1 件は借方合計と貸方合計が一致する明細行の集合。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub date: Date,
    pub description: String,
    pub lines: Vec<EntryLine>,
}

impl JournalEntry {
    pub fn total_debit(&self) -> Yen {
        self.lines.iter().map(|l| l.debit).sum()
    }
    pub fn total_credit(&self) -> Yen {
        self.lines.iter().map(|l| l.credit).sum()
    }
    /// 借方合計 == 貸方合計。
    pub fn is_balanced(&self) -> bool {
        self.total_debit() == self.total_credit()
    }

    /// 仕訳としての妥当性: 2 行以上・各行の片側性・貸借一致・合計が正。
    pub fn validate(&self) -> Result<(), JournalError> {
        if self.lines.len() < 2 {
            return Err(JournalError::EmptyEntry);
        }
        if !self.lines.iter().all(EntryLine::has_valid_sides) {
            return Err(JournalError::InvalidLine);
        }
        let debit = self.total_debit();
        if debit != self.total_credit() {
            return Err(JournalError::Unbalanced);
        }
        if !debit.is_positive() {
            return Err(JournalError::NonPositiveAmount);
        }
        Ok(())
    }
}

/// 会計ロジックのエラー。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// 日付の範囲外。
    InvalidDate,
    /// 借方合計 != 貸方合計。
    Unbalanced,
    /// 明細行が 2 行未満。
    EmptyEntry,
    /// 明細行が片側性を満たさない (両側正 / 両側 0 / 負値)。
    InvalidLine,
    /// 金額が 0 以下。
    NonPositiveAmount,
}

/// 出納帳の入出金種別。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CashbookKind {
    /// 入金 (収益)
    Income,
    /// 出金 (費用)
    Expense,
}

/// 出納帳 1 行の入力。
#[derive(Clone, Debug)]
pub struct CashbookInput {
    pub date: Date,
    pub kind: CashbookKind,
    /// 決済科目 (現金・普通預金・クレカ等)。
    pub payment_account: AccountCode,
    /// 費目・収入科目 (食費・給与収入等)。
    pub category_account: AccountCode,
    pub amount: Yen,
    pub description: String,
}

/// 出納帳入力を 2 行仕訳へ変換する。
///
/// - 出金: 借方=費目, 貸方=決済科目
/// - 入金: 借方=決済科目, 貸方=収入科目
pub fn cashbook_to_entry(input: CashbookInput) -> Result<JournalEntry, JournalError> {
    if !input.amount.is_positive() {
        return Err(JournalError::NonPositiveAmount);
    }
    let lines = match input.kind {
        CashbookKind::Expense => vec![
            EntryLine::debit(input.category_account, input.amount),
            EntryLine::credit(input.payment_account, input.amount),
        ],
        CashbookKind::Income => vec![
            EntryLine::debit(input.payment_account, input.amount),
            EntryLine::credit(input.category_account, input.amount),
        ],
    };
    let entry = JournalEntry {
        date: input.date,
        description: input.description,
        lines,
    };
    // 構成上必ず balanced だが、不変条件を明示的に検証する。
    entry.validate()?;
    Ok(entry)
}
