//! 残高ロールアップと試算表。

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::chart::{AccountCode, Side};
use crate::journal::JournalEntry;
use crate::money::Yen;

/// 1 科目の借方・貸方累計。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountBalance {
    pub code: AccountCode,
    pub debit_total: Yen,
    pub credit_total: Yen,
}

impl AccountBalance {
    /// 正常残高側に対する純額 (正常側がプラスになる)。
    pub fn net(&self, normal_balance: Side) -> Yen {
        match normal_balance {
            Side::Debit => self.debit_total - self.credit_total,
            Side::Credit => self.credit_total - self.debit_total,
        }
    }
}

/// 試算表。科目別の借方/貸方累計と総計。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialBalance {
    /// コード昇順。
    pub rows: Vec<AccountBalance>,
    pub total_debit: Yen,
    pub total_credit: Yen,
}

impl TrialBalance {
    /// 借方総計 == 貸方総計 (健全な仕訳集合なら必ず成立)。
    pub fn is_balanced(&self) -> bool {
        self.total_debit == self.total_credit
    }
}

/// 科目別の (借方累計, 貸方累計) を集計する。
pub fn account_balances<'a, I>(entries: I) -> BTreeMap<AccountCode, (Yen, Yen)>
where
    I: IntoIterator<Item = &'a JournalEntry>,
{
    let mut map: BTreeMap<AccountCode, (Yen, Yen)> = BTreeMap::new();
    for entry in entries {
        for line in &entry.lines {
            let slot = map
                .entry(line.account.clone())
                .or_insert((Yen::ZERO, Yen::ZERO));
            slot.0 += line.debit;
            slot.1 += line.credit;
        }
    }
    map
}

/// 試算表を構築する (科目コード昇順)。
pub fn trial_balance<'a, I>(entries: I) -> TrialBalance
where
    I: IntoIterator<Item = &'a JournalEntry>,
{
    let mut rows = Vec::new();
    let mut total_debit = Yen::ZERO;
    let mut total_credit = Yen::ZERO;
    for (code, (debit, credit)) in account_balances(entries) {
        total_debit += debit;
        total_credit += credit;
        rows.push(AccountBalance {
            code,
            debit_total: debit,
            credit_total: credit,
        });
    }
    TrialBalance {
        rows,
        total_debit,
        total_credit,
    }
}
