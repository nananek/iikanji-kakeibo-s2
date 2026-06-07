//! 確定申告向けの税区分集計。`tax_category` を持つ科目を区分ごとに合算する。

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::chart::{Chart, TaxCategory};
use crate::journal::JournalEntry;
use crate::ledger::account_balances;
use crate::money::Yen;
use crate::statements::LineItem;

/// 1 税区分の集計 (該当科目とその合計)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxCategorySummary {
    pub category: TaxCategory,
    pub accounts: Vec<LineItem>,
    pub total: Yen,
}

/// 税区分ごとに集計する (区分は宣言順、科目はコード昇順)。
///
/// 控除対象は費用科目を想定し、金額は純額 (借方−貸方) を用いる。医療費の明細内訳は
/// [`crate::medical::medical_summary`] で別途扱う (本集計には医療費科目の総額が入る)。
pub fn tax_summary<'a, I>(entries: I, chart: &Chart) -> Vec<TaxCategorySummary>
where
    I: IntoIterator<Item = &'a JournalEntry>,
{
    let balances = account_balances(entries);
    let mut map: BTreeMap<TaxCategory, (Vec<LineItem>, Yen)> = BTreeMap::new();
    for (code, &(debit, credit)) in &balances {
        if let Some(info) = chart.get(code) {
            if let Some(category) = info.tax_category {
                let amount = debit - credit;
                let slot = map.entry(category).or_insert((Vec::new(), Yen::ZERO));
                slot.0.push(LineItem {
                    code: code.clone(),
                    amount,
                });
                slot.1 += amount;
            }
        }
    }
    map.into_iter()
        .map(|(category, (accounts, total))| TaxCategorySummary {
            category,
            accounts,
            total,
        })
        .collect()
}
