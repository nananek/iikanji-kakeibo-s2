//! `iikanji-domain` — 純会計ロジック (複式簿記・StandardChart・試算表・元帳)。
//!
//! 方針 (CLAUDE.md):
//! - **no_std + alloc / I/O 無し**。client (WASM) と server で共有し、将来の native/CLI でも再利用。
//! - **金額は整数 (円, [`Yen`])。float 厳禁**。
//! - 標準勘定科目は [`standard_chart`] にコンパイル同梱した版管理カタログ。ユーザー差分の
//!   merge は records/sync 連携 PR で追加する。
//!
//! このスライスの範囲: money / chart / journal (出納帳→仕訳・複式不変条件) / ledger (残高・試算表)。
//! 後続 PR: reports (PL/BS・税集計・月次比較・着地予測) / fiscal (締め状態機械) / import (CSV/OFX/Web)。

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod chart;
mod journal;
mod ledger;
mod money;

#[cfg(test)]
mod tests;

pub use chart::{
    standard_chart, AccountCode, AccountInfo, AccountType, Chart, CostType, Side,
    StandardAccountDef, SystemRole, TaxCategory, STANDARD_CHART_VERSION,
};
pub use journal::{
    cashbook_to_entry, CashbookInput, CashbookKind, Date, EntryLine, JournalEntry, JournalError,
};
pub use ledger::{account_balances, trial_balance, AccountBalance, TrialBalance};
pub use money::Yen;
