//! 勘定科目と StandardChart カタログ。
//!
//! 標準科目はこの crate にコンパイル同梱した不変・版管理カタログ ([`standard_chart`])。
//! `enc_records` にはユーザー差分のみを保存し、実効 chart = merge(カタログ, 差分) で構成する
//! (merge は records/sync 連携 PR で追加)。顧問 (auditor) 機能は廃止のため `事業主/proprietor` は除外。

use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use core::fmt;

/// 勘定科目コード (例: "1010")。ユーザー追加科目も扱えるよう文字列で保持する。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountCode(String);

impl AccountCode {
    pub fn new(code: impl Into<String>) -> Self {
        AccountCode(code.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for AccountCode {
    fn from(s: &str) -> Self {
        AccountCode(s.to_owned())
    }
}

impl fmt::Debug for AccountCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountCode({})", self.0)
    }
}

impl fmt::Display for AccountCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 勘定科目の 5 区分。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AccountType {
    Asset,
    Liability,
    Equity,
    Revenue,
    Expense,
}

/// 借方 / 貸方。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Debit,
    Credit,
}

impl AccountType {
    /// 正常残高がどちら側か。資産・費用は借方、負債・純資産・収益は貸方。
    pub const fn normal_balance(self) -> Side {
        match self {
            AccountType::Asset | AccountType::Expense => Side::Debit,
            AccountType::Liability | AccountType::Equity | AccountType::Revenue => Side::Credit,
        }
    }
}

/// 確定申告の税区分 (集計用)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaxCategory {
    /// 医療費控除
    Medical,
    /// 社会保険料控除
    SocialInsurance,
    /// 生命保険料控除
    LifeInsurance,
    /// 地震保険料控除
    EarthquakeInsurance,
    /// 寄附金控除
    Donation,
    /// 小規模企業共済等掛金控除
    SmallBusinessMutualAid,
    /// 源泉所得税
    WithholdingTax,
    /// 住民税
    ResidentTax,
}

/// 費目の性質 (月次比較・着地予測で使用)。割り当ては暫定で、reports PR で調整しうる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CostType {
    /// 固定費
    Fixed,
    /// 変動費
    Variable,
    /// 随時費
    Occasional,
}

/// 特殊な役割を持つ科目 (締め処理等で参照)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SystemRole {
    /// 元入金
    Capital,
    /// 繰越利益
    RetainedEarnings,
}

/// カタログ 1 行 (静的データ)。
#[derive(Clone, Copy, Debug)]
pub struct StandardAccountDef {
    pub code: &'static str,
    pub account_type: AccountType,
    pub name: &'static str,
    pub tax_category: Option<TaxCategory>,
    pub cost_type: Option<CostType>,
    pub system_role: Option<SystemRole>,
}

/// StandardChart の版。新標準科目を出すときに上げ、merge を版管理する。
pub const STANDARD_CHART_VERSION: u32 = 1;

const fn def(
    code: &'static str,
    account_type: AccountType,
    name: &'static str,
    tax_category: Option<TaxCategory>,
    cost_type: Option<CostType>,
    system_role: Option<SystemRole>,
) -> StandardAccountDef {
    StandardAccountDef {
        code,
        account_type,
        name,
        tax_category,
        cost_type,
        system_role,
    }
}

use AccountType::{Asset, Equity, Expense, Liability, Revenue};
use CostType::{Fixed, Occasional, Variable};
use SystemRole::{Capital, RetainedEarnings};
use TaxCategory::{
    Donation, EarthquakeInsurance, LifeInsurance, Medical, ResidentTax, SmallBusinessMutualAid,
    SocialInsurance, WithholdingTax,
};

static STANDARD: &[StandardAccountDef] = &[
    // 資産
    def("1010", Asset, "現金", None, None, None),
    def("1020", Asset, "普通預金", None, None, None),
    def("1030", Asset, "定期預金", None, None, None),
    def("1040", Asset, "電子マネー", None, None, None),
    def("1050", Asset, "有価証券", None, None, None),
    def("1060", Asset, "未収入金", None, None, None),
    // 負債
    def("2010", Liability, "クレジットカード", None, None, None),
    def("2020", Liability, "未払金", None, None, None),
    def("2030", Liability, "借入金", None, None, None),
    def("2040", Liability, "住宅ローン", None, None, None),
    // 純資産
    def("3010", Equity, "元入金", None, None, Some(Capital)),
    def(
        "3020",
        Equity,
        "繰越利益",
        None,
        None,
        Some(RetainedEarnings),
    ),
    // 収益
    def("4010", Revenue, "給与収入", None, None, None),
    def("4020", Revenue, "事業収入", None, None, None),
    def("4030", Revenue, "利息収入", None, None, None),
    def("4040", Revenue, "配当収入", None, None, None),
    def("4050", Revenue, "雑収入", None, None, None),
    // 費用 (生活費)
    def("5010", Expense, "食費", None, Some(Variable), None),
    def("5020", Expense, "住居費", None, Some(Fixed), None),
    def("5030", Expense, "水道光熱費", None, Some(Fixed), None),
    def("5040", Expense, "通信費", None, Some(Fixed), None),
    def("5050", Expense, "交通費", None, Some(Variable), None),
    def("5060", Expense, "日用品費", None, Some(Variable), None),
    def("5070", Expense, "被服費", None, Some(Variable), None),
    def("5080", Expense, "美容費", None, Some(Variable), None),
    def("5090", Expense, "交際費", None, Some(Variable), None),
    def("5100", Expense, "趣味・娯楽費", None, Some(Variable), None),
    def("5110", Expense, "教育費", None, Some(Variable), None),
    def("5120", Expense, "雑費", None, Some(Variable), None),
    // 費用 (医療費控除)
    def(
        "6010",
        Expense,
        "医療費",
        Some(Medical),
        Some(Occasional),
        None,
    ),
    // 費用 (社会保険料控除)
    def(
        "6020",
        Expense,
        "健康保険料",
        Some(SocialInsurance),
        Some(Fixed),
        None,
    ),
    def(
        "6030",
        Expense,
        "厚生年金保険料",
        Some(SocialInsurance),
        Some(Fixed),
        None,
    ),
    def(
        "6040",
        Expense,
        "国民年金保険料",
        Some(SocialInsurance),
        Some(Fixed),
        None,
    ),
    def(
        "6050",
        Expense,
        "国民健康保険料",
        Some(SocialInsurance),
        Some(Fixed),
        None,
    ),
    def(
        "6060",
        Expense,
        "雇用保険料",
        Some(SocialInsurance),
        Some(Fixed),
        None,
    ),
    def(
        "6070",
        Expense,
        "介護保険料",
        Some(SocialInsurance),
        Some(Fixed),
        None,
    ),
    // 費用 (生命保険料控除)
    def(
        "7010",
        Expense,
        "生命保険料",
        Some(LifeInsurance),
        Some(Fixed),
        None,
    ),
    def(
        "7020",
        Expense,
        "個人年金保険料",
        Some(LifeInsurance),
        Some(Fixed),
        None,
    ),
    // 費用 (地震保険料控除)
    def(
        "7030",
        Expense,
        "地震保険料",
        Some(EarthquakeInsurance),
        Some(Fixed),
        None,
    ),
    // 費用 (寄附金控除)
    def(
        "7040",
        Expense,
        "ふるさと納税",
        Some(Donation),
        Some(Occasional),
        None,
    ),
    def(
        "7050",
        Expense,
        "その他寄附金",
        Some(Donation),
        Some(Occasional),
        None,
    ),
    // 費用 (小規模企業共済等掛金控除)
    def(
        "7060",
        Expense,
        "iDeCo掛金",
        Some(SmallBusinessMutualAid),
        Some(Fixed),
        None,
    ),
    def(
        "7070",
        Expense,
        "小規模企業共済",
        Some(SmallBusinessMutualAid),
        Some(Fixed),
        None,
    ),
    // 費用 (税)
    def(
        "8010",
        Expense,
        "源泉所得税",
        Some(WithholdingTax),
        None,
        None,
    ),
    def("8020", Expense, "住民税", Some(ResidentTax), None, None),
];

/// コンパイル同梱の標準勘定科目カタログ。
pub fn standard_chart() -> &'static [StandardAccountDef] {
    STANDARD
}

/// 実効的な勘定科目 1 件 (カタログ + ユーザー差分を反映したもの)。
#[derive(Clone, Debug)]
pub struct AccountInfo {
    pub code: AccountCode,
    pub account_type: AccountType,
    pub name: String,
    pub tax_category: Option<TaxCategory>,
    pub cost_type: Option<CostType>,
    pub system_role: Option<SystemRole>,
    pub is_active: bool,
    pub display_order: i32,
}

/// 勘定科目表。コード→科目情報の索引。
#[derive(Clone, Debug, Default)]
pub struct Chart {
    accounts: BTreeMap<AccountCode, AccountInfo>,
}

impl Chart {
    /// 標準カタログから構築する (ユーザー差分の merge は後続 PR)。
    pub fn standard() -> Chart {
        let mut accounts = BTreeMap::new();
        for (i, d) in STANDARD.iter().enumerate() {
            let code = AccountCode::from(d.code);
            accounts.insert(
                code.clone(),
                AccountInfo {
                    code,
                    account_type: d.account_type,
                    name: d.name.to_owned(),
                    tax_category: d.tax_category,
                    cost_type: d.cost_type,
                    system_role: d.system_role,
                    is_active: true,
                    display_order: i as i32,
                },
            );
        }
        Chart { accounts }
    }

    pub fn get(&self, code: &AccountCode) -> Option<&AccountInfo> {
        self.accounts.get(code)
    }

    pub fn account_type(&self, code: &AccountCode) -> Option<AccountType> {
        self.accounts.get(code).map(|a| a.account_type)
    }

    /// 科目の正常残高側。未知科目は `None`。
    pub fn normal_balance(&self, code: &AccountCode) -> Option<Side> {
        self.account_type(code).map(AccountType::normal_balance)
    }

    pub fn iter(&self) -> impl Iterator<Item = &AccountInfo> {
        self.accounts.values()
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}
