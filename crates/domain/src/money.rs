//! 金額型。**円 (整数, 最小単位無し)**。float は使わない。
//!
//! 現実の家計データでは i64 はまず溢れない (旧モデルは 12 桁 = 最大 10^12、i64 は ~9.2×10^18)。
//! 演算子 (`+`/`-`) は内部で `checked_*` を使い、万一の溢れ時のみ panic する。明示的に扱いたい
//! 場合は [`Yen::checked_add`] / [`Yen::checked_sub`] を使う。

use core::fmt;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Neg, Sub, SubAssign};

/// 円。整数 (`i64`)。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Yen(i64);

impl Yen {
    /// 0 円。
    pub const ZERO: Yen = Yen(0);

    /// 円額から生成する。
    pub const fn new(value: i64) -> Yen {
        Yen(value)
    }

    /// 円額を取り出す。
    pub const fn amount(self) -> i64 {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }
    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }

    /// 絶対値。
    pub fn abs(self) -> Yen {
        Yen(self.0.abs())
    }

    /// 溢れたら `None`。
    pub fn checked_add(self, other: Yen) -> Option<Yen> {
        self.0.checked_add(other.0).map(Yen)
    }
    /// 溢れたら `None`。
    pub fn checked_sub(self, other: Yen) -> Option<Yen> {
        self.0.checked_sub(other.0).map(Yen)
    }
}

impl fmt::Debug for Yen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Yen({})", self.0)
    }
}

impl fmt::Display for Yen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for Yen {
    type Output = Yen;
    fn add(self, rhs: Yen) -> Yen {
        self.checked_add(rhs).expect("Yen addition overflow")
    }
}

impl Sub for Yen {
    type Output = Yen;
    fn sub(self, rhs: Yen) -> Yen {
        self.checked_sub(rhs).expect("Yen subtraction overflow")
    }
}

impl Neg for Yen {
    type Output = Yen;
    fn neg(self) -> Yen {
        Yen(self.0.checked_neg().expect("Yen negation overflow"))
    }
}

impl AddAssign for Yen {
    fn add_assign(&mut self, rhs: Yen) {
        *self = *self + rhs;
    }
}

impl SubAssign for Yen {
    fn sub_assign(&mut self, rhs: Yen) {
        *self = *self - rhs;
    }
}

impl Sum for Yen {
    fn sum<I: Iterator<Item = Yen>>(iter: I) -> Yen {
        iter.fold(Yen::ZERO, |acc, y| acc + y)
    }
}
