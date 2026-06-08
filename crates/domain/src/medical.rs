//! 医療費の記録と集計 (医療費控除用)。受診者 → 病院の階層で自己負担額を集計する。

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::journal::Date;
use crate::money::Yen;

/// 医療費 1 件。
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MedicalExpense {
    pub date: Date,
    pub patient: String,
    pub hospital: String,
    pub treatment: String,
    /// 支払額。
    pub paid: Yen,
    /// 保険等で補填される額。
    pub reimbursement: Yen,
}

impl MedicalExpense {
    /// 自己負担額 = 支払額 − 補填額。
    pub fn net(&self) -> Yen {
        self.paid - self.reimbursement
    }
}

/// 支払・補填・自己負担の合計。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MedicalTotals {
    pub paid: Yen,
    pub reimbursement: Yen,
    pub net: Yen,
}

impl MedicalTotals {
    fn add(&mut self, paid: Yen, reimbursement: Yen) {
        self.paid += paid;
        self.reimbursement += reimbursement;
        self.net += paid - reimbursement;
    }
}

/// 病院別の集計。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HospitalMedical {
    pub hospital: String,
    pub totals: MedicalTotals,
    pub count: usize,
}

/// 受診者別の集計 (病院別内訳を含む)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatientMedical {
    pub patient: String,
    pub by_hospital: Vec<HospitalMedical>,
    pub totals: MedicalTotals,
}

/// 医療費集計の全体。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MedicalSummary {
    pub by_patient: Vec<PatientMedical>,
    pub totals: MedicalTotals,
}

/// 受診者 → 病院で自己負担額を集計する (受診者名・病院名の昇順)。
pub fn medical_summary(expenses: &[MedicalExpense]) -> MedicalSummary {
    // patient -> hospital -> (totals, count)
    let mut grouped: BTreeMap<String, BTreeMap<String, (MedicalTotals, usize)>> = BTreeMap::new();
    for e in expenses {
        let hospital = grouped
            .entry(e.patient.clone())
            .or_default()
            .entry(e.hospital.clone())
            .or_default();
        hospital.0.add(e.paid, e.reimbursement);
        hospital.1 += 1;
    }

    let mut summary = MedicalSummary::default();
    for (patient, hospitals) in grouped {
        let mut pm = PatientMedical {
            patient,
            by_hospital: Vec::new(),
            totals: MedicalTotals::default(),
        };
        for (hospital, (totals, count)) in hospitals {
            pm.totals.add(totals.paid, totals.reimbursement);
            pm.by_hospital.push(HospitalMedical {
                hospital,
                totals,
                count,
            });
        }
        summary.totals.add(pm.totals.paid, pm.totals.reimbursement);
        summary.by_patient.push(pm);
    }
    summary
}
