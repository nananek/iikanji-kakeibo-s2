//! 型別マージ規則と incremental reconcile (クライアント側、復号済み Record に対して)。
//!
//! 規則 (CLAUDE.md): fiscal-close は前方向ラッチの**単調マージ** (`closed_period = max`)、
//! その他は LWW (より新しい = サーバーに commit された remote を採用)。
//! IndexedDB/HTTP との配線は browser 結合 PR で行う。

use std::collections::BTreeMap;

use iikanji_domain::{Record, RecordPayload};
use uuid::Uuid;

/// 同一 record_id の local / remote (いずれも復号済み) を型別規則でマージする。
pub fn resolve(local: &Record, remote: &Record) -> Record {
    match (&local.payload, &remote.payload) {
        // fiscal-close: 単調マージ (素朴 LWW は禁止)。
        (RecordPayload::FiscalClose(l), RecordPayload::FiscalClose(r)) => {
            Record::new(RecordPayload::FiscalClose(l.merge(*r)))
        }
        // その他: LWW (remote 優先)。
        _ => remote.clone(),
    }
}

/// pull で取得した remote レコード (復号済み)。
pub struct RemoteRecord {
    pub id: Uuid,
    pub version: u32,
    pub record: Record,
}

/// remote 群を local 既知状態 (id → (version, record)) に突き合わせ、ローカルへ適用すべき
/// (id, version, record) を返す。新規 / remote が新しい場合のみ採用し、後者は型別 resolve を適用。
pub fn reconcile(
    local: &BTreeMap<Uuid, (u32, Record)>,
    remote: &[RemoteRecord],
) -> Vec<(Uuid, u32, Record)> {
    let mut updates = Vec::new();
    for r in remote {
        match local.get(&r.id) {
            None => updates.push((r.id, r.version, r.record.clone())),
            Some((local_version, local_record)) if r.version > *local_version => {
                updates.push((r.id, r.version, resolve(local_record, &r.record)));
            }
            Some(_) => {} // ローカルが最新/同等 → 適用しない
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    use super::*;
    use iikanji_domain::{AccountCode, Date, EntryLine, FiscalClose, JournalEntry, Yen};

    fn fiscal(year: i32, closed: u8) -> Record {
        Record::new(RecordPayload::FiscalClose(
            FiscalClose::new(year).close_to(closed).unwrap(),
        ))
    }

    fn journal(desc: &str) -> Record {
        Record::new(RecordPayload::JournalEntry(JournalEntry {
            date: Date::new(2026, 6, 8).unwrap(),
            description: desc.into(),
            lines: vec![
                EntryLine::debit(AccountCode::from("5010"), Yen::new(100)),
                EntryLine::credit(AccountCode::from("1010"), Yen::new(100)),
            ],
        }))
    }

    fn closed_of(rec: &Record) -> i8 {
        match &rec.payload {
            RecordPayload::FiscalClose(f) => f.closed_period(),
            _ => panic!("not fiscal"),
        }
    }

    #[test]
    fn resolve_fiscal_is_monotonic_and_commutative() {
        // 単調: より大きい closed_period を採用 (引数順に依らず)。
        assert_eq!(closed_of(&resolve(&fiscal(2026, 3), &fiscal(2026, 6))), 6);
        assert_eq!(closed_of(&resolve(&fiscal(2026, 8), &fiscal(2026, 5))), 8);
        // 可換: resolve(a, b) == resolve(b, a)。
        let (a, b) = (fiscal(2026, 3), fiscal(2026, 6));
        assert_eq!(resolve(&a, &b), resolve(&b, &a));
    }

    #[test]
    fn resolve_non_fiscal_is_lww_remote() {
        assert_eq!(
            resolve(&journal("local"), &journal("remote")),
            journal("remote")
        );
    }

    #[test]
    fn reconcile_applies_new_and_newer_only() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let mut local = BTreeMap::new();
        local.insert(a, (2u32, journal("old")));

        let remote = vec![
            RemoteRecord {
                id: a,
                version: 3,
                record: journal("newer"),
            }, // 採用
            RemoteRecord {
                id: a,
                version: 1,
                record: journal("stale"),
            }, // 旧 → 無視
            RemoteRecord {
                id: b,
                version: 1,
                record: journal("created"),
            }, // 新規 → 採用
        ];
        let updates = reconcile(&local, &remote);
        assert_eq!(updates.len(), 2);
        assert!(updates.iter().any(|(id, v, _)| *id == a && *v == 3));
        assert!(updates.iter().any(|(id, v, _)| *id == b && *v == 1));
    }

    #[test]
    fn reconcile_merges_fiscal_monotonically() {
        let id = Uuid::from_u128(9);
        let mut local = BTreeMap::new();
        local.insert(id, (1u32, fiscal(2026, 8)));
        // remote が新 version だが closed_period は小さい → 単調マージで 8 を維持。
        let remote = vec![RemoteRecord {
            id,
            version: 2,
            record: fiscal(2026, 5),
        }];
        let updates = reconcile(&local, &remote);
        assert_eq!(updates.len(), 1);
        assert_eq!(closed_of(&updates[0].2), 8);
    }
}
