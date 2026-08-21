//! Terminal `header_encrypted` classification (TODO 131 rung 5).
//!
//! The RAR continuation pilot (research/RAR-continuation-pilot-2026-08-10)
//! measured 24 of 26 sampled RAR5 sets carrying `-hp` header encryption -
//! 98% of the band BY BYTES. Those archives know their own names and will
//! not say without a password we do not have. No fetch budget opens them;
//! only a password does. Without a record of that, every present and
//! future naming lane pays the same articles to rediscover the same wall.
//!
//! This module is that record: one stamp, per release, that says "the
//! bytes themselves are locked", so a lane can skip the row instead of
//! re-probing it.
//!
//! # Why this is safe to make terminal, and how it stays revisable
//!
//! The byte-probe lanes learned the cost of a permanent stamp the hard
//! way (memory `nzbfast-byteprobe-lane-starvation`): saturating
//! `probe_tries` on a filter REJECT encoded the filter's current opinion
//! forever, and 19 correct names became permanently unreachable behind
//! rows nothing could re-pick. The fix there was to stamp `probe_at`
//! only, never tries - an opinion must stay revisable.
//!
//! `header_encrypted` is a different kind of thing: a fact about the
//! bytes on the wire (a RAR5 HEAD_CRYPT block, a RAR4 MHD_PASSWORD main
//! header, a 7z AES end header), not a filter's judgement about a stem.
//! Facts about bytes do not change when we change our mind.
//!
//! But the CODE that reads those bytes can be wrong, and a wrong
//! classifier stamped terminally is the same trap wearing a better
//! argument. So the stamp is **versioned**, not boolean:
//!
//! - [`ENC_CLASS`] is the current classifier generation. A row counts as
//!   terminally encrypted only while `enc_class == ENC_CLASS`.
//! - Any change that could make a past verdict wrong - a new blocker
//!   mapping, a fixed parser, a container whose detection was too eager -
//!   bumps [`ENC_CLASS`]. Every row stamped by an older generation stops
//!   matching and re-enters every lane's pick on its own, with no
//!   migration, no backfill, and no manual sweep.
//! - `enc_kind` records WHICH container and WHICH signature earned the
//!   stamp (`rar5/head-crypt`, `rar4/mhd-password`, `7z/aes-header`), so
//!   a bump can be argued from the recorded evidence instead of a
//!   re-probe, and so a mis-firing detector is visible in the tallies
//!   before it is visible in the yield.
//!
//! The rule for anyone editing the classifier: **if you change what
//! counts as encrypted, bump [`ENC_CLASS`]**. The test
//! `a_stale_generation_stops_being_terminal` pins that a bump un-retires
//! the whole band.

use rusqlite::OptionalExtension;

use super::Index;

/// Current classifier generation. Rows stamped with this value are
/// terminally header-encrypted; rows stamped with anything lower were
/// classified by code we no longer stand behind and are eligible again.
///
/// **Bump this whenever the meaning of "header encrypted" changes.**
/// Generation 1: RAR5 type-4 HEAD_CRYPT, RAR4 MHD_PASSWORD, 7z AES end
/// header - all three read out of an archive's own leading/trailing
/// bytes by `nameprobe`, never inferred from a filename or a stem.
pub const ENC_CLASS: i64 = 1;

/// What a caller may record as the evidence for a stamp. A closed set:
/// the tallies are only useful if the vocabulary cannot drift, and an
/// unrecognised string would quietly become its own bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncKind {
    /// RAR5 type-4 block (HEAD_CRYPT) right after the signature.
    Rar5HeadCrypt,
    /// RAR4 main header carrying MHD_PASSWORD (0x0080).
    Rar4MhdPassword,
    /// 7z `-mhe`: the end header is AES-encrypted.
    SevenzAesHeader,
}

impl EncKind {
    pub fn tag(self) -> &'static str {
        match self {
            EncKind::Rar5HeadCrypt => "rar5/head-crypt",
            EncKind::Rar4MhdPassword => "rar4/mhd-password",
            EncKind::SevenzAesHeader => "7z/aes-header",
        }
    }
}

impl Index {
    /// Record that release `rid`'s own archive bytes are header-encrypted.
    ///
    /// Idempotent, and it never touches a name: an encrypted set may
    /// still be named later by a lane that does not read the container
    /// (a relay pairing, a posted NZB, a Spotnet record). This stamp
    /// retires the row from BYTE probing only - which is the whole
    /// claim the pilot supports.
    pub fn mark_header_encrypted(&self, rid: i64, kind: EncKind, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET enc_class=?2, enc_kind=?3, enc_at=?4 WHERE id=?1",
            rusqlite::params![rid, ENC_CLASS, kind.tag(), now],
        )?;
        Ok(())
    }

    /// Is this release terminally header-encrypted under the CURRENT
    /// classifier generation? A row stamped by an older generation
    /// answers false - that is the un-retirement, and it is the whole
    /// point of versioning the stamp.
    pub fn header_encrypted(&self, rid: i64) -> bool {
        self.db
            .query_row(
                "SELECT 1 FROM releases WHERE id=?1 AND enc_class=?2",
                rusqlite::params![rid, ENC_CLASS],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    /// The same question for a whole page at once: which of `ids` carry
    /// the current generation's stamp.
    ///
    /// One statement rather than a lookup per row because the caller is
    /// a browse page deciding which rows to offer the on-demand namer
    /// on, and that runs on every keystroke of the wall's filter. An
    /// empty input asks nothing.
    pub fn header_encrypted_ids(&self, ids: &[i64]) -> std::collections::HashSet<i64> {
        if ids.is_empty() {
            return std::collections::HashSet::new();
        }
        // Bound parameters, not interpolated ids: they are i64 and safe
        // either way, but a literal-splicing habit is the one that
        // eventually meets a string.
        let holes = std::iter::repeat_n("?", ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut args: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(ids.len() + 1);
        for id in ids {
            args.push(id);
        }
        args.push(&ENC_CLASS);
        let n = args.len();
        let sql = format!("SELECT id FROM releases WHERE id IN ({holes}) AND enc_class=?{n}");
        let Ok(mut stmt) = self.db.prepare_cached(&sql) else {
            return std::collections::HashSet::new();
        };
        stmt.query_map(args.as_slice(), |r| r.get::<_, i64>(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    /// What the classification has retired, and what a bump would give
    /// back. `stale` is the count carrying an older generation's stamp -
    /// non-zero only after a bump, and the number that says how much
    /// work re-entered the lanes.
    pub fn header_encrypted_stats(&self) -> serde_json::Value {
        let scalar = |sql: &str| -> i64 {
            self.db
                .query_row(sql, rusqlite::params![ENC_CLASS], |r| r.get::<_, i64>(0))
                .optional()
                .ok()
                .flatten()
                .unwrap_or(0)
        };
        // `AND enc_class>0` on every one of these is not redundant, and the
        // `stale` line below has always carried it. `idx_rel_enc` is partial
        // on `enc_class>0`, and SQLite reaches a partial index only when the
        // statement implies its predicate - it cannot derive that from a
        // bound `enc_class=?1`. Without the term these three planned as
        // `SCAN releases`: on the 43.3 M-row index measured 20 Aug 2026, a
        // full pass over the whole table to count the 184 rows that are
        // actually classified, three times, per stats call. Same shape as the
        // trigger wedge in schema.rs; `plan_tests.rs` now holds all four.
        let mut by_kind = serde_json::Map::new();
        if let Ok(mut stmt) = self.db.prepare(
            "SELECT enc_kind, COUNT(*), COALESCE(SUM(total_bytes),0)
               FROM releases WHERE enc_class=?1 AND enc_class>0 GROUP BY enc_kind",
        ) && let Ok(rows) = stmt.query_map(rusqlite::params![ENC_CLASS], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        }) {
            for (kind, n, bytes) in rows.flatten() {
                by_kind.insert(kind, serde_json::json!({"releases": n, "bytes": bytes}));
            }
        }
        serde_json::json!({
            "class": ENC_CLASS,
            "releases": scalar(
                "SELECT COUNT(*) FROM releases WHERE enc_class=?1 AND enc_class>0",
            ),
            // The number the pilot cared about: bytes never fetched again.
            "bytes": scalar(
                "SELECT COALESCE(SUM(total_bytes),0) FROM releases
                   WHERE enc_class=?1 AND enc_class>0",
            ),
            "stale": scalar("SELECT COUNT(*) FROM releases WHERE enc_class>0 AND enc_class<>?1"),
            "by_kind": by_kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::teardown;
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-index-enc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn seed(ix: &Index, stem: &str, bytes: i64) -> i64 {
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, total_bytes, files, junk, first_posted)
                 VALUES(?1, 'p@example', 'alt.binaries.tv', ?2, 2, 80, 1000)",
                rusqlite::params![stem, bytes],
            )
            .unwrap();
        ix.db.last_insert_rowid()
    }

    #[test]
    fn a_stamp_is_terminal_under_the_current_generation() {
        let d = dir("stamp");
        let ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&ix, "blob", 10_000_000_000);
        assert!(!ix.header_encrypted(rid), "unstamped rows are not retired");
        ix.mark_header_encrypted(rid, EncKind::Rar5HeadCrypt, 2000)
            .unwrap();
        assert!(ix.header_encrypted(rid));
        // Idempotent: a second probe that hits the same wall re-stamps
        // without changing the verdict or duplicating a row.
        ix.mark_header_encrypted(rid, EncKind::Rar5HeadCrypt, 3000)
            .unwrap();
        let s = ix.header_encrypted_stats();
        assert_eq!(s["releases"], 1);
        assert_eq!(s["bytes"], 10_000_000_000i64);
        assert_eq!(s["stale"], 0);
        assert_eq!(s["by_kind"]["rar5/head-crypt"]["releases"], 1);
        teardown(&d, ix);
    }

    /// The batched form answers exactly what the per-row form answers,
    /// generation included - it feeds the browse page's decision about
    /// which rows to offer the on-demand namer on, and a wrong answer
    /// there either nags about archives nobody can read or hides the
    /// affordance from rows that would give up a name.
    #[test]
    fn the_batched_lookup_agrees_with_the_single_one() {
        let d = dir("batch");
        let ix = Index::open(&d.join("index.db")).unwrap();
        let stamped = seed(&ix, "blob-a", 1_000);
        let plain = seed(&ix, "blob-b", 1_000);
        let stale = seed(&ix, "blob-c", 1_000);
        ix.mark_header_encrypted(stamped, EncKind::Rar5HeadCrypt, 2000)
            .unwrap();
        ix.db
            .execute(
                "UPDATE releases SET enc_class=?2 WHERE id=?1",
                rusqlite::params![stale, ENC_CLASS + 1],
            )
            .unwrap();
        let all = [stamped, plain, stale, 9_999];
        let got = ix.header_encrypted_ids(&all);
        assert_eq!(
            got,
            std::collections::HashSet::from([stamped]),
            "only the current generation's stamp counts, and an id that \
             does not exist is not a hit"
        );
        for id in all {
            assert_eq!(got.contains(&id), ix.header_encrypted(id), "id {id}");
        }
        assert!(ix.header_encrypted_ids(&[]).is_empty());
        teardown(&d, ix);
    }

    /// THE guard the design rests on. A terminal stamp is only
    /// defensible because a later code change can take it back - so a
    /// row stamped by an older classifier generation must stop being
    /// terminal the moment ENC_CLASS moves, with no migration step. If
    /// this test ever needs "fixing" by writing a backfill, the stamp
    /// has become the permanent opinion the byte-probe lanes already
    /// paid for once.
    #[test]
    fn a_stale_generation_stops_being_terminal() {
        let d = dir("stale");
        let ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&ix, "blob2", 5_000_000_000);
        // Stand in for a bump: the row carries a stamp from a
        // classifier generation that is not the one this code is. (Any
        // difference counts, in either direction - a rollback must
        // un-retire exactly like a bump does.)
        ix.db
            .execute(
                "UPDATE releases SET enc_class=?2, enc_kind='rar5/head-crypt', enc_at=1
                  WHERE id=?1",
                rusqlite::params![rid, ENC_CLASS + 1],
            )
            .unwrap();
        assert!(
            !ix.header_encrypted(rid),
            "an older generation's verdict is not this generation's verdict"
        );
        let s = ix.header_encrypted_stats();
        assert_eq!(s["releases"], 0, "not counted as retired");
        assert_eq!(s["stale"], 1, "counted as re-entered");
        teardown(&d, ix);
    }

    /// The stamp retires a row from BYTE probing and nothing else: it
    /// must not touch the name, the stem, or the junk score. An
    /// encrypted archive is still nameable by a relay pairing, a posted
    /// NZB or a spot - lanes that never read the container.
    #[test]
    fn a_stamp_never_touches_the_name() {
        let d = dir("name");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&ix, "97VN9stfYqRAatUXTPVP0ApMrDua72fl", 1_000_000);
        ix.mark_header_encrypted(rid, EncKind::Rar4MhdPassword, 2000)
            .unwrap();
        let claim = super::super::NameClaim {
            name: "Some.Movie.2024.1080p.WEB-DL.x264-GRP".into(),
            evidence: super::super::NameEvidence::MsgidSet,
            key: "k1".into(),
            source: "nzb/import".into(),
        };
        assert_eq!(
            ix.apply_proven_name(rid, &claim, 3000).unwrap(),
            super::super::ProvenOutcome::Applied,
            "an encrypted set is still nameable by evidence that is not its bytes"
        );
        assert!(ix.header_encrypted(rid), "and stays retired from probing");
        teardown(&d, ix);
    }
}
