//! Index side of the pesto tiny-PAR2 naming rung (TODO 131, red-team
//! 5a): tiny-sidecar candidate selection, recovery-set storage (deduped
//! by set id), the counter+length backward link, the mandatory 16k-MD5
//! payload gate, the proven-name write, and the daily tallies.
//!
//! The lane in one sentence: the pesto poster tool obfuscates
//! everything EXCEPT the PAR2 sidecar it posts after the payload, so
//! fetching the tiny sidecar, parsing it, and linking it backward by
//! message-id counter names the payload with PAR2-grade identity
//! (filename + exact length + full MD5 + first-16k MD5 + set id).
//!
//! What the census (research/PESTO-par2-census-2026-08-10.md) makes
//! non-negotiable here:
//!  - dedupe by Recovery Set ID (617 objects -> 489 sets);
//!  - counter containment + tight length ratio are a PRE-FILTER only -
//!    they mislinked 8/330 and once named one payload as three
//!    different shows;
//!  - a name claim is written ONLY after the payload's own first
//!    article hash-matches a FileDesc (`pesto_confirm`), for the clean
//!    tier too, until the census's 40/40 rate is re-earned at scale.
//!
//! Scope honesty: the band is ~5% of dark bytes (moovee + teevee, one
//! tool's output). The lane is P0 because it is nearly free and yields
//! the strongest identity keys in the program, not because it is big.
//! Firm floor from the census: 64.6% of sets cleanly linkable at 100%
//! confirmed precision on the sample - do not quote above that.

use rusqlite::OptionalExtension;

use super::{Index, SegList};
use crate::pesto::PestoDesc;

/// Attempts after which a tiny sidecar row, or a set's link hunt, is
/// abandoned. Same rationale as the 7z prober: chasing is the known
/// fetch livelock; a payload out of retention will not come back.
pub const PESTO_GIVE_UP: i64 = 3;

/// Upper bound of a pesto tiny sidecar object. Census: 638 candidate
/// objects, 12.6 MiB total - all single-part posts under 100 KB.
pub const PESTO_TINY_MAX: i64 = 100_000;

/// Retry spacing for transient failures (fetch misses on some servers,
/// a payload still mid-post).
const RETRY_SECS: i64 = 21_600;

/// The pesto tiny-sidecar band, as LITERAL terms - the WHERE prefix of
/// `pesto_pick` and, verbatim, the predicate of `idx_rel_pesto_tiny`
/// (schema.rs). One builder feeds both so they cannot drift; literals
/// because a partial index is reachable only when the statement's own
/// WHERE implies its predicate, proven from literal terms and never
/// from a bound parameter (the N1 rule). The rotation terms (probe_at,
/// probe_tries) stay out of the band for the same reason as the 7z
/// lane's.
pub(crate) fn pesto_band_sql() -> String {
    format!(
        "pesto_ctr_min IS NOT NULL AND junk>=70 AND files=1 \
         AND total_bytes>0 AND total_bytes<{PESTO_TINY_MAX}"
    )
}

/// The pick's full SQL, shared with plan_tests.rs so the plan gate
/// asserts the statement the daemon actually runs. Pinned, and for
/// this lane the pin is not just insurance: the planner actually
/// prefers an `idx_rel_size` range plus a temp sort here (measured on
/// a fresh database AND the 10 M row prototype), because the
/// `total_bytes<100000` term looks selective to a cost model that
/// cannot see the junk band it drags in. The unpinned form is the
/// pre-backfill fallback, where INDEXED BY would fail to prepare.
pub(crate) fn pesto_pick_sql() -> String {
    pesto_pick_sql_with("INDEXED BY idx_rel_pesto_tiny")
}

pub(crate) fn pesto_pick_sql_unpinned() -> String {
    pesto_pick_sql_with("")
}

fn pesto_pick_sql_with(pin: &str) -> String {
    format!(
        "SELECT id, stem, total_bytes FROM releases {pin}
          WHERE {}
            AND probe_tries<?3
            AND probe_at<=?1
          ORDER BY first_posted DESC LIMIT ?2",
        pesto_band_sql()
    )
}

/// One parsed recovery set awaiting (or done with) its backward link.
#[derive(Debug, Clone)]
pub struct PestoSetRow {
    /// Recovery Set ID, lowercase hex - the dedupe and claim key.
    pub set_id: String,
    pub grp: String,
    /// Smallest message-id counter among the set's sidecar objects:
    /// the backward-link key C (the payload's last article is C-1).
    pub base_ctr: i64,
    /// sum(FileDesc.length) - the decoded payload size.
    pub sum_len: i64,
    pub files: Vec<PestoDesc>,
    pub tries: i64,
}

/// Chunked, time-bounded, cursor-resumed fill of the pesto counter
/// columns for files rows scanned before the columns existed - the
/// nsegs/msgid_map shape, for the same reasons (a one-shot UPDATE
/// loses the write lock to a live scanner; an unbounded loop stalls
/// every daemon start).
pub(super) fn pesto_backfill(db: &mut rusqlite::Connection) {
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='pesto_fill'", [], |r| r.get(0))
        .ok();
    if done.as_deref() == Some("1") {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let _ = (|| -> rusqlite::Result<()> {
        loop {
            let tx =
                rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
            let cursor: i64 = tx
                .query_row("SELECT v FROM kv WHERE k='pesto_at'", [], |r| {
                    r.get::<_, String>(0)
                })
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let rows: Vec<(i64, i64, SegList)> = {
                let mut sel = tx.prepare_cached(
                    "SELECT rowid, release_id, segments FROM files
                      WHERE rowid > ?1 ORDER BY rowid LIMIT 2000",
                )?;
                sel.query_map([cursor], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let Some(&(last, _, _)) = rows.last() else {
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('pesto_fill','1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )?;
                tx.commit()?;
                return Ok(());
            };
            {
                let mut upd = tx.prepare_cached(
                    "UPDATE releases SET
                       pesto_ctr_min = MIN(COALESCE(pesto_ctr_min, ?2), ?2),
                       pesto_ctr_max = MAX(COALESCE(pesto_ctr_max, ?3), ?3),
                       pesto_clock   = MIN(COALESCE(pesto_clock, ?4), ?4)
                     WHERE id=?1",
                )?;
                for (_, rid, segs) in &rows {
                    let parsed = &segs.0;
                    let mut fold: Option<(i64, i64, i64)> = None;
                    for (_, id, _) in parsed {
                        if let Some(p) = crate::pesto::parse_msgid(id) {
                            let (c, k) = (p.counter as i64, p.clock.min(i64::MAX as u64) as i64);
                            fold = Some(match fold {
                                None => (c, c, k),
                                Some((lo, hi, ck)) => (lo.min(c), hi.max(c), ck.min(k)),
                            });
                        }
                    }
                    if let Some((lo, hi, ck)) = fold {
                        upd.execute(rusqlite::params![rid, lo, hi, ck])?;
                    }
                }
            }
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('pesto_at', ?1)
                 ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                [last.to_string()],
            )?;
            tx.commit()?;
            if std::time::Instant::now() >= deadline {
                return Ok(());
            }
        }
    })();
}

impl Index {
    /// Tiny sidecar objects the fetcher should visit, newest first.
    /// Rides the shared probe_at/probe_tries rotation columns - safe,
    /// because the 7z prober's pick needs files>=2 and >=100 MB and
    /// this one needs files=1 and <100 KB, so no row is ever in both
    /// lanes. The Rust-side obfuscation filter is the same guard the
    /// 7z pick carries, `bare_stem` and all: a readable tiny post is
    /// not pesto's shape, and a sidecar that kept an extension must
    /// not be judged as a two-token stem (see `probe7z_pick`).
    pub fn pesto_pick(
        &self,
        now: i64,
        limit: usize,
    ) -> rusqlite::Result<Vec<super::ProbeCandidate>> {
        // Pinned form first, unpinned for a pre-backfill database -
        // see probe7z_pick.
        let mut stmt = match self.db.prepare_cached(&pesto_pick_sql()) {
            Ok(s) => s,
            Err(_) => self.db.prepare_cached(&pesto_pick_sql_unpinned())?,
        };
        let rows: Vec<super::ProbeCandidate> = stmt
            .query_map(
                rusqlite::params![now - RETRY_SECS, (limit * 4).max(16) as i64, PESTO_GIVE_UP],
                |r| {
                    Ok(super::ProbeCandidate {
                        id: r.get(0)?,
                        stem: r.get(1)?,
                        total_bytes: r.get(2)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<_>>()?;
        // Same stamp as `probe7z_pick`, same reasons both ways: an
        // unstamped reject squats in the newest-first window until it
        // walls off every older candidate, and a SATURATED reject
        // encodes the filter's current opinion permanently - probe_at
        // only, so a fixed gate re-reaches the row after RETRY_SECS.
        let (keep, reject): (Vec<_>, Vec<_>) = rows
            .into_iter()
            .partition(|c| !crate::release::stem_is_a_name(&c.stem));
        for c in &reject {
            self.db
                .prepare_cached("UPDATE releases SET probe_at=?2 WHERE id=?1")?
                .execute(rusqlite::params![c.id, now])?;
        }
        Ok(keep.into_iter().take(limit).collect())
    }

    /// The group a release was scanned in - the sidecar's group scopes
    /// its set's payload search (a pesto session posts to one group).
    pub fn release_grp(&self, release_id: i64) -> rusqlite::Result<Option<String>> {
        self.db
            .query_row("SELECT grp FROM releases WHERE id=?1", [release_id], |r| {
                r.get(0)
            })
            .optional()
    }

    /// Fold one parsed sidecar object into `pesto_sets`. Dedupe is BY
    /// SET ID and mandatory: a second descriptor object of the same
    /// set only ever lowers `base_ctr` toward the true base index (C
    /// is the smallest counter among the set's objects). Returns false
    /// when the set describes no files (nothing to link or name).
    pub fn pesto_set_store(
        &self,
        grp: &str,
        obj_counter: i64,
        set: &crate::par2::Par2Set,
        now: i64,
    ) -> rusqlite::Result<bool> {
        let descs = PestoDesc::from_set(set);
        if descs.is_empty() {
            return Ok(false);
        }
        // Saturating: every length is a u64 the sidecar's author wrote,
        // and ~1500 descs fit in one tiny object - two absurd lengths
        // must clamp, not wrap (release) or panic (debug). Clamped to
        // the SIGNED range as well, because the column is SQLite's i64:
        // a saturated u64::MAX stored as -1 compares below every real
        // size in SQL and prints as a negative byte count (L12).
        let sum_len: u64 = descs
            .iter()
            .fold(0u64, |a, d| a.saturating_add(d.length))
            .min(i64::MAX as u64);
        self.db
            .prepare_cached(
                "INSERT INTO pesto_sets(set_id, grp, base_ctr, sum_len, files, first_seen)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(set_id) DO UPDATE SET
                   base_ctr = MIN(base_ctr, excluded.base_ctr)",
            )?
            .execute(rusqlite::params![
                crate::par2::hex16(&set.recovery_set_id),
                grp,
                obj_counter,
                sum_len as i64,
                serde_json::to_string(&descs).unwrap_or_else(|_| "[]".into()),
                now
            ])?;
        Ok(true)
    }

    /// Sets still awaiting their backward link, oldest-stamp first.
    pub fn pesto_pending(&self, now: i64, limit: usize) -> rusqlite::Result<Vec<PestoSetRow>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT set_id, grp, base_ctr, sum_len, files, tries FROM pesto_sets
              WHERE status='pending' AND tries<?2 AND at<=?1
              ORDER BY at LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(
                rusqlite::params![now - RETRY_SECS, PESTO_GIVE_UP, limit as i64],
                |r| {
                    Ok(PestoSetRow {
                        set_id: r.get(0)?,
                        grp: r.get(1)?,
                        base_ctr: r.get(2)?,
                        sum_len: r.get(3)?,
                        files: serde_json::from_str::<Vec<PestoDesc>>(&r.get::<_, String>(4)?)
                            .unwrap_or_default(),
                        tries: r.get(5)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Stamp a link attempt BEFORE the wire work (the sampler's rule:
    /// a hunt that dies mid-fetch still rotates the pick).
    pub fn pesto_set_touch(&self, set_id: &str, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE pesto_sets SET at=?2, tries=tries+1 WHERE set_id=?1",
            rusqlite::params![set_id, now],
        )?;
        Ok(())
    }

    /// Settle a set's final state (`named`/`conflict`/`junkname`/
    /// `unresolved`/`nopayload`), recording which release it named.
    pub fn pesto_set_resolve(
        &self,
        set_id: &str,
        status: &str,
        release_id: i64,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE pesto_sets SET status=?2, release_id=?3, at=?4 WHERE set_id=?1",
            rusqlite::params![set_id, status, release_id, now],
        )?;
        Ok(())
    }

    /// Payload candidates for one set: counter-range containment
    /// (`pesto_ctr_min <= C-1 <= pesto_ctr_max`, same group) AND the
    /// tight on-wire/decoded length ratio. Counter arithmetic alone
    /// links across the wrong session - the census's first pass
    /// produced a 4.15 GB set pointing at a 76 MB payload - and even
    /// both filters together once matched FOUR sets to one payload, so
    /// every candidate returned here still has to pass the hash gate.
    /// Biggest-first: the true payload is the one the length band was
    /// derived from, and sidecar-sized rows can never pass the band.
    pub fn pesto_candidates(
        &self,
        set: &PestoSetRow,
    ) -> rusqlite::Result<Vec<super::ProbeCandidate>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT id, stem, total_bytes FROM releases
              WHERE grp=?1 AND pesto_ctr_min IS NOT NULL
                AND pesto_ctr_min <= ?2 AND pesto_ctr_max >= ?2
                AND total_bytes > 0
              ORDER BY total_bytes DESC LIMIT 8",
        )?;
        let rows: Vec<super::ProbeCandidate> = stmt
            .query_map(rusqlite::params![set.grp, set.base_ctr - 1], |r| {
                Ok(super::ProbeCandidate {
                    id: r.get(0)?,
                    stem: r.get(1)?,
                    total_bytes: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows
            .into_iter()
            .filter(|c| crate::pesto::length_ratio_ok(c.total_bytes as u64, set.sum_len as u64))
            .collect())
    }

    /// THE hash gate, and the only place this lane may write a name.
    /// `head` is the decoded offset-0 span of the candidate payload's
    /// first article. Returns `None` when the bytes match no FileDesc
    /// - the candidate is NOT the payload this set describes, whatever
    /// the counters said - and the caller moves on. On a match the
    /// name goes in through the claims layer at the Par2SetId tier
    /// with the set id as the proving key, and every member fingerprint
    /// is taught to `par_hashes`, so any future obfuscated repost of
    /// the same bytes is named for free.
    pub fn pesto_confirm(
        &mut self,
        set: &PestoSetRow,
        release_id: i64,
        head: &[u8],
        now: i64,
    ) -> rusqlite::Result<Option<&'static str>> {
        if crate::pesto::match_filedesc(&set.files, head).is_none() {
            return Ok(None);
        }
        // The release's name is the media file the set describes: the
        // largest member (a multi-file set's furniture never outweighs
        // the payload), extension-stripped, refused when the result is
        // itself an obfuscated blob.
        let biggest = set
            .files
            .iter()
            .max_by_key(|d| d.length)
            .expect("pesto_set_store refuses empty sets");
        let Some(title) = super::probe::probed_title(&biggest.name) else {
            self.pesto_set_resolve(&set.set_id, "junkname", release_id, now)?;
            return Ok(Some("junkname"));
        };
        // Teach the repost table first: the pairing (member hash16k ->
        // name) was just PROVEN by the payload's own bytes, and it
        // stays true even if the claims layer declines to rename the
        // row today (an equal-or-stronger name already applied).
        let pairs: Vec<(String, String)> = set
            .files
            .iter()
            .filter(|d| d.length >= 16384)
            .map(|d| (d.md5_16k.clone(), d.name.clone()))
            .collect();
        let title_key = crate::categories::classify(&title, &self.custom).key;
        self.par_hash_remember(&pairs, &title, &title_key, now)?;
        let claim = super::NameClaim {
            name: title.clone(),
            evidence: super::NameEvidence::Par2SetId,
            key: set.set_id.clone(),
            source: "body/par2/pesto".into(),
        };
        use super::ProvenOutcome;
        let outcome = match self.apply_proven_name(release_id, &claim, now)? {
            ProvenOutcome::Applied | ProvenOutcome::Replaced | ProvenOutcome::Confirmed => "named",
            // A hash-proven name that disagrees with an equal-or-
            // stronger applied name. Rare and worth its own count -
            // for this band the sidecar is near-ground-truth.
            ProvenOutcome::Conflict => "conflict",
            ProvenOutcome::Recorded | ProvenOutcome::Rejected => "junkname",
        };
        self.pesto_set_resolve(&set.set_id, outcome, release_id, now)?;
        Ok(Some(outcome))
    }

    /// Fold one finished unit of work into the daily/lifetime tallies.
    /// Fixed field list so unknown labels land in `other` instead of
    /// silently widening the schema. `parsefail` is its own canary,
    /// distinct from `notpar2`: PAR2 magic present but unparseable
    /// means the tool changed shape, and the lane needs re-derivation.
    pub fn pesto_note(
        &self,
        now: i64,
        outcome: &str,
        articles: u64,
        bytes: u64,
    ) -> rusqlite::Result<()> {
        const FIELDS: &[&str] = &[
            // Sidecar fetch outcomes.
            "par2ok",
            "notpar2",
            "parsefail",
            "fetchmiss",
            // Link/confirm outcomes.
            "named",
            "conflict",
            "junkname",
            "hashreject",
            "nolink",
            "nopayload",
            "nohead",
            // Wire trouble (retried on rotation).
            "fetchfail",
        ];
        let field = if FIELDS.contains(&outcome) {
            outcome
        } else {
            "other"
        };
        for key in [
            format!("pesto_day:{}", now.div_euclid(86_400)),
            "pesto_total".to_string(),
        ] {
            let mut m: serde_json::Map<String, serde_json::Value> = self
                .kv_get(&key)
                .and_then(|v| serde_json::from_str(&v).ok())
                .unwrap_or_default();
            for (k, by) in [
                ("attempts", 1),
                (field, 1),
                ("articles", articles as i64),
                ("bytes", bytes as i64),
            ] {
                let n = m.get(k).and_then(|v| v.as_i64()).unwrap_or(0) + by;
                m.insert(k.to_string(), serde_json::json!(n));
            }
            self.kv_set(&key, &serde_json::Value::Object(m).to_string())?;
        }
        Ok(())
    }

    /// Today's and yesterday's tallies plus the lifetime total and the
    /// live backlog - the readout that makes a pesto tool update (MID
    /// grammar change, cadence stop, sidecars going dark) visible the
    /// day it happens.
    pub fn pesto_stats(&self, now: i64) -> serde_json::Value {
        let day = now.div_euclid(86_400);
        let read = |key: String| -> serde_json::Value {
            self.kv_get(&key)
                .and_then(|v| serde_json::from_str(&v).ok())
                .unwrap_or_else(|| serde_json::json!({}))
        };
        let count = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> Option<i64> {
            self.db
                .query_row(sql, params, |r| r.get::<_, i64>(0))
                .optional()
                .ok()
                .flatten()
        };
        serde_json::json!({
            "today": read(format!("pesto_day:{day}")),
            "yesterday": read(format!("pesto_day:{}", day - 1)),
            "total": read("pesto_total".to_string()),
            // Tiny sidecars not yet fetched (the pick minus rotation).
            "eligible": count(
                "SELECT COUNT(*) FROM releases
                  WHERE pesto_ctr_min IS NOT NULL AND junk>=70 AND files=1
                    AND total_bytes>0 AND total_bytes<?1 AND probe_tries<?2",
                &[&PESTO_TINY_MAX, &PESTO_GIVE_UP],
            ),
            "sets_pending": count(
                "SELECT COUNT(*) FROM pesto_sets WHERE status='pending'",
                &[],
            ),
            "sets_named": count(
                "SELECT COUNT(*) FROM pesto_sets WHERE status='named'",
                &[],
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::teardown;
    use super::*;
    use md5::{Digest, Md5};

    fn dir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-index-pesto-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn open(d: &std::path::Path) -> Index {
        Index::open(&d.join("index.db")).unwrap()
    }

    /// A pesto-grammar message-id at the given counter, bare - the
    /// `entry()` helper adds the OVER brackets itself.
    fn mid(counter: u32) -> String {
        format!("18ca0dc84ce1ff8c.{counter:04x}.75d9c5a63ebd783a@example.org")
    }

    /// Ingest one single-file release whose articles carry pesto ids
    /// from `ctr_from` for `nsegs` counters; returns its release id.
    fn seed_pesto(
        ix: &mut Index,
        grp: &str,
        stem: &str,
        ctr_from: u32,
        nsegs: u32,
        seg_bytes: u64,
    ) -> i64 {
        use crate::index::testutil::entry;
        let entries: Vec<_> = (0..nsegs)
            .map(|i| {
                entry(
                    &format!(r#""{stem}.rar" yEnc ({}/{nsegs})"#, i + 1),
                    "p@x",
                    &mid(ctr_from + i),
                    seg_bytes,
                )
            })
            .collect();
        ix.ingest(grp, &entries, 1000).unwrap();
        let ids = ix.release_ids_by_stem(&format!("{stem}.rar")).unwrap();
        assert_eq!(ids.len(), 1, "seed must resolve unambiguously");
        ids[0]
    }

    /// Build a minimal valid PAR2 set (Main + one FileDesc per file)
    /// describing `(name, length, head_bytes)` members.
    fn par2_bytes(set_id: [u8; 16], files: &[(&str, u64, &[u8])]) -> Vec<u8> {
        let pkt = |ptype: &[u8; 16], body: &[u8]| -> Vec<u8> {
            let mut p = Vec::new();
            p.extend_from_slice(crate::par2::MAGIC);
            p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
            p.extend_from_slice(&[0u8; 16]);
            p.extend_from_slice(&set_id);
            p.extend_from_slice(ptype);
            p.extend_from_slice(body);
            let md5: [u8; 16] = Md5::digest(&p[32..]).into();
            p[16..32].copy_from_slice(&md5);
            p
        };
        let fid = |i: usize| -> [u8; 16] { [i as u8 + 1; 16] };
        let mut main = Vec::new();
        main.extend_from_slice(&768_000u64.to_le_bytes());
        main.extend_from_slice(&(files.len() as u32).to_le_bytes());
        for i in 0..files.len() {
            main.extend_from_slice(&fid(i));
        }
        let mut out = pkt(b"PAR 2.0\0Main\0\0\0\0", &main);
        for (i, (name, length, head)) in files.iter().enumerate() {
            let mut desc = Vec::new();
            desc.extend_from_slice(&fid(i));
            desc.extend_from_slice(&[0u8; 16]); // whole-file md5 (unused here)
            let want = (*length).min(16384) as usize;
            let h16: [u8; 16] = Md5::digest(&head[..want.min(head.len())]).into();
            desc.extend_from_slice(&h16);
            desc.extend_from_slice(&length.to_le_bytes());
            let mut n = name.as_bytes().to_vec();
            while n.len() % 4 != 0 {
                n.push(0);
            }
            desc.extend_from_slice(&n);
            out.extend(pkt(b"PAR 2.0\0FileDesc", &desc));
        }
        out
    }

    /// The full lane against a synthetic session: payload at counters
    /// 0x100..0x105, sidecar at 0x105 - containment plus the ratio
    /// band find it, the hash gate confirms it, the claim lands at the
    /// Par2SetId tier, and par_hashes learns the fingerprint.
    #[test]
    fn link_gate_and_claim_end_to_end() {
        let d = dir("e2e");
        let mut ix = open(&d);
        let head: Vec<u8> = (0..20_000u32).map(|i| (i * 7) as u8).collect();
        // 5 segments of 205_000 wire bytes ~= 1_025_000 total; declared
        // length 1_000_000 -> ratio 1.025, mid-band.
        let rid = seed_pesto(
            &mut ix,
            "alt.binaries.moovee",
            "a1b2c3d4e5f6a7b8c9",
            0x100,
            5,
            205_000,
        );
        let set = crate::par2::Par2Set::parse(&[&par2_bytes(
            [9u8; 16],
            &[("Real.Show.S01E01.1080p.WEB-GRP.mkv", 1_000_000, &head)],
        )])
        .unwrap();
        assert!(
            ix.pesto_set_store("alt.binaries.moovee", 0x105, &set, 50)
                .unwrap()
        );
        let rows = ix.pesto_pending(1_000_000, 10).unwrap();
        assert_eq!(rows.len(), 1);
        let cands = ix.pesto_candidates(&rows[0]).unwrap();
        assert_eq!(cands.iter().map(|c| c.id).collect::<Vec<_>>(), vec![rid]);

        // The gate refuses wrong bytes even for the linked candidate...
        assert_eq!(
            ix.pesto_confirm(&rows[0], rid, &head[1..], 60).unwrap(),
            None
        );
        // ...and confirms the true ones.
        assert_eq!(
            ix.pesto_confirm(&rows[0], rid, &head, 60).unwrap(),
            Some("named")
        );
        let (title, source): (String, String) = ix
            .db
            .query_row(
                "SELECT pre_title, pre_source FROM releases WHERE id=?1",
                [rid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(title, "Real.Show.S01E01.1080p.WEB-GRP");
        assert_eq!(source, "proven:par2-set-id:body/par2/pesto");
        // The repost table learned the proven pairing.
        let h16 = crate::par2::hex16(&Md5::digest(&head[..16384]).into());
        let hit = ix
            .par_hash_lookup(&[(h16, String::new())])
            .unwrap()
            .expect("fingerprint must be on file");
        assert_eq!(hit.1, "Real.Show.S01E01.1080p.WEB-GRP");
        // And the set is settled.
        let st: String = ix
            .db
            .query_row("SELECT status FROM pesto_sets LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(st, "named");
        teardown(&d, ix);
    }

    /// Set-ID dedupe is mandatory: two sidecar objects of one set fold
    /// to ONE row, and base_ctr converges on the smaller counter.
    #[test]
    fn duplicate_descriptor_objects_dedupe_by_set_id() {
        let d = dir("dedupe");
        let ix = open(&d);
        let head = [5u8; 16384];
        let set = crate::par2::Par2Set::parse(&[&par2_bytes(
            [7u8; 16],
            &[("How.Dare.You.2026.S01E04.mkv", 700_000_000, &head)],
        )])
        .unwrap();
        assert!(
            ix.pesto_set_store("alt.binaries.moovee", 0x2000, &set, 10)
                .unwrap()
        );
        assert!(
            ix.pesto_set_store("alt.binaries.moovee", 0x1ff0, &set, 11)
                .unwrap()
        );
        let (n, base): (i64, i64) = ix
            .db
            .query_row("SELECT COUNT(*), MIN(base_ctr) FROM pesto_sets", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(n, 1, "617 objects must collapse to their sets");
        assert_eq!(base, 0x1ff0, "base_ctr is the smallest object counter");
        teardown(&d, ix);
    }

    /// Containment is per-session: a payload whose counter range does
    /// not contain C-1 is no candidate however well its size fits, and
    /// the ratio band rejects a wrong-session payload that counter
    /// arithmetic alone would have linked (the census's 4.15 GB set ->
    /// 76 MB payload failure).
    #[test]
    fn containment_and_ratio_prefilter_candidates() {
        let d = dir("contain");
        let mut ix = open(&d);
        // In-range but absurdly small: ratio kills it.
        seed_pesto(
            &mut ix,
            "alt.binaries.moovee",
            "b1b2c3d4e5f6a7b8c9",
            0x300,
            4,
            19_000_000,
        );
        // Right size, wrong session (range ends before C-1).
        seed_pesto(
            &mut ix,
            "alt.binaries.moovee",
            "c1b2c3d4e5f6a7b8c9",
            0x200,
            5,
            820_000_000,
        );
        // Right size, right range, wrong GROUP.
        seed_pesto(
            &mut ix,
            "alt.binaries.teevee",
            "d1b2c3d4e5f6a7b8c9",
            0x300,
            5,
            820_000_000,
        );
        let row = PestoSetRow {
            set_id: "f".repeat(32),
            grp: "alt.binaries.moovee".into(),
            base_ctr: 0x304,
            sum_len: 4_000_000_000,
            files: vec![],
            tries: 0,
        };
        assert!(
            ix.pesto_candidates(&row).unwrap().is_empty(),
            "no candidate may survive the pre-filters"
        );
        // The true payload: right group, contains C-1, ratio 1.025.
        let rid = seed_pesto(
            &mut ix,
            "alt.binaries.moovee",
            "e1b2c3d4e5f6a7b8c9",
            0x300,
            5,
            820_000_000,
        );
        let cands = ix.pesto_candidates(&row).unwrap();
        assert_eq!(cands.iter().map(|c| c.id).collect::<Vec<_>>(), vec![rid]);
        teardown(&d, ix);
    }

    /// The pick wants tiny obfuscated single-file pesto rows only, and
    /// the shared rotation columns gate it exactly like the 7z lane.
    #[test]
    fn pick_rotation_and_give_up() {
        let d = dir("pick");
        let mut ix = open(&d);
        let tiny = seed_pesto(
            &mut ix,
            "alt.binaries.teevee",
            "97vn9stfyqraatuxtpvp",
            0x400,
            1,
            19_000,
        );
        // Readable stem: not pesto's shape even if the grammar matched.
        ix.ingest(
            "alt.binaries.teevee",
            &[crate::index::testutil::entry(
                r#""Readable.Show.S01E01.par2" yEnc (1/1)"#,
                "p@x",
                &mid(0x500),
                19_000,
            )],
            1000,
        )
        .unwrap();
        // Non-pesto msgid: no counter, never picked.
        ix.ingest(
            "alt.binaries.teevee",
            &[crate::index::testutil::entry(
                r#""8f3acd2b91e04c5a77.rar" yEnc (1/1)"#,
                "p@x",
                "plain1@example.org",
                19_000,
            )],
            1000,
        )
        .unwrap();
        let now = 1_000_000;
        let picks = ix.pesto_pick(now, 10).unwrap();
        assert_eq!(picks.iter().map(|c| c.id).collect::<Vec<_>>(), vec![tiny]);
        ix.probe7z_mark(tiny, now).unwrap();
        assert!(ix.pesto_pick(now, 10).unwrap().is_empty());
        assert_eq!(ix.pesto_pick(now + RETRY_SECS, 10).unwrap().len(), 1);
        ix.probe7z_give_up(tiny, now).unwrap();
        assert!(ix.pesto_pick(now + 10 * RETRY_SECS, 10).unwrap().is_empty());
        teardown(&d, ix);
    }

    /// Ingest persists the counter range monotonically across batches,
    /// and the backfill fills rows scanned before the columns existed.
    #[test]
    fn counter_range_persists_and_backfills() {
        let d = dir("range");
        let mut ix = open(&d);
        let rid = seed_pesto(
            &mut ix,
            "alt.binaries.moovee",
            "f1e2d3c4b5a6978869",
            0x150,
            3,
            700_000,
        );
        let range = |ix: &Index| -> (i64, i64, i64) {
            ix.db
                .query_row(
                    "SELECT pesto_ctr_min, pesto_ctr_max, pesto_clock
                       FROM releases WHERE id=?1",
                    [rid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap()
        };
        assert_eq!(range(&ix), (0x150, 0x152, 0x18ca0dc84ce1ff8c));
        // A later batch (a sibling file at a lower counter) widens the
        // range, never narrows it.
        ix.ingest(
            "alt.binaries.moovee",
            &[crate::index::testutil::entry(
                r#""f1e2d3c4b5a6978869.r00" yEnc (1/1)"#,
                "p@x",
                &mid(0x14f),
                700_000,
            )],
            1001,
        )
        .unwrap();
        assert_eq!(range(&ix).0, 0x14f);

        // Simulate a pre-column database and re-run the backfill.
        ix.db
            .execute(
                "UPDATE releases SET pesto_ctr_min=NULL, pesto_ctr_max=NULL, pesto_clock=NULL",
                [],
            )
            .unwrap();
        ix.db
            .execute("DELETE FROM kv WHERE k IN ('pesto_fill','pesto_at')", [])
            .unwrap();
        pesto_backfill(&mut ix.db);
        assert_eq!(range(&ix), (0x14f, 0x152, 0x18ca0dc84ce1ff8c));
        assert_eq!(ix.kv_get("pesto_fill").as_deref(), Some("1"));
        teardown(&d, ix);
    }

    #[test]
    fn daily_tallies_roll_and_count_the_canary() {
        let d = dir("tally");
        let ix = open(&d);
        let now = 40 * 86_400 + 100;
        ix.pesto_note(now, "par2ok", 1, 20_000).unwrap();
        ix.pesto_note(now, "parsefail", 1, 20_000).unwrap();
        ix.pesto_note(now + 86_400, "named", 1, 760_000).unwrap();
        let s = ix.pesto_stats(now + 86_400);
        assert_eq!(s["today"]["named"], 1);
        assert_eq!(s["yesterday"]["parsefail"], 1);
        assert_eq!(s["total"]["attempts"], 3);
        teardown(&d, ix);
    }
}
