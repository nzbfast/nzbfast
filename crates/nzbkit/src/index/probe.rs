//! Index side of the byte-probe naming lane (TODO 131 B3): candidate
//! selection, rotation stamps, the proven-name write, and the daily
//! hit-rate tallies the telemetry reads.
//!
//! Scope honesty: the selection targets the single-logical-7z shape,
//! which on the measured index is ~29% of currently-dark bytes and is
//! effectively one automated reposter's TV output. The lane's worth is
//! watched, not assumed - see the `probe7z_day` tallies.

use rusqlite::OptionalExtension;

use super::{Index, SegList};

/// Attempts after which a row is left to the post-grab naming path.
/// Two extra head fetches cover the pilot's ~1/29 scrambled-order case;
/// anything still unreadable after three visits is the shape a bounded
/// probe cannot crack, and chasing it is the known fetch livelock.
pub const PROBE7Z_GIVE_UP: i64 = 3;

/// Byte floor for probe-worthy rows: below ~100 MB the band is junk
/// one-file posts (R6), and the probe would spend articles on rows the
/// wall hides anyway.
pub const PROBE7Z_MIN_BYTES: i64 = 100_000_000;

/// Retry spacing for rows whose last attempt failed transiently.
const RETRY_SECS: i64 = 21_600;

/// The probe-worthy band, as LITERAL terms - the WHERE prefix of
/// `probe7z_pick` and, verbatim, the predicate of `idx_rel_probe7z`
/// (schema.rs). One builder feeds both so they cannot drift, and the
/// terms are literals rather than bound parameters because SQLite
/// reaches a partial index only when the statement's own WHERE implies
/// its predicate, proven from literal terms - never from a parameter
/// (the N1 rule; `idx_titles_*`). The rotation terms (probe_at,
/// probe_tries, enc_class) stay OUT of the band: they move per row and
/// per classifier generation, and a predicate that names them would
/// stop being provable the day a constant changes.
pub(crate) fn probe7z_band_sql() -> String {
    format!("junk>=70 AND pre_title='' AND files>=2 AND total_bytes>={PROBE7Z_MIN_BYTES}")
}

/// The pick's full SQL, shared with plan_tests.rs so the plan gate
/// asserts the statement the daemon actually runs. Pinned to the band
/// index (the cards.rs `INDEXED BY` rationale: a background statement
/// whose wrong plan is a wedge does not get left to the cost model);
/// the unpinned form below is the fallback for a database the
/// maintenance backfill has not reached yet, where INDEXED BY would
/// fail to prepare at all.
pub(crate) fn probe7z_pick_sql() -> String {
    probe7z_pick_sql_with("INDEXED BY idx_rel_probe7z")
}

pub(crate) fn probe7z_pick_sql_unpinned() -> String {
    probe7z_pick_sql_with("")
}

fn probe7z_pick_sql_with(pin: &str) -> String {
    format!(
        "SELECT id, stem, total_bytes FROM releases {pin}
          WHERE {}
            AND probe_tries<?3
            AND probe_at<=?1
            AND enc_class<>?4
            AND EXISTS (SELECT 1 FROM files f
                         WHERE f.release_id=releases.id
                           AND (lower(f.filename) GLOB '*.7z'
                             OR lower(f.filename) GLOB '*.7z.[0-9][0-9][0-9]'
                             OR lower(f.filename) GLOB '*.7z.[0-9][0-9][0-9][0-9]'))
          ORDER BY first_posted DESC LIMIT ?2",
        probe7z_band_sql()
    )
}

/// One release the prober should look at next.
#[derive(Debug, Clone)]
pub struct ProbeCandidate {
    pub id: i64,
    pub(crate) stem: String,
    pub(crate) total_bytes: i64,
}

/// One file row of a candidate, segments decoded and msgids normalized
/// to bracketed form (they are stored WITH angle brackets; wrapping
/// them again earns a 430 from every provider).
#[derive(Debug, Clone)]
pub struct ProbeFile {
    pub filename: String,
    pub bytes: i64,
    /// (part number, bracketed message-id, over-wire bytes), part order.
    pub segments: Vec<(u32, String, u64)>,
}

impl Index {
    /// Releases the byte prober should visit, newest first - the lane's
    /// job is keeping up with the current dark inflow; the backlog
    /// drains with whatever budget is left over.
    ///
    /// The SQL narrows to the probe-worthy band (obfuscation-scored,
    /// unnamed, multi-file, big enough, carrying a `.7z`-family file);
    /// the stem check narrows to ACTUAL semantic obfuscation - R6's
    /// sample caught a real named mkv at junk>=70, and renaming a
    /// readable post from its own archive would be pure loss.
    ///
    /// The stem check runs on `bare_stem`, NOT the raw stem. This band's
    /// stems keep their archive extension ("kXcNT9Bf….7z" - 14,349 of
    /// 14,349 on the live index), which splits into two tokens and
    /// falls straight out of `looks_obfuscated`'s single-token rules.
    /// Judging the raw stem here matched zero rows in production while
    /// the fixtures, which seed a bare stem, all passed.
    pub fn probe7z_pick(&self, now: i64, limit: usize) -> rusqlite::Result<Vec<ProbeCandidate>> {
        // Pinned form first; a pre-backfill database (large, opened
        // before the daemon's maintenance pass built idx_rel_probe7z)
        // cannot prepare it and keeps the old shape until then.
        let mut stmt = match self.db.prepare_cached(&probe7z_pick_sql()) {
            Ok(s) => s,
            Err(_) => self.db.prepare_cached(&probe7z_pick_sql_unpinned())?,
        };
        let rows: Vec<ProbeCandidate> = stmt
            .query_map(
                rusqlite::params![
                    now - RETRY_SECS,
                    // Over-fetch so the semantic-obfuscation filter
                    // below cannot starve the pick.
                    (limit * 4).max(16) as i64,
                    PROBE7Z_GIVE_UP,
                    // Header-encrypted under the CURRENT classifier
                    // generation: the archive itself says no. Excluded
                    // by the fact, not by a saturated try counter, so a
                    // bump of ENC_CLASS puts the whole band back in the
                    // pick without a migration.
                    super::ENC_CLASS,
                ],
                |r| {
                    Ok(ProbeCandidate {
                        id: r.get(0)?,
                        stem: r.get(1)?,
                        total_bytes: r.get(2)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<_>>()?;
        // An unstamped reject stays in the newest-first window: once 16
        // readable-stem rows outdate the oldest real candidate, the pick
        // returns empty every tick and the whole older backlog is
        // unreachable (the same walling d8b33bd0 fixed at the filter
        // itself). Stamp probe_at ONLY - not tries. Saturating tries
        // would make the filter's CURRENT opinion permanent, and a
        // wrong opinion once stranded this lane's entire payoff
        // (probe_tries=3 rows are un-re-pickable; the first production
        // names sat exactly there). A probe_at bump costs one cheap
        // re-filter per RETRY_SECS and lets a fixed gate reach the row
        // on its own.
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

    /// All file rows of one candidate, segment lists decoded.
    pub fn probe7z_files(&self, release_id: i64) -> rusqlite::Result<Vec<ProbeFile>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT filename, bytes, segments FROM files WHERE release_id=?1 ORDER BY filename",
        )?;
        let rows: Vec<(String, i64, SegList)> = stmt
            .query_map([release_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows
            .into_iter()
            .map(|(filename, bytes, segs)| {
                let mut segments = segs.0;
                for (_, id, _) in &mut segments {
                    if !id.starts_with('<') {
                        *id = format!("<{id}>");
                    }
                }
                ProbeFile {
                    filename,
                    bytes,
                    segments,
                }
            })
            .collect())
    }

    /// Stamp a visit BEFORE the wire work, like the oracle sampler: a
    /// probe that dies mid-fetch still rotates the pick, so one broken
    /// release cannot pin the lane.
    pub fn probe7z_mark(&self, release_id: i64, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET probe_at=?2, probe_tries=probe_tries+1 WHERE id=?1",
            rusqlite::params![release_id, now],
        )?;
        Ok(())
    }

    /// The archive's own bytes said "password required": retire the row
    /// from BYTE probing by the FACT, not by the try counter.
    ///
    /// Deliberately not `probe7z_give_up`. A saturated `probe_tries` is
    /// permanent and unversioned - it would wall the row even after a
    /// bump of [`super::ENC_CLASS`] un-retired it, which is precisely
    /// the un-retirement this design exists to keep possible. Only
    /// `probe_at` moves, so the row rotates out of the immediate window
    /// and the classification alone holds it out.
    ///
    /// (Rows saturated by the OLD encrypted give-up path, before this
    /// existed, keep their tries: nothing distinguishes them from any
    /// other give-up, so a bump cannot reach them. They re-enter only
    /// via the post-grab naming path, as they did before.)
    pub fn probe7z_retire_encrypted(
        &self,
        release_id: i64,
        kind: super::EncKind,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET probe_at=?2 WHERE id=?1",
            rusqlite::params![release_id, now],
        )?;
        self.mark_header_encrypted(release_id, kind, now)
    }

    /// Structural failure (scrambled, unparseable, wrong shape):
    /// saturate the tries so the row leaves the pick for good. The
    /// post-grab naming path still gets its chance if a user ever
    /// downloads it. Header encryption goes through
    /// [`Self::probe7z_retire_encrypted`] instead - that one is a fact
    /// about the bytes and stays revisable.
    pub fn probe7z_give_up(&self, release_id: i64, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET probe_at=?2, probe_tries=?3 WHERE id=?1",
            rusqlite::params![release_id, now, PROBE7Z_GIVE_UP],
        )?;
        Ok(())
    }

    /// Attach a byte-recovered inner filename to a release.
    ///
    /// The name is PROVEN (read out of the post's own archive), so it
    /// goes in through the claims layer at the top `BodyProbe` tier,
    /// source `body/7z` - never the `predb/...` vocabulary, and never
    /// the tentative correlated badge. It is still an uploader's
    /// string: the title keeps only a sane, extension-stripped form,
    /// and a name that is itself an obfuscated blob is refused (naming
    /// junk with junk would only hide the row from better lanes).
    /// Returns the claim outcome, `None` when the inner name did not
    /// survive sanitising.
    pub fn apply_probed_name(
        &mut self,
        release_id: i64,
        inner_filename: &str,
        now: i64,
    ) -> rusqlite::Result<Option<super::ProvenOutcome>> {
        let Some(title) = probed_title(inner_filename) else {
            return Ok(None);
        };
        // The proving value: the exact inner filename the bytes carried.
        // Two probes of the same archive re-prove the identical fact
        // (same name + key), which the claims layer treats as one
        // claim, not a corroborating second opinion - correct, it is.
        let claim = super::NameClaim {
            name: title,
            evidence: super::NameEvidence::BodyProbe,
            key: inner_filename.trim().to_string(),
            source: "body/7z".into(),
        };
        self.apply_proven_name(release_id, &claim, now).map(Some)
    }

    /// Attach an inner filename read out of a RAR volume's own header
    /// (TODO 131 rung 5, ON DEMAND only - the pilot said NO-GO on a
    /// scan-time RAR lane and that verdict stands).
    ///
    /// Same claims-layer contract as the 7z lane, one tier apart in
    /// provenance: `body/rar`, so a later reader can tell which
    /// container proved the name and re-argue this lane alone. The key
    /// is the header's `{unpacked_size}:{crc32}` - exact for the
    /// volume, weaker than a PAR2 set ID, and repeated in EVERY volume,
    /// which is what lets a mid-set head corroborate a first-volume one.
    ///
    /// When the header carries no usable content key the FILENAME keys
    /// the claim, exactly as the 7z lane does - never a constant, which
    /// would make every keyless RAR corroborate every other.
    ///
    /// `None` when the inner name did not survive sanitising, which
    /// includes the pilot's commonest RAR4 outcome by far: an inner
    /// filename as obfuscated as the outer post (7 of 13 plaintext
    /// headers). Naming junk with junk only hides the row from better
    /// lanes, so no claim is written at all.
    pub fn apply_rar_named(
        &mut self,
        release_id: i64,
        inner_filename: &str,
        content_key: Option<&str>,
        now: i64,
    ) -> rusqlite::Result<Option<super::ProvenOutcome>> {
        let Some(title) = probed_title(inner_filename) else {
            return Ok(None);
        };
        let claim = super::NameClaim {
            name: title,
            evidence: super::NameEvidence::BodyProbe,
            key: content_key
                .map(str::to_string)
                .unwrap_or_else(|| inner_filename.trim().to_string()),
            source: "body/rar".into(),
        };
        self.apply_proven_name(release_id, &claim, now).map(Some)
    }

    /// Fold one finished probe into the daily and lifetime tallies.
    /// `outcome` is one of the fixed field names below; unknown labels
    /// land in `other` rather than growing the schema silently.
    pub fn probe7z_note(
        &self,
        now: i64,
        outcome: &str,
        articles: u64,
        bytes: u64,
    ) -> rusqlite::Result<()> {
        const FIELDS: &[&str] = &[
            "named",
            "encrypted",
            "unreachable",
            "nohead",
            "tailmiss",
            "parsefail",
            "fetchfail",
            "junkname",
            // A byte-recovered name that disagreed with an
            // equal-or-stronger name already applied. Rare and worth
            // watching: for this band the probe is near-ground-truth.
            "conflict",
            "noshape",
        ];
        let field = if FIELDS.contains(&outcome) {
            outcome
        } else {
            "other"
        };
        for key in [
            format!("probe7z_day:{}", now.div_euclid(86_400)),
            "probe7z_total".to_string(),
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

    /// Today's and yesterday's tallies plus the lifetime total - the
    /// readout that makes a poster-side shape change (cadence stop,
    /// header encryption appearing) visible the day it happens.
    pub fn probe7z_stats(&self, now: i64) -> serde_json::Value {
        let day = now.div_euclid(86_400);
        let read = |key: String| -> serde_json::Value {
            self.kv_get(&key)
                .and_then(|v| serde_json::from_str(&v).ok())
                .unwrap_or_else(|| serde_json::json!({}))
        };
        serde_json::json!({
            "today": read(format!("probe7z_day:{day}")),
            "yesterday": read(format!("probe7z_day:{}", day - 1)),
            "total": read("probe7z_total".to_string()),
            // How much of the band is still ahead of the prober. The
            // pick's own filters, minus the rotation gates.
            "eligible": self.db.query_row(
                "SELECT COUNT(*) FROM releases
                  WHERE junk>=70 AND pre_title='' AND files>=2
                    AND total_bytes>=?1 AND probe_tries<?2 AND enc_class<>?3
                    AND EXISTS (SELECT 1 FROM files f
                                 WHERE f.release_id=releases.id
                                   AND (lower(f.filename) GLOB '*.7z'
                                     OR lower(f.filename) GLOB '*.7z.[0-9][0-9][0-9]'
                                     OR lower(f.filename) GLOB '*.7z.[0-9][0-9][0-9][0-9]'))",
                rusqlite::params![PROBE7Z_MIN_BYTES, PROBE7Z_GIVE_UP, super::ENC_CLASS],
                |r| r.get::<_, i64>(0),
            ).optional().ok().flatten(),
            // What the terminal classification has taken off the table
            // for good - the pilot's most reusable output, metered.
            "encrypted": self.header_encrypted_stats(),
        })
    }
}

/// Title a recovered inner filename earns on the wall: the final path
/// component with a media extension stripped, refused when the result
/// is empty or itself an obfuscated blob. Shared with the pesto rung -
/// a PAR2 FileDesc name is an uploader string exactly like a 7z entry.
pub(super) fn probed_title(inner: &str) -> Option<String> {
    let base = inner.trim();
    let title = match base.rsplit_once('.') {
        // At least one letter: an all-digit tail is not an extension,
        // it is the year of an extensionless "Some.Movie.2024" - the
        // one token predb/wall matching needs most.
        Some((stem, ext))
            if !stem.is_empty()
                && (2..=4).contains(&ext.len())
                && ext.chars().all(|c| c.is_ascii_alphanumeric())
                && ext.chars().any(|c| c.is_ascii_alphabetic()) =>
        {
            stem
        }
        _ => base,
    };
    let title = title.trim();
    if title.is_empty() || crate::release::looks_obfuscated(title) {
        return None;
    }
    Some(title.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::testutil::teardown;
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-index-probe-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn open(d: &std::path::Path) -> Index {
        Index::open(&d.join("index.db")).unwrap()
    }

    fn seed_release(
        ix: &mut Index,
        stem: &str,
        files: &[(&str, u64, &[&str])],
        total_bytes: i64,
        junk: i64,
    ) -> i64 {
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, total_bytes, files, junk, first_posted)
                 VALUES(?1, 'p@example', 'alt.binaries.tv', ?2, ?3, ?4, 1000)",
                rusqlite::params![stem, total_bytes, files.len() as i64, junk],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        for (name, bytes, ids) in files {
            let segs: Vec<(u32, String, u64)> = ids
                .iter()
                .enumerate()
                .map(|(i, id)| (i as u32 + 1, id.to_string(), 700_000))
                .collect();
            ix.db
                .execute(
                    "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        rid,
                        name,
                        segs.len() as i64,
                        *bytes as i64,
                        crate::index::segcodec::encode(&segs),
                        segs.len() as i64
                    ],
                )
                .unwrap();
        }
        rid
    }

    const BLOB: &str = "97VN9stfYqRAatUXTPVP0ApMrDua72fl";

    /// The shape production actually stores: the release stem keeps the
    /// archive extension. Every one of the 14,349 eligible rows on the
    /// live index looked like this, and every one of them fell out of
    /// the pick's obfuscation filter, because the fixtures above seed a
    /// BARE stem and never exercised the two-token path. The lane made
    /// zero probes in its entire production life on the strength of it.
    #[test]
    fn pick_matches_stems_that_kept_their_extension() {
        let d = dir("ext");
        let mut ix = open(&d);
        let rid = seed_release(
            &mut ix,
            &format!("{BLOB}.7z"),
            &[
                (&format!("{BLOB}.7z"), 900_000_000, &["<g1@x>", "<g2@x>"]),
                (&format!("{BLOB}.par2"), 50_000, &["<g3@x>"]),
            ],
            900_050_000,
            80,
        );
        // Still a readable name once the extension comes off: R6's trap
        // row survives the strip and must stay out.
        seed_release(
            &mut ix,
            "Some.Show.S01E01.1080p.WEB-DL.x264-GRP.7z",
            &[
                ("x.7z", 900_000_000, &["<h1@x>"]),
                ("y.par2", 1, &["<h2@x>"]),
            ],
            900_000_001,
            72,
        );
        assert_eq!(
            ix.probe7z_pick(1_000_000, 10)
                .unwrap()
                .iter()
                .map(|c| c.id)
                .collect::<Vec<_>>(),
            vec![rid],
            "the extension is stripped before the obfuscation test, not after"
        );
        // And the readable rows the filter rejected are STAMPED out of
        // the window (probe_at bumped), not left to squat in it:
        // unstamped rejects accumulate at the top of the newest-first
        // pick until the over-fetch window holds nothing else and every
        // older real candidate is walled off. But NOT saturated - a
        // filter's opinion must stay revisable (a wrong gate once
        // stranded the lane's whole payoff behind probe_tries=3), so
        // the reject keeps its tries and re-auditions after RETRY_SECS.
        let (at, tries): (i64, i64) = ix
            .db
            .query_row(
                "SELECT probe_at, probe_tries FROM releases
                  WHERE stem='Some.Show.S01E01.1080p.WEB-DL.x264-GRP.7z'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(at, 1_000_000, "reject stamped out of the immediate window");
        assert_eq!(tries, 0, "a filter reject is not a probe attempt");
        teardown(&d, ix);
    }

    #[test]
    fn pick_wants_obfuscated_7z_rows_only() {
        let d = dir("pick");
        let mut ix = open(&d);
        let a = seed_release(
            &mut ix,
            BLOB,
            &[
                (&format!("{BLOB}.7z"), 900_000_000, &["<a1@x>", "a2@x"]),
                (&format!("{BLOB}.par2"), 50_000, &["<p1@x>"]),
            ],
            900_050_000,
            80,
        );
        // Named-looking stem at junk>=70: R6's trap row - must not match.
        seed_release(
            &mut ix,
            "Some.Show.S01E01.1080p.WEB-DL.x264-GRP",
            &[
                ("x.7z", 900_000_000, &["<b1@x>"]),
                ("y.par2", 1, &["<b2@x>"]),
            ],
            900_000_001,
            72,
        );
        // Obfuscated but RAR: not this recipe's shape.
        seed_release(
            &mut ix,
            "n1iY94U6fTpMVY9GPDxx",
            &[
                ("v.part01.rar", 500_000_000, &["<c1@x>"]),
                ("v.part02.rar", 500_000_000, &["<c2@x>"]),
            ],
            1_000_000_000,
            90,
        );
        // Too small.
        seed_release(
            &mut ix,
            "2EBoCStAISSbbbbbbbbb",
            &[
                ("t.7z", 50_000_000, &["<d1@x>"]),
                ("t.par2", 1, &["<d2@x>"]),
            ],
            50_000_001,
            90,
        );
        let picks = ix.probe7z_pick(1_000_000, 10).unwrap();
        assert_eq!(
            picks.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![a],
            "only the obfuscated single-7z row is probe-worthy"
        );
        teardown(&d, ix);
    }

    #[test]
    fn split_volumes_match_the_shape_glob() {
        let d = dir("split");
        let mut ix = open(&d);
        let rid = seed_release(
            &mut ix,
            BLOB,
            &[
                (&format!("{BLOB}.7z.001"), 500_000_000, &["<e1@x>"]),
                (&format!("{BLOB}.7z.002"), 400_000_000, &["<e2@x>"]),
            ],
            900_000_000,
            85,
        );
        let picks = ix.probe7z_pick(1_000_000, 10).unwrap();
        assert_eq!(picks.iter().map(|c| c.id).collect::<Vec<_>>(), vec![rid]);
        teardown(&d, ix);
    }

    #[test]
    fn rotation_and_give_up_gate_the_pick() {
        let d = dir("rotate");
        let mut ix = open(&d);
        let rid = seed_release(
            &mut ix,
            BLOB,
            &[
                (&format!("{BLOB}.7z"), 900_000_000, &["<f1@x>"]),
                ("z.par2", 1, &["<f2@x>"]),
            ],
            900_000_001,
            80,
        );
        let now = 1_000_000;
        ix.probe7z_mark(rid, now).unwrap();
        // Freshly tried: out of the pick until the retry spacing lapses.
        assert!(ix.probe7z_pick(now, 10).unwrap().is_empty());
        assert_eq!(ix.probe7z_pick(now + RETRY_SECS, 10).unwrap().len(), 1);
        ix.probe7z_give_up(rid, now).unwrap();
        assert!(
            ix.probe7z_pick(now + 10 * RETRY_SECS, 10)
                .unwrap()
                .is_empty(),
            "given-up rows leave the lane for good"
        );
        teardown(&d, ix);
    }

    /// The terminal classification takes a row out of the pick by the
    /// FACT its bytes carried, and gives it straight back when the
    /// classifier generation moves - no migration, no backfill. The
    /// second half is the guard: a stamp that could not be taken back
    /// would be the saturating-probe_tries trap again (19 correct names
    /// stranded, memory nzbfast-byteprobe-lane-starvation), wearing a
    /// better argument.
    #[test]
    fn header_encrypted_rows_leave_the_pick_and_come_back_on_a_bump() {
        let d = dir("enc");
        let mut ix = open(&d);
        let rid = seed_release(
            &mut ix,
            &format!("{BLOB}.7z"),
            &[
                (&format!("{BLOB}.7z"), 900_000_000, &["<i1@x>"]),
                ("e.par2", 1, &["<i2@x>"]),
            ],
            900_000_001,
            80,
        );
        let now = 1_000_000;
        assert_eq!(ix.probe7z_pick(now, 10).unwrap().len(), 1);
        ix.probe7z_retire_encrypted(rid, super::super::EncKind::SevenzAesHeader, now)
            .unwrap();
        assert!(
            ix.probe7z_pick(now + 100 * RETRY_SECS, 10)
                .unwrap()
                .is_empty(),
            "an archive that says 'password required' is not re-probed"
        );
        // And the try counter is UNTOUCHED - it is the tries that make a
        // verdict permanent, and this verdict must not be.
        let tries: i64 = ix
            .db
            .query_row("SELECT probe_tries FROM releases WHERE id=?1", [rid], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(tries, 0, "encryption is classified, never counted out");
        assert_eq!(ix.probe7z_stats(now)["encrypted"]["releases"], 1);
        // Stand in for a bump of ENC_CLASS: the row's stamp is now from
        // a generation this code is not.
        ix.db
            .execute(
                "UPDATE releases SET enc_class=enc_class+1 WHERE id=?1",
                [rid],
            )
            .unwrap();
        assert_eq!(
            ix.probe7z_pick(now + 100 * RETRY_SECS, 10)
                .unwrap()
                .iter()
                .map(|c| c.id)
                .collect::<Vec<_>>(),
            vec![rid],
            "bumping the classifier generation re-opens the band by itself"
        );
        teardown(&d, ix);
    }

    #[test]
    fn msgids_come_back_bracketed_once() {
        let d = dir("msgids");
        let mut ix = open(&d);
        let rid = seed_release(
            &mut ix,
            BLOB,
            &[
                (&format!("{BLOB}.7z"), 900_000_000, &["<g1@x>", "g2@x"]),
                ("q.par2", 1, &["<g3@x>"]),
            ],
            900_000_001,
            80,
        );
        let files = ix.probe7z_files(rid).unwrap();
        let seg_ids: Vec<&str> = files
            .iter()
            .find(|f| f.filename.ends_with(".7z"))
            .unwrap()
            .segments
            .iter()
            .map(|(_, id, _)| id.as_str())
            .collect();
        assert_eq!(seg_ids, vec!["<g1@x>", "<g2@x>"]);
        teardown(&d, ix);
    }

    #[test]
    fn probed_name_is_proven_provenance_and_watch_visible() {
        let d = dir("apply");
        let mut ix = open(&d);
        let rid = seed_release(
            &mut ix,
            BLOB,
            &[
                (&format!("{BLOB}.7z"), 900_000_000, &["<h1@x>"]),
                ("w.par2", 1, &["<h2@x>"]),
            ],
            900_000_001,
            80,
        );
        assert_eq!(
            ix.apply_probed_name(
                rid,
                "Some.Show.S01E02.1080p.WEB-DL.AAC2.0.x264-GRP.mkv",
                2000
            )
            .unwrap(),
            Some(super::super::ProvenOutcome::Applied)
        );
        let (title, source): (String, String) = ix
            .db
            .query_row(
                "SELECT pre_title, pre_source FROM releases WHERE id=?1",
                [rid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(title, "Some.Show.S01E02.1080p.WEB-DL.AAC2.0.x264-GRP");
        // The claims layer's provenance form: a byte-proven name at the
        // BodyProbe tier, source body/7z. NOT the predb/... vocabulary,
        // and the wall reads its `proven:body-probe` prefix as the
        // "archive" badge, never the tentative correlated one.
        assert_eq!(source, "proven:body-probe:body/7z");
        // A different byte-recovered name is a Conflict against an
        // equal-tier name already applied - recorded, never overwritten.
        assert_eq!(
            ix.apply_probed_name(rid, "Other.Name.mkv", 3000).unwrap(),
            Some(super::super::ProvenOutcome::Conflict)
        );
        teardown(&d, ix);
    }

    #[test]
    fn junk_inner_names_are_refused() {
        assert_eq!(probed_title("d41d8cd98f00b204e9800998ecf8427e.mkv"), None);
        assert_eq!(probed_title("   "), None);
        assert_eq!(
            probed_title("Show.S01E01.720p.x264-GRP.mkv").as_deref(),
            Some("Show.S01E01.720p.x264-GRP")
        );
        // No extension: kept whole.
        assert_eq!(
            probed_title("Show.S01E01.720p.x264-GRP").as_deref(),
            Some("Show.S01E01.720p.x264-GRP")
        );
    }

    /// A RAR-recovered inner name is body-derived truth and goes in
    /// through the SAME entry point as every other proof, with its own
    /// provenance so this lane can be re-argued alone. The content key
    /// is the header's size+CRC - a corroborating key, exact for the
    /// volume, and repeated in every volume of the set, which is what
    /// lets a mid-set head and a first-volume head confirm each other.
    #[test]
    fn rar_named_rows_carry_their_own_provenance_and_content_key() {
        let d = dir("rarname");
        let mut ix = open(&d);
        let rid = seed_release(
            &mut ix,
            BLOB,
            &[
                (&format!("{BLOB}.part01.rar"), 500_000_000, &["<j1@x>"]),
                (&format!("{BLOB}.part02.rar"), 500_000_000, &["<j2@x>"]),
            ],
            1_000_000_000,
            90,
        );
        assert_eq!(
            ix.apply_rar_named(
                rid,
                "Some.Movie.2011.1080p.BluRay.x264-GRP.mkv",
                Some("8000000000:deadbeef"),
                2000
            )
            .unwrap(),
            Some(super::super::ProvenOutcome::Applied)
        );
        let (title, source): (String, String) = ix
            .db
            .query_row(
                "SELECT pre_title, pre_source FROM releases WHERE id=?1",
                [rid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(title, "Some.Movie.2011.1080p.BluRay.x264-GRP");
        assert_eq!(
            source, "proven:body-probe:body/rar",
            "body/rar, NOT body/7z - which container proved it is part of the record"
        );
        // The same fact re-proved from another volume is one claim, not
        // a second opinion: same name, same key.
        assert_eq!(
            ix.apply_rar_named(
                rid,
                "Some.Movie.2011.1080p.BluRay.x264-GRP.mkv",
                Some("8000000000:deadbeef"),
                3000
            )
            .unwrap(),
            Some(super::super::ProvenOutcome::Confirmed)
        );
        // The pilot's commonest RAR4 outcome by far (7 of 13 plaintext
        // headers): the inner name is as obfuscated as the outer post.
        // No claim at all - naming junk with junk would only hide the
        // row from the lanes that could still name it.
        let rid2 = seed_release(
            &mut ix,
            "n1iY94U6fTpMVY9GPDxx",
            &[("v.part01.rar", 500_000_000, &["<k1@x>"])],
            500_000_000,
            90,
        );
        assert_eq!(
            ix.apply_rar_named(rid2, "BW90gZxQrxHh.mkv", Some("1:2"), 4000)
                .unwrap(),
            None
        );
        teardown(&d, ix);
    }

    #[test]
    fn daily_tallies_roll_and_persist() {
        let d = dir("tally");
        let ix = open(&d);
        let now = 40 * 86_400 + 100;
        ix.probe7z_note(now, "named", 3, 2_000_000).unwrap();
        ix.probe7z_note(now, "encrypted", 1, 700_000).unwrap();
        ix.probe7z_note(now + 86_400, "named", 2, 1_500_000)
            .unwrap();
        let s = ix.probe7z_stats(now + 86_400);
        assert_eq!(s["today"]["attempts"], 1);
        assert_eq!(s["today"]["named"], 1);
        assert_eq!(s["yesterday"]["attempts"], 2);
        assert_eq!(s["yesterday"]["encrypted"], 1);
        assert_eq!(s["total"]["attempts"], 3);
        assert_eq!(s["total"]["articles"], 6);
        teardown(&d, ix);
    }
}
