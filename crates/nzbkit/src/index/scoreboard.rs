//! Parity scoreboard (research R1 / red-team build-order #8): given a
//! reference indexer's newest releases, answer per release - do we have
//! the post, is it NAMED in our index, and how far behind were we?
//!
//! The verdicts follow Codex's refinement from the red-team round:
//! `have_named` requires EXACT title/episode-level parity between the
//! reference's display name and the name we hold (stem or fed pre
//! name), not merely a plausible size+time neighbour. Presence via the
//! size+time band alone is `have_unnamed` - a raw-coverage ESTIMATE
//! whose false-positive rate the calibration subset measures - and the
//! consumers must present it as an estimate, never a hard number.
//!
//! What the scoreboard MEASURES, settled with the REFRESH sweep's M8
//! (TODO §144 item 2): the unit is the RELEASE, not the article set.
//! "Could a user of our index find this release, under its real name,
//! and how far behind the reference were we?" That is why an older
//! repost of the same release name counts as a hit - our user finds it
//! and downloads it, and telling the naming lanes to go chase a post
//! we already serve would be a lie in the other direction. Identity
//! itself is [`stem_evidence`]'s one rule: a stem proves what it means.

use super::*;

/// How far our `first_posted` may sit from the reference's usenetdate
/// and still be the same post. Both sides derive from article Date
/// headers, but a multi-hour upload and scan timing skew the edges;
/// two days is comfortably past both without dragging in last week.
const BAND_WINDOW_SECS: i64 = 48 * 3_600;

/// Rows a band scan will look at before giving up. A two-day window on
/// a busy index is thousands of rows; past this cap the scan calls the
/// window saturated and answers with what it saw, the same principle
/// as `corr_eval`'s candidate cap.
const BAND_SCAN_CAP: usize = 5_000;

/// Characters a stem must carry, after any file extension is dropped,
/// before an exact match on it may stand as identity at all. A length
/// floor and not a deny-list of role words, because a deny-list is
/// incomplete by construction and wrong in every language the feed is
/// not written in. Measured against a 15.9 M release index (10 Aug
/// 2026): it refuses 3,530 stems, none of them a release identity -
/// `sample.mkv`, `Subs`, `VIDEO_TS`, `001`, `1`, `index.html`,
/// `.course_id`, `style.css` - and matching one of those proves only
/// that somebody, somewhere, posted a file with that role name.
const IDENT_MIN_CHARS: usize = 12;

/// Separator-delimited tokens a stem must carry to be read as a release
/// NAME rather than an opaque token. Real release names are built out
/// of title, year or episode, quality and group, so three is a floor no
/// scene or p2p name misses. What it holds back to a time-bounded
/// presence claim is the two-token middle ground: `files_manifest`, and
/// the hash-plus-tag stems a repacker leaves behind
/// (`3c501c38a7924fb7a4d64977a7562900-NZBG`, 14 releases over 48 days).
const IDENT_MIN_TOKENS: usize = 3;

/// What an exact match on a stem is allowed to prove.
///
/// The scoreboard's one identity rule, and the answer to the REFRESH
/// sweep's M8: **a stem proves what it means.** A stem that reads as a
/// release name proves naming, and proves it wherever it is found - a
/// repost carries the same name and is the same release. A stem that
/// reads as an opaque token (an obfuscated filename) carries no
/// meaning to be "the same release" under, so it proves only that the
/// bytes are present, and only when it lands at the reference's posted
/// time. Anything too slight to be either proves nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StemEvidence {
    /// Furniture, a bare number, a couple of characters. No lookup.
    None,
    /// A release name: global, and it proves the name.
    Name,
    /// An opaque identity token: time-bounded, and it proves presence
    /// only - never that we hold the release under its real name.
    Token,
}

/// Classify a stem for the two identity lookups. Public because the
/// before/after ruler (`tests/integration/scoreboard_parity_measure.rs`) reports
/// the census this rule was chosen from.
///
/// Length is the floor against triviality; the token count is what
/// separates a name from an opaque blob; and for everything that is
/// not a name it is the CALLER's 48 h bound, not this function, that
/// does the real work. So the failure mode here is deliberately
/// one-sided: a terse two-token name (`Inception.2010`) reads as a
/// token and scores presence rather than naming. Under-claiming the
/// KPI is the safe direction, and the alternative - accepting two
/// tokens as a name - would hand a global, unbounded match to
/// `files_manifest` and to the hash-plus-tag stems a repacker leaves
/// behind.
pub fn stem_evidence(stem: &str) -> StemEvidence {
    let stem = stem.trim();
    let bare = crate::release::bare_stem(stem);
    if bare.chars().count() < IDENT_MIN_CHARS {
        return StemEvidence::None;
    }
    let tokens = bare
        .split(['.', '_', ' ', '-'])
        .filter(|t| !t.is_empty())
        .count();
    if tokens >= IDENT_MIN_TOKENS && crate::release::stem_is_a_name(stem) {
        StemEvidence::Name
    } else {
        StemEvidence::Token
    }
}

/// One sampled reference release, ready to store.
#[derive(Debug, Clone)]
pub struct ScoreboardSample {
    /// Reference host (never the URL - it can carry a key).
    pub source: String,
    pub category: String,
    pub ref_guid: String,
    pub ref_name: String,
    pub ref_size: u64,
    pub ref_posted: i64,
    pub ref_group: String,
    /// have_named | have_unnamed | missing
    pub verdict: String,
    pub matched_release_id: i64,
    /// stem | band | subject_stem ('' when missing)
    pub key_used: String,
    pub lag_secs: i64,
}

/// What `scoreboard_match` decided for one reference release.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreboardMatch {
    /// have_named | have_unnamed | missing
    pub verdict: &'static str,
    /// stem | band ('' when missing)
    pub key_used: &'static str,
    pub release_id: i64,
    pub lag_secs: i64,
}

/// Per-category aggregate over a window of samples.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreboardCat {
    pub category: String,
    pub total: u64,
    pub have_named: u64,
    pub have_unnamed: u64,
    pub missing: u64,
    /// Median `lag_secs` over the samples we DO have (named or not).
    /// 0 when there were no hits.
    pub lag_median_secs: i64,
}

/// Exact title/episode parity between two parsed release names: same
/// dedupe key (title + year for movies), same season/episode span, and
/// the same daily date for dated posts. The dedupe key alone groups a
/// show's whole run under one card, which is exactly the coarseness
/// the red-team told the scoreboard not to inherit.
fn exact_parity(a: &crate::release::Parsed, b: &crate::release::Parsed) -> bool {
    // A key whose title segment normalized to nothing ("m:" - a name
    // with no alphanumerics at all) would "match" the first equally
    // degenerate row in the band: two normalization failures agreeing
    // is not parity.
    let titled = |k: &str| k.split(':').nth(1).is_some_and(|t| !t.is_empty());
    titled(&a.key)
        && a.key == b.key
        && a.season == b.season
        && a.episode == b.episode
        && a.episode2 == b.episode2
        && a.date == b.date
}

impl Index {
    /// Decide, for one reference release, whether our index holds the
    /// same post and under what name. Read-only; safe on the read pool.
    pub fn scoreboard_match(
        &self,
        ref_name: &str,
        ref_size: u64,
        ref_posted: i64,
    ) -> rusqlite::Result<ScoreboardMatch> {
        let missing = ScoreboardMatch {
            verdict: "missing",
            key_used: "",
            release_id: 0,
            lag_secs: 0,
        };
        let lag = |first_seen: i64| {
            if ref_posted > 0 && first_seen > ref_posted {
                first_seen - ref_posted
            } else {
                0
            }
        };
        // Key (a): exact stem. A named post's subject stem IS its
        // release name, so this answers "do we hold this post under
        // its real name" with one indexed lookup and no fetch.
        //
        // What it may CONCLUDE is [`stem_evidence`]'s call. A name
        // matches globally and proves naming; an obfuscated reference
        // title matches only inside the band and proves presence
        // alone, because neither side has a name to be in parity
        // about; a stem too slight to be either does not look at all.
        let stem = release_stem(ref_name.trim());
        // A token lookup needs a reference time to bound it; with none,
        // an opaque token proves nothing.
        let keyed = match stem_evidence(&stem) {
            StemEvidence::Name => Some(("have_named", self.stem_hit(&stem)?)),
            StemEvidence::Token if ref_posted > 0 => {
                Some(("have_unnamed", self.stem_hit_near(&stem, ref_posted)?))
            }
            _ => None,
        };
        if let Some((verdict, Some((id, seen)))) = keyed {
            return Ok(ScoreboardMatch {
                verdict,
                key_used: "stem",
                release_id: id,
                lag_secs: lag(seen),
            });
        }
        // Key (b): the size+time band, the raw-coverage estimate. Also
        // where a post named through the pre feed (stem obfuscated,
        // pre_title real) earns exact parity.
        if ref_posted <= 0 {
            return Ok(missing);
        }
        let want = crate::release::parse_release(ref_name.trim());
        let mut stmt = self.db.prepare_cached(
            "SELECT id, stem, pre_title, total_bytes, first_seen
               FROM releases WHERE first_posted BETWEEN ?1 AND ?2
              LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![
                ref_posted - BAND_WINDOW_SECS,
                ref_posted + BAND_WINDOW_SECS,
                BAND_SCAN_CAP as i64
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )?;
        let mut band_hit: Option<(i64, i64)> = None;
        for row in rows {
            let (id, rstem, pre_title, total_bytes, seen) = row?;
            // Same size model as the correlation scorer: our
            // total_bytes is over-wire, the reference's size is
            // content, and the yEnc factor sits between them.
            let size_ok = ref_size > 0 && {
                let est = total_bytes.max(0) as f64 / crate::predb_corr::YENC_FACTOR;
                let ratio = est / ref_size as f64;
                (crate::predb_corr::RATIO_MIN..=crate::predb_corr::RATIO_MAX).contains(&ratio)
            };
            // Exact parity through the display name we would actually
            // show: the fed pre name when one applied, the stem
            // otherwise. Checked for every row in the window - a
            // renamed post's SIZE can sit outside the band (par2
            // accounting differs per indexer) while its name is still
            // exactly right.
            let display = if pre_title.trim().is_empty() {
                rstem.as_str()
            } else {
                pre_title.trim()
            };
            let have = crate::release::parse_release(display);
            if exact_parity(&want, &have) {
                return Ok(ScoreboardMatch {
                    verdict: "have_named",
                    key_used: "band",
                    release_id: id,
                    lag_secs: lag(seen),
                });
            }
            if size_ok && band_hit.is_none() {
                band_hit = Some((id, seen));
            }
        }
        Ok(match band_hit {
            Some((id, seen)) => ScoreboardMatch {
                verdict: "have_unnamed",
                key_used: "band",
                release_id: id,
                lag_secs: lag(seen),
            },
            None => missing,
        })
    }

    /// Oldest release carrying this stem, anywhere in the index. Used
    /// only where the stem is a NAME: a repost of a release carries the
    /// same name and is the same release, so the match is deliberately
    /// unbounded in time.
    fn stem_hit(&self, stem: &str) -> rusqlite::Result<Option<(i64, i64)>> {
        self.db
            .prepare_cached(
                "SELECT id, first_seen FROM releases WHERE stem=?1
                  ORDER BY first_posted LIMIT 1",
            )?
            .query_row([stem], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
    }

    /// The same lookup, bounded to the reference's posting window. Used
    /// where the stem is an opaque TOKEN, which identifies one posting
    /// and nothing else. Measured on a 15.9 M release index (10 Aug
    /// 2026): 574,951 of the 575,486 shared stems - 99.91% - have every
    /// row inside a single 48 h window, so the bound costs the true
    /// case essentially nothing and is the only thing standing between
    /// a reused filler filename (one stem there carries 22,831
    /// unrelated releases) and a proof of presence.
    fn stem_hit_near(&self, stem: &str, posted: i64) -> rusqlite::Result<Option<(i64, i64)>> {
        self.db
            .prepare_cached(
                "SELECT id, first_seen FROM releases
                  WHERE stem=?1 AND first_posted BETWEEN ?2 AND ?3
                  ORDER BY first_posted LIMIT 1",
            )?
            .query_row(
                rusqlite::params![stem, posted - BAND_WINDOW_SECS, posted + BAND_WINDOW_SECS],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
    }

    /// Exact presence lookup for the calibration subset: the stems out
    /// of a fetched reference NZB's article subjects are the same bytes
    /// the scanner clustered under, so a hit here is proof of presence
    /// regardless of obfuscation. Returns (release_id, first_seen).
    ///
    /// `ref_posted` is the reference release's posting time, and it is
    /// required: the calibration pass reads EVERY distinct subject stem
    /// in a fetched NZB, which is where a set's furniture lives. Under
    /// [`stem_evidence`] a role name (`Subs`, `sample.mkv`, `001`)
    /// proves nothing at all, and an obfuscated inner filename proves
    /// presence only if our copy of it sits at the reference's posted
    /// time. Only a stem that reads as a real release name is allowed
    /// to answer from anywhere in the index.
    pub fn scoreboard_stem_lookup(
        &self,
        stem: &str,
        ref_posted: i64,
    ) -> rusqlite::Result<Option<(i64, i64)>> {
        let stem = stem.trim();
        match stem_evidence(stem) {
            StemEvidence::Name => self.stem_hit(stem),
            StemEvidence::Token if ref_posted > 0 => self.stem_hit_near(stem, ref_posted),
            _ => Ok(None),
        }
    }

    /// Store a batch of samples, idempotently: a re-run of the same day
    /// re-answers the same guids and the verdicts simply refresh (which
    /// is also how the calibration pass corrects a band verdict).
    pub fn scoreboard_store(
        &mut self,
        samples: &[ScoreboardSample],
        now: i64,
    ) -> rusqlite::Result<usize> {
        let tx = self.db.transaction()?;
        let mut stored = 0usize;
        for s in samples {
            if s.ref_guid.trim().is_empty() || s.ref_name.trim().is_empty() {
                continue;
            }
            // The conflict arm carries the recheck's invariants, because
            // slow categories re-serve the same guid on consecutive
            // days: nothing downgrades (a retention eviction between
            // runs is policy, not a scan failure), calibration truth
            // (`subject_stem`, byte-proven) is never overwritten by a
            // cheaper key, and only calibration itself may restate a
            // verdict without improving it - that stamp is what keeps
            // the row out of the next day's grab-quota pool.
            stored += tx
                .prepare_cached(
                    "INSERT INTO scoreboard_samples(
                        source, category, ref_guid, ref_name, ref_size,
                        ref_posted, ref_group, verdict, matched_release_id,
                        key_used, lag_secs, at)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
                     ON CONFLICT(source, ref_guid) DO UPDATE SET
                       verdict=excluded.verdict,
                       matched_release_id=excluded.matched_release_id,
                       key_used=excluded.key_used,
                       lag_secs=excluded.lag_secs
                     WHERE scoreboard_samples.key_used<>'subject_stem'
                       AND (excluded.key_used='subject_stem'
                         OR (CASE excluded.verdict
                               WHEN 'have_named' THEN 2
                               WHEN 'have_unnamed' THEN 1 ELSE 0 END)
                          > (CASE scoreboard_samples.verdict
                               WHEN 'have_named' THEN 2
                               WHEN 'have_unnamed' THEN 1 ELSE 0 END))",
                )?
                .execute(rusqlite::params![
                    s.source,
                    s.category,
                    s.ref_guid.trim(),
                    s.ref_name.trim(),
                    s.ref_size as i64,
                    s.ref_posted,
                    s.ref_group,
                    s.verdict,
                    s.matched_release_id,
                    s.key_used,
                    s.lag_secs,
                    now
                ])?;
        }
        tx.commit()?;
        Ok(stored)
    }

    /// Re-match recent unproven samples against TODAY's index, at zero
    /// API cost. A reference release sampled before our scanner reached
    /// its post reads as `missing` on day one; without this pass that
    /// verdict froze into a permanent coverage hole, when the truth is
    /// "we got it a day later" - which is exactly what the lag column
    /// exists to say.
    ///
    /// Upgrade-only, deliberately: `missing` can become a hit and
    /// `have_unnamed` can become `have_named` (the pre feed naming a
    /// post after the sample), but nothing downgrades - a later
    /// retention eviction is policy, not a scan failure, and
    /// `subject_stem` rows are calibration TRUTH the cheaper keys must
    /// not overwrite. Returns how many rows improved.
    /// `after` is an id cursor: only rows with `id > after` are
    /// examined, and the second return value is the last id examined
    /// (None when the window is exhausted). The caller chunks the pass
    /// across separate lock holds - each row here can cost a full band
    /// scan (thousands of `parse_release` calls), and one hold across
    /// the whole window starved every other index user for the
    /// duration.
    pub fn scoreboard_recheck(
        &mut self,
        since: i64,
        after: i64,
        limit: usize,
    ) -> rusqlite::Result<(usize, Option<i64>)> {
        let rank = |v: &str| match v {
            "have_named" => 2u8,
            "have_unnamed" => 1,
            _ => 0,
        };
        let rows: Vec<(i64, String, u64, i64, String)> = self
            .db
            .prepare_cached(
                "SELECT id, ref_name, ref_size, ref_posted, verdict
                   FROM scoreboard_samples
                  WHERE id>?3 AND at>=?1 AND verdict<>'have_named'
                    AND key_used<>'subject_stem'
                  ORDER BY id LIMIT ?2",
            )?
            .query_map(rusqlite::params![since, limit as i64, after], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get::<_, i64>(2)?.max(0) as u64,
                    r.get(3)?,
                    r.get(4)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut improved = 0usize;
        let mut last = None;
        for (id, name, size, posted, old) in rows {
            last = Some(id);
            let m = self.scoreboard_match(&name, size, posted)?;
            if rank(m.verdict) <= rank(&old) {
                continue;
            }
            self.db.execute(
                "UPDATE scoreboard_samples
                    SET verdict=?1, matched_release_id=?2, key_used=?3, lag_secs=?4
                  WHERE id=?5",
                rusqlite::params![m.verdict, m.release_id, m.key_used, m.lag_secs, id],
            )?;
            improved += 1;
        }
        Ok((improved, last))
    }

    /// Today's samples still eligible for calibration: band or missing
    /// verdicts (a stem hit is already exact). Newest first, capped.
    pub fn scoreboard_calibratable(
        &self,
        since: i64,
        limit: usize,
    ) -> rusqlite::Result<Vec<(String, String, u64, i64)>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT ref_guid, ref_name, ref_size, ref_posted
               FROM scoreboard_samples
              WHERE at>=?1 AND key_used<>'stem' AND key_used<>'subject_stem'
              ORDER BY at DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![since, limit as i64], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get::<_, i64>(2)?.max(0) as u64,
                    r.get(3)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// Per-category aggregates over samples stored since `since`.
    /// Read the doc note on [`ScoreboardCat`]: `have_unnamed` is the
    /// band estimate, not proof.
    /// Read-only; the volume (hundreds of rows a day) makes fetching
    /// the verdict rows and reducing here cheaper than wrestling a
    /// median out of SQL.
    pub fn scoreboard_stats(&self, since: i64) -> rusqlite::Result<Vec<ScoreboardCat>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT category, verdict, lag_secs FROM scoreboard_samples
              WHERE at>=?1",
        )?;
        let rows = stmt.query_map([since], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut cats: BTreeMap<String, (u64, u64, u64, u64, Vec<i64>)> = BTreeMap::new();
        for row in rows {
            let (cat, verdict, lag) = row?;
            let e = cats.entry(cat).or_default();
            e.0 += 1;
            match verdict.as_str() {
                "have_named" => e.1 += 1,
                "have_unnamed" => e.2 += 1,
                _ => e.3 += 1,
            }
            if verdict != "missing" {
                e.4.push(lag);
            }
        }
        Ok(cats
            .into_iter()
            .map(|(category, (total, named, unnamed, missing, mut lags))| {
                lags.sort_unstable();
                let lag_median_secs = if lags.is_empty() {
                    0
                } else {
                    lags[lags.len() / 2]
                };
                ScoreboardCat {
                    category,
                    total,
                    have_named: named,
                    have_unnamed: unnamed,
                    missing,
                    lag_median_secs,
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::teardown;
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-index-sb-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn posted_entry(subject: &str, id: &str, posted: i64, bytes: u64) -> OverEntry {
        OverEntry {
            number: 0,
            subject: subject.into(),
            from: "poster@example".into(),
            message_id: format!("<{id}>"),
            bytes,
            date: posted,
        }
    }

    const T: i64 = 1_700_000_000;

    /// A named post answers through the stem key alone: exact by
    /// construction, lag measured from our first_seen.
    #[test]
    fn a_named_post_is_have_named_via_stem() {
        let d = dir("stem");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[posted_entry(
                r#""Some.Show.S01E02.1080p.WEB-GRP.rar" yEnc (1/1)"#,
                "a1",
                T,
                4_000_000_000,
            )],
            T + 7_200,
        )
        .unwrap();
        let m = ix
            .scoreboard_match("Some.Show.S01E02.1080p.WEB-GRP", 3_900_000_000, T)
            .unwrap();
        assert_eq!((m.verdict, m.key_used), ("have_named", "stem"));
        assert_eq!(m.lag_secs, 7_200);
        teardown(&d, ix);
    }

    /// The identity rule itself, on the shapes the 10 Aug 2026 census
    /// of a 15.9 M release index actually turned up.
    #[test]
    fn a_stem_proves_what_it_means() {
        let ev = stem_evidence;
        // Release names: what the reference indexer lists.
        for name in [
            "Some.Show.S01E02.1080p.WEB-GRP",
            "Chop.Chop.Inc-TENOKE",
            "1.Queen.5.Queers.S01E01.Love.1080p.AMZN.WEB-DL.H.264-NYXIS.mkv",
            "Topaz Video AI Pro 7.1.6 (x64)",
        ] {
            assert_eq!(ev(name), StemEvidence::Name, "{name}");
        }
        // Opaque tokens: presence only, and only in the window. The
        // underscore-separated shapes are the ones a first cut of this
        // rule wrongly refused - `looks_obfuscated` only judges
        // single-token blobs, and these are the bulk of what the
        // calibration pass has to work with.
        for blob in [
            "w17vwqfb7antoeed8.mkv",
            "147062135667c86fca7cff2656e179ad24a67b69",
            "sbTEd5SQ7ziV_7G38m3iNSBPH9W",
            "d_nB7zvMRV7RwL86Gc23bE",
            // Not a blob, but not a release name either: two tokens
            // buys a time-bounded presence claim, never a global one.
            "files_manifest.json",
            "3c501c38a7924fb7a4d64977a7562900-NZBG",
        ] {
            assert_eq!(ev(blob), StemEvidence::Token, "{blob}");
        }
        // Furniture and near-nothing: an exact match on these proves
        // only that SOMEBODY posted a file with that role name. The
        // whole finding.
        for junk in [
            "",
            "  ",
            "sample",
            "sample.mkv",
            "Subs",
            "VIDEO_TS",
            "001",
            "1",
            "screenshot",
            "subtitles",
            "index.html",
            ".course_id",
        ] {
            assert_eq!(ev(junk), StemEvidence::None, "{junk}");
        }
    }

    /// M8: a generic inner stem must not answer the calibration pass,
    /// and an obfuscated one must land at the reference's posted time.
    /// Both lookups previously matched `stem` alone, so a `Subs` row
    /// anywhere in the index proved the reference posting was present.
    #[test]
    fn calibration_lookups_are_bounded_by_what_the_stem_means() {
        let d = dir("callookup");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[
                posted_entry(r#""Subs.rar" yEnc (1/1)"#, "j1", T, 1_000),
                // The same opaque filler filename, a month apart.
                posted_entry(
                    r#""w17vwqfb7antoeed8.mkv" yEnc (1/1)"#,
                    "j2",
                    T,
                    4_000_000_000,
                ),
                posted_entry(
                    r#""Real.Show.S01E01.1080p.WEB-GRP.rar" yEnc (1/1)"#,
                    "j3",
                    T - 90 * 86_400,
                    4_000_000_000,
                ),
            ],
            T,
        )
        .unwrap();

        // Furniture proves nothing, at any time. The row IS in the
        // index - the old unconditional `WHERE stem=?1` answered it,
        // which is the finding - so this None is the guard's doing.
        assert_eq!(
            ix.db
                .query_row("SELECT count(*) FROM releases WHERE stem='Subs'", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(ix.scoreboard_stem_lookup("Subs", T).unwrap(), None);
        // The token proves presence in its own window...
        assert!(
            ix.scoreboard_stem_lookup("w17vwqfb7antoeed8.mkv", T)
                .unwrap()
                .is_some()
        );
        // ...and nothing a month later, which is the reused-filler case.
        assert_eq!(
            ix.scoreboard_stem_lookup("w17vwqfb7antoeed8.mkv", T + 30 * 86_400)
                .unwrap(),
            None
        );
        // A token with no reference time to be bounded by is refused.
        assert_eq!(
            ix.scoreboard_stem_lookup("w17vwqfb7antoeed8.mkv", 0)
                .unwrap(),
            None
        );
        // A real NAME still answers from anywhere: the release-level
        // ruling, and the reason the pre feed's own names still work.
        assert!(
            ix.scoreboard_stem_lookup("Real.Show.S01E01.1080p.WEB-GRP", T)
                .unwrap()
                .is_some()
        );
        teardown(&d, ix);
    }

    /// An obfuscated reference title cannot claim NAMED parity: neither
    /// side holds a name, so the most it can say is that we have the
    /// bytes - and only inside the reference's posting window.
    #[test]
    fn an_obfuscated_reference_title_proves_presence_not_naming() {
        let d = dir("reftoken");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[posted_entry(
                r#""p148beoohuwrf7lhxzb66o.mkv" yEnc (1/1)"#,
                "t1",
                T,
                4_000_000_000,
            )],
            T + 600,
        )
        .unwrap();
        let m = ix
            .scoreboard_match("p148beoohuwrf7lhxzb66o.mkv", 3_900_000_000, T)
            .unwrap();
        assert_eq!((m.verdict, m.key_used), ("have_unnamed", "stem"));
        // A month away it is a different posting that reused the name.
        let m = ix
            .scoreboard_match("p148beoohuwrf7lhxzb66o.mkv", 3_900_000_000, T + 30 * 86_400)
            .unwrap();
        assert_eq!(m.verdict, "missing");
        teardown(&d, ix);
    }

    /// The release-level ruling, stated as a test: a repost carries the
    /// same release name and IS the same release, so an older copy is a
    /// hit however far back it sits. A date band on the name key would
    /// turn every repost into a coverage hole the band scan cannot
    /// rescue (it sees 5,000 of a ~289,000-row window at real density).
    #[test]
    fn an_older_repost_of_the_same_name_is_a_hit() {
        let d = dir("repost");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[posted_entry(
                r#""Old.Post.S01E01.1080p.WEB-GRP.rar" yEnc (1/1)"#,
                "o1",
                T - 120 * 86_400,
                4_000_000_000,
            )],
            T - 120 * 86_400 + 600,
        )
        .unwrap();
        let m = ix
            .scoreboard_match("Old.Post.S01E01.1080p.WEB-GRP", 3_900_000_000, T)
            .unwrap();
        assert_eq!((m.verdict, m.key_used), ("have_named", "stem"));
        // We held it before the reference listed it, so there is no lag
        // to report - not a negative one.
        assert_eq!(m.lag_secs, 0);
        teardown(&d, ix);
    }

    /// An obfuscated post in the right size+time band is presence, not
    /// naming - and a pre-fed real name upgrades it to have_named, but
    /// ONLY at exact episode parity (the Codex refinement).
    #[test]
    fn band_hits_split_on_exact_name_parity() {
        let d = dir("band");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[posted_entry(
                r#""a9f3c2d1e4b5.rar" yEnc (1/1)"#,
                "b1",
                T,
                4_000_000_000,
            )],
            T + 600,
        )
        .unwrap();
        let m = ix
            .scoreboard_match("Some.Show.S01E02.1080p.WEB-GRP", 3_900_000_000, T)
            .unwrap();
        assert_eq!((m.verdict, m.key_used), ("have_unnamed", "band"));

        // The pre feed names the post: same episode = exact parity.
        ix.db
            .execute(
                "UPDATE releases SET pre_title='Some.Show.S01E02.1080p.WEB-GRP'",
                [],
            )
            .unwrap();
        let m = ix
            .scoreboard_match("Some.Show.S01E02.1080p.WEB-GRP", 3_900_000_000, T)
            .unwrap();
        assert_eq!((m.verdict, m.key_used), ("have_named", "band"));

        // A DIFFERENT episode of the same show must not count as
        // named parity - that is the coarse presence number the
        // red-team ruled out.
        let m = ix
            .scoreboard_match("Some.Show.S01E03.1080p.WEB-GRP", 3_900_000_000, T)
            .unwrap();
        assert_eq!((m.verdict, m.key_used), ("have_unnamed", "band"));
        teardown(&d, ix);
    }

    /// Outside the time window, or with nothing indexed, the verdict
    /// is missing - a sizeless reference cannot claim a band hit.
    #[test]
    fn missing_when_nothing_plausible_exists() {
        let d = dir("missing");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[posted_entry(
                r#""c0ffee00.rar" yEnc (1/1)"#,
                "c1",
                T,
                4_000_000_000,
            )],
            T + 600,
        )
        .unwrap();
        // A week away in time: no band candidate.
        let m = ix
            .scoreboard_match(
                "Other.Film.2026.1080p.BluRay-GRP",
                3_900_000_000,
                T + 7 * 86_400,
            )
            .unwrap();
        assert_eq!(m.verdict, "missing");
        // In the window but sizeless: presence cannot be claimed.
        let m = ix
            .scoreboard_match("Other.Film.2026.1080p.BluRay-GRP", 0, T)
            .unwrap();
        assert_eq!(m.verdict, "missing");
        teardown(&d, ix);
    }

    /// The recheck pass turns a too-early `missing` into a hit once
    /// the scanner catches up - upgrade-only, and calibration truth
    /// (`subject_stem`) is never overwritten by the cheaper keys.
    #[test]
    fn recheck_upgrades_but_never_downgrades() {
        let d = dir("recheck");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let sample = |guid: &str, verdict: &str, key: &str| ScoreboardSample {
            source: "ref.example".into(),
            category: "tv".into(),
            ref_guid: guid.into(),
            ref_name: "Late.Show.S02E05.1080p.WEB-GRP".into(),
            ref_size: 3_900_000_000,
            ref_posted: T,
            ref_group: String::new(),
            verdict: verdict.into(),
            matched_release_id: 0,
            key_used: key.into(),
            lag_secs: 0,
        };
        ix.scoreboard_store(
            &[
                // Sampled before the scanner saw the post.
                sample("g1", "missing", ""),
                // Calibration already proved this one ABSENT; the band
                // rechecking must not resurrect it.
                sample("g2", "missing", "subject_stem"),
            ],
            T,
        )
        .unwrap();
        // The scanner catches up a day later.
        ix.ingest(
            "alt.binaries.teevee",
            &[posted_entry(
                r#""Late.Show.S02E05.1080p.WEB-GRP.rar" yEnc (1/1)"#,
                "r1",
                T,
                4_000_000_000,
            )],
            T + 86_400,
        )
        .unwrap();
        assert_eq!(ix.scoreboard_recheck(T - 1, 0, 100).unwrap().0, 1);
        let stats = ix.scoreboard_stats(T - 1).unwrap();
        let tv = &stats[0];
        assert_eq!((tv.have_named, tv.missing), (1, 1));
        // The upgraded row carries the catch-up as LAG - the whole
        // point of the pass.
        assert_eq!(tv.lag_median_secs, 86_400);
        // Nothing left to improve: the named row is settled, the
        // subject_stem row is out of scope.
        assert_eq!(ix.scoreboard_recheck(T - 1, 0, 100).unwrap().0, 0);
        teardown(&d, ix);
    }

    /// Storing is idempotent per (source, guid), a calibration re-store
    /// corrects the verdict in place, and the aggregates count what the
    /// rows say.
    #[test]
    fn store_upserts_and_stats_aggregate() {
        let d = dir("store");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let sample = |guid: &str, cat: &str, verdict: &str, key: &str, lag: i64| ScoreboardSample {
            source: "ref.example".into(),
            category: cat.into(),
            ref_guid: guid.into(),
            ref_name: format!("Name.{guid}"),
            ref_size: 1,
            ref_posted: T,
            ref_group: String::new(),
            verdict: verdict.into(),
            matched_release_id: 0,
            key_used: key.into(),
            lag_secs: lag,
        };
        let n = ix
            .scoreboard_store(
                &[
                    sample("g1", "tv", "have_named", "stem", 100),
                    sample("g2", "tv", "have_unnamed", "band", 900),
                    sample("g3", "tv", "missing", "", 0),
                    sample("g4", "movies", "missing", "", 0),
                ],
                T,
            )
            .unwrap();
        assert_eq!(n, 4);
        // The calibration pass re-answers g2 exactly.
        ix.scoreboard_store(&[sample("g2", "tv", "have_named", "subject_stem", 900)], T)
            .unwrap();
        let stats = ix.scoreboard_stats(T - 1).unwrap();
        assert_eq!(stats.len(), 2);
        let tv = stats.iter().find(|c| c.category == "tv").unwrap();
        assert_eq!(
            (tv.total, tv.have_named, tv.have_unnamed, tv.missing),
            (3, 2, 0, 1)
        );
        assert_eq!(tv.lag_median_secs, 900);
        let movies = stats.iter().find(|c| c.category == "movies").unwrap();
        assert_eq!((movies.total, movies.missing), (1, 1));
        // A window that excludes everything aggregates to nothing.
        assert!(ix.scoreboard_stats(T + 1).unwrap().is_empty());
        // Calibration candidates: only non-exact keys qualify.
        let cal = ix.scoreboard_calibratable(T - 1, 10).unwrap();
        assert_eq!(cal.len(), 2, "g3+g4 (g1 stem, g2 now subject_stem)");

        // A slow category re-serves the same guid tomorrow. The
        // re-sample answers WORSE (the release aged out of retention):
        // the stored hit must stand - eviction is policy, not a
        // coverage hole.
        ix.scoreboard_store(&[sample("g1", "tv", "missing", "", 0)], T + 86_400)
            .unwrap();
        // And the calibration truth on g2 must survive a cheaper key's
        // re-answer, upgrade or not.
        ix.scoreboard_store(
            &[sample("g2", "tv", "have_unnamed", "band", 50)],
            T + 86_400,
        )
        .unwrap();
        let verdicts: Vec<(String, String)> = {
            let mut q = ix
                .db
                .prepare("SELECT verdict, key_used FROM scoreboard_samples WHERE ref_guid IN ('g1','g2') ORDER BY ref_guid")
                .unwrap();
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(
            verdicts,
            vec![
                ("have_named".to_string(), "stem".to_string()),
                ("have_named".to_string(), "subject_stem".to_string()),
            ],
            "no downgrade, no truth overwrite"
        );
        // Calibration may RESTATE a verdict it merely confirms - the
        // subject_stem stamp is what retires the row from the daily
        // grab-quota pool.
        ix.scoreboard_store(
            &[sample("g3", "tv", "missing", "subject_stem", 0)],
            T + 86_400,
        )
        .unwrap();
        let g3key: String = ix
            .db
            .query_row(
                "SELECT key_used FROM scoreboard_samples WHERE ref_guid='g3'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(g3key, "subject_stem");
        teardown(&d, ix);
    }
}
