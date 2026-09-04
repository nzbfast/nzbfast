//! The anchorless session fold (family S of
//! research/REDDIT-INDEXER-GROUPING-CLAIM-2026-08-31.md section 2, built
//! to the shape research/INDEXER-NAMING-PROTOTYPE-2026-08-31.md measured
//! and research/INDEXER-NAMING-CEILING-2026-09-01.md ranked): a dark
//! upload session posts N complete single files under N random stems
//! from ONE stable per-session poster handle, so each file groups fine
//! at the article level and nothing above it knows the N files are one
//! release. This pass folds them.
//!
//! The inverse of `shatter_fold`, which merges one file's rows across
//! rotated posters: here the poster is the STABLE half and the stem is
//! the rotated half. `session.rs` links the same shape read-only around
//! a NAMED anchor for the wall sheet; an all-dark session has no anchor,
//! which is why this is a fold and not a sibling query.
//!
//! What makes it safe to merge rather than merely suggest is the
//! self-validating proof the commissioning memo named: a candidate
//! session claims N files of P parts each at one volume size, and every
//! member's stored segment list must cover 1..P exactly once. Measured
//! on the frozen 3 Aug index: 845 raw (poster, grp) groups pass the
//! cheap screens' floor, 289 pass screens AND proof, folding 26,257
//! rows into 1.9 TB of real releases - and zero groups passed the
//! screens while failing the proof, so the proof is a guarantee being
//! double-checked, not a filter doing daily work.
//!
//! Folding is the precondition for naming, not naming itself: the
//! folded release has a true total size and a real file count, which is
//! what `corr_score` needs (a sizeless row caps at SIZELESS_MAX 58,
//! below STRONG 80, and a per-file size against a whole-release pre is
//! vetoed on ratio before it is scored). The fold writes no name and no
//! claim; the correlation walk picks the folded row up like any other,
//! suggest-only - and whether those suggestions are worth showing on
//! this band is a measured open question, not an assumption
//! (research/NAMECORR-PRECISION-2026-09-01.md: the PROTOTYPE's scorer
//! measured 0% precision on ground truth; the folds themselves stand).
//! The value that does not depend on any of that: a folded session is
//! one downloadable release that names itself from the inside on
//! completion, instead of N junk rows that never could.
//!
//! The walk is over POSTING TIME, not id - unlike every sibling fold,
//! and measured rather than preferred: sessions are at most an hour of
//! `first_posted` by definition, while their id spread is whatever else
//! the scan interleaved (on the frozen index, 120 of the 289 proven
//! sessions span more than 10,000 ids and the widest spans 299,824, so
//! an id-substride walk would have split 40% of them). Time windows
//! ride `idx_rel_posted`, and overlapping them by MAX_SPAN gives a
//! containment guarantee: a session straddling one window's end lies
//! whole inside the next, because its own span cannot exceed the
//! overlap.
//!
//! Stated limits. A member the scan backfills LATER with a
//! `first_posted` behind the parked cursor is not revisited - the same
//! park-at-the-top trade `shatter_fold` documents. And a session whose
//! early half already clears every screen on its own can fold before
//! its late half is seen, leaving two releases where one was posted -
//! under-merging, never garbage-union; the SETTLE margin below keeps
//! the ordinary cause of that (folding mid-ingest) out.

use super::*;

/// Fewer files than this is not a session, it is a coincidence: the
/// frozen-index measurement folded nothing real below it, and the
/// screens' power comes from repetition (one poster, N same-size
/// files) that 2-3 files cannot demonstrate.
const MIN_FILES: usize = 4;

/// Widest posting span a session may cover. The measured sessions run
/// 73 s to 3,426 s first-to-last; an hour holds them all with room,
/// and a (poster, grp) pair active for LONGER than this is a stable
/// handle - a different animal from a per-session identity.
const MAX_SPAN: i64 = 3_600;

/// Volume-size uniformity: (max - min) <= max * 2%. Every measured
/// session's volumes agree within 0.1 MB on ~hundreds of MB; 2% is
/// generous and still rejected 520 of the 845 raw groups.
const SIZE_TOL_PCT: i64 = 2;

/// Ceiling on members read per group. The measured sessions are ~100
/// files; a "session" past this is either a stable handle or an
/// adversarial shape, and both are skipped rather than half-read.
const MEMBER_CAP: usize = 2_000;

/// One member of a candidate session, as the window query reads it.
struct SessMember {
    id: i64,
    first_posted: i64,
    first_seen: i64,
    total_bytes: i64,
    need_parts: i64,
    has_par2: bool,
}

impl Index {
    /// One budgeted slice of the session fold: merge each proven dark
    /// upload session (N complete single-file rows, one poster, one
    /// group, uniform size and parts, 1..P cover per file) into its
    /// lowest-id member as one N-file release with a true total size.
    /// Returns (sessions folded, rows folded away, caught up).
    pub fn session_fold(
        &mut self,
        now: i64,
        budget: std::time::Duration,
    ) -> rusqlite::Result<(usize, usize, bool)> {
        /// One walk window. Longer than 2 x MAX_SPAN, which is what
        /// makes the straddle argument in the module header true.
        const WINDOW: i64 = 4 * 3_600;
        /// How far behind the wall clock the walk stays. A session the
        /// scan is STILL INGESTING has rows in the table and more
        /// coming; folding its early half now would split it for good.
        const SETTLE: i64 = 2 * 3_600;
        let started = std::time::Instant::now();
        let deadline = started + budget;
        let horizon = now.saturating_sub(SETTLE);
        let mut cursor: i64 = match self.kv_get("session_fold_at").and_then(|v| v.parse().ok()) {
            Some(v) => v,
            // First run: start at the earliest posting on record (an
            // O(1) probe of `idx_rel_posted`), not at zero - stepping
            // window-by-window up from the epoch would spend the first
            // hundred calls' budgets crossing fifty empty years.
            None => self.db.query_row(
                "SELECT COALESCE(MIN(first_posted), ?1) FROM releases WHERE first_posted>0",
                [horizon],
                |r| r.get(0),
            )?,
        };
        let (mut sessions, mut folded) = (0usize, 0usize);
        let mut caught_up = false;
        // The closure shape is `shatter_fold`'s, for its reason: each
        // session commits its own transaction, so work done before a
        // mid-pass error is real and the tally flush below must see it.
        let run: rusqlite::Result<()> = (|| {
            loop {
                if cursor.saturating_add(WINDOW) > horizon {
                    // The remaining span is still inside the settle
                    // margin; it folds once time has passed it.
                    caught_up = true;
                    break;
                }
                let hi = cursor + WINDOW;
                let (s, n, seen, complete) = self.session_fold_window(cursor, hi, now, deadline)?;
                sessions += s;
                folded += n;
                if !complete {
                    // Deadline hit mid-window. Park the cursor at the
                    // window START: folded sessions rescan to nothing
                    // (their members are gone and the kept row now has
                    // files>1), so revisiting is idempotent, while
                    // advancing would orphan the remainder.
                    break;
                }
                // Overlap the next window by MAX_SPAN so a straddling
                // session is seen whole; an EMPTY window has nothing to
                // straddle, so it advances whole - which is what keeps
                // a sparse or fresh index from costing 1,600 tiny steps
                // per lap.
                cursor = if seen == 0 { hi } else { hi - MAX_SPAN };
                self.kv_set("session_fold_at", &cursor.to_string())?;
                if started.elapsed() >= budget {
                    break;
                }
            }
            Ok(())
        })();
        if folded > 0 {
            for (key, add) in [
                ("session_fold_rows", folded),
                ("session_fold_sessions", sessions),
            ] {
                let cur: u64 = self.kv_get(key).and_then(|v| v.parse().ok()).unwrap_or(0);
                self.kv_set(key, &(cur + add as u64).to_string())?;
            }
        }
        run?;
        if caught_up {
            // The cursor is NOT advanced here, and that is the whole
            // point of catching up: the span [cursor, horizon) was
            // never scanned - the loop broke before its SELECT - so
            // parking on it would jump the walk over every session
            // posted in it, permanently, since a ~18 min maintenance
            // lap re-satisfies `cursor + WINDOW > horizon` every time.
            // The cursor moves only at the in-loop park above, after a
            // window has actually been read.
            // Re-open the correlation walk over what this call folded.
            // Deliberately WIDER than `shatter_fold`'s once-per-lifetime
            // bump: that fold's quarry is a standing backlog, this one's
            // arrives a few sessions a day forever, and a folded row
            // keeps its old id - BELOW the parked backlog cursor - so
            // without the bump the true size this fold exists to
            // produce would never be scored.
            if folded > 0 || self.kv_get("session_fold_lap_v1").is_none() {
                self.kv_set("session_fold_lap_v1", "1")?;
                let g: u64 = self
                    .kv_get("predb_seed_gen")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                self.kv_set("predb_seed_gen", &(g + 1).to_string())?;
            }
        }
        Ok((sessions, folded, caught_up))
    }

    /// Collect one posting-time window's candidate sessions, screen
    /// them, and fold the survivors. Returns (sessions, rows folded,
    /// population rows seen, complete); complete is false only when
    /// the deadline passed mid-window.
    fn session_fold_window(
        &mut self,
        lo: i64,
        hi: i64,
        now: i64,
        deadline: std::time::Instant,
    ) -> rusqlite::Result<(usize, usize, usize, bool)> {
        // The population is the commissioning memo's: dark, individually
        // COMPLETE single files claiming more than one part. A poster
        // key of "" groups nothing. Rides `idx_rel_posted`.
        let mut groups: std::collections::HashMap<(String, String), Vec<SessMember>> =
            Default::default();
        let mut seen = 0usize;
        {
            let mut stmt = self.db.prepare_cached(
                "SELECT id, poster, grp, first_posted, first_seen,
                        total_bytes, need_parts, has_par2
                   FROM releases
                  WHERE first_posted>=?1 AND first_posted<?2
                    AND junk>=70 AND pre_title=''
                    AND complete=1 AND files=1 AND need_parts>1
                    AND poster<>''",
            )?;
            let rows = stmt.query_map([lo, hi], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    SessMember {
                        id: r.get(0)?,
                        first_posted: r.get(3)?,
                        first_seen: r.get(4)?,
                        total_bytes: r.get(5)?,
                        need_parts: r.get(6)?,
                        has_par2: r.get(7)?,
                    },
                ))
            })?;
            for row in rows {
                let (poster, grp, m) = row?;
                seen += 1;
                groups.entry((poster, grp)).or_default().push(m);
            }
        }
        let (mut sessions, mut folded) = (0usize, 0usize);
        // Deterministic order under replay: by lowest member id.
        let mut cands: Vec<Vec<SessMember>> = groups
            .into_values()
            .filter(|v| (MIN_FILES..=MEMBER_CAP).contains(&v.len()))
            .collect();
        cands.sort_by_key(|v| v.iter().map(|m| m.id).min().unwrap_or(0));
        for members in cands {
            let fp_min = members.iter().map(|m| m.first_posted).min().unwrap_or(0);
            let fp_max = members.iter().map(|m| m.first_posted).max().unwrap_or(0);
            // A session STARTING inside the window's final MAX_SPAN
            // strip may extend past `hi`, and folding the visible half
            // now would split it for good. Defer it: the next window
            // begins at `hi - MAX_SPAN`, so a deferred session is seen
            // whole there. This start-strip rule, with the matching
            // cursor overlap in the caller, is what makes "every
            // session is folded exactly once, whole" an invariant
            // rather than a hope.
            if fp_min >= hi - MAX_SPAN {
                continue;
            }
            if fp_max - fp_min > MAX_SPAN {
                continue;
            }
            let szmax = members.iter().map(|m| m.total_bytes).max().unwrap_or(0);
            let szmin = members.iter().map(|m| m.total_bytes).min().unwrap_or(0);
            if szmin <= 0 || (szmax - szmin) * 100 > szmax * SIZE_TOL_PCT {
                continue;
            }
            let need = members[0].need_parts;
            if members.iter().any(|m| m.need_parts != need) {
                continue;
            }
            let n = self.session_fold_members(&members, need, now)?;
            if n > 0 {
                sessions += 1;
                folded += n;
            }
            if std::time::Instant::now() >= deadline {
                return Ok((sessions, folded, seen, false));
            }
        }
        Ok((sessions, folded, seen, true))
    }

    /// The proof and the merge for one screened candidate session.
    /// Returns rows folded away (0 = a gate refused it).
    fn session_fold_members(
        &mut self,
        members: &[SessMember],
        need: i64,
        now: i64,
    ) -> rusqlite::Result<usize> {
        let Ok(need_u32) = u32::try_from(need) else {
            return Ok(0);
        };
        // THE PROOF: every member's one stored file must cover parts
        // 1..P exactly once, under its own claimed total. `complete=1`
        // already promises nsegs >= total_parts; this is stricter -
        // exact cover, no duplicates, no out-of-range part - and it is
        // what licenses a MERGE where a heuristic could only suggest.
        // Filenames must also be distinct, since they move under one
        // release_id below.
        let mut fnames: std::collections::HashSet<String> = Default::default();
        let mut exe = 0i64;
        {
            let mut stmt = self.db.prepare_cached(
                "SELECT filename, total_parts, segments FROM files WHERE release_id=?1",
            )?;
            for m in members {
                let rows: Vec<(String, i64, SegList)> = stmt
                    .query_map([m.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                let [(fname, total_parts, segs)] = rows.as_slice() else {
                    return Ok(0);
                };
                if *total_parts != need || !fnames.insert(fname.clone()) {
                    return Ok(0);
                }
                let mut parts: Vec<u32> = segs.0.iter().map(|s| s.0).collect();
                parts.sort_unstable();
                if parts.len() != need_u32 as usize
                    || parts
                        .iter()
                        .zip(1..=need_u32)
                        .any(|(have, want)| *have != want)
                {
                    return Ok(0);
                }
                exe += i64::from(super::aggregates::is_exe_file(fname));
            }
        }
        let keep = members.iter().map(|m| m.id).min().unwrap_or(0);
        let list = members
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != keep)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let n = members.len();
        let bytes: i64 = members.iter().map(|m| m.total_bytes).sum();
        let fp = members.iter().map(|m| m.first_posted).min().unwrap_or(0);
        let fs = members.iter().map(|m| m.first_seen).min().unwrap_or(now);
        let has_par2 = members.iter().any(|m| m.has_par2);
        let tx = self.db.unchecked_transaction()?;
        // Merge the pesto/session markers BEFORE the source rows die,
        // aggregate MIN/MAX ignoring NULLs - `shatter_fold`'s rule.
        #[expect(clippy::type_complexity)]
        let (pmin, pmax, pck, sidx, stot): (
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
        ) = tx.query_row(
            &format!(
                "SELECT MIN(pesto_ctr_min), MAX(pesto_ctr_max), MIN(pesto_clock),
                        MAX(sess_idx), MAX(sess_total)
                   FROM releases WHERE id IN ({list}) OR id=?1"
            ),
            [keep],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        // Unlike the shatter fold, members hold DISTINCT files (the
        // fold key checked them distinct above), so the files rows are
        // repointed whole, not unioned.
        tx.execute(
            &format!("UPDATE files SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        // Stale per-file audit rows: every member was scored (if at
        // all) as one volume against whole-release pres, which is the
        // ratio-veto shape; the folded release starts clean.
        tx.execute(
            &format!("DELETE FROM pre_corr WHERE release_id IN ({list}) OR release_id=?1"),
            [keep],
        )?;
        // Message-id keys move WITH the articles, as in every fold.
        tx.execute(
            &format!("UPDATE OR IGNORE msgid_map SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        tx.execute(&format!("DELETE FROM releases WHERE id IN ({list})"), [])?;
        let (stem, grp): (String, String) =
            tx.query_row("SELECT stem, grp FROM releases WHERE id=?1", [keep], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        // Classified the way INGEST classifies, recoveries included -
        // the rule every pass that rewrites kind/title_key/junk owes,
        // and this one rewrites junk. `album_fold_merge` is where it
        // was found live, and its comment is the reference. The members
        // carry no fed name (`pre_title=''` is a screen), so ingest
        // scored this same stem through these same two calls, and a
        // bare classify here would score the row's junk against a kind
        // its own `kind` column does not hold.
        //
        // Measured before adding them, so nobody reads them as a fix
        // for something that was showing: on THIS population they are
        // inert. `recover_media_kind` returns at once when the fed name
        // and the stem are one string, and the junk>=70 screen admits
        // only rows whose score came from `Kind::Other` (which
        // `recover_kind_from_group` refuses on purpose), from an
        // obfuscation 70, or from an .exe 85 - and both of those
        // dominate every kind branch of `junk_score`, so no recovered
        // lane here can move the number. One week of this population on
        // the live 65.8M-row index: 12,534 `other` and 548 `movie`,
        // zero music or book, and not one of the 548 in a group
        // `group_media_kind` vouches for. They stay because the rule
        // then holds by construction rather than by an arithmetic
        // accident three modules away.
        let mut p = crate::categories::classify(&stem, &self.custom);
        crate::release::recover_media_kind(&mut p, &stem, &stem);
        crate::release::recover_kind_from_group(&mut p, &grp, &stem);
        // The video-group twin, with the gate ingest asks it behind:
        // the blob test has to be taken BEFORE the pass, because the
        // season this rule records would otherwise make that test more
        // lenient than it was. Inert on this population for a second
        // reason of its own - the screen is `junk>=70`, and the gate
        // below is the same `stem_obfuscated` that puts most of the
        // band there.
        if !stem_obfuscated(&stem, &p) {
            crate::release::recover_episode_from_group(&mut p, &grp, &stem);
        }
        tx.execute(
            "UPDATE releases
                SET total_bytes=?2, files=?3, complete=1, has_par2=?4,
                    first_posted=?5, first_seen=?6,
                    have_parts=?7, need_parts=?7,
                    junk=?8,
                    pesto_ctr_min=?9, pesto_ctr_max=?10, pesto_clock=?11,
                    sess_idx=?12, sess_total=?13,
                    nfiles_complete=?3, nfiles_exe=?14
              WHERE id=?1",
            rusqlite::params![
                keep,
                bytes,
                n as i64,
                has_par2,
                fp,
                fs,
                // Every member proved an exact 1..P cover, so held and
                // needed are the same number: N files times P parts.
                need * n as i64,
                junk_score(&stem, &p, bytes as u64, exe > 0),
                pmin,
                pmax,
                pck,
                sidx,
                stot,
                exe,
            ],
        )?;
        // The kept stem is unchanged, so rel_fts needs no manual write;
        // the row deletions are covered by rel_fts_ad.
        tx.commit()?;
        Ok(n - 1)
    }
}
