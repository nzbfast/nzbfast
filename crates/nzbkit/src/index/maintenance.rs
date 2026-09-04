//! Database maintenance (TODO 106 phase 2.2, cut 5): pruning, split-part
//! merging, PAR2 sidecar folding, NZB synthesis, compaction/optimize and
//! the size accounting. Bodies are verbatim moves from the old index.rs.

use super::*;

/// One member row of a split-container set, as `split_merge_group`
/// reads it.
struct SplitMember {
    id: i64,
    stem: String,
    has_par2: bool,
    first_posted: i64,
    first_seen: i64,
    pre_named: bool,
}

/// One member row of a shattered posting, as `shatter_fold_group`
/// reads it.
#[derive(Clone)]
struct ShatterMember {
    id: i64,
    has_par2: bool,
    first_posted: i64,
    first_seen: i64,
    need_parts: i64,
    /// The newsgroup, carried for the classify recoveries at the fold's
    /// UPDATE. The fold unions members across GROUPS on purpose (this
    /// family rotates the group per article), so there is no single
    /// group for the set - the kept row's is the right one, because it
    /// is the group ingest classified that row under.
    grp: String,
}

/// Escape for XML - and DROP what XML 1.0 cannot carry at all.
///
/// The emitted NZB's `poster=` is the raw OVER `From:` header and
/// `subject=`/filename come from the article, so a single C0 control byte
/// makes `/getnzb/<id>.nzb` unparseable to whatever consumes it -
/// SABnzbd/expat, NZBGet/libxml2, any XML tooling. Escaping cannot help:
/// `&#1;` is illegal too, and emitting one breaks our own quick-xml
/// reader. See the twin `esc_xml` in nzbfast's sabcompat.rs.
fn xml_escape(s: &str) -> String {
    let clean: String = s
        .chars()
        .filter(|&c| {
            matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{FFFE}' && c != '\u{FFFF}')
        })
        .collect();
    clean
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ===== M32: user-chosen index size cap, with automatic eviction =====

/// §95: how this database can reclaim its freed pages. The difference
/// the caller cares about is not speed, it is whether standing down for
/// a download is prompt: a `Chunked` compaction stops between chunks and
/// keeps what it has already reclaimed, a `FullRewrite` can only be
/// asked to stop and may well refuse (see `Index::interrupt_handle`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactStyle {
    /// Incremental auto-vacuum is on: `compact_chunk` in a loop.
    Chunked,
    /// Still in SQLite's default mode, so the only way to reclaim - and
    /// the only way to reach `Chunked` - is one full `compact()`.
    FullRewrite,
}

impl Index {
    /// Remember what a set of PAR2 member fingerprints was called, so a
    /// later repost of the same bytes under an obfuscated name can be
    /// told. `pairs` is `(hash16k hex, member name)` from
    /// [`Par2Set::member_hash16k`](crate::par2::Par2Set::member_hash16k);
    /// the member names are not stored (they are volume names, not
    /// identities) - `name` is the release the whole set belongs to.
    /// `evidence` is what PROVED that name against these bytes.
    ///
    /// This is the only naming tier in the product with MEMORY, and it
    /// used to be the only one that never declined anything. It was
    /// first-writer-wins forever - whatever named a fingerprint first
    /// owned it, a later job that named the same bytes correctly could
    /// not displace it, and nothing reported the disagreement (W7-01).
    /// Three rules replace that, all of them decided on the §131
    /// evidence ladder rather than on arrival order:
    ///
    /// * **Strictly stronger evidence corrects.** A PAR2-set-id proof
    ///   (`pesto_confirm`, which matched the payload's own bytes
    ///   against the FileDesc) outranks a posted stem, so the wrong
    ///   name a weak lane taught is repaired rather than permanent.
    /// * **Weaker evidence loses, silently.** A subject parse
    ///   disagreeing with a byte-level proof is not news.
    /// * **Equal evidence is AMBIGUITY, and ambiguity is a refusal.**
    ///   The key is `hash16k` - the identical-head twin family
    ///   (zero-filled VOB heads, padded disc images) that `try_match_whole`
    ///   exists for and that every in-job tier declines. Two jobs with
    ///   equally good claims and different names mark the row
    ///   `contested`, and [`Index::par_hash_lookup`] then refuses it
    ///   (W7-03). The row is kept rather than deleted so a later proof
    ///   can still settle it.
    ///
    /// The name must LOOK like a name here as well as at the call site
    /// (W7-02): the guard is on the write rather than left to each
    /// caller, so an obfuscated stem can neither be filed - which would
    /// hand every future repost the same non-answer - nor CONTEST a
    /// good name it has no standing to argue with.
    ///
    /// Returns how many rows this call wrote (inserted, corrected, or
    /// marked contested).
    pub fn par_hash_remember(
        &self,
        pairs: &[(String, String)],
        name: &str,
        title_key: &str,
        now: i64,
        evidence: NameEvidence,
    ) -> rusqlite::Result<usize> {
        let name = name.trim();
        if name.is_empty() || !crate::release::stem_is_a_name(name) {
            return Ok(0);
        }
        let mut read = self
            .db
            .prepare_cached("SELECT name, tier, contested FROM par_hashes WHERE hash16k = ?1")?;
        let mut ins = self.db.prepare_cached(
            "INSERT INTO par_hashes(hash16k, name, title_key, at, tier, contested)
             VALUES(?1, ?2, ?3, ?4, ?5, 0)
             ON CONFLICT(hash16k) DO NOTHING",
        )?;
        let mut replace = self.db.prepare_cached(
            "UPDATE par_hashes SET name=?2, title_key=?3, at=?4, tier=?5, contested=0
             WHERE hash16k=?1",
        )?;
        let mut upgrade = self
            .db
            .prepare_cached("UPDATE par_hashes SET tier=?2, contested=0 WHERE hash16k=?1")?;
        let mut contest = self
            .db
            .prepare_cached("UPDATE par_hashes SET contested=1 WHERE hash16k=?1")?;
        let mut n = 0;
        for (hash, _member) in pairs {
            let held: Option<(String, String, i64)> = read
                .query_row([hash], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()?;
            let Some((held_name, held_tier, contested)) = held else {
                n += ins.execute(rusqlite::params![
                    hash,
                    name,
                    title_key,
                    now,
                    evidence.tag()
                ])?;
                continue;
            };
            // An unreadable tag is treated as the weakest thing on the
            // ladder rather than as a reason to refuse: the tags are
            // append-only by contract, so this is a row from a future
            // version read by an older binary, and letting a proof
            // correct it is the safer of the two mistakes.
            let held_rank = NameEvidence::parse(&held_tier)
                .unwrap_or(NameEvidence::Adjacency)
                .rank();
            if held_name == name {
                // The same answer again. Only a STRICTLY STRONGER
                // proof of it changes anything: it upgrades the row's
                // tier - so the next weak disagreement loses instead
                // of contesting - and settles any contest, because
                // the contest was between this name and some other
                // one and this side just won on evidence.
                //
                // Re-teaching at the SAME tier deliberately does not,
                // which is the whole point of contesting on evidence
                // rather than on arrival: a twin that happens to be
                // downloaded twice would otherwise clear an ambiguity
                // it never resolved, and the more-frequent poster
                // would win - first-writer-wins wearing a different
                // hat.
                if evidence.rank() > held_rank {
                    n += upgrade.execute(rusqlite::params![hash, evidence.tag()])?;
                }
            } else if evidence.rank() > held_rank {
                n += replace.execute(rusqlite::params![
                    hash,
                    name,
                    title_key,
                    now,
                    evidence.tag()
                ])?;
            } else if evidence.rank() == held_rank && contested == 0 {
                // SAY SO. This is the moment the product learns that
                // two releases share a 16 KiB head, which is a fact
                // about the CORPUS and not about this job - the twin
                // family the whole matcher ladder is built around -
                // and without this line the discovery is one bit
                // written to a table that nothing anywhere reports.
                // The sibling decline in `par_hash_lookup` already
                // speaks; the contest that CAUSES it did not.
                //
                // `warn!` rather than `info!` precisely because nobody
                // has measured how often this fires. If a mature index
                // turns out to contest routinely then these lines ARE
                // that measurement, and the level is the thing to
                // revisit - not the reporting.
                warn!(
                    target: "identity",
                    "repost table: {hash} is claimed by both {held_name:?} and {name:?} \
                     at the same evidence tier ({}) - refusing it until a proof settles it",
                    evidence.tag()
                );
                n += contest.execute([hash])?;
            }
        }
        Ok(n)
    }

    /// What we last called a release carrying any of these member
    /// fingerprints. Returns `(hash16k, name, title_key)` for the hash
    /// that proved it, or `None` when the set does not have one answer.
    ///
    /// Two ways it declines, and both are the same rule every in-job
    /// naming tier already follows - ambiguity is a refusal, not a
    /// guess. A row two equally-evidenced jobs named differently is
    /// `contested` and is skipped outright. And the members are ALL
    /// consulted rather than the first hit being taken: the old
    /// reasoning was that "a set's volumes all belong to one release,
    /// so one hit answers for the set", which is true of an honest set
    /// and false the moment one member's 16 KiB head collides with
    /// another release's - so members that answer two different names
    /// answer nothing (W7-03).
    ///
    /// When they agree, the STRONGEST-evidenced hit is returned: the
    /// hash comes back with the name because it is the proving key the
    /// §131 claims layer records beside the answer, and it should be
    /// the best-proved one on offer.
    pub fn par_hash_lookup(
        &self,
        pairs: &[(String, String)],
    ) -> rusqlite::Result<Option<(String, String, String)>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT name, title_key, tier FROM par_hashes WHERE hash16k = ?1 AND contested = 0",
        )?;
        let mut best: Option<(i32, (String, String, String))> = None;
        for (hash, _member) in pairs {
            let hit: Option<(String, String, String)> = stmt
                .query_row([hash], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()?;
            let Some((name, title_key, tier)) = hit else {
                continue;
            };
            if let Some((_, (_, held, _))) = &best
                && *held != name
            {
                // One set, two releases. Nothing here is an answer -
                // and it is worth saying, because a fingerprint two
                // releases share is a fact about the CORPUS that no
                // other surface reports.
                warn!(
                    target: "identity",
                    "repost table: one set names two releases ({held:?} and {name:?}) - declining"
                );
                return Ok(None);
            }
            let rank = NameEvidence::parse(&tier)
                .unwrap_or(NameEvidence::Adjacency)
                .rank();
            if best.as_ref().is_none_or(|(r, _)| rank > *r) {
                best = Some((rank, (hash.clone(), name, title_key)));
            }
        }
        Ok(best.map(|(_, hit)| hit))
    }

    /// One release's name, by id. `None` when there is no such row.
    /// Grabbing from the wall needs exactly this and nothing else: the
    /// stem becomes the job name, and through it the output directory,
    /// the spool file, the history label and the duplicate key.
    /// The name a release is KNOWN by - the pre feed's title when it
    /// supplied one, the posted stem otherwise. This is what names the
    /// job a grab creates, and the job name is what the duplicate hold,
    /// the watchlist's history check and the wall's "have" badge all key
    /// on, so a rescued release grabbed under its obfuscated stem would
    /// be invisible to every one of them.
    pub fn stem_by_id(&self, release_id: i64) -> rusqlite::Result<Option<String>> {
        self.db
            .query_row(
                "SELECT COALESCE(NULLIF(pre_title,''), stem) FROM releases WHERE id=?1",
                [release_id],
                |r| r.get(0),
            )
            .optional()
    }

    /// Synthesize an NZB for a release.
    pub fn make_nzb(&self, release_id: i64) -> rusqlite::Result<String> {
        let (grp, poster, posted): (String, String, i64) = self.db.query_row(
            "SELECT grp, poster, first_posted FROM releases WHERE id=?1",
            [release_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let mut stmt = self
            .db
            .prepare("SELECT filename, total_parts, segments FROM files WHERE release_id=?1 ORDER BY filename")?;
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        let rows = stmt.query_map([release_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, SegList>(2)?.0,
            ))
        })?;
        for row in rows {
            let (fname, total, segs) = row?;
            // date carries the release's real post time: the pool's
            // retention routing and the availability ledger's age
            // buckets both key off it (date="0" recorded every
            // index-grab as a 0-day-old post).
            xml.push_str(&format!(
                "  <file poster=\"{}\" date=\"{posted}\" subject=\"{}\">\n    <groups><group>{}</group></groups>\n    <segments>\n",
                // The stored poster may carry promote_spot's generation
                // discriminator (it lives in `poster` because the
                // UNIQUE is a table constraint); the NZB gets the real
                // From.
                xml_escape(spots::base_poster(&poster)),
                xml_escape(&format!("\"{fname}\" yEnc (1/{total})")),
                xml_escape(&grp)
            ));
            for (num, msgid, bytes) in segs {
                xml.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{}</segment>\n",
                    xml_escape(msgid.trim_matches(['<', '>']))
                ));
            }
            xml.push_str("    </segments>\n  </file>\n");
        }
        xml.push_str("</nzb>\n");
        Ok(xml)
    }

    /// Delete releases outside [min,max] total bytes (0 = unbounded).
    /// Oversize releases can only grow, so they go immediately; undersize
    /// ones are pruned once FULLY PRESENT (every seen file has all its
    /// parts - the upload finished and it's still tiny, which is exactly
    /// what indexer spam looks like: one 1 MB .m3u/.nfo posted solo).
    /// A release still missing parts may be mid-upload, so it stays.
    /// Rare boundary miss: a release straddling two scan runs with only
    /// its smallest file landed can lose that file's rows - the next
    /// scan re-adds the rest, so the cost is one sibling file, not the
    /// release. Returns rows removed.
    pub fn prune_size(&self, min: u64, max: u64) -> rusqlite::Result<usize> {
        // Set once an orphan sweep has completed on this index under the
        // current (transactional) shape - see the gate below.
        const ORPHAN_SWEEP_STAMP: &str = "orphan_sweep_done_v1";
        // One transaction: releases.id has no AUTOINCREMENT, so SQLite
        // reuses max(rowid)+1 - exactly the just-pruned oversize ids. As
        // separate autocommit statements, a crash (or the n>0 gate)
        // between delete and sweep left orphan files rows that the next
        // ingest's recycled id ADOPTED: wrong counts/complete flag, and
        // make_nzb synthesized an NZB from another release's segments.
        let tx = self.db.unchecked_transaction()?;
        let mut n = 0;
        if max > 0 {
            n += tx.execute("DELETE FROM releases WHERE total_bytes > ?1", [max as i64])?;
        }
        if min > 0 {
            n += tx.execute(
                "DELETE FROM releases WHERE total_bytes < ?1 AND NOT EXISTS (
                     SELECT 1 FROM files WHERE release_id = releases.id
                     AND (CASE WHEN nsegs > 0 THEN nsegs
                               ELSE seg_count(segments) END) < total_parts)",
                [min as i64],
            )?;
        }
        // The sweep below is two anti-joins, and the `files` half reads
        // every row of the biggest table in the index (through
        // UNIQUE(release_id,filename), so an index walk rather than a
        // table scan - still O(files)). It runs on the WRITER
        // connection once per gated group scan, where the prune usually
        // matches nothing, so gate it: sweep when this call deleted
        // something, or when the stamp says no sweep has yet completed
        // on this index.
        //
        // That stamp is the crash recovery, not a substitute for it. It
        // is written inside this same transaction as the sweep, so the
        // only committed states are "swept and stamped" and "neither":
        // a crash or a rollback anywhere in between leaves it absent and
        // the next call sweeps unconditionally. The hazard the
        // unconditional shape guarded needs an orphan to outlive a
        // COMMITTED delete, and no state reachable from here has one
        // without the stamp being missing too. Its absence on an
        // existing index is also what buys the single historical-repair
        // pass, for orphans left behind by the autocommit era described
        // above (and by the n>0 gate that shipped with it).
        let swept_before = tx
            .query_row("SELECT 1 FROM kv WHERE k=?1", [ORPHAN_SWEEP_STAMP], |_| {
                Ok(())
            })
            .optional()?
            .is_some();
        if n == 0 && swept_before {
            tx.commit()?;
            return Ok(0);
        }
        tx.execute(
            "DELETE FROM files WHERE release_id NOT IN (SELECT id FROM releases)",
            [],
        )?;
        // Same recycled-id hazard, one table over: `pre_corr.release_id`
        // IS the primary key, so an orphaned verdict left behind here is
        // adopted whole by whatever release next takes that rowid -
        // handing a brand-new post another release's `applied`/`confirmed`
        // correlation, and with it a wrong name.
        tx.execute(
            "DELETE FROM pre_corr WHERE release_id NOT IN (SELECT id FROM releases)",
            [],
        )?;
        tx.execute(
            "INSERT INTO kv(k, v) VALUES(?1, '1') ON CONFLICT(k) DO NOTHING",
            [ORPHAN_SWEEP_STAMP],
        )?;
        tx.commit()?;
        Ok(n)
    }

    pub fn stats(&self) -> rusqlite::Result<(u64, u64)> {
        let snap = self.db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(complete),0) FROM releases",
            [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )?;
        self.stats_cache
            .set(Some((std::time::Instant::now(), snap)));
        Ok(snap)
    }

    /// [`Self::stats`] through a per-connection TTL memo. The exact
    /// query is a full `SCAN releases` (nothing indexes `complete`),
    /// seconds on a production-sized index - and the scan progress
    /// line used to ask for it every ~100k headers on up to eight
    /// concurrent group connections. A progress line tolerates figures
    /// a TTL old; anything that needs the exact answer calls
    /// [`Self::stats`], which also refreshes this memo for free.
    pub fn stats_cached(&self, ttl: std::time::Duration) -> rusqlite::Result<(u64, u64)> {
        if let Some((at, snap)) = self.stats_cache.get()
            && at.elapsed() < ttl
        {
            return Ok(snap);
        }
        self.stats()
    }

    /// M31a: delete a batch of release ids and their files rows in one
    /// transaction. Files first so no orphan is left if we crash between;
    /// the `rel_fts_ad` trigger keeps FTS in sync on the releases delete.
    /// Returns rows removed from `releases`.
    pub(super) fn prune_batch(&self, ids: &[i64]) -> rusqlite::Result<usize> {
        // Unbudgeted: the size-cap evictor re-measures the file between
        // batches and has to know the batch it asked for actually left.
        let no_budget = std::time::Instant::now() + std::time::Duration::from_secs(86_400);
        Ok(self.prune_batch_until(ids, no_budget).0)
    }

    /// The same delete, bounded in TIME rather than in rows: chunked, with
    /// the clock read between chunks, and the chunk size re-measured each
    /// time so the bound holds whatever a row costs. Returns (rows removed
    /// from `releases`, ids consumed) - `consumed < ids.len()` means the
    /// budget ran out and the tail is untouched, which the reapers' cursors
    /// resume from.
    ///
    /// A row count cannot bound this and never could. Every caller passes a
    /// count picked when a delete was a handful of b-tree writes, but the
    /// cost of one is whatever `releases` currently carries - 14 secondary
    /// indexes, two FTS tables and three trigger statements, on this index,
    /// today - and a single delete statement has no await point, so nothing
    /// preempts it once it starts. That is how 8000 ids became eleven minutes
    /// of held write mutex when one trigger statement lost its index (see
    /// `rel_identity_ad_v3` in schema.rs): the constant was still 8000 and
    /// still looked reasonable. So the loop below measures instead of
    /// assuming, and the next per-row regression costs a slower reap rather
    /// than a wedged daemon.
    pub(super) fn prune_batch_until(
        &self,
        ids: &[i64],
        deadline: std::time::Instant,
    ) -> (usize, usize) {
        // What one chunk should take. Small enough that overshooting the
        // caller's deadline by a whole chunk is not worth noticing, large
        // enough that the per-transaction overhead stays in the noise.
        const CHUNK_TARGET: std::time::Duration = std::time::Duration::from_millis(100);
        // ...and the range the measurement is allowed to steer it over. The
        // floor keeps a pathologically slow row from grinding to one-at-a-
        // time; the ceiling is the row count every caller used to pass.
        const CHUNK_MIN: usize = 64;
        const CHUNK_MAX: usize = 8_000;
        let (mut removed, mut done) = (0usize, 0usize);
        // Start at the floor and let the measurement raise it. The first
        // chunk is the only one whose cost is a guess, so it must be the
        // cheapest thing we are willing to do; one extra transaction is a
        // small price for never guessing large.
        let mut chunk = CHUNK_MIN;
        while done < ids.len() {
            let take = chunk.min(ids.len() - done);
            let started = std::time::Instant::now();
            let Ok(n) = self.prune_chunk(&ids[done..done + take]) else {
                // A busy or interrupted chunk stops the run rather than
                // spinning on it: the ids are still there, and the caller's
                // cursor has not moved past them.
                break;
            };
            removed += n;
            done += take;
            // Re-aim at CHUNK_TARGET from what that chunk actually cost.
            let spent = started.elapsed().max(std::time::Duration::from_micros(1));
            let scaled = (take as f64 * CHUNK_TARGET.as_secs_f64() / spent.as_secs_f64()) as usize;
            chunk = scaled.clamp(CHUNK_MIN, CHUNK_MAX);
            // AFTER the chunk, never before: a caller that arrives already
            // past its deadline still makes progress rather than none.
            if std::time::Instant::now() >= deadline {
                break;
            }
        }
        (removed, done)
    }

    /// One chunk of [`Self::prune_batch_until`], in one transaction.
    fn prune_chunk(&self, ids: &[i64]) -> rusqlite::Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            &format!("DELETE FROM files WHERE release_id IN ({list})"),
            [],
        )?;
        // `pre_corr.release_id` is the primary key, and `releases.id` has
        // no AUTOINCREMENT (see `prune_size`), so a verdict left behind
        // here is inherited by the next release to reuse that rowid.
        tx.execute(
            &format!("DELETE FROM pre_corr WHERE release_id IN ({list})"),
            [],
        )?;
        let n = tx.execute(&format!("DELETE FROM releases WHERE id IN ({list})"), [])?;
        tx.commit()?;
        Ok(n)
    }

    /// Fold the fragments of a split-container set (`x.7z.001` ...)
    /// back into one release. Rows indexed before `release_stem`
    /// learned the split shapes carry one fragment each - which hides
    /// the set's true size from correlation, the wall, retention, all
    /// of it (found live 2 Aug: one obfuscated post as 122 half-GB
    /// rows). One-time and budgeted: an id-stride walk per call, kv
    /// cursor, and when the walk completes it bumps `predb_seed_gen`
    /// once so both correlation walks re-run against the real sizes.
    ///
    /// Scoped to junk>=70: those are the rows whose size is load-
    /// bearing evidence. A readable fragmented set displays fine and
    /// is left alone. Groups where any member already carries a fed
    /// name are skipped whole - identity fights are not this pass's
    /// job. Returns (groups merged, fragment rows folded, walk done).
    /// Bounded per call in TIME as well as id space, same shape as
    /// `par2_sidecar_fold`: the caller holds the shared index write
    /// mutex for the whole call, so the stride goes in sub-strides
    /// with the cursor persisted after each, and the call returns when
    /// `budget` is spent. The next tick resumes from the cursor.
    pub fn split_merge(
        &mut self,
        now: i64,
        budget: std::time::Duration,
    ) -> rusqlite::Result<(usize, usize, bool)> {
        if self.kv_get("split_merge_done_v1").is_some() {
            return Ok((0, 0, true));
        }
        const STRIDE: i64 = 100_000;
        const SUB_STRIDE: i64 = 1_000;
        let started = std::time::Instant::now();
        let mut cursor: i64 = self
            .kv_get("split_merge_cursor")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let top: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
        let call_top = cursor.saturating_add(STRIDE);
        let (mut groups, mut folded) = (0usize, 0usize);
        let mut seen_bases: std::collections::HashSet<(String, String, String)> =
            std::collections::HashSet::new();
        let done = loop {
            let hi = cursor.saturating_add(SUB_STRIDE).min(call_top);
            // Candidate fragments in this sub-stride. The LIKE
            // prefilter keeps the scan cheap; release_stem() is the
            // real test.
            let cands: Vec<(i64, String, String, String)> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT id, stem, poster, grp FROM releases
                      WHERE id>?1 AND id<=?2 AND junk>=70
                        AND (stem LIKE '%.7z.%' OR stem LIKE '%.zip.%')",
                )?;
                stmt.query_map([cursor, hi], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            for (_, stem, poster, grp) in cands {
                let base = crate::names::release_stem(&stem);
                if base == stem {
                    continue; // not a fragment shape after all
                }
                if !seen_bases.insert((base.clone(), poster.clone(), grp.clone())) {
                    continue; // this call already merged the group
                }
                let n = self.split_merge_group(&base, &poster, &grp, now)?;
                if n > 0 {
                    groups += 1;
                    folded += n;
                }
            }
            cursor = hi;
            if hi >= top {
                break true;
            }
            self.kv_set("split_merge_cursor", &cursor.to_string())?;
            if hi >= call_top || started.elapsed() >= budget {
                break false;
            }
        };
        if done {
            self.kv_set("split_merge_done_v1", "1")?;
            self.db
                .execute("DELETE FROM kv WHERE k='split_merge_cursor'", [])?;
            // The whole point: the merged rows now carry true sizes
            // worth re-correlating against.
            let g: u64 = self
                .kv_get("predb_seed_gen")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            self.kv_set("predb_seed_gen", &(g + 1).to_string())?;
        }
        Ok((groups, folded, done))
    }

    /// Merge every fragment of one (base, poster, grp) set into its
    /// lowest-id member (or the row already wearing the base stem).
    /// Returns fragment rows folded away (0 = nothing to do / skipped).
    fn split_merge_group(
        &mut self,
        base: &str,
        poster: &str,
        grp: &str,
        now: i64,
    ) -> rusqlite::Result<usize> {
        // The stem range (base||'.', base||'/') covers every fragment
        // ('.'+digits); the exact base row - already-correct rows from
        // post-fix ingest - joins via the equality arm.
        let members: Vec<SplitMember> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT id, stem, has_par2, first_posted, first_seen, pre_title
                   FROM releases
                  WHERE poster=?1 AND grp=?2
                    AND (stem=?3 OR (stem>=?3||'.' AND stem<?3||'/'))",
            )?;
            stmt.query_map(rusqlite::params![poster, grp, base], |r| {
                Ok(SplitMember {
                    id: r.get(0)?,
                    stem: r.get(1)?,
                    has_par2: r.get(2)?,
                    first_posted: r.get(3)?,
                    first_seen: r.get(4)?,
                    pre_named: !r.get::<_, String>(5)?.is_empty(),
                })
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        // Keep only true fragments of THIS base (plus the base row).
        let members: Vec<SplitMember> = members
            .into_iter()
            .filter(|m| m.stem == base || crate::names::release_stem(&m.stem) == base)
            .collect();
        if members.len() < 2 {
            return Ok(0);
        }
        if members.iter().any(|m| m.pre_named) {
            // Somebody (feed, correlation, a human) already named a
            // member. Merging under it would silently extend that
            // claim to bytes it never covered.
            return Ok(0);
        }
        let keep = members
            .iter()
            .find(|m| m.stem == base)
            .map(|m| m.id)
            .unwrap_or_else(|| members.iter().map(|m| m.id).min().unwrap_or(0));
        let old_stem = members
            .iter()
            .find(|m| m.id == keep)
            .map(|m| m.stem.clone())
            .unwrap_or_default();
        let others: Vec<i64> = members
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != keep)
            .collect();
        let list = others
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let tx = self.db.unchecked_transaction()?;
        // Files move to the kept row; a duplicate filename (the same
        // part posted into two fragments) keeps the kept row's copy.
        tx.execute(
            &format!("UPDATE OR IGNORE files SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        tx.execute(
            &format!("DELETE FROM files WHERE release_id IN ({list})"),
            [],
        )?;
        // Stale audit rows: fragment suggestions die with the
        // fragments, and the kept row's (scored against one fragment's
        // size) is wrong by construction now.
        tx.execute(
            &format!("DELETE FROM pre_corr WHERE release_id IN ({list}) OR release_id=?1"),
            [keep],
        )?;
        // §131 identity substrate: the message-id keys move WITH the
        // files. `rel_identity_ad` drops every source row's `msgid_map`
        // on the delete below, and a fold that skipped this would
        // destroy the strongest naming evidence the index holds - the
        // articles are still in the kept release, so a later posted-NZB
        // or spot lookup must still resolve them (and still reach
        // quorum) rather than miss a release that visibly survived.
        // OR IGNORE: the kept row may already hold the same key.
        tx.execute(
            &format!("UPDATE OR IGNORE msgid_map SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        // The pesto counter range and session fields merge like
        // shatter_fold_members' (whose comment calls the merge
        // load-bearing): pesto_candidates keys on counter-range
        // containment, so a fold that dropped a member's range left the
        // folded set's sidecar unable to find its payload. Read BEFORE
        // the members are deleted.
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
        tx.execute(&format!("DELETE FROM releases WHERE id IN ({list})"), [])?;
        // Parts and completeness from the POST-merge files table (the
        // ingest aggregate's shape), not from member sums: OR IGNORE
        // above drops duplicate filenames, so the pre-merge sums counted
        // the dropped copies' parts and a dropped incomplete duplicate
        // marked a wholly-complete merged row incomplete.
        let agg = super::aggregates::RelAgg::recompute(&tx, keep)?;
        let fp = members
            .iter()
            .map(|m| m.first_posted)
            .filter(|v| *v > 0)
            .min()
            .unwrap_or(0);
        let fs = members.iter().map(|m| m.first_seen).min().unwrap_or(now);
        let has_par2 = members.iter().any(|m| m.has_par2);
        // Classified the way INGEST classifies, recoveries included -
        // the rule every pass that rewrites kind/title_key/junk owes.
        // `album_fold_merge` is where it was found live, on readable
        // album stems, and its comment is the reference. The base IS
        // the stem here, so the recoveries take it twice.
        //
        // Measured before adding them, so nobody reads them as a fix
        // for something that was showing: on THIS pass they are inert.
        // `recover_media_kind` returns at once when the fed name and
        // the stem are one string; `recover_kind_from_group` refuses a
        // stem ending in a plain extension, and `release_stem` keeps
        // the `.7z`/`.zip` a true split set was split from, so this
        // base wears one. What is left is the junk>=70 scoping, where
        // the parse is `Kind::Other` - refused on purpose, a hash must
        // not become an album - or an obfuscation 70 that dominates
        // every kind branch of `junk_score`. One week of this
        // population on the live 65.8M-row index: 1,891 dark rows,
        // 1,835 ending in `.7z`/`.zip`, every one of them `kind=movie`.
        // The video-group recovery below is inert for a reason of its
        // own: it only touches `Kind::Movie`, and a dark row that is
        // not obfuscated - the only kind its gate lets through - got
        // its 70 from `Kind::Other`, which it declines.
        // They stay because the rule then holds by construction rather
        // than by an arithmetic accident three modules away, and that
        // accident is the only thing making it true today.
        let mut p = crate::categories::classify(base, &self.custom);
        crate::release::recover_media_kind(&mut p, base, base);
        crate::release::recover_kind_from_group(&mut p, grp, base);
        // The video-group twin, with the gate ingest asks it behind:
        // the blob test has to be taken BEFORE the pass, because the
        // season this rule records would otherwise make that test more
        // lenient than it was.
        if !stem_obfuscated(base, &p) {
            crate::release::recover_episode_from_group(&mut p, grp, base);
        }
        tx.execute(
            "UPDATE releases
                SET stem=?2, total_bytes=?3, files=?4, complete=?5, has_par2=?6,
                    first_posted=?7, first_seen=?8, have_parts=?9, need_parts=?10,
                    kind=?11, res=?12, title_key=?13, junk=?14, langs=?15,
                    vcodec=?16, acodec=?17, hdr=?18,
                    pesto_ctr_min=?19, pesto_ctr_max=?20, pesto_clock=?21,
                    sess_idx=?22, sess_total=?23,
                    nfiles_complete=?24, nfiles_exe=?25, stem_fold=?26
              WHERE id=?1",
            rusqlite::params![
                keep,
                base,
                agg.tbytes,
                agg.nfiles,
                agg.complete(),
                has_par2,
                fp,
                fs,
                agg.have,
                agg.need,
                kind_str(&p.kind),
                p.res.as_deref().unwrap_or_default(),
                p.key,
                junk_score(base, &p, agg.tbytes.max(0) as u64, agg.nexe > 0),
                p.langs.join(" "),
                p.vcodec.as_deref().unwrap_or_default(),
                p.acodec.as_deref().unwrap_or_default(),
                p.hdr.as_deref().unwrap_or_default(),
                pmin,
                pmax,
                pck,
                sidx,
                stot,
                agg.ncomplete,
                agg.nexe,
                // The stem rewrite carries its fold with it. Leaving
                // this out kept the FRAGMENT's fold on the merged row,
                // so the LIKE arms in query.rs and browse.rs searched a
                // stem the row no longer wears. `fold::stored` is
                // sparse - "" for anything SQLite's own LOWER() would
                // compute identically - and that empty value is exactly
                // what those arms read as "no stored fold here".
                super::fold::stored(base)
            ],
        )?;
        // rel_fts has no UPDATE trigger (external-content over stems),
        // so the stem rewrite maintains it by hand. The fragment
        // deletions above were covered by rel_fts_ad.
        if self.fts && old_stem != base {
            tx.execute(
                "INSERT INTO rel_fts(rel_fts, rowid, stem) VALUES('delete', ?1, ?2)",
                rusqlite::params![keep, old_stem],
            )?;
            tx.execute(
                "INSERT INTO rel_fts(rowid, stem) VALUES(?1, ?2)",
                rusqlite::params![keep, base],
            )?;
        }
        tx.commit()?;
        Ok(others.len())
    }

    /// Fold a split-container set's par2 SIDECAR row into its
    /// container release. The posting habit behind it: the volumes go
    /// up as `x.7z.001`..`x.7z.121` and the recovery set as `x.par2` +
    /// `x.volNN+MM.par2`, so ingest builds TWO rows - the container on
    /// `x.7z` and a par2-only twin on the bare `x`. Measured against
    /// a 30M-row live index, this is the norm, not an edge case:
    /// 9,261 of 10,490 container rows (88%)
    /// have such a twin - 77,977 files, 4,289 GiB of spurious rows.
    /// Folding also closes a scoring leak: with its par2 in a separate
    /// row the container reads `par2_identified=false`, which opens
    /// the 22-point hidden-par2 size band for bytes that provably
    /// contain no hidden par2.
    ///
    /// The join is exact and narrow: same poster and group, twin stem
    /// equals the container stem minus its `.7z`/`.zip`, twin carries
    /// nothing but par2 files (sampled 400 of the 9,261: all pure).
    ///
    /// Unlike `split_merge` this walk can never finish for good -
    /// ingest keeps producing new pairs, because a par2 filename gives
    /// `release_stem` no way to see the `.7z` it belongs to. So the
    /// cursor parks at the top id and follows it, and each stride
    /// looks BOTH ways (a container in the stride, or a twin in the
    /// stride whose container an earlier stride already passed), so a
    /// pair folds no matter which row the walk meets first. It waits
    /// for `split_merge` to complete so the containers exist to fold
    /// into, and the first full lap bumps `predb_seed_gen` once: the
    /// folded rows carry different sizes and a true `has_par2`, worth
    /// re-correlating. Returns (pairs folded, par2 files moved, walk
    /// caught up with the top id).
    ///
    /// Bounded per call in TIME as well as id space. The caller holds
    /// the shared index write mutex for the whole call, and the twin
    /// probes make each row cost two index lookups - measured on a
    /// large live index, one 100k stride ran for tens of seconds with
    /// every other index user (ingest, the API, a starting download)
    /// parked behind it. So the walk goes in sub-strides, persisting
    /// the cursor after each, and returns when `budget` is spent; the
    /// next tick resumes where this one stopped.
    pub fn par2_sidecar_fold(
        &mut self,
        budget: std::time::Duration,
    ) -> rusqlite::Result<(usize, usize, bool)> {
        if self.kv_get("split_merge_done_v1").is_none() {
            // Containers are partly split_merge's output; walking ids
            // it has not folded yet would pass pairs it later creates.
            return Ok((0, 0, false));
        }
        const STRIDE: i64 = 100_000;
        const SUB_STRIDE: i64 = 1_000;
        let started = std::time::Instant::now();
        let top: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
        let mut cursor: i64 = self
            .kv_get("par2_fold_cursor")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // A cursor ABOVE the top id means the fold itself deleted the
        // row it parked on (folding removes the bare twin release, and
        // that twin can be the maximum). releases.id has no
        // AUTOINCREMENT, so the next insert reuses exactly that id -
        // and a strictly-greater scan would then never visit the
        // recreated row while every later insert passed it by (Codex
        // sweep 3 Aug M3). Rewind to the surviving top; the pair logic
        // is idempotent, so re-walking a fringe of ids is only cheap
        // re-reads.
        if cursor > top {
            cursor = top;
            self.kv_set("par2_fold_cursor", &cursor.to_string())?;
        }
        if cursor >= top {
            return Ok((0, 0, true));
        }
        let call_top = cursor.saturating_add(STRIDE).min(top);
        let (mut pairs, mut moved) = (0usize, 0usize);
        let mut reached_top = false;
        loop {
            let hi = cursor.saturating_add(SUB_STRIDE).min(call_top);
            // Either half of a pair makes a row a candidate. The
            // twin-side EXISTS probes are point lookups on the
            // (stem, poster, grp) unique index, so the sub-stride
            // stays cheap.
            let cands: Vec<(String, String, String)> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT stem, poster, grp FROM releases AS t
                      WHERE t.id>?1 AND t.id<=?2 AND t.junk>=70
                        AND (t.stem LIKE '%.7z' OR t.stem LIKE '%.zip'
                             OR EXISTS(SELECT 1 FROM releases c
                                        WHERE c.stem IN (t.stem||'.7z', t.stem||'.zip')
                                          AND c.poster=t.poster AND c.grp=t.grp
                                          AND c.junk>=70))",
                )?;
                stmt.query_map([cursor, hi], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for (stem, poster, grp) in cands {
                let containers: Vec<String> = if stem.ends_with(".7z") || stem.ends_with(".zip") {
                    vec![stem]
                } else {
                    // Twin side: its container wears one of the two exts.
                    vec![format!("{stem}.7z"), format!("{stem}.zip")]
                };
                for cstem in &containers {
                    let n = self.par2_sidecar_fold_pair(cstem, &poster, &grp)?;
                    if n > 0 {
                        pairs += 1;
                        moved += n;
                        break;
                    }
                }
            }
            // Clamped to the max id that SURVIVED this sub-stride:
            // folding deletes bare twin rows, and if one of them was
            // the table maximum, parking the cursor on its id would let
            // SQLite hand the same id to the next insert - a row a
            // strictly-greater scan then never visits (Codex sweep
            // 3 Aug M3). The head-side rewind above only helps when the
            // recreation happens AFTER the next fold call; this clamp
            // closes the delete-and-recreate-between-folds
            // interleaving too.
            let survived: i64 =
                self.db
                    .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
            cursor = hi.min(survived);
            self.kv_set("par2_fold_cursor", &cursor.to_string())?;
            // Caught up two ways, and the second one matters: `hi`
            // reached the top this call started from, OR the rows above
            // `hi` are GONE because this fold deleted them, so
            // `survived` has collapsed to at or below the cursor and
            // the `top` read at entry can never be reached. Without
            // that second test the loop re-queries an empty id range,
            // advancing nothing, until its whole budget is spent -
            // measured on the 20,001-member fixture in predb_tests: the
            // fold itself finished in well under a second and the call
            // then span for the remaining 4 s of a 5 s budget, and
            // reported "not caught up" so the lap never completed.
            if hi >= top || cursor >= survived {
                reached_top = true;
                break;
            }
            if hi >= call_top || started.elapsed() >= budget {
                break;
            }
        }
        let done = reached_top;
        if done && self.kv_get("par2_fold_lap_v1").is_none() {
            self.kv_set("par2_fold_lap_v1", "1")?;
            // The backlog lap is what moves thousands of sizes at
            // once; later steady-state folds ride the live legs.
            let g: u64 = self
                .kv_get("predb_seed_gen")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            self.kv_set("predb_seed_gen", &(g + 1).to_string())?;
        }
        Ok((pairs, moved, done))
    }

    /// Fold one container's par2 twin, if it has one. Returns the par2
    /// files moved in (0 = no twin, twin not purely par2, or a fed
    /// name froze the pair).
    fn par2_sidecar_fold_pair(
        &mut self,
        cstem: &str,
        poster: &str,
        grp: &str,
    ) -> rusqlite::Result<usize> {
        let Some(base) = cstem
            .strip_suffix(".7z")
            .or_else(|| cstem.strip_suffix(".zip"))
            .filter(|b| !b.is_empty())
        else {
            return Ok(0);
        };
        let read = |db: &rusqlite::Connection,
                    sql: &str,
                    stem: &str|
         -> rusqlite::Result<Option<SplitMember>> {
            db.prepare_cached(sql)?
                .query_row(rusqlite::params![stem, poster, grp], |r| {
                    Ok(SplitMember {
                        id: r.get(0)?,
                        stem: r.get(1)?,
                        has_par2: r.get(2)?,
                        first_posted: r.get(3)?,
                        first_seen: r.get(4)?,
                        pre_named: !r.get::<_, String>(5)?.is_empty(),
                    })
                })
                .optional()
        };
        const COLS: &str = "SELECT id, stem, has_par2, first_posted, first_seen, pre_title
                   FROM releases";
        // The junk>=70 scope rides on the CONTAINER: those are the
        // obfuscated rows whose size is load-bearing correlation
        // evidence. (The twin-side arm of the walk already required
        // it; rechecking here keeps both arms identical.)
        let Some(cont) = read(
            &self.db,
            &format!("{COLS} WHERE stem=?1 AND poster=?2 AND grp=?3 AND junk>=70"),
            cstem,
        )?
        else {
            return Ok(0);
        };
        let Some(twin) = read(
            &self.db,
            &format!("{COLS} WHERE stem=?1 AND poster=?2 AND grp=?3"),
            base,
        )?
        else {
            return Ok(0);
        };
        if cont.pre_named || twin.pre_named {
            // Somebody (feed, correlation, a human) named a half.
            // Merging under it would silently extend that claim to
            // bytes it never covered.
            return Ok(0);
        }
        // The twin must be NOTHING but par2. One content file means it
        // is a genuine release that happens to share the base name.
        let (tfiles, nonpar2): (i64, i64) = self.db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LOWER(filename) NOT LIKE '%.par2'),0)
               FROM files WHERE release_id=?1",
            [twin.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if tfiles == 0 || nonpar2 > 0 {
            return Ok(0);
        }
        let tx = self.db.unchecked_transaction()?;
        // Files move to the container; a duplicate filename keeps the
        // container's copy.
        tx.execute(
            "UPDATE OR IGNORE files SET release_id=?1 WHERE release_id=?2",
            [cont.id, twin.id],
        )?;
        tx.execute("DELETE FROM files WHERE release_id=?1", [twin.id])?;
        // Stale audit rows: the twin's suggestions die with it, and
        // the container's were scored against a size and a
        // par2_identified flag that are both wrong now.
        tx.execute(
            "DELETE FROM pre_corr WHERE release_id IN (?1, ?2)",
            [cont.id, twin.id],
        )?;
        // The twin's message-id keys move with its par2 files, for the
        // reason spelled out in `split_merge_group`: `rel_identity_ad`
        // would otherwise drop them on the delete below and the fold
        // would erase identity for articles that are still indexed.
        tx.execute(
            "UPDATE OR IGNORE msgid_map SET release_id=?1 WHERE release_id=?2",
            [cont.id, twin.id],
        )?;
        // The pesto counter range and session fields merge like
        // shatter_fold_members' (load-bearing there): pesto_candidates
        // keys on counter-range containment, so dropping the twin's
        // range would leave the folded set's sidecar unable to find its
        // payload. Read BEFORE the twin's row is deleted.
        #[expect(clippy::type_complexity)]
        let (pmin, pmax, pck, sidx, stot): (
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
        ) = tx.query_row(
            "SELECT MIN(pesto_ctr_min), MAX(pesto_ctr_max), MIN(pesto_clock),
                    MAX(sess_idx), MAX(sess_total)
               FROM releases WHERE id IN (?1, ?2)",
            [cont.id, twin.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        // rel_fts_ad covers this deletion; the kept stem is untouched,
        // so no manual FTS maintenance this time.
        tx.execute("DELETE FROM releases WHERE id=?1", [twin.id])?;
        // Parts and completeness from the POST-merge files table (the
        // ingest aggregate's shape), not cont+twin sums: OR IGNORE above
        // drops duplicate filenames, so the pre-merge sums counted the
        // dropped copies' parts and a dropped incomplete duplicate
        // marked a wholly-complete merged row incomplete.
        let agg = super::aggregates::RelAgg::recompute(&tx, cont.id)?;
        let fp = [cont.first_posted, twin.first_posted]
            .into_iter()
            .filter(|v| *v > 0)
            .min()
            .unwrap_or(0);
        // Ingest's recovery chain, so this recomputed score is the one
        // ingest would have written for the stem the row still wears
        // (the kept stem is `cstem`, unchanged by the fold, and the
        // pre_named gate above means no fed name - so the stem is both
        // arguments, as at every other fold).
        //
        // INERT on today's population, and said out loud so nobody
        // reads it as a fix for a hidden row. The container is admitted
        // at `junk>=70`, and for a `Kind::Movie` parse the only ways to
        // reach 70 are `stem_obfuscated` (70) and an .exe (85) - both
        // kind-INDEPENDENT, and both above every kind branch
        // `junk_score` has (the largest is 60). So the recovered lane
        // moves no number this population can carry.
        // `recover_kind_from_group` is stronger than inert here: it is
        // dead by this fn's own entry guard, since `cstem` always ends
        // in `.7z`/`.zip` and the rule declines a plain extension. It
        // is called anyway because the inertness lives in `junk_score`,
        // three modules away, and nothing there knows the folds depend
        // on its branches all sitting below 70.
        let mut p = crate::categories::classify(cstem, &self.custom);
        crate::release::recover_media_kind(&mut p, cstem, cstem);
        crate::release::recover_kind_from_group(&mut p, grp, cstem);
        // Gate taken BEFORE the pass: `stem_obfuscated`'s second arm is
        // guarded on `p.season.is_none()`, so asking afterwards judges
        // the blob by the season the pass just wrote.
        if !stem_obfuscated(cstem, &p) {
            crate::release::recover_episode_from_group(&mut p, grp, cstem);
        }
        tx.execute(
            "UPDATE releases
                SET total_bytes=?2, files=?3, complete=?4, has_par2=1,
                    first_posted=?5, first_seen=?6, have_parts=?7, need_parts=?8,
                    junk=?9,
                    pesto_ctr_min=?10, pesto_ctr_max=?11, pesto_clock=?12,
                    sess_idx=?13, sess_total=?14,
                    nfiles_complete=?15, nfiles_exe=?16
              WHERE id=?1",
            rusqlite::params![
                cont.id,
                agg.tbytes,
                agg.nfiles,
                agg.complete(),
                fp,
                cont.first_seen.min(twin.first_seen),
                agg.have,
                agg.need,
                junk_score(cstem, &p, agg.tbytes.max(0) as u64, agg.nexe > 0),
                pmin,
                pmax,
                pck,
                sidx,
                stot,
                agg.ncomplete,
                agg.nexe
            ],
        )?;
        tx.commit()?;
        Ok(tfiles as usize)
    }

    /// Fold releases SHATTERED by per-article poster randomization.
    ///
    /// The dominant obfuscated-poster family posts one file under a
    /// stable blob subject name while randomizing the From on every
    /// article (and rotating the group per article on top). The
    /// cluster key is (stem, poster, grp), so a 562-part file lands as
    /// up to 562 one-segment release rows, each holding one article
    /// and the true `need_parts`. Measured on a 20.5M-row live index,
    /// 13 Aug 2026: ~19.9M dark rows are ~1.08M such postings - 97% of
    /// all dark rows. The fold key is therefore the STEM ALONE, across
    /// posters AND groups.
    ///
    /// The gates keep it narrow: every member must be dark
    /// (`junk>=70`, unnamed, and the stem fails
    /// `release::stem_is_a_name` - the ONE shared verdict), a
    /// single-file row, carry a real subject part total, and agree on
    /// that total; the stem must be at least 12 chars (`LENGTH(stem)
    /// >= 12` in the statement below) so a generic readable-ish token
    /// ("1917", "Subs") can never bridge two posters' unrelated files.
    /// That floor was 16 until 1 Sep 2026 - the comment on the statement
    /// itself carries why it moved and why 12 is the measured bottom.
    /// Members' one-file segment lists are UNIONED by part number (all
    /// rows share the filename, so repointing rows would silently drop
    /// segments).
    ///
    /// Like `par2_sidecar_fold` this can never finish for good -
    /// ingest keeps shattering new postings - so the cursor parks at
    /// the top id and follows it. Bounded per call in time and id
    /// space; the caller holds the index write mutex throughout.
    /// Returns (postings folded, rows folded away, caught up).
    pub fn shatter_fold(
        &mut self,
        now: i64,
        budget: std::time::Duration,
    ) -> rusqlite::Result<(usize, usize, bool)> {
        const STRIDE: i64 = 100_000;
        const SUB_STRIDE: i64 = 1_000;
        let started = std::time::Instant::now();
        let top: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
        let mut cursor: i64 = self
            .kv_get("shatter_fold_cursor")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // Same id-reuse hazard as `par2_sidecar_fold`: the fold deletes
        // rows, releases.id has no AUTOINCREMENT, and a cursor parked
        // above the surviving maximum would never visit a recreated id.
        if cursor > top {
            cursor = top;
            self.kv_set("shatter_fold_cursor", &cursor.to_string())?;
        }
        if cursor >= top {
            return Ok((0, 0, true));
        }
        let call_top = cursor.saturating_add(STRIDE).min(top);
        let deadline = started + budget;
        let (mut groups, mut folded) = (0usize, 0usize);
        let mut reached_top = false;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        // The loop runs inside a closure so EVERY exit - normal break, a
        // mid-pass SQL error, a deadline bail - flows through the tally
        // flush below. Each group's fold commits its own transaction, so
        // work done before an error is real and must be counted; the old
        // shape lost it to the `?` (14 Aug sweep).
        let run: rusqlite::Result<()> = (|| {
            'pass: loop {
                let hi = cursor.saturating_add(SUB_STRIDE).min(call_top);
                // Cheap SQL prefilter; `stem_is_a_name` is the real test
                // and runs on the Rust side. files=1 is the shattered
                // shape (one file row holding one segment). The length
                // floor was 16 until 1 Sep 2026, which structurally
                // excluded 481k dark rows (2.2% of the band) - the
                // teevee family's stems are commonly 15 characters
                // (`LgXNckle2TSyKUA`), a whole family one character
                // under the line. 12 is the measured safe floor: below
                // it the candidate set starts admitting `)` and
                // `12345`, which must NOT lose the poster from their
                // cluster key
                // (research/SHATTER-FOLD-STARVATION-2026-09-01.md).
                let cands: Vec<String> = {
                    let mut stmt = self.db.prepare_cached(
                        "SELECT DISTINCT stem FROM releases
                          WHERE id>?1 AND id<=?2 AND junk>=70 AND pre_title=''
                            AND files=1 AND need_parts>0
                            AND LENGTH(stem) >= 12",
                    )?;
                    stmt.query_map([cursor, hi], |r| r.get(0))?
                        .collect::<rusqlite::Result<_>>()?
                };
                for stem in cands {
                    if crate::release::stem_is_a_name(&stem) || !seen.insert(stem.clone()) {
                        continue;
                    }
                    let (g, n, complete) = self.shatter_fold_stem(&stem, now, deadline)?;
                    groups += g;
                    folded += n;
                    if !complete {
                        // Time ran out inside this stem. Leave the
                        // cursor at the substride START so the next call
                        // revisits the remainder (already-folded groups
                        // rescan to nothing) - advancing it would orphan
                        // the unfolded rows forever, since the cursor
                        // never returns below its park.
                        break 'pass;
                    }
                }
                // Clamp to the surviving maximum for the same
                // delete-and-recreate interleaving `par2_sidecar_fold`
                // guards against.
                let survived: i64 =
                    self.db
                        .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
                cursor = hi.min(survived);
                self.kv_set("shatter_fold_cursor", &cursor.to_string())?;
                // Caught up two ways, and the second one matters: `hi`
                // reached the top this call started from, OR the rows above
                // `hi` are GONE because this fold deleted them, so
                // `survived` has collapsed to at or below the cursor and
                // the `top` read at entry can never be reached. Without
                // that second test the loop re-queries an empty id range,
                // advancing nothing, until its whole budget is spent -
                // measured on the 20,001-member fixture in predb_tests: the
                // fold itself finished in well under a second and the call
                // then span for the remaining 4 s of a 5 s budget, and
                // reported "not caught up" so the lap never completed.
                if hi >= top || cursor >= survived {
                    reached_top = true;
                    break;
                }
                if hi >= call_top || started.elapsed() >= budget {
                    break;
                }
            }
            Ok(())
        })();
        // Lifetime tallies for the settings-card census: the per-pass
        // log line scrolls away, and "how much of the dark band has
        // been merged" needs running totals.
        if folded > 0 {
            // The counters postdate the fold itself (v1.1.1 shipped the
            // fold and the lap marker, the tallies came later), so a
            // database whose first lap predates them has merged rows
            // nothing ever counted. Stamp that fact now, before the
            // counter keys exist: once they do, the absence that proved
            // it is gone and the totals would read as lifetime numbers.
            if self.kv_get("shatter_fold_lap_v1").is_some()
                && self.kv_get("shatter_fold_rows").is_none()
                && self.kv_get("shatter_fold_groups").is_none()
            {
                self.kv_set("shatter_fold_census_partial", "1")?;
            }
            for (key, add) in [
                ("shatter_fold_rows", folded),
                ("shatter_fold_groups", groups),
            ] {
                let cur: u64 = self.kv_get(key).and_then(|v| v.parse().ok()).unwrap_or(0);
                self.kv_set(key, &(cur + add as u64).to_string())?;
            }
        }
        run?;
        let done = reached_top;
        if done && self.kv_get("shatter_fold_lap_v1").is_none() {
            self.kv_set("shatter_fold_lap_v1", "1")?;
            // A lap completed under counter-aware code has counted every
            // merge it made, so materialize zeroes: without the keys this
            // database would be indistinguishable from a pre-counter one
            // and read as "lifetime unknown" forever.
            for key in ["shatter_fold_rows", "shatter_fold_groups"] {
                if self.kv_get(key).is_none() {
                    self.kv_set(key, "0")?;
                }
            }
            // The folded rows are the first time this band has real
            // sizes and times - exactly what the correlation walks
            // score on. Re-open them once.
            let g: u64 = self
                .kv_get("predb_seed_gen")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            self.kv_set("predb_seed_gen", &(g + 1).to_string())?;
        }
        Ok((groups, folded, done))
    }

    /// The fold's running census for the settings card: lifetime rows
    /// merged and postings made whole, plus how far the current sweep
    /// has got. Read-only; same readout contract as `probe7z_stats`.
    pub fn shatter_fold_stats(&self) -> serde_json::Value {
        let kv_u64 = |k: &str| self.kv_get(k).and_then(|v| v.parse::<u64>().ok());
        let top: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))
            .unwrap_or(0);
        let rows = kv_u64("shatter_fold_rows");
        let groups = kv_u64("shatter_fold_groups");
        let first_lap = self.kv_get("shatter_fold_lap_v1").is_some();
        // A pre-counter database: either stamped as such the moment the
        // counters were first written, or still recognizable read-only
        // by a completed lap with no counter keys. Its totals are
        // since-upgrade, not lifetime, and the card must say so instead
        // of quoting a confident zero.
        let partial = self.kv_get("shatter_fold_census_partial").is_some()
            || (first_lap && rows.is_none() && groups.is_none());
        serde_json::json!({
            "rows_folded": rows.unwrap_or(0),
            "postings": groups.unwrap_or(0),
            "lifetime_known": !partial,
            "cursor": kv_u64("shatter_fold_cursor").unwrap_or(0),
            "top": top,
            "first_lap_done": first_lap,
        })
    }

    /// Fold every posting sharing `stem`, ONE FILENAME AT A TIME.
    ///
    /// `release_stem` deliberately reduces `x.part01.rar`,
    /// `x.part02.rar`, `x.vol000+01.par2` … to the same `x`: that is
    /// what makes a set one release. The shattered dark band posts a
    /// single file per stem, but an obfuscated multi-volume set does
    /// not, and those volumes are DISTINCT files with their own
    /// part-number universes. Folding them together would union two
    /// unrelated `(1/2)`/`(2/2)` pairs under whichever filename sorted
    /// first and delete the rest of the set - the same garbage-union
    /// hazard the part-total class gate exists to stop, one level up.
    /// So the filename is part of the fold key.
    ///
    /// Returns (postings folded, rows folded away, complete). `complete`
    /// is false when `deadline` passed mid-stem: the caller must NOT
    /// advance its cursor past this stem's substride, so the remainder
    /// is revisited on the next call. The per-group batch walk used to
    /// ignore the pass budget entirely, and a single 200k-member posting
    /// held the index write mutex for the whole multi-batch fold
    /// (14 Aug sweep).
    fn shatter_fold_stem(
        &mut self,
        stem: &str,
        now: i64,
        deadline: std::time::Instant,
    ) -> rusqlite::Result<(usize, usize, bool)> {
        let names: Vec<String> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT DISTINCT f.filename
                   FROM releases r JOIN files f ON f.release_id=r.id
                  WHERE r.stem=?1 AND r.junk>=70 AND r.pre_title=''
                    AND r.files=1 AND r.need_parts>0",
            )?;
            stmt.query_map([stem], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        let (mut groups, mut folded) = (0usize, 0usize);
        for name in names {
            let (n, complete) = self.shatter_fold_group(stem, &name, now, deadline)?;
            if n > 0 {
                groups += 1;
                folded += n;
            }
            if !complete || std::time::Instant::now() >= deadline {
                return Ok((groups, folded, false));
            }
        }
        Ok((groups, folded, true))
    }

    /// Fold every dark single-file row wearing `stem` and holding
    /// `fname` - across posters and groups - into the lowest-id
    /// member, unioning their segment lists by part number. Returns
    /// rows folded away (0 = nothing to do or the group failed a
    /// gate).
    fn shatter_fold_group(
        &mut self,
        stem: &str,
        fname: &str,
        now: i64,
        deadline: std::time::Instant,
    ) -> rusqlite::Result<(usize, bool)> {
        // Hard cap keeps the id list bounded. A posting bigger than
        // the cap folds over successive PASSES of this same call (see
        // the loop below): the cursor parks at the top id once the lap
        // completes, so "it folds on a later lap" was never true for a
        // posting that has stopped arriving.
        const MEMBER_CAP: usize = 20_000;
        let mut folded = 0usize;
        loop {
            let members: Vec<ShatterMember> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT r.id, r.has_par2, r.first_posted, r.first_seen, r.need_parts,
                            r.grp
                       FROM releases r JOIN files f ON f.release_id=r.id
                      WHERE r.stem=?1 AND r.junk>=70 AND r.pre_title=''
                        AND r.files=1 AND r.need_parts>0 AND f.filename=?2
                      ORDER BY r.id LIMIT ?3",
                )?;
                stmt.query_map(rusqlite::params![stem, fname, MEMBER_CAP as i64], |r| {
                    Ok(ShatterMember {
                        id: r.get(0)?,
                        has_par2: r.get(1)?,
                        first_posted: r.get(2)?,
                        first_seen: r.get(3)?,
                        need_parts: r.get(4)?,
                        grp: r.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            let capped = members.len() >= MEMBER_CAP;
            let n = self.shatter_fold_members(stem, fname, members, now)?;
            folded += n;
            // Another cap's worth may be waiting behind this one. Stop
            // when the batch came in under the cap, or when a capped
            // batch made no progress (a gate refused it - looping
            // would spin).
            if !capped || n == 0 {
                return Ok((folded, true));
            }
            // Each batch commits its own transaction, so stopping here
            // is clean - but the remainder must be REVISITED, which is
            // what the false `complete` makes the top-level cursor do.
            if std::time::Instant::now() >= deadline {
                return Ok((folded, false));
            }
        }
    }

    /// One capped batch of `shatter_fold_group`'s members.
    fn shatter_fold_members(
        &mut self,
        stem: &str,
        fname: &str,
        members: Vec<ShatterMember>,
        now: i64,
    ) -> rusqlite::Result<usize> {
        type Member = ShatterMember;
        // The subject's "(x/y)" total is per-posting truth: members of
        // one posting agree on it. Fold only the largest agreeing
        // class - a disagreeing minority is a different posting that
        // happens to reuse the stem, and unioning two part universes
        // is the exact garbage-download hazard the ingest D3 backstop
        // exists to stop.
        let mut by_total: std::collections::HashMap<i64, Vec<Member>> = Default::default();
        for m in members {
            by_total.entry(m.need_parts).or_default().push(m);
        }
        let Some(class) = by_total
            .into_values()
            .max_by_key(|v| (v.len(), v.first().map(|m| -m.id).unwrap_or(0)))
        else {
            return Ok(0);
        };
        if class.len() < 2 {
            return Ok(0);
        }
        let need = class[0].need_parts;
        let Some(kept) = class.iter().min_by_key(|m| m.id) else {
            return Ok(0);
        };
        let (keep, keep_grp) = (kept.id, kept.grp.clone());
        let others: Vec<i64> = class
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != keep)
            .collect();
        // Union the one-file segment lists, keep's copy winning per
        // part, then ascending id order - deterministic under replay.
        let mut merged: std::collections::BTreeMap<u32, (String, u64)> = Default::default();
        let mut total_parts: i64 = 0;
        {
            // Every member holds `fname` - that is the fold key - so
            // the union needs no filename reconciliation.
            let mut stmt = self.db.prepare_cached(
                "SELECT total_parts, segments FROM files
                  WHERE release_id=?1 AND filename=?2",
            )?;
            let mut ids = vec![keep];
            ids.extend(&others);
            for id in ids {
                let Some((tp, segs)) = stmt
                    .query_row(rusqlite::params![id, fname], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, SegList>(1)?.0))
                    })
                    .optional()?
                else {
                    continue;
                };
                total_parts = total_parts.max(tp);
                for (n, id, b) in segs {
                    merged.entry(n).or_insert((id, b));
                }
            }
        }
        if merged.is_empty() {
            return Ok(0);
        }
        let bytes: u64 = merged.values().map(|v| v.1).sum();
        let seg_blob = segcodec::encode(
            &merged
                .iter()
                .map(|(n, (id, b))| (*n, id.clone(), *b))
                .collect::<Vec<_>>(),
        );
        let nsegs = merged.len() as i64;
        let list = others
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let tx = self.db.unchecked_transaction()?;
        // Merge the pesto counter range BEFORE the source rows die -
        // aggregate MIN/MAX ignore NULLs, matching ingest's monotonic
        // merge rule.
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
        // All members share the filename, so the source files rows are
        // consumed by the in-memory union above, not repointed.
        tx.execute(
            &format!("DELETE FROM files WHERE release_id IN ({list})"),
            [],
        )?;
        tx.execute(
            "UPDATE files SET total_parts=?2, bytes=?3, segments=?4, nsegs=?5
              WHERE release_id=?1 AND filename=?6",
            rusqlite::params![
                keep,
                total_parts.max(need),
                bytes as i64,
                seg_blob,
                nsegs,
                fname
            ],
        )?;
        // Stale audit rows: fragment suggestions die with the rows,
        // and the kept row's were scored against one article's size.
        tx.execute(
            &format!("DELETE FROM pre_corr WHERE release_id IN ({list}) OR release_id=?1"),
            [keep],
        )?;
        // The message-id keys move WITH the articles (see
        // `split_merge_group` for why losing them would erase the
        // strongest naming evidence the index holds).
        tx.execute(
            &format!("UPDATE OR IGNORE msgid_map SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        tx.execute(&format!("DELETE FROM releases WHERE id IN ({list})"), [])?;
        let fp = class
            .iter()
            .map(|m| m.first_posted)
            .filter(|v| *v > 0)
            .min()
            .unwrap_or(0);
        let fs = class.iter().map(|m| m.first_seen).min().unwrap_or(now);
        let has_par2 = class.iter().any(|m| m.has_par2);
        // Ingest's recovery chain, against the KEPT row's group, so
        // this recomputed score is the one ingest would have written
        // for the stem the row still wears. The members screen on
        // `pre_title=''`, so there is no fed name and the stem is both
        // arguments.
        //
        // INERT on this population, twice over, and said out loud so
        // nobody reads it as a fix for a hidden row. The walk skips
        // every candidate `stem_is_a_name` accepts, so a member's stem
        // is exactly what `looks_obfuscated` damns - which is
        // `stem_obfuscated`'s own first arm. So (a) the stem parses to
        // `Kind::Other`, which both group rules decline on purpose (an
        // obfuscated stem must not become a book with a hash for a
        // title) and which the episode gate below declines outright,
        // and (b) the 70 those members carry is kind-INDEPENDENT and
        // sits above every kind branch `junk_score` has (the largest is
        // 60), so no recovered lane could move the number even if one
        // fired. That closes the `has_exe=false` seam below as well: an
        // .exe member loses its 85 here, but the blob floor is still
        // 70. Measured on the live index 2 Sep 2026, before the
        // Rust-side name filter: 57.9M `other` against 6.02M `movie` in
        // the SQL band, and of those 6.02M exactly TWO carry an exe -
        // both `Chainsaw-hrscovers.com` in `alt.binaries.movies`, a
        // group neither rule vouches for.
        //
        // Called anyway because the inertness is arithmetic in
        // `junk_score` and a predicate in `release`, neither of which
        // knows the folds depend on it.
        let mut p = crate::categories::classify(stem, &self.custom);
        crate::release::recover_media_kind(&mut p, stem, stem);
        crate::release::recover_kind_from_group(&mut p, &keep_grp, stem);
        // Gate taken BEFORE the pass: `stem_obfuscated`'s second arm is
        // guarded on `p.season.is_none()`, so asking afterwards judges
        // the blob by the season the pass just wrote.
        if !stem_obfuscated(stem, &p) {
            crate::release::recover_episode_from_group(&mut p, &keep_grp, stem);
        }
        tx.execute(
            "UPDATE releases
                SET total_bytes=?2, files=1, complete=?3, has_par2=?4,
                    first_posted=?5, first_seen=?6, have_parts=?7, need_parts=?8,
                    junk=?9,
                    pesto_ctr_min=?10, pesto_ctr_max=?11, pesto_clock=?12,
                    sess_idx=?13, sess_total=?14,
                    nfiles_complete=?15, nfiles_exe=?16
              WHERE id=?1",
            rusqlite::params![
                keep,
                bytes as i64,
                nsegs >= need,
                has_par2,
                fp,
                fs,
                nsegs,
                need,
                junk_score(stem, &p, bytes, false),
                pmin,
                pmax,
                pck,
                sidx,
                stot,
                // Recompute-exact for the one file row this release now
                // holds, so the next ingest touch stays incremental: the
                // stored total is `total_parts.max(need)`, not `need`.
                i64::from(nsegs >= total_parts.max(need)),
                i64::from(super::aggregates::is_exe_file(fname)),
            ],
        )?;
        // The stem is unchanged, so rel_fts needs no manual write; the
        // row deletions above are covered by rel_fts_ad.
        tx.commit()?;
        Ok(others.len())
    }

    /// M31a: age-based retention. Deletes releases older than the window,
    /// EXCEPT unknown-date rows (`first_posted` 0, whose OVER Date failed
    /// to parse) and titles the user has hidden (the Hidden panel must
    /// keep showing them). Chunked so a big first prune never holds the
    /// write lock past the parallel scanners' 10 s busy timeout. Freed
    /// pages get reused by later scans, so the DB size plateaus even
    /// without VACUUM. Returns (rows removed, caught up).
    ///
    /// `deadline` is what makes the chunking mean what the line above
    /// claims. The batch bounds one TRANSACTION; the loop around it was
    /// unbounded, so on a large index "chunked" bought nothing and the
    /// write mutex stayed held for the whole reap - see
    /// [`Self::prune_stale_partials`] for the wedge that measured it.
    ///
    /// Note: an owned release older than the window IS pruned from the
    /// INDEX - the downloaded file and history entry are untouched
    /// (have-badges compute from daemon history, not the index), and a
    /// re-scan re-adds it if it's still within the ingest gate.
    pub fn prune_age(
        &self,
        max_age_secs: i64,
        now: i64,
        deadline: std::time::Instant,
    ) -> rusqlite::Result<(usize, bool)> {
        if max_age_secs <= 0 {
            return Ok((0, true));
        }
        let cutoff = now - max_age_secs;
        let mut removed = 0;
        loop {
            let ids: Vec<i64> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT id FROM releases
                     WHERE first_posted > 0 AND first_posted < ?1
                       AND title_key NOT IN (SELECT key FROM wall_hidden)
                     LIMIT 8000",
                )?;
                stmt.query_map([cutoff], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            if ids.is_empty() {
                return Ok((removed, true));
            }
            // AFTER the batch, never before: an entry already past the
            // deadline still does one batch, so a budget the caller set
            // too tight reaps slowly rather than never. The batch is
            // budgeted too, so "one batch" is a bounded hold of the write
            // mutex and not however long 8000 deletes happen to take; a
            // short one simply leaves its tail for the next entry, which
            // re-selects it (there is no cursor here - the selection is a
            // seek on `idx_rel_posted` and the reaped rows leave it).
            let (n, consumed) = self.prune_batch_until(&ids, deadline);
            removed += n;
            if consumed < ids.len() || std::time::Instant::now() >= deadline {
                return Ok((removed, false));
            }
        }
    }

    /// M31a: reap dead junk fragments regardless of max_age - the bulk
    /// of a raw a.b.teevee/moovee index is single-segment fragments of
    /// obfuscated posts that never form a complete release (measured on
    /// the live 800k-row index: ~87% are junk-hidden, tiny, incomplete).
    /// prune_size spares anything missing parts forever (can't tell a
    /// mid-upload from a dead one), so this is where they die.
    ///
    /// DELIBERATELY gated on `junk >= 50` (already hidden from the wall)
    /// so the always-on reaper NEVER touches wall-visible content - a
    /// release is reaped only when it is already-junk AND older than the
    /// settle window (so not a live mid-upload; Usenet propagation is
    /// hours, not days) AND still missing parts (confirmed incomplete on
    /// the server). Wall-visible old content is the opt-in age prune's
    /// job, never this one's. Same chunking + hidden protection.
    /// Returns (rows removed, caught up).
    ///
    /// BUDGETED, and the reason is a measured wedge (15 Aug, on a live
    /// 34.6 M-row / 49.7 GB index): the loop below had no deadline, so
    /// one entry reaped until it ran out of rows - six hours and
    /// counting, holding the write mutex the whole time. None of the
    /// selection's own predicates has an index to ride (a `junk` range
    /// plus a correlated EXISTS over `json_array_length(f.segments)`),
    /// and it restarted at the top of the table on every batch, so the
    /// scan prefix of rows that do NOT match grew as the ones that do
    /// were deleted: the cost per batch climbed while the work left
    /// barely moved. Every index consumer blocked behind it, the
    /// download runner included, which froze a finished job in the queue
    /// reading "Extracting" for as long as the daemon lived.
    ///
    /// So the caller gets its lock back on a clock. `caught up` false
    /// means rows are still waiting: come back on the next pass rather
    /// than on the hourly gate.
    ///
    /// The deadline only means that because the SELECTION is bounded
    /// too, which is the second half of the same wedge (read-only sweep
    /// 3, 16 Aug 2026, M9). A deadline checked between statements cannot
    /// interrupt the statement that is running, and the unbounded
    /// selection above was minutes of it on a large index: once it
    /// started, neither the 1 s slice nor the caller's 30 s pass could
    /// stop it, and the write mutex stayed held for the whole of it -
    /// the same block, in the small, that the loop above used to hold
    /// for hours. Worse, it was PERMANENT rather than a migration cost:
    /// once the reap is caught up, every hourly entry pays one terminal
    /// full walk of the table to return zero rows.
    ///
    /// So the walk is an id stride with a kv cursor, the shape
    /// [`Self::split_merge`] and `par2_sidecar_fold` already use here: a
    /// rowid range is the one predicate this selection CAN ride, each
    /// statement examines at most `SUB_STRIDE` rows whatever the table
    /// size, and the deadline lands between them. A lap that runs out of
    /// budget resumes at the cursor on the next pass instead of
    /// restarting at the top of the table, so the cost per batch stops
    /// climbing as well. `caught up` is now "a full lap finished", and
    /// the cursor parks at 0 so the next entry starts a fresh one.
    ///
    /// Rowids are recycled (`releases.id` has no AUTOINCREMENT), so a
    /// new row minted below the cursor waits for the next lap. That is
    /// harmless here and nowhere else: nothing this reaper takes is
    /// younger than the settle window.
    pub fn prune_stale_partials(
        &self,
        settle_secs: i64,
        now: i64,
        deadline: std::time::Instant,
    ) -> rusqlite::Result<(usize, bool)> {
        // Rowids per statement. Deliberately the batch size the old
        // LIMIT used, so one statement still yields at most one delete
        // batch and a spent budget still buys exactly one of them.
        const SUB_STRIDE: i64 = 8_000;
        let cutoff = now - settle_secs;
        let top: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
        let mut cursor: i64 = self
            .kv_get("stale_prune_cursor")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // A cursor at or past the top is a finished lap - or an index
        // that has since shrunk under it. Either way the next thing to
        // do is a fresh lap, not sitting past the end reporting caught
        // up forever.
        if cursor >= top {
            cursor = 0;
        }
        let mut removed = 0;
        loop {
            let hi = cursor.saturating_add(SUB_STRIDE).min(top);
            let ids: Vec<i64> = {
                let mut stmt = self.db.prepare_cached(
                    // first_seen (when WE indexed it) is the settle clock, not
                    // first_posted (the post's own age). During history backfill
                    // every post is old by definition, so gating only on
                    // first_posted reaped releases still being assembled across
                    // scan slices. Require BOTH: settled by post age AND known to
                    // the index for the settle window.
                    "SELECT id FROM releases
                     WHERE id > ?1 AND id <= ?2
                       AND junk >= 50 AND first_posted > 0 AND first_posted < ?3
                       AND first_seen > 0 AND first_seen < ?3
                       AND title_key NOT IN (SELECT key FROM wall_hidden)
                       AND EXISTS (SELECT 1 FROM files f
                                   WHERE f.release_id = releases.id
                                     AND (CASE WHEN f.nsegs > 0 THEN f.nsegs
                                               ELSE seg_count(f.segments) END) < f.total_parts)",
                )?;
                stmt.query_map([cursor, hi, cutoff], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            // The stride bounds what the SELECT examines; this bounds
            // what the DELETE costs, which is the other half and the one
            // that wedged (see `prune_batch_until`). A budget spent
            // part-way through the list parks the cursor on the last id
            // that actually went, not at `hi` - the ids are in rowid
            // order, so the untouched tail is exactly what the next pass
            // re-selects.
            let (n, consumed) = self.prune_batch_until(&ids, deadline);
            removed += n;
            let short = consumed < ids.len();
            cursor = if short {
                if consumed == 0 {
                    // Nothing went at all (the deadline landed before
                    // the first batch, or its delete errored). The
                    // cursor must NOT move: the selection is `id > ?1`,
                    // so parking on `ids[0]` - an id that was not
                    // deleted - skips that release for an entire lap.
                    cursor
                } else {
                    ids[consumed - 1]
                }
            } else {
                hi
            };
            if !short && hi >= top {
                self.kv_set("stale_prune_cursor", "0")?;
                return Ok((removed, true));
            }
            // AFTER the stride, never before: an entry already past the
            // deadline still does one stride, so a budget the caller set
            // too tight reaps slowly rather than never.
            if short || std::time::Instant::now() >= deadline {
                self.kv_set("stale_prune_cursor", &cursor.to_string())?;
                return Ok((removed, false));
            }
        }
    }

    /// M31a: reclaim freed pages to disk by rewriting the whole file.
    /// Exclusive-locks it for the duration, so the caller MUST ensure no
    /// scan pass or download is in flight.
    ///
    /// §95: this is now the SLOW path, kept for one reason - it is the
    /// only way to put an existing database into incremental
    /// auto-vacuum mode, which is what makes every later compact
    /// abortable. See `compact_chunk`. `PRAGMA auto_vacuum` is a no-op
    /// on a database that already has tables UNLESS a VACUUM follows it
    /// on the same connection, so the two belong in one batch: the
    /// migration IS a compact, and it is the last full rewrite this
    /// database ever needs.
    ///
    /// If it is interrupted the pragma does not stick either, which is
    /// the behaviour we want - `compact_pending` is sticky, so the
    /// migration simply retries at the next idle moment.
    pub fn compact(&self) -> rusqlite::Result<()> {
        let vacuumed = self
            .db
            .execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM");
        // Hand the WAL spike back HERE rather than at whatever later
        // checkpoint happens to reset it. VACUUM is one transaction over
        // the whole database, so it leaves a write-ahead log the size of
        // the database - 28.1 GiB of it on the live index, still sitting
        // there weeks later (see `WAL_SIZE_LIMIT` for the measurement).
        // `journal_size_limit` alone would cap that eventually, but only
        // at the next reset, and this is the one moment we know both
        // that the WAL is enormous and that nothing else wants the
        // database: the compaction loop only runs at idle.
        //
        // Best-effort by design. If a reader does arrive first TRUNCATE
        // reports busy in its result row rather than failing, and the
        // size limit is still there to catch it. An interrupted VACUUM
        // lands here with the interrupt flag still set and simply skips
        // - same fallback. Neither outcome may mask the VACUUM's own
        // result, which is what the caller acts on.
        let _ = self
            .db
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        vacuumed
    }

    /// Fold the write-ahead log back into the database file and cut the
    /// -wal to nothing, waiting at most `wait` for whoever is in the
    /// way. `Ok(false)` is "someone was still reading": the frames it
    /// managed to copy are copied either way, the log is simply still
    /// on disk.
    ///
    /// This exists for the way out. A WAL database that is CLOSED
    /// checkpoints on the way and deletes its -wal and -shm, but the
    /// daemon does not leave by dropping things - it leaves by
    /// `std::process::exit`, and on `mode=restart` by `exec`, neither of
    /// which runs a destructor. So every stop this daemon has ever made
    /// left the whole log behind for the next start to recover.
    /// Measured 14 Aug 2026: SIGTERM, process gone, port free, and a
    /// 28.1 GiB `index.db-wal` plus a 6.9 MiB `-shm` still sitting
    /// beside the database.
    ///
    /// `wait` replaces the connection's 10 s busy timeout for this call
    /// and is put back after it. TRUNCATE waits for readers to catch up
    /// to the latest snapshot, and the caller is an exit with a budget
    /// it would rather keep than spend: a log left behind costs the next
    /// start a recovery pass, which is exactly what happens today, while
    /// an exit that overruns costs a SIGKILL.
    pub fn checkpoint_truncate(&self, wait: std::time::Duration) -> rusqlite::Result<bool> {
        // Read it back rather than assuming `open`'s figure: this is a
        // public method on a connection whose timeout the caller may
        // have set, and it has no business changing it permanently.
        let previous: i64 = self
            .db
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap_or(10_000);
        self.db.busy_timeout(wait)?;
        // The result row is (busy, log frames, checkpointed frames) and
        // a checkpoint that could not finish reports itself in `busy`
        // rather than failing the statement - so `?` here is a real
        // error (the database went away), not contention.
        let busy: i64 = self
            .db
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        let _ = self
            .db
            .busy_timeout(std::time::Duration::from_millis(previous.max(0) as u64));
        Ok(busy == 0)
    }

    /// Free pages this database is holding that `compact_chunk` could
    /// hand back to the filesystem, in PAGES (multiply by `PRAGMA
    /// page_size` for bytes).
    pub fn freelist_pages(&self) -> rusqlite::Result<u64> {
        let n: i64 = self
            .db
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        Ok(n.max(0) as u64)
    }

    /// §95: reclaim at most `pages` freed pages, and return how many are
    /// still on the freelist afterwards (0 = fully compacted).
    ///
    /// This exists because aborting a VACUUM is a request, not a
    /// guarantee (see `interrupt_handle`), and the gap between those two
    /// is a download sitting in `Downloading` making no progress. A
    /// bounded chunk needs no abort mechanism at all: it is short by
    /// construction, so the caller just checks between chunks and stops.
    /// Nothing races, nothing is interrupted, and no phase of it is
    /// immune to being stopped - the three things wrong with doing it as
    /// one VACUUM.
    ///
    /// It is also RESUMABLE, which the VACUUM never was. Each chunk
    /// commits and truncates the file, so standing down for a download
    /// keeps every page reclaimed so far; an aborted VACUUM threw away
    /// all of its work and started from the top next time.
    ///
    /// It reclaims strictly less than a VACUUM: whole free pages go
    /// back, but free space stranded inside partly-emptied pages is not
    /// defragmented. For this schema that gap is small - the bulk of the
    /// bytes are `files.segments` blobs on overflow chains, which are
    /// released whole when their row goes - and it is the same
    /// approximation `live_bytes` already documents.
    ///
    /// Requires incremental auto-vacuum: on a database still in the
    /// default mode this is a silent no-op, which is why the caller must
    /// consult `compact_style` first.
    /// The statement is STEPPED TO COMPLETION, and that is the whole
    /// trick. `PRAGMA incremental_vacuum(N)` is a VDBE loop that frees
    /// one page per step, so `execute_batch` - which steps once and
    /// stops - frees exactly ONE page whatever N says. Measured: with a
    /// 20,000-page freelist, `execute_batch("PRAGMA
    /// incremental_vacuum(2048)")` freed 1 page; the same pragma
    /// stepped to completion freed 2048. The first shape still WORKS
    /// (the daemon loops until the freelist empties), which is what
    /// makes it dangerous - it just costs one write transaction per
    /// page, and it turned a 49 MB reclaim into 12,013 chunks.
    pub fn compact_chunk(&self, pages: u32) -> rusqlite::Result<u64> {
        let mut stmt = self
            .db
            .prepare(&format!("PRAGMA incremental_vacuum({})", pages.max(1)))?;
        let mut rows = stmt.query([])?;
        while rows.next()?.is_some() {}
        drop(rows);
        drop(stmt);
        self.freelist_pages()
    }

    /// Which compaction path this database can take right now.
    pub fn compact_style(&self) -> rusqlite::Result<CompactStyle> {
        let mode: i64 = self.db.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
        // 0 = NONE, 1 = FULL, 2 = INCREMENTAL. FULL is not a mode this
        // code ever sets, but a database that somehow has it already
        // reclaims on every commit and needs no compaction loop at all;
        // treating it as chunked is still correct (the freelist is
        // empty, so the loop exits at once) and costs one PRAGMA.
        Ok(if mode >= 1 {
            CompactStyle::Chunked
        } else {
            CompactStyle::FullRewrite
        })
    }

    /// Refresh the query planner's statistics.
    ///
    /// Without `sqlite_stat1` SQLite plans from built-in guesses, and on a
    /// large index those guesses go wrong in exactly one direction: it
    /// picks the index that satisfies a DISTINCT or a GROUP BY over the
    /// one that cuts the row count, and scans the whole releases table.
    /// Measured 2 Aug on the live 32M-release index, which had never been
    /// analyzed: `wall2`'s card COUNT took 85s, and 0.38s once these
    /// statistics existed - a 224x difference in one query, from a plan
    /// that flipped from "scan 32M releases, probe titles" to "scan 8.9k
    /// titles, probe releases".
    ///
    /// `analysis_limit` is what makes this affordable to run on a
    /// schedule: statistics are gathered from a bounded sample per index
    /// rather than a full pass. `PRAGMA optimize` then does
    /// nothing at all on the passes where nothing has changed enough to
    /// matter - but it only reconsiders tables this connection has
    /// queried, so a database with no statistics AT ALL gets a plain
    /// ANALYZE (still under the sample limit) to guarantee a first set.
    ///
    /// It is the FIRST set, not the right one, and this function is no
    /// longer the whole story. The sampled numbers are 24x to 5,554x low
    /// on a real index and carry no STAT4 samples at all, which costs
    /// one measured plan; the measurement, what it steers and what fixes
    /// it are in [`Self::shallow_stat_index`], and the daemon deepens
    /// one index per maintenance pass on top of this. Nothing here
    /// changes: a cheap pass that lands a usable set in seconds on a
    /// fresh install is still the right first move, and the deep leg is
    /// built to repair what this leaves behind rather than to replace
    /// it.
    ///
    /// Slow on the first run against a big unanalyzed database (~3
    /// minutes on the 45 GB live index) and it holds the write
    /// connection throughout, so it belongs in a maintenance leg behind
    /// the same "nothing is downloading" gate as the prune.
    pub fn optimize(&self) -> rusqlite::Result<()> {
        self.db.execute_batch("PRAGMA analysis_limit=1000")?;
        let analyzed: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'sqlite_stat1'",
            [],
            |r| r.get(0),
        )?;
        if analyzed > 0 {
            self.db.execute_batch("PRAGMA optimize")
        } else {
            self.db.execute_batch("ANALYZE")
        }
    }

    /// TODO 198 tail: the next index whose statistics are still a
    /// SAMPLE rather than a measurement, biggest first - or `None` once
    /// every index in this database has been measured properly.
    ///
    /// `PRAGMA analysis_limit=1000` above does two things, and only one
    /// of them is the approximation its own documentation describes.
    ///
    /// The documented half: the per-value estimates in `sqlite_stat1`
    /// are computed from the rows ANALYZE visited rather than from the
    /// index, so they are capped near the limit. Measured 22 Aug 2026 on
    /// a 33,359,631-release / 51 GB index, `idx_rel_kind` records
    /// **1001** rows per `kind` value against a true **5,559,939** - a
    /// 5,554x under-count - and it is not one index's problem: every
    /// index on `releases` comes back 24x to 109x low (`idx_rel_stem`
    /// 1 against 26, `idx_rel_seen` 23 against 2502, `idx_rel_posted` 2
    /// against 99).
    ///
    /// The undocumented half, and the one that decides the shape of this
    /// function: ANY non-zero limit turns STAT4 off entirely. In
    /// `analyze.c` the sample budget is `p->mxSample = p->nLimit==0 ?
    /// mxSample : 0`, so a limited pass writes NO `sqlite_stat4` rows at
    /// all and the planner loses every per-value histogram - the thing
    /// that would tell it `kind='movie'` (5.6M rows) from `kind='tv'`
    /// (31k). That is also what makes the probe below exact rather than
    /// a heuristic: 24 samples per index is what a full pass leaves and
    /// zero is what a limited one leaves, so "has no `sqlite_stat4` row"
    /// IS "was analyzed under a limit". Verified on the same database:
    /// after a full pass all 52 non-empty indexes carry samples, so this
    /// converges to `None` rather than cycling.
    ///
    /// Self-healing by construction, which a stamp would not be:
    /// `PRAGMA optimize` re-analyzes a whole table (at the sampled
    /// limit, wiping its samples) whenever one of its indexes lacks a
    /// `sqlite_stat1` row - which is exactly what the B1 picker backfill
    /// produces when it lands a new index. Measured on the 2M-row
    /// fixture: build one index, and the next `PRAGMA optimize` resets
    /// `i_kind` from a measured 5,559,939-shaped row back to 1001 and
    /// deletes every sample. Reading the state out of the database means
    /// the next pass simply measures it again.
    ///
    /// Empty indexes are skipped: a full pass writes no samples for one,
    /// so including them would make this cycle forever. On a build
    /// without `SQLITE_ENABLE_STAT4` the probe errors and the whole leg
    /// is a permanent no-op, which is the right degradation - without
    /// the samples there is no way to tell a measured row from a
    /// sampled one. nzbkit's rusqlite is `bundled`, and that build
    /// defines it.
    pub fn shallow_stat_index(&self) -> Option<String> {
        self.db
            .query_row(
                "SELECT s.idx FROM sqlite_stat1 s
                  WHERE s.idx IS NOT NULL
                    AND CAST(s.stat AS INTEGER) > 0
                    AND NOT EXISTS(SELECT 1 FROM sqlite_stat4 x
                                    WHERE x.idx = s.idx)
                  ORDER BY CAST(s.stat AS INTEGER) DESC, s.idx LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok()
    }

    /// Measure one index's statistics with no sample limit (TODO 198
    /// tail). The caller owns picking it - [`Self::shallow_stat_index`]
    /// - and owns making the work abortable: this reads the whole index
    /// holding the write lock, exactly like `build_picker_index`, so the
    /// daemon runs it on a blocking thread under a `MaintenanceArm` and
    /// an interrupt rolls it back for the next pass to retry.
    ///
    /// One index, not the database, because the cost is per index and
    /// wildly uneven: on the 33.4M-release index the whole-database pass
    /// is 238 s, but `idx_rel_complete_kind` is 0.1 s of it and
    /// `idx_rel_stem` 74.4 s. A per-index pass makes the unit of work
    /// bounded and, unlike a whole-database ANALYZE (one transaction),
    /// makes an interrupted pass keep everything it had already
    /// measured.
    ///
    /// ANALYZE of one index replaces only that index's rows, in both
    /// stat tables - verified on the live-shaped index: after measuring
    /// six of them by name the other twelve still carried their sampled
    /// values. The name is a database identifier from `sqlite_stat1`,
    /// not caller text.
    pub fn analyze_index_deep(&self, name: &str) -> rusqlite::Result<()> {
        // `analysis_limit` is per connection and sticky: the daemon's
        // writer has had it set to 1000 by `optimize` since the first
        // maintenance pass, and leaving it there would make this
        // statement a second sampled pass that looks like a deep one.
        self.db.execute_batch("PRAGMA analysis_limit=0")?;
        let r = self
            .db
            .execute_batch(&format!("ANALYZE main.\"{}\"", name.replace('"', "\"\"")));
        // Back to the sampled limit whatever happened, so the next
        // `PRAGMA optimize` on this connection stays the cheap pass it
        // is meant to be.
        self.db.execute_batch("PRAGMA analysis_limit=1000")?;
        r
    }

    /// B1: the first deferred partial index this database is still
    /// missing, if any - `Index::open` only builds them inline under
    /// `PICKER_INDEX_INLINE_MAX`, so a large pre-existing index reaches
    /// here without them and the daemon's maintenance pass backfills
    /// them one per pass through `build_picker_index`. sqlite_master
    /// presence IS the state; once all of `picker_index_ddl` exists
    /// this is a sub-millisecond catalog probe.
    pub fn missing_picker_index(&self) -> Option<&'static str> {
        super::schema::picker_index_ddl()
            .into_iter()
            .map(|(name, _)| name)
            .find(|name| {
                !self
                    .db
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master
                          WHERE type='index' AND name=?1)",
                        [name],
                        |r| r.get::<_, bool>(0),
                    )
                    .unwrap_or(true)
            })
    }

    /// Test hook: drop every picker index and push `MAX(id)` past the
    /// inline bound, so the next `Index::open` declines to create them
    /// and the database reaches the daemon in the DEFERRED state - the
    /// one a real installation is in after growing past the threshold.
    ///
    /// Reproducing that state honestly would mean writing a million
    /// releases into a test database; the bound is read from `MAX(id)`
    /// precisely because it is an O(1) proxy, so one high-id row is the
    /// same state by the code's own definition.
    #[doc(hidden)]
    pub fn debug_defer_picker_indexes(&self) {
        for (name, _) in super::schema::picker_index_ddl() {
            let _ = self.db.execute(&format!("DROP INDEX IF EXISTS {name}"), []);
        }
        self.db
            .execute(
                "INSERT INTO releases(id, stem, poster, grp)
                   VALUES (?1, 'deferred-bound', 'p', 'g')",
                [super::schema::PICKER_INDEX_INLINE_MAX + 1],
            )
            .expect("seed the deferred-state row");
    }

    /// Build one named picker index (from `missing_picker_index`).
    /// CREATE INDEX reads the whole `releases` table once holding the
    /// write lock, so the caller owns making that visible and abortable
    /// - the daemon runs this on a blocking thread under a
    /// `MaintenanceArm`, exactly the ANALYZE shape, and an interrupt
    /// rolls the build back cleanly for the next pass to retry.
    pub fn build_picker_index(&self, name: &str) -> rusqlite::Result<()> {
        let Some((_, ddl)) = super::schema::picker_index_ddl()
            .into_iter()
            .find(|(n, _)| *n == name)
        else {
            return Ok(());
        };
        self.db.execute_batch(&ddl)
    }

    /// A handle another thread can use to abort whatever statement this
    /// connection is currently running.
    ///
    /// It exists for `compact()`, which since §95 is only the one-time
    /// migration to incremental auto-vacuum - the routine path is
    /// `compact_chunk`, which needs no interrupt because a chunk is
    /// short by construction. Everything below is why that change was
    /// worth making, and still applies to the migration rewrite.
    ///
    /// On a multi-GB index a VACUUM is minutes
    /// of synchronous rewriting, and it is held under the same gate that
    /// a starting download waits on - so a job that arrives one moment
    /// after the "is anything downloading?" check sits in `Downloading`,
    /// making no progress and logging nothing, until the rewrite ends.
    /// VACUUM is a single transaction, so aborting it leaves the database
    /// exactly as it was and costs only the work done so far.
    ///
    /// Interrupting is per-CONNECTION, not per-statement: only call this
    /// while you know the statement you mean to stop is the one running.
    ///
    /// It also does not abort a VACUUM at an arbitrary point, which is
    /// easy to assume and wrong. The flag is only read from the VDBE, so
    /// it reaches the phase that copies live pages into the temp
    /// database and not the `sqlite3BtreeCopyFile` tail that writes the
    /// result back over the original - a job arriving during the tail
    /// still waits it out.
    ///
    /// Measured on Windows against an 80 MB index, 20 000 rows of 4 KB
    /// with half deleted (interrupt once at a fixed offset, sweep the
    /// offset - the abort test now builds a tenth of that, because a
    /// progress handler needs opcodes rather than time): the rewrite
    /// stops accepting an interrupt after the first few hundred
    /// milliseconds, out of ~2 s idle and ~6 s with the cores busy. The
    /// abortable part runs at memory speed - temp_store=MEMORY over a
    /// cache that just wrote the data - while the tail is disk-bound, so
    /// load and size both stretch the tail and leave the window where it
    /// was. The abortable FRACTION therefore shrinks exactly when the
    /// abort matters most, and on the multi-GB index this exists for it
    /// is small. Interrupting still helps and still costs nothing; it is
    /// just not the guarantee the name suggests.
    pub fn interrupt_handle(&self) -> InterruptHandle {
        self.db.get_interrupt_handle()
    }

    // -- M32: size cap + eviction (types and SQL near the end of the file) --

    /// Current on-disk size: page_count * page_size, including the freelist.
    ///
    /// This is what the user sees in Finder/`ls`, so it is what the cap
    /// is expressed against - even though the freelist part of it is
    /// space DELETE has already released for reuse and only `compact()`
    /// can hand back to the filesystem.
    pub fn db_bytes(&self) -> rusqlite::Result<u64> {
        let pages: i64 = self.db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let size: i64 = self.db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok(pages.max(0) as u64 * size.max(0) as u64)
    }

    /// Bytes of the file that still hold live content: `db_bytes()` minus
    /// the freelist. This - not `db_bytes()` - is what eviction can move,
    /// and it is the size the file WOULD have after a `compact()`, so it
    /// is the honest quantity to compare against the user's cap.
    ///
    /// It over-states live content by the free space stranded inside
    /// partially-emptied pages, which the freelist does not count. For
    /// this schema that error is small: the bulk of the bytes are the
    /// `files.segments` blobs, which live on overflow chains that are
    /// released whole when their row goes.
    ///
    /// PUBLIC, and deliberately so: the daemon compares the user's cap
    /// against THIS, not against `db_bytes()`. Comparing against the raw
    /// file size meant an evicted database never got back under its cap
    /// (DELETE frees pages to the freelist without shortening the file),
    /// so automatic eviction re-fired on every scan pass forever.
    pub fn live_bytes(&self) -> rusqlite::Result<u64> {
        let pages: i64 = self.db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let free: i64 = self
            .db
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        let size: i64 = self.db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok((pages - free).max(0) as u64 * size.max(0) as u64)
    }
}

#[cfg(test)]
mod tests;
