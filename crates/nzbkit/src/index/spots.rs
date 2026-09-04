//! Spotnet rows (TODO 106 phase 2.2, cut 1): the spots table's insert,
//! search, browse and NZB-synthesis methods plus their row types. Bodies
//! are verbatim moves from the old index.rs.

use super::*;

impl Index {
    /// The one insert both the single and the batch entry point run.
    const SPOT_INSERT: &'static str =
        "INSERT INTO spots(msgid, title, category, subcats, size, date,
                           spotter_id, verified, hashcash_ok, nzb_msgids)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(msgid) DO NOTHING";

    /// Bind one spot to [`Self::SPOT_INSERT`]; `Ok(true)` if the row was
    /// new, `Ok(false)` if the message-id was already indexed.
    fn insert_spot_stmt(stmt: &mut rusqlite::Statement<'_>, s: &Spot) -> rusqlite::Result<bool> {
        let n = stmt.execute(rusqlite::params![
            s.msgid,
            s.title,
            s.category,
            s.subcats,
            s.size as i64,
            s.date,
            s.spotter_id,
            s.verified,
            s.hashcash_ok,
            serde_json::to_string(&s.nzb_msgids).unwrap(),
        ])?;
        Ok(n > 0)
    }

    /// Insert one verified spot; `Ok(true)` if it was new, `Ok(false)` if
    /// the message-id was already indexed.
    ///
    /// One autocommit transaction per call. That is fine for the odd
    /// single insert (and for the tests), but a scan pass holds thousands
    /// of spots per OVER chunk - use [`Self::insert_spots`] there.
    pub fn insert_spot(&self, s: &Spot) -> rusqlite::Result<bool> {
        let mut stmt = self.db.prepare_cached(Self::SPOT_INSERT)?;
        Self::insert_spot_stmt(&mut stmt, s)
    }

    /// Insert a whole OVER chunk's worth of verified spots in ONE
    /// transaction; returns how many rows were new.
    ///
    /// The per-row [`Self::insert_spot`] was one write transaction each -
    /// its own lock acquisition, its own WAL commit and fsync - thousands
    /// of times per chunk. The header scanner already batches its chunk
    /// the same way (`ingest::ingest_pass`), and for the same reason.
    ///
    /// IMMEDIATE, not the default DEFERRED, for the reason written up at
    /// that call site: a deferred transaction upgrades to a write lock
    /// lazily and SQLite does NOT apply the busy timeout to the upgrade,
    /// so a concurrent writer fails the whole batch outright instead of
    /// waiting for it.
    ///
    /// Crash semantics only improve: the scan's high-water mark is
    /// written after the batch, so a crash mid-batch re-reads the same
    /// articles next pass and the insert is `ON CONFLICT DO NOTHING`.
    /// Before this, a crash could leave part of a chunk stored with the
    /// mark still behind it - the same outcome, reached less tidily.
    pub fn insert_spots(&mut self, spots: &[Spot]) -> rusqlite::Result<usize> {
        if spots.is_empty() {
            return Ok(0);
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut new = 0usize;
        {
            let mut stmt = tx.prepare_cached(Self::SPOT_INSERT)?;
            for s in spots {
                if Self::insert_spot_stmt(&mut stmt, s)? {
                    new += 1;
                }
            }
        }
        tx.commit()?;
        Ok(new)
    }

    /// Search spots by title substring (case-insensitive), newest first.
    pub fn spot_search(&self, query: &str, limit: u32) -> rusqlite::Result<Vec<Spot>> {
        let mut stmt = self.db.prepare(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots WHERE title LIKE '%' || ?1 || '%'
             ORDER BY date DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![query, limit], spot_from_row)?;
        rows.collect()
    }

    /// A Browse page of spots: newest first, with paging and a total.
    ///
    /// `include_adult` is off by default because a third of free.pt is
    /// erotica (4,884 of 15,258 spots measured on a live scan) and it
    /// would otherwise be most of what a first search returns. The
    /// marker is the `d75` subcategory, which separates cleanly - it is
    /// what the poster themselves filed the spot under.
    pub fn spot_browse(&self, q: &SpotQuery) -> rusqlite::Result<(Vec<Spot>, u64)> {
        let mut where_sql = String::from(" WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if !q.q.trim().is_empty() {
            where_sql.push_str(" AND title LIKE '%' || ? || '%'");
            args.push(Box::new(q.q.trim().to_string()));
        }
        if let Some(c) = q.category {
            where_sql.push_str(" AND category = ?");
            args.push(Box::new(c));
        }
        if !q.include_adult {
            where_sql.push_str(&format!(
                " AND ',' || subcats || ',' NOT LIKE '%,{ADULT_SUBCAT},%'"
            ));
        }
        // Moderation records are no longer stored (nzbkit::spot::is_moderation),
        // but a database scanned before that are still full of them, and they
        // read like releases. Cheaper to exclude here than to migrate.
        where_sql.push_str(" AND title NOT LIKE 'DISPOSE %'");
        let params: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();

        let total: i64 = self.db.query_row(
            &format!("SELECT COUNT(*) FROM spots{where_sql}"),
            params.as_slice(),
            |r| r.get(0),
        )?;

        let mut page = params.clone();
        let (limit, offset) = (q.limit.clamp(1, 500) as i64, q.offset as i64);
        page.push(&limit);
        page.push(&offset);
        let mut stmt = self.db.prepare(&format!(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots{where_sql} ORDER BY date DESC, id DESC LIMIT ? OFFSET ?"
        ))?;
        let rows = stmt.query_map(page.as_slice(), spot_from_row)?;
        Ok((rows.collect::<rusqlite::Result<Vec<_>>>()?, total as u64))
    }

    pub fn spot_by_msgid(&self, msgid: &str) -> rusqlite::Result<Option<Spot>> {
        let mut stmt = self.db.prepare(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots WHERE msgid=?1",
        )?;
        let mut rows = stmt.query_map([msgid], spot_from_row)?;
        rows.next().transpose()
    }

    /// Cache the NZB payload segment ids once a spot has been fetched.
    pub fn set_spot_nzb(&self, msgid: &str, segment_ids: &[String]) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE spots SET nzb_msgids=?2 WHERE msgid=?1",
            rusqlite::params![msgid, serde_json::to_string(segment_ids).unwrap()],
        )?;
        Ok(())
    }

    pub fn spot_stats(&self) -> rusqlite::Result<u64> {
        self.db
            .query_row("SELECT COUNT(*) FROM spots", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
    }

    /// The one article a spot-born release's declared completeness is
    /// worth corroborating against: the lowest-numbered segment of its
    /// largest file, bracketed as every msgid is stored here.
    ///
    /// LARGEST, not first in the NZB. Sidecars (`.par2`, `.nfo`, a
    /// sample) are routinely posted in a different run from the payload
    /// and expire on their own schedule, so asking about one answers a
    /// question nobody asked; the biggest file is the content itself
    /// and the article a download would reach for first. Lowest segment
    /// because that is the one part every file has.
    pub fn release_head_article(&self, rid: i64) -> rusqlite::Result<Option<String>> {
        let segs: Option<SegList> = self
            .db
            .prepare_cached(
                "SELECT segments FROM files WHERE release_id=?1
                 ORDER BY bytes DESC, filename ASC LIMIT 1",
            )?
            .query_row([rid], |r| r.get(0))
            .optional()?;
        let Some(SegList(mut parsed)) = segs else {
            return Ok(None);
        };
        parsed.sort_by_key(|(n, _, _)| *n);
        Ok(parsed.into_iter().next().map(|(_, id, _)| id))
    }

    /// Record what one corroborating STAT said about a promoted spot,
    /// and make the card say the same thing.
    ///
    /// A spot-born release's `complete` is computed from the segments
    /// the NZB declares about itself - every part accounted for,
    /// because the document listing them is the same document claiming
    /// they exist. Nothing on that path has ever asked a provider. At
    /// the tip that is usually harmless; at depth it is not, and the
    /// spot catalogue now walks back to 2011.
    ///
    /// So an absent head article demotes the card to incomplete. It is
    /// not a census - one article cannot prove the other 5,000 are
    /// there - but it is the difference between "nobody has ever
    /// looked" and "we looked once and the post is gone", and it is one
    /// round trip with no body transfer.
    ///
    /// The verdict is not permanent by design: if the header scanner
    /// later ingests real files for this release, its own aggregate
    /// recompute wins, and that recompute is grounded in articles the
    /// scanner actually saw on the wire.
    pub fn spot_stat_verdict(
        &self,
        spot_msgid: &str,
        rid: i64,
        present: bool,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE spots SET stat_ok=?2 WHERE msgid=?1",
            rusqlite::params![spot_msgid, if present { 1 } else { 2 }],
        )?;
        if !present {
            self.db
                .execute("UPDATE releases SET complete=0 WHERE id=?1", [rid])?;
        }
        Ok(())
    }

    /// Corroboration tallies for the readout: (checked, gone).
    pub fn spot_stat_counts(&self) -> rusqlite::Result<(u64, u64)> {
        self.db.query_row(
            "SELECT COALESCE(SUM(stat_ok>0),0), COALESCE(SUM(stat_ok=2),0) FROM spots",
            [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )
    }

    /// One page of spots the resolver still owes an NZB fetch, newest
    /// first. Excludes legacy moderation records and spots whose fetch
    /// has failed `SPOT_NZB_TRIES` times.
    ///
    /// Adult spots used to be excluded here too, and that was a
    /// workaround standing in for a missing marker: the wall's adult
    /// filter reads enriched genres, a fresh card has none, so a
    /// promoted `d75` card would have sailed straight past
    /// `wall_hide_adult`. Not promoting them kept the wall right and
    /// cost the catalogue 31% of the feed - the largest single hole in
    /// it. Now `promote_spot` marks the card `adult` from the spot's
    /// own subcategory and [`ADULT_MARK_SQL`] filters on that, so the
    /// setting works and the rows exist. What the user sees by default
    /// is unchanged: `wall_hide_adult` is on, the raw Spots list still
    /// hides them behind Include adult.
    pub fn spots_unresolved(&self, limit: u32) -> rusqlite::Result<Vec<Spot>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots
             WHERE release_id=0 AND nzb_tried < {SPOT_NZB_TRIES}
               AND title NOT LIKE 'DISPOSE %'
             ORDER BY date DESC, id DESC LIMIT ?1"
        ))?;
        let rows = stmt.query_map([limit], spot_from_row)?;
        rows.collect()
    }

    /// Record a failed NZB fetch; after `SPOT_NZB_TRIES` of these the
    /// resolver stops spending budget on the spot (its payload articles
    /// are usually just gone from the provider).
    pub fn spot_nzb_failed(&self, msgid: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE spots SET nzb_tried=nzb_tried+1 WHERE msgid=?1",
            [msgid],
        )?;
        Ok(())
    }

    /// One-shot repair of spot cards named with XML markup instead of a
    /// title: `parse_spot_xml` used to hand `<![CDATA[Shark Night
    /// (2011) R5 LiNE XviD - MiSTERE]]>` straight to the wall, because
    /// it entity-unescaped the element text without unwrapping CDATA.
    /// 54 cards on a live index, 6.5% of its spot catalogue, and a
    /// much larger share the deeper the feed is read - the 2011 depth
    /// sample is CDATA throughout.
    ///
    /// Driven from `spots` (a few tens of thousands of rows with an
    /// indexed `release_id`), never from a `releases` scan: the live
    /// table is 15.5 M rows and `pre_title` has no index. The name is
    /// cleared and re-applied through `apply_named` rather than
    /// UPDATEd, so `title_key`, `kind`, `junk`, the FTS row and the
    /// watchlist all re-derive from the corrected title - a bare
    /// `pre_title` write would leave a card that searches under its own
    /// markup.
    pub fn repair_cdata_spot_titles(&mut self, now: i64) -> rusqlite::Result<usize> {
        if self.kv_get("spot_cdata_fix_v1").is_some() {
            return Ok(0);
        }
        let broken: Vec<(i64, String, String)> = {
            let mut stmt = self.db.prepare(
                "SELECT r.id, r.pre_title, r.pre_source
                   FROM spots s JOIN releases r ON r.id=s.release_id
                  WHERE s.release_id>0 AND r.pre_title LIKE '%CDATA[%'",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut fixed = 0usize;
        for (rid, stored, label) in &broken {
            let Some(inner) = strip_stored_cdata(stored) else {
                continue;
            };
            let title = crate::release::sanitize_name(inner.trim());
            // The refusals promote_spot applies to a fresh title. A row
            // that cannot produce a usable one keeps its markup rather
            // than losing its name outright; there is nothing better to
            // put there without refetching the spot.
            if title.is_empty()
                || title.contains('/')
                || title.contains('\\')
                || title.starts_with('.')
                || title.contains("CDATA[")
            {
                continue;
            }
            // The row's OWN label, not a hardcoded `spot`: the repair
            // clears `pre_title` to re-derive through the naming seam,
            // and re-stamping the legacy label would quietly demote a
            // `proven:msgid-set:spot` row back to the unarbitrable
            // i32::MAX grade that `applied_strength` gives anything
            // without a `proven:` prefix.
            // One transaction for the clear-and-reapply pair: as two
            // autocommit statements, an error or kill between them left
            // the row permanently un-named AND outside the driving LIKE
            // predicate, so the re-run never revisited it. apply_named
            // runs on the same connection, so it joins this transaction;
            // an error unwinds the clear.
            let tx = rusqlite::Transaction::new_unchecked(
                &self.db,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            tx.execute("UPDATE releases SET pre_title='' WHERE id=?1", [rid])?;
            if self.apply_named(*rid, &title, label, now)? {
                fixed += 1;
            }
            tx.commit()?;
        }
        self.kv_set("spot_cdata_fix_v1", "1")?;
        Ok(fixed)
    }

    /// One-shot provenance backfill for spot cards promoted before the
    /// fresh branch wrote a claim: put the ledger row on file and
    /// relabel `pre_source` from the bare `spot` to
    /// `proven:msgid-set:spot`.
    ///
    /// Without it the fix is future-only, and the whole existing
    /// spot-born population (862 rows on the live index, the largest
    /// named population there) keeps the defect the fix exists to
    /// close: `applied_strength` grades a non-`proven:` label at
    /// `i32::MAX`, so no byte proof can ever correct those titles.
    ///
    /// Driven from `spots` for the same reason the CDATA repair is -
    /// `spots` is small with an indexed `release_id`, `releases` is
    /// 15.5 M rows with no `pre_source` index. Only rows still holding
    /// the exact legacy label are touched, so a row some other lane has
    /// since proven is left alone.
    ///
    /// The claim key is derived from the release's CURRENT articles
    /// (lowest-numbered segment per file - what `promote_spot` keys),
    /// not from the `nzb_msgids` cache, which pre-dates the E3 fix on
    /// some rows and holds deflate-chunk ids that join nothing. On a
    /// row that later absorbed scanner files that set is wider than the
    /// spot's own payload was, so the key can differ from the one a
    /// re-promotion would compute: the claim is still about this
    /// release and this name, it just reads as independent of that
    /// re-promotion rather than identical to it. A row with no files
    /// has no article set to bind to and is left as it is - it also has
    /// nothing for a byte proof to read, so the grade cannot matter
    /// there the way it does for a row the archive can still speak for.
    ///
    /// A row whose claim the ledger REFUSES is relabelled all the same:
    /// see the note at that call.
    pub fn relabel_spot_names(&mut self, now: i64) -> rusqlite::Result<usize> {
        // v2: v1 left every row whose claim was refused on the legacy
        // label, and set its guard anyway, so those rows could never
        // heal. Bumping the key re-runs the pass once on an index that
        // already ran v1 - cheap, because the driving query only ever
        // sees rows still holding the legacy label, and by then that is
        // just the residue v1 skipped.
        if self.kv_get("spot_claim_ledger_v2").is_some() {
            return Ok(0);
        }
        let stale: Vec<(i64, String)> = {
            let mut stmt = self.db.prepare(
                "SELECT r.id, r.pre_title
                   FROM spots s JOIN releases r ON r.id=s.release_id
                  WHERE s.release_id>0 AND r.pre_source=?1 AND r.pre_title<>''",
            )?;
            let rows = stmt.query_map([SPOT_SOURCE], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let label = claims::proven_label(SPOT_EVIDENCE, SPOT_SOURCE);
        let mut done = 0usize;
        for (rid, title) in &stale {
            let mut payload: Vec<String> = Vec::new();
            {
                let mut stmt = self
                    .db
                    .prepare_cached("SELECT segments FROM files WHERE release_id=?1")?;
                let rows = stmt.query_map([rid], |r| r.get::<_, SegList>(0))?;
                for segs in rows {
                    let mut parsed = segs?.0;
                    parsed.sort_by_key(|(n, _, _)| *n);
                    if let Some((_, id, _)) = parsed.first() {
                        payload.push(id.clone());
                    }
                }
            }
            if payload.is_empty() {
                continue;
            }
            let claim = NameClaim {
                name: title.clone(),
                evidence: SPOT_EVIDENCE,
                key: msgid_set_key(payload.iter()),
                source: SPOT_SOURCE.into(),
            };
            // Relabel whether or not the claim could be FILED. The two
            // are separable: `applied_strength` reads `pre_source`
            // alone, so the label is the grade and the ledger row is
            // provenance on top of it.
            //
            // Skipping the relabel on a refused claim stranded exactly
            // the rows that most need grading down. `record_name_claim`
            // refuses a name holding a path separator, and the 13 rows
            // it refused on the live index are all spot titles where
            // `/` is ordinary punctuation - "Upscaled/Remastered",
            // "x86/x64", the Dutch "t/m 20". Today's promotion gate
            // rejects such a title outright, so no new ones appear;
            // these are pre-gate residue holding a name nothing can
            // correct, pinned at `i32::MAX` above every byte proof by
            // the very pass whose job was to make them arbitrable.
            self.record_name_claim(*rid, &claim, now)?;
            // Counted on the UPDATE, not the loop: 59 of the live
            // index's spots are spot-to-spot dedups sharing one
            // release, so the driving join hands the same row out
            // twice (953 rows for 862 releases). The claim insert is
            // idempotent and the second relabel is a no-op - the
            // COUNT should say so.
            done += self.db.execute(
                "UPDATE releases SET pre_source=?2 WHERE id=?1 AND pre_source=?3",
                rusqlite::params![rid, label, SPOT_SOURCE],
            )?;
        }
        self.kv_set("spot_claim_ledger_v2", "1")?;
        Ok(done)
    }

    /// Fold one fetched spot NZB into `releases` as a first-class named
    /// row (E3 / TODO 131: Spotnet as a catalogue-addition source).
    ///
    /// If the post is already indexed - found through the identity
    /// substrate's reverse message-id lookup, quorum-checked here - the
    /// existing row takes the spot's signed title through the claims
    /// ledger and no twin card is created (the ~0.6% dedup case). A row
    /// that merely shares the (stem, poster, grp) triple is NOT that
    /// post - see the note at the fresh-row upsert - and a repost with
    /// fresh article ids gets a release of its own.
    ///
    /// Otherwise the NZB's files become real `files` rows and a new
    /// release is inserted and named the same way, so cards, enrichment,
    /// watch arrivals and NZB synthesis all work unchanged.
    ///
    /// One promotion, one commit (savepoint): the fresh path is a
    /// half-dozen statements (release upsert, files, msgid_map,
    /// aggregates, name), and a promotion interrupted between them
    /// used to take the OTHER branch on redo - the half-built row was
    /// findable by its msgids, so the next pass "upgraded" it, naming
    /// a card that never got its aggregates (0 files / 0 bytes,
    /// forever). Rolled back whole, the redo genuinely redoes.
    pub fn promote_spot(
        &mut self,
        spot_msgid: &str,
        title: &str,
        nzb: &crate::nzb::Nzb,
        now: i64,
    ) -> rusqlite::Result<SpotPromotion> {
        // The same refusals every other title path enforces
        // (apply_proven_name applies them to the Upgraded branch, but
        // the fresh branch's apply_named only trims): a signed spot is
        // authenticated, not trustworthy, and its title becomes a wall
        // card, a watchlist input and an FTS row.
        let raw = title.trim();
        if raw.contains('/') || raw.contains('\\') || raw.starts_with('.') {
            self.db.execute(
                &format!("UPDATE spots SET nzb_tried={SPOT_NZB_TRIES} WHERE msgid=?1"),
                [spot_msgid],
            )?;
            return Ok(SpotPromotion::Unusable);
        }
        let title = crate::release::sanitize_name(raw);
        if title.is_empty() {
            self.db.execute(
                &format!("UPDATE spots SET nzb_tried={SPOT_NZB_TRIES} WHERE msgid=?1"),
                [spot_msgid],
            )?;
            return Ok(SpotPromotion::Unusable);
        }
        self.db.execute_batch("SAVEPOINT promote_spot")?;
        let out = self.promote_spot_locked(spot_msgid, &title, nzb, now);
        match &out {
            Ok(_) => self.db.execute_batch("RELEASE promote_spot")?,
            Err(_) => {
                let _ = self
                    .db
                    .execute_batch("ROLLBACK TO promote_spot; RELEASE promote_spot");
            }
        }
        out
    }

    fn promote_spot_locked(
        &mut self,
        spot_msgid: &str,
        title: &str,
        nzb: &crate::nzb::Nzb,
        now: i64,
    ) -> rusqlite::Result<SpotPromotion> {
        // Per-file shape, mirroring the scanner's ingest: quoted
        // filename from the subject (whole subject when nothing is
        // quoted), bracketed message-ids as OVER stores them.
        struct PromoFile {
            fname: String,
            total: u32,
            parts: Vec<(u32, String, u64)>,
        }
        let mut files: Vec<PromoFile> = Vec::new();
        let mut stems: HashMap<String, usize> = HashMap::new();
        let mut grps: HashMap<String, usize> = HashMap::new();
        let mut posters: HashMap<String, usize> = HashMap::new();
        let mut first_posted = i64::MAX;
        for f in &nzb.files {
            let base = ingest::split_subject(&f.subject)
                .map(|(b, _, _)| b)
                .unwrap_or_else(|| f.subject.clone());
            let fname = ingest::quoted_name(&base).unwrap_or(base);
            if fname.trim().is_empty() || f.segments.is_empty() {
                continue;
            }
            let mut parts: Vec<(u32, String, u64)> = f
                .segments
                .iter()
                .map(|s| (s.number, format!("<{}>", s.message_id), s.bytes))
                .collect();
            parts.sort_by_key(|(n, _, _)| *n);
            parts.dedup_by_key(|(n, _, _)| *n);
            // Declared-but-refused segments still count toward the
            // total, same contract as the NZB downloader's.
            let declared = (f.segments.len() + f.dropped_segments) as u32;
            let total = parts.last().map(|(n, _, _)| *n).unwrap_or(0).max(declared);
            *stems.entry(crate::names::release_stem(&fname)).or_insert(0) += 1;
            for g in &f.groups {
                *grps.entry(g.clone()).or_insert(0) += 1;
            }
            *posters.entry(f.poster.clone()).or_insert(0) += 1;
            if f.date > 0 {
                first_posted = first_posted.min(f.date);
            }
            files.push(PromoFile {
                fname,
                total,
                parts,
            });
        }
        let payload: Vec<String> = files
            .iter()
            .filter_map(|f| f.parts.first())
            .map(|(_, id, _)| id.clone())
            .collect();
        let by_count = |m: &HashMap<String, usize>| {
            m.iter()
                .max_by_key(|(k, n)| (**n, std::cmp::Reverse(k.as_str().to_string())))
                .map(|(k, _)| k.clone())
        };
        let (Some(stem), Some(grp)) = (by_count(&stems), by_count(&grps)) else {
            // Nothing usable in the NZB: remember what we learned and
            // stop spending fetches on it.
            self.set_spot_nzb(spot_msgid, &payload)?;
            self.db.execute(
                &format!("UPDATE spots SET nzb_tried={SPOT_NZB_TRIES} WHERE msgid=?1"),
                [spot_msgid],
            )?;
            return Ok(SpotPromotion::Unusable);
        };
        let poster = by_count(&posters).unwrap_or_default();

        // Dedup: the identity substrate's reverse message-id lookup
        // (the same join E3 measured at ~0.6%). The CALLER owns the
        // quorum - a hostile spot NZB can embed one real id - so two
        // matched ids always suffice, and a single-file spot (which can
        // only ever match one) must ALSO agree on the posted stem. The
        // hit is booked through apply_proven_name as MsgidSet evidence,
        // so a conflicting or weaker existing name is arbitrated and
        // ledgered instead of silently dropped.
        let hits = self.find_releases_by_msgids(payload.iter().map(String::as_str))?;
        let set_key = msgid_set_key(payload.iter());
        if let Some(&(rid, matched)) = hits.first() {
            let quorum = matched >= 2
                || (payload.len() == 1 && matched == 1 && {
                    let victim: Option<String> = self
                        .db
                        .prepare_cached("SELECT stem FROM releases WHERE id=?1")?
                        .query_row([rid], |r| r.get(0))
                        .optional()?;
                    victim.as_deref() == Some(stem.as_str())
                });
            if quorum {
                let claim = NameClaim {
                    name: title.to_string(),
                    evidence: SPOT_EVIDENCE,
                    key: set_key.clone(),
                    source: SPOT_SOURCE.into(),
                };
                let _ = self.apply_proven_name(rid, &claim, now)?;
                self.set_spot_nzb(spot_msgid, &payload)?;
                self.db.execute(
                    "UPDATE spots SET release_id=?2 WHERE msgid=?1",
                    rusqlite::params![spot_msgid, rid],
                )?;
                return Ok(SpotPromotion::Upgraded(rid));
            }
        }

        // Fresh row: the same upsert + merge the scanner's ingest uses,
        // minus its gates - spots are their own switched source, curated
        // by signature verification instead. Same clamp as ingest: the
        // Date attribute is untrusted input and a far-future value would
        // pin the card atop every Latest view and dodge the retention
        // prunes.
        let up = if first_posted == i64::MAX {
            now
        } else {
            first_posted.min(now + 86_400)
        };
        // (stem, poster, grp) is the SCANNER's release identity, and
        // upserting onto it is right whenever the row it lands on holds
        // the post this spot describes. It is wrong when the same poster
        // reposts the same name to the same group with FRESH article ids
        // (a re-rar, a repair repost, an automated reposter's second
        // pass): the upsert hands generation 2 the row of generation 1,
        // ON CONFLICT(release_id, filename) overwrites its manifest,
        // apply_named renames its card, and the new message-ids resolve
        // to it forever. One row, two generations, and a synthesised NZB
        // that mixes both into a "complete" download of garbage.
        //
        // So the triple decides where to LOOK; the article set decides
        // whether to adopt. `hits` is the reverse message-id lookup for
        // this exact payload: any overlap at all - short of the naming
        // quorum above, which is a higher bar because it licenses a
        // RENAME - still proves the row and the spot share articles.
        // Zero overlap against a row that is itself keyed into
        // msgid_map is the opposite proof, and that spot gets its own
        // release rather than the collision.
        //
        // The msgid_map coverage test is load-bearing, not belt: the map
        // backfills over many index opens, and on an index that has not
        // converged yet an unkeyed row would read as "disjoint" from
        // every spot and mint a twin card for the ~0.6% case the dedup
        // exists to catch. Unkeyed means unknown, and unknown keeps the
        // old adopt-in-place behaviour.
        let mut poster_key = poster.clone();
        let prior: Option<i64> = self
            .db
            .prepare_cached("SELECT id FROM releases WHERE stem=?1 AND poster=?2 AND grp=?3")?
            .query_row(rusqlite::params![stem, poster, grp], |r| r.get(0))
            .optional()?;
        if let Some(prior) = prior
            && !hits.iter().any(|&(r, n)| r == prior && n > 0)
        {
            let keyed: bool = self
                .db
                .prepare_cached("SELECT EXISTS(SELECT 1 FROM msgid_map WHERE release_id=?1)")?
                .query_row([prior], |r| r.get(0))?;
            // ...or the backfill has FINISHED, which answers the same
            // question for the whole index at once. "Unkeyed means
            // unknown" was true only while the map was still filling in;
            // once `msgid_map_fill` is set, every release that has
            // articles has its keys, so an unkeyed row with zero overlap
            // is positive proof of a different posting rather than an
            // index that has not caught up. Reading the flag closes the
            // upgrade window in which a fresh repost could still adopt
            // and overwrite an unrelated generation (H2, 10 Aug sweep).
            let converged: bool = self
                .db
                .prepare_cached(
                    "SELECT EXISTS(SELECT 1 FROM kv WHERE k='msgid_map_fill' AND v='1')",
                )?
                .query_row([], |r| r.get(0))?;
            if keyed || converged {
                poster_key = format!("{poster}{POSTER_GEN_MARK}{}", &set_key[..GEN_HEX]);
                warn!(
                    target: "index",
                    "spot {spot_msgid}: {stem} by {poster} in {grp} is already release \
                     {prior} with different articles - indexing this posting separately"
                );
            }
        }
        // Does the row this promotion is about to write already exist?
        // Only the adult marker below cares, and it cares a lot: see
        // the note at that write.
        let born_here = if poster_key == poster {
            prior.is_none()
        } else {
            self.db
                .prepare_cached("SELECT id FROM releases WHERE stem=?1 AND poster=?2 AND grp=?3")?
                .query_row(rusqlite::params![stem, poster_key, grp], |r| {
                    r.get::<_, i64>(0)
                })
                .optional()?
                .is_none()
        };
        self.db
            .prepare_cached(
                // stem_fold: the Unicode fold the LIKE search paths
                // need, '' for an ASCII stem. Not in the DO UPDATE arm
                // because `stem` is part of the conflict key - see the
                // same write in ingest.rs, and index/fold.rs.
                "INSERT INTO releases(stem, poster, grp, first_seen, first_posted, stem_fold)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(stem, poster, grp) DO UPDATE SET
                   first_posted=MIN(first_posted, excluded.first_posted)",
            )?
            .execute(rusqlite::params![
                stem,
                poster_key,
                grp,
                now,
                up,
                fold::stored(&stem)
            ])?;
        let rid: i64 = self
            .db
            .prepare_cached("SELECT id FROM releases WHERE stem=?1 AND poster=?2 AND grp=?3")?
            .query_row(rusqlite::params![stem, poster_key, grp], |r| r.get(0))?;
        for f in &files {
            let bytes: u64 = f.parts.iter().map(|(_, _, b)| *b).sum();
            let seg_blob = segcodec::encode(&f.parts);
            self.db
                .prepare_cached(
                    "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(release_id, filename) DO UPDATE SET
                       total_parts=excluded.total_parts, bytes=excluded.bytes,
                       segments=excluded.segments, nsegs=excluded.nsegs",
                )?
                .execute(rusqlite::params![
                    rid,
                    f.fname,
                    f.total,
                    bytes as i64,
                    seg_blob,
                    f.parts.len() as i64
                ])?;
            // Key into the reverse message-id map exactly as ingest
            // does, so later spots (and the posted-NZB lane) can find
            // this release by its articles - which is also what makes
            // a duplicate spot for the same post dedup instead of
            // minting a twin card.
            claims::msgid_map_insert(&self.db, rid, f.parts.iter().map(|(_, id, _)| id.as_str()))?;
        }
        // Aggregates, same formula as ingest. The naming-derived
        // columns (kind, junk, title_key, ...) come from apply_named
        // below, not from here.
        let agg = super::aggregates::RelAgg::recompute(&self.db, rid)?;
        self.db
            .prepare_cached(
                "UPDATE releases SET files=?2, total_bytes=?3, has_par2=?4, complete=?5,
                        have_parts=?6, need_parts=?7, nfiles_complete=?8, nfiles_exe=?9
                 WHERE id=?1",
            )?
            .execute(rusqlite::params![
                rid,
                agg.nfiles,
                agg.tbytes,
                agg.has_par2,
                agg.complete(),
                agg.have,
                agg.need,
                agg.ncomplete,
                agg.nexe
            ])?;
        // The poster's own adult filing, carried onto the card they
        // filed. This is what lets `wall_hide_adult` work on spot-born
        // cards at all - the genre test it runs on has nothing to read
        // until (and unless) enrichment reaches the title.
        //
        // ONLY on a row this promotion brought into being. A spot that
        // lands on a release the scanner already holds - by the msgid
        // quorum above, or by the (stem, poster, grp) upsert adopting
        // it here - is a claim about SOMEBODY ELSE'S row, and honoring
        // it would hand anyone who can publish a signed spot a way to
        // take an existing card off the default wall: Spotnet keys are
        // free, and the message-ids needed to aim at a post are in any
        // NZB of it. A row that exists only because of this spot has
        // nothing to lose that way.
        if born_here
            && self
                .db
                .prepare_cached("SELECT subcats FROM spots WHERE msgid=?1")?
                .query_row([spot_msgid], |r| r.get::<_, String>(0))
                .optional()?
                .is_some_and(|s| spot_is_adult(&s))
        {
            self.db
                .prepare_cached("UPDATE releases SET adult=1 WHERE id=?1")?
                .execute([rid])?;
        }
        // The same claim the dedup branch books, on the row this spot
        // just built. Two things ride on it.
        //
        // The LEDGER row, because a name with no claim behind it has no
        // provenance: `applied_strength` grades any `pre_source` that
        // is not `proven:` at `i32::MAX`, so a bare `spot` label held
        // every spot-born name above PAR2 set-ID and body-probe
        // evidence - a byte probe that reads the real filename out of
        // the archive could only ever log a Conflict against it. A spot
        // title is AUTHENTICATED (signed by its poster), not proven by
        // bytes, and self-signed keys are free. The label makes it
        // arbitrable: msgid-set tier, so archive bytes outrank it and
        // nothing weaker does. It also makes the ledger honest - spot
        // named 830 rows on the live index while reading as 7 there,
        // and a build order was very nearly cut on that number.
        //
        // The name is still applied DIRECTLY rather than through
        // `apply_proven_name`: that path prefers a readable stem over a
        // joined claim, which is right when a lane names somebody
        // else's row and wrong here - the stem is one filename out of
        // the very NZB this title announces. Measured on the live index
        // it would have refused 262 of 869 spot-named rows, mostly ones
        // where the spot title is the better name ("…-Retail", "NL
        // Subs", a real title over a blob stem).
        let claim = NameClaim {
            name: title.to_string(),
            evidence: SPOT_EVIDENCE,
            key: set_key,
            source: SPOT_SOURCE.into(),
        };
        if self.apply_named(
            rid,
            title,
            &claims::proven_label(SPOT_EVIDENCE, SPOT_SOURCE),
            now,
        )? {
            self.record_name_claim(rid, &claim, now)?;
        } else {
            // The upsert landed on a row that already has a name (an
            // earlier promotion, or the scanner reached the post
            // first): that IS a competing claim, so let the claims
            // layer arbitrate and ledger it instead of dropping the
            // spot's title on the floor.
            let _ = self.apply_proven_name(rid, &claim, now)?;
        }
        self.set_spot_nzb(spot_msgid, &payload)?;
        self.db.execute(
            "UPDATE spots SET release_id=?2 WHERE msgid=?1",
            rusqlite::params![spot_msgid, rid],
        )?;
        Ok(SpotPromotion::Promoted(rid))
    }
}

/// The title inside a stored CDATA wrapper, in either shape the live
/// index holds it.
///
/// Two shapes because the wrapper met `sanitize_name` on some paths and
/// not others: it maps `<` and `>` to spaces (they are illegal in
/// filenames on Windows), so the same spot is stored as
/// `<![CDATA[title]]>` on one path and `![CDATA[title]]` on another.
/// Returns `None` for anything that is not actually wrapped, so a title
/// that merely mentions CDATA is left alone.
fn strip_stored_cdata(stored: &str) -> Option<String> {
    let t = stored.trim();
    let body = t
        .strip_prefix("<![CDATA[")
        .or_else(|| t.strip_prefix("![CDATA["))?;
    let body = body
        .strip_suffix("]]>")
        .or_else(|| body.strip_suffix("]]"))
        .unwrap_or(body);
    Some(body.to_string())
}

/// How many times the resolver retries a spot's NZB fetch before
/// writing the spot off as list-only.
pub const SPOT_NZB_TRIES: i64 = 3;

/// How many completeness-corroborating STATs one resolver pass may
/// spend ([`Index::spot_stat_verdict`]).
///
/// One per freshly promoted card, and at the default budget of 40
/// spots per pass that reaches all of them - a STAT is a round trip
/// with no body, against a promotion that already cost a HEAD and
/// several BODYs. The cap is here for the other case: a deep backfill
/// with the resolve budget wound up (the setting goes to 1000) would
/// otherwise turn every pass into a STAT run of the same size. Spots
/// the cap does not reach keep the NZB's own declared verdict, which
/// is exactly what every spot-born card had before.
pub const SPOT_STAT_PER_PASS: u32 = 40;

/// The claims ladder tier a spot title enters at, on both promotion
/// branches. The BINDING is the spot's own NZB - the exact article set
/// this title is published about - which is what msgid-set means; the
/// `spot` source is what says who is asserting it. So archive bytes
/// (`body-probe`) outrank it and everything below msgid-set does not.
pub(super) const SPOT_EVIDENCE: NameEvidence = NameEvidence::MsgidSet;

/// The lane name in `name_claims.source`, and the tail of the
/// `proven:msgid-set:spot` provenance label. The wall's `spot` badge
/// matches that label and the legacy bare `spot` one.
pub(super) const SPOT_SOURCE: &str = "spot";

/// What `promote_spot` - and, since the scanner half landed, `ingest` -
/// appends to `releases.poster` when the post it is indexing collides
/// with a DIFFERENT post already holding the (stem, poster, grp)
/// triple. See the long note at the fresh-row upsert here, and
/// `ingest`'s `pick_release_row` for the scanner's detection half.
///
/// `releases` carries `UNIQUE(stem, poster, grp)` as a table
/// constraint, so the discriminator has to live inside one of the three
/// columns; `poster` is the only one that is not a join key elsewhere.
/// `stem` fans out to browse's one-card-per-stem dedup, predb lookups,
/// obfuscation scoring and the download-side stem correlation, and
/// `grp` is written verbatim into synthesised NZBs as the group to
/// fetch from. A marked poster costs only the (poster, grp) sidecar
/// folds in maintenance, which are the wrong thing to do across two
/// generations anyway, and `base_poster` keeps it out of make_nzb's
/// `poster=` attribute.
///
/// The suffix is the payload's canonical `msgid_set_key`, not an
/// ordinal, so it is a function of the articles: a redo of the same
/// spot lands on the same row instead of minting a third.
pub(super) const POSTER_GEN_MARK: &str = " #gen:";

/// How many hex characters of the msgid-set key `POSTER_GEN_MARK`
/// carries. 48 bits over the reposts of one name by one poster in one
/// group.
pub(super) const GEN_HEX: usize = 12;

/// The real `From` a `releases.poster` was built from, with any
/// [`POSTER_GEN_MARK`] discriminator removed. Only strips a suffix that
/// is exactly `GEN_HEX` lowercase hex digits, so a poster who really
/// does write " #gen:" survives intact.
pub(crate) fn base_poster(poster: &str) -> &str {
    let Some((head, tail)) = poster.rsplit_once(POSTER_GEN_MARK) else {
        return poster;
    };
    if tail.len() == GEN_HEX
        && tail
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        head
    } else {
        poster
    }
}

/// What [`Index::promote_spot`] did with a fetched spot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpotPromotion {
    /// The post was already indexed: the existing release took the
    /// spot's title (unless it was already named) and no twin card was
    /// created.
    Upgraded(i64),
    /// A fresh release row was created from the spot's NZB.
    Promoted(i64),
    /// The NZB parsed to nothing usable; the spot stays list-only.
    Unusable,
}

#[cfg(test)]
mod tests {
    use super::testutil::{entry, teardown};
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-spotpromo-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn spot(msgid: &str, title: &str, subcats: &str) -> Spot {
        Spot {
            id: 0,
            msgid: msgid.into(),
            title: title.into(),
            category: 0,
            subcats: subcats.into(),
            size: 4 << 30,
            date: 1_700_000_000,
            spotter_id: "sp1".into(),
            verified: true,
            hashcash_ok: true,
            nzb_msgids: Vec::new(),
        }
    }

    fn nzb_file(subject: &str, group: &str, segs: &[(u32, &str, u64)]) -> crate::nzb::NzbFile {
        crate::nzb::NzbFile {
            subject: subject.into(),
            poster: "spotter@x".into(),
            date: 1_700_000_000,
            groups: vec![group.into()],
            segments: segs
                .iter()
                .map(|(n, id, b)| crate::nzb::Segment {
                    number: *n,
                    bytes: *b,
                    message_id: (*id).into(),
                })
                .collect(),
            dropped_segments: 0,
        }
    }

    /// A fetched spot becomes a real, named, wall-visible release: files
    /// One OVER chunk is ONE transaction, and it stores exactly what the
    /// row-at-a-time path stored.
    ///
    /// `insert_spot` autocommits, so a scan pass paid a write lock, a WAL
    /// commit and an fsync per spot - thousands of them per chunk. The
    /// batch entry point has to be a drop-in for that: same rows, same
    /// `ON CONFLICT DO NOTHING` (a chunk re-read after a crash, or the
    /// deepening leg walking back through a band the forward leg already
    /// covered, must not duplicate anything), and the same "was it new?"
    /// answer, which is the scan summary's `new` count.
    #[test]
    fn a_spot_batch_is_one_transaction_and_ignores_what_it_already_holds() {
        let d = dir("batch");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let batch = vec![
            spot("<b1@spot>", "One.S01E01.1080p.WEB.x264-GRP", "a09"),
            spot("<b2@spot>", "Two.S01E01.1080p.WEB.x264-GRP", "a09"),
            // A duplicate INSIDE the batch: the OVER window can hand the
            // same message-id twice across a chunk boundary.
            spot("<b1@spot>", "One.S01E01.1080p.WEB.x264-GRP", "a09"),
        ];
        assert_eq!(
            ix.insert_spots(&batch).unwrap(),
            2,
            "two distinct message-ids are two new rows"
        );
        let q = SpotQuery {
            limit: 10,
            ..Default::default()
        };
        let (rows, total) = ix.spot_browse(&q).unwrap();
        assert_eq!((rows.len(), total), (2, 2));

        // Re-offering the whole chunk stores nothing and says so - this
        // is what makes the high-water mark safe to write AFTER the
        // batch rather than before it.
        assert_eq!(ix.insert_spots(&batch).unwrap(), 0);
        assert_eq!(ix.spot_browse(&q).unwrap().1, 2);

        // The single-row entry point still works and still agrees.
        assert!(!ix.insert_spot(&batch[0]).unwrap());
        assert!(
            ix.insert_spot(&spot("<b3@spot>", "Three.S01E01.1080p.WEB.x264-GRP", "a09"))
                .unwrap()
        );
        assert_eq!(ix.spot_browse(&q).unwrap().1, 3);

        // An empty chunk opens no transaction at all.
        assert_eq!(ix.insert_spots(&[]).unwrap(), 0);
        teardown(&d, ix);
    }

    /// rows from the NZB, the title through the sanctioned naming seam
    /// with its own provenance label, and an NZB synthesizable back out
    /// of the stored segments.
    #[test]
    fn a_promoted_spot_is_a_first_class_named_release() {
        let d = dir("fresh");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let s = spot("<sp1@spot>", "Some.Show.S01E01.1080p.WEB.x264-GRP", "a09");
        ix.insert_spot(&s).unwrap();
        assert_eq!(ix.spots_unresolved(10).unwrap().len(), 1);

        let nzb = crate::nzb::Nzb {
            files: vec![
                nzb_file(
                    r#""abc123xy.part01.rar" yEnc (1/2)"#,
                    "alt.binaries.misc",
                    &[(1, "d1@x", 2_000_000_000), (2, "d2@x", 2_000_000_000)],
                ),
                nzb_file(
                    r#""abc123xy.part02.rar" yEnc (1/1)"#,
                    "alt.binaries.misc",
                    &[(1, "d3@x", 1_000_000)],
                ),
            ],
            meta: Vec::new(),
        };
        let rid = match ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap() {
            SpotPromotion::Promoted(rid) => rid,
            other => panic!("expected a fresh release, got {other:?}"),
        };

        let rows = ix.search("Some Show", 10).unwrap();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.id, rid);
        // The posted identity stays the stem; the spot's signed title
        // rides pre_title with its own provenance label.
        assert_eq!(r.stem, "abc123xy");
        assert_eq!(r.pre_title, "Some.Show.S01E01.1080p.WEB.x264-GRP");
        // Provenance, not a bare lane tag: the label is what
        // `applied_strength` reads, and anything without a `proven:`
        // prefix is graded above every byte proof.
        assert_eq!(r.pre_source, "proven:msgid-set:spot");
        // ...and the ledger row that label promises, so a later proof
        // arbitrates against a claim instead of a bare name - and so
        // anything counting lanes by `name_claims` sees this one.
        let claims = ix.name_claims(rid).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "Some.Show.S01E01.1080p.WEB.x264-GRP");
        assert_eq!(claims[0].1, "msgid-set");
        assert_eq!(
            claims[0].2,
            msgid_set_key(["<d1@x>", "<d3@x>"]),
            "keyed on the payload set"
        );
        assert_eq!(claims[0].3, "spot");
        assert_eq!(r.grp, "alt.binaries.misc");
        assert!(r.complete, "every declared segment is present");
        let (junk, files): (i64, i64) = ix
            .db
            .query_row("SELECT junk, files FROM releases WHERE id=?1", [rid], |x| {
                Ok((x.get(0)?, x.get(1)?))
            })
            .unwrap();
        assert!(
            junk < 50,
            "a named spot release is wall-visible (junk={junk})"
        );
        assert_eq!(files, 2);
        // The stored segments synthesize a working NZB.
        let xml = ix.make_nzb(rid).unwrap();
        for id in ["d1@x", "d2@x", "d3@x"] {
            assert!(xml.contains(id), "make_nzb lost {id}");
        }
        // Bookkeeping: payload ids cached (first segment per file,
        // bracketed), release linked, resolver done with it.
        let again = ix.spot_by_msgid(&s.msgid).unwrap().unwrap();
        assert_eq!(again.nzb_msgids, vec!["<d1@x>", "<d3@x>"]);
        let linked: i64 = ix
            .db
            .query_row(
                "SELECT release_id FROM spots WHERE msgid=?1",
                [&s.msgid],
                |x| x.get(0),
            )
            .unwrap();
        assert_eq!(linked, rid);
        assert!(ix.spots_unresolved(10).unwrap().is_empty());
        teardown(&d, ix);
    }

    /// A spot names the WORK, and for a book that costs the only
    /// evidence there is.
    ///
    /// The signed title of a Spotnet e-book spot is "Hetty Luiten - Op
    /// eigen benen"; the posted file is "Luiten, Hetty - Op eigen
    /// benen.epub". Classification reads the fed title (it must - the
    /// stem is usually the obfuscated one), so the `.epub` went missing,
    /// the parse fell through `None => Kind::Movie`, and an
    /// evidence-free movie scores 60 - hidden on a wall that shows
    /// junk < 50. Measured on the live index 16 Aug 2026: 33 of 38
    /// August rows from e-book groups were filed as hidden movies. Now
    /// the stem puts the lane back.
    #[test]
    fn a_spot_named_ebook_lands_in_the_book_lane_not_the_film_lane() {
        let d = dir("spotbook");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let s = spot("<sp2@spot>", "Hetty Luiten - Op eigen benen", "a09");
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![nzb_file(
                r#""Luiten, Hetty - Op eigen benen.epub" yEnc (1/1)"#,
                "alt.binaries.e-book",
                &[(1, "b1@x", 1_400_000)],
            )],
            meta: Vec::new(),
        };
        let rid = match ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap() {
            SpotPromotion::Promoted(rid) => rid,
            other => panic!("expected a fresh release, got {other:?}"),
        };
        let (kind, junk, key): (String, i64, String) = ix
            .db
            .query_row(
                "SELECT kind, junk, title_key FROM releases WHERE id=?1",
                [rid],
                |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?)),
            )
            .unwrap();
        assert_eq!(kind, "book", "the payload is an epub");
        assert!(junk < 50, "a book is wall-visible (junk={junk})");
        assert!(key.starts_with("bk:"), "keyed into the book lane: {key}");
        teardown(&d, ix);
    }

    /// TODO 131: an adult spot is promoted like any other, and the card
    /// carries the poster's own filing so the wall's adult setting can
    /// act on it.
    ///
    /// Before the marker existed the resolver simply skipped `d75`
    /// spots - 31% of the feed, the biggest single hole in the
    /// catalogue - because the only adult test the wall had reads
    /// enriched genres, and a fresh spot-born card has none. What the
    /// user sees by default is unchanged; what changed is that the
    /// setting now has something to read.
    #[test]
    fn an_adult_spot_becomes_a_card_the_adult_setting_can_hide() {
        let d = dir("adult");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let plain = spot("<pl1@spot>", "Plain.Show.S01E01.1080p.WEB.x264-GRP", "a09");
        let adult = spot(
            "<ad1@spot>",
            "Adult.Feature.2026.1080p.WEB.x264-GRP",
            &format!("a09,{ADULT_SUBCAT}"),
        );
        ix.insert_spot(&plain).unwrap();
        ix.insert_spot(&adult).unwrap();
        // It is offered to the resolver at all - the old exclusion here
        // is what kept a third of the feed out of the index.
        assert_eq!(ix.spots_unresolved(10).unwrap().len(), 2);

        let mut rid_adult = 0;
        for (s, stem, id) in [
            (&plain, "aa11bb22cc", "p1@x"),
            (&adult, "dd33ee44ff", "a1@x"),
        ] {
            let nzb = crate::nzb::Nzb {
                files: vec![nzb_file(
                    &format!(r#""{stem}.part01.rar" yEnc (1/1)"#),
                    "alt.binaries.misc",
                    &[(1, id, 4 << 30)],
                )],
                meta: Vec::new(),
            };
            match ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap() {
                SpotPromotion::Promoted(rid) => {
                    if s.msgid == adult.msgid {
                        rid_adult = rid;
                    }
                }
                other => panic!("expected a fresh release, got {other:?}"),
            }
        }
        let marked: i64 = ix
            .db
            .query_row("SELECT adult FROM releases WHERE id=?1", [rid_adult], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(marked, 1, "the d75 filing did not reach the card");

        // Both views, because they are the two halves that have to
        // agree - the flat list was how the genre filter got bypassed
        // once already.
        let cards = |hide_adult: bool| -> Vec<String> {
            let (cards, _) = ix
                .browse_cards(
                    &BrowseQuery {
                        curated: true,
                        hide_adult,
                        limit: 50,
                        ..Default::default()
                    },
                    CardSort::Title,
                    false,
                    false,
                    None,
                )
                .unwrap();
            cards.into_iter().map(|c| c.title_key).collect()
        };
        let flat = |hide_adult: bool| -> Vec<String> {
            let (rows, total) = ix
                .browse(&BrowseQuery {
                    curated: true,
                    hide_adult,
                    limit: 50,
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(total as usize, rows.len(), "total disagrees with the page");
            rows.iter().map(|r| r.display_name().to_string()).collect()
        };
        let adult_shown = |v: &[String]| v.iter().any(|s| s.to_lowercase().contains("adult"));
        let plain_shown = |v: &[String]| v.iter().any(|s| s.to_lowercase().contains("plain"));
        for (view, on, off) in [
            ("cards", cards(true), cards(false)),
            ("flat", flat(true), flat(false)),
        ] {
            assert!(
                adult_shown(&off) && plain_shown(&off),
                "{view}: nothing is filtered with the setting off: {off:?}"
            );
            assert!(
                !adult_shown(&on),
                "{view}: the marked card survived the filter: {on:?}"
            );
            assert!(
                plain_shown(&on),
                "{view}: the filter took an unmarked card with it: {on:?}"
            );
        }
        teardown(&d, ix);
    }

    /// TODO 131: a spot-born card's completeness is the NZB's own claim
    /// about itself until one STAT says otherwise.
    ///
    /// The corroboration asks about the largest file's first article -
    /// the payload, not a par2 sidecar posted in a different run - and
    /// an absent answer demotes the card. One article cannot prove a
    /// set is whole; it can prove the post is gone, which is the case
    /// the depth walk keeps producing.
    #[test]
    fn one_stat_can_take_a_declared_complete_card_back() {
        let d = dir("stat");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let s = spot("<st1@spot>", "Deep.Old.Release.2011.720p-GRP", "a09");
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![
                // A sidecar posted first, and small.
                nzb_file(
                    r#""7a1b2c3d.par2" yEnc (1/1)"#,
                    "alt.binaries.misc",
                    &[(1, "pp@x", 1 << 20)],
                ),
                // The payload, out of segment order in the NZB.
                nzb_file(
                    r#""7a1b2c3d.part01.rar" yEnc (1/2)"#,
                    "alt.binaries.misc",
                    &[(2, "b2@x", 2 << 30), (1, "b1@x", 2 << 30)],
                ),
            ],
            meta: Vec::new(),
        };
        let rid = match ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap() {
            SpotPromotion::Promoted(rid) => rid,
            other => panic!("expected a fresh release, got {other:?}"),
        };
        let complete = |ix: &Index| -> i64 {
            ix.db
                .query_row("SELECT complete FROM releases WHERE id=?1", [rid], |r| {
                    r.get(0)
                })
                .unwrap()
        };
        assert_eq!(complete(&ix), 1, "the NZB declares every part present");
        assert_eq!(
            ix.release_head_article(rid).unwrap().as_deref(),
            Some("<b1@x>"),
            "the payload's first part, not the par2 and not NZB order"
        );

        // Present: nothing changes except the record that we asked.
        ix.spot_stat_verdict(&s.msgid, rid, true).unwrap();
        assert_eq!(complete(&ix), 1);
        assert_eq!(ix.spot_stat_counts().unwrap(), (1, 0));

        // Gone: the card stops claiming to be whole.
        ix.spot_stat_verdict(&s.msgid, rid, false).unwrap();
        assert_eq!(
            complete(&ix),
            0,
            "the head article is gone and the card still said complete"
        );
        assert_eq!(ix.spot_stat_counts().unwrap(), (1, 1));
        teardown(&d, ix);
    }

    /// The marker is written ONLY on a row the spot brought into being.
    ///
    /// A spot that lands on a release the scanner already holds is a
    /// claim about somebody else's row, and Spotnet keys are free: if
    /// filing `d75` against an existing post hid its card, anyone who
    /// can read an NZB's message-ids could take any card off the
    /// default wall for the cost of one signed spot.
    #[test]
    fn an_adult_spot_cannot_mark_a_release_it_merely_matched() {
        let d = dir("adultdedup");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        // The scanner's row first, with the articles the spot will name.
        ix.ingest(
            "alt.binaries.misc",
            &[
                entry(
                    r#""Scanner.Held.2026.1080p.WEB.x264-GRP.mkv" yEnc (1/2)"#,
                    "up@x",
                    "s1@x",
                    1 << 30,
                ),
                entry(
                    r#""Scanner.Held.2026.1080p.WEB.x264-GRP.mkv" yEnc (2/2)"#,
                    "up@x",
                    "s2@x",
                    1 << 30,
                ),
            ],
            1_000,
        )
        .unwrap();
        let s = spot(
            "<ad2@spot>",
            "Scanner.Held.2026.1080p.WEB.x264-GRP",
            &format!("a09,{ADULT_SUBCAT}"),
        );
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![nzb_file(
                r#""Scanner.Held.2026.1080p.WEB.x264-GRP.mkv" yEnc (1/2)"#,
                "alt.binaries.misc",
                &[(1, "s1@x", 1 << 30), (2, "s2@x", 1 << 30)],
            )],
            meta: Vec::new(),
        };
        let rid = match ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap() {
            SpotPromotion::Upgraded(rid) | SpotPromotion::Promoted(rid) => rid,
            other => panic!("expected the spot to resolve, got {other:?}"),
        };
        let marked: i64 = ix
            .db
            .query_row("SELECT adult FROM releases WHERE id=?1", [rid], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            marked, 0,
            "a spot marked a row it did not create - that is a free card-hiding primitive"
        );
        teardown(&d, ix);
    }

    /// A spot title is authenticated, not proven: anyone can mint a
    /// self-signed Spotnet key. So archive bytes must be able to
    /// correct one, and an equal-tier claim from another lane must not
    /// - the old bare `spot` label put spot-born names at `i32::MAX`,
    /// where a byte probe reading the real filename out of the archive
    /// could only ever log a Conflict.
    #[test]
    fn a_byte_proof_outranks_a_spot_title_and_an_equal_tier_claim_does_not() {
        let d = dir("arb");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let s = spot("<sp9@spot>", "Wrong.Name.2026.1080p.WEB-DL.x264-GRP", "a09");
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![nzb_file(
                r#""9f3a1c7e2b.7z" yEnc (1/1)"#,
                "alt.binaries.misc",
                &[(1, "w1@x", 4 << 30)],
            )],
            meta: Vec::new(),
        };
        let rid = match ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap() {
            SpotPromotion::Promoted(rid) => rid,
            other => panic!("expected a fresh release, got {other:?}"),
        };

        // Equal tier, different lane, different name: the standing name
        // holds and the newcomer is ledgered, not applied. Equal-strength
        // proof never flips, or two lanes could rename a card forever.
        let rival = NameClaim {
            name: "Rival.Name.2026.1080p.WEB-DL.x264-OTHER".into(),
            evidence: NameEvidence::MsgidSet,
            key: "0123456789abcdef0123456789abcdef".into(),
            source: "posted-nzb".into(),
        };
        assert_eq!(
            ix.apply_proven_name(rid, &rival, 3000).unwrap(),
            ProvenOutcome::Conflict
        );
        let (pre, src): (String, String) = ix
            .db
            .query_row(
                "SELECT pre_title, pre_source FROM releases WHERE id=?1",
                [rid],
                |x| Ok((x.get(0)?, x.get(1)?)),
            )
            .unwrap();
        assert_eq!(pre, "Wrong.Name.2026.1080p.WEB-DL.x264-GRP");
        assert_eq!(src, "proven:msgid-set:spot");

        // The archive's own end-header outranks it, and says so in the
        // provenance label.
        let bytes = NameClaim {
            name: "Real.Name.2026.1080p.WEB-DL.x264-GRP".into(),
            evidence: NameEvidence::BodyProbe,
            key: "beefbeefbeefbeefbeefbeefbeefbeef".into(),
            source: "body/7z".into(),
        };
        assert_eq!(
            ix.apply_proven_name(rid, &bytes, 4000).unwrap(),
            ProvenOutcome::Replaced
        );
        let (pre, src): (String, String) = ix
            .db
            .query_row(
                "SELECT pre_title, pre_source FROM releases WHERE id=?1",
                [rid],
                |x| Ok((x.get(0)?, x.get(1)?)),
            )
            .unwrap();
        assert_eq!(pre, "Real.Name.2026.1080p.WEB-DL.x264-GRP");
        assert_eq!(src, "proven:body-probe:body/7z");
        // Truth is kept: all three claims stay on file.
        assert_eq!(ix.name_claims(rid).unwrap().len(), 3);
        teardown(&d, ix);
    }

    /// Spot cards promoted before the fresh branch wrote a claim carry
    /// a bare `spot` label, which `applied_strength` grades at
    /// `i32::MAX` - the defect, on the whole existing population. The
    /// backfill puts them on the ledger and relabels them, once.
    #[test]
    fn legacy_spot_rows_are_backfilled_onto_the_claims_ledger() {
        let d = dir("relabel");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let s = spot("<sp8@spot>", "Legacy.Card.2026.1080p.WEB.x264-GRP", "a09");
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![nzb_file(
                r#""legacyblob01.part01.rar" yEnc (1/1)"#,
                "alt.binaries.misc",
                &[(1, "L1@x", 4 << 30), (2, "L2@x", 1 << 30)],
            )],
            meta: Vec::new(),
        };
        let rid = match ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap() {
            SpotPromotion::Promoted(rid) => rid,
            other => panic!("expected a fresh release, got {other:?}"),
        };
        // Wind the row back to exactly what a pre-fix promotion left.
        ix.db
            .execute("UPDATE releases SET pre_source='spot' WHERE id=?1", [rid])
            .unwrap();
        ix.db
            .execute("DELETE FROM name_claims WHERE release_id=?1", [rid])
            .unwrap();

        assert_eq!(ix.relabel_spot_names(3000).unwrap(), 1);
        let src: String = ix
            .db
            .query_row("SELECT pre_source FROM releases WHERE id=?1", [rid], |x| {
                x.get(0)
            })
            .unwrap();
        assert_eq!(src, "proven:msgid-set:spot");
        let claims = ix.name_claims(rid).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "Legacy.Card.2026.1080p.WEB.x264-GRP");
        assert_eq!(claims[0].1, "msgid-set");
        assert_eq!(claims[0].3, "spot");
        // Keyed on the LOWEST-numbered segment per file, the same set
        // `promote_spot` keys, not on every segment the row holds.
        assert_eq!(claims[0].2, msgid_set_key(["<L1@x>"]));

        // Idempotent and kv-guarded: a second call is free, and a row
        // some other lane has since proven is never dragged back.
        assert_eq!(ix.relabel_spot_names(4000).unwrap(), 0);
        teardown(&d, ix);
    }

    /// A legacy title the ledger REFUSES still gets graded down.
    ///
    /// `record_name_claim` rejects a name holding a path separator, and
    /// on the live index every row it refused was a spot title using
    /// `/` as punctuation ("Upscaled/Remastered", "x86/x64"). The first
    /// backfill skipped the relabel on those and set its guard anyway,
    /// so 13 rows kept the bare `spot` label - `i32::MAX`, above every
    /// byte proof - which is the exact opposite of what the pass is
    /// for: these are the WORST titles, and they were the ones made
    /// permanently uncorrectable.
    #[test]
    fn a_legacy_title_the_ledger_refuses_is_still_graded_down() {
        let d = dir("relabel_refused");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        // Promoted under the old gate: today `promote_spot` refuses a
        // `/` title outright, so this shape only exists as residue.
        let s = spot(
            "<sp9@spot>",
            "Nina Simone - Live [Upscaled/Remastered]",
            "a10",
        );
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![nzb_file(
                r#""oldblob01.part01.rar" yEnc (1/1)"#,
                "alt.binaries.misc",
                &[(1, "R1@x", 4 << 30)],
            )],
            meta: Vec::new(),
        };
        let rid = match ix
            .promote_spot(&s.msgid, "Legit.Name.2026", &nzb, 2000)
            .unwrap()
        {
            SpotPromotion::Promoted(rid) => rid,
            other => panic!("expected a fresh release, got {other:?}"),
        };
        ix.db
            .execute(
                "UPDATE releases SET pre_source='spot', pre_title=?2 WHERE id=?1",
                rusqlite::params![rid, "Nina Simone - Live [Upscaled/Remastered]"],
            )
            .unwrap();
        ix.db
            .execute("DELETE FROM name_claims WHERE release_id=?1", [rid])
            .unwrap();

        assert_eq!(ix.relabel_spot_names(3000).unwrap(), 1);
        let src: String = ix
            .db
            .query_row("SELECT pre_source FROM releases WHERE id=?1", [rid], |x| {
                x.get(0)
            })
            .unwrap();
        // Graded down to msgid-set, so a body probe (a stronger tier)
        // can now correct the title. That is the whole point.
        assert_eq!(src, "proven:msgid-set:spot");
        // ...and the ledger stays honest: the refused name is NOT on
        // file, because a path is not a release name from any source.
        assert!(ix.name_claims(rid).unwrap().is_empty());
        teardown(&d, ix);
    }

    /// Cards named with the spot XML's raw markup get the title that
    /// was inside it - and everything the old name derived is
    /// re-derived, so the card does not go on searching under
    /// `<![CDATA[`.
    #[test]
    fn cdata_named_cards_are_repaired_and_re_derived() {
        let d = dir("cdata");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let s = spot("<spc@spot>", "irrelevant", "a09");
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![nzb_file(
                r#""zz9plural.part01.rar" yEnc (1/1)"#,
                "alt.binaries.misc",
                &[(1, "c1@x", 4_000_000_000)],
            )],
            meta: Vec::new(),
        };
        // What the old parser handed the naming seam, verbatim.
        let rid = match ix
            .promote_spot(
                &s.msgid,
                "<![CDATA[Shark.Night.2011.1080p.BluRay.x264-GRP]]>",
                &nzb,
                2000,
            )
            .unwrap()
        {
            SpotPromotion::Promoted(rid) => rid,
            other => panic!("expected a fresh release, got {other:?}"),
        };
        let before: (String, String) = ix
            .db
            .query_row(
                "SELECT pre_title, title_key FROM releases WHERE id=?1",
                [rid],
                |x| Ok((x.get(0)?, x.get(1)?)),
            )
            .unwrap();
        // `sanitize_name` maps the angle brackets to spaces on this
        // path, so the stored shape is the bracketless one; rows named
        // through the other path keep `<![CDATA[…]]>` verbatim. Both
        // are repaired, and both shapes are asserted below.
        assert!(before.0.starts_with("![CDATA["), "{before:?}");
        assert_eq!(
            strip_stored_cdata("<![CDATA[Verbatim Title]]>").as_deref(),
            Some("Verbatim Title")
        );
        assert_eq!(strip_stored_cdata("A film about CDATA[s]").as_deref(), None);

        assert_eq!(ix.repair_cdata_spot_titles(3000).unwrap(), 1);
        let after: (String, String, String, i64) = ix
            .db
            .query_row(
                "SELECT pre_title, pre_source, title_key, junk FROM releases WHERE id=?1",
                [rid],
                |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?)),
            )
            .unwrap();
        assert_eq!(after.0, "Shark.Night.2011.1080p.BluRay.x264-GRP");
        assert_eq!(
            after.1, "proven:msgid-set:spot",
            "provenance survives the repair - re-stamping a bare `spot` \
             label here would demote the row back to unarbitrable"
        );
        assert_ne!(
            after.2, before.1,
            "title_key re-derived from the real title"
        );
        assert!(after.3 < 50, "still a wall-visible card (junk={})", after.3);
        // The FTS/search side agrees, which a bare pre_title UPDATE
        // would not have given.
        assert_eq!(ix.search("Shark Night", 10).unwrap().len(), 1);

        // Idempotent, and kv-guarded: a second call is free.
        assert_eq!(ix.repair_cdata_spot_titles(4000).unwrap(), 0);
        teardown(&d, ix);
    }

    /// The ~0.6% overlap case: the spot's post is already indexed (dark,
    /// obfuscated stem). The existing row is named through the seam and
    /// no twin card appears.
    #[test]
    fn a_spot_for_an_indexed_post_upgrades_instead_of_duplicating() {
        let d = dir("dedup");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[
                entry(
                    r#""p5cbKvaDJ1Y0PW6DvKCIfztzZ.part01.rar" yEnc (1/1)"#,
                    "poster@x",
                    "o1",
                    4 << 30,
                ),
                entry(
                    r#""p5cbKvaDJ1Y0PW6DvKCIfztzZ.part02.rar" yEnc (1/1)"#,
                    "poster@x",
                    "o2",
                    4 << 30,
                ),
            ],
            1000,
        )
        .unwrap();
        let s = spot("<sp2@spot>", "Other.Film.2026.1080p.WEB-DL.x264-GRP", "a09");
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![nzb_file(
                r#""p5cbKvaDJ1Y0PW6DvKCIfztzZ.part01.rar" yEnc (1/1)"#,
                "alt.binaries.misc",
                &[(1, "o1", 4 << 30)],
            )],
            meta: Vec::new(),
        };
        let rid = match ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap() {
            SpotPromotion::Upgraded(rid) => rid,
            other => panic!("expected an upgrade of the indexed row, got {other:?}"),
        };
        let n: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases", [], |x| x.get(0))
            .unwrap();
        assert_eq!(n, 1, "no twin card next to the indexed post");
        let (pre, src): (String, String) = ix
            .db
            .query_row(
                "SELECT pre_title, pre_source FROM releases WHERE id=?1",
                [rid],
                |x| Ok((x.get(0)?, x.get(1)?)),
            )
            .unwrap();
        assert_eq!(pre, "Other.Film.2026.1080p.WEB-DL.x264-GRP");
        // Booked through the claims ledger as message-id-set evidence,
        // not stamped directly: an existing name would be arbitrated.
        assert_eq!(src, "proven:msgid-set:spot");
        let claims = ix.name_claims(rid).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1, "msgid-set");
        assert_eq!(claims[0].3, "spot");
        teardown(&d, ix);
    }

    /// Same name, same poster, same group, DIFFERENT articles - a plain
    /// repost. The (stem, poster, grp) upsert used to hand generation 2
    /// generation 1's row: manifest overwritten through
    /// ON CONFLICT(release_id, filename), card renamed, new ids
    /// resolving to the old row, and a synthesised NZB that mixed both
    /// postings. The two postings must stay two releases.
    #[test]
    fn a_repost_with_fresh_articles_does_not_eat_the_first_posting() {
        let d = dir("repost");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[
                entry(
                    r#""Repost.Me.2026.1080p.WEB.x264-GRP.part01.rar" yEnc (1/1)"#,
                    "spotter@x",
                    "gen1a",
                    4 << 30,
                ),
                entry(
                    r#""Repost.Me.2026.1080p.WEB.x264-GRP.part02.rar" yEnc (1/1)"#,
                    "spotter@x",
                    "gen1b",
                    4 << 30,
                ),
            ],
            1000,
        )
        .unwrap();
        let first: i64 = ix
            .db
            .query_row("SELECT id FROM releases", [], |x| x.get(0))
            .unwrap();

        // The repost: identical filenames (so identical stem) from the
        // same poster into the same group, but every article is new.
        let s = spot("<sp3@spot>", "Repost.Me.2026.1080p.WEB.x264-GRP", "a09");
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![
                nzb_file(
                    r#""Repost.Me.2026.1080p.WEB.x264-GRP.part01.rar" yEnc (1/1)"#,
                    "alt.binaries.misc",
                    &[(1, "gen2a", 4 << 30)],
                ),
                nzb_file(
                    r#""Repost.Me.2026.1080p.WEB.x264-GRP.part02.rar" yEnc (1/1)"#,
                    "alt.binaries.misc",
                    &[(1, "gen2b", 4 << 30)],
                ),
            ],
            meta: Vec::new(),
        };
        let second = match ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap() {
            SpotPromotion::Promoted(rid) => rid,
            other => panic!("expected a distinct release for the repost, got {other:?}"),
        };
        assert_ne!(second, first, "the repost must not reuse the first row");
        let n: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases", [], |x| x.get(0))
            .unwrap();
        assert_eq!(n, 2, "two postings, two releases");

        // The first posting is untouched: still nameless, still its own
        // poster, still exactly its own articles.
        let (pre, poster): (String, String) = ix
            .db
            .query_row(
                "SELECT pre_title, poster FROM releases WHERE id=?1",
                [first],
                |x| Ok((x.get(0)?, x.get(1)?)),
            )
            .unwrap();
        assert_eq!(pre, "", "the repost's title must not rename the original");
        assert_eq!(poster, "spotter@x");
        let one = ix.make_nzb(first).unwrap();
        for id in ["gen1a", "gen1b"] {
            assert!(one.contains(id), "the first posting lost {id}");
        }
        for id in ["gen2a", "gen2b"] {
            assert!(!one.contains(id), "the first posting swallowed {id}");
        }

        // The second is a real named release holding only generation 2,
        // and its synthesised NZB carries the true From, not the row's
        // generation-marked one.
        let two = ix.make_nzb(second).unwrap();
        for id in ["gen2a", "gen2b"] {
            assert!(two.contains(id), "the repost lost {id}");
        }
        for id in ["gen1a", "gen1b"] {
            assert!(!two.contains(id), "the repost swallowed {id}");
        }
        assert!(
            two.contains(r#"poster="spotter@x""#),
            "make_nzb leaked the generation marker: {two}"
        );
        let (pre2, stem2, poster2): (String, String, String) = ix
            .db
            .query_row(
                "SELECT pre_title, stem, poster FROM releases WHERE id=?1",
                [second],
                |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?)),
            )
            .unwrap();
        assert_eq!(pre2, "Repost.Me.2026.1080p.WEB.x264-GRP");
        assert_eq!(
            stem2, "Repost.Me.2026.1080p.WEB.x264-GRP",
            "only the poster carries the discriminator - stem stays a join key"
        );
        assert_eq!(base_poster(&poster2), "spotter@x");
        assert_ne!(poster2, "spotter@x");

        // Idempotent: re-promoting the same payload finds the row it
        // already minted (message-id quorum) instead of a third.
        ix.insert_spot(&spot(
            "<sp4@spot>",
            "Repost.Me.2026.1080p.WEB.x264-GRP",
            "a09",
        ))
        .unwrap();
        assert_eq!(
            ix.promote_spot("<sp4@spot>", &s.title, &nzb, 3000).unwrap(),
            SpotPromotion::Upgraded(second)
        );
        let n: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases", [], |x| x.get(0))
            .unwrap();
        assert_eq!(n, 2, "a re-spot of the repost is still two releases");
        teardown(&d, ix);
    }

    /// The other half of the collision rule: WHILE THE MAP IS STILL
    /// FILLING, a row with no message-id coverage cannot be told apart
    /// from the spot's post. Unkeyed means unknown there, and unknown
    /// keeps adopting in place - otherwise every spot on a
    /// not-yet-converged index would mint a twin card.
    ///
    /// The backfill flag is what makes "still filling" a fact rather
    /// than a guess; see the converged case below.
    #[test]
    fn an_unkeyed_row_still_adopts_the_spot_in_place() {
        let d = dir("unkeyed");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[entry(
                r#""Dark.Row.2026.1080p.WEB.x264-GRP.part01.rar" yEnc (1/1)"#,
                "spotter@x",
                "old1",
                4 << 30,
            )],
            1000,
        )
        .unwrap();
        let first: i64 = ix
            .db
            .query_row("SELECT id FROM releases", [], |x| x.get(0))
            .unwrap();
        // Pre-substrate row: indexed before msgid_map existed, on an
        // index whose backfill has NOT finished yet.
        ix.db.execute("DELETE FROM msgid_map", []).unwrap();
        ix.db
            .execute("DELETE FROM kv WHERE k='msgid_map_fill'", [])
            .unwrap();

        let s = spot("<sp5@spot>", "Dark.Row.2026.1080p.WEB.x264-GRP", "a09");
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![nzb_file(
                r#""Dark.Row.2026.1080p.WEB.x264-GRP.part01.rar" yEnc (1/1)"#,
                "alt.binaries.misc",
                &[(1, "new1", 4 << 30)],
            )],
            meta: Vec::new(),
        };
        assert_eq!(
            ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap(),
            SpotPromotion::Promoted(first)
        );
        let n: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases", [], |x| x.get(0))
            .unwrap();
        assert_eq!(n, 1);
        teardown(&d, ix);
    }

    /// ...and once the backfill HAS finished, an unkeyed row with zero
    /// article overlap is a different posting, not an unknown one.
    ///
    /// This is the upgrade window the previous test describes, closed:
    /// the backfill is time-bounded per open, so a fresh repost could be
    /// spotted before an old row was keyed, and the deliberate
    /// adopt-in-place then overwrote that row's manifest with the
    /// repost's - the very collision the generation discriminator
    /// exists to stop (H2, 10 Aug sweep). `msgid_map_fill` says the map
    /// is complete for the whole index, so silence from it is evidence.
    #[test]
    fn a_converged_index_splits_an_unkeyed_collision() {
        let d = dir("converged");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[entry(
                r#""Dark.Row.2026.1080p.WEB.x264-GRP.part01.rar" yEnc (1/1)"#,
                "spotter@x",
                "old1",
                4 << 30,
            )],
            1000,
        )
        .unwrap();
        let first: i64 = ix
            .db
            .query_row("SELECT id FROM releases", [], |x| x.get(0))
            .unwrap();
        // Same pre-substrate row - but this index HAS converged.
        ix.db.execute("DELETE FROM msgid_map", []).unwrap();
        ix.db
            .execute(
                "INSERT INTO kv(k, v) VALUES('msgid_map_fill','1')
                 ON CONFLICT(k) DO UPDATE SET v='1'",
                [],
            )
            .unwrap();

        let s = spot("<sp6@spot>", "Dark.Row.2026.1080p.WEB.x264-GRP", "a09");
        ix.insert_spot(&s).unwrap();
        let nzb = crate::nzb::Nzb {
            files: vec![nzb_file(
                r#""Dark.Row.2026.1080p.WEB.x264-GRP.part01.rar" yEnc (1/1)"#,
                "alt.binaries.misc",
                &[(1, "new1", 4 << 30)],
            )],
            meta: Vec::new(),
        };
        let promoted = ix.promote_spot(&s.msgid, &s.title, &nzb, 2000).unwrap();
        assert!(
            !matches!(promoted, SpotPromotion::Promoted(id) if id == first),
            "the spot adopted an unrelated generation's row: {promoted:?}"
        );
        let n: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases", [], |x| x.get(0))
            .unwrap();
        assert_eq!(n, 2, "the repost needs its own release row");
        // ...and the first generation's manifest is untouched.
        let old_seg = ix
            .db
            .query_row(
                "SELECT segments FROM files WHERE release_id=?1",
                [first],
                |x| x.get::<_, SegList>(0),
            )
            .unwrap()
            .0;
        assert!(
            old_seg.iter().any(|(_, id, _)| id.contains("old1")),
            "the repost overwrote the original manifest: {old_seg:?}"
        );
        teardown(&d, ix);
    }

    /// The resolver's queue: legacy moderation rows are skipped and a
    /// fetch that keeps failing is written off after the retry cap.
    ///
    /// Adult spots are NOT skipped any more - they are promoted like
    /// anything else and the card carries the poster's filing, which is
    /// what `wall_hide_adult` reads (see
    /// `an_adult_spot_becomes_a_card_the_adult_setting_can_hide`). The
    /// old skip was a stand-in for that marker and it cost the
    /// catalogue 31% of the feed.
    #[test]
    fn the_resolver_queue_skips_disposed_and_capped_spots() {
        let d = dir("queue");
        let ix = Index::open(&d.join("index.db")).unwrap();
        ix.insert_spot(&spot("<a@s>", "Normal.Release.1080p", "a09"))
            .unwrap();
        ix.insert_spot(&spot("<b@s>", "Filed As Adult", "a09,d75"))
            .unwrap();
        ix.insert_spot(&spot("<c@s>", "DISPOSE <x@y> - gone", "a09"))
            .unwrap();
        ix.insert_spot(&spot("<d@s>", "Articles Expired", "a09"))
            .unwrap();
        for _ in 0..SPOT_NZB_TRIES {
            ix.spot_nzb_failed("<d@s>").unwrap();
        }
        let pending = ix.spots_unresolved(10).unwrap();
        assert_eq!(
            pending.iter().map(|s| s.msgid.as_str()).collect::<Vec<_>>(),
            vec!["<b@s>", "<a@s>"],
            "newest first, adult included, DISPOSE and capped left out"
        );
        teardown(&d, ix);
    }
}

/// The Spotnet subcategory a poster files erotica under. Hidden from
/// Browse unless asked for; see [`Index::spot_browse`].
pub const ADULT_SUBCAT: &str = "d75";

/// A Browse query over the spots table.
#[derive(Debug, Clone, Default)]
pub struct SpotQuery {
    pub q: String,
    /// 0-based Spotnet category: 0 video, 1 music, 2 game, 3 application.
    pub category: Option<u8>,
    pub include_adult: bool,
    pub limit: u32,
    pub offset: u32,
}

/// Does this spot carry the adult subcategory?
pub fn spot_is_adult(subcats: &str) -> bool {
    subcats.split(',').any(|s| s.trim() == ADULT_SUBCAT)
}

/// The four Spotnet categories as our own content kinds. Spotnet does not
/// separate film from television - both are category 0 - so video maps to
/// the generic kind and the title parser does the rest downstream.
pub fn spot_kind(category: u8) -> &'static str {
    match category {
        0 => "video",
        1 => "music",
        2 => "game",
        3 => "app",
        _ => "other",
    }
}

/// One ingested Spotnet spot (M14j).
#[derive(Debug, Clone)]
pub struct Spot {
    pub id: i64,
    /// With angle brackets, as seen in OVER.
    pub msgid: String,
    pub title: String,
    /// Spotnet category, 0-based: 0 video, 1 music, 2 game, 3 application.
    pub category: u8,
    /// Comma-joined subcategory runs, e.g. `a09,b04`.
    pub subcats: String,
    pub size: u64,
    /// Unix timestamp from the spot record.
    pub date: i64,
    pub spotter_id: String,
    /// RSA signature verified (always true for stored spots today).
    pub(crate) verified: bool,
    /// V2 hashcash proof-of-work passed (warning flag when false).
    pub hashcash_ok: bool,
    /// NZB payload segment ids, cached after the first fetch.
    pub nzb_msgids: Vec<String>,
}

impl Spot {
    /// A stored-shaped spot minted by hand, for a test in ANOTHER crate
    /// that needs rows in the `spots` table without a signed wire scan.
    ///
    /// `#[doc(hidden)] pub` for the same reason [`crate::mock`] is: the
    /// nzbfast resolver's integration suite has to seed a pending
    /// backlog, and it has no way to. `verified` is `pub(crate)` (it is
    /// always true for a stored spot, so nothing downstream should be
    /// branching on it) which makes the struct unconstructable from
    /// outside; `scan_spots` is the only other door and it demands a
    /// real RSA signature, which only this crate's own `#[cfg(test)]`
    /// `make_spot` can mint. Re-widening the field was the alternative
    /// and is worse: it puts a field that carries no information back on
    /// the public surface for good, which is precisely what the TODO 103
    /// item 6 sweep took it off for (f09c67e4e).
    ///
    /// Not a production constructor. The insert still goes through
    /// [`Index::insert_spots`], so a test seeded this way exercises the
    /// same rows a scan would have written.
    #[doc(hidden)]
    pub fn for_test(msgid: &str, title: &str, date: i64) -> Spot {
        Spot {
            id: 0,
            msgid: msgid.to_string(),
            title: title.to_string(),
            category: 0,
            subcats: String::new(),
            size: 1_048_576,
            date,
            spotter_id: String::new(),
            verified: true,
            hashcash_ok: true,
            nzb_msgids: Vec::new(),
        }
    }
}

fn spot_from_row(r: &rusqlite::Row) -> rusqlite::Result<Spot> {
    Ok(Spot {
        id: r.get(0)?,
        msgid: r.get(1)?,
        title: r.get(2)?,
        category: r.get(3)?,
        subcats: r.get(4)?,
        size: r.get::<_, i64>(5)? as u64,
        date: r.get(6)?,
        spotter_id: r.get(7)?,
        verified: r.get(8)?,
        hashcash_ok: r.get(9)?,
        nzb_msgids: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or_default(),
    })
}
