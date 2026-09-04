//! Size-pressure eviction (TODO 106 phase 2.2, cut 1): the policy
//! ladder, the protected set, and `evict_to` itself. Bodies are verbatim
//! moves from the old index.rs; see research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::*;

impl Index {
    /// Evict until the database would fit in `target_bytes`, honouring the
    /// policy order and never touching anything in `protected`.
    /// `target_bytes == 0` means unlimited: return immediately, remove nothing.
    ///
    /// Deletes go through `prune_batch`, so the `files` cascade, the
    /// single transaction and the FTS trigger behave exactly as they do
    /// for the age/size pruners.
    ///
    /// `bytes_after` will usually EQUAL `bytes_before`: DELETE in SQLite
    /// moves pages to the freelist, it does not shorten the file. That is
    /// correct and expected, and is the entire reason `needs_compact`
    /// exists - `compact()` takes an exclusive lock and rewrites the whole
    /// file, so the daemon schedules it for an idle window rather than
    /// having eviction do it inline.
    ///
    /// If the protected set (plus the kinds filter) leaves too little to
    /// delete, eviction stops early: the target is simply not reached and
    /// `removed` reports how far it got. Protection outranks the cap.
    pub fn evict_to(
        &self,
        target_bytes: u64,
        policy: &EvictPolicy,
        protected: &Protected,
    ) -> rusqlite::Result<EvictReport> {
        let before = self.db_bytes()?;
        let live_before = self.live_bytes()?;
        // 0 = unlimited. Do this before anything else touches the db.
        if target_bytes == 0 {
            return Ok(EvictReport {
                removed: 0,
                bytes_before: before,
                bytes_after: before,
                live_before,
                live_after: live_before,
                needs_compact: false,
                blocked: false,
            });
        }
        let low = evict_low_water(target_bytes, policy);

        // The authoritative protection check. The `NOT IN` binds below are
        // an optimisation that keeps protected rows out of the candidate
        // pages when the set is small enough to bind; these two sets are
        // what actually decides, and they hold EVERYTHING the caller
        // passed, with no cap.
        //
        // An empty title_key is dropped deliberately: `releases.title_key`
        // defaults to '' for rows that predate M28 or never parsed, so a
        // stray '' in the protected list would silently protect every
        // unclassified row in the index and wedge eviction shut.
        let prot_ids: std::collections::HashSet<i64> =
            protected.release_ids.iter().copied().collect();
        let prot_keys: std::collections::HashSet<&str> = protected
            .title_keys
            .iter()
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .collect();

        // -- candidate query, built once, SHARED with evict_preview --
        // The preview's whole promise is that it walks the exact sequence
        // a real eviction would, so the two must build their SQL through
        // the one function below and can never drift.
        let (sql, params) = candidate_query(policy, protected);

        // -- the eviction loop --
        //
        // Two independent stop signals, and EITHER can stop us, because
        // over-deleting is the one failure mode that costs the user data:
        //
        //  measured  - live_bytes() re-read from the file after every
        //              batch. Ground truth, but blind to space stranded
        //              in partly-emptied pages, so it can lag reality.
        //  predicted - starts at the measured size and walks down by the
        //              estimated payload of what we delete. Immune to
        //              that lag, but only as good as the estimate.
        //
        // `scale` lifts the raw payload estimate to real page cost
        // (b-tree fanout, idx_rel_stem, idx_rel_kind, FTS5). It is fitted
        // from the previous batch's observed drop rather than from a
        // whole-table scan, which on an 800k-row index would mean reading
        // every segments blob just to decide what to delete. It is
        // clamped at >= 1.0 because a deleted row's own bytes are a hard
        // floor on what a later VACUUM reclaims, and <= 4.0 so one odd
        // batch cannot make `predicted` fall off a cliff.
        //
        // ERROR BOUND, measured (see the tests at the end of this file):
        //  * blob-dominated rows, the shape that actually fills this
        //    database - real page cost / raw payload = 0.997 to 1.010.
        //    The estimate is essentially exact.
        //  * 200-byte rows, where per-row and index overhead dominates -
        //    1.18 to 1.25. The seed of 1.0 makes the FIRST batch of a
        //    call take up to ~20% more rows than it needed; every batch
        //    after it uses the fitted value.
        // A batch stops the moment the estimate reaches the low water
        // mark, so a call's overshoot is its LAST batch's overshoot, and
        // is bounded by EVICT_PAGE rows regardless of what the estimate
        // does. On top of that sits the indivisible-row floor: the row
        // that crosses the line is deleted whole, so a single 256 MB
        // release can carry the file well past the mark on its own.
        // End to end that put the test fixtures at 75-84% of the cap
        // instead of the 90% low water mark - inside the hysteresis band
        // by construction, and never near emptying the index.
        //
        // Under-shooting (the estimate claiming more freed than really
        // was) is self-correcting and costs nothing: the daemon's next
        // pass sees the file still over the cap and evicts again.
        let mut removed = 0usize;
        let mut offset = 0usize; // protected rows already stepped over
        let mut scale = 1.0f64;
        let mut predicted = self.live_bytes()? as f64;
        let mut guard = 0u32;
        // Set at every exit that is NOT "we got under the low water mark".
        // Reconciled against the real size once the loop is done.
        let mut blocked = false;
        loop {
            guard += 1;
            if guard > 100_000 {
                blocked = true;
                break;
            }
            let measured = self.live_bytes()? as f64;
            let effective = measured.min(predicted);
            if effective <= low as f64 {
                break;
            }
            let need = effective - low as f64;

            let page: Vec<(i64, String, i64)> = {
                let mut stmt = self.db.prepare_cached(&sql)?;
                let mut binds: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|b| b.as_ref()).collect();
                let lim = EVICT_PAGE as i64;
                let off = offset as i64;
                binds.push(&lim);
                binds.push(&off);
                stmt.query_map(binds.as_slice(), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            if page.is_empty() {
                blocked = true;
                break; // nothing left we are allowed to touch
            }
            let exhausted = page.len() < EVICT_PAGE;

            let mut ids: Vec<i64> = Vec::new();
            let mut payload = 0f64;
            let mut skipped = 0usize;
            for (id, key, pl) in &page {
                if prot_ids.contains(id) || prot_keys.contains(key.as_str()) {
                    // Survives, and stays in the table - so the next page
                    // must start past it or we would re-read it forever.
                    skipped += 1;
                    continue;
                }
                ids.push(*id);
                payload += (*pl).max(0) as f64;
                if payload * scale >= need {
                    break;
                }
            }
            offset += skipped;
            if ids.is_empty() {
                if exhausted {
                    blocked = true;
                    break; // every remaining candidate is protected
                }
                continue; // whole page was protected; offset advanced
            }

            removed += self.prune_batch(&ids)?;
            let after = self.live_bytes()? as f64;
            if payload > 0.0 {
                scale = ((measured - after) / payload).clamp(1.0, 4.0);
            }
            predicted = (predicted - payload * scale).max(0.0);
        }

        let after = self.db_bytes()?;
        let live_after = self.live_bytes()?;
        Ok(EvictReport {
            removed,
            bytes_before: before,
            bytes_after: after,
            live_before,
            live_after,
            needs_compact: removed > 0,
            // Stopping early only counts as blocked if it actually left
            // the database over the target. Stopping between the low
            // water mark and the target is the hysteresis band doing its
            // job, not a failure.
            blocked: blocked && live_after > target_bytes,
        })
    }

    /// What `evict_to` WOULD delete, without deleting it. Walks the same
    /// candidate query in the same order (they share `candidate_query`,
    /// so they cannot drift) and stops where the estimator says the low
    /// water mark is reached - or at `max_examine` rows, because on a
    /// tens-of-millions-row index an unbounded read-only walk is still a
    /// long time inside the write lock the caller holds.
    ///
    /// The byte figure is the raw payload estimate at scale 1.0. A real
    /// eviction fits its scale from what each batch actually frees, so on
    /// overhead-dominated rows (tiny segments) the preview can OVERSTATE
    /// the rows needed by up to ~25%; on the blob-dominated rows that
    /// actually fill this database it is within ~1% (the measured bounds
    /// in `evict_to`'s comment). A preview is an estimate, and the report
    /// says so by carrying `est_` names.
    pub fn evict_preview(
        &self,
        target_bytes: u64,
        policy: &EvictPolicy,
        protected: &Protected,
        max_examine: usize,
    ) -> rusqlite::Result<EvictPreview> {
        let live = self.live_bytes()?;
        let mut out = EvictPreview {
            live_bytes: live,
            target_bytes,
            low_bytes: if target_bytes == 0 {
                0
            } else {
                evict_low_water(target_bytes, policy)
            },
            ..Default::default()
        };
        // 0 = unlimited: nothing would be evicted, and that is an answer.
        if target_bytes == 0 || live <= target_bytes {
            out.reachable = true;
            return Ok(out);
        }
        let need = (live - out.low_bytes) as f64;

        let prot_ids: std::collections::HashSet<i64> =
            protected.release_ids.iter().copied().collect();
        let prot_keys: std::collections::HashSet<&str> = protected
            .title_keys
            .iter()
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .collect();

        let (sql, params) = candidate_query(policy, protected);
        let mut by_kind: std::collections::HashMap<String, (usize, u64)> =
            std::collections::HashMap::new();
        let mut payload = 0f64;
        let mut offset = 0usize;
        let mut examined = 0usize;
        'walk: loop {
            let page: Vec<(i64, String, i64, String)> = {
                let mut stmt = self.db.prepare_cached(&sql)?;
                let mut binds: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|b| b.as_ref()).collect();
                let lim = EVICT_PAGE as i64;
                let off = offset as i64;
                binds.push(&lim);
                binds.push(&off);
                stmt.query_map(binds.as_slice(), |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            if page.is_empty() {
                break; // ran out of candidates: the cap is not reachable
            }
            let exhausted = page.len() < EVICT_PAGE;
            offset += page.len();
            for (id, key, pl, kind) in &page {
                examined += 1;
                if prot_ids.contains(id) || prot_keys.contains(key.as_str()) {
                    out.protected_skipped += 1;
                    continue;
                }
                out.rows += 1;
                let b = (*pl).max(0) as u64;
                out.est_bytes += b;
                payload += b as f64;
                let slot = by_kind.entry(kind.clone()).or_default();
                slot.0 += 1;
                slot.1 += b;
                if payload >= need {
                    out.reachable = true;
                    break 'walk;
                }
                if examined >= max_examine {
                    out.truncated = true;
                    break 'walk;
                }
            }
            if exhausted {
                break;
            }
            if examined >= max_examine {
                out.truncated = true;
                break;
            }
        }
        out.by_kind = {
            let mut v: Vec<(String, usize, u64)> =
                by_kind.into_iter().map(|(k, (n, b))| (k, n, b)).collect();
            v.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
            v
        };
        Ok(out)
    }

    // -- Spotnet spots (M14j) - curated metadata layered over the raw index --
}

/// The candidate SELECT `evict_to` deletes from and `evict_preview`
/// reads, built ONCE here so the two can never disagree about what is
/// eligible. Returns the SQL (with `LIMIT ?n OFFSET ?n+1` as the last
/// two placeholders) and the bound parameters for everything before them.
fn candidate_query(
    policy: &EvictPolicy,
    protected: &Protected,
) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    let mut wheres: Vec<String> = Vec::new();
    if !policy.kinds.is_empty() {
        // Bound parameters, never interpolated - `kinds` comes off the
        // settings API. Note an unclassified row (kind = '') matches no
        // filter, so a kind-restricted eviction spares it: protect
        // more, never less.
        let ph: Vec<String> = policy
            .kinds
            .iter()
            .map(|k| {
                params.push(Box::new(k.clone()));
                format!("?{}", params.len())
            })
            .collect();
        wheres.push(format!("r.kind IN ({})", ph.join(",")));
    }
    if !policy.keep_kinds.is_empty() {
        // The protective direction of the same filter: rows of these
        // kinds are simply never candidates, whatever `kinds` says - a
        // kind named in both lists is KEPT, because when two settings
        // disagree the answer that deletes less is the safe one. An
        // unclassified row ('' kind) is NOT covered: this list names
        // kinds, and '' is the absence of one. `NOT IN` over bound
        // literals - see the NULL-trap note below.
        let ph: Vec<String> = policy
            .keep_kinds
            .iter()
            .map(|k| {
                params.push(Box::new(k.clone()));
                format!("?{}", params.len())
            })
            .collect();
        wheres.push(format!("r.kind NOT IN ({})", ph.join(",")));
    }
    if let Some(scope_sql) = evict_scope_sql(policy.scope) {
        wheres.push(scope_sql.to_string());
    }
    // NULL TRAP: the schema comment on `wall_hidden` records that one
    // NULL key makes `x NOT IN (SELECT ...)` evaluate NULL for every
    // row and silently disable the whole prune. These `NOT IN` lists
    // are immune by construction - they are bound literals from Rust
    // `i64`/`String`, never a subquery and never NULL - and the left
    // sides (`releases.id` PRIMARY KEY, `releases.title_key` NOT NULL,
    // `releases.kind` NOT NULL) cannot be NULL either. No subquery form
    // is used anywhere in this path for exactly that reason.
    let mut budget = EVICT_PROTECT_BIND_CAP;
    for chunk in protected.release_ids.chunks(EVICT_PROTECT_CHUNK) {
        if budget == 0 {
            break;
        }
        let take = chunk.len().min(budget);
        budget -= take;
        let ph: Vec<String> = chunk[..take]
            .iter()
            .map(|id| {
                params.push(Box::new(*id));
                format!("?{}", params.len())
            })
            .collect();
        wheres.push(format!("r.id NOT IN ({})", ph.join(",")));
    }
    for chunk in protected.title_keys.chunks(EVICT_PROTECT_CHUNK) {
        if budget == 0 {
            break;
        }
        let keys: Vec<&String> = chunk.iter().filter(|s| !s.is_empty()).collect();
        let take = keys.len().min(budget);
        if take == 0 {
            continue;
        }
        budget -= take;
        let ph: Vec<String> = keys[..take]
            .iter()
            .map(|k| {
                params.push(Box::new((*k).clone()));
                format!("?{}", params.len())
            })
            .collect();
        wheres.push(format!("r.title_key NOT IN ({})", ph.join(",")));
    }
    let where_sql = if wheres.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", wheres.join(" AND "))
    };
    let limit_ph = params.len() + 1;
    let offset_ph = params.len() + 2;
    let sql = format!(
        "SELECT r.id, r.title_key, {EVICT_PAYLOAD_SQL}, r.kind FROM releases r
         {where_sql} ORDER BY {} LIMIT ?{limit_ph} OFFSET ?{offset_ph}",
        evict_order_sql(policy.order)
    );
    (sql, params)
}

/// Which releases give way first when the index has to shrink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvictOrder {
    /// Default. An ordered ladder, not a single rule: reap what nobody
    /// would miss before touching anything they would.
    ///
    ///   rung 0  junk AND incomplete - dead obfuscated fragments
    ///   rung 1  junk but complete
    ///   rung 2  incomplete but not junk (a stalled/abandoned post)
    ///   rung 3  everything else - real, complete, wall-visible content
    ///
    /// and within a rung, oldest by `first_posted` first, then largest
    /// by `total_bytes` (free the most for the fewest deletions).
    /// Measured on the live index ~87% of rows sit on rungs 0-1, so in
    /// practice the ladder absorbs the whole cap before rung 3 is ever
    /// reached.
    #[default]
    Ladder,
    /// Single-key orders. No ladder, no junk/completeness preference.
    Oldest,
    Newest,
    Largest,
    Smallest,
}

/// Which rows are candidates AT ALL, before any order is applied. The
/// junk threshold is the same `>= 50` the ladder's rung 0/1 and
/// `prune_stale_partials` use, so the three can never disagree about
/// what "junk" means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvictScope {
    /// Default: every row is a candidate (the orders decide sequence).
    #[default]
    All,
    /// Only rows already scored junk (`junk >= 50`).
    Junk,
    /// Only incomplete rows (`complete = 0`).
    Incomplete,
    /// Junk OR incomplete - the union, which is exactly "never delete
    /// real, complete content, whatever the cap says". Under this scope
    /// a cap the junk cannot satisfy reports `blocked` rather than
    /// reaching into the wall's real rows.
    JunkOrIncomplete,
}

/// The scope's WHERE fragment; `None` for All so the common case adds
/// no clause at all.
fn evict_scope_sql(scope: EvictScope) -> Option<&'static str> {
    match scope {
        EvictScope::All => None,
        EvictScope::Junk => Some("r.junk >= 50"),
        EvictScope::Incomplete => Some("r.complete = 0"),
        EvictScope::JunkOrIncomplete => Some("(r.junk >= 50 OR r.complete = 0)"),
    }
}

#[derive(Debug, Clone, Default)]
pub struct EvictPolicy {
    pub order: EvictOrder,
    /// Restrict eviction to these kinds ("movie"/"tv"/"software"/"other").
    /// Empty = all kinds.
    pub kinds: Vec<String>,
    /// Kinds that are NEVER evicted, whatever `kinds` says - the
    /// protective complement. A kind in both lists is kept. Empty =
    /// nothing is exempt by kind.
    pub keep_kinds: Vec<String>,
    /// Which rows are candidates at all. Default All.
    pub scope: EvictScope,
    /// How far below the cap an eviction empties, in percent of the
    /// cap: `Some(20)` evicts to 80% of the target. `None` = the
    /// default `EVICT_HEADROOM_DEFAULT_PCT`. Clamped to 0..=50 - past
    /// 50 the "headroom" would be deleting most of a database the user
    /// said could be twice the size. 0 means evict exactly to the cap,
    /// which weakens the anti-thrash promise (see the hysteresis note
    /// on `EVICT_HEADROOM_DEFAULT_PCT`) but is an honest request.
    pub headroom_pct: Option<u32>,
}

/// The low water mark a policy's headroom asks for. Shared by
/// `evict_to` and `evict_preview` so the two stop at the same line.
fn evict_low_water(target_bytes: u64, policy: &EvictPolicy) -> u64 {
    let pct = policy
        .headroom_pct
        .unwrap_or(EVICT_HEADROOM_DEFAULT_PCT)
        .min(50) as u64;
    target_bytes / 100 * (100 - pct)
}

/// What the daemon forbids evicting. index.rs NEVER reaches out for this -
/// the daemon owns the queue, watchlist and history and passes it in.
#[derive(Debug, Clone, Default)]
pub struct Protected {
    pub title_keys: Vec<String>,
    pub release_ids: Vec<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct EvictReport {
    pub removed: usize,
    /// Raw file size (`db_bytes()`) either side of the call. This is what
    /// the user sees in Finder, so it is what the daemon reports - but it
    /// barely moves, because DELETE frees pages to the freelist rather
    /// than shortening the file. Do NOT test progress with it.
    pub bytes_before: u64,
    pub bytes_after: u64,
    /// `live_bytes()` either side of the call: the honest figure, and the
    /// one to compare against the target. `live_after <= target` is what
    /// "we got there" means.
    pub live_before: u64,
    pub live_after: u64,
    /// True when rows were deleted, so the caller should schedule a compact.
    pub needs_compact: bool,
    /// True when eviction stopped with the database still above its
    /// target because it ran out of rows it was ALLOWED to delete - every
    /// remaining candidate is protected, or the kinds filter excludes it.
    ///
    /// Without this the caller cannot tell "there was nothing left to do"
    /// from "we were stopped", and a still-oversized database looks like a
    /// success. `live_after` says how far it got; this says it stopped
    /// short on purpose rather than because the target was met.
    pub blocked: bool,
}

/// What `evict_preview` reports: the candidates a real eviction at the
/// same target and policy would take, summed but untouched. Every byte
/// figure is the raw payload estimate (scale 1.0 - see the method doc
/// for the measured error bounds), which is why the names say `est_`.
#[derive(Debug, Clone, Default)]
pub struct EvictPreview {
    /// Rows the walk selected for deletion.
    pub rows: usize,
    /// Their estimated payload bytes.
    pub est_bytes: u64,
    /// Per-kind breakdown of the same rows: (kind, rows, est bytes),
    /// biggest first. `""` is a row that never classified.
    pub by_kind: Vec<(String, usize, u64)>,
    /// The live size the walk started from, and the line it walked to.
    pub live_bytes: u64,
    pub target_bytes: u64,
    pub low_bytes: u64,
    /// True when the candidates reach the low water mark (per the
    /// estimate). False = a real eviction would stop short too: the
    /// scope, kinds filters and protections leave too little.
    pub reachable: bool,
    /// Candidates the walk itself stepped over because they are
    /// protected. A SMALL protected set is excluded inside the SQL and
    /// never reaches the walk, so this is usually 0; it counts the rows
    /// the bind-cap optimisation could not exclude, exactly as the real
    /// eviction's Rust-side re-check does. The daemon reports the full
    /// protected-set size separately.
    pub protected_skipped: usize,
    /// True when the walk hit its `max_examine` bound before an answer:
    /// the figures are a floor, not the total.
    pub truncated: bool,
}

/// Evict down to this far below the cap rather than to the cap itself,
/// unless the policy names its own `headroom_pct`.
///
/// HYSTERESIS. Without a gap, a database sitting one page over the cap
/// would be trimmed back to exactly the cap, the next scan pass would
/// push it one page over again, and every pass from then on would take
/// the write lock, delete a handful of rows and set `needs_compact` -
/// a permanent grind at the boundary that also means a permanent VACUUM
/// backlog. Emptying to 90% buys roughly a tenth of the cap of headroom,
/// so on a 2 GB cap the index has ~200 MB to refill before eviction is
/// due again - hours of scanning, not one pass.
const EVICT_HEADROOM_DEFAULT_PCT: u32 = 10;

/// Rows examined (and at most deleted) per batch. Bounds how long one
/// `prune_batch` holds the write lock against the parallel scanners'
/// 10 s busy timeout, and bounds how far a single batch can overshoot
/// the low-water mark. `prune_age` uses 8000; eviction re-measures the
/// file between batches, so it wants smaller, more frequent steps.
///
/// The cost of the smaller step is that each batch re-runs the candidate
/// query, and no index can serve the ladder's CASE expression, so that is
/// a scan-and-sort of `releases` every time. Measured: a 266 MB / 60k-row
/// index evicts 12_440 rows (7 batches) in 616 ms. That is fine for the
/// scheduled maintenance pass this is; if it ever stops being fine, the
/// fix is to fetch ids in much larger pages and pull the per-row payload
/// only for the chunk about to be deleted - one sort per page instead of
/// one per batch, with the byte-accurate stop point kept intact.
const EVICT_PAGE: usize = 2_000;

/// How many protected entries we are willing to push into the candidate
/// SQL as bound `NOT IN` parameters. SQLite hard-limits a statement to
/// 32766 variables, and the existing `OWNED_IN_CAP` picks 10_000 for the
/// same reason. Anything past the cap is NOT dropped: the SQL filter is
/// only an optimisation, and every candidate row is re-checked in Rust
/// against the FULL protected set before it can be deleted (see
/// `evict_to`). Overflowing the cap therefore costs a little scan work,
/// never a lost protection.
const EVICT_PROTECT_BIND_CAP: usize = 10_000;

/// Bound parameters per `NOT IN (...)` clause; several clauses are ANDed
/// so the cap above can be spent without any one list going near the
/// per-statement variable limit.
const EVICT_PROTECT_CHUNK: usize = 500;

/// Per-release payload estimate, in SQL. The bulk of this database is
/// the `files.segments` JSON blobs, which run from a few bytes to
/// hundreds of KB per release, so a row count is a useless proxy for
/// bytes - the estimate has to read the actual value lengths.
///
/// `LENGTH()` on a TEXT column counts characters, not bytes; `segments`
/// and `filename` are ASCII JSON / ASCII-ish names, so the two agree in
/// practice, and the constants below (24 bytes per `files` row, 96 per
/// `releases` row) stand in for the record headers, rowid keys and the
/// small fixed integer columns. Everything the estimate cannot see -
/// b-tree interior pages, `idx_rel_stem` / `idx_rel_kind`, the FTS5
/// index - is folded in by the runtime scale factor in `evict_to`.
const EVICT_PAYLOAD_SQL: &str = "(SELECT COALESCE(SUM(LENGTH(f.segments) \
     + LENGTH(f.filename) + 24), 0) FROM files f WHERE f.release_id = r.id) \
     + LENGTH(r.stem) + LENGTH(r.poster) + LENGTH(r.grp) + LENGTH(r.title_key) \
     + LENGTH(r.res) + LENGTH(r.kind) + LENGTH(r.langs) + 96";

/// The ORDER BY that turns a policy into an eviction sequence.
///
/// `first_posted = 0` means the post's OVER Date failed to parse, not
/// that it is from 1970. `prune_age` spares those rows outright; here
/// they cannot be spared (the cap is a hard limit), so instead the
/// leading `(r.first_posted = 0) ASC` term parks them at the BACK of
/// every date-driven order - unknown-date rows are the last thing an
/// age-shaped policy touches, in both directions. `r.id` closes every
/// order so the sequence is total and a paged scan is stable.
fn evict_order_sql(order: EvictOrder) -> &'static str {
    match order {
        // `junk` is the M28 0-100 curation score, not a flag; >= 50 is
        // the established "already hidden from the wall" threshold that
        // `prune_stale_partials` reaps on, reused here so the two can
        // never disagree about what "junk" means.
        EvictOrder::Ladder => {
            "CASE WHEN r.junk >= 50 AND r.complete = 0 THEN 0 \
                  WHEN r.junk >= 50 THEN 1 \
                  WHEN r.complete = 0 THEN 2 \
                  ELSE 3 END ASC, \
             (r.first_posted = 0) ASC, r.first_posted ASC, \
             r.total_bytes DESC, r.id ASC"
        }
        EvictOrder::Oldest => "(r.first_posted = 0) ASC, r.first_posted ASC, r.id ASC",
        EvictOrder::Newest => "(r.first_posted = 0) ASC, r.first_posted DESC, r.id DESC",
        EvictOrder::Largest => "r.total_bytes DESC, r.id ASC",
        EvictOrder::Smallest => "r.total_bytes ASC, r.id ASC",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::teardown;

    /// One fixture release, written straight to SQL so every column the
    /// eviction orders read (junk / complete / first_posted / total_bytes
    /// / kind / title_key) can be set exactly. `blob` is the size of the
    /// fake `segments` payload, which is what actually makes the database
    /// file grow - `total_bytes` is only metadata about the Usenet post.
    fn ev_rel(
        ix: &Index,
        id: i64,
        junk: i64,
        complete: i64,
        posted: i64,
        total_bytes: i64,
        kind: &str,
        title_key: &str,
        blob: usize,
    ) {
        ix.db
            .execute(
                "INSERT INTO releases(id, stem, poster, grp, total_bytes, files,
                     has_par2, complete, first_posted, first_seen, kind, res,
                     have_parts, need_parts, title_key, junk, oracle_at, langs)
                 VALUES(?1, ?2, 'p@p', 'alt.test', ?3, 1, 0, ?4, ?5, ?5, ?6,
                        '1080p', 1, 1, ?7, ?8, 0, '')",
                rusqlite::params![
                    id,
                    format!("Fixture.Release.{id}.1080p.WEB.x264-EV"),
                    total_bytes,
                    complete,
                    posted,
                    kind,
                    title_key,
                    junk
                ],
            )
            .unwrap();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments)
                 VALUES(?1, ?2, 1, ?3, ?4)",
                rusqlite::params![id, format!("f{id}.mkv"), total_bytes, "x".repeat(blob)],
            )
            .unwrap();
    }

    fn ev_open(tag: &str) -> (std::path::PathBuf, Index) {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-ev-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        (dir, ix)
    }

    fn ev_ids(ix: &Index) -> Vec<i64> {
        let mut stmt = ix
            .db
            .prepare("SELECT id FROM releases ORDER BY id")
            .unwrap();
        let v: Vec<i64> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        v
    }

    /// Every deleted id must come from the front of `expected` and every
    /// survivor from the back - i.e. eviction walked the policy order and
    /// stopped somewhere, never picked out of sequence.
    fn assert_prefix_evicted(expected: &[i64], survivors: &[i64]) {
        let cut = expected.len() - survivors.len();
        let want_tail: Vec<i64> = expected[cut..].to_vec();
        let mut got = survivors.to_vec();
        let mut want = want_tail.clone();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(
            got, want,
            "survivors must be the tail of the policy order\n  order:     {expected:?}\n  survivors: {survivors:?}"
        );
    }

    /// 8 uniform-payload releases. `total_bytes` is deliberately shuffled
    /// against `first_posted` so the size orders and the date orders are
    /// different permutations and cannot be confused for each other.
    const EV_BLOB: usize = 64 * 1024;
    const EV_SIZES: [i64; 8] = [500, 800, 100, 700, 300, 900, 200, 400];

    fn ev_eight(ix: &Index) {
        for i in 1..=8i64 {
            ev_rel(
                ix,
                i,
                0,
                1,
                1000 * i,
                EV_SIZES[(i - 1) as usize],
                "movie",
                &format!("m:fixture {i}:2020"),
                EV_BLOB,
            );
        }
    }

    /// Target that forces roughly a third of the file away - enough that
    /// several releases must go, not so much that everything does.
    fn ev_target(ix: &Index) -> u64 {
        ix.db_bytes().unwrap() * 3 / 4
    }

    #[test]
    fn evict_target_zero_is_unlimited_and_removes_nothing() {
        let (dir, ix) = ev_open("zero");
        ev_eight(&ix);
        let before = ix.db_bytes().unwrap();
        let rep = ix
            .evict_to(0, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert_eq!(rep.removed, 0);
        assert_eq!(rep.bytes_before, before);
        assert_eq!(rep.bytes_after, before);
        assert!(!rep.needs_compact);
        assert_eq!(ev_ids(&ix).len(), 8, "no row may be touched when unlimited");
        teardown(&dir, ix);
    }

    #[test]
    fn evict_single_key_orders_follow_their_key() {
        // (order, the exact sequence eviction must walk)
        let cases: [(EvictOrder, [i64; 8]); 4] = [
            (EvictOrder::Oldest, [1, 2, 3, 4, 5, 6, 7, 8]),
            (EvictOrder::Newest, [8, 7, 6, 5, 4, 3, 2, 1]),
            // total_bytes DESC: 900,800,700,500,400,300,200,100
            (EvictOrder::Largest, [6, 2, 4, 1, 8, 5, 7, 3]),
            (EvictOrder::Smallest, [3, 7, 5, 8, 1, 4, 2, 6]),
        ];
        for (order, expected) in cases {
            let (dir, ix) = ev_open(&format!("ord{order:?}"));
            ev_eight(&ix);
            let target = ev_target(&ix);
            let policy = EvictPolicy {
                order,
                ..Default::default()
            };
            let rep = ix.evict_to(target, &policy, &Protected::default()).unwrap();
            let left = ev_ids(&ix);
            assert!(rep.removed > 0, "{order:?} must evict something");
            assert!(!left.is_empty(), "{order:?} must not empty the index");
            assert_eq!(rep.removed, 8 - left.len(), "{order:?} removed count");
            assert!(
                rep.needs_compact,
                "{order:?} deleted rows, so compact is due"
            );
            assert_prefix_evicted(&expected, &left);
            teardown(&dir, ix);
        }
    }

    #[test]
    fn evict_ladder_climbs_junk_then_incomplete_then_age_then_size() {
        let (dir, ix) = ev_open("ladder");
        // rung 0: junk AND incomplete, oldest first, then largest.
        ev_rel(&ix, 1, 80, 0, 5_000, 100, "movie", "m:a:2020", EV_BLOB);
        ev_rel(&ix, 2, 80, 0, 9_000, 900, "movie", "m:b:2020", EV_BLOB);
        // rung 1: junk but complete.
        ev_rel(&ix, 3, 80, 1, 1_000, 900, "movie", "m:c:2020", EV_BLOB);
        // rung 2: incomplete but clean - note it is the OLDEST row in the
        // whole fixture, so a plain age sort would take it first.
        ev_rel(&ix, 4, 0, 0, 100, 900, "movie", "m:d:2020", EV_BLOB);
        // rung 3: real content. Older first, then bigger first on a tie.
        ev_rel(&ix, 5, 0, 1, 2_000, 100, "movie", "m:e:2020", EV_BLOB);
        ev_rel(&ix, 6, 0, 1, 7_000, 900, "movie", "m:f:2020", EV_BLOB);
        ev_rel(&ix, 7, 0, 1, 7_000, 100, "movie", "m:g:2020", EV_BLOB);
        // rung 3 with an unparsed date: parked at the very back, exactly
        // as prune_age spares first_posted = 0.
        ev_rel(&ix, 8, 0, 1, 0, 900, "movie", "m:h:2020", EV_BLOB);
        let expected = [1i64, 2, 3, 4, 5, 6, 7, 8];

        let target = ev_target(&ix);
        let rep = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        let left = ev_ids(&ix);
        assert!(rep.removed > 0);
        assert!(!left.is_empty());
        assert_prefix_evicted(&expected, &left);
        // The ladder's whole point: junk goes before real content does.
        assert!(!left.contains(&1), "junk+incomplete must go first");
        assert!(left.contains(&8), "unknown-date real content goes last");
        teardown(&dir, ix);
    }

    #[test]
    fn evict_protection_is_absolute_even_at_maximum_pressure() {
        let (dir, ix) = ev_open("prot");
        ev_eight(&ix);
        // Protect id 4 by id and id 6 by title_key. Then ask for a cap of
        // one byte: every other release must go, and the two protected
        // ones must survive even though they are then the ONLY thing left
        // that could possibly free another byte.
        let prot = Protected {
            title_keys: vec!["m:fixture 6:2020".into()],
            release_ids: vec![4],
        };
        let rep = ix.evict_to(1, &EvictPolicy::default(), &prot).unwrap();
        let left = ev_ids(&ix);
        assert_eq!(left, vec![4, 6], "protected rows survive maximum pressure");
        assert_eq!(rep.removed, 6);
        // It could not reach the target, and says so by leaving the file
        // above it rather than by deleting the protected rows anyway.
        assert!(
            ix.db_bytes().unwrap() > 1,
            "target unreachable: the report is `removed`, not a lie about size"
        );

        // A second run at the same impossible target must be a no-op, not
        // a retry that grinds through the protected rows.
        let again = ix.evict_to(1, &EvictPolicy::default(), &prot).unwrap();
        assert_eq!(again.removed, 0);
        assert!(!again.needs_compact);
        assert_eq!(ev_ids(&ix), vec![4, 6]);
        teardown(&dir, ix);
    }

    #[test]
    fn evict_hysteresis_second_call_removes_nothing() {
        let (dir, ix) = ev_open("hyst");
        ev_eight(&ix);
        let target = ev_target(&ix);
        let first = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert!(first.removed > 0);
        let after_first = ev_ids(&ix);

        // The headroom the low-water mark bought, stated the way the
        // DAEMON reads it: `evict_pass` acts only when live_bytes is over
        // the cap, so landing anywhere inside the band means the next
        // scan pass does nothing at all. This is the anti-thrash promise.
        let live_after_first = ix.live_bytes().unwrap();
        assert!(
            live_after_first <= target,
            "first call left {live_after_first} over the cap {target}, so every \
             scan pass would evict again - the grind hysteresis exists to stop"
        );

        // Calling evict_to again at the same target is a stricter probe
        // than the daemon ever makes, and it is NOT promised to be a
        // no-op: the loop exits on `min(measured, predicted)`, so a
        // prediction that under-shot by less than one row leaves the file
        // a few bytes above the low-water mark and a second call shaves
        // that one row. What must hold is that it CONVERGES rather than
        // walking the file down a row per call.
        //
        // This used to be asserted as `second.removed == 0`, which passed
        // on page-boundary luck: measured on this fixture, the first call
        // landed 1228 bytes UNDER the mark before §95 gave the database a
        // pointer-map page, and 103 bytes OVER it after - a 1.3 KB swing
        // on a 540 KB fixture, decided entirely by 4 KB page granularity
        // and never by hysteresis.
        let second = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert!(
            second.removed <= 1,
            "a second call at the same target took {} rows - that is a grind, \
             not a boundary rounding",
            second.removed
        );
        let third = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert_eq!(third.removed, 0, "hysteresis: no boundary thrash");
        assert!(!third.needs_compact);
        if second.removed == 0 {
            assert_eq!(ev_ids(&ix), after_first);
        }

        // And the file really is under the cap (not merely under the
        // low-water estimate) once the freed pages are given back.
        ix.compact().unwrap();
        assert!(
            ix.db_bytes().unwrap() <= target,
            "post-compact size {} must fit the cap {target}",
            ix.db_bytes().unwrap()
        );
        teardown(&dir, ix);
    }

    #[test]
    fn evict_kinds_filter_restricts_to_listed_kinds() {
        let (dir, ix) = ev_open("kinds");
        for i in 1..=4i64 {
            ev_rel(
                &ix,
                i,
                0,
                1,
                1000 * i,
                100,
                "tv",
                &format!("t:s{i}"),
                EV_BLOB,
            );
        }
        for i in 5..=8i64 {
            ev_rel(
                &ix,
                i,
                0,
                1,
                1000 * i,
                100,
                "movie",
                &format!("m:f{i}"),
                EV_BLOB,
            );
        }
        // A legacy row that never got classified. It matches no filter, so
        // a kind-restricted eviction must leave it alone.
        ev_rel(&ix, 9, 90, 0, 10, 100, "", "", EV_BLOB);

        // Impossible cap, but only "tv" may be touched.
        let policy = EvictPolicy {
            order: EvictOrder::Oldest,
            kinds: vec!["tv".into()],
            ..Default::default()
        };
        let rep = ix.evict_to(1, &policy, &Protected::default()).unwrap();
        assert_eq!(rep.removed, 4);
        assert_eq!(
            ev_ids(&ix),
            vec![5, 6, 7, 8, 9],
            "only tv rows were eligible"
        );
        teardown(&dir, ix);
    }

    #[test]
    fn evict_protected_set_past_the_bind_limit_still_protects_everything() {
        let (dir, ix) = ev_open("bindcap");
        ev_eight(&ix);
        // 30_000 protected ids - far past both EVICT_PROTECT_BIND_CAP and
        // SQLite's 32766-variable ceiling - with the ids that actually
        // exist deliberately placed at the END, past anything the SQL
        // `NOT IN` binds can reach. Only the Rust-side check can save
        // them, which is exactly the fallback being tested.
        let mut ids: Vec<i64> = (1_000_000..1_030_000).collect();
        ids.extend([1i64, 2, 3, 4, 5, 6, 7, 8]);
        let mut keys: Vec<String> = (0..30_000).map(|i| format!("m:filler {i}:1999")).collect();
        keys.push("m:fixture 1:2020".into());
        let prot = Protected {
            title_keys: keys,
            release_ids: ids,
        };

        let rep = ix.evict_to(1, &EvictPolicy::default(), &prot).unwrap();
        assert_eq!(
            rep.removed, 0,
            "nothing may be deleted when all is protected"
        );
        assert!(!rep.needs_compact);
        assert_eq!(ev_ids(&ix), vec![1, 2, 3, 4, 5, 6, 7, 8]);

        // Same oversized set, but now one row is genuinely unprotected:
        // eviction must still make progress rather than stall on the
        // protected rows it keeps scanning past.
        let mut ids2: Vec<i64> = (1_000_000..1_030_000).collect();
        ids2.extend([1i64, 2, 3, 4, 5, 6, 7]); // 8 left out
        let prot2 = Protected {
            title_keys: (0..30_000).map(|i| format!("m:filler {i}:1999")).collect(),
            release_ids: ids2,
        };
        let rep2 = ix.evict_to(1, &EvictPolicy::default(), &prot2).unwrap();
        assert_eq!(rep2.removed, 1);
        assert_eq!(ev_ids(&ix), vec![1, 2, 3, 4, 5, 6, 7]);
        teardown(&dir, ix);
    }

    /// THE size-cap blocker, pinned. `db_bytes()` cannot fall after a
    /// DELETE, so a caller that compares the user's cap against it never
    /// sees the database get back under the cap and re-evicts forever.
    /// `live_bytes()` is the quantity that actually moves, which is why it
    /// is public and why the daemon compares against it.
    #[test]
    fn live_bytes_falls_after_a_delete_where_db_bytes_cannot() {
        let (dir, ix) = ev_open("livebytes");
        ev_uneven(&ix);
        ix.compact().unwrap();
        let db_before = ix.db_bytes().unwrap();
        let live_before = ix.live_bytes().unwrap();

        let rep = ix
            .evict_to(
                db_before / 2,
                &EvictPolicy {
                    order: EvictOrder::Oldest,
                    ..Default::default()
                },
                &Protected::default(),
            )
            .unwrap();
        assert!(rep.removed > 0);

        assert_eq!(
            ix.db_bytes().unwrap(),
            db_before,
            "the file cannot shrink until a compact runs - the whole trap"
        );
        assert!(
            ix.live_bytes().unwrap() < live_before,
            "live_bytes must fall as rows go: {} !< {live_before}",
            ix.live_bytes().unwrap()
        );
        assert_eq!(rep.live_before, live_before);
        assert_eq!(rep.live_after, ix.live_bytes().unwrap());
        assert!(
            rep.live_after < rep.bytes_after,
            "the gap a compact would reclaim"
        );
        teardown(&dir, ix);
    }

    /// `blocked` is the difference between "done" and "stopped", and the
    /// caller cannot tell them apart from `removed` alone: both can be 0.
    #[test]
    fn evict_reports_blocked_only_when_it_was_stopped_short() {
        let (dir, ix) = ev_open("blocked");
        ev_eight(&ix);

        // Everything protected, impossible target: stopped short.
        let all: Vec<i64> = (1..=8).collect();
        let rep = ix
            .evict_to(
                1,
                &EvictPolicy::default(),
                &Protected {
                    title_keys: vec![],
                    release_ids: all,
                },
            )
            .unwrap();
        assert_eq!(rep.removed, 0);
        assert!(rep.blocked, "every candidate was protected: {rep:?}");
        assert!(rep.live_after > 1);

        // Nothing protected, generous target already met: done, not
        // stopped - even though `removed` is 0 here too.
        let big = ix.live_bytes().unwrap() * 4;
        let rep = ix
            .evict_to(big, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert_eq!(rep.removed, 0);
        assert!(
            !rep.blocked,
            "already under the target is not blocked: {rep:?}"
        );

        // Unlimited is never blocked either.
        let rep = ix
            .evict_to(0, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert!(!rep.blocked);
        assert_eq!(rep.live_before, rep.live_after);
        teardown(&dir, ix);
    }

    /// Not a behaviour gate so much as a standing measurement: how close
    /// does the estimator land to the size the file really takes once the
    /// freed pages are handed back? Asserted loosely (the exact ratio
    /// moves with page size and fixture shape), printed so a regression
    /// in the estimator is visible in `cargo test -- --nocapture`.
    fn ev_uneven(ix: &Index) {
        // Wildly uneven payloads: the case a row count gets badly wrong.
        // 24 releases, blob sizes cycling 4K / 64K / 16K / 256K.
        for i in 1..=24i64 {
            let blob = match i % 4 {
                0 => 256 * 1024,
                1 => 4 * 1024,
                2 => 64 * 1024,
                _ => 16 * 1024,
            };
            ev_rel(
                ix,
                i,
                0,
                1,
                1000 * i,
                100,
                "movie",
                &format!("m:e{i}:2020"),
                blob,
            );
        }
    }

    /// The other size regime, and the only test that spans more than one
    /// batch. 4000 releases with 200-byte segments: the payload estimate
    /// no longer dominates, so the b-tree, `idx_rel_stem`, `idx_rel_kind`
    /// and the FTS5 index carry most of the real page cost (measured
    /// scale here: 1.18-1.25, against ~1.00 when the blobs are large).
    /// This is what the runtime-fitted scale factor exists for.
    #[test]
    fn evict_spans_batches_when_row_overhead_dominates() {
        let (dir, ix) = ev_open("manyrows");
        // One transaction for the seed: 4,000 autocommit rows are 8,000
        // journal flushes, and the subject starts at the compact below.
        ix.db.execute_batch("BEGIN").unwrap();
        for i in 1..=4000i64 {
            ev_rel(&ix, i, 0, 1, i, 100, "movie", &format!("m:s{i}:2020"), 200);
        }
        ix.db.execute_batch("COMMIT").unwrap();
        ix.compact().unwrap();
        let before = ix.db_bytes().unwrap();
        let target = before / 2;
        let policy = EvictPolicy {
            order: EvictOrder::Oldest,
            ..Default::default()
        };
        let rep = ix.evict_to(target, &policy, &Protected::default()).unwrap();
        assert!(
            rep.removed > EVICT_PAGE,
            "fixture must force more than one batch, removed {}",
            rep.removed
        );
        let left = ev_ids(&ix);
        assert_eq!(rep.removed, 4000 - left.len());
        // Oldest == id order here, so the survivors are the high ids.
        assert_eq!(left.first().copied(), Some(rep.removed as i64 + 1));
        ix.compact().unwrap();
        let actual = ix.db_bytes().unwrap();
        assert!(actual <= target, "must reach the cap: {actual} > {target}");
        assert!(
            left.len() >= 1000,
            "over-eviction: only {} of 4000 rows left to free half the file",
            left.len()
        );
        teardown(&dir, ix);
    }

    #[test]
    fn evict_keep_kinds_are_never_candidates_even_at_maximum_pressure() {
        let (dir, ix) = ev_open("keepkinds");
        for i in 1..=4i64 {
            ev_rel(
                &ix,
                i,
                0,
                1,
                1000 * i,
                100,
                "tv",
                &format!("t:k{i}"),
                EV_BLOB,
            );
        }
        for i in 5..=8i64 {
            ev_rel(
                &ix,
                i,
                0,
                1,
                1000 * i,
                100,
                "movie",
                &format!("m:k{i}"),
                EV_BLOB,
            );
        }
        // An unclassified row: keep_kinds names kinds, and '' is the
        // absence of one, so it stays a candidate.
        ev_rel(&ix, 9, 0, 1, 10, 100, "", "", EV_BLOB);

        let policy = EvictPolicy {
            order: EvictOrder::Oldest,
            keep_kinds: vec!["tv".into()],
            ..Default::default()
        };
        let rep = ix.evict_to(1, &policy, &Protected::default()).unwrap();
        assert_eq!(rep.removed, 5, "movies and the unclassified row go");
        assert_eq!(
            ev_ids(&ix),
            vec![1, 2, 3, 4],
            "kept kinds survive an impossible cap"
        );
        assert!(rep.blocked, "the cap was not reached and it must say so");
        teardown(&dir, ix);
    }

    #[test]
    fn evict_keep_wins_when_a_kind_is_in_both_lists() {
        let (dir, ix) = ev_open("keepboth");
        ev_eight(&ix); // all movies
        let policy = EvictPolicy {
            order: EvictOrder::Oldest,
            kinds: vec!["movie".into()],
            keep_kinds: vec!["movie".into()],
            ..Default::default()
        };
        let rep = ix.evict_to(1, &policy, &Protected::default()).unwrap();
        assert_eq!(rep.removed, 0, "keep outranks the restriction list");
        assert!(rep.blocked);
        assert_eq!(ev_ids(&ix).len(), 8);
        teardown(&dir, ix);
    }

    #[test]
    fn evict_scope_junk_incomplete_never_touches_real_complete_content() {
        let (dir, ix) = ev_open("scope");
        // 1-2 junk, 3-4 incomplete, 5-8 real complete content.
        ev_rel(&ix, 1, 80, 1, 1_000, 100, "movie", "m:sa:2020", EV_BLOB);
        ev_rel(&ix, 2, 90, 0, 2_000, 100, "movie", "m:sb:2020", EV_BLOB);
        ev_rel(&ix, 3, 0, 0, 3_000, 100, "movie", "m:sc:2020", EV_BLOB);
        ev_rel(&ix, 4, 0, 0, 4_000, 100, "movie", "m:sd:2020", EV_BLOB);
        for i in 5..=8i64 {
            ev_rel(
                &ix,
                i,
                0,
                1,
                1000 * i,
                100,
                "movie",
                &format!("m:se{i}:2020"),
                EV_BLOB,
            );
        }
        let policy = EvictPolicy {
            scope: EvictScope::JunkOrIncomplete,
            ..Default::default()
        };
        // Impossible cap: everything the scope allows must go, and not
        // one row past it.
        let rep = ix.evict_to(1, &policy, &Protected::default()).unwrap();
        assert_eq!(rep.removed, 4);
        assert_eq!(
            ev_ids(&ix),
            vec![5, 6, 7, 8],
            "real complete rows survive whatever the cap says"
        );
        assert!(rep.blocked, "stopped short of the cap, on purpose");

        // The narrower scopes each take only their own class.
        let (dir2, ix2) = ev_open("scope-junk");
        ev_rel(&ix2, 1, 80, 1, 1_000, 100, "movie", "m:ja:2020", EV_BLOB);
        ev_rel(&ix2, 2, 0, 0, 2_000, 100, "movie", "m:jb:2020", EV_BLOB);
        ev_rel(&ix2, 3, 0, 1, 3_000, 100, "movie", "m:jc:2020", EV_BLOB);
        let junk_only = EvictPolicy {
            scope: EvictScope::Junk,
            ..Default::default()
        };
        ix2.evict_to(1, &junk_only, &Protected::default()).unwrap();
        assert_eq!(ev_ids(&ix2), vec![2, 3], "junk scope takes only junk");
        let inc_only = EvictPolicy {
            scope: EvictScope::Incomplete,
            ..Default::default()
        };
        ix2.evict_to(1, &inc_only, &Protected::default()).unwrap();
        assert_eq!(
            ev_ids(&ix2),
            vec![3],
            "incomplete scope takes only incomplete"
        );
        teardown(&dir, ix);
        teardown(&dir2, ix2);
    }

    #[test]
    fn evict_headroom_controls_how_far_below_the_cap_it_empties() {
        // Same fixture, three headrooms: deeper headroom must land the
        // live size lower (or equal - row granularity can tie), and 0
        // must still get under the cap itself.
        let mut lands: Vec<u64> = Vec::new();
        for (tag, hr) in [("hr0", Some(0u32)), ("hr10", None), ("hr40", Some(40u32))] {
            let (dir, ix) = ev_open(&format!("headroom-{tag}"));
            ev_eight(&ix);
            let target = ev_target(&ix);
            let policy = EvictPolicy {
                order: EvictOrder::Oldest,
                headroom_pct: hr,
                ..Default::default()
            };
            let rep = ix.evict_to(target, &policy, &Protected::default()).unwrap();
            assert!(
                rep.live_after <= target,
                "{tag}: {} must be under the cap {target}",
                rep.live_after
            );
            let low = evict_low_water(target, &policy);
            assert!(
                rep.live_after <= low,
                "{tag}: {} must reach its own low water {low}",
                rep.live_after
            );
            lands.push(rep.live_after);
            teardown(&dir, ix);
        }
        assert!(
            lands[2] <= lands[1] && lands[1] <= lands[0],
            "deeper headroom lands lower: {lands:?}"
        );
    }

    #[test]
    fn evict_preview_matches_the_eviction_it_predicts_and_deletes_nothing() {
        let (dir, ix) = ev_open("preview");
        ev_eight(&ix);
        let target = ev_target(&ix);
        let policy = EvictPolicy {
            order: EvictOrder::Oldest,
            ..Default::default()
        };
        let pv = ix
            .evict_preview(target, &policy, &Protected::default(), usize::MAX)
            .unwrap();
        assert_eq!(ev_ids(&ix).len(), 8, "a preview deletes nothing");
        assert!(pv.rows > 0 && pv.reachable && !pv.truncated);
        assert_eq!(
            pv.by_kind.iter().map(|(_, n, _)| n).sum::<usize>(),
            pv.rows,
            "the per-kind breakdown accounts for every row"
        );
        assert_eq!(pv.by_kind[0].0, "movie");

        // The prediction against the real thing, on the blob-dominated
        // shape where the estimator is near-exact: the same policy at the
        // same target must delete what the preview said, within the one
        // batch of slack the fitted scale can move it.
        let rep = ix.evict_to(target, &policy, &Protected::default()).unwrap();
        assert!(
            (rep.removed as i64 - pv.rows as i64).abs() <= 1,
            "preview said {} rows, eviction took {}",
            pv.rows,
            rep.removed
        );

        // Under the cap already: an honest empty answer, reachable, no walk.
        let pv2 = ix
            .evict_preview(u64::MAX, &policy, &Protected::default(), usize::MAX)
            .unwrap();
        assert_eq!(pv2.rows, 0);
        assert!(pv2.reachable);

        // Unlimited: same shape.
        let pv3 = ix
            .evict_preview(0, &policy, &Protected::default(), usize::MAX)
            .unwrap();
        assert_eq!((pv3.rows, pv3.est_bytes), (0, 0));
        assert!(pv3.reachable);
        teardown(&dir, ix);
    }

    #[test]
    fn evict_preview_reports_protection_truncation_and_unreachable_caps() {
        let (dir, ix) = ev_open("preview-edges");
        ev_eight(&ix);
        // A small protected set is excluded in the SQL, so the walk never
        // sees it: skipped stays 0 and the survivors are simply absent
        // from the count. Same behaviour as the real eviction.
        let small = Protected {
            title_keys: vec!["m:fixture 2:2020".into()],
            release_ids: vec![1],
        };
        let policy = EvictPolicy {
            order: EvictOrder::Oldest,
            ..Default::default()
        };
        let pv = ix
            .evict_preview(ev_target(&ix), &policy, &small, usize::MAX)
            .unwrap();
        assert_eq!(pv.protected_skipped, 0, "SQL-excluded, never walked");
        assert!(pv.rows > 0 && pv.reachable);

        // A max_examine bound of 3: the walk stops early and says so.
        let pv2 = ix.evict_preview(1, &policy, &small, 3).unwrap();
        assert!(pv2.truncated, "{pv2:?}");
        assert!(!pv2.reachable);
        assert!(pv2.rows <= 3);

        // Past the bind cap - the shape the Rust-side re-check exists
        // for, exercised exactly as the bindcap eviction test does: 30k
        // filler ids spend the SQL budget, the real ids ride at the END
        // where no `NOT IN` can reach them, and only the walk's own
        // check can spare them. Impossible cap: unreachable, zero rows,
        // and protected_skipped says why.
        let mut ids: Vec<i64> = (1_000_000..1_030_000).collect();
        ids.extend(1..=8i64);
        let all = Protected {
            title_keys: vec![],
            release_ids: ids,
        };
        let pv3 = ix.evict_preview(1, &policy, &all, usize::MAX).unwrap();
        assert_eq!(pv3.rows, 0);
        assert!(!pv3.reachable);
        assert_eq!(pv3.protected_skipped, 8);
        assert_eq!(ev_ids(&ix).len(), 8);
        teardown(&dir, ix);
    }

    #[test]
    fn evict_estimator_lands_near_the_target_after_compact() {
        let (dir, ix) = ev_open("estim");
        ev_uneven(&ix);
        ix.compact().unwrap();
        let before = ix.db_bytes().unwrap();
        let target = before / 2;
        let rep = ix
            .evict_to(
                target,
                &EvictPolicy {
                    order: EvictOrder::Oldest,
                    ..Default::default()
                },
                &Protected::default(),
            )
            .unwrap();
        assert!(rep.removed > 0);
        assert_eq!(
            rep.bytes_after, rep.bytes_before,
            "DELETE does not shorten a SQLite file - that is what needs_compact is for"
        );
        assert!(rep.needs_compact);
        ix.compact().unwrap();
        let actual = ix.db_bytes().unwrap();
        let low = evict_low_water(target, &EvictPolicy::default());
        println!(
            "estimator: cap {before} -> target {target} (low water {low}), \
             removed {} rows, real post-compact size {actual} = {:.1}% of target",
            rep.removed,
            actual as f64 / target as f64 * 100.0
        );
        // The contract that matters: it got under the cap.
        assert!(actual <= target, "must reach the cap: {actual} > {target}");
        assert!(!ev_ids(&ix).is_empty());

        // MINIMALITY, the assertion that actually guards user data. The
        // landing point sits below the low-water mark, but only because a
        // release is indivisible - the row that crosses the line here is
        // a 256 KB one. Prove that is granularity and not over-eviction
        // by replaying the same fixture with ONE FEWER deletion in the
        // same order: it must still be above the low-water mark, i.e.
        // every row eviction took was a row it had to take.
        let (dir2, ix2) = ev_open("estim-minimal");
        ev_uneven(&ix2);
        ix2.compact().unwrap();
        let keep_one_more: Vec<i64> = (1..rep.removed as i64).collect(); // Oldest = id order
        ix2.prune_batch(&keep_one_more).unwrap();
        ix2.compact().unwrap();
        let one_fewer = ix2.db_bytes().unwrap();
        assert!(
            one_fewer > low,
            "over-eviction: stopping one row earlier ({one_fewer}) would already \
             have been under the low water mark ({low})"
        );
        teardown(&dir, ix);
        teardown(&dir2, ix2);
    }
}
