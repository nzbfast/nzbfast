//! Schema creation and the migration ladder (TODO 106 phase 2.2, cut 6):
//! `open` decomposed at its own comment seams into sequential step fns,
//! plus `open_read_only`. Except for the step-fn plumbing every line is a
//! verbatim move from the old index.rs open(); each step keeps its error
//! handling identical - non-fatal `let _ =` migrations STAY non-fatal
//! (a failed step is retried by the next open), and the people schema
//! keeps its fatal `?`. Call order is load-bearing; see
//! research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::*;

/// Bytes of write-ahead log the writer keeps when a checkpoint resets
/// it. Past this, the WAL file is truncated back to here.
///
/// SQLite's default is no limit, and the WAL then keeps its all-time
/// high-water mark FOREVER: it is reused from the front after every
/// checkpoint but never shrinks. Measured on the live index on 14 Aug
/// 2026 - a 28.1 GiB `index.db-wal` alongside a 39 GiB `index.db`,
/// holding exactly ONE live frame (`mxFrame=1`). Nothing was wrong with
/// checkpointing and no reader was pinning anything; the file was a
/// fossil of the one-pass `compact` VACUUM, which is a single
/// transaction over the whole database and so pushed all 7,331,058
/// pages through the WAL at once. Thousands of checkpoint resets since
/// then reused the front of the file and left the other 28 GiB
/// allocated.
///
/// 64 MiB because routine work must never reach it - a truncate the
/// daemon pays on every commit is churn, and churn in a multi-gigabyte
/// file is what makes Time Machine snapshots expensive, which is the
/// bill this whole investigation started from.
///
/// Sized from the live daemon, not from taste. Sampling `mxFrame` out
/// of the wal-index once a second for three minutes while it indexed:
/// peak 4,036 frames (15.9 MiB), typical 94-902 (0.4-3.5 MiB), floor 1.
/// The autocheckpoint threshold is 1000 pages (4 MiB) and the largest
/// routine write transaction in the tree is `COMPACT_CHUNK_PAGES` at
/// 2048 pages (8 MiB), both consistent with that. 64 MiB is 4x the
/// measured live peak, so only a one-shot whole-database rewrite ever
/// crosses it.
///
/// It bounds, it does not block: a transaction bigger than this still
/// grows the WAL as far as it needs. The limit applies when the WAL is
/// next reset, which is what hands the space back.
///
/// So DO NOT be alarmed by a WAL over the limit during startup. Watched
/// across the 14 Aug restart, the boot burst (backfills and the spot
/// history scan) drove it to 1.12 GiB of genuinely LIVE frames, drained
/// in about 40 seconds, and the file went straight back to exactly this
/// limit and stayed there - live content 0.5-3.6 MiB across the next
/// five minutes. That is one truncate per daemon start, which is the
/// churn we are happy to pay; the steady-state figure above is what the
/// limit is sized against. Tell the two apart with `mxFrame` from the
/// wal-index rather than the file size: live frames say whether the
/// bytes are in use or are the dead space this constant exists to stop.
pub const WAL_SIZE_LIMIT: i64 = 64 * 1024 * 1024;

/// WAL pages the committing connection lets accumulate before it stops
/// to checkpoint, in pages (SQLite's default is 1000, so 4 MiB at the
/// 4 KiB page size this index uses).
///
/// **The automatic checkpoint inside `tx.commit()` is the scan-side
/// ingest's single most expensive site, and the only one whose cost
/// explodes when the disk is busy.** Profiled 3 Sep 2026 on a hermetic
/// 2,000,000-header rig (`cargo run -p nzbkit --example
/// indexscan_bench`, `sample` mid-scan). Three profiles of the SAME
/// binary at the same sampling point put the checkpoint between
/// **9.4% and 54.3%** of everything inside `Index::ingest` - the index
/// size does not move that, disk contention does, and 54.3% is the
/// reading from a box loaded by other work, which is the condition a
/// user's machine is normally in. On an uncontended disk the ranking is
/// the release upsert 25.0%, the aggregate UPDATE 21.9%, this commit
/// 18.1%, `pick_release_row` 12.7% - and the whole of the subject
/// parsing and classification 7.5%, which is the finding this audit went
/// looking for and did not get.
///
/// The checkpoint work itself is not waste; the FREQUENCY is. A
/// checkpoint writes each DISTINCT page the WAL holds exactly once, so a
/// btree page that a scan pass dirties in fifty consecutive transactions
/// costs one write-back per checkpoint rather than fifty. Cutting the
/// checkpoint count coalesces the repeats.
///
/// Measured, one binary per arm, five pairs alternating leg by leg,
/// 800,000 headers at a 20,000 batch, median: **+24.2% headers/s
/// (20,971 -> 26,046) and a 38.9% shorter per-batch p50 (855 -> 522
/// ms)**, p90 -26.6%, max -13.1%, user CPU -3.9%, instructions -1.1%.
/// The checkpoint's own share of ingest falls by a third at two
/// independent sampling points (9.4 -> 6.0%, 12.9 -> 8.7%). Row set
/// identical across the arms over the full 2,000,000-header dump. Full
/// record: `research/INDEXER-SCAN-CPU-AUDIT-2026-09-03.md`.
///
/// 4,000 pages (16 MiB) rather than something larger for two reasons,
/// both measured rather than chosen. It is the live daemon's OWN
/// observed peak - 4,036 frames, the figure [`WAL_SIZE_LIMIT`] above is
/// sized against - so it asks for no more WAL space than a real scan
/// has already been seen to use, and it stays 4x under that limit,
/// which is what keeps the truncate churn the limit exists to prevent
/// out of the routine path. It also bounds the one cost that could go
/// the wrong way: a checkpoint runs inside `Index::ingest`, which the
/// daemon holds the index mutex across (memory topic
/// `nzbfast-tail-blocked-on-index-mutex`), so a rarer checkpoint is a
/// LONGER single hold. In the event it did not go the wrong way - p50,
/// p90 and max all improved, because there is less checkpoint work in
/// total - but four times rarer is a trade the measurement can carry
/// and forty times would not be.
pub const WAL_AUTOCHECKPOINT_PAGES: i64 = 4_000;

/// Page cache for the shared writer, in MiB. It is one connection, it
/// holds the compaction and migration transactions, and every chunk
/// commit used to pay a full fsync against SQLite's 2 MB default on a
/// multi-gigabyte index.
const WRITER_CACHE_MIB: i64 = 256;

/// Page cache for a scratch scan connection, in MiB - see
/// [`Index::open_scratch`]. A quarter of the writer's, matching the
/// read-only handle's figure for the same reason: several of these are
/// open at once and none of them needs the writer's working set.
const SCRATCH_CACHE_MIB: i64 = 64;

/// Per-phase stopwatch for [`Index::open`], and the reason it exists.
///
/// Nothing had ever timed an index open. Round 21 of
/// `research/RAR-PERF-AUDIT-2026-09-02.md` timed the daemon's whole boot
/// (0.115-0.139 s to the first API answer) against an EMPTY index and
/// said so rather than letting that read as covered - the open is a
/// ladder of migrations, EXISTS probes and conditional index builds, and
/// which rung a slow open is stuck on is not derivable from a total. It
/// is Round 38 of that same file that measured the open, using this, and
/// the numbers below come from there.
///
/// Cost is one `Instant::now()` per rung (eleven), which is tens of
/// nanoseconds against an open that is milliseconds at its cheapest.
/// The line is `info!` only past [`OPEN_SLOW_MS`], so an ordinary open -
/// and the scan loop opens up to eight per group per pass - says nothing
/// at the default level; `NZBFAST_LOG=debug` prints every one.
#[derive(Default)]
struct OpenTrace {
    laps: Vec<(&'static str, f64)>,
    last: Option<std::time::Instant>,
    start: Option<std::time::Instant>,
}

impl OpenTrace {
    fn start() -> Self {
        let now = std::time::Instant::now();
        Self {
            laps: Vec::with_capacity(12),
            last: Some(now),
            start: Some(now),
        }
    }

    /// Close the rung named `what` and open the next one.
    fn lap(&mut self, what: &'static str) {
        let now = std::time::Instant::now();
        if let Some(prev) = self.last.replace(now) {
            self.laps.push((what, (now - prev).as_secs_f64() * 1e3));
        }
    }

    /// Emit the line. `path` is logged because a process holds several
    /// databases open over its life (the index, and a test's scratch
    /// copies) and a bare duration cannot be attributed to one.
    fn finish(self, path: &Path, cache_mib: i64) {
        let Some(start) = self.start else { return };
        let total = start.elapsed().as_secs_f64() * 1e3;
        // Slowest first: a slow open is one rung nearly every time, and
        // the whole point of the line is to name it without a profiler.
        let mut laps = self.laps;
        laps.sort_by(|a, b| b.1.total_cmp(&a.1));
        let detail = laps
            .iter()
            .filter(|(_, ms)| *ms >= 0.5)
            .map(|(what, ms)| format!("{what} {ms:.0} ms"))
            .collect::<Vec<_>>()
            .join(", ");
        let detail = if detail.is_empty() {
            "every phase under 0.5 ms".to_string()
        } else {
            detail
        };
        if total >= OPEN_SLOW_MS {
            tracing::info!(
                target: "index",
                "open {} in {total:.0} ms (cache {cache_mib} MiB) - {detail}",
                path.display()
            );
        } else {
            tracing::debug!(
                target: "index",
                "open {} in {total:.1} ms (cache {cache_mib} MiB) - {detail}",
                path.display()
            );
        }
    }
}

/// Above this many milliseconds an `Index::open` is reported at `info!`
/// rather than `debug!`.
///
/// 250 ms is chosen against the measurement rather than by taste: Round
/// 38 read a fully-migrated open at 1.9-3.2 ms at every size from empty
/// to 32.7 M releases / 30 GB, and the shapes that are NOT that - a
/// migration meeting a large table for the first time (3m42s at that
/// size), a WAL left by an unclean exit (790 ms) - are exactly the ones
/// worth a line in a user's log.
const OPEN_SLOW_MS: f64 = 250.0;

fn create_base_schema(db: &Connection, cache_mib: i64) -> rusqlite::Result<()> {
    // Only journal_mode was ever set, so every chunk commit paid a
    // full fsync and the page cache stayed at SQLite's 2 MB default
    // against a multi-gigabyte index.
    //
    // synchronous=NORMAL is the one that matters for ingest. In WAL
    // mode it cannot corrupt the database - the documented exposure
    // is losing the last commits on a power cut or OS crash, which
    // for an index rebuildable from Usenet is the right trade. A
    // scan pass simply re-fetches the headers whose commit was lost;
    // the high-water mark only advances over a contiguous prefix.
    db.execute_batch(
        // §95: FIRST, and before any CREATE TABLE. Incremental
        // auto-vacuum is what lets `compact_chunk` reclaim space in
        // bounded, abortable pieces instead of one VACUUM that a
        // starting download cannot reliably stop. SQLite only
        // accepts the change on a database with no tables yet, so
        // this line does the whole job for a fresh install and is a
        // silent no-op on an existing one - those migrate on their
        // next compact (see `Index::compact`).
        //
        // The cost is pointer-map pages: one per ~800 pages, so
        // ~0.1% of the file, plus a ptrmap write when a page is
        // allocated or freed. Cheap against a multi-GB index that
        // otherwise blocks a download for minutes.
        &format!(
            "PRAGMA auto_vacuum=INCREMENTAL;
             PRAGMA journal_mode=WAL;
             PRAGMA journal_size_limit={WAL_SIZE_LIMIT};
             PRAGMA wal_autocheckpoint={WAL_AUTOCHECKPOINT_PAGES};
             PRAGMA synchronous=NORMAL;
             PRAGMA temp_store=MEMORY;
             PRAGMA cache_size=-{};
             PRAGMA mmap_size=1073741824;",
            cache_mib * 1024
        ),
    )?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS releases(
            id INTEGER PRIMARY KEY,
            stem TEXT NOT NULL,
            poster TEXT NOT NULL,
            grp TEXT NOT NULL,
            total_bytes INTEGER NOT NULL DEFAULT 0,
            files INTEGER NOT NULL DEFAULT 0,
            has_par2 INTEGER NOT NULL DEFAULT 0,
            complete INTEGER NOT NULL DEFAULT 0,
            first_posted INTEGER NOT NULL DEFAULT 0,
            first_seen INTEGER NOT NULL DEFAULT 0,
            UNIQUE(stem, poster, grp));
         CREATE TABLE IF NOT EXISTS files(
            release_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            total_parts INTEGER NOT NULL,
            bytes INTEGER NOT NULL DEFAULT 0,
            -- `nsegs` sits AHEAD of the blob on purpose (§26c A5): a
            -- row whose segment list overflows its page has every
            -- column after the blob at the end of an overflow chain,
            -- and the completeness aggregate reads `nsegs` on every
            -- chunk of every release. A database created before the
            -- 22 Aug 2026 layout has them the other way round until
            -- `segmig` rebuilds it. The blob itself is segcodec's
            -- compact form; JSON rows from before the migration are
            -- read by the same readers, see index/segcodec.rs.
            nsegs INTEGER NOT NULL DEFAULT 0,
            segments BLOB NOT NULL DEFAULT '[]',
            UNIQUE(release_id, filename));
         CREATE TABLE IF NOT EXISTS marks(
            -- A8 multi-server indexing: article NUMBERS are assigned
            -- per server spool (message-ids are the portable half),
            -- so scan coverage is tracked per (group, server). The
            -- server key is the lowercased host; '' marks rows from
            -- the single-server era, adopted by the historical
            -- primary via adopt_legacy_marks.
            grp TEXT NOT NULL,
            server TEXT NOT NULL DEFAULT '',
            high INTEGER NOT NULL,
            low INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(grp, server));
         CREATE INDEX IF NOT EXISTS idx_rel_stem ON releases(stem);
         CREATE TABLE IF NOT EXISTS spots(
            id INTEGER PRIMARY KEY,
            msgid TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            category INTEGER NOT NULL DEFAULT 0,
            subcats TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL DEFAULT 0,
            date INTEGER NOT NULL DEFAULT 0,
            spotter_id TEXT NOT NULL DEFAULT '',
            verified INTEGER NOT NULL DEFAULT 0,
            hashcash_ok INTEGER NOT NULL DEFAULT 1,
            nzb_msgids TEXT NOT NULL DEFAULT '[]');
         CREATE INDEX IF NOT EXISTS idx_spots_title ON spots(title);
         CREATE TABLE IF NOT EXISTS titles(
            key TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            year INTEGER NOT NULL DEFAULT 0,
            tmdb_id INTEGER NOT NULL DEFAULT 0,
            overview TEXT NOT NULL DEFAULT '',
            rating REAL NOT NULL DEFAULT 0,
            genres TEXT NOT NULL DEFAULT '',
            poster TEXT NOT NULL DEFAULT '',
            backdrop TEXT NOT NULL DEFAULT '',
            checked INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS imdb_ratings(
            tconst TEXT PRIMARY KEY,
            rating REAL NOT NULL,
            votes INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS kv(
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL);
         -- M30 wall curation: per-title 'Not interested' hides,
         -- learned/manual hide rules, and suggestion dismissals
         -- (so a declined suggestion never nags again).
         CREATE TABLE IF NOT EXISTS wall_hidden(
            -- NOT NULL is explicit: a non-INTEGER PRIMARY KEY is NOT
            -- implicitly NOT NULL in SQLite, and a single NULL key here
            -- makes `key NOT IN (SELECT key FROM wall_hidden)` (used by
            -- the pruners AND the wall curation filter) evaluate to NULL
            -- for every row - silently disabling pruning and blanking
            -- the whole wall.
            key TEXT PRIMARY KEY NOT NULL,
            at INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS wall_rules(
            id INTEGER PRIMARY KEY,
            field TEXT NOT NULL,
            value TEXT NOT NULL,
            added INTEGER NOT NULL,
            auto INTEGER NOT NULL DEFAULT 0,
            UNIQUE(field, value));
         CREATE TABLE IF NOT EXISTS wall_dismissed(
            field TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY(field, value));
         -- Pre feed (opt-in, off by default): one row per release a
         -- relay channel has announced. The column that earns the
         -- table is `filename` - the name the release was POSTED
         -- under, which is the only thing that can join a real title
         -- onto a deliberately obfuscated post.
         --
         -- Keyed on the title because that is what the relay treats
         -- as the identity: a NEW line announces it, and UPD lines
         -- fill fields in afterwards (very often the filename
         -- itself, minutes later). Upserts therefore only ever
         -- overwrite a field with a NON-EMPTY value.
         CREATE TABLE IF NOT EXISTS predb(
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL UNIQUE,
            -- Posted filename, as the relay sent it.
            filename TEXT NOT NULL DEFAULT '',
            -- release_stem(filename), lowercased: the exact join key.
            fnstem TEXT NOT NULL DEFAULT '',
            -- predb::match_key(fnstem): separators and case removed,
            -- the fallback join key.
            fnkey TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL DEFAULT 0,
            files INTEGER NOT NULL DEFAULT 0,
            category TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            requestid TEXT NOT NULL DEFAULT '',
            grp TEXT NOT NULL DEFAULT '',
            nuked INTEGER NOT NULL DEFAULT 0,
            nuke_reason TEXT NOT NULL DEFAULT '',
            -- When the RELAY says it was pre'd (0 = it did not say).
            pre_at INTEGER NOT NULL DEFAULT 0,
            -- When WE heard it. Drives pruning; always set.
            seen_at INTEGER NOT NULL DEFAULT 0,
            -- Last time this row was swept against already-indexed
            -- releases, so the retro pass can round-robin instead of
            -- re-trying the newest rows forever.
            tried_at INTEGER NOT NULL DEFAULT 0);
         CREATE INDEX IF NOT EXISTS idx_predb_fnstem ON predb(fnstem);
         CREATE INDEX IF NOT EXISTS idx_predb_fnkey ON predb(fnkey);
         CREATE INDEX IF NOT EXISTS idx_predb_seen ON predb(seen_at);
         CREATE INDEX IF NOT EXISTS idx_predb_tried ON predb(tried_at);
         -- Phase 2: correlation candidates. One row per release -
         -- the BEST candidate only, with enough recorded to audit
         -- the decision and to rank a re-computation against it.
         -- Alternates are recomputed on demand, never stored.
         CREATE TABLE IF NOT EXISTS pre_corr(
            release_id INTEGER PRIMARY KEY,
            predb_id   INTEGER NOT NULL,
            score      INTEGER NOT NULL,
            -- first_posted - pt, seconds. The audit trail.
            delta      INTEGER NOT NULL,
            -- est_content/SZ in thousandths (0 = sizeless pair).
            ratio      INTEGER NOT NULL DEFAULT 0,
            -- Best competing score at decision time.
            runner_up  INTEGER NOT NULL DEFAULT 0,
            -- suggested | applied | confirmed | rejected | revoked
            status     TEXT NOT NULL DEFAULT 'suggested',
            at         INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS idx_precorr_predb ON pre_corr(predb_id);
         CREATE INDEX IF NOT EXISTS idx_precorr_status ON pre_corr(status);
         -- Repost fingerprints: the PAR2 hash16k of a member file
         -- (an OUTER volume) of a download we managed to name,
         -- against the name we gave it. A later obfuscated post
         -- whose sidecar presents the same hash is the same bytes,
         -- so it can be told what it is. The identity is read from
         -- the .par2 sidecar and never from the archive, which is
         -- why it survives RAR header encryption - the one naming
         -- path in the pipeline that does.
         --
         -- Only names REPOSTS, so the yield grows with the age of
         -- the table and is zero on a fresh install. It costs ~80
         -- bytes per volume of every named download, which is why
         -- there is no expiry: an old fingerprint is exactly the
         -- one worth having.
         CREATE TABLE IF NOT EXISTS par_hashes(
            hash16k TEXT PRIMARY KEY NOT NULL,
            -- The release name we knew this by.
            name TEXT NOT NULL,
            -- The wall's identity for it, when the name parsed to
            -- one ('' when it did not).
            title_key TEXT NOT NULL DEFAULT '',
            at INTEGER NOT NULL,
            -- How well the stored name was PROVED against these
            -- bytes - an `index::claims::NameEvidence` tag. This
            -- table used to be first-writer-wins forever: whatever
            -- named a fingerprint first owned it, and a later job
            -- that named the same bytes correctly, with a byte-level
            -- proof, could not displace it. The tier is what gives
            -- the correction path a rule (strictly stronger evidence
            -- replaces) instead of a race.
            tier TEXT NOT NULL DEFAULT 'hash16k-len',
            -- Two equally-evidenced jobs called this fingerprint
            -- different things, so it is not an answer. hash16k is
            -- the identical-head twin family every in-job tier
            -- DECLINES (the rule stated in live.rs, sfvname.rs and
            -- emptydesc.rs alike); the row is kept, and the lookup
            -- refuses it, rather than the guess being served forever.
            contested INTEGER NOT NULL DEFAULT 0);
         -- §131 identity substrate: every naming lane's proof about a
         -- release, kept as COMPETING claims with provenance rather
         -- than a first-writer-wins name. `tier` is the evidence
         -- strength (see index::claims::NameEvidence), `key` the
         -- proving value (a PAR2 set id, a crc32, a hash16k, a
         -- message-id-set digest), `source` which lane produced it.
         -- The UNIQUE doubles as the release_id index (leftmost
         -- column), so re-claims are idempotent and the delete
         -- trigger below stays cheap.
         CREATE TABLE IF NOT EXISTS name_claims(
            id INTEGER PRIMARY KEY,
            release_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            tier TEXT NOT NULL,
            key TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            at INTEGER NOT NULL,
            UNIQUE(release_id, tier, key, name));
         -- Reverse message-id lookup: 64-bit hash of a segment
         -- message-id -> the release that carries it, so a set of
         -- message-ids (a posted NZB, a spot NZB, an *arr handoff)
         -- can join to dark scan rows. Only the 3 lowest-numbered
         -- segments of each file are keyed (the query side may probe
         -- every id it has - extra probes just miss), which bounds
         -- the table at ~3 rows per file instead of one per segment.
         -- WITHOUT ROWID: the (h, release_id) pair IS the row.
         CREATE TABLE IF NOT EXISTS msgid_map(
            h INTEGER NOT NULL,
            release_id INTEGER NOT NULL,
            PRIMARY KEY(h, release_id)) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS idx_msgid_map_rel ON msgid_map(release_id);
         -- Both tables reference release rowids, and SQLite reuses the
         -- highest rowid after an eviction deletes it - a stale row
         -- would then attach someone else's identity to a brand-new
         -- release. A trigger catches every delete path (retention
         -- prune, size-cap evict, twin dedupe, wall fix-up) including
         -- ones added later; both deletes are indexed. The trigger
         -- ITSELF is created by `additive_migrations` (as
         -- `rel_identity_ad_v3`, which also unbinds `spots`) and
         -- deliberately NOT here: this batch used to re-create the v1
         -- name that the migration then drops, so every single
         -- `Index::open` wrote sqlite_master twice on an
         -- already-migrated database. See the schema-churn note there.
         -- Pesto tiny-PAR2 rung (TODO 131, red-team 5a): one row per
         -- PAR2 Recovery Set parsed out of the family's tiny sidecar
         -- objects. Keyed on the set id because dedupe is mandatory -
         -- the census's 617 fetched objects collapsed to 489 sets
         -- (127 sets had multiple descriptor objects). `base_ctr` is
         -- the smallest message-id counter among the set's objects
         -- (the backward-link key C); `files` is the FileDesc list as
         -- JSON (name, exact length, full MD5, first-16k MD5).
         CREATE TABLE IF NOT EXISTS pesto_sets(
            set_id TEXT PRIMARY KEY NOT NULL,
            grp TEXT NOT NULL,
            base_ctr INTEGER NOT NULL,
            sum_len INTEGER NOT NULL,
            files TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            -- pending | named | conflict | junkname | unresolved | nopayload
            status TEXT NOT NULL DEFAULT 'pending',
            release_id INTEGER NOT NULL DEFAULT 0,
            tries INTEGER NOT NULL DEFAULT 0,
            at INTEGER NOT NULL DEFAULT 0);
         CREATE INDEX IF NOT EXISTS idx_pesto_status ON pesto_sets(status, at);
         -- Parity scoreboard (build-order #8): one row per reference
         -- release sampled from a user-configured newznab indexer,
         -- with the verdict of whether OUR index has that post and
         -- whether it is NAMED (exact title/episode parity, not mere
         -- presence). Aggregated by GROUP BY over a rolling window;
         -- volume is hundreds of rows a day, so no rollup table.
         CREATE TABLE IF NOT EXISTS scoreboard_samples(
            id INTEGER PRIMARY KEY,
            -- Reference host, so two sources never collide on a guid.
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            ref_guid TEXT NOT NULL,
            ref_name TEXT NOT NULL,
            ref_size INTEGER NOT NULL DEFAULT 0,
            -- The reference's usenetdate (upload time), unix.
            ref_posted INTEGER NOT NULL DEFAULT 0,
            ref_group TEXT NOT NULL DEFAULT '',
            -- have_named | have_unnamed | missing
            verdict TEXT NOT NULL,
            matched_release_id INTEGER NOT NULL DEFAULT 0,
            -- stem | band | subject_stem ('' when missing)
            key_used TEXT NOT NULL DEFAULT '',
            -- our first_seen - ref_posted for hits, floored at 0.
            lag_secs INTEGER NOT NULL DEFAULT 0,
            at INTEGER NOT NULL,
            UNIQUE(source, ref_guid));
         CREATE INDEX IF NOT EXISTS idx_sb_at ON scoreboard_samples(at);
         CREATE INDEX IF NOT EXISTS idx_sb_cat ON scoreboard_samples(category, at);
         -- Search-miss log (TODO 131 workstream D, item D3; design
         -- research/DESIGN-D3-search-log-2026-08-11.md). What the user
         -- and their *arr clients asked this index for, and how many
         -- rows they got back - so the queries we answer with nothing
         -- can tell the scanner what to deepen or backfill next.
         --
         -- PRIVACY: this is LOCAL-ONLY behaviour data about the person
         -- running the daemon. It is never enriched (no network lookup
         -- reads it), never exported (not in the SAB or newznab
         -- facades, not in any diagnostic bundle or update payload),
         -- never aggregated across installs, and its readout sits
         -- behind the full API key. The live setting index_search_log
         -- turns recording off AND clears the table. Nothing in this
         -- table may ever leave the box.
         --
         -- One row per DISTINCT (surface, q, kind), not per search
         -- event: an *arr re-asks the same RSS query every 15 minutes
         -- and the wall's box searches as you type, so an event stream
         -- would be tens of thousands of near-duplicate rows a day.
         -- `q` is the normalized form the matcher actually sees
         -- (lowercased, separators collapsed), never the raw keystroke.
         CREATE TABLE IF NOT EXISTS search_log(
            id INTEGER PRIMARY KEY,
            -- wall | newznab. Where the query came from; a miss an
            -- *arr reports is a different problem from one a human
            -- typed, and the fixes differ.
            surface TEXT NOT NULL,
            q TEXT NOT NULL,
            -- The kind filter in force ('' when none): a movie search
            -- that misses is not the same hole as a global one.
            kind TEXT NOT NULL DEFAULT '',
            -- Times asked, and times answered with nothing (or with
            -- fewer rows than the readout's `thin` bar).
            n INTEGER NOT NULL DEFAULT 0,
            zero_n INTEGER NOT NULL DEFAULT 0,
            first_at INTEGER NOT NULL,
            last_at INTEGER NOT NULL,
            -- last_hits is the CURRENT truth; best_hits is whether we
            -- ever answered it at all. A query that missed for a week
            -- and now returns rows is a hole the scanner FILLED, and
            -- must fall out of the top-misses list rather than sit at
            -- the top of it forever on the strength of its history.
            last_hits INTEGER NOT NULL DEFAULT 0,
            best_hits INTEGER NOT NULL DEFAULT 0,
            UNIQUE(surface, q, kind));
         -- One index, serving both the retention sweep and the
         -- readout's rolling window. The ranking sort is left to
         -- SQLite: the row cap keeps this table at thousands of rows,
         -- where an index on the ordering key would cost more to
         -- maintain than the sort costs to run.
         CREATE INDEX IF NOT EXISTS idx_search_log_last ON search_log(last_at);",
    )?;
    Ok(())
}

/// The additive half of the schema, in THREE ordered steps.
///
/// Split out of one 495-line function on 1 Sep 2026, 5 lines under the
/// size gate's 500-line fn ceiling and the narrowest margin in the tree
/// (claim `size-ceiling-additive-migrations`). A migrations list is
/// append-only by nature, so the next schema change would have reddened
/// main for whoever pushed it. The seam is the one this function's own
/// comment already described - columns, then what is derived from them -
/// not an arbitrary cut to buy lines.
///
/// THE ORDER IS LOAD-BEARING AND IS THE REASON THIS ORCHESTRATOR EXISTS
/// rather than three calls at the call site. Every index and backfill
/// below reads a column that only [`additive_columns`] guarantees:
/// `idx_titles_air_backfill` needs `air_tried`, `idx_titles_tvdb_backfill`
/// needs `tvdb_tried`, `idx_rel_pesto` needs `pesto_ctr_min`,
/// `idx_rel_visible_posted` needs `junk`, `idx_rel_enc` needs `enc_class`,
/// and the predb backfill needs `pt`. Creating one before its ALTER is a
/// silent no-op on a fresh install - `CREATE INDEX IF NOT EXISTS` on a
/// missing column simply fails and is discarded, exactly like the ALTERs
/// - so the index would never exist and the query it serves would walk
/// the table forever with nothing to say so. Do not reorder these three,
/// and do not call them individually from anywhere else.
fn additive_migrations(db: &Connection) {
    additive_columns(db);
    derived_indexes_and_triggers(db);
    predb_pt_backfill(db);
}

/// Step 1: columns added after their table first shipped.
///
/// ALTER has no IF NOT EXISTS, so failed re-adds are expected and
/// harmless - every statement here is fired and its error discarded,
/// which is what makes the list safe to append to. Nothing in this
/// function may read a column: it is what GUARANTEES the columns the
/// other two steps read, and [`additive_migrations`] documents why that
/// ordering cannot be relaxed.
fn additive_columns(db: &Connection) {
    // Columns added after the titles table first shipped - ALTER has
    // no IF NOT EXISTS, so failed re-adds are expected and harmless.
    for ddl in [
        "ALTER TABLE titles ADD COLUMN imdb TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE titles ADD COLUMN actors TEXT NOT NULL DEFAULT ''",
        // Full release / first-air date (ISO). Rows enriched before
        // this column existed keep '' and sort by `year` instead -
        // they only gain a real date when re-enriched.
        "ALTER TABLE titles ADD COLUMN air_date TEXT NOT NULL DEFAULT ''",
        // Whether a provider has been ASKED for this title's date.
        // Distinct from a non-empty air_date: plenty of titles have
        // no date to give, and without this the backfill lane would
        // re-ask them forever. Rows enriched before air_date existed
        // default to 0, which is what makes them eligible for it.
        "ALTER TABLE titles ADD COLUMN air_tried INTEGER NOT NULL DEFAULT 0",
        // TODO 187: TheTVDB series id, from TVmaze's `externals.thetvdb`.
        // The newznab facade resolves a Sonarr `tvdbid` through it, and
        // ONLY advertises the parameter once the column actually holds
        // ids - an empty column plus a caps promise is a series search
        // that answers empty forever, which Sonarr reads as "this
        // indexer has nothing".
        "ALTER TABLE titles ADD COLUMN tvdb INTEGER NOT NULL DEFAULT 0",
        // Whether TVmaze has been asked for this show's TVDB id, on the
        // same reasoning as air_tried: plenty of shows have no id to
        // give, and 0 alone cannot tell "none published" from "never
        // asked" - so the backfill lane would re-ask them forever.
        "ALTER TABLE titles ADD COLUMN tvdb_tried INTEGER NOT NULL DEFAULT 0",
        // Resolving a tvdbid is a single-row lookup on every series
        // search Sonarr makes; without this it is a scan of the whole
        // titles table.
        //
        // PARTIAL, so the lookup has to repeat the predicate to reach
        // it: SQLite will not prove `tvdb=?1` implies `tvdb>0` (nor even
        // `tvdb=81189`, measured), so a query without a literal `tvdb>0`
        // term plans as SCAN titles and this index answers nothing. See
        // `title_key_for_tvdb`, and the plan gate in plan_tests.rs that
        // keeps the pairing honest.
        "CREATE INDEX IF NOT EXISTS idx_titles_tvdb ON titles(tvdb) WHERE tvdb > 0",
        // The same shape for Radarr's PRIMARY lookup, which had no index
        // at all: `title_key_for_imdb` runs on every `t=movie&imdbid=`
        // search, and on a 300 k-title table the scan measured 17.3 ms
        // against 0.07 ms through this index. Partial on the same
        // reasoning as the ids above - the empty string is the default
        // for every title no provider has resolved, which on a fresh
        // index is all of them, and none of those rows is ever a search
        // target.
        "CREATE INDEX IF NOT EXISTS idx_titles_imdb ON titles(imdb) WHERE imdb <> ''",
        // And Radarr's fallback id, for a film with no IMDb id on its
        // side. Same partial shape, same required guard; the column
        // holds a TVmaze show id on TV rows, which is why every reader
        // of it also filters `kind` (see `title_key_for_tmdb`).
        "CREATE INDEX IF NOT EXISTS idx_titles_tmdb ON titles(tmdb_id) WHERE tmdb_id > 0",
        // The "hide adult" exclusion list, which the FLAT release list
        // builds as `title_key NOT IN (SELECT t.key FROM titles t WHERE
        // <the genre test>)`. That subquery planned as `SCAN t` - a full
        // pass over `titles`, ALIASED, so the string "SCAN titles" never
        // appeared anywhere to give it away. And it ran FOUR times per
        // request: browse renders its whole predicate list twice (once
        // unqualified, once against the `d.` alias of the
        // best-copy-per-stem subquery) and runs two statements, the
        // exact COUNT and the page.
        //
        // So a fixed O(titles) term on every release-list request,
        // entirely independent of how selective the rest of the filter
        // is. Measured on a synthetic 1M-title corpus (browse.rs's
        // `adult_cost`): 3.4 ms with the filter off, 1,235 ms with it
        // on, for the same ~2,500 rows.
        //
        // Partial, and COVERING (`key` is the only column the subquery
        // selects), so the list is built by walking the few adult
        // entries instead of every title. On that corpus: 283 ms ->
        // 0.59 ms for the key set, 1,235 ms -> 25.7 ms end to end at 4%
        // adult titles, 1,179 -> 9.4 ms at 1%, 1,157 -> 4.7 ms at 0.1%
        // (what is left scales with the ADULT population, not with
        // `titles`, which is why hoisting the four evaluations down to
        // one was priced and dropped). A long-running real index of
        // 5,863 titles carries 14 adult ones, and paid ~3 ms per scan
        // warm and 143 ms cold - x4 - with nobody noticing. See
        // research/BROWSE-adult-exclusion-2026-08-20.md.
        //
        // The predicate is generated from the SAME macro the query uses
        // (`adult_genre_match_sql!`), with the alias prefix as its one
        // argument, because a partial index answers NOTHING unless the
        // statement repeats its predicate verbatim - the trap three
        // *arr id lookups sat in for weeks. `plan_tests.rs::
        // the_adult_exclusion_list_reaches_its_partial_index` names this
        // index, so a drift fails there rather than on someone's daemon.
        concat!(
            "CREATE INDEX IF NOT EXISTS idx_titles_adult ON titles(key) WHERE ",
            crate::index::browse::adult_genre_match_sql!(""),
        ),
        // Which provider's numbering `tmdb_id` is in, as that provider's
        // own name ('tvmaze' | 'tmdb' | 'anilist' | 'omdb' | 'wikidata' |
        // 'musicbrainz' | 'openlibrary'). One column carries at least
        // four unrelated dense-integer namespaces, and until this existed
        // nothing recorded which - a TV row holds a TVmaze show id under
        // the keyless default, an AniList media id when TVmaze missed the
        // romaji title (the routine anime case, no key needed), and a
        // TMDB series id when a TMDB key is configured; a movie row holds
        // a TMDB movie id with a key and the bare IMDb NUMBER from OMDb
        // without one. Readers guessed by `kind` alone and guessed wrong
        // (Codex sweep 7, H2). The worst of it was a silent permanent
        // write: the TVDB backfill asked TVmaze with an AniList media id,
        // and its one guard - "the payload is about the show we asked
        // about" - is satisfied whenever that number is also a live
        // TVmaze show id, so an unrelated series' thetvdb id was stamped
        // on the row for good.
        //
        // '' is the legacy value and every reader below keeps admitting
        // it, because a row written before this column existed means
        // exactly what its documentation said it meant then.
        "ALTER TABLE titles ADD COLUMN id_src TEXT NOT NULL DEFAULT ''",
        // Scan low-water mark (history auto-deepen).
        "ALTER TABLE marks ADD COLUMN low INTEGER NOT NULL DEFAULT 0",
        // M25 browse view: classification + exact part counts, so
        // SQL can filter "movie AND 2160p" and sort by completeness
        // without re-parsing every stem per request.
        "ALTER TABLE releases ADD COLUMN kind TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN res TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN have_parts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE releases ADD COLUMN need_parts INTEGER NOT NULL DEFAULT 0",
        // M28 indexer v2: the parse key ("t:breaking bad" /
        // "m:inception:2010") persisted so the poster grid groups in
        // SQL, plus a 0-100 junk score for default-wall curation.
        "ALTER TABLE releases ADD COLUMN title_key TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN junk INTEGER NOT NULL DEFAULT 0",
        // M29 availability oracle: when the idle STAT sampler last
        // probed this release (0 = never) - oldest-verdict-first.
        "ALTER TABLE releases ADD COLUMN oracle_at INTEGER NOT NULL DEFAULT 0",
        // M30 curation: audio-language tags from the stem, space-
        // joined lowercase ("german" / "german multi"; '' = untagged
        // = English by scene convention). Filled at ingest and by
        // the junk_v6 re-score pass, queried by language hide rules.
        "ALTER TABLE releases ADD COLUMN langs TEXT NOT NULL DEFAULT ''",
        // Cached segment count (`json_array_length(segments)` then,
        // `seg_count(segments)` now). The completeness aggregate called
        // that twice per file row of a release, on every chunk that
        // touched it - so a 210-file release with 13 MB of segments
        // JSON re-parsed all of it just to count parts. Measured on the
        // live index: 16.3 ms with the JSON calls, 0.3 ms without.
        // Written alongside `segments`, so the two cannot drift. On a
        // database from before 22 Aug 2026 this ALTER put the column
        // behind the blob; the §26c A5 rebuild (segmig.rs) moves it
        // ahead, and a fresh database is created that way.
        "ALTER TABLE files ADD COLUMN nsegs INTEGER NOT NULL DEFAULT 0",
        // What separates two encodes of the same film once resolution
        // ties: the release name already carries these, and the parser
        // already read them, but until now they were parsed and thrown
        // away. '' = the name said nothing (or the row predates the
        // columns and the quality_v10 pass hasn't reached it).
        "ALTER TABLE releases ADD COLUMN vcodec TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN acodec TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN hdr TEXT NOT NULL DEFAULT ''",
        // Monotonic wall-arrival cursor. A release id alone is not a
        // safe cursor because SQLite may reuse the highest rowid after
        // eviction deletes it.
        "ALTER TABLE releases ADD COLUMN arrival_seq INTEGER NOT NULL DEFAULT 0",
        // A8 targeted gap-fill: when a secondary-server window scan
        // last tried to complete this release (0 = never) - oldest
        // first, like oracle_at.
        "ALTER TABLE releases ADD COLUMN gapfill_at INTEGER NOT NULL DEFAULT 0",
        // Pre feed: the real name a relay channel gave this release,
        // and where that name came from. Kept BESIDE `stem` rather
        // than replacing it - the stem is the posted identity, it is
        // half of the UNIQUE key that makes ingest idempotent, and
        // the FTS index is external-content over it with no UPDATE
        // trigger. Overwriting it would break all three and lose the
        // evidence that the two names are different things.
        //
        // '' = never named from the feed. Non-empty is a claim made
        // by somebody else, which is why `pre_source` is not
        // optional in practice: a name whose origin we cannot state
        // is a name we should not be showing.
        "ALTER TABLE releases ADD COLUMN pre_title TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN pre_source TEXT NOT NULL DEFAULT ''",
        // When the retro sweep last considered this row (0 = never).
        // Lets the backlog pass move through the index once instead
        // of re-examining the newest rows every tick.
        "ALTER TABLE releases ADD COLUMN pre_at INTEGER NOT NULL DEFAULT 0",
        // Phase 2 correlation: the normalized pre time - announced
        // time when the relay claimed one, arrival time otherwise.
        // A stored column rather than a CASE expression because the
        // correlation window range-scans it and an expression over
        // two columns cannot use one index.
        "ALTER TABLE predb ADD COLUMN pt INTEGER NOT NULL DEFAULT 0",
        // Byte-probe naming lane (TODO 131 B3): when the prober last
        // touched this row (0 = never, oldest-first rotation like
        // oracle_at/gapfill_at) and how many attempts it has spent.
        // Tries saturate at the give-up cap so a row that cannot be
        // probed (scrambled order, missing head, packed-out-of-reach
        // header) drops out of the pick instead of being chased -
        // chasing is the 779-fetch livelock the lane exists to avoid.
        "ALTER TABLE releases ADD COLUMN probe_at INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE releases ADD COLUMN probe_tries INTEGER NOT NULL DEFAULT 0",
        // Terminal header-encryption classification (TODO 131 rung 5,
        // research/RAR-continuation-pilot-2026-08-10): the archive's own
        // bytes say a password is required, so NO byte probe at any
        // budget will ever read a name out of it. 0 = never classified.
        //
        // A GENERATION number, not a boolean, and that is load-bearing:
        // only `enc_class == index::ENC_CLASS` counts as terminal, so
        // bumping that constant un-retires every row a wrong classifier
        // stamped, with no migration. See index/encrypted.rs for why a
        // terminal stamp is defensible here when the byte-probe lanes'
        // saturating probe_tries was not.
        "ALTER TABLE releases ADD COLUMN enc_class INTEGER NOT NULL DEFAULT 0",
        // Which container and which signature earned the stamp
        // ('rar5/head-crypt', 'rar4/mhd-password', '7z/aes-header') -
        // the evidence a later generation is argued from.
        "ALTER TABLE releases ADD COLUMN enc_kind TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN enc_at INTEGER NOT NULL DEFAULT 0",
        // Pesto family (TODO 131, red-team 5a): the decoded message-id
        // counter range and earliest clock of a release whose articles
        // match the pesto grammar, persisted at scan time. NULL = not
        // pesto. The counter is the per-session key the tiny-PAR2 rung
        // links backward through; the randomized Date header is NEVER
        // used for association (census, 10 Aug 2026). Nullable on
        // purpose - 0 is a legal counter value.
        "ALTER TABLE releases ADD COLUMN pesto_ctr_min INTEGER",
        "ALTER TABLE releases ADD COLUMN pesto_ctr_max INTEGER",
        "ALTER TABLE releases ADD COLUMN pesto_clock INTEGER",
        // Indexer-confirm lane: when this suggestion was last spent an
        // external lookup on (0 = never). Stamped after the search
        // attempt whether or not it found anything, so one suggestion
        // can never cost the user's indexer quota twice.
        "ALTER TABLE pre_corr ADD COLUMN checked_at INTEGER NOT NULL DEFAULT 0",
        // Posting-session tag (13 Aug 2026 census): the leading
        // "[037/209]" many posting tools put on every subject - THIS
        // file is number 37 of a 209-file posting session. The
        // shattered-poster family carries it even while randomizing
        // From per article, so it is the cheapest session-assembly
        // evidence the wire offers (a future pass can stitch the 209
        // per-file rows into one release). Persisted at ingest, first
        // writer wins. NULL = subject carried no digit-only tag; 0 is
        // never written.
        "ALTER TABLE releases ADD COLUMN sess_idx INTEGER",
        "ALTER TABLE releases ADD COLUMN sess_total INTEGER",
        // Spot-born adult marker (TODO 131): the person who posted this
        // release filed it under the Spotnet adult subcategory. 0 = no
        // such claim, which is every scanner-born row and every spot
        // filed anywhere else - it is NOT "known not adult".
        //
        // Distinct from the wall's genre test (index/browse.rs) on
        // purpose: that one reads `titles.genres`, which only exists
        // once enrichment has reached the title, and a fresh spot-born
        // card usually has no enrichment at all - so on the one source
        // that is a third erotica the filter had nothing to read. This
        // column is the poster's own filing of their own post, written
        // at promotion time, and the two are OR'd together.
        "ALTER TABLE releases ADD COLUMN adult INTEGER NOT NULL DEFAULT 0",
        // Spot promotion (TODO 131): the release row this spot became
        // (or was found to duplicate); 0 = not resolved yet. Set once
        // the spot's NZB has been fetched and folded into `releases`,
        // so it doubles as the resolver's "done" marker.
        "ALTER TABLE spots ADD COLUMN release_id INTEGER NOT NULL DEFAULT 0",
        // NZB fetch attempts for the resolver's retry cap. A spot
        // whose payload articles are gone stops being retried after a
        // few passes instead of burning the budget forever.
        "ALTER TABLE spots ADD COLUMN nzb_tried INTEGER NOT NULL DEFAULT 0",
        // What the one corroborating STAT said about the promoted
        // release's head article (TODO 131): 0 never asked, 1 the
        // article is there, 2 it is not. A spot-born card's
        // completeness is otherwise the NZB's own declaration about
        // itself, which nothing has ever checked against a provider -
        // survivable at the tip, badly wrong at depth, where the
        // catalogue now reaches back to 2011.
        "ALTER TABLE spots ADD COLUMN stat_ok INTEGER NOT NULL DEFAULT 0",
        // N8 incremental ingest aggregates: the two release-level counts
        // that `files`, `total_bytes`, `have_parts`, `need_parts` and
        // `has_par2` did not already carry - how many of the release's
        // files are complete, and how many look like Windows
        // executables. -1 means "unknown": rows from before this column
        // (and rows whose files table a maintenance path rewrote without
        // recomputing) take one full-scan recompute on their next ingest
        // touch, which stamps the real counts and switches the row to
        // the incremental path for good.
        "ALTER TABLE releases ADD COLUMN nfiles_complete INTEGER NOT NULL DEFAULT -1",
        "ALTER TABLE releases ADD COLUMN nfiles_exe INTEGER NOT NULL DEFAULT -1",
        // TODO 5 phase 2c: the Unicode fold of `stem`, for the search
        // paths that are not FTS - SQLite's `LOWER()` folds ASCII and
        // nothing else, so `война` never matched `ВОЙНА.И.МИР` down the
        // LIKE fallback. index/fold.rs holds the expression this
        // mirrors and why the column is SPARSE ('' = "LOWER() already
        // folds this row", true of nearly every stem), so a reader must
        // OR this arm onto the existing expression, never replace it.
        // Written by `fold_backfill` for existing rows, by
        // `fold_reconcile` for rows a stem rewrite left disagreeing
        // with their stem, and by the two production writers
        // (ingest.rs, spots.rs) for new ones.
        // Deliberately UNINDEXED: the arm rides inside a query that is
        // already scanning, and building an index at open is the
        // whole-table write lock the B1 picker indexes exist to avoid.
        "ALTER TABLE releases ADD COLUMN stem_fold TEXT NOT NULL DEFAULT ''",
        // Exact external-NZB naming needs a quiet window after the local file
        // manifest last changed. Kept on the release row, rather than in an
        // auxiliary per-release table, so enabling the optional proof catalog
        // cannot grow a second uncharged B-tree across the whole index.
        "ALTER TABLE releases ADD COLUMN seed_manifest_at INTEGER NOT NULL DEFAULT 0",
        // W7-01..03: the repost table's evidence tier and its
        // ambiguity marker. Rows written before these columns existed
        // default to the weakest tier and uncontested, which is the
        // honest reading of them - nothing recorded what proved them,
        // and any of them may be a twin-family guess - and it is also
        // the safe one: a later PROVEN naming outranks them and
        // corrects the row, where the old table would have kept the
        // first writer's answer forever.
        "ALTER TABLE par_hashes ADD COLUMN tier TEXT NOT NULL DEFAULT 'hash16k-len'",
        "ALTER TABLE par_hashes ADD COLUMN contested INTEGER NOT NULL DEFAULT 0",
    ] {
        let _ = db.execute(ddl, []);
    }
}

/// Step 2: the indexes and triggers derived from those columns.
///
/// Runs AFTER [`additive_columns`], which is what guarantees the columns
/// each predicate names; see [`additive_migrations`] for what breaks if
/// that is reordered. Several of these are PARTIAL indexes whose
/// predicate is written out verbatim in the matching where-builder, and
/// each one says so at its own statement - a partial index is reachable
/// only when the statement's own WHERE implies its predicate, so the two
/// copies are load-bearing and must not be "tidied" apart.
fn derived_indexes_and_triggers(db: &Connection) {
    // The three enricher lane queues (N1). Each lane thread asks its
    // own question every 15 s for the life of the daemon, through
    // `with_index` - the write connection and the index write mutex
    // with the recorded wedge history - and NOTHING indexed `checked`,
    // `air_tried` or `tvdb_tried`, so every one of those ticks was a
    // full pass over `titles` plus a correlated `MAX(first_posted)` per
    // candidate row plus a temp B-tree sort, to return six to twelve
    // rows (or, on a settled install, none at all).
    //
    // PARTIAL on the queue's own "not done yet" flag, which is what
    // makes them nearly free: the two backfill lanes exist to be
    // FINISHED, so on a mature index these indexes hold approximately
    // nothing, and the first lane's index holds only what enrichment
    // has not reached yet. A partial index is also reachable only when
    // the statement's own WHERE implies its predicate - SQLite proves
    // that from a literal term, never from a bound parameter - so each
    // predicate below is written out verbatim in the matching
    // where-builder in titles.rs (`pending_lane_where`,
    // `missing_date_where`, `tvdb_queue_where`). Do not "tidy" either
    // copy: `idx_titles_tvdb` shipped without its term and answered
    // nothing for weeks, and plan_tests.rs now names the index each
    // statement must use so that cannot happen quietly again.
    //
    // `kind` is the indexed column because every one of the three
    // queries also filters on it (the lane split), which turns the
    // movie, music/book and tv arms into a seek rather than a walk of
    // the whole partial. They live after the ALTERs above, which are
    // what guarantee `air_tried` and `tvdb_tried` exist at all.
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_titles_unchecked ON titles(kind) WHERE checked = 0",
        [],
    );
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_titles_air_backfill ON titles(kind) WHERE air_tried = 0",
        [],
    );
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_titles_tvdb_backfill
           ON titles(kind) WHERE tvdb_tried = 0",
        [],
    );
    // The pesto backward-link's candidate query is a (grp, counter)
    // range probe; partial so the millions of non-pesto rows cost
    // nothing. Lives after the ALTERs that guarantee the column.
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_rel_pesto
           ON releases(grp, pesto_ctr_min) WHERE pesto_ctr_min IS NOT NULL",
        [],
    );
    // The oracle sampler's seeks, which `idx_rel_posted` could not
    // serve. They order by `first_posted` but filter `junk < 50`, and
    // no index carried `junk` - it arrives by ALTER TABLE with no index
    // of its own - so SQLite walked idx_rel_posted from the drawn
    // instant doing a rowid table fetch PER ENTRY to test junk, with no
    // upper bound on the forward statement and no wall-clock budget in
    // the draw loop. A long recent run of junk rows above the draw
    // therefore cost one fetch each until three visible rows turned up
    // or the index ended. The existing plan gate cannot see it: it
    // forbids the literal string "SCAN releases", and this plans as a
    // SEARCH with a post-filter, which passes.
    //
    // Partial on the same predicate the seeks use, so the walk stays
    // inside rows that already qualify and junk rows are not in the
    // index at all. Matches the sampler's WHERE exactly - widen one
    // without the other and it silently stops being used (Codex sweep
    // 4, L3 mechanism B).
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_rel_visible_posted
           ON releases(first_posted) WHERE junk < 50",
        [],
    );
    // `spots.release_id` dangled across release deletion: releases.id
    // has no AUTOINCREMENT, so the freed top rowid is reused by the
    // next insert, and a promoted spot silently rebound to an unrelated
    // release - wrong card links, the resolver never re-offering, and
    // the CDATA/relabel repair passes writing onto somebody else's row.
    // Exactly the recycled-id hazard the v1 trigger closes for
    // name_claims/msgid_map, so it moves into the same trigger. -1, not
    // 0: the eviction deleted the release deliberately, so the spot is
    // "resolved, release gone", never re-offered (offers match =0) and
    // never joined (repair passes match >0). Lives after the ALTER that
    // guarantees the column; the partial index keeps the trigger's
    // UPDATE off the unresolved millions - but ONLY because the trigger
    // repeats `release_id>0`. It did not until v3, so from c03a48a7
    // (14 Aug 2026) to 20 Aug this index answered nothing and the UPDATE
    // scanned every spot per deleted release. See the trigger below.
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_spots_rel ON spots(release_id) WHERE release_id>0",
        [],
    );
    // predb_sweep's exact-match leg probes
    // `WHERE pre_title='' AND LOWER(stem)=?1`. The plain idx_rel_stem is
    // BINARY, so LOWER() disqualified it and the "cheap indexed exact
    // match" was a full releases scan per swept feed row, held on the
    // shared write handle. Expression index in the query's exact shape;
    // partial on the same pre_title='' arm so already-named rows fall
    // out of it as naming progresses.
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_rel_stem_lower
           ON releases(LOWER(stem)) WHERE pre_title=''",
        [],
    );
    // The DROP is the one-time retirement of the v1 trigger, and it has
    // to STAY a no-op afterwards: `create_base_schema` used to re-create
    // `rel_identity_ad` on every open, so this pair wrote sqlite_master
    // twice per `Index::open` forever. That is not cosmetic. The daemon
    // opens a fresh read-write connection between passes (spot scan,
    // spot resolve, the retention republish, reclassify), so every one
    // of those opens bumped the schema cookie under the pooled READ-ONLY
    // connections that answer the wall, search and the newznab facade.
    // A reader then has to re-prepare, re-preparing reconnects the fts5
    // vtables, and a vtable constructor that loses that race fails the
    // whole statement with SQLITE_SCHEMA ("vtable constructor failed:
    // rel_fts") - which every query endpoint renders as an EMPTY answer,
    // i.e. a Sonarr search that silently finds nothing. Measured 9 times
    // in 160 runs of `newznab_honours_the_arr_search_parameters`, which
    // is the flake nextest's retry was hiding.
    //
    // v3 repeats `release_id>0` in the spots UPDATE, and that term is
    // the whole point of the version bump. `idx_spots_rel` is PARTIAL
    // on `release_id>0`, and SQLite reaches a partial index only when
    // the statement's own WHERE implies its predicate - it does not
    // derive `release_id>0` from `release_id=old.id`, because it cannot
    // know what `old.id` holds. So v2's UPDATE planned as `SCAN spots`:
    // a full pass over every spot ever seen, ONCE PER DELETED RELEASE,
    // inside the trigger, inside the caller's transaction, on the
    // shared index write mutex, with no await point anywhere in it.
    //
    // Measured 20 Aug 2026, end to end on this schema with 2.0 M spots,
    // three runs: 83-98 ms per deleted release against 0.26-0.42 ms with
    // the term. So one 8000-id `prune_batch` held the write mutex for
    // eleven MINUTES where it should hold it for about three seconds.
    // That is Gary's report: a finished job sitting in the queue while
    // the hourly retention reap ran, the tail resuming in the same second
    // the reap's line printed. His log reaped 4585 rows across an 8m46s
    // silence, which is 115 ms a row - one spots scan each.
    //
    // The term is exactly equivalent - `releases.id` is a rowid, always
    // >= 1, so no row can match `release_id=old.id` and fail
    // `release_id>0` - and it turns the scan into `SEARCH spots USING
    // INDEX idx_spots_rel`. It looks redundant. It is load-bearing, and
    // `plan_tests.rs` now asserts every trigger statement plans without
    // a scan so the next one cannot ship silently.
    let _ = db.execute_batch(
        "DROP TRIGGER IF EXISTS rel_identity_ad;
         DROP TRIGGER IF EXISTS rel_identity_ad_v2;
         CREATE TRIGGER IF NOT EXISTS rel_identity_ad_v3 AFTER DELETE ON releases BEGIN
           DELETE FROM name_claims WHERE release_id=old.id;
           DELETE FROM msgid_map WHERE release_id=old.id;
           UPDATE spots SET release_id=-1 WHERE release_id=old.id AND release_id>0;
         END;",
    );
    // The header-encryption stats group by kind over a band that is a
    // rounding error next to the whole table; partial so the millions of
    // never-classified rows cost nothing to store or maintain.
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_rel_enc
           ON releases(enc_class) WHERE enc_class>0",
        [],
    );
}

/// Step 3: the predb.pt index and its one-shot backfill.
///
/// Last, and after [`additive_columns`] has guaranteed `pt` on every
/// install. The kv flag is what keeps the UPDATE from re-running on
/// every open of a large feed table.
fn predb_pt_backfill(db: &Connection) {
    // The pt index and its one-shot backfill live here, after the
    // ALTER above has guaranteed the column on every install. The
    // kv flag keeps the UPDATE from re-running on every open of a
    // large feed table; it runs BEFORE anything samples predb.
    let _ = db.execute("CREATE INDEX IF NOT EXISTS idx_predb_pt ON predb(pt)", []);
    let pt_done: bool = db
        .query_row(
            "SELECT 1 FROM kv WHERE k='predb_pt_backfill_v1'",
            [],
            |_| Ok(()),
        )
        .is_ok();
    if !pt_done {
        let done = db
            .execute(
                "UPDATE predb SET pt=CASE WHEN pre_at>0 THEN pre_at ELSE seen_at END
                  WHERE pt=0",
                [],
            )
            .is_ok();
        if done {
            let _ = db.execute(
                "INSERT OR REPLACE INTO kv(k,v) VALUES('predb_pt_backfill_v1','1')",
                [],
            );
        }
    }
}

/// A8: rebuild a single-server-era marks table to (grp, server).
fn rebuild_marks_if_needed(db: &Connection) {
    // A8: rebuild a single-server-era marks table (PRIMARY KEY(grp))
    // to the (grp, server) shape. SQLite cannot ALTER a primary key,
    // so this is the standard rebuild - one-time; the PRAGMA guard
    // keeps every later open from bumping the schema version. Rows
    // keep server='' until adopt_legacy_marks assigns them to the
    // server that actually built them. Non-fatal like the other
    // migrations: on failure the next open retries, and the worst a
    // lost marks table costs is a rescan (ingest is idempotent).
    let has_server_col = db
        .prepare("SELECT 1 FROM pragma_table_info('marks') WHERE name='server'")
        .and_then(|mut s| s.exists([]))
        .unwrap_or(false);
    if !has_server_col {
        // A real Transaction object, not a BEGIN/COMMIT batch: a
        // mid-batch failure would otherwise leave the transaction
        // open on this connection, and every later statement in this
        // open() would silently run (and hold the write lock) inside
        // it. The drop of an uncommitted Transaction rolls back.
        let rebuild = db.unchecked_transaction().and_then(|tx| {
            tx.execute_batch(
                "DROP TABLE IF EXISTS marks_v2;
                 CREATE TABLE marks_v2(
                    grp TEXT NOT NULL,
                    server TEXT NOT NULL DEFAULT '',
                    high INTEGER NOT NULL,
                    low INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(grp, server));
                 INSERT INTO marks_v2(grp, server, high, low)
                   SELECT grp, '', high, low FROM marks;
                 DROP TABLE marks;
                 ALTER TABLE marks_v2 RENAME TO marks;",
            )?;
            tx.commit()
        });
        let _ = rebuild;
    }
}

/// The wall arrival-seq counter/trigger and the M28 browse indexes.
fn arrival_counter_and_indexes(db: &Connection) {
    // Existing rows receive their current id as an initial cursor.
    // New inserts advance a persistent counter in the same SQLite write
    // transaction, so same-second arrivals and rowid reuse both remain
    // visible to an already-open wall.
    // Non-fatal, like every other migration in this function. This
    // batch ENDS in an unconditional `UPDATE kv ... WHERE
    // k='wall_arrival_seq'`, which always matches a row, so every
    // single `Index::open` takes the SQLite write lock. A scan pass
    // opens up to 8 handles concurrently while a foreground ingest
    // chunk holds the writer, so exceeding the busy timeout is a
    // routine event, not a corrupt database - and propagating it made
    // `with_index` hand back None, which skips a whole group's scan
    // for the interval and answers wall/browse/search with nothing.
    // Every statement here is idempotent and self-healing: a later
    // open re-runs it, and rows that missed the trigger keep
    // arrival_seq=0 until the first line above claims them.
    let _ = db.execute_batch(
        "UPDATE releases SET arrival_seq=id WHERE arrival_seq=0;
         INSERT OR IGNORE INTO kv(k, v)
           VALUES('wall_arrival_seq',
                  (SELECT CAST(COALESCE(MAX(arrival_seq), 0) AS TEXT) FROM releases));
         UPDATE kv
            SET v=CAST(MAX(CAST(v AS INTEGER),
                           (SELECT COALESCE(MAX(arrival_seq), 0) FROM releases)) AS TEXT)
          WHERE k='wall_arrival_seq';
         -- The COALESCE is what keeps this trigger fail-SAFE rather
         -- than fail-DEAD. `arrival_seq` is NOT NULL, so if the kv
         -- row is ever absent the SELECT yields NULL, the UPDATE
         -- violates the constraint, and the constraint takes the
         -- whole ingest transaction with it - every insert into
         -- `releases` fails for as long as the row is gone. Nothing
         -- deletes it today, but three places do `DELETE FROM kv
         -- WHERE k=...` and one mistyped key would make the index
         -- permanently unwritable. Falling back to the row id costs
         -- at worst a cursor value shared with an evicted row, and
         -- the statements above restore the counter from
         -- MAX(arrival_seq) on the very next open.
         --
         -- Suffixed `_v2` rather than DROP+CREATEd: the drop of the
         -- old name is a no-op once it has run, so an already
         -- migrated database does not bump its schema version (and
         -- invalidate every other connection's prepared statements)
         -- on every single open.
         DROP TRIGGER IF EXISTS rel_arrival_seq_ai;
         CREATE TRIGGER IF NOT EXISTS rel_arrival_seq_ai_v2
           AFTER INSERT ON releases WHEN new.arrival_seq=0 BEGIN
             UPDATE kv SET v=CAST(CAST(v AS INTEGER)+1 AS TEXT)
               WHERE k='wall_arrival_seq';
             UPDATE releases
                SET arrival_seq=COALESCE(
                      CAST((SELECT v FROM kv
                            WHERE k='wall_arrival_seq') AS INTEGER),
                      new.id)
              WHERE id=new.id;
           END;",
    );
    // M28: browse-path indexes - every filter/sort was a full scan
    // (only idx_rel_stem existed).
    let _ = db.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_rel_posted ON releases(first_posted);
         CREATE INDEX IF NOT EXISTS idx_rel_kind ON releases(kind, first_posted);
         CREATE INDEX IF NOT EXISTS idx_rel_title_key ON releases(title_key);
         CREATE INDEX IF NOT EXISTS idx_rel_size ON releases(total_bytes);
         -- The arrival signal orders by when WE saw a release, not
         -- when it was posted: a backfill leg discovers genuinely old
         -- uploads, and those are not arrivals. Without this index
         -- `wall_tip` is a full scan on every poll.
         CREATE INDEX IF NOT EXISTS idx_rel_seen ON releases(first_seen);
         CREATE INDEX IF NOT EXISTS idx_rel_arrival ON releases(arrival_seq);",
    );
}

/// Largest `releases` rowid an ordinary `Index::open` may pay a picker
/// index build for. CREATE INDEX on `releases` reads the whole table
/// once, holding the write lock for the duration - measured 20 Aug
/// 2026 on the production-shaped 10 M row / 3.6 GB prototype at 2.7 s
/// per index, so ~0.3 s at this bound and minutes at the live 38 M/
/// 55.9 GB shape. Under the bound (fresh installs, tests, small
/// indexes) the build is noise and runs inline; over it, `open` leaves
/// the indexes absent and the daemon's maintenance pass builds them
/// one per pass with visible state (`build_picker_index`), abortable
/// the moment a download starts. A CLI-only install over the bound
/// simply keeps today's plans - the picks are correct without the
/// indexes, just unbounded.
pub(crate) const PICKER_INDEX_INLINE_MAX: i64 = 1_000_000;

/// The partial indexes on `releases` that `Index::open` will not pay
/// for inline above `PICKER_INDEX_INLINE_MAX`, `(name, ddl)`. The
/// `picker_*` names date from B1, when the three background pickers
/// were the only members; §198 added the two `complete` browse indexes
/// to the same deferred build because they have the same shape of cost.
///
/// Predicates come verbatim from the builders the statements
/// themselves use (`probe7z_band_sql`, `pesto_band_sql`,
/// `GAPFILL_BAND_SQL`, and browse's own `{}complete` term), because
/// SQLite reaches a partial index only when the statement's own WHERE
/// implies the predicate, proven from literal terms - one source for
/// both sides is what keeps them provable. The two probe lanes'
/// indexes carry `first_posted` so the newest-first pick walks them in
/// order; the gapfill one carries the pick's ORDER BY expressions byte
/// for byte, which is what retires its per-pick temp B-tree over the
/// whole incomplete band.
///
/// **The two browse indexes are a pair and neither is redundant** -
/// measured 20 Aug 2026 on the 13.2M-release live index
/// (`research/BROWSE-complete-index-2026-08-20.md`). `complete` is 1.5%
/// of the table and nothing indexed it, so every uncurated browse -
/// which is to say every *arr RSS sync - counted its `total` through a
/// full 13.2M-row table scan.
///
/// * `idx_rel_complete_kind` leads with `kind` because every *arr query
///   carries one (`t=movie` and `t=tvsearch` each set it even with no
///   `cat`), and that is the shape the RSS syncs issue: Radarr's
///   `kind='movie' AND complete` count went 1.05 s -> 0.11 s.
/// * `idx_rel_complete_posted` leads with `first_posted` because the
///   PAGE's `ORDER BY first_posted DESC LIMIT n` needs the index to
///   supply the order, not just the rows. Ship the kind-leading one
///   ALONE and the no-cat page regresses 16x (0.056 s -> 0.88 s): the
///   planner takes it for the rows and then sorts all 204k of them.
///   With both present the page walks this one in order and stops at
///   the page: 0.056 s -> 0.0017 s.
///
/// Both carry `stem` because that is what browse's `total` counts
/// (`browse_total_sql`), so the count never leaves the index. 11.1 MB
/// and 11.7 MB on that 26 GB database, and ~3 us per row that is
/// actually `complete` at ingest.
pub(crate) fn picker_index_ddl() -> [(&'static str, String); 5] {
    [
        (
            "idx_rel_probe7z",
            format!(
                "CREATE INDEX IF NOT EXISTS idx_rel_probe7z
                   ON releases(first_posted) WHERE {}",
                probe::probe7z_band_sql()
            ),
        ),
        (
            "idx_rel_pesto_tiny",
            format!(
                "CREATE INDEX IF NOT EXISTS idx_rel_pesto_tiny
                   ON releases(first_posted) WHERE {}",
                pesto::pesto_band_sql()
            ),
        ),
        (
            "idx_rel_gapfill",
            format!(
                "CREATE INDEX IF NOT EXISTS idx_rel_gapfill
                   ON releases({GAPFILL_ORDER_SQL}) WHERE {GAPFILL_BAND_SQL}"
            ),
        ),
        // Deployment order within the pair matters: the deferred
        // builder installs ONE list entry per idle pass, a scan interval
        // (or more) apart, so whichever member is listed first stands
        // alone for at least one interval on a migrating database. The
        // posted-leading member alone is only an improvement (the
        // no-cat page and every count get the partial index); the
        // kind-leading member alone is the measured 16x page regression
        // described above. Posted first, always.
        (
            "idx_rel_complete_posted",
            "CREATE INDEX IF NOT EXISTS idx_rel_complete_posted
               ON releases(first_posted, stem, kind) WHERE complete"
                .to_string(),
        ),
        (
            "idx_rel_complete_kind",
            "CREATE INDEX IF NOT EXISTS idx_rel_complete_kind
               ON releases(kind, first_posted, stem) WHERE complete"
                .to_string(),
        ),
    ]
}

/// The inline arm: create the picker indexes at open, but ONLY under
/// the size bound - the B1 deployment rule is that ordinary
/// `Index::open` must never block on an index build across the
/// production shape. `MAX(id)` is the O(1) proxy for table size (a
/// COUNT is itself a full scan); pruning gaps make it an
/// overestimate, which errs toward deferring.
fn picker_indexes(db: &Connection) {
    let top: i64 = db
        .query_row("SELECT COALESCE(MAX(id), 0) FROM releases", [], |r| {
            r.get(0)
        })
        .unwrap_or(i64::MAX);
    if top > PICKER_INDEX_INLINE_MAX {
        return;
    }
    for (_, ddl) in picker_index_ddl() {
        let _ = db.execute(&ddl, []);
    }
}

/// The two release FTS tables; (fts, pre_fts) availability flags.
fn ensure_fts(db: &Connection) -> (bool, bool) {
    // M28: FTS5 over raw stems (unicode61 tokenizer already treats
    // ./-/_ as separators, so no normalized shadow column is needed).
    // External-content table + triggers stay in sync with prune
    // deletes; stems are immutable so no UPDATE trigger. Wrapped in
    // is_ok() so a non-FTS build just keeps the LIKE path.
    let fts = db
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS rel_fts
               USING fts5(stem, content='releases', content_rowid='id');
             CREATE TRIGGER IF NOT EXISTS rel_fts_ai AFTER INSERT ON releases BEGIN
               INSERT INTO rel_fts(rowid, stem) VALUES(new.id, new.stem); END;
             CREATE TRIGGER IF NOT EXISTS rel_fts_ad AFTER DELETE ON releases BEGIN
               INSERT INTO rel_fts(rel_fts, rowid, stem)
                 VALUES('delete', old.id, old.stem); END;",
        )
        .is_ok();
    // A SECOND, tiny FTS index over the names the pre feed supplied.
    //
    // Not a column added to `rel_fts`: that is an external-content
    // table over millions of stems, and widening it means dropping,
    // recreating and rebuilding the whole thing at open - a minutes-
    // long startup stall on a large index, paid by every install
    // including the ones that never turn the feed on. This one only
    // ever holds rows that HAVE a fed name, so on a default install
    // it stays empty and costs a table definition.
    //
    // Unlike stems, a fed name arrives by UPDATE (the retro sweep
    // names a release long after it was inserted), so this one does
    // need the update trigger the stem index can do without.
    let pre_fts = db
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS pre_fts
               USING fts5(pre_title, content='releases', content_rowid='id');
             CREATE TRIGGER IF NOT EXISTS pre_fts_ai AFTER INSERT ON releases
               WHEN new.pre_title<>'' BEGIN
                 INSERT INTO pre_fts(rowid, pre_title)
                   VALUES(new.id, new.pre_title); END;
             CREATE TRIGGER IF NOT EXISTS pre_fts_ad AFTER DELETE ON releases
               WHEN old.pre_title<>'' BEGIN
                 INSERT INTO pre_fts(pre_fts, rowid, pre_title)
                   VALUES('delete', old.id, old.pre_title); END;
             CREATE TRIGGER IF NOT EXISTS pre_fts_au
               AFTER UPDATE OF pre_title ON releases BEGIN
                 INSERT INTO pre_fts(pre_fts, rowid, pre_title)
                   SELECT 'delete', old.id, old.pre_title WHERE old.pre_title<>'';
                 INSERT INTO pre_fts(rowid, pre_title)
                   SELECT new.id, new.pre_title WHERE new.pre_title<>''; END;",
        )
        .is_ok();
    (fts, pre_fts)
}

/// People + credits schema (fatal on failure, unlike the migrations)
/// and the people_fts index; returns whether people_fts is usable.
fn ensure_people(db: &Connection) -> rusqlite::Result<bool> {
    // Cast and crew as entities rather than a rendered string.
    // `titles.actors` stays exactly as it is - it is what every card
    // renders today, and nothing may regress while this join table
    // fills in behind it. The join table is what the person page,
    // name search and cast-overlap affinity read.
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS people(
            id           INTEGER PRIMARY KEY,
            name         TEXT NOT NULL,
            imdb         TEXT NOT NULL DEFAULT '',
            -- The two filmography handles. TVmaze's person id answers
            -- 'what else did they do on TV'; the Wikidata Q-id answers
            -- the film half. Neither source covers the other, so a
            -- person legitimately carries both.
            tvmaze_id    INTEGER NOT NULL DEFAULT 0,
            wikidata_qid TEXT NOT NULL DEFAULT '',
            bio          TEXT NOT NULL DEFAULT '',
            born         TEXT NOT NULL DEFAULT '',
            -- The provider's headshot URL, and unlike titles.poster
            -- it stays a URL. The cached file is evictable (a large
            -- index would otherwise quietly fill a NAS with
            -- headshots), and after an eviction the URL is the only
            -- thing that can fetch it back.
            photo        TEXT NOT NULL DEFAULT '',
            checked      INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS title_people(
            key       TEXT NOT NULL,
            person_id INTEGER NOT NULL,
            role      TEXT NOT NULL DEFAULT 'actor',
            character TEXT NOT NULL DEFAULT '',
            ord       INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(key, person_id, role));
         CREATE INDEX IF NOT EXISTS idx_tp_person ON title_people(person_id, ord);
         -- Partial uniques, so the handle-first upsert cannot race two
         -- threads into two rows for one person. They must stay
         -- partial: the default 0 / '' is 'no handle', and a plain
         -- UNIQUE would let exactly one person exist without one.
         CREATE UNIQUE INDEX IF NOT EXISTS idx_people_tvmaze
           ON people(tvmaze_id) WHERE tvmaze_id > 0;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_people_qid
           ON people(wikidata_qid) WHERE wikidata_qid <> '';
         -- Same rule for the IMDb id, and safe to add to an existing
         -- database: nothing ever wrote this column before the
         -- Wikidata P345 lane did, so every pre-existing row holds
         -- '' and falls outside the partial index. It carries the
         -- same trade the other two already do - the blank-fill
         -- UPDATE can collide when the handle-first lookup lands on
         -- a row whose blank belongs to another row's id, which
         -- fails that one title's credit write and lets the next
         -- enrichment retry it. Duplicate Wikidata items for one
         -- person, which is the common way two rows share an nm id,
         -- resolve through the lookup instead and merge cleanly.
         CREATE UNIQUE INDEX IF NOT EXISTS idx_people_imdb
           ON people(imdb) WHERE imdb <> '';
         CREATE INDEX IF NOT EXISTS idx_people_name ON people(name COLLATE NOCASE);",
    )?;
    // Name search. Unlike rel_fts there IS an UPDATE trigger: a
    // person row's name improves when a second provider supplies a
    // better-cased or fuller spelling, and an external-content FTS
    // that missed the update returns the row under a name it no
    // longer has.
    let people_fts = db.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS people_fts
           USING fts5(name, content='people', content_rowid='id');
         CREATE TRIGGER IF NOT EXISTS people_fts_ai AFTER INSERT ON people BEGIN
           INSERT INTO people_fts(rowid, name) VALUES(new.id, new.name); END;
         CREATE TRIGGER IF NOT EXISTS people_fts_ad AFTER DELETE ON people BEGIN
           INSERT INTO people_fts(people_fts, rowid, name)
             VALUES('delete', old.id, old.name); END;
         CREATE TRIGGER IF NOT EXISTS people_fts_au
           AFTER UPDATE OF name ON people BEGIN
           INSERT INTO people_fts(people_fts, rowid, name)
             VALUES('delete', old.id, old.name);
           INSERT INTO people_fts(rowid, name) VALUES(new.id, new.name); END;",
    );
    Ok(people_fts.is_ok())
}

/// TODO 5 phase 2c: fill `releases.stem_fold` for rows written before
/// the column existed.
///
/// Chunked with a kv rowid cursor and time-bounded, the `nsegs_fill`
/// shape and for the same two reasons: a single UPDATE over the whole
/// releases table (16.5 M rows on the live index) loses the write lock
/// to a running scanner and is silently discarded, and an unbounded
/// loop here blocks daemon startup, since every scan task opens its own
/// Index. Whatever is left resumes on the next open, and the read side
/// is correct throughout - an unfilled row is findable exactly as it
/// was before the column existed.
///
/// The `GLOB '*[^ -~]*'` term is what keeps this cheap: it is SQLite's
/// way of asking "does this stem hold a byte outside printable ASCII",
/// so the chunk hands Rust only the handful of rows that could possibly
/// earn a fold instead of marshalling 16.5 M stems across the boundary
/// to discover they are all ASCII. It is a filter, not a correctness
/// term - [`fold::stored`] re-decides for itself, and returns '' for
/// every non-ASCII stem `LOWER()` was already folding correctly.
///
/// This generation only ever ADDS a fold, which is all a never-filled
/// column needs. Clearing a fold that has gone stale is the second
/// generation's job, in [`fold_reconcile`].
fn fold_backfill(db: &mut Connection) {
    fold_pass(db, "fold_v1", "fold_at", "stem GLOB '*[^ -~]*'");
}

/// TODO 5 phase 2c, corrective generation: reconcile `stem_fold` with
/// what [`fold::stored`] says the row's stem folds to, on databases
/// carrying a fold left behind by a stem rewrite.
///
/// `Index::split_merge_group` in `maintenance.rs` collapses a split
/// release's volumes into one row and rewrites `stem` to the common
/// prefix. Until 886785fd7 (23 Aug 2026) it left `stem_fold` holding
/// the fold of the stem it had just replaced - so a merged Cyrillic
/// group keeps a fold ending in the volume suffix the merge removed,
/// ` 001`. Both non-FTS readers match on that column and so answer for
/// a stem that no longer exists: [`query::stem_fold_arm`], which is the
/// whole search path on a build without FTS, and the browse hide rule
/// that spells the same expression by hand. The FTS arm never saw it -
/// it tokenizes `stem`.
///
/// 886785fd7 stopped new ones being written; it could not repair the
/// ones already on disk, and [`fold_backfill`] above cannot either. Its
/// flag is long since stamped on every live index, and even re-armed it
/// only ever writes a NON-empty fold, so a row whose replacement stem
/// is ASCII would keep the stale one. Hence a second generation with
/// its own flag rather than a rearm of the first.
///
/// Two things follow from that, both in the prefilter:
///
/// * `stem_fold <> ''` is a correctness term here, not just a cost one.
///   A merge that shortens `ВОЙНА.001` to an ASCII stem leaves a fold
///   the GLOB above would never look at.
/// * The sparse rule survives: this writes back exactly what
///   [`fold::stored`] returns, which is `''` for an ASCII stem and for
///   any stem `LOWER()` already folds correctly, so a corrected row
///   costs a record-header byte rather than a second copy of the stem.
///
/// There is no `WHERE stem_fold <> fold(stem)` to write instead of the
/// walk: the fold is Rust, and the daemon's SQLite carries no function
/// for it.
fn fold_reconcile(db: &mut Connection) {
    fold_pass(
        db,
        "fold_v2",
        "fold_v2_at",
        "(stem GLOB '*[^ -~]*' OR stem_fold <> '')",
    );
}

/// The chunked rowid walk both `stem_fold` generations above are: read
/// the cursor, re-judge every row in the next stride that `prefilter`
/// admits, write back the ones [`fold::stored`] disagrees with, move
/// the cursor. `done_key` is stamped when the walk runs off the end of
/// the table; until then each open resumes where the last one stopped.
///
/// A generation is identified by its two kv keys, and nothing else -
/// the prefilter may be widened for a later one without disturbing an
/// earlier one's flag.
fn fold_pass(db: &mut Connection, done_key: &str, at_key: &str, prefilter: &str) {
    /// Rowids per chunk. Twenty times `nsegs_fill`'s because the
    /// prefilter turns almost every row into a rejected comparison
    /// rather than a row read plus an UPDATE.
    const CHUNK: i64 = 20_000;
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k=?1", [done_key], |r| r.get(0))
        .ok();
    if done.as_deref() == Some("1") {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let sel_sql = format!(
        "SELECT id, stem, stem_fold FROM releases
          WHERE rowid > ?1 AND rowid <= ?2 AND {prefilter}"
    );
    let _ = (|| -> rusqlite::Result<()> {
        loop {
            // Immediate, and the cursor read INSIDE it: several scan
            // connections open the index at once, and a deferred
            // transaction let two of them read the same cursor and the
            // slower one write back a stale lower value.
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let cursor: i64 = tx
                .query_row("SELECT v FROM kv WHERE k=?1", [at_key], |r| {
                    r.get::<_, String>(0)
                })
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            // Advance by rowid, never by "stem_fold = ''": that is the
            // steady state of nearly every row, so it would re-select
            // the same chunk forever.
            let next: Option<i64> = tx.query_row(
                "SELECT MAX(rowid) FROM
                   (SELECT rowid FROM releases WHERE rowid > ?1 ORDER BY rowid LIMIT ?2)",
                [cursor, CHUNK],
                |r| r.get(0),
            )?;
            let Some(next) = next else {
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES(?1,'1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [done_key],
                )?;
                tx.commit()?;
                return Ok(());
            };
            {
                let mut sel = tx.prepare(&sel_sql)?;
                let mut upd = tx.prepare("UPDATE releases SET stem_fold=?2 WHERE id=?1")?;
                let rows: Vec<(i64, String, String)> = sel
                    .query_map([cursor, next], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                for (id, stem, held) in rows {
                    let f = super::fold::stored(&stem);
                    // Compared, not written unconditionally: on a
                    // healthy index every admitted row already agrees,
                    // so the pass reads and writes nothing.
                    if f != held {
                        upd.execute(rusqlite::params![id, f])?;
                    }
                }
            }
            // Cursor moves with the rows, in the same transaction: a
            // busy failure rolls back both and the chunk is redone.
            tx.execute(
                "INSERT INTO kv(k, v) VALUES(?1, ?2)
                 ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                rusqlite::params![at_key, next.to_string()],
            )?;
            tx.commit()?;
            if std::time::Instant::now() >= deadline {
                return Ok(());
            }
        }
    })();
}

/// The one-shot, kv-stamped retroactive backfills (completeness rule,
/// nsegs, M25 kind/res, M28 FTS + title_key/junk, stem_fold in its two
/// generations, quality_v10).
fn retroactive_backfills(db: &mut Connection, fts: bool) {
    // One-time retroactive recompute after the completeness-rule
    // change (nfiles >= 2 → >= 1): existing rows only re-evaluate
    // when a scan touches them, which for finished uploads is never.
    let rule: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='complete_rule'", [], |r| r.get(0))
        .ok();
    if rule.as_deref() != Some("2") {
        // One transaction, and the done-flag only lands if the
        // recompute did: as two autocommit statements, a SQLITE_BUSY
        // on the big UPDATE (discarded) with the tiny insert
        // succeeding stamped the migration done while every
        // completeness flag stayed stale - permanently.
        let _ = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            tx.execute(
                "UPDATE releases SET complete =
                   EXISTS(SELECT 1 FROM files f WHERE f.release_id=releases.id)
                   AND NOT EXISTS(SELECT 1 FROM files f WHERE f.release_id=releases.id
                                  AND (CASE WHEN f.nsegs > 0 THEN f.nsegs
                                               ELSE seg_count(f.segments) END) < f.total_parts)",
                [],
            )?;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('complete_rule','2')
                 ON CONFLICT(k) DO UPDATE SET v='2'",
                [],
            )?;
            tx.commit()
        })();
    }
    // Retroactive fill of `nsegs` for rows written before the column
    // existed. Finished uploads are never re-ingested, so without
    // this they would take the JSON-parsing fallback above forever.
    //
    // Chunked with a kv rowid cursor, and time-bounded, for two
    // reasons learned the hard way. A single UPDATE over the whole
    // files table (1.6 M rows on the live index) loses the write
    // lock to a running scanner and is silently discarded - the
    // junk_v6 re-score did exactly that. And an unbounded loop here
    // would block daemon startup for minutes, since every scan task
    // opens its own Index. Whatever is left resumes on the next
    // open; the read side is correct throughout either way.
    let filled: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='nsegs_fill'", [], |r| r.get(0))
        .ok();
    if filled.as_deref() != Some("1") {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let _ = (|| -> rusqlite::Result<()> {
            loop {
                // Acquire the writer reservation BEFORE reading the
                // cursor. Several scan connections open the index at
                // once; a deferred transaction let two of them read
                // the same cursor, then a delayed one could overwrite
                // a later cursor with its stale lower value.
                let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let cursor: i64 = tx
                    .query_row("SELECT v FROM kv WHERE k='nsegs_at'", [], |r| {
                        r.get::<_, String>(0)
                    })
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                // Advance by rowid, never by "nsegs = 0": a row whose
                // segments JSON will not parse stays 0 forever and
                // would be re-selected every pass, spinning here.
                let next: Option<i64> = tx.query_row(
                    "SELECT MAX(rowid) FROM
                       (SELECT rowid FROM files WHERE rowid > ?1 ORDER BY rowid LIMIT 5000)",
                    [cursor],
                    |r| r.get(0),
                )?;
                let Some(next) = next else {
                    tx.execute(
                        "INSERT INTO kv(k, v) VALUES('nsegs_fill','1')
                         ON CONFLICT(k) DO UPDATE SET v='1'",
                        [],
                    )?;
                    tx.commit()?;
                    return Ok(());
                };
                tx.execute(
                    "UPDATE files SET nsegs = COALESCE(seg_count(segments), 0)
                     WHERE rowid > ?1 AND rowid <= ?2",
                    [cursor, next],
                )?;
                // Cursor moves with the rows, in the same
                // transaction: a busy failure rolls back both and
                // the chunk is simply redone.
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('nsegs_at', ?1)
                     ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    [next.to_string()],
                )?;
                tx.commit()?;
                if std::time::Instant::now() >= deadline {
                    return Ok(());
                }
            }
        })();
    }
    fold_backfill(db);
    fold_reconcile(db);
    // M25 browse view: retroactive fill of the new kind/res/part
    // columns for rows indexed before they existed. Same shape as
    // the complete_rule migration: one transaction, flag stamped
    // only if the fill landed, so SQLITE_BUSY just retries next open.
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='browse_cols'", [], |r| r.get(0))
        .ok();
    if done.as_deref() != Some("1") {
        let _ = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            tx.execute(
                "UPDATE releases SET
                   have_parts = COALESCE((SELECT SUM(seg_count(segments))
                                          FROM files WHERE release_id=releases.id), 0),
                   need_parts = COALESCE((SELECT SUM(total_parts)
                                          FROM files WHERE release_id=releases.id), 0)",
                [],
            )?;
            {
                let mut sel = tx.prepare("SELECT id, stem FROM releases WHERE kind=''")?;
                let mut upd = tx.prepare("UPDATE releases SET kind=?2, res=?3 WHERE id=?1")?;
                let rows: Vec<(i64, String)> = sel
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                for (id, stem) in rows {
                    let p = crate::release::parse_release(&stem);
                    upd.execute(rusqlite::params![
                        id,
                        kind_str(&p.kind),
                        p.res.unwrap_or_default()
                    ])?;
                }
            }
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('browse_cols','1')
                 ON CONFLICT(k) DO UPDATE SET v='1'",
                [],
            )?;
            tx.commit()
        })();
    }
    // M28: one-time FTS backfill for rows inserted before the
    // triggers existed - 'rebuild' re-reads the whole content table.
    // Same stamped-in-transaction shape as the migrations above.
    if fts {
        let done: Option<String> = db
            .query_row("SELECT v FROM kv WHERE k='fts_v1'", [], |r| r.get(0))
            .ok();
        if done.as_deref() != Some("1") {
            let _ = (|| -> rusqlite::Result<()> {
                let tx = db.unchecked_transaction()?;
                tx.execute("INSERT INTO rel_fts(rel_fts) VALUES('rebuild')", [])?;
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('fts_v1','1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )?;
                tx.commit()
            })();
        }
    }
    // M28: retroactive title_key + junk fill (rows only re-parse when
    // a scan touches them, which for finished uploads is never).
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='browse2'", [], |r| r.get(0))
        .ok();
    if done.as_deref() != Some("1") {
        let _ = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            {
                let mut sel =
                    tx.prepare("SELECT id, stem, total_bytes FROM releases WHERE title_key=''")?;
                let mut upd =
                    tx.prepare("UPDATE releases SET title_key=?2, junk=?3 WHERE id=?1")?;
                let rows: Vec<(i64, String, i64)> = sel
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                for (id, stem, bytes) in rows {
                    let p = crate::release::parse_release(&stem);
                    upd.execute(rusqlite::params![
                        id,
                        p.key,
                        junk_score(&stem, &p, bytes as u64, false)
                    ])?;
                }
            }
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('browse2','1')
                 ON CONFLICT(k) DO UPDATE SET v='1'",
                [],
            )?;
            tx.commit()
        })();
    }
    // §131 identity substrate: key existing files rows into msgid_map
    // (rows only pass through ingest when a scan touches them, which
    // for finished uploads is never). Same chunked, time-bounded,
    // cursor-resumed shape as the nsegs fill above, for the same
    // reasons: the live table is millions of rows, a single UPDATE
    // loses the write lock to a running scanner, and an unbounded
    // loop would stall daemon startup. Resumes on the next open.
    super::claims::msgid_map_backfill(db);
    // Pesto counter/clock fill for rows scanned before the columns
    // existed - same chunked, time-bounded, cursor-resumed shape, for
    // the same reasons.
    super::pesto::pesto_backfill(db);
    quality_backfill(db);
}

/// quality_v10 (2 Sep 2026, was quality_v9 on 16 Aug, quality_v8
/// before that, junk_v7 before that): the bump re-files the book,
/// music and anime lanes. Six classifier fixes landed on 2 Sep and
/// NONE of them could reach a row already stored - the `pdf`/`max`/
/// edition-number reads (d94b4735c), the group prior (e2f399a57),
/// the rot13 music and book rescue (633b7baf8), the fansub episode
/// read (ea2229aa2), the dashed `Show - NNN - Title` episode read
/// (3f52c0ca4) and the masthead date reading (4724a8f0b). An
/// audiobook folder in alt.binaries.mp3.audiobooks carries
/// `kind=movie, junk=60`, the naming seam refuses a row whose
/// pre_title is set, and the custom-category sweep only runs when
/// the category config changes. Without the bump every one of those
/// fixes would apply to new posts only.
///
/// Two of the six are GROUP-aware, which is what v10 costs over a
/// free re-run of v9: the SELECT carries `grp` and the pass runs the
/// group half of ingest's chain as well as the name half it already
/// ran.
///
/// v9's own reason, kept because the bump inherits it: the book lane
/// re-file, junk_v6's rules plus a full
/// re-parse - title_key/kind/res so ROT13 rescues that the parser
/// newly decodes regroup under their real titles, and now
/// vcodec/acodec/hdr, which rows indexed before those columns
/// existed have never carried. The kv key names the CURRENT
/// version; bumping it re-parses every row exactly once, which is
/// what backfills the new columns - free, because this pass
/// already parses every row's effective name. CHUNKED with a
/// persisted id cursor - the
/// one-big-tx shape could never win the write lock against
/// parallel scanners on a live daemon (SQLITE_BUSY → silently
/// skipped forever). 10k rows per transaction interleaves with
/// scan ingest; a partial pass resumes from the cursor on the
/// next open.
///
/// TIME-BOUNDED, unlike v9's inline loop, and that is the other half of
/// what makes a bump safe to take again. This runs inside
/// `Index::open`, so an unbounded loop re-parses the whole table before
/// the daemon serves its first request - and v9's loop was unbounded.
/// MEASURED, release build, 400k synthetic rows with two `files` rows
/// each so the SELECT's EXISTS probe does real work (the rig is
/// `qual_bench::time_the_quality_pass`, `--ignored`). Twice, because
/// the first run was on a box carrying five other worktree builds and
/// the spread is the interesting part:
///
///     load ~39   30.8 s / 400k   =  77.1 s per million rows
///     load ~23   16.6 s / 400k   =  41.6 s per million rows
///
/// So a 67M-row index, which the largest live ones are, is somewhere
/// between 46 and 86 minutes, and it is CPU that a busy box makes
/// worse. Stated limits in
/// both directions: a loaded box inflates the rate, and a 400k-row
/// scratch index sits entirely in page cache while a live 67M-row one
/// does not, which deflates it. Neither matters to the decision. What
/// this is not is borderline: the conclusion survives being wrong by
/// 4x either way.
///
/// So the pass takes the shape of the two backfills above it instead: a
/// budget per call, the persisted cursor doing the resuming, and a
/// maintenance leg in the indexer lap
/// (`passes::quality_backfill_pass`) finishing what the 2 s at open
/// could not. The heal is therefore gradual rather than instant, which
/// is the right trade for a re-file of rows that have been mis-filed
/// since they were indexed: nothing downstream has a deadline on it.
fn quality_backfill(db: &mut Connection) {
    quality_backfill_slice(db, std::time::Duration::from_secs(2));
}

/// One budgeted slice of [`quality_backfill`]. Returns true when the
/// pass is COMPLETE, so a caller's slice loop can stop early - the same
/// caught-up contract as `msgid_map_backfill_slice`.
pub(super) fn quality_backfill_slice(db: &mut Connection, budget: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    let mut complete = false;
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='quality_v10'", [], |r| r.get(0))
        .ok();
    if done.as_deref() == Some("1") {
        return true;
    }
    let _ = (|| -> rusqlite::Result<()> {
        let mut cursor: i64 = db
            .query_row("SELECT v FROM kv WHERE k='quality_v10_cursor'", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        loop {
            // IMMEDIATE, like the nsegs, reclassify and ingest
            // transactions: this reads a cursor and writes it
            // back, and a deferred lock upgrade does NOT get the
            // busy timeout - it returns SQLITE_BUSY at once. A
            // deferred wrapper here meant a contended pass
            // abandoned mid-chunk and left the cursor parked.
            let tx =
                rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
            // The effective name, NOT the raw stem: a row named
            // after ingest (`apply_named` - predb sweep, spot
            // promotion, byte probes) derived every classification
            // column from pre_title, and its stem is an obfuscated
            // hash. Re-parsing the stem here would clobber the row
            // back to the junk>=70 no-card answer, and nothing
            // would ever heal it - the naming seam refuses rows
            // whose pre_title is already set. Same COALESCE the
            // ingest and card paths use.
            // `grp` is the sixth column and the reason this key
            // is v10: two of the six classifier fixes it heals are
            // GROUP-aware (`recover_kind_from_group` and
            // `recover_episode_from_group`), and v9's SELECT could
            // not feed them. `releases.grp` is NOT NULL in the
            // original CREATE TABLE and part of the row's UNIQUE
            // identity, so every row ever written carries it - there
            // is no era of blank groups for this to no-op over.
            let rows: Vec<(i64, String, i64, bool, String, String)> = {
                let mut sel = tx.prepare_cached(&format!(
                    "SELECT id, COALESCE(NULLIF(pre_title,''), stem),
                                total_bytes,
                                EXISTS(SELECT 1 FROM files
                                       WHERE release_id=releases.id AND {EXE_FILE_SQL}),
                                stem, grp
                         FROM releases WHERE id > ?1 ORDER BY id LIMIT 10000"
                ))?;
                sel.query_map([cursor], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            if rows.is_empty() {
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('quality_v10','1')
                         ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )?;
                tx.commit()?;
                complete = true;
                return Ok(());
            }
            {
                // `parse_release` is CUSTOM-BLIND: `Index::open`
                // runs before `set_custom`, by construction (the
                // constructor hardcodes an empty category list),
                // so this pass cannot know the user's categories.
                // Re-parsing a row that `reclassify_custom`
                // classified would therefore rewrite kind and
                // title_key back to the built-in answer - every
                // session of an F1 season collapsing onto one
                // movie card, out of the category tab, and losing
                // the Custom junk exemption. Worse, it does not
                // heal: `reclassify_custom` sees an unchanged
                // fingerprint and no cursor and returns Ok(0) on
                // every later start.
                //
                // So the classification columns are written only
                // for rows still carrying a built-in kind. The
                // rest - the codec/resolution/language backfill
                // this pass exists for - is unconditional, and is
                // correct for custom rows too, because
                // `apply_custom` mutates ONLY kind and key.
                // '' is in the list deliberately: a row that has
                // never been classified still needs its first
                // parse.
                let mut upd = tx.prepare_cached(
                    "UPDATE releases SET langs=?2, res=?3,
                                vcodec=?4, acodec=?5, hdr=?6
                         WHERE id=?1 AND (langs<>?2 OR res<>?3
                                OR vcodec<>?4 OR acodec<>?5 OR hdr<>?6)",
                )?;
                let mut upd_class = tx.prepare_cached(
                    "UPDATE releases SET junk=?2, title_key=?3, kind=?4
                         WHERE id=?1
                           AND kind IN ('movie','tv','music','book',
                                        'software','other','')
                           AND (junk<>?2 OR title_key<>?3 OR kind<>?4)",
                )?;
                for (id, name, bytes, has_exe, stem, grp) in &rows {
                    let mut p = crate::release::parse_release(name);
                    // A fed name names the work; the stem names the
                    // file. Only the file says "book".
                    crate::release::recover_media_kind(&mut p, name, stem);
                    // THE SAME CHAIN AS `ingest_pass`, IN THE SAME
                    // ORDER (custom categories excepted, for the
                    // reason written below), because a backfill that
                    // classifies differently from ingest is a second
                    // classifier: rows would flap between the two
                    // answers on every scan touch. The group prior
                    // first (it
                    // returns early on an episode, so an episode
                    // invented ahead of it disarms the book/music
                    // rescue), then the episode read, gated on the
                    // same obfuscation test for the same reason -
                    // the season it records would make the blob test
                    // more lenient than it was.
                    crate::release::recover_kind_from_group(&mut p, grp, stem);
                    if !stem_obfuscated(stem, &p) {
                        crate::release::recover_episode_from_group(&mut p, grp, name);
                    }
                    upd.execute(rusqlite::params![
                        id,
                        p.langs.join(" "),
                        p.res.as_deref().unwrap_or_default(),
                        p.vcodec.as_deref().unwrap_or_default(),
                        p.acodec.as_deref().unwrap_or_default(),
                        p.hdr.as_deref().unwrap_or_default()
                    ])?;
                    upd_class.execute(rusqlite::params![
                        id,
                        junk_score(name, &p, *bytes as u64, *has_exe),
                        p.key,
                        kind_str(&p.kind)
                    ])?;
                }
            }
            cursor = rows.last().unwrap().0;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('quality_v10_cursor', ?1)
                     ON CONFLICT(k) DO UPDATE SET v=?1",
                [cursor.to_string()],
            )?;
            tx.commit()?;
            // The budget is spent BETWEEN chunks, never inside one:
            // the cursor and the rows it covers are one transaction,
            // and a slice that stopped mid-chunk would either park
            // the cursor behind work it had already done or roll the
            // work back. Same place `msgid_map_backfill_slice`
            // checks its own deadline, for the same reason.
            if std::time::Instant::now() >= deadline {
                return Ok(());
            }
        }
    })();
    complete
}

std::thread_local! {
    /// How many read-write [`Index::open`] calls THIS THREAD has made -
    /// each one is a full migration-ladder run over the schema. B4
    /// instrumentation: a scan pass used to pay one of these per group
    /// just to republish the shared connection, and the tests that pin
    /// the hand-back path assert this does not creep back in.
    /// Per-thread, not process-global: the hand-back is synchronous on
    /// the publishing thread, so its own count is the whole claim,
    /// while a process-global counter is bumped by whatever else the
    /// process is opening - under an in-process parallel test runner
    /// (plain `cargo test`, where every test shares one process) that
    /// made the hand-back assertion flake.
    static OPEN_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

impl Index {
    /// One budgeted slice of the quality re-classification backfill,
    /// for the indexer lap's maintenance leg. `Index::open` gets two
    /// seconds of it; on an index of any size that is a start and not a
    /// finish, and the lap is what finishes it. Returns true when the
    /// pass is COMPLETE. See [`quality_backfill`].
    pub fn quality_backfill_slice(&mut self, budget: std::time::Duration) -> bool {
        quality_backfill_slice(&mut self.db, budget)
    }

    /// How far the quality backfill has walked (0 = not started, None =
    /// finished), so the lap can log its advance rather than leaving it
    /// visible only in `kv`.
    pub fn quality_backfill_cursor(&self) -> Option<i64> {
        if self.kv_get("quality_v10").as_deref() == Some("1") {
            return None;
        }
        Some(
            self.kv_get("quality_v10_cursor")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        )
    }

    /// Put an open index into the state a PRE-BUMP one is in: every
    /// stored row carrying an older classifier's answer in the three
    /// classification columns, and the version key un-stamped so
    /// [`quality_backfill_slice`] has the whole table to walk. Returns
    /// the rows poisoned.
    ///
    /// It exists because that state cannot be reached any other way
    /// from outside this crate, and a test that cannot reach it cannot
    /// see the pass run AT ALL - which is exactly how the daemon-side
    /// lap leg shipped with no coverage. A fresh test index is empty,
    /// so the very first `Index::open` finds no rows, stamps the key
    /// and every later call returns at the first kv read. Same reason
    /// `debug_defer_picker_indexes` exists next door: the honest state
    /// is unreachable, and the code's own definition of it is cheap to
    /// write directly.
    ///
    /// Un-stamping with `LIKE 'quality_v%'` rather than naming v10, so
    /// the next version bump does not quietly leave a caller pinning a
    /// key nothing reads any more.
    #[doc(hidden)]
    pub fn debug_stale_classification(&self, kind: &str, junk: i64) -> usize {
        let n = self
            .db
            .execute(
                "UPDATE releases SET kind=?1, junk=?2, title_key='stale-answer'",
                rusqlite::params![kind, junk],
            )
            .expect("write the stale classification");
        self.db
            .execute("DELETE FROM kv WHERE k LIKE 'quality_v%'", [])
            .expect("un-stamp the quality version");
        n
    }

    /// See [`OPEN_COUNT`]; counts the calling thread's opens only.
    pub fn open_count() -> u64 {
        OPEN_COUNT.with(|c| c.get())
    }

    /// A scan's own connection: [`Self::open`], with a page cache sized
    /// for a scratch pass instead of for the shared writer.
    ///
    /// `open`'s `cache_size` is the writer's 256 MiB, and the daemon
    /// opens one of these PER GROUP - up to eight at once on a busy pass,
    /// plus the two spot passes - so the writer's figure let a pass
    /// address ~2.5 GiB of page cache on a machine that may have 2 GB
    /// total. A scan is streaming upserts and point lookups: it reads
    /// each btree page it touches once and dirties it once, which is the
    /// access pattern a large cache does least for, and reads ride the
    /// 1 GB mmap window rather than the cache anyway.
    ///
    /// A/B'd against a 47 GB live index (20 Aug 2026), three alternating
    /// pairs, each ingesting 4,000 clusters under stems sampled at random
    /// across all 41 M releases - a scan re-seeing articles for releases
    /// it already holds, which is the shape that actually fills a cache.
    /// Ingest time was a wash (6.65/8.47/7.94 s scratch against
    /// 6.64/8.49/7.68 s writer, the arms trading the win); SQLite's own
    /// heap settled at 78 MiB against 237-250 MiB, and its high-water
    /// went from ~314 MiB per connection to ~86 MiB. The daemon opens one
    /// of these per group, so that is the figure multiplied by eight.
    ///
    /// The shared writer keeps 256 MiB - it is one connection and it
    /// holds the compaction and migration transactions.
    pub fn open_scratch(path: &Path) -> rusqlite::Result<Index> {
        Self::open_with_cache(path, SCRATCH_CACHE_MIB)
    }

    pub fn open(path: &Path) -> rusqlite::Result<Index> {
        Self::open_with_cache(path, WRITER_CACHE_MIB)
    }

    fn open_with_cache(path: &Path, cache_mib: i64) -> rusqlite::Result<Index> {
        OPEN_COUNT.with(|c| c.set(c.get() + 1));
        let mut trace = OpenTrace::start();
        let mut db = Connection::open(path)?;
        // Several connections share this db (scan scratch, API queries,
        // wall enricher, IMDb refresher). Without a busy timeout a
        // schema-creation or checkpoint race fails INSTANTLY with
        // "database is locked" - which made the daemon's first scan pass
        // silently skip a whole interval (the long-standing
        // scan_loop_populates_index_live "flake").
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        segcodec::register(&db)?;
        trace.lap("connect");
        create_base_schema(&db, cache_mib)?;
        trace.lap("base schema");
        additive_migrations(&db);
        trace.lap("additive migrations");
        rebuild_marks_if_needed(&db);
        trace.lap("marks");
        arrival_counter_and_indexes(&db);
        trace.lap("arrival");
        picker_indexes(&db);
        trace.lap("picker indexes");
        let (fts, pre_fts) = ensure_fts(&db);
        let people_fts_ok = ensure_people(&db)?;
        let people_fts = fts && people_fts_ok;
        trace.lap("fts");
        retroactive_backfills(&mut db, fts);
        trace.lap("retroactive backfills");
        // M29 availability oracle: (backbone, family, age-bucket) ledger.
        let _ = crate::oracle::ensure_schema(&db);
        trace.lap("oracle");
        // `EXISTS` rather than a count: this only has to answer "is the
        // feed worth consulting", and on a large predb the count is a
        // full index scan at every open.
        let predb = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM predb WHERE fnkey<>'')",
                [],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false);
        // The named-count's partial index rides on feed activity, not
        // on `predb` above: a title-only feed (the common live shape)
        // has no nameable rows yet still names releases through the
        // correlation legs, and the settings card asks for the count
        // either way. Any row in predb at all means the build is
        // worth paying once here, on the writer - the API's read-only
        // handle cannot create it. An install whose feed never ran
        // has an empty table and never pays.
        let feed_ever = db
            .query_row("SELECT EXISTS(SELECT 1 FROM predb)", [], |r| {
                r.get::<_, bool>(0)
            })
            .unwrap_or(false);
        if feed_ever {
            // Part of the open-time ladder, so no `ddl` stamp: nothing
            // pooled can predate a connection's own open.
            let _ = Self::ensure_named_index(&db);
        }
        // C3 prototype. The env flag INSTALLS the schema; the schema is
        // what makes it on from then on, so a daemon that started with
        // the flag keeps its summaries maintained across the scan
        // loop's re-opens even where the variable is not inherited.
        // Turning the flag to 0 explicitly uninstalls, so the triggers
        // stop costing writes the moment the experiment ends.
        let want = std::env::var("NZBFAST_TITLE_SUMMARIES").ok();
        let summaries = match want.as_deref() {
            Some("0") => {
                let _ = summaries::drop_schema(&db);
                false
            }
            Some("1") => summaries::ensure_schema(&db).is_ok(),
            _ => table_exists(&db, "title_summaries"),
        };
        // The predb EXISTS pair, `ensure_named_index` and the summaries
        // question, together: all four are cheap on a feed-less install
        // and all four read a table whose size nothing else here bounds.
        trace.lap("predb probe");
        let index = Index {
            db,
            gate: None,
            fts,
            pre_fts,
            people_fts,
            custom: Vec::new(),
            predb,
            watch: None,
            hits: Default::default(),
            retry: Default::default(),
            ddl: std::cell::Cell::new(false),
            summaries,
            stats_cache: Default::default(),
            wall_window: Self::wall_window_armed(),
            cards_total_memo: Default::default(),
            deadline: Default::default(),
        };
        // Existing prototype catalogs may carry sampled Message-ID claims
        // from before whole-manifest verification. Upgrade and withdraw those
        // claims before this writer can serve them, even when background seed
        // maintenance is paused. Do not install the optional catalog on an
        // index that never used it.
        if index.nzb_seed_schema_present()? {
            index.ensure_nzb_seed_schema()?;
            // Seeds stored before the strong per-file manifest key existed
            // carry a legacy MD5 membership key the verifier can never match,
            // so they replay to `unsafe` forever and can never name a row.
            // Re-key them in place from evidence already on disk; the marker
            // makes this a one-shot repair, and it is bounded per open so a
            // large catalogue cannot stall the writer here. A failure is
            // propagated for the same reason the schema upgrade above is: a
            // seed catalogue this writer cannot repair is one it must not
            // then serve. Each chunk is its own savepoint, so a refusal
            // leaves the marker unset and the earlier chunks committed.
            for _ in 0..seed::SEED_REKEY_CHUNKS_PER_OPEN {
                if index.nzb_seed_legacy_rekey_slice()?.done {
                    break;
                }
            }
            // What the re-key deliberately leaves behind: a legacy set with
            // no strong file keys on disk at all cannot express its identity,
            // so it replays to `unsafe` forever and costs a replay slot every
            // lap. Delete it, so a later grab of the same NZB re-seeds it
            // cleanly under a strong key. Same one-shot, bounded, own-marker
            // shape as the re-key above, and it propagates a failure for the
            // same reason; every ledger decrement is clamped so a drifted
            // ledger cannot turn this into a refused open.
            for _ in 0..seed::SEED_PURGE_CHUNKS_PER_OPEN {
                if index.nzb_seed_unrepairable_purge_slice()?.done {
                    break;
                }
            }
            // Open-time DDL cannot stale a reader from this generation.
            index.ddl.set(false);
        }
        trace.lap("seed catalogue");
        trace.finish(path, cache_mib);
        Ok(index)
    }

    /// TODO 300: whether the wall page's window fast path is armed.
    ///
    /// On unless `NZBFAST_WALL_WINDOW=0`, which is the kill switch AND the
    /// lever the before/after measurement rides: the fast path's whole
    /// contract is "same page, less work", so the only honest way to price
    /// it on a live-size index is to ask the same binary the same request
    /// both ways. See `cards::Index::wall_page_keys` and
    /// `research/WALL-SHOWALL-QUERY-COST-2026-08-26.md`.
    fn wall_window_armed() -> bool {
        std::env::var("NZBFAST_WALL_WINDOW").as_deref() != Ok("0")
    }

    /// A read-only connection for query handlers, so an interactive
    /// wall/search/browse request never queues behind whoever is holding
    /// a read-write connection through a long ingest or maintenance
    /// pass. The database is WAL, so this connection's reads run
    /// concurrently with the writer and each query begins a fresh read
    /// transaction - it always sees the latest committed data without
    /// being reopened.
    ///
    /// Skips every migration `open` runs (a read-only handle cannot run
    /// them, and must not need to): callers open this only after a
    /// read-write `open` has brought the schema up to date. Fails if the
    /// database file does not exist yet - it must never be the call that
    /// creates the file.
    pub fn open_read_only(path: &Path) -> rusqlite::Result<Index> {
        let db = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        // Readers in WAL only ever wait on the brief WAL-reset window of
        // a checkpoint, but "brief" still deserves a timeout rather than
        // an instant "database is locked".
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        segcodec::register(&db)?;
        // The per-connection tuning half of open()'s pragmas; query_only
        // makes any write that sneaks onto this connection fail loudly
        // instead of contending for the write lock.
        //
        // cache_size is a quarter of the writer's 256 MB: the daemon
        // pools up to four of these connections and never evicts an
        // idle one, so the writer's figure here would let query bursts
        // pin ~1 GB of page cache forever - the difference between
        // fitting and swapping on a NAS. Reads mostly ride the 1 GB
        // mmap window anyway, which costs only address space.
        db.execute_batch(
            "PRAGMA query_only=ON;
             PRAGMA temp_store=MEMORY;
             PRAGMA cache_size=-65536;
             PRAGMA mmap_size=1073741824;",
        )?;
        // FTS availability is detected, not created: the tables exist iff
        // the read-write open that ran the schema managed to create them.
        let has = |name: &str| {
            db.query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |_| Ok(()),
            )
            .is_ok()
        };
        let fts = has("rel_fts");
        let people_fts = fts && has("people_fts");
        // Same detection for the pre-feed name index. Load-bearing: this
        // is the connection every interactive search and browse runs on,
        // so if it read `false` here a release the pre feed rescued would
        // be findable by its obfuscated stem and by nothing else.
        let pre_fts = has("pre_fts");
        // C3 prototype, detected exactly like FTS: the read-only handle
        // never installs anything, it only reads what the read-write
        // open put there.
        let summaries = has("title_summaries") && has("title_dirty");
        // `predb` gates the ingest-time naming lookup only, and ingest
        // never happens on a query_only connection.
        let predb = false;
        // No gate and no custom categories: both are ingest-time policy,
        // and ingest cannot happen on a query_only connection. Same for
        // the arrival watch - nothing arrives on a reader.
        let ix = Index {
            db,
            gate: None,
            fts,
            pre_fts,
            people_fts,
            custom: Vec::new(),
            predb,
            watch: None,
            hits: Default::default(),
            retry: Default::default(),
            ddl: std::cell::Cell::new(false),
            summaries,
            stats_cache: Default::default(),
            wall_window: Self::wall_window_armed(),
            cards_total_memo: Default::default(),
            deadline: Default::default(),
        };
        // Disarmed; the daemon arms it per borrow, because how long an
        // HTTP worker may hold a pooled reader is its call and not
        // SQLite's. Read-only connections ONLY - the reasoning is at
        // `install_query_deadline`.
        ix.install_query_deadline()?;
        Ok(ix)
    }
}

/// Does this database hold a table by that name? The read-write open's
/// twin of `open_read_only`'s local `has`.
fn table_exists(db: &Connection, name: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |_| Ok(()),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{entry, teardown};

    /// TODO 5 phase 2c: `releases.stem_fold` on rows that predate the
    /// column. The chunked `fold_v1` backfill has to reach them, and it
    /// has to be sparse when it gets there - an ASCII stem earns
    /// nothing, because `LOWER()` already folds it correctly and a
    /// second copy of every stem on a 16.5 M-row index is not a rounding
    /// error.
    ///
    /// The `GLOB '*[^ -~]*'` prefilter in that pass is the part worth
    /// pinning: it is a cost filter, not a correctness term, so a
    /// non-ASCII row it lets through must still be re-judged by
    /// `fold::stored` (the accented-lowercase row below is the case that
    /// passes the GLOB and stores nothing anyway).
    #[test]
    fn the_fold_backfill_reaches_rows_written_before_the_column() {
        let dir = std::env::temp_dir().join(format!("nzbfast-foldbf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let stems = [
            "ВОЙНА.И.МИР.S01E01.1080p-GRP",
            "ΟΔΥΣΣΕΙΑ.2019.1080p-GRP",
            "Ordinary.Ascii.Release.2019-GRP",
            "Café.Society.2016.1080p-GRP",
        ];
        {
            let ix = Index::open(&db).unwrap();
            for stem in stems {
                ix.db
                    .execute(
                        "INSERT INTO releases(stem, poster, grp, first_seen, first_posted)
                         VALUES(?1, 'p@x', 'alt.binaries.test', 100, 100)",
                        [stem],
                    )
                    .unwrap();
            }
            // Exactly the state a database upgraded into this column is
            // in: the rows are there, the column is empty, and nothing
            // has stamped the migration.
            ix.db
                .execute("DELETE FROM kv WHERE k IN ('fold_v1','fold_at')", [])
                .unwrap();
            ix.db
                .execute("UPDATE releases SET stem_fold=''", [])
                .unwrap();
        }

        let ix = Index::open(&db).unwrap();
        let fold = |stem: &str| -> String {
            ix.db
                .query_row(
                    "SELECT stem_fold FROM releases WHERE stem=?1",
                    [stem],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(fold(stems[0]), "война и мир s01e01 1080p grp");
        assert_eq!(fold(stems[1]), "οδυσσεια 2019 1080p grp");
        assert_eq!(fold(stems[2]), "", "an ASCII stem earned a stored fold");
        assert_eq!(
            fold(stems[3]),
            "",
            "a stem LOWER() already folds correctly earned one"
        );
        // Stamped done, so the next open does no work at all.
        assert_eq!(
            ix.db
                .query_row("SELECT v FROM kv WHERE k='fold_v1'", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "1"
        );
        teardown(&dir, ix);
    }

    /// The corrective generation. `split_merge_group` rewrote `stem`
    /// without `stem_fold` until 886785fd7, so a database that merged a
    /// split release before then carries the fold of a stem that no
    /// longer exists - matched by [`query::stem_fold_arm`] and by the
    /// browse hide rule, neither of which reads `stem`.
    ///
    /// The second row is the one a rearm of `fold_v1` could never have
    /// repaired: that generation looks only at non-ASCII stems, and the
    /// merge that stranded the fold left an ASCII one behind.
    #[test]
    fn the_fold_reconcile_pass_clears_a_stale_stored_fold() {
        let dir = std::env::temp_dir().join(format!("nzbfast-foldrec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        // (stem, the fold on disk before the pass). The first is a
        // merged Cyrillic group: its fold still ends in the ` 001` the
        // merge took off the stem. The second is the case the GLOB
        // prefilter alone cannot see - the merge left an ASCII stem, so
        // nothing about the row says "look at me" except the fold
        // itself. The third and fourth are already correct and must not
        // be touched.
        let rows = [
            ("ВОЙНА.И.МИР.S01E01-GRP", "война и мир s01e01 grp 001"),
            ("Merged.Ascii.Release-GRP", "мир 001"),
            ("ΟΔΥΣΣΕΙΑ.2019-GRP", "οδυσσεια 2019 grp"),
            ("Ordinary.Ascii.Release.2019-GRP", ""),
        ];
        {
            let ix = Index::open(&db).unwrap();
            for (stem, held) in rows {
                ix.db
                    .execute(
                        "INSERT INTO releases(stem, stem_fold, poster, grp,
                                              first_seen, first_posted)
                         VALUES(?1, ?2, 'p@x', 'alt.binaries.test', 100, 100)",
                        [stem, held],
                    )
                    .unwrap();
            }
            // The state a live index is in: the first generation ran
            // long ago and is stamped, and this one has never run.
            ix.db
                .execute(
                    "INSERT INTO kv(k,v) VALUES('fold_v1','1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )
                .unwrap();
            ix.db
                .execute("DELETE FROM kv WHERE k IN ('fold_v2','fold_v2_at')", [])
                .unwrap();
        }

        let ix = Index::open(&db).unwrap();
        let fold = |stem: &str| -> String {
            ix.db
                .query_row(
                    "SELECT stem_fold FROM releases WHERE stem=?1",
                    [stem],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(fold(rows[0].0), "война и мир s01e01 grp");
        assert_eq!(
            fold(rows[1].0),
            "",
            "an ASCII stem kept a fold from the stem it replaced"
        );
        assert_eq!(fold(rows[2].0), "οδυσσεια 2019 grp");
        assert_eq!(
            fold(rows[3].0),
            "",
            "an ASCII row with nothing stored earned a fold"
        );
        // Stamped, and the first generation's flag is untouched.
        let kv = |k: &str| -> String {
            ix.db
                .query_row("SELECT v FROM kv WHERE k=?1", [k], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(kv("fold_v2"), "1");
        assert_eq!(kv("fold_v1"), "1");
        teardown(&dir, ix);
    }

    /// The read-only connection behind the daemon's interactive query
    /// endpoints: it reads what the writer commits WITHOUT being
    /// reopened (WAL - each query is a fresh read transaction), and any
    /// write that sneaks onto it fails instead of contending for the
    /// write lock.
    #[test]
    fn read_only_connection_sees_fresh_commits_and_refuses_writes() {
        let dir = crate::testscratch::ScratchDir::attach(
            &std::env::temp_dir().join(format!("nzbfast-index-ro-{}", std::process::id())),
        );
        let db = dir.join("index.db");
        let mut rw = Index::open(&db).unwrap();
        rw.ingest(
            "alt.binaries.test",
            &[entry(
                r#""First.Release.S01E01.720p-GRP.rar" yEnc (1/1)"#,
                "p@x",
                "ro1",
                900,
            )],
            1000,
        )
        .unwrap();

        let ro = Index::open_read_only(&db).unwrap();
        assert_eq!(ro.search("first", 10).unwrap().len(), 1);

        // A commit AFTER the read-only open, visible without a reopen.
        rw.ingest(
            "alt.binaries.test",
            &[entry(
                r#""Second.Release.S01E02.720p-GRP.rar" yEnc (1/1)"#,
                "p@x",
                "ro2",
                900,
            )],
            1000,
        )
        .unwrap();
        assert_eq!(ro.search("second", 10).unwrap().len(), 1);

        // query_only: the connection refuses writes rather than taking
        // the write lock.
        assert!(ro.kv_set("k", "v").is_err());
        // And it must never be the open that CREATES a database.
        assert!(Index::open_read_only(&dir.join("absent.db")).is_err());
    }

    /// A scan's scratch connection carries the scratch page cache and
    /// the shared writer carries the writer's - and the scratch figure
    /// must be in place for the OPEN, not applied after it, or a pass
    /// still touches the writer's ceiling on the way in (measured: the
    /// per-connection high-water was ~314 MiB when the pragma landed
    /// last, ~86 MiB when it leads).
    #[test]
    fn a_scratch_open_carries_the_smaller_page_cache() {
        let dir = std::env::temp_dir().join(format!("nzbfast-cachesz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        // Negative cache_size is KiB of memory rather than a page count,
        // which is the whole point of the sign - a page-count cache is
        // sized in pages whose bytes depend on page_size.
        let of = |ix: &Index| -> i64 {
            ix.db
                .query_row("PRAGMA cache_size", [], |r| r.get(0))
                .unwrap()
        };
        let writer = Index::open(&db).unwrap();
        assert_eq!(of(&writer), -(WRITER_CACHE_MIB * 1024));
        let scratch = Index::open_scratch(&db).unwrap();
        assert_eq!(of(&scratch), -(SCRATCH_CACHE_MIB * 1024));
        assert!(SCRATCH_CACHE_MIB < WRITER_CACHE_MIB);
        // The scratch connection is a full read-write Index, migrations
        // and all - it is a scan's own handle, not a reader.
        assert!(scratch.kv_set("k", "v").is_ok());
        drop(scratch);
        teardown(&dir, writer);
    }

    /// `Index::open` must leave the schema cookie ALONE on a database it
    /// has already migrated.
    ///
    /// The daemon opens a fresh read-write connection between passes
    /// while pooled read-only connections are answering the wall, search
    /// and the newznab facade. A bumped cookie invalidates every one of
    /// those readers' prepared statements; re-preparing reconnects the
    /// fts5 virtual tables, and a constructor that loses that race fails
    /// the statement outright with SQLITE_SCHEMA ("vtable constructor
    /// failed: rel_fts"). Every query endpoint turns that into an EMPTY
    /// answer, so a Sonarr search silently finds nothing - which is what
    /// `newznab_honours_the_arr_search_parameters` was intermittently
    /// catching (9 hits in 160 runs) before `rel_identity_ad` stopped
    /// being created here and dropped again one migration later.
    ///
    /// So this asserts the PROPERTY, not the one statement: any future
    /// DDL that re-creates something on every open reddens it.
    #[test]
    fn repeat_opens_do_not_churn_the_schema() {
        let dir = std::env::temp_dir().join(format!("nzbfast-schema-churn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let cookie = |ix: &Index| -> i64 {
            ix.db
                .query_row("PRAGMA schema_version", [], |r| r.get(0))
                .unwrap()
        };

        let mut first = Index::open(&db).unwrap();
        // With content, so the fts triggers and every content-gated
        // migration have run: an empty database can be stable for the
        // uninteresting reason that half of open() short-circuits.
        first
            .ingest(
                "alt.binaries.test",
                &[entry(
                    r#""Churn.Probe.S01E01.720p-GRP.rar" yEnc (1/1)"#,
                    "p@x",
                    "churn1",
                    900,
                )],
                1000,
            )
            .unwrap();
        let baseline = cookie(&first);

        for round in 0..3 {
            let again = Index::open(&db).unwrap();
            assert_eq!(
                cookie(&again),
                baseline,
                "open #{} rewrote sqlite_master on an already-migrated database -                  some DDL in open() is not idempotent, and every pooled reader's                  statements have just been invalidated",
                round + 2
            );
        }

        // The retirement itself still has to work: a database carrying
        // the v1 trigger loses it and gains v2, and is stable from the
        // NEXT open on rather than churning forever.
        let named = |ix: &Index, name: &str| -> i64 {
            ix.db
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [name],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(named(&first, "rel_identity_ad_v3"), 1);
        assert_eq!(named(&first, "rel_identity_ad_v2"), 0);
        assert_eq!(named(&first, "rel_identity_ad"), 0);
        // Both retirements, from the two shapes a real install can be
        // carrying: the v1 name, and the v2 whose spots UPDATE
        // full-scanned because it did not repeat `release_id>0`.
        first
            .db
            .execute_batch(
                "CREATE TRIGGER rel_identity_ad AFTER DELETE ON releases BEGIN
                   DELETE FROM name_claims WHERE release_id=old.id;
                 END;
                 DROP TRIGGER rel_identity_ad_v3;
                 CREATE TRIGGER rel_identity_ad_v2 AFTER DELETE ON releases BEGIN
                   UPDATE spots SET release_id=-1 WHERE release_id=old.id;
                 END;",
            )
            .unwrap();
        let migrated = Index::open(&db).unwrap();
        assert_eq!(named(&migrated, "rel_identity_ad"), 0, "v1 was not retired");
        assert_eq!(
            named(&migrated, "rel_identity_ad_v2"),
            0,
            "v2 was not retired"
        );
        assert_eq!(named(&migrated, "rel_identity_ad_v3"), 1);
        let after_retire = cookie(&migrated);
        let settled = Index::open(&db).unwrap();
        assert_eq!(
            cookie(&settled),
            after_retire,
            "the v1 retirement is not a one-time migration - it churns"
        );

        drop(migrated);
        drop(settled);
        teardown(&dir, first);
    }

    /// The `release_id>0` term in `rel_identity_ad_v3` is what lets the
    /// trigger reach `idx_spots_rel`, and `plan_tests.rs` asserts that.
    /// This asserts the other half: adding it did not change what the
    /// trigger DOES, which is the risk with any predicate bolted on for
    /// the planner's benefit.
    ///
    /// The recycled-rowid hazard is the whole reason the trigger exists.
    /// `releases.id` has no AUTOINCREMENT, so the id of a reaped release
    /// is handed straight to the next insert - and a spot still pointing
    /// at it would rebind to a stranger, giving a brand-new post another
    /// release's card link and repair history.
    #[test]
    fn deleting_a_release_unbinds_its_spot_and_leaves_the_others_alone() {
        let dir = std::env::temp_dir().join(format!("nzbfast-spot-unbind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        ix.db
            .execute(
                "INSERT INTO releases(id, stem, poster, grp, first_posted)
                 VALUES(7,'Doomed.Release','p','g',1), (9,'Kept.Release','p','g',1)",
                [],
            )
            .unwrap();
        ix.db
            .execute(
                "INSERT INTO spots(msgid, title, release_id) VALUES
                   ('bound@x','bound',7),
                   ('other@x','other',9),
                   ('unresolved@x','unresolved',0),
                   ('gone@x','gone',-1)",
                [],
            )
            .unwrap();
        ix.db
            .execute("DELETE FROM releases WHERE id=7", [])
            .unwrap();
        let rel = |msgid: &str| -> i64 {
            ix.db
                .query_row(
                    "SELECT release_id FROM spots WHERE msgid=?1",
                    [msgid],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(
            rel("bound@x"),
            -1,
            "the spot kept pointing at a freed rowid"
        );
        assert_eq!(rel("other@x"), 9, "an unrelated binding was collateral");
        assert_eq!(
            rel("unresolved@x"),
            0,
            "an unresolved spot must stay offerable"
        );
        assert_eq!(rel("gone@x"), -1);
        teardown(&dir, ix);
    }

    fn wal_len(db: &Path) -> u64 {
        let mut s = db.as_os_str().to_os_string();
        s.push("-wal");
        std::fs::metadata(std::path::PathBuf::from(s))
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// The writer must declare a bound on how much WAL it keeps.
    ///
    /// SQLite's default is no limit at all, and the consequence is not
    /// that checkpointing stops - it is that the WAL file never SHRINKS.
    /// It is reused from the front after every checkpoint and stays at
    /// its all-time high-water mark forever, so one whole-database
    /// rewrite pins its own size in dead space permanently. The live
    /// index was found on 14 Aug 2026 carrying 28.1 GiB of exactly that
    /// while holding one live frame.
    ///
    /// Delete the pragma and this reads back -1.
    #[test]
    fn the_writer_bounds_how_much_wal_it_keeps() {
        let dir = std::env::temp_dir().join(format!("nzbfast-wal-lim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let ix = Index::open(&db).unwrap();

        let limit: i64 = ix
            .db
            .query_row("PRAGMA journal_size_limit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            limit, WAL_SIZE_LIMIT,
            "the writer is not carrying the WAL size limit; -1 means SQLite's \
             unbounded default and a WAL that keeps its high-water mark forever"
        );
        // The bound has to be a bound. Sanity in both directions: below
        // the 15.9 MiB peak measured on the live daemon it would truncate
        // during ordinary indexing, which is churn in a file big enough
        // to make snapshots expensive; unbounded is the bug itself.
        assert!(
            (32 * 1024 * 1024..=256 * 1024 * 1024).contains(&limit),
            "WAL_SIZE_LIMIT {limit} is outside the range the live measurement supports"
        );
        teardown(&dir, ix);
    }

    /// ...and it must declare how OFTEN it stops to checkpoint, which
    /// is a different question from how much WAL it keeps and by far
    /// the more expensive one to get wrong.
    ///
    /// SQLite's default is 1,000 pages, and at that setting the
    /// automatic checkpoint inside `tx.commit()` measured between 9.4%
    /// and 54.3% of the whole of `Index::ingest` - the spread is disk
    /// contention, and the top of it is an ordinarily busy machine (3
    /// Sep 2026 - see [`WAL_AUTOCHECKPOINT_PAGES`]). Delete the pragma
    /// and this reads back 1000 and the scan loop pays that again.
    ///
    /// The upper bound is the interesting half. A checkpoint runs with
    /// the daemon's index mutex held, so this constant is also the
    /// ceiling on one uninterruptible hold; and it has to stay well
    /// under [`WAL_SIZE_LIMIT`], because a routine commit that reaches
    /// the size limit pays a truncate, which is the churn that limit
    /// exists to prevent.
    #[test]
    fn the_writer_declares_how_often_it_checkpoints() {
        let dir = std::env::temp_dir().join(format!("nzbfast-wal-auto-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let ix = Index::open(&db).unwrap();

        let pages: i64 = ix
            .db
            .query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            pages, WAL_AUTOCHECKPOINT_PAGES,
            "the writer is not carrying the autocheckpoint threshold; 1000 is \
             SQLite's default, which this was measured 24.2% slower than"
        );
        // A WAL this threshold allows must still fit inside the size
        // limit with room to spare, or the cheap checkpoint the raise
        // buys is paid back as a truncate on the very same commit.
        let page_size: i64 = ix
            .db
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .unwrap();
        assert!(
            pages * page_size * 2 <= WAL_SIZE_LIMIT,
            "an autocheckpoint at {pages} pages of {page_size} bytes can reach \
             {} of the {WAL_SIZE_LIMIT}-byte WAL limit",
            pages * page_size
        );
        teardown(&dir, ix);
    }

    /// `compact` is a single VACUUM over the whole database, so it
    /// leaves behind a WAL as large as the database - this is what put
    /// 28.1 GiB beside the live index. It must hand that back before it
    /// returns, while it still holds the idle moment the compaction loop
    /// waited for, rather than leaving it for whatever checkpoint
    /// happens next.
    #[test]
    fn compact_hands_back_the_wal_its_vacuum_inflated() {
        let dir = std::env::temp_dir().join(format!("nzbfast-wal-compact-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let mut ix = Index::open(&db).unwrap();

        // Enough bulk that the VACUUM has something real to push
        // through the WAL - the assertion below is about megabytes
        // coming back, not about an empty file staying empty.
        for r in 0..4_000u32 {
            ix.ingest(
                "alt.binaries.test",
                &[entry(
                    &format!(r#""Ballast.Release.{r:06}.1080p.WEB-DL.x264-GRP.rar" yEnc (1/1)"#),
                    "p@x",
                    &format!("wal{r:06}"),
                    900_000,
                )],
                1_000,
            )
            .unwrap();
        }
        assert!(
            wal_len(&db) > 0,
            "nothing in the WAL to reclaim - the fixture wrote too little to test anything"
        );

        ix.compact().unwrap();

        assert_eq!(
            wal_len(&db),
            0,
            "compact left its VACUUM's write-ahead log on disk; on the live \
             index that log was 28.1 GiB and it stayed there"
        );
        teardown(&dir, ix);
    }

    /// End to end: a WAL driven far past the limit comes back down.
    ///
    /// The sequence is load-bearing and is why the pragma alone is worth
    /// a behavioural test. SQLite does not truncate at the checkpoint -
    /// a restart only sets `truncateOnCommit`, and the file is cut on
    /// the first COMMIT after it. So a bound that is never followed by a
    /// write is a bound that has not been applied yet.
    #[test]
    fn a_runaway_wal_comes_back_down_to_the_limit() {
        let dir = std::env::temp_dir().join(format!("nzbfast-wal-runaway-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let ix = Index::open(&db).unwrap();

        // One transaction bigger than the limit, which is exactly the
        // shape of the one-pass compact that did this for real.
        ix.db
            .execute_batch("CREATE TABLE _wal_ballast(b BLOB)")
            .unwrap();
        let blob = vec![7u8; 256 * 1024];
        let over = WAL_SIZE_LIMIT as usize + 24 * 1024 * 1024;
        {
            let tx = ix.db.unchecked_transaction().unwrap();
            {
                let mut st = tx
                    .prepare("INSERT INTO _wal_ballast(b) VALUES(?1)")
                    .unwrap();
                for _ in 0..over.div_ceil(blob.len()) {
                    st.execute(rusqlite::params![blob.as_slice()]).unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let peak = wal_len(&db);
        assert!(
            peak > WAL_SIZE_LIMIT as u64,
            "fixture never drove the WAL past the limit (peak {peak}) - the \
             assertion below would pass without proving anything"
        );

        // Backfill everything and restart the log, then commit once.
        // Both halves are required; see the doc comment.
        let _ = ix
            .db
            .query_row("PRAGMA wal_checkpoint(RESTART)", [], |_| Ok(()));
        ix.kv_set("wal_probe", "1").unwrap();

        let after = wal_len(&db);
        assert!(
            after <= WAL_SIZE_LIMIT as u64 + 1024 * 1024,
            "WAL stayed at {after} bytes after a checkpoint and a commit; it \
             peaked at {peak} and the limit is {WAL_SIZE_LIMIT}. An unbounded \
             WAL keeps its high-water mark for the life of the database."
        );
        teardown(&dir, ix);
    }

    /// The live reclaim path: a database whose WAL is ALREADY over the
    /// limit before this build ever opened it.
    ///
    /// This is the shape the fix has to handle for real - 28.1 GiB was
    /// on disk long before the pragma existed, and it comes back when
    /// the daemon restarts onto a binary that carries the limit. A
    /// second connection stays open throughout so that dropping the
    /// first does not delete the WAL: SQLite removes it only when the
    /// LAST connection closes, and a daemon restart on a live index is
    /// not that.
    #[test]
    fn a_reopen_reclaims_a_wal_that_was_already_oversized() {
        let dir = std::env::temp_dir().join(format!("nzbfast-wal-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");

        let keepalive = {
            let first = Index::open(&db).unwrap();
            first
                .db
                .execute_batch("CREATE TABLE _wal_ballast(b BLOB)")
                .unwrap();
            // Held across the drop below, so the WAL outlives `first`.
            let keepalive = Index::open_read_only(&db).unwrap();
            let blob = vec![7u8; 256 * 1024];
            let over = WAL_SIZE_LIMIT as usize + 24 * 1024 * 1024;
            let tx = first.db.unchecked_transaction().unwrap();
            {
                let mut st = tx
                    .prepare("INSERT INTO _wal_ballast(b) VALUES(?1)")
                    .unwrap();
                for _ in 0..over.div_ceil(blob.len()) {
                    st.execute(rusqlite::params![blob.as_slice()]).unwrap();
                }
            }
            tx.commit().unwrap();
            drop(first);
            keepalive
        };
        let inherited = wal_len(&db);
        assert!(
            inherited > WAL_SIZE_LIMIT as u64,
            "fixture did not leave an oversized WAL behind ({inherited} bytes)"
        );

        // What the daemon does on restart: open, and get on with it.
        let ix = Index::open(&db).unwrap();
        let _ = ix
            .db
            .query_row("PRAGMA wal_checkpoint(RESTART)", [], |_| Ok(()));
        ix.kv_set("wal_probe", "1").unwrap();

        let after = wal_len(&db);
        assert!(
            after <= WAL_SIZE_LIMIT as u64 + 1024 * 1024,
            "reopening an index with a {inherited}-byte WAL left {after} bytes \
             behind - the 28.1 GiB on the live index would never come back"
        );
        drop(keepalive);
        teardown(&dir, ix);
    }

    /// The quality_v10 bump: prove the pass HEALS a stored row rather
    /// than only classifying a new one.
    ///
    /// Five of the six classifier fixes that landed on 2 Sep 2026 ride a
    /// version bump for free, because they live in `parse_release` and
    /// `recover_media_kind`, which the pass already ran at v9. The group
    /// prior and the dashed-episode read cannot: both take the NEWSGROUP,
    /// and v9's SELECT did not carry it, so a bump without `grp` would
    /// have left every audiobook and magazine row filed as an
    /// evidence-free movie at junk 60 - hidden by the wall's default
    /// hide-at-50 - for good.
    ///
    /// Each row is stamped with the answer the v9 chain actually
    /// produces (asserted, not assumed), so the "before" state is the
    /// real one and not a hand-written guess at it.
    ///
    /// The third row is the control that licenses the second: `Author -
    /// 04 - Chapter` is the dashed-episode shape to the letter, and it
    /// must stay a BOOK, because the group is what vouches for the
    /// reading and a book group vouches for the opposite.
    #[test]
    fn the_quality_bump_heals_stored_rows_through_the_group() {
        let dir = std::env::temp_dir().join(format!("nzbfast-qualv10-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        // (stem, group, kind after the bump, title_key after the bump)
        let cases: [(&str, &str, &str, &str); 4] = [
            (
                "Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)",
                "alt.binaries.mp3.audiobooks",
                "book",
                "bk:perry rhodan 3390 die stunde der deponentin ungekuerzt",
            ),
            (
                "Bleach - 187 - Ichigo Rages! The Assassin's Secret.mkv",
                "alt.binaries.multimedia.anime.highspeed",
                "tv",
                "t:bleach",
            ),
            (
                "Stephen King - 04 - The Gunslinger",
                "alt.binaries.e-book",
                "book",
                "bk:stephen king 04 the gunslinger",
            ),
            (
                "Dune.Part.Two.2024.2160p.BluRay.x264-GRP.mkv",
                "alt.binaries.boneless",
                "movie",
                "m:dune part two:2024",
            ),
        ];
        {
            let ix = Index::open(&db).unwrap();
            for (stem, grp, _, _) in cases {
                // The v9 chain, verbatim: parse the effective name, then
                // recover the media kind from the stem. No group.
                let mut old = crate::release::parse_release(stem);
                crate::release::recover_media_kind(&mut old, stem, stem);
                ix.db
                    .execute(
                        "INSERT INTO releases(stem, poster, grp, total_bytes,
                                              first_seen, first_posted,
                                              kind, title_key, junk)
                         VALUES(?1, 'p@x', ?2, 2000000000, 100, 100, ?3, ?4, ?5)",
                        rusqlite::params![
                            stem,
                            grp,
                            kind_str(&old.kind),
                            old.key,
                            junk_score(stem, &old, 2_000_000_000, false),
                        ],
                    )
                    .unwrap();
            }
            // The three rows this bump exists for were all evidence-free
            // movies at 60 under v9, which is what the wall hid.
            let hidden: i64 = ix
                .db
                .query_row(
                    "SELECT COUNT(*) FROM releases WHERE kind='movie' AND junk>=50",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(hidden, 3, "the v9 answer for these three is a hidden movie");
            ix.db
                .execute("DELETE FROM kv WHERE k LIKE 'quality_v%'", [])
                .unwrap();
        }
        let ix = Index::open(&db).unwrap();
        assert_eq!(ix.kv_get("quality_v10").as_deref(), Some("1"));
        for (stem, grp, kind, key) in cases {
            let (got_kind, got_key, got_junk): (String, String, i64) = ix
                .db
                .query_row(
                    "SELECT kind, title_key, junk FROM releases WHERE stem=?1",
                    [stem],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(
                (got_kind.as_str(), got_key.as_str()),
                (kind, key),
                "{stem} in {grp} should have been re-filed by the bump"
            );
            assert!(
                got_junk < 50,
                "{stem} should be visible after the bump, junk was {got_junk}"
            );
        }
        teardown(&dir, ix);
    }

    /// The budget half of the same pass: a slice that runs out of time
    /// must PARK, not finish, and the next one must pick up where it
    /// stopped rather than starting over.
    ///
    /// Pinned with a ZERO budget, the way `msgid_map_backfill_slice`'s
    /// own test does it, because that is the only budget a loaded box
    /// cannot accidentally satisfy. Zero still buys one chunk - the
    /// deadline is checked BETWEEN chunks, since the cursor and the rows
    /// it covers are one transaction - so with the chunk at 10k rows and
    /// a handful of rows here, the first call does all the work and
    /// parks, and the second finds nothing left and stamps the pass
    /// done. That is exactly the sequence a big index runs thousands of
    /// times, and the "returns false while rows remain" contract is what
    /// the indexer lap's slice loop reads to decide whether to call
    /// again.
    #[test]
    fn a_spent_quality_slice_parks_and_the_next_one_resumes() {
        let dir = std::env::temp_dir().join(format!("nzbfast-qualslice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        for i in 0..3 {
            ix.db
                .execute(
                    "INSERT INTO releases(stem, poster, grp, first_seen, first_posted)
                     VALUES(?1, 'p@x', 'alt.binaries.mp3.audiobooks', 100, 100)",
                    [format!("Perry Rhodan 33{i:02} - Die Stunde der Deponentin")],
                )
                .unwrap();
        }
        ix.db
            .execute("DELETE FROM kv WHERE k LIKE 'quality_v%'", [])
            .unwrap();
        assert_eq!(ix.quality_backfill_cursor(), Some(0), "nothing walked yet");

        assert!(
            !ix.quality_backfill_slice(std::time::Duration::ZERO),
            "a spent slice reports the pass INCOMPLETE, or the lap stops calling it"
        );
        let parked = ix.quality_backfill_cursor();
        assert_eq!(parked, Some(3), "one chunk done, cursor persisted");
        // ...and the work of that chunk landed, not just the cursor.
        let books: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM releases WHERE kind='book'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(books, 3, "a parked slice still commits what it did");

        assert!(
            ix.quality_backfill_slice(std::time::Duration::ZERO),
            "the resuming slice finds no rows past the cursor and stamps the pass"
        );
        assert_eq!(ix.quality_backfill_cursor(), None, "complete");
        // And a completed pass is free to ask about, every lap, forever.
        assert!(ix.quality_backfill_slice(std::time::Duration::ZERO));
        teardown(&dir, ix);
    }
}

#[cfg(test)]
mod qual_bench {
    use super::*;

    /// The rig behind the number quoted in [`quality_backfill`]: time
    /// one WHOLE quality pass over N synthetic rows, each with two
    /// `files` rows so the SELECT's EXISTS probe does real work.
    ///
    /// `#[ignore]`d and it asserts NOTHING. It exists so the next lane
    /// taking a version bump can re-derive the per-million-row rate on
    /// its own box instead of trusting a comment, and a rig that only
    /// prints cannot rot into a red on a loaded machine the way a
    /// timing ASSERTION would. Run it in release - a debug build
    /// measures the debug parser, which is a different program:
    ///
    ///     QUAL_N=400000 cargo test --release -p nzbkit --lib \
    ///       -- --ignored --nocapture qual_bench
    ///
    /// It calls the slice directly with an unreachable budget, because
    /// `Index::open` deliberately gives the pass only two seconds.
    #[test]
    #[ignore]
    fn time_the_quality_pass() {
        let n: i64 = std::env::var("QUAL_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200_000);
        let dir = std::env::temp_dir().join(format!("nzbfast-qualbench-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let shapes: [(&str, &str); 8] = [
            (
                "Dune.Part.Two.2024.2160p.UHD.BluRay.REMUX.DV.HDR.HEVC.TrueHD.Atmos-GRP",
                "alt.binaries.boneless",
            ),
            (
                "[SubsPlease] Frieren - 18 (1080p) [ABCD1234]",
                "alt.binaries.multimedia.anime.highspeed",
            ),
            (
                "Bleach - 187 - Ichigo Rages! The Assassin's Secret",
                "alt.binaries.multimedia.anime.highspeed",
            ),
            ("Max Brooks - World War Z (epub)", "alt.binaries.e-book"),
            (
                "Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)",
                "alt.binaries.mp3.audiobooks",
            ),
            ("04-kmfdm-anarchy-web-2026", "alt.binaries.sounds.mp3"),
            (
                "The New York Times - 15 August 2026",
                "alt.binaries.e-book.magazines",
            ),
            ("NGKzwg4lCQF_vMr95eoDx2X9NxbLi", "alt.binaries.boneless"),
        ];
        {
            let mut ix = Index::open(&db).unwrap();
            let tx = ix.db.transaction().unwrap();
            {
                let mut st = tx
                    .prepare(
                        "INSERT INTO releases(stem, poster, grp, total_bytes,
                                              first_seen, first_posted)
                         VALUES(?1, ?2, ?3, ?4, 100, 100)",
                    )
                    .unwrap();
                let mut fs = tx
                    .prepare(
                        "INSERT INTO files(release_id, filename, total_parts, bytes)
                         VALUES(?1, ?2, 10, 1000)",
                    )
                    .unwrap();
                for i in 0..n {
                    let (stem, grp) = shapes[(i % shapes.len() as i64) as usize];
                    st.execute(rusqlite::params![
                        format!("{stem} #{i}"),
                        format!("p{}@x", i % 977),
                        grp,
                        2_000_000_000i64,
                    ])
                    .unwrap();
                    let rid = tx.last_insert_rowid();
                    fs.execute(rusqlite::params![rid, format!("{stem}.part1.rar")])
                        .unwrap();
                    fs.execute(rusqlite::params![rid, format!("{stem}.par2")])
                        .unwrap();
                }
            }
            tx.commit().unwrap();
        }
        let mut ix = Index::open(&db).unwrap();
        // Un-stamp AFTER the open, not before it: `Index::open` spends
        // its own 2 s slice on the pass, and doing this the other way
        // round would leave that work out of the timed region and
        // understate the rate by however much it got through.
        ix.db
            .execute("DELETE FROM kv WHERE k LIKE 'quality_v%'", [])
            .unwrap();
        let t0 = std::time::Instant::now();
        let done = ix.quality_backfill_slice(std::time::Duration::from_secs(86_400));
        let dt = t0.elapsed();
        assert!(done, "the rig's budget must cover the whole pass");
        let per_m = dt.as_secs_f64() / (n as f64) * 1e6;
        println!(
            "QUALBENCH rows={n} wall={:.3}s -> {per_m:.1}s per million rows; \
             67M extrapolates to {:.0}s",
            dt.as_secs_f64(),
            per_m * 67.0
        );
        drop(ix);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
