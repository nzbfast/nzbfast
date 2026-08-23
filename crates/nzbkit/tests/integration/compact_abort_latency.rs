//! §95: how long does a download that starts mid-compact actually wait?
//!
//! `Index::interrupt_handle`'s doc explains WHY aborting a VACUUM is
//! weak (sqlite3_interrupt is read only from the VDBE, so it never
//! reaches the `sqlite3BtreeCopyFile` tail). This measures WHAT THAT
//! COSTS the user, which is the number the feature is judged on: a job
//! arrives at some offset into the rewrite, the daemon aborts, and the
//! job sits in `Downloading` until compaction lets go of the gate. That
//! gap - not the rewrite's duration - is the stall.
//!
//! It sweeps the arrival offset across three paths on ONE ballast:
//!   1. VACUUM + interrupt, the pre-§95 behaviour (fixture forced back
//!      to `auto_vacuum=NONE`, which is what every existing install is).
//!   2. the one-time migration rewrite, which is honestly not abortable.
//!   3. `compact_chunk` in a loop, the path every later compact takes.
//!
//! Ignored: it builds a multi-hundred-megabyte database and sweeps it,
//! so it is minutes of disk, not a per-push test. Run it deliberately:
//!
//! ```sh
//! cargo test -p nzbkit --release --test compact_abort_latency -- --ignored --nocapture
//! ```
//!
//! Knobs: `BALLAST_RELEASES` (default 6000), `BALLAST_PARTS` (default
//! 200) - raise them to model the multi-GB index the feature exists for.

use nzbkit::index::{CompactStyle, Index};
use nzbkit::nntp::OverEntry;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Mirrors `serve::daemon::COMPACT_CHUNK_PAGES`. Duplicated rather than
/// shared because nzbkit must not depend on the daemon crate; if that
/// constant moves, this is the measurement that justifies its value.
const CHUNK_PAGES: u32 = 2048;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-compact-latency-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// A database with the shape the real thing has: releases whose bulk is
/// the `files.segments` blob. Ingest ONLY - the prune that creates the
/// freelist happens per-fixture in `prune`, after the auto_vacuum mode
/// is settled, because forcing the mode costs a VACUUM and a VACUUM
/// would reclaim the very freelist being measured.
fn build_ballast(path: &Path, releases: usize, parts: usize) {
    let _ = std::fs::remove_file(path);
    let mut ix = Index::open(path).unwrap();
    let now = 1_900_000_000i64;
    let mut batch: Vec<OverEntry> = Vec::with_capacity(parts);
    for r in 0..releases {
        batch.clear();
        let stem = format!("Ballast.Release.{r:07}.1080p.WEB-DL.x264-GRP");
        // Half old (pruned), half recent (kept), so the freelist ends up
        // large without the file being near-empty.
        let age = if r % 2 == 0 { 400 * 86_400 } else { 0 };
        for p in 1..=parts {
            batch.push(OverEntry {
                number: (r * parts + p) as u64,
                subject: format!(r#"poster - "{stem}.part01.rar" yEnc ({p}/{parts})"#),
                from: format!("poster{}@example.invalid", r % 32),
                message_id: format!("<{r:07}.{p:05}.ballast@example.invalid>"),
                bytes: 768_000,
                date: now - age,
            });
        }
        ix.ingest("alt.binaries.ballast", &batch, now).unwrap();
    }
    println!(
        "ballast: {releases} releases x {parts} parts -> {:.0} MB",
        ix.db_bytes().unwrap() as f64 / 1e6,
    );
    drop(ix); // closes WAL, so the copies below are coherent
}

/// Delete half the corpus, leaving a large freelist. Run per fixture,
/// AFTER its auto_vacuum mode is settled.
fn prune(path: &Path, label: &str) {
    let ix = Index::open(path).unwrap();
    let before = ix.db_bytes().unwrap();
    let (pruned, _) = ix
        .prune_age(
            200 * 86_400,
            1_900_000_000,
            std::time::Instant::now() + std::time::Duration::from_secs(3_600),
        )
        .unwrap();
    let live = ix.live_bytes().unwrap();
    let free = ix.freelist_pages().unwrap();
    println!(
        "{label}: pruned {pruned} releases -> {:.0} MB file, {:.0} MB live, \
         {free} free pages ({:.0} MB reclaimable)",
        before as f64 / 1e6,
        live as f64 / 1e6,
        (before - live) as f64 / 1e6,
    );
    drop(ix);
}

/// The pre-§95 fixture. Every database that exists today was created
/// before `Index::open` set the pragma, so measuring the old path on a
/// db that is already incremental would flatter it.
fn force_auto_vacuum_none(path: &Path) {
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch("PRAGMA auto_vacuum=NONE; VACUUM;")
        .unwrap();
    let mode: i64 = db
        .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, 0, "fixture did not go back to auto_vacuum=NONE");
}

fn auto_vacuum_mode(path: &Path) -> i64 {
    let db = rusqlite::Connection::open(path).unwrap();
    db.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
        .unwrap()
}

fn fresh_copy(base: &Path, run: &Path) {
    for p in [run.to_path_buf(), wal(run), shm(run)] {
        let _ = std::fs::remove_file(p);
    }
    std::fs::copy(base, run).unwrap();
}

fn wal(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push("-wal");
    PathBuf::from(s)
}
fn shm(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push("-shm");
    PathBuf::from(s)
}

struct Step {
    arrival: Duration,
    /// Time from the job arriving to compaction letting go. THE number.
    waited: Duration,
    total: Duration,
    /// Did the arriving job actually stop it, or did it run to the end?
    stopped: bool,
    reclaimed_mb: f64,
    chunks: u64,
}

/// `arrival: None` measures an undisturbed run - the calibration the
/// sweep's offsets are cut from.
fn measure_vacuum(base: &Path, arrival: Option<Duration>) -> Step {
    let run = scratch("run.db");
    fresh_copy(base, &run);
    let before = std::fs::metadata(&run).map(|m| m.len()).unwrap_or(0);
    let ix = Index::open(&run).unwrap();
    let handle = ix.interrupt_handle();
    let started = Instant::now();
    let worker = std::thread::spawn(move || {
        let r = ix.compact();
        drop(ix); // as the daemon's blocking task does
        r.is_ok()
    });
    let job_arrived = match arrival {
        Some(a) => {
            std::thread::sleep(a);
            let t = Instant::now();
            handle.interrupt();
            t
        }
        None => started,
    };
    let ok = worker.join().unwrap();
    let returned = Instant::now();
    let after = std::fs::metadata(&run).map(|m| m.len()).unwrap_or(0);
    Step {
        arrival: arrival.unwrap_or_default(),
        waited: returned.duration_since(job_arrived),
        total: returned.duration_since(started),
        stopped: !ok,
        reclaimed_mb: before.saturating_sub(after) as f64 / 1e6,
        chunks: 1,
    }
}

/// The daemon's `chunked_compact` loop, reproduced: reclaim a bounded
/// chunk, then check whether a job has appeared. `stop` stands in for
/// `index_jobs_active`.
fn measure_chunked(base: &Path, arrival: Option<Duration>) -> Step {
    let run = scratch("run.db");
    fresh_copy(base, &run);
    let before = std::fs::metadata(&run).map(|m| m.len()).unwrap_or(0);
    let ix = Index::open(&run).unwrap();
    assert_eq!(
        ix.compact_style().unwrap(),
        CompactStyle::Chunked,
        "fixture is not in incremental mode, so this would measure a no-op"
    );
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let started = Instant::now();
    let worker = std::thread::spawn(move || {
        let mut chunks = 0u64;
        let mut worst = Duration::ZERO;
        let mut left = ix.freelist_pages().unwrap();
        let mut stood_down = false;
        while left > 0 {
            if flag.load(Ordering::Acquire) {
                stood_down = true;
                break;
            }
            let t = Instant::now();
            let now_left = ix.compact_chunk(CHUNK_PAGES).unwrap();
            worst = worst.max(t.elapsed());
            chunks += 1;
            if now_left >= left {
                break;
            }
            left = now_left;
        }
        drop(ix);
        (chunks, stood_down, worst)
    });
    let job_arrived = match arrival {
        Some(a) => {
            std::thread::sleep(a);
            let t = Instant::now();
            stop.store(true, Ordering::Release);
            t
        }
        None => started,
    };
    let (chunks, stood_down, worst) = worker.join().unwrap();
    let returned = Instant::now();
    let after = std::fs::metadata(&run).map(|m| m.len()).unwrap_or(0);
    if arrival.is_none() {
        println!(
            "  (chunked: {chunks} chunks of {CHUNK_PAGES} pages, worst single chunk {:.0} ms)",
            worst.as_secs_f64() * 1e3
        );
    }
    Step {
        arrival: arrival.unwrap_or_default(),
        waited: returned.duration_since(job_arrived),
        total: returned.duration_since(started),
        stopped: stood_down,
        reclaimed_mb: before.saturating_sub(after) as f64 / 1e6,
        chunks,
    }
}

fn report(label: &str, steps: &[Step]) {
    println!("\n== {label}");
    println!(
        "{:>10} {:>12} {:>10} {:>9} {:>8} {:>13}",
        "arrival_ms", "WAITED_ms", "total_ms", "stopped", "chunks", "reclaimed_MB"
    );
    for s in steps {
        println!(
            "{:>10.0} {:>12.0} {:>10.0} {:>9} {:>8} {:>13.1}",
            s.arrival.as_secs_f64() * 1e3,
            s.waited.as_secs_f64() * 1e3,
            s.total.as_secs_f64() * 1e3,
            if s.stopped { "yes" } else { "NO" },
            s.chunks,
            s.reclaimed_mb,
        );
    }
    let worst = steps
        .iter()
        .map(|s| s.waited.as_secs_f64() * 1e3)
        .fold(0.0f64, f64::max);
    let stopped = steps.iter().filter(|s| s.stopped).count();
    let kept: f64 = steps
        .iter()
        .filter(|s| s.stopped)
        .map(|s| s.reclaimed_mb)
        .sum();
    println!(
        "  WORST WAIT {worst:.0} ms; stopped {stopped}/{} arrivals; \
         MB kept across the stopped runs {kept:.1}",
        steps.len()
    );
}

fn offsets(full: Duration) -> Vec<Duration> {
    [0.0f64, 0.02, 0.05, 0.1, 0.2, 0.35, 0.5, 0.7, 0.9]
        .iter()
        .map(|f| Duration::from_secs_f64(full.as_secs_f64() * f))
        .collect()
}

// -- cheap properties, run on every push --

/// Ballast straight through a second connection: far quicker than
/// `ingest`, and these tests are about page accounting, not schema.
///
/// Opens an `Index` FIRST. SQLite only accepts `auto_vacuum` on a
/// database with no tables yet, so creating the ballast table on a
/// virgin file would leave the database in the default mode and make
/// every `compact_chunk` below a silent no-op - which is precisely the
/// failure this helper existed to trip over once already.
fn quick_ballast(path: &Path, rows: usize) -> Index {
    let ix = Index::open(path).unwrap();
    assert_eq!(
        ix.compact_style().unwrap(),
        CompactStyle::Chunked,
        "fixture is not in incremental mode; compact_chunk would do nothing"
    );
    drop(ix);
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE IF NOT EXISTS ballast(id INTEGER PRIMARY KEY, b BLOB)")
        .unwrap();
    let payload = vec![7u8; 4096];
    let tx = db.unchecked_transaction().unwrap();
    for _ in 0..rows {
        tx.execute("INSERT INTO ballast(b) VALUES(?1)", [&payload])
            .unwrap();
    }
    tx.commit().unwrap();
    db.execute("DELETE FROM ballast WHERE id % 2 = 0", [])
        .unwrap();
    drop(db);
    Index::open(path).unwrap()
}

fn case(name: &str) -> PathBuf {
    let p = scratch(&format!("{name}.db"));
    for q in [p.clone(), wal(&p), shm(&p)] {
        let _ = std::fs::remove_file(q);
    }
    p
}

#[test]
fn a_new_database_is_incremental_from_birth() {
    let p = case("birth");
    let ix = Index::open(&p).unwrap();
    assert_eq!(
        ix.compact_style().unwrap(),
        CompactStyle::Chunked,
        "a fresh install must never need the migration rewrite"
    );
}

#[test]
fn compact_migrates_an_existing_database_to_incremental() {
    let p = case("migrate");
    drop(Index::open(&p).unwrap());
    force_auto_vacuum_none(&p);
    let ix = Index::open(&p).unwrap();
    assert_eq!(ix.compact_style().unwrap(), CompactStyle::FullRewrite);
    ix.compact().unwrap();
    assert_eq!(
        ix.compact_style().unwrap(),
        CompactStyle::Chunked,
        "the one full rewrite every existing install pays must also be the \
         last one it ever pays"
    );
}

/// Regression guard for a trap that silently costs a write transaction
/// PER PAGE: `PRAGMA incremental_vacuum(N)` is a VDBE loop that frees
/// one page per step, so running it with `execute_batch` - which steps
/// once - frees exactly 1 page however large N is. The daemon's loop
/// still terminates, so nothing fails; it just does 2048x the
/// transactions. Measured before the fix: 12,013 chunks to reclaim
/// 49 MB, where 6 chunks now do it.
#[test]
fn a_chunk_reclaims_the_whole_chunk_not_one_page() {
    let p = case("chunksize");
    let ix = quick_ballast(&p, 4_000);
    let before = ix.freelist_pages().unwrap();
    assert!(
        before > 600,
        "ballast left only {before} free pages, too few to tell a full chunk \
         from a single page"
    );
    let after = ix.compact_chunk(512).unwrap();
    let freed = before - after;
    assert!(
        freed >= 500,
        "one compact_chunk(512) freed {freed} pages - the pragma is being \
         stepped once instead of to completion"
    );
}

#[test]
fn a_chunk_hands_the_space_back_and_keeps_it() {
    let p = case("keeps");
    let ix = quick_ballast(&p, 4_000);
    let before = ix.db_bytes().unwrap();
    assert!(ix.freelist_pages().unwrap() > 0);
    ix.compact_chunk(512).unwrap();
    let after = ix.db_bytes().unwrap();
    assert!(
        after < before,
        "the file did not shrink ({before} -> {after}), so standing down \
         after a chunk would keep nothing"
    );
    // Committed, not pending: a second handle sees the shorter file.
    drop(ix);
    let reopened = Index::open(&p).unwrap();
    assert!(reopened.db_bytes().unwrap() <= after);
}

/// The loop the daemon runs, in miniature: chunks until the freelist is
/// empty, and stops on request without losing what it has done.
#[test]
fn the_chunk_loop_terminates_and_is_resumable() {
    let p = case("loop");
    let ix = quick_ballast(&p, 4_000);
    let start = ix.db_bytes().unwrap();
    // Stand down after one chunk, exactly as a job arriving would.
    let mid = ix.compact_chunk(256).unwrap();
    let after_one = ix.db_bytes().unwrap();
    assert!(after_one < start, "the first chunk kept nothing");
    // Resume: the rest still goes, and the loop ends.
    let mut left = mid;
    let mut guard = 0;
    while left > 0 && guard < 10_000 {
        let now_left = ix.compact_chunk(256).unwrap();
        guard += 1;
        if now_left >= left {
            break;
        }
        left = now_left;
    }
    assert_eq!(
        ix.freelist_pages().unwrap(),
        0,
        "the loop stopped with pages still on the freelist"
    );
    assert!(ix.db_bytes().unwrap() < after_one);
}

#[test]
#[ignore = "builds a large database and sweeps it; run deliberately"]
fn a_job_arriving_mid_compact_waits_this_long() {
    let releases = env_usize("BALLAST_RELEASES", 6000);
    let parts = env_usize("BALLAST_PARTS", 200);
    let base = scratch("base.db");
    build_ballast(&base, releases, parts);

    // -- 1. today: one VACUUM, aborted with sqlite3_interrupt --
    // Force the mode FIRST (that costs a VACUUM), prune SECOND, so the
    // fixture has the freelist the old path would have faced.
    let old = scratch("old.db");
    fresh_copy(&base, &old);
    force_auto_vacuum_none(&old);
    prune(&old, "BEFORE fixture");
    // The AFTER fixture is `base` itself: created incremental by
    // Index::open, which is the state a fresh install starts in.
    prune(&base, "AFTER fixture");
    let solo = measure_vacuum(&old, None);
    println!(
        "uninterrupted VACUUM: {:.0} ms, {:.1} MB reclaimed",
        solo.total.as_secs_f64() * 1e3,
        solo.reclaimed_mb,
    );
    let old_steps: Vec<Step> = offsets(solo.total)
        .into_iter()
        .map(|o| measure_vacuum(&old, Some(o)))
        .collect();
    report("BEFORE - VACUUM + sqlite3_interrupt", &old_steps);

    // -- 2. the one-time migration, which is honestly not abortable --
    let migrated = scratch("migrated.db");
    fresh_copy(&old, &migrated);
    assert_eq!(auto_vacuum_mode(&migrated), 0);
    let t = Instant::now();
    Index::open(&migrated).unwrap().compact().unwrap();
    println!(
        "\n== MIGRATION (once per existing install)\n  \
         full rewrite {:.0} ms, auto_vacuum now {} (2 = INCREMENTAL)",
        t.elapsed().as_secs_f64() * 1e3,
        auto_vacuum_mode(&migrated),
    );
    assert_eq!(
        auto_vacuum_mode(&migrated),
        2,
        "compact() must leave the database in incremental mode, or every \
         later compact silently stays a full VACUUM"
    );

    // -- 3. after: bounded chunks, checked between --
    // `base` came from Index::open, so it is already incremental - which
    // is exactly the state a fresh install starts in.
    let solo_chunked = measure_chunked(&base, None);
    println!(
        "uninterrupted chunked compact: {:.0} ms, {:.1} MB reclaimed, {} chunks",
        solo_chunked.total.as_secs_f64() * 1e3,
        solo_chunked.reclaimed_mb,
        solo_chunked.chunks,
    );
    let new_steps: Vec<Step> = offsets(solo_chunked.total)
        .into_iter()
        .map(|o| measure_chunked(&base, Some(o)))
        .collect();
    report("AFTER - compact_chunk loop", &new_steps);

    // The properties, not the timings. Deliberately loose bounds: this
    // asserts the SHAPE, and the printed table carries the numbers.
    //
    // Note what is NOT asserted - that every arrival stopped it. An
    // arrival late in the sweep can legitimately land after the last
    // chunk has already committed, and "it had already finished" is a
    // fine answer to "how long did the job wait?". The wait is what
    // matters.
    let worst = new_steps.iter().map(|s| s.waited).max().unwrap();
    assert!(
        worst < solo_chunked.total / 2,
        "worst chunked wait {worst:?} is not meaningfully shorter than the \
         whole compaction ({:?}) - chunks are not bounding the stall",
        solo_chunked.total,
    );
    // The resumability half: a compaction that stood down mid-run must
    // have KEPT what it reclaimed. The VACUUM path cannot have this
    // property at all - every abort there reclaimed 0.0 MB.
    let mid_run: Vec<&Step> = new_steps
        .iter()
        .filter(|s| s.stopped && s.chunks > 0)
        .collect();
    assert!(
        !mid_run.is_empty(),
        "the sweep never caught a compaction mid-run, so it proved nothing"
    );
    for s in mid_run {
        assert!(
            s.reclaimed_mb > 0.0,
            "stood down after {} chunks having reclaimed nothing - the chunks \
             are not committing, so this is no better than an aborted VACUUM",
            s.chunks,
        );
    }
}
