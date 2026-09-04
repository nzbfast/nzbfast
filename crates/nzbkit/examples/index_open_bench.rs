//! `Index::open` at a stated size - the one call audit Round 21 said it
//! had NOT measured.
//!
//! Round 21 (`research/RAR-PERF-AUDIT-2026-09-02.md`) timed the daemon's
//! whole boot at 0.115-0.139 s to the first API answer, over an EMPTY
//! index, and recorded that the index open was therefore not covered.
//! The open is not a `sqlite3_open`: it is a ladder of eleven rungs -
//! schema creation, additive migrations, a marks rebuild, the arrival
//! counter and its six indexes, the conditional picker-index build, two
//! FTS tables, the retroactive backfills, the oracle schema, two predb
//! EXISTS probes, and the seed catalogue's bounded re-key. Several of
//! those rungs read or write `releases`, and which one a slow open is
//! stuck on cannot be recovered from a total.
//!
//! This opens ONE database and prints the per-phase line
//! `Index::open` already emits (`target: "index"`, `debug!` under
//! [`OPEN_SLOW_MS`] and `info!` over it), plus its own wall.
//!
//!     cargo run --release -p nzbkit --example index_open_bench -- \
//!         --db /path/to/index.db [--reps 3]
//!
//! ONE PROCESS PER COLD READING. Reps inside a process are page-cache
//! and SQLite-page-cache warm by the second one, so they measure a
//! re-open and not a boot; both are worth having and the output labels
//! which is which. Drive it a fresh process per cold reading, and purge
//! nothing - a real daemon restart on a live box finds the file warm
//! too.
//!
//! Row counts are deliberately NOT taken here. `SELECT COUNT(*)` over
//! `releases` is a full index scan, and taking one in this process would
//! warm exactly the pages the next open is being timed reading; the rig
//! asks `sqlite3` for them in a separate process once the timings are
//! banked.
//!
//! Touches no network and no provider; it opens a file you name.

use std::path::PathBuf;
use std::time::Instant;

use nzbkit::index::Index;

type Fail = Box<dyn std::error::Error>;

fn main() -> Result<(), Fail> {
    let mut db: Option<PathBuf> = None;
    let mut reps: usize = 1;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().expect("missing value");
        match a.as_str() {
            "--db" => db = Some(PathBuf::from(val())),
            "--reps" => reps = val().parse()?,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    let db = db.expect("--db is required (the index.db to open)");
    if !db.exists() {
        return Err(format!("{} does not exist", db.display()).into());
    }

    // The per-phase line is a `tracing` event, so without a subscriber
    // the whole point of this rig is invisible. DEBUG, because a
    // fully-migrated open is milliseconds and would otherwise print
    // nothing at all.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .without_time()
        .init();

    let bytes = std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0);
    let wal = std::fs::metadata(db.with_extension("db-wal"))
        .map(|m| m.len())
        .unwrap_or(0);
    println!(
        "db {} ({:.2} GB, wal {:.2} MB)",
        db.display(),
        bytes as f64 / 1e9,
        wal as f64 / 1e6
    );

    let mut last: Option<Index> = None;
    for rep in 1..=reps {
        // The previous handle is dropped BEFORE the next open is timed,
        // not after: SQLite's close can checkpoint, and a checkpoint
        // billed to the next open is a reading of the wrong thing.
        drop(last.take());
        let t0 = Instant::now();
        let ix = Index::open(&db)?;
        let ms = t0.elapsed().as_secs_f64() * 1e3;
        let label = if rep == 1 { "cold-ish" } else { "re-open" };
        println!("open rep {rep} ({label}) {ms:.2} ms");
        last = Some(ix);
    }

    Ok(())
}
