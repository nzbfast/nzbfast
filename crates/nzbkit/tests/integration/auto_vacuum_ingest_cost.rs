//! §95 follow-up: what does `auto_vacuum=INCREMENTAL` cost the SCAN
//! path, forever, to make an occasional maintenance operation abortable?
//!
//! Incremental auto-vacuum adds pointer-map pages, and every allocation
//! or free updates one. Ingest is the write-heavy path that pays it -
//! `compact_abort_latency` measures the benefit, this measures the bill.
//! The two together are the trade.
//!
//! Ignored: minutes of disk. Run deliberately:
//!
//! ```sh
//! cargo test -p nzbkit --release --test auto_vacuum_ingest_cost -- --ignored --nocapture
//! ```

use nzbkit::index::Index;
use nzbkit::nntp::OverEntry;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-av-cost-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// Create the file with `auto_vacuum` already decided. A table has to
/// exist before `Index::open` runs, or its own `PRAGMA
/// auto_vacuum=INCREMENTAL` would take effect and both arms would be
/// the same database.
fn seed(path: &Path, incremental: bool) {
    for p in [path.to_path_buf(), wal(path), shm(path)] {
        let _ = std::fs::remove_file(p);
    }
    let db = rusqlite::Connection::open(path).unwrap();
    let mode = if incremental { "INCREMENTAL" } else { "NONE" };
    db.execute_batch(&format!(
        "PRAGMA auto_vacuum={mode};
         PRAGMA journal_mode=WAL;
         CREATE TABLE _seed(x INTEGER);"
    ))
    .unwrap();
    let got: i64 = db
        .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        got,
        if incremental { 2 } else { 0 },
        "seed did not take the mode it was asked for"
    );
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

struct Arm {
    ingest_secs: f64,
    bytes: u64,
    delete_secs: f64,
}

fn run_arm(path: &Path, incremental: bool, releases: usize, parts: usize) -> Arm {
    seed(path, incremental);
    let mut ix = Index::open(path).unwrap();
    let now = 1_900_000_000i64;
    let mut batch: Vec<OverEntry> = Vec::with_capacity(parts);
    let t = Instant::now();
    for r in 0..releases {
        batch.clear();
        let stem = format!("Ballast.Release.{r:07}.1080p.WEB-DL.x264-GRP");
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
    let ingest_secs = t.elapsed().as_secs_f64();
    let bytes = ix.db_bytes().unwrap();
    // The other half of the bill: freeing pages also touches ptrmap.
    let t = Instant::now();
    ix.prune_age(
        200 * 86_400,
        now,
        std::time::Instant::now() + std::time::Duration::from_secs(3_600),
    )
    .unwrap();
    let delete_secs = t.elapsed().as_secs_f64();
    Arm {
        ingest_secs,
        bytes,
        delete_secs,
    }
}

#[test]
#[ignore = "minutes of disk; run deliberately"]
fn what_incremental_auto_vacuum_costs_the_scan_path() {
    let releases: usize = std::env::var("BALLAST_RELEASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30_000);
    let parts: usize = std::env::var("BALLAST_PARTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    // Interleave the arms so a thermal or cache drift hits both.
    let none_a = run_arm(&scratch("none_a.db"), false, releases, parts);
    let inc_a = run_arm(&scratch("inc_a.db"), true, releases, parts);
    let inc_b = run_arm(&scratch("inc_b.db"), true, releases, parts);
    let none_b = run_arm(&scratch("none_b.db"), false, releases, parts);

    let none_ingest = (none_a.ingest_secs + none_b.ingest_secs) / 2.0;
    let inc_ingest = (inc_a.ingest_secs + inc_b.ingest_secs) / 2.0;
    let none_delete = (none_a.delete_secs + none_b.delete_secs) / 2.0;
    let inc_delete = (inc_a.delete_secs + inc_b.delete_secs) / 2.0;
    let none_bytes = (none_a.bytes + none_b.bytes) / 2;
    let inc_bytes = (inc_a.bytes + inc_b.bytes) / 2;

    println!("\n== auto_vacuum cost, {releases} releases x {parts} parts, 2 runs each");
    println!(
        "{:>14} {:>12} {:>12} {:>10}",
        "", "NONE", "INCREMENTAL", "delta"
    );
    println!(
        "{:>14} {:>12.2} {:>12.2} {:>9.1}%",
        "ingest s",
        none_ingest,
        inc_ingest,
        (inc_ingest / none_ingest - 1.0) * 100.0
    );
    println!(
        "{:>14} {:>12.2} {:>12.2} {:>9.1}%",
        "prune s",
        none_delete,
        inc_delete,
        (inc_delete / none_delete - 1.0) * 100.0
    );
    println!(
        "{:>14} {:>12.1} {:>12.1} {:>9.2}%",
        "file MB",
        none_bytes as f64 / 1e6,
        inc_bytes as f64 / 1e6,
        (inc_bytes as f64 / none_bytes as f64 - 1.0) * 100.0
    );
    println!(
        "  (spread: ingest NONE {:.2}/{:.2}, INCREMENTAL {:.2}/{:.2})",
        none_a.ingest_secs, none_b.ingest_secs, inc_a.ingest_secs, inc_b.ingest_secs
    );

    // Not a pass/fail threshold dressed up as a fact - just a tripwire
    // wide enough that only a real regression trips it. The printed
    // table is the result.
    assert!(
        inc_ingest < none_ingest * 1.5,
        "incremental auto-vacuum cost ingest {:.0}% - that is no longer a \
         fair trade for an abortable compact; reconsider VACUUM INTO",
        (inc_ingest / none_ingest - 1.0) * 100.0
    );
}
