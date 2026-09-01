//! TODO 30a Finding 6 - the batch-rule test and the isolated cpu_s
//! harness, split out
//! of `journal.rs` to keep it under the size ceiling (TODO 106), same
//! pattern as `zip_tests.rs`. Ignored; run by hand (see the fn doc).

use super::{Frag, Journal};

fn frag(file: &str, file_off: u64, vol_off: u64, len: u64) -> Frag {
    Frag {
        file: file.to_string(),
        file_off,
        vol_off,
        len,
    }
}

/// Replays the 16 GiB store leg's ~24.6k-record pattern through the real
/// `Journal` twice on the same device: arm A flushes after every record
/// (pre-30a behaviour), arm B batches. getrusage user+sys, so it prices
/// the journal write path with no network, decode or payload pwrite in
/// the sample. The win scales with append latency (~2.7 us tmpfs, ~15 us
/// loaded FileVault APFS), so run it where the product's journal lives,
/// not on a RAM disk:
/// `cargo test -p nzbkit --release journal_batch_cpu_bench -- --ignored --nocapture`.
#[test]
#[ignore]
fn journal_batch_cpu_bench() {
    // Via `crate::mem` rather than a local `libc::getrusage`, which does
    // not exist on Windows: this is a `cfg(test)` module of the LIB, so
    // the raw call held `windows-build` red at `cargo test --no-run`
    // (not only `--all-targets` clippy). `cpu_time_secs` already has
    // both platforms' halves - GetProcessTimes over there.
    fn cpu_s() -> f64 {
        crate::mem::cpu_time_secs().unwrap_or(0.0)
    }
    const N: u64 = 24_580;
    let run = |batched: bool| -> f64 {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-jbench-{}-{batched}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (j, _) = Journal::open(&dir, b"<bench/>").unwrap();
        let c0 = cpu_s();
        for i in 0..N {
            let off = i * 700_000;
            j.record_placed(
                0,
                &format!("<art{i}@bench>"),
                Some(("movie.bin".to_string(), N * 700_000)),
                "movie.bin",
                N * 700_000,
                &[frag("movie.bin", off, off, 700_000)],
                None,
            );
            if !batched {
                j.flush();
            }
        }
        j.flush();
        let dt = cpu_s() - c0;
        drop(j);
        let _ = std::fs::remove_dir_all(&dir);
        dt
    };
    // Interleave A B A B ... so any drift cancels; median of 5.
    let mut a = Vec::new();
    let mut b = Vec::new();
    for _ in 0..5 {
        a.push(run(false));
        b.push(run(true));
    }
    a.sort_by(|x, y| x.partial_cmp(y).unwrap());
    b.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let (am, bm) = (a[2], b[2]);
    println!(
        "journal_batch_cpu_bench: {N} records, one slot\n  \
         flush-per-record (before): {am:.3} cpu_s  ({:.1} us/record)\n  \
         batched (after):           {bm:.3} cpu_s  ({:.1} us/record)\n  \
         saved: {:.3} cpu_s  ({:.1}x)",
        am / N as f64 * 1e6,
        bm / N as f64 * 1e6,
        am - bm,
        if bm > 0.0 { am / bm } else { f64::INFINITY },
    );
}

/// TODO 30a Finding 6: placement records are batched, so a fresh
/// record is NOT on disk yet; `flush`, an immediate line (`M`) and
/// `Drop` each land the queue, and always in record order.
#[test]
fn placement_records_batch_and_land_in_order() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-batch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (j, _) = Journal::open(&dir, b"<nzb/>").unwrap();
    let path = j.path.clone();
    // Skip the header AND X5-01's generation claim, which `Journal::open`
    // writes directly behind it - this test is about the BATCH rule, and
    // both of those lines are written before any record exists to batch.
    let lines = |p: &std::path::Path| -> Vec<String> {
        std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .skip(2)
            .map(str::to_string)
            .collect()
    };
    j.record_placed(
        3,
        "<a@x>",
        None,
        "vol.rar",
        100,
        &[frag("in.bin", 1, 2, 3)],
        None,
    );
    // Queued, not landed: the file still holds only the header.
    assert!(
        lines(&path).is_empty(),
        "a fresh record must be queued, not written"
    );
    j.flush();
    assert_eq!(
        lines(&path),
        ["S 3 100 vol.rar", "F 0 in.bin", "R 3 0:1:2:3 <a@x>"]
    );
    // An immediate line drains the queue AHEAD of itself.
    j.record_placed(
        3,
        "<b@x>",
        None,
        "vol.rar",
        100,
        &[frag("in.bin", 4, 5, 6)],
        None,
    );
    j.record_materialized(7, "other.rar", 50);
    assert_eq!(
        lines(&path)[3..],
        ["R 3 0:4:5:6 <b@x>", "S 7 50 other.rar", "M 7"]
    );
    // Drop lands whatever is left.
    j.record("<c@x>");
    assert_eq!(lines(&path).len(), 6);
    drop(j);
    assert_eq!(lines(&path).last().map(String::as_str), Some("<c@x>"));
    let _ = std::fs::remove_dir_all(&dir);
}
