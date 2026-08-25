//! The par-race experiment's pure pieces (`get/workers.rs`): the
//! estimate, the missing-block count and the race task itself against
//! a FileSlot fixture.
//!
//! A child of `workers`, out here for the size gate (TODO 106): the
//! parent is production code sitting 35 lines under the 3,000-line
//! file ceiling, and its inline test modules were a fifth of it. The
//! module is named for its file so size-gate.py's CFG_TEST_MOD resolver
//! still reads it as test code; `super` is still `workers`, so
//! `use super::*` reaches exactly what the inline module reached.

use super::recovery::*;
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

fn slot(hint: &str, remaining: usize, missing: usize) -> Arc<FileSlot> {
    Arc::new(FileSlot {
        hint: hint.into(),
        is_par2_main: false,
        sample_skipped: false,
        par2_sniffed: AtomicBool::new(false),
        total_segments: 3,
        remaining: AtomicUsize::new(remaining),
        missing: AtomicUsize::new(missing),
        errors: AtomicUsize::new(0),
        deferred: AtomicUsize::new(0),
        abandoned: AtomicUsize::new(0),
        capture: std::sync::Mutex::new(None),
    })
}

fn nzb() -> Nzb {
    Nzb::parse(
        r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"a.rar" yEnc (1/3)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="4000" number="1">a1@t</segment>
   <segment bytes="4000" number="2">a2@t</segment>
   <segment bytes="400000" number="3">a3@t</segment>
  </segments>
 </file>
 <file subject='"b.sample.mkv" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="1000" number="1">b1@t</segment>
   <segment bytes="50000" number="2">b2@t</segment>
  </segments>
 </file>
</nzb>"#
            .as_bytes(),
    )
    .expect("test NZB parses")
}

/// Codex 5 Aug M2 defect 1: a file the recovery set does not cover
/// must never become a cancellation candidate - repair cannot heal
/// it, so abandoning its articles is permanent damage.
#[test]
fn an_uncovered_companion_is_never_a_candidate() {
    let n = nzb();
    let slots = vec![slot("a.rar", 2, 0), slot("b.sample.mkv", 2, 0)];
    let set_names: std::collections::HashSet<String> =
        [nzbkit::disk::sanitize_filename("a.rar").to_lowercase()]
            .into_iter()
            .collect();
    let est = par_race_estimate(&set_names, 4096, &slots, &[0, 1], &n);
    assert!(est.want.contains("<a1@t>"));
    assert!(
        !est.want.iter().any(|id| id.starts_with("<b")),
        "uncovered b.sample.mkv articles must stay out of the race: {:?}",
        est.want
    );
}

/// Codex 5 Aug M2 defect 2: the damage guard charges the file's
/// LARGEST still-possible segments at exact bytes. With 2 tiny
/// segments done and one 400 KB straggler queued, the old average
/// math advertised ~34 blocks of worst-case damage; the truth is 99.
#[test]
fn damage_worst_case_uses_exact_largest_segments_not_the_average() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 1, 0), slot("b.sample.mkv", 0, 0)];
    let set_names: std::collections::HashSet<String> =
        [nzbkit::disk::sanitize_filename("a.rar").to_lowercase()]
            .into_iter()
            .collect();
    let est = par_race_estimate(&set_names, block, &slots, &[0, 1], &n);
    // One unresolved article: worst case is the 400000-byte
    // segment - ceil(400000/4096)+1 = 99 blocks.
    assert_eq!(est.out_blocks, 98 + 1);
    // The average estimator (408000/3 = 136000 -> 35 blocks) must
    // not be what guards the cancel.
    assert!(est.out_blocks > 35);
}

/// Missing articles are bounded by their own slot's largest
/// declared segment, not a cross-file average.
#[test]
fn missing_blocks_bound_by_the_slots_own_largest_segment() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 0, 0), slot("b.sample.mkv", 0, 2)];
    // b's largest segment is 50000 bytes: ceil(50000/4096)+1 = 14
    // blocks, twice.
    assert_eq!(par_race_missing_blocks(block, &slots, &[0, 1], &n), 28);
}

/// The race is an experiment and must stay dark by default.
#[test]
fn par_race_defaults_off() {
    assert!(
        std::env::var("NZBFAST_PAR_RACE").is_err(),
        "NZBFAST_PAR_RACE leaked into the test environment"
    );
}

/// §146 tail give-up decision: one uncovered walker vetoes the whole
/// trade, and the 2x margin is a hard floor - at ceiling*2-1 the
/// ladder keeps walking.
#[test]
fn tail_giveup_needs_every_walker_covered_at_twice_the_ceiling() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let set_names: std::collections::HashSet<String> =
        [nzbkit::disk::sanitize_filename("a.rar").to_lowercase()]
            .into_iter()
            .collect();
    let est = par_race_estimate(&set_names, block, &slots, &[0, 1], &n);
    // Walkers a1+a2: 2 blocks each (ceil(4000/4096)+1). No other
    // damage priced in: ceiling 4, so 8 recovery blocks commit and
    // 7 do not.
    let wk = |id: &str, ord: u32| nzbkit::pool::Walker { id: id.into(), ord };
    let walkers = vec![wk("<a1@t>", 0), wk("<a2@t>", 1)];
    assert!(tail_giveup_covered(&walkers, &est, block, 0, 0, 8));
    assert!(!tail_giveup_covered(&walkers, &est, block, 0, 0, 7));
    // Damage already priced in raises the ceiling with it.
    assert!(!tail_giveup_covered(&walkers, &est, block, 3, 0, 8));
    assert!(tail_giveup_covered(&walkers, &est, block, 3, 0, 14));
    // An uncovered companion's article vetoes everything, however
    // many blocks are on hand - repair cannot rebuild it.
    let with_b = vec![wk("<a1@t>", 0), wk("<b1@t>", 2)];
    assert!(!tail_giveup_covered(&with_b, &est, block, 0, 0, 10_000));
}

/// R1, 20 Aug 2026: recovery volumes are PREALLOCATED to their full
/// length at the first article, so a census scan taken while the
/// side-fetch is still writing sees the final length with only some
/// of the content - and the old (path -> len, count) cache served
/// that mid-write undercount for the rest of the job (traced live:
/// 17 of 128 slices on one leg, 6 on another). `on_hand` froze, the
/// 2x margin never cleared, the tail give-up never fired, and
/// damaged posts walked the refusal ladder 32-68% slower. A first
/// fix that refused to cache only a ZERO scan was falsified by R1
/// step 3 - a nonzero undercount poisons identically.
///
/// The invariant that actually holds: a scan of a file written to
/// within [`CENSUS_QUIET`] is returned but never remembered, and a
/// quiet file's scan is remembered even when it found nothing (the
/// index par2 genuinely has no slices - re-reading it every 200 ms
/// tick is the cost A5 exists to remove).
#[test]
fn a_busy_files_scan_is_never_cached_a_quiet_ones_is() {
    let dir = std::env::temp_dir().join(format!("nzbfast-r1-census-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let mut cache: std::collections::HashMap<PathBuf, (u64, std::time::SystemTime, usize)> =
        std::collections::HashMap::new();

    // Freshly written = mtime now = a writer may still be active.
    // Content does not matter (not par2, scans to 0); what is pinned
    // is that NOTHING about a busy file is remembered.
    let busy = dir.join("half-written.par2");
    std::fs::write(&busy, vec![0u8; 4096]).unwrap();
    assert_eq!(
        cached_recovery_blocks(&busy, &[7u8; 16], 1024, &mut cache),
        0
    );
    assert!(
        cache.is_empty(),
        "a busy file's scan was cached - a mid-write undercount would be served all job"
    );

    // The same file, quiet: backdate mtime past the gate. Now the
    // zero IS remembered - it is the file's true count.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    std::fs::File::options()
        .write(true)
        .open(&busy)
        .unwrap()
        .set_modified(old)
        .unwrap();
    assert_eq!(
        cached_recovery_blocks(&busy, &[7u8; 16], 1024, &mut cache),
        0
    );
    assert_eq!(
        cache.get(&busy).map(|&(l, _, n)| (l, n)),
        Some((4096, 0)),
        "a quiet file's scan must be cached, zero included"
    );

    // A later write moves mtime, which must invalidate the entry:
    // same length, new content, fresh scan (and no re-cache while
    // the file is busy again).
    std::fs::write(&busy, vec![1u8; 4096]).unwrap();
    assert_eq!(
        cached_recovery_blocks(&busy, &[7u8; 16], 1024, &mut cache),
        0
    );
    let cached_mtime = cache.get(&busy).map(|&(_, t, _)| t).unwrap();
    assert_eq!(
        cached_mtime, old,
        "a rewritten (busy) file re-entered the cache through the stale entry"
    );

    // Unreadable / absent: never remembered.
    let missing = dir.join("not-here.par2");
    assert_eq!(
        cached_recovery_blocks(&missing, &[7u8; 16], 1024, &mut cache),
        0
    );
    assert!(!cache.contains_key(&missing), "a failed read was cached");

    let _ = std::fs::remove_dir_all(&dir);
}
