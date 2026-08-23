//! The M15b backfill runs its slots on a pool, and must reach exactly
//! the verdicts the one-slot-at-a-time version reached (TODO 129's
//! "the resume/backfill hash path must ride the parallel-MD5 pool").
//!
//! A child module file rather than an inline `mod tests`: unpack.rs is
//! near its size-gate ceiling (TODO 106) and the numbers only go down.
//! Same pattern as `pwfile_tests.rs`.
//!
//! Both routes `take_pre_spans` can hand back are driven, because they
//! are the two halves of the item's own name: `PreSpanSrc::Backfill`
//! (spans THIS run decoded before activation, claimable CRC-only) and
//! `PreSpanSrc::Disk` (a crash RESUME's seeded spans, always full-MD5).
//! Only the second is the one whose bytes can run to tens of GB, and it
//! is the one whose hot loop is `md5::soft`.

use super::*;
use nzbkit::live::{LiveVerifier, SlotReport};

const MAIN: &[u8] = include_bytes!("../../../nzbkit/tests/fixtures/par2/testset.par2");
const ALPHA: &[u8] = include_bytes!("../../../nzbkit/tests/fixtures/par2/alpha.bin");
const BETA: &[u8] = include_bytes!("../../../nzbkit/tests/fixtures/par2/beta.bin");

/// The set's two members, one per slot. Block size is 4096: beta is
/// 33 KiB / 9 blocks, alpha 10 KiB / 3 blocks.
const MEMBERS: [(&str, &[u8]); 2] = [("beta.bin", BETA), ("alpha.bin", ALPHA)];

/// What the run must agree on, whichever way the backfill was driven.
/// `SlotReport` has no `PartialEq`, and the fields that matter here are
/// the verdict (`bad_blocks`), the deobfuscated name the FileDesc gave
/// it, and the SPLIT between blocks the backfill claimed and blocks it
/// left for settle read-back - the last being the number the pass exists
/// to move.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    fed: u64,
    slots: Vec<(Option<String>, usize, Vec<usize>, u64, u64)>,
}

fn flatten(fed: u64, reports: Vec<Option<SlotReport>>) -> Outcome {
    Outcome {
        fed,
        slots: reports
            .into_iter()
            .map(|r| {
                let r = r.expect("every slot matched a set member");
                (
                    r.par2_name,
                    r.total_blocks,
                    r.bad_blocks,
                    r.live_blocks,
                    r.readback_blocks,
                )
            })
            .collect(),
    }
}

/// One whole run: write both members through an extractor, register
/// their pre-activation spans, activate, back-fill, settle.
///
/// `resume` picks the route - seeded spans (a crash resume, `Disk`)
/// against spans this run decoded (`Backfill`). `pooled` picks the
/// driver: `backfill_pre_activation` (the pool) against a plain loop
/// over `backfill_slot` on this thread, which IS the pre-pool code.
///
/// `art` is deliberately misaligned with the 4096-byte block, and the
/// spans are left with a HOLE, so blocks straddle span boundaries and
/// the partials path is exercised rather than a single whole-file feed.
fn run(dir: &std::path::Path, resume: bool, pooled: bool, art: usize) -> Outcome {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let ex = nzbkit::extract::Extractor::new(dir, MEMBERS.len(), true);
    let v = LiveVerifier::new(MEMBERS.len());

    for (sidx, (name, data)) in MEMBERS.iter().enumerate() {
        let size = data.len() as u64;
        if resume {
            // What `get::rig`'s replay does beside `seed_pre_spans`: the
            // journal's on-disk name is what matches the FileDesc, since
            // seeded spans are offsets only and the backfill re-feeds
            // them nameless.
            v.set_name_hint(sidx, name);
        }
        // A hole in the middle: one article's bytes are on disk but the
        // verifier is never told about them, so its blocks are absent
        // from `pre_spans`, the backfill has two DISJOINT ranges to walk
        // instead of one, and the blocks it skips fall through to settle
        // read-back - which finds them clean. That is the split the
        // comparison below is really about; without a hole both drivers
        // would feed one whole-file span and agree trivially.
        let hole = (data.len() / art / 2).max(1);
        for (i, chunk) in data.chunks(art).enumerate() {
            let off = (i * art) as u64;
            ex.write(sidx, name, size, off, chunk).unwrap();
            if i == hole {
                continue;
            }
            if resume {
                // Crash resume: the bytes are on disk from an earlier
                // run and the journal restored their offsets. Nothing in
                // THIS run vouches for them.
                v.seed_pre_spans(sidx, &[(off, chunk.len() as u64)]);
            } else {
                // Decoded here, before the set went live: recorded as a
                // pre-activation span by `on_data` itself.
                v.on_data(sidx, name, size, off, chunk);
            }
        }
    }
    v.activate(&[MAIN]).unwrap();

    let par2_slots = vec![false; MEMBERS.len()];
    let fed = if pooled {
        backfill_pre_activation(&v, &ex, MEMBERS.len(), &par2_slots)
    } else {
        let mut buf = vec![0u8; 4 << 20];
        (0..MEMBERS.len())
            .map(|sidx| backfill_slot(&v, &ex, sidx, &mut buf))
            .sum()
    };

    let reports = (0..MEMBERS.len())
        .map(|sidx| v.finish_slot(sidx, ex.slot_path(sidx).as_deref()))
        .collect();
    let out = flatten(fed, reports);
    let _ = std::fs::remove_dir_all(dir);
    out
}

/// The differential the item asked for: the pooled backfill and the
/// serial one hash the same bytes to the same answers.
///
/// Not just "both clean" - the fed byte count, the per-slot claimed/
/// read-back split and the deobfuscated names all have to match, so a
/// pool that silently skipped a slot (or double-fed one) fails here
/// rather than passing on a verdict the settle read-back would have
/// rescued anyway.
#[test]
fn the_pooled_backfill_matches_the_serial_one_on_both_routes() {
    for resume in [false, true] {
        for art in [1000usize, 4096, 5000, 7000] {
            let tag = format!(
                "nzbfast-bfpar-{}-{resume}-{art}-{:?}",
                std::process::id(),
                std::thread::current().id()
            );
            let dir = std::env::temp_dir().join(&tag);
            let serial = run(&dir, resume, false, art);
            let pooled = run(&dir, resume, true, art);
            assert_eq!(
                serial, pooled,
                "pooled backfill diverged from serial (resume={resume}, art={art})"
            );
            // The run has to be worth comparing: bytes actually flowed,
            // every block is accounted for, and the hole really did
            // leave work for settle - otherwise this would pass on an
            // empty backfill.
            assert!(pooled.fed > 0, "nothing was backfilled (art={art})");
            for (name, total, bad, live, readback) in &pooled.slots {
                assert!(name.is_some(), "slot never matched (art={art})");
                assert!(bad.is_empty(), "clean bytes reported bad: {bad:?}");
                assert_eq!(
                    live + readback,
                    *total as u64,
                    "blocks unaccounted for (art={art})"
                );
                assert!(*readback > 0, "the hole left nothing for settle");
            }
        }
    }
}
