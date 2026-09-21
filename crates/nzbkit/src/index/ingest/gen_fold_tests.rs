//! The per-group fold that turned the generation-row bookkeeping from a
//! line per INGEST_BATCH into a line per group pass (18 Sep 2026).
//!
//! What these pin is the arithmetic and the attribution, not the
//! wording: the counters are the same counters the two `warn!`s used to
//! print, so a fold that loses or misattributes one is a figure gone
//! missing from the log with nothing to say it went. `super` is
//! `ingest`, so `take_gen_fold` is reachable as it is in the parent.

use super::*;
use crate::index::testutil::teardown;

fn scratch(name: &str) -> (std::path::PathBuf, Index) {
    let dir = std::env::temp_dir().join(format!("nzbfast-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    (dir, ix)
}

/// The batches of one group pass add up, and the fold survives until
/// somebody asks for it: that is the whole point of folding rather than
/// printing. `deepest` is a MAX across batches and not a sum - it names
/// the worst slot seen, and summing it would report a depth no slot
/// ever had.
#[test]
fn a_groups_batches_add_up_and_the_depth_is_the_worst_one() {
    let (dir, mut ix) = scratch("genfold-add");

    ix.fold_gen("alt.binaries.teevee", 3, 1, 0, 0);
    ix.fold_gen("alt.binaries.teevee", 0, 0, 40, 137);
    ix.fold_gen("alt.binaries.teevee", 5, 2, 10, 12);

    let f = ix.take_gen_fold().expect("three batches with news in them");
    assert_eq!(f.group.as_deref(), Some("alt.binaries.teevee"));
    assert_eq!(f.batches, 3);
    assert_eq!(f.minted, 8);
    assert_eq!(f.capped, 3);
    assert_eq!(f.dropped, 50);
    assert_eq!(f.deepest, 137, "deepest is the worst slot, never the sum");

    // Taken means taken: the next pass starts from nothing, or a group
    // scanned twice reports the first pass's figures again.
    assert!(ix.take_gen_fold().is_none());
    teardown(&dir, ix);
}

/// A batch for a DIFFERENT group flushes what is pending first. Without
/// this the counters of whoever ingested last would be printed under
/// the name of whoever ingests next - and the scan's explicit flush
/// cannot save a caller that does not make one (the seed importer, the
/// NZB import, a test).
#[test]
fn a_new_group_flushes_the_old_ones_figures_rather_than_inheriting_them() {
    let (dir, mut ix) = scratch("genfold-switch");

    ix.fold_gen("alt.binaries.moovee", 7, 0, 0, 0);
    ix.fold_gen("alt.binaries.teevee", 1, 0, 0, 0);

    // moovee's 7 went out with the auto-flush at the group change, so
    // what is pending is teevee's alone.
    let f = ix.take_gen_fold().expect("the second group is pending");
    assert_eq!(f.group.as_deref(), Some("alt.binaries.teevee"));
    assert_eq!(f.minted, 1, "moovee's 7 must not land on teevee's line");
    assert_eq!(f.batches, 1);
    teardown(&dir, ix);
}

/// A pass over a group with no reposts at all has no news, and says
/// nothing. The batch COUNT alone is never a reason to write a line -
/// that was the shape of the noise this fold exists to remove.
#[test]
fn a_quiet_pass_says_nothing_however_many_batches_it_took() {
    let (dir, mut ix) = scratch("genfold-quiet");

    for _ in 0..4_000 {
        ix.fold_gen("alt.binaries.teevee", 0, 0, 0, 0);
    }

    assert!(
        ix.take_gen_fold().is_none(),
        "4,000 uneventful batches are 4,000 lines of nothing"
    );
    teardown(&dir, ix);
}
