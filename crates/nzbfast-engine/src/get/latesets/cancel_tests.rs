//! X5-13: cancellation during the late recovery-set pass.
//!
//! A sibling file rather than a block in `latesets.rs`'s own `tests`
//! module, by the rule this directory already runs on - one subject per
//! file, and both `shape_tests` and `par2_window_tests` are here for it.
//!
//! THE ROW, and why it got WORSE rather than better on 31 Aug 2026.
//! `apply_nonactivated_disk_sets` runs only after an otherwise-good
//! settle, and it repairs every non-activated recovery set it finds on
//! disk - a full CPU-and-disk pass per set. W4-12 then made it a bounded
//! FIXPOINT, so it can take several census-and-repair rounds, and the
//! window in which nothing can stop it got LONGER. It had no
//! cancellation token at all, so a user who pressed delete waited out
//! every set on disk and then raced finalization.
//!
//! WHAT IS GRADED HERE is the WORK, never a clock. The bound the pass
//! now offers is "at most one more set repair after the latch is
//! raised", and that is assertable on a box running nine lanes' cargo
//! builds in a way `elapsed() < 200ms` is not - the theme of this week's
//! flakes. The rows below build REAL recovery sets with
//! `nzbkit::par2gen`, damage their members, and ask which ones came
//! back: the control repairs every one, the cancelled pass repairs none,
//! and the difference is bytes on disk rather than milliseconds.
//!
//! IN PROCESS AND WITHOUT THE `par2` BINARY, which is what makes this a
//! unit row rather than an e2e one - `par2gen::create_into` builds the
//! set here, so `tools/par2-gate.py`'s `have_par2()` guard is not owed
//! and a box with no `par2` binary installed runs it like every other.

use super::*;
use std::sync::Arc;

/// One payload file plus its own recovery set, written into `dir`,
/// answering the payload's path and its correct bytes.
///
/// A SET PER MEMBER, deliberately: the pass repairs set by set, so the
/// work bound this row is about is only visible when there is more than
/// one set for it to stop between.
fn set_of(dir: &std::path::Path, name: &str, seed: u8) -> (std::path::PathBuf, Vec<u8>) {
    let data: Vec<u8> = (0..64_000u32)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect();
    let path = dir.join(name);
    std::fs::write(&path, &data).expect("write the payload");
    nzbkit::par2gen::create_into(
        dir,
        &[nzbkit::par2gen::Member {
            name: name.to_string(),
            path: path.clone(),
        }],
        name,
        &nzbkit::par2gen::Par2Spec {
            redundancy_pct: 50,
            block_size: Some(4_096),
        },
    )
    .expect("par2gen builds the set");
    (path, data)
}

/// Flip a byte in the middle of `path`, which is damage every one of
/// these sets carries enough parity to undo.
fn damage(path: &std::path::Path) {
    let mut b = std::fs::read(path).expect("read the payload back");
    let mid = b.len() / 2;
    b[mid] ^= 0xff;
    std::fs::write(path, &b).expect("write the damaged payload");
}

/// Run the pass over `dir` with `cancel`, and answer which of `members`
/// came back byte-exact.
fn healed(
    dir: &std::path::Path,
    members: &[(std::path::PathBuf, Vec<u8>)],
    cancel: Option<&crate::repair::SideCancel>,
) -> usize {
    // No slots and no active sets: every payload file in the directory
    // is unclaimed, which is what opens `has_unclaimed`'s door, and
    // nothing is skipped for being active. `all_good` in as TRUE so the
    // verdict arithmetic - a different row - stays out of this one.
    let slots: Vec<Arc<FileSlot>> = Vec::new();
    // `enabled: false` and zero slots: this pass never routes a byte
    // through the extractor, it only hands it to the repair for the
    // adoption scan. Both halves are what `tools/extractor-anchor-gate.py`
    // exempts, and correctly - a disabled root with no slots has nothing
    // to anchor and no chase to lose.
    let extractor = Arc::new(nzbkit::extract::Extractor::new(dir, 0, false));
    let _ = super::apply_nonactivated_disk_sets(
        &[],
        dir,
        &slots,
        &extractor,
        super::Outstanding(true, 0, 0, Vec::new(), None),
        cancel,
    );
    members
        .iter()
        .filter(|(p, want)| std::fs::read(p).ok().as_ref() == Some(want))
        .count()
}

/// THE CONTROL, and it has to come first: with nothing cancelling, the
/// pass repairs EVERY damaged set it finds.
///
/// Without it the row below is met by a pass that had stopped repairing
/// anything at all - which is the failure mode a "nothing was repaired"
/// assertion cannot tell from a fix, and the reason `daemon_crashtx`
/// landed its own control alongside its probe.
#[test]
fn the_late_set_pass_repairs_every_damaged_set_when_nobody_cancels() {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-lateset-cancel-ctl-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _scratch = Scratch(dir.clone());
    std::fs::create_dir_all(&dir).unwrap();
    let members: Vec<_> = (0..3)
        .map(|i| set_of(&dir, &format!("m{i}.bin"), 10 + i as u8))
        .collect();
    for (p, _) in &members {
        damage(p);
    }
    assert_eq!(
        healed(&dir, &members, None),
        3,
        "the uncancelled pass must repair all three sets - a row that asserts \
         a cancelled pass repairs NONE means nothing beside a pass that \
         repairs none either way"
    );
}

/// X5-13: a latch already raised when the pass starts must stop it
/// before it repairs anything.
///
/// THE BOUND IS WORK AND NOT TIME. `stopped` is read at the top of the
/// round loop and again at the top of the set loop, both BEFORE any call
/// to `repair_dir_set_with_donors_scoped`, so the pass can never begin a
/// repair with the latch up - which for a latch raised before the call
/// is ZERO repairs, and for one raised mid-pass is at most the one
/// already in flight. That second half is a fact about WHERE the reads
/// are and is pinned as one, in
/// `shape_tests::the_late_set_pass_can_be_cancelled_between_sets`: a
/// test that tried to race a real latch against a real repair would be
/// asserting on the scheduler.
///
/// NEVER MID-REPAIR, which is the design and not a limitation.
/// `repair_dir_set_with_donors_scoped` writes files; torn down halfway
/// it leaves a set half-applied, and no caller afterwards could tell
/// that from a set that simply failed.
#[test]
fn a_cancelled_job_stops_the_late_set_pass_before_it_repairs_anything() {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-lateset-cancel-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _scratch = Scratch(dir.clone());
    std::fs::create_dir_all(&dir).unwrap();
    let members: Vec<_> = (0..3)
        .map(|i| set_of(&dir, &format!("m{i}.bin"), 10 + i as u8))
        .collect();
    for (p, _) in &members {
        damage(p);
    }
    let cancel = crate::repair::SideCancel::new();
    cancel.cancel();
    assert_eq!(
        healed(&dir, &members, Some(&cancel)),
        0,
        "a cancelled job must not have a single set repaired for it - the pass \
         is the longest uninterruptible thing left on the tail, and the user \
         has already said they do not want the result"
    );
    // ...and the damage is still there, said separately because "0
    // healed" would also be true of a pass that deleted them.
    for (p, want) in &members {
        let got = std::fs::read(p).expect("the payload is still on disk");
        assert_eq!(got.len(), want.len(), "{p:?} changed size");
        assert_ne!(&got, want, "{p:?} was repaired by a cancelled pass");
    }
}

/// The latch's polarity, driven directly, because getting it backwards
/// is the one mistake that disables every check above in silence and
/// leaves both rows green in the wrong direction.
///
/// `None` reaches this from no production path - every run carries a
/// handle, and a CLI run's is one nobody can reach - so it is driven
/// here rather than left as an arm nothing exercises.
#[test]
fn only_a_raised_latch_stops_the_pass() {
    assert!(!super::stopped(None, "in a test"), "the CLI never cancels");
    let live = crate::repair::SideCancel::new();
    assert!(
        !super::stopped(Some(&live), "in a test"),
        "a latch nobody raised must not stop the pass"
    );
    live.cancel();
    assert!(
        super::stopped(Some(&live), "in a test"),
        "a raised latch must stop the pass"
    );
}

/// Remove the fixture directory whatever the row did, including on a
/// panic - these rows write real recovery sets and a failing one would
/// otherwise leave them in `$TMPDIR` forever.
struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
