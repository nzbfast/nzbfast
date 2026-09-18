//! The refetch gap, deterministically: a recovery volume the in-stream
//! deferral left HOLED is bought back before the late-set pass reads it.
//!
//! A sibling file rather than a block in `latesets.rs`'s own `tests`
//! module, by the rule this directory already runs on - one subject per
//! file, beside `shape_tests`, `par2_window_tests`, `cancel_tests` and
//! `foreign_tests`.
//!
//! # Why this exists (claim `lateset-deferred-parity-refetch-16sep`)
//!
//! `unpack::instream`'s deferral keeps a sniffed volume's head article
//! and cancels its still-queued tail, which leaves the volume on disk at
//! full declared length with a ZERO HOLE. On 16 Sep 2026 that was
//! MEASURED as the live cause of a flake in two `e2e_lateset::x5_24_*`
//! probes: `setx2.vol07+8` at 83,336 bytes with zeros from offset
//! 40,000, the late-set pass reporting `needed=18 have=17`, and
//! `Charlie.Three.bin` never rebuilt
//! (`research/E2E-X5-24-SIGNATURE-2-IS-A-MISREAD-2026-09-16.md`).
//!
//! Those probes are a 1-2% timing flake and are not a pin. This file is
//! the pin: the same shape, decided without a clock, a mock server or
//! the `par2` binary - `par2gen::create_into` builds the set in process
//! and the pass is driven directly, as `foreign_tests` does.
//!
//! The rows are the fix's two halves and the second is not optional.
//! [`super::holed_deferred_volumes`] buying a volume back is worth
//! nothing if it also buys one back on every healthy job: the deferral
//! is a measured bandwidth saving, so a refetch that cannot say NO is a
//! regression wearing a fix's name.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};

/// Block size the set is built at, so the member's block count is its
/// length over this.
const BLOCK: u64 = 10_000;

/// The member length every row here uses: 18 blocks at [`BLOCK`], which
/// is the x5_24 fixtures' own `Charlie.Three.bin` and therefore the
/// arithmetic the measured failure reported (`needed=18`).
const MEMBER_LEN: usize = 180_000;

/// An arbitrary stand-in for the volume's NZB file index. The selector
/// never interprets it - it hands whatever it is given back for
/// `repair::fetch_volumes` to fetch - so any value proves the plumbing
/// as well as the real one, and a distinctive one makes a wrong answer
/// obvious in the failure message.
const VOL_FILE_INDEX: usize = 7;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A scratch directory holding the unclaimed sidecar
/// [`super::has_unclaimed`] needs before the pass will run at all - the
/// real shape always has one (the post's own arrived payload, still
/// wearing a hash), so this stands in for it rather than being a special
/// case. Shorter than one block on purpose: every regular file here is
/// an adoption candidate and a few dozen bytes cannot carry one.
fn scratch(tag: &str) -> (PathBuf, Scratch) {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-lateset-refetch-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("unclaimed.nfo"),
        b"a sidecar no recovery set names\n",
    )
    .unwrap();
    (dir.clone(), Scratch(dir))
}

/// Unrelated pseudo-random bytes. NOT `(i * k + seed) as u8` and for the
/// reason `foreign_tests` records at length: that form is periodic in
/// `i` with the seed as an OFFSET, so two payloads are one sequence at a
/// shift and `par2repair::adopt`'s sliding scan finds a member's block
/// inside another file.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15u64 ^ seed.wrapping_mul(0xD1B5_4A32_D192_ED03);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// One payload plus a 100%-parity set over it ALONE, then the payload is
/// deleted - the wholly-missing shape the pass exists to rebuild.
///
/// Answers the member's path, its correct bytes, and the set's recovery
/// volume files newest-first by size, so a caller can hole the one
/// carrying the most blocks.
fn wholly_missing_set(dir: &Path, name: &str, seed: u64) -> (PathBuf, Vec<u8>, Vec<PathBuf>) {
    let data = payload(MEMBER_LEN, seed);
    let path = dir.join(name);
    std::fs::write(&path, &data).expect("write the payload");
    let made = nzbkit::par2gen::create_into(
        dir,
        &[nzbkit::par2gen::Member {
            name: name.to_string(),
            path: path.clone(),
        }],
        name,
        &nzbkit::par2gen::Par2Spec {
            redundancy_pct: 100,
            block_size: Some(BLOCK),
        },
    )
    .expect("par2gen builds the set");
    std::fs::remove_file(&path).expect("the member is WHOLLY missing");
    // The volumes, not the index: the index carries the critical packets
    // and no recovery slices, so holing it would test a different thing
    // (an unreadable definition) than the one this file is about.
    let mut vols: Vec<PathBuf> = made
        .iter()
        .filter(|n| n.contains(".vol"))
        .map(|n| dir.join(n))
        .collect();
    vols.sort_by_key(|p| std::cmp::Reverse(std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)));
    (path, data, vols)
}

/// Do to a volume what the deferral's `queue.cancel` does: keep the head
/// article and leave the rest as a zero hole, at the file's full
/// declared length.
///
/// `HEAD` is the x5_24 fixtures' article size, which is the size the
/// measured failure was taken at. Answers the bytes that were lost, so
/// the row can put them back exactly as `repair::fetch_volumes` would.
fn hole_the_tail(path: &Path) -> Vec<u8> {
    const HEAD: usize = 40_000;
    let whole = std::fs::read(path).expect("the volume is on disk");
    assert!(
        whole.len() > HEAD,
        "the fixture needs a MULTI-ARTICLE volume for the cancel to have \
         anything to cancel - this one is {} bytes, inside one {HEAD}-byte \
         article, which is the shape `LEFTOVER_VOL_ART` uses to step around \
         this defect entirely",
        whole.len()
    );
    let mut holed = whole.clone();
    holed[HEAD..].fill(0);
    std::fs::write(path, &holed).expect("write the holed volume");
    whole
}

/// A slot that lost every one of its `total` segments - [`super::lost_whole`]'s
/// shape, which is the only shape a residual may be assigned to.
fn lost_slot(hint: &str, total: usize) -> Arc<FileSlot> {
    Arc::new(FileSlot {
        hint: hint.into(),
        hint_is_posted_name: true,
        yenc_votes: Default::default(),
        name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
        is_par2_main: false,
        sample_skipped: false,
        par2_name_demoted: Default::default(),
        par2_sniffed: AtomicBool::new(false),
        total_segments: total,
        remaining: AtomicUsize::new(0),
        missing: AtomicUsize::new(total),
        errors: AtomicUsize::new(0),
        deferred: AtomicUsize::new(0),
        abandoned: AtomicUsize::new(0),
        capture: std::sync::Mutex::new(None),
    })
}

/// Run the whole pass with no active sets, so every set on disk is
/// non-activated and nothing vouches for any of them - the `!mine`
/// family the measured failure sits in.
fn run_pass(dir: &Path, slots: &[Arc<FileSlot>], slot_bytes: Vec<u64>) -> bool {
    let extractor = Arc::new(nzbkit::extract::Extractor::new(dir, 0, false));
    super::apply_nonactivated_disk_sets(
        &[],
        dir,
        slots,
        &extractor,
        super::Outstanding(false, slots.len(), 0, slot_bytes, None),
        None,
    )
    .0
}

/// The encoded-bytes declaration for a wholly-lost 180,000-byte member
/// over five articles, inside [`super::fits`]' band (162,000..217,280) -
/// the same pairing `foreign_tests` uses, so the residual tier can
/// actually assign the rebuild.
const LOST_DECL: u64 = 185_400;

/// THE ROW. A wholly-missing member whose own 100%-parity set is on
/// disk, and whose volume the deferral holed: the pass cannot rebuild
/// it, the selector names the volume, and once the cancelled bytes are
/// back the very same pass rebuilds the member byte-exact.
///
/// All three statements are in ONE row deliberately. The first alone is
/// a characterisation of the defect and passes before and after the fix;
/// the third alone would pass over a fixture whose volume was never
/// holed at all. Together they say the thing the claim is about: the
/// hole is what stopped the rebuild, and buying it back is what starts
/// it.
#[test]
fn a_holed_deferred_volume_is_bought_back_before_the_late_pass_reads_it() {
    let (dir, _scratch) = scratch("buyback");
    let (member, want, vols) = wholly_missing_set(&dir, "Charlie.Three.bin", 41);
    let cancelled = hole_the_tail(&vols[0]);
    let slots = [lost_slot("Charlie.Three.bin", 5)];

    // 1. The defect. 100% parity and no margin: the blocks inside the
    //    hole are exactly the ones the rebuild needs.
    run_pass(&dir, &slots, vec![LOST_DECL]);
    assert!(
        !member.exists(),
        "the fixture did not reproduce the measured shape - the member \
         rebuilt off a HOLED volume, so either the hole missed every \
         recovery slice or the set carries margin this row assumes it \
         does not"
    );

    // 2. The fix's decision.
    let holed = [(VOL_FILE_INDEX, vols[0].clone())];
    assert_eq!(
        super::holed_deferred_volumes(&dir, &[], &holed, false),
        vec![VOL_FILE_INDEX],
        "the late-set pass is about to repair a set off a volume the \
         in-stream cancel left holed, and nothing asked for the cancelled \
         articles back - which on a clean-live-set job is the ONLY route \
         there is, because the repair's exact-fit list is built per \
         damaged LIVE set and there is no plan at all"
    );

    // 3. What the decision buys. `fetch_volumes` re-decodes the whole
    //    volume to the same path, which is these bytes.
    std::fs::write(&vols[0], &cancelled).unwrap();
    run_pass(&dir, &slots, vec![LOST_DECL]);
    assert_eq!(
        std::fs::read(&member).ok(),
        Some(want),
        "with its parity whole the set still did not rebuild the member - \
         the refetch is reaching the volume but not the pass"
    );
}

/// THE NEGATIVE CONTROL, and it grades the half a fix is easy to get
/// wrong: every door that must answer NO.
///
/// The deferral's cancel is a measured bandwidth saving - a refetch that
/// fires whenever a volume is holed simply undoes it. Each arm below is
/// a job that must not spend a byte, and they are in one row so that a
/// selector loosened to make the row above pass cannot quietly leave any
/// of them behind.
#[test]
fn a_job_that_does_not_need_the_deferred_parity_does_not_buy_it() {
    let (dir, _scratch) = scratch("nobuy");
    let (_member, _want, vols) = wholly_missing_set(&dir, "Charlie.Three.bin", 41);
    hole_the_tail(&vols[0]);
    let holed = [(VOL_FILE_INDEX, vols[0].clone())];

    // Door 1: the download is COMPLETE. Nothing is outstanding, so the
    // pass has nothing to rebuild and the saving stands.
    assert!(
        super::holed_deferred_volumes(&dir, &[], &holed, true).is_empty(),
        "a complete download re-bought parity it had deliberately \
         cancelled - this is the bandwidth saving issue #14 exists for, \
         and the fix must not fire on the healthy path"
    );

    // Door 3: the set is ALREADY ACTIVE. Its parity is the repair's
    // exact-fit fetch's business, and buying it here buys it twice.
    let active: Vec<Arc<nzbkit::par2::Par2Set>> =
        nzbkit::live::pick_sets(&[std::fs::read(&vols[0]).unwrap().as_slice()])
            .expect("the holed volume still carries its definition")
            .into_iter()
            .map(Arc::new)
            .collect();
    assert!(
        !active.is_empty(),
        "the fixture needs the holed volume to still parse, or door 3 is \
         not the door being tested"
    );
    assert!(
        super::holed_deferred_volumes(&dir, &active, &holed, false).is_empty(),
        "a volume of an ACTIVE set was put on the late pass's fetch list - \
         the exact-fit path owns that set's parity and this is a second \
         buyer for the same bytes"
    );

    // Door 3 again, from the other side: a file that is not recovery
    // data at all. The sniff's magic test can be wrong, and a PAYLOAD
    // refetched from here would be bytes bought for nobody.
    let notpar2 = dir.join("payload.bin");
    std::fs::write(&notpar2, payload(50_000, 99)).unwrap();
    assert!(
        super::holed_deferred_volumes(&dir, &[], &[(VOL_FILE_INDEX, notpar2)], false).is_empty(),
        "a file carrying no recovery set id was fetched as a recovery volume"
    );

    // Door 4: the set's member is WHOLE on disk, so the set has nothing
    // left to do and its remaining parity is worth nothing to this job.
    std::fs::write(dir.join("Charlie.Three.bin"), payload(MEMBER_LEN, 41)).unwrap();
    assert!(
        super::holed_deferred_volumes(&dir, &[], &holed, false).is_empty(),
        "parity was bought for a set every one of whose members is already \
         on disk at its declared length"
    );
}

/// Door 2: the pass's OWN door, asked before a byte is spent.
///
/// [`super::apply_nonactivated_disk_sets`] returns before its first
/// census when nothing in the directory is unclaimed, so a fetch past
/// this test would be a fetch for a pass that never runs. Its own row
/// because it needs a directory WITHOUT the sidecar every other row here
/// plants, which is the one fixture difference in the file.
#[test]
fn nothing_is_bought_for_a_pass_that_will_not_run() {
    let (dir, _scratch) = scratch("nodoor");
    std::fs::remove_file(dir.join("unclaimed.nfo")).unwrap();
    let (_member, _want, vols) = wholly_missing_set(&dir, "Charlie.Three.bin", 41);
    hole_the_tail(&vols[0]);

    assert!(
        super::holed_deferred_volumes(&dir, &[], &[(VOL_FILE_INDEX, vols[0].clone())], false)
            .is_empty(),
        "parity was fetched for a late-set pass that returns on \
         `has_unclaimed` before its first census - the door is asked here \
         rather than copied so the two can never disagree"
    );
}
