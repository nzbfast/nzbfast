//! X5-24 through the WHOLE late-set pass, deterministically: a foreign
//! set's rebuild is dropped and an entitled set's rebuild is kept.
//!
//! A sibling file rather than a block in `latesets.rs`'s own `tests`
//! module, by the rule this directory already runs on - one subject per
//! file, beside `shape_tests`, `par2_window_tests` and `cancel_tests`.
//!
//! # Why this exists (claim `e2e-x5-24-signature2-recreate-16sep`)
//!
//! Until 16 Sep 2026 the only thing grading this end to end was
//! `e2e_lateset::x5_24_control_a_foreign_set_must_never_be_assigned`,
//! and that probe is a TIMING-DEPENDENT FLAKE - measured 2/25 and 3/25
//! on 3 Sep 2026, 3/100 on 16 Sep, and e2e runs on every push, so it
//! reddens main for whoever pushes next. `latesets.rs`'s own unit rows
//! drive [`super::assign_by_length`] and [`super::decide`] directly,
//! which grades the RULE but not the pass: whether a declined residual
//! is actually gone from the output directory once every round has run
//! is a property of [`super::apply_nonactivated_disk_sets`], and
//! nothing asserted it without a mock NNTP server and a race.
//!
//! IT COST A DAY OF SOMEBODY'S TIME THAT IT DID NOT. The 3 Sep handoff
//! recorded a second failure signature for that probe - "the gate RUNS
//! and declines correctly, and `Not.Ours.bin` is in the output
//! directory anyway" - and minted a claim for the engine defect behind
//! it. There is no such defect, and there structurally cannot be: the
//! decline is the LAST mutation the pass makes (`late_set_tiers` runs
//! after the round loop, and nothing between it and the end of settle
//! writes a payload file), so no later round can re-create what an
//! earlier round's decline dropped. What that probe actually fails on
//! is its NEXT assertion - `left: 0, right: 180000`, the entitled
//! member not rebuilt - for a reason one seam away
//! (`research/E2E-X5-24-SIGNATURE-2-IS-A-MISREAD-2026-09-16.md`).
//!
//! So both halves are pinned HERE, where they are decidable without a
//! clock: the foreign rebuild is dropped, and the entitled one is kept.
//! A reader who sees the e2e probe red again can run these two and know
//! in seconds whether the GATE is what moved.
//!
//! IN PROCESS AND WITHOUT THE `par2` BINARY, like `cancel_tests`:
//! `par2gen::create_into` builds the sets here, so `tools/par2-gate.py`'s
//! `have_par2()` guard is not owed and a box with no `par2` installed
//! runs these like any other row.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};

/// Block size every set here is built at, so a member's block count is
/// its length over this and the parity below is whole-file.
const BLOCK: u64 = 10_000;

/// One payload file plus a recovery set over it ALONE at 100% parity -
/// enough for the set to rebuild the member from nothing - then the
/// payload is deleted, which is the wholly-missing shape both rows are
/// about. Answers the payload's path and its correct bytes.
fn wholly_missing_set(
    dir: &std::path::Path,
    name: &str,
    len: usize,
    seed: u64,
) -> (PathBuf, Vec<u8>) {
    // UNRELATED STREAMS, and it has to be said why, because the obvious
    // `(i * k + seed) as u8` is WRONG here and looked right for one
    // build. That form is periodic in `i` and the seed is a constant
    // OFFSET, so two payloads written from it are the same sequence at
    // a shift - and `par2repair::adopt`'s sliding scan finds a member's
    // block in another file at ANY offset. The foreign set then adopted
    // its own block out of the entitled member's rebuilt bytes,
    // `file_had_bytes_on_disk` answered true, `residual_creations`
    // yielded nothing for it, and the gate never got to judge the one
    // file this row exists to judge. The rebuild was KEPT and the row
    // failed for a reason that was entirely the fixture's.
    let data: Vec<u8> = {
        let mut x = 0x9E37_79B9_7F4A_7C15u64 ^ seed.wrapping_mul(0xD1B5_4A32_D192_ED03);
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    };
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
            redundancy_pct: 100,
            block_size: Some(BLOCK),
        },
    )
    .expect("par2gen builds the set");
    std::fs::remove_file(&path).expect("the member is WHOLLY missing");
    (path, data)
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

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str) -> (PathBuf, Scratch) {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-lateset-foreign-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // THE DOOR. `apply_nonactivated_disk_sets` returns before its first
    // census unless `has_unclaimed` finds a file no active set names and
    // that is not itself recovery data - which, once both members below
    // are deleted, nothing in the directory is. The real shape always
    // has one (the post's own arrived payload, still wearing a hash), so
    // this is the fixture standing in for it rather than a special case.
    //
    // SHORTER THAN ONE BLOCK on purpose: every regular file here is an
    // adoption candidate, and a few dozen bytes cannot carry one.
    std::fs::write(
        dir.join("unclaimed.nfo"),
        b"a sidecar no recovery set names\n",
    )
    .unwrap();
    (dir.clone(), Scratch(dir))
}

/// Run the whole pass over `dir` with `slots` and no active sets, so
/// every set on disk is non-activated and nothing vouches for any of
/// them - `mine` is false throughout, which is the `!mine` residual
/// family both rows grade.
///
/// `all_good` goes in FALSE and `incomplete` as the short count, which
/// is the shape settle hands it for a download that lost a whole file:
/// the verdict arithmetic is a different row's subject, but handing in
/// a job that is already good would let `keep_uniquely_assignable_residuals`
/// be reached with nothing outstanding and grade the wrong thing.
fn run_pass(
    dir: &std::path::Path,
    slots: &[Arc<FileSlot>],
    slot_bytes: Vec<u64>,
) -> (bool, Option<crate::repair::RepairShortfall>) {
    let extractor = Arc::new(nzbkit::extract::Extractor::new(dir, 0, false));
    super::apply_nonactivated_disk_sets(
        &[],
        dir,
        slots,
        &extractor,
        super::Outstanding(false, slots.len(), 0, slot_bytes, None),
        None,
    )
}

/// THE ROW: a recovery set for a file this post never offered a slot
/// for must not leave that file in the output directory - and the
/// statement is about the state AFTER every round, not about the log.
///
/// Both sets are wholly-missing one-member sets at 100% parity, so both
/// rebuild. `Entitled.bin` is 180,000 bytes and the post declares a
/// wholly-lost slot of 185,400 encoded bytes over 5 articles for it;
/// `Foreign.bin` is 90,000 and the post declares nothing at all. Under
/// [`super::fits`] the shared band admits the first pairing (185,400 is
/// inside 162,000..217,280) and refuses the second (185,400 is outside
/// 81,000..109,280), so the post decides one and cannot decide the other
/// - which is the whole of X5-24's rule.
#[test]
fn a_foreign_sets_rebuild_is_not_left_in_the_output_directory() {
    let (dir, _scratch) = scratch("drop");
    let (entitled, want) = wholly_missing_set(&dir, "Entitled.bin", 180_000, 11);
    let (foreign, _) = wholly_missing_set(&dir, "Foreign.bin", 90_000, 22);
    let slots = [lost_slot("Entitled.bin", 5)];

    let (good, _) = run_pass(&dir, &slots, vec![185_400]);

    assert!(
        !foreign.exists(),
        "a recovery set for a file this post never offers a slot for was \
         materialised into the output directory and left there - X5-24's \
         decline either did not run or did not remove the file"
    );
    // THE NEGATIVE CONTROL, and it has to be in the same row as the
    // assertion above: a pass that stopped writing anything at all - or
    // one whose gate declined everything - satisfies the drop and is
    // not a fix. The entitled member must come back BYTE-EXACT, which
    // is stronger than "exists": it is what the set MD5-proved.
    assert_eq!(
        std::fs::read(&entitled).ok(),
        Some(want),
        "the foreign set in the same directory cost the uniquely \
         assignable member its rebuild"
    );
    assert!(
        good,
        "every short slot is accounted for by a rebuild the pass kept, so \
         the pass owes the job its green"
    );
}

/// The other side of the same rule, and the reason the row above cannot
/// be met by a gate that simply keeps everything: TWO wholly missing
/// slots of EQUAL declared size make the pairing undecidable, so a
/// rebuild that fits both must be dropped rather than picked.
///
/// [`super::decide`]'s "lost more than one whole file of that size",
/// driven through the pass rather than through the fit table (which
/// `latesets.rs`'s own rows already pin) because what is graded is
/// again the FILE: an undecidable rebuild is deleted, not merely
/// uncredited.
///
/// ITS OWN CONTROL RIDES WITH IT, in the same directory and the same
/// call: "the ambiguous rebuild is absent" is satisfied by a pass that
/// never ran at all (this one returns before its first census unless
/// `has_unclaimed` opens the door), so an entitled set beside it has to
/// come back byte-exact for the absence to mean anything.
#[test]
fn an_undecidable_rebuild_is_dropped_rather_than_picked() {
    let (dir, _scratch) = scratch("ambiguous");
    let (ambiguous, _) = wholly_missing_set(&dir, "Ambiguous.bin", 120_000, 33);
    let (entitled, want) = wholly_missing_set(&dir, "Entitled.bin", 180_000, 44);
    // Two slots declaring the same encoded size, both wholly lost: the
    // 120,000-byte rebuild fits both and can be neither. The third
    // declares 185,400 over 5, which only the 180,000-byte rebuild fits
    // - 123,600 is under its 0.9 floor, and 185,400 is over the
    // 120,000-byte rebuild's ceiling.
    let slots = [
        lost_slot("a.bin", 4),
        lost_slot("b.bin", 4),
        lost_slot("Entitled.bin", 5),
    ];

    let (good, _) = run_pass(&dir, &slots, vec![123_600, 123_600, 185_400]);

    assert!(
        !ambiguous.exists(),
        "a rebuild that fits two equal losses was picked for one of them - \
         ambiguity must decline, and the decline removes the file"
    );
    assert_eq!(
        std::fs::read(&entitled).ok(),
        Some(want),
        "the pass rebuilt nothing at all, so the absence above says nothing \
         about the gate"
    );
    assert!(
        !good,
        "two of the three short slots are still unaccounted for, so the \
         pass must not green the job"
    );
}
