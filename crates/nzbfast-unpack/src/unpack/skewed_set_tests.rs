//! A PAR2 set with ONE DOMINANT MEMBER, which no corpus in this tree had.
//!
//! The shape is the ordinary one this driver meets on a bare-file post: a
//! single large payload with small sidecars beside it (`.nfo`, `.sfv`, a
//! sample), rather than the equal-volume RAR release every other PAR2
//! fixture here is. Its absence is exactly why the defect entry 1 of
//! `research/SERIAL-BOUND-SURVEY-2026-09-16.md` measured - `verify_dir`
//! dividing the machine ONCE, uniformly, so the dominant member was
//! hashed by one lane of eighteen and set the whole wall by itself -
//! survived every suite in the repo for as long as it did. Measured
//! there: the same 4 GiB verified in 0.45 s as one member and 3.87 s as
//! twenty-one, with user CPU flat across the table, so the 8.6x was pure
//! loss of concurrency.
//!
//! Two things are pinned, and they are the two that can break
//! separately:
//!
//! 1. the SCHEDULE - the dominant member gets a proportional share of the
//!    lane budget rather than one lane, and the budget is never
//!    oversubscribed. A revert to `machine / workers` fails this;
//! 2. the VERDICT - every member's block bitmap and MD5 flags are the
//!    same at every lane width. A scheduling change that alters a verdict
//!    is not a scheduling change, which is why the survey's acceptance
//!    ran an FNV digest of the bitmaps on both arms.
//!
//! Small on purpose: 12 MiB dominant against 20 x 64 KiB sidecars is the
//! same RATIO the measured corpus had (three quarters of the bytes in one
//! member) at a thousandth of the bytes, and it clears the 8 MiB
//! `VERIFY_PAR_MIN_BYTES` floor so the parallel block path is the one
//! actually exercised. The set is index-only (`redundancy_pct: 0`): it
//! carries the FileDesc and IFSC this pass reads and none of the
//! Reed-Solomon it does not.
use super::*;

const DOMINANT_BYTES: usize = 12 << 20;
const SIDECARS: usize = 20;
const SIDECAR_BYTES: usize = 64 << 10;
const BLOCK: u64 = 64 << 10;

fn scratch(tag: &str) -> crate::testscratch::ScratchDir {
    crate::testscratch::ScratchDir::attach(&std::env::temp_dir().join(format!(
        "nzbfast-skewset-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )))
}

fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut data = vec![0u8; len];
    let mut x = seed | 1;
    for b in &mut data {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    data
}

/// The corpus: one dominant member, twenty sidecars, one real set over
/// all of them. Returns the directory and the dominant member's bytes.
fn skewed_set(tag: &str) -> (crate::testscratch::ScratchDir, Vec<u8>) {
    let dir = scratch(tag);
    let big = noise(DOMINANT_BYTES, 0x9E37_79B9);
    std::fs::write(dir.join("feature.mkv"), &big).unwrap();
    let mut members = vec![nzbkit::par2gen::Member {
        name: "feature.mkv".to_string(),
        path: dir.join("feature.mkv"),
    }];
    for i in 0..SIDECARS {
        let name = format!("sidecar{i:02}.nfo");
        std::fs::write(dir.join(&name), noise(SIDECAR_BYTES, 0x1000 + i as u32)).unwrap();
        members.push(nzbkit::par2gen::Member {
            name: name.clone(),
            path: dir.join(&name),
        });
    }
    nzbkit::par2gen::create_into(
        &dir,
        &members,
        "feature",
        &nzbkit::par2gen::Par2Spec {
            redundancy_pct: 0,
            block_size: Some(BLOCK),
        },
    )
    .expect("par2 set written");
    (dir, big)
}

/// The member sizes the driver plans over, biggest first - derived the
/// same way `verify_dir` derives them, off the SET rather than off the
/// fixture's own constants, so a change in how the set is written cannot
/// leave this test planning over a shape that is no longer on disk.
fn set_sizes(dir: &std::path::Path) -> Vec<u64> {
    let (bytes, _) = collect_par2_bytes(dir, 64 << 20).unwrap();
    let refs: Vec<&[u8]> = bytes.iter().map(|v| v.as_slice()).collect();
    let sets = nzbkit::live::pick_sets(&refs).expect("set parses");
    let mut sizes: Vec<u64> = sets
        .iter()
        .flat_map(|s| s.files.iter().map(|f| f.length))
        .collect();
    sizes.sort_unstable_by_key(|&n| std::cmp::Reverse(n));
    sizes
}

/// THE DEFECT, as a schedule rather than as a clock: the member holding
/// most of the bytes must get most of the lanes.
///
/// `lane_plan` is the function `verify_dir` calls, with the arguments
/// `verify_dir` passes; the arithmetic is not copied here. A revert to
/// the `(machine / workers).max(1)` division this replaced gives the
/// dominant member ONE lane on any box with fewer cores than this set has
/// members, which is what the first assertion refuses.
#[test]
fn the_dominant_member_gets_a_proportional_share_of_the_lane_budget() {
    let (dir, _) = skewed_set("schedule");
    let sizes = set_sizes(&dir);
    assert_eq!(sizes.len(), SIDECARS + 1);
    assert_eq!(sizes[0], DOMINANT_BYTES as u64, "biggest first");

    for machine in 2..=18usize {
        let lanes = nzbkit::par2::lane_plan(&sizes, machine, sizes.len());
        assert!(
            lanes.iter().sum::<usize>() <= machine,
            "one global lane budget, never oversubscribed ({machine} cores)"
        );
        assert!(lanes.iter().all(|&n| n >= 1));
        let uniform = (machine / machine.min(sizes.len())).max(1);
        assert!(
            lanes[0] > uniform || machine == 2,
            "the dominant member must beat the uniform division at \
             {machine} cores (got {lanes:?})"
        );
    }
    // The measured box, spelled out: 12 of 13.25 MiB in one member is
    // sixteen of eighteen lanes, against the one lane it used to get.
    let lanes = nzbkit::par2::lane_plan(&sizes, 18, sizes.len());
    assert_eq!(lanes[0], 16);
    assert!(
        lanes.len() < sizes.len(),
        "fewer outer workers than members"
    );
}

/// THE VERDICT, which the schedule must not touch: the same bitmap and
/// the same MD5 flags at every lane width, clean and holed.
///
/// This is the fixture's half of the survey's FNV-digest acceptance -
/// `nzbkit`'s `par2_verify_bench` prints that digest over a real corpus,
/// and this pins the same identity over a corpus that lives in the tree.
#[test]
fn every_lane_width_reaches_the_same_verdict_on_the_dominant_member() {
    let (dir, big) = skewed_set("verdict");
    let (bytes, _) = collect_par2_bytes(&dir, 64 << 20).unwrap();
    let refs: Vec<&[u8]> = bytes.iter().map(|v| v.as_slice()).collect();
    let sets = nzbkit::live::pick_sets(&refs).expect("set parses");
    let set = &sets[0];
    let file = set
        .files
        .iter()
        .find(|f| f.name == "feature.mkv")
        .expect("the dominant member is in the set");
    let path = dir.join("feature.mkv");

    let widths = [1usize, 2, 3, 5, 16, 64];
    let mut clean = Vec::new();
    for w in widths {
        let v = nzbkit::par2::verify_file_path(&path, file, set.block_size, w).unwrap();
        clean.push((v.blocks.clone(), v.md5_ok, v.md5_16k_ok));
    }
    assert!(
        clean[0].1 && clean[0].2,
        "the fixture writes a clean member"
    );
    assert!(clean[0].0.iter().all(|&ok| ok));
    for (w, got) in widths.iter().zip(&clean) {
        assert_eq!(got, &clean[0], "width {w} reached a different verdict");
    }

    // ...and holed, where the bitmap is the answer the repair reads. Two
    // holes, one at a block boundary and one straddling two blocks, so a
    // range split that lands between them cannot hide either.
    let mut holed = big.clone();
    for b in &mut holed[(BLOCK as usize) * 3..(BLOCK as usize) * 4] {
        *b ^= 0xFF;
    }
    let straddle = (BLOCK as usize) * 100 - 16;
    for b in &mut holed[straddle..straddle + 32] {
        *b ^= 0xA5;
    }
    std::fs::write(&path, &holed).unwrap();
    let mut damaged = Vec::new();
    for w in widths {
        let v = nzbkit::par2::verify_file_path(&path, file, set.block_size, w).unwrap();
        damaged.push((v.blocks.clone(), v.md5_ok, v.md5_16k_ok));
    }
    assert!(!damaged[0].1, "a holed member is not clean");
    assert_eq!(
        damaged[0].0.iter().filter(|ok| !**ok).count(),
        3,
        "block 3 and the two block 99/100 straddles"
    );
    for (w, got) in widths.iter().zip(&damaged) {
        assert_eq!(got, &damaged[0], "width {w} reached a different verdict");
    }
}

/// The whole driver over the skewed shape, both answers. `verify_dir` is
/// what the daemon's post-download pass, `nzbfast verify` and
/// `nzbfast extract` all call, and it is the copy of the rule that this
/// fixture's shape defeated.
#[test]
fn verify_dir_reads_the_skewed_set_clean_and_then_damaged() {
    let (dir, big) = skewed_set("driver");
    assert_eq!(verify_dir(&dir).unwrap(), DirVerify::Clean);
    let mut holed = big.clone();
    for b in &mut holed[(BLOCK as usize) * 7..(BLOCK as usize) * 8] {
        *b ^= 0xFF;
    }
    std::fs::write(dir.join("feature.mkv"), &holed).unwrap();
    assert_eq!(verify_dir(&dir).unwrap(), DirVerify::Damaged);
    // A damaged SIDECAR is the same verdict from the other end of the
    // size distribution - the lanes the dominant member is now holding
    // must not cost the short members their own pass.
    std::fs::write(dir.join("feature.mkv"), &big).unwrap();
    assert_eq!(verify_dir(&dir).unwrap(), DirVerify::Clean);
    let mut bad = noise(SIDECAR_BYTES, 0x1000);
    bad[10] ^= 0xFF;
    std::fs::write(dir.join("sidecar00.nfo"), &bad).unwrap();
    assert_eq!(verify_dir(&dir).unwrap(), DirVerify::Damaged);
}
