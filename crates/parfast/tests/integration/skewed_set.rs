//! A set with ONE DOMINANT MEMBER, through the verify command.
//!
//! `survey_inner` hashes members CONCURRENTLY and prints from `verdicts`
//! in the SET's order, and since 16 Sep 2026 it claims them biggest-first
//! with a lane budget split by size (entry 1 of
//! `research/SERIAL-BOUND-SURVEY-2026-09-16.md`: the uniform
//! `machine / width` division handed the dominant member one lane of
//! eighteen and cost 8.6x). Two separate things could break in that:
//!
//! 1. the printed ORDER, if the hashing order ever reached the output;
//! 2. the VERDICTS, if a lane width changed an answer.
//!
//! So this runs the same skewed set at three outer widths - the default,
//! `-T1` (the whole machine on one member at a time, the schedule that
//! measured 0.36 s against the default's 3.87 s) and `-T21` - and holds
//! all three to byte-identical stdout, clean and damaged. A set whose
//! members were all one size could not see either defect, and every other
//! parfast fixture in this tree is exactly that.
use std::path::PathBuf;

use crate::scratch::{Scratch, scratch};

const BLOCK: usize = 65_536;
/// Three quarters of the bytes in one member, which is the ratio the
/// measured corpus had. 96 blocks against twenty single-block sidecars.
const DOMINANT_BLOCKS: usize = 96;
const SIDECARS: usize = 20;

fn noise(len: usize, seed: u32) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect()
}

fn run(args: &[String]) -> (u8, String, String) {
    let mut sink = parfast::out::Sink::buffered();
    let code = parfast::run_with("parfast", args, &mut sink);
    let (out, err) = sink.take();
    (code, out, err)
}

fn arg(s: &str) -> String {
    s.to_string()
}

/// The corpus and its set. Returns the scratch directory alongside the
/// set path and the dominant member's path: the guard OWNS the tree
/// those two paths point into, so a caller that dropped it here would
/// be handed two paths to a directory that had just been removed.
fn skewed_set(tag: &str) -> (Scratch, PathBuf, PathBuf) {
    let dir = scratch(tag);
    let big = dir.join("feature.mkv");
    std::fs::write(&big, noise(BLOCK * DOMINANT_BLOCKS, 1)).expect("payload");
    let mut args = vec![arg("c"), arg("-q"), arg(&format!("-s{BLOCK}")), arg("-c8")];
    let set = dir.join("feature.par2");
    args.push(arg(&set.to_string_lossy()));
    args.push(arg(&big.to_string_lossy()));
    for i in 0..SIDECARS {
        let side = dir.join(format!("sidecar{i:02}.nfo"));
        std::fs::write(&side, noise(BLOCK, 0x100 + i as u32)).expect("sidecar");
        args.push(arg(&side.to_string_lossy()));
    }
    let (code, _, err) = run(&args);
    assert_eq!(code, 0, "fixture create failed: {err}");
    (dir, set, big)
}

/// Every outer width prints the same lines in the same order and exits
/// the same way - clean, and then with the dominant member holed.
#[test]
fn the_outer_width_changes_no_line_of_a_skewed_verify() {
    let (_dir, set, big) = skewed_set("skewed-set");
    let widths = ["", "-T1", "-T21", "-T3"];
    let mut clean: Vec<(u8, String)> = Vec::new();
    for w in widths {
        let mut args = vec![arg("v")];
        if !w.is_empty() {
            args.push(arg(w));
        }
        args.push(arg(&set.to_string_lossy()));
        let (code, out, err) = run(&args);
        assert_eq!(code, 0, "clean verify at {w:?} failed: {err}");
        clean.push((code, out));
    }
    for (w, got) in widths.iter().zip(&clean) {
        assert_eq!(got, &clean[0], "{w:?} printed a different clean verify");
    }
    assert!(
        clean[0].1.contains("feature.mkv"),
        "the dominant member is named in the output"
    );

    // Hole the dominant member: the damaged verdict is the one a repair
    // reads, and it must not depend on the schedule either.
    let mut holed = std::fs::read(&big).expect("payload");
    for b in &mut holed[BLOCK * 5..BLOCK * 6] {
        *b ^= 0xFF;
    }
    std::fs::write(&big, &holed).expect("hole");
    let mut damaged: Vec<(u8, String)> = Vec::new();
    for w in widths {
        let mut args = vec![arg("v")];
        if !w.is_empty() {
            args.push(arg(w));
        }
        args.push(arg(&set.to_string_lossy()));
        let (code, out, _) = run(&args);
        damaged.push((code, out));
    }
    assert_ne!(damaged[0].0, 0, "a holed member is not a clean verify");
    for (w, got) in widths.iter().zip(&damaged) {
        assert_eq!(got, &damaged[0], "{w:?} printed a different damaged verify");
    }

    // The other tier, on its own copy of the same shape, in this same
    // test: see that function's note on why it is not a test of its own.
    the_slow_tier_agrees_at_every_outer_width("skewed-set-slow");
}

/// The SAME shape under `--slow`, where the tier is the FileDesc
/// whole-file MD5 and a member's verdict is one serial chain that no
/// number of inner lanes can widen.
///
/// This arm exists because the fix narrows the OUTER width - six workers
/// on the measured corpus where the uniform division ran twenty-one - and
/// on this tier the outer width is the only parallelism there is. The
/// wall is still set by the dominant member's own chain either way (its
/// share of the budget is the largest, so it is claimed first and runs
/// alone for longer than every short member put together), but "still
/// correct at every width" is the part a test can hold, and nothing else
/// in the tree verifies a dominant-member set on this tier at all.
///
/// NOT a `#[test]` of its own, deliberately: the tier is a process
/// GLOBAL that `parfast::run_with` sets on EVERY run
/// (`par2::set_fast_check`, lib.rs), and these runs are in-process. Two
/// test functions flipping it would race under `cargo test`, which runs a
/// target's tests as threads in one process - nextest's per-test process
/// hides that, which is exactly why it must not be written that way here.
/// Called from the test above, after it finishes with the default tier.
fn the_slow_tier_agrees_at_every_outer_width(dir_tag: &str) {
    let (_dir, set, big) = skewed_set(dir_tag);
    let widths = ["", "-T1", "-T21", "-T3"];
    let slow = |w: &str, set: &PathBuf| {
        let mut args = vec![arg("v"), arg("--slow")];
        if !w.is_empty() {
            args.push(arg(w));
        }
        args.push(arg(&set.to_string_lossy()));
        let (code, out, err) = run(&args);
        (code, out, err)
    };
    let clean: Vec<(u8, String)> = widths
        .iter()
        .map(|w| {
            let (code, out, err) = slow(w, &set);
            assert_eq!(code, 0, "clean --slow verify at {w:?} failed: {err}");
            (code, out)
        })
        .collect();
    for (w, got) in widths.iter().zip(&clean) {
        assert_eq!(got, &clean[0], "--slow {w:?} printed a different verify");
    }

    let mut holed = std::fs::read(&big).expect("payload");
    for b in &mut holed[BLOCK * 5..BLOCK * 6] {
        *b ^= 0xFF;
    }
    std::fs::write(&big, &holed).expect("hole");
    let damaged: Vec<(u8, String)> = widths
        .iter()
        .map(|w| {
            let (code, out, _) = slow(w, &set);
            (code, out)
        })
        .collect();
    assert_ne!(damaged[0].0, 0, "a holed member is not a clean verify");
    for (w, got) in widths.iter().zip(&damaged) {
        assert_eq!(
            got, &damaged[0],
            "--slow {w:?} printed a different damaged verify"
        );
    }
    // The tier is a GLOBAL (`par2::set_fast_check`), and every run above
    // set it to the slow value. Put it back the way a default run leaves
    // it, so a test that shares this process and does not set it
    // explicitly cannot inherit this one's choice.
    nzbkit::par2::clear_fast_check();
}
