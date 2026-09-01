//! Wave-4 row X6-02: adoption source discovery and target resolution
//! must share one namespace.
//!
//! [`super::adoption_candidates`] was a flat `read_dir` while every
//! `Target::path` resolves through `join_out_name`, so a tree-named set
//! - a disc post spelling `VIDEO_TS/VTS_01_1.VOB` - had NO adoption
//! candidate at all and the repair priced its payload wholly missing.
//! These pins are on the candidate list rather than on a whole repair
//! because that list is the decision: what is in it is what the sliding
//! scan may read from, what the `identified` gate may exclude, and what
//! the spent-donor sweep may later unlink.
//!
//! Each of the six was verified to bite by reverting the walk to
//! `std::fs::read_dir(d)` and watching the named assertion fail; the
//! flat-order case is the CONTROL and correctly survives that revert,
//! because its whole claim is that an unchanged tree yields an
//! unchanged answer.

use super::*;

/// A `ScratchDir` and not a bare `PathBuf`, for the reason `tests.rs`
/// next door gives: a helper that creates under `temp_dir()` and never
/// removes leaves one `$TMPDIR` entry per tag per RUN, forever. These
/// six were leaking on every green CI sweep within hours of landing -
/// see `research/TMPDIR-SCRATCH-LEAK-2026-08-31.md`. The guard also
/// clears on entry, which is what the two lines it replaced did.
fn tmpdir(tag: &str) -> crate::testscratch::ScratchDir {
    crate::testscratch::ScratchDir::attach(&std::env::temp_dir().join(format!(
        "nzbfast-adoptwalk-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )))
}

fn write(p: &Path, bytes: &[u8]) {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(p, bytes).unwrap();
}

/// A `Target` naming `name` relative to `dir`, resolved the way
/// `repair_dir_set` resolves one - through `join_out_name`, which is the
/// half of the namespace that was already tree-correct.
fn tree_target(dir: &Path, name: &str, length: u64, identified: bool) -> Target {
    Target {
        file: Par2File {
            file_id: [1u8; 16],
            name: name.into(),
            length,
            md5: [0u8; 16],
            md5_16k: [0u8; 16],
            blocks: Vec::new(),
        },
        path: crate::disk::join_out_name(dir, &crate::disk::sanitize_out_name(name)),
        first_slice: 0,
        n_slices: 1,
        present: vec![identified],
        intact: false,
        exists: identified,
        resume: None,
    }
}

fn names(dir: &Path, got: &[(PathBuf, u64)]) -> Vec<String> {
    got.iter()
        .map(|(p, _)| crate::disk::out_name_of(dir, p))
        .collect()
}

fn candidates(dir: &Path, donors: &[PathBuf], targets: &[Target]) -> (Vec<(PathBuf, u64)>, usize) {
    adoption_candidates(dir, donors, targets, &HashSet::new()).expect("candidates")
}

/// The row's arm 1: a tree-named set whose payload sits under an
/// obfuscated hash name INSIDE the tree it declares.
#[test]
fn a_source_one_directory_down_is_a_candidate() {
    let dir = &tmpdir("treesrc");
    write(&dir.join("VIDEO_TS/a1b2c3d4"), b"payload bytes");
    let targets = [tree_target(dir, "VIDEO_TS/VTS_01_1.VOB", 13, false)];
    let (got, donor_from) = candidates(dir, &[], &targets);
    assert_eq!(names(dir, &got), vec!["VIDEO_TS/a1b2c3d4"]);
    assert_eq!(donor_from, 1, "a repair-dir file is not a donor");
}

/// The row's arm 2: a DONOR directory holding a predecessor's
/// tree-shaped output (§293). Donors ride the same closure, so this was
/// the same blindness one argument further along.
#[test]
fn a_donor_tree_donates() {
    let d = tmpdir("donortree");
    let dir = d.join("job");
    let donor = d.join("prev");
    write(&dir.join("root.bin"), b"here");
    write(&donor.join("VIDEO_TS/left.vob"), b"there");
    let (got, donor_from) = candidates(&dir, std::slice::from_ref(&donor), &[]);
    assert_eq!(donor_from, 1, "the repair dir's own file comes first");
    assert_eq!(crate::disk::out_name_of(&dir, &got[0].0), "root.bin");
    assert_eq!(
        got.len(),
        2,
        "the donor's tree file must be offered: {got:?}"
    );
    assert_eq!(
        crate::disk::out_name_of(&donor, &got[1].0),
        "VIDEO_TS/left.vob"
    );
}

/// The CONTROL. A directory with no subdirectories must yield exactly
/// the list the flat walk yielded, in exactly its order - the standard
/// this module's fan-out is held to at `sliding_scan`, applied to the
/// reach: it may widen, an adoption decision on an unchanged tree may
/// not. This case is expected to PASS against the pre-fix walk.
#[test]
fn a_flat_directory_answers_exactly_as_it_always_did() {
    let dir = &tmpdir("flat");
    for n in ["c.bin", "a.bin", "b.bin"] {
        write(&dir.join(n), b"x");
    }
    let (got, _) = candidates(dir, &[], &[]);
    assert_eq!(names(dir, &got), vec!["a.bin", "b.bin", "c.bin"]);
}

/// Depth before name, so the shallowest copy of a name still wins the
/// first-candidate-wins race. A plain path sort puts `VIDEO_TS/z.bin`
/// in front of `zz.bin` and would have reordered the root against
/// itself on any tree post.
#[test]
fn the_root_is_offered_before_anything_below_it() {
    let dir = &tmpdir("depth");
    write(&dir.join("zz.bin"), b"x");
    write(&dir.join("AAA/z.bin"), b"y");
    let (got, _) = candidates(dir, &[], &[]);
    assert_eq!(names(dir, &got), vec!["zz.bin", "AAA/z.bin"]);
}

/// `get::latesets` hands this function `nested_subdirs(out_dir)` as
/// DONORS - a workaround for this very defect - so with the walk fixed
/// every file under the job arrives twice. Folded to one, first
/// occurrence kept, and the donor boundary still says where the repair
/// dir's own files stopped.
#[test]
fn a_subdirectory_offered_as_its_own_donor_is_not_offered_twice() {
    let dir = &tmpdir("dedupe");
    write(&dir.join("META/inner.bin"), b"once");
    let sub = dir.join("META");
    let (got, donor_from) = candidates(dir, std::slice::from_ref(&sub), &[]);
    assert_eq!(names(dir, &got), vec!["META/inner.bin"]);
    assert_eq!(donor_from, 1, "the file was found as the repair dir's own");
}

/// The exclusion the flat walk could never apply, because on a
/// tree-named set the candidate list and the `identified` set were
/// disjoint by construction. An identified target is pinned block by
/// block already; re-scanning it is the perf trap the gate exists for.
#[test]
fn an_identified_target_in_the_tree_is_not_its_own_source() {
    let dir = &tmpdir("identified");
    write(&dir.join("VIDEO_TS/VTS_01_1.VOB"), b"payload bytes");
    write(&dir.join("VIDEO_TS/stray.bin"), b"payload bytes");
    let targets = [tree_target(dir, "VIDEO_TS/VTS_01_1.VOB", 13, true)];
    let (got, _) = candidates(dir, &[], &targets);
    assert_eq!(names(dir, &got), vec!["VIDEO_TS/stray.bin"]);
}
