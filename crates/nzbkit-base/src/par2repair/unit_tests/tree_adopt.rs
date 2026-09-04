//! Wave-4 row X6-02: the adoption scan under the relpath-preserve
//! ruling - a target in a SUBDIRECTORY, and a source that is there.
//!
//! The 29 Aug 2026 ruling exists so a `VIDEO_TS` tree keeps its shape,
//! and `par2repair.rs` resolves every FileDesc through
//! `join_out_name(dir, sanitize_out_name(&d.name))`, so a set whose
//! descriptors spell `VIDEO_TS/VTS_01_1.VOB` has its targets inside
//! directories. Two scans behind that ruling were still a single flat
//! `read_dir` filtered on `is_file()`, and a directory fails that test
//! in one step - so on a tree-named set the candidate list and the
//! `identified` set were DISJOINT BY CONSTRUCTION: nothing was ever
//! excluded as identified because nothing was ever a candidate.
//!
//! The two are a DOOR and a REACH, which is M4-102's split one path
//! over, and both were measured RED on `272a84bcd` before the fix:
//!
//! * the door, `repair_sets_catalog`'s renamed-fallback gate ("does
//!   this directory hold any non-packet file that could serve as an
//!   adoption source"). With the payload a directory down the root
//!   holds packets only, so the gate never opened and
//!   `repair_present_or_renamed_sets` returned `[]` - the set was not
//!   attempted AT ALL, and the caller reads an empty Vec as "no repair
//!   happened", which is [`super::super::repair_present_or_renamed_sets`]'s
//!   documented shape for a job that finishes with its payload still
//!   wearing a hash.
//! * the reach, `adopt::adoption_candidates`. Reached directly through
//!   [`super::super::repair_dir_set_with_donors`], a donor holding a
//!   predecessor's tree-shaped output offered ZERO candidates and the
//!   set priced its only member wholly missing:
//!   `Unrepairable { needed: 4, have: 0, adopted: 0 }`. No error, no
//!   log line - the user is handed a parity number, which reads as a
//!   recovery shortage rather than as a blind scanner, so the CLAUSE is
//!   graded below as well as the status.
//!
//! Fixing one alone leaves the row live either way, which is why both
//! arms are here: the door alone lets the scan run and price the member
//! missing, the reach alone is never asked.
//!
//! Both now go through `nested::walk_files` - the SAME walk
//! `walk_candidates` and `nested_subdirs` use, at its existing
//! `charge_bytes = false` arm rather than as a third implementation, so
//! depth, directories, entries and the symlink rule are decided in one
//! place. `walk_files`' own doc carries why the byte budget is the one
//! bound an adoption scan must not take.
//!
//! A CHILD of `unit_tests` for `padded_windows`' two reasons: it
//! reaches the helpers above while that file stays inside its size-gate
//! ceiling.

use super::*;

/// The row itself, on the ORDINARY repair path: an obfuscated payload
/// published INSIDE the tree its set names, with nothing unclaimed at
/// the root at all.
///
/// That is a real publication shape and not a contrivance - a poster
/// who obfuscates the basename and keeps the directory honest posts
/// `VIDEO_TS/<hash>`, `sanitize_out_name` rules that a safe relative
/// path and preserves it, and the file lands a directory down.
#[test]
fn a_payload_obfuscated_inside_the_tree_is_adopted_under_its_declared_name() {
    let dir = tmpdir("x602-tree");
    let a = payload(200, 7);
    let files: &[(&str, &[u8])] = &[("VIDEO_TS/VTS_01_1.VOB", &a)];
    std::fs::create_dir_all(dir.join("VIDEO_TS")).unwrap();
    std::fs::write(dir.join("VIDEO_TS").join("0f9a7c"), &a).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();

    // The plain presence gate still skips it - no FileDesc name on disk
    // - exactly as it does for the flat shape.
    assert!(
        repair_present_sets(&dir)
            .expect("present-set walk")
            .is_empty(),
        "no declared name on disk means the plain entry point skips"
    );
    let outcomes = repair_present_or_renamed_sets(&dir).expect("fallback runs");
    assert_eq!(
        outcomes.len(),
        1,
        "the renamed fallback's own gate has to see a candidate a DIRECTORY down, \
         or the set is never attempted and the job finishes hash-named"
    );
    let report = match outcomes[0].status.as_ref().expect("set repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 4, "every slice found in the copy");
    assert_eq!(report.files_created, ["VIDEO_TS/VTS_01_1.VOB"]);
    // The sentence, not just the status: a bare shortfall reads as a
    // recovery shortage, and what happened here is that the bytes were
    // found. `adopted_from` names a PLACE since X6-02c - see the two
    // pins at the bottom of this file, which own that rule.
    let clause = adopted_from_clause(report.blocks_adopted, &report.adopted_from);
    assert!(
        clause.contains("4 block(s) adopted from") && clause.contains("VIDEO_TS/0f9a7c"),
        "the user is told where the bytes came from, got {clause:?}"
    );
    assert_eq!(
        std::fs::read(dir.join("VIDEO_TS").join("VTS_01_1.VOB")).unwrap(),
        a,
        "and it lands at the path the set names, not flattened to the root"
    );
    // The source is this directory's own junk and is spendable: a
    // subdirectory of the repair dir starts_with it, which is the same
    // ownership test the flat scan always applied.
    assert_eq!(
        report.consumed_sources,
        [dir.join("VIDEO_TS").join("0f9a7c")]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The §293 arm: a DONOR directory holding a predecessor's output,
/// tree-shaped exactly as publication leaves it.
///
/// Reached through the set-scoped entry the ordinary repair path uses
/// (`repair::nativepass` -> `repair_dir_set_with_donors`), so this is
/// the shape a switched job actually presents. Before the fix the donor
/// offered zero candidates and the set answered
/// `Unrepairable { needed: 4, have: 0, adopted: 0 }`.
#[test]
fn a_donor_holding_a_tree_shaped_predecessor_output_donates_its_blocks() {
    let dir = tmpdir("x602-donor");
    let donor = tmpdir("x602-donor-src");
    let a = payload(200, 7);
    let files: &[(&str, &[u8])] = &[("VIDEO_TS/VTS_01_1.VOB", &a)];
    std::fs::create_dir_all(donor.join("VIDEO_TS")).unwrap();
    std::fs::write(donor.join("VIDEO_TS").join("VTS_01_1.VOB"), &a).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();

    let got = repair_dir_set_with_donors(&dir, &SET, std::slice::from_ref(&donor))
        .expect("set attempted");
    let report = match &got {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 4, "every slice found in the donor");
    assert_eq!(
        std::fs::read(dir.join("VIDEO_TS").join("VTS_01_1.VOB")).unwrap(),
        a
    );
    assert!(
        report.consumed_sources.is_empty(),
        "a donor is another job's payload and is never swept, however far down it sits"
    );
    // The donor's own tree is untouched.
    assert!(donor.join("VIDEO_TS").join("VTS_01_1.VOB").is_file());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// What the widening had to bring with it: the SWEEP guard, which
/// compared a candidate's BASENAME against the names the directory's
/// sets declare.
///
/// Equivalent for a flat candidate - its basename IS its out-relative
/// name - and blind for a nested one, in the direction that DELETES. A
/// member another set declares at a tree path (`other/movie.mkv`) that
/// happens to be byte-identical to one of this set's targets cleared
/// the basename test, matched the target MD5, and was reported in
/// `consumed_sources` for the caller to sweep. Before the widening it
/// could not be a candidate at all, so this is a hazard the fix
/// creates and has to close in the same commit.
#[test]
fn a_nested_member_another_set_declares_is_never_swept_as_junk() {
    let dir = tmpdir("x602-sweep");
    let a = payload(200, 7);
    let readme = payload(80, 11);
    // Set A wants `payload/movie.mkv`, which is absent, and also names
    // a file that IS here so the plain presence gate admits the set.
    let a_files: &[(&str, &[u8])] = &[("payload/movie.mkv", &a), ("readme.txt", &readme)];
    // Set B declares the byte-identical twin, at ITS own tree path.
    let b_files: &[(&str, &[u8])] = &[("other/movie.mkv", &a)];
    const SET_B: [u8; 16] = [4u8; 16];

    std::fs::write(dir.join("readme.txt"), &readme).unwrap();
    std::fs::create_dir_all(dir.join("other")).unwrap();
    std::fs::write(dir.join("other").join("movie.mkv"), &a).unwrap();
    std::fs::write(dir.join("a-set.par2"), par2_index(SET, BS, a_files)).unwrap();
    std::fs::write(dir.join("b-set.par2"), par2_index(SET_B, BS, b_files)).unwrap();

    let outcomes = repair_present_sets(&dir).expect("present-set walk");
    assert_eq!(outcomes.len(), 2, "both sets have a declared name on disk");
    let a_out = outcomes
        .iter()
        .find(|o| o.set_id == SET)
        .expect("set A ran");
    let report = match a_out.status.as_ref().expect("set A repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(
        report.blocks_adopted, 4,
        "the widening is what makes the twin reachable in the first place"
    );
    assert!(
        report.consumed_sources.is_empty(),
        "another set declares those bytes at that path - sweeping them deletes its payload, \
         got {:?}",
        report.consumed_sources
    );
    assert!(dir.join("other").join("movie.mkv").is_file());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A SYMLINKED tree contributes nothing, and that is the historical
/// answer kept rather than a new refusal.
///
/// A `DirEntry`'s own file type is an `lstat`, so the flat scan this
/// replaces already declined a symlinked FILE; `nested::walk` applies
/// the identical test to directories, which is what makes "no yielded
/// path can leave `dir`" true. Extending the scan into subdirectories
/// without it would let a donor - a directory this job does not own -
/// aim the adoption scan anywhere on the filesystem, so the no-follow
/// rule is load-bearing here in a way it was not when the walk had no
/// depth to escape through.
#[test]
#[cfg(unix)]
fn a_symlinked_tree_is_not_followed_by_the_adoption_scan() {
    let dir = tmpdir("x602-link");
    let outside = tmpdir("x602-link-outside");
    let a = payload(200, 7);
    let files: &[(&str, &[u8])] = &[("VIDEO_TS/VTS_01_1.VOB", &a)];
    std::fs::write(outside.join("0f9a7c"), &a).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("VIDEO_TS")).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();

    // Nothing reachable, so the renamed fallback's gate stays shut and
    // the set is not attempted - the same answer the flat scan gave.
    assert!(
        repair_present_or_renamed_sets(&dir)
            .expect("fallback runs")
            .is_empty(),
        "a symlink is never followed, so the bytes behind one are not candidates"
    );
    assert!(
        outside.join("0f9a7c").is_file(),
        "and nothing outside the repair directory was touched"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&outside);
}

/// X6-02c, BUILT 31 Aug 2026 (claim `x6-02c-adopted-from-tree-path`).
/// The stated limit that used to sit here said `adopted_from` holds a
/// BASENAME, so on a tree `disc1/x.vob` and `disc2/x.vob` print the
/// same and a DONOR's file reads as though it were in this directory -
/// and that the respelling was not free, because
/// `get::latesets::repair_accounts_for_the_shortfall` matches a slot's
/// own name against these entries and is one of the few rules that
/// turns a failed job GREEN. Both halves moved in one commit. This is
/// the engine half's pin: two same-leaf payloads a directory apart,
/// both adopted, and the clause has to tell them apart.
///
/// The consumer half is pinned in `nzbfast::get::latesets`' own tests,
/// and the argument for why the new comparison is STRICTER rather than
/// merely different is written at that call site.
#[test]
fn two_same_leaf_payloads_in_different_directories_are_named_apart() {
    let dir = tmpdir("x602c-leafclash");
    let a = payload(200, 11);
    let b = payload(200, 12);
    let files: &[(&str, &[u8])] = &[("disc1/x.vob", &a), ("disc2/x.vob", &b)];
    for d in ["disc1", "disc2"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    // Each payload sits under a hash name in its OWN directory, so the
    // set finds both only by content and both are adoption sources.
    std::fs::write(dir.join("disc1").join("1a2b3c"), &a).unwrap();
    std::fs::write(dir.join("disc2").join("4d5e6f"), &b).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();

    let outcomes = repair_present_or_renamed_sets(&dir).expect("fallback runs");
    let report = match outcomes[0].status.as_ref().expect("set repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(
        report.adopted_from,
        ["disc1/1a2b3c", "disc2/4d5e6f"],
        "each source is named at a path the reader can open, not by a leaf"
    );
    // The whole point of the row: the two are DISTINGUISHABLE. Under
    // the basename spelling a same-leaf pair collapsed to one entry.
    let clause = adopted_from_clause(report.blocks_adopted, &report.adopted_from);
    assert!(
        clause.contains("disc1/1a2b3c") && clause.contains("disc2/4d5e6f"),
        "got {clause:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other producer, and the half no out-relative name can answer: a
/// candidate from a §293 DONOR directory is not under `dir` at all, so
/// it keeps its leaf and is MARKED. That marker is what stops a donor's
/// basename colliding with a short slot's and being credited as its
/// source by the consumer above - see
/// [`crate::par2repair::adopt::adopted_from_names`] for why naming the
/// donor directory instead was refused.
#[test]
fn a_donor_directorys_file_is_marked_rather_than_read_as_one_of_ours() {
    let dir = tmpdir("x602c-donor");
    let donor = tmpdir("x602c-donorsrc");
    let a = payload(200, 13);
    let files: &[(&str, &[u8])] = &[("x.vob", &a)];
    // Nothing of the payload is in the repair dir; the bytes are a
    // predecessor job's, offered as a donor.
    std::fs::write(donor.join("x.vob"), &a).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();

    let status =
        crate::par2repair::repair_dir_set_with_donors(&dir, &SET, std::slice::from_ref(&donor))
            .expect("set repairs off the donor");
    let report = match &status {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(
        report.adopted_from,
        [format!("x.vob {}", crate::par2repair::adopt::DONOR_MARK)],
        "a donor is named as not-ours rather than as a file in this directory"
    );
    assert!(
        report.consumed_sources.is_empty(),
        "and a donor is never swept - it is another job's file"
    );
    assert!(
        donor.join("x.vob").is_file(),
        "the donor's own copy is untouched"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}
