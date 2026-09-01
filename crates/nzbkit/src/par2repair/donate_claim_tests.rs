//! The occupancy WINDOW at the donation commit.
//!
//! A child of `unit_tests` rather than a sibling of it, so this reaches
//! that module's `par2_index`/`payload`/`tmpdir` fixtures through
//! `use super::*` with no re-export - and so `unit_tests.rs` itself
//! stays inside its size-gate entry, which it is 36 lines under.
//!
//! `donate_whole_files` establishes that a member's name is free and
//! then, minutes of whole-file MD5 later, renames onto it.
//! `unit_tests.rs`'s own donation cases pin WHICH QUESTION is asked -
//! an entry that holds the name, not a name that resolves - and the
//! `symlink_metadata` at the head of that loop answers it exactly as
//! the `create_new` claim at the commit does. What separates them is
//! the gap behind the answer, which here is the widest of the nine
//! doors on the 31 Aug 2026 census: see `crate::renameclaim` for the
//! measurement and for why the arrival hunts the rename rather than
//! sweeping a fixed span.

use super::*;

/// VERIFIED red with the commit claim removed and the head-of-loop
/// `symlink_metadata` left in place, which is the state that door was
/// in before 31 Aug 2026.
///
/// What a lost window costs: the loser is an IN-PROGRESS FETCH's inode,
/// which is the harm the head-of-loop guard's own comment names - "an
/// in-progress fetch owns that inode, and overwriting it is how a
/// donation turns into corruption".
#[test]
fn a_member_name_created_beside_the_donation_is_never_renamed_over() {
    let donor = tmpdir("donate-claim-src");
    let dir = tmpdir("donate-claim-dst");
    let good = payload(260, 31);
    let files: &[(&str, &[u8])] = &[("good.bin", &good)];
    std::fs::write(donor.join("good.bin"), &good).unwrap();

    let index = par2_index(SET, BS, files);
    let set = par2::Par2Set::parse(&[&index]).expect("fixture parses");
    let target = dir.join("good.bin");
    crate::renameclaim::never_renames_over_a_neighbour(
        &target,
        300,
        || {
            // The copy's own temporary, in case a trial was cut short
            // between the copy and the rename.
            let _ = std::fs::remove_file(dir.join(".good.bin.donating"));
        },
        || {
            donate_whole_files(&set, std::slice::from_ref(&donor), &dir);
        },
    );
    let _ = std::fs::remove_dir_all(&donor);
    let _ = std::fs::remove_dir_all(&dir);
}
