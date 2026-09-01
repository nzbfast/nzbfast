//! A member whose name is AT the component cap still gets its donation.
//!
//! The donor copy is staged beside its destination under
//! `.<leaf>.donating`, and that leaf is a [`crate::disk::sanitize_out_name`]
//! result - so for a long posted name it is EXACTLY the 255-byte
//! component cap, capping being what produced it. Ten more bytes is not
//! a name any filesystem creates (measured on APFS 31 Aug 2026: 255
//! creates, 256 is `ENAMETOOLONG`), so the copy could not be staged and
//! the member fell through to needing recovery blocks with a perfectly
//! good donor sitting beside it.
//!
//! SILENTLY, which is what makes it worth a pin rather than a note: the
//! `copy_verified` error arm breaks out of the candidate loop and says
//! nothing, so the only visible trace is a repair that fetched more than
//! it had to.
//!
//! A child of `unit_tests` for its fixture helpers and because
//! `unit_tests.rs` sits inside 1% of its size-gate ceiling.

use super::*;

#[test]
fn a_member_named_at_the_cap_is_still_donated() {
    let donor = tmpdir("donatecap-src");
    let dir = tmpdir("donatecap-dst");

    // Any name past the cap comes back at EXACTLY the cap - that is the
    // premise, and it is asserted rather than assumed.
    let posted = format!("{}.bin", "y".repeat(400));
    let leaf = crate::disk::sanitize_out_name(&posted);
    assert_eq!(leaf.len(), 255, "the premise moved");

    let bytes = payload(300, 11);
    // The donor's own name is irrelevant - candidates are matched by
    // length and MD5 - so it is short on purpose, which keeps the test
    // about the DESTINATION leaf and nothing else.
    std::fs::write(donor.join("whatever.bin"), &bytes).unwrap();

    let index = par2_index(SET, BS, &[(posted.as_str(), &bytes)]);
    let set = par2::Par2Set::parse(&[&index]).expect("fixture parses");
    let placed = donate_whole_files(&set, std::slice::from_ref(&donor), &dir);

    assert_eq!(
        placed.len(),
        1,
        "the donor holds this member whole; it must not be left to the wire"
    );
    assert_eq!(placed[0].name, leaf);
    assert_eq!(
        std::fs::read(dir.join(&leaf)).unwrap(),
        bytes,
        "and the bytes at the capped name are the member's"
    );
    // No half-written temporary survives, whatever its name came out as.
    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".donating"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporaries left behind: {leftovers:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}
