//! A 16 KiB HEAD is evidence, not authority.
//!
//! Found while closing no-RAR matrix rows M4-03/W4-04 (both-damaged
//! identical-head twins) and M4-04/W4-02 (crossed yEnc names), both of
//! which are green. Those two rows are the name-authority rule - a
//! weaker clue may NOMINATE, only the strongest available evidence may
//! FINALIZE identity - held at the NAME door. This is the same rule at
//! the CONTENT door, and it is not held there.
//!
//! `SlotState::try_match`'s md5-16k tier claims outright
//! (`claimed[fi] = Some(slot)`, `confirmed = true`) whenever the slot's
//! first 16 KiB matches exactly one unclaimed descriptor. Nothing after
//! that re-reads the file: `settle_binding` returns early on
//! `confirmed`, and `try_match_whole` is never reached because the slot
//! already has a file. So a payload the recovery set does not cover
//! takes a member's descriptor the moment it shares that member's first
//! 16 KiB - which is the ordinary shape of a zero-filled head, and the
//! tier's OWN comment names "padded VOBs, disk images" as the reason it
//! declines a PLURAL head match.
//!
//! Length does not save it: the candidate filter compares
//! `f.length.min(HEAD_LEN)`, so every file of 16 KiB or more is in one
//! bucket. `get/settle/noset.rs::reclaim_par2_named_payload` asks the same
//! question with the EXACT length beside the head digest, so the
//! stricter spelling already exists one module over.
//!
//! Unit-level pin and mechanism:
//! `nzbkit::live::tests::an_uncovered_file_sharing_a_zero_head_claims_the_member_it_is_not`.
//! This file is the product cost.

use super::*;
use crate::payloads;

/// CONFIRMED GAP, pinned and deliberately NOT fixed.
///
/// DETERMINISTIC BY CONSTRUCTION, and the first cut was not - which is
/// worth recording, because the racy shape PASSED. Posting the member
/// AND an uncovered file that shares its head puts TWO slots in front of
/// ONE descriptor, and whichever asks first claims it; that run happened
/// to be the member, everything landed, and the test would have been a
/// coin-flip pin asserting nothing. That a published identity depends on
/// that race is a finding in itself, but it is not something to assert
/// on.
///
/// So the member is COVERED BY THE SET AND NEVER POSTED, and only the
/// uncovered payload is on the wire - an incomplete post beside an extra
/// file, which is an ordinary shape. Now exactly one slot exists and it
/// is not a member of anything.
///
/// What SHOULD happen: the uncovered payload is not covered by the set,
/// so it is published as itself, and the set reports its member missing.
/// The set's own parity (20%) cannot rebuild a wholly-missing member and
/// is not supposed to.
///
/// What HAPPENS: the slot's first 16 KiB matches the sole unclaimed
/// descriptor, so `try_match`'s md5-16k tier finalizes identity on that
/// alone. Every block past the shared head then reads as damage to a
/// member, and the uncovered file is consumed by a repair it was never
/// part of.
#[tokio::test(flavor = "multi_thread")]
async fn an_uncovered_payload_sharing_a_members_zero_head_is_claimed_by_the_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut member = vec![0u8; 200_000];
    member[20_000..].copy_from_slice(&payloads::unique_payload(180_000, 0x6106));
    // Not in the set, a DIFFERENT length, and sharing only the zero head.
    let mut loose = vec![0u8; 120_000];
    loose[20_000..].copy_from_slice(&payloads::unique_payload(100_000, 0x6207));

    let mut fx = Fixture::new("norarheadauth");
    // Staged on disk so `par2 create` covers it, but NEVER posted: the
    // set declares a member the wire does not carry.
    std::fs::write(fx.dir.join("Head.Member.vob"), &member).unwrap();
    assert!(fx.add_par2(20, &["Head.Member.vob"], 40_000));
    // The only payload on the wire, and the set covers no such file.
    let segs = make_file_articles(
        "Bq8wZn41LcH",
        &loose,
        40_000,
        "headauth-loose",
        &mut fx.articles,
    );
    fx.nzb_files.push(("Bq8wZn41LcH".to_string(), segs));

    let (log, ok, out) = run_norar(&fx).await;

    // MEASURED 30 Aug 2026, deterministically, twice:
    //
    //   [extract] renamed Bq8wZn41LcH -> Head.Member.vob
    //   [verify]  x Head.Member.vob - 1800/2000 blocks bad
    //   [repair]  unrepairable: 1800 blocks needed, only 400 recovery
    //             blocks in the NZB
    //
    // The 200 blocks that DID match are exactly the shared zero head
    // (20,000 bytes at this set's 100-byte blocks), which is the whole
    // of the evidence the claim was made on.
    let published = std::fs::read(out.join("Head.Member.vob"));
    assert!(
        published.as_deref().is_ok_and(|b| b == loose),
        "TODAY'S BEHAVIOUR HAS CHANGED - re-read this row rather than \
         adjusting it. The uncovered payload is no longer published under \
         the member's FileDesc name, which is the FIXED outcome: delete this \
         pin and say so.\ntree: {:?}\n{log}",
        out_tree(&out)
            .iter()
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        log.contains("renamed Bq8wZn41LcH") && log.contains("Head.Member.vob"),
        "the uncovered payload was expected to be renamed onto the member\n{log}"
    );
    // And the cost: the file the user actually posted is gone under
    // another name, and the job fails because that name's descriptor
    // describes bytes nobody posted.
    assert!(
        !ok,
        "the job was expected to fail as unrepairable once an uncovered \
         payload stood in for the member\n{log}"
    );
}
