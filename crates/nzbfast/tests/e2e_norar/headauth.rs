//! A 16 KiB HEAD is evidence, not authority.
//!
//! Found while closing no-RAR matrix rows M4-03/W4-04 (both-damaged
//! identical-head twins) and M4-04/W4-02 (crossed yEnc names), both of
//! which are green. Those two rows are the name-authority rule - a
//! weaker clue may NOMINATE, only the strongest available evidence may
//! FINALIZE identity - held at the NAME door. This was the same rule at
//! the CONTENT door, and it was not held there.
//!
//! `SlotState::try_match`'s md5-16k tier used to claim outright
//! (`claimed[fi] = Some(slot)`, `confirmed = true`) whenever the slot's
//! first 16 KiB matched exactly one unclaimed descriptor. Nothing after
//! that re-read the file: `settle_binding` returns early on
//! `confirmed`, and `try_match_whole` is never reached because the slot
//! already has a file. So a payload the recovery set did not cover took
//! a member's descriptor the moment it shared that member's first
//! 16 KiB - which is the ordinary shape of a zero-filled head, and the
//! tier's OWN comment names "padded VOBs, disk images" as the reason it
//! declines a PLURAL head match.
//!
//! FIXED 31 Aug 2026 (M4-103): the head NOMINATES. It still takes the
//! claim - that is what every exclusion the tier depends on is built
//! from, and what keeps the hottest matcher in the engine exactly as
//! fast as it was - but the claim is REVOCABLE, and `settle_binding`
//! re-judges it at finish on evidence the head cannot manufacture:
//! whether this slot's own blocks ever matched again past the run they
//! share. An impostor matches a PREFIX and then nothing; damage does
//! not look like that, because damage is missing ARTICLES and a block
//! no article covered is `Pending` rather than `Bad`, so the real bytes
//! on the far side of a hole still match. A signature that does look
//! like an impostor escalates to the whole-file MD5, which is what
//! keeps M4-69's forged-IFSC rows - every block of a byte-exact file
//! failing - inside their own recovery set.
//!
//! TWO LENGTH RULES WERE BUILT AND REFUSED, and both are written up at
//! `SlotState::head_nomination_holds`. The bare comparison
//! (`f.length != file_size`) denies the honest posts whose `size=`
//! disagrees with the FileDesc that `HeadSays::Unknown` exists for; and
//! the seemingly stronger spelling, the slot's SETTLED extent, collapses
//! to the same comparison in production because `get` preallocates the
//! output file at the declared size - it went red on
//! `e2e_norar::lying_yenc_size_lands_at_the_filedesc_length`, matrix
//! finding F5. `get/settle/noset.rs::reclaim_par2_named_payload` asks
//! the length question at a seam where nothing is nominated and there is
//! no finish to defer to, which is why it can.
//!
//! Unit-level pins and mechanism, including the halves this file does
//! not cover:
//! `nzbkit::live::tests::an_uncovered_file_sharing_a_zero_head_is_left_out_of_the_set`,
//! `a_damaged_member_keeps_the_descriptor_its_head_nominated`,
//! `a_nomination_every_block_refuses_is_held_by_the_whole_file_md5`,
//! `a_head_that_covers_the_whole_descriptor_still_claims_in_stream`,
//! `differential_a_head_shorter_than_its_descriptor_nominates_in_both_drains`.
//! This file is the product cost.

use super::*;
use crate::payloads;

/// M4-103's product cost, now the pin of the FIX. It replaces
/// `an_uncovered_payload_sharing_a_members_zero_head_is_claimed_by_the_set`
/// (30 Aug 2026), which asserted today's behaviour so a fix would have a
/// red line to turn green, and which went red on the fix exactly as its
/// own comment said it should.
///
/// DETERMINISTIC BY CONSTRUCTION, and the first cut was not - which is
/// worth keeping, because the racy shape PASSED. Posting the member AND
/// an uncovered file that shares its head puts TWO slots in front of ONE
/// descriptor, and whichever asks first claims it; that run happened to
/// be the member, everything landed, and the test would have been a
/// coin-flip pin asserting nothing. That a published identity depended
/// on that race is a finding in itself (it is the M4-03/M4-04 lane's
/// follow-up 1, still open and NOT settled by this fix), but it is not
/// something to assert on.
///
/// So the member is COVERED BY THE SET AND NEVER POSTED, and only the
/// uncovered payload is on the wire - an incomplete post beside an extra
/// file, which is an ordinary shape. Exactly one slot exists and it is
/// not a member of anything.
///
/// WHAT WAS MEASURED BEFORE THE FIX, deterministically, twice:
///
///   [extract] renamed Bq8wZn41LcH -> Head.Member.vob
///   [verify]  x Head.Member.vob - 1800/2000 blocks bad
///   [repair]  unrepairable: 1800 blocks needed, only 400 recovery
///             blocks in the NZB
///
/// The 200 blocks that DID match are exactly the shared zero head
/// (20,000 bytes at this set's 100-byte blocks), which is the whole of
/// the evidence the claim was made on - and the reason the fix cannot be
/// "ask for one matching block at finish" either.
///
/// WHAT HAPPENS NOW: past the 200 blocks of shared zero head this
/// payload carries not one of the member's blocks, and it is not the
/// member whole either, so the nomination is denied, the claim is
/// released, and the file is published as itself.
/// The job still FAILS - the set's member is wholly missing and 20%
/// parity cannot rebuild it, which is the honest verdict - but the
/// user's file survives under its own name instead of being consumed by
/// a repair it was never part of.
#[tokio::test(flavor = "multi_thread")]
async fn an_uncovered_payload_sharing_a_members_zero_head_is_published_as_itself() {
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

    let tree = out_tree(&out);
    // The member's name must not be worn by bytes that are not its own.
    // Read as BYTES rather than by absence: a file under that name whose
    // content is the loose payload is the whole defect, and asserting
    // only "the name is not there" would pass on a run that published
    // nothing at all.
    assert!(
        !std::fs::read(out.join("Head.Member.vob")).is_ok_and(|b| b == loose),
        "the uncovered payload is wearing the member's FileDesc name \
         again - M4-103 has regressed\ntree: {:?}\n{log}",
        tree.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>()
    );
    // And it is published, at its own length, under a name of its own.
    assert!(
        tree.iter().any(|(_, bytes)| bytes == &loose),
        "the payload the user actually posted is gone\ntree: {:?}\n{log}",
        tree.iter()
            .map(|(n, b)| (n.clone(), b.len()))
            .collect::<Vec<_>>()
    );
    // The job still fails, and that is the honest answer: the set's only
    // member was never posted and 20% parity cannot rebuild a wholly
    // missing file. What changed is WHY - a missing member rather than a
    // member whose bytes turned out to be somebody else's.
    assert!(
        !ok,
        "a set whose only member was never posted cannot complete\n{log}"
    );
}
