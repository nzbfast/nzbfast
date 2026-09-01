//! Follow-up 13a-3: a file wearing a name the recovery set DECLARES
//! whose bytes answer to none of it.
//!
//! Its own file rather than a row in `mod.rs`, which was at 2,942 of
//! the size gate's 3,000-line ceiling on 30 Aug 2026 - the same reason
//! `twin_adopt`,
//! `join`, `pins` and the rest are each out here.
//!
//! THE TWO ADOPTION GATES DISAGREED, and these rows are what the
//! disagreement cost. `nzbkit::par2repair::adopt::adoption_candidates`
//! excludes a target only when it is IDENTIFIED - it exists AND at
//! least one of its blocks verified - so a file carrying a declared
//! name that verifies zero blocks is an ordinary adoption candidate to
//! the engine, and `repair_dir_set_inner`'s own comment names the shape
//! ("missing, renamed, SHIFTED - nothing on disk verifies").
//! `crates/nzbfast/src/repair.rs::adoption_candidates_present` excluded
//! it by NAME alone, so on the get path the shortfall was called FINAL
//! and the engine was never asked.
//!
//! AND THEN THEY STILL DISAGREED, one rule further down, which is the
//! fourth row here (follow-up 13a-4, 31 Aug 2026). 13a-3 replaced the
//! name test with a bounded block probe and let a declared name through
//! only on a POSITIVE DENIAL - read some blocks, matched none. The
//! engine's last-resort escalation goes the other way for exactly the
//! file that DOES match: `repair_dir_set_inner` appends every
//! IDENTIFIED DAMAGED target once damage outruns the recovery on disk,
//! because "a mid-file insertion leaves a file half-verified with the
//! rest of its content byte-shifted inside itself". So a member with an
//! insertion at its midpoint is longer than its descriptor (the length
//! screen passes it), verifies its head (the probe hits), and was
//! excluded on that hit - with the escalation written for it never
//! reached. Past a length screen a match cannot mean INTACT; it can
//! only mean identified and damaged.
//!
//! THE PAYLOADS ARE `payloads::unique_payload` and the rows assert
//! byte-exact output plus an EXACT adopted count, for the reason
//! follow-up 13c wrote up: `payload(n, s)` is one periodic sequence, so
//! a fixture that damages it and then reaches the sliding scan can
//! green out of its own periodicity rather than out of the mechanism
//! under test.

use super::*;
use crate::payloads;

/// The bytes on the WIRE are not the bytes `par2 create` saw.
///
/// `real` is written to disk under `name`, so the recovery set covers
/// it and declares its blocks; `posted` is what the articles actually
/// carry, under the same honest yEnc `name=`. Nothing else in the
/// fixture builder can express this: every other constructor posts the
/// bytes it staged, so the set always describes what lands.
fn add_file_posting_other_bytes(
    fx: &mut Fixture,
    name: &str,
    real: &[u8],
    posted: &[u8],
    art_size: usize,
) {
    std::fs::write(fx.dir.join(name), real).unwrap();
    let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
    let segs = make_file_articles(name, posted, art_size, &tag, &mut fx.articles);
    fx.nzb_files.push((name.to_string(), segs));
}

/// A slot claimed by its own honest name whose content sits at a SHIFT
/// the block grid does not name: the poster put 3,000 bytes of
/// container furniture in front of the payload the recovery set was
/// built over.
///
/// THE ARITHMETIC. 2,000-byte blocks over two 200,000-byte files: 100
/// blocks each, 200 in the set, and `-r5` posts 10 recovery blocks.
/// `Shift.vob` lands 203,000 bytes long with its content at offset
/// 3,000 - one and a half blocks, so NOT ONE aligned block verifies,
/// the live name tier says so in as many words ("carries none of that
/// file's bytes") and leaves the slot out of the set, and verify prices
/// the member wholly missing. All 100 of its blocks are then damaged
/// against 10 recovery blocks, so the shortfall is 100-over-10 and the
/// gate under test decides the job.
///
/// Every one of those 100 blocks is sitting in that same file, whole,
/// at an offset the sliding scan reaches on its first pass. Measured
/// before the fix: `unrepairable: 100 blocks needed, only 10 recovery
/// blocks in the NZB`, job failed, bytes on disk.
#[tokio::test(flavor = "multi_thread")]
async fn a_declared_name_over_shifted_bytes_reaches_the_adoption_scan() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarshiftname");
    // The arithmetic above is this waiver: 100 blocks damaged against 10
    // posted, so parity cannot rebuild the member and is not meant to.
    // Reaching the sliding scan at all is the whole row.
    crate::adoptguard::adoption_is_the_premise(
        &fx.dir,
        "100 of the member's blocks are damaged against 10 recovery \
         blocks in the post - the shortfall is the fixture, and every \
         one of the 100 sitting whole at a shifted offset of the same \
         file is what the scan is being asked to find",
    );
    let keep = payloads::unique_payload(200_000, 0x5b13_a301);
    let real = payloads::unique_payload(200_000, 0x5b13_a302);
    let mut posted = payloads::unique_payload(3_000, 0x5b13_a303);
    posted.extend_from_slice(&real);
    fx.add_file("Keep.vob", &keep, 4_000);
    add_file_posting_other_bytes(&mut fx, "Shift.vob", &real, &posted, 4_000);
    assert!(fx.add_par2_opts(5, Some(2_000), &["Keep.vob", "Shift.vob"], 4_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(
        ok,
        "a member whose every block is on disk under its own name, at a \
         shift, must not be reported unrepairable:\n{log}"
    );
    assert!(
        std::fs::read(out.join("Shift.vob")).unwrap_or_default() == real,
        "Shift.vob is not the payload the recovery set declares\n{log}"
    );
    assert!(
        std::fs::read(out.join("Keep.vob")).unwrap_or_default() == keep,
        "Keep.vob did not survive the repair\n{log}"
    );
    assert!(
        log.contains("scanning the job's own unclaimed files for their blocks"),
        "the shortfall was not taken through the F7/F9 arm - if some other \
         arm carried it, this row has stopped measuring the gate it is \
         named for\n{log}"
    );
    // The exact count, for the reason the module note gives: 100 is
    // every block of the shifted member and nothing else. A different
    // number means the two payload streams have started agreeing by
    // accident and the row has stopped being a test of adoption.
    assert!(
        log.contains("100 block(s) adopted from"),
        "expected all 100 blocks to be lifted out of the shifted file\n{log}"
    );
}

/// The other side of the same gate, and the reason it is a screen and
/// not a removal: an ordinary unrepairable post must still give up
/// without buying a byte of recovery data.
///
/// Same geometry, but `Shift.vob` lands at its DECLARED length with a
/// hole in it - which is what damage from this pipeline looks like,
/// since the get path writes every article at its declared yEnc offset
/// and a missing one leaves a gap rather than shifting what follows.
/// The member is identified, the engine would exclude it from the scan
/// itself, and the shortfall is genuinely final.
#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_hole_at_the_declared_length_is_still_a_final_shortfall() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarholename");
    let keep = payloads::unique_payload(200_000, 0x5b13_a311);
    let real = payloads::unique_payload(200_000, 0x5b13_a312);
    fx.add_file("Keep.vob", &keep, 4_000);
    fx.add_file("Hole.vob", &real, 4_000);
    assert!(fx.add_par2_opts(5, Some(2_000), &["Keep.vob", "Hole.vob"], 4_000));
    // 4,000-byte articles over a 200,000-byte file are parts 1..=50;
    // dropping 20 of them costs 40 blocks against the 10 posted.
    let mut corrupt = HashSet::new();
    for p in 11..=30 {
        corrupt.insert(format!("<Hole_vob-1-{p}@mock>"));
    }
    let (log, ok, _out) = run_norar_chaos(
        &fx,
        Chaos {
            corrupt,
            ..Chaos::default()
        },
    )
    .await;
    assert!(
        !ok,
        "40 blocks of damage over 10 recovery blocks must fail\n{log}"
    );
    assert!(
        log.contains("unrepairable:") && log.contains("only 10 recovery blocks in the NZB"),
        "the ordinary unrepairable post must keep the verdict it always \
         had, and must reach it before any fetch\n{log}"
    );
    assert!(
        !log.contains("recovery short ("),
        "a full-length damaged member is the set's own file - letting it \
         through the gate buys an adoption scan for an answer arithmetic \
         has already given\n{log}"
    );
}

/// The stated limit of the screen above, pinned so it is KNOWN rather
/// than found: a declared name over a wholly foreign payload of
/// EXACTLY the declared length is still a final shortfall.
///
/// The gate reaches for the probe only where the on-disk length is not
/// the descriptor's, because a full-length file is not a shifted one
/// and probing every heavily damaged member of an unrepairable post is
/// the read the name exclusion existed to avoid. What that costs is
/// this row: a foreign payload that happens to land at the declared
/// length is never asked, so a poster who both prefixed AND truncated
/// to the byte would not be reached. Widening to cover it means paying
/// the probe on every full-length member of every failing job; that
/// trade has not been made, and this row is where it would be unmade.
///
/// It is also the row that keeps the screen honest in the other
/// direction: delete it and this post pays an adoption scan before
/// reporting the same shortfall.
///
/// WHAT THAT SCAN COSTS was repriced on 31 Aug 2026 and the screen was
/// KEPT on the new number - see `repair::adoption_candidates_present`
/// and `research/ADOPTION-GATE-NAME-VS-IDENTIFIED-2026-08-31.md` R-1.
/// It was a whole recovery fetch when this row was written; follow-up
/// 13a-1 landed hours later and made it one scan of the job's own
/// files. The screen stays because a member landing full length with
/// every strided probe position a hole (measured: 98.0-98.5% head
/// damage, which "only the last article survived" reaches) is a
/// POSITIVE DENIAL and would buy that scan for nothing - not because
/// the probe itself is dear, which it measured not to be.
#[tokio::test(flavor = "multi_thread")]
async fn a_foreign_payload_at_the_declared_length_is_not_probed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsamelen");
    let keep = payloads::unique_payload(200_000, 0x5b13_a321);
    let real = payloads::unique_payload(200_000, 0x5b13_a322);
    let foreign = payloads::unique_payload(200_000, 0x5b13_a323);
    fx.add_file("Keep.vob", &keep, 4_000);
    add_file_posting_other_bytes(&mut fx, "Same.vob", &real, &foreign, 4_000);
    assert!(fx.add_par2_opts(5, Some(2_000), &["Keep.vob", "Same.vob"], 4_000));
    let (log, ok, _out) = run_norar(&fx).await;
    assert!(!ok, "a wholly foreign payload cannot be repaired\n{log}");
    assert!(
        log.contains("unrepairable:") && log.contains("only 10 recovery blocks in the NZB"),
        "the verdict must be the arithmetic one, reached before any fetch\n{log}"
    );
    assert!(
        !log.contains("recovery short ("),
        "a full-length declared name is held out by the length screen - if \
         this fell through, the screen is gone and every full-length \
         member of every failing job is now being probed\n{log}"
    );
}

/// Follow-up 13a-4: the SAME gate one rule down. A mid-file insertion,
/// where the head still verifies - so the member is IDENTIFIED, which
/// is the whole difference from row 1.
///
/// THE ARITHMETIC. Same geometry as row 1: 2,000-byte blocks over two
/// 200,000-byte files, `-r5` posts 10 recovery blocks. `Half.vob` is
/// posted with 3,000 bytes of furniture spliced in at its MIDPOINT, so
/// it lands 203,000 bytes long, blocks 0..49 verify untouched and
/// blocks 50..99 are the same content shifted +3,000 inside the same
/// file. Verify prices it `50/100 blocks bad`, so the shortfall is
/// 50-over-10 and this gate decides the job.
///
/// THAT IS THE ENGINE'S OWN ESCALATION TARGET, in its own words: "a
/// mid-file insertion leaves a file half-verified with the rest of its
/// content byte-shifted inside itself; only a scan of that file can
/// find it" (`par2repair::repair_dir_set_inner`). The gate excluded it
/// anyway, because the probe HIT on the verified head and the rule was
/// `read > 0 && hit == 0`. Past the length screen a hit cannot mean
/// intact, so it was excluding the one shape the escalation exists for.
///
/// MEASURED on origin/main at 670bed24a, before the rule moved:
/// `[verify] ✘ Half.vob - 50/100 blocks bad`, then `[repair]
/// unrepairable: 50 blocks needed, only 10 recovery blocks in the NZB`
/// with no `recovery short (` line at all - the shortfall was FINAL and
/// the engine was never asked - and `out/Half.vob` sitting there at
/// 203,000 bytes holding all 50 of those blocks whole. After: `50
/// block(s) adopted from Half.vob`, and the file back at 200,000
/// byte-exact.
///
/// REACHABILITY WAS THE FIRST QUESTION, not an afterthought, because a
/// shift cannot come from damage here - the get path writes every
/// article at its declared yEnc offset, so a lost one leaves a HOLE and
/// never moves what follows. It has to be POSTED, and this row is the
/// proof that a posted one lands in exactly the state the escalation
/// names. How OFTEN a real poster does it is not established and the
/// gate's header says so; what carries the fix is that the escalation
/// is PARITY code - par2cmdline has its own target scan for this shape,
/// pinned against ours in `nzbkit`'s
/// `integration::par2repair_parity::mid_file_insertion_escalates_to_target_scan`.
#[tokio::test(flavor = "multi_thread")]
async fn a_declared_name_over_midfile_inserted_bytes_reaches_the_adoption_scan() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarmidshift");
    // 50 blocks damaged against 10 posted: parity cannot rebuild the
    // member and is not meant to. Reaching the escalation is the row.
    crate::adoptguard::adoption_is_the_premise(
        &fx.dir,
        "50 of the member's blocks are damaged against 10 recovery \
         blocks in the post - the shortfall is the fixture, and every \
         one of the 50 sitting whole 3,000 bytes further into the same \
         half-verified file is what the escalation is being asked to find",
    );
    let keep = payloads::unique_payload(200_000, 0x5b13_b401);
    let real = payloads::unique_payload(200_000, 0x5b13_b402);
    let furniture = payloads::unique_payload(3_000, 0x5b13_b403);
    // The insertion is at the MIDPOINT and on a block boundary, so the
    // split is clean: blocks 0..49 are untouched and 50..99 are whole
    // at +3,000. A ragged offset would additionally destroy the block
    // it lands inside, which is a different row - the engine's own
    // parity test covers that one (one RS rebuild for the split block).
    let mut posted = Vec::with_capacity(203_000);
    posted.extend_from_slice(&real[..100_000]);
    posted.extend_from_slice(&furniture);
    posted.extend_from_slice(&real[100_000..]);
    fx.add_file("Keep.vob", &keep, 4_000);
    add_file_posting_other_bytes(&mut fx, "Half.vob", &real, &posted, 4_000);
    assert!(fx.add_par2_opts(5, Some(2_000), &["Keep.vob", "Half.vob"], 4_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(
        ok,
        "a HALF-verified member whose remaining blocks sit shifted inside \
         itself must not be reported unrepairable - the engine has an \
         escalation for exactly this file\n{log}"
    );
    assert!(
        std::fs::read(out.join("Half.vob")).unwrap_or_default() == real,
        "Half.vob is not the payload the recovery set declares\n{log}"
    );
    assert!(
        std::fs::read(out.join("Keep.vob")).unwrap_or_default() == keep,
        "Keep.vob did not survive the repair\n{log}"
    );
    assert!(
        log.contains("50/100 blocks bad"),
        "the member must be IDENTIFIED and DAMAGED - if verify prices it \
         wholly missing, the head has stopped verifying and this row has \
         become row 1 rather than the escalation shape it is named for\n{log}"
    );
    assert!(
        log.contains("scanning the job's own unclaimed files for their blocks"),
        "the shortfall was not taken through the F7/F9 arm - if some other \
         arm carried it, this row has stopped measuring the gate it is \
         named for\n{log}"
    );
    // The exact count, per the module note: 50 is every shifted block of
    // the member and nothing else, and 0 rebuilt says parity contributed
    // nothing - which is the point, there being only 10 blocks of it.
    assert!(
        log.contains("0 block(s) rebuilt across 1 file(s), 50 block(s) adopted from"),
        "expected all 50 shifted blocks to be lifted out of the member's \
         own bytes with no parity rebuild at all\n{log}"
    );
}
