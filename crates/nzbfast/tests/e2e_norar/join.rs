//! The SPLIT/JOIN family of the no-RAR matrix: cases 18a, 18b (finding
//! F7) and 18c (matrix row M4-01) - one post's payload cut in half, and
//! the three ways a PAR2 set can name the pieces. They belong together
//! because each is the OTHER's inverse: 18b works precisely BECAUSE its
//! halves stay unclaimed and reach the adoption scan as ordinary
//! candidates, and 18c is what happens when naming the parts as well
//! takes that away.
//!
//! A child module rather than a sibling directory (the parent is what
//! the size gate was about, and these three were its most self-contained
//! subject) so `run_norar` and the packet patchers stay one `super`
//! away. ONE `use` reaches everything, which is worth knowing before
//! adding a second: a child can see its parent's PRIVATE items, and the
//! parent's own `use super::*` is one of them, so `Fixture`, `payload`
//! and `add_par2` arrive through this glob as well - a `use crate::*`
//! beside it is dead and `-D warnings` says so.

use super::*;
use crate::payloads;

/// Case 18a: RAW SPLIT PARTS, no archive - an obfuscated post of
/// `Rawsplit.mkv.001` / `.002` (plain byte halves, no container bytes),
/// FileDesc naming the PARTS. The rename lands them as a split set the
/// post-processing joiner (splitjoin.rs, the SAB-joiner arm) then
/// concatenates. This row measures the whole chain end to end.
#[tokio::test(flavor = "multi_thread")]
async fn raw_split_parts_named_by_filedesc_land_and_join() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsplit");
    let full = payload(200_000, 73);
    fx.add_file_renamed_by_par2("Rawsplit.mkv.001", "Kf6dZr34XnP", &full[..100_000], 40_000);
    fx.add_file_renamed_by_par2("Rawsplit.mkv.002", "Yw9gCt58BvJ", &full[100_000..], 40_000);
    assert!(fx.add_par2(20, &["Rawsplit.mkv.001", "Rawsplit.mkv.002"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "raw-split post failed:\n{log}");
    let joined = std::fs::read(out.join("Rawsplit.mkv"));
    match joined {
        Ok(bytes) => {
            assert!(bytes == full, "joined file not byte-exact\n{log}");
        }
        Err(_) => {
            // Joiner did not run: honest fallback is both parts exact
            // under their FileDesc names. If this arm fires, the matrix
            // row is "renamed, not joined" - re-measure before editing.
            let p1 = std::fs::read(out.join("Rawsplit.mkv.001"))
                .unwrap_or_else(|e| panic!("neither join nor parts landed: {e}\n{log}"));
            let p2 = std::fs::read(out.join("Rawsplit.mkv.002"))
                .unwrap_or_else(|e| panic!("part 2 missing: {e}\n{log}"));
            assert!(
                p1 == full[..100_000] && p2 == full[100_000..],
                "split parts not byte-exact\n{log}"
            );
            panic!("MEASURE: parts landed but did not join - update this row\n{log}");
        }
    }
}

/// Case 18b, finding F7 - CLOSED 30 Aug 2026 (`join-block-adoption`):
/// raw split posted as two obfuscated halves while the FileDesc names
/// only the JOINED file (MultiPar can hash a join). The block size
/// divides the split point, so every joined block exists at an aligned
/// offset of one of the halves. It used to die "10 recovery block(s)
/// needed ... carries only 4" because `fetch_and_repair` bailed
/// on the declared-parity arithmetic before the adoption scan could
/// run; the shortfall now falls through when unclaimed candidates sit
/// in the job dir, and the sliding scan assembles the join with zero
/// recovery spend.
///
/// **BOTH HALVES ARE ASSERTED TO CONTRIBUTE, and on `payload` neither
/// the bytes nor the row could say so** (follow-up 13c.4, 30 Aug 2026,
/// `research/E2E-PARITY-BUDGET-CENSUS-2026-08-30.md`). `payload` has a
/// self-period of 131,072 bytes, and `full` was 256,000 of them - so
/// the two posted halves OVERLAP in content and the second one alone
/// satisfies every block of the join. The output was byte-exact and the
/// repair line named one source and never the other, which is to say
/// the word "halves" in this row's name was not tested. On
/// `payloads::unique_payload` the halves are block-disjoint, so an
/// assembly that reads only one of them cannot produce the file - and
/// the `adopted from` list below is what makes that a failure rather
/// than a silence.
#[tokio::test(flavor = "multi_thread")]
async fn a_filedesc_naming_the_join_of_posted_halves_assembles() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarjoin");
    // Adoption is not an accident here, it is the row. The FileDesc
    // names a file nothing posted, so there is no parity route to it:
    // every one of its ten blocks has to be found at an aligned offset
    // of a posted half, which is what the sliding scan is for. 10 blocks
    // needed against 4 posted is the premise and not a shortfall.
    crate::adoptguard::adoption_is_the_premise(
        &fx.dir,
        "the FileDesc names the JOIN of two posted halves, so no block of \
         it can come from parity - the sliding scan finding all ten at \
         aligned offsets of the halves IS the assertion",
    );
    let full = payloads::unique_payload(256_000, 74);
    std::fs::write(fx.dir.join("Rawjoin.mkv"), &full).unwrap();
    assert!(fx.add_par2_opts(20, Some(12_800), &["Rawjoin.mkv"], 40_000));
    std::fs::remove_file(fx.dir.join("Rawjoin.mkv")).unwrap();
    fx.add_file_obfuscated("Ng2mVx71DkF", "Ng2mVx71DkF", &full[..128_000], 40_000);
    fx.add_file_obfuscated("Ub5qJw43ScH", "Ub5qJw43ScH", &full[128_000..], 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the join-of-halves post failed:\n{log}");
    let assembled = std::fs::read(out.join("Rawjoin.mkv"))
        .unwrap_or_else(|e| panic!("the joined file never landed: {e}\n{log}"));
    assert!(assembled == full, "joined file not byte-exact\n{log}");
    // The premise, spelled out: the join is assembled out of BOTH
    // posted halves. `repair.rs` prints every source it adopted from,
    // comma-separated, so naming only one is the failure this row
    // could not previously see.
    assert!(
        log.contains("Ng2mVx71DkF") && log.contains("Ub5qJw43ScH"),
        "the repair must adopt from BOTH posted halves, not one:\n{log}"
    );
    // AND IT COST NOTHING (follow-up 13a-1, 31 Aug 2026). This row's own
    // doc says the scan "assembles the join with zero recovery spend",
    // and until the reorder that was true of the SCAN and false of the
    // job: `have` is 4 against a `needed` of 10, so `fetch_and_repair`'s
    // target collapsed to `have` and it bought every recovery volume the
    // NZB declares before `repair_dir` read a byte. The scan now runs
    // first (`repair::adoption_narrowed_need`), so the sentence is true
    // of the job too.
    //
    // Both volume-buying lines, because there are two doors: the planned
    // fetch and the escalation's "all remaining". Verified to bite -
    // with the reorder reverted this row logs "need 10 block(s) →
    // fetching" and fails here while still passing every assertion
    // above it, which is exactly why the byte-exactness checks cannot
    // stand in for this one.
    assert!(
        !log.contains("→ fetching") && !log.contains("repair short - fetching all"),
        "a post the adoption scan repairs on its own must buy no recovery \
         volume at all:\n{log}"
    );
}

/// Case 18c, matrix row M4-01 - CLOSED 30 Aug 2026
/// (`norar-wave4-parts-and-join`): ONE set whose FileDescs name the
/// PARTS *and* the JOIN - `Rawsplit.mkv.001`, `Rawsplit.mkv.002` AND
/// `Rawsplit.mkv`. The combination is what n18 and n19 above each miss:
/// n18 names only the parts, n19 only the join, and F7 works precisely
/// BECAUSE its halves stay unclaimed and reach the sliding scan as
/// ordinary adoption candidates.
///
/// Here the halves post honestly under hashes, get claimed by their own
/// descriptors and land INTACT - so `adoption_candidates` excludes them
/// (identified targets are skipped by design, and rolling a block
/// window over every intact file in a 50 GB set is the perf trap that
/// exclusion exists for), and `adoption_candidates_present` skips them
/// too - they wear declared names AND land at the length those
/// descriptors declare, which since follow-up 13a-3 is what that gate
/// asks rather than the name alone. The join was then a wholly
/// missing file whose every block sat next door, and a byte-complete
/// post died "1000 blocks needed, only 200 recovery blocks in the NZB"
/// at r=10.
///
/// Closed by `par2repair`'s in-set harvest, which pairs a missing slice
/// with a present one declaring the same block checksums and re-proves
/// the bytes before adopting them, plus `repair::in_set_harvest_possible`
/// so the shortfall arithmetic is not final while that is available.
///
/// SPEND IS GRADED, not only the end-state hash: at a redundancy that
/// covers the whole join, reconstruct rebuilding it from parity also
/// lands byte-exact and is still the bug, so this row asserts the
/// repair rebuilt ZERO blocks and adopted them instead.
#[tokio::test(flavor = "multi_thread")]
async fn a_filedesc_naming_both_the_parts_and_the_join_harvests_the_parts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarpartsjoin");
    // The paragraph above is this waiver: the row asserts ZERO blocks
    // rebuilt on purpose, because at a redundancy that covers the whole
    // join, buying it back from parity lands byte-exact and is still
    // the bug.
    crate::adoptguard::adoption_is_the_premise(
        &fx.dir,
        "the in-set harvest is the subject - the join's every block sits \
         in the two intact parts, and a repair that spent parity on it \
         instead would be the regression this row exists to catch",
    );
    let full = payload(200_000, 88);
    std::fs::write(fx.dir.join("Rawsplit.mkv.001"), &full[..100_000]).unwrap();
    std::fs::write(fx.dir.join("Rawsplit.mkv.002"), &full[100_000..]).unwrap();
    std::fs::write(fx.dir.join("Rawsplit.mkv"), &full).unwrap();
    assert!(fx.add_par2(
        10,
        &["Rawsplit.mkv.001", "Rawsplit.mkv.002", "Rawsplit.mkv"],
        40_000
    ));
    for n in ["Rawsplit.mkv", "Rawsplit.mkv.001", "Rawsplit.mkv.002"] {
        std::fs::remove_file(fx.dir.join(n)).unwrap();
    }
    fx.add_file_obfuscated("Vt6yHb20Kw", "Vt6yHb20Kw", &full[..100_000], 40_000);
    fx.add_file_obfuscated("Vt6yHb21Kw", "Vt6yHb21Kw", &full[100_000..], 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(
        ok,
        "the parts-and-join post failed - the join is priced wholly \
         missing while every one of its blocks is on disk:\n{log}"
    );
    let got = std::fs::read(out.join("Rawsplit.mkv"))
        .unwrap_or_else(|e| panic!("the joined file never landed: {e}\n{log}"));
    assert!(got == full, "joined file not byte-exact\n{log}");
    // The parts are declared names of this set, so nothing may sweep
    // them: "kept" is the product policy the sweep's target-key
    // exclusion already states.
    for (n, want) in [
        ("Rawsplit.mkv.001", &full[..100_000]),
        ("Rawsplit.mkv.002", &full[100_000..]),
    ] {
        let part = std::fs::read(out.join(n))
            .unwrap_or_else(|e| panic!("declared part {n} was swept: {e}\n{log}"));
        assert!(part == want, "part {n} not byte-exact\n{log}");
    }
    // Zero recovery spend. `0 block(s) rebuilt` is the reconstruct
    // ledger; the adoption clause is the floor that keeps this from
    // passing on a run where the repair never happened at all.
    assert!(
        log.contains("0 block(s) rebuilt"),
        "M4-01 spend: the join was reconstructed from parity instead of \
         harvested from the parts already on disk\n{log}"
    );
    assert!(
        log.contains("1000 block(s) adopted from"),
        "M4-01 spend: every one of the join's 1000 blocks must come from \
         the parts, so a repair that adopted fewer spent recovery on the \
         rest\n{log}"
    );
}
