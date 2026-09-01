//! Follow-up 13a-1's trap, end to end: a shortfall on a post that is
//! ALREADY holding recovery blocks on disk.
//!
//! Its own file rather than a row in `mod.rs`, by the same rule as
//! `twin_adopt` beside it - several lanes append to that file at once
//! and it is kept inside its size-gate ceiling.
//!
//! WHAT THIS IS FOR. `repair::adoption_narrowed_need` runs the PAR2
//! engine before the recovery fetch and sizes the buy from what the
//! adoption scan leaves behind. The engine and the caller do not mean
//! the same thing by "needed": the engine reports its TOTAL
//! post-adoption missing count alongside the recovery it ALREADY holds
//! on disk, while `fetch_and_repair`'s own `needed` is ADDITIONAL -
//! `get/settle.rs` builds it as `damage_by_set[si] - on_hand[si]` and
//! `repair::recovery_candidates` drops the volumes already on hand from
//! the fetch list to match. So the comparable figure is
//! `after - on_disk`, and comparing the engine's total against the
//! caller's remainder declares a BUYABLE post unrepairable.
//!
//! That subtraction is pinned in memory by
//! `repair::shortfall_gate_tests::on_disk_recovery_is_subtracted_before_the_engine_is_compared`,
//! with the engine injected as a closure. NOTHING COULD SEE IT END TO
//! END - and the census that establishes that says something narrower,
//! and sharper, than the lane that landed the reorder believed, so it
//! is worth reading before trusting this row's premise.
//!
//! MEASURED 31 Aug 2026, the whole e2e binary (387 rows) with both
//! quantities logged at every decision. FIVE decisions DO reach the
//! probe holding recovery on disk, so "no row runs a shortfall with
//! recovery already on disk" was simply wrong; every one of them is in
//! `e2e_multiset`, and every one holds ONE block or TWO, because
//! par2cmdline's default layout is exponential and puts a single block
//! in the smallest volume. Those five are all the SNIFFED road (hash
//! subjects, so the set is reached by the offset-0 magic sniff); this
//! row is the NAMED bootstrap road. That difference is not what makes
//! this row bite, and reading it that way would cost the next lane a
//! row it does not need - what makes it bite is the uniform GEOMETRY
//! below, which puts half the declared parity on disk instead of one
//! block. A fixture on any road under the default layout would be as
//! blind as those five are. Four of the five reach the same verdict
//! whichever form of the comparison is used. The fifth genuinely FLIPS
//! - `after 4, on_disk 1, needed 4, have 3` is a buy of 3 with the
//! subtraction and `Final` without it - and it still cannot catch the
//! regression, because it belongs to
//! `e2e_multiset::control_both_sets_insufficient_fails_honestly`, a row
//! whose whole assertion is that the job FAILS. Its sibling set goes
//! `Final` either way, so the job fails either way and the control
//! passes either way.
//!
//! DRIVEN RATHER THAN REASONED: with `after - on_disk` reverted to
//! `after`, all 30 rows of `e2e_multiset` and `e2e_faults` - the two
//! modules holding every one of those five decisions - still pass, and
//! this row fails. That is the whole argument for it. The rest of the
//! tree agrees for the reason the reorder's own record gives: the four
//! fixtures it was priced on and the two e2e rows it landed with all
//! carry ZERO recovery on disk at the moment the decision is made
//! (`research/ADOPT-SCAN-ORDER-2026-08-31.md`), and at zero the right
//! and wrong forms of the comparison are the same expression.
//!
//! WHY THE PAYLOADS ARE NOT `payload()` is `twin_adopt`'s note and
//! applies here unchanged: that generator repeats itself, so a sliding
//! adoption scan cross-matches one file's missing blocks out of the
//! other's for reasons that have nothing to do with the post, and a row
//! about adoption written on it measures the generator.
//! `payloads::unique_payload` has no repeated block at any alignment,
//! so every block this row says was adopted came from the head the two
//! files really do share.

use super::*;
use crate::payloads;

/// `par2 create` with the recovery geometry spelled out, posting the
/// VOLUMES ONLY.
///
/// TWO DEPARTURES FROM `Fixture::add_par2_opts`, and both are what puts
/// recovery on disk before the repair decides anything.
///
/// THE INDEX IS NOT POSTED. With no `.par2` main in the NZB,
/// `get::plan` elects the smallest VOLUME as the set's bootstrap
/// (`nzbkit::nzb::par2_seed_file`), promotes its articles to the front
/// so the set activates in-stream, and settle then counts that volume's
/// own recovery slices into `on_hand` and strikes its NZB entry off the
/// fetch list. The index carries no recovery slices at all, so a post
/// that ships one bootstraps with `on_hand` at zero - which is every
/// other PAR2 fixture in this binary. This is not a corner shape: a
/// post whose index never made it, or was never posted, is ordinary,
/// and `plan.rs` has carried the arm for it since the sniff landed.
///
/// THE GEOMETRY IS UNIFORM (`-u -n<v> -c<n>`) rather than par2's
/// default limited layout, which is exponential - 1, 2, 4, 8 blocks -
/// and whose SMALLEST volume therefore carries one block. One block on
/// disk is a subtraction this row could not tell from an off-by-one.
/// Uniform volumes put half the declared recovery on disk before the
/// fetch, which is what makes the two forms of the comparison reach
/// opposite verdicts.
///
/// Returns false if par2 is not installed, exactly as its siblings do.
fn add_par2_volumes_only(
    fx: &mut Fixture,
    block_size: u64,
    recovery_blocks: u32,
    volumes: u32,
    files: &[&str],
    art_size: usize,
) -> bool {
    let st = std::process::Command::new("par2")
        .arg("create")
        .arg(format!("-s{block_size}"))
        .arg(format!("-c{recovery_blocks}"))
        .arg(format!("-n{volumes}"))
        .arg("-u")
        .arg("-q")
        .arg("testset")
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return false,
    }
    let mut par2s: Vec<std::path::PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    let mut posted = 0usize;
    for p in &par2s {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        // Volumes only. The index is created (par2cmdline writes one
        // whatever you ask for) and then dropped on the floor with the
        // rest of the scratch files below.
        if name.contains(".vol") {
            let data = std::fs::read(p).unwrap();
            let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
            let segs = make_file_articles(&name, &data, art_size, &tag, &mut fx.articles);
            fx.nzb_files.push((name, segs));
            posted += 1;
        }
        std::fs::remove_file(p).unwrap();
    }
    // A geometry par2cmdline declined to produce would leave this row
    // measuring some other post's arithmetic, so it is a refusal rather
    // than a quiet pass.
    posted == volumes as usize
}

/// The `twin_adopt` post, re-posted with its PAR2 index missing so half
/// the declared recovery is already on disk when the fetch is sized -
/// and short enough that the engine's total and the caller's remainder
/// reach OPPOSITE verdicts.
///
/// THE ARITHMETIC, and every figure in it is asserted below rather than
/// described. 2000-byte blocks over two 200000-byte files: 100 blocks
/// each, 200 in all. `-c26 -n2 -u` posts 26 recovery blocks as two
/// volumes of 13. Alpha is damaged for 10 blocks INSIDE the 40000-byte
/// run the twins share and past the 16 KiB head hash, so the twin tier
/// still claims it (that placement is `twin_adopt`'s, and its header
/// explains why each end of it matters); Beta for 20 past the shared
/// run entirely. So:
///
/// * damage is 30 blocks, and the bootstrap volume already on disk
///   holds 13, so settle asks for **17**;
/// * the other volume is the whole of what is left for sale, so `have`
///   is **13** - and 13 under 17 is the shortfall branch this is about;
/// * `shortfall_is_final` falls through on the third arm (the set
///   declares 20 blocks twice, against a 4-block gap), so the probe
///   runs;
/// * the engine reads the volume on disk, adopts Alpha's 10 shared
///   blocks out of Beta, and reports `needed: 20, have: 13` - its
///   TOTAL, against what it is already holding;
/// * `20 - 13` is **7**, which is inside the 13 still for sale, so the
///   job buys the second volume and repairs.
///
/// WITHOUT THE SUBTRACTION the engine's 20 is compared against the
/// caller's 13, `adoption_narrowed_need` returns `Final`, and this post
/// - which repairs, with parity to spare - is declared unrepairable
/// having bought nothing.
///
/// THREE MUTATIONS WERE DRIVEN AGAINST THE REAL FILES and all three
/// redden this row, which is what makes the claim above it that the row
/// covers the whole `damage - on_hand` accounting rather than one line
/// of it. Reverting `after - on_disk` to `after` in
/// `repair::adoption_narrowed_need` fails it on the exit status, with
/// the log carrying `unrepairable after the adoption scan: 20 more
/// recovery block(s) still needed, only 13 left in the NZB` in place of
/// the narrowing line - and the two premises asserted below the status
/// still hold, both printed in the failing run. Dropping the
/// `saturating_sub(on_hand[si])` from `get::settle`'s `SetPlan::needed`
/// fails it on the `17`/`13` line, with the status and the bootstrap
/// assertion above it still passing. And stopping
/// `repair::recovery_candidates` from dropping the already-fetched
/// volume fails it on that same line from the other side, because
/// `have` becomes 26 and 26 over 17 is no shortfall at all.
///
/// DO NOT relax the exact counts. `10 block(s) adopted` is the shared
/// run and nothing else, `17`/`13` is the `damage - on_hand` accounting
/// on both sides of the decision, and `7` is the subtraction itself. A
/// figure that drifts means one of those three stopped being what this
/// row is named for - and the byte-exact comparisons at the foot are
/// what stop a repair that produced the wrong bytes passing anyway.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_already_on_disk_is_subtracted_before_the_shortfall_is_called_final() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarondiskrec");
    let head = payloads::unique_payload(40_000, 41);
    let mut a = head.clone();
    a.extend_from_slice(&payloads::unique_payload(160_000, 42));
    let mut b = head;
    b.extend_from_slice(&payloads::unique_payload(160_000, 43));
    let (pa, pb) = ("Vt6nGp37Qd9", "Hs1xKw54Bz8");
    fx.add_file_renamed_by_par2("Twin.Alpha.vob", pa, &a, 4_000);
    fx.add_file_renamed_by_par2("Twin.Beta.vob", pb, &b, 4_000);
    assert!(add_par2_volumes_only(
        &mut fx,
        2_000,
        26,
        2,
        &["Twin.Alpha.vob", "Twin.Beta.vob"],
        4_000,
    ));
    assert!(
        !fx.nzb_files.iter().any(|(n, _)| n == "testset.par2"),
        "the index is in the NZB, so nothing bootstraps from a volume \
         and this row measures an ordinary zero-on-hand shortfall"
    );
    // Parts are 1-based over 4000-byte articles: Alpha 20000..40000 is
    // parts 6..=10, Beta 80000..120000 is parts 21..=30.
    let mut corrupt = HashSet::new();
    for p in 6..=10 {
        corrupt.insert(format!("<{pa}-0-{p}@mock>"));
    }
    for p in 21..=30 {
        corrupt.insert(format!("<{pb}-1-{p}@mock>"));
    }
    let (log, ok, out) = run_norar_chaos(
        &fx,
        Chaos {
            corrupt,
            ..Chaos::default()
        },
    )
    .await;
    assert!(
        ok,
        "a post whose post-adoption shortfall is inside the recovery it \
         still has for sale must not fail - the engine's total was \
         compared against the caller's remainder:\n{log}"
    );
    // THE PREMISE, first: recovery really is on disk before anything is
    // bought. Without this the three counts below would all still hold
    // with `on_hand` at zero and the row would prove nothing.
    assert!(
        log.contains("no main .par2 in NZB - bootstrapping set from smallest volume"),
        "no volume was elected bootstrap, so no recovery reached disk \
         ahead of the repair decision\n{log}"
    );
    // The `damage_by_set - on_hand` accounting, on BOTH sides of it: 30
    // blocks of damage less the 13 the bootstrap volume already holds
    // is 17, and the 26 declared less that same volume is 13 still for
    // sale. Either half left un-subtracted moves a figure here.
    assert!(
        log.contains("recovery short (17 blocks needed, 13 in the NZB)"),
        "the fetch arithmetic did not discount the volume already on \
         disk - 30 blocks of damage less 13 on hand is 17, against 13 \
         still for sale\n{log}"
    );
    // The subtraction itself. The engine's own count is 20 (30 damaged
    // less the 10 it adopts) and it is already holding 13, so 7 is what
    // is left to buy - and 7 is inside the 13 the NZB still has.
    assert!(
        log.contains(
            "the adoption scan covered 10 of 17 block(s) - buying recovery for the \
             remaining 7, not for all 13"
        ),
        "the probe did not subtract the recovery it was already holding \
         before sizing the buy\n{log}"
    );
    assert!(
        log.contains("need 7 block(s) → fetching"),
        "the fetch was not sized by the post-adoption remainder\n{log}"
    );
    // ...and it never reached the bail. Falsifiable in the direction
    // that matters: this is the line the un-subtracted comparison
    // prints instead.
    assert!(
        !log.contains("unrepairable after the adoption scan"),
        "the probe declared a buyable post unrepairable\n{log}"
    );
    assert!(
        log.contains("10 block(s) adopted from"),
        "expected exactly the 10 shared-head blocks to be donated - a \
         different count means the two payload streams have started \
         agreeing by accident\n{log}"
    );
    assert!(
        std::fs::read(out.join("Twin.Alpha.vob")).unwrap_or_default() == a,
        "Twin.Alpha.vob is not the repaired original\n{log}"
    );
    assert!(
        std::fs::read(out.join("Twin.Beta.vob")).unwrap_or_default() == b,
        "Twin.Beta.vob is not the repaired original\n{log}"
    );
}
