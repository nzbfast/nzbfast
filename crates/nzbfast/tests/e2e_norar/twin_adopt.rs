//! Follow-up 13a: the claimed twin that donates the head it shares.
//!
//! Its own file rather than a row in `mod.rs`, which was at 2,928 of
//! the size gate's 3,000-line ceiling on 30 Aug 2026.
//!
//! WHY THE PAYLOADS ARE NOT `payload()`. Follow-up 13c measured that
//! generator: `payload(n, s)` is `i*37 + s + (i>>9)`, so for ANY two
//! seeds there is a shift at which the two streams agree at ~84% of
//! offsets, and a sliding adoption scan then cross-matches one file's
//! missing blocks out of the other's for reasons that have nothing to
//! do with the post. A row about adoption written on it measures the
//! generator. `payloads::unique_payload` has no repeated block at any
//! alignment, within one output or across two seeds, and the row
//! asserts the EXACT adopted count, so a stream that started agreeing
//! by accident fails rather than passing louder.

use super::*;
use crate::payloads;

/// Two identical-head twins, BOTH claimed in place by the twin tier,
/// both damaged, and the set posted short of the parity the damage
/// costs - the shape sweep item 13 created and this row is the measured
/// answer to (follow-up 13a).
///
/// THE DAMAGE IS PLACED, not scattered, and each placement is doing a
/// job. Alpha's is at 20000..40000: inside the 40000-byte run the twins
/// share, and PAST the 16 KiB window the head hash reads - so the tier
/// still sees an identical-head group and still claims Alpha on its own
/// surviving blocks, which is the precondition for the whole row.
/// Damage the first 16 KiB instead and Alpha is not a twin at all, it
/// is an unclaimed hash-named file, which is the F7/F9 arm this row is
/// not about. Beta's is at 80000..120000, past the shared run entirely,
/// so it can only be paid for out of parity.
///
/// THE ARITHMETIC. 2000-byte blocks over two 200000-byte files: 100
/// blocks each. Alpha loses 10, Beta 20, so 30 are needed and r=13
/// posts 26. `par2 v` over the same two damaged files agrees and says
/// what a competitor shelling out to par2cmdline would: "You have 170
/// out of 200 data blocks available. You have 26 recovery blocks
/// available. Repair is not possible. You need 4 more recovery blocks."
/// The 10 Alpha lost are inside the shared run, so the set declares
/// each of them TWICE and Beta still holds every one - the escalation
/// lifts them across, 20 remain, and 26 recovery blocks close it. The
/// gate's own arithmetic agrees before a byte is fetched: the set
/// declares 20 blocks twice against a 4-block shortfall, and 20 is an
/// upper bound on what aligned donation can supply.
///
/// WITHOUT THE THIRD ARM this job fails, and not in the repair: both
/// members carry the names the set declares AND land at the length
/// those descriptors declare - the get path writes every article at its
/// declared yEnc offset, so damage leaves a HOLE and never shortens the
/// file - so `repair::adoption_candidates_present` excludes both
/// (follow-up 13a-3 made that gate ask about the bytes, and this is the
/// shape it still, rightly, holds out),
/// `shortfall_is_final` calls 30-over-26 final, and the recovery volumes
/// are never fetched at all. Before the twin tier the same post passed
/// here, because the damaged slot stayed unclaimed and hash-named.
#[tokio::test(flavor = "multi_thread")]
async fn a_claimed_twin_donates_the_shared_head_it_declares_twice() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norartwinadopt");
    let head = payloads::unique_payload(40_000, 11);
    let mut a = head.clone();
    a.extend_from_slice(&payloads::unique_payload(160_000, 22));
    let mut b = head;
    b.extend_from_slice(&payloads::unique_payload(160_000, 33));
    let (pa, pb) = ("Qh4vBn82Rk5", "Zx7mLc09Wt3");
    fx.add_file_renamed_by_par2("Twin.Alpha.vob", pa, &a, 4_000);
    fx.add_file_renamed_by_par2("Twin.Beta.vob", pb, &b, 4_000);
    assert!(fx.add_par2_opts(13, Some(2_000), &["Twin.Alpha.vob", "Twin.Beta.vob"], 4_000));
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
        "a post 4 recovery blocks short of its damage, over a set that \
         declares 20 blocks twice, must not fail:\n{log}"
    );
    assert!(
        std::fs::read(out.join("Twin.Alpha.vob")).unwrap_or_default() == a,
        "Twin.Alpha.vob is not the repaired original\n{log}"
    );
    assert!(
        std::fs::read(out.join("Twin.Beta.vob")).unwrap_or_default() == b,
        "Twin.Beta.vob carries the other twin's bytes\n{log}"
    );
    assert!(
        log.contains("the set's own files for the blocks it declares twice"),
        "the shortfall was not taken through the third arm - if it fell \
         through as an UNCLAIMED candidate instead, the twin tier stopped \
         claiming and this row no longer measures what it is named for\n{log}"
    );
    // The exact count, for the reason the module note gives: 10 is the
    // shared run's damaged blocks and nothing else. More means the two
    // payload streams have started agreeing by accident and the row has
    // stopped being a test of adoption.
    assert!(
        log.contains("10 block(s) adopted from"),
        "expected exactly the 10 shared-head blocks to be donated\n{log}"
    );
    // AND THE SHORTFALL LINE DID NOT LIE ABOUT WHERE THEY CAME FROM.
    // This row's donor is Twin.Beta.vob, a file the set DECLARES: the
    // 10 blocks cross by the in-set escalation, not by a §293 donor.
    // Until 31 Aug 2026 the probe pass reported them "in files outside
    // the recovery set", which is this row's own log saying the
    // opposite of its own next line. See `repair::adopted_clause`.
    assert!(
        !log.contains("outside the recovery set"),
        "the shortfall clause claimed an outside donor for an IN-SET \
         donation - Twin.Beta.vob is declared by this set\n{log}"
    );
    // AND THE FETCH WAS SIZED BY THE SCAN, not by the ledger (follow-up
    // 13a-1, 31 Aug 2026). This is the partial arm: adoption bridges 10
    // of the 30 and parity has to pay for the other 20. Before the
    // reorder `have` (26) was under `needed` (30), so the target
    // collapsed to `have` and all 26 declared blocks were bought;
    // `repair::adoption_narrowed_need` now runs the scan first and
    // narrows the buy to what is left. The exact counts are asserted
    // rather than the shape, for the reason the count above it is: a
    // number that drifts means the two payload streams have started
    // agreeing by accident and the row has stopped measuring adoption.
    assert!(
        log.contains("the adoption scan covered 10 of 30 block(s) - buying recovery for the remaining 20, not for all 26"),
        "the scan did not run before the buy, or did not narrow it\n{log}"
    );
    assert!(
        log.contains("need 20 block(s) → fetching"),
        "the fetch was still planned against the ledger's 30 rather than \
         the scan's 20\n{log}"
    );
}
