//! The par-race experiment's pure pieces (`get/workers.rs`): the
//! estimate, the missing-block count and the race task itself against
//! a FileSlot fixture.
//!
//! A child of `workers`, out here for the size gate (TODO 106): the
//! parent is production code sitting 35 lines under the 3,000-line
//! file ceiling, and its inline test modules were a fifth of it. The
//! module is named for its file so size-gate.py's CFG_TEST_MOD resolver
//! still reads it as test code; `super` is still `workers`, so
//! `use super::*` reaches exactly what the inline module reached.

use super::recovery::*;
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

fn slot(hint: &str, remaining: usize, missing: usize) -> Arc<FileSlot> {
    Arc::new(FileSlot {
        hint: hint.into(),
        hint_is_posted_name: nzbkit::release::stem_is_a_name(hint),
        yenc_votes: Default::default(),
        name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
        is_par2_main: false,
        sample_skipped: false,
        par2_name_demoted: Default::default(),
        par2_sniffed: AtomicBool::new(false),
        total_segments: 3,
        remaining: AtomicUsize::new(remaining),
        missing: AtomicUsize::new(missing),
        errors: AtomicUsize::new(0),
        deferred: AtomicUsize::new(0),
        abandoned: AtomicUsize::new(0),
        capture: std::sync::Mutex::new(None),
    })
}

fn nzb() -> Nzb {
    Nzb::parse(
        r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"a.rar" yEnc (1/3)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="4000" number="1">a1@t</segment>
   <segment bytes="4000" number="2">a2@t</segment>
   <segment bytes="400000" number="3">a3@t</segment>
  </segments>
 </file>
 <file subject='"b.sample.mkv" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="1000" number="1">b1@t</segment>
   <segment bytes="50000" number="2">b2@t</segment>
  </segments>
 </file>
</nzb>"#
            .as_bytes(),
    )
    .expect("test NZB parses")
}

/// Codex 5 Aug M2 defect 1: a file the recovery set does not cover
/// must never become a cancellation candidate - repair cannot heal
/// it, so abandoning its articles is permanent damage.
#[test]
fn an_uncovered_companion_is_never_a_candidate() {
    let n = nzb();
    let slots = vec![slot("a.rar", 2, 0), slot("b.sample.mkv", 2, 0)];
    let set_names: std::collections::HashSet<String> =
        [nzbkit::disk::sanitize_filename("a.rar").to_lowercase()]
            .into_iter()
            .collect();
    let est = par_race_estimate(&set_names, &[], None, 4096, &slots, &[0, 1], &n);
    assert!(est.want.contains("<a1@t>"));
    assert!(
        !est.want.iter().any(|id| id.starts_with("<b")),
        "uncovered b.sample.mkv articles must stay out of the race: {:?}",
        est.want
    );
}

/// Codex 5 Aug M2 defect 2: the damage guard charges the file's
/// LARGEST still-possible segments at exact bytes. With 2 tiny
/// segments done and one 400 KB straggler queued, the old average
/// math advertised ~34 blocks of worst-case damage; the truth is 99.
#[test]
fn damage_worst_case_uses_exact_largest_segments_not_the_average() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 1, 0), slot("b.sample.mkv", 0, 0)];
    let set_names: std::collections::HashSet<String> =
        [nzbkit::disk::sanitize_filename("a.rar").to_lowercase()]
            .into_iter()
            .collect();
    let est = par_race_estimate(&set_names, &[], None, block, &slots, &[0, 1], &n);
    // One unresolved article: worst case is the 400000-byte
    // segment - ceil(400000/4096)+1 = 99 blocks.
    assert_eq!(est.out_blocks, 98 + 1);
    // The average estimator (408000/3 = 136000 -> 35 blocks) must
    // not be what guards the cancel.
    assert!(est.out_blocks > 35);
}

/// Missing articles are bounded by their own slot's largest
/// declared segment, not a cross-file average.
#[test]
fn missing_blocks_bound_by_the_slots_own_largest_segment() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 0, 0), slot("b.sample.mkv", 0, 2)];
    // b's largest segment is 50000 bytes: ceil(50000/4096)+1 = 14
    // blocks, twice.
    assert_eq!(par_race_missing_blocks(block, &slots, &[0, 1], &n), 28);
}

/// The race is an experiment and must stay dark by default.
#[test]
fn par_race_defaults_off() {
    assert!(
        std::env::var("NZBFAST_PAR_RACE").is_err(),
        "NZBFAST_PAR_RACE leaked into the test environment"
    );
}

/// One [`SetTail`] over the fixture NZB, for the decision tests.
fn tail(
    covers: &[&str],
    slots: &[Arc<FileSlot>],
    n: &Nzb,
    block: usize,
    live_bad: usize,
    missing_blocks: usize,
    on_hand: usize,
) -> SetTail {
    let set_names: std::collections::HashSet<String> = covers
        .iter()
        .map(|f| nzbkit::disk::sanitize_filename(f).to_lowercase())
        .collect();
    SetTail {
        est: par_race_estimate(&set_names, &[], None, block, slots, &[0, 1], n),
        block,
        live_bad,
        missing_blocks,
        on_hand,
    }
}

fn wk(id: &str, ord: u32) -> nzbkit::pool::Walker {
    nzbkit::pool::Walker { id: id.into(), ord }
}

/// §146 tail give-up decision: the 2x margin is a hard floor - at
/// ceiling*2-1 the ladder keeps walking - and a walker NO set covers is
/// never claimed however much parity is on hand.
#[test]
fn tail_giveup_needs_every_walker_covered_at_twice_the_ceiling() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    // Walkers a1+a2: 2 blocks each (ceil(4000/4096)+1). No other
    // damage priced in: ceiling 4, so 8 recovery blocks commit and
    // 7 do not.
    let walkers = vec![wk("<a1@t>", 0), wk("<a2@t>", 1)];
    let one = |bad, miss, on_hand| tail(&["a.rar"], &slots, &n, block, bad, miss, on_hand);
    assert_eq!(
        tail_giveup_verdict(&walkers, &[one(0, 0, 8)]).claim.len(),
        2
    );
    assert!(
        tail_giveup_verdict(&walkers, &[one(0, 0, 7)])
            .claim
            .is_empty()
    );
    // Damage already priced in raises the ceiling with it.
    assert!(
        tail_giveup_verdict(&walkers, &[one(3, 0, 8)])
            .claim
            .is_empty()
    );
    assert_eq!(
        tail_giveup_verdict(&walkers, &[one(3, 0, 14)]).claim.len(),
        2
    );
    // An article no adopted set covers is never claimed - repair
    // rebuilds nothing outside its own set - however many blocks are
    // on hand.
    let with_b = vec![wk("<a1@t>", 0), wk("<b1@t>", 2)];
    let v = tail_giveup_verdict(&with_b, &[one(0, 0, 10_000)]);
    assert_eq!(v.uncovered, 1);
    assert_eq!(
        v.claim.iter().map(|w| &*w.id).collect::<Vec<_>>(),
        ["<a1@t>"],
        "the uncovered companion's article vetoes ITSELF, not its neighbour"
    );
}

/// The §146 starvation arm's claim (`starved_walkers`): exactly the
/// SHORT sets' walkers, never an uncovered one, never a set that is
/// not short. This is the decision half the 30 Aug 2026 wedge was
/// missing - a post whose whole declared recovery supply (301 blocks)
/// could never meet the 2x ceiling (135,204 blocks) held 33,757
/// walkers on the refusal ladder for hours after the prefetch ladder
/// had quietly returned.
#[test]
fn starved_claim_is_the_short_sets_walkers_and_nothing_else() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let one = |bad, miss, on_hand| tail(&["a.rar"], &slots, &n, block, bad, miss, on_hand);
    // a1/a2 belong to the set; c1 is covered by no set (its per-article
    // veto stands - its own refusal ladder is bounded and ends it).
    let walkers = vec![wk("<a1@t>", 0), wk("<a2@t>", 1), wk("<c1@t>", 9)];
    let sets = [one(0, 0, 3)]; // ceiling 4, needs 8, has 3: short forever
    let v = tail_giveup_verdict(&walkers, &sets);
    assert!(v.claim.is_empty());
    assert_eq!(v.short.len(), 1);
    assert_eq!(v.uncovered, 1);
    let forced = starved_walkers(&walkers, &sets, &v.short);
    assert_eq!(
        forced.iter().map(|w| &*w.id).collect::<Vec<_>>(),
        ["<a1@t>", "<a2@t>"],
        "the starved claim takes the short set's walkers and leaves the uncovered one"
    );
    // A set that CLEARS its margin is a normal claim, and the starved
    // arm has nothing to add: verdict.short is empty, so the forced
    // list is too.
    let cleared = [one(0, 0, 8)];
    let v2 = tail_giveup_verdict(&walkers, &cleared);
    assert_eq!(v2.claim.len(), 2);
    assert!(starved_walkers(&walkers, &cleared, &v2.short).is_empty());
}

/// TODO 311 follow-on B, the widening this replaced the single-set arm
/// for. Two sets, one file each - GH #63's shape - and a walker in
/// EACH. Under the old rule the give-up read one representative set,
/// found the other set's walker missing from its candidate map, and
/// vetoed the whole trade: on eighteen one-file sets that is seventeen
/// tracks that could never take the shortcut at any amount of parity.
#[test]
fn every_set_races_its_own_walkers_against_its_own_parity() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let walkers = vec![wk("<a1@t>", 0), wk("<b1@t>", 1)];
    // a1 and b1 are 2 blocks each (ceil(bytes/4096)+1 on 4000 and
    // 1000 bytes). Each set carries parity for its own file only, and
    // 4 blocks is exactly the 2x each one needs.
    let sets = vec![
        tail(&["a.rar"], &slots, &n, block, 0, 0, 4),
        tail(&["b.sample.mkv"], &slots, &n, block, 0, 0, 4),
    ];
    let v = tail_giveup_verdict(&walkers, &sets);
    assert_eq!(v.uncovered, 0);
    let mut got: Vec<&str> = v.claim.iter().map(|w| &*w.id).collect();
    got.sort_unstable();
    assert_eq!(got, ["<a1@t>", "<b1@t>"]);
    // The negative control, and it is the measurement rather than a
    // restatement of the code. Until TODO 311 follow-on B this arm read
    // ONE representative set and committed the census list whole, so a
    // walker outside that set's candidate map ended the trade for every
    // OTHER walker too. Both halves are visible over the SAME walkers
    // and the SAME parity: judged against set 0 alone `b1` is
    // uncovered - the `return false` the old rule took - and what that
    // veto cost is `a1`, whose own set had already bought its margin.
    let single = tail_giveup_verdict(&walkers, &sets[..1]);
    assert_eq!(single.uncovered, 1, "set 0 cannot speak for b1");
    assert_eq!(
        single.claim.iter().map(|w| &*w.id).collect::<Vec<_>>(),
        ["<a1@t>"],
        "a1 is what the old whole-census veto gave away"
    );
}

/// A set that has NOT bought its margin yet does not ride its
/// sibling's: the second set's walker keeps walking, and the report
/// says which set is short and by how much, so the spec prefetch has a
/// number to fetch toward.
#[test]
fn a_short_set_holds_only_its_own_walkers_back() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let walkers = vec![wk("<a1@t>", 0), wk("<b1@t>", 1)];
    let sets = vec![
        tail(&["a.rar"], &slots, &n, block, 0, 0, 4),
        tail(&["b.sample.mkv"], &slots, &n, block, 0, 0, 3),
    ];
    let v = tail_giveup_verdict(&walkers, &sets);
    assert_eq!(
        v.claim.iter().map(|w| &*w.id).collect::<Vec<_>>(),
        ["<a1@t>"]
    );
    assert_eq!(v.uncovered, 0);
    assert_eq!(
        v.short,
        vec![(1, 1, 2)],
        "set 1 is short of a 2-block ceiling"
    );
}

/// One set's DAMAGE must not raise another set's ceiling. Set 0 carries
/// every bad block in the post; set 1's own walker still clears its own
/// margin, which is exactly what a job-wide `live_counts` would have
/// denied it.
#[test]
fn a_sets_damage_is_never_charged_to_its_sibling() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let walkers = vec![wk("<b1@t>", 0)];
    let sets = vec![
        tail(&["a.rar"], &slots, &n, block, 500, 500, 0),
        tail(&["b.sample.mkv"], &slots, &n, block, 0, 0, 4),
    ];
    assert_eq!(tail_giveup_verdict(&walkers, &sets).claim.len(), 1);
}

/// An article TWO sets both name is claimed by neither: the verifier
/// has evidently not adjudicated it, and picking one would be a guess
/// at whose parity heals it.
#[test]
fn an_article_two_sets_both_name_is_never_claimed() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let walkers = vec![wk("<a1@t>", 0)];
    let sets = vec![
        tail(&["a.rar"], &slots, &n, block, 0, 0, 10_000),
        tail(&["a.rar"], &slots, &n, block, 0, 0, 10_000),
    ];
    let v = tail_giveup_verdict(&walkers, &sets);
    assert!(v.claim.is_empty());
    assert_eq!(v.uncovered, 1);
}

/// The PAR-RACE arm's own per-set gate, which is the half of TODO 311
/// follow-on B that no test reached. Both arms went per-set in
/// `a4852dd7c`, but they compose `SetTail`'s fields DIFFERENTLY and only
/// one composition was pinned: the tail give-up prices a NAMED walker
/// list through [`SetTail::ceiling`], which every test above drives,
/// while the par-race prices EVERY unresolved candidate of the set
/// through [`SetTail::race_ceiling`] - reachable only from the dark
/// `spawn_par_race` loop, so `grep race_ceiling` over this file returned
/// nothing before this test.
///
/// Written 31 Aug 2026 as the pass pin for a backlog entry that was
/// already stale when it was dispatched. That entry said both arms
/// "still take `sets()[0]`", and it was true for the three hours and
/// forty-five minutes between it being written and `a4852dd7c` landing
/// the same afternoon. Neither arm has taken a single-set reading since;
/// the only surviving `sets()[0]` in `workers.rs` is
/// `DamageWatch::project`'s, which is deliberate and says so at its own
/// site. This test is what makes that green measurable rather than
/// asserted.
///
/// WHAT IT DOES AND DOES NOT HOLD, stated rather than left to be found.
/// `race_ceiling` and `covers` are the production functions and are
/// driven directly. The two-line ELIGIBILITY expression they sit inside
/// (`recovery.rs`, `!est.want.is_empty() && covers(race_ceiling())`)
/// lives in a spawned async task with a queue and a verifier behind it,
/// so it is re-spelled here rather than called - this test says the
/// per-set arithmetic is right, never that the loop still asks for it.
/// `every_set_races_its_own_walkers_against_its_own_parity` above is the
/// same distinction for the other arm and does reach its decision
/// function.
#[test]
fn the_par_race_ceiling_prices_each_set_off_its_own_candidates() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let a = tail(&["a.rar"], &slots, &n, block, 0, 0, 206);
    let b = tail(&["b.sample.mkv"], &slots, &n, block, 0, 0, 32);
    // a.rar's three unresolved segments at their exact declared bytes:
    // 400000 -> 99 blocks, 4000 -> 2, 4000 -> 2 (`blocks_for` is
    // div_ceil plus one for the block the tail straddles).
    assert_eq!(a.race_ceiling(), 103);
    // b.sample.mkv's two: 50000 -> 14, 1000 -> 2. Its sibling's 103
    // blocks are nowhere in it.
    assert_eq!(b.race_ceiling(), 16);
    // The 2x margin, per set: each has bought exactly its own.
    assert!(a.covers(a.race_ceiling()));
    assert!(b.covers(b.race_ceiling()));
    assert!(!tail(&["b.sample.mkv"], &slots, &n, block, 0, 0, 31).covers(16));

    // THE NEGATIVE CONTROL, and it is the measurement rather than a
    // restatement of the code. A job-wide ceiling - what a single
    // representative set's arithmetic amounts to once every candidate in
    // the post is priced against it - is 119, so the 238 blocks it
    // demands are more than either set here has. Both sets decline, and
    // set 1 declines holding parity that covers its own damage sevenfold.
    let job_wide = a.race_ceiling() + b.race_ceiling();
    assert_eq!(job_wide, 119);
    assert!(!a.covers(job_wide) && !b.covers(job_wide));

    // Each set's OWN block size, too: the same two segments cost 4
    // blocks at 64 KiB where they cost 16 at 4 KiB. A post whose sets
    // disagree about block size has no one figure, which is exactly why
    // `DamageWatch::project` states its projection in one representative
    // set's blocks and this gate does not.
    assert_eq!(
        tail(&["b.sample.mkv"], &slots, &n, 65536, 0, 0, 0).race_ceiling(),
        4
    );

    // Damage already charged to a set raises ITS ceiling and no other's.
    assert_eq!(
        tail(&["b.sample.mkv"], &slots, &n, block, 5, 7, 0).race_ceiling(),
        28
    );
    assert_eq!(
        a.race_ceiling(),
        103,
        "set 0 is untouched by set 1's damage"
    );
}

/// The candidate filter's VETO: the name is the NZB subject's, and
/// where the verifier reconciled the slot to a different set - a post
/// whose yEnc header names disagree with its subjects - the verifier's
/// answer wins. Abandoning an article off a set whose parity does not
/// cover it is the one permanent loss this trade must never take.
#[test]
fn the_verifiers_own_attribution_vetoes_a_name_match() {
    let n = nzb();
    let block = 4096usize;
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let set_names: std::collections::HashSet<String> =
        [nzbkit::disk::sanitize_filename("a.rar").to_lowercase()]
            .into_iter()
            .collect();
    // The verifier says slot 0 belongs to set 1; this estimate is set
    // 0's, so a.rar's articles must stay out of it.
    let est = par_race_estimate(
        &set_names,
        &[Some(1), Some(1)],
        Some(0),
        block,
        &slots,
        &[0, 1],
        &n,
    );
    assert!(
        est.want.is_empty(),
        "vetoed by the verifier: {:?}",
        est.want
    );
    // The same estimate taken FOR set 1 keeps them.
    let est1 = par_race_estimate(
        &set_names,
        &[Some(1), Some(1)],
        Some(1),
        block,
        &slots,
        &[0, 1],
        &n,
    );
    assert!(est1.want.contains("<a1@t>"));
    // A slot the verifier has not matched yet has no answer to give,
    // so the name still speaks for it.
    let est_unmatched = par_race_estimate(
        &set_names,
        &[None, None],
        Some(0),
        block,
        &slots,
        &[0, 1],
        &n,
    );
    assert!(est_unmatched.want.contains("<a1@t>"));
}

/// Missing articles are charged to the set that CLAIMS the slot, in
/// that set's own block size; a slot no set claims and no set NAMES is
/// charged to nobody - no parity on hand rebuilds it.
#[test]
fn missing_blocks_are_charged_per_set() {
    let n = nzb();
    let slots = vec![slot("a.rar", 0, 1), slot("b.sample.mkv", 0, 2)];
    let unnamed = [
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    ];
    // a.rar's largest segment is 400000 bytes, b's is 50000.
    // Set 0 at 4096: ceil(400000/4096)+1 = 99. Set 1 at 8192:
    // (ceil(50000/8192)+1) * 2 = 16.
    let by_set = par_race_missing_blocks_by_set(
        &[4096, 8192],
        &[Some(0), Some(1)],
        &unnamed,
        &slots,
        &[0, 1],
        &n,
    );
    assert_eq!(by_set, vec![99, 16]);
    // An unclaimed slot NO set names is charged to nobody.
    let orphan = par_race_missing_blocks_by_set(
        &[4096, 8192],
        &[Some(0), None],
        &unnamed,
        &slots,
        &[0, 1],
        &n,
    );
    assert_eq!(orphan, vec![99, 0]);
}

/// 30 Aug 2026 sweep: a file the set NAMES but that never landed a byte
/// has no claim - the verifier only claims a slot once some of it
/// arrives - and its damage used to be charged to no set at all, while
/// `par_race_estimate` was happily pricing its walkers as abandonable by
/// that same set. The margin then cleared on parity that could not
/// rebuild what was being abandoned.
///
/// Verified RED against the pre-fix function: it returned `[99, 0]`.
#[test]
fn a_named_but_unclaimed_slot_is_charged_to_the_set_that_names_it() {
    let n = nzb();
    let slots = vec![slot("a.rar", 0, 1), slot("b.sample.mkv", 0, 2)];
    let named = [
        std::collections::HashSet::from(["a.rar".to_string()]),
        std::collections::HashSet::from(["b.sample.mkv".to_string()]),
    ];
    // Slot 1 is wholly taken down: every article 430, so nothing landed
    // and `slot_sets()` has no answer for it. Set 1 names it, so set 1
    // wears its damage - the same 16 blocks a claimed slot would cost.
    let by_set = par_race_missing_blocks_by_set(
        &[4096, 8192],
        &[Some(0), None],
        &named,
        &slots,
        &[0, 1],
        &n,
    );
    assert_eq!(
        by_set,
        vec![99, 16],
        "a set must wear the damage of a file it names but never saw"
    );
    // And a CLAIM still wins outright over the name: set 0 names
    // b.sample.mkv too here, but the verifier put the slot in set 1.
    let both = [
        std::collections::HashSet::from(["a.rar".to_string(), "b.sample.mkv".to_string()]),
        std::collections::HashSet::from(["b.sample.mkv".to_string()]),
    ];
    let claimed = par_race_missing_blocks_by_set(
        &[4096, 8192],
        &[Some(0), Some(1)],
        &both,
        &slots,
        &[0, 1],
        &n,
    );
    assert_eq!(
        claimed,
        vec![99, 16],
        "the verifier's claim is the answer; the name never adds to it"
    );
}

/// R1, 20 Aug 2026: recovery volumes are PREALLOCATED to their full
/// length at the first article, so a census scan taken while the
/// side-fetch is still writing sees the final length with only some
/// of the content - and the old (path -> len, count) cache served
/// that mid-write undercount for the rest of the job (traced live:
/// 17 of 128 slices on one leg, 6 on another). `on_hand` froze, the
/// 2x margin never cleared, the tail give-up never fired, and
/// damaged posts walked the refusal ladder 32-68% slower. A first
/// fix that refused to cache only a ZERO scan was falsified by R1
/// step 3 - a nonzero undercount poisons identically.
///
/// The invariant that actually holds: a scan of a file written to
/// within [`CENSUS_QUIET`] is returned but never remembered, and a
/// quiet file's scan is remembered even when it found nothing (the
/// index par2 genuinely has no slices - re-reading it every 200 ms
/// tick is the cost A5 exists to remove).
#[test]
fn a_busy_files_scan_is_never_cached_a_quiet_ones_is() {
    let dir = std::env::temp_dir().join(format!("nzbfast-r1-census-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let mut cache = CensusCache::new();

    // Freshly written = mtime now = a writer may still be active.
    // Content does not matter (not par2, scans to 0); what is pinned
    // is that NOTHING about a busy file is remembered.
    let busy = dir.join("half-written.par2");
    std::fs::write(&busy, vec![0u8; 4096]).unwrap();
    assert_eq!(
        cached_recovery_blocks(&busy, &[7u8; 16], 1024, &mut cache),
        0
    );
    assert!(
        cache.is_empty(),
        "a busy file's scan was cached - a mid-write undercount would be served all job"
    );

    // The same file, quiet: backdate mtime past the gate. Now the
    // zero IS remembered - it is the file's true count.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    std::fs::File::options()
        .write(true)
        .open(&busy)
        .unwrap()
        .set_modified(old)
        .unwrap();
    assert_eq!(
        cached_recovery_blocks(&busy, &[7u8; 16], 1024, &mut cache),
        0
    );
    assert_eq!(
        cache.get(&busy).map(|e| (e.len, e.count(&[7u8; 16], 1024))),
        Some((4096, 0)),
        "a quiet file's scan must be cached, zero included"
    );

    // A later write moves mtime, which must invalidate the entry:
    // same length, new content, fresh scan (and no re-cache while
    // the file is busy again).
    std::fs::write(&busy, vec![1u8; 4096]).unwrap();
    assert_eq!(
        cached_recovery_blocks(&busy, &[7u8; 16], 1024, &mut cache),
        0
    );
    let cached_mtime = cache.get(&busy).map(|e| e.mtime).unwrap();
    assert_eq!(
        cached_mtime, old,
        "a rewritten (busy) file re-entered the cache through the stale entry"
    );

    // Unreadable / absent: never remembered.
    let missing = dir.join("not-here.par2");
    assert_eq!(
        cached_recovery_blocks(&missing, &[7u8; 16], 1024, &mut cache),
        0
    );
    assert!(!cache.contains_key(&missing), "a failed read was cached");

    // TODO 311 follow-on B: one cache serves every adopted set, and a
    // file is read ONCE for all of them. Both halves matter and they
    // pull opposite ways. A raw count keyed by path alone answers set 3
    // with set 0's count - an OVER-count, the direction that fires the
    // give-up on parity that is not there, and measured invisible: it
    // left the whole multi-set e2e suite green. A count keyed per set
    // instead is honest but reads the same volume once per adopted set
    // to answer 0 for all but the one that owns it, which on GH #63's
    // eighteen one-file sets is an N-squared read of every volume on
    // disk. Grouping the file's slices BY set id inside the entry is
    // what buys both.
    let before = cache.len();
    let vol = dir.join("shared.par2");
    std::fs::write(&vol, vec![2u8; 4096]).unwrap();
    let old2 = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    std::fs::File::options()
        .write(true)
        .open(&vol)
        .unwrap()
        .set_modified(old2)
        .unwrap();
    assert_eq!(
        cached_recovery_blocks(&vol, &[1u8; 16], 1024, &mut cache),
        0
    );
    assert_eq!(
        cached_recovery_blocks(&vol, &[2u8; 16], 1024, &mut cache),
        0
    );
    assert_eq!(
        cache.len(),
        before + 1,
        "the file was memoized once, not once per asking set: {cache:?}"
    );
    // And every set gets its own honest answer off that one read. This
    // fixture is not par2 at all, so it holds nobody's slices - what is
    // pinned is that the entry answers PER SET and PER BLOCK rather
    // than handing back one number.
    let e = cache.get(&vol).unwrap();
    assert_eq!(e.count(&[1u8; 16], 1024), 0);
    assert_eq!(e.count(&[2u8; 16], 2048), 0);

    let _ = std::fs::remove_dir_all(&dir);
}

/// N6-11, the parser/front-door addendum's arithmetic row.
/// `Nzb::total_bytes` and `NzbFile::bytes` saturate, and that is where
/// the safety stopped: the recovery estimators took those saturated
/// `u64` figures into a `as usize` narrowing, a plain multiply and a
/// plain `sum()`.
///
/// RED on origin/main at 8fbe1c3bd, every one of these:
/// `est.out_bytes += rem as u64 * per` with `per` at `u64::MAX/1`,
/// `(*b as usize).div_ceil(block) + 1` summed over segments, and the
/// same expression in `par_race_missing_blocks` and
/// `par_race_missing_blocks_by_set`. In THIS profile (debug) each is an
/// `attempt to multiply with overflow` / `attempt to add with overflow`
/// panic; built optimized each wraps instead, and a wrapped ceiling
/// near zero is a give-up trade taken on the belief that repair can
/// rebuild everything.
///
/// The assertions are on saturated VALUES rather than on "it did not
/// panic", so this test is meaningful in both profiles: debug fails by
/// panicking, release fails on the numbers. Run the release half with
/// `cargo test -p nzbfast --release --bin nzbfast extreme_declared_bytes`.
///
/// TWO files, and that is what makes the test bite rather than
/// decoration: every one of these estimators ACCUMULATES across slots,
/// so the reachable overflow is in the accumulation and not in any
/// single term. Measured - with one file, `est.out_bytes += rem as u64
/// * per` cannot overflow at all (`per` is `f.bytes()/n` and `rem` is
/// at most `n`, so the product is bounded by the saturated total), and
/// mutations reverting three of the four sites SURVIVED a one-file
/// version of this test.
fn extreme_nzb() -> Nzb {
    Nzb::parse(
        r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"a.rar" yEnc (1/3)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="18446744073709551615" number="1">x1@t</segment>
   <segment bytes="18446744073709551614" number="2">x2@t</segment>
   <segment bytes="9223372036854775808" number="3">x3@t</segment>
  </segments>
 </file>
 <file subject='"c.rar" yEnc (1/3)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="18446744073709551615" number="1">y1@t</segment>
   <segment bytes="18446744073709551614" number="2">y2@t</segment>
   <segment bytes="9223372036854775808" number="3">y3@t</segment>
  </segments>
 </file>
</nzb>"#
            .as_bytes(),
    )
    .expect("extreme byte claims are legal u64 and must still parse")
}

#[test]
fn extreme_declared_bytes_saturate_the_recovery_estimators() {
    let n = extreme_nzb();
    // The declared totals themselves already saturate - that half was
    // never the defect, and this pins the premise the rest rests on.
    assert_eq!(n.files[0].bytes(), u64::MAX);
    assert_eq!(n.total_bytes(), u64::MAX);

    // A block size of ONE is a legal PAR2 claim (`block_size.max(1)`),
    // and it is what makes a single article's block cost saturate
    // `usize` on its own - so the per-slot SUMS have something to
    // overflow. At a realistic 4 KiB block a `u64::MAX` article is
    // ~4.5e15 blocks and it takes ~4,000 of them to reach the ceiling,
    // which no fixture can carry; the arithmetic being pinned is the
    // same either way.
    let block = 1usize;
    let slots = vec![slot("a.rar", 3, 0), slot("c.rar", 3, 0)];
    let set_names: std::collections::HashSet<String> = ["a.rar", "c.rar"]
        .into_iter()
        .map(|n| nzbkit::disk::sanitize_filename(n).to_lowercase())
        .collect();

    // par_race_estimate: `rem as u64 * per` accumulated across slots,
    // and the per-slot block sum.
    let est = par_race_estimate(&set_names, &[], None, block, &slots, &[0, 1], &n);
    assert_eq!(
        est.out_bytes,
        u64::MAX,
        "two files each claiming ~u64::MAX must saturate the byte estimate, not wrap"
    );
    assert_eq!(
        est.out_blocks,
        usize::MAX,
        "and the block ceiling must saturate, not wrap to a small number"
    );

    // par_race_missing_blocks: the same expression on the missing side,
    // summed across both slots.
    let missing = vec![slot("a.rar", 0, 3), slot("c.rar", 0, 3)];
    assert_eq!(
        par_race_missing_blocks(block, &missing, &[0, 1], &n),
        usize::MAX,
        "missing-block worst case must not wrap"
    );

    // par_race_missing_blocks_by_set: the per-set form, where both
    // slots charge the SAME set so the `out[si] +=` accumulates.
    let by_set = par_race_missing_blocks_by_set(
        &[block],
        &[None, None],
        std::slice::from_ref(&set_names),
        &missing,
        &[0, 1],
        &n,
    );
    assert_eq!(by_set[0], usize::MAX, "per-set worst case must not wrap");

    // A block size of zero is a legal claim too, and every one of these
    // divides by it.
    let _ = par_race_missing_blocks(0, &missing, &[0, 1], &n);
    let _ = par_race_estimate(&set_names, &[], None, 0, &slots, &[0, 1], &n);
}

/// N6-11's other half, and the one no box on this fleet can see: the
/// narrowing happens BEFORE the bound.
///
/// `(bytes as usize).div_ceil(block)` is a no-op on the 64-bit boxes
/// this fleet builds on and TRUNCATES on the shipped 32-bit
/// `armv7-unknown-linux-musleabihf` target, where `u64::MAX` becomes
/// `u32::MAX` and a 16 EB claim prices as a 4 GB one - the class
/// `tools/chunk-narrow-gate.py` exists for, in a shape that gate cannot
/// match. This pins the ORDER: the division happens in `u64`, and only
/// its ANSWER meets the word size.
///
/// WHAT THE ANSWER THEN IS DEPENDS ON THE TARGET, and this test asserted
/// otherwise until 31 Aug 2026 - a flat `got as u128 == want`, where
/// `want` is 17,592,186,044,417 and a 32-bit `usize` stops at
/// 4,294,967,295. It was RED in nightly's `armv7-cross` (run
/// 33376949508), deterministically, and the product was right the whole
/// time: `blocks_for` narrows with `usize::try_from(..).unwrap_or
/// (usize::MAX)`, so armv7 gets the most expensive count it can express
/// rather than a wrapped or truncated one. That is the same defect
/// `5dd24e2fc` fixed in `MemBudget` - a fixture asserting a figure that
/// is arithmetically impossible on the target - and NOT a later lane
/// repeating it: this test landed at 30 Aug 23:20Z (`97e4dea88`) and
/// that fix at 31 Aug 04:28Z, so three lanes wrote three such fixtures
/// inside one five-hour window and the fix repaired the only one its
/// own nightly log had named. The first run to see any of the other
/// two was 33376949508, nine hours later.
///
/// So the expectation is DERIVED from the target's own width, which
/// leaves the test meaningful on both: 64-bit pins the exact quotient,
/// armv7 pins that the answer SATURATES at the ceiling of the word.
/// Neither can be the pre-fix 4,097, which is what a wholly-lost file
/// priced at nothing looks like. Deliberately NOT `#[cfg]`-ed off
/// armv7: that leaves the one target the order matters on pinned by
/// nothing.
#[test]
fn block_pricing_divides_before_it_narrows() {
    // The division, in `u64`, on every target. This is the whole claim.
    let bytes = u64::MAX;
    let block = 1usize << 20;
    let quotient = bytes.div_ceil(block as u64).saturating_add(1);
    // What the old expression computed once `usize` is 32 bits: the
    // value truncates first, so the answer is ~4 billion times small.
    // Spelled against `u32` rather than `usize` so this arm is the same
    // arithmetic wherever it runs, not a statement about the host.
    let truncated = ((bytes as u32) as u64).div_ceil(block as u64) + 1;
    assert!(
        (truncated as u128) * 1_000_000 < quotient as u128,
        "the pre-fix order really is orders out ({truncated} vs {quotient})"
    );

    // As much of that answer as THIS target can carry: the whole of it
    // on a 64-bit box, `usize::MAX` on armv7.
    let want = usize::try_from(quotient).unwrap_or(usize::MAX);

    let n = extreme_nzb();
    let slots = vec![slot("a.rar", 0, 1)];
    let got = par_race_missing_blocks(block, &slots, &[0], &n);
    assert_eq!(
        got, want,
        "the block count must come from a u64 division, narrowed with saturation"
    );
    // And whichever of the two arms this target took, it is still
    // orders above the narrow-first answer - which is what keeps this a
    // real test on armv7 rather than one that merely compiles there.
    assert!(
        (got as u128) > (truncated as u128) * 1_000,
        "{got} must not be the narrow-first price ({truncated})"
    );
}

/// Sorted ids, so an assertion over a decision built out of a `HashSet`
/// is a statement about the decision rather than about hash order.
fn ids(set: &std::collections::HashSet<Arc<str>>) -> Vec<String> {
    let mut v: Vec<String> = set.iter().map(|id| id.to_string()).collect();
    v.sort_unstable();
    v
}

fn ids_of(list: &[Arc<str>]) -> Vec<String> {
    let mut v: Vec<String> = list.iter().map(|id| id.to_string()).collect();
    v.sort_unstable();
    v
}

/// The two eligible sets of the fixture NZB, one file each, each
/// holding EXACTLY its own 2x margin: a.rar's three unresolved segments
/// price at 99+2+2 = 103 blocks and b.sample.mkv's two at 14+2 = 16, so
/// 206 and 32 recovery blocks are the tightest on-hand figures that
/// clear. The whole job's expected remainder is 408,000 + 51,000 bytes.
fn two_eligible_sets(slots: &[Arc<FileSlot>], n: &Nzb) -> Vec<SetTail> {
    vec![
        tail(&["a.rar"], slots, n, 4096, 0, 0, 206),
        tail(&["b.sample.mkv"], slots, n, 4096, 0, 0, 32),
    ]
}

/// `par_race_verdict`'s eta gate, which is the first thing the race asks
/// and the one part of it that is a policy rather than arithmetic: a
/// healthy line finishes the stragglers before any repair could start
/// its verify pass, so the trade would spend parity to lose time.
///
/// The remainder is the JOB's, summed over every set - cancelling one
/// set's stragglers shortens a job only while some other set is still
/// the thing holding it open - so the gate is driven here over two sets
/// whose bytes only clear it together.
#[test]
fn the_par_race_declines_until_the_fetch_remainder_is_far_enough() {
    let n = nzb();
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let sets = two_eligible_sets(&slots, &n);
    // 459,000 bytes of expected remainder over both sets.
    let fast = par_race_verdict(&sets, 100_000.0);
    assert!((fast.eta - 4.59).abs() < 1e-9);
    assert!(
        fast.want.is_empty() && fast.eligible.is_empty(),
        "a line that finishes the remainder in 4.6s must not spend parity to save it"
    );
    // The floor is inclusive: 459,000 / 15,300 is exactly 30 s.
    let onthirty = par_race_verdict(&sets, 15_300.0);
    assert_eq!(onthirty.eta, 30.0);
    assert_eq!(onthirty.want.len(), 5);
    // A hair faster and it declines, which is the boundary rather than a
    // restatement - the gate is `< 30`, not `<= 30`.
    assert!(par_race_verdict(&sets, 15_301.0).want.is_empty());
    let slow = par_race_verdict(&sets, 10_000.0);
    assert!((slow.eta - 45.9).abs() < 1e-9);
    assert_eq!(slow.eligible, vec![0, 1]);
    assert_eq!(
        ids(&slow.want),
        ["<a1@t>", "<a2@t>", "<a3@t>", "<b1@t>", "<b2@t>"]
    );
    // A line that has stopped moving altogether is an INFINITE
    // remainder, never a zero one: `rate > 0.0` is what guards the
    // division, and the wrong answer there would decline exactly when
    // the trade is worth most.
    let stalled = par_race_verdict(&sets, 0.0);
    assert!(stalled.eta.is_infinite());
    assert_eq!(stalled.want.len(), 5);
}

/// `par_race_verdict`'s eligibility filter: a set that has not bought
/// its own 2x margin does not ride its sibling's, and its articles stay
/// on the wire. The composition is what this reaches - `race_ceiling`
/// and `covers` each have their own pin, and neither says which ids the
/// tick would actually hand to `cancel`.
#[test]
fn only_the_sets_that_bought_their_own_margin_reach_the_cancel_list() {
    let n = nzb();
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    // Set 1 is one block short of its 32.
    let sets = vec![
        tail(&["a.rar"], &slots, &n, 4096, 0, 0, 206),
        tail(&["b.sample.mkv"], &slots, &n, 4096, 0, 0, 31),
    ];
    let v = par_race_verdict(&sets, 10_000.0);
    assert_eq!(v.eligible, vec![0]);
    assert_eq!(ids(&v.want), ["<a1@t>", "<a2@t>", "<a3@t>"]);
    // The short set still counts toward the remainder the gate is
    // judged against - its 51,000 bytes are part of what the run is
    // waiting on even though nothing of it is cancellable.
    assert!((v.eta - 45.9).abs() < 1e-9);
    // Damage already charged to a set raises ITS bar and no other's:
    // one bad block takes set 0 to 104, so its 206 no longer covers.
    let hurt = vec![
        tail(&["a.rar"], &slots, &n, 4096, 1, 0, 206),
        tail(&["b.sample.mkv"], &slots, &n, 4096, 0, 0, 32),
    ];
    let v2 = par_race_verdict(&hurt, 10_000.0);
    assert_eq!(v2.eligible, vec![1]);
    assert_eq!(ids(&v2.want), ["<b1@t>", "<b2@t>"]);
    // Nobody eligible is a quiet decline, not a cancel of nothing.
    let none = vec![tail(&["a.rar"], &slots, &n, 4096, 0, 0, 205)];
    let v3 = par_race_verdict(&none, 10_000.0);
    assert!(v3.eligible.is_empty() && v3.want.is_empty());
}

/// The par-race arm's own `sole_set` scoping, and the judgement the
/// brief for this extraction named first: an article TWO adopted sets
/// both name reaches NEITHER cancel list.
///
/// It cannot be dropped from `want` later instead - `cancel` answers ONE
/// id list, and an id cancelled that no set then owns is one nothing
/// decrements `remaining` for, which is a run that never finishes. So
/// the exclusion has to happen here, before the queue is asked.
///
/// `an_article_two_sets_both_name_is_never_claimed` above is the same
/// judgement for the tail give-up; this is the race's, which composes
/// `SetTail` differently (every unresolved candidate, not a named walker
/// list) and reached no test at all before this one.
#[test]
fn an_article_two_sets_both_name_reaches_neither_cancel_list() {
    let n = nzb();
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    // Two sets that both name a.rar, each holding parity far past any
    // ceiling: the decline is the ambiguity and nothing else.
    let both = vec![
        tail(&["a.rar"], &slots, &n, 4096, 0, 0, 10_000),
        tail(&["a.rar"], &slots, &n, 4096, 0, 0, 10_000),
    ];
    let v = par_race_verdict(&both, 10_000.0);
    assert_eq!(
        v.eligible,
        vec![0, 1],
        "both sets clear their margin - the veto must be the article's, not the set's"
    );
    assert!(
        v.want.is_empty(),
        "the verifier has not adjudicated a.rar: picking a set would be a guess \
         at whose parity heals it"
    );
    // And it is per ARTICLE rather than per tick. Set 0 covers both
    // files, set 1 only a.rar, so a.rar's three articles are ambiguous
    // and b.sample.mkv's two are not: the unambiguous pair still races
    // off the set that solely speaks for them.
    let mixed = vec![
        tail(&["a.rar", "b.sample.mkv"], &slots, &n, 4096, 0, 0, 238),
        tail(&["a.rar"], &slots, &n, 4096, 0, 0, 206),
    ];
    let v2 = par_race_verdict(&mixed, 10_000.0);
    assert_eq!(v2.eligible, vec![0, 1]);
    assert_eq!(
        ids(&v2.want),
        ["<b1@t>", "<b2@t>"],
        "the ambiguous articles keep fetching; their neighbours do not pay for it"
    );
}

/// `par_race_recheck`, and the judgement the extraction's brief named
/// second: one set's EXACT damage outgrowing its estimate rolls that set
/// back ALONE, without costing a sibling the race its own parity has
/// already paid for.
///
/// The re-check exists because the cancel is the first moment the exact
/// straggler list is known, and it reads a FRESH `live_bad_by_set` -
/// damage can grow in the second between the estimate and the queue's
/// answer. That is also why this is a second function rather than an
/// argument to the first: neither `removed` nor this damage vector
/// exists at the moment `par_race_verdict` decides.
#[test]
fn one_sets_exact_damage_rolls_that_set_back_alone() {
    let n = nzb();
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let sets = two_eligible_sets(&slots, &n);
    let v = par_race_verdict(&sets, 10_000.0);
    // The queue took everything asked for.
    let removed: Vec<Arc<str>> = {
        let mut r: Vec<Arc<str>> = v.want.iter().cloned().collect();
        r.sort_unstable();
        r
    };

    // Nothing moved since the estimate: both sets race.
    let clean = par_race_recheck(&sets, &v.eligible, &removed, &[0, 0]);
    assert!(clean.rollback.is_empty());
    assert_eq!(ids_of(&clean.keep), ids(&v.want));

    // One block of damage arrived against set 0 in the meantime, taking
    // its exact ceiling from 103 to 104 - past what 206 blocks cover.
    // Set 1's 32 blocks are untouched by it.
    let hurt = par_race_recheck(&sets, &v.eligible, &removed, &[1, 0]);
    assert_eq!(hurt.rollback.len(), 1);
    let (si, mine, ceiling) = &hurt.rollback[0];
    assert_eq!(*si, 0);
    assert_eq!(*ceiling, 104);
    assert_eq!(ids_of(mine), ["<a1@t>", "<a2@t>", "<a3@t>"]);
    assert_eq!(
        ids_of(&hurt.keep),
        ["<b1@t>", "<b2@t>"],
        "set 1 keeps the race its own parity bought"
    );

    // The mirror image, so the asymmetry is the damage and not the set
    // index: one block against set 1 takes its ceiling to 17 (needs 34,
    // has 32) and set 0 races on.
    let hurt1 = par_race_recheck(&sets, &v.eligible, &removed, &[0, 1]);
    assert_eq!(hurt1.rollback.len(), 1);
    assert_eq!(hurt1.rollback[0].0, 1);
    assert_eq!(hurt1.rollback[0].2, 17);
    assert_eq!(ids_of(&hurt1.keep), ["<a1@t>", "<a2@t>", "<a3@t>"]);

    // A damage vector SHORTER than the set list is not a licence to
    // race: the missing entry reads as zero damage, which is what
    // `live_bad_by_set` returns for a plan that is no longer Active, and
    // the exact ceiling still has to be covered.
    let short_vec = par_race_recheck(&sets, &v.eligible, &removed, &[]);
    assert!(short_vec.rollback.is_empty());
    assert_eq!(short_vec.keep.len(), 5);

    // The queue answering with a SUBSET is the ordinary case - an
    // article already in flight is not removed - and each set is then
    // priced on what it actually lost. Set 0 keeping only its two 4,000
    // byte segments is a 4-block ceiling, which 206 covers many times.
    let partial: Vec<Arc<str>> = vec!["<a1@t>".into(), "<a2@t>".into()];
    let sub = par_race_recheck(&sets, &v.eligible, &partial, &[0, 0]);
    assert!(sub.rollback.is_empty());
    assert_eq!(ids_of(&sub.keep), ["<a1@t>", "<a2@t>"]);
}

/// `par_race_charge`, and the judgement the brief named third: when
/// `requeue`'s all-or-nothing rollback finds the run winding down the
/// cancel is already irreversible, so the arm falls through to the
/// abandonment accounting rather than dropping those articles on the
/// floor. Cancelled articles never get a pool outcome, so this arm owns
/// the bar exactly as a sniff deferral does - `remaining` down,
/// `abandoned` up, and the freed bytes credited to `fetch_done`.
///
/// The two halves are driven over the SAME cancel, because the
/// difference between them IS the finding: a rollback that works costs
/// set 0 its race, and a rollback that cannot must still complete set
/// 0's bar or the run never finishes.
#[test]
fn an_irreversible_rollback_still_settles_the_bar() {
    let n = nzb();
    let block = 4096usize;

    // (a) the rollback succeeded: only set 1's articles are charged, and
    // set 0's slot is left exactly as the queue put it back.
    let slots = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let sets = two_eligible_sets(&slots, &n);
    let v = par_race_verdict(&sets, 10_000.0);
    let mut removed: Vec<Arc<str>> = v.want.iter().cloned().collect();
    removed.sort_unstable();
    let r = par_race_recheck(&sets, &v.eligible, &removed, &[1, 0]);
    let freed = par_race_charge(&sets, &r.keep, &slots);
    assert_eq!(freed, 1000 + 50000);
    assert_eq!(slots[0].remaining.load(Ordering::Relaxed), 3);
    assert_eq!(slots[0].abandoned.load(Ordering::Relaxed), 0);
    assert_eq!(slots[1].remaining.load(Ordering::Relaxed), 0);
    assert_eq!(slots[1].abandoned.load(Ordering::Relaxed), 2);

    // (b) the same tick with `requeue` finding the run winding down, so
    // the rolled-back ids join the claim. Every cancelled article is
    // accounted for and both bars reach zero.
    let slots2 = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let sets2 = two_eligible_sets(&slots2, &n);
    let mut r2 = par_race_recheck(&sets2, &v.eligible, &removed, &[1, 0]);
    for (_si, mine, _ceiling) in std::mem::take(&mut r2.rollback) {
        r2.keep.extend(mine); // requeue returned 0 - irreversible
    }
    let freed2 = par_race_charge(&sets2, &r2.keep, &slots2);
    assert_eq!(
        freed2,
        4000 + 4000 + 400000 + 1000 + 50000,
        "every cancelled article's declared bytes are credited, or the bar never completes"
    );
    assert_eq!(slots2[0].remaining.load(Ordering::Relaxed), 0);
    assert_eq!(slots2[0].abandoned.load(Ordering::Relaxed), 3);
    assert_eq!(slots2[1].remaining.load(Ordering::Relaxed), 0);
    assert_eq!(slots2[1].abandoned.load(Ordering::Relaxed), 2);

    // An id no adopted set prices is charged to nobody rather than to
    // the first slot in the list - it cannot arrive through
    // `par_race_verdict`, and guessing a slot for it would decrement a
    // bar that is still going to receive its outcome.
    let slots3 = vec![slot("a.rar", 3, 0), slot("b.sample.mkv", 2, 0)];
    let one = vec![tail(&["a.rar"], &slots3, &n, block, 0, 0, 206)];
    let stray: Vec<Arc<str>> = vec!["<zz@t>".into()];
    assert_eq!(par_race_charge(&one, &stray, &slots3), 0);
    assert_eq!(slots3[0].remaining.load(Ordering::Relaxed), 3);
    assert_eq!(slots3[1].remaining.load(Ordering::Relaxed), 2);
}

/// The order rule as ARITHMETIC at 32-bit width, so armv7's numbers are
/// readable from a box that cannot run armv7.
///
/// The test above cannot give you that half. On a 64-bit host
/// `usize::try_from(u64)` never fails, so `blocks_for`'s
/// `unwrap_or(usize::MAX)` arm is unreachable there - the one arm the
/// 32-bit target takes is the one no box on this fleet can execute.
///
/// WHAT THIS CANNOT DO, said rather than left to be found: no change to
/// the product can redden it. That is not a shortcoming to be fixed by
/// widening it - it is the shape of the defect. `bytes as usize` is a
/// no-op on every box here, so a narrow-first regression is BIT
/// IDENTICAL to the correct code on this fleet and NOTHING runnable
/// here can catch it; only `armv7-cross` can, through the test above.
/// What this pins instead is the pair of numbers that test's failure
/// message will print - 4,097 against `u32::MAX`, six orders apart -
/// so the next reader of that log knows which order produced which,
/// without a qemu run to tell them.
#[test]
fn the_two_orders_at_32_bit_width_are_six_orders_apart() {
    let bytes = u64::MAX;
    let block = 1u64 << 20;

    // Divide first, then meet the word: the answer is too big for 32
    // bits, so it SATURATES - the most expensive price expressible, and
    // an over-estimate is the safe direction for a repair ceiling.
    let quotient = bytes.div_ceil(block).saturating_add(1);
    assert_eq!(quotient, (1u64 << 44) + 1);
    assert_eq!(u32::try_from(quotient).unwrap_or(u32::MAX), u32::MAX);

    // Meet the word first, then divide: 16 EB of declared bytes price
    // as 4,097 blocks. Six orders under the truth, and in the direction
    // that abandons payload the parity on hand cannot rebuild.
    let narrow_first = (bytes as u32 as u64).div_ceil(block) + 1;
    assert_eq!(narrow_first, 4_097);
    assert!(u64::from(u32::MAX) > narrow_first * 1_000);
}
