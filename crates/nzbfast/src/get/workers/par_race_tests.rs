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
        name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
        is_par2_main: false,
        sample_skipped: false,
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
/// that set's own block size, and a slot no set claims is charged to
/// nobody - no parity on hand rebuilds it.
#[test]
fn missing_blocks_are_charged_per_set() {
    let n = nzb();
    let slots = vec![slot("a.rar", 0, 1), slot("b.sample.mkv", 0, 2)];
    // a.rar's largest segment is 400000 bytes, b's is 50000.
    // Set 0 at 4096: ceil(400000/4096)+1 = 99. Set 1 at 8192:
    // (ceil(50000/8192)+1) * 2 = 16.
    let by_set =
        par_race_missing_blocks_by_set(&[4096, 8192], &[Some(0), Some(1)], &slots, &[0, 1], &n);
    assert_eq!(by_set, vec![99, 16]);
    // An unclaimed slot is charged to nobody.
    let orphan =
        par_race_missing_blocks_by_set(&[4096, 8192], &[Some(0), None], &slots, &[0, 1], &n);
    assert_eq!(orphan, vec![99, 0]);
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
