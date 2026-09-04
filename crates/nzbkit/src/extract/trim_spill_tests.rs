//! TODO 37's "open, recorded not fixed" trio, closed 23 Aug 2026: the
//! drop-behind trim's spill runs OFF the routing lock, a failed spill
//! leaves its prefix in RAM, and a nested spill no longer charges the
//! bomb budget for good. Child of `extract` like `nested_tests`, so
//! `super::*` and `super::testutil::*` name what the other suites name;
//! its own file because `chase_tests.rs` sits near the size gate.

use super::chase::chase_tests::{chase_volume_set, eat_budget_to};
use super::testutil::*;
use super::*;
use crate::rar::fixtures;

// -- the buffer-level contract --

/// A planned trim moves nothing: `base` stays, the bytes stay readable,
/// only the budget's view (`stored`) shrinks. Commit drains exactly the
/// plan; abandon gives the bytes back to the budget with no other
/// change. And while one is in flight, both a second plan and the
/// one-step `trim_to` decline - one prefix at a time is what makes
/// `base == at` a sufficient commit proof.
#[test]
fn a_planned_trim_leaves_ram_alone_until_it_commits() {
    let buf = FrontierBuffer::new(100_000);
    let bytes = payload(60_000, 7);
    buf.write_span(0, &bytes);
    assert_eq!(buf.stored(), 60_000);

    let (at, n, seq) = buf.trim_plan(40_000, 1).expect("a plan");
    assert_eq!((at, n), (0, 40_000));
    assert_eq!(buf.base(), 0, "a plan moved base");
    assert_eq!(buf.stored(), 20_000, "the budget was not credited at plan");
    assert!(buf.trim_plan(50_000, 1).is_none(), "two plans in flight");
    assert!(buf.trim_to(50_000, 1).is_none(), "trim_to cut under a plan");
    // The bytes are still served from RAM, and the chunks are the plan.
    let mut got = vec![0u8; 1000];
    buf.peek(500, &mut got).unwrap();
    assert_eq!(got, bytes[500..1500]);
    let c0 = buf.trim_chunk(at, 0, 16_384, seq).unwrap();
    let c1 = buf.trim_chunk(at, 16_384, 16_384, seq).unwrap();
    let c2 = buf.trim_chunk(at, 32_768, 16_384, seq).unwrap();
    assert_eq!([c0, c1, c2].concat(), bytes[..40_000]);
    assert!(
        buf.trim_chunk(at, 40_000, 16_384, seq).is_none(),
        "past the plan"
    );

    // Abandon: everything exactly as before the plan.
    buf.trim_abandon();
    assert_eq!(buf.base(), 0);
    assert_eq!(buf.stored(), 60_000, "an abandoned plan kept its credit");
    assert!(
        buf.trim_to(50_000, 1).is_some(),
        "trim_to still declined after abandon"
    );
    // That trim_to moved base to 50_000; plan and commit the rest.
    let (at, n, seq) = buf.trim_plan(60_000, 1).unwrap();
    assert_eq!((at, n), (50_000, 10_000));
    assert_eq!(buf.trim_commit(at, seq), Some(10_000));
    assert_eq!(buf.base(), 60_000);
    assert_eq!(buf.stored(), 0);
    assert!(
        buf.trim_commit(at, seq).is_none(),
        "a second commit of nothing"
    );
}

/// The commit re-proves the plan. A differing rewrite inside the prefix
/// after the plan (legal when the decode has not read it: no conflict)
/// means the chunk already copied out may be STALE, so the chunk walk
/// stops and the commit refuses - nothing drains, and `base` does not
/// move over bytes the file may hold wrong. A demote that popped the
/// run refuses the same way.
#[test]
fn a_rewrite_under_a_planned_trim_refuses_the_commit() {
    let buf = FrontierBuffer::new(100_000);
    let bytes = payload(60_000, 8);
    buf.write_span(0, &bytes);
    let (at, _n, seq) = buf.trim_plan(40_000, 1).unwrap();
    assert!(buf.trim_chunk(at, 0, 16_384, seq).is_some());
    let mut other = payload(1000, 9);
    other[0] ^= 0xFF;
    buf.write_span(20_000, &other);
    assert!(
        buf.trim_chunk(at, 16_384, 16_384, seq).is_none(),
        "chunk after a rewrite"
    );
    assert!(buf.trim_commit(at, seq).is_none(), "commit after a rewrite");
    assert_eq!(buf.base(), 0);
    assert_eq!(buf.stored(), 60_000, "refused commit kept the credit");
    // An agreeing duplicate is not a rewrite and changes nothing.
    let (at, _n, seq) = buf.trim_plan(40_000, 1).unwrap();
    buf.write_span(0, &bytes[..5000]);
    assert!(buf.trim_chunk(at, 0, 1000, seq).is_some());
    assert_eq!(buf.trim_commit(at, seq), Some(40_000));
    // Popped out from under a plan (a demote): refuse.
    let (at, _n, seq) = buf.trim_plan(60_000, 1).unwrap();
    let _ = buf.pop_span().unwrap();
    assert!(buf.trim_commit(at, seq).is_none());
}

// -- the extractor-level routes --

/// The lock-placement oracle for the 7z trim, on the route-counter
/// principle (`HoldsScratch::locked_reads`; a timing test cannot pin
/// where an I/O happened). `trim_spilled_off_lock` is bumped only by
/// the off-lock job, at commit; the under-lock route (`plain_span`)
/// never touches it. So every byte `base` advanced over must be
/// accounted for by the counter, or some of the spill ran under the
/// routing lock. Reverting `sevenz_trim_part` to `trim_to` +
/// `plain_span` fails this with the counter at 0.
#[test]
fn sevenz_trim_spills_off_the_routing_lock() {
    let f = noisy(24 << 20, 140);
    let arch = sevenz_archive(
        &[("F.bin", &f)],
        Some(vec![sevenz_rust2::EncoderConfiguration::new(
            sevenz_rust2::EncoderMethod::COPY,
        )]),
        false,
    );
    let dir = tmpdir("7z-trim-offlock");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    // Copy fixture: the direct map would take it and there would be
    // nothing to trim - see `sevenz_trim_streams_an_archive_over_the_cap`.
    ex.set_sevenz_direct(false);
    ex.set_holds_cap(1); // floors at 8 MB, so the archive is 3x the cap
    let high_base = feed_paced_tail_first(&ex, 0, "big.7z", &arch, 256 << 10, 2 << 20, 0);
    assert!(
        high_base > 0,
        "nothing was ever trimmed - the test proved nothing"
    );
    assert_eq!(
        ex.trim_spilled_off_lock(),
        high_base,
        "bytes left RAM that the off-lock route never wrote"
    );
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The nested compressed set of
/// `a_nested_chase_over_the_cap_spills_its_trim_and_streams`, fed the
/// same way: the CHILD trims under an 8 MB cap and, being a child,
/// spills every trimmed byte. Returns the extractor still open.
fn run_nested_trim_chase(dir: &Path) -> Arc<Extractor> {
    let (_, vols, names) = chase_volume_set();
    let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = names
        .iter()
        .zip(vols.iter())
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&outer_entries);
    let headroom = 3 * vols[0].len();
    let ex = Arc::new(Extractor::new(dir, 4, true));
    ex.anchor();
    ex.set_holds_cap(1);
    eat_budget_to(&ex, 1, headroom, 151);
    let cum: Vec<usize> = vols
        .iter()
        .scan(0usize, |t, v| {
            *t += v.len();
            Some(*t)
        })
        .collect();
    let (art, lead) = (7000usize, 2usize);
    for i in 0..outer.len().div_ceil(art) {
        let s = i * art;
        let e = (s + art).min(outer.len());
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
        let arrived = cum.iter().take_while(|&&c| c <= e).count();
        let lagging = || {
            arrived >= lead
                && ex.chase_consumed_volumes() + lead <= arrived
                && ex.chase_retained_bytes() > 0
        };
        let deadline = std::time::Instant::now() + NO_PROGRESS;
        while lagging() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if lagging() {
            eprintln!(
                "PACED FEED DEADLINE EXPIRED: chunk {i} fed but engine consumed only {} volumes \
                 (lead {lead}, retained {} bytes) after {}s - the rest of this case measures a \
                 runaway feed, not the paced shape it was written for",
                ex.chase_consumed_volumes(),
                ex.chase_retained_bytes(),
                NO_PROGRESS.as_secs()
            );
        }
    }
    ex
}

/// The RAR twin of the 7z oracle above, on a CHILD slot (the only RAR
/// trim that always spills): every trimmed byte went through the
/// off-lock route. `chase_trimmed_bytes` counts RAR trims at commit,
/// so the two counters must agree exactly.
#[test]
fn rar_trim_spills_off_the_routing_lock() {
    let dir = tmpdir("rar-trim-offlock");
    let ex = run_nested_trim_chase(&dir);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert!(ex.chase_trimmed_bytes() > 0, "the child never trimmed");
    assert_eq!(ex.chase_dropped_bytes(), 0, "a child dropped");
    assert_eq!(
        ex.trim_spilled_off_lock(),
        ex.chase_trimmed_bytes(),
        "trimmed bytes that the off-lock route never wrote"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 37 item 3. A spill whose write fails must leave the prefix in
/// RAM - the old shape drained the buffer first and wrote second, so a
/// transient ENOSPC left a hole in neither place. The failure is
/// injected by PARKING the slot's writer (custody for an external
/// tool: its handle is closed and every write fails NotConnected),
/// which is the one write failure a test can raise without a full
/// disk. The article that planned the spill gets the error, as it
/// always did; `base` has not moved, every byte is still retained,
/// and once the writer is back the next breach trims and the job
/// finishes one-pass byte-exact - no hole, no demote.
#[test]
fn a_failed_spill_keeps_the_prefix_in_ram() {
    let f = noisy(24 << 20, 141);
    let arch = sevenz_archive(
        &[("F.bin", &f)],
        Some(vec![sevenz_rust2::EncoderConfiguration::new(
            sevenz_rust2::EncoderMethod::COPY,
        )]),
        false,
    );
    let dir = tmpdir("7z-trim-enospc");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    // Copy fixture: the direct map would take it and there would be
    // nothing to trim - see `sevenz_trim_streams_an_archive_over_the_cap`.
    ex.set_sevenz_direct(false);
    ex.set_holds_cap(1);
    let n = arch.len();
    let chunk = 256 << 10;
    let put = |off: usize, end: usize| {
        ex.write(0, "big.7z", n as u64, off as u64, &arch[off..end.min(n)])
    };
    put(0, chunk).unwrap();
    let tail_from = n.saturating_sub(chunk * 2).max(chunk);
    put(tail_from, n).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match sevenz_ctl(&ex, 0) {
            Some(c) if c.trim_ok.load(Ordering::Relaxed) => break,
            Some(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
            None => break,
        }
    }
    // The slot has classified, so the writer the trim will spill into
    // is the one created now - parked, every spill write fails.
    let writer = {
        let mut g = ex.inner.lock().unwrap();
        let inner = &mut *g;
        ex.ensure_plain_writer(inner, 0).unwrap()
    };
    writer.park().unwrap();
    let buf = ex.inner.lock().unwrap().slots[0]
        .chase
        .as_ref()
        .map(|c| c.buf.clone())
        .unwrap();
    let mut failed = 0usize;
    let mut off = chunk;
    while off < tail_from {
        match put(off, off + chunk) {
            Ok(_) => {}
            Err(e) => {
                failed += 1;
                assert!(e.to_string().contains("parked"), "{e}");
                // The prefix never left RAM: base unmoved, retained ==
                // everything below the tail, and nothing was committed.
                assert_eq!(buf.base(), 0, "a failed spill moved base");
                // `stored` is the run plus the parked tail, so "the
                // whole run is still in RAM" reads as at least the
                // contiguous edge from offset 0.
                assert!(
                    buf.stored() as u64 >= buf.frontier(),
                    "a failed spill left bytes in neither place: {} retained, run to {}",
                    buf.stored(),
                    buf.frontier()
                );
                assert_eq!(ex.trim_spilled_off_lock(), 0);
                assert_eq!(
                    ex.chase_retained_bytes(),
                    buf.stored(),
                    "budget out of step"
                );
                writer.unpark().unwrap();
            }
        }
        off += chunk;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let low = sevenz_ctl(&ex, 0).map_or(u64::MAX, |c| c.low_water.load(Ordering::Relaxed));
            if low + (2 << 20) >= buf.frontier() || std::time::Instant::now() > deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    assert_eq!(failed, 1, "the parked writer failed {failed} spills");
    assert!(buf.base() > 0, "no trim after the writer came back");
    assert_eq!(ex.trim_spilled_off_lock(), buf.base());
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The breach rule the off-lock spill needs (found on the loopback
/// mock, 23 Aug 2026, 20 connections): a holds-cap breach that lands
/// while a spill is still being written is relief in flight, not a
/// forfeit. `breach_stands` answers false and marks the carrying write
/// to wait for the spill; once nothing is in flight the same breach
/// stands. Without the deferral the first concurrent breach demoted a
/// 1 GB COPY 7z that the under-lock write streamed.
#[test]
fn a_breach_during_an_in_flight_spill_is_deferred_not_forfeited() {
    let dir = tmpdir("spill-breach-defer");
    let ex = Extractor::new(&dir, 1, true);
    ex.set_holds_cap(1); // floors at 8 MB
    let mut g = ex.inner.lock().unwrap();
    let inner = &mut *g;
    assert!(
        !Extractor::breach_stands(inner),
        "no breach under an empty budget"
    );
    inner.budget.add(9 << 20);
    assert!(inner.budget.over());
    inner.spills_in_flight = 1;
    assert!(
        !Extractor::breach_stands(inner),
        "a breach with a spill in flight forfeited"
    );
    assert!(
        inner.defer_breach,
        "the deferred breach did not mark its write"
    );
    inner.defer_breach = false;
    inner.spills_in_flight = 0;
    assert!(
        Extractor::breach_stands(inner),
        "a breach with nothing in flight was waved through"
    );
    assert!(!inner.defer_breach);
    inner.budget.sub(9 << 20);
    drop(g);
    std::fs::remove_dir_all(&dir).unwrap();
}
