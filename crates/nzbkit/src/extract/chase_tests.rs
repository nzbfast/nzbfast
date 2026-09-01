//! The chase engine's tests, split out of `chase.rs` whole (TODO 106
//! size gate) - the code is verbatim, only the indent changed. Same
//! shape as `crypto_tests.rs` and `mod_tests.rs` beside it: a `#[path]`
//! child of the module under test, so `super::*` still reaches
//! everything the inline block reached.
//!
//! Halved again on 23 Aug 2026, at 3,000 lines against a 3,000-line
//! ceiling: the shape-and-volume half is `chase_shape_tests.rs`, and
//! its header says what went and why. What stayed is the engine's
//! dynamics - the one-pass and gated basics, frontier gaps, the holds
//! budget and the drop-behind trim, paging, the resume ledger and the
//! forfeit paths - which is where the fixtures and the fused case live.

use super::*;
use crate::rar::fixtures;

use super::chase_shape_tests::chase_decodes_a_volume_before_its_tail_arrives;
use crate::extract::park::park_engage_mark;
use crate::extract::testutil::*;

/// A store outer wrapping a COMPRESSED RAR5 inner: the chase engages
/// (no demotion), the final payload is byte-identical, and neither
/// the outer volume nor the inner archive ever exists on disk.
#[test]
fn chase_compressed_inner_one_pass() {
    let dir = tmpdir("chase1");
    let f = payload(300_000, 91);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 7000, 9);
    let rep = ex.finish().unwrap();
    // No fallback = the chase ran, it did not demote.
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert!(
        rep.extracted
            .iter()
            .any(|(n, s)| n == "F.bin" && *s == f.len() as u64),
        "{:?}",
        rep.extracted
    );
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    // One pass: no outer volume, no intermediate archive - ever.
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    // And no paging: a healthy chase with no terminal verdict must
    // never pay the stalled-frontier spill's I/O.
    assert_eq!(ex.holds_paged_total(), 0, "a healthy chase paged");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// §94 B: a GATED chase parks until the verified watermark covers
/// what it wants to decode, then completes byte-exact. The gate is
/// driven by hand here exactly as the verifier drives it (engage at
/// claim, advance as blocks verify) - the extractor-side contract is
/// what this pins: gated buffers wait, wake on advance, and the
/// result is indistinguishable from an ungated run.
#[test]
fn gated_chase_waits_for_verification_then_completes() {
    let dir = tmpdir("chase-gate");
    let f = payload(300_000, 96);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 1, true);
    let gate = crate::live::VerifyGate::new(1);
    ex.set_verify_gate(gate.clone());
    gate.engage(0); // the verifier claimed slot 0
    feed(&ex, 0, "v.rar", &outer, 7000, 9);
    // The chase worker is parked at watermark 0 with every byte
    // already in the frontier. Release it the way verification
    // does: an advance to the volume midpoint, then full.
    let total = outer.len() as u64;
    let g = gate.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(120));
        g.advance(0, total / 2);
        std::thread::sleep(std::time::Duration::from_millis(120));
        g.advance(0, u64::MAX);
    });
    let rep = ex.finish().unwrap();
    t.join().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Out-of-order arrival with a mid-file gap filled LAST: the chase
/// worker blocks at the frontier until the gap span lands, then runs
/// through - proving the frontier buffer's hole tracking and the
/// blocking read contract end to end.
#[test]
fn chase_blocks_at_frontier_until_gap_fills() {
    let dir = tmpdir("chase-gap");
    // noisy: the packed inner archive stays ~150 KB, so the outer
    // really spans many articles and the gap sits mid-bitstream.
    let f = noisy(300_000, 92);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let art = 999usize; // odd size: gap edges land mid-anything
    let n_arts = outer.len().div_ceil(art);
    let gap = n_arts / 2;
    let ex = Extractor::new(&dir, 1, true);
    // Everything except the gap article, in reverse order (offset 0
    // arrives late, spans park out of order in the frontier buffer).
    for i in (0..n_arts).rev() {
        if i == gap {
            continue;
        }
        let s = i * art;
        let e = (s + art).min(outer.len());
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
    }
    // The chase is attached and its worker blocked at the gap; fill it.
    let (s, e) = (gap * art, ((gap + 1) * art).min(outer.len()));
    ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
        .unwrap();
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// PAR2 interplay: a rebuilt block re-enters via patch_volume_span ->
/// routing -> frontier fill, and the blocked chase simply unblocks.
/// No chase-specific repair code exists - this proves none is needed.
#[test]
fn chase_unblocks_on_patched_volume_span() {
    let dir = tmpdir("chase-patch");
    let f = noisy(300_000, 93);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let art = 1000usize;
    let n_arts = outer.len().div_ceil(art);
    let lost = n_arts / 2;
    let ex = Extractor::new(&dir, 1, true);
    for i in 0..n_arts {
        if i == lost {
            continue;
        }
        let s = i * art;
        let e = (s + art).min(outer.len());
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
    }
    // "Repair" rebuilds the lost article's bytes and patches them in.
    let (s, e) = (lost * art, ((lost + 1) * art).min(outer.len()));
    ex.patch_volume_span(0, s as u64, &outer[s..e]).unwrap();
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Shape-coverage row 27, closed: poster-side damage in the OUTER
/// (the article CRC passes over wrong bytes, only PAR2 sees them)
/// under a GATED run. The differing bytes are delivered, not a hole;
/// the child chase decodes through the parent's watermark
/// (`ChildGate`), parks at the damaged block instead of consuming it,
/// the mapped repair delivers the corrected span into the child
/// frontier BEHIND nothing, and the chase finishes one-pass: no
/// fallback, byte-exact output, no inner archive on disk. Before the
/// child gate existed this exact delivery forfeited with `"repair
/// rewrote chased bytes"` and cost 2.55x payload of disk I/O
/// (measured 22 Aug 2026).
///
/// The gate is driven by hand as the verifier drives it: engaged at
/// claim, advanced to the damaged block (the Ok-prefix stops there),
/// released in full once the repair has proved the set - which is the
/// `release_verify_gate` call settle makes.
#[test]
fn gated_child_chase_takes_a_differing_repair_without_forfeit() {
    let dir = tmpdir("chase-row27");
    let f = noisy(2_400_000, 127);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    const BAD: usize = 10;
    const STEP: usize = 50_000;
    assert!(
        outer.len() > (BAD + 4) * STEP,
        "outer too small: {}",
        outer.len()
    );

    // Anchored: the child gate reaches the root through the chain.
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    let gate = crate::live::VerifyGate::new(1);
    ex.set_verify_gate(gate.clone());
    gate.engage(0);
    // Everything before the damage is vouched for; the damaged block
    // and everything after it is not (a Bad block stops the prefix).
    gate.advance(0, (BAD * STEP) as u64);
    for (i, chunk) in outer.chunks(STEP).enumerate() {
        let off = (i * STEP) as u64;
        let bytes: std::borrow::Cow<[u8]> = if i == BAD {
            let mut stale = chunk.to_vec();
            for b in stale.iter_mut() {
                *b ^= 0xff;
            }
            stale.into()
        } else {
            chunk.into()
        };
        ex.write(0, "v.rar", outer.len() as u64, off, &bytes)
            .unwrap();
    }
    // The child decode is parked at the translated watermark: give it
    // time to prove it by NOT passing the damage. Child offsets sit
    // `data_off` below the outer's, so the outer bound is the looser.
    let served_before = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(400);
        let mut last = None;
        while std::time::Instant::now() < deadline {
            last = child_chase_served(&ex);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        last.expect("the child chase attached")
    };
    assert!(
        served_before < (BAD * STEP) as u64,
        "the gated child decode read past the damaged block: {served_before}"
    );
    // The mapped repair: the corrected bytes through the repair path,
    // then the set is proved and the gate released.
    let fixed = &outer[BAD * STEP..(BAD + 1) * STEP];
    ex.patch_volume_span(0, (BAD * STEP) as u64, fixed).unwrap();
    ex.release_verify_gate();
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.is_empty(),
        "the chase forfeited: {:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A RAR4 inner whose "compressed" member is a lying method byte over
/// store bytes: the chase attaches (RAR4 chases now), the decode
/// fails, and the group demotes to a byte-exact materialized level-1
/// archive - the job still succeeds with today's output.
#[test]
fn chase_demotes_on_rar4() {
    let dir = tmpdir("chase-rar4");
    let data = payload(60_000, 94);
    let mut v4 = fixtures::rar4_volume(&[("c.bin", 60_000, &data, false, false)]);
    // Flip the fixed-layout method byte to "compressed" (see the
    // rar.rs compressed_flagged_not_store test for the offset math).
    let m_off = 7 + 13 + 11 + 14;
    assert_eq!(v4[m_off], 0x30);
    v4[m_off] = 0x33;
    fixtures::restamp_v4_block(&mut v4, fixtures::V4_FIRST_BLOCK);
    assert_not_store(&v4);
    let outer = fixtures::rar5_volume(&[("inner.rar", v4.len() as u64, &v4, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 5000, 11);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), v4);
    assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Budget breach mid-chase: the retained frontier bytes charge the
/// SHARED holds budget, and crossing the cap demotes the group to a
/// materialized level-1 archive - complete and byte-exact, with the
/// partial chase output deleted, no hang, no leaked worker.
#[test]
fn chase_budget_breach_demotes() {
    let dir = tmpdir("chase-budget");
    // ~1.2 MB packed (half-entropy input bounds it near half size).
    let f = noisy(2_400_000, 95);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    assert!(
        inner_arch.len() > 900_000,
        "packed too small: {}",
        inner_arch.len()
    );
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 3, true);
    ex.set_holds_cap(1); // floors at 8 MB
    // Eat most of the budget with two never-classifying slots held
    // just under their per-slot spill (4 MB each at this cap).
    let junk = payload(65_000, 96);
    for slot in [1usize, 2] {
        for i in 0..60u64 {
            ex.write(
                slot,
                &format!("dummy{slot}.bin"),
                8_000_000,
                64_000 + i * 65_000,
                &junk,
            )
            .unwrap();
        }
    }
    // Sequential outer feed: the chase attaches at the inner sniff,
    // then its retained bytes push the shared budget over the cap.
    for (i, chunk) in outer.chunks(50_000).enumerate() {
        ex.write(0, "v.rar", outer.len() as u64, (i * 50_000) as u64, chunk)
            .unwrap();
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    // The level-1 archive materialized COMPLETE (buffer bytes +
    // post-demote write-through), ready for the disk post-pass.
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
    assert!(!dir.join("F.bin").exists(), "partial chase output survived");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Three junk slots holding the shared holds budget down to about
/// `headroom` bytes of slack, without any of them crossing the
/// per-slot unclassified spill (a quarter of the cap, floored at
/// 4 MB) that would send them to disk instead.
pub(in crate::extract) fn eat_budget_to(
    ex: &Extractor,
    first_slot: usize,
    headroom: usize,
    seed: u8,
) {
    const CAP: usize = 8 << 20; // set_holds_cap(1) floors here
    const CHUNK: usize = 65_000;
    let want = CAP.saturating_sub(headroom);
    let per_slot = want.div_ceil(3);
    let chunks = per_slot / CHUNK;
    assert!(
        per_slot < 4 << 20,
        "a junk slot would spill instead of holding: {per_slot}"
    );
    let junk = payload(CHUNK, seed);
    for slot in first_slot..first_slot + 3 {
        for i in 0..chunks as u64 {
            ex.write(
                slot,
                &format!("dummy{slot}.bin"),
                8_000_000,
                64_000 + i * CHUNK as u64,
                &junk,
            )
            .unwrap();
        }
    }
}

/// The posted compressed set the drop-behind tests share: payload,
/// volumes and volume names.
///
/// The member has to clear 4 MiB - `should_stream_decode`'s bar, and
/// therefore the incremental split path's - and encoding it is slow
/// enough (tens of seconds in a debug build) that the sixteen cases
/// build it once between them, through `chase_volume_set_cases`.
pub(in crate::extract) fn chase_volume_set() -> &'static (Vec<u8>, Vec<Vec<u8>>, Vec<String>) {
    static SET: std::sync::OnceLock<(Vec<u8>, Vec<Vec<u8>>, Vec<String>)> =
        std::sync::OnceLock::new();
    SET.get_or_init(|| {
        let f = noisy(5 << 20, 140);
        let vols = rars_compressed_volumes("F.bin", &f, 200_000);
        assert!(vols.len() >= 8, "want many volumes, got {}", vols.len());
        for v in &vols {
            assert_not_store(v);
        }
        let names = (0..vols.len())
            .map(|i| format!("release.part{}.rar", i + 1))
            .collect();
        (f, vols, names)
    })
}

/// The sixteen cases that share `chase_volume_set`, run as ONE test.
///
/// nextest gives every `#[test]` its own process, which puts the
/// `OnceLock` above out of reach: each case built the 5 MiB compressed
/// set again. Measured 17 Aug 2026, when the list was seven cases: 19
/// CPU-seconds apiece - 132 of the chase module's 186 - and about 52 s
/// apiece on a CI Windows runner. Built once, the same seven cost
/// about 20. The list has grown since (sixteen as of 25 Aug 2026, the
/// last addition being TODO 220's nested-chase case) and the per-case
/// figures were not re-taken; the merged test is the suite's one SLOW
/// case, 74.8 s wall on this machine on 22 Aug 2026.
///
/// They are independent: each makes its own tmpdir and its own
/// `Extractor`, and none reads state the others wrote. The price of
/// the merge is that the first failure hides the cases after it, and
/// the panic message is the case that failed rather than the test
/// name - so each keeps its own doc comment and its own name in the
/// backtrace. Those case names are NOT nextest-selectable - it filters
/// on `#[test]` names, so `-E 'test(<a case>)'` runs nothing, exits 0,
/// and verifies nothing. Filter on `chase_volume_set_cases`.
///
/// One case is not in this file: `chase_decodes_a_volume_before_its_tail_arrives`
/// went to `chase_shape_tests.rs` with the rest of its TODO 220 group in
/// the 23 Aug 2026 split, and is imported at the top. That costs the
/// fusion nothing - `chase_volume_set` is a function-local `OnceLock`, so
/// it is one object however many modules call it, and the build was
/// counted after the split to be sure. Wherever a case lives, it must
/// still be CALLED from here: it carries no `#[test]`, so a case that
/// loses its call runs nowhere and fails nothing.
#[test]
fn chase_volume_set_cases() {
    chase_over_cap_multi_volume_set_trims_and_streams();
    chase_over_cap_multi_volume_set_demotes_with_the_trim_off();
    chase_patch_below_the_trim_point_forfeits_and_materializes_repaired();
    a_forfeit_after_a_drop_reports_the_holes_for_refetch();
    a_chase_beside_a_lost_article_spills_instead_of_dropping();
    a_chase_beside_a_doubted_article_spills_instead_of_dropping();
    stalled_chase_pages_cold_frontier_then_demotes_byte_exact();
    chase_read_defers_its_paged_preads_off_the_extractor_lock();
    healthy_chase_never_pages_on_a_loss_it_does_not_own();
    a_hole_ahead_of_the_engine_pages_beyond_it_and_still_resumes();
    a_trim_drops_only_what_the_verifier_vouched_for();
    a_nested_chase_over_the_cap_spills_its_trim_and_streams();
    an_outer_breach_relieves_the_child_chase_before_demoting_the_group();
    a_top_level_breach_relieves_the_chase_before_demoting_a_volume();
    chase_decodes_a_volume_before_its_tail_arrives();
    holds_backpressure_parks_near_the_cap_and_reopens_as_the_engine_catches_up();
    an_sfx_first_volume_chases_and_trims_in_file_coordinates();
    // Not an assert on purpose: a paced-feed expiry is contention, not
    // a defect, and the per-expiry line from the helper already names
    // the volume. This just leaves the tally where a reader looks.
    let n = paced_deadline_expiries();
    if n > 0 {
        eprintln!("chase_volume_set_cases: {n} paced-feed deadline expiries (see lines above)");
    }
}

/// TODO 94 item E (22 Aug 2026): a chased set whose arrivals outrun the
/// engine PARKS its slots at the pool at the engage mark with the room
/// under the cap as their allowance, the allowance shrinks to nothing
/// while the engine is held, reopens once the engine's catch-up trim
/// releases the consumed volumes, and the set never breaks the budget
/// on the way. Deterministic by construction: the engine is held for
/// the whole feed, then let go, so the transitions are forced rather
/// than raced.
///
/// WHAT "BY CONSTRUCTION" COST (§287, 24 Aug 2026). The hold used to be
/// taken AFTER volume 0 was fed, and `pause_chase_reads` was a snapshot
/// of the volumes registered at that instant - so it held the engine
/// only while the engine was still inside volume 0. Lose the race
/// between the last article of volume 0 and the pause (about 200 kB of
/// decode, which a loaded box hands over freely) and the engine is past
/// the one paused buffer; volumes 1..n register during the pause and
/// nothing paused THEM, so the engine ran away through the whole set.
/// It never breached, because `park_reeval` runs the drop-behind trim
/// BEFORE it parks: the runaway engine kept releasing consumed volumes
/// faster than the feed added them, the pressure never reached the
/// engage mark, and the park log stayed empty - the `[]` this case
/// failed with in 2 of 6 full CI sweeps. The pause now latches on the
/// extractor and a volume registering under it is born paused, so it is
/// taken here BEFORE the chase exists and the engine cannot read a byte
/// of ANY volume until the guard drops. That is what the watermark
/// assertion below pins; it is not decoration.
fn holds_backpressure_parks_near_the_cap_and_reopens_as_the_engine_catches_up() {
    let dir = tmpdir("chase-holds-park");
    let (f, vols, names) = chase_volume_set();
    const CAP: usize = 8 << 20; // set_holds_cap(1) floors here
    let engage = park_engage_mark(CAP);
    let packed: usize = vols.iter().map(|v| v.len()).sum();
    let junk = 7 << 19; // 3.5 MiB against the ~3.9 MB packed set
    assert!(
        junk + packed < CAP && junk + packed - vols[vols.len() - 1].len() > engage,
        "the fixture must cross the engage mark without breaching: \
         junk {junk} packed {packed} engage {engage} cap {CAP}"
    );

    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1);
    let log: Arc<std::sync::Mutex<Vec<(Vec<usize>, Option<u64>)>>> = Arc::default();
    let sink = log.clone();
    ex.set_park_hook(
        Arc::new(move |slots: &[usize], allow: Option<u64>| {
            sink.lock().unwrap().push((slots.to_vec(), allow));
        }),
        None,
    );
    eat_budget_to(&ex, vols.len(), CAP - junk, 151);

    // The hold goes on BEFORE the set registers, so every volume of it
    // is born paused and the engine's progress is this test's to give.
    let pause = ex.pause_chase_reads();
    // Volume 0 registers the chase, under the hold.
    feed(&ex, 0, &names[0], &vols[0], 7000, 33);
    assert_eq!(
        ex.chase_watermark_bytes(),
        0,
        "the hold did not reach volume 0 - the engine read {} byte(s) of \
         it, so everything below measures a race and not the backpressure",
        ex.chase_watermark_bytes()
    );
    assert!(log.lock().unwrap().is_empty(), "parked under the mark");
    for i in 1..vols.len() - 1 {
        feed(&ex, i, &names[i], &vols[i], 7000, 33 + i as u64);
    }
    // The mark is crossed part-way through the set: every call so far
    // parks (Some), each names every slot joined so far, and the
    // allowance only ever shrinks while the engine is held - to under a
    // body's worth, which is the liveness floor's job to carry.
    let (parks, parked_union) = {
        let l = log.lock().unwrap();
        assert!(
            !l.is_empty() && l.iter().all(|(_, a)| a.is_some()),
            "{}: park log {l:?} (holds {} of cap {}, engage {engage}, \
             trimmed {}, consumed {} of {}, watermark {})",
            if l.is_empty() {
                "nothing ever parked - the holds never reached the engage \
                 mark, or the trim kept releasing them faster than the feed \
                 filled them"
            } else {
                "a park entry carried no allowance - a RELEASE (None) was \
                 raised while the engine was still held"
            },
            ex.holds_budget_for_tests().len(),
            ex.holds_cap(),
            ex.chase_trimmed_bytes(),
            ex.chase_consumed_volumes(),
            vols.len(),
            ex.chase_watermark_bytes()
        );
        let allows: Vec<u64> = l.iter().map(|(_, a)| a.unwrap()).collect();
        assert!(allows.windows(2).all(|w| w[1] <= w[0]), "{allows:?}");
        assert!(
            *allows.last().unwrap() < 800 * 1024,
            "under one body's worth by the end: {allows:?}"
        );
        let last = &l[l.len() - 1].0;
        let want: Vec<usize> = (0..vols.len() - 1).collect();
        assert_eq!(
            last, &want,
            "every slot of the chased group, and only those"
        );
        (l.len(), want)
    };
    assert_eq!(ex.holds_park_cycles(), 1);
    assert_eq!(
        ex.chase_trimmed_bytes(),
        0,
        "nothing was consumed, so nothing could be trimmed"
    );

    // Let the engine go and catch up on everything fed so far (it can
    // finish volume k only once k+1 has arrived, so it stops one short).
    // Its progress marks drive the pager, whose re-evaluation trims the
    // consumed volumes and reopens the allowance.
    drop(pause);
    let mut seen = ex.chase_consumed_volumes();
    let mut deadline = std::time::Instant::now() + NO_PROGRESS;
    while ex.chase_consumed_volumes() + 2 < vols.len() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(2));
        let c = ex.chase_consumed_volumes();
        if c > seen {
            seen = c;
            deadline = std::time::Instant::now() + NO_PROGRESS;
        }
    }
    assert!(
        ex.chase_consumed_volumes() + 2 >= vols.len(),
        "engine stalled: no volume consumed for {}s at {} of {}",
        NO_PROGRESS.as_secs(),
        ex.chase_consumed_volumes(),
        vols.len()
    );
    let last = vols.len() - 1;
    feed(&ex, last, &names[last], &vols[last], 7000, 33 + last as u64);
    {
        let l = log.lock().unwrap();
        assert!(l.len() > parks, "no refresh after the catch-up: {l:?}");
        let (slots, allow) = &l[l.len() - 1];
        let mut slots = slots.clone();
        slots.sort_unstable();
        let mut want = parked_union.clone();
        want.push(last);
        assert_eq!(slots, want, "the last volume joined the parked group");
        assert!(
            allow.is_some_and(|a| a > 0),
            "the allowance reopened with the room the trim made: {allow:?}"
        );
    }
    assert!(
        ex.chase_trimmed_bytes() > 0,
        "the catch-up trim released nothing"
    );

    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(ex.holds_park_cycles(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 94 C follow-up: the same over-cap set with its FIRST volume
/// behind a launcher stub - what a self-extracting multi-volume release
/// looks like on the wire (`release.exe`, `release.r00`, ...). The chase
/// serves that volume to the engine through the offset adapter, the
/// engine's watermarks come back translated into FILE coordinates, and
/// the drop-behind trim runs off them exactly as on a bare set: the
/// member comes out byte-exact, something was trimmed, and nothing is
/// left on disk - no volume, no stub, no spilled prefix.
fn an_sfx_first_volume_chases_and_trims_in_file_coordinates() {
    let dir = tmpdir("chase-trim-sfx");
    let (f, vols, names) = chase_volume_set();
    let mut vols = vols.clone();
    let mut names = names.clone();
    const STUB: usize = 3_000;
    vols[0] = super::sfx_tests::sfx(STUB, &vols[0]);
    names[0] = "release.exe".to_string();
    let headroom = 3 * vols[0].len();

    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB
    eat_budget_to(&ex, vols.len(), headroom, 143);
    let trimmed = feed_chase_volumes_paced(&ex, &names, &vols, 7000, 2);
    let rep = ex.finish().unwrap();

    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert!(
        trimmed > 0,
        "nothing was ever trimmed - the test proved nothing"
    );
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
    let mut want = vec!["F.bin".to_string()];
    want.extend((0..3).map(|i| format!("dummy{}.bin", vols.len() + i)));
    want.sort();
    assert_eq!(dir_files(&dir), want, "a volume survived the chase");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Bug sweep 22 Aug 2026: a dropped range has no copy anywhere, and the
/// PAR2 settle read-back reads a live chase's still-Pending blocks back
/// through `read_at`, which has nothing to answer below the buffer's
/// base - every such block read as Bad. So with a verify gate attached
/// (every real run, now), a trim DROPS only bytes under the slot's
/// engaged watermark and SPILLS the rest: an unengaged slot (the set
/// not yet active) spills every trim, the same set with every slot
/// vouched for drops, and both chase to the same byte-exact result.
fn a_trim_drops_only_what_the_verifier_vouched_for() {
    let (f, vols, names) = chase_volume_set();
    let headroom = 3 * vols[0].len();
    for vouched in [false, true] {
        let dir = tmpdir(if vouched {
            "chase-drop-vouched"
        } else {
            "chase-drop-unvouched"
        });
        let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
        ex.anchor();
        ex.set_holds_cap(1);
        let gate = crate::live::VerifyGate::new(vols.len() + 3);
        ex.set_verify_gate(gate.clone());
        ex.set_verify_gate_waits(false);
        if vouched {
            for slot in 0..vols.len() {
                gate.engage(slot);
                gate.advance(slot, u64::MAX);
            }
        }
        eat_budget_to(&ex, vols.len(), headroom, 143);
        let trimmed = feed_chase_volumes_paced(&ex, names, vols, 7000, 2);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert!(trimmed > 0, "nothing was ever trimmed");
        if vouched {
            assert!(
                ex.chase_dropped_bytes() > 0,
                "a vouched-for prefix must still drop, or drop-not-spill is dead"
            );
        } else {
            assert_eq!(
                ex.chase_dropped_bytes(),
                0,
                "an unvouched prefix dropped: the settle read-back would find a hole"
            );
        }
        assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The drop ceiling, as arithmetic rather than as a race (TODO 214).
///
/// The three health conditions on the drop gate say nothing about how
/// big the set is, and past `cap / (1 - RAR_DROP_PACE)` a chase that is
/// keeping pace STILL forfeits - measured 22 Aug 2026 at ten times the
/// cap, where the forfeiting legs cost 1.79-2.12x of payload with the
/// drop on against 1.55x with it off, because the re-fetch also stands
/// the resume ledger down. Pinned here as a pure function because the
/// end-to-end shape is a coin flip on a busy box, which is exactly what
/// a test must not assert.
#[test]
fn the_drop_ceiling_is_five_times_the_cap() {
    let cap = 943_000_000usize;
    let five = (cap as f64 / (1.0 - Extractor::RAR_DROP_PACE)) as u64;
    assert!(
        Extractor::rar_drop_can_finish(cap, five - 1),
        "a set just inside five times the cap must still drop"
    );
    assert!(
        !Extractor::rar_drop_can_finish(cap, five + cap as u64),
        "a set comfortably past the line must not"
    );
    // The two rungs the 22 Aug rounds actually ran, against this set:
    // 4713 MB of volumes at a 943 MB cap is 4.999x and drops, at a
    // 471 MB cap it is 10x and does not.
    assert!(Extractor::rar_drop_can_finish(942_750_000, 4_712_959_327));
    assert!(!Extractor::rar_drop_can_finish(471_150_000, 4_712_959_327));
    // Zero-sized edge: nothing seen yet cannot be past any line.
    assert!(Extractor::rar_drop_can_finish(1, 0));
}

/// THE test that defines the drop-behind: a posted compressed set
/// whose retained bytes are several times the budget headroom chases
/// all the way to completion, byte-exact, with nothing left on disk -
/// because the engine keeps saying which volumes it is finished with
/// and routing keeps releasing them into the volumes' own files.
///
/// Before the incremental split decode this shape could only demote:
/// the split member decoded at its FINISH fragment, so every volume
/// had to be retained until the last one landed.
fn chase_over_cap_multi_volume_set_trims_and_streams() {
    let dir = tmpdir("chase-trim-stream");
    let (f, vols, names) = chase_volume_set();
    let packed: usize = vols.iter().map(|v| v.len()).sum();
    let headroom = 3 * vols[0].len();
    assert!(
        packed > 4 * headroom,
        "the set must be well past the headroom or the test proves nothing: \
         {packed} vs {headroom}"
    );

    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB
    eat_budget_to(&ex, vols.len(), headroom, 141);
    let trimmed = feed_chase_volumes_paced(&ex, names, vols, 7000, 2);
    let rep = ex.finish().unwrap();

    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert!(
        trimmed > 0,
        "nothing was ever trimmed - the test proved nothing"
    );
    // Drop-not-spill (22 Aug 2026): a healthy top-level chase releases
    // its consumed prefix with no disk copy, and a chase that SUCCEEDS
    // leaves nothing for anyone to re-fetch.
    assert!(
        ex.chase_dropped_bytes() > 0,
        "a healthy chase spilled every trim: {trimmed} trimmed, 0 dropped"
    );
    assert!(
        ex.dropped_volumes().is_empty(),
        "{:?}",
        ex.dropped_volumes()
    );
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
    // The payload plus the budget-eating junk slots, and nothing
    // else: no volume, and no spilled prefix of one.
    let mut want = vec!["F.bin".to_string()];
    want.extend((0..3).map(|i| format!("dummy{}.bin", vols.len() + i)));
    want.sort();
    assert_eq!(
        dir_files(&dir),
        want,
        "a spilled volume survived the successful chase"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The same set with the trim gated OFF demotes, exactly as it did
/// before drop-behind existed. Two things at once: the escape hatch
/// works, and the test above is measuring the trim rather than a
/// budget that was never tight.
fn chase_over_cap_multi_volume_set_demotes_with_the_trim_off() {
    assert!(rar_trim_env_off_value(Some("1")));
    assert!(!rar_trim_env_off_value(Some("0")));
    assert!(!rar_trim_env_off_value(None));

    let dir = tmpdir("chase-trim-off");
    let (_, vols, names) = chase_volume_set();
    let headroom = 3 * vols[0].len();

    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1);
    ex.set_rar_trim(false);
    // Paging OFF as well as the trim: the two are independent budget
    // reliefs, and this case measures the trim escape hatch. With paging
    // on, a loaded box takes the scratch-paging branch instead - "held
    // spans over the RAM cap - paging to scratch, set stays one-pass" -
    // which relieves the breach without a forfeit, so the set never
    // demotes and the assertion below fired with an empty `[]` on a busy
    // runner (TODO 241, both retries). With both reliefs off the only
    // answer to an over-cap set is the demote, whatever the load.
    ex.set_holds_paging(false);
    eat_budget_to(&ex, vols.len(), headroom, 143);
    for (index, vol) in vols.iter().enumerate() {
        feed(&ex, index, &names[index], vol, 7000, 33 + index as u64);
    }
    let rep = ex.finish().unwrap();

    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("held-bytes cap: chase memory")),
        "trim and paging both off, so the over-cap set must demote on the \
         held-bytes cap; got fallbacks {:?}, trimmed {} B, paged {} B, \
         holds peak {} B against an 8 MB cap",
        rep.fallbacks,
        ex.chase_trimmed_bytes(),
        ex.holds_paged_total(),
        ex.holds_peak(),
    );
    assert_eq!(ex.chase_trimmed_bytes(), 0, "the gate did not hold");
    // Every volume materialized COMPLETE, ready for the disk pass.
    for (index, vol) in vols.iter().enumerate() {
        assert_eq!(
            &std::fs::read(dir.join(&names[index])).unwrap(),
            vol,
            "{}",
            names[index]
        );
    }
    assert_resume_ledger_honest(&dir, "F.bin", &rep, &chase_volume_set().0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The nested twin of `chase_over_cap_multi_volume_set_trims_and_streams`:
/// the same compressed set, wrapped in a STORE outer so it is chased on
/// a CHILD slot at depth 1.
///
/// A 22 Aug 2026 measured round reported `holds peak 6492 MB - chase
/// trimmed 0 MB (0 dropped)` on a CLEAN 6.49 GB nested set and read it
/// as "the drop-behind never fires on a child slot". Nothing in
/// `rar_trim_set` is depth-gated and the trim does fire; what that round
/// actually saw is a budget nothing ever breached - on a box whose auto
/// budget ceiling is 16 GiB, holds_cap was 7.2 GiB against a 6.05 GiB
/// set, so `budget.over()` was never true. Measured again with the cap
/// moved UNDER the set, the same shape forfeits at every rung - and
/// forfeits identically at depth 0, because the bar is the VOLUME size
/// against the cap and not the nesting.
///
/// So this pins the two halves separately, which is what no test did
/// before: under a cap the set cannot fit, the CHILD trims and stays
/// one-pass, and every trimmed byte SPILLS. The spill is not a
/// shortcoming - `drop` carries `self.depth == 0` because one-pass never
/// materialises the outer, so a dropped range in an inner volume has no
/// copy anywhere and no re-fetch can reach it. A change that makes a
/// child drop turns this set into an unrecoverable one.
///
/// TODO 37 med1, the second claim: THE SPILL MUST NOT MOVE THE BOMB
/// RATIO. A child spill goes out through `ensure_plain_writer`, which
/// at depth > 0 attaches the decompression-bomb budget - right while
/// the prefix is on the volume, wrong the moment `chase_finish` unlinks
/// it. Uncredited, this job ends with the whole trimmed prefix still
/// counted against an allowance that stands for free space, and the
/// next nested archive in the same job is judged against what is left:
/// enough of them and a legitimate extract is refused as a bomb. So the
/// budget here must end at the payload exactly, however much was
/// spilled on the way.
fn a_nested_chase_over_the_cap_spills_its_trim_and_streams() {
    let dir = tmpdir("chase-trim-nested");
    let (f, vols, names) = chase_volume_set();
    let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = names
        .iter()
        .zip(vols.iter())
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&outer_entries);
    let headroom = 3 * vols[0].len();

    let ex = Arc::new(Extractor::new(&dir, 4, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB
    // Room for the payload several times over: the claim below is what
    // the budget READS at the end, not whether it trips.
    ex.set_extract_budget(64 << 20);
    eat_budget_to(&ex, 1, headroom, 149);

    // Cumulative inner-volume sizes, so the paced feed below can say
    // which inner volume the outer bytes fed so far have completed.
    // Approximate by the outer's headers, and deliberately so: it is a
    // pacing signal, not an assertion.
    let cum: Vec<usize> = vols
        .iter()
        .scan(0usize, |t, v| {
            *t += v.len();
            Some(*t)
        })
        .collect();
    // Sequential, not `feed`'s shuffle: the inner volumes sit in the
    // outer in volume order, so an in-order feed is what makes the
    // child's arrivals arrive in order. Paced on the CHILD's own
    // progress - every chase accessor walks the child chain - for the
    // reason `feed_chase_volumes_paced` documents: an unpaced feed
    // outruns the decode, and a breach that finds nothing finished
    // demotes, which is the honest answer to that arrival pattern and
    // not what a drop-behind test is trying to measure.
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
    let rep = ex.finish().unwrap();

    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert!(
        ex.chase_trimmed_bytes() > 0,
        "the child chase never trimmed: holds peak {} B against an 8 MB cap",
        ex.holds_peak()
    );
    // The depth gate, stated as an assertion rather than a comment.
    assert_eq!(
        ex.chase_dropped_bytes(),
        0,
        "a child slot dropped bytes that nothing on the wire can restore"
    );
    assert!(
        ex.dropped_volumes().is_empty(),
        "{:?}",
        ex.dropped_volumes()
    );
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
    // The spill was charged while it existed and credited back when
    // `chase_finish` unlinked it, so what the guard sees is the payload
    // and nothing else. Uncredited this reads f + the trimmed bytes.
    assert_eq!(
        ex.extract_budget_used(),
        f.len() as u64,
        "the unlinked spill is still counted against the bomb budget \
         ({} B trimmed, payload {} B)",
        ex.chase_trimmed_bytes(),
        f.len()
    );
    // One pass: the payload and the budget-eating junk slots, and no
    // spilled inner volume left beside them (`chase_finish` deletes the
    // partial file a spill wrote, at every depth).
    let mut want = vec!["F.bin".to_string()];
    want.extend((1..4).map(|i| format!("dummy{i}.bin")));
    want.sort();
    assert_eq!(
        dir_files(&dir),
        want,
        "a spilled inner volume survived the successful nested chase"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A held-bytes breach that an OUTER slot notices must not take the
/// outer group down while a child chase is holding the budget.
///
/// Measured 22 Aug 2026 (`research/MEASURED-HOLDS-RACE-2026-08-22.md`).
/// The budget is shared root-to-child, so two call sites can see
/// `budget.over()` and they used to do completely different things
/// about it. `chase_span` trims, and forfeits only if the trim did not
/// relieve. An outer slot's hold or header stash went straight to
/// `fallback_slot_or_group`, which materializes the outer group,
/// DELETES the inner volumes already written in-stream
/// (`delete_group_out_files`) and aborts the child chase under them
/// (`abandon_slot`) - so the outer is unpacked again from disk and the
/// inner volumes written a second time. Which site saw it first was a
/// race: on the `gran` fixture two reps of one configuration cost
/// 2.083x and 4.566x of payload in device I/O, and across a rung ladder
/// the expensive ending reached 4.806x against 1.808x one-pass.
///
/// THE BREACH IS MANUFACTURED, and it has to be. Leaving it to the race
/// is what the round measured: a first attempt here fed a large
/// out-of-order outer slab and passed with the fix REMOVED, because the
/// child's own site got there first every time. So the budget is put
/// over by hand under the lock and then ONE small outer span is
/// written - small on purpose, under `HOLDS_PAGE_MIN`, because a hold
/// that paging can move is not the breach in question. That is the real
/// call site, driven deterministically.
///
/// What is pinned is only the part that is always true. Whether the
/// relief stops at the trim or goes on to forfeit the chase depends on
/// what the engine has consumed by then, and both are correct endings.
/// The OUTER volume materializing is not: it means the chain paid the
/// expensive ending for two kilobytes of somebody else's hold.
fn an_outer_breach_relieves_the_child_chase_before_demoting_the_group() {
    let dir = tmpdir("chase-relief-outer");
    let (_, vols, names) = chase_volume_set();
    let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = names
        .iter()
        .zip(vols.iter())
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&outer_entries);

    let ex = Arc::new(Extractor::new(&dir, 4, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB

    let cum: Vec<usize> = vols
        .iter()
        .scan(0usize, |t, v| {
            *t += v.len();
            Some(*t)
        })
        .collect();
    let (art, lead) = (7000usize, 2usize);
    // The far-end slab is held back so there is an unmapped offset left
    // to write at after the chase is live: beyond `mapped_through` with
    // the mapper incomplete, an outer span is HELD, which is the site.
    let tail = outer.len() - 2048;
    let chunks = tail.div_ceil(art);
    let mut breached = false;
    for i in 0..chunks {
        let s = i * art;
        let e = (s + art).min(tail);
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
        if !breached && ex.chase_retained_bytes() > (128 << 10) {
            // Over the cap by hand, and only JUST over: a real run gets
            // here by the chase sitting at the cap when a header
            // parses, which is a race no test can schedule. Only just,
            // because relief that cannot clear the overshoot is
            // supposed to decline - an inflated charge no forfeit could
            // ever cover would test the decline, not the ladder. The
            // charge is given back below.
            let fake = {
                let inner = ex.inner.lock_ok();
                let fake = inner.budget.cap().saturating_sub(inner.budget.len()) + 1;
                inner.budget.add(fake);
                fake
            };
            ex.write(0, "v.rar", outer.len() as u64, tail as u64, &outer[tail..])
                .unwrap();
            ex.inner.lock_ok().budget.sub(fake);
            breached = true;
        }
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
    assert!(breached, "the chase never held a byte - nothing was tested");
    let rep = ex.finish().unwrap();

    let files = dir_files(&dir);
    assert!(
        !files.iter().any(|n| n == "v.rar"),
        "the outer materialized for a child chase's budget: {files:?} / {:?}",
        rep.fallbacks
    );
    // Every inner volume the chase gave up is COMPLETE, whichever
    // ending the relief took - the disk pass reads these.
    for (index, vol) in vols.iter().enumerate() {
        let p = dir.join(&names[index]);
        if p.exists() {
            assert_eq!(&std::fs::read(&p).unwrap(), vol, "{}", names[index]);
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The resume ledger at the seam, driven directly rather than through a
/// race with the decode: what `chase_teardown` does to a sink slot on a
/// held-bytes-cap forfeit, what `finish` then does to the file, and what
/// a repair does to both.
///
/// The end-to-end route into this is the trim-then-forfeit sequence a
/// fast line produces (`research/MEASURED-HOLDS-LADDER-2026-08-21.md`
/// §3), and whether the engine has flushed a megabyte to the sink by
/// the time the breach fires depends on how loaded the machine is - so
/// the suite pins the CONTRACT here and the invariant
/// (`assert_resume_ledger_honest`) on the real forfeit paths.
///
/// The slot is set up exactly as a chase sink sets one up: a plain write
/// of a member's leading bytes into a freshly allocated slot, declared
/// at the member's full size so the writer preallocates - which is the
/// whole reason the ledger has to truncate.
#[test]
fn a_kept_sink_slot_is_measured_and_cut_to_its_contiguous_prefix() {
    let dir = tmpdir("resume-ledger-cut");
    let f = payload(400_000, 61);
    // Depth 1, the shape a chase sink's child really has: the prefix
    // hash arms on nested plain writers only, and without it the ledger
    // records nothing at all (TODO 217).
    let ex = Extractor::new_nested_for_tests(&dir, 1);
    // Declared 1 MB, 400 KB delivered: the file is created full-length
    // and sparse, which is what a `stat` would read as a complete
    // extraction if nothing cut it down.
    ex.write(0, "F.bin", 1_000_000, 0, &f).unwrap();
    let out = dir.join("F.bin");
    assert_eq!(
        std::fs::metadata(&out).unwrap().len(),
        1_000_000,
        "the writer did not preallocate - this test proves nothing"
    );

    let kept = ex.retain_slot_output(0).expect("a settled plain output");
    assert_eq!(kept.0, "F.bin");
    {
        let mut inner = ex.inner.lock_ok();
        inner.resume_pending.push(kept);
        let ledger = Extractor::settle_resume_ledger(&mut inner);
        assert_eq!(ledger.len(), 1, "{ledger:?}");
        assert_eq!(ledger[0].member, "F.bin");
        assert_eq!(ledger[0].path, out);
        assert_eq!(ledger[0].len, 400_000);
        assert_eq!(
            ledger[0].crc32,
            crc32fast::hash(&f),
            "the mark's crc must be the crc of the delivered prefix"
        );
    }
    assert_eq!(
        std::fs::read(&out).unwrap(),
        f,
        "the kept file must be the delivered prefix, cut to length"
    );
    // And the slot swallows everything after: a late span must not
    // extend a file the ledger has already measured.
    ex.write(0, "F.bin", 1_000_000, 400_000, &payload(1_000, 62))
        .unwrap();
    assert_eq!(std::fs::metadata(&out).unwrap().len(), 400_000);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A GAP in the delivered bytes is what makes the mark the contiguous
/// prefix rather than the byte count: a hole at 100 KB means only the
/// first 100 KB may be resumed from, however much landed above it.
#[test]
fn a_kept_sink_slot_is_measured_to_the_hole_not_the_byte_count() {
    let dir = tmpdir("resume-ledger-hole");
    let f = payload(300_000, 63);
    let ex = Extractor::new_nested_for_tests(&dir, 1);
    ex.write(0, "F.bin", 1_000_000, 0, &f[..100_000]).unwrap();
    ex.write(0, "F.bin", 1_000_000, 200_000, &f[200_000..])
        .unwrap();

    let kept = ex.retain_slot_output(0).expect("a settled plain output");
    let mut inner = ex.inner.lock_ok();
    inner.resume_pending.push(kept);
    let ledger = Extractor::settle_resume_ledger(&mut inner);
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(
        ledger[0].len, 100_000,
        "the mark must stop at the hole, not count the bytes above it"
    );
    assert_eq!(ledger[0].crc32, crc32fast::hash(&f[..100_000]));
    drop(inner);
    assert_eq!(std::fs::metadata(dir.join("F.bin")).unwrap().len(), 100_000);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 217 hard part 2, pinned: the recorded mark is the CHECKSUMMED
/// length, never the raw contiguous frontier. Filling a hole makes the
/// file contiguous to 300 KB, but the hash froze at the hole - the
/// bytes above it were never seen in write order - so the ledger may
/// claim only the first 100 KB. A revert that records
/// `contiguous_from_start` again ships 300 KB of which 200 KB nothing
/// can verify, and this test goes red on it.
#[test]
fn a_backfilled_hole_is_contiguous_but_never_extends_the_mark() {
    let dir = tmpdir("resume-ledger-backfill");
    let f = payload(300_000, 66);
    let ex = Extractor::new_nested_for_tests(&dir, 1);
    ex.write(0, "F.bin", 1_000_000, 0, &f[..100_000]).unwrap();
    ex.write(0, "F.bin", 1_000_000, 200_000, &f[200_000..])
        .unwrap();
    // The hole is filled: the file now holds all 300 KB contiguously.
    ex.write(0, "F.bin", 1_000_000, 100_000, &f[100_000..200_000])
        .unwrap();

    let kept = ex.retain_slot_output(0).expect("a settled plain output");
    let mut inner = ex.inner.lock_ok();
    inner.resume_pending.push(kept);
    let ledger = Extractor::settle_resume_ledger(&mut inner);
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(
        ledger[0].len, 100_000,
        "the mark must be the checksummed length, not the contiguous frontier"
    );
    assert_eq!(ledger[0].crc32, crc32fast::hash(&f[..100_000]));
    drop(inner);
    assert_eq!(std::fs::metadata(dir.join("F.bin")).unwrap().len(), 100_000);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The other degradation: a write landing INSIDE the hashed prefix
/// poisons the hash (the folded-in bytes were rewritten, so the value
/// describes nothing on disk), and a poisoned writer records no entry
/// at all - its file is removed like any zero mark.
#[test]
fn a_rewrite_inside_the_hashed_prefix_records_no_entry() {
    let dir = tmpdir("resume-ledger-poison");
    let f = payload(200_000, 67);
    let ex = Extractor::new_nested_for_tests(&dir, 1);
    ex.write(0, "F.bin", 1_000_000, 0, &f).unwrap();
    // A rewrite of bytes already hashed - a duplicate span, a repair
    // coming through the writer, anything. Same bytes or not, the hash
    // can no longer be tied to what is on disk.
    ex.write(0, "F.bin", 1_000_000, 50_000, &f[50_000..60_000])
        .unwrap();

    let kept = ex.retain_slot_output(0).expect("a settled plain output");
    let mut inner = ex.inner.lock_ok();
    inner.resume_pending.push(kept);
    let ledger = Extractor::settle_resume_ledger(&mut inner);
    assert!(
        ledger.is_empty(),
        "a poisoned prefix hash must record nothing: {ledger:?}"
    );
    drop(inner);
    assert!(
        !dir.join("F.bin").exists(),
        "an unrecordable partial must not be left in the output directory"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A repair rewrite anywhere in the job voids the ledger and removes the
/// files, whatever it rewrote.
///
/// The in-chase guard (`mark_conflict`) covers the repair that lands
/// while the chase is LIVE - it forfeits with its own reason, so no
/// ledger is ever written for it. This is the other order: cap forfeit
/// first, repair second, ledger already standing. The prefix may have
/// been decoded off the stale copy with every CRC on the path passing,
/// so nothing downstream would catch it.
#[test]
fn a_repair_rewrite_voids_the_whole_resume_ledger() {
    let dir = tmpdir("resume-ledger-repair");
    let f = payload(400_000, 64);
    let ex = Extractor::new(&dir, 2, true);
    ex.write(0, "F.bin", 1_000_000, 0, &f).unwrap();
    let kept = ex.retain_slot_output(0).expect("a settled plain output");
    ex.inner.lock_ok().resume_pending.push(kept);

    // A repair on an unrelated slot: the guard is deliberately blunt.
    ex.write_repair(1, "other.bin", 10_000, 0, &payload(10_000, 65))
        .unwrap();

    assert!(
        ex.inner.lock_ok().resume_pending.is_empty(),
        "the repair did not void the ledger"
    );
    assert!(
        !dir.join("F.bin").exists(),
        "a voided partial must not be left in the output directory"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The escape hatch parses like every other one, and nothing else.
#[test]
fn the_resume_escape_hatch_takes_only_the_literal_one() {
    use crate::extract::resume::chase_resume_env_off_value;
    assert!(chase_resume_env_off_value(Some("1")));
    assert!(!chase_resume_env_off_value(Some("0")));
    assert!(!chase_resume_env_off_value(Some("true")));
    assert!(!chase_resume_env_off_value(None));
}

/// Only a settled plain output qualifies. A slot still holding its
/// pre-sniff spans has bytes in RAM and not on disk, so there is nothing
/// to resume from - it takes the old route and leaves nothing behind.
#[test]
fn an_unsettled_sink_slot_is_abandoned_rather_than_kept() {
    let dir = tmpdir("resume-ledger-unsettled");
    let ex = Extractor::new(&dir, 1, true);
    // Never written to: the slot is Unknown, with no writer.
    assert!(ex.retain_slot_output(0).is_none());
    assert!(dir_files(&dir).is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The demote path stays free ACROSS a trim, and the PAR2 case the
/// plan calls out: a repair rewrite landing BELOW the trim point.
///
/// Those bytes are on disk, not in the buffer, so nothing can compare
/// them - the buffer takes the rewrite as a forfeit, the file takes
/// the corrected bytes, and the disk ladder re-extracts. Trimming and
/// demote-to-volumes are not exclusive, because the trim spills into
/// the volume's OWN file: what a demotion would have written, written
/// early. So the materialized volume is byte-identical to what was
/// posted, trimmed prefix and all.
fn chase_patch_below_the_trim_point_forfeits_and_materializes_repaired() {
    assert!(rar_drop_env_off_value(Some("1")));
    assert!(!rar_drop_env_off_value(Some("0")));
    assert!(!rar_drop_env_off_value(None));
    // The doubt veto's own hatch, which restores the pre-30 Aug 2026
    // race so the spill it costs can be priced on the loopback rig.
    assert!(loss_doubt_env_off_value(Some("1")));
    assert!(!loss_doubt_env_off_value(Some("0")));
    assert!(!loss_doubt_env_off_value(None));

    let dir = tmpdir("chase-trim-patch");
    let (_, vols, names) = chase_volume_set();
    let headroom = 3 * vols[0].len();

    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1);
    // The spill bargain is what this case pins; with the drop on, the
    // trimmed volumes' files carry holes by design - see the case after.
    ex.set_rar_drop(false);
    eat_budget_to(&ex, vols.len(), headroom, 145);
    // Feed every volume but the last, so the chase is still live
    // (and trimmed) when the rewrite lands.
    let live = vols.len() - 1;
    let trimmed = feed_chase_volumes_paced(&ex, names, &vols[..live], 7000, 2);
    assert!(trimmed > 0, "nothing was trimmed - the test proved nothing");
    let base = ex.inner.lock_ok().slots[0]
        .chase
        .as_ref()
        .map_or(0, |ch| ch.buf.base());
    assert!(base > 0, "volume 0 was never trimmed: base {base}");

    // A repair rewriting a range the chase consumed AND released:
    // different bytes, wholly below the trim point.
    let mut stale = vols[0][..crate::disk::chunk_len(base, vols[0].len())].to_vec();
    for b in stale.iter_mut() {
        *b ^= 0xff;
    }
    ex.write(0, &names[0], vols[0].len() as u64, 0, &stale)
        .unwrap();
    // ...then the truth, and the last volume.
    ex.write(
        0,
        &names[0],
        vols[0].len() as u64,
        0,
        &vols[0][..stale.len()],
    )
    .unwrap();
    feed(&ex, live, &names[live], &vols[live], 7000, 99);

    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("rewrote")),
        "a rewrite over trimmed bytes must forfeit, and say why: {:?}",
        rep.fallbacks
    );
    // Byte-exact against what was posted: the spilled prefix, the
    // bytes still in RAM, and the corrected rewrite on top.
    for (index, vol) in vols.iter().enumerate() {
        assert_eq!(
            &std::fs::read(dir.join(&names[index])).unwrap(),
            vol,
            "{}",
            names[index]
        );
    }
    assert!(!dir.join("F.bin").exists(), "partial chase output survived");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The other half of drop-not-spill: a demote AFTER a dropping trim
/// materializes every volume with holes exactly where the dropped
/// prefix was, and reports those holes so the caller can re-fetch the
/// volumes (get/dropped.rs) before anything reads them back. Every
/// byte outside the holes is what was posted; every byte inside is
/// unwritten. The forfeit here is the conflict guard's - a differing
/// rewrite of bytes the chase still holds - because it is the one
/// forfeit a healthy, keeping-pace chase can still meet.
fn a_forfeit_after_a_drop_reports_the_holes_for_refetch() {
    let dir = tmpdir("chase-drop-forfeit");
    let (_, vols, names) = chase_volume_set();
    let headroom = 3 * vols[0].len();

    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1);
    eat_budget_to(&ex, vols.len(), headroom, 147);
    let live = vols.len() - 1;
    feed_chase_volumes_paced(&ex, names, &vols[..live], 7000, 2);
    assert!(
        ex.chase_dropped_bytes() > 0,
        "nothing was dropped - the test proved nothing"
    );
    // A differing rewrite of a span the chase still holds in RAM: the
    // buffer takes it as the truth and forfeits. Then the truth lands
    // on the materialized file, as a real repair's would. The span is
    // parked in the middle of the volume NOT yet fed, with nothing
    // before it: the engine reads forward from offset 0, so it cannot
    // have consumed (and the trim cannot have dropped) a byte of it.
    // This used to rewrite the middle of the previous volume, which
    // only held while the engine happened to be behind that point - a
    // race the incremental volume open (TODO 220) let the engine win
    // under load, leaving no conflict and no forfeit.
    let t = live;
    let at = vols[t].len() / 2;
    ex.write(
        t,
        &names[t],
        vols[t].len() as u64,
        at as u64,
        &vols[t][at..at + 4096],
    )
    .unwrap();
    let mut stale = vols[t][at..at + 4096].to_vec();
    for b in stale.iter_mut() {
        *b ^= 0xff;
    }
    ex.write(t, &names[t], vols[t].len() as u64, at as u64, &stale)
        .unwrap();
    ex.write(
        t,
        &names[t],
        vols[t].len() as u64,
        at as u64,
        &vols[t][at..at + 4096],
    )
    .unwrap();
    feed(&ex, live, &names[live], &vols[live], 7000, 99);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("rewrote")),
        "{:?}",
        rep.fallbacks
    );
    let dropped = ex.dropped_volumes();
    assert!(
        !dropped.is_empty(),
        "a demote after a drop reported no holes"
    );
    let mut holed = 0u64;
    for DroppedVolume {
        slot,
        posted,
        current,
        ranges,
    } in &dropped
    {
        assert_eq!(posted, &names[*slot]);
        assert_eq!(current, &names[*slot]);
        // A volume dropped WHOLE never had a writer, so it has no file:
        // the refetch creates it from nothing. Read that as all holes.
        let got = std::fs::read(dir.join(&names[*slot])).unwrap_or_else(|_| {
            assert_eq!(
                ranges.as_slice(),
                &[(0, vols[*slot].len() as u64)],
                "{}",
                names[*slot]
            );
            vec![0; vols[*slot].len()]
        });
        assert_eq!(got.len(), vols[*slot].len(), "{}", names[*slot]);
        let mut want = vols[*slot].clone();
        for &(at, len) in ranges {
            let (at, len) = (at as usize, len as usize);
            assert!(at + len <= want.len(), "{:?} past the end", ranges);
            want[at..at + len].fill(0);
            holed += len as u64;
        }
        assert_eq!(
            got, want,
            "{}: holes must be exactly the dropped ranges",
            names[*slot]
        );
    }
    assert_eq!(
        holed,
        ex.chase_dropped_bytes(),
        "reported holes != bytes dropped"
    );
    // Volumes that never dropped materialized complete.
    for (index, vol) in vols.iter().enumerate() {
        if dropped.iter().any(|d| d.slot == index) {
            continue;
        }
        let got = std::fs::read(dir.join(&names[index])).unwrap_or_else(|e| {
            panic!("{} (slot {index}, dropped {dropped:?}): {e}", names[index])
        });
        assert_eq!(&got, vol, "{}", names[index]);
    }
    // The caller's acknowledgement clears the claim, per slot.
    for d in &dropped {
        ex.note_dropped_refetched(d.slot);
    }
    assert!(ex.dropped_volumes().is_empty());
    assert!(!dir.join("F.bin").exists(), "partial chase output survived");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A lost article anywhere in the job is a demote waiting to happen,
/// and a demote after a drop is a re-download - so beside one, the
/// trim keeps spilling. The loss belongs to a slot the chase does not
/// own, which is exactly the case where the chase itself stays
/// healthy and would otherwise drop.
fn a_chase_beside_a_lost_article_spills_instead_of_dropping() {
    let dir = tmpdir("chase-drop-lost");
    let (f, vols, names) = chase_volume_set();
    let headroom = 3 * vols[0].len();

    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1);
    eat_budget_to(&ex, vols.len(), headroom, 149);
    ex.note_article_lost(vols.len());
    let trimmed = feed_chase_volumes_paced(&ex, names, vols, 7000, 2);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert!(trimmed > 0, "nothing was trimmed - the test proved nothing");
    assert_eq!(ex.chase_dropped_bytes(), 0, "dropped beside a lost article");
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The same veto ONE ROUND TRIP EARLIER, and the case the flag above
/// cannot cover on its own (30 Aug 2026,
/// `research/CHASE-TRIM-DROPS-BEFORE-VERDICT-2026-08-30.md`).
///
/// `note_article_lost` is called from a TERMINAL fetch verdict and its
/// own doc says those land late - "retries exhaust last" - so between
/// the pool deciding an article is one refusal from gone and the
/// verdict arriving, the gate above still reads false and the trim
/// DROPS. Measured on the row-26 e2e leg under the holds park: 10 of 12
/// loaded runs dropped a PAR2-vouched prefix, and every one of the 10
/// then took the disk ladder because `try_mapped_repair` had no backing
/// data left. So the pool raises [`LossDoubt`] at the hold, and this
/// pins that it vetoes the drop exactly as a landed verdict does.
///
/// Deliberately a sibling of the case above rather than a parameter on
/// it: what is being asserted is that a SECOND, differently-sourced
/// flag reaches the same gate, and a shared body could pass with either
/// one of them wired to nothing.
fn a_chase_beside_a_doubted_article_spills_instead_of_dropping() {
    let dir = tmpdir("chase-drop-doubt");
    let (f, vols, names) = chase_volume_set();
    let headroom = 3 * vols[0].len();

    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1);
    eat_budget_to(&ex, vols.len(), headroom, 149);
    // No slot, and no terminal verdict: the pool is still ASKING.
    ex.loss_doubt().raise();
    assert!(
        !ex.inner_read().lost_articles.load(Ordering::Relaxed),
        "the doubt must not stand in for a terminal verdict - it does          not arm the paging pass and does not mark a slot"
    );
    let trimmed = feed_chase_volumes_paced(&ex, names, vols, 7000, 2);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert!(trimmed > 0, "nothing was trimmed - the test proved nothing");
    assert_eq!(
        ex.chase_dropped_bytes(),
        0,
        "dropped while a terminal verdict was being held back"
    );
    assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The conflict forfeit, end to end through `write` - the trigger the
/// buffer-level tests do not exercise.
///
/// The story is the one the guard exists for: an article arrives whose
/// own CRC passes but whose bytes are wrong, the chase decodes them,
/// and only then does PAR2 rebuild the range and deliver a DIFFERING
/// copy. Carrying on would ship what was decoded from the stale bytes
/// with every checksum on the path still passing, so the rewrite must
/// forfeit the chase. The retained record ends up holding the repaired
/// bytes, so the materialized volume is byte-exact and the disk pass
/// re-extracts it.
#[test]
fn chase_differing_rewrite_forfeits_and_materializes_repaired() {
    let dir = tmpdir("chase-rewrite");
    let f = noisy(2_400_000, 121);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    // Well past the outer headers, so the damaged chunk lands in the
    // inner payload the chase is decoding, not in the mapping.
    const BAD: usize = 10;
    const STEP: usize = 50_000;
    assert!(
        outer.len() > (BAD + 4) * STEP,
        "outer too small: {}",
        outer.len()
    );

    let ex = Extractor::new(&dir, 1, true);
    for (i, chunk) in outer.chunks(STEP).enumerate() {
        let off = (i * STEP) as u64;
        if i == BAD {
            // Passes its own CRC, still wrong.
            let mut stale = chunk.to_vec();
            for b in stale.iter_mut() {
                *b ^= 0xff;
            }
            ex.write(0, "v.rar", outer.len() as u64, off, &stale)
                .unwrap();
            continue;
        }
        ex.write(0, "v.rar", outer.len() as u64, off, chunk)
            .unwrap();
    }
    // The repair lands after the chase has already consumed the range
    // - WAIT for that, rather than race the decode thread for it: a
    // rewrite that lands ahead of the decode is no conflict at all
    // (row 27), and the test would then be pinning the other outcome.
    // The child volume starts `data_off` into the outer, so a child
    // served line past `(BAD + 1) * STEP` covers the outer range.
    wait_child_chase_served(
        &ex,
        ((BAD + 1) * STEP) as u64,
        std::time::Duration::from_secs(30),
    );
    let fixed = &outer[BAD * STEP..(BAD + 1) * STEP];
    ex.write(0, "v.rar", outer.len() as u64, (BAD * STEP) as u64, fixed)
        .unwrap();

    let rep = ex.finish().unwrap();
    let reasons: Vec<&str> = rep.fallbacks.iter().map(|(_, w)| w.as_str()).collect();
    assert!(
        reasons.iter().any(|w| w.contains("rewrote")),
        "the forfeit must be reported, and say why: {reasons:?}"
    );
    // Byte-exact against the REPAIRED archive: the later delivery won,
    // so nothing decoded from the stale copy survived into the output.
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
    assert!(!dir.join("F.bin").exists(), "partial chase output survived");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Bytes never arrive: finish() aborts the still-blocked chase and
/// demotes cleanly - no hang, job Ok, the materialized level-1
/// archive carries everything that DID arrive (the lost article's
/// range stays an uncovered hole), partial output deleted.
#[test]
fn chase_abort_on_finish_with_missing_bytes() {
    let dir = tmpdir("chase-missing");
    let f = noisy(300_000, 97);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    // Locate the outer data area so the withheld article is pure
    // inner-archive bytes.
    let data_off = {
        let mut m = VolumeMapper::new(outer.len() as u64);
        m.feed(0, &outer);
        m.entries[0].data_off as usize
    };
    let art = 1000usize;
    let lost = (data_off / art) + 2; // fully inside the data area
    let (ls, le) = (lost * art, ((lost + 1) * art).min(outer.len()));
    let ex = Extractor::new(&dir, 1, true);
    for i in 0..outer.len().div_ceil(art) {
        if i == lost {
            continue;
        }
        let s = i * art;
        let e = (s + art).min(outer.len());
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    assert!(!dir.join("F.bin").exists(), "partial chase output survived");
    // Materialized volume: byte-exact outside the lost range, hole
    // (zeros, uncovered) inside it.
    let got = std::fs::read(dir.join("inner.rar")).unwrap();
    let mut expect = inner_arch.clone();
    expect[ls - data_off..le - data_off].fill(0);
    assert_eq!(got, expect);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The 11 Aug 2026 soak shape, bounded: a damaged compressed
/// multi-volume set whose decode wedges on a terminally-missing
/// article used to hold every downloaded byte in RAM to the holds
/// cap. The terminal verdict (`note_article_lost`, landing AFTER
/// the pile has built, as retries do) must page the cold frontier
/// to scratch immediately - and the demote at finish must still
/// materialize every volume byte-exact from the paged spans.
fn stalled_chase_pages_cold_frontier_then_demotes_byte_exact() {
    let dir = tmpdir("chase-stall-page");
    let (_, vols, names) = chase_volume_set();
    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB; stall window = 4 MB
    // Enough junk that the shared budget sits past the window, but
    // the total stays under the cap - the cap arbiter must never
    // fire, or the set demotes before the spill is even tested.
    let packed: usize = vols.iter().map(|v| v.len()).sum();
    eat_budget_to(&ex, vols.len(), packed + (1 << 20), 151);
    // Volume 0 loses one article deep inside its packed stream;
    // everything else arrives.
    let art = 7000usize;
    let lost = {
        let mut m = VolumeMapper::new(vols[0].len() as u64);
        m.feed(0, &vols[0]);
        let e = &m.entries[0];
        ((e.data_off + e.data_len / 2) / art as u64) as usize
    };
    for i in 0..vols[0].len().div_ceil(art) {
        if i == lost {
            continue;
        }
        let s = i * art;
        let e = (s + art).min(vols[0].len());
        ex.write(0, &names[0], vols[0].len() as u64, s as u64, &vols[0][s..e])
            .unwrap();
    }
    for (vi, vol) in vols.iter().enumerate().skip(1) {
        feed(&ex, vi, &names[vi], vol, art, 60 + vi as u64);
    }
    assert_eq!(
        ex.holds_paged_total(),
        0,
        "nothing may page before the verdict"
    );
    ex.note_article_lost(0);
    assert!(
        ex.holds_paged_total() > 1 << 20,
        "the cold frontier never paged: {}",
        ex.holds_paged_total()
    );
    assert!(
        ex.chase_retained_bytes() < 1 << 20,
        "retained stayed near the whole set: {}",
        ex.chase_retained_bytes()
    );
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "an unfillable gap must demote");
    for (vi, vol) in vols.iter().enumerate() {
        let got = std::fs::read(dir.join(&names[vi])).unwrap();
        let mut want = vol.clone();
        if vi == 0 {
            let (s, e) = (lost * art, ((lost + 1) * art).min(vol.len()));
            want[s..e].fill(0);
        }
        assert_eq!(got, want, "{}", names[vi]);
    }
    assert!(!dir.join("F.bin").exists(), "partial chase output survived");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO §156 item 8(b): the chase arm of `Extractor::read_at`
/// served a chased slot straight out of `FrontierBuffer::peek`,
/// which preads any paged span WHILE the global extractor mutex is
/// held. Once the stalled-chase spill above started moving cold
/// bytes to scratch, that arm's "RAM memcpy" comment stopped being
/// true: a request reaching a spilled span does real disk I/O with
/// every other extractor thread queued behind the one lock. The arm
/// now plans those sub-ranges and preads them after the guard
/// drops, like every other paged read in reader.rs.
///
/// The oracle is WHERE the bytes come from, not just that they are
/// right. `HoldsScratch::read` is the under-a-lock route - exactly
/// what `peek` calls - and it bumps `locked_reads`; a deferred
/// `Plan::S` reads the file handle after the guard block and does
/// not. The range read back is lifted out of the buffer's own
/// `paged` map, so a request that never touched scratch cannot pass
/// this vacuously.
fn chase_read_defers_its_paged_preads_off_the_extractor_lock() {
    let dir = tmpdir("chase-read-defer");
    let (_, vols, names) = chase_volume_set();
    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB; stall window = 4 MB
    let packed: usize = vols.iter().map(|v| v.len()).sum();
    eat_budget_to(&ex, vols.len(), packed + (1 << 20), 151);
    // Volume 0 loses one article deep inside its packed stream, so
    // the decode wedges and the verdict spills the cold frontier.
    let art = 7000usize;
    let lost = {
        let mut m = VolumeMapper::new(vols[0].len() as u64);
        m.feed(0, &vols[0]);
        let e = &m.entries[0];
        ((e.data_off + e.data_len / 2) / art as u64) as usize
    };
    for i in 0..vols[0].len().div_ceil(art) {
        if i == lost {
            continue;
        }
        let s = i * art;
        let e = (s + art).min(vols[0].len());
        ex.write(0, &names[0], vols[0].len() as u64, s as u64, &vols[0][s..e])
            .unwrap();
    }
    for (vi, vol) in vols.iter().enumerate().skip(1) {
        feed(&ex, vi, &names[vi], vol, art, 60 + vi as u64);
    }
    ex.note_article_lost(0);
    assert!(
        ex.holds_paged_total() > 1 << 20,
        "the cold frontier never paged: {}",
        ex.holds_paged_total()
    );

    // The widest paged span still registered to a chased slot: a
    // volume range that is provably not in RAM.
    let (slot, at, len) = {
        let inner = ex.inner_read();
        let mut best: Option<(usize, u64, usize)> = None;
        for (slot, s) in inner.slots.iter().enumerate() {
            let Some(ch) = s.chase.as_ref() else { continue };
            let st = ch.buf.state.lock_ok();
            for (&at, &(_, len)) in &st.paged {
                if best.is_none_or(|(_, _, best_len)| len > best_len) {
                    best = Some((slot, at, len));
                }
            }
        }
        best.expect("the spill left no paged span to read back")
    };
    assert!(
        len >= 1 << 16,
        "paged span too small to be a fair read: {len}"
    );

    let reads_before = ex.inner_read().scratch.locked_reads.load(Ordering::Relaxed);
    let mut back = vec![0u8; len];
    ex.read_at(slot, at, &mut back).unwrap();
    assert_eq!(
        ex.inner_read().scratch.locked_reads.load(Ordering::Relaxed),
        reads_before,
        "the chase arm pread the holds scratch under the extractor lock"
    );
    assert_eq!(
        back,
        vols[slot][at as usize..at as usize + len],
        "the deferred plan must serve the paged span byte-exact"
    );

    // And reading through the plan consumed nothing: the demote
    // still materializes that same range out of the paged spans.
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "an unfillable gap must demote");
    let got = std::fs::read(dir.join(&names[slot])).unwrap();
    assert_eq!(got[at as usize..at as usize + len], back[..]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The rescue half of the stalled-chase spill: the verdict lands
/// and the cold bytes page, then the gap fills anyway (a straggler
/// retry, a repair) - the decode must resume straight off the paged
/// spans and complete one-pass, byte-exact, nothing else on disk.
#[test]
fn stalled_chase_resumes_from_paged_spans_when_the_gap_fills() {
    let dir = tmpdir("chase-stall-resume");
    let f = noisy(2_400_000, 153);
    let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&inner_arch);
    assert!(
        inner_arch.len() > 900_000,
        "packed too small: {}",
        inner_arch.len()
    );
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Arc::new(Extractor::new(&dir, 4, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB; stall window = 4 MB
    eat_budget_to(&ex, 1, 3 << 20, 154);
    // Withhold one article deep inside the packed inner stream.
    let art = 7000usize;
    let lost = {
        let mut m = VolumeMapper::new(outer.len() as u64);
        m.feed(0, &outer);
        let e = &m.entries[0];
        ((e.data_off + e.data_len / 2) / art as u64) as usize
    };
    for i in 0..outer.len().div_ceil(art) {
        if i == lost {
            continue;
        }
        let s = i * art;
        let e = (s + art).min(outer.len());
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
    }
    ex.note_article_lost(0);
    assert!(
        ex.holds_paged_total() > 300_000,
        "the cold frontier never paged: {}",
        ex.holds_paged_total()
    );
    // The gap fills after all - decode resumes from paged bytes.
    let (s, e) = (lost * art, ((lost + 1) * art).min(outer.len()));
    ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
        .unwrap();
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    let mut want = vec!["F.bin".to_string()];
    want.extend((1..4).map(|i| format!("dummy{i}.bin")));
    want.sort();
    assert_eq!(dir_files(&dir), want);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// §156.1: the spill trigger is the WEDGE, not the verdict. A
/// terminal loss in a slot the chase does not own (the A/B's shape:
/// one article of an unrelated plain file, everything the chase
/// needs arriving fine) must page NOTHING - the old any-verdict
/// trigger skimmed the healthy chase's entire pile through scratch
/// and pread it straight back, 527 MB of doubled I/O on the A/B's
/// 614 MB set.
fn healthy_chase_never_pages_on_a_loss_it_does_not_own() {
    let dir = tmpdir("chase-healthy-no-page");
    let (f, vols, names) = chase_volume_set();
    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB; stall window = 4 MB
    let packed: usize = vols.iter().map(|v| v.len()).sum();
    eat_budget_to(&ex, vols.len(), packed + (1 << 20), 155);
    let art = 7000usize;
    for (vi, vol) in vols.iter().enumerate() {
        feed(&ex, vi, &names[vi], vol, art, 70 + vi as u64);
    }
    // The verdict lands on a junk slot, with the shared budget well
    // past the window - exactly the state that used to page.
    ex.note_article_lost(vols.len());
    assert_eq!(
        ex.holds_paged_total(),
        0,
        "a healthy chase paged on an unrelated loss"
    );
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(ex.holds_paged_total(), 0, "paged during the finish");
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), *f);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// §156.1: the coldness boundary is the lowest DOOMED volume, not
/// the engine's position. A hole ahead of the engine pages the
/// bytes beyond it right away (the engine provably cannot reach
/// them until the hole fills) while the volume the engine is parked
/// in - which lost nothing - stays warm; when the hole then fills,
/// the decode resumes straight through the paged spans and
/// completes one-pass, byte-exact.
fn a_hole_ahead_of_the_engine_pages_beyond_it_and_still_resumes() {
    let dir = tmpdir("chase-ahead-hole-page");
    let (f, vols, names) = chase_volume_set();
    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB; stall window = 4 MB
    let packed: usize = vols.iter().map(|v| v.len()).sum();
    eat_budget_to(&ex, vols.len(), packed + (1 << 20), 156);
    let art = 7000usize;
    // Volume 0: everything but its LAST article, so the engine is
    // provably parked inside a volume that lost nothing. Volume 1:
    // one article deep in its packed stream never arrives.
    let v0_tail = (vols[0].len() - 1) / art * art;
    for i in 0..vols[0].len().div_ceil(art) {
        if i * art == v0_tail {
            continue;
        }
        let s = i * art;
        let e = (s + art).min(vols[0].len());
        ex.write(0, &names[0], vols[0].len() as u64, s as u64, &vols[0][s..e])
            .unwrap();
    }
    let lost = {
        let mut m = VolumeMapper::new(vols[1].len() as u64);
        m.feed(0, &vols[1]);
        let e = &m.entries[0];
        ((e.data_off + e.data_len / 2) / art as u64) as usize
    };
    for i in 0..vols[1].len().div_ceil(art) {
        if i == lost {
            continue;
        }
        let s = i * art;
        let e = (s + art).min(vols[1].len());
        ex.write(1, &names[1], vols[1].len() as u64, s as u64, &vols[1][s..e])
            .unwrap();
    }
    for (vi, vol) in vols.iter().enumerate().skip(2) {
        feed(&ex, vi, &names[vi], vol, art, 80 + vi as u64);
    }
    ex.note_article_lost(1);
    assert!(
        ex.holds_paged_total() > 0,
        "the bytes beyond the doomed volume never paged"
    );
    // Volume 0 completes and the hole fills - the engine decodes
    // through the paged spans to the end.
    ex.write(
        0,
        &names[0],
        vols[0].len() as u64,
        v0_tail as u64,
        &vols[0][v0_tail..],
    )
    .unwrap();
    let (s, e) = (lost * art, ((lost + 1) * art).min(vols[1].len()));
    ex.write(1, &names[1], vols[1].len() as u64, s as u64, &vols[1][s..e])
        .unwrap();
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), *f);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A reclaim that fails while seeding the frontier (a dead scratch
/// under a paged hold) must still leave the slot a CHASED slot: it was
/// flipped to `SlotMode::RarChase` and committed to the group before
/// the seed loop, so a bail-out with `chase == None` sends every later
/// span into `chase_span`'s impossible arm - a debug assert here, and
/// a silent byte drop in release.
#[test]
fn failed_reclaim_at_attach_leaves_the_slot_chased() {
    let dir = tmpdir("chase-attach-reclaim-fail");
    let f = noisy(300_000, 137);
    let arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&arch);
    let art = 7000usize;
    let n = arch.len().div_ceil(art);
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    // Everything but the head and the tail: with offset 0 still
    // missing nothing is classified, so these all land in the holds.
    for i in (1..n - 1).rev() {
        let s = i * art;
        let e = (s + art).min(arch.len());
        ex.write(0, "release.rar", arch.len() as u64, s as u64, &arch[s..e])
            .unwrap();
    }
    // A paged hold whose scratch file is gone: the seed loop's very
    // first reclaim fails.
    {
        let mut g = ex.inner.lock_ok();
        let inner = &mut *g;
        let junk = vec![0x5Au8; 4096];
        let off = inner.scratch.append(&junk, u64::MAX).unwrap();
        inner.slots[0].holds.insert(
            0,
            (
                art as u64,
                HoldSpan::Paged {
                    off,
                    len: junk.len(),
                },
            ),
        );
        inner.scratch.st().file = None;
    }
    // The head classifies, the attach commits the slot and then the
    // seed fails.
    assert!(
        ex.write(0, "release.rar", arch.len() as u64, 0, &arch[..art])
            .is_err(),
        "a dead scratch must fail the attach's seed"
    );
    {
        let g = ex.inner.lock_ok();
        assert!(matches!(g.slots[0].mode, SlotMode::RarChase));
        assert!(
            g.slots[0].chase.is_some(),
            "the attach bailed out leaving a chased slot with no chase"
        );
    }
    // The span that used to hit the impossible arm.
    let s = (n - 1) * art;
    ex.write(
        0,
        "release.rar",
        arch.len() as u64,
        s as u64,
        &arch[s..arch.len()],
    )
    .expect("a later span for the chased slot must still route");
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "the failed chase must demote");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 251: a held-bytes breach on a TOP-LEVEL chased set must ask
/// that set's own chase for relief before demoting anything.
///
/// `relieve_by_child_chase` finds its victim through the demoting
/// slot's group `routed` map - the CHILD chase the group's inner files
/// feed - so it covers the nested shape TODO 220 measured and nothing
/// else. A compressed RAR posted DIRECTLY has no store outer and no
/// routed members at all (`chase_open_sink` registers decoded members
/// in the ctl's `sink_slots`), so the relief declined and whichever
/// call site saw `budget.over()` first decided, which is the race TODO
/// 220 priced at 4.3-4.9x of payload on the nested shape.
///
/// THE SITE IS THE PRE-SNIFF HOLD, and that is what makes this shape
/// worth a case of its own rather than a copy of the outer one. Holds
/// come from ARRIVAL ORDER - an offset-0 article landing after its
/// payload - so on a top-level set the slot that breaches is typically
/// a volume nobody has sniffed yet, and `overflow_to_plain` flips EVERY
/// Unknown slot holding bytes to `Plain`. A volume flipped that way can
/// never join the set. Measured here before the fix, with 18 of 20
/// volumes already consumed and ONE 7000-byte pre-sniff span: the
/// engine reached the plain volume and died with `chase failed: RAR 5
/// split entry is incomplete`, all twenty volumes materialized, and the
/// job produced NO payload in-stream - not even under the cap reason,
/// so `chase_resume_ok` was false and the disk pass would start from
/// byte zero.
///
/// THE BREACH IS MANUFACTURED, for the reason the outer case gives:
/// left to the race the chase's own site gets there first every time.
/// The budget is put ONE byte over under the lock and then one small
/// span is written - only just over, because a relief that cannot clear
/// the overshoot is supposed to decline, and an inflated charge no
/// forfeit could cover would test the decline instead of the ladder.
///
/// Both rungs are driven, by how much the engine has been allowed to
/// consume:
/// - `trim`: the set is fed paced, so the engine has finished with
///   volumes and the spill releases them. The set stays one-pass.
/// - `forfeit`: only volume 0 is fed, so no watermark exists, the trim
///   can release nothing and the ladder goes on to forfeit. That is the
///   RIGHT ending and not a regression: it raises `HELD_BYTES_CAP_CHASE`,
///   the one reason the in-stream output survives, where the ending it
///   replaces keeps nothing.
///
/// What is pinned in BOTH arms is the part that is always true: the
/// breaching slot must not be flipped to Plain, and no volume may be
/// left holding a `chase failed` reason.
fn a_top_level_breach_relieves_the_chase_before_demoting_a_volume() {
    let (f, vols, names) = chase_volume_set();
    const ART: usize = 7000;
    for rung in ["trim", "forfeit"] {
        let dir = tmpdir(&format!("chase-relief-top-{rung}"));
        let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
        ex.anchor();
        ex.set_holds_cap(1); // floors at 8 MB
        // Paging OFF: it is an independent budget relief, and with it on
        // a loaded box can take that branch instead and never reach the
        // ladder this case measures (the same reason
        // `chase_over_cap_multi_volume_set_demotes_with_the_trim_off`
        // turns it off).
        ex.set_holds_paging(false);
        // The slot that breaches is the LAST volume, still unsniffed.
        let breach_at = vols.len() - 1;
        let fed = if rung == "trim" { breach_at } else { 1 };
        feed_chase_volumes_paced(&ex, &names[..fed], &vols[..fed], ART, 2);
        let consumed = ex.chase_consumed_volumes();
        assert!(
            ex.chase_retained_bytes() > 0,
            "{rung}: the chase holds nothing - there is no budget to relieve"
        );
        if rung == "trim" && consumed == 0 {
            // A box loaded enough that the engine finished with no
            // volume at all is the OTHER rung, whatever this arm meant
            // to drive: the assertions below still hold, the one-pass
            // ending cannot.
            eprintln!(
                "a_top_level_breach_relieves_the_chase_before_demoting_a_volume: \
                 engine consumed 0 volumes after a paced feed - the trim arm is \
                 measuring the forfeit rung on this run"
            );
        }
        let fake = {
            let inner = ex.inner.lock_ok();
            let fake = inner.budget.cap().saturating_sub(inner.budget.len()) + 1;
            inner.budget.add(fake);
            fake
        };
        let last = &vols[breach_at];
        // A NON-zero offset on a slot that has not sniffed: the
        // pre-sniff hold, and the shotgun behind it.
        ex.write(
            breach_at,
            &names[breach_at],
            last.len() as u64,
            ART as u64,
            &last[ART..2 * ART],
        )
        .unwrap();
        ex.inner.lock_ok().budget.sub(fake);
        let mode = format!("{:?}", ex.inner.lock_ok().slots[breach_at].mode);
        assert_ne!(
            mode, "Plain",
            "{rung}: an unsniffed volume of a live chased set was flipped to \
             Plain for a {ART}-byte hold - it can never join the set now"
        );
        // The rest of the set, including the breaching volume in full.
        for index in fed..vols.len() {
            feed(
                &ex,
                index,
                &names[index],
                &vols[index],
                ART,
                71 + index as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("chase failed")),
            "{rung}: the chase died on a volume the breach took away from it: {:?}",
            rep.fallbacks
        );
        if rung == "trim" && consumed > 0 {
            assert!(
                rep.fallbacks.is_empty(),
                "trim: the spill rung had consumed volumes to release and the set \
                 still demoted: {:?}",
                rep.fallbacks
            );
            assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
            assert_eq!(
                dir_files(&dir),
                vec!["F.bin".to_string()],
                "a volume survived the relieved chase"
            );
        } else {
            assert!(
                rep.fallbacks
                    .iter()
                    .any(|(_, w)| w.contains("held-bytes cap: chase memory")),
                "forfeit: the ladder must raise the cap reason - the one the \
                 resume ledger accepts; got {:?}",
                rep.fallbacks
            );
            // Every volume the chase gave up is COMPLETE - the disk pass
            // reads these.
            for (index, vol) in vols.iter().enumerate() {
                let p = dir.join(&names[index]);
                if p.exists() {
                    assert_eq!(&std::fs::read(&p).unwrap(), vol, "{}", names[index]);
                }
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
