//! The chase engine's tests, split out of `chase.rs` whole (TODO 106
//! size gate) - the code is verbatim, only the indent changed. Same
//! shape as `crypto_tests.rs` and `mod_tests.rs` beside it: a `#[path]`
//! child of the module under test, so `super::*` still reaches
//! everything the inline block reached.

use super::*;
use crate::rar::fixtures;

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
fn eat_budget_to(ex: &Extractor, first_slot: usize, headroom: usize, seed: u8) {
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
/// enough (tens of seconds in a debug build) that the seven cases
/// build it once between them, through `chase_volume_set_cases`.
fn chase_volume_set() -> &'static (Vec<u8>, Vec<Vec<u8>>, Vec<String>) {
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

/// The seven cases that share `chase_volume_set`, run as ONE test.
///
/// nextest gives every `#[test]` its own process, which puts the
/// `OnceLock` above out of reach: each case built the 5 MiB compressed
/// set again. Measured here, 19 CPU-seconds apiece - 132 of the chase
/// module's 186 - and about 52 s apiece on a CI Windows runner. Built
/// once, the same seven cost about 20.
///
/// They are independent: each makes its own tmpdir and its own
/// `Extractor`, and none reads state the others wrote. The price of
/// the merge is that the first failure hides the cases after it, and
/// the panic message is the case that failed rather than the test
/// name - so each keeps its own doc comment and its own name in the
/// backtrace.
#[test]
fn chase_volume_set_cases() {
    chase_over_cap_multi_volume_set_trims_and_streams();
    chase_over_cap_multi_volume_set_demotes_with_the_trim_off();
    chase_patch_below_the_trim_point_forfeits_and_materializes_repaired();
    stalled_chase_pages_cold_frontier_then_demotes_byte_exact();
    chase_read_defers_its_paged_preads_off_the_extractor_lock();
    healthy_chase_never_pages_on_a_loss_it_does_not_own();
    a_hole_ahead_of_the_engine_pages_beyond_it_and_still_resumes();
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
    eat_budget_to(&ex, vols.len(), headroom, 143);
    for (index, vol) in vols.iter().enumerate() {
        feed(&ex, index, &names[index], vol, 7000, 33 + index as u64);
    }
    let rep = ex.finish().unwrap();

    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("held-bytes cap: chase memory")),
        "{:?}",
        rep.fallbacks
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
    assert!(!dir.join("F.bin").exists(), "partial chase output survived");
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
    let dir = tmpdir("chase-trim-patch");
    let (_, vols, names) = chase_volume_set();
    let headroom = 3 * vols[0].len();

    let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
    ex.anchor();
    ex.set_holds_cap(1);
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
    let mut stale = vols[0][..(base as usize).min(vols[0].len())].to_vec();
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
    // The repair lands after the chase has already consumed the range.
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

/// A compressed member split across FOUR inner volumes, all wrapped
/// in one store outer: the sequence driver pulls volume k+1 only
/// after k, split read-back reaches retained earlier volumes, and
/// the final payload lands byte-exact with nothing else on disk.
#[test]
fn chase_multi_volume_compressed_inner() {
    let f = noisy(300_000, 98);
    let vols = rars_compressed_volumes("F.bin", &f, 50_000);
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    let pieces: Vec<(String, &Vec<u8>)> = vols
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("inner.part{}.rar", i + 1), v))
        .collect();
    let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
        .iter()
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&outer_entries);
    // Two feed orders: forward and reverse (later inner volumes'
    // buffers register before the chase can use them).
    for (t, rev) in [false, true].iter().enumerate() {
        let dir = tmpdir(&format!("chase-mv{t}"));
        let ex = Extractor::new(&dir, 1, true);
        let art = 7000usize;
        let n_arts = outer.len().div_ceil(art);
        let order: Vec<usize> = if *rev {
            (0..n_arts).rev().collect()
        } else {
            (0..n_arts).collect()
        };
        for i in order {
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "rev={rev}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "rev={rev}");
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "rev={rev}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// A store outer wrapping a COMPRESSED RAR4 (RAR 2.9/3.x) inner: the
/// chase engages through the `rar15_40` engine, the payload lands
/// byte-identical, and neither the outer volume nor the inner archive
/// ever exists on disk.
#[test]
fn chase_compressed_rar4_inner_one_pass() {
    let dir = tmpdir("chase-v4");
    let f = payload(300_000, 191);
    let inner_arch = rars_v4_compressed_volume(&[("F.bin", &f)]);
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
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A compressed RAR4 member split across volumes, both naming
/// schemes: `.partNN.rar` (1-based, shifts down) and old-style
/// `.rar`/`.r00`/`.r01` (already 0-based) - the volume index comes
/// from the NAME for RAR4, so both must sequence correctly, forward
/// and reverse arrival.
#[test]
fn chase_multi_volume_compressed_rar4_inner() {
    let f = noisy(300_000, 198);
    let vols = rars_v4_compressed_volumes("F.bin", &f, 50_000);
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    let naming: [Box<dyn Fn(usize) -> String>; 2] = [
        Box::new(|i| format!("inner.part{}.rar", i + 1)),
        Box::new(|i| {
            if i == 0 {
                "inner.rar".to_string()
            } else {
                format!("inner.r{:02}", i - 1)
            }
        }),
    ];
    for (scheme, name_of) in naming.iter().enumerate() {
        let pieces: Vec<(String, &Vec<u8>)> = vols
            .iter()
            .enumerate()
            .map(|(i, v)| (name_of(i), v))
            .collect();
        let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
            .iter()
            .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
            .collect();
        let outer = fixtures::rar5_volume(&outer_entries);
        for (t, rev) in [false, true].iter().enumerate() {
            let dir = tmpdir(&format!("chase-v4mv{scheme}{t}"));
            let ex = Extractor::new(&dir, 1, true);
            let art = 7000usize;
            let n_arts = outer.len().div_ceil(art);
            let order: Vec<usize> = if *rev {
                (0..n_arts).rev().collect()
            } else {
                (0..n_arts).collect()
            };
            for i in order {
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(
                rep.fallbacks.is_empty(),
                "scheme={scheme} rev={rev}: {:?}",
                rep.fallbacks
            );
            assert_eq!(
                std::fs::read(dir.join("F.bin")).unwrap(),
                f,
                "scheme={scheme} rev={rev}"
            );
            assert_eq!(
                dir_files(&dir),
                vec!["F.bin".to_string()],
                "scheme={scheme} rev={rev}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

/// Encrypted (-p) compressed RAR4, split across volumes: the chase
/// decrypts through the rar15_40 engine's own sequential cipher (a
/// salt per member, key derived once per member on the WORKER thread,
/// never in the mapper - the §RAR4 KDF-DoS rule), payload byte-exact,
/// one pass.
#[test]
fn chase_encrypted_compressed_rar4_inner_one_pass() {
    let f = noisy(300_000, 199);
    let vols = rars_v4_encrypted_volumes("F.bin", &f, 60_000, "chasepw", false);
    assert!(vols.len() >= 2, "want a split set, got {}", vols.len());
    for v in &vols {
        assert_not_store(v);
    }
    let pieces: Vec<(String, &Vec<u8>)> = vols
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("inner.part{}.rar", i + 1), v))
        .collect();
    let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
        .iter()
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&outer_entries);
    let dir = tmpdir("chase-v4enc");
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("chasepw");
    feed(&ex, 0, "v.rar", &outer, 7000, 13);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The -hp shape: RAR4 with ENCRYPTED HEADERS. The mapper needs the
/// password to enumerate entries at all; past that the chase drives
/// the same engine (parse_stream decrypts headers per block).
#[test]
fn chase_header_encrypted_compressed_rar4_inner() {
    let f = noisy(200_000, 201);
    let vols = rars_v4_encrypted_volumes("F.bin", &f, 80_000, "hppw", true);
    // A password-less mapper must see nothing but EncryptedHeaders -
    // that both proves the -hp shape and stands in for
    // assert_not_store, which cannot read a method byte it cannot
    // decrypt.
    for v in &vols {
        let mut m = crate::rar::VolumeMapper::new(v.len() as u64);
        m.feed(0, v);
        assert_eq!(m.blocker, Some(crate::rar::MapBlocker::EncryptedHeaders));
    }
    let pieces: Vec<(String, &Vec<u8>)> = vols
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("inner.part{}.rar", i + 1), v))
        .collect();
    let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
        .iter()
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&outer_entries);
    let dir = tmpdir("chase-v4hp");
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hppw");
    feed(&ex, 0, "v.rar", &outer, 7000, 17);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Encrypted RAR4 with NO password available: the chase must not
/// attach (nothing can decode anywhere) - the set demotes to
/// byte-exact materialized volumes, today's output.
#[test]
fn chase_encrypted_rar4_without_password_demotes() {
    let f = noisy(120_000, 203);
    let vol = rars_v4_encrypted_volume("F.bin", &f, "nopw");
    let outer =
        fixtures::rar5_volume(&[("inner.rar", vol.len() as u64, vol.as_slice(), false, false)]);
    let dir = tmpdir("chase-v4enc-nopw");
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 5000, 19);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TOP-LEVEL chase (the RAR analogue of TODO 37 step 1): a POSTED
/// compressed RAR5 - no store wrapper - chases at depth 0, its
/// payload promotes to the root output, and neither the volume nor
/// any intermediate archive ever exists on disk. Three arrival
/// orders, mirroring the 7z twin.
#[test]
fn top_level_compressed_rar_chases_one_pass() {
    let f = payload(300_000, 131);
    let arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&arch);
    let art = 7000usize;
    let n_arts = arch.len().div_ceil(art);
    let orders: Vec<Vec<usize>> = vec![
        (0..n_arts).collect(),
        (0..n_arts).rev().collect(),
        (0..n_arts).map(|i| (i * 7 + 3) % n_arts).collect(),
    ];
    for (t, order) in orders.iter().enumerate() {
        let dir = tmpdir(&format!("rar-top-onepass{t}"));
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        let mut seen = vec![false; n_arts];
        for &i in order {
            if std::mem::replace(&mut seen[i], true) {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(arch.len());
            ex.write(0, "release.rar", arch.len() as u64, s as u64, &arch[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "order {t}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The multi-volume shape at depth 0: each volume of a posted
/// compressed set is its own top-level file (own slot, own name),
/// registering with the group's chase at its header volume number.
/// Forward and reverse volume-arrival orders.
#[test]
fn top_level_compressed_rar_multivolume_chases_one_pass() {
    let f = noisy(300_000, 132);
    let vols = rars_compressed_volumes("F.bin", &f, 50_000);
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    for (t, rev) in [false, true].iter().enumerate() {
        let dir = tmpdir(&format!("rar-top-mv{t}"));
        let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
        ex.anchor();
        let order: Vec<usize> = if *rev {
            (0..vols.len()).rev().collect()
        } else {
            (0..vols.len()).collect()
        };
        for &vi in &order {
            feed(
                &ex,
                vi,
                &format!("release.part{}.rar", vi + 1),
                &vols[vi],
                7000,
                33 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "rev={rev}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "rev={rev}");
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "rev={rev}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The kill switch restores the pre-lift behaviour exactly: gate
/// off, a posted compressed RAR materializes byte-exact with the
/// NotStore demote reason and no partial output. Also pins the env
/// parse ("1" and nothing else).
#[test]
fn top_level_chase_gate_off_materializes() {
    assert!(top_chase_env_off_value(Some("1")));
    assert!(!top_chase_env_off_value(Some("0")));
    assert!(!top_chase_env_off_value(None));
    let f = noisy(300_000, 133);
    let arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&arch);
    let dir = tmpdir("rar-top-gateoff");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_top_level_chase(false);
    feed(&ex, 0, "release.rar", &arch, 7000, 34);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("compressed or encrypted entries")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("release.rar")).unwrap(), arch);
    assert!(!dir.join("F.bin").exists(), "gate off must not stream");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A depth-0 chase over the holds cap demotes cleanly: the volume
/// materializes COMPLETE for the unrar ladder (whose "held-bytes
/// cap" keying the reason carries), and no partial payload survives.
/// This is the pre-lift exit path, reached through the chase.
#[test]
fn top_level_chase_budget_breach_demotes_to_volume() {
    let f = noisy(2_400_000, 134);
    let arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&arch);
    assert!(arch.len() > 900_000, "packed too small: {}", arch.len());
    let dir = tmpdir("rar-top-budget");
    let ex = Arc::new(Extractor::new(&dir, 3, true));
    ex.anchor();
    ex.set_holds_cap(1); // floors at 8 MB
    let junk = payload(65_000, 135);
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
    for (i, chunk) in arch.chunks(50_000).enumerate() {
        ex.write(
            0,
            "release.rar",
            arch.len() as u64,
            (i * 50_000) as u64,
            chunk,
        )
        .unwrap();
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("held-bytes cap: chase memory")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("release.rar")).unwrap(), arch);
    assert!(!dir.join("F.bin").exists(), "partial chase output survived");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Encrypted + compressed at depth 0: with the password set the
/// chase attaches (the gate admits an encrypted compressed entry
/// when `inner.password` is some) and the worker decrypts through
/// `rar_read_options` - byte-exact payload, no volume on disk.
/// Without a password the same set must demote and materialize:
/// nothing can decode it anywhere, and a partial output would be
/// garbage. First test of the chase's decrypt path at ANY depth.
#[test]
fn top_level_encrypted_compressed_rar_chases_one_pass() {
    use rars::rar50::{EncryptedCompressedEntry, Rar50VolumeWriter, WriterOptions};
    let f = noisy(300_000, 137);
    let mut features = rars::FeatureSet::store_only();
    features.file_encryption = true;
    let opts = WriterOptions::new(rars::ArchiveVersion::Rar50, features);
    let vols = Rar50VolumeWriter::new(opts)
        .encrypted_compressed_entries(&[EncryptedCompressedEntry {
            name: b"F.bin",
            data: &f,
            mtime: None,
            attributes: 0,
            host_os: 0,
            password: b"hunter2",
        }])
        .max_payload_per_volume(50_000)
        .finish()
        .unwrap();
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    // Password in hand: one-pass.
    let dir = tmpdir("rar-top-enccomp");
    let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
    ex.anchor();
    ex.set_password("hunter2");
    for (vi, vol) in vols.iter().enumerate() {
        feed(
            &ex,
            vi,
            &format!("release.part{}.rar", vi + 1),
            vol,
            7000,
            60 + vi as u64,
        );
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
    // No password: demote, volumes materialize byte-exact.
    let dir = tmpdir("rar-top-enccomp-nopw");
    let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
    ex.anchor();
    for (vi, vol) in vols.iter().enumerate() {
        feed(
            &ex,
            vi,
            &format!("release.part{}.rar", vi + 1),
            vol,
            7000,
            70 + vi as u64,
        );
    }
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "no-password set must demote");
    for (vi, vol) in vols.iter().enumerate() {
        assert_eq!(
            std::fs::read(dir.join(format!("release.part{}.rar", vi + 1))).unwrap(),
            *vol,
            "volume {vi} must materialize byte-exact"
        );
    }
    assert!(!dir.join("F.bin").exists(), "no partial decrypt output");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A resumed run never chases at the top level (twin of the 7z
/// pin): the disabled extractor materializes the volume untouched
/// for the disk path.
#[test]
fn top_level_chase_never_runs_on_a_resumed_run() {
    let f = noisy(200_000, 136);
    let arch = rars_compressed_volume(&[("F.bin", &f)]);
    assert_not_store(&arch);
    let dir = tmpdir("rar-top-resume");
    let ex = Arc::new(Extractor::with_resume(&dir, 1, false, true));
    ex.anchor();
    feed(&ex, 0, "release.rar", &arch, 7000, 55);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("release.rar")).unwrap(), arch);
    assert_eq!(dir_files(&dir), vec!["release.rar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Chase + repair at multi-volume scale (the multi-volume extension
/// of `chase_unblocks_on_patched_volume_span`): a compressed member
/// split across 3+ inner volumes, wrapped in a TWO-volume store
/// outer with an inner volume file spanning the outer boundary. One
/// article is lost inside the packed stream of EACH outer volume;
/// everything else arrives, then both holes are patched via
/// patch_volume_span (the mapped-repair re-entry path). The blocked
/// chase must resume through both fills and complete byte-exact,
/// with neither an outer volume nor an inner archive on disk.
#[test]
fn chase_multi_volume_patched_spans_complete() {
    let dir = tmpdir("chase-mv-patch");
    let f = noisy(300_000, 101);
    let vols = rars_compressed_volumes("F.bin", &f, 50_000);
    assert!(
        vols.len() >= 3,
        "want a real multi-volume set, got {}",
        vols.len()
    );
    for v in &vols {
        assert_not_store(v);
    }
    // Outer vol 1: inner.part1.rar whole + the head of inner.part2.rar;
    // outer vol 2: the rest of inner.part2.rar + the remaining volumes.
    let cut = vols[1].len() / 2;
    let names: Vec<String> = (1..=vols.len())
        .map(|i| format!("inner.part{i}.rar"))
        .collect();
    let o1_entries: Vec<(&str, u64, &[u8], bool, bool)> = vec![
        (
            names[0].as_str(),
            vols[0].len() as u64,
            &vols[0][..],
            false,
            false,
        ),
        (
            names[1].as_str(),
            vols[1].len() as u64,
            &vols[1][..cut],
            false,
            true,
        ),
    ];
    let mut o2_entries: Vec<(&str, u64, &[u8], bool, bool)> = vec![(
        names[1].as_str(),
        vols[1].len() as u64,
        &vols[1][cut..],
        true,
        false,
    )];
    for (i, v) in vols.iter().enumerate().skip(2) {
        o2_entries.push((names[i].as_str(), v.len() as u64, v, false, false));
    }
    let outers = [
        fixtures::rar5_volume_n(&o1_entries, 0),
        fixtures::rar5_volume_n(&o2_entries, 1),
    ];
    // Lose one article deep inside each outer volume's first data
    // area - packed LZ bitstream bytes, not envelope.
    let art = 1000usize;
    let lost: Vec<usize> = outers
        .iter()
        .map(|o| {
            let mut m = VolumeMapper::new(o.len() as u64);
            m.feed(0, o);
            let e = &m.entries[0];
            ((e.data_off + e.data_len / 2) / art as u64) as usize
        })
        .collect();
    let ex = Extractor::new(&dir, 2, true);
    for (si, o) in outers.iter().enumerate() {
        for i in 0..o.len().div_ceil(art) {
            if i == lost[si] {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(o.len());
            ex.write(
                si,
                &format!("o.part{}.rar", si + 1),
                o.len() as u64,
                s as u64,
                &o[s..e],
            )
            .unwrap();
        }
    }
    // "Repair" both holes - rebuilt blocks re-enter through the
    // normal patch path, exactly as mapped PAR2 repair delivers them.
    for (si, o) in outers.iter().enumerate() {
        let (s, e) = (lost[si] * art, ((lost[si] + 1) * art).min(o.len()));
        assert!(
            !ex.covered(si, s as u64, e - s),
            "vol {si} hole really is a hole"
        );
        ex.patch_volume_span(si, s as u64, &o[s..e]).unwrap();
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The chase SINK is the routing seam (n-deep): a compressed layer
/// wrapping a STORE archive - the chase's decompressed output routes
/// into a child slot, sniffs as RAR, and the store layer below keeps
/// streaming. Only the innermost payload ever touches disk.
#[test]
fn chase_output_store_archive_streams_below() {
    let dir = tmpdir("chase-deep");
    let g = payload(120_000, 99);
    let deep = fixtures::rar5_volume(&[("G.bin", 120_000, &g, false, false)]);
    let inner_arch = rars_compressed_volume(&[("deep.rar", &deep)]);
    assert_not_store(&inner_arch);
    let outer = fixtures::rar5_volume(&[(
        "inner.rar",
        inner_arch.len() as u64,
        &inner_arch,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &outer, 7000, 13);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("G.bin")).unwrap(), g);
    // No outer volume, no compressed archive, no store archive.
    assert_eq!(dir_files(&dir), vec!["G.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The chase gates: NZBFAST_NO_NESTED_CHASE=1 parses as off, and the
/// runtime setter drives the same latch - with it off, a compressed
/// inner demotes to a materialized file exactly as before the chase
/// existed (nested routing itself stays on). The env PARSE is
/// asserted on the pure helper for the same parallel-runner reason
/// as `nested_disabled_by_env`.
#[test]
fn chase_disabled_by_env() {
    assert!(chase_env_off_value(Some("1")));
    assert!(!chase_env_off_value(Some("0")));
    assert!(!chase_env_off_value(None));

    let dir = tmpdir("chase-env");
    let f = payload(200_000, 90);
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
    assert!(ex.inner.lock().unwrap().chase_on, "gate must default on");
    ex.set_nested_chase(false);
    feed(&ex, 0, "v.rar", &outer, 7000, 15);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
    assert!(!dir.join("F.bin").exists());
    assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Cancel semantics: dropping an extractor mid-chase (job abandoned)
/// aborts the chase buffers and the worker exits - the drop returns
/// instead of hanging on a frontier that will never fill.
#[test]
fn chase_worker_exits_on_extractor_drop() {
    let dir = tmpdir("chase-drop");
    let f = noisy(300_000, 89);
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
    // Just enough for the chase to attach and its worker to block at
    // the frontier - then abandon the job.
    ex.write(0, "v.rar", outer.len() as u64, 0, &outer[..4000])
        .unwrap();
    drop(ex);
    std::fs::remove_dir_all(&dir).unwrap();
}
