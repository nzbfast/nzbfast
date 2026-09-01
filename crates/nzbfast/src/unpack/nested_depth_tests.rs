//! The nested depth cap at the DISK site, and the store exemption it
//! owes the in-stream one.
//!
//! `c0b1c788a` (31 Aug 2026) stopped charging STORED layers against the
//! nested depth cap: the cap is a decompression-bomb backstop, and a
//! stored layer is the same bytes with a header on the front, so it
//! cannot expand. It changed ONE of the two sites that enforce the cap
//! and said so in its own message - the in-stream chain in
//! `nzbkit::extract`, which is enough for a live download, and not the
//! disk post-pass here, which is what a RESUMED or disk-only job runs.
//! The same post therefore got two different answers depending on a
//! path the user never chose. Its own regression test still passed
//! after the change, because that test drives this site.
//!
//! The evidence is the hard part and it is why this is not a
//! transcription of the in-stream code. That side learns an entry's
//! compression method from the RAR mapper as the articles arrive
//! (`Inner::saw_store` / `saw_compressed`, latched in `chase.rs`); this
//! side walks files that are already on disk and had no such evidence
//! at all. [`nzbkit::rar::volume_is_store_only`] is the disk reader -
//! a header walk that seeks PAST each member's data area, so it costs
//! about two reads per healthy volume whatever its size, immediately
//! before this same level extracts those archives in full.
//!
//! What is tested here, in the order the defect has to be caught:
//! the evidence reader's own direction (positive evidence only, and a
//! COMPRESSING layer must still charge), the cap threading that carries
//! a raise down the recursion, and the hard ceiling that stops the
//! exemption being an open licence.
use super::*;
use nzbkit::extract::NESTED_MAX_DEPTH_HARD_CEILING;
use nzbkit::rar::fixtures;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-nestdepth-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Anywhere in the subtree: the ladder stages through `.nzbfast-nest`
/// and lifts back, and a level's output can land in a subfolder.
fn find_file(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(hit) = find_file(&p, name) {
                return Some(hit);
            }
        } else if p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
    }
    None
}

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// One STORE-mode RAR5 volume holding `inner` under `name`.
fn store_rar(name: &str, inner: &[u8]) -> Vec<u8> {
    fixtures::rar5_volume(&[(name, inner.len() as u64, inner, false, false)])
}

/// A genuinely COMPRESSING RAR4 volume from the vendored writer - a real
/// LZ bitstream, not a store archive with a flag flipped. The `noisy`
/// shape (xorshift byte, zero byte, ...) is compressible enough that the
/// writer keeps the compressed method; the control assertion in
/// [`the_evidence_reader_only_answers_yes_to_a_proven_store_layer`]
/// pins that it really did, so a writer that fell back to store cannot
/// turn this fixture into a second store test in silence.
fn compressed_rar(name: &str, data: &[u8]) -> Vec<u8> {
    use rars::rar15_40::{FileEntry, WriterOptions, write_compressed_archive};
    use rars::{ArchiveVersion, FeatureSet};
    write_compressed_archive(
        &[FileEntry {
            name: name.as_bytes(),
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    )
    .unwrap()
}

/// Half-entropy bytes: compressible enough that the RAR4 writer keeps
/// the compressed method. Same shape as `extract::testutil::noisy`,
/// which is `pub(super)` to that module and out of reach here.
fn noisy(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            } else {
                0
            }
        })
        .collect()
}

/// The evidence half, on its own, in BOTH directions.
///
/// This is the arm that can rot silently: `layer_stores_everything`
/// answering `false` everywhere leaves the disk site exactly as it was
/// before this work, which is a passing suite and a defect. So the
/// positive direction is pinned as hard as the negative one, and the
/// compressing fixture carries a control - if the writer ever stored it
/// instead of compressing it, the "still charges" leg would be a second
/// store test wearing the wrong name.
#[test]
fn the_evidence_reader_only_answers_yes_to_a_proven_store_layer() {
    let dir = tmpdir("evidence");
    let data = payload(40_000, 11);

    // Nothing to judge is not evidence of anything.
    assert!(
        !layer_stores_everything(&snapshot_recursive(&dir).unwrap()),
        "an empty level proves nothing and must not raise the cap"
    );

    // A plain data file is not an archive: still nothing to judge.
    std::fs::write(dir.join("readme.nfo"), b"ripped by nobody\n").unwrap();
    assert!(
        !layer_stores_everything(&snapshot_recursive(&dir).unwrap()),
        "a level with no archive proves nothing"
    );

    // One proven store volume: the raise is earned.
    let store = store_rar("payload.bin", &data);
    std::fs::write(dir.join("release.rar"), &store).unwrap();
    assert!(
        layer_stores_everything(&snapshot_recursive(&dir).unwrap()),
        "a store-only RAR layer must be recognised - without this the \
         whole exemption is dead at the disk site and nothing says so"
    );

    // The control: the compressing fixture really does compress.
    let packed = compressed_rar("payload.bin", &noisy(40_000, 7));
    let cdir = tmpdir("evidence-c");
    std::fs::write(cdir.join("packed.rar"), &packed).unwrap();
    assert!(
        !nzbkit::rar::volume_is_store_only(&cdir.join("packed.rar")),
        "fixture is not compressed - this leg would prove nothing"
    );
    assert!(
        !layer_stores_everything(&snapshot_recursive(&cdir).unwrap()),
        "a compressing layer must still spend a level of the cap"
    );

    // A store volume BESIDE a compressing one: the level can expand, and
    // it is the other archive that would do the expanding.
    std::fs::write(dir.join("packed.rar"), &packed).unwrap();
    assert!(
        !layer_stores_everything(&snapshot_recursive(&dir).unwrap()),
        "every candidate must prove it, not the first one"
    );
    std::fs::remove_file(dir.join("packed.rar")).unwrap();

    // A zip proves nothing about compression here - there is no method
    // for this reader to read - so it withholds the raise exactly as an
    // unreadable volume does.
    let zip = dir.join("inner.zip");
    std::fs::write(&zip, b"PK\x03\x04rest-of-a-zip-nobody-parses").unwrap();
    assert!(
        !layer_stores_everything(&snapshot_recursive(&dir).unwrap()),
        "a non-RAR archive is UNKNOWN, never proven store"
    );
    std::fs::remove_file(&zip).unwrap();

    // A `.rar` whose signature bytes were destroyed is in scope by NAME
    // and must withhold the raise rather than be skipped past.
    std::fs::write(dir.join("broken.rar"), b"not a rar at all").unwrap();
    assert!(
        !layer_stores_everything(&snapshot_recursive(&dir).unwrap()),
        "an unreadable named volume is UNKNOWN, never proven store"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&cdir);
}

/// The disk twin of `nested_depth_cap_materializes`: a store ladder
/// deeper than the cap reaches its payload, because no layer in it
/// spends a level.
///
/// Six store layers against a cap of five. Before this work the sixth
/// stopped short and left `L06.rar` materialized on disk - correct
/// behaviour for a bomb guard and wrong about this ladder, which cannot
/// expand a byte. The cap is passed rather than set, so this test
/// mutates no process-global state (the daemon setter is a static, and
/// two tests moving it are reading each other's writes).
#[test]
fn a_proven_store_ladder_does_not_spend_a_level() {
    let dir = tmpdir("storeladder");
    let data = payload(60_000, 23);
    // outer < L02 < L03 < L04 < L05 < L06 < payload.bin: six layers,
    // one deeper than the cap of five.
    let mut cur = store_rar("payload.bin", &data);
    for i in (2..=6).rev() {
        cur = store_rar(&format!("L{i:02}.rar"), &cur);
    }
    std::fs::write(dir.join("release.rar"), &cur).unwrap();

    let ok = extract_nested_capped(&dir, None, 0, 5, &mut None).expect("extract_nested_capped");
    assert!(ok.produced(), "a store ladder must not fail: {ok:?}");
    let got = find_file(&dir, "payload.bin").expect("payload past the un-exempted cap");
    assert_eq!(
        std::fs::read(&got).unwrap(),
        data,
        "payload must be byte-exact"
    );
    assert!(
        find_file(&dir, "L06.rar").is_none(),
        "the deepest layer must have been unpacked, not left materialized"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A COMPRESSING layer still spends one: the SAME two-rung ladder
/// reaches its payload when the outer layer stores and stops one level
/// short when it compresses. The two legs differ in exactly one thing -
/// the outer archive's compression method.
///
/// THE CAP GATES DESCENT, NOT THIS LEVEL'S OWN EXTRACTION, which is the
/// thing to understand before writing another test here. A level always
/// unpacks what it holds; the cap decides whether the recursion enters
/// what that unpacking produced. So a single packed rung at the BOTTOM
/// of a store ladder proves nothing at all - the descent into it was
/// already authorised by the store layer above, and its payload comes
/// out either way. The difference a packed layer makes is visible only
/// where the cap actually binds, which is why this pair runs at a cap
/// of ONE: with it the store leg descends once and the compressing leg
/// does not, and nothing else about them differs.
///
/// This is the leg that keeps the exemption honest at the disk site. It
/// fails if [`layer_stores_everything`] is loosened into "some archive
/// here is store" or into an unconditional raise - neither of which the
/// store ladder above can see, because a ladder that is store all the
/// way down passes under both.
#[test]
fn a_compressing_layer_still_spends_a_level() {
    let data = payload(60_000, 19);
    let inner = store_rar("payload.bin", &data);

    // Store outer, cap 1: the layer earns its raise, so the recursion
    // enters the archive it just produced and the payload comes out.
    let sdir = tmpdir("mixed-store");
    std::fs::write(sdir.join("release.rar"), store_rar("L02.rar", &inner)).unwrap();
    let ok = extract_nested_capped(&sdir, None, 0, 1, &mut None).expect("extract_nested_capped");
    assert!(ok.produced(), "a store ladder must not fail: {ok:?}");
    assert_eq!(
        std::fs::read(find_file(&sdir, "payload.bin").expect("payload past the raised cap"))
            .unwrap(),
        data,
        "payload must be byte-exact"
    );

    // Compressing outer, same cap, same inner archive: no raise, so the
    // descent stops and the inner layer is left materialized.
    let cdir = tmpdir("mixed-packed");
    let outer = compressed_rar("L02.rar", &inner);
    std::fs::write(cdir.join("release.rar"), &outer).unwrap();
    assert!(
        !nzbkit::rar::volume_is_store_only(&cdir.join("release.rar")),
        "fixture is not compressed - this leg would be a second store test"
    );
    let ok = extract_nested_capped(&cdir, None, 0, 1, &mut None).expect("extract_nested_capped");
    assert!(
        ok.produced(),
        "a too-deep chain degrades, never fails: {ok:?}"
    );
    let left = find_file(&cdir, "L02.rar").expect("deepest layer left materialized");
    assert_eq!(
        std::fs::read(&left).unwrap(),
        inner,
        "the materialized archive must be byte-exact"
    );
    assert!(
        find_file(&cdir, "payload.bin").is_none(),
        "the compressing layer spends the level - its payload is past the cap"
    );
    let _ = std::fs::remove_dir_all(&sdir);
    let _ = std::fs::remove_dir_all(&cdir);
}

/// The bound on the exemption at the disk site, the twin of
/// `nested_store_ladder_stops_at_the_hard_ceiling`: a store ladder
/// deeper than [`NESTED_MAX_DEPTH_HARD_CEILING`] materializes AT the
/// ceiling.
///
/// A store ladder a million levels deep inflates no byte and still costs
/// a real extractor, real buffers and real scratch per level, so the
/// raise is clamped rather than open-ended. Without the clamp this
/// ladder unpacks whole.
///
/// It STARTS deep rather than running 64 real extractions: `depth` is a
/// counter and `cap` is now a parameter, so entering six levels below
/// the ceiling with a cap the raise saturates against exercises the
/// clamp itself - the one thing the ladder above cannot reach - at six
/// extractions instead of sixty-four. Every number is DERIVED from the
/// constant, so moving the ceiling moves this test with it rather than
/// leaving a magic number that passes for the wrong reason.
#[test]
fn a_store_ladder_stops_at_the_hard_ceiling() {
    let ceiling = NESTED_MAX_DEPTH_HARD_CEILING;
    let start = ceiling - 6;
    let dir = tmpdir("ceiling");
    let data = payload(1_000, 91);
    // The archive materialized at depth k is named `L{k}.rar`, so the
    // one left behind names the ceiling itself.
    let at_ceiling = store_rar("payload.bin", &data);
    let mut cur = at_ceiling.clone();
    for k in (start + 1..=ceiling).rev() {
        cur = store_rar(&format!("L{k}.rar"), &cur);
    }
    std::fs::write(dir.join("release.rar"), &cur).unwrap();

    // A cap two below the ceiling, so the raise saturates rather than
    // the ladder simply running out.
    let ok = extract_nested_capped(&dir, None, start, ceiling - 2, &mut None)
        .expect("extract_nested_capped");
    assert!(
        ok.produced(),
        "materializing at the ceiling is never a hard failure: {ok:?}"
    );
    let want = format!("L{ceiling}.rar");
    let left = find_file(&dir, &want).unwrap_or_else(|| panic!("{want} left materialized"));
    // Not just the NAME: the bytes are the whole remaining ladder, which
    // is what "materializes" has to mean - a name check alone passes on
    // a truncated or empty file.
    assert_eq!(
        std::fs::read(&left).unwrap(),
        at_ceiling,
        "the materialized archive must be byte-exact"
    );
    assert!(
        find_file(&dir, "payload.bin").is_none(),
        "the clamp must stop the ladder at the ceiling"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The shape a real release actually has: a MULTI-VOLUME store set. Every
/// volume has to read store-only on its own for the level to earn the
/// raise, and a mid-set volume is a different parse from a standalone one
/// - it opens on a continuation piece and ends at EOF rather than on an
/// end-of-archive block. If that came back `false` the exemption would be
/// dead for every ordinary post while the single-volume ladders above
/// stayed green, which is precisely the failure this file exists to make
/// impossible.
#[test]
fn a_multi_volume_store_set_is_proven_by_every_volume() {
    let dir = tmpdir("multivol");
    let total = payload(120_000, 3);
    let half = total.len() / 2;
    let v1 = fixtures::rar5_volume_n(
        &[("film.mkv", total.len() as u64, &total[..half], false, true)],
        0,
    );
    let v2 = fixtures::rar5_volume_n(
        &[("film.mkv", total.len() as u64, &total[half..], true, false)],
        1,
    );
    std::fs::write(dir.join("s.part01.rar"), &v1).unwrap();
    std::fs::write(dir.join("s.part02.rar"), &v2).unwrap();
    assert!(
        nzbkit::rar::volume_is_store_only(&dir.join("s.part01.rar")),
        "the first volume of a store set must prove itself"
    );
    assert!(
        nzbkit::rar::volume_is_store_only(&dir.join("s.part02.rar")),
        "a CONTINUATION volume must prove itself too - it opens mid-entry \
         and ends at EOF, not on an end-of-archive block"
    );
    assert!(
        layer_stores_everything(&snapshot_recursive(&dir).unwrap()),
        "a multi-volume store set is a proven store layer"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// One RAR4 volume holding `inner` under `name`, with a compressible
/// companion beside it so the layer reads NON-store.
///
/// The obvious spelling - wrap the inner archive with
/// [`compressed_rar`] - does not build a compressing ladder, which is
/// worth knowing before writing another depth test here. Measured
/// 31 Aug 2026: an already-RAR-compressed payload is incompressible, so
/// the writer falls back to STORE, and a five-rung ladder built that way
/// came out store / compressed / store / store / compressed in that
/// order. Every stored rung then earns the exemption's raise back and
/// the ladder measures the hard ceiling instead of the cap - a test that
/// passes for the wrong reason. The companion is what fixes it: one
/// compressible member makes the whole layer able to expand, which is
/// exactly the rule [`layer_stores_everything`] enforces, and the
/// control in the test below pins that it really did.
fn charging_layer(name: &str, inner: &[u8], filler: &str, seed: u64) -> Vec<u8> {
    use rars::rar15_40::{FileEntry, WriterOptions, write_compressed_archive};
    use rars::{ArchiveVersion, FeatureSet};
    let noise = noisy(20_000, seed);
    fn mk<'a>(n: &'a str, d: &'a [u8]) -> FileEntry<'a> {
        FileEntry {
            name: n.as_bytes(),
            data: d,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }
    }
    write_compressed_archive(
        &[mk(name, inner), mk(filler, &noise)],
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    )
    .unwrap()
}

/// The tail's entry depth costs EXACTLY ONE level of the disk pass's own
/// budget, and buys the whole of the rest of it however many levels the
/// in-stream half already spent.
///
/// This is the pin under [`TAIL_NESTED_ENTRY_DEPTH`], and the measured
/// half of the composition that constant documents. ONE ladder, TWO
/// entry depths: from 0 (the disk-only path, `extract_local`) it unpacks
/// `CAP` layers and reaches the payload; from `TAIL_NESTED_ENTRY_DEPTH`
/// (what `get::tail` passes once the in-stream half has run) it unpacks
/// one fewer and leaves the deepest layer materialized. So the disk
/// budget is `CAP - TAIL_NESTED_ENTRY_DEPTH`, INDEPENDENT of the layers
/// the in-stream chain may already have spent, and the documented total
/// for a demoted job is `2 * cap - 1`.
///
/// Every layer here CHARGES the cap, which is the only thing that makes
/// the count readable - a proven-store ladder earns its raise back at
/// each rung and measures the hard ceiling instead (see
/// [`a_proven_store_ladder_does_not_spend_a_level`]). The cap is passed
/// rather than set, so this mutates no process-global state.
///
/// Verified to bite three ways: the constant moved to 0 (leg 2 reaches
/// the payload), moved to 2 (leg 2 stops two short, which is what the
/// named-leftover assertion is for and the absent payload alone cannot
/// see), and the fixture reverted to a store layer (the control).
///
/// TWO THINGS IT PINS THE MEANING OF AND NOT THE SPELLING, said rather
/// than left to be found. A lane that threaded a computed depth into the
/// tail call instead would leave this green - what refuses that is the
/// constant going unused, which is `dead_code` under the clippy gate,
/// and the argument at [`TAIL_NESTED_ENTRY_DEPTH`] that a reader hits
/// on the way. And it does not assert the in-stream half's own `cap`
/// layers, and cannot: `nzbkit`'s fixtures build no COMPRESSING RAR5,
/// so an in-stream chain that spends more than one level before demoting
/// is not buildable from here. That number is a property of the
/// `depth < cap` gate in `Extractor::ensure_child` instead.
#[test]
fn the_tail_entry_depth_costs_exactly_one_level() {
    const CAP: usize = 5;
    let data = payload(30_000, 41);
    // release.rar < L2 < L3 < L4 < L5 < payload.bin: five layers to
    // unpack, so entering at 0 reaches the payload with nothing to
    // spare and entering one level deeper cannot.
    let mut cur = store_rar("payload.bin", &data);
    for i in (2..=5).rev() {
        cur = charging_layer(
            &format!("L{i}.rar"),
            &cur,
            &format!("f{i}.bin"),
            i as u64 * 9 + 1,
        );
    }
    let outer = cur;

    // The control: these layers really do charge. Without it the pair
    // below is two readings of the store exemption wearing the wrong
    // name, and BOTH legs would reach the payload.
    let probe = tmpdir("entrydepth-probe");
    std::fs::write(probe.join("release.rar"), &outer).unwrap();
    assert!(
        !layer_stores_everything(&snapshot_recursive(&probe).unwrap()),
        "fixture layer does not charge the cap - this test would prove nothing"
    );
    let _ = std::fs::remove_dir_all(&probe);

    // Leg 1: the disk-only path. `CAP` levels, and the payload comes out.
    let d0 = tmpdir("entrydepth-0");
    std::fs::write(d0.join("release.rar"), &outer).unwrap();
    let ok = extract_nested_capped(&d0, None, 0, CAP, &mut None).expect("extract_nested_capped");
    assert!(
        ok.produced(),
        "a ladder within the cap must not fail: {ok:?}"
    );
    assert_eq!(
        std::fs::read(find_file(&d0, "payload.bin").expect("payload within the cap")).unwrap(),
        data,
        "payload must be byte-exact"
    );

    // Leg 2: the tail's entry. The SAME ladder, one level short.
    let d1 = tmpdir("entrydepth-tail");
    std::fs::write(d1.join("release.rar"), &outer).unwrap();
    let ok = extract_nested_capped(&d1, None, TAIL_NESTED_ENTRY_DEPTH, CAP, &mut None)
        .expect("extract_nested_capped");
    assert!(
        ok.produced(),
        "a too-deep chain degrades, never fails: {ok:?}"
    );
    assert!(
        find_file(&d1, "payload.bin").is_none(),
        "entering at {TAIL_NESTED_ENTRY_DEPTH} must cost exactly one level of the \
         disk budget - the payload is past it"
    );
    // Not just the absent payload: NAME the layer left behind, so a leg
    // that stopped two levels short - or never ran at all - cannot pass.
    assert!(
        find_file(&d1, "L5.rar").is_some(),
        "the deepest layer reached must be left materialized, not lost"
    );
    let _ = std::fs::remove_dir_all(&d0);
    let _ = std::fs::remove_dir_all(&d1);
}
