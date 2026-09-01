//! Flat-set extraction tests - volume naming, store sets, budgets,
//! protected sources and the archive-shape badge - moved out of
//! extract/mod.rs bodily (TODO 106).
//!
//! The recursive half of the same block lives in `nested_tests.rs`; see the
//! note there for why it is two files.

use super::*;
use crate::rar::fixtures;

use super::testutil::*;

/// M4-44: the chain-shared output-name claim keys on what the VOLUME
/// files as one object, and `str::to_lowercase` is weaker than that.
/// These five pairs are each ONE file object on APFS (measured 31 Aug
/// 2026 by creating both and comparing inodes) and each was TWO keys
/// before this site moved to `disk::case_fold_key` - so both claims
/// succeeded, the second `FileWriter::create` truncated the first, and a
/// chain finished a payload short at rc=0.
///
/// The `fold = false` half is not decoration: on a case-sensitive volume
/// these ARE distinct files, and a fold applied unconditionally would
/// rename one of them for nothing.
#[test]
fn the_output_name_claim_folds_the_way_the_volume_does() {
    let one_object = [
        ("Straße.mkv", "STRASSE.MKV"),
        ("ﬁle.txt", "file.txt"),
        ("ſample.nfo", "sample.nfo"),
        ("ΟΔΟΣ.txt", "οδος.txt"),
        ("README.NFO", "readme.nfo"),
    ];
    for (a, b) in one_object {
        assert_eq!(
            name_collision_key(true, a),
            name_collision_key(true, b),
            "{a:?} and {b:?} name ONE object on a case-insensitive volume; \
             two keys here means the second create truncates the first"
        );
        assert_ne!(
            name_collision_key(false, a),
            name_collision_key(false, b),
            "{a:?} and {b:?} are distinct files on a case-sensitive volume"
        );
    }
    // The over-fold direction, which costs a needless `001-` rename here
    // and a DROPPED FILE in `nzbfast::rarfix` - which is why that site
    // deliberately still lowercases. APFS keeps these apart.
    assert_ne!(
        name_collision_key(true, "I.txt"),
        name_collision_key(true, "ı.txt")
    );
}

/// The stem is the grouping identity for a whole posted set, so
/// every volume-naming shape must reduce to one base - and things
/// that merely LOOK like part numbers must survive untouched.
#[test]
fn release_stems_reduce_every_volume_shape() {
    let st = |n: &str| release_stem(n);
    // The classic RAR shapes, unchanged.
    assert_eq!(st("x.part01.rar"), "x");
    assert_eq!(st("x.r00"), "x");
    // Old-style rollover volumes past .r99: the letter walks s..z,
    // one stem the whole way (vol_sort_key orders the same range).
    assert_eq!(st("x.s00"), "x");
    assert_eq!(st("x.t00"), "x");
    assert_eq!(st("x.z99"), "x");
    assert_eq!(st("x.z01"), "x");
    assert_eq!(st("x.vol000+01.par2"), "x");
    assert_eq!(st("x.par2"), "x");
    // Bare-ordinal recovery volumes: nothing before the dash. The stem
    // must lose the ".vol-01" or the release shatters in the index -
    // live rows sat at "….playWEB.vol-01" until 13 Aug 2026.
    assert_eq!(st("x.vol-01.par2"), "x");
    assert_eq!(
        st("Fightland.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-playWEB.vol-07.par2"),
        "Fightland.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-playWEB"
    );
    // Not volumes: "volume" spelt out, and a compilation numbered
    // Vol-3 - that single digit names a release.
    assert_eq!(st("Rel.volume-2.par2"), "Rel.volume-2");
    assert_eq!(st("VA.Best.Hits.Vol-3.par2"), "VA.Best.Hits.Vol-3");
    // Split containers: parts and their par2 sidecars share a base.
    assert_eq!(st("Some.Set.7z.001"), "Some.Set.7z");
    assert_eq!(st("Some.Set.7z.122"), "Some.Set.7z");
    assert_eq!(st("Some.Set.7z.1000"), "Some.Set.7z");
    assert_eq!(st("Some.Set.zip.001"), "Some.Set.zip");
    assert_eq!(st("Some.Set.7z.001.par2"), "Some.Set.7z");
    assert_eq!(st("Some.Set.7z.vol03+04.par2"), "Some.Set.7z");
    // Not volumes: a single archive, short numeric tails, digits
    // with no container extension in front of them.
    assert_eq!(st("Album.Track.01"), "Album.Track.01");
    assert_eq!(st("v1.7z"), "v1.7z");
    assert_eq!(st("Backup.2019.001"), "Backup.2019.001");
    assert_eq!(st("Some.Set.7z.01"), "Some.Set.7z.01");
}

#[test]
fn vol_sort_key_letter_rollover_and_numeric() {
    let k = |n: &str| vol_sort_key(n).0;
    assert!(k("x.rar") < k("x.r00"));
    assert_eq!(k("x.r00"), 1);
    assert_eq!(k("x.r99"), 100);
    // 100+-volume sets roll the letter: continuity across .r99 → .s00
    // (was u64::MAX, breaking base-resolution at the boundary).
    assert_eq!(k("x.s00"), 101);
    assert_eq!(k("x.t00"), 201);
    // WinRAR numeric volumes order numerically.
    assert!(k("x.001") < k("x.002"));
    // Non-volume extensions stay in the terminal bucket.
    assert_eq!(k("x.srt"), u64::MAX);
    assert_eq!(k("x.mkv"), u64::MAX);
}

#[test]
fn single_volume_direct_extract() {
    let dir = tmpdir("single");
    let data = payload(200_000, 1);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    let rep = ex.finish().unwrap();
    assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 200_000)]);
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    // The volume file must NOT exist (one-pass!).
    assert!(!dir.join("v.rar").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A slot fed strictly out of order (offset 0 dead LAST - the
/// synthesized-segment-numbering shape) must ask the installed
/// promote hook to front-load the offset-0 article on its FIRST held
/// span: the honest-ladder span (0, 1) plus the rotation guess
/// (size-X, +1) derived from that first span's offset X. Exactly once
/// HERE, because these arrivals climb - `probe_offset0` re-aims only
/// on a falling minimum, and the test below covers that. The set still
/// classifies when offset 0 lands and extracts one-pass.
#[test]
fn out_of_order_slot_probes_offset0_promote_once() {
    let dir = tmpdir("probe0");
    let data = payload(200_000, 11);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>, bool)>>>;
    let calls: Calls = Default::default();
    let sink = calls.clone();
    ex.set_promote_hook(Arc::new(
        move |n: &str, s: u64, sp: &[(u64, u64)], u: bool| {
            sink.lock()
                .unwrap()
                .push((n.to_string(), s, sp.to_vec(), u));
        },
    ));
    let art = 7000usize;
    let n_arts = vol.len().div_ceil(art);
    let size = vol.len() as u64;
    for i in (1..n_arts).chain([0]) {
        let s = i * art;
        let e = (s + art).min(vol.len());
        ex.write(0, "v.rar", size, s as u64, &vol[s..e]).unwrap();
    }
    // Asked once, on the first hold: offset 0 where the ladder says
    // it is, and where a posting-order rotation would put it given
    // that the first arrival carried offset `art` - which is also the
    // lowest offset this slot ever holds, so nothing re-aims. The second call
    // is the inner file's own one-shot probe: drain_holds re-feeds
    // the held spans BEFORE the classifying span's own forward, so
    // the child slot also starts out of order (no rotation guess
    // below the root - rotation is a posting-layer phenomenon).
    // Probes are NON-urgent: nothing blocks on them, so they must
    // not flip the pool into stream mode.
    let x = art as u64;
    assert_eq!(
        calls.lock().unwrap().clone(),
        vec![
            (
                "v.rar".to_string(),
                size,
                vec![(0, 1), (size - x, size - x + 1)],
                false
            ),
            ("movie.mkv".to_string(), 200_000, vec![(0, 1)], false),
        ]
    );
    let rep = ex.finish().unwrap();
    assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 200_000)]);
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    assert!(!dir.join("v.rar").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The one-shot probe's blind spot. Under a rotated ladder the
/// rotation guess is `size - offset` for the FIRST span that arrives,
/// which lands on the head's declared byte only when that first span
/// is the `head_ids` article (declared position 0). If ordinary
/// payload beats it into the decoder - a delayed or retried head - the
/// guess undershoots by one article per declared position it missed,
/// and `map_span_ids` gives it only +3 articles of forward slack.
///
/// So the estimator must be the MINIMUM arrived offset, not the first,
/// and the probe must re-issue as that minimum falls: the late
/// `head_ids` article carries a lower offset than everything that beat
/// it, and its arrival is exactly the correction. Bounded re-issues
/// (`PROBE0_MAX`), so this still cannot fight the M11 stream reader's
/// rolling re-promote.
#[test]
fn a_late_head_ids_article_re_aims_the_rotation_guess() {
    let dir = tmpdir("probe0-reissue");
    let data = payload(200_000, 11);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>, bool)>>>;
    let calls: Calls = Default::default();
    let sink = calls.clone();
    ex.set_promote_hook(Arc::new(
        move |n: &str, s: u64, sp: &[(u64, u64)], u: bool| {
            sink.lock()
                .unwrap()
                .push((n.to_string(), s, sp.to_vec(), u));
        },
    ));
    let art = 7000usize;
    let n = vol.len().div_ceil(art);
    let size = vol.len() as u64;
    // A rot-3 ladder: declared position p announces the article whose
    // actual yEnc offset is `((p + 3) % n) * art`, so the head sits at
    // declared position n-3 and declared 0 carries byte 3*art.
    const K: usize = 3;
    let actual = |p: usize| (p + K) % n;
    let len_of = |i: usize| ((i + 1) * art).min(vol.len()) - i * art;
    // Declared byte position of declared slot p - what a promote span
    // has to name for `map_span_ids` to resolve it to that article.
    let declared_byte = |p: usize| (0..p).map(|q| len_of(actual(q))).sum::<usize>() as u64;
    let head_byte = declared_byte(n - K);

    // Arrival order, by DECLARED position: four ordinary articles beat
    // the head_ids article (declared 0) into the decoder, then it
    // lands, then the rest, with the real head dead last.
    let lead = [4usize, 5, 6, 7, 0];
    assert!(!lead.contains(&(n - K)), "fixture: head is in the lead run");
    let mut order: Vec<usize> = lead.to_vec();
    order.extend((1..n).filter(|p| !lead.contains(p) && *p != n - K));
    order.push(n - K);
    for p in order {
        let i = actual(p);
        let s = i * art;
        let e = (s + art).min(vol.len());
        ex.write(0, "v.rar", size, s as u64, &vol[s..e]).unwrap();
    }

    // Every rotation guess this slot asked for, in order.
    let guesses: Vec<u64> = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(name, ..)| name == "v.rar")
        .filter_map(|(_, _, sp, _)| sp.iter().find(|(s, _)| *s != 0).map(|(s, _)| *s))
        .collect();
    // Exactly two, and both exact. The first is the blind spot: taken
    // from the first arrival (declared 4), it undershoots the head by
    // four articles - past `map_span_ids`'s +3 slack, so it front-loads
    // the wrong articles and, with the old latch, that was final. The
    // second is the correction the late head_ids article paid for.
    //
    // Nothing after it: the ladder's WRAP (declared 27 and 28 carry
    // bytes 7000 and 14000, BELOW the head_ids article's 21000) lands
    // past `PROBE0_WINDOW` held spans and must not re-aim, or the guess
    // walks past the head instead of onto it.
    assert_eq!(
        guesses,
        vec![head_byte - 4 * art as u64, head_byte],
        "head byte {head_byte}, art {art}"
    );
    assert!(guesses.len() <= PROBE0_MAX as usize, "{guesses:?}");
    // And the set still extracts in place.
    let rep = ex.finish().unwrap();
    assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 200_000)]);
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    assert!(!dir.join("v.rar").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The re-issue's bound, pinned directly. A promote must not fight the
/// M11 stream reader's rolling re-promote, so a slot whose minimum
/// keeps falling gets a handful of monotonically-improving guesses and
/// then stops - never a promote per article. Ten strictly falling
/// arrivals, `PROBE0_MAX` promotes.
#[test]
fn the_offset0_reprobe_stops_at_the_bound() {
    let dir = tmpdir("probe0-bound");
    let data = payload(200_000, 11);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>, bool)>>>;
    let calls: Calls = Default::default();
    let sink = calls.clone();
    ex.set_promote_hook(Arc::new(
        move |n: &str, s: u64, sp: &[(u64, u64)], u: bool| {
            sink.lock()
                .unwrap()
                .push((n.to_string(), s, sp.to_vec(), u));
        },
    ));
    let art = 7000usize;
    let n = vol.len().div_ceil(art);
    let size = vol.len() as u64;
    // Ten arrivals walking DOWN the file, then the rest, then the head.
    let order: Vec<usize> = (1..=10).rev().chain(11..n).chain([0]).collect();
    for i in order {
        let s = i * art;
        let e = (s + art).min(vol.len());
        ex.write(0, "v.rar", size, s as u64, &vol[s..e]).unwrap();
    }
    let guesses: Vec<u64> = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(name, ..)| name == "v.rar")
        .filter_map(|(_, _, sp, _)| sp.iter().find(|(s, _)| *s != 0).map(|(s, _)| *s))
        .collect();
    let a = art as u64;
    assert_eq!(
        guesses,
        vec![size - 10 * a, size - 9 * a, size - 8 * a, size - 7 * a]
    );
    assert_eq!(guesses.len(), PROBE0_MAX as usize);
    // Still one-pass with the head dead last.
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    assert!(!dir.join("v.rar").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// BUG (HIGH): the in-stream extractor reserved an attacker-declared
/// size. `inner_writer` passes the entry's `unpacked_size` - a RAR
/// header vint the poster controls - straight to `FileWriter::create`,
/// which `set_len`s and (on Linux) really `fallocate`s it. The
/// volume-bounds check does NOT close this in the `split_after`
/// shape: the writer is created with the inflated declaration DURING
/// the download and the demote only lands at `finish()`, long after
/// the blocks are gone.
///
/// The ceiling is the NZB's own posted byte count: a store archive
/// cannot legitimately unpack to more than what was posted.
#[test]
fn an_inflated_unpacked_size_cannot_reserve_past_the_posted_ceiling() {
    let dir = tmpdir("prealloc-cap");
    let data = payload(200_000, 9);
    // 200 KB really posted; the header declares 8 TiB and sets
    // split_after, so nothing demotes until finish().
    const HUGE: u64 = 8 << 40;
    let vol = fixtures::rar5_volume(&[("movie.mkv", HUGE, &data, false, true)]);
    let ex = Extractor::new(&dir, 1, true);
    let posted = vol.len() as u64;
    ex.set_prealloc_ceiling(posted);
    feed(&ex, 0, "x.part1.rar", &vol, 7000, 3);

    // MID-DOWNLOAD - the window the finish-time gates cannot cover.
    let reserved = std::fs::metadata(dir.join("movie.mkv")).unwrap().len();
    assert!(
        reserved <= posted,
        "reserved {reserved} bytes for a {posted}-byte post declaring {HUGE}"
    );
    let _ = ex.finish();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The other half, and the one a wrong fix breaks silently: a
/// legitimate inner file BIGGER than any single volume must still be
/// preallocated in full as soon as the first volume identifies it -
/// the whole point of preallocation is that the extents are reserved
/// before the rest of the download races other files for them.
///
/// (This is also why the ceiling is the NZB total and not the sum of
/// the group's slot sizes: group membership accretes as volumes
/// arrive, so at this point only ONE volume is known.)
#[test]
fn a_legitimate_large_inner_file_still_preallocates_in_full() {
    let dir = tmpdir("prealloc-ok");
    let total = payload(500_000, 2);
    let vols: Vec<Vec<u8>> = vec![
        fixtures::rar5_volume(&[("film.mkv", 500_000, &total[..200_000], false, true)]),
        fixtures::rar5_volume(&[("film.mkv", 500_000, &total[200_000..400_000], true, true)]),
        fixtures::rar5_volume(&[("film.mkv", 500_000, &total[400_000..], true, false)]),
    ];
    let posted: u64 = vols.iter().map(|v| v.len() as u64).sum();
    assert!(posted > 500_000);
    let ex = Extractor::new(&dir, 3, true);
    ex.set_prealloc_ceiling(posted);

    feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 12);
    assert_eq!(
        std::fs::metadata(dir.join("film.mkv")).unwrap().len(),
        500_000,
        "a legitimate 500 KB inner file must be reserved in full from the first volume"
    );

    feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 13);
    feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 11);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.extracted, vec![("film.mkv".to_string(), 500_000)]);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// BUG (MEDIUM): the decompression-bomb guard counted bytes only on
/// the disk and post-pass sinks, so it protected the fallback and not
/// the in-stream path every download actually takes. The budget is
/// shared across the whole job - inner files do not each get a fresh
/// allowance.
#[test]
fn the_in_stream_path_is_bounded_by_the_extract_budget() {
    let dir = tmpdir("bomb-instream");
    let a = payload(200_000, 4);
    let b = payload(200_000, 5);
    let vol = fixtures::rar5_volume(&[
        ("one.bin", 200_000, &a, false, false),
        ("two.bin", 200_000, &b, false, false),
    ]);
    let ex = Extractor::new(&dir, 1, true);
    // Room for the first inner file and not the second: a shared
    // budget must refuse, a per-file one would wave both through.
    ex.set_extract_budget(300_000);

    let art = 8192;
    let mut err = None;
    for s in (0..vol.len()).step_by(art) {
        let e = (s + art).min(vol.len());
        if let Err(x) = ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e]) {
            err = Some(x);
            break;
        }
    }
    let err = err.expect("a 400 KB extract under a 300 KB budget must be refused");
    assert!(err.to_string().contains("decompression bomb"), "{err}");
    assert!(ex.extract_budget_used() > 300_000);
    let _ = ex.finish();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The budget must not fire on a job that merely fits - the guard
/// exists for bombs, not for large legitimate extracts.
#[test]
fn the_extract_budget_never_trips_on_a_job_that_fits() {
    let dir = tmpdir("bomb-fits");
    let data = payload(200_000, 1);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_extract_budget(200_000);
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    assert_eq!(ex.extract_budget_used(), 200_000);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn split_volumes_out_of_order() {
    let dir = tmpdir("split");
    let total = payload(500_000, 2);
    let vols: Vec<Vec<u8>> = vec![
        fixtures::rar5_volume(&[("film.mkv", 500_000, &total[..200_000], false, true)]),
        fixtures::rar5_volume(&[("film.mkv", 500_000, &total[200_000..400_000], true, true)]),
        fixtures::rar5_volume(&[("film.mkv", 500_000, &total[400_000..], true, false)]),
    ];
    // Feed volumes interleaved and shuffled - vol 3 first.
    let ex = Extractor::new(&dir, 3, true);
    feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 11);
    feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 12);
    feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 13);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    assert!(!dir.join("x.part1.rar").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A store entry that DECLARES far more data than the volume holds
/// must never ship as a successful extraction. Before the
/// volume-bounds check the parse cursor jumped past the volume end,
/// the EOF rule marked the volume complete, `mapped_through()` went
/// to u64::MAX (so no tail-hold), the end-of-download settle saw
/// nothing incomplete, and the CRC gate skipped the file because its
/// composed run was shorter than the declared piece - leaving a
/// preallocated, mostly-zero file reported as output with exit 0.
#[test]
fn oversized_data_area_never_ships_a_sparse_file() {
    let dir = tmpdir("oversize-a");
    let data = payload(4_000, 5);
    // 4 KB really posted; the header claims 8 MB of data area.
    let vol = fixtures::rar5_volume_oversized("movie.mkv", 8 << 20, &data, 8 << 20);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 700, 3);
    let rep = ex.finish().unwrap();
    assert!(
        !rep.fallbacks.is_empty(),
        "a volume that overruns itself must demote, got {:?}",
        rep.fallbacks
    );
    assert!(
        !dir.join("movie.mkv").exists(),
        "no sparse output may survive the demote"
    );
    assert!(
        rep.extracted.iter().all(|(n, _)| n != "movie.mkv"),
        "{:?}",
        rep.extracted
    );
    // The volume itself materialized for the disk path, byte-exact,
    // so unrar gets to fail the job honestly.
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 118 item 2, reproduced at the layer the field report came from:
/// a set that is not damaged in any way demotes on EVERY volume because
/// the length the POST declared is short.
///
/// The reason `advance_to` refuses on is `volume_size`, and the
/// extractor's `volume_size` is the `size` argument to `write*` - which
/// in `nzbfast`'s download path is `yenc::Decoded::file_size`, i.e.
/// `=ybegin size=`, a poster-written field `check_part_geometry`
/// explicitly declines to verify. Feed the identical bytes twice, once
/// at the length they really are and once 64 bytes short, and the
/// second run demotes all three volumes with "data area exceeds
/// volume". That is the shape of the 60-of-60 report: not one odd
/// volume, but the whole set at once, because one poster's field is
/// wrong the same way on every article of every volume.
///
/// It stays SAFE, which is the other half of the report: the volumes
/// materialize byte-exact for the disk path and no sparse member ships.
/// The cost is the one-pass property, and it is real.
#[test]
fn an_understated_posted_size_demotes_a_healthy_set_on_every_volume() {
    let total = payload(250_000, 11);
    let vols = [
        fixtures::rar5_volume_n(&[("film.mkv", 250_000, &total[..100_000], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("film.mkv", 250_000, &total[100_000..200_000], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("film.mkv", 250_000, &total[200_000..], true, false)], 2),
    ];
    let names = ["v.part1.rar", "v.part2.rar", "v.part3.rar"];

    // Control: the same bytes at their true declared length extract
    // one-pass, so anything the short run does is the declaration's
    // doing and not the fixture's.
    let dir = tmpdir("declared-true");
    let ex = Extractor::new(&dir, 3, true);
    for (i, v) in vols.iter().enumerate() {
        feed(&ex, i, names[i], v, 700, 7);
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.is_empty(),
        "the set is healthy: {:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    std::fs::remove_dir_all(&dir).unwrap();

    // The same feed with a declaration 64 bytes short on every volume.
    let dir = tmpdir("declared-short");
    let ex = Extractor::new(&dir, 3, true);
    for (i, v) in vols.iter().enumerate() {
        let short = v.len() as u64 - 64;
        for s in (0..v.len()).step_by(700) {
            let e = (s + 700).min(v.len());
            ex.write(i, names[i], short, s as u64, &v[s..e]).unwrap();
        }
    }
    let rep = ex.finish().unwrap();
    assert!(
        !rep.fallbacks.is_empty()
            && rep
                .fallbacks
                .iter()
                .all(|(_, why)| why.contains("data area exceeds volume")),
        "every volume must demote on the bound, got {:?}",
        rep.fallbacks
    );
    // Safe, just slower: the volumes are on disk byte-exact and no
    // half-mapped member was written.
    for (i, v) in vols.iter().enumerate() {
        assert_eq!(&std::fs::read(dir.join(names[i])).unwrap(), v);
    }
    assert!(!dir.join("film.mkv").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Variant B: every per-volume invariant holds (the data area ends
/// exactly at the volume end, the end-of-archive block is there, the
/// bytes all arrive) but `split_after` is set on the only piece and
/// `unpacked_size` is 8 MB against 4 KB of real data. The parser
/// cannot object - the continuation volume it promises simply never
/// exists - so the CRC gate has to notice that the header set does
/// not tile the file it declares. It used to skip: `split_after`
/// nulled the header CRC, and every demote below was gated on
/// `tiled`.
#[test]
fn split_after_with_oversized_unpacked_size_demotes() {
    let dir = tmpdir("oversize-b");
    let data = payload(4_000, 6);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 8 << 20, &data, false, true)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 700, 4);
    let rep = ex.finish().unwrap();
    assert!(
        !rep.fallbacks.is_empty(),
        "headers that do not cover the file must demote, got {:?}",
        rep.fallbacks
    );
    assert!(
        !dir.join("movie.mkv").exists(),
        "no sparse output may survive the demote"
    );
    assert!(
        rep.extracted.iter().all(|(n, _)| n != "movie.mkv"),
        "{:?}",
        rep.extracted
    );
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Variant C: the same truncated header set with the output-CRC
/// gate OFF (NZBFAST_NO_OUTPUT_CRC). The knob buys back the CRC
/// composition cost, not the structural check - tiling is a pure
/// header property, and with it skipped a par-less truncated store
/// set shipped its preallocated size as a silent success.
#[test]
fn oversized_unpacked_size_demotes_even_with_output_crc_off() {
    let dir = tmpdir("oversize-nocrc");
    let data = payload(4_000, 6);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 8 << 20, &data, false, true)]);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_verify_output_crc(false);
    feed(&ex, 0, "v.rar", &vol, 700, 4);
    let rep = ex.finish().unwrap();
    assert!(
        !rep.fallbacks.is_empty(),
        "the tiling check must run with the CRC gate off, got {:?}",
        rep.fallbacks
    );
    assert!(
        !dir.join("movie.mkv").exists(),
        "no sparse output may survive the demote"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The regression that matters most: a REAL multi-volume split set
/// (per-volume `data_len` well under the declared whole-file
/// `unpacked_size`, stored CRCs, out-of-order arrival) must still go
/// through the one-pass path untouched - no demote, byte-exact
/// output, no volume files left behind.
#[test]
fn legitimate_split_set_still_extracts_one_pass() {
    let dir = tmpdir("split-legit");
    let total = payload(500_000, 8);
    let cut = |r: std::ops::Range<usize>| crc32fast::hash(&total[r]);
    let vols = [
        fixtures::rar5_volume_n_crc(
            &[(
                "film.mkv",
                500_000,
                &total[..200_000],
                false,
                true,
                Some(cut(0..200_000)),
            )],
            0,
        ),
        fixtures::rar5_volume_n_crc(
            &[(
                "film.mkv",
                500_000,
                &total[200_000..400_000],
                true,
                true,
                Some(cut(200_000..400_000)),
            )],
            1,
        ),
        // Last piece carries the WHOLE-file CRC, the way real
        // archivers write it - so the composed gate actually runs.
        fixtures::rar5_volume_n_crc(
            &[(
                "film.mkv",
                500_000,
                &total[400_000..],
                true,
                false,
                Some(cut(0..500_000)),
            )],
            2,
        ),
    ];
    let ex = Extractor::new(&dir, 3, true);
    feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 31);
    feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 32);
    feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 33);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    assert!(!dir.join("x.part1.rar").exists());
    assert!(!dir.join("x.part3.rar").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn obfuscated_names_group_by_inner_file() {
    let dir = tmpdir("obf");
    let total = payload(300_000, 5);
    let v1 = fixtures::rar5_volume_n(&[("real.mkv", 300_000, &total[..150_000], false, true)], 0);
    let v2 = fixtures::rar5_volume_n(&[("real.mkv", 300_000, &total[150_000..], true, false)], 1);
    let ex = Extractor::new(&dir, 2, true);
    // Hash-garbage yEnc names; sorted order of names is WRONG (b < a).
    feed(&ex, 0, "bbbb1234.bin", &v1, 8000, 7);
    feed(&ex, 1, "aaaa9999.bin", &v2, 8000, 8);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("real.mkv")).unwrap(), total);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO §7 #1 regression: a store set carrying MORE THAN ONE inner
/// file, with a file boundary inside a middle volume. Volumes group
/// by their first inner name, so the E02-only continuation volumes
/// formed a separate group that could never base-resolve; at finish()
/// that group fell back and deleted E02.mkv - including the head
/// bytes the healthy group had extracted (its volumes were never
/// materialized), i.e. deterministic whole-file loss at exit 0.
#[test]
fn multi_file_store_set_extracts_across_file_boundary() {
    let dir = tmpdir("multifile");
    let e01 = payload(350_000, 21);
    let e02 = payload(250_000, 22);
    let vols = [
        fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[..200_000], false, true)], 0),
        fixtures::rar5_volume_n(
            &[
                ("E01.mkv", 350_000, &e01[200_000..], true, false),
                ("E02.mkv", 250_000, &e02[..50_000], false, true),
            ],
            1,
        ),
        fixtures::rar5_volume_n(&[("E02.mkv", 250_000, &e02[50_000..], true, false)], 2),
    ];
    // Obfuscated volume names; feed the continuation-only volume FIRST
    // so its group forms before the boundary volume can link it.
    let ex = Extractor::new(&dir, 3, true);
    feed(&ex, 2, "ccc.bin", &vols[2], 9000, 51);
    feed(&ex, 0, "bbb.bin", &vols[0], 9000, 52);
    feed(&ex, 1, "aaa.bin", &vols[1], 9000, 53);
    let rep = ex.finish().unwrap();
    // Multi-file sets live and die on the CHAIN path: the arithmetic
    // gate must never have placed beyond it here.
    assert!(
        ex.arith_engaged_groups().is_empty(),
        "{:?}",
        ex.arith_engaged_groups()
    );
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        rep.extracted,
        vec![
            ("E01.mkv".to_string(), 350_000),
            ("E02.mkv".to_string(), 250_000)
        ]
    );
    assert_eq!(std::fs::read(dir.join("E01.mkv")).unwrap(), e01);
    assert_eq!(std::fs::read(dir.join("E02.mkv")).unwrap(), e02);
    for n in ["bbb.bin", "aaa.bin", "ccc.bin"] {
        assert!(!dir.join(n).exists(), "volume {n} materialized");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Finding 14: two DISTINCT inner entries whose names sanitize to the
/// same on-disk name must each get their own output. Keyed on the
/// sanitized name they shared one writer and the second silently
/// overwrote the first; keyed on the raw name they land as two
/// disambiguated files. (The original pair was "a/b.txt" vs "a_b.txt";
/// a provably safe path now keeps its tree, so the colliding pair here
/// is one the flatten fallback still owns: "a//b.txt" has an empty
/// component and flattens to "a__b.txt".)
#[test]
fn distinct_names_that_sanitize_alike_dont_share_output() {
    let dir = tmpdir("sanitize-collide");
    let a = payload(120_000, 61);
    let b = payload(90_000, 62);
    let vol = fixtures::rar5_volume(&[
        ("a//b.txt", 120_000, &a, false, false),
        ("a__b.txt", 90_000, &b, false, false),
    ]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 63);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    // Both payloads must survive intact on disk under two distinct names,
    // never one truncated/interleaved file.
    let landed: Vec<Vec<u8>> = dir_files(&dir)
        .into_iter()
        .map(|n| std::fs::read(dir.join(n)).unwrap())
        .collect();
    assert!(landed.iter().any(|f| f == &a), "first entry's bytes lost");
    assert!(landed.iter().any(|f| f == &b), "second entry's bytes lost");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Tree preservation (the relpath-preserve ruling, 29 Aug 2026): an
/// archive member whose
/// path is provably safe keeps its directory structure - a VIDEO_TS
/// tree has to stay a tree to play. Unsafe shapes keep flattening.
#[test]
fn safe_member_paths_land_as_a_tree() {
    let dir = tmpdir("member-tree");
    let a = payload(120_000, 64);
    let b = payload(90_000, 65);
    let vol = fixtures::rar5_volume(&[
        ("VIDEO_TS/VTS_01_1.VOB", 120_000, &a, false, false),
        ("../evil.bin", 90_000, &b, false, false),
    ]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 66);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        std::fs::read(dir.join("VIDEO_TS").join("VTS_01_1.VOB")).unwrap(),
        a,
        "safe member path must keep its tree"
    );
    // The traversal member still flattens and still cannot escape. The
    // SPELLING moved on 30 Aug 2026 (M4-66): leading dots are mapped to
    // `_` rather than deleted, so `../evil.bin` is `.._evil.bin` after
    // the separator map and `___evil.bin` after it - where it used to be
    // `_evil.bin`. That is not incidental. `../evil.bin`, `./evil.bin`
    // and a poster's literal `_evil.bin` ALL flattened onto `_evil.bin`
    // before, so a hostile member and an honest one claimed one name;
    // the three are distinct now, which is the same collision the row
    // was filed about. Contained either way - what this test is for.
    assert_eq!(
        std::fs::read(dir.join("___evil.bin")).unwrap(),
        b,
        "a traversal name must still flatten, contained, under the job dir"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Finding 15: on a case-insensitive default volume (macOS/Windows)
/// "README" and "readme" name one filesystem object, so the second
/// output would truncate the first. The claim key folds case there, so
/// the second disambiguates and both payloads survive. (On case-
/// sensitive Linux they are distinct files already; either way both
/// payloads land intact.)
#[test]
fn case_only_name_collision_keeps_both_outputs() {
    let dir = tmpdir("case-collide");
    let a = payload(120_000, 71);
    let b = payload(90_000, 72);
    let vol = fixtures::rar5_volume(&[
        ("README", 120_000, &a, false, false),
        ("readme", 90_000, &b, false, false),
    ]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 73);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    let landed: Vec<Vec<u8>> = dir_files(&dir)
        .into_iter()
        .map(|n| std::fs::read(dir.join(n)).unwrap())
        .collect();
    assert!(landed.iter().any(|f| f == &a), "README bytes lost");
    assert!(landed.iter().any(|f| f == &b), "readme bytes lost");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Same layout at season-pack scale - six volumes, boundary inside
/// v3 - driven through every linking path: sequential (the
/// deterministic-loss order), continuations first (the group forms
/// before its head volume exists), and boundary volume first (the
/// alias exists before either neighbor group).
#[test]
fn multi_file_store_set_survives_all_feed_orders() {
    let e01 = payload(350_000, 21);
    let e02 = payload(250_000, 22);
    let vols: Vec<Vec<u8>> = vec![
        fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[..100_000], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("E01.mkv", 350_000, &e01[100_000..200_000], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("E01.mkv", 350_000, &e01[200_000..300_000], true, true)],
            2,
        ),
        fixtures::rar5_volume_n(
            &[
                ("E01.mkv", 350_000, &e01[300_000..], true, false),
                ("E02.mkv", 250_000, &e02[..50_000], false, true),
            ],
            3,
        ),
        fixtures::rar5_volume_n(
            &[("E02.mkv", 250_000, &e02[50_000..150_000], true, true)],
            4,
        ),
        fixtures::rar5_volume_n(&[("E02.mkv", 250_000, &e02[150_000..], true, false)], 5),
    ];
    for (t, order) in [
        [0usize, 1, 2, 3, 4, 5],
        [4, 5, 0, 1, 2, 3],
        [3, 4, 5, 2, 1, 0],
    ]
    .iter()
    .enumerate()
    {
        let dir = tmpdir(&format!("multifile{t}"));
        let ex = Extractor::new(&dir, 6, true);
        for &vi in order {
            let name = format!("obf{:02x}.bin", (vi as u8) ^ 0x5a);
            feed(&ex, vi, &name, &vols[vi], 7000, 40 + vi as u64);
        }
        let rep = ex.finish().unwrap();
        // No engagement assert here (unlike the §7 test above): when
        // the boundary volume's E01-tail parses alone, it is a lone
        // FINAL piece and the gate may transiently place it at
        // `total - data_len` - which is the true base of any split
        // file's final piece, so the chain confirms it and the
        // one-pass outcome below is what actually matters.
        assert!(
            rep.fallbacks.is_empty(),
            "order {order:?}: {:?}",
            rep.fallbacks
        );
        assert_eq!(
            rep.extracted,
            vec![
                ("E01.mkv".to_string(), 350_000),
                ("E02.mkv".to_string(), 250_000)
            ],
            "order {order:?}"
        );
        assert_eq!(
            std::fs::read(dir.join("E01.mkv")).unwrap(),
            e01,
            "order {order:?}"
        );
        assert_eq!(
            std::fs::read(dir.join("E02.mkv")).unwrap(),
            e02,
            "order {order:?}"
        );
        // One-pass: no volume file may exist.
        let files: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(files.len(), 2, "order {order:?}: {files:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// SPEC Part A acceptance 1 + 7: a 45-volume uniform single-file
/// store set with dotless obfuscated names, fed in a shuffled order
/// that keeps the chain short for the whole download, extracts
/// one-pass under a tight holds budget - the arithmetic gate places
/// every volume the moment its own headers parse. This exact fixture
/// demotes with "held-bytes cap" without the gate (the ~13 MB of
/// unplaceable spans overrun the 8 MB floor).
#[test]
fn obfuscated_uniform_store_set_streams_one_pass_any_order() {
    let dir = tmpdir("arith-onepass");
    let inner = "qCNsampBzXuv9m9z.mkv";
    let (data, vols, names) = uniform_store_set(inner, 300_000, 44, 200_000, 31);
    let ex = Extractor::new(&dir, vols.len(), true);
    ex.set_holds_cap(8 << 20);
    // Volume 0 arrives LAST, and the set's final volume early. Either
    // one is enough: volume 0 proves the file starts where the
    // arithmetic assumes, and the final piece proves the same thing
    // through the closure identity (and separately seeds the chain's
    // backward walk). One of the two is all a set needs to place
    // every other volume off its own headers.
    let mut order = shuffled_zero_last(vols.len(), 0xC0FFEE);
    let tail = vols.len() - 1;
    let at = order.iter().position(|&v| v == tail).unwrap();
    order.remove(at);
    order.insert(0, tail);
    for vi in order {
        feed(&ex, vi, &names[vi], &vols[vi], 9000, 60 + vi as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.extracted, vec![(inner.to_string(), data.len() as u64)]);
    assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
    assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
    assert!(
        !ex.arith_engaged_groups().is_empty(),
        "the gate never engaged"
    );
    // Memory acceptance: holds never accumulated the set - only the
    // in-flight volume's pre-parse spans.
    assert!(
        ex.holds_peak() < data.len() / 2,
        "holds peak {}",
        ex.holds_peak()
    );
    for n in &names {
        assert!(!dir.join(n).exists(), "volume {n} materialized");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The honest limit of the same shape: when NEITHER the file's first
/// nor its last volume has parsed, no offset is derivable from any
/// header, so the bytes must be held. (The offsets are only knowable
/// relative to one of those two ends - anything else would be placing
/// on an unproven premise, which is exactly what mis-placed a season
/// pack's continuation volumes.) A production-sized holds budget
/// absorbs that window and the set still one-passes; a budget smaller
/// than the window demotes, correctly.
#[test]
fn a_set_with_neither_end_parsed_holds_then_places() {
    let inner = "late.mkv";
    let (data, vols, names) = uniform_store_set(inner, 300_000, 44, 200_000, 31);
    // Feed order that keeps both ends late: this is the case the
    // arithmetic gate used to guess its way through.
    let mut order = shuffled_zero_last(vols.len(), 0xC0FFEE);
    let tail = vols.len() - 1;
    let at = order.iter().position(|&v| v == tail).unwrap();
    order.remove(at);
    order.insert(order.len() - 1, tail);

    // Budget above the window: one-pass, byte-exact.
    let dir = tmpdir("arith-lateends-ok");
    let ex = Extractor::new(&dir, vols.len(), true);
    ex.set_holds_cap(64 << 20);
    for &vi in &order {
        feed(&ex, vi, &names[vi], &vols[vi], 9000, 70 + vi as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
    std::fs::remove_dir_all(&dir).unwrap();

    // Budget below it: demotes on the holds cap, and every volume
    // still reconstructs byte-exact for the disk path. Paging OFF -
    // with it on (the default) this window pages to scratch and the
    // set one-passes instead (pinned separately below); this leg
    // keeps the demote plumbing itself honest.
    let dir = tmpdir("arith-lateends-tight");
    let ex = Extractor::new(&dir, vols.len(), true);
    ex.set_holds_cap(8 << 20);
    ex.set_holds_paging(false);
    for &vi in &order {
        feed(&ex, vi, &names[vi], &vols[vi], 9000, 70 + vi as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("held-bytes cap")),
        "{:?}",
        rep.fallbacks
    );
    for (vi, vol) in vols.iter().enumerate() {
        assert_eq!(
            &std::fs::read(dir.join(&names[vi])).unwrap(),
            vol,
            "volume {vi}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SPEC Part A acceptance 2: the same shape with ONE mid-set volume
/// declaring a different `data_len`. The gate engages on the uniform
/// majority; the odd volume's parse contradicts the premise while
/// unconfirmed placements exist, so the WHOLE group demotes with the
/// distinct reason - and every volume reconstructs byte-exact (the
/// unrar path's input), with no half-extracted inner file left.
#[test]
fn uniform_store_set_with_odd_mid_volume_demotes_whole() {
    let dir = tmpdir("arith-nonuniform");
    let inner = "inner.bin";
    let dl = 60_000usize;
    let n_full = 44usize;
    let tail = 40_000usize;
    let total = ((dl + 1) + (n_full - 1) * dl + tail) as u64; // as declared; vol 20 lies
    let data = payload((dl + 1) + (n_full - 1) * dl + tail, 33);
    let mut vols: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0usize;
    for k in 0..n_full {
        let len = if k == 0 {
            dl + 1
        } else if k == 20 {
            30_000 // the odd one out
        } else {
            dl
        };
        let piece = &data[pos..pos + len];
        pos += len;
        vols.push(fixtures::rar5_volume_n_crc(
            &[(
                inner,
                total,
                piece,
                k > 0,
                true,
                Some(crc32fast::hash(piece)),
            )],
            k as u64,
        ));
    }
    vols.push(fixtures::rar5_volume_n_crc(
        &[(
            inner,
            total,
            &data[pos..pos + tail],
            true,
            false,
            Some(crc32fast::hash(&data)),
        )],
        n_full as u64,
    ));
    let ex = Extractor::new(&dir, vols.len(), true);
    // Everything but the odd volume first (volume 0 late, so the
    // gate engages with provisional placements), the odd one last.
    let mut order: Vec<usize> = (1..=19).chain(21..=44).chain([0, 20]).collect();
    assert_eq!(order.len(), vols.len());
    for vi in order.drain(..) {
        feed(
            &ex,
            vi,
            &format!("g{vi:02}NoDot"),
            &vols[vi],
            9000,
            80 + vi as u64,
        );
    }
    let rep = ex.finish().unwrap();
    assert_eq!(
        rep.fallbacks,
        vec![(inner.to_string(), "non-uniform store set".to_string())]
    );
    for (vi, vol) in vols.iter().enumerate() {
        assert_eq!(
            &std::fs::read(dir.join(format!("g{vi:02}NoDot"))).unwrap(),
            vol,
            "volume {vi} must reconstruct byte-exact"
        );
    }
    assert!(
        !dir.join(inner).exists(),
        "no partial inner file may survive"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SPEC Part A acceptance 4: an encrypted uniform single-file set
/// must never engage the arithmetic gate - in-stream decryption was
/// built and verified against chained placement, and behavior stays
/// exactly as before (this set still one-passes: it completes, so
/// the chain closes at the end).
#[test]
fn encrypted_uniform_store_set_stays_on_chain_path() {
    let dir = tmpdir("arith-enc");
    let plain = payload(900_000, 35);
    let f = fixtures::encrypt_file("hunter2", &plain, 5);
    let n = f.cipher.len();
    let (a, b) = (300_000, 600_000);
    // Uniform piece sizes on purpose: were encryption not excluded,
    // this shape would qualify.
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let ex = Extractor::new(&dir, 3, true);
    ex.set_password("hunter2");
    feed(&ex, 2, "zzNoDot", &vols[2], 8000, 91);
    feed(&ex, 0, "aaNoDot", &vols[0], 8000, 92);
    feed(&ex, 1, "mmNoDot", &vols[1], 8000, 93);
    let rep = ex.finish().unwrap();
    assert!(
        ex.arith_engaged_groups().is_empty(),
        "arithmetic gate engaged on an encrypted set"
    );
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The gate's bet is right for a multi-file set's FIRST file (it
/// really does start at volume 0, offset 0): continuation volumes
/// arriving early engage provisionally, the chain confirms each
/// placement as the head volumes fill in, and the boundary volume
/// then reveals the multi-file truth WITHOUT a demote - both files
/// extract one-pass.
#[test]
fn provisional_placements_confirmed_by_chain_survive_multifile_reveal() {
    let dir = tmpdir("arith-confirm");
    // WinRAR-true: volume 0 carries one byte more (see uniform_store_set).
    let a = payload(450_001, 41); // spans vols 0..=4, boundary in vol 4
    let b = payload(120_000, 42); // head 50k in vol 4, final 70k in vol 5
    let vols = [
        fixtures::rar5_volume_n(&[("A.mkv", 450_001, &a[..100_001], false, true)], 0),
        fixtures::rar5_volume_n(&[("A.mkv", 450_001, &a[100_001..200_001], true, true)], 1),
        fixtures::rar5_volume_n(&[("A.mkv", 450_001, &a[200_001..300_001], true, true)], 2),
        fixtures::rar5_volume_n(&[("A.mkv", 450_001, &a[300_001..400_001], true, true)], 3),
        fixtures::rar5_volume_n(
            &[
                ("A.mkv", 450_001, &a[400_001..], true, false),
                ("B.mkv", 120_000, &b[..50_000], false, true),
            ],
            4,
        ),
        fixtures::rar5_volume_n(&[("B.mkv", 120_000, &b[50_000..], true, false)], 5),
    ];
    let ex = Extractor::new(&dir, 6, true);
    for vi in [2usize, 3, 5, 0, 1, 4] {
        feed(
            &ex,
            vi,
            &format!("c{vi}NoDot"),
            &vols[vi],
            9000,
            70 + vi as u64,
        );
    }
    let rep = ex.finish().unwrap();
    assert!(
        !ex.arith_engaged_groups().is_empty(),
        "vols 2+3 arriving first must have engaged the gate"
    );
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("A.mkv")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("B.mkv")).unwrap(), b);
    for vi in 0..6 {
        assert!(
            !dir.join(format!("c{vi}NoDot")).exists(),
            "volume {vi} materialized"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The shape that USED to expose a wrong bet: a big second file
/// behind a small first one. Its continuation volumes look
/// arithmetically plausible (the file is large, so `volnum * data_len`
/// fits inside it) but the true bases are shifted by the first file's
/// share of volume 0.
///
/// The gate no longer bets on it at all: with neither a volume 0 that
/// starts this file nor a closure identity that holds, the premise is
/// unproven and the group goes to chain resolution - which places it
/// correctly. So the set now extracts ONE-PASS where it previously
/// wrote bytes at wrong offsets and demoted to recover. The old
/// demote-and-reconstruct path is still exercised by
/// `uniform_store_set_with_odd_mid_volume_demotes_whole`.
#[test]
fn a_big_second_file_now_places_instead_of_mis_betting() {
    let dir = tmpdir("arith-contradict");
    let f1 = payload(30_000, 43); // wholly inside vol 0
    let f2 = payload(520_000, 44); // 50k in vol 0, then 4 x 100k, tail 70k
    let vols = [
        fixtures::rar5_volume_n(
            &[
                ("f1.bin", 30_000, &f1, false, false),
                ("f2.bin", 520_000, &f2[..50_000], false, true),
            ],
            0,
        ),
        fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[50_000..150_000], true, true)], 1),
        fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[150_000..250_000], true, true)], 2),
        fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[250_000..350_000], true, true)], 3),
        fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[350_000..450_000], true, true)], 4),
        fixtures::rar5_volume_n(&[("f2.bin", 520_000, &f2[450_000..], true, false)], 5),
    ];
    let ex = Extractor::new(&dir, 6, true);
    // Vols 3+4 first: the gate engages and places them at 300k/400k
    // (true bases 250k/350k). Vol 0 reveals the second entry; the
    // chain then reaches vol 3 when vols 1+2 parse and contradicts.
    for vi in [3usize, 4, 0, 1, 2, 5] {
        feed(
            &ex,
            vi,
            &format!("x{vi}NoDot"),
            &vols[vi],
            9000,
            50 + vi as u64,
        );
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), f1);
    assert_eq!(std::fs::read(dir.join("f2.bin")).unwrap(), f2);
    for vi in 0..vols.len() {
        assert!(
            !dir.join(format!("x{vi}NoDot")).exists(),
            "volume {vi} materialized"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A volume missing from the NZB entirely: the gate placed the rest
/// arithmetically (no holds, mappers complete), so only the closure
/// ruling at settle can notice the set never proved itself - it must
/// demote rather than ship a file with a silent hole.
#[test]
fn unclosed_arithmetic_set_demotes_at_finish() {
    let dir = tmpdir("arith-unclosed");
    let inner = "gap.bin";
    let (_data, vols, names) = uniform_store_set(inner, 60_000, 9, 40_000, 37);
    let ex = Extractor::new(&dir, vols.len(), true);
    // Volume 4 never arrives; 0 arrives last among those that do.
    for vi in [7usize, 2, 9, 5, 1, 8, 3, 6, 0] {
        feed(&ex, vi, &names[vi], &vols[vi], 9000, 40 + vi as u64);
    }
    let rep = ex.finish().unwrap();
    assert_eq!(
        rep.fallbacks,
        vec![(inner.to_string(), "non-uniform store set".to_string())]
    );
    assert!(!dir.join(inner).exists(), "no holed inner file may survive");
    for vi in [7usize, 2, 9, 5, 1, 8, 3, 6, 0] {
        assert_eq!(
            &std::fs::read(dir.join(&names[vi])).unwrap(),
            &vols[vi],
            "volume {vi} must reconstruct byte-exact"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The failure the first LIVE run of the gate exposed (Ant-Man, 134
/// volumes): the volume-number vint in the main header grows a byte
/// at volume 128, and real archivers keep the VOLUME size constant,
/// so the data area shrinks by that byte - `data_len` is NOT
/// uniform. A >127-volume set must still qualify and place every
/// band correctly (vol 0: D bytes; 1..127: D-1; 128+: D-2).
#[test]
fn store_set_crossing_the_volnum_vint_band_still_one_passes() {
    let dir = tmpdir("arith-band");
    let inner = "band.mkv";
    let d = 5_001usize; // vol 0's data bytes
    let n_full = 131usize; // vols 0..=130 non-final, 131 final
    let tail = 3_000usize;
    let total = d + 127 * (d - 1) + 3 * (d - 2) + tail;
    let data = payload(total, 39);
    let mut vols: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0usize;
    for k in 0..n_full {
        let len = if k == 0 {
            d
        } else if k < 128 {
            d - 1
        } else {
            d - 2
        };
        let piece = &data[pos..pos + len];
        pos += len;
        vols.push(fixtures::rar5_volume_n_crc(
            &[(
                inner,
                total as u64,
                piece,
                k > 0,
                true,
                Some(crc32fast::hash(piece)),
            )],
            k as u64,
        ));
    }
    vols.push(fixtures::rar5_volume_n_crc(
        &[(
            inner,
            total as u64,
            &data[pos..],
            true,
            false,
            Some(crc32fast::hash(&data)),
        )],
        n_full as u64,
    ));
    let names: Vec<String> = (0..vols.len()).map(|k| format!("bx{k:03}NoDot")).collect();
    let ex = Extractor::new(&dir, vols.len(), true);
    for vi in shuffled_zero_last(vols.len(), 0xBAD5EED) {
        feed(&ex, vi, &names[vi], &vols[vi], 1_500, 30 + vi as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert!(
        !ex.arith_engaged_groups().is_empty(),
        "the gate never engaged"
    );
    assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
    for n in &names {
        assert!(!dir.join(n).exists(), "volume {n} materialized");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// PLAN-multifile acceptance 1: a season-pack-shaped store set - six
/// inner files across 60 volumes, boundaries mid-volume, dotless
/// obfuscated names - fed in a shuffled order with volume 0 arriving
/// LAST, extracts one-pass under a tight holds budget.
///
/// This is the 25%-of-multivol-bytes shape the census found (92% of
/// bytes above 60 GB). Before tail anchoring it demoted: forward-only
/// resolution could place nothing until volume 0 parsed, so the
/// unplaceable spans overran the cap.
#[test]
fn obfuscated_season_pack_streams_one_pass_with_volume_zero_last() {
    let dir = tmpdir("multifile-pack");
    // Six episodes, each spanning several volumes, boundaries landing
    // mid-volume so volumes carry two entries.
    let eps: Vec<Vec<u8>> = (0..6)
        .map(|k| payload(1_400_000 + k * 9_000, 40 + k as u8))
        .collect();
    // Lay the episodes end to end, then cut at a fixed volume size:
    // exactly how a real archiver fills volumes.
    let mut stream: Vec<(usize, usize)> = Vec::new(); // (episode, byte)
    for (i, e) in eps.iter().enumerate() {
        for b in 0..e.len() {
            stream.push((i, b));
        }
    }
    const VOL: usize = 150_000;
    let mut vols: Vec<Vec<u8>> = Vec::new();
    let mut at = 0usize;
    let mut vol_no = 0u64;
    while at < stream.len() {
        let end = (at + VOL).min(stream.len());
        // Which episodes does this volume touch, and how much of each?
        let mut pieces: Vec<(usize, usize, usize)> = Vec::new(); // (ep, from, to)
        let mut i = at;
        while i < end {
            let (ep, off) = stream[i];
            let run_end = (i..end).take_while(|&j| stream[j].0 == ep).count() + i;
            pieces.push((ep, off, off + (run_end - i)));
            i = run_end;
        }
        let specs: Vec<(String, u64, Vec<u8>, bool, bool)> = pieces
            .iter()
            .map(|&(ep, from, to)| {
                (
                    format!("Show.S01E{:02}.mkv", ep + 1),
                    eps[ep].len() as u64,
                    eps[ep][from..to].to_vec(),
                    from > 0,
                    to < eps[ep].len(),
                )
            })
            .collect();
        let refs: Vec<(&str, u64, &[u8], bool, bool)> = specs
            .iter()
            .map(|(n, t, d, b, a)| (n.as_str(), *t, d.as_slice(), *b, *a))
            .collect();
        vols.push(fixtures::rar5_volume_n(&refs, vol_no));
        vol_no += 1;
        at = end;
    }
    assert!(
        vols.len() >= 55,
        "expected a season-pack-scale set, got {}",
        vols.len()
    );
    let names: Vec<String> = (0..vols.len())
        .map(|k| format!("{:06x}SeasonNoDot{k}", (k as u64 * 2654435761) & 0xffffff))
        .collect();

    let ex = Extractor::new(&dir, vols.len(), true);
    ex.set_holds_cap(8 << 20);
    for vi in shuffled_zero_last(vols.len(), 0x5EA5_0DE7) {
        feed(&ex, vi, &names[vi], &vols[vi], 9000, 100 + vi as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    for (i, e) in eps.iter().enumerate() {
        let p = dir.join(format!("Show.S01E{:02}.mkv", i + 1));
        assert_eq!(&std::fs::read(&p).unwrap(), e, "episode {} differs", i + 1);
    }
    for n in &names {
        assert!(!dir.join(n).exists(), "volume {n} materialized");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// PLAN-multifile acceptance 2: an ISLAND of volumes away from volume
/// 0 places its pieces. Each inner file needs a parsed run containing
/// its own head or tail, not one reaching back to the start of the
/// set - that is the whole point of the tail seed.
#[test]
fn a_mid_set_island_resolves_without_volume_zero() {
    let dir = tmpdir("multifile-island");
    let a = payload(400_000, 61);
    let b = payload(300_000, 62);
    // A ends in volume 3; B starts there and ends in volume 5.
    let vols = [
        fixtures::rar5_volume_n(&[("A.mkv", 400_000, &a[..100_000], false, true)], 0),
        fixtures::rar5_volume_n(&[("A.mkv", 400_000, &a[100_000..200_000], true, true)], 1),
        fixtures::rar5_volume_n(&[("A.mkv", 400_000, &a[200_000..300_000], true, true)], 2),
        fixtures::rar5_volume_n(
            &[
                ("A.mkv", 400_000, &a[300_000..], true, false),
                ("B.mkv", 300_000, &b[..50_000], false, true),
            ],
            3,
        ),
        fixtures::rar5_volume_n(&[("B.mkv", 300_000, &b[50_000..150_000], true, true)], 4),
        fixtures::rar5_volume_n(&[("B.mkv", 300_000, &b[150_000..], true, false)], 5),
    ];
    // Feed ONLY volumes 3-5: an island with no path back to volume 0.
    let ex = Extractor::new(&dir, 6, true);
    for vi in [4usize, 5, 3] {
        feed(
            &ex,
            vi,
            &format!("isl{vi}NoDot"),
            &vols[vi],
            9000,
            10 + vi as u64,
        );
    }
    // Before finish, B's pieces are PLACED: volume 3 starts B (base
    // 0) and volume 5 ends it (base = total - data_len), so the whole
    // island resolves with no path back to volume 0. Forward-only
    // resolution placed nothing here.
    assert!(ex.bases_known(&["B.mkv"]), "island pieces must be placed");
    let rep = ex.finish().unwrap();
    // The SET is still incomplete - A's head never arrived - so the
    // group demotes at settle and its partial output is removed. The
    // point of this test is the placement above, not the verdict.
    assert!(!rep.fallbacks.is_empty(), "an incomplete set still demotes");
    assert!(
        !dir.join("B.mkv").exists(),
        "a demote removes partial output"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// PLAN-multifile acceptance 5: headers that disagree with THEMSELVES.
/// The middle volume claims a piece that does not fit the gap its two
/// neighbours leave, so the piece resolves to different offsets from
/// each side. No offset here is trustworthy, so the group demotes
/// with its own reason - and every volume still reconstructs
/// byte-exact for the disk path.
#[test]
fn a_self_contradictory_chain_demotes_with_its_own_reason() {
    let dir = tmpdir("chain-contradict");
    let f = payload(300_000, 71);
    let vols = [
        fixtures::rar5_volume_n(&[("f.bin", 300_000, &f[..100_000], false, true)], 0),
        // Overlaps: claims 150 KB where 100 KB fits.
        fixtures::rar5_volume_n(&[("f.bin", 300_000, &f[..150_000], true, true)], 1),
        fixtures::rar5_volume_n(&[("f.bin", 300_000, &f[200_000..], true, false)], 2),
    ];
    let ex = Extractor::new(&dir, 3, true);
    for vi in [0usize, 1, 2] {
        feed(
            &ex,
            vi,
            &format!("cc{vi}NoDot"),
            &vols[vi],
            9000,
            80 + vi as u64,
        );
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w == "inconsistent volume chain"),
        "{:?}",
        rep.fallbacks
    );
    for (vi, vol) in vols.iter().enumerate() {
        assert_eq!(
            &std::fs::read(dir.join(format!("cc{vi}NoDot"))).unwrap(),
            vol,
            "volume {vi} must reconstruct byte-exact"
        );
    }
    assert!(!dir.join("f.bin").exists(), "no partial output may survive");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SPEC Part A trap: under protect_sources (offline `nzbfast
/// extract`), an arithmetic demote must DISCARD like the chain path
/// does - never materialize a "volume" over the source file it is
/// reading.
#[test]
fn protect_sources_arithmetic_demote_discards() {
    let dir = tmpdir("arith-protect");
    let inner = "film.mkv";
    let dl = 60_000usize;
    let total = ((dl + 1) + 4 * dl + 40_000) as u64; // declared; vol 3 lies
    let data = payload((dl + 1) + 4 * dl + 40_000, 45);
    let mut vols: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0usize;
    for k in 0..5usize {
        let len = if k == 0 {
            dl + 1
        } else if k == 3 {
            30_000
        } else {
            dl
        };
        let piece = &data[pos..pos + len];
        pos += len;
        vols.push(fixtures::rar5_volume_n(
            &[(inner, total, piece, k > 0, true)],
            k as u64,
        ));
    }
    vols.push(fixtures::rar5_volume_n(
        &[(inner, total, &data[pos..pos + 40_000], true, false)],
        5,
    ));
    let names: Vec<String> = (0..6).map(|k| format!("src{k}NoDot")).collect();
    for (n, v) in names.iter().zip(&vols) {
        std::fs::write(dir.join(n), v).unwrap();
    }
    let ex = Extractor::new(&dir, vols.len(), true);
    ex.set_protect_sources();
    // Engage on the uniform majority (vol 0 late), then the odd
    // volume contradicts and the whole group demotes - to Discard.
    for vi in [1usize, 2, 4, 5, 0, 3] {
        feed(&ex, vi, &names[vi], &vols[vi], 9000, 20 + vi as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, why)| why == "non-uniform store set"),
        "{:?}",
        rep.fallbacks
    );
    // Sources byte-identical, and no output was left behind.
    for (n, v) in names.iter().zip(&vols) {
        assert_eq!(
            &std::fs::read(dir.join(n)).unwrap(),
            v,
            "source {n} touched"
        );
    }
    assert!(!dir.join(inner).exists(), "partial output must not survive");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Two archives in one NZB that reuse an inner filename must not
/// share a writer (conflicting-offset interleave, silent since inner
/// files aren't PAR2-covered) - and must NOT be merged into one group
/// (the shared name is wholly contained, not split: no archive-chain
/// evidence).
#[test]
fn same_inner_name_across_archives_gets_own_files() {
    let dir = tmpdir("namecollide");
    let film_a = payload(120_000, 31);
    let film_b = payload(140_000, 32);
    let samp_a = payload(30_000, 33);
    let samp_b = payload(40_000, 34);
    let va = fixtures::rar5_volume(&[
        ("filmA.mkv", 120_000, &film_a, false, false),
        ("sample.mkv", 30_000, &samp_a, false, false),
    ]);
    let vb = fixtures::rar5_volume(&[
        ("filmB.mkv", 140_000, &film_b, false, false),
        ("sample.mkv", 40_000, &samp_b, false, false),
    ]);
    let ex = Extractor::new(&dir, 2, true);
    feed(&ex, 0, "a.rar", &va, 8000, 61);
    feed(&ex, 1, "b.rar", &vb, 8000, 62);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("filmA.mkv")).unwrap(), film_a);
    assert_eq!(std::fs::read(dir.join("filmB.mkv")).unwrap(), film_b);
    // One sample per archive, the second under a disambiguated name.
    let mut samples: Vec<Vec<u8>> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with("sample.mkv"))
        .map(|e| std::fs::read(e.path()).unwrap())
        .collect();
    samples.sort_by_key(|s| s.len());
    assert_eq!(samples.len(), 2, "each archive keeps its own sample");
    assert_eq!(samples[0], samp_a);
    assert_eq!(samples[1], samp_b);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn plain_files_still_work() {
    let dir = tmpdir("plain");
    let data = payload(50_000, 9);
    let ex = Extractor::new(&dir, 1, true);
    // Not a rar - offset-0 article sniffs plain. Feed out of order.
    ex.write(0, "doc.iso", 50_000, 30_000, &data[30_000..])
        .unwrap();
    ex.write(0, "doc.iso", 50_000, 0, &data[..30_000]).unwrap();
    ex.finish().unwrap();
    assert_eq!(std::fs::read(dir.join("doc.iso")).unwrap(), data);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn encrypted_headers_fall_back_to_materialized_volume() {
    let dir = tmpdir("enc");
    // Signature + encryption block type 4 (valid CRC).
    let mut vol = Vec::new();
    vol.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
    let hdr = [0x04u8, 0x00]; // type 4, flags 0
    vol.extend_from_slice(&crc32fast::hash(&hdr).to_le_bytes());
    vol.push(2); // header size vint
    vol.extend_from_slice(&hdr);
    vol.extend_from_slice(&payload(5000, 6)); // opaque encrypted stuff
    let ex = Extractor::new(&dir, 1, true);
    let n = vol.len();
    ex.write(0, "sec.rar", n as u64, 0, &vol[..2000]).unwrap();
    ex.write(0, "sec.rar", n as u64, 2000, &vol[2000..])
        .unwrap();
    let rep = ex.finish().unwrap();
    assert!(rep.extracted.is_empty());
    // Volume materialized byte-exactly for a future unrar-with-password.
    assert_eq!(std::fs::read(dir.join("sec.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn protect_sources_happy_path_extracts_normally() {
    let dir = tmpdir("protect-ok");
    let total = payload(300_000, 12);
    let vols = [
        fixtures::rar5_volume_n(&[("film.mkv", 300_000, &total[..150_000], false, true)], 0),
        fixtures::rar5_volume_n(&[("film.mkv", 300_000, &total[150_000..], true, false)], 1),
    ];
    let ex = Extractor::new(&dir, 2, true);
    ex.set_protect_sources();
    feed(&ex, 0, "x.part1.rar", &vols[0], 8000, 41);
    feed(&ex, 1, "x.part2.rar", &vols[1], 8000, 42);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The 2026-07 damaged-post bench corruption: re-extraction fed
/// volumes off disk, hit the holds cap, and the fallback materialized
/// "volumes" over the very files being read (FileWriter::create
/// truncates). Protect-sources mode must leave the source files
/// byte-identical, never create slot writers, and delete any partial
/// inner file.
#[test]
fn protect_sources_fallback_never_touches_source_files() {
    let dir = tmpdir("protect-fb");
    // THREE volumes, unequal, and the MIDDLE one is fed first. A
    // middle piece is neither its file's head nor its tail, so it
    // has no seed of its own and cannot resolve until a neighbour
    // parses - the only remaining shape that piles up holds now that
    // tail anchoring places final pieces on sight. (The arithmetic
    // gate also stays out: the sizes are not uniform.)
    let total = payload(30_000_000, 13);
    let vols = [
        fixtures::rar5_volume_n(
            &[("film.mkv", 30_000_000, &total[..7_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "film.mkv",
                30_000_000,
                &total[7_000_000..22_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("film.mkv", 30_000_000, &total[22_000_000..], true, false)],
            2,
        ),
    ];
    // The volume files exist on disk, as in reextract_dir.
    std::fs::write(dir.join("x.part1.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("x.part2.rar"), &vols[1]).unwrap();
    std::fs::write(dir.join("x.part3.rar"), &vols[2]).unwrap();

    let ex = Extractor::new(&dir, 3, true);
    ex.set_protect_sources();
    ex.set_holds_cap(1); // floors at 8 MB - part2's data area exceeds it
    // Paging OFF: with it on this window pages and the set
    // re-extracts one-pass; the subject here is the fallback
    // discipline under budget pressure, so force the breach.
    ex.set_holds_paging(false);
    let feed_seq = |slot: usize, name: &str, vol: &[u8]| {
        for (i, chunk) in vol.chunks(65_000).enumerate() {
            ex.write(slot, name, vol.len() as u64, (i * 65_000) as u64, chunk)
                .unwrap();
        }
    };
    feed_seq(1, "x.part2.rar", &vols[1]);
    feed_seq(0, "x.part1.rar", &vols[0]);
    feed_seq(2, "x.part3.rar", &vols[2]);
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "expected a holds-cap fallback");

    // Source volumes byte-identical - NOT truncated/rewritten.
    assert_eq!(std::fs::read(dir.join("x.part1.rar")).unwrap(), vols[0]);
    assert_eq!(std::fs::read(dir.join("x.part2.rar")).unwrap(), vols[1]);
    assert_eq!(std::fs::read(dir.join("x.part3.rar")).unwrap(), vols[2]);
    // No slot writers, no half-written inner file masquerading as output.
    assert!(ex.slot_path(0).is_none());
    assert!(ex.slot_path(1).is_none());
    assert!(ex.slot_path(2).is_none());
    assert!(!dir.join("film.mkv").exists());
    let extra: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n != "x.part1.rar" && n != "x.part2.rar" && n != "x.part3.rar")
        .collect();
    assert!(extra.is_empty(), "unexpected files: {extra:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The same shape with paging ON (the default): the re-extraction
/// that used to DISCARD on the holds cap - a real failure mode, the
/// 2026-07 damaged-post bench ran into exactly this - now pages the
/// middle volume's window to scratch and completes one-pass, sources
/// untouched and no scratch left behind.
#[test]
fn protect_sources_paged_holds_reextract_one_pass() {
    let dir = tmpdir("protect-paged");
    let total = payload(30_000_000, 13);
    let vols = [
        fixtures::rar5_volume_n(
            &[("film.mkv", 30_000_000, &total[..7_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "film.mkv",
                30_000_000,
                &total[7_000_000..22_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("film.mkv", 30_000_000, &total[22_000_000..], true, false)],
            2,
        ),
    ];
    std::fs::write(dir.join("x.part1.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("x.part2.rar"), &vols[1]).unwrap();
    std::fs::write(dir.join("x.part3.rar"), &vols[2]).unwrap();
    let ex = Extractor::new(&dir, 3, true);
    ex.set_protect_sources();
    ex.set_holds_cap(1); // floors at 8 MB - part2's data area exceeds it
    let feed_seq = |slot: usize, name: &str, vol: &[u8]| {
        for (i, chunk) in vol.chunks(65_000).enumerate() {
            ex.write(slot, name, vol.len() as u64, (i * 65_000) as u64, chunk)
                .unwrap();
        }
    };
    feed_seq(1, "x.part2.rar", &vols[1]);
    feed_seq(0, "x.part1.rar", &vols[0]);
    feed_seq(2, "x.part3.rar", &vols[2]);
    let rep = ex.finish().unwrap();
    assert!(ex.holds_paged_total() > 0, "paging never engaged");
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    // Sources byte-identical, and nothing else in the directory -
    // in particular no scratch outliving finish. Handle closed
    // first (delete-pending filesystems keep the unlinked name
    // listed until last close).
    drop(ex);
    assert_eq!(std::fs::read(dir.join("x.part1.rar")).unwrap(), vols[0]);
    assert_eq!(std::fs::read(dir.join("x.part2.rar")).unwrap(), vols[1]);
    assert_eq!(std::fs::read(dir.join("x.part3.rar")).unwrap(), vols[2]);
    assert_eq!(
        dir_files(&dir),
        vec![
            "film.mkv".to_string(),
            "x.part1.rar".to_string(),
            "x.part2.rar".to_string(),
            "x.part3.rar".to_string()
        ]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// GitHub issue #40: a `.cbr` comic is a RAR container whose FILE is the
/// deliverable. The offset-0 sniff must route it Plain - materialize the
/// comic byte-identical - never map it as a volume and explode it into
/// loose pages. The zip twin (`comic.cbz` never attaches) is pinned in
/// `zip.rs`; this is the RAR-family mirror.
#[test]
fn a_named_cbr_is_payload_and_never_extracts() {
    let dir = tmpdir("cbr-payload");
    let page = payload(200_000, 15);
    let vol = fixtures::rar5_volume(&[("page01.jpg", 200_000, &page, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "Event Leviathan 01 (2019).cbr", &vol, 8000, 44);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        std::fs::read(dir.join("Event Leviathan 01 (2019).cbr")).unwrap(),
        vol,
        "the comic must materialize byte-identical"
    );
    assert!(
        !dir.join("page01.jpg").exists(),
        "no page may be extracted from a payload file"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The guard keys on the NAMED extension alone (the zip side's standing
/// trade-off): an obfuscated post keeps the magic sniff.
#[test]
fn payload_names_are_final_and_archive_names_are_not() {
    for n in ["comic.cbr", "COMIC.CBR", "book.cb7", "a b (2019).cbr"] {
        assert!(is_final_name(n), "{n} is payload");
    }
    for n in ["x.rar", "x.r00", "x.7z", "x.cbr.rar", "cbr", "deadbeef"] {
        assert!(!is_final_name(n), "{n} is not payload");
    }
}

/// T6: `Path::extension()` answers `Some("")` on `comic.cbr.` and
/// `Some("cbr ")` on `comic.cbr ` - neither matches the deny list, so
/// both used to read as "not payload" and earned the RAR chase, which
/// is exactly the data loss this guard exists to prevent. The trailing
/// tail is the one Windows folds away, so `comic.CBR` (case only, no
/// stray tail) must keep passing.
#[test]
fn a_trailing_dot_or_space_does_not_defeat_is_final_name() {
    for n in ["comic.cbr.", "comic.cbr..", "comic.cbr ", "comic.cbr . "] {
        assert!(is_final_name(n), "{n} is payload despite its trailing tail");
    }
    assert!(is_final_name("comic.CBR"), "case alone must still pass");
}

#[test]
fn protect_sources_non_rar_sniff_discards() {
    let dir = tmpdir("protect-plain");
    let data = payload(50_000, 14);
    std::fs::write(dir.join("doc.bin"), &data).unwrap();
    let ex = Extractor::new(&dir, 1, true);
    ex.set_protect_sources();
    ex.write(0, "doc.bin", 50_000, 0, &data[..30_000]).unwrap();
    ex.write(0, "doc.bin", 50_000, 30_000, &data[30_000..])
        .unwrap();
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.iter().any(|(_, w)| w.contains("not a RAR")));
    // Source untouched - a plain writer would have truncated it.
    assert_eq!(std::fs::read(dir.join("doc.bin")).unwrap(), data);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Volume bytes that belong to no data area - service blocks (a RAR
/// recovery record) and anything past the end-of-archive marker - go
/// to the header stash, and once the mapper is complete that is EVERY
/// remaining byte of the volume. Uncharged, a crafted volume (a tiny
/// archive plus gigabytes of trailing junk) pinned all of it in RAM
/// with no spill and no demote. The stash charges the holds budget,
/// so the volume materializes instead.
#[test]
fn trailing_bytes_past_archive_end_are_capped() {
    let dir = tmpdir("hdrcap");
    let data = payload(1_000, 12);
    let mut vol = fixtures::rar5_volume(&[("a.bin", 1_000, &data, false, false)]);
    let archive_end = vol.len();
    vol.extend(payload(12 << 20, 3)); // junk past the end block
    let ex = Extractor::new(&dir, 1, true);
    ex.set_holds_cap(1); // floors at 8 MB
    // Paging OFF: with it on the junk pages to scratch and the tiny
    // archive extracts one-pass (bounded by the scratch ceiling,
    // pinned separately) - this test keeps the charge-and-demote
    // plumbing itself honest.
    ex.set_holds_paging(false);
    let art = 64_000;
    let mut s = 0usize;
    while s < vol.len() {
        let e = (s + art).min(vol.len());
        ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
            .unwrap();
        s = e;
    }
    assert!(
        ex.holds_peak() <= (8 << 20) + art + archive_end,
        "stash peaked at {} - the junk was never charged",
        ex.holds_peak()
    );
    let rep = ex.finish().unwrap();
    // The reason must be one the caller ROUTES: a level-0 demote it
    // does not recognize means loose volumes, no payload, exit 0.
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("held-bytes cap") && !w.starts_with("nested fallback:")),
        "{:?}",
        rep.fallbacks
    );
    // Demoting is not losing: the volume is byte-identical on disk.
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

// -- archive shape (the live badge's facts) --

#[test]
fn shape_is_empty_until_something_archive_shaped_parses() {
    let dir = tmpdir("shape-none");
    let ex = Extractor::new(&dir, 1, true);
    assert!(ex.archive_shape().is_none(), "nothing fed yet");
    // A loose file is not an archive and must never grow a badge.
    let data = payload(50_000, 9);
    feed(&ex, 0, "notes.txt", &data, 7000, 3);
    ex.finish().unwrap();
    assert!(ex.archive_shape().is_none(), "{:?}", shape_of(&ex));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shape_reports_rar5_store_one_pass() {
    let dir = tmpdir("shape-store");
    let data = payload(200_000, 1);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    // Known DURING the download, not just at finish - that is the
    // whole point of the live badge.
    assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
    ex.finish().unwrap();
    assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
    assert_eq!(
        ex.archive_shape().unwrap().display(),
        "RAR5 · stored · one-pass"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The badge for a set the mappers never saw: nzbfast's disk SFX arm
/// latches the family it is about to unpack, so a self-extractor whose
/// stub outruns the offset-0 sniff stops finishing with an EMPTY shape
/// while the other two SFX routes fill theirs.
///
/// Only existing tokens, deliberately - the dashboard translates the
/// token list and a new word would need all 27 i18n catalogues.
#[test]
fn a_disk_pass_can_name_the_family_it_unpacked() {
    for (what, tag, english) in [
        (
            DiskArchive::Rar5,
            "rar5 on-disk",
            "RAR5 · unpacked after download",
        ),
        (
            DiskArchive::Rar4,
            "rar4 on-disk",
            "RAR4 · unpacked after download",
        ),
        (
            DiskArchive::SevenZ,
            "7z on-disk",
            "7z · unpacked after download",
        ),
        (
            DiskArchive::Zip,
            "zip on-disk",
            "zip · unpacked after download",
        ),
    ] {
        let dir = tmpdir("shape-disk");
        let ex = Extractor::new(&dir, 1, true);
        // A plain data file is all this route's slot ever was.
        let data = payload(50_000, 9);
        feed(&ex, 0, "release.exe", &data, 7000, 3);
        assert!(ex.archive_shape().is_none(), "the sniff saw a data file");
        ex.note_disk_archive(what);
        assert_eq!(ex.archive_shape().unwrap().tag(), tag);
        assert_eq!(ex.archive_shape().unwrap().display(), english);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Latched, not overwritten - the same rule every other shape bit
/// follows. A set that streamed something out AND had an SFX unpacked
/// off disk beside it reads as "partly on disk", which is what happened.
#[test]
fn a_disk_family_joins_the_latch_rather_than_replacing_it() {
    let dir = tmpdir("shape-disk-latch");
    let data = payload(200_000, 1);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
    ex.note_disk_archive(DiskArchive::SevenZ);
    assert_eq!(shape_of(&ex), ["rar5", "store", "mixed-pass"]);
    ex.finish().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The naming oracle's key (Tier C item 4): the inner file's stated
/// CRC32, latched off the same header parse the shape badge uses.
/// Available DURING the download for the same reason the badge is.
#[test]
fn the_inner_file_crc_is_latched_for_the_naming_oracle() {
    let dir = tmpdir("crc-latch");
    let data = payload(200_000, 1);
    let want = crc32fast::hash(&data);
    // With the data CRC the way a real archiver always writes it.
    let vol = fixtures::rar5_volume_n_crc(
        &[("movie.mkv", 200_000, &data, false, false, Some(want))],
        0,
    );
    let ex = Extractor::new(&dir, 1, true);
    assert_eq!(ex.inner_crc(), None, "nothing fed yet");
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    assert_eq!(ex.inner_crc(), Some(("movie.mkv".to_string(), want)));
    ex.finish().unwrap();
    assert_eq!(ex.inner_crc(), Some(("movie.mkv".to_string(), want)));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A header-encrypted set is the case the oracle cannot serve, and
/// it must say so rather than offering a CRC of something else: the
/// headers never parse, so there is no entry and no key. This is the
/// `-hp` floor, pinned.
#[test]
fn a_header_encrypted_set_yields_no_crc_key() {
    let dir = tmpdir("crc-hdr");
    // Encrypted headers and no password: nothing parses, exactly as
    // for an obfuscated `-hp` post nobody has the key to.
    let vol = fixtures::rar4_encrypted_headers(200_000);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    ex.finish().unwrap();
    assert!(shape_of(&ex).contains(&"encrypted"), "{:?}", shape_of(&ex));
    assert_eq!(ex.inner_crc(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shape_reports_rar4() {
    let dir = tmpdir("shape-rar4");
    let data = payload(120_000, 4);
    let vol = fixtures::rar4_volume(&[("movie.mkv", 120_000, &data, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    ex.finish().unwrap();
    assert_eq!(shape_of(&ex)[0], "rar4", "{:?}", shape_of(&ex));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shape_reports_compressed_set_as_unpacked_on_disk() {
    let dir = tmpdir("shape-comp");
    let data = payload(120_000, 2);
    // A compressed entry cannot be mapped at the top level: the
    // volume materializes and the badge has to say so.
    let vol = rar5_compressed_volume("movie.mkv", &data);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    ex.finish().unwrap();
    let sh = shape_of(&ex);
    assert_eq!(sh[0], "rar5", "{sh:?}");
    assert!(sh.contains(&"compressed"), "{sh:?}");
    assert!(sh.contains(&"on-disk"), "{sh:?}");
    assert!(!sh.contains(&"one-pass"), "{sh:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shape_says_one_pass_when_an_encrypted_set_decrypts_in_stream() {
    let dir = tmpdir("shape-enc");
    let plain = payload(200_003, 41);
    let f = fixtures::encrypt_file("hunter2", &plain, 5);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    // Plaintext-once: nothing is ever stored locked, so this is an
    // ordinary one-pass set that happens to be encrypted.
    assert_eq!(shape_of(&ex), ["rar5", "store", "encrypted", "one-pass"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The badge a RAR4 encrypted set earns. It read "unlock-at-end" until
/// TODO 27 phase 3: RAR4 stores no password check, and the route gate
/// demanded one, so the set assembled ciphertext and unlocked in the
/// finish pass. The re-encrypt shim retired that requirement - a wrong
/// key still rebuilds byte-exact volumes for the demote - so RAR4 now
/// decrypts as its bytes arrive like every other encrypted set, and the
/// badge says so.
#[test]
fn shape_says_rar4_encrypted_goes_one_pass() {
    let dir = tmpdir("shape-enc4");
    let plain = payload(120_007, 43);
    let f = fixtures::encrypt_file_v4("hunter2", &plain, 51);
    let vol = fixtures::rar4_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        shape_of(&ex),
        ["rar4", "store", "encrypted", "one-pass"],
        "RAR4 must not be badged as materialized any more"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shape_says_encrypted_when_the_headers_are_locked() {
    let dir = tmpdir("shape-hdr");
    // Encrypted headers with no password: nothing parses, so the
    // blocker is the only place the fact can come from.
    let vol = fixtures::rar4_encrypted_headers(200_000);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    ex.finish().unwrap();
    let sh = shape_of(&ex);
    assert!(sh.contains(&"encrypted"), "{sh:?}");
    assert!(sh.contains(&"on-disk"), "{sh:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shape_reports_a_top_level_7z_as_unpacked_on_disk() {
    let dir = tmpdir("shape-7z");
    // A top-level .7z the chase cannot take - here the start header
    // fails its own CRC, so `sevenz_start_header` declines before the
    // depth question even arises - lands on disk for the post-pass.
    // Without the signature sniff the badge would say nothing at all
    // about a 7z release. (A well-formed one streams instead: see
    // `sevenz_top_level_extracts_one_pass`.)
    let mut vol = b"7z\xbc\xaf\x27\x1c".to_vec();
    vol.extend_from_slice(&payload(80_000, 6));
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "release.7z", &vol, 7000, 3);
    ex.finish().unwrap();
    assert_eq!(shape_of(&ex), ["7z", "on-disk"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shape_tag_round_trips_through_the_wire_form() {
    let dir = tmpdir("shape-tag");
    let data = payload(200_000, 1);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    ex.finish().unwrap();
    // The daemon persists exactly this string and the dashboard
    // splits it back apart on whitespace.
    let tag = ex.archive_shape().unwrap().tag();
    assert_eq!(tag, "rar5 store one-pass");
    assert_eq!(
        tag.split(' ').map(shape_word).collect::<Vec<_>>(),
        ["RAR5", "stored", "one-pass"]
    );
    // An unknown token from a newer daemon still reads as itself.
    assert_eq!(shape_word("rar9"), "rar9");
}
