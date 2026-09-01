//! Preclaimed-name and replay-span tests, split out of
//! `extract/mod_tests.rs` bodily (§106, file-size ceiling): payload
//! source provenance, adoptable preclaimed names, and what a resumed
//! run's replayed spans and forwarded fragments are allowed to leave in
//! place. `mod_tests.rs`'s own header (volume naming, store sets,
//! budgets, protected sources, the archive-shape badge) predates this
//! family; this file is the sixth topic that grew past it.

use super::*;
use crate::rar::fixtures;

use super::testutil::*;

/// TODO 159 item 1: the failed-job quarantine has to withhold ONE
/// archive's payload without withholding its neighbours', which means
/// asking which source volumes fed each output file. Two independent
/// single-volume archives in one post - the advYB shape - must answer
/// with two disjoint slot sets.
#[test]
fn payload_sources_name_each_archives_own_volumes() {
    let dir = tmpdir("provenance");
    let a = payload(120_000, 11);
    let b = payload(90_000, 22);
    let va = fixtures::rar5_volume(&[("one.bin", 120_000, &a, false, false)]);
    let vb = fixtures::rar5_volume(&[("two.bin", 90_000, &b, false, false)]);
    let ex = Extractor::new(&dir, 2, true);
    feed(&ex, 0, "a.rar", &va, 7000, 3);
    feed(&ex, 1, "b.rar", &vb, 7000, 5);
    let rep = ex.finish().unwrap();
    let names: Vec<&str> = rep.extracted.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["one.bin", "two.bin"], "{rep:?}", rep = names);
    let src = ex.payload_sources().expect("both slots are grouped");
    assert_eq!(src.get("one.bin"), Some(&vec![0usize]));
    assert_eq!(src.get("two.bin"), Some(&vec![1usize]));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The multi-volume half of the same question, and the reason the map
/// answers at GROUP granularity: an inner file split across two volumes
/// must name BOTH, so damage to either one withholds it.
#[test]
fn payload_sources_name_every_volume_of_a_split_file() {
    let dir = tmpdir("provenance-split");
    let data = payload(300_000, 7);
    let v1 = fixtures::rar5_volume_n(&[("big.bin", 300_000, &data[..150_000], false, true)], 0);
    let v2 = fixtures::rar5_volume_n(&[("big.bin", 300_000, &data[150_000..], true, false)], 1);
    let ex = Extractor::new(&dir, 2, true);
    feed(&ex, 0, "s.part1.rar", &v1, 7000, 3);
    feed(&ex, 1, "s.part2.rar", &v2, 7000, 4);
    let rep = ex.finish().unwrap();
    assert!(
        rep.extracted.iter().any(|(n, _)| n == "big.bin"),
        "{:?}",
        rep.extracted
    );
    let src = ex.payload_sources().expect("every slot is grouped");
    assert_eq!(
        src.get("big.bin"),
        Some(&vec![0usize, 1]),
        "a split file is only whole if every volume carrying it is"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// §94 A: the crash-resume replay preclaims a restored file's name so an
/// inner member cannot open the same inode as a live source (Codex sweep
/// 3 Aug H3) - but the claim must not lock the SLOT'S OWN plain writer
/// out of the file it is replaying.
///
/// Without the slot half of the claim, `claim_name` disambiguated the
/// slot away from its own restored file to `000-<name>`. A resumed plain
/// payload then finished byte-perfect under the mangled name while the
/// orphaned restored stub kept the real one, which is what PAR2 read
/// back and condemned (1947 of 2000 blocks bad on the obfuscated resume
/// pin), and the cleanup swept the stub as a leftover.
///
/// Both halves asserted: the owning slot adopts, a different slot does
/// not.
#[test]
fn a_preclaimed_name_is_adoptable_by_its_own_slot_only() {
    let dir = tmpdir("preclaim");
    let data = payload(50_000, 5);
    let ex = Extractor::new(&dir, 2, true);
    ex.preclaim_name(0, "payload.bin");
    // Slot 0 owns the claim: its plain writer must land on that exact
    // path, which is the restored file the replay is feeding back.
    ex.write(0, "payload.bin", data.len() as u64, 0, &data)
        .unwrap();
    // Slot 1 is a different file that happens to sanitize the same way:
    // it must be pushed off the claimed name, as an inner member is.
    ex.write(1, "payload.bin", data.len() as u64, 0, &data)
        .unwrap();
    ex.finish().unwrap();
    assert_eq!(
        std::fs::read(dir.join("payload.bin")).unwrap(),
        data,
        "the preclaiming slot did not adopt its own restored file"
    );
    assert!(
        dir.join("001-payload.bin").exists(),
        "a non-owning slot took the preclaimed name: {:?}",
        std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect::<Vec<_>>()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The disambiguating prefix lands on a name `sanitize_out_name` has
/// already capped, and a name at the 255-byte component cap plus
/// `001-` is 259 bytes that `openat` refuses - so the second slot's
/// plain writer could not be created and the member was lost.
///
/// The name is AT the cap precisely because capping is what produced
/// it, so this is the ordinary overlong-member path and not a corner.
#[test]
fn a_second_slot_wanting_one_overlong_name_still_gets_a_file() {
    let dir = tmpdir("capclaim");
    let long = format!("{}.bin", "y".repeat(400));
    let capped = crate::disk::sanitize_out_name(&long);
    assert_eq!(capped.len(), 255, "the premise moved");
    let first = payload(1_000, 7);
    let second = payload(2_000, 9);
    let ex = Extractor::new(&dir, 2, true);
    ex.write(0, &long, first.len() as u64, 0, &first).unwrap();
    ex.write(1, &long, second.len() as u64, 0, &second).unwrap();
    ex.finish().unwrap();
    let mut got: Vec<Vec<u8>> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    got.sort();
    let mut want = vec![first, second];
    want.sort();
    assert_eq!(got, want, "both slots must land their own bytes");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// §94 A map mode (Codex F-03): the replay preclaims the SOURCE file
/// it reads (the earlier run's extracted member) under the volume's
/// slot. The archive re-creating that very member must adopt the name
/// - the inner writer is made by whichever slot's bytes reach it, not
/// necessarily the preclaiming slot, so the grant is by archive group -
/// while a plain file of a different slot is still pushed off it.
#[test]
fn a_preclaimed_source_is_adoptable_by_its_own_archive_group() {
    let dir = tmpdir("preclaim-group");
    let inner = "movie.mkv";
    let data = payload(300_000, 17);
    let vol = fixtures::rar5_volume_n(&[(inner, data.len() as u64, &data, false, false)], 0);
    let ex = Arc::new(Extractor::with_resume(&dir, 2, true, true));
    ex.anchor();
    // What the replay does: the volume's own name and its source.
    ex.preclaim_name(0, "v.part01.rar");
    ex.preclaim_name(0, inner);
    // A stranger plain file with the member's name must not take it.
    let other = payload(10_000, 3);
    ex.write(1, inner, other.len() as u64, 0, &other).unwrap();
    ex.write(0, "v.part01.rar", vol.len() as u64, 0, &vol)
        .unwrap();
    ex.finish().unwrap();
    assert_eq!(
        std::fs::read(dir.join(inner)).unwrap(),
        data,
        "the archive did not adopt its own preclaimed member name"
    );
    assert_eq!(
        std::fs::read(dir.join("001-movie.mkv")).unwrap(),
        other,
        "the stranger was not pushed off the preclaimed name"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// §94 A: the replay's ORDER is what decides whether it costs memory.
///
/// A resumed job feeds its restored spans back through `write` before
/// the pool opens. Fed in volume order, each volume's base offset is
/// already resolvable when its data arrives and every byte places
/// straight into the output: holds stay at zero. Fed out of order, a
/// volume whose predecessors have not been seen has no base yet, so
/// every byte of it parks in `holds` until `reresolve` catches up and
/// drains it - and the PEAK is what the held-bytes cap is judged
/// against, so an out-of-order replay demotes (or pages) sets that an
/// ordered one streams.
///
/// This is the measurement behind `get/rig.rs` sorting its seeds:
/// `journal::restore` returns them from a `HashMap`, i.e. in a
/// different arbitrary order every process run, which is why the F4
/// disk round saw a held peak of 100% of the replayed bytes and why two
/// runs of the same leg differed by 2.6x.
#[test]
fn a_replayed_store_set_places_only_in_volume_order_and_only_with_its_head() {
    let inner = "movie.mkv";
    let n_vols = 8usize;
    let per = 200_000usize;
    let total = per * n_vols;
    let data = payload(total, 41);
    let vols: Vec<Vec<u8>> = (0..n_vols)
        .map(|k| {
            fixtures::rar5_volume_n(
                &[(
                    inner,
                    total as u64,
                    &data[k * per..(k + 1) * per],
                    k > 0,
                    k < n_vols - 1,
                )],
                k as u64,
            )
        })
        .collect();
    // Half the articles of each volume are missing, head always present:
    // roughly what a killed run leaves behind.
    let art = 25_000usize;
    let replay = |tag: &str, order: Vec<usize>, skip_head: bool| -> usize {
        let dir = tmpdir(&format!("replayorder-{tag}"));
        let ex = Arc::new(Extractor::with_resume(&dir, n_vols, true, true));
        ex.anchor();
        for k in order {
            let name = format!("v.part{:02}.rar", k + 1);
            ex.preclaim_name(k, &name);
            for i in 0..vols[k].len().div_ceil(art) {
                if i % 2 == 1 || (skip_head && i == 0) {
                    continue;
                }
                let s = i * art;
                let e = (s + art).min(vols[k].len());
                ex.write(k, &name, vols[k].len() as u64, s as u64, &vols[k][s..e])
                    .unwrap();
            }
        }
        let peak = ex.holds_peak();
        std::fs::remove_dir_all(&dir).unwrap();
        peak
    };
    let replayed = n_vols * (vols[0].len().div_ceil(art).div_ceil(2)) * art;
    let ordered = replay("fwd", (0..n_vols).collect(), false);
    let reversed = replay("rev", (0..n_vols).rev().collect(), false);
    let headless = replay("nohead", (0..n_vols).collect(), true);
    assert!(
        ordered < 64 << 10,
        "volume-order replay held {ordered} bytes of ~{replayed} - it should place them all"
    );
    assert!(
        reversed > replayed / 2,
        "reverse-order replay held only {reversed} bytes of ~{replayed}; if that is no longer \
         true the driver's sort in get/rig.rs may have stopped being load-bearing"
    );
    // And the half nothing can sort its way out of: a resume never has
    // the offset-0 article. That article carries the RAR headers, whose
    // bytes land nowhere on disk (the mapper consumes them), so it never
    // completes into an `R` record and every restored volume starts at
    // its SECOND article - a hole exactly where the header is. Fed then,
    // the mapper cannot parse the volume at all and holds all of it,
    // whatever the order. This is why `ReplayPending` waits for the head
    // to refetch instead of replaying before the pool opens.
    assert!(
        headless > replayed / 2,
        "a headless replay held only {headless} bytes of ~{replayed} - if the mapper can now \
         start a volume without its offset-0 bytes, the deferral in get/rig.rs is free to go"
    );
}

/// A volume whose recovery record (a multi-MB service block) sits
/// between the file data and the end-of-archive block, with the tail
/// articles arriving BEFORE the article that carries the record's
/// header. Measured in the field 22 Aug 2026 (DISKSHAPE-ROUND
/// 2026-08-21 §2.1b): a `-rr10p` store set demoted on 2 of 13 legs
/// with `incomplete mapping at end of download`, always on the
/// slowest legs, i.e. the most reordered tails.
///
/// The mapper's window only keeps bytes near its cursor, so the end
/// block's article is dropped from the window and parked in holds.
/// When the record's header lands, the parse SKIPS the record - the
/// cursor moves past it, but no new entry appears, and the extractor
/// used to re-drain holds only on a new entry. The end block then sat
/// in holds with nothing left to wake it, and settle demoted a
/// healthy set. Every cursor advance must count as progress.
#[test]
fn service_block_skip_redrains_tail_holds() {
    let dir = tmpdir("rr_skip");
    let data = payload(300_000, 5);
    let rr = payload(5 << 20, 6);
    let vol =
        fixtures::rar5_volume_n_service(&[("movie.mkv", 300_000, &data, false, false)], 0, &rr);
    let art = 256 << 10;
    let n_arts = vol.len().div_ceil(art);
    // The service header lives in the article holding the end of the
    // file data; the end block is in the last article, more than the
    // 4 MiB window past it.
    let hdr_art = (vol.len() - rr.len() - 64) / art;
    assert!(hdr_art >= 1 && hdr_art + 16 < n_arts, "fixture layout");
    let order: Vec<usize> = [0, n_arts - 1, n_arts - 2, hdr_art]
        .into_iter()
        .chain((1..n_arts).filter(|&i| i != hdr_art && i < n_arts - 2))
        .collect();
    let ex = Extractor::new(&dir, 1, true);
    let size = vol.len() as u64;
    for i in order {
        let s = i * art;
        let e = (s + art).min(vol.len());
        ex.write(0, "v.rar", size, s as u64, &vol[s..e]).unwrap();
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 300_000)]);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    assert!(!dir.join("v.rar").exists(), "volume landed: not one-pass");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// §94 A residual (22 Aug 2026): the replay's WRITE half is skipped
/// only when this run's derived placement is the very (file, offset)
/// the journal read the bytes from, and on any mismatch the span is
/// written - never "covered" on the journal's say-so.
///
/// Run 1 writes a store volume's second article through the ordinary
/// path and keeps its `Placed` frag, which is byte-for-byte what the
/// journal's `R` record would carry. Run 2 (a resume on the same
/// directory) re-derives the map from the head article, then is handed
/// the same span with the frag's coordinates. The output range is
/// first poisoned with a sentinel, so the two outcomes are
/// distinguishable on disk: a skip leaves the sentinel (the mechanism
/// really did not write), a write replaces it with the posted bytes.
#[test]
fn a_replayed_span_is_left_in_place_only_where_the_derived_map_agrees() {
    let inner = "movie.mkv";
    let data = payload(300_000, 23);
    let vol = fixtures::rar5_volume_n(&[(inner, data.len() as u64, &data, false, false)], 0);
    let name = "v.part01.rar";
    let art = 25_000usize;
    let head = &vol[..art];
    let span = &vol[art..2 * art];

    // Run 1: the ordinary path, and the frag the journal would record.
    let dir = tmpdir("inplace");
    let frag = {
        let ex = Arc::new(Extractor::with_resume(&dir, 1, true, true));
        ex.anchor();
        ex.write(0, name, vol.len() as u64, 0, head).unwrap();
        match ex
            .write(0, name, vol.len() as u64, art as u64, span)
            .unwrap()
        {
            Persist::Placed(f) => f,
            _ => panic!("second article did not place"),
        }
    };
    assert_eq!(frag.len(), 1, "one contiguous placement expected: {frag:?}");
    let (file, file_off) = (frag[0].file.clone(), frag[0].file_off);
    assert_eq!(file, inner);
    let expect = std::fs::read(dir.join(inner)).unwrap();

    // Run 2, three times over, from the state run 1 left: a resume
    // extractor re-parses the head, then meets the replayed span.
    let resume = |src_file: &str, src_off: u64| -> (u64, Vec<u8>) {
        // Poison the range the span maps to, so a skip is visible.
        {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(dir.join(inner))
                .unwrap();
            crate::disk::write_all_at(&f, &vec![0xEEu8; art], file_off).unwrap();
        }
        let ex = Arc::new(Extractor::with_resume(&dir, 1, true, true));
        ex.anchor();
        ex.preclaim_name(0, name);
        ex.preclaim_name(0, inner);
        ex.write(0, name, vol.len() as u64, 0, head).unwrap();
        let (_, covered) = ex
            .write_in_place(
                0,
                name,
                vol.len() as u64,
                art as u64,
                span,
                src_file,
                src_off,
            )
            .unwrap();
        (covered, std::fs::read(dir.join(inner)).unwrap())
    };

    // The match: derived placement == journal placement, so no write.
    let (covered, got) = resume(&file, file_off);
    assert_eq!(
        covered, art as u64,
        "the matching span was not left in place"
    );
    assert!(
        got[file_off as usize..file_off as usize + art]
            .iter()
            .all(|&b| b == 0xEE),
        "a matching span was written anyway - the skip is not reaching the pwrite"
    );
    // Off by one byte: the journal disagrees with the map, so WRITE.
    let (covered, got) = resume(&file, file_off + 1);
    assert_eq!(covered, 0, "an offset mismatch was marked covered");
    assert_eq!(got, expect, "an offset-mismatched span was not written");
    // A different file of the same name shape: WRITE.
    let (covered, got) = resume("other.mkv", file_off);
    assert_eq!(covered, 0, "a file mismatch was marked covered");
    assert_eq!(got, expect, "a file-mismatched span was not written");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// §94 A in-place replay through a CHILD forward. With nested routing on
/// (the default) a store member the root maps is written by the child
/// extractor, and before the source rode along with the forward this
/// exact scenario left 0 bytes in place - every resumed byte of the
/// member wrote itself back. Marker bytes the span does not carry prove
/// the skip reaches the child's pwrite; an off-by-one source offset and
/// a different source file both fail the match and write.
#[test]
fn a_child_forwarded_replay_span_is_left_in_place_only_where_the_map_agrees() {
    let dir = tmpdir("inplace-child");
    let data = payload(200_000, 5);
    let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
    let data_off = vol
        .windows(64)
        .position(|w| w == &data[..64])
        .expect("store payload sits verbatim in the volume");
    let marker: Vec<u8> = vec![0xEE; 200_000];
    std::fs::write(dir.join("movie.mkv"), &marker).unwrap();

    let ex = Extractor::with_resume(&dir, 1, true, true);
    ex.preclaim_name(0, "movie.mkv");
    ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..data_off])
        .unwrap();

    let span = &vol[data_off..data_off + 100_000];
    let (_, covered) = ex
        .write_in_place(
            0,
            "v.rar",
            vol.len() as u64,
            data_off as u64,
            span,
            "movie.mkv",
            0,
        )
        .unwrap();
    assert_eq!(
        covered, 100_000,
        "the child forward lost the in-place source"
    );
    assert!(ex.covered(0, data_off as u64, 100_000));
    let on_disk = std::fs::read(dir.join("movie.mkv")).unwrap();
    assert_eq!(
        &on_disk[..100_000],
        &marker[..100_000],
        "a covered span was rewritten"
    );

    let span = &vol[data_off + 100_000..data_off + 150_000];
    let (_, covered) = ex
        .write_in_place(
            0,
            "v.rar",
            vol.len() as u64,
            (data_off + 100_000) as u64,
            span,
            "movie.mkv",
            100_001,
        )
        .unwrap();
    assert_eq!(covered, 0, "an off-by-one source was left in place");
    let on_disk = std::fs::read(dir.join("movie.mkv")).unwrap();
    assert_eq!(&on_disk[100_000..150_000], &data[100_000..150_000]);

    let span = &vol[data_off + 150_000..];
    let (_, covered) = ex
        .write_in_place(
            0,
            "v.rar",
            vol.len() as u64,
            (data_off + 150_000) as u64,
            span,
            "other.bin",
            150_000,
        )
        .unwrap();
    assert_eq!(covered, 0, "a different source file was left in place");
    let on_disk = std::fs::read(dir.join("movie.mkv")).unwrap();
    assert_eq!(&on_disk[150_000..], &data[150_000..]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 252 (23 Aug 2026): the widened parked-article claim rests on
/// `materialized_span_on_disk`, so pin what it will and will not vouch
/// for. The advG shape: a two-volume store set whose second volume
/// never gets its offset-0 header article. That volume can map nothing,
/// so the group demotes at `finish` and volume 1 - which mapped and
/// extracted - is reconstructed on disk, carrying exactly the articles
/// that arrived. A mid-volume article held back from it is a sparse
/// hole that preads as zeros, and a wrong `Some` there is a journal
/// record that hands a later resume zeros in place of the posted
/// bytes.
#[test]
fn materialized_span_on_disk_vouches_for_written_ranges_only() {
    let dir = tmpdir("matspan");
    let inner = payload(600_000, 88);
    let half = inner.len() / 2;
    let vols: Vec<Vec<u8>> = (0..2)
        .map(|i| {
            let part = if i == 0 {
                &inner[..half]
            } else {
                &inner[half..]
            };
            fixtures::rar5_volume_n(
                &[("F.mkv", inner.len() as u64, part, i > 0, i == 0)],
                i as u64,
            )
        })
        .collect();
    let ex = Extractor::new(&dir, 2, true);
    let art = 25_000usize;
    // A slot still waiting on its sniff owns no file, so it vouches for
    // nothing whatever its holds carry.
    assert_eq!(
        ex.materialized_span_on_disk(0, art as u64, art as u64),
        None
    );
    // Volume 2's header article never arrives, which is what demotes the
    // group; volume 1 loses a mid-volume payload article, which is the
    // hole under test.
    let gap = 4usize;
    for (slot, vol) in vols.iter().enumerate() {
        for i in 0..vol.len().div_ceil(art) {
            if (slot == 1 && i == 0) || (slot == 0 && i == gap) {
                continue;
            }
            let (s, e) = (i * art, ((i + 1) * art).min(vol.len()));
            ex.write(
                slot,
                &format!("r.part{}.rar", slot + 1),
                vol.len() as u64,
                s as u64,
                &vol[s..e],
            )
            .unwrap();
        }
    }
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "the group must demote");
    assert!(
        ex.slot_materialized(0),
        "the mapped volume must materialize"
    );
    let vol = &vols[0];
    for i in 0..vol.len().div_ceil(art) {
        let (s, e) = (i * art, ((i + 1) * art).min(vol.len()));
        let got = ex.materialized_span_on_disk(0, s as u64, (e - s) as u64);
        if i == gap {
            assert_eq!(got, None, "vouched for the hole a lost article left");
        } else {
            assert_eq!(
                got.as_ref().map(|(f, _)| f.as_str()),
                Some("r.part1.rar"),
                "article {i} is on disk and unvouched"
            );
        }
    }
    // A span STRADDLING the hole is refused too - the coverage is
    // gap-free or it is nothing.
    assert_eq!(
        ex.materialized_span_on_disk(0, ((gap - 1) * art) as u64, (art * 3) as u64),
        None,
        "vouched for a span straddling the hole"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Read-only sweep finding 6 (31 Aug 2026): the HELD remainder's frags
/// must name their file the way the PLACED ones do - `out_name_of`'s
/// out_dir-relative form, which is what the journal's `S`/`M` records
/// carry - and never the bare basename.
///
/// `jobs_to_persist` builds both lists twenty lines apart. The Placed
/// arm was moved onto `out_name_of` by the 30 Aug 2026 relpath sweep and
/// carries the argument in its own comment; the Held arm was left
/// behind. What that costs is a resumed held span of a tree payload:
/// restore joins `Frag::file` onto out_dir, so `VTS_01_1.VOB` sends the
/// replay to `out_dir/VTS_01_1.VOB` while the writer is at
/// `out_dir/VIDEO_TS/VTS_01_1.VOB`.
///
/// The shape is a PARTIALLY held span, which is the only one that
/// produces a non-empty `plain_frags` at all: a two-entry volume
/// delivered in order, where the article straddling the first entry's
/// data end places its head and holds the tail past `mapped_through`
/// until the second entry's header arrives.
#[test]
fn a_held_frag_of_a_tree_payload_names_its_file_the_way_the_journal_does() {
    let dir = tmpdir("held-tree-frag");
    let mk = |seed: u32, n: usize| -> Vec<u8> {
        (0..n as u32)
            .map(|i| (i.wrapping_mul(seed) as u8).wrapping_add(7))
            .collect()
    };
    let (a, b) = (mk(17, 400_000), mk(29, 200_000));
    // The first member's own name carries a directory:
    // `sanitize_out_name` rules the path safe and preserves it, which is
    // the whole reason the basename and the journal name differ here.
    let vol = fixtures::rar5_volume(&[
        ("VIDEO_TS/VTS_01_1.VOB", 400_000, a.as_slice(), false, false),
        ("VIDEO_TS/VTS_01_2.VOB", 200_000, b.as_slice(), false, false),
    ]);
    let ex = Extractor::new(&dir, 1, true);
    let art = 100_000usize;
    let n = vol.len().div_ceil(art);
    let mut seen = 0usize;
    for i in 0..n {
        let s = i * art;
        let e = ((i + 1) * art).min(vol.len());
        if let Persist::Held(frags) = ex
            .write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
            .unwrap()
        {
            for f in &frags {
                seen += 1;
                assert!(
                    f.file.starts_with("VIDEO_TS/"),
                    "a Held frag named its file {:?} by basename - restore joins this \
                     onto out_dir and opens a path nothing wrote",
                    f.file
                );
            }
        }
    }
    // Floored rather than assumed: a fixture that stopped producing a
    // partially-held span would pass every assertion above vacuously.
    assert!(
        seen > 0,
        "no Held frag was produced - the fixture no longer exercises the arm"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Read-only sweep finding 11 (31 Aug 2026): §94 A's in-place replay
/// must recognise its own bytes when the payload lives in a TREE.
///
/// `InPlace::matches` compared `j.writer.path.file_name()` against the
/// journal's `Frag::file`, and that name became out_dir-RELATIVE in the
/// 30 Aug 2026 relpath sweep - so for any payload carrying a directory
/// the test compared `VTS_01_1.VOB` against `VIDEO_TS/VTS_01_1.VOB`,
/// matched nothing, and every replayed span wrote itself back. Correct
/// bytes, and the whole of the saved I/O thrown away on exactly the
/// shape (a disc tree) that has the most of it.
///
/// The control is the same replay one directory off: a source name that
/// is genuinely not this writer's must still fail the match and write.
#[test]
fn a_replay_span_of_a_tree_payload_is_left_in_place() {
    let dir = tmpdir("inplace-tree");
    let name = "VIDEO_TS/VTS_01_1.VOB";
    let data = payload(200_000, 9);
    // Run 1: land the payload, so run 2 has a real file to replay from.
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.write(0, name, data.len() as u64, 0, &data).unwrap();
    drop(ex);
    let replay = |src_file: &str| -> u64 {
        let ex = Arc::new(Extractor::with_resume(&dir, 1, true, true));
        ex.anchor();
        ex.preclaim_name(0, name);
        let (_, covered) = ex
            .write_in_place(0, name, data.len() as u64, 0, &data, src_file, 0)
            .unwrap();
        covered
    };
    assert_eq!(
        replay(name),
        data.len() as u64,
        "the replay rewrote a tree payload's own bytes - InPlace::matches is \
         comparing a basename against the journal's out_dir-relative name"
    );
    assert_eq!(
        replay("VTS_01_1.VOB"),
        0,
        "a bare basename is NOT this writer's journal name and must not match"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
