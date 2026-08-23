//! §94 D, nested half: a byte-split zip inside a store RAR streams as
//! one container, counted off the outer archive's entry list (see
//! `zip_split.rs`). The three closes (a following entry, the archive
//! end at finish, a run spanning outer volumes), the two refusals (a
//! hole in the run, bare-numeric parts that are not a zip), and the
//! negative control (a single `.zip` never opens a set).

use super::*;
use crate::extract::testutil::*;
use crate::rar::fixtures;

type Piece<'a> = (&'a str, u64, &'a [u8], bool, bool);

fn whole<'a>(name: &'a str, data: &'a [u8]) -> Piece<'a> {
    (name, data.len() as u64, data, false, false)
}

/// Feed `outer` as one slot in three orders: natural, reversed, and a
/// seeded shuffle. A real permutation each time - the `(i * 7 + 3) %
/// n` scramble the nested-zip tests use is one only when `n` is
/// coprime with 7, and a fixture that lands on 35 articles feeds five.
fn feed_orders(
    tag: &str,
    outer: &[u8],
    check: impl Fn(usize, &Path, &Arc<Extractor>, ExtractReport),
) {
    let art = 7000usize;
    let n_arts = outer.len().div_ceil(art);
    let mut shuffled: Vec<usize> = (0..n_arts).collect();
    let mut state = 0x94Du64;
    for i in (1..shuffled.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        shuffled.swap(i, (state >> 33) as usize % (i + 1));
    }
    let orders: Vec<Vec<usize>> =
        vec![(0..n_arts).collect(), (0..n_arts).rev().collect(), shuffled];
    for (t, order) in orders.iter().enumerate() {
        let dir = tmpdir(&format!("{tag}{t}"));
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        for &i in order {
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        check(t, &dir, &ex, rep);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The child's declaration map and the root group's open list, for
/// asserting what the wiring did rather than only what came out.
fn split_state(ex: &Extractor) -> (Vec<(String, Option<u32>)>, Vec<String>) {
    let inner = ex.inner.lock().unwrap();
    let open: Vec<String> = inner
        .groups
        .values()
        .flat_map(|g| g.zip_splits_open.iter().cloned())
        .collect();
    let decl = match &inner.child {
        Some(c) => {
            let mut v: Vec<(String, Option<u32>)> = c
                .inner
                .lock()
                .unwrap()
                .zip_split_decl
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            v.sort();
            v
        }
        None => Vec::new(),
    };
    (decl, open)
}

/// A `.zip.001`/`.002`/`.003` run followed by another entry: the
/// outer's entry walk counts the set the moment that entry's header
/// parses, and the zip streams out of the chase - no part, no outer
/// volume on disk. All three feed orders, because the count may land
/// before or after any given part attaches.
#[test]
fn nested_zip_split_counted_by_the_following_entry_extracts_one_pass() {
    let a = payload(300_000, 180);
    let readme = payload(5_000, 181);
    let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
    let parts = split_zip(&arch, 3);
    assert_eq!(parts.len(), 3, "fixture must really split");
    let outer = fixtures::rar5_volume(&[
        whole("inner.zip.001", &parts[0]),
        whole("inner.zip.002", &parts[1]),
        whole("inner.zip.003", &parts[2]),
        whole("readme.txt", &readme),
    ]);
    feed_orders("zip-nested-split-follow", &outer, |t, dir, ex, rep| {
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
        assert_eq!(
            std::fs::read(dir.join("readme.txt")).unwrap(),
            readme,
            "order {t}"
        );
        assert_eq!(
            dir_files(dir),
            vec!["a.bin".to_string(), "readme.txt".to_string()],
            "order {t}: parts and volume must not land"
        );
        let (decl, open) = split_state(ex);
        assert_eq!(
            decl,
            vec![("inner.zip".to_string(), Some(3))],
            "order {t}: the child must hold the count"
        );
        assert!(open.is_empty(), "order {t}: the set must be closed");
    });
}

/// The set is the LAST thing in the archive: no header follows it, so
/// nothing can count it before every byte is in, and the parent's
/// finish closes it on what the walk collected. Still one pass.
#[test]
fn nested_zip_split_ending_the_archive_closes_at_finish() {
    let a = payload(240_000, 182);
    let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
    let parts = split_zip(&arch, 2);
    let outer = fixtures::rar5_volume(&[
        whole("inner.zip.001", &parts[0]),
        whole("inner.zip.002", &parts[1]),
    ]);
    feed_orders("zip-nested-split-end", &outer, |t, dir, ex, rep| {
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
        assert_eq!(dir_files(dir), vec!["a.bin".to_string()], "order {t}");
        let (decl, open) = split_state(ex);
        assert_eq!(decl, vec![("inner.zip".to_string(), Some(2))], "order {t}");
        assert!(open.is_empty(), "order {t}");
    });
}

/// The run spans THREE outer volumes, part 2 cut across a volume
/// boundary, fed last volume first. The walk must not count the set
/// off volume 2's `readme.txt` while volume 1 (holding `.002`'s tail
/// and `.003`) has not parsed - the gap rule - and must count it once
/// it has. Feeding volumes backwards is the order that breaks a
/// base-trusting walk: the island `vol 2` resolves on its own.
#[test]
fn nested_zip_split_across_outer_volumes_waits_for_the_gap() {
    let a = payload(360_000, 183);
    let readme = payload(3_000, 184);
    let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
    let parts = split_zip(&arch, 3);
    let cut = parts[1].len() / 2;
    let p2 = parts[1].len() as u64;
    let vols = [
        fixtures::rar5_volume_n(
            &[
                whole("inner.zip.001", &parts[0]),
                ("inner.zip.002", p2, &parts[1][..cut], false, true),
            ],
            0,
        ),
        fixtures::rar5_volume_n(
            &[
                ("inner.zip.002", p2, &parts[1][cut..], true, false),
                whole("inner.zip.003", &parts[2]),
            ],
            1,
        ),
        fixtures::rar5_volume_n(&[whole("readme.txt", &readme)], 2),
    ];
    let dir = tmpdir("zip-nested-split-vols");
    let ex = Arc::new(Extractor::new(&dir, 3, true));
    ex.anchor();
    // Volume 2 whole, first: its entry list is complete and holds a
    // non-sibling, but part 1 has not been seen - nothing to count.
    feed(&ex, 2, "v.part3.rar", &vols[2], 7000, 90);
    let (decl, open) = split_state(&ex);
    assert!(
        decl.is_empty() && open.is_empty(),
        "nothing routed yet: {decl:?} {open:?}"
    );
    // Volume 0: part 1 routes and opens the set; the run ends on an
    // incomplete piece whose continuation is in the unparsed volume 1,
    // so the set must stay OPEN - volume 2's readme is not adjacent.
    feed(&ex, 0, "v.part1.rar", &vols[0], 7000, 91);
    let (decl, open) = split_state(&ex);
    assert_eq!(
        decl,
        vec![("inner.zip".to_string(), None)],
        "open, uncounted"
    );
    assert_eq!(open, vec!["inner.zip".to_string()]);
    // Volume 1 closes the gap: the walk now runs .001 .002 .003 and
    // reaches volume 2's readme.
    feed(&ex, 1, "v.part2.rar", &vols[1], 7000, 92);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    let (decl, open) = split_state(&ex);
    assert_eq!(decl, vec![("inner.zip".to_string(), Some(3))]);
    assert!(open.is_empty());
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("readme.txt")).unwrap(), readme);
    assert_eq!(
        dir_files(&dir),
        vec!["a.bin".to_string(), "readme.txt".to_string()]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A hole in the run (`.001`, `.003`): no count can ever resolve it,
/// so the set is REFUSED and each part materializes byte-exact under
/// its own name - the disk pass's input, which declines the hole too.
/// The refusal's wording carries no entry name, so the laundering
/// barrier has nothing to catch - asserted anyway, as the property.
#[test]
fn nested_zip_split_with_a_hole_is_refused_and_materializes() {
    let a = payload(240_000, 185);
    let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
    let parts = split_zip(&arch, 3);
    let readme = payload(2_000, 186);
    let outer = fixtures::rar5_volume(&[
        whole("password.zip.001", &parts[0]),
        whole("password.zip.003", &parts[2]),
        whole("readme.txt", &readme),
    ]);
    feed_orders("zip-nested-split-hole", &outer, |t, dir, _ex, rep| {
        assert!(
            !rep.fallbacks.is_empty()
                && rep
                    .fallbacks
                    .iter()
                    .all(|(_, w)| w == "nested fallback: zip split parts are not contiguous"),
            "order {t}: {:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("password.zip.001")).unwrap(),
            parts[0],
            "order {t}"
        );
        assert_eq!(
            std::fs::read(dir.join("password.zip.003")).unwrap(),
            parts[2],
            "order {t}"
        );
        assert!(
            !dir.join("a.bin").exists(),
            "order {t}: a hole must not stream"
        );
        assert_eq!(std::fs::read(dir.join("readme.txt")).unwrap(), readme);
    });
}

/// Bare-numeric parts inside the RAR that are NOT a zip (an HJSplit run
/// of a raw payload): the grammar opens the set speculatively, part 1's
/// missing `PK` magic forfeits it, and every part lands byte-exact for
/// the disk pass's plain-split joiner. No chase, no output invented.
#[test]
fn nested_bare_numeric_parts_without_zip_magic_materialize() {
    let raw = payload(200_000, 187);
    let cut = raw.len() / 2;
    let outer = fixtures::rar5_volume(&[
        whole("movie.001", &raw[..cut]),
        whole("movie.002", &raw[cut..]),
    ]);
    feed_orders("zip-nested-numeric-raw", &outer, |t, dir, _ex, rep| {
        assert_eq!(
            std::fs::read(dir.join("movie.001")).unwrap(),
            raw[..cut],
            "order {t}"
        );
        assert_eq!(
            std::fs::read(dir.join("movie.002")).unwrap(),
            raw[cut..],
            "order {t}"
        );
        assert_eq!(
            dir_files(dir),
            vec!["movie.001".to_string(), "movie.002".to_string()],
            "order {t}: {:?}",
            rep.fallbacks
        );
    });
}

/// Negative control: a single `inner.zip` inside the store RAR is not a
/// split part under either grammar, so no set opens, nothing is
/// declared on the child, and it takes the single-container attach it
/// always took (TODO 94's 2 Aug shape, unchanged).
#[test]
fn nested_single_zip_never_opens_a_split_set() {
    let a = payload(120_000, 188);
    let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
    let outer = store_outer("inner.zip", &arch);
    feed_orders("zip-nested-single-ctl", &outer, |t, dir, ex, rep| {
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
        assert_eq!(dir_files(dir), vec!["a.bin".to_string()], "order {t}");
        let (decl, open) = split_state(ex);
        assert!(
            decl.is_empty(),
            "order {t}: a single zip must not be declared: {decl:?}"
        );
        assert!(open.is_empty(), "order {t}");
    });
}

/// The nested zip gate still rules: with `NZBFAST_NO_NESTED_ZIP` the
/// parent opens the set (it knows nothing of the child's gates), the
/// child's attach declines every part, and the late count finds no
/// pending set - the parts materialize for the disk pass as before.
#[test]
fn nested_zip_split_with_the_nested_gate_off_materializes() {
    let a = payload(200_000, 189);
    let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
    let parts = split_zip(&arch, 2);
    let outer = fixtures::rar5_volume(&[
        whole("inner.zip.001", &parts[0]),
        whole("inner.zip.002", &parts[1]),
    ]);
    let dir = tmpdir("zip-nested-split-gate-off");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.inner.lock().unwrap().nested_zip_on = false;
    feed(&ex, 0, "v.rar", &outer, 7000, 93);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("inner.zip.001")).unwrap(), parts[0]);
    assert_eq!(std::fs::read(dir.join("inner.zip.002")).unwrap(), parts[1]);
    assert!(!dir.join("a.bin").exists());
    let (decl, open) = split_state(&ex);
    assert_eq!(
        decl,
        vec![("inner.zip".to_string(), Some(2))],
        "counted, unused"
    );
    assert!(open.is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A nested split's outer archive, `n` parts and a trailing readme, as
/// the budget tests build it: `set` is the zip's EXACT byte length
/// (the payload is sized back from the container overhead), so a test
/// can put the set a single byte either side of a cap.
fn sized_split_outer(set: usize, n: usize, seed: u8) -> (Vec<u8>, Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
    let probe = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored(
        "a.bin",
        &payload(1000, seed),
    )]);
    let a = payload(set - (probe.len() - 1000), seed);
    let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
    assert_eq!(
        arch.len(),
        set,
        "the overhead must not depend on the payload length"
    );
    let parts = split_zip(&arch, n);
    assert_eq!(parts.len(), n);
    let readme = payload(2_000, seed.wrapping_add(1));
    let names: Vec<String> = (1..=n).map(|i| format!("inner.zip.{i:03}")).collect();
    let mut entries: Vec<Piece> = names
        .iter()
        .zip(parts.iter())
        .map(|(nm, p)| whole(nm, p))
        .collect();
    entries.push(whole("readme.txt", &readme));
    (fixtures::rar5_volume(&entries), a, parts, readme)
}

/// The bound `zip_split.rs`'s module doc reasons about, MEASURED (22
/// Aug 2026, ladder in the commit that added this test): the count
/// can only land behind the set's last byte, so the set holds every
/// byte until then and the chase budget is the one thing that bounds
/// it. Against the 8 MiB floor a 3-part set one-passes at `cap - 149`
/// bytes and forfeits at `cap - 148`, in natural and shuffled order
/// alike - the 149 is the OUTER volume's own header bytes (24 for the
/// archive head, ~33 per part header, 26 for the readme's), charged on
/// the same chain-wide budget as the set; without the readme it is
/// 123, with two parts 90. So the threshold is `holds cap - outer
/// header bytes`, and the peak held is the whole set plus those
/// headers: at 45% of a 16 GiB host that is a 7.2 GiB set resident.
///
/// Both sides of the line here, one byte apart, so a change in what the
/// budget charges moves the test. The forfeit road must deliver every
/// part byte-exact under its own name (the disk pass's input) with the
/// readme beside them and no payload invented, and the count must
/// still have been delivered - the demote is the budget's, not the
/// walk's.
#[test]
fn nested_zip_split_one_passes_to_the_holds_cap_and_forfeits_one_byte_over() {
    const CAP: usize = 8 << 20; // set_holds_cap floors here
    const OUTER_HDR: usize = 149;
    for (t, (set, forfeits)) in [(CAP - OUTER_HDR, false), (CAP - OUTER_HDR + 1, true)]
        .into_iter()
        .enumerate()
    {
        let (outer, a, parts, readme) = sized_split_outer(set, 3, 192);
        let dir = tmpdir(&format!("zip-nested-split-cap{t}"));
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_holds_cap(1);
        feed(&ex, 0, "v.rar", &outer, 700_000, 95);
        let rep = ex.finish().unwrap();
        let (decl, open) = split_state(&ex);
        assert_eq!(decl, vec![("inner.zip".to_string(), Some(3))], "leg {t}");
        assert!(open.is_empty(), "leg {t}");
        assert_eq!(
            std::fs::read(dir.join("readme.txt")).unwrap(),
            readme,
            "leg {t}"
        );
        if forfeits {
            assert!(
                !rep.fallbacks.is_empty()
                    && rep
                        .fallbacks
                        .iter()
                        .all(|(_, w)| w == "nested fallback: inner holds budget exceeded"),
                "leg {t}: {:?}",
                rep.fallbacks
            );
            for (i, p) in parts.iter().enumerate() {
                let name = format!("inner.zip.{:03}", i + 1);
                assert_eq!(
                    std::fs::read(dir.join(&name)).unwrap(),
                    *p,
                    "leg {t}: {name} lost bytes across the forfeit"
                );
            }
            assert!(
                !dir.join("a.bin").exists(),
                "leg {t}: no payload from a forfeited set"
            );
            assert_eq!(
                dir_files(&dir),
                vec![
                    "inner.zip.001".to_string(),
                    "inner.zip.002".to_string(),
                    "inner.zip.003".to_string(),
                    "readme.txt".to_string()
                ],
                "leg {t}"
            );
        } else {
            assert!(rep.fallbacks.is_empty(), "leg {t}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "leg {t}");
            assert_eq!(
                dir_files(&dir),
                vec!["a.bin".to_string(), "readme.txt".to_string()],
                "leg {t}"
            );
        }
        // The whole set is resident until the count lands, plus the
        // outer headers - and nothing more. Measured exactly `set +
        // 149` on both legs; the slack covers a header-size drift.
        let peak = ex.holds_peak();
        assert!(
            peak >= set && peak <= set + 2 * OUTER_HDR,
            "leg {t}: peak {peak} against a {set}-byte set"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The OTHER bound the ladder found, which the module doc does not
/// name: a PART larger than the per-slot pre-sniff window
/// (`unclassified_spill`, a quarter of the cap) whose byte 0 arrives
/// after that much of it has been held spills to Plain - `head_grace`
/// is root-only, so a nested slot gets no wait for its late head - and
/// a set with a Plain part can never complete: at finish it aborts
/// unresolved. Measured 22 Aug 2026 at a 32 MiB cap: a 30 MiB set in
/// three 10 MiB parts forfeited on 2 of 5 shuffles while the same set
/// in six 5 MiB parts, or the same three parts at a 64 MiB cap, never
/// did. Independent of the set bound above (the set here is well under
/// the cap), and per part, so at 45% of a 16 GiB host it is a 1.8 GiB
/// part with a late head. Pinned with the head of part 2 withheld to
/// the end, so the order is the test's and not a seed's. The forfeit
/// road is still byte-exact.
#[test]
fn nested_zip_split_part_over_the_pre_sniff_window_with_a_late_head_forfeits() {
    const CAP: usize = 16 << 20; // unclassified_spill = 4 MiB
    let (outer, _a, parts, readme) = sized_split_outer(15 << 20, 3, 194);
    assert!(
        parts[1].len() > unclassified_spill(CAP),
        "part 2 must exceed the window"
    );
    // The article holding part 2's byte 0: a RAR5 file header ends on
    // the name, and the data follows it. (Not a search for the data
    // itself - `payload` has period 256, so a window of it matches
    // inside part 1 first.)
    let name = b"inner.zip.002";
    let p2_head = outer
        .windows(name.len())
        .position(|w| w == name)
        .expect("part 2's header must sit in the outer")
        + name.len();
    assert_eq!(&outer[p2_head..p2_head + 64], &parts[1][..64]);
    let art = 700_000usize;
    let head_art = p2_head / art;
    let dir = tmpdir("zip-nested-split-late-head");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_holds_cap(CAP);
    let n_arts = outer.len().div_ceil(art);
    for i in (0..n_arts).filter(|&i| i != head_art).chain([head_art]) {
        let s = i * art;
        let e = (s + art).min(outer.len());
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
    }
    let rep = ex.finish().unwrap();
    // Part 1 classified and its worker parked on the resolve, so finish
    // aborts the incomplete set under the worker's wording. (Withhold
    // part 1's OWN head instead and the set never opens a worker at
    // all: that is the "zip split set never found its first part"
    // arm.) No entry name leaks either way, and the spilled part is
    // absent from the list: it was Plain before the set demoted.
    assert_eq!(
        rep.fallbacks,
        vec![
            (
                "inner.zip.001".to_string(),
                "nested fallback: chase set aborted before it resolved".to_string()
            ),
            (
                "inner.zip.003".to_string(),
                "nested fallback: chase set aborted before it resolved".to_string()
            ),
        ]
    );
    let (decl, open) = split_state(&ex);
    assert_eq!(
        decl,
        vec![("inner.zip".to_string(), Some(3))],
        "counted, unusable"
    );
    assert!(open.is_empty());
    for (i, p) in parts.iter().enumerate() {
        let name = format!("inner.zip.{:03}", i + 1);
        assert_eq!(std::fs::read(dir.join(&name)).unwrap(), *p, "{name}");
    }
    assert_eq!(std::fs::read(dir.join("readme.txt")).unwrap(), readme);
    assert!(!dir.join("a.bin").exists());
    assert!(
        ex.holds_peak() < CAP,
        "the set bound must not be what fired: peak {}",
        ex.holds_peak()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
