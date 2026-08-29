//! TODO 311: a post that ships ONE recovery set PER FILE.
//!
//! GH #63's reporter posted eighteen tracks, eighteen `.par2` index
//! files, each set covering exactly one track. His log read
//! `[par2] set live: 1 file(s)` and `[verify] verified 1 file(s)`:
//! `live::pick_set` took the largest single set and dropped the other
//! seventeen in silence, so seventeen tracks were never verified and the
//! job reported clean.
//!
//! A child module in a sibling dir (the `e2e_repair` pattern) so e2e.rs
//! stays inside its size-gate baseline; the harness comes through
//! `super::*`.

use super::*;

/// A payload no OTHER `unshared_payload` seed shares a PAR2 block with.
///
/// `e2e.rs`'s own `payload(n, seed)` cannot do this job, and the
/// difference is not cosmetic. It is `(i * 37 + seed + (i >> 9)) as u8`,
/// which is one periodic sequence that a change of `seed` merely SHIFTS
/// - measured over the three 400,000-byte tracks below, all 250 of
/// track01's damaged 200-byte blocks appear verbatim inside track02,
/// and vice versa. A repair over such a fixture is satisfied entirely by
/// the extra-file adoption scan (`0 block(s) rebuilt ... 250 block(s)
/// adopted from track02.bin`), which is a correct adoption of genuinely
/// matching bytes and a useless test of Reed-Solomon per set: it greens
/// whether or not each set ever found its own parity. An xorshift keeps
/// the three payloads block-disjoint, so every block this leg heals has
/// to come out of that set's OWN recovery slices.
fn unshared_payload(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 33) as u8
        })
        .collect()
}

/// `add_par2`, but one INDEPENDENT recovery set per file - the shape
/// #63's poster used. `Fixture::add_par2` runs one `par2 create` over
/// every named file, which is one set covering all of them; this runs
/// one per file, each with its own base name, so the post carries N
/// sets with N distinct recovery-set ids and N (possibly different)
/// block sizes.
fn add_par2_per_file(fx: &mut Fixture, redundancy: u32, files: &[&str], art_size: usize) -> bool {
    add_par2_per_file_named(fx, redundancy, files, None, art_size)
}

/// `add_par2_per_file`, but the set BASE NAMES come from `bases` rather
/// than from each payload's own stem - `par2 create -q cd1.par2
/// track01.bin`, which is the ordinary way to post a multi-disc or
/// multi-part release. Passing `None` keeps the payload-stem naming.
fn add_par2_per_file_named(
    fx: &mut Fixture,
    redundancy: u32,
    files: &[&str],
    bases: Option<&[&str]>,
    art_size: usize,
) -> bool {
    for (i, f) in files.iter().enumerate() {
        let base = match bases {
            Some(b) => b[i],
            None => f.rsplit_once('.').map_or(*f, |(stem, _)| stem),
        };
        let st = Command::new("par2")
            .arg("create")
            .arg(format!("-r{redundancy}"))
            .arg("-q")
            .arg(format!("{base}.par2"))
            .arg(f)
            .current_dir(&fx.dir)
            .status();
        match st {
            Ok(s) if s.success() => {}
            _ => return false,
        }
        let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                (p.extension().is_some_and(|x| x == "par2")).then_some(p)
            })
            .collect();
        par2s.sort();
        for p in par2s {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            let data = std::fs::read(&p).unwrap();
            let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
            let segs = make_file_articles(&name, &data, art_size, &tag, &mut fx.articles);
            fx.nzb_files.push((name, segs));
            std::fs::remove_file(&p).unwrap();
        }
    }
    true
}

/// TODO 311, the VERIFICATION half: every set in the post is adopted, so
/// every file it covers is verified.
///
/// Before the fix this reported `verified 1 file(s)` on a three-set post
/// and called the job clean - which is #63's log exactly.
#[tokio::test(flavor = "multi_thread")]
async fn every_recovery_set_in_a_per_file_post_is_adopted() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("multiset-adopt");
    let tracks: Vec<(String, Vec<u8>)> = (1..=3)
        .map(|i| (format!("track{i:02}.bin"), payload(400_000, i as u8 * 11)))
        .collect();
    for (name, data) in &tracks {
        fx.add_file(name, data, 50_000);
    }
    let names: Vec<&str> = tracks.iter().map(|(n, _)| n.as_str()).collect();
    assert!(add_par2_per_file(&mut fx, 20, &names, 50_000));

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{log}");
    assert!(
        log.contains("verified 3 file(s)"),
        "a three-set post must verify all three files, not one:\n{log}"
    );
    // TODO 311 item 5: the banner must SAY it adopted three sets. Before
    // the fix it read "set live: 1 file(s)" on a post that had just
    // fetched three index files, which is why #63 needed a reporter's
    // log to find. `set live` stays the literal prefix so nothing that
    // greps for it goes quietly unmatched.
    assert!(
        log.contains("[par2] set live: 3 sets, 3 file(s)"),
        "the banner must name how many sets were adopted:\n{log}"
    );
}

/// TODO 311, the REPAIR half - the claim §311 could only INFER from
/// `settle.rs` branching on the single adopted set.
///
/// One article is damaged in EVERY track, so whichever set `pick_set`
/// would have adopted, at least two damaged files sit outside it. Each
/// set carries 20% redundancy over its own file, so every one of them is
/// repairable ON ITS OWN - a failure here is the adoption, never the
/// parity.
#[tokio::test(flavor = "multi_thread")]
async fn damage_outside_the_largest_set_is_still_repaired() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("multiset-repair");
    let tracks: Vec<(String, Vec<u8>)> = (1..=3)
        .map(|i| (format!("track{i:02}.bin"), payload(400_000, i as u8 * 11)))
        .collect();
    for (name, data) in &tracks {
        fx.add_file(name, data, 50_000);
    }
    let names: Vec<&str> = tracks.iter().map(|(n, _)| n.as_str()).collect();
    assert!(add_par2_per_file(&mut fx, 20, &names, 50_000));

    // One mid-file article per track. `make_file_articles` tags each
    // file `track01_bin-<n>`, so the key carries the track name.
    let corrupt: std::collections::HashSet<String> = (1..=3)
        .map(|i| {
            let stem = format!("track{i:02}_bin");
            fx.articles
                .keys()
                .find(|k| k.contains(&stem) && k.ends_with("-3@mock>"))
                .unwrap_or_else(|| panic!("no article 3 for {stem}"))
                .clone()
        })
        .collect();
    let chaos = Chaos {
        corrupt,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "damaged per-file-set post did not finish clean:\n{log}");
    // Compared as a boolean, never with `assert_eq!` on the bytes: a
    // mismatch would otherwise print two 400 KB vectors into the run.
    for (name, data) in &tracks {
        let got = std::fs::read(fx.dir.join("out").join(name)).unwrap_or_default();
        assert!(
            got == *data,
            "{name} was not repaired ({} bytes on disk of {} expected) - \
             its set was never adopted:\n{log}",
            got.len(),
            data.len()
        );
    }
}

/// The other side of "adopt every set": a set whose files are NOT IN
/// THE POST AT ALL, because the poster left a DIFFERENT release's
/// `.par2` in the NZB.
///
/// Adopting every set is right for the complements above and has to be
/// harmless here. Every file the stray declares is unclaimed, and an
/// unclaimed set file is charged to `damage` and rebuilt from parity -
/// which for this set means pulling recovery for a release that was
/// never posted, and failing a job whose own payload is perfect.
///
/// Nothing in the packets separates this from the par-only shape (every
/// payload article lost, and parity is exactly what rebuilds it - bench
/// leg a2-par-only), so the shape is worth a pin either way: whatever
/// mechanism keeps it green, a change that loses it turns a clean
/// download into a failed one.
///
/// The stray declares MORE files than the real release, deliberately.
/// Under the old `max_by_key` rule that is the set that would have been
/// adopted, taking the real one with it; under the new rule size no
/// longer decides anything, and this pins that it does not.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovery_set_for_a_release_that_is_not_in_the_post_does_not_fail_the_job() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("multiset-stray");
    let mine = payload(400_000, 5);
    fx.add_file("mine.bin", &mine, 50_000);
    assert!(add_par2_per_file(&mut fx, 20, &["mine.bin"], 50_000));

    // The other release: its files exist only long enough for par2 to
    // describe them, and only the RECOVERY SETS are posted.
    let elsewhere = ["elsewhere-a.bin", "elsewhere-b.bin"];
    for (i, n) in elsewhere.iter().enumerate() {
        std::fs::write(fx.dir.join(n), payload(250_000, 71 + i as u8)).unwrap();
    }
    assert!(add_par2_per_file(&mut fx, 20, &elsewhere, 50_000));
    for n in elsewhere {
        std::fs::remove_file(fx.dir.join(n)).unwrap();
    }

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();

    assert!(
        ok,
        "another release's recovery set failed a clean download:\n{log}"
    );
    let got = std::fs::read(fx.dir.join("out/mine.bin")).unwrap_or_default();
    assert!(
        got == mine,
        "the post's own payload is {} bytes on disk of {} expected:\n{log}",
        got.len(),
        mine.len()
    );
    for n in elsewhere {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "{n} belongs to another release and was rebuilt from parity anyway:\n{log}"
        );
    }
}

/// The same three-set post as
/// `damage_outside_the_largest_set_is_still_repaired`, with ONE change:
/// each set's base name is a RELEASE name (`cd1`, `cd2`, `cd3`) rather
/// than its payload's stem. That is an ordinary way to post a
/// multi-disc release, and it is the shape TODO 311's name-affinity
/// filter cannot see - `repair::recovery_candidates` matches a volume's
/// base against the set's own FileDesc PAYLOAD names, so a
/// release-shaped base is affine to nothing, the none-affine fallback
/// fires by design, and every set is offered every other set's parity.
///
/// On origin/main at `b5e8f0717` that returned exit 0 and
/// `repair complete ✔` over two files holed with 49,805 and 49,804 zero
/// bytes at offset 100,000 - a clean verdict over wrong bytes, which is
/// the worst thing a repair can print. The 28 Aug 2026 multi-set
/// follow-ups note records that shape and argues it is unreachable;
/// section 4 of
/// `research/VOLUME-ATTRIBUTION-BY-CONTENT-2026-08-29.md` measures
/// that it is reachable, and this is that measurement as a pin.
#[tokio::test(flavor = "multi_thread")]
async fn a_release_named_multi_set_post_never_greens_over_a_holed_file() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("multiset-relnamed");
    let tracks: Vec<(String, Vec<u8>)> = (1..=3)
        .map(|i| (format!("track{i:02}.bin"), unshared_payload(400_000, i)))
        .collect();
    for (name, data) in &tracks {
        fx.add_file(name, data, 50_000);
    }
    let names: Vec<&str> = tracks.iter().map(|(n, _)| n.as_str()).collect();
    assert!(add_par2_per_file_named(
        &mut fx,
        20,
        &names,
        Some(&["cd1", "cd2", "cd3"]),
        50_000
    ));

    let corrupt: std::collections::HashSet<String> = (1..=3)
        .map(|i| {
            let stem = format!("track{i:02}_bin");
            fx.articles
                .keys()
                .find(|k| k.contains(&stem) && k.ends_with("-3@mock>"))
                .unwrap_or_else(|| panic!("no article 3 for {stem}"))
                .clone()
        })
        .collect();
    let chaos = Chaos {
        corrupt,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    // Compared as a boolean, never with `assert_eq!` on the bytes: a
    // mismatch would otherwise print two 400 KB vectors into the run.
    for (name, data) in &tracks {
        let got = std::fs::read(fx.dir.join("out").join(name)).unwrap_or_default();
        assert!(
            got == *data,
            "{name} is wrong on disk ({} bytes of {} expected, job ok={ok}) - \
             a repair must never green over a file it did not make whole:\n{log}",
            got.len(),
            data.len()
        );
    }
    assert!(ok, "damaged release-named per-file-set post failed:\n{log}");
}

/// The MIXTURE the stray-release guard could not tell FROM a stray: a
/// per-file-set post where one file the post OFFERED was taken down
/// whole, its siblings arriving perfectly (#63's eighteen tracks with
/// seventeen of them healthy, at the three the rig uses).
///
/// That set has no claims and a sibling that does, which is the guard's
/// exact fingerprint, so it was skipped as another release's - about the
/// reporter's OWN track. `names_offered_by_the_post` is the discriminator
/// the PACKETS cannot carry: the NZB names the file, so the post offered
/// it and its absence is damage to charge, not a stray to ignore.
///
/// MEASURED at `d1516104a`, the origin/main this was written against and
/// the tree the guard landed on: this leg exits 1 with `track03.bin` at
/// 0 bytes of 400000, having logged that it was `named by a recovery set
/// that matched nothing in this post ... treating it as a different
/// release's set`, with the parity that rebuilds it sitting unfetched in
/// the NZB.
///
/// 100% redundancy on the taken-down track deliberately, and it is the
/// whole leg rather than a convenience: at the 20% its siblings carry, a
/// wholly-absent file is unrepairable either way and the guard costs only
/// a wrong sentence. The consequence is visible only where the parity CAN
/// rebuild it - the par-only shape (bench leg a2-par-only) mixed in among
/// healthy siblings, which is exactly what this is.
///
/// `a_recovery_set_for_a_release_that_is_not_in_the_post_does_not_fail_the_job`
/// above is this leg's negative control and must stay green beside it: an
/// offered-census that answered yes to everything passes this one and
/// fails that one.
#[tokio::test(flavor = "multi_thread")]
async fn a_set_whose_file_the_post_offered_and_lost_whole_is_still_rebuilt() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("multiset-mixture");
    let tracks: Vec<(String, Vec<u8>)> = (1..=3)
        .map(|i| (format!("track{i:02}.bin"), payload(400_000, i as u8 * 11)))
        .collect();
    for (name, data) in &tracks {
        fx.add_file(name, data, 50_000);
    }
    assert!(add_par2_per_file(
        &mut fx,
        20,
        &["track01.bin", "track02.bin"],
        50_000
    ));
    assert!(add_par2_per_file(&mut fx, 100, &["track03.bin"], 50_000));

    // Every payload article of track 3, and none of its recovery data:
    // `make_file_articles` tags the payload `track03_bin-<n>` and the
    // volumes `track03_vol00+NN_par2-<n>`, so the stem separates them.
    let gone: std::collections::HashSet<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("track03_bin-"))
        .cloned()
        .collect();
    assert!(!gone.is_empty(), "no payload articles found for track03");
    let chaos = Chaos {
        missing: gone,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();

    assert!(
        !log.contains("treating it as a different release's set"),
        "track03.bin is in this NZB - the post offered it:\n{log}"
    );
    assert!(ok, "a taken-down track with its own parity posted:\n{log}");
    // Compared as a boolean, never with `assert_eq!` on the bytes: a
    // mismatch would otherwise print two 400 KB vectors into the run.
    let got = std::fs::read(fx.dir.join("out").join(&tracks[2].0)).unwrap_or_default();
    assert!(
        got == tracks[2].1,
        "track03.bin was not rebuilt ({} bytes on disk of {} expected):\n{log}",
        got.len(),
        tracks[2].1.len()
    );
}

/// TODO 311 follow-on B: the §146 tail give-up across EVERY adopted set,
/// end to end.
///
/// Two tracks, one recovery set each, and one article of EACH refused by
/// every server. That is the tail stall the give-up exists for - the
/// wire carrying nothing but "no such article" while both tracks' own
/// parity sits on the server unfetched - and on a per-file-set post the
/// single-set arm could not act on it at either step. Its candidate map
/// is one set's, so track02's walker read as an article repair cannot
/// rebuild; that vetoed the trade for track01's walker too, AND
/// suppressed the standing order that makes the spec prefetch go and
/// fetch the parity in the first place, so the margin could never grow
/// into one. Both are per set now.
///
/// The assertion is the LOG rather than the outcome, deliberately: a run
/// that never gives up still repairs after the ladder finishes and still
/// exits 0, so the outcome alone cannot tell the two apart. What the
/// outcome IS good for is the safety half - both tracks byte-exact says
/// no article was abandoned off a sibling set's parity, which is the one
/// permanent loss this widening must never take.
///
/// Four servers and a slow refusal give the census a wide window: each
/// un-echoed 430 buys a confirming repeat, so a refused article is asked
/// up to eight times before it goes terminal.
#[tokio::test(flavor = "multi_thread")]
async fn the_tail_give_up_reaches_every_set_in_a_per_file_post() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("multiset-tail-giveup");
    let tracks: Vec<(String, Vec<u8>)> = (1..=2)
        .map(|i| (format!("track{i:02}.bin"), payload(400_000, i as u8 * 17)))
        .collect();
    for (name, data) in &tracks {
        fx.add_file(name, data, 50_000);
    }
    let names: Vec<&str> = tracks.iter().map(|(n, _)| n.as_str()).collect();
    assert!(add_par2_per_file(&mut fx, 30, &names, 50_000));

    // One article per track, refused by every server. `make_file_
    // articles` tags each file `track01_bin-<n>`, so the key carries
    // the track name.
    let missing: std::collections::HashSet<String> = (1..=2)
        .map(|i| {
            let stem = format!("track{i:02}_bin");
            fx.articles
                .keys()
                .find(|k| k.contains(&stem) && k.ends_with("-4@mock>"))
                .unwrap_or_else(|| panic!("no article 4 for {stem}"))
                .clone()
        })
        .collect();
    let chaos = || Chaos {
        missing: missing.clone(),
        missing_delay_ms: 700,
        ..Default::default()
    };
    let mut srvs = Vec::new();
    for _ in 0..4 {
        srvs.push(MockServer::start(fx.articles.clone(), chaos()).await);
    }
    let refs: Vec<&MockServer> = srvs.iter().collect();
    let cfg = fx.write_config(&refs);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "the per-file-set post did not finish clean:\n{log}");
    assert!(
        log.contains("[par2] set live: 2 sets"),
        "both sets must be adopted before the give-up has anything to widen over:\n{log}"
    );
    assert!(
        log.contains("tail give-up:"),
        "the give-up never fired on a two-set post whose every walker its own \
         set's parity covers - which is what taking one representative set cost:\n{log}"
    );
    // The safety half. A give-up that abandoned an article off the WRONG
    // set's parity leaves a hole repair cannot fill; byte-exact is the
    // only thing that says it did not.
    for (name, data) in &tracks {
        let got = std::fs::read(fx.dir.join("out").join(name)).unwrap_or_default();
        assert!(
            got == *data,
            "{name} is {} bytes on disk of {} expected - an article was given up \
             against parity that does not cover it:\n{log}",
            got.len(),
            data.len()
        );
    }
}
