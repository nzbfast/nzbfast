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
use crate::payloads;

/// How much parity a fixture asks `par2 create` for.
///
/// `Pct` is par2's own `-r`, and it is CAPPED AT 100 - not by taste, by
/// the tool. par2cmdline refuses anything above with `Invalid redundancy
/// option: -rNNN` and a non-zero exit, and THE DEV MAC DOES NOT: version
/// 1.2.0 relaxed that hard cap to a warning (`WARNING: Creating recovery
/// file(s) with 130% redundancy.`) while the `par2` apt installs on the
/// CI runners still refuses. So a leg written with `-r130` builds here,
/// on the one box anybody would test it on, and on no runner - which is
/// exactly what took `long-suites` AND `one-process-heavy` red on
/// 31 Aug 2026 (nightly run 33376949508, sha 9e1478f7). Both jobs failed
/// in 0.013 s at `.expect("par2 create (bravo)")`, in FIXTURE SETUP,
/// before a line of nzbfast ran, and nothing in the tree could see it:
/// every gate is a source scan and this is a property of the binary on
/// the far end of `Command::new("par2")`.
///
/// `Blocks` is `-c`, the recovery-block COUNT, which carries no such cap
/// in any par2cmdline and is what a set meant to rebuild a WHOLLY
/// missing member actually means - a count of blocks, not a ratio.
///
/// Measured 31 Aug 2026 over this fixture's own geometry, a
/// 200 000-byte member at 10 004-byte blocks (20 blocks): `-c26` emits
/// byte-for-byte the volume set `-r130` did, and `-r100` is exactly
/// `-c20`. So the two legs below keep the parity budget they were
/// written with; only the spelling that reaches par2 changed.
///
/// The assertion fires on the dev box the moment a percentage goes over,
/// whatever wrapper the value arrived through - which is the half a
/// static scan cannot do here, since the 130 sat two calls away from the
/// `-r` that carried it. THAT IS NOT A HYPOTHETICAL AND IT PAID FOR
/// ITSELF ON ITS FIRST RUN: the guard immediately refused a SECOND
/// instance the nightly had never seen, `run_asymmetric_sets`' `-r150`
/// (`74382d45a`, landed hours AFTER run 33376949508), which would have
/// taken both jobs red again tonight on two more tests. A scan written
/// against the two known call sites would have shipped blind to it; a
/// scan written to resolve wrappers would have had to resolve a
/// different wrapper. `-c60` is byte-for-byte that set too.
///
/// The sibling copies of these helpers in
/// `e2e_lateset/`, `e2e_norar/` and the rest are all at 100 or below
/// today (measured, every call site in `crates/`), so this guards the
/// file the defect happened in and does not sweep them.
#[derive(Clone, Copy)]
enum Parity {
    /// par2 `-r`: a percentage of the source block count. Max 100.
    Pct(u32),
    /// par2 `-c`: an explicit recovery-block count, uncapped.
    Blocks(u32),
}

impl Parity {
    fn arg(self) -> String {
        match self {
            Parity::Pct(n) => {
                assert!(
                    n <= 100,
                    "par2 refuses `-r{n}`: redundancy over 100% is `Invalid redundancy option` \
                     on the CI runners' par2cmdline and only a warning on the dev Mac's 1.2.0. \
                     Ask for the recovery-block COUNT instead - `Parity::Blocks(n)`, par2's -c."
                );
                format!("-r{n}")
            }
            Parity::Blocks(n) => format!("-c{n}"),
        }
    }
}

/// The guard above is the whole point of the type, so pin it. Neither of
/// these needs par2 on the box - they read what would be handed to it.
#[test]
fn a_percentage_par2_would_refuse_is_refused_here_first() {
    assert_eq!(Parity::Pct(100).arg(), "-r100");
    assert_eq!(Parity::Blocks(26).arg(), "-c26");
    // The count form is what carries a set past 100% of its member, so
    // it must NOT inherit the cap.
    assert_eq!(Parity::Blocks(400).arg(), "-c400");
    let over = std::panic::catch_unwind(|| Parity::Pct(101).arg());
    assert!(
        over.is_err(),
        "-r101 builds on the dev Mac's par2cmdline 1.2.0 and is `Invalid redundancy option` \
         on the runners', which is how nightly run 33376949508 went red - so it must not \
         survive being spelled here"
    );
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
            .arg(Parity::Pct(redundancy).arg())
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
        .map(|i| {
            (
                format!("track{i:02}.bin"),
                payloads::unique_payload(400_000, i * 11),
            )
        })
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
        .map(|i| {
            (
                format!("track{i:02}.bin"),
                payloads::unique_payload(400_000, i * 11),
            )
        })
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
    let mine = payloads::unique_payload(400_000, 5);
    fx.add_file("mine.bin", &mine, 50_000);
    assert!(add_par2_per_file(&mut fx, 20, &["mine.bin"], 50_000));

    // The other release: its files exist only long enough for par2 to
    // describe them, and only the RECOVERY SETS are posted.
    let elsewhere = ["elsewhere-a.bin", "elsewhere-b.bin"];
    for (i, n) in elsewhere.iter().enumerate() {
        std::fs::write(
            fx.dir.join(n),
            payloads::unique_payload(250_000, 71 + i as u64),
        )
        .unwrap();
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
        .map(|i| {
            (
                format!("track{i:02}.bin"),
                payloads::unique_payload(400_000, i),
            )
        })
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

    // THE SCOPING ITSELF, and not merely the bytes on disk being right.
    // The assertion above says the job did not green over a hole; this
    // one says each set bought ITS OWN parity to do it.
    //
    // Every stem here is `track01.bin` and every volume base is `cd1`,
    // `cd2` or `cd3`, so `repair::recovery_candidates`'s payload-name
    // arm makes nothing affine and the none-affine fallback offers each
    // set all three sets' volumes. The INDEX-NAME rule (31 Aug 2026)
    // reads `cd1.par2` off disk, finds this set's id in its packets, and
    // scopes the list to the base par2cmdline gave that set - zero round
    // trips, because the index was downloaded long before any repair
    // asked.
    //
    // MEASURED both ways on this leg, which is where the threshold comes
    // from rather than from taste. Unscoped: SEVEN fetches totalling
    // 9.3 MB - six of 0.7 MB plus one 5.1 MB escalation that buys every
    // remaining volume in the post - and all three mapped repairs
    // DECLINE, healing on the disk path after materialize instead
    // (13.7 s). Scoped: THREE fetches of 0.8 MB, 2.4 MB in total, every
    // mapped repair carrying its set first time (9.2 s). The whole
    // post's parity is ~5.1 MB, so 4.0 MB separates "each set bought its
    // own" from "the sets bought each other's" with room on both sides.
    //
    // BYTES AND NOT THE ROUTE: which engine heals a set is a decision
    // other lanes move, and this pin must not go red about that. What it
    // asserts is the one thing this rule owns - how much recovery data
    // came off the wire.
    let recovery_mb: f64 = log
        .lines()
        .filter_map(|l| {
            l.split_once("fetched ")?
                .1
                .split_once(" MB of recovery data")
        })
        .filter_map(|(mb, _)| mb.parse::<f64>().ok())
        .sum();
    assert!(
        recovery_mb > 0.0 && recovery_mb < 4.0,
        "recovery fetched {recovery_mb:.1} MB across the job - the sets are \
         buying each other's parity again (scoped is ~2.4 MB, unscoped 9.3):\n{log}"
    );
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
        .map(|i| {
            (
                format!("track{i:02}.bin"),
                payloads::unique_payload(400_000, i * 11),
            )
        })
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
        .map(|i| {
            (
                format!("track{i:02}.bin"),
                payloads::unique_payload(400_000, i * 17),
            )
        })
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

/// How many fill tiers the starvation test stacks, and how slowly each
/// refuses. See that test's doc comment: an article must be refused by
/// every tier IN TURN before it can go terminal, so the head start
/// these buy the give-up arm is `2 * FILL_TIERS * FILL_REFUSAL_MS` (an
/// un-echoed 430 buys a confirming repeat, hence the 2), against the
/// arm's fixed 10 s grace - while the time a LOST race takes to finish
/// stays at about `30 * FILL_REFUSAL_MS`, because each added tier
/// brings its own connections. Tiers buy margin; the delay buys margin
/// and run time together, which is why the margin is spent here.
const FILL_TIERS: usize = 3;
const FILL_REFUSAL_MS: u64 = 5_000;

/// [`Fixture::write_config`] with an M14e `level` per server: 0 is a
/// primary, and a level-N server is asked for an article only once
/// every live lower-level server has already missed it
/// (`nzbkit::config::Server::level`).
///
/// It lives here rather than beside `write_config` in `e2e.rs` because
/// that file sits ONE line under its `tools/size-gate.py` ceiling, and
/// this is its only caller.
fn write_config_levels(fx: &Fixture, servers: &[(&MockServer, u32)]) -> PathBuf {
    let entries: Vec<String> = servers
        .iter()
        .map(|(s, level)| {
            format!(
                "{{\"host\":\"{}\",\"port\":{},\"tls\":false,\"level\":{level}}}",
                s.addr.ip(),
                s.addr.port()
            )
        })
        .collect();
    let path = fx.dir.join("config.json");
    std::fs::write(&path, format!("{{\"servers\":[{}]}}", entries.join(","))).unwrap();
    path
}

/// The §146 STARVATION arm, end to end: a post whose declared recovery
/// supply can never fund the give-up's 2x margin must still CONCLUDE.
///
/// Twelve of sixteen payload articles are refused by every server, and
/// the post carries -r1 parity - a few recovery blocks against a
/// walker ceiling in the hundreds. The old behaviour was the 30 Aug
/// 2026 live wedge: the spec prefetch fetched everything it had and
/// RETURNED, the give-up's veto printed "walking the ladder instead"
/// once, and the job then bought refusal verdicts for every walker at
/// provider pace - hours on a real post - with the queue row saying
/// nothing. The starvation arm turns that into a bounded wait: ladder
/// over, census still for the grace window, walkers abandoned, settle
/// runs, and the failure states the shortfall while the journal keeps
/// every byte for a retry.
///
/// WHAT KEEPS THE RACE FROM BEING A RACE, and it is NOT the refusal
/// delay this comment used to name (it also said 2000 ms while the code
/// set 2500). The arm fires a fixed 10 s grace after the census goes
/// STILL, and stillness is measured on delivery: ANY article going
/// terminal moves the owed count and restarts the clock. So what the
/// arm is racing is not the drain finishing, it is the FIRST walker
/// going terminal - once they start they arrive closer together than
/// the grace (four connections against one refusal delay each), and the
/// clock never runs to 10 s again. The primaries' delay sets when the
/// census opens AND when that first terminal lands, together, in one
/// proportion, so raising it buys both sides of the race and widens the
/// margin only by the fixed 10 s.
///
/// Measured 31 Aug 2026 on the shared dev box, the natural drain taken
/// directly by disabling the arm with `NZBFAST_NO_TAIL_GIVEUP=1` rather
/// than extrapolated: the arm fires at 28.3 s (the pool line's `drained
/// at`) against a 59.3 s drain - the whole margin was 2.1x. Under load
/// (12 concurrent runs of this test, load average 70-90) the cliff sat
/// between 1300 ms, where 10 of 12 runs lost the race, and 2500 ms,
/// where 0 of 12 did. That is the flake Y6 recorded: 2 TRY-1 failures
/// in 18 runs on origin/main, invisible in CI because `retries = 1`
/// reports a first-attempt failure as "1 flaky" at exit 0 - the
/// FORTY-FIRST gate's argument applied to an ordinary FAILURE rather
/// than to a timeout.
///
/// THE FILL TIERS ARE WHAT DECOUPLE THEM, and they are the whole fix. A
/// level-N server is asked for an article only once every live
/// lower-level server has missed it (`nzbkit::config::Server::level`),
/// so an article must be refused by each tier IN TURN before it can go
/// terminal: the head start before the first one is
/// `2 * FILL_TIERS * FILL_REFUSAL_MS` (30 s here) against a 10 s grace,
/// while the census still opens when the primaries say it does. Tiers
/// are the lever and the delay is not, because each tier brings its own
/// connections: stacking them multiplies the head start and leaves a
/// LOST race costing about `30 * FILL_REFUSAL_MS`, so a regression
/// still fails on the assertion below instead of running past a
/// per-test ceiling and reporting a timeout.
///
/// Measured the same day and the same way: the drain goes from 59.3 s
/// to 212.3 s against an unmoved 28.3 s arm, so 2.1x becomes 7.5x. Over
/// 48 runs 12-way under load the test lost the race 0 times, and it
/// still passes 12 of 12 at primary delays of 900, 600 and even 300 ms
/// - where the shape WITHOUT the tiers loses all 12 at 900 and at 600,
/// and loses both attempts at 300 on an IDLE box. So the cliff moved
/// from ~2000 ms to under 300 ms, better than 8x of it, and the run
/// costs nothing extra (30.4 s against 30.2 s): the tiers are never
/// fetched from, so their delay is margin bought for free.
///
/// THREE THINGS NOT TO DO. Do not give these tiers `echo_missing_id`:
/// an un-echoed 430 buys a confirming repeat, which is the 2 in the
/// head start above, and echoing HALVES it. Do not make a tier a server
/// that cannot ANSWER - a `body_error` tier was measured and WEDGES the
/// run (400 s with no end, against 15 s for a refusing one), because a
/// session error is not a refusal-walker, so the census never opens and
/// the arm never gets to run at all. And do not reach for the
/// primaries' delay to buy margin: it is what this test already did,
/// and 30 s of run bought 2.1x.
#[tokio::test(flavor = "multi_thread")]
async fn a_margin_no_fetch_can_meet_abandons_the_walkers_instead_of_wedging() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("multiset-tail-starved");
    let data = payloads::unique_payload(3_200_000, 77);
    fx.add_file("track01.bin", &data, 50_000);
    assert!(add_par2_per_file(&mut fx, 1, &["track01.bin"], 50_000));

    // Sixty of the sixty-four payload articles refused everywhere,
    // forever. The count sets how long the pool stays pending at all -
    // the first cut of this test used twelve and the pool drained
    // naturally at 14 s, beating the arm to the finish line - but it is
    // NOT what holds the margin open any more; the fill tier below is.
    // See the doc comment: sixty against a 2500 ms delay was measured
    // at 1.9x, which is the flake.
    let missing: std::collections::HashSet<String> = fx
        .articles
        .keys()
        .filter(|k| k.contains("track01_bin-"))
        .take(60)
        .cloned()
        .collect();
    assert_eq!(missing.len(), 60, "fixture must carry 64 payload articles");
    let chaos = || Chaos {
        missing: missing.clone(),
        missing_delay_ms: 2500,
        ..Default::default()
    };
    let mut srvs = Vec::new();
    for _ in 0..4 {
        srvs.push(MockServer::start(fx.articles.clone(), chaos()).await);
    }
    // The FILL TIERS: three more servers that do not have the articles
    // either, stacked one per level and refusing far more slowly than
    // the primaries. Nothing is ever fetched from them. Doc comment
    // above for what they buy and why there are three of them.
    let mut fills = Vec::new();
    for _ in 0..FILL_TIERS {
        fills.push(
            MockServer::start(
                fx.articles.clone(),
                Chaos {
                    missing: missing.clone(),
                    missing_delay_ms: FILL_REFUSAL_MS,
                    ..Default::default()
                },
            )
            .await,
        );
    }
    let mut tiers: Vec<(&MockServer, u32)> = srvs.iter().map(|s| (s, 0u32)).collect();
    for (i, f) in fills.iter().enumerate() {
        tiers.push((f, i as u32 + 1));
    }
    let cfg = write_config_levels(&fx, &tiers);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();

    // The job cannot succeed - the post genuinely lacks the parity -
    // and it must SAY so rather than walk the refusal ladder to
    // terminal with the give-up's veto as its final state.
    assert!(
        !ok,
        "sixty missing articles against -r1 parity repaired?!\n{log}"
    );
    assert!(
        log.contains("tail give-up: the recovery ladder is exhausted"),
        "the starvation arm never fired - the run either wedged on the veto or \
         walked every walker to terminal, which is the wait this arm removes:\n{log}"
    );
    assert!(
        log.contains("unrepairable:"),
        "settle must still run after the starved give-up and state the shortfall:\n{log}"
    );
}

// ---------------------------------------------------------------- W4-15
//
// W4-15 (30 Aug 2026 Wave-4 adversarial matrix, CONFIRMED and then
// CORRECTED by measurement). The mirror of this file's own subject:
// #63's post was one set PER FILE, disjoint; this is TWO sets over ONE
// file, overlapping. Both are "the post carries more than one recovery
// set", and both used to answer it by picking one and dropping the rest.
//
// The row predicted "selected in set order" and the probes found an
// in-stream arrival RACE: the sniff elects one bootstrap volume for the
// whole job, so only the set whose volume was sniffed first ever
// activated, and a member both sets named belonged to it alone. Measured
// with the weak set (one recovery block) winning: `native repair: 2
// block(s) damaged, only 1 recovery block(s) on disk`, job failed,
// everything quarantined - while the strong set's five volumes lay on
// disk beside it.
//
// EVERY LEG IS ORDER-CONTROLLED WITH `Chaos::stall`, which delays only a
// FIRST request, so a stalled volume still arrives - late, not absent,
// which is the whole shape: the parity that would have healed the file
// is on disk the entire time. Unstalled this was measured red about 3
// runs in 10.

/// The engine over `fx` with `chaos` injected. `MULTISET_DUMP_LOG=1`
/// prints the raw engine log under `--no-capture`.
async fn run_multiset(fx: &Fixture, chaos: Chaos) -> (String, bool, PathBuf) {
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    if std::env::var("MULTISET_DUMP_LOG").is_ok() {
        eprintln!("==== run log ====\n{log}\n==== end ====");
    }
    (log, ok, out)
}

/// Every regular file under `out`, recursively, as (relpath, len) - the
/// tree dump a failing assertion prints so a red names what DID land.
fn read_tree(out: &Path) -> Vec<(String, usize)> {
    let mut v = Vec::new();
    fn walk(dir: &Path, base: &Path, v: &mut Vec<(String, usize)>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, base, v);
            } else if let Ok(bytes) = std::fs::read(&p) {
                let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                v.push((rel, bytes.len()));
            }
        }
    }
    walk(out, out, &mut v);
    v
}

/// `Fixture::add_par2_obfuscated` with an explicit set base name and
/// block size, so one fixture can carry TWO recovery sets over the same
/// member. Returns every volume article id, which is how a `Chaos` arm
/// decides which set wins the in-stream bootstrap race.
///
/// The hash subject must be unique ACROSS sets: `base` is what separates
/// them, and two sets sharing a prefix silently overwrite each other in
/// the article map.
fn add_named_par2_obfuscated(
    fx: &mut Fixture,
    base: &str,
    parity: Parity,
    block: u64,
    files: &[&str],
    art_size: usize,
) -> Option<Vec<String>> {
    let st = Command::new("par2")
        .arg("create")
        .arg(parity.arg())
        .arg(format!("-s{block}"))
        .arg("-q")
        .arg(base)
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return None,
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    let mut ids = Vec::new();
    for (i, p) in par2s.iter().enumerate() {
        let data = std::fs::read(p).unwrap();
        let hash = format!("{base}{i:02}zXm9rTb");
        let tag = format!("{base}-obf-{i}");
        let segs = make_file_articles(&hash, &data, art_size, &tag, &mut fx.articles);
        ids.extend(segs.iter().map(|(id, _, _)| format!("<{id}>")));
        fx.nzb_files.push((hash, segs));
        std::fs::remove_file(p).unwrap();
    }
    Some(ids)
}

/// Build the W4-15 fixture: ONE damaged obfuscated payload covered by
/// TWO active recovery sets over the same member, `setalpha` at
/// `r_alpha` redundancy and `setbravo` at `r_bravo`. `stall` names the
/// set whose volumes are delayed, so the OTHER one wins the in-stream
/// bootstrap race - which is the only thing that differs between the two
/// legs below. The bytes on the wire are identical in both.
///
/// Returns the `Fixture` too, and that is not tidiness: it owns the
/// scratch guard, so dropping it here would delete the output tree
/// before the caller could grade it - a probe written the other way
/// reads as a spectacular false red (`rc ok=true, 0 of 200000 bytes`,
/// empty tree) against a directory that no longer exists.
async fn run_two_sets(
    tag: &str,
    r_alpha: Parity,
    r_bravo: Parity,
    stall: Option<&str>,
) -> (Fixture, String, bool, Vec<u8>, PathBuf) {
    let data = payloads::unique_payload(200_000, 71);
    let mut fx = Fixture::new(tag);
    std::fs::write(fx.dir.join("Twin.Payload.bin"), &data).unwrap();
    // Two sets over one member, distinguished by block size so their ids
    // differ. Blocks are 10 000 bytes, so 20 blocks of member.
    let alpha_ids = add_named_par2_obfuscated(
        &mut fx,
        "setalpha",
        r_alpha,
        10_000,
        &["Twin.Payload.bin"],
        40_000,
    )
    .expect("par2 create (alpha)");
    let bravo_ids = add_named_par2_obfuscated(
        &mut fx,
        "setbravo",
        r_bravo,
        10_004,
        &["Twin.Payload.bin"],
        40_000,
    )
    .expect("par2 create (bravo)");
    std::fs::remove_file(fx.dir.join("Twin.Payload.bin")).unwrap();
    let payload_ids: Vec<String> = {
        let before = fx.nzb_files.len();
        fx.add_file_obfuscated("Zc4hVn78Kp", "Zc4hVn78Kp", &data, 40_000);
        fx.nzb_files[before]
            .1
            .iter()
            .map(|(id, _, _)| format!("<{id}>"))
            .collect()
    };
    // Damage: one whole payload article (40 000 bytes = 4 blocks) is
    // gone. The weak set cannot cover that; the strong one can.
    let mut chaos = Chaos::default();
    chaos.missing.insert(payload_ids[1].clone());
    match stall {
        Some("alpha") => chaos.stall.extend(alpha_ids),
        Some("bravo") => chaos.stall.extend(bravo_ids),
        _ => {}
    }

    let (log, ok, out) = run_multiset(&fx, chaos).await;
    (fx, log, ok, data, out)
}

/// W4-15: two ACTIVE recovery sets name the same damaged member, one
/// with the parity to heal it and one without, and the WEAK one wins the
/// in-stream bootstrap race.
///
/// The strong set's volumes are stalled, so they still land on disk -
/// they are late, not absent. Correct result: the member is repaired
/// from whichever set can do it and the bytes land byte-exact.
#[tokio::test(flavor = "multi_thread")]
async fn the_weak_set_winning_the_race_must_still_use_the_strong_parity() {
    if !have_par2() {
        eprintln!("w4_15: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, data, out) =
        run_two_sets("w415weak", Parity::Pct(2), Parity::Pct(40), Some("bravo")).await;
    let landed = std::fs::read(out.join("Twin.Payload.bin")).unwrap_or_default();
    assert!(
        ok && landed == data,
        "the weak set won the race and owned the slot, so the strong \
         set's parity was never used for the member both sets name: \
         rc ok={ok}, {} of {} bytes; tree = {:?}\n{log}",
        landed.len(),
        data.len(),
        read_tree(&out)
    );
}

/// W4-15 (control): the same fixture with the WEAK set stalled, so the
/// strong one wins the race and owns the slot.
///
/// A green here beside the leg above is what makes the row an
/// ownership/order defect rather than a shortage of parity - the bytes
/// on the wire are identical in both, and only the arrival order moved.
#[tokio::test(flavor = "multi_thread")]
async fn control_the_strong_set_winning_the_race_repairs() {
    if !have_par2() {
        eprintln!("w4_15 control: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, data, out) =
        run_two_sets("w415strong", Parity::Pct(2), Parity::Pct(40), Some("alpha")).await;
    let landed = std::fs::read(out.join("Twin.Payload.bin")).unwrap_or_default();
    assert!(
        ok && landed == data,
        "control leg failed too - the strong set winning the race does \
         not repair either, so the row is not about ownership: rc \
         ok={ok}, {} of {} bytes\n{log}",
        landed.len(),
        data.len()
    );
}

/// W4-15 (insufficient-both control): both sets too weak for the damage.
///
/// The job must fail HONESTLY, and this is the leg that stops a
/// permissive fix from satisfying the two above: every rule the fix adds
/// - charging a shared member's damage to both sets, forgiving a set
/// whose files another set has already proved - is one that could be
/// written to forgive a job nothing repaired at all.
#[tokio::test(flavor = "multi_thread")]
async fn control_both_sets_insufficient_fails_honestly() {
    if !have_par2() {
        eprintln!("w4_15 control: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, _data, _out) =
        run_two_sets("w415none", Parity::Pct(2), Parity::Pct(2), None).await;
    assert!(
        !ok,
        "both sets lack the parity for the damage, yet the job reported \
         success\n{log}"
    );
}

// ---------------------------------------------- W4-09 residue, item 2
//
// W4-15's rule at the OTHER door. That row is a member that arrived
// DAMAGED and is named by two overlapping sets: `charge_reported_damage`
// charges the owning set AND every twin, because which set owns a slot
// is an arrival race and which set can heal it is not. The same post
// with the member lost WHOLE never reached that rule - `missing_files`
// carries a NAME, the charge loop gives it to the first set naming it,
// and `missing_file_names`' own note records the sibling as "charged
// nothing at all" and leaves it there. A set with no damage gets no
// plan, so its parity is never spent.
//
// Found (31 Aug 2026) while answering the question W4-09's fix left
// open: whether a member can be priced too LOW rather than at nothing.
// Within one set it cannot - `div_ceil` is exact in that set's own
// geometry, and any nonzero price plans the set, so the repair's own
// whole-file MD5 is the proof. ACROSS sets it can, and the price is
// zero for the sibling: measured on origin/main as `native
// repair: 20 block(s) damaged, only 1 recovery block(s) on disk` and a
// verdict reading `20 recovery block(s) needed but the NZB only carries
// 1`, which is false about a post carrying 23, with the strong set's 22
// slices already fetched and on disk.
//
// The two legs differ ONLY in which set the arrival race hands the
// member to - the bytes on the wire are identical, exactly as in the
// W4-15 pair above, which is what makes this an ownership defect rather
// than a shortage of parity. `Chaos::stall` delays a FIRST request only,
// so a stalled volume is late and never absent.

/// `run_two_sets`, but the member is lost WHOLE - every payload article
/// refused - rather than damaged in one article. Redundancy is set high
/// enough that a set which IS charged can rebuild the file from parity
/// alone (the par-only shape).
///
/// The strong leg is spelled as a BLOCK COUNT rather than a percentage,
/// and that is the point of `Parity` rather than a preference: covering
/// a wholly missing 20-block member takes at least 20 recovery blocks,
/// which is over 100% of the member, and 100% is where par2's `-r` stops
/// on every box but the dev Mac. See `Parity`.
async fn run_two_sets_whole_loss(
    tag: &str,
    r_alpha: Parity,
    r_bravo: Parity,
    stall: Option<&str>,
) -> (Fixture, String, bool, Vec<u8>, PathBuf) {
    let data = payload(200_000, 71);
    let mut fx = Fixture::new(tag);
    std::fs::write(fx.dir.join("Twin.Payload.bin"), &data).unwrap();
    let alpha_ids = add_named_par2_obfuscated(
        &mut fx,
        "setalpha",
        r_alpha,
        10_000,
        &["Twin.Payload.bin"],
        40_000,
    )
    .expect("par2 create (alpha)");
    let bravo_ids = add_named_par2_obfuscated(
        &mut fx,
        "setbravo",
        r_bravo,
        10_004,
        &["Twin.Payload.bin"],
        40_000,
    )
    .expect("par2 create (bravo)");
    std::fs::remove_file(fx.dir.join("Twin.Payload.bin")).unwrap();
    let payload_ids: Vec<String> = {
        let before = fx.nzb_files.len();
        fx.add_file_obfuscated("Zc4hVn78Kp", "Zc4hVn78Kp", &data, 40_000);
        fx.nzb_files[before]
            .1
            .iter()
            .map(|(id, _, _)| format!("<{id}>"))
            .collect()
    };
    let mut chaos = Chaos::default();
    for id in &payload_ids {
        chaos.missing.insert(id.clone());
    }
    match stall {
        Some("alpha") => chaos.stall.extend(alpha_ids),
        Some("bravo") => chaos.stall.extend(bravo_ids),
        _ => {}
    }
    let (log, ok, out) = run_multiset(&fx, chaos).await;
    (fx, log, ok, data, out)
}

/// The red leg: the WEAK set is handed the wholly missing member, and
/// the strong set - whose 22 recovery blocks are on disk - is charged
/// nothing and never planned.
#[tokio::test(flavor = "multi_thread")]
async fn a_whole_loss_charged_to_the_weak_set_must_use_the_strong_parity() {
    if !have_par2() {
        eprintln!("w4_09 item 2: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, data, out) =
        run_two_sets_whole_loss("wlweak", Parity::Pct(5), Parity::Blocks(26), Some("bravo")).await;
    let landed = std::fs::read(out.join("Twin.Payload.bin")).unwrap_or_default();
    assert!(
        ok && landed == data,
        "the set the arrival race handed the whole loss to cannot cover it, and the \
         sibling set that names the same member was charged nothing - so its parity \
         was never planned: rc ok={ok}, {} of {} bytes; tree = {:?}\n{log}",
        landed.len(),
        data.len(),
        read_tree(&out)
    );
    // Pinned by REASON as well as by rc, so a job that greens for some
    // other reason cannot stand in for the parity actually being spent.
    assert!(
        !log.contains("only 1 recovery block(s) on disk"),
        "the repair still read only the weak set's parity\n{log}"
    );
}

/// The control with the predicted trigger removed: the STRONG set is
/// handed the member, so the first-set pick is already the right one.
///
/// A green here beside the leg above is what makes the row an ownership
/// defect - identical bytes on the wire, only the arrival order moved -
/// and it was GREEN on origin/main while the leg above was red.
#[tokio::test(flavor = "multi_thread")]
async fn control_a_whole_loss_charged_to_the_strong_set_repairs() {
    if !have_par2() {
        eprintln!("w4_09 item 2 control: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, data, out) = run_two_sets_whole_loss(
        "wlstrong",
        Parity::Pct(5),
        Parity::Blocks(26),
        Some("alpha"),
    )
    .await;
    let landed = std::fs::read(out.join("Twin.Payload.bin")).unwrap_or_default();
    assert!(
        ok && landed == data,
        "control leg failed too - the strong set being charged does not rebuild the \
         whole loss either, so the row is not about which set was charged: rc \
         ok={ok}, {} of {} bytes\n{log}",
        landed.len(),
        data.len()
    );
}

// -------------------------------------- W4-09 residue (ii), 31 Aug 2026
//
// A PER-SET shortfall stated as a claim about the whole NZB.
// `RepairShortfall::Blocks` carries `have` =
// `recovery_candidates(nzb, set, ..)` folded - the volumes of ONE
// recovery set - and the clause spelled it "the NZB only carries
// {have}". Exact on the single-set post that is the overwhelming
// majority; false on a per-file-set or overlapping post, and measured
// verbatim on 31 Aug 2026 as `20 recovery block(s) needed but the NZB
// only carries 1` over a post carrying 23.
//
// Not a counting slip. `RepairShortfall`'s own doc says its two arms
// exist "because the answers are opposite": `Blocks` means the poster
// shipped too little parity and no provider could have helped, which is
// "give up" - and a per-set figure reported as the post's total says
// that about parity which was never this set's to spend.
//
// The second seam in the same family: the shortfall is assigned inside
// a PER-SET loop, so on a post with two unrepairable sets the job's
// fail message states one set's arithmetic with nothing saying which.
// Both are answered by the same change - the figure is scoped to the
// set in words, and the set is NAMED wherever the post carries more
// than one (first 8 of `par2::hex16`, the tag every `[par2]`/`[verify]`
// console line already uses).
//
// The pair below is the ownership pattern the W4-09 legs above use: the
// leg and its control run the SAME shape with the predicted trigger -
// a post carrying more than one recovery set - removed, so a red that
// is really about something else shows up as a red control.

/// The clause the job fails with, if it carried one. Isolated so an
/// assertion prints the sentence rather than a whole run log, and so a
/// leg that never reached the arithmetic at all fails saying so instead
/// of passing vacuously on a `!contains`.
fn shortfall_sentence(log: &str) -> Option<&str> {
    log.lines().find(|l| l.contains("recovery block(s) needed"))
}

/// A one-set post whose only member is lost WHOLE, with redundancy far
/// under what rebuilding it would take. The control shape: there is
/// exactly one recovery set, so there is nothing for a set tag to
/// disambiguate.
async fn run_one_set_whole_loss(tag: &str, redundancy: u32) -> (Fixture, String, bool) {
    let data = payload(200_000, 71);
    let mut fx = Fixture::new(tag);
    std::fs::write(fx.dir.join("Solo.Payload.bin"), &data).unwrap();
    add_named_par2_obfuscated(
        &mut fx,
        "setsolo",
        Parity::Pct(redundancy),
        10_000,
        &["Solo.Payload.bin"],
        40_000,
    )
    .expect("par2 create (solo)");
    std::fs::remove_file(fx.dir.join("Solo.Payload.bin")).unwrap();
    let payload_ids: Vec<String> = {
        let before = fx.nzb_files.len();
        fx.add_file_obfuscated("Qw7bTr21Ls", "Qw7bTr21Ls", &data, 40_000);
        fx.nzb_files[before]
            .1
            .iter()
            .map(|(id, _, _)| format!("<{id}>"))
            .collect()
    };
    let mut chaos = Chaos::default();
    for id in &payload_ids {
        chaos.missing.insert(id.clone());
    }
    let (log, ok, _out) = run_multiset(&fx, chaos).await;
    (fx, log, ok)
}

/// A per-file-set post (#63's shape) where ONE set is short and the
/// other has nothing to do: two files with one recovery set each, the
/// first lost WHOLE against redundancy nowhere near enough to rebuild
/// it, the second arriving clean.
///
/// This is the shape the finding names, and it is what pins the one
/// non-obvious half of the fix: the tag is scoped by how many recovery
/// sets the POST carries, not by how many took damage. `settle`'s plan
/// list is "one plan per set that took damage", so a plan count drops
/// the tag on exactly this post - the one where the old sentence was
/// most wrong, since the sibling set's parity is real, present, and
/// mathematically incapable of covering the other file.
async fn run_per_file_sets_one_short(tag: &str) -> (Fixture, String, bool) {
    let mut fx = Fixture::new(tag);
    let lost = payloads::unique_payload(200_000, 71);
    let kept = payloads::unique_payload(200_000, 23);
    fx.add_file("Lost.bin", &lost, 40_000);
    let lost_ids: Vec<String> = fx.nzb_files[0]
        .1
        .iter()
        .map(|(id, _, _)| format!("<{id}>"))
        .collect();
    fx.add_file("Kept.bin", &kept, 40_000);
    // 5% over one file is a handful of blocks - nothing like the 20 a
    // whole 200 kB member costs, so the set that is charged cannot pay.
    assert!(add_par2_per_file(
        &mut fx,
        5,
        &["Lost.bin", "Kept.bin"],
        40_000
    ));
    let mut chaos = Chaos::default();
    for id in &lost_ids {
        chaos.missing.insert(id.clone());
    }
    let (log, ok, _out) = run_multiset(&fx, chaos).await;
    (fx, log, ok)
}

/// The named leg: a per-file-set post whose short set is one of two,
/// with the other set's parity untouched and unable to help.
#[tokio::test(flavor = "multi_thread")]
async fn a_per_file_set_shortfall_is_scoped_and_names_its_set() {
    if !have_par2() {
        eprintln!("w4_09 item ii per-file: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok) = run_per_file_sets_one_short("sfxperfile").await;
    assert!(!ok, "5% cannot rebuild a member lost whole\n{log}");
    let line = shortfall_sentence(&log)
        .unwrap_or_else(|| panic!("the run never reached the block arithmetic\n{log}"));
    assert!(
        !line.contains("the NZB only carries"),
        "the other set's volumes ARE in this NZB and cannot cover this file, so a \
         per-set figure reported as the post's total is false twice over: {line}"
    );
    assert!(
        line.contains("(recovery set "),
        "the post carries two recovery sets and only one of them took damage - the \
         count that decides the tag is the POST's sets, not the damaged ones: {line}"
    );
}

/// The red leg: two recovery sets, neither able to cover the loss, so
/// the arithmetic in the fail message is one set's out of two.
///
/// Two assertions, one per seam. The figure must not be stated as a
/// property of the NZB - on origin/main this post failed `... but the
/// NZB only carries N` while its sibling set's volumes sat on disk -
/// and the sentence must name WHICH set it measured, which nothing in
/// the message did.
#[tokio::test(flavor = "multi_thread")]
async fn a_two_set_shortfall_is_scoped_and_names_its_set() {
    if !have_par2() {
        eprintln!("w4_09 item ii: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, _data, _out) =
        run_two_sets_whole_loss("sfxtwo", Parity::Pct(5), Parity::Pct(10), None).await;
    assert!(!ok, "neither set can cover a whole-file loss\n{log}");
    let line = shortfall_sentence(&log)
        .unwrap_or_else(|| panic!("the run never reached the block arithmetic\n{log}"));
    assert!(
        !line.contains("the NZB only carries"),
        "`have` is ONE recovery set's volumes; stating it as the post's total tells \
         the user the poster shorted them about parity that was never this set's to \
         spend: {line}"
    );
    // Cut at the CLOSING paren rather than trimming the tail: the CLI
    // banner (` [nzbfast <version>]`) follows the message on the same
    // line, so a right-trim keeps it and the hex test fails for a
    // reason that is nothing to do with the tag.
    let tag = line
        .split_once("(recovery set ")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(tag, _)| tag);
    let tag = tag.unwrap_or_else(|| {
        panic!("two sets came up short and the message says which one about neither: {line}")
    });
    assert!(
        tag.len() == 8 && tag.bytes().all(|b| b.is_ascii_hexdigit()),
        "the tag has to be the set id the `[par2]` lines print, so a reader can \
         correlate the two: {line}"
    );
}

/// The control with the predicted trigger removed: ONE recovery set, so
/// there is nothing to disambiguate and the tag must stay off.
///
/// It is what stops the leg above being satisfied by stamping every
/// failure with a set id - which would put an opaque hash in front of
/// every user whose post has a single set, the overwhelming majority.
/// The scoping half is asserted here too, because that half is not
/// conditional on anything.
#[tokio::test(flavor = "multi_thread")]
async fn control_a_one_set_shortfall_carries_no_set_tag() {
    if !have_par2() {
        eprintln!("w4_09 item ii control: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok) = run_one_set_whole_loss("sfxone", 10).await;
    assert!(
        !ok,
        "10% redundancy cannot rebuild a member lost whole\n{log}"
    );
    let line = shortfall_sentence(&log)
        .unwrap_or_else(|| panic!("the run never reached the block arithmetic\n{log}"));
    assert!(
        !line.contains("the NZB only carries"),
        "the scoping is unconditional - a one-set post is the case where the old \
         wording happened to be true, not a case where it is wanted: {line}"
    );
    assert!(
        !line.contains("(recovery set "),
        "one set means nothing to disambiguate, and a hash tag in a sentence a user \
         reads costs more than it says: {line}"
    );
}

/// The insufficient-both control, and it is what stops a permissive fix
/// passing the two above: charging every set that names a missing member
/// is a rule that could equally be written to forgive a job no set could
/// repair. Neither set here has the parity for a whole-file loss.
#[tokio::test(flavor = "multi_thread")]
async fn control_a_whole_loss_neither_set_can_cover_fails_honestly() {
    if !have_par2() {
        eprintln!("w4_09 item 2 control: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, _data, _out) =
        run_two_sets_whole_loss("wlnone", Parity::Pct(5), Parity::Pct(10), None).await;
    assert!(
        !ok,
        "neither set carries the parity for a whole-file loss, yet the job reported \
         success\n{log}"
    );
}

// ---------------------------- the stray-release guard reads the race
//
// `sets_with_claims` marks set N claimed only where some slot's OWNING
// descriptor is N's, and ownership is SINGULAR - `Plan::set_of` returns
// one `usize`. That is `LiveVerifier::slot_twin_damage`'s own stated
// premise: "a slot has exactly ONE owning descriptor, and which set that
// is comes down to the in-stream bootstrap race". So on a post whose
// sets overlap, the set the race did not hand the arrival to claims
// nothing at all - and the stray-release guard beside the damage loop
// then reads the job's OWN sibling set as a foreign release's leftovers,
// declines it in a sentence that is false about the post, and spends
// none of its parity on members it names.
//
// WHAT THE SHAPE HAS TO BE. Three mechanisms narrow it and every one was
// measured against origin/main rather than reasoned out:
//
//   * THE CLAIMING SET MUST CARRY A MEMBER THE OTHER DOES NOT. Every
//     tier takes the first unclaimed descriptor in FLAT order
//     (`Active::new` lays sets out in activation order and both the name
//     and md5-16k tiers walk it), so a member BOTH sets name is claimed
//     in the lower set - which is also the set the charge loop's
//     `find_map` hands a missing name to, and the guard cannot fire.
//   * SO THE CLAIMING SET IS THE LATER ONE. The sniff elects a bootstrap
//     volume and DEFERS the rest, and `settle::activate_deferred_sets`
//     brings the second set up at settle from the bytes on disk; the set
//     that bootstrapped is set 0, which is the one knob the two graded
//     legs turn. WHICH SET GETS THERE FIRST IS ITSELF A RACE and NZB
//     order does not settle it - measured, the control leg bootstrapped
//     from the wrong set 1 run in 4 unpaced, and a run has been seen
//     announcing a bootstrap for BOTH sets. So the losing set's volumes
//     carry `slow_ttfb`, which is dead air before the status line on
//     EVERY request (unlike `stall`, which answers the retry instantly
//     and would put them straight back in the race). They still all
//     land; they just cannot be first.
//   * A SLOT JUDGED WHILE ONLY THE FIRST SET WAS LIVE COULD NOT CLAIM
//     THE SECOND - AND THAT CONSTRAINT IS GONE SINCE 31 Aug 2026, so
//     read this bullet as why the fixture has the SHAPE it has, not as a
//     live limit. A completed head that matched nothing latched
//     `unmatchable`, and `finish_slot` then skipped the whole-file and
//     named tiers for the rest of the run - measured, and the first cut
//     of this fixture read `verified 0 file(s)` for exactly that reason.
//     The way out taken here is the one shape that does NOT latch: an
//     AMBIGUOUS head. The three payloads share their first 16 KiB and
//     their length and differ after it, so the claiming member's head
//     matches both of the bootstrap set's descriptors, the md5-16k tier
//     declines on rivalry rather than latching (W4-15's twin skip does
//     not apply - the two rivals disagree on the whole-file MD5, so they
//     really are two files), and the slot is still open at settle for
//     the name tier to claim the deferred set with. It arrives WHOLE and
//     intact, so nothing in the graded outcome depends on repairing it.
//
//     The latch itself now carries the ADOPTION GENERATION it was
//     reached under (`Active::adopted_gen`), so adopting a set re-opens
//     every slot whose refusal that adoption staled and the rivalry
//     trick is no longer LOAD-BEARING here. It is kept anyway: these
//     legs grade which set's parity gets spent, and re-cutting their
//     payloads would re-open the arrangement assertions below for a
//     property they do not measure. A fixture that wants the plain
//     shape - a head matching nothing live at download time, named only
//     by the deferred set - has one in `nzbkit`'s own
//     `live::tests::a_second_set_reopens_a_slot_the_first_one_latched`,
//     which pins the mechanism directly and costs milliseconds.
//
// The two graded legs carry the same two sets over the same members with
// the same parity and the same bytes on the wire; only which set is
// posted first, and so which one bootstraps, moves. Both assert the
// arrangement they need before grading anything, because both ways of
// losing it are SILENT: a post where nothing claimed anything is one the
// guard is scoped not to fire on, and a post where the claiming set
// bootstrapped hands the missing names to a set that has claims.

/// Three payloads of one length sharing their first 16 KiB and
/// differing after it - `(claimer, one, two)`.
///
/// The shared span is exactly `HEAD_LEN`, which is what makes all three
/// declare the same `md5_16k` while declaring different whole-file MD5s.
/// See the section header for why the claiming member needs a head its
/// bootstrap-set rivals share.
fn shared_head_payloads() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let head = payloads::unique_payload(16_384, 7);
    let mk = |seed: u64| {
        let mut v = head.clone();
        v.extend(payloads::unique_payload(200_000 - 16_384, seed));
        v
    };
    (mk(22), mk(33), mk(44))
}

/// Two overlapping recovery sets over `Lost.One.bin` and `Lost.Two.bin`,
/// both lost WHOLE and both posted obfuscated, plus `Claimer.bin` -
/// named by the SECOND set alone, arriving whole, and so the only thing
/// in this post that claims anything.
///
/// `pair_first` posts the two-member set ahead of the three-member one,
/// which decides which bootstraps and so which set the charge loop hands
/// a missing name to.
///
/// Returns the `Fixture` too, and that is not tidiness: it owns the
/// scratch guard, so dropping it here would delete the output tree
/// before the caller could grade it.
async fn run_asymmetric_sets(
    tag: &str,
    r_pair: Parity,
    r_all: Parity,
    pair_first: bool,
) -> (Fixture, String, bool, Vec<u8>, Vec<u8>, PathBuf) {
    let (claimer, one, two) = shared_head_payloads();
    let mut fx = Fixture::new(tag);
    for (n, d) in [
        ("Lost.One.bin", &one),
        ("Lost.Two.bin", &two),
        ("Claimer.bin", &claimer),
    ] {
        std::fs::write(fx.dir.join(n), d).unwrap();
    }
    // One `par2 create` at a time: `add_named_par2_obfuscated` globs
    // every `*.par2` in the staging directory and removes what it
    // posted, so the two calls cannot be reordered without reordering
    // the NZB - which is exactly the knob this fixture turns.
    let post_pair = |fx: &mut Fixture| {
        add_named_par2_obfuscated(
            fx,
            "setpair",
            r_pair,
            10_000,
            &["Lost.One.bin", "Lost.Two.bin"],
            40_000,
        )
        .expect("par2 create (pair)")
    };
    let post_all = |fx: &mut Fixture| {
        add_named_par2_obfuscated(
            fx,
            "setall",
            r_all,
            10_004,
            &["Lost.One.bin", "Lost.Two.bin", "Claimer.bin"],
            40_000,
        )
        .expect("par2 create (all)")
    };
    // The set posted second is also the one held back, so the first one
    // is first onto the wire AND first to answer. Both halves are needed:
    // NZB order alone loses the race about one run in four.
    let held_back = if pair_first {
        post_pair(&mut fx);
        post_all(&mut fx)
    } else {
        post_all(&mut fx);
        post_pair(&mut fx)
    };
    for n in ["Lost.One.bin", "Lost.Two.bin", "Claimer.bin"] {
        std::fs::remove_file(fx.dir.join(n)).unwrap();
    }
    // The two losses, posted under hash subjects AND hash yEnc names, so
    // the post offers no name for either and the guard's
    // `names_offered_by_the_post` clause cannot stand in for the one this
    // leg is about - that clause can never help a fully obfuscated post
    // at all, which is half of why this row is not the residual tier's.
    let mut lost_ids: Vec<String> = Vec::new();
    for (subject, data) in [("Qr7bXm2Ld9", &one), ("Vt3kNp8Wz5", &two)] {
        let before = fx.nzb_files.len();
        fx.add_file_obfuscated(subject, subject, data, 40_000);
        lost_ids.extend(
            fx.nzb_files[before]
                .1
                .iter()
                .map(|(id, _, _)| format!("<{id}>")),
        );
    }
    // Truthfully named, so the name tier has a candidate to claim the
    // deferred set with once it is live at settle.
    fx.add_file("Claimer.bin", &claimer, 40_000);

    let mut chaos = Chaos::default();
    for id in &lost_ids {
        chaos.missing.insert(id.clone());
    }
    for id in held_back {
        chaos.slow_ttfb.insert(id, 500);
    }
    let (log, ok, out) = run_multiset(&fx, chaos).await;
    (fx, log, ok, one, two, out)
}

/// The arrangement both graded legs depend on: `expect_first`
/// bootstrapped, so it is set 0 and the charge loop hands it the missing
/// names, and something claimed a set, which is what makes
/// `some_set_claimed` true and puts the guard in scope at all.
fn assert_arrangement(log: &str, expect_first: &str) {
    let bootstrap = log
        .lines()
        .find(|l| l.contains("bootstrapping the PAR2 set from it"))
        .unwrap_or_else(|| panic!("no set bootstrapped at all\n{log}"));
    assert!(
        bootstrap.contains(expect_first),
        "{expect_first} was meant to bootstrap, so it is set 0 and the charge loop \
         hands it the missing names; this run bootstrapped from the other set, so the \
         leg proves nothing: {bootstrap}\n{log}"
    );
    assert!(
        log.contains("verified 1 file(s)"),
        "the arriving member claimed no set, so no set has claims and the stray-release \
         guard is out of scope - the leg proves nothing\n{log}"
    );
}

/// The red leg: the two-member set bootstraps, so it is the set the
/// charge loop hands both wholly-missing names to - and it claimed
/// nothing, because the only member that arrived is one the OTHER set
/// alone carries. The guard reads it as a foreign release, so neither
/// set is charged for either loss, neither is planned, and the parity
/// that covers both sits on disk unspent.
///
/// X5-24's residual tier cannot rescue this, and that is deliberate
/// rather than a gap: it declines the moment a leftover set names more
/// than one unlisted loss ("it names 2 files this post neither delivered
/// nor listed"), which is this post exactly. The evidence here is a
/// different kind and a stronger one - a sibling set describing the SAME
/// bytes did claim, which is direct evidence the post owns both sets.
#[tokio::test(flavor = "multi_thread")]
async fn a_sibling_set_the_race_left_unclaimed_is_not_a_stray_release() {
    if !have_par2() {
        eprintln!("stray-guard race: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, one, two, out) =
        run_asymmetric_sets("strayrace", Parity::Blocks(60), Parity::Pct(5), true).await;
    assert_arrangement(&log, "setpair");
    let got_one = std::fs::read(out.join("Lost.One.bin")).unwrap_or_default();
    let got_two = std::fs::read(out.join("Lost.Two.bin")).unwrap_or_default();
    assert!(
        ok && got_one == one && got_two == two,
        "the set the arrival race left unclaimed was declined as another release's, so \
         its parity was never spent on the members it names: rc ok={ok}, {} of {} and {} \
         of {} bytes; tree = {:?}\n{log}",
        got_one.len(),
        one.len(),
        got_two.len(),
        two.len(),
        read_tree(&out)
    );
    // Pinned by REASON as well as by bytes: the decline prints the set it
    // refused, so a job that greens some other way cannot stand in for
    // the guard having stopped firing on the job's own sibling.
    assert!(
        !log.contains("matched nothing in this post"),
        "the guard still declined the job's own sibling set\n{log}"
    );
}

/// The control with the predicted trigger removed: the SAME two sets
/// over the same members with the same parity, posted the other way
/// round, so the set that bootstraps is the one the arrival claimed and
/// the guard never fires.
///
/// Green on origin/main beside a red leg above is what makes this an
/// arrival-order defect rather than a shortage of parity: the bytes on
/// the wire are identical and only the posting order moved.
#[tokio::test(flavor = "multi_thread")]
async fn control_the_claiming_set_named_first_spends_the_sibling_parity() {
    if !have_par2() {
        eprintln!("stray-guard race control: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, one, two, out) =
        run_asymmetric_sets("strayracectl", Parity::Blocks(60), Parity::Pct(5), false).await;
    assert_arrangement(&log, "setall");
    let got_one = std::fs::read(out.join("Lost.One.bin")).unwrap_or_default();
    let got_two = std::fs::read(out.join("Lost.Two.bin")).unwrap_or_default();
    assert!(
        ok && got_one == one && got_two == two,
        "control leg failed too - the claiming set bootstrapping does not rebuild the \
         pair either, so the row is not about which set the race claimed: rc ok={ok}, \
         {} of {} and {} of {} bytes\n{log}",
        got_one.len(),
        one.len(),
        got_two.len(),
        two.len()
    );
}

/// The insufficient-both control, and it is what stops a permissive fix
/// passing the two above: forgiving every set some sibling claimed for
/// is a rule that could equally be written to forgive a job no set could
/// repair. Neither set here carries the parity for two whole losses, so
/// the job must fail and the pair must not appear.
#[tokio::test(flavor = "multi_thread")]
async fn control_neither_set_can_cover_the_asymmetric_loss() {
    if !have_par2() {
        eprintln!("stray-guard race control: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, _one, _two, out) =
        run_asymmetric_sets("strayracenone", Parity::Pct(5), Parity::Pct(5), true).await;
    assert!(
        !ok && !out.join("Lost.One.bin").exists() && !out.join("Lost.Two.bin").exists(),
        "neither set carries the parity for two whole-file losses, yet the job reported \
         rc ok={ok} with tree = {:?}\n{log}",
        read_tree(&out)
    );
}

// ---------------------------------------------------------------------
// W4-15 on RESUME: the second set's only volume is already on disk.
// ---------------------------------------------------------------------

/// `add_named_par2_obfuscated` restricted to the RECOVERY volumes - the
/// index file (`<base>.par2`, no recovery slices) is created and thrown
/// away instead of posted.
///
/// A post shaped this way is what makes the resume leg below a test of
/// activation rather than of the election: every file of the set has to
/// be restored from run 1, or a fresh arrival gives the settle-time
/// activation a writer to find and the defect hides. One volume is the
/// only way to guarantee that, and `par2 create -n1` plus dropping the
/// index is how you get one. A volume carries the critical packets
/// (main, FileDesc, IFSC) in its own right - that is what
/// "bootstrapping the set from the smallest volume" already relies on -
/// so the set is fully definable from it.
///
/// Returns the volume article ids and the volume's byte length, which is
/// how a caller checks the run it is resuming from left the file WHOLE
/// rather than preallocated with a hole in it.
fn add_par2_volumes_only_obfuscated(
    fx: &mut Fixture,
    base: &str,
    redundancy: u32,
    block: u64,
    files: &[&str],
    art_size: usize,
) -> Option<(Vec<String>, usize)> {
    let st = Command::new("par2")
        .arg("create")
        .arg(Parity::Pct(redundancy).arg())
        .arg(format!("-s{block}"))
        .arg("-n1")
        .arg("-q")
        .arg(base)
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return None,
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    let mut ids = Vec::new();
    let mut bytes = 0usize;
    for (i, p) in par2s.iter().enumerate() {
        let is_index = !p.file_name().unwrap().to_string_lossy().contains(".vol");
        let data = std::fs::read(p).unwrap();
        std::fs::remove_file(p).unwrap();
        if is_index {
            continue;
        }
        bytes += data.len();
        let hash = format!("{base}{i:02}zXm9rTb");
        let tag = format!("{base}-obf-{i}");
        let segs = make_file_articles(&hash, &data, art_size, &tag, &mut fx.articles);
        ids.extend(segs.iter().map(|(id, _, _)| format!("<{id}>")));
        fx.nzb_files.push((hash, segs));
    }
    Some((ids, bytes))
}

/// W4-15 on a RESUMED job: two recovery sets over one member, and the
/// strong one's single volume is already on disk from the killed run.
///
/// `get::settle::activate_deferred_sets` reaches the deferred volumes'
/// bytes through `Extractor::slot_path`, which answers from the slot's
/// WRITER. A resume-recognised volume never gets one:
/// `get::plan` marks the slot `par2_sniffed` at build time from
/// `resume_vols`, and `get::rig::replay_or_adopt_restored` skips every
/// `is_par2()` slot - "its file simply waits on disk for a repair". So
/// the set whose parity would heal the member is a file sitting in
/// `out_dir` that nothing ever parses.
///
/// The leg is the resumed twin of
/// `the_weak_set_winning_the_race_must_still_use_the_strong_parity`,
/// and the two differ in exactly one thing: how the strong set's bytes
/// got onto the disk. There they arrive late over the wire; here they
/// were already there when the run opened.
async fn run_two_sets_resumed(tag: &str) -> (Fixture, String, bool, Vec<u8>, PathBuf) {
    let data = payload(200_000, 71);
    let mut fx = Fixture::new(tag);
    std::fs::write(fx.dir.join("Twin.Payload.bin"), &data).unwrap();
    // The WEAK set, posted whole: 2% of 20 blocks is one block, which
    // cannot cover the four-block hole below.
    let alpha_ids = add_named_par2_obfuscated(
        &mut fx,
        "setalpha",
        Parity::Pct(2),
        10_000,
        &["Twin.Payload.bin"],
        40_000,
    )
    .expect("par2 create (alpha)");
    // The STRONG set, one volume and no index - see the helper.
    // ONE article, so run 1 restores the volume WHOLE: a partially
    // restored volume is a second question (settle re-fetches it, see
    // the `resume_vols` partial rule) and would leave this leg unable
    // to say which half it was testing.
    let (bravo_ids, bravo_len) = add_par2_volumes_only_obfuscated(
        &mut fx,
        "setbravo",
        40,
        10_004,
        &["Twin.Payload.bin"],
        1_000_000,
    )
    .expect("par2 create (bravo)");
    assert_eq!(
        bravo_ids.len(),
        1,
        "the strong set's volume is more than one article, so run 1 can \
         restore it in part and the leg stops being decisive"
    );
    assert_eq!(
        fx.nzb_files.last().map(|(n, _)| n.as_str()),
        Some(BRAVO_VOL),
        "the strong set is not the single file this leg needs"
    );
    std::fs::remove_file(fx.dir.join("Twin.Payload.bin")).unwrap();
    let payload_ids: Vec<String> = {
        let before = fx.nzb_files.len();
        fx.add_file_obfuscated("Zc4hVn78Kp", "Zc4hVn78Kp", &data, 40_000);
        fx.nzb_files[before]
            .1
            .iter()
            .map(|(id, _, _)| format!("<{id}>"))
            .collect()
    };
    let out = fx.dir.join("out");
    let nzb = fx.write_nzb();

    // RUN 1, which FAILS on purpose. Everything but the strong set's one
    // volume is REFUSED, and that does two jobs at once: it makes the
    // volume the only bootstrap candidate, so it downloads in full, and
    // it stops any PAYLOAD article landing - a payload article that
    // lands is journaled, restored by run 2, and fills the very hole run
    // 2 exists to leave.
    //
    // A SIGKILL was tried first and is NOT needed. A finished failure
    // quarantines the volume to `*.nzbfast-partial`, which looks fatal
    // for a leg whose whole premise is that run 2 recognises the file by
    // reading its first bytes - and is not:
    // `journal::restore::unquarantine_partials` walks the output tree
    // and renames every one of them back BEFORE `restore` runs, which is
    // upstream of where `get::plan` builds `resume_vols`. Measured both
    // ways; the killed version passed 12 of 12 and this one is simply
    // shorter and has no poll loop or deadline in it. Do not reintroduce
    // the kill on the theory that the quarantine hides the volume.
    {
        let mut refused: std::collections::HashSet<String> = alpha_ids.iter().cloned().collect();
        refused.extend(payload_ids.iter().cloned());
        let srv = MockServer::start(
            fx.articles.clone(),
            Chaos {
                missing: refused,
                ..Chaos::default()
            },
        )
        .await;
        let cfg = fx.write_config(&[&srv]);
        let (nzb1, out1) = (nzb.clone(), out.clone());
        let (log1, ok1) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb1, &out1, &[]))
            .await
            .unwrap();
        assert!(
            !ok1,
            "run 1 was served nothing but one recovery volume and still \
             reported success, so there is no failed attempt to resume \
             from\n{log1}"
        );
    }
    // Under EITHER name, because which of the two a failed attempt
    // leaves depends on what else was on disk to quarantine - and the
    // point of the assert is the BYTES, so that the leg cannot pass
    // having resumed from a volume that is not whole.
    let left_behind = [
        out.join(BRAVO_VOL),
        out.join(format!("{BRAVO_VOL}.nzbfast-partial")),
    ]
    .into_iter()
    .find_map(|p| std::fs::read(&p).ok());
    assert!(
        left_behind.is_some_and(|b| b.len() == bravo_len && b[..8] == *nzbkit::par2::MAGIC),
        "run 1 left no whole strong-set volume on disk, so run 2 has \
         nothing to recognise and the leg would pass for the wrong \
         reason; tree = {:?}",
        read_tree(&out)
    );

    // RUN 2, resumed. The strong volume is restored by content; the weak
    // set arrives fresh, wins the election unopposed, and owns the slot.
    // One payload article - four of the member's twenty blocks - is gone.
    let mut chaos = Chaos::default();
    chaos.missing.insert(payload_ids[1].clone());
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    if std::env::var("MULTISET_DUMP_LOG").is_ok() {
        eprintln!("==== resumed run log (rc ok={ok}) ====\n{log}\n==== end ====");
    }
    (fx, log, ok, data, out)
}

/// The obfuscated name `add_par2_volumes_only_obfuscated` gives the
/// strong set's one volume - index 1 of the sorted par2 output, the
/// index file being 0.
const BRAVO_VOL: &str = "setbravo01zXm9rTb";

#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_job_activates_the_second_set_that_is_already_on_disk() {
    if !have_par2() {
        eprintln!("w4_15 resume: par2 unavailable - skipping");
        return;
    }
    let (_fx, log, ok, data, out) = run_two_sets_resumed("w415resume").await;
    assert!(
        log.contains("recovery volumes by content"),
        "run 2 never recognised the restored volume, so this leg is not \
         testing what it says\n{log}"
    );
    let landed = std::fs::read(out.join("Twin.Payload.bin")).unwrap_or_default();
    assert!(
        ok && landed == data,
        "the strong set's only volume was on disk the whole time and was \
         never activated, so its parity was never spent: rc ok={ok}, {} \
         of {} bytes; tree = {:?}\n{log}",
        landed.len(),
        data.len(),
        read_tree(&out)
    );
}

/// A deferred set whose DEFINITION does not fit in the bytes that
/// landed, which is what the second half of this row is about: correct,
/// and until now silent.
///
/// It is not a corner. `par2 create` writes a volume whose FIRST packet
/// is a recovery SLICE - measured on par2cmdline 0.8.x, block size
/// 10 004 gives `RecvSlic` at 0 (10 072 bytes), `Main` at 10 072,
/// `FileDesc` at 20 236 - so the critical packets that DEFINE the set
/// begin one whole block into the file. A deferral cancels the volume's
/// still-queued articles the moment its offset-0 article says `PAR2\0PKT`,
/// so what is on disk is that one article and a hole; when the article
/// is smaller than the leading slice, every packet the definition needs
/// is in the hole. #63's poster used 716 800-byte blocks, which is
/// larger than an article on any real post.
///
/// `settle::activate_deferred_sets` then reads a set id (the slice
/// packet's own header carries one) and no set, and skips the volume.
/// That is the right thing to do - there is nothing on disk to parse and
/// nothing here may guess - but from outside it is indistinguishable
/// from "this post had one recovery set", which is the difference
/// between a job that failed for a reason and a job that failed.
///
/// The leg is written on a provider that will not serve the REST of
/// that volume, and that is what makes it decisive rather than a coin
/// toss: a deferred volume stays on the repair's own fetch list, so on a
/// provider that does serve it the rest arrives, the definition parses
/// there, and the set is reached after all. Both worlds are real; this
/// is the one where the warning is the only account of what happened.
#[tokio::test(flavor = "multi_thread")]
async fn a_deferred_set_whose_definition_did_not_land_says_so() {
    if !have_par2() {
        eprintln!("w4_15 undefined: par2 unavailable - skipping");
        return;
    }
    let data = payload(200_000, 71);
    let mut fx = Fixture::new("w415undef");
    std::fs::write(fx.dir.join("Twin.Payload.bin"), &data).unwrap();
    let _alpha = add_named_par2_obfuscated(
        &mut fx,
        "setalpha",
        Parity::Pct(2),
        10_000,
        &["Twin.Payload.bin"],
        40_000,
    )
    .expect("par2 create (alpha)");
    // 4 000-byte articles against a 10 004-byte block: the leading
    // recovery slice packet spans articles 1-3, so nothing the deferral
    // lets land is a complete packet the parse can use.
    let (bravo_ids, _) = add_par2_volumes_only_obfuscated(
        &mut fx,
        "setbravo",
        40,
        10_004,
        &["Twin.Payload.bin"],
        4_000,
    )
    .expect("par2 create (bravo)");
    assert!(
        bravo_ids.len() > 3,
        "the strong set's volume is not split finely enough for its \
         definition to land in the hole"
    );
    std::fs::remove_file(fx.dir.join("Twin.Payload.bin")).unwrap();
    let payload_ids: Vec<String> = {
        let before = fx.nzb_files.len();
        fx.add_file_obfuscated("Zc4hVn78Kp", "Zc4hVn78Kp", &data, 40_000);
        fx.nzb_files[before]
            .1
            .iter()
            .map(|(id, _, _)| format!("<{id}>"))
            .collect()
    };
    let mut chaos = Chaos::default();
    // One payload article gone, so there is a repair to decline.
    chaos.missing.insert(payload_ids[1].clone());
    // Every article of the strong volume EXCEPT its offset-0 one is
    // refused. Two things at once, both needed: what lands is exactly
    // what the deferral would have left however the cancel raced the
    // fetcher (`Chaos::stall` was tried and does NOT do this - a stalled
    // id serves on RETRY, 0.1 MB of the volume landed and the definition
    // parsed), and the repair's own later fetch of the same volume
    // cannot rescue it either, so the run ends on the state this leg is
    // about.
    chaos.missing.extend(bravo_ids[1..].iter().cloned());
    let (log, ok, _out) = run_multiset(&fx, chaos).await;
    assert!(
        log.contains("does not fit in what landed"),
        "the strong set's volume was skipped in silence, so a reader of \
         this failure cannot tell it from a post with one set\n{log}"
    );
    assert!(
        !ok,
        "4 000 bytes of a recovery volume is not parity, so this job \
         has nothing to repair with and must not green\n{log}"
    );
}
