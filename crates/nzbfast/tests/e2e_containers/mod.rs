//! The non-RAR containers AT THE TOP LEVEL: a `.7z` or a `.zip` posted
//! as the release itself, with no RAR around it. Everything here is one
//! subject - what the chase does when the outermost thing on the wire is
//! a container the RAR reader cannot open - and it runs the whole ladder
//! for both formats: single file, byte-split set (`.7z.001`, `.zip.001`
//! and the bare-numeric hjsplit shape), a store RAR wrapping a zip, the
//! retention-cap trim and the demote that has to land identically when
//! the trim cannot happen, the damaged post that must materialize and
//! repair on disk, and the encrypted zip the chase decrypts in stream
//! (plus the zip it DECLINES, which must land exactly where the gate-off
//! path leaves it).
//!
//! A child module so e2e.rs stays inside its size-gate baseline (the
//! e2e_zipsplit pattern: harness reached through `super::*`).
//!
//! THE THREE FIXTURE BUILDERS THESE TESTS LEAN ON STAYED IN `e2e.rs` -
//! `incompressible`, `sevenz_container` and `sevenz_store_container` -
//! and that is deliberate rather than an oversight: e2e_chaseresume,
//! e2e_resume, e2e_tar and e2e_zipsplit all reach them through
//! `super::`, so moving them here would respell a path in four sibling
//! files to buy about fifty lines. It is why this seam came out of
//! e2e.rs as three ranges rather than one.

use super::*;

/// TODO 37 step 1: a POSTED single-file `.7z` - no RAR around it, the
/// shape 3.3% of releases actually use. The chase now takes it at depth
/// 0, so its payload streams out while the archive downloads and the
/// `.7z` itself never touches disk. Before this, the badge said
/// `7z · unpacked after download` and the archive sat on disk waiting
/// for the post-pass.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_7z_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7z");
    // Incompressible, like real payload: LZMA2 leaves it ~1:1, so the
    // posted archive is genuinely article-sized rather than a stub.
    let movie = incompressible(900_000, 41);
    let arch = sevenz_container(&[("movie.mkv", &movie)]);
    fx.add_file("release.7z", &arch, 60_000);
    assert!(fx.add_par2(10, &["release.7z"], 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    // The chase's byte count, which read "(0.0 MB)" here too until the
    // zip work surfaced it on a live post (31 Jul).
    assert!(
        !log.contains("in-stream (0.0 MB)"),
        "the in-stream summary lost its byte count:\n{log}"
    );
    assert!(
        log.contains("7z · one-pass"),
        "badge still says on-disk:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(
        !fx.dir.join("out/release.7z").exists(),
        "the archive must not touch disk"
    );
}

/// The same shape, damaged. A chased slot cannot take a mapped repair
/// (its bytes are in RAM, not a file par2 can patch), so the ladder must
/// materialize it first - which is the pre-TODO-37 end state - repair it
/// on disk, and let the 7z post-pass unpack it. The failure this pins is
/// silent and total: without the chased slot in the materialize sweep,
/// par2 finds no `release.7z` at all and calls the whole file missing.
#[tokio::test(flavor = "multi_thread")]
async fn damaged_top_level_7z_materializes_repairs_and_unpacks() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7zdmg");
    let movie = incompressible(900_000, 42);
    let arch = sevenz_container(&[("movie.mkv", &movie)]);
    fx.add_file("release.7z", &arch, 60_000);
    assert!(fx.add_par2(30, &["release.7z"], 60_000));
    // Two mid-archive articles vanish: enough damage to need repair,
    // well inside the 30% redundancy.
    let victims: Vec<String> = ["-3@mock>", "-5@mock>"]
        .iter()
        .map(|suffix| {
            fx.articles
                .keys()
                .find(|k| k.contains("release_7z") && k.ends_with(suffix))
                .unwrap_or_else(|| panic!("no {suffix} article: {:?}", fx.articles.len()))
                .clone()
        })
        .collect();
    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        !log.contains("file missing entirely"),
        "par2 could not see the chased archive:\n{log}"
    );
    assert!(log.contains("materializing volumes for repair"), "{log}");
    assert!(log.contains("repair complete"), "no repair:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("payload after repair"),
        movie,
        "payload differs after repair + post-pass"
    );
}

/// TODO 37 step 2: an archive several times the retention cap streams
/// anyway. The chase drops the prefix the decoder has already read past
/// out of RAM and into the archive's own path as it goes, so what bounds
/// it is the live window rather than the whole file; on success that
/// partial spill is removed and the payload is the only thing left.
///
/// `--mem-limit 64M` floors the budget, which puts the extractor's
/// held-span ceiling at ~29 MB against a ~36 MB archive. Before
/// trimming, a job like this could only demote.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_7z_over_the_cap_trims_and_still_streams() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7ztrim");
    // Store-codec 7z over incompressible payload - the shape the census
    // says dominates (already-compressed video), and the one where
    // decode keeps up with arrival so the trim watermark advances.
    let movie = incompressible(36 << 20, 43);
    let arch = sevenz_store_container(&[("movie.mkv", &movie)]);
    assert!(arch.len() > 36 << 20, "fixture too small: {}", arch.len());
    fx.add_file("release.7z", &arch, 700_000);
    // PAR2 stays on for this one: verifying a slot whose prefix has been
    // trimmed out from under it is the interaction most likely to break.
    assert!(fx.add_par2(5, &["release.7z"], 700_000));
    // A server that delivers at a plausible rate rather than at memcpy
    // speed. Trimming releases what the decoder has already READ, so a
    // mock that hands over 40 MB in 0.3 s is testing the case trimming
    // cannot help (arrivals outrunning decode, which correctly demotes),
    // not the case it exists for.
    //
    // 150ms rather than 60: this margin is what keeps the trim path the
    // branch that actually runs below. At 60 the suite's own parallel
    // load was enough to let arrivals outrun decode.
    let chaos = Chaos {
        delay_ms: 150,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        // The direct map is held off: this test is about the TRIM, and a
        // Copy container the map takes never retains a frontier to trim.
        // The trim still owns every container the map declines (LZMA2,
        // encrypted, BCJ2) and the zip chase; a stored fixture is used
        // here because a stored container is the one whose decode keeps
        // up with arrivals, which is the precondition the trim needs.
        // The direct map's own behaviour at this same cap is
        // `top_level_7z_copy_maps_direct_and_never_reaches_the_cap`.
        run_get_args(
            &cfg,
            &nzb,
            &out,
            &[("NZBFAST_NO_7Z_DIRECT", "1")],
            &["--mem-limit", "64M"],
        )
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    // True on either path: the payload is exact, and the archive - spilled
    // partially or materialized whole - does not outlive the job.
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(
        !fx.dir.join("out/release.7z").exists(),
        "the archive survived the job"
    );
    // Which path it took is a race, and the sibling test below says why
    // asserting on the winner is a mistake - it pins its own direction
    // with the kill switch for exactly this reason. Trimming only wins
    // while decode keeps up with arrivals; on a machine running the rest
    // of this suite in parallel it sometimes does not, and demoting then
    // is the DOCUMENTED right answer rather than a regression. Asserting
    // `!log.contains("held-bytes cap")` failed about one full-suite run
    // in six for that reason, while passing 10/10 on its own.
    //
    // So: assert the trim contract when trimming happened, the demotion
    // contract when it did not. The `delay_ms` margin above is what
    // keeps the first branch the usual one; the second exists so a busy
    // box reports the truth instead of a failure.
    if log.contains("held-bytes cap") {
        eprintln!(
            "note: arrivals outran decode, so this run covered the demotion \
             fallback rather than the trim path"
        );
        assert!(
            log.contains("7z unpack complete"),
            "demoted, but the disk post-pass never ran:\n{log}"
        );
    } else {
        assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
        assert!(log.contains("7z · one-pass"), "{log}");
    }
}

/// TODO 37 step 4: the EXACT arrangement of the demote test below - a
/// 36 MB Copy container, a 64 MB limit, `NZBFAST_NO_7Z_TRIM=1` so the
/// chase has no way out but the held-bytes cap - and the direct map
/// streams it anyway.
///
/// That pairing is the point: the two tests differ in one environment
/// variable and nothing else, so this one cannot pass for an incidental
/// reason. Without the map the container is buffered whole and the only
/// exits are the trim (held off) or the cap (demote to disk, which is
/// what the sibling asserts). With the map it is never buffered at all -
/// each member is one contiguous range of the pack stream and its
/// articles go straight to the output - so the cap is not approached,
/// nothing lands on disk, and the disk post-pass never runs.
///
/// Stated as behaviour; the numbers are audit round 17 (1.09-1.25 s and
/// 1.29 GB peak down to 0.62-0.63 s and 40 MB on a 1 GiB split set at
/// 14.6 Gbps loopback).
#[tokio::test(flavor = "multi_thread")]
async fn top_level_7z_copy_maps_direct_and_never_reaches_the_cap() {
    let mut fx = Fixture::new("top7zdirect");
    let movie = incompressible(36 << 20, 46);
    let arch = sevenz_store_container(&[("movie.mkv", &movie)]);
    assert!(arch.len() > 36 << 20, "fixture too small: {}", arch.len());
    fx.add_file("release.7z", &arch, 700_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(
            &cfg,
            &nzb,
            &out,
            &[("NZBFAST_NO_7Z_TRIM", "1")],
            &["--mem-limit", "64M"],
        )
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(log.contains("7z \u{b7} one-pass"), "{log}");
    assert!(
        !log.contains("held-bytes cap"),
        "the map still went through the frontier:\n{log}"
    );
    assert!(
        !log.contains("7z unpack complete"),
        "the disk post-pass ran, so something demoted:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(
        !fx.dir.join("out/release.7z").exists(),
        "the archive survived the job"
    );
}

/// The other half of the same story: whenever a trim cannot happen, the
/// job must land exactly where it did before trimming existed - archive
/// materialized, disk post-pass unpacks it, payload still right.
///
/// Driven through the kill switch rather than by outrunning the decoder.
/// Arrival-beats-decode reaches the same code, but asserting on it means
/// asserting on who won a race: under a loaded machine the chase wins,
/// streams, and the "it demoted" assertion fails for the best possible
/// reason. The gate pins the behaviour; the race is a field question.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_7z_over_the_cap_demotes_cleanly_when_it_cannot_trim() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7znotrim");
    let movie = incompressible(36 << 20, 44);
    let arch = sevenz_store_container(&[("movie.mkv", &movie)]);
    // No PAR2: this test is about where the archive ENDS UP, and the
    // set costs more to build than the rest of the case put together.
    // The chase-plus-PAR2 interactions have their own tests, small ones.
    fx.add_file("release.7z", &arch, 700_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(
            &cfg,
            &nzb,
            &out,
            // The direct map goes off with the trim: a Copy container
            // it takes never retains a frontier at all, so there is no
            // held-bytes forfeit to observe. See its sibling in
            // `e2e_chaseresume` for the full reasoning.
            &[("NZBFAST_NO_7Z_TRIM", "1"), ("NZBFAST_NO_7Z_DIRECT", "1")],
            &["--mem-limit", "64M"],
        )
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("held-bytes cap: chase memory"), "{log}");
    assert!(
        log.contains("7z unpack complete"),
        "the post-pass never ran:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("payload after the disk pass"),
        movie,
        "the demoted archive did not reconstruct"
    );
}

/// TODO 37 step 3: a `.7z.001` SPLIT SET posted as three files streams
/// as one container. 7z multipart is a raw byte split, so the set is a
/// single archive with seams in it: part 1's start header sizes the
/// whole thing, and the continuation parts - which carry no signature
/// whatsoever - join by name. Nothing lands on disk.
///
/// Before this, the parts materialized and the post-pass concatenated
/// them into a scratch container before unpacking, which is a full extra
/// copy of the archive on top of the download.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_7z_split_set_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("top7zsplit");
    let movie = incompressible(6 << 20, 45);
    let arch = sevenz_store_container(&[("movie.mkv", &movie)]);
    // Exactly how `7z -v` splits: every part the split size, last one
    // the remainder.
    let split = arch.len().div_ceil(3);
    let parts: Vec<&[u8]> = arch.chunks(split).collect();
    assert_eq!(parts.len(), 3, "fixture must really split");
    let names: Vec<String> = (1..=3).map(|i| format!("release.7z.{i:03}")).collect();
    for (i, name) in names.iter().enumerate() {
        fx.add_file(name, parts[i], 200_000);
    }
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(5, &refs, 200_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(
        log.contains("7z · one-pass"),
        "the set did not stream:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    for name in &names {
        assert!(
            !fx.dir.join("out").join(name).exists(),
            "{name} must not touch disk"
        );
    }
}

/// One-pass zip (phase 2): a POSTED store zip - the shape phase 1 sent
/// to disk. The chase takes it at depth 0 now (the tail prefetch
/// front-loads the central directory, which is the last thing in a
/// zip), so its payload streams out while the archive downloads and the
/// `.zip` itself never touches disk.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_zip_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("topzip");
    // Incompressible, like real payload, STORED in the container - the
    // dominant zip shape and the one the store fast path exists for.
    let movie = incompressible(900_000, 46);
    let arch =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)]);
    fx.add_file("release.zip", &arch, 60_000);
    assert!(fx.add_par2(10, &["release.zip"], 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("clean download"), "no clean verdict:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    // The SIZE in that summary, not just the count. Every chase (7z and
    // zip) reported "(0.0 MB)" under a correct per-file list, because
    // the extractor's byte counter only advances on the RAR mapping
    // path - invisible until a live 160 MB zip printed it (31 Jul).
    assert!(
        !log.contains("in-stream (0.0 MB)"),
        "the in-stream summary lost its byte count:\n{log}"
    );
    assert!(
        log.contains("zip · one-pass"),
        "badge still says on-disk:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(
        !fx.dir.join("out/release.zip").exists(),
        "the archive must not touch disk"
    );
}

/// A `.zip.001` byte-split set posted as three files streams as one
/// container. Unlike 7z, no zip part carries a header that sizes the
/// set - the cut is arbitrary and only part 1 even has a signature -
/// so the NZB's own file list declares the part count and the geometry
/// resolves once every part's decoded size has arrived. Nothing lands
/// on disk.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_zip_split_set_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("topzipsplit");
    let movie = incompressible(2 << 20, 49);
    let arch =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)]);
    // A uniform byte split: every part the split size, last the
    // remainder - what hjsplit and `split -b` produce.
    let split = arch.len().div_ceil(3);
    let parts: Vec<&[u8]> = arch.chunks(split).collect();
    assert_eq!(parts.len(), 3, "fixture must really split");
    let names: Vec<String> = (1..=3).map(|i| format!("release.zip.{i:03}")).collect();
    for (i, name) in names.iter().enumerate() {
        fx.add_file(name, parts[i], 60_000);
    }
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(5, &refs, 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(
        log.contains("zip · one-pass"),
        "the set did not stream:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    for name in &names {
        assert!(
            !fx.dir.join("out").join(name).exists(),
            "{name} must not touch disk"
        );
    }
}

/// A BARE-NUMERIC byte-split set (`release.001`, no `.zip.` infix - the
/// hjsplit shape) streams the same way: the NZB's file list is the
/// declaration and part 1's magic is the gate, so the ambiguity with
/// RAR numeric volumes costs nothing. This pins the get/vrig.rs
/// declaration path for the numeric grammar end to end.
#[tokio::test(flavor = "multi_thread")]
async fn top_level_bare_numeric_zip_split_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("topnumsplit");
    let movie = incompressible(2 << 20, 51);
    let arch =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)]);
    let split = arch.len().div_ceil(3);
    let parts: Vec<&[u8]> = arch.chunks(split).collect();
    assert_eq!(parts.len(), 3, "fixture must really split");
    let names: Vec<String> = (1..=3).map(|i| format!("release.{i:03}")).collect();
    for (i, name) in names.iter().enumerate() {
        fx.add_file(name, parts[i], 60_000);
    }
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(5, &refs, 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(log.contains("extracted 1 file(s) in-stream"), "{log}");
    assert!(
        log.contains("zip · one-pass"),
        "the set did not stream:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    for name in &names {
        assert!(
            !fx.dir.join("out").join(name).exists(),
            "{name} must not touch disk"
        );
    }
}

/// The nested zip lift end to end: a store RAR wrapping a zip streams
/// both layers in one pass - rc=0, the payload byte-exact, and no
/// materialized intermediate (no inner .zip, no outer volume) touches
/// the output directory.
#[tokio::test(flavor = "multi_thread")]
async fn store_rar_wrapped_zip_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rarzip");
    let movie = incompressible(900_000, 50);
    let arch =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)]);
    let outer = fixtures::rar5_volume(&[("inner.zip", arch.len() as u64, &arch[..], false, false)]);
    fx.add_file("o.rar", &outer, 60_000);
    assert!(fx.add_par2(10, &["o.rar"], 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        !log.contains("fell back") && !log.contains("nested fallback"),
        "chase demoted:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    // One pass all the way down: no outer volume, no inner zip.
    for v in ["o.rar", "inner.zip"] {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "{v} must not touch disk:\n{log}"
        );
    }
}

/// The same shape, damaged - the riskiest inherited seam, and it now
/// has TWO routes through it, so both are run.
///
/// A CHASED slot cannot take a mapped repair (its bytes are in RAM, not
/// a file par2 can patch), so for a container the direct map declines -
/// here a DEFLATED entry - the ladder must materialize the zip first,
/// repair it on disk, and let the zip step of the disk post-pass unpack
/// it. The silent failure that arm pins: a chased zip missing from the
/// materialize sweep reads back as "file missing entirely" and the
/// repair rebuilds nothing.
///
/// A STORED entry may be DIRECT-MAPPED (`nzbkit::extract::zip_map`), and
/// then its bytes are in the output file already and par2 patches them
/// there: the repair goes straight into the output and no container is
/// ever written. That is the stored-RAR route, reached by a zip for the
/// first time, and it is strictly the better one.
///
/// **WHICH ROUTE A DAMAGED STORED CONTAINER TAKES IS NOT DETERMINISTIC,
/// and this test no longer asserts it.** It did, from `cd90cb6f7` until
/// 3 Sep 2026, and that assertion was red on CI run 33806764772 through
/// BOTH nextest retries; measured on this fixture afterwards it loses
/// 1-10% of runs on a loaded box, by two independent races that live in
/// the ENGINE and not in this file
/// (`research/MEASURED-2026-09-03-zip-mapped-damaged-container-races.md`):
///
///   1. the zip worker reads the central directory FIRST (it is at the
///      tail), and the §94 B chase verify gate pins that slot's
///      watermark at the first damaged block - 119,780 of 900,116 here -
///      so the read parks until settle abandons the chase and the map is
///      never decided. It is decided at all only when the chase's
///      frontier was built before the PAR2 set claimed the slot, i.e.
///      with no gate attached (`NZBFAST_CHASE_VERIFY_GATE=0` takes the
///      arm 20/20);
///   2. when the map IS taken, the self-prove PREFIX hasher can read the
///      container back through `Extractor::read_at` in the window around
///      the promote and get ZEROS for the whole member data area, commit
///      that digest, and make the mapped repair decline on a whole-file
///      MD5 that a full reread of the same bytes passes.
///
/// So the arms below assert what every route owes - the job succeeds,
/// par2 could see the archive, the repair completes, the payload is
/// byte-exact and no container is left in the output - plus the
/// invariant of whichever route actually ran. Do NOT put the route
/// assertion back without fixing one of the two races first: it is the
/// engine that is non-deterministic here, not the test.
#[tokio::test(flavor = "multi_thread")]
async fn damaged_top_level_zip_materializes_repairs_and_unpacks() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for (tag, stored) in [("mapped", true), ("chased", false)] {
        damaged_top_level_zip_arm(tag, stored).await;
    }
}

/// One arm of [`damaged_top_level_zip_materializes_repairs_and_unpacks`].
async fn damaged_top_level_zip_arm(tag: &str, stored: bool) {
    let mut fx = Fixture::new(&format!("topzipdmg-{tag}"));
    let movie = incompressible(900_000, 48);
    let spec = if stored {
        nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)
    } else {
        nzbkit::zip::fixtures::Spec::deflated("movie.mkv", &movie)
    };
    let arch = nzbkit::zip::fixtures::zip_of(&[spec]);
    fx.add_file("release.zip", &arch, 60_000);
    assert!(fx.add_par2(30, &["release.zip"], 60_000));
    // Two mid-archive articles vanish: enough damage to need repair,
    // well inside the 30% redundancy.
    let victims: Vec<String> = ["-3@mock>", "-5@mock>"]
        .iter()
        .map(|suffix| {
            fx.articles
                .keys()
                .find(|k| k.contains("release_zip") && k.ends_with(suffix))
                .unwrap_or_else(|| panic!("no {suffix} article: {:?}", fx.articles.len()))
                .clone()
        })
        .collect();
    let chaos = Chaos {
        missing: victims.into_iter().collect(),
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "{tag}: get failed:\n{log}");
    assert!(
        !log.contains("file missing entirely"),
        "{tag}: par2 could not see the chased archive:\n{log}"
    );
    let mapped_repair = log.contains("rebuilt directly into the output");
    // The stored container is direct-mapped and its mapped repair
    // finishes, EVERY run: race 1 decided whether the map was screened
    // at all, race 2 whether a screened map's repair was kept, and both
    // are fixed. The decline line is named in the message because it
    // separates the two at a glance if one ever comes back - present
    // means the map WAS taken and race 2 is the suspect, absent means
    // the tail read never got off the verify gate.
    assert_eq!(
        stored,
        mapped_repair,
        "{tag}: wrong route (mapped repair declined: {}):\n{log}",
        log.contains("mapped repair declined")
    );
    if stored && mapped_repair {
        // The mapped route ran: the damaged blocks were patched in the
        // OUTPUT, so nothing may have been materialized on the way.
        assert!(
            !log.contains("materializing volumes for repair"),
            "{tag}: a mapped repair and a materialize in one run:\n{log}"
        );
    } else {
        // Every other route - the chased arm by construction, the stored
        // arm whenever either race in this test's header went the other
        // way - materializes the container, repairs it on disk and lets
        // the disk pass unpack it.
        assert!(
            log.contains("materializing volumes for repair"),
            "{tag}: neither route ran - no mapped repair and no \
             materialize:\n{log}"
        );
    }
    // Owed by EVERY route, and the reason the arms above may branch: the
    // container is an intermediate, so it is swept whether it was
    // materialized for the repair or never written at all. A leftover
    // here is the shape the materialize sweep used to miss.
    assert!(
        !fx.dir.join("out/release.zip").exists(),
        "{tag}: the container was left in the output:\n{log}"
    );
    assert!(log.contains("repair complete"), "{tag}: no repair:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("payload after repair"),
        movie,
        "{tag}: payload differs after repair + post-pass"
    );
}

/// Phase 3 end to end: an ENCRYPTED zip (WinZip AE-256) posted with its
/// password riding the `Name{{pw}}.nzb` convention. The chase now
/// decrypts IN STREAM, so the container never touches disk - it used to
/// decline encrypted, materialize, and let the disk post-pass unpack it
/// (and before that, fail the job outright with "the payload is a zip
/// that could not be unpacked").
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_zip_completes_with_a_braces_password() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("topzipenc");
    let movie = incompressible(400_000, 50);
    let arch = nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec {
        encrypt: Some(nzbkit::zip::fixtures::Encrypt::Ae {
            password: "s3cretpw",
            strength: 3,
            vendor_version: 2,
        }),
        ..nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)
    }]);
    fx.add_file("release.zip", &arch, 60_000);
    assert!(fx.add_par2(10, &["release.zip"], 60_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let locked = fx.dir.join("release{{s3cretpw}}.nzb");
    std::fs::rename(&nzb, &locked).unwrap();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &locked, &out, &[]))
        .await
        .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("decrypted payload"),
        movie,
        "decrypted bytes differ"
    );
    // The whole point: no container on disk at any moment, and the disk
    // post-pass never needed. Its absence from the log is what says the
    // chase did the work rather than declining to it.
    assert!(
        !fx.dir.join("out/release.zip").exists(),
        "the container must never touch disk"
    );
    assert!(
        !log.contains("zip unpack complete"),
        "the disk pass ran - the chase declined instead of decrypting:\n{log}"
    );
}

/// Encrypted-zip PARITY against the disk reader, both schemes. The
/// in-stream and disk paths share `zip::entry_crypto` verbatim, and this
/// is what pins that sharing: the same post decrypted by the chase and
/// by the phase-1 disk pass (`NZBFAST_NO_TOP_ZIP=1`) must produce
/// byte-identical output. Correctness first - a shape that demotes to
/// disk still works, a shape that silently mis-decrypts does not, and
/// AE in particular has three places (LE counter from 1, partial
/// keystream carry, HMAC at source EOF) where a divergence would show up
/// as plausible-looking wrong bytes rather than an error.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_zip_one_pass_matches_the_disk_path() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let movie = incompressible(400_000, 71);
    let schemes: Vec<(&str, nzbkit::zip::fixtures::Encrypt)> = vec![
        (
            "zipcrypto",
            nzbkit::zip::fixtures::Encrypt::ZipCrypto {
                password: "s3cretpw",
            },
        ),
        (
            "ae256",
            nzbkit::zip::fixtures::Encrypt::Ae {
                password: "s3cretpw",
                strength: 3,
                vendor_version: 2,
            },
        ),
    ];
    for (scheme, enc) in schemes {
        // Deflate, so the decoder stops at its own stream end and the
        // drain that reaches the AE HMAC is actually exercised.
        let arch = nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec {
            encrypt: Some(enc),
            ..nzbkit::zip::fixtures::Spec::deflated("movie.mkv", &movie)
        }]);
        let mut got: Vec<Vec<u8>> = Vec::new();
        for (t, env) in [("on", &[][..]), ("off", &[("NZBFAST_NO_TOP_ZIP", "1")][..])] {
            let mut fx = Fixture::new(&format!("zipencparity-{scheme}-{t}"));
            fx.add_file("release.zip", &arch, 60_000);
            assert!(fx.add_par2(10, &["release.zip"], 60_000));
            let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
            let cfg = fx.write_config(&[&srv]);
            let nzb = fx.write_nzb();
            let locked = fx.dir.join("release{{s3cretpw}}.nzb");
            std::fs::rename(&nzb, &locked).unwrap();
            let out = fx.dir.join("out");
            let env: Vec<(&str, &str)> = env.to_vec();

            let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &locked, &out, &env))
                .await
                .unwrap();
            assert!(ok, "{scheme}/{t}: get failed:\n{log}");
            got.push(
                std::fs::read(fx.dir.join("out/movie.mkv"))
                    .unwrap_or_else(|e| panic!("{scheme}/{t}: no payload ({e}):\n{log}")),
            );
            // The one observable that must DIFFER. Not the container on
            // disk - the disk pass unpacks it and then sweeps it, so
            // both runs end with a clean output dir. What separates them
            // is whether that pass ran at all.
            assert_eq!(
                log.contains("zip unpack complete"),
                t == "off",
                "{scheme}/{t}: the disk pass running is the gate's signature:\n{log}"
            );
        }
        assert_eq!(got[0], movie, "{scheme}: in-stream bytes differ");
        assert_eq!(got[0], got[1], "{scheme}: in-stream and disk paths diverge");
    }
}

/// Demote parity: a zip the one-pass path DECLINES (here: a zstd
/// entry, a method the tree does not carry) must land exactly where it
/// lands today - container materialized byte-exact in the output
/// directory, disk post-pass attempted and failing with the same
/// method-naming message, job failed because the zip IS the payload.
/// Run twice, gate on and gate off (`NZBFAST_NO_TOP_ZIP=1` = the
/// phase-1 path verbatim), asserting the SAME end state; the demote
/// marker in the log is what proves the gate-on run actually attached
/// and declined rather than never chasing at all.
#[tokio::test(flavor = "multi_thread")]
async fn declined_zip_lands_exactly_like_the_gate_off_path() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for (t, env) in [("on", &[][..]), ("off", &[("NZBFAST_NO_TOP_ZIP", "1")][..])] {
        let mut fx = Fixture::new(&format!("topzipdecline-{t}"));
        let movie = incompressible(300_000, 47);
        let arch = nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec {
            method: 93, // zstd: declined BY NAME, in-stream and on disk
            ..nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)
        }]);
        fx.add_file("release.zip", &arch, 60_000);
        assert!(fx.add_par2(10, &["release.zip"], 60_000));
        let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
        let cfg = fx.write_config(&[&srv]);
        let nzb = fx.write_nzb();
        let out = fx.dir.join("out");
        let env: Vec<(&str, &str)> = env.to_vec();

        let (log, ok) = tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &env))
            .await
            .unwrap();
        assert!(!ok, "gate {t}: a packed payload must fail the job:\n{log}");
        assert!(
            log.contains("uses zstd compression"),
            "gate {t}: the declined method must be named:\n{log}"
        );
        assert_eq!(
            std::fs::read(fx.dir.join("out/release.zip")).expect("materialized container"),
            arch,
            "gate {t}: the container must land byte-exact"
        );
        assert!(
            !fx.dir.join("out/movie.mkv").exists(),
            "gate {t}: no payload may appear from a declined method"
        );
        // The runs differ in exactly one observable: with the gate on,
        // the chase attached and DEMOTED under the zip marker; with it
        // off, nothing ever chased.
        let marked = log.contains("zip materialized for the disk pass");
        assert_eq!(
            marked,
            t == "on",
            "gate {t}: demote marker presence is the gate's own signature:\n{log}"
        );
    }
}
