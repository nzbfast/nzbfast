//! Drop-not-spill (22 Aug 2026): a healthy top-level RAR chase releases
//! its consumed prefix with NO disk copy, and a demote that comes after
//! all re-fetches the dropped volumes off the wire before anything reads
//! them back (get/dropped.rs). Measured 21 Aug in
//! research/MEASURED-HOLDS-LADDER-2026-08-21.md: the spill was the
//! whole 0.48x of disk over payload on a set a few times the holds cap.
//!
//! A sibling-dir child module (the `e2e_repair` pattern, harness
//! reached through `super::*`) so `e2e.rs` stays inside its size-gate
//! baseline.

use super::*;

/// The forced-demote leg: a compressed set several times the holds cap,
/// paced so the engine keeps up (and so trims DROP), with one article
/// posted CORRUPT under a valid CRC. Nothing is lost, so the chase is
/// healthy and drops; then settle's PAR2 read-back finds the bad block,
/// materializes the live chase for repair, and the materialized volumes
/// have holes exactly where the drops were - which parity could never
/// cover. The re-fetch has to land first, the repair patches the one
/// block, and the disk pass extracts the set. Byte-exact either way.
///
/// Which branch runs is a race with the box (see the 7z trim rig in
/// e2e.rs for why the winner is not asserted): on a loaded machine the
/// engine falls behind, the pace gate makes every trim SPILL, and the
/// demote is free - the old path, still correct. The refetch contract
/// is asserted when a drop happened, the plain repair when it did not.
#[tokio::test(flavor = "multi_thread")]
async fn a_demote_after_a_drop_refetches_the_holed_volumes_and_repairs() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // 60 MB half-entropy at the writer's fastest level -> ~50 MB of
    // compressed volumes against the 28.8 MB holds cap of the 64 MB
    // budget floor (--mem-limit 8M clamps up to it), so most volumes
    // trim. Level 1 because the writer's default costs 3 s/MB in a
    // debug build and the fixture is the whole price of this leg.
    let doc = half_entropy(60_000_000, 0x2545f4914f6cdd1d);
    let vols = rars::rar50::Rar50VolumeWriter::new(
        rars::rar50::WriterOptions::default().with_compression_level(1),
    )
    .compressed_entries(&[rars::rar50::CompressedEntry {
        name: b"movie.bin",
        data: &doc,
        mtime: None,
        attributes: 0,
        host_os: 0,
    }])
    .max_payload_per_volume(1_500_000)
    .finish()
    .unwrap();
    assert!(vols.len() >= 8, "want many volumes, got {}", vols.len());
    let mut fx = Fixture::new("drop-refetch");
    let names: Vec<String> = (1..=vols.len()).map(|i| format!("d.part{i}.rar")).collect();
    for (name, vol) in names.iter().zip(&vols) {
        fx.add_file(name, vol, 300_000);
    }
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(10, &name_refs, 300_000), "par2 create failed");
    // Re-post the LAST volume with a byte run flipped, re-encoded so
    // every article CRC is valid for the bytes it carries: the download
    // sees nothing wrong, PAR2 does. The last one, because the engine
    // dies where it meets the damage, and from then on every trim
    // reads the engine as behind the line and spills; the drops this
    // leg is about happen while the engine is still decoding.
    let victim = vols.len() - 1;
    let mut bad = vols[victim].clone();
    let at = bad.len() / 2;
    for b in &mut bad[at..at + 64] {
        *b ^= 0x5a;
    }
    let tag = format!("{}-{}", names[victim].replace('.', "_"), victim);
    make_file_articles(&names[victim], &bad, 300_000, &tag, &mut fx.articles);
    let chaos = Chaos {
        delay_ms: 150,
        ..Default::default()
    };
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out, &[], &["--mem-limit", "8M"])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        log.contains("materializing volumes for repair"),
        "the forced demote never happened - the test proved nothing:\n{log}"
    );
    assert!(log.contains("repair complete"), "no repair:\n{log}");
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.bin")).expect("extracted file"),
        doc,
        "extracted bytes differ"
    );
    let mem = log.lines().find(|l| l.starts_with("[mem] ")).unwrap_or("");
    eprintln!("{mem}");
    for l in log
        .lines()
        .filter(|l| l.contains("re-fetching") || l.contains("fetched "))
    {
        eprintln!("{l}");
    }
    let dropped_mb: u64 = mem
        .split("chase trimmed ")
        .nth(1)
        .and_then(|s| s.split('(').nth(1))
        .and_then(|s| s.split(' ').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if dropped_mb > 0 {
        assert!(
            log.contains("re-fetching") && log.contains("the one-pass trim dropped"),
            "volumes were dropped ({dropped_mb} MB) and demoted but never re-fetched:\n{log}"
        );
        assert!(
            !log.contains("holes stay") && !log.contains("did not come back"),
            "{log}"
        );
    } else {
        eprintln!(
            "note: the engine fell behind the line, so every trim spilled and this run \
             covered the free-demote path rather than the re-fetch"
        );
        assert!(!log.contains("re-fetching"), "{log}");
    }
    for n in &names {
        assert!(
            !fx.dir.join("out").join(n).exists(),
            "volume {n} survived the job:\n{log}"
        );
    }
}
