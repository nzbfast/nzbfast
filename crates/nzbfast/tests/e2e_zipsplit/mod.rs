//! TODO 94 D's nested half, end to end: a `.zip.001` byte split INSIDE
//! a store RAR, counted off the outer archive's entry list rather than
//! the NZB's (`nzbkit::extract::zip_split`), streams as one container
//! through the real `get` pipeline - and with the nested-zip gate off,
//! the same post takes the road it took before the wiring existed: the
//! parts land and the nested disk pass joins them.
//!
//! A child module so e2e.rs stays inside its size-gate baseline (the
//! e2e_split pattern: harness reached through `super::*`).

use super::*;

/// The post under test: a store RAR5 wrapping `movie.mkv`'s zip cut
/// into three parts, with a `readme.txt` behind them so the count can
/// close on a following entry. Returns the fixture and the payload.
fn nested_split_post(tag: &str, seed: u64) -> (Fixture, Vec<u8>) {
    let mut fx = Fixture::new(tag);
    let movie = incompressible(900_000, seed);
    let arch =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)]);
    let parts: Vec<&[u8]> = arch.chunks(arch.len().div_ceil(3)).collect();
    assert_eq!(parts.len(), 3, "fixture must really split");
    let readme = b"release notes\n".repeat(200);
    let outer = fixtures::rar5_volume(&[
        (
            "inner.zip.001",
            parts[0].len() as u64,
            parts[0],
            false,
            false,
        ),
        (
            "inner.zip.002",
            parts[1].len() as u64,
            parts[1],
            false,
            false,
        ),
        (
            "inner.zip.003",
            parts[2].len() as u64,
            parts[2],
            false,
            false,
        ),
        ("readme.txt", readme.len() as u64, &readme[..], false, false),
    ]);
    fx.add_file("o.rar", &outer, 60_000);
    assert!(fx.add_par2(10, &["o.rar"], 60_000));
    (fx, movie)
}

/// One pass all the way down: rc=0, the payload byte-exact, no chase
/// demoted, and neither the outer volume nor any inner part touched
/// the output directory.
#[tokio::test(flavor = "multi_thread")]
async fn nested_zip_split_in_a_store_rar_extracts_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, movie) = nested_split_post("rarzipsplit", 52);
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
    // The payload and the readme, and NOT three parts: what the stream
    // extracted is how the one-pass road and the disk road differ in
    // the log (the gate-off leg below counts four).
    assert!(
        log.contains("extracted 2 file(s) in-stream"),
        "the split did not stream:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(fx.dir.join("out/readme.txt").exists(), "{log}");
    for v in ["o.rar", "inner.zip.001", "inner.zip.002", "inner.zip.003"] {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "{v} must not touch disk:\n{log}"
        );
    }
}

/// The road the wiring replaced, still open behind the gate: with
/// `NZBFAST_NO_NESTED_ZIP=1` the parent still counts the set but the
/// child declines every part, the three parts materialize, and the
/// nested disk pass (`unpack` step 5, `zip::scan`'s byte-split set)
/// joins and extracts them. Same payload out, a job that completes.
#[tokio::test(flavor = "multi_thread")]
async fn nested_zip_split_with_the_gate_off_lands_and_the_disk_pass_joins_it() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, movie) = nested_split_post("rarzipsplitoff", 53);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_NESTED_ZIP", "1")])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    // Three parts plus the readme came out of the stream as plain
    // files; the payload did not - the disk pass made it.
    assert!(
        log.contains("extracted 4 file(s) in-stream"),
        "the parts did not land as plain files:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    for v in ["inner.zip.001", "inner.zip.002", "inner.zip.003"] {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "{v} was left beside the payload:\n{log}"
        );
    }
}

/// The budget road, end to end (the bound `zip_split.rs`'s module doc
/// reasons about and `zip_split_tests` measures): the count can only
/// land behind the set's last byte, so a set that does not fit the
/// holds cap forfeits in the chase - and the nested disk pass's
/// `zip::scan` step joins the landed parts. `--mem-limit` floors at 64
/// MiB, whose 45% slice is 30,198,960 bytes; a 31 MiB set is over it
/// whatever else the chain is holding. Six parts, not three, so each
/// part (5.4 MiB) sits under the quarter-cap pre-sniff window
/// (7.5 MiB) and only the SET bound can fire - the per-part bound has
/// its own unit test. Same payload out, byte-exact, a job that
/// completes: the forfeit is a memory verdict, never a lost download.
#[tokio::test(flavor = "multi_thread")]
async fn nested_zip_split_over_the_holds_cap_forfeits_and_the_disk_pass_joins_it() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rarzipsplitcap");
    let movie = incompressible(31 << 20, 54);
    let arch =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)]);
    let parts: Vec<&[u8]> = arch.chunks(arch.len().div_ceil(6)).collect();
    assert_eq!(parts.len(), 6, "fixture must really split");
    let readme = b"release notes\n".repeat(200);
    let names: Vec<String> = (1..=6).map(|i| format!("inner.zip.{i:03}")).collect();
    let mut entries: Vec<(&str, u64, &[u8], bool, bool)> = names
        .iter()
        .zip(parts.iter())
        .map(|(n, p)| (n.as_str(), p.len() as u64, *p, false, false))
        .collect();
    entries.push(("readme.txt", readme.len() as u64, &readme[..], false, false));
    let outer = fixtures::rar5_volume(&entries);
    fx.add_file("o.rar", &outer, 300_000);
    assert!(fx.add_par2(5, &["o.rar"], 300_000));
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get_args(&cfg, &nzb, &out, &[], &["--mem-limit", "64M"])
    })
    .await
    .unwrap();
    assert!(ok, "get failed:\n{log}");
    assert!(
        log.contains("inner holds budget exceeded"),
        "the set must forfeit on the cap:\n{log}"
    );
    // Six parts plus the readme came out of the stream as plain files,
    // and the disk pass joined them - the same split-zip step the
    // gate-off leg above exercises, reached by the budget this time.
    assert!(
        log.contains("extracted 7 file(s) in-stream"),
        "the parts did not land as plain files:\n{log}"
    );
    assert!(
        log.contains("unpacking split zip natively"),
        "the disk pass did not join the parts:\n{log}"
    );
    assert_eq!(
        std::fs::read(fx.dir.join("out/movie.mkv")).expect("extracted file"),
        movie,
        "extracted bytes differ"
    );
    assert!(fx.dir.join("out/readme.txt").exists(), "{log}");
    for v in names.iter().map(String::as_str).chain(["o.rar"]) {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "{v} was left beside the payload:\n{log}"
        );
    }
}
