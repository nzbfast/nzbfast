//! Tree-preserving member paths, end to end (the relpath-preserve
//! ruling, 29 Aug 2026: a DVD or Blu-ray has to have its directory
//! structure intact for it to play).
//!
//! A sibling-dir child of e2e.rs (the e2e_repair pattern) so the parent
//! stays inside its size-gate baseline; helpers via `super::*`.
//!
//! Both member-path sources are pinned here: PAR2 FileDesc names on a
//! bare no-RAR post (the disc-tree shape the Reddit round asked about),
//! and archive member paths through the in-stream extractor. The
//! flatten fallback is pinned from the same angle: a traversal-shaped
//! name lands FLAT and contained, exactly as it always has.

use super::*;

/// A bare no-RAR disc tree: the payload is posted fully obfuscated
/// (hash subjects, hash yEnc names), and the only place the real names
/// exist is the PAR2 FileDesc - which spells them as paths,
/// `VIDEO_TS/VTS_01_1.VOB`. The adoption/verify tier ties each slot to
/// its descriptor by content, and the verified-name publish must land
/// the TREE, not `VIDEO_TS_VTS_01_1.VOB` flat.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_tree_post_lands_its_video_ts_tree_intact() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("reltree");
    let vob = payload(900_000, 91);
    let ifo = payload(120_000, 92);
    fx.add_file_renamed_by_par2("VIDEO_TS/VTS_01_1.VOB", "Xk4pQn8rLw1", &vob, 60_000);
    fx.add_file_renamed_by_par2("VIDEO_TS/VTS_01_0.IFO", "Zm2vTc5yHd9", &ifo, 60_000);
    assert!(
        fx.add_par2(
            20,
            &["VIDEO_TS/VTS_01_1.VOB", "VIDEO_TS/VTS_01_0.IFO"],
            60_000
        ),
        "par2 create failed"
    );
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    assert!(ok, "get failed on a bare tree post:\n{log}");
    // The tree, intact and plays-shaped: VIDEO_TS/ with its files.
    let landed_vob = std::fs::read(out.join("VIDEO_TS").join("VTS_01_1.VOB"))
        .unwrap_or_else(|e| panic!("VOB missing from the tree: {e}\n{log}"));
    assert_eq!(landed_vob, vob, "VOB bytes differ\n{log}");
    let landed_ifo = std::fs::read(out.join("VIDEO_TS").join("VTS_01_0.IFO"))
        .unwrap_or_else(|e| panic!("IFO missing from the tree: {e}\n{log}"));
    assert_eq!(landed_ifo, ifo, "IFO bytes differ\n{log}");
    // Nothing may land under the flattened spelling.
    assert!(
        !out.join("VIDEO_TS_VTS_01_1.VOB").exists(),
        "the VOB landed flat as well as (or instead of) in the tree\n{log}"
    );
}

/// M4-71: the DEEPEST shape a real disc has. The existing pin above is
/// a 2-component DVD tree; a Blu-ray goes to four -
/// `BDMV/BACKUP/CLIPINF/00000.clpi` - and the matrix row predicted the
/// relpath depth cap flattens a playable disc. Measured 30 Aug 2026 it
/// does not: real trees are 2-4 deep with 12-16 byte components against
/// caps of 16 / 255 / 1024, which
/// `relpath::tests::every_real_disc_tree_path_is_preserved_with_room_to_spare`
/// pins exactly. This is that measurement taken end to end, through the
/// PAR2 FileDesc publish that actually builds the directories - the
/// unit test knows what the NAME should be, only a run knows whether
/// four levels of parent get created under the job dir.
#[tokio::test(flavor = "multi_thread")]
async fn a_four_deep_bluray_tree_lands_intact() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("bdmvtree");
    let m2ts = payload(700_000, 71);
    let clpi = payload(90_000, 72);
    // Three deep, and the four-deep backup arm beside it.
    fx.add_file_renamed_by_par2("BDMV/STREAM/00000.m2ts", "Qw9zRt3vBn6", &m2ts, 60_000);
    fx.add_file_renamed_by_par2(
        "BDMV/BACKUP/CLIPINF/00000.clpi",
        "Hy7dKs2mPx4",
        &clpi,
        60_000,
    );
    assert!(
        fx.add_par2(
            20,
            &["BDMV/STREAM/00000.m2ts", "BDMV/BACKUP/CLIPINF/00000.clpi"],
            60_000
        ),
        "par2 create failed"
    );
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    assert!(ok, "get failed on a four-deep Blu-ray tree:\n{log}");
    let landed = std::fs::read(out.join("BDMV").join("STREAM").join("00000.m2ts"))
        .unwrap_or_else(|e| panic!("m2ts missing from the tree: {e}\n{log}"));
    assert_eq!(landed, m2ts, "m2ts bytes differ\n{log}");
    let landed = std::fs::read(
        out.join("BDMV")
            .join("BACKUP")
            .join("CLIPINF")
            .join("00000.clpi"),
    )
    .unwrap_or_else(|e| panic!("clpi missing from the four-deep arm: {e}\n{log}"));
    assert_eq!(landed, clpi, "clpi bytes differ\n{log}");
    // A disc that plays needs the tree, not the bytes: nothing may land
    // under the flattened spelling of either.
    for flat in ["BDMV_STREAM_00000.m2ts", "BDMV_BACKUP_CLIPINF_00000.clpi"] {
        assert!(
            !out.join(flat).exists(),
            "{flat} landed flat as well as (or instead of) in the tree\n{log}"
        );
    }
    // Keep the fixture alive past every assertion - its ScratchDir
    // guard deletes the tree the asserts above are graded against.
    drop(fx);
}

/// The other member-path source: the same disc tree inside a store-mode
/// RAR. The in-stream extractor delivers the member at its tree path.
#[tokio::test(flavor = "multi_thread")]
async fn a_rar_d_tree_lands_intact() {
    let mut fx = Fixture::new("rartree");
    let inner = payload(700_000, 93);
    let vol = fixtures::rar5_volume(&[("VIDEO_TS/VTS_01_1.VOB", 700_000, &inner, false, false)]);
    fx.add_file("r.rar", &vol, 60_000);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    assert!(ok, "get failed on a RAR'd tree:\n{log}");
    let landed = std::fs::read(out.join("VIDEO_TS").join("VTS_01_1.VOB"))
        .unwrap_or_else(|e| panic!("member missing from the tree: {e}\n{log}"));
    assert_eq!(landed, inner, "member bytes differ\n{log}");
    assert!(
        !out.join("VIDEO_TS_VTS_01_1.VOB").exists(),
        "the member landed flat as well\n{log}"
    );
}

/// Duplicate basenames in different directories are two files, not one:
/// `a/readme.txt` and `b/readme.txt` each keep their own tree and their
/// own bytes. (Flattened, the pair used to collide and ride the
/// disambiguation suffix.)
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_basenames_in_two_dirs_both_land() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("reldup");
    let one = payload(300_000, 94);
    let two = payload(300_000, 95);
    fx.add_file_renamed_by_par2("a/readme.txt", "Qw7fJm2nRv4", &one, 60_000);
    fx.add_file_renamed_by_par2("b/readme.txt", "Ht5kBc9xPz6", &two, 60_000);
    assert!(
        fx.add_par2(20, &["a/readme.txt", "b/readme.txt"], 60_000),
        "par2 create failed"
    );
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    assert!(ok, "get failed on the duplicate-basename tree:\n{log}");
    assert_eq!(
        std::fs::read(out.join("a").join("readme.txt")).expect("a/readme.txt"),
        one,
        "a/readme.txt bytes differ\n{log}"
    );
    assert_eq!(
        std::fs::read(out.join("b").join("readme.txt")).expect("b/readme.txt"),
        two,
        "b/readme.txt bytes differ\n{log}"
    );
}

/// The flatten fallback, unchanged byte for byte: traversal-shaped yEnc
/// names land FLAT inside the output directory and never outside it.
/// par2-gate: exercises the no-par2 flatten path on purpose.
#[tokio::test(flavor = "multi_thread")]
async fn traversal_names_flatten_and_stay_contained() {
    let mut fx = Fixture::new("reltrav");
    let a = payload(80_000, 96);
    let b = payload(80_000, 97);
    let c = payload(80_000, 98);
    // Straight to articles - `add_file` stages the fixture copy on disk
    // for par2 create, and a traversal name must not be joined onto
    // ANY directory, the fixture's included.
    let post = |name: &str, data: &[u8], fx: &mut Fixture| {
        let tag = format!("trav-{}", fx.nzb_files.len());
        let segs = make_file_articles(name, data, 60_000, &tag, &mut fx.articles);
        fx.nzb_files.push((name.to_string(), segs));
    };
    post("../evil.bin", &a, &mut fx);
    post("/abs/evil2.bin", &b, &mut fx);
    post("C:\\evil3.dll", &c, &mut fx);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    assert!(ok, "get failed on traversal-shaped names:\n{log}");
    // Contained: nothing escaped past the output directory.
    assert!(
        !fx.dir.join("evil.bin").exists() && !fx.dir.join("evil2.bin").exists(),
        "a traversal name escaped the output directory\n{log}"
    );
    // Flat and contained, which is what this test is for. The SPELLING
    // of the `../` shape moved on 30 Aug 2026 (M4-66): leading dots are
    // mapped to `_` rather than deleted, so `../evil.bin` is
    // `.._evil.bin` after the separator map and `___evil.bin` after the
    // dot map, where it used to be `_evil.bin`. That is the point of the
    // row rather than a side effect - `../evil.bin`, `./evil.bin` and a
    // poster's literal `_evil.bin` all used to flatten onto ONE name.
    assert_eq!(
        std::fs::read(out.join("___evil.bin")).expect("../ shape"),
        a
    );
    assert_eq!(
        std::fs::read(out.join("_abs_evil2.bin")).expect("absolute shape"),
        b
    );
    // ':' maps on Windows only; on unix the drive-letter shape keeps its
    // colon but still flattens the separator.
    let win = out.join("C__evil3.dll");
    let unix = out.join("C:_evil3.dll");
    let got = std::fs::read(if cfg!(windows) { &win } else { &unix })
        .expect("drive-letter shape must land flat");
    assert_eq!(got, c);
}

/// X5-09 (codex Extreme Wave 5, 30 Aug 2026): a canonical-name
/// publication FAILURE must reach the verdict.
///
/// The injection is the one `create_out_dirs` already refuses on
/// purpose - a symlink where a member path needs a real directory - and
/// it takes the same arm EXDEV, EACCES and a Windows sharing violation
/// take: `publish_verified_name` warns and returns `None`. That `None`
/// is also what "already at the right name" returns, so no caller could
/// tell them apart and the job used to finish rc=0 with the payload
/// still under its hash and one warn line to show for it.
///
/// Correct: nonzero, WITH the verified source preserved - never a
/// quarantine of bytes the recovery set vouched for, and never anything
/// written through the symlink.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_member_path_fails_the_job_and_keeps_the_source() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("relrefused");
    let child = payload(200_000, 99);
    fx.add_file_renamed_by_par2("sub/child.bin", "Zk9pLm42Qw", &child, 40_000);
    assert!(
        fx.add_par2(20, &["sub/child.bin"], 40_000),
        "par2 create failed"
    );
    std::fs::remove_file(fx.dir.join("sub/child.bin")).unwrap();
    // The output directory exists before the job, with `sub` a symlink
    // pointing at a real directory OUTSIDE it.
    let escape = fx.dir.join("escape");
    std::fs::create_dir_all(&escape).unwrap();
    let out = fx.dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::os::unix::fs::symlink(&escape, out.join("sub")).unwrap();
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    assert!(
        !ok,
        "a refused member path finished rc=0 - the publication failure never \
         reached the verdict (X5-09)\n{log}"
    );
    // The verified bytes are still there, under the name they were
    // posted under. Preserved, not quarantined and not deleted.
    assert_eq!(
        std::fs::read(out.join("Zk9pLm42Qw")).expect("the verified source must be preserved"),
        child,
        "the preserved source is not byte-exact\n{log}"
    );
    // Nothing was routed through the symlink.
    assert_eq!(
        std::fs::read_dir(&escape).unwrap().count(),
        0,
        "the payload was written outside the output directory\n{log}"
    );
}
