use super::*;
use nzbkit::par2::{Par2File, Par2Set};

fn tdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-parity-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pfile(name: &str, length: u64) -> Par2File {
    Par2File {
        file_id: [1u8; 16],
        name: name.to_string(),
        length,
        md5: [0u8; 16],
        md5_16k: [0u8; 16],
        blocks: Vec::new(),
    }
}

fn pset(files: Vec<Par2File>) -> Par2Set {
    Par2Set {
        recovery_set_id: [0u8; 16],
        block_size: 4096,
        files,
        recovery_blocks_seen: 3,
    }
}

/// Drive `try_mapped_repair` with no servers, no reports, and the
/// given par2 set + missing names; return its verdict.
async fn mapped_verdict(
    dir: &Path,
    ex: &nzbkit::extract::Extractor,
    set: &Par2Set,
    missing: &[String],
) -> bool {
    mapped_verdict_with_reports(dir, ex, set, missing, &[]).await
}

/// [`mapped_verdict`] with slot reports, for the gate cases that need
/// a verified/damaged slot rather than an unclaimed file.
async fn mapped_verdict_with_reports(
    dir: &Path,
    ex: &nzbkit::extract::Extractor,
    set: &Par2Set,
    missing: &[String],
    reports: &[(usize, nzbkit::live::SlotReport)],
) -> bool {
    let servers: Vec<(ServerConfig, nzbkit::pool::PoolConfig)> = Vec::new();
    let nzb = Nzb {
        files: Vec::new(),
        meta: Vec::new(),
    };
    try_mapped_repair(
        &servers,
        &nzb,
        dir,
        set,
        0,
        &[],
        &[],
        nzbkit::pool::BufPool::new(4),
        ex,
        reports,
        missing,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut None,
        false,
        None,
        // `needed` is 0 here, so nothing fetches and the seam is
        // never exercised - an unheld handle keeps this test off the
        // process-global permit the parallel suite shares.
        &mut crate::lanegate::HeavyCpu::unheld(),
    )
    .await
    .expect("guard declines are Ok(false), not errors")
}

/// Adversarial: a par2 set declaring a 64 GiB target over 4 KiB
/// blocks (16M slices against a 32768-slice format) with a handful
/// of recovery blocks must be refused BEFORE any slot allocation or
/// preallocation - no file, no reservation, just a decline to the
/// disk path.
#[tokio::test]
async fn parity_source_refuses_a_preallocation_bomb() {
    let dir = tdir("bomb");
    let ex = nzbkit::extract::Extractor::new(&dir, 0, true);
    let set = pset(vec![pfile("huge.bin", 64 << 30)]);
    assert!(!mapped_verdict(&dir, &ex, &set, &["huge.bin".to_string()]).await);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "the declined bomb must leave nothing behind"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Adversarial: a FileDesc name colliding with a file some output
/// writer already carries - posted wins, no second slot, decline to
/// the disk path (whose adoption scan owns renamed/shifted cases).
#[tokio::test]
async fn parity_source_never_double_slots_a_posted_name() {
    let dir = tdir("collide");
    let ex = nzbkit::extract::Extractor::new(&dir, 1, true);
    let posted = vec![0x5Au8; 8192];
    ex.write(0, "movie.mkv", 8192, 0, &posted).unwrap();
    let set = pset(vec![pfile("movie.mkv", 8192)]);
    assert!(!mapped_verdict(&dir, &ex, &set, &["movie.mkv".to_string()]).await);
    assert_eq!(
        std::fs::read(dir.join("movie.mkv")).unwrap(),
        posted,
        "the posted file must be untouched"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A zero-length declared target and an absurd recreated-file count
/// both decline (the disk path creates empty files; a fed slot with
/// no writes would "verify" without creating one).
#[tokio::test]
async fn parity_source_declines_zero_length_and_absurd_counts() {
    let dir = tdir("zeroct");
    let ex = nzbkit::extract::Extractor::new(&dir, 0, true);
    let set = pset(vec![pfile("empty.bin", 0)]);
    assert!(!mapped_verdict(&dir, &ex, &set, &["empty.bin".to_string()]).await);

    let many: Vec<Par2File> = (0..1001)
        .map(|i| pfile(&format!("f{i}.bin"), 4096))
        .collect();
    let names: Vec<String> = many.iter().map(|f| f.name.clone()).collect();
    let set = pset(many);
    assert!(!mapped_verdict(&dir, &ex, &set, &names).await);
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(feature = "indexer")]
#[test]
fn trunc_respects_char_boundaries() {
    // `&stem[..60]` panicked mid-char on non-ASCII release names.
    let s = "é".repeat(40); // 80 bytes; byte 60 is mid-char
    let t = trunc(&s, 60);
    assert!(t.len() <= 60 && s.starts_with(t));
    assert_eq!(trunc("short", 60), "short");
    assert_eq!(trunc("exactly!", 8), "exactly!");
}

#[test]
fn first_rar_volume_picks_lowest_part_any_width() {
    let paths = |names: &[&str]| -> Vec<PathBuf> { names.iter().map(PathBuf::from).collect() };
    let pick =
        |names: &[&str]| first_rar_volume(&paths(names)).map(|p| p.to_string_lossy().into_owned());
    // 3-digit set with a stray sample: part001 must win.
    assert_eq!(
        pick(&["Movie.sample.rar", "Movie.part002.rar", "Movie.part001.rar"]),
        Some("Movie.part001.rar".to_string())
    );
    // 2- and 1-digit conventions still work.
    assert_eq!(
        pick(&["X.part02.rar", "X.part01.rar"]),
        Some("X.part01.rar".to_string())
    );
    assert_eq!(
        pick(&["X.part2.rar", "X.part1.rar"]),
        Some("X.part1.rar".to_string())
    );
    // No part-numbered files → lexically first plain .rar.
    assert_eq!(pick(&["b.rar", "a.rar"]), Some("a.rar".to_string()));
    // ".part" without digits is not a part number.
    assert_eq!(pick(&["The.Party.rar"]), Some("The.Party.rar".to_string()));
    assert_eq!(pick(&[]), None);
}

#[test]
fn vol_counts_parse() {
    assert_eq!(vol_count_from_name("x.vol063+64.par2"), Some(64));
    assert_eq!(vol_count_from_name("x.vol0+1.par2"), Some(1));
    assert_eq!(vol_count_from_name("X.VOL127+53.PAR2"), Some(53));
    assert_eq!(vol_count_from_name("x.par2"), None);
    assert_eq!(vol_count_from_name("x.vol1.par2"), None);
    // par2cmdline at -b32768 emits zero-count volumes and 5-digit
    // exponents (par2cmdline#205) - both must parse, never panic.
    assert_eq!(vol_count_from_name("disk1.vol34529+00000.par2"), Some(0));
    assert_eq!(vol_count_from_name("x.vol10000+12345.par2"), Some(12345));
}

/// The speculative recovery prefetch promises "a tiny side pool (1
/// conn/server)": the main pool already holds this account's grants, so
/// a second full fleet mid-download runs the provider's connection cap
/// over and gets the whole job refused. The pool sizes itself from
/// PoolConfig, so setting only ServerConfig.connections leaves it
/// full-size.
#[test]
fn speculative_prefetch_side_pool_is_one_connection_per_server() {
    let server = |host: &str| nzbkit::config::ServerConfig {
        host: host.into(),
        port: 119,
        tls: false,
        username: None,
        password: None,
        connections: 50,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: None,
        block_account: false,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
    };
    let live = nzbkit::pool::LiveStats::for_servers(&[
        (server("a.example"), nzbkit::pool::PoolConfig::default()),
        (server("b.example"), nzbkit::pool::PoolConfig::default()),
    ]);
    let main: Vec<_> = ["a.example", "b.example"]
        .iter()
        .map(|h| {
            (
                server(h),
                nzbkit::pool::PoolConfig {
                    connections: 50,
                    window: 8,
                    live: Some(live.clone()),
                    ..Default::default()
                },
            )
        })
        .collect();
    let side = side_pool_servers(&main);
    assert_eq!(side.len(), 2, "every server keeps a side connection");
    for (sc, pc) in &side {
        assert_eq!(
            pc.connections, 1,
            "{}: side pool opened a full fleet",
            sc.host
        );
        assert_eq!(sc.connections, 1, "{}: server config not shrunk", sc.host);
        // Side-pool workers are not the download; they must not move
        // the dashboard's per-server gauges.
        assert!(
            pc.live.is_none(),
            "{}: side pool feeds the dashboard",
            sc.host
        );
        // Everything else about the fleet is preserved.
        assert_eq!(pc.window, 8, "{}: unrelated pool settings dropped", sc.host);
    }
    // The download's own fleet is untouched.
    assert_eq!(main[0].1.connections, 50, "main pool shrunk");
    assert_eq!(main[0].0.connections, 50, "main server config shrunk");
}

#[test]
fn braces_password_convention() {
    let p = |s: &str| braces_password(std::path::Path::new(s));
    assert_eq!(p("Movie.2026{{s3cret}}.nzb"), Some("s3cret".into()));
    assert_eq!(p("/spool/Show{{p w!d}}.nzb"), Some("p w!d".into()));
    assert_eq!(p("Movie.2026.nzb"), None);
    assert_eq!(p("Odd{{}}.nzb"), None);
}

#[test]
fn exact_fit_beats_greedy() {
    // Need 5. Volumes: 1+2+4 series (bytes ∝ slices).
    let vols = vec![(0, 1, 100), (1, 2, 200), (2, 4, 400), (3, 8, 800)];
    let chosen = pick_volumes(&vols, 5);
    let blocks: usize = chosen.iter().map(|&i| vols[i].1).sum();
    let bytes: u64 = chosen.iter().map(|&i| vols[i].2).sum();
    assert!(blocks >= 5);
    // Optimal is 1+4 = 500 bytes (not 8 = 800, not 1+2+4 = 700).
    assert_eq!(bytes, 500, "chosen {chosen:?}");
}

#[test]
fn single_oversize_when_cheapest() {
    let vols = vec![(0, 1, 900), (1, 10, 500)];
    let chosen = pick_volumes(&vols, 2);
    assert_eq!(chosen, vec![1]);
}

fn reex_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-reex-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The hold exists to protect the outer volume set during nested
/// extraction, so "the restore failed, therefore delete what we were
/// protecting" is the one response it must never have. It used to swallow
/// every rename error and then `remove_dir_all` the hold regardless.
#[test]
fn outer_hold_never_deletes_a_volume_it_could_not_put_back() {
    let dir = reex_dir("holdstrand");
    let hold = dir.join(".nzbfast-hold");
    std::fs::create_dir_all(&hold).unwrap();
    std::fs::write(hold.join("parked.rar"), b"the only copy").unwrap();
    // Something already occupies the destination name as a DIRECTORY, so
    // renaming the file back over it cannot succeed.
    std::fs::create_dir_all(dir.join("parked.rar")).unwrap();
    std::fs::write(dir.join("parked.rar/blocker"), b"x").unwrap();

    drop(super::OuterHold {
        dir: dir.clone(),
        hold: hold.clone(),
    });

    assert!(
        hold.join("parked.rar").exists(),
        "a volume that could not be restored was deleted with the hold"
    );
    assert_eq!(
        std::fs::read(hold.join("parked.rar")).unwrap(),
        b"the only copy"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and it never REPLACES a file that took the name while the volume
/// was parked.
///
/// The nested pass runs with the hold live, and it publishes through
/// `lift_scratch_into`, whose collision test is existence only - so a
/// nested member legitimately named like one of the outer volumes finds
/// the name free (the volume is in the hold) and lands on it. `restore`
/// then renamed the volume straight over it: POSIX rename replaces a
/// regular file, so the produced deliverable was destroyed and the job
/// still completed green. Both files survive now, which is the same rule
/// `ExtractStaging` documents for the identical collision.
#[test]
fn outer_hold_restore_never_replaces_a_file_that_took_the_name() {
    let dir = reex_dir("holdcollide");
    let hold = dir.join(".nzbfast-hold");
    std::fs::create_dir_all(&hold).unwrap();
    std::fs::write(hold.join("parked.rar"), b"the parked volume").unwrap();
    // The nested pass produced a member of exactly that name while the
    // volume was out of the way.
    std::fs::write(dir.join("parked.rar"), b"the produced payload").unwrap();

    drop(super::OuterHold {
        dir: dir.clone(),
        hold: hold.clone(),
    });

    assert_eq!(
        std::fs::read(dir.join("parked.rar")).unwrap(),
        b"the parked volume",
        "the volume must be restored under the name its set depends on"
    );
    let aside = dir.join("extracted-1-parked.rar");
    assert!(
        aside.exists(),
        "the produced file was replaced instead of being moved aside"
    );
    assert_eq!(
        std::fs::read(&aside).unwrap(),
        b"the produced payload",
        "the produced file survived under the wrong bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `park`'s SELECTION had no direct coverage: it was exercised only
/// through the three `compressed_*` e2e tests, and Part B of the
/// one-pass spec deletes spent volumes BEFORE the nested pass, so
/// `outer_vols_on_disk()` is false there now and those tests park
/// nothing. The path is still live in production (encrypted-no-password
/// keeps its volumes; a `spent()` that reports nothing leaves them), and
/// getting the selection wrong in either direction is bad: park too
/// little and the nested pass re-extracts the outer set beside the
/// payload, park too much and the payload itself vanishes mid-pass.
#[test]
fn outer_hold_parks_only_the_outer_volume_set() {
    let dir = reex_dir("holdpark");
    let stems: std::collections::HashSet<String> = ["Release.Name.2015.2160p-GRP".to_string()]
        .into_iter()
        .collect();
    let vols = [
        "Release.Name.2015.2160p-GRP.part001.rar",
        "Release.Name.2015.2160p-GRP.part002.rar",
    ];
    for v in vols {
        std::fs::write(dir.join(v), v.as_bytes()).unwrap();
    }
    // Produced BY the outer unpack - a different stem, so the nested pass
    // must still see it.
    std::fs::write(dir.join("inner.rar"), b"nested archive").unwrap();
    // Not a RAR at all, and a subdirectory: neither is park's business.
    std::fs::write(dir.join("movie.mkv"), b"payload").unwrap();
    std::fs::create_dir_all(dir.join("Sub")).unwrap();
    std::fs::write(
        dir.join("Sub/Release.Name.2015.2160p-GRP.part003.rar"),
        b"deeper",
    )
    .unwrap();

    let hold = {
        let parked = super::OuterHold::park(&dir, &stems).unwrap();
        let hold = dir.join(".nzbfast-outer-hold");
        for v in vols {
            assert!(hold.join(v).is_file(), "{v} was not parked");
            assert!(!dir.join(v).exists(), "{v} left behind in the job dir");
        }
        assert!(
            dir.join("inner.rar").is_file(),
            "the nested archive was parked"
        );
        assert!(dir.join("movie.mkv").is_file(), "the payload was parked");
        assert!(
            dir.join("Sub/Release.Name.2015.2160p-GRP.part003.rar")
                .is_file(),
            "park reached into a subdirectory"
        );
        drop(parked);
        hold
    };

    // Drop puts the set back byte-exact and takes the hold with it.
    for v in vols {
        assert_eq!(
            std::fs::read(dir.join(v)).unwrap(),
            v.as_bytes(),
            "{v} not restored"
        );
    }
    assert!(!hold.exists(), "an emptied hold should be removed");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A crashed run can leave volumes parked. The next `park` must fold
/// them back before it starts, or the second park's hold silently
/// shadows the first one's contents and the restore returns only half
/// the set to the job dir.
#[test]
fn outer_hold_park_folds_back_a_crashed_runs_hold_first() {
    let dir = reex_dir("holdcrash");
    let stems: std::collections::HashSet<String> = ["x".to_string()].into_iter().collect();
    // Left behind by a run that died mid-pass.
    let stale = dir.join(".nzbfast-outer-hold");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join("x.part001.rar"), b"vol one").unwrap();
    // ...while volume two is still sitting in the job dir.
    std::fs::write(dir.join("x.part002.rar"), b"vol two").unwrap();

    let parked = super::OuterHold::park(&dir, &stems).unwrap();
    assert!(
        stale.join("x.part001.rar").is_file() && stale.join("x.part002.rar").is_file(),
        "park did not fold the stale hold back before re-parking"
    );
    drop(parked);

    assert_eq!(
        std::fs::read(dir.join("x.part001.rar")).unwrap(),
        b"vol one"
    );
    assert_eq!(
        std::fs::read(dir.join("x.part002.rar")).unwrap(),
        b"vol two"
    );
    assert!(!stale.exists(), "an emptied hold should be removed");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// ...and the ordinary path still cleans up after itself.
#[test]
fn outer_hold_restores_and_removes_itself_when_it_can() {
    let dir = reex_dir("holdclean");
    let hold = dir.join(".nzbfast-hold");
    std::fs::create_dir_all(&hold).unwrap();
    std::fs::write(hold.join("vol.rar"), b"payload").unwrap();

    drop(super::OuterHold {
        dir: dir.clone(),
        hold: hold.clone(),
    });

    assert_eq!(std::fs::read(dir.join("vol.rar")).unwrap(), b"payload");
    assert!(!hold.exists(), "an emptied hold should be removed");
    let _ = std::fs::remove_dir_all(&dir);
}

fn reex_vols(total: &[u8]) -> [Vec<u8>; 2] {
    use nzbkit::rar::fixtures;
    let n = total.len() as u64;
    let half = total.len() / 2;
    [
        fixtures::rar5_volume_n(&[("film.mkv", n, &total[..half], false, true)], 0),
        fixtures::rar5_volume_n(&[("film.mkv", n, &total[half..], true, false)], 1),
    ]
}

/// The nest lift-back must merge produced subdirs into pre-existing
/// ones and disambiguate file collisions instead of silently
/// overwriting - the old blind rename-then-sweep swallowed the
/// ENOTEMPTY failure and then deleted the stranded payload.
#[test]
fn lift_nest_outputs_merges_and_never_overwrites() {
    let dir = reex_dir("liftback");
    let sub = dir.join(".nzbfast-nest");
    std::fs::create_dir_all(sub.join("Sub")).unwrap();
    std::fs::create_dir_all(dir.join("Sub")).unwrap();
    std::fs::write(dir.join("Sub").join("keep.bin"), b"keep").unwrap();
    std::fs::write(dir.join("a.bin"), b"original").unwrap();
    std::fs::write(sub.join("Sub").join("inner.bin"), b"inner").unwrap();
    std::fs::write(sub.join("a.bin"), b"produced").unwrap();
    std::fs::write(sub.join("fresh.bin"), b"fresh").unwrap();
    assert!(lift_nest_outputs(&sub, &dir));
    // Pre-existing content survives untouched…
    assert_eq!(
        std::fs::read(dir.join("Sub").join("keep.bin")).unwrap(),
        b"keep"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), b"original");
    // …and produced content all arrives (collision disambiguated).
    assert_eq!(
        std::fs::read(dir.join("Sub").join("inner.bin")).unwrap(),
        b"inner"
    );
    assert_eq!(
        std::fs::read(dir.join("nested-1-a.bin")).unwrap(),
        b"produced"
    );
    assert_eq!(std::fs::read(dir.join("fresh.bin")).unwrap(), b"fresh");
    // The scratch dir is fully emptied - safe for the caller to sweep.
    assert!(std::fs::read_dir(&sub).unwrap().next().is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Only the operator-supplied job password may pay for a hostile-depth
/// KDF; harvested candidates stop at the ceiling.
#[test]
fn kdf_gate_spares_structured_candidates_only() {
    assert!(kdf_candidate_allowed(24, true));
    assert!(!kdf_candidate_allowed(24, false));
    assert!(kdf_candidate_allowed(PW_KDF_MAX_LG2, false));
    assert!(kdf_candidate_allowed(15, false));
}

/// A zip is a real archive as far as descent is concerned, but a
/// `.cbz` payload never is.
#[test]
fn zip_counts_as_an_archive_for_descent() {
    let dir = reex_dir("zipdescent");
    std::fs::write(dir.join("a.zip"), b"PK\x03\x04zip").unwrap();
    std::fs::write(dir.join("comic.cbz"), b"PK\x03\x04zip").unwrap();
    assert!(is_extractable_archive(&dir.join("a.zip")));
    assert!(!is_extractable_archive(&dir.join("comic.cbz")));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The shape that used to complete SILENTLY: a byte-split zip matched
/// no detector at all, so the pass reported "nothing to extract" and
/// the job succeeded with its whole payload still packed.
#[test]
fn byte_split_zip_is_reported_not_silently_passed() {
    let dir = reex_dir("zipsplit");
    std::fs::write(dir.join("movie.zip.001"), b"PK\x03\x04first part").unwrap();
    std::fs::write(dir.join("movie.zip.002"), b"second part").unwrap();
    assert_eq!(
        extract_nested(&dir, None, 0).unwrap(),
        NestOutcome::ZipGap,
        "must not report success"
    );
    let u = unsupported_archive_present(&dir).expect("the split set must be found");
    assert_eq!(u.display, "movie.zip.001");
    assert_eq!(u.shape, "split zip");
    assert!(
        u.blocking,
        "the zip is all there is - the user got nothing usable"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A zip in a release subfolder used to be invisible: descent only
/// seeded subdirs holding RAR or 7z magic, so nothing ever looked.
#[test]
fn subfolder_zip_is_found_and_ranked_against_the_payload() {
    let dir = reex_dir("zipsub");
    std::fs::create_dir_all(dir.join("Subs")).unwrap();
    std::fs::write(dir.join("Subs/subs.zip"), b"PK\x03\x04subtitles").unwrap();
    // Sidecar: the feature landed, so the zip is a note, not a problem.
    std::fs::write(dir.join("movie.mkv"), b"the actual payload").unwrap();
    let u = unsupported_archive_present(&dir).expect("subfolder zip must be found");
    assert_eq!(u.display, "Subs/subs.zip");
    assert!(!u.blocking, "a subs zip beside a feature is not a blocker");
    // ...and an offline `extract` must NOT fail over it.
    assert!(
        extract_local(&dir, None).unwrap(),
        "a sidecar zip must not fail the extract"
    );

    // Take the payload away and the same zip becomes the whole story.
    std::fs::remove_file(dir.join("movie.mkv")).unwrap();
    assert!(unsupported_archive_present(&dir).unwrap().blocking);
    assert!(
        !extract_local(&dir, None).unwrap(),
        "a payload zip must fail loudly"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A sidecar zip must not absolve an UNRELATED extraction failure.
/// The forgiving arm keyed off "is there a non-blocking zip anywhere",
/// so a 7z we could not unpack plus any `Subs/subs.zip` exited 0 with
/// nothing importable on disk (and the daemon reported Completed).
#[test]
fn failed_sevenz_is_not_forgiven_by_a_sidecar_zip() {
    let dir = reex_dir("zipalibi");
    // Not a real 7z: extraction is guaranteed to fail.
    std::fs::write(dir.join("movie.7z"), b"7z\xbc\xaf\x27\x1cnot really").unwrap();
    std::fs::create_dir_all(dir.join("Subs")).unwrap();
    std::fs::write(dir.join("Subs/subs.zip"), b"PK\x03\x04subtitles").unwrap();
    // The zip finding on its own reads as a harmless sidecar: the .7z
    // itself counts as payload, so nothing here is "blocking".
    assert!(!unsupported_archive_present(&dir).unwrap().blocking);
    // The pass stopped at the 7z, not the zip, so it must still fail.
    assert_eq!(extract_nested(&dir, None, 0).unwrap(), NestOutcome::Failed);
    assert!(
        !extract_local(&dir, None).unwrap(),
        "a failed 7z must fail the extract"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The same alibi on the early-return path: a zip found FIRST must not
/// end the pass while a supported archive still sits unattempted in a
/// subfolder. `extract_one_level` only ever sees one level, so the
/// descent has to run before the forgivable zip cause may be reported -
/// otherwise the job completed with nothing but two packed archives.
#[test]
fn a_top_level_zip_does_not_skip_the_subfolder_archive() {
    let dir = reex_dir("zipfirst");
    std::fs::write(dir.join("extras.zip"), b"PK\x03\x04extras").unwrap();
    std::fs::create_dir_all(dir.join("CD1")).unwrap();
    // Not a real 7z: the subfolder extraction is guaranteed to fail.
    std::fs::write(dir.join("CD1/movie.7z"), b"7z\xbc\xaf\x27\x1cnot really").unwrap();
    // The zip on its own reads as a harmless sidecar - the still-packed
    // .7z counts as payload - so the heuristic cannot be what decides it.
    assert!(!unsupported_archive_present(&dir).unwrap().blocking);
    assert_eq!(extract_nested(&dir, None, 0).unwrap(), NestOutcome::Failed);
    assert!(
        !extract_local(&dir, None).unwrap(),
        "a subfolder archive we could not unpack must fail the extract"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// PAR2 sets and scene furniture are not payload: a directory holding
/// only a zip and its recovery files still leaves the user empty.
#[test]
fn furniture_does_not_count_as_payload() {
    let dir = reex_dir("zipfurniture");
    std::fs::write(dir.join("movie.zip"), b"PK\x03\x04packed").unwrap();
    std::fs::write(dir.join("movie.par2"), b"PAR2\x00PKT").unwrap();
    std::fs::write(dir.join("movie.nfo"), b"scene notes").unwrap();
    assert!(unsupported_archive_present(&dir).unwrap().blocking);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Build a store-only RAR5 holding one entry.
fn rar_of(name: &'static [u8], data: &[u8]) -> Vec<u8> {
    rars::rar50::Rar50Writer::new(rars::rar50::WriterOptions::new(
        rars::ArchiveVersion::Rar50,
        rars::FeatureSet::store_only(),
    ))
    .stored_entries(&[rars::rar50::StoredEntry {
        name,
        data,
        mtime: None,
        attributes: 0,
        host_os: 0,
    }])
    .finish()
    .unwrap()
}

/// EVERY archive family in a directory is unpacked, not just the
/// first one the ladder matches.
///
/// The ladder used to return at its first claiming arm, so a RAR set
/// beside a zip extracted the RAR and left the zip packed, unopened
/// by any reader - no error, no line in the log, just a container
/// nobody looked at. It cost the torture round's advMA two oracle
/// leaves and it is what SABnzbd and NZBGet do differently
/// (TODO 159 item 5). Ordinary posts hit it too: a release plus its
/// `subs.zip` is exactly this shape.
#[test]
fn every_archive_family_in_a_directory_is_unpacked() {
    let dir = reex_dir("families");
    let rdata: Vec<u8> = (0..70_000u32).map(|i| (i as u8).wrapping_mul(31)).collect();
    let zdata: Vec<u8> = (0..40_000u32)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(5))
        .collect();
    std::fs::write(dir.join("movie.rar"), rar_of(b"movie.mkv", &rdata)).unwrap();
    std::fs::write(
        dir.join("subs.zip"),
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::deflated("subs.srt", &zdata)]),
    )
    .unwrap();
    assert!(extract_nested(&dir, None, 0).unwrap().produced());
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), rdata);
    assert_eq!(std::fs::read(dir.join("subs.srt")).unwrap(), zdata);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Carrying on past a failed arm must not turn a failure into a
/// success. A RAR we cannot produce beside a zip we can is still a
/// payload we did not produce, and the zip's output must not absolve
/// it - the exact laundering `NestOutcome` carries a CAUSE to
/// prevent.
#[test]
fn a_later_arm_succeeding_never_absolves_an_earlier_failure() {
    let dir = reex_dir("families-fail");
    let zdata: Vec<u8> = (0..20_000u32).map(|i| (i as u8).wrapping_mul(7)).collect();
    // A RAR head with a destroyed body: named like a volume, opens
    // like nothing.
    let mut broken = rar_of(b"movie.mkv", b"payload that will not survive");
    let n = broken.len();
    broken[n / 2..].fill(0);
    std::fs::write(dir.join("movie.rar"), &broken).unwrap();
    std::fs::write(
        dir.join("subs.zip"),
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::deflated("subs.srt", &zdata)]),
    )
    .unwrap();
    assert_eq!(
        extract_nested(&dir, None, 0).unwrap(),
        NestOutcome::Failed,
        "the zip landing must not launder the RAR failure"
    );
    // ...and the zip really was attempted, which is the point of
    // carrying on at all.
    assert_eq!(std::fs::read(dir.join("subs.srt")).unwrap(), zdata);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn extract_nested_seeds_preexisting_subdir_archives() {
    // CD1/CD2 layout: the archives are already IN subdirs when the
    // pass starts, so the after/before diff never sees them - only
    // the pre-existing-subdir seeding reaches them.
    let dir = reex_dir("presub");
    let store = |name: &'static [u8], data: &[u8]| -> Vec<u8> {
        rars::rar50::Rar50Writer::new(rars::rar50::WriterOptions::new(
            rars::ArchiveVersion::Rar50,
            rars::FeatureSet::store_only(),
        ))
        .stored_entries(&[rars::rar50::StoredEntry {
            name,
            data,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .finish()
        .unwrap()
    };
    let d1: Vec<u8> = (0..80_000u32).map(|i| (i as u8).wrapping_mul(31)).collect();
    let d2: Vec<u8> = (0..60_000u32)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
        .collect();
    std::fs::create_dir_all(dir.join("CD1")).unwrap();
    std::fs::create_dir_all(dir.join("CD2")).unwrap();
    std::fs::write(dir.join("CD1/a.rar"), store(b"a.bin", &d1)).unwrap();
    std::fs::write(dir.join("CD2/b.rar"), store(b"b.bin", &d2)).unwrap();
    assert!(extract_nested(&dir, None, 0).unwrap().produced());
    assert_eq!(std::fs::read(dir.join("CD1/a.bin")).unwrap(), d1);
    assert_eq!(std::fs::read(dir.join("CD2/b.bin")).unwrap(), d2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn reextract_dir_sorts_volumes_and_cleans_up() {
    let dir = reex_dir("ok");
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(7))
        .collect();
    let vols = reex_vols(&total);
    // .rar/.r00 naming: lexical order (.r00 < .rar) is the WRONG feed
    // order - the natural volume sort must put .rar first.
    std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
    assert!(reextract_dir(&dir, None).unwrap());
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    assert!(
        !dir.join("x.rar").exists(),
        "volumes removed after extraction"
    );
    assert!(!dir.join("x.r00").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 101: a RESUMED job arms the volume-eating unpack and then
/// calls `reextract_dir`, which used to send every unencrypted set
/// down the disk-feed ladder first. That ladder reads every volume
/// IN FULL through the `Extractor`, budgets against the free space
/// as it stands (`set_extract_budget`, no credit for a volume that
/// has not been handed back yet) and removes the sources only after
/// `finish()` - so on the one shape where the disk is tightest by
/// definition it could refuse the extraction the arming exists to
/// rescue, and reach the eating path only by demoting to it after
/// re-reading the whole set. An armed job now goes straight there.
///
/// What this pins is the routed behaviour end to end: the set
/// extracts, the volumes are spent, and a set that fails VERIFYING
/// takes the documented trade - the volumes it had already read are
/// gone, so a retry re-downloads rather than silently unpacking from
/// half a set. (It cannot pin which route ran: the ladder's demote
/// reaches the same native eating unpack, which is why the harm here
/// is a wasted full read and a budget measured too early rather than
/// a payload left packed.)
#[test]
fn reextract_dir_armed_eats_volumes_as_it_goes() {
    use nzbkit::rar::fixtures;
    let dir = reex_dir("armed-eats");
    let a: Vec<u8> = (0..90_000u32)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(3))
        .collect();
    let b: Vec<u8> = (0..70_000u32)
        .map(|i| (i as u8).wrapping_mul(11).wrapping_add(7))
        .collect();
    let v0 = fixtures::rar5_volume_n(&[("a.bin", a.len() as u64, &a, false, false)], 0);
    // A stored CRC that does not match the bytes: the headers parse,
    // the first volume extracts, and the SECOND member fails when it
    // is verified - which is the only moment that can tell the two
    // routes apart from outside.
    let v1 = fixtures::rar5_volume_n_crc(
        &[("b.bin", b.len() as u64, &b, false, false, Some(0xDEAD_BEEF))],
        1,
    );
    std::fs::write(dir.join("x.part1.rar"), &v0).unwrap();
    std::fs::write(dir.join("x.part2.rar"), &v1).unwrap();

    let _arm = crate::eatvol::EatArm::new(true);
    assert!(
        !reextract_dir(&dir, None).unwrap(),
        "a set whose second volume will not decode is not a success"
    );
    assert!(
        !dir.join("x.part1.rar").exists(),
        "the spent first volume was not handed back during extraction"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Part B (research/SPEC-onepass-obfuscated-store-sets-2026-07-29.md):
/// a set the streaming extractor DEMOTES (two compressed entries in
/// one volume, so the chase cannot own it) unpacks through the
/// `try_unrar` fallback - and that success must spend the volumes
/// exactly like the clean path above does, instead of leaving the
/// full set beside the payload (observed live: 144 volumes, ~57 GB,
/// beside a 58.76 GB extracted movie).
#[test]
fn reextract_dir_demoted_set_removes_spent_volumes() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let dir = reex_dir("spent-demoted");
    let a: Vec<u8> = (0..150_000u32)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(1))
        .collect();
    let b: Vec<u8> = (0..120_000u32)
        .map(|i| (i as u8).wrapping_mul(19).wrapping_add(5))
        .collect();
    let archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&[
            CompressedEntry {
                name: b"a.bin",
                data: &a,
                mtime: None,
                attributes: 0,
                host_os: 0,
            },
            CompressedEntry {
                name: b"b.bin",
                data: &b,
                mtime: None,
                attributes: 0,
                host_os: 0,
            },
        ])
        .finish()
        .unwrap();
    std::fs::write(dir.join("set.rar"), &archive).unwrap();
    assert!(
        reextract_dir(&dir, None).unwrap(),
        "the fallback unpack failed"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b);
    assert_eq!(
        names_in(&dir),
        vec!["a.bin".to_string(), "b.bin".to_string()],
        "spent volumes survived the fallback unpack"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 211's third call site: the re-extract after a PAR2 repair.
///
/// The same byte split of one container (`stage.rar.001`..`.004`) that the
/// download tail now rescues, reached through `reextract_dir` instead -
/// the path a repaired job and a resumed run both take. The volume grammar
/// at the top of this function pulls out part 1 ALONE, because it is the
/// only part carrying the `Rar!` magic that `.001` has to earn, so the feed
/// loop hands the mapper a quarter of an archive, every arm demotes, and
/// the unrar fallback finds nothing it can open. Before the rescue rung
/// this returned Ok(false) with all four parts on disk and nothing
/// delivered - a repaired split-container post failing exactly as TODO 211
/// described, while the identical undamaged post succeeded.
///
/// The recovery file beside the parts is the second half of the proof: it
/// is not joined (a `.par2` base refuses in either reading) and it is not
/// swept, because deciding a job's recovery data is `par_cleanup`'s call
/// downstream and never this function's.
///
/// "The unrar fallback finds nothing it can open" is the second rung of a
/// two-rung ladder, and it is a subprocess. This test needs it to fail
/// before the rescue is reached, and the exact listing below needs the
/// failed attempt to have left nothing behind - which used to hold only
/// because no box the suite runs on has an `unrar` on `$PATH`. It holds
/// by construction now: the hatch is closed for the whole unit-test build
/// (`rarfix::external_unrar_closed`, which carries the reasoning).
#[test]
fn reextract_dir_rescues_a_split_container_after_repair() {
    use nzbkit::rar::fixtures;
    let dir = reex_dir("split-container");
    let total: Vec<u8> = (0..240_000u32)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
        .collect();
    let archive = fixtures::rar5_volume(&[("film.mkv", total.len() as u64, &total, false, false)]);
    let chunk = archive.len().div_ceil(4);
    let parts: Vec<PathBuf> = archive
        .chunks(chunk)
        .enumerate()
        .map(|(i, c)| {
            let p = dir.join(format!("stage.rar.{:03}", i + 1));
            std::fs::write(&p, c).unwrap();
            p
        })
        .collect();
    assert_eq!(parts.len(), 4);
    let par2 = dir.join("stage.par2");
    let mut packet = b"PAR2\x00PKT".to_vec();
    packet.extend(std::iter::repeat_n(0x11u8, 4_000));
    std::fs::write(&par2, &packet).unwrap();

    assert!(
        reextract_dir(&dir, None).unwrap(),
        "the repaired split container was not rescued"
    );
    assert_eq!(
        std::fs::read(dir.join("film.mkv")).unwrap(),
        total,
        "the archive member is delivered byte for byte"
    );
    for p in &parts {
        assert!(!p.exists(), "{} is spent and removed", p.display());
    }
    assert!(
        !dir.join("stage.rar").exists(),
        "the container the rescue built is spent too"
    );
    assert!(
        par2.exists(),
        "the recovery file is not this pass's to sweep"
    );
    assert_eq!(
        names_in(&dir),
        vec!["film.mkv".to_string(), "stage.par2".to_string()]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The disk pass picks up where a forfeited chase stopped.
///
/// The proof is deliberately destructive: the partial on disk is
/// POISONED, so its bytes are not what the archive holds. If the pass
/// resumed, those bytes survive and only the tail is appended; if it
/// re-extracted from byte zero, they are overwritten and the file comes
/// out byte-exact. Asserting the poison survives is the only assertion
/// that can tell the two apart from outside - a correct-prefix fixture
/// passes either way and proves nothing.
///
/// (In production the prefix IS the archive's own bytes - the extractor
/// only records a mark for output it wrote itself, and voids the ledger
/// if a repair rewrites what it decoded from. See
/// `nzbkit::extract::ResumeOutput`.)
#[test]
fn a_resumed_member_keeps_its_prefix_and_gets_only_the_tail_appended() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let dir = reex_dir("resume-append");
    let a: Vec<u8> = (0..200_000u32)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
        .collect();
    let archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&[CompressedEntry {
            name: b"a.bin",
            data: &a,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .finish()
        .unwrap();
    std::fs::write(dir.join("set.rar"), &archive).unwrap();

    const MARK: u64 = 80_000;
    let out = dir.join("a.bin");
    // The chase's kept prefix: the member's own leading bytes, with the
    // checksum the chase would have recorded over them (TODO 217 - a
    // filler prefix no longer passes, because the pass now VERIFIES the
    // re-decode against the mark's crc before appending a byte).
    std::fs::write(&out, &a[..MARK as usize]).unwrap();
    // Append-proof: a hard link shares the inode, so it sees the append
    // in place; a from-zero re-extract publishes a NEW inode over the
    // name and the witness keeps the short prefix.
    let witness = dir.join("witness.bin");
    std::fs::hard_link(&out, &witness).unwrap();
    let _arm = crate::resumeout::ResumeArm::new(&[nzbkit::extract::ResumeOutput {
        member: "a.bin".to_string(),
        path: out.clone(),
        len: MARK,
        crc32: crc32fast::hash(&a[..MARK as usize]),
    }]);

    let spent = try_unrar_spent(&dir, None).expect("the unpack failed");
    let got = std::fs::read(&out).unwrap();
    assert_eq!(got, a, "the published member is not byte-exact");
    assert_eq!(
        std::fs::read(&witness).unwrap(),
        a,
        "the pass did not append to the kept prefix in place - it re-extracted"
    );
    // And the set is SPENT. The proof-of-output rule the deletion needs
    // is a before/after diff of the directory, and a resumed member is
    // invisible to it - its path was there before this pass ran. Without
    // `resumeout::finished_any` the payload comes out complete with the
    // whole volume set still sitting beside it.
    assert_eq!(
        spent,
        vec![dir.join("set.rar")],
        "the volumes the resumed unpack read were not reported spent"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 217's mismatch arm, driven through the real native pass: the
/// kept prefix carries the checksum the chase honestly recorded, but
/// the volumes on disk decode to something else (a repair or a dropped
/// range's re-fetch rewrote them after the chase read them). The
/// verification catches it at the mark, the rewind clears the ledger,
/// and the retry extracts from byte zero - so the published member is
/// byte-exact where a trusting resume would have published the stale
/// prefix under a passing job.
///
/// RED against a revert: without the checksum compare the pass appends
/// the member's tail to the stale prefix and the first assert fails on
/// a corrupt `a.bin`.
#[test]
fn a_stale_prefix_fails_its_checksum_and_the_pass_rewinds_to_byte_zero() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let dir = reex_dir("resume-mismatch");
    let a: Vec<u8> = (0..200_000u32)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
        .collect();
    let archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&[CompressedEntry {
            name: b"a.bin",
            data: &a,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .finish()
        .unwrap();
    std::fs::write(dir.join("set.rar"), &archive).unwrap();

    const MARK: u64 = 80_000;
    // What the chase wrote and hashed - decoded from a copy of the
    // volumes that no longer matches what is on disk now. The ledger
    // entry is internally consistent (its crc IS the crc of its file),
    // which is exactly why only comparing against the RE-DECODE can
    // catch it.
    let stale: Vec<u8> = (0..MARK as usize).map(|i| (i as u8) ^ 0x5A).collect();
    let out = dir.join("a.bin");
    std::fs::write(&out, &stale).unwrap();
    let witness = dir.join("witness.bin");
    std::fs::hard_link(&out, &witness).unwrap();
    let _arm = crate::resumeout::ResumeArm::new(&[nzbkit::extract::ResumeOutput {
        member: "a.bin".to_string(),
        path: out.clone(),
        len: MARK,
        crc32: crc32fast::hash(&stale),
    }]);

    assert!(try_unrar(&dir, None), "the rewind should still unpack");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        a,
        "the published member must be the from-zero extract, not the stale splice"
    );
    // The stale partial's inode was unlinked by the rewind, never
    // appended to: the witness (its other hard link) still holds
    // exactly the stale prefix.
    assert_eq!(
        std::fs::read(&witness).unwrap(),
        stale,
        "the stale prefix was appended to instead of being abandoned"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Two entries of one name share one plan key, so a resume of `a.bin`
/// would have BOTH open the partial at the mark and the published file
/// come out as A's prefix with B's tail - while both entries report
/// success (Codex F-02). A name the batch carries twice is not resumed.
#[test]
fn duplicate_member_names_are_never_resumed() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let dir = reex_dir("resume-dupe-names");
    let a: Vec<u8> = (0..120_000u32)
        .map(|i| (i as u8).wrapping_mul(19).wrapping_add(3))
        .collect();
    let b: Vec<u8> = (0..120_000u32)
        .map(|i| (i as u8).wrapping_mul(5).wrapping_add(7))
        .collect();
    let entry = |data: &'static [u8]| CompressedEntry {
        name: b"a.bin",
        data,
        mtime: None,
        attributes: 0,
        host_os: 0,
    };
    let (a_static, b_static): (&'static [u8], &'static [u8]) = (
        Box::leak(a.clone().into_boxed_slice()),
        Box::leak(b.clone().into_boxed_slice()),
    );
    let archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&[entry(a_static), entry(b_static)])
        .finish()
        .unwrap();
    std::fs::write(dir.join("set.rar"), &archive).unwrap();

    const MARK: u64 = 40_000;
    let out = dir.join("a.bin");
    std::fs::write(&out, vec![0xA5u8; MARK as usize]).unwrap();
    let _arm = crate::resumeout::ResumeArm::new(&[nzbkit::extract::ResumeOutput {
        member: "a.bin".to_string(),
        path: out.clone(),
        len: MARK,
        crc32: 0,
    }]);
    assert!(try_unrar(&dir, None), "the unpack failed");
    let got = std::fs::read(&out).unwrap();
    assert!(
        got == a || got == b,
        "the published file is neither member whole - a spliced resume"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The two guards that send a member down the ordinary byte-zero route.
///
/// A partial whose length has MOVED since the extractor cut it is no
/// longer the prefix the mark speaks for; a partial sitting somewhere
/// other than where this pass would publish the member (a deduplicated
/// name, here) is not the member's file at all. Either way the entry is
/// skipped and the extraction is exactly what it always was - which the
/// poisoned prefix proves by being overwritten.
#[test]
fn a_partial_that_moved_or_was_renamed_is_extracted_from_byte_zero() {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let a: Vec<u8> = (0..120_000u32)
        .map(|i| (i as u8).wrapping_mul(23).wrapping_add(5))
        .collect();
    let archive = Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&[CompressedEntry {
            name: b"a.bin",
            data: &a,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .finish()
        .unwrap();

    // Guard 1: the file grew after the mark was taken.
    {
        let dir = reex_dir("resume-moved");
        std::fs::write(dir.join("set.rar"), &archive).unwrap();
        let out = dir.join("a.bin");
        std::fs::write(&out, vec![0xA5u8; 50_000]).unwrap();
        let _arm = crate::resumeout::ResumeArm::new(&[nzbkit::extract::ResumeOutput {
            member: "a.bin".to_string(),
            path: out.clone(),
            len: 40_000,
            crc32: 0,
        }]);
        assert!(try_unrar(&dir, None), "the unpack failed");
        assert_eq!(
            std::fs::read(&out).unwrap(),
            a,
            "it should have re-extracted"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    // Guard 2: the partial is not at the path this pass publishes to.
    {
        let dir = reex_dir("resume-renamed");
        std::fs::write(dir.join("set.rar"), &archive).unwrap();
        let stray = dir.join("a-1.bin");
        std::fs::write(&stray, vec![0xA5u8; 40_000]).unwrap();
        {
            let _arm = crate::resumeout::ResumeArm::new(&[nzbkit::extract::ResumeOutput {
                member: "a.bin".to_string(),
                path: stray.clone(),
                len: 40_000,
                crc32: 0,
            }]);
            assert!(try_unrar(&dir, None), "the unpack failed");
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
        }
        // ...and the arm took the stray away with it, rather than
        // leaving a short file beside the payload.
        assert!(!stray.exists(), "the untaken partial was left behind");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// KEEP (Part B): an encrypted set with no password. The verified
/// volumes ARE the deliverable until a password arrives, and the
/// unlock flow re-reads them - a successful "password required" pass
/// must leave every volume in place. Once the password shows up, the
/// unlock spends them like any other successful unpack.
#[test]
fn reextract_dir_encrypted_no_password_keeps_volumes() {
    use nzbkit::rar::fixtures;
    let dir = reex_dir("spent-enc-keep");
    let plain: Vec<u8> = (0..90_000u32)
        .map(|i| (i as u8).wrapping_mul(41).wrapping_add(7))
        .collect();
    let f = fixtures::encrypt_file("sesame", &plain, 9);
    let vol = fixtures::rar5_volume_enc_headers(
        &[("film.mkv", &f, 0..f.cipher.len(), false, false)],
        None,
        "sesame",
        9,
    );
    std::fs::write(dir.join("x.rar"), &vol).unwrap();
    assert!(
        reextract_dir(&dir, None).unwrap(),
        "verified encrypted volumes are a deliverable, not a failure"
    );
    assert!(
        dir.join("x.rar").exists(),
        "encrypted volumes must survive until a password arrives"
    );
    assert!(!dir.join("film.mkv").exists());

    // ...and the unlock that follows (same entry point smart::unlock
    // uses) both produces the payload and spends the volumes.
    assert!(
        reextract_dir(&dir, Some("sesame")).unwrap(),
        "unlock failed"
    );
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), plain);
    assert!(
        !dir.join("x.rar").exists(),
        "volumes are spent once the unlock succeeds"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A RAR4 `-hp` set with the password in hand. What is asserted here
/// is the ladder's end state, not which rung did the work: the payload
/// is out and the volume is spent, with no unrar in the story. Which
/// rung it is has moved - the streaming extractor could never map this
/// shape until RAR4 header decryption landed, so it used to be handed
/// straight to the native disk path by `headers_encrypted_to`.
#[test]
fn reextract_dir_unpacks_a_rar4_header_encrypted_set() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/rars/tests/fixtures/rar15_40/encrypted/header_rar420_password.rar");
    let dir = reex_dir("rar4-hp");
    std::fs::copy(&fixture, dir.join("x.rar")).unwrap();
    assert!(
        reextract_dir(&dir, Some("password")).unwrap(),
        "a RAR4 -hp set with its password must unpack"
    );
    let out = std::fs::read(dir.join("hello.txt")).unwrap();
    assert_eq!(
        crc32fast::hash(&out),
        0xa538_535e,
        "decrypted payload CRC (fixture README oracle)"
    );
    assert!(
        !dir.join("x.rar").exists(),
        "the volume is spent once the payload is out"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// KEEP (Part B): a failed unpack. The volumes are the only recovery,
/// so `try_unrar_spent` answers None and nothing may be deleted.
#[test]
fn failed_unpack_reports_none_and_keeps_volumes() {
    let dir = reex_dir("spent-fail-keep");
    let mut junk = b"Rar!\x1a\x07\x01\x00".to_vec();
    junk.extend(std::iter::repeat_n(0xA5u8, 4096));
    std::fs::write(dir.join("x.rar"), &junk).unwrap();
    assert_eq!(try_unrar_spent(&dir, None), None);
    assert!(
        dir.join("x.rar").exists(),
        "a failed unpack must keep its volumes"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// KEEP (Part B): the offline `nzbfast extract` flow (depth 0 of the
/// nested pass) unpacks over the USER'S OWN directory - retention
/// there is finalize/policy's call, and spent-volume deletion belongs
/// to the daemon finalize and reextract flows alone.
#[test]
fn offline_extract_keeps_named_volumes_at_depth_zero() {
    let dir = reex_dir("spent-offline-keep");
    let total: Vec<u8> = (0..250_000u32)
        .map(|i| (i as u8).wrapping_mul(11).wrapping_add(3))
        .collect();
    let vols = reex_vols(&total);
    std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
    assert!(extract_nested(&dir, None, 0).unwrap().produced());
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    assert!(
        dir.join("x.rar").exists() && dir.join("x.r00").exists(),
        "the offline flow must never delete volumes in the user's own directory"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Phase 0(b): the disk post-pass classifies and tallies a nested
/// layer. `nested_inner_kind` names the shape from the head (store vs
/// compressed), and `extract_one_level` at depth 1 (a nested level)
/// extracts it and bumps the `disk` + `rar_store` counters. The tally
/// is process-global under the parallel runner, so the counter checks
/// are lower-bound deltas; the classifier checks are exact.
#[test]
fn nested_prevalence_classifies_and_counts_disk_layer() {
    use nzbkit::rar::fixtures;
    let data: Vec<u8> = (0..90_000u32).map(|i| (i as u8).wrapping_mul(7)).collect();

    // Compressed inner classifies distinctly (no extraction, no count).
    let cdir = reex_dir("nestprev-comp");
    let comp = {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&[CompressedEntry {
                name: b"c.bin",
                data: &data,
                mtime: None,
                attributes: 0,
                host_os: 0,
            }])
            .finish()
            .unwrap()
    };
    std::fs::write(cdir.join("c.rar"), &comp).unwrap();
    assert_eq!(nested_inner_kind(&cdir), Some("rar-compressed"));
    std::fs::remove_dir_all(&cdir).unwrap();

    // Store inner: classify, then run the disk post-pass at depth 1.
    let before = nzbkit::extract::nested_prevalence();
    let dir = reex_dir("nestprev-store");
    let vol = fixtures::rar5_volume(&[("movie.mkv", data.len() as u64, &data, false, false)]);
    std::fs::write(dir.join("inner.rar"), &vol).unwrap();
    assert_eq!(nested_inner_kind(&dir), Some("rar-store"));
    assert_eq!(
        extract_one_level(&dir, None, 1).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
    let after = nzbkit::extract::nested_prevalence();
    assert!(
        after.disk > before.disk,
        "disk counter did not advance ({} -> {})",
        before.disk,
        after.disk
    );
    assert!(
        after.rar_store > before.rar_store,
        "rar_store counter did not advance ({} -> {})",
        before.rar_store,
        after.rar_store
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `reex_vols` with a chosen member name - the alias fixtures below
/// need the archived member to be named after a source volume.
fn reex_vols_named(total: &[u8], member: &str) -> [Vec<u8>; 2] {
    use nzbkit::rar::fixtures;
    let n = total.len() as u64;
    let half = total.len() / 2;
    [
        fixtures::rar5_volume_n(&[(member, n, &total[..half], false, true)], 0),
        fixtures::rar5_volume_n(&[(member, n, &total[half..], true, false)], 1),
    ]
}

/// Sweep finding 8: a member named exactly like the FIRST source
/// volume. The decoder reopens that volume by path for every range it
/// reads, so writing the member beside it truncated the file mid-read,
/// failed the extraction, and handed a destroyed set to the unrar
/// fallback. Extraction stages its output instead, so the volume is
/// never opened for writing and both files survive.
#[test]
fn rar_member_named_like_first_volume_leaves_it_intact() {
    let dir = reex_dir("alias-first");
    let total: Vec<u8> = (0..300_000u32)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(5))
        .collect();
    let vols = reex_vols_named(&total, "x.rar");
    std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
    assert_eq!(
        extract_one_level(&dir, None, 1).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(
        std::fs::read(dir.join("x.rar")).unwrap(),
        vols[0],
        "first volume was rewritten by the member named after it"
    );
    assert_eq!(std::fs::read(dir.join("x.r00")).unwrap(), vols[1]);
    // The member is still delivered, under a disambiguated name.
    assert_eq!(std::fs::read(dir.join("extracted-1-x.rar")).unwrap(), total);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Same shape against a LATER volume (`x.r00`), which the decoder only
/// reopens once it has consumed the first - the byte the old code
/// destroyed had not even been read yet when it was truncated.
#[test]
fn rar_member_named_like_later_volume_leaves_it_intact() {
    let dir = reex_dir("alias-later");
    let total: Vec<u8> = (0..300_000u32)
        .map(|i| (i as u8).wrapping_mul(23).wrapping_add(9))
        .collect();
    let vols = reex_vols_named(&total, "x.r00");
    std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
    assert_eq!(
        extract_one_level(&dir, None, 1).unwrap(),
        Some(NestOutcome::Produced)
    );
    assert_eq!(std::fs::read(dir.join("x.rar")).unwrap(), vols[0]);
    assert_eq!(
        std::fs::read(dir.join("x.r00")).unwrap(),
        vols[1],
        "later volume was rewritten by the member named after it"
    );
    assert_eq!(std::fs::read(dir.join("extracted-1-x.r00")).unwrap(), total);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A native extraction that fails AFTER writing bytes (the last piece
/// carries a wrong stored CRC) must publish nothing: every source
/// volume keeps its bytes, and no partial output is left for a later
/// pass - or the unrar fallback - to mistake for payload.
#[test]
fn failed_native_extraction_publishes_nothing() {
    use nzbkit::rar::fixtures;
    let dir = reex_dir("alias-fail");
    let total: Vec<u8> = (0..300_000u32)
        .map(|i| (i as u8).wrapping_mul(11).wrapping_add(3))
        .collect();
    let n = total.len() as u64;
    let half = total.len() / 2;
    let vols = [
        fixtures::rar5_volume_n_crc(&[("x.rar", n, &total[..half], false, true, None)], 0),
        // Wrong plaintext CRC on the last piece - extraction writes
        // every byte, then rejects the entry.
        fixtures::rar5_volume_n_crc(
            &[("x.rar", n, &total[half..], true, false, Some(0xDEAD_BEEF))],
            1,
        ),
    ];
    std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
    assert!(
        try_rars_native(&dir, &dir.join("x.rar"), None).is_err(),
        "a CRC-failing entry must not report success"
    );
    assert_eq!(std::fs::read(dir.join("x.rar")).unwrap(), vols[0]);
    assert_eq!(std::fs::read(dir.join("x.r00")).unwrap(), vols[1]);
    let left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(left.len(), 2, "staging leaked into the job dir: {left:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Live 1.0.11b8 failure (Avengers remux, 57.8 GB): a 144-volume set
/// renamed out of obfuscation to `raRjHaZZ…partNNN.rar` reported "no
/// volumes found for …part001.rar", and the external unrar then
/// unpacked the very same directory. `release_stem` compares suffixes
/// case-insensitively but returns a slice of the name it was HANDED, so
/// the stem taken from the original-case first volume never equalled
/// the stem of a lowercased directory entry - zero matches for any
/// mixed-case stem. Two costs, both observed: a whole wasted
/// external-unrar pass (an outright failure where unrar is absent), and
/// 55 GB of spent volumes left on disk, since the caller deletes
/// exactly the set this reports.
#[test]
fn stem_volume_set_matches_a_mixed_case_obfuscated_part_set() {
    let dir = reex_dir("stem-case");
    // The real stem from the live job, capitals and all.
    let stem = "raRjHaZZWXEY9fdmj3bofuaWRrAbj1n";
    let magic = b"Rar!\x1a\x07\x01\x00";
    for n in 1..=5u32 {
        std::fs::write(dir.join(format!("{stem}.part{n:03}.rar")), magic).unwrap();
    }
    // A second, unrelated set must stay out of the reported group.
    std::fs::write(dir.join("OtherRelease.part001.rar"), magic).unwrap();

    let first = dir.join(format!("{stem}.part001.rar"));
    let found = stem_volume_set(&dir, &first).unwrap();
    let names: Vec<String> = found
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        names,
        (1..=5u32)
            .map(|n| format!("{stem}.part{n:03}.rar"))
            .collect::<Vec<_>>(),
        "a mixed-case .partNNN set must resolve in volume order"
    );

    // The same set with the capitals in the OTHER direction: a
    // lowercased first volume against mixed-case entries on disk. The
    // pre-fix code got this one right by accident, and it must stay
    // right - the comparison has to be case-insensitive both ways.
    let lower_first = dir.join(format!("{}.part001.rar", stem.to_lowercase()));
    assert_eq!(
        stem_volume_set(&dir, &lower_first).unwrap().len(),
        5,
        "the stem comparison must be case-insensitive in both directions"
    );

    // A stem with no sibling is still its own group, and picking it must
    // not drag in the 5-volume set next to it.
    assert_eq!(
        stem_volume_set(&dir, &dir.join("OtherRelease.part001.rar"))
            .unwrap()
            .len(),
        1,
        "the foreign stem is its own one-volume group"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Sweep finding A7: a `release.7z` carrying a member named
/// `release.7z`. `ArchiveReader::open` holds the container open and
/// reads from it as each member decodes, so writing that member beside
/// it truncated the inode still backing its own reader - destroying the
/// only downloaded copy of the archive. The joined-container scratch
/// dir is separate from the output dir for the same reason.
#[test]
fn sevenz_member_named_like_its_own_container_leaves_it_intact() {
    let dir = reex_dir("alias-7z");
    let payload: Vec<u8> = (0..250_000u32)
        .map(|i| (i as u8).wrapping_mul(19).wrapping_add(4))
        .collect();
    let container = {
        let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file("release.7z"),
            Some(payload.as_slice()),
        )
        .unwrap();
        w.finish().unwrap().into_inner()
    };
    let path = dir.join("release.7z");
    std::fs::write(&path, &container).unwrap();
    assert!(extract_sevenz(&dir, &[vec![path.clone()]], None));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        container,
        "the container was truncated by the member named after it"
    );
    assert_eq!(
        std::fs::read(dir.join("extracted-1-release.7z")).unwrap(),
        payload
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An obfuscated 7z keeps whatever extension the poster gave it, and
/// `.bin` is a common one. The collector used to sniff magic ONLY on
/// extensionless files, so this container was invisible to the disk
/// post-pass: nothing extracted, the pass reported "nothing to
/// unpack", and the job completed holding one unopened archive.
#[test]
fn an_obfuscated_7z_is_found_under_any_extension() {
    let dir = reex_dir("obf-7z-ext");
    let payload: Vec<u8> = (0..120_000u32)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(7))
        .collect();
    let container = {
        let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file("feature.mkv"),
            Some(payload.as_slice()),
        )
        .unwrap();
        w.finish().unwrap().into_inner()
    };
    // The name a fully-obfuscated post lands under: a hash, and an
    // extension that says nothing about the contents.
    let path = dir.join("a3f19c04e8b2.bin");
    std::fs::write(&path, &container).unwrap();
    assert!(sevenz_archive_part(&path), "magic outranks the extension");
    let jobs = collect_sevenz_archives(&dir).unwrap();
    assert_eq!(jobs, vec![vec![path.clone()]]);
    // And the whole pass now delivers, where it used to report
    // Produced ("nothing to unpack") over an untouched container.
    assert!(extract_nested(&dir, None, 0).unwrap().produced());
    assert_eq!(std::fs::read(dir.join("feature.mkv")).unwrap(), payload);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The door `Ok(None)` opens is a COMPLETED job, so nothing that
/// still has an archive's head may leave through it. Detection and
/// routing drifted apart once already (the `.bin` case above); this
/// pins the disagreement itself as a failure rather than a silent
/// success.
#[test]
fn an_archive_no_extractor_claims_fails_the_pass() {
    let dir = reex_dir("stray-archive");
    // A 7z signature over bytes no reader can parse: sniffed as an
    // archive, routed by nothing, extracted by nobody.
    let mut bytes = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    bytes.extend(std::iter::repeat_n(0u8, 4096));
    std::fs::write(dir.join("payload.bin"), &bytes).unwrap();
    assert_eq!(
        extract_one_level(&dir, None, 0).unwrap(),
        Some(NestOutcome::Failed)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Sweep finding A6 (the directory half): the collision walk steps
/// around a directory whose payload belongs to a COMPLETED job and
/// records the canonical name to publish over. A FAILED job maps to
/// `Free` at the call site, so its leftovers are still reused in place.
#[test]
fn out_dir_choice_steps_around_a_completed_payload() {
    use crate::serve::{DirClaim, choose_out_dir};
    let base = std::path::Path::new("/dl/tv/Release");
    // Free (nothing there, or a failed job's junk): reuse in place,
    // nothing to replace.
    let (d, r) = choose_out_dir(base, "Release", &|_| DirClaim::Free);
    assert_eq!(d, base);
    assert_eq!(r, None);
    // A completed payload: download beside it, publish over it later.
    let (d, r) = choose_out_dir(base, "Release", &|p| {
        if p == base {
            DirClaim::Payload
        } else {
            DirClaim::Free
        }
    });
    assert_eq!(d, std::path::Path::new("/dl/tv/Release.2"));
    assert_eq!(r, Some(base.to_path_buf()));
    // An ACTIVE job holds the canonical name: step aside as before,
    // and never replace what a running job is writing.
    let (d, r) = choose_out_dir(base, "Release", &|p| {
        if p == base {
            DirClaim::Active
        } else {
            DirClaim::Free
        }
    });
    assert_eq!(d, std::path::Path::new("/dl/tv/Release.2"));
    assert_eq!(r, None);
    // Canonical holds a payload and .2 is busy: land on .3, and still
    // replace only the canonical one.
    let (d, r) = choose_out_dir(base, "Release", &|p| match p.to_string_lossy() {
        c if c.ends_with("Release") => DirClaim::Payload,
        c if c.ends_with("Release.2") => DirClaim::Active,
        _ => DirClaim::Free,
    });
    assert_eq!(d, std::path::Path::new("/dl/tv/Release.3"));
    assert_eq!(r, Some(base.to_path_buf()));
}

/// A6 publication: the previous result survives a failed hand-over,
/// and is replaced only once the new payload is in place.
#[test]
fn replacing_a_previous_result_never_loses_it() {
    use crate::serve::publish_over_previous;
    let root = reex_dir("a6-replace");
    let canon = root.join("Release");
    let fresh = root.join("Release.2");
    std::fs::create_dir_all(&canon).unwrap();
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::write(canon.join("payload.iso"), b"the good old copy").unwrap();
    std::fs::write(fresh.join("payload.iso"), b"the new copy").unwrap();
    assert_eq!(publish_over_previous(&fresh, &canon), Some(canon.clone()));
    assert_eq!(
        std::fs::read(canon.join("payload.iso")).unwrap(),
        b"the new copy"
    );
    assert!(!fresh.exists(), "the staged directory was left behind");
    // Nothing aside from the canonical directory survives the swap.
    let left: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(left, vec!["Release".to_string()], "leftovers: {left:?}");

    // A job that never produced its directory leaves the old result
    // exactly where it was.
    let missing = root.join("Release.3");
    assert_eq!(publish_over_previous(&missing, &canon), None);
    assert_eq!(
        std::fs::read(canon.join("payload.iso")).unwrap(),
        b"the new copy"
    );
    // And a job that already owns the canonical name is a no-op.
    assert_eq!(publish_over_previous(&canon, &canon), None);
    assert_eq!(
        std::fs::read(canon.join("payload.iso")).unwrap(),
        b"the new copy"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

/// Regression: a failed re-extraction must never damage the (PAR2-
/// verified) volume files it reads - the old fallback truncated them
/// in place and destroyed a repaired 62-volume set.
#[test]
fn reextract_dir_failure_preserves_source_volumes() {
    let dir = reex_dir("damaged");
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(3))
        .collect();
    let mut vols = reex_vols(&total);
    vols[1][..4].fill(0); // corrupt volume 2's signature
    std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();
    assert!(
        !reextract_dir(&dir, None).unwrap(),
        "damaged set must not report success"
    );
    assert_eq!(std::fs::read(dir.join("x.rar")).unwrap(), vols[0]);
    assert_eq!(std::fs::read(dir.join("x.r00")).unwrap(), vols[1]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Differential: an obfuscated volume set (extensionless names, filename
/// order deliberately INVERTED against volume order) must extract
/// byte-identically to the same set under normal names. Proves both the
/// magic-based detection and the header-volume-number ordering.
#[test]
fn obfuscated_volumes_extract_like_named_ones() {
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(11))
        .collect();
    let vols = reex_vols(&total);

    let named = reex_dir("obf-named");
    std::fs::write(named.join("x.rar"), &vols[0]).unwrap();
    std::fs::write(named.join("x.r00"), &vols[1]).unwrap();
    assert!(extract_local(&named, None).unwrap());
    let want = std::fs::read(named.join("film.mkv")).unwrap();
    assert_eq!(want, total);

    let obf = reex_dir("obf-hex");
    // volume 0 gets the lexically LATER name: filename sort would feed
    // the set backwards; only the header volume number saves it.
    std::fs::write(obf.join("bb0a1f"), &vols[0]).unwrap();
    std::fs::write(obf.join("aa93c2"), &vols[1]).unwrap();
    assert!(
        extract_local(&obf, None).unwrap(),
        "obfuscated set must extract"
    );
    assert_eq!(
        std::fs::read(obf.join("film.mkv")).unwrap(),
        want,
        "obfuscated payload differs from named-set payload"
    );

    std::fs::remove_dir_all(&named).unwrap();
    std::fs::remove_dir_all(&obf).unwrap();
}

/// Two obfuscated two-volume RAR5 sets in one directory that span a
/// member of the SAME name (`film.mkv`) with different bytes, with the
/// continuation names sorted in the reverse order of the heads.
///
/// Both heads are open and both expect volume 1, and the only linkage
/// evidence - the split member's name across the boundary - is
/// identical for both. The partitioner used to take the FIRST such
/// match, so the second set's continuation was appended to the first
/// set, which then closed, and the first set's continuation fell
/// through to the sole-candidate arm and was appended to the second
/// with no boundary check at all. Two complete sets became two
/// cross-wired ones: with no stored CRC to catch it, one of them
/// "extracted" and published a `film.mkv` that is the head of one set
/// glued to the tail of the other.
///
/// Ambiguous evidence is no evidence: the pass must decline, publish
/// nothing, and keep every input byte-identical for PAR2 repair or a
/// retry to work from.
#[test]
fn ambiguous_obfuscated_continuations_are_not_guessed() {
    let a: Vec<u8> = (0..200_000u32)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(5))
        .collect();
    let b: Vec<u8> = (0..200_000u32)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(2))
        .collect();
    let va = reex_vols_named(&a, "film.mkv");
    let vb = reex_vols_named(&b, "film.mkv");

    // Heads sort A then B; continuations sort B then A.
    let dir = reex_dir("obf-ambig");
    let files = [
        ("aa01", &va[0]),
        ("aa02", &vb[0]),
        ("ab01", &vb[1]),
        ("ab02", &va[1]),
    ];
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    let ok = extract_local(&dir, None).unwrap_or(false);
    assert!(
        !ok,
        "two sets whose boundary evidence is identical cannot be partitioned, \
         so the pass must not report success"
    );
    assert!(
        !dir.join("film.mkv").exists(),
        "a cross-wired payload was published"
    );
    for (name, bytes) in files {
        assert_eq!(
            &std::fs::read(dir.join(name)).unwrap(),
            bytes,
            "input volume {name} was consumed or altered"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// One four-volume RAR4 stored set, written twice: once under names
/// that order it and once under hash names that do not.
fn rar4_vols(total: &[u8], per_volume: usize) -> Vec<Vec<u8>> {
    rars::rar15_40::write_stored_volumes(
        rars::rar15_40::StoredEntry {
            name: b"film.mkv",
            data: total,
            file_time: 0,
            file_attr: 0,
            host_os: 0,
            password: None,
            file_comment: None,
        },
        rars::rar15_40::WriterOptions::default(),
        per_volume,
    )
    .unwrap()
}

/// The obfuscated collector cannot order a RAR4 volume set, and the
/// boundary is the NAMES, not the family: the same four volumes extract
/// under `.rar`/`.rNN` and cannot be touched under hash names. RAR4
/// headers carry no volume number and, as `archive_volume_number`
/// records, interior volumes are otherwise header-identical, so nothing
/// on this path can put them back in order.
///
/// Pinned because the failure has to stay the SAFE one. This is a
/// missing capability, and a missing capability must not turn into a
/// lost download: the run may not publish a partial `film.mkv`, and it
/// may not spend a single volume - PAR2 repair, `.rev` reconstruction
/// and a plain retry all read them, and on a finished download they are
/// the only copy. It must also still FAIL, so an *arr sees a failure and
/// re-grabs rather than importing an empty directory.
#[test]
fn obfuscated_rar4_set_fails_cleanly_and_keeps_every_volume() {
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(23).wrapping_add(7))
        .collect();
    let vols = rar4_vols(&total, 100_000);
    assert_eq!(vols.len(), 4, "fixture must be a real multi-volume set");

    // Named: the ordinary RAR4 path unpacks it, so the family itself is
    // supported and only the ordering is at stake below.
    let named = reex_dir("rar4-named");
    std::fs::write(named.join("x.rar"), &vols[0]).unwrap();
    for (i, v) in vols[1..].iter().enumerate() {
        std::fs::write(named.join(format!("x.r{i:02}")), v).unwrap();
    }
    assert!(
        extract_local(&named, None).unwrap(),
        "named RAR4 volume set must extract"
    );
    assert_eq!(std::fs::read(named.join("film.mkv")).unwrap(), total);

    // Obfuscated: same bytes, hash names in an order that is not volume
    // order. Nothing can recover the sequence, so the job fails.
    let obf = reex_dir("rar4-obf");
    let hashes = ["d1f9c0", "a074be", "c55201", "b3e8a7"];
    for (name, v) in hashes.iter().zip(vols.iter()) {
        std::fs::write(obf.join(name), v).unwrap();
    }
    assert!(
        !extract_local(&obf, None).unwrap_or(false),
        "an obfuscated RAR4 set cannot be ordered, so it must not report success"
    );
    assert!(
        !obf.join("film.mkv").exists(),
        "a partial payload was published from an unordered set"
    );
    for (name, v) in hashes.iter().zip(vols.iter()) {
        assert_eq!(
            &std::fs::read(obf.join(name)).unwrap(),
            v,
            "volume {name} was spent or damaged by a run that produced nothing"
        );
    }

    std::fs::remove_dir_all(&named).unwrap();
    std::fs::remove_dir_all(&obf).unwrap();
}

/// TODO 205 end to end: the disk ladder must report what it is doing
/// while it does it. Issue #47's reporter watched a 130-volume
/// obfuscated set unpack for several minutes on a NAS behind one static
/// word - the queue row could not say whether it was one volume or his
/// hundred and thirty, nor how far in it was.
///
/// This runs the same route his set takes (`extract_obfuscated_rar`,
/// reached here through `extract_local`) with the ladder armed, and
/// asks the hub entry the queue payload reads: the volume count is
/// there before a byte moves, and the byte total arrives from the
/// archive headers rather than from anything the extraction had to
/// finish first.
#[test]
fn an_armed_disk_ladder_publishes_its_volume_count_and_its_bytes() {
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(23).wrapping_add(5))
        .collect();
    let vols = reex_vols(&total);
    let dir = reex_dir("prog-obf");
    std::fs::write(dir.join("bb0a1f"), &vols[0]).unwrap();
    std::fs::write(dir.join("aa93c2"), &vols[1]).unwrap();

    let hub = std::sync::Arc::new(crate::streamhub::StreamHub::default());
    let arm = crate::unpackprog::arm(&Some(hub.clone()), "nzo-205", 2);
    let p = hub
        .unpack
        .lock_ok()
        .get("nzo-205")
        .cloned()
        .expect("the arm registers the job");
    // Before anything runs: the count is knowable (the set is on disk),
    // the bytes are not yet.
    assert_eq!((p.volumes(), p.total(), p.done()), (2, 0, 0));

    assert!(extract_local(&dir, None).unwrap(), "set must extract");
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    // The member is ONE file split across both volumes, and both
    // volumes carry its whole-file header - the total must be the file,
    // not the file times the volume count.
    assert_eq!(p.total(), 400_000, "header total counts each file once");
    assert_eq!(p.done(), 400_000, "every byte reported by the end");

    // ...and the row stops claiming to unpack the moment the ladder is
    // over, on this path and on the failure ones.
    drop(arm);
    assert!(hub.unpack.lock_ok().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Sorted file names directly inside `dir` (our scratch dirs excluded).
fn names_in(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| !n.starts_with(".nzbfast"))
        .collect();
    v.sort();
    v
}

/// A `.rev`-shaped file: the real RAR5 recovery-volume signature (so
/// `Rar!` magic collects it as an obfuscated candidate), with a
/// memberless RAR5 archive further in - the SFX scan latches onto that
/// and hands back a set with nothing in it. Recovery data must survive
/// this misdetection; sweeping it would delete the only thing that can
/// rebuild a damaged set.
fn rev_shaped_file() -> Vec<u8> {
    let mut out = b"Rar!\x1aRev".to_vec();
    out.extend(std::iter::repeat_n(0x5Au8, 64));
    out.extend_from_slice(&nzbkit::rar::fixtures::rar5_volume(&[]));
    out
}

/// Run the disk extraction over `dir` the way each of its two real
/// callers does. Depth 0 is the offline `nzbfast extract` CLI; depth 1
/// is the daemon's post-download nested pass, which is the call that
/// unpacked the reported job (its `reextract_dir` step is name-gated
/// and never saw the hash-named volumes at all). Both are exercised
/// because only depth >= 1 also runs `sweep_spent_entry`.
fn obf_extract_at(dir: &std::path::Path, depth: usize) -> bool {
    if depth == 0 {
        extract_local(dir, None).unwrap_or(false)
    } else {
        matches!(extract_nested(dir, None, depth), Ok(NestOutcome::Produced))
    }
}

/// The reported bug: a completed obfuscated download left its seven
/// extension-less hash-named volumes sitting beside the extracted
/// video. `sweep_spent_entry`'s name grouping cannot see them (each
/// hash name is its own `release_stem`, so its "exactly one set"
/// guard trips), so the sweep has to happen where the volumes were
/// actually proven spent - in the obfuscated extractor itself.
#[test]
fn obfuscated_extraction_removes_the_volumes_it_consumed() {
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(23).wrapping_add(5))
        .collect();
    let vols = reex_vols(&total);
    for depth in [0usize, 1] {
        let dir = reex_dir(&format!("obf-sweep-{depth}"));
        std::fs::write(dir.join("301c0186f3bbdc58ac03a8739f989391c4"), &vols[0]).unwrap();
        std::fs::write(dir.join("0a77bd41e9c2f6538ab10d47cc9021ef73"), &vols[1]).unwrap();

        assert!(
            obf_extract_at(&dir, depth),
            "depth {depth}: set must extract"
        );
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        // Depth 0 is the user's own downloaded set (or an offline
        // `extract` target): its retention belongs to finalize/policy,
        // exactly as for a NAMED set, so the volumes stay. Only a
        // deeper level is ours to clean, because it exists solely
        // because an outer pass produced it.
        let want: Vec<String> = if depth == 0 {
            vec![
                "0a77bd41e9c2f6538ab10d47cc9021ef73".into(),
                "301c0186f3bbdc58ac03a8739f989391c4".into(),
                "film.mkv".into(),
            ]
        } else {
            vec!["film.mkv".into()]
        };
        assert_eq!(
            names_in(&dir),
            want,
            "depth {depth}: wrong retention for a successfully extracted set"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// ...and the mirror guarantee, which outranks it: a set that did NOT
/// extract keeps every volume. They are the only copy on disk, and
/// PAR2 repair, `.rev` reconstruction and a plain retry all read them.
#[test]
fn failed_obfuscated_extraction_keeps_every_volume() {
    use nzbkit::rar::fixtures;
    let total: Vec<u8> = (0..200_000u32)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(7))
        .collect();
    let half = total.len() / 2;
    let n = total.len() as u64;
    // Both volumes parse and group into ONE set (so both are in the
    // extractor's source list), but the member name escapes the output
    // directory, so `write_archives_to` fails after the set is bound.
    let vols = [
        fixtures::rar5_volume_n(&[("../escape.mkv", n, &total[..half], false, true)], 0),
        fixtures::rar5_volume_n(&[("../escape.mkv", n, &total[half..], true, false)], 1),
    ];
    for depth in [0usize, 1] {
        let dir = reex_dir(&format!("obf-failkeep-{depth}"));
        std::fs::write(dir.join("c41d8fa9f00b204e98009980"), &vols[0]).unwrap();
        std::fs::write(dir.join("7215ee9c7d9dc229d2921a40"), &vols[1]).unwrap();

        assert!(
            !obf_extract_at(&dir, depth),
            "depth {depth}: an extraction that produced nothing reported success"
        );
        assert_eq!(
            std::fs::read(dir.join("c41d8fa9f00b204e98009980")).unwrap(),
            vols[0],
            "depth {depth}: volume 1 of a failed set was altered or removed"
        );
        assert_eq!(
            std::fs::read(dir.join("7215ee9c7d9dc229d2921a40")).unwrap(),
            vols[1],
            "depth {depth}: volume 2 of a failed set was altered or removed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// A volume that begins INSIDE a member whose earlier volume is not on
/// disk - a mid-set fragment. `Rar!` magic, parses fine, and no
/// unpacker on earth can produce a byte from it.
fn mid_set_fragment() -> Vec<u8> {
    use nzbkit::rar::fixtures;
    let body: Vec<u8> = (0..80_000u32).map(|i| (i as u8) ^ 0x5A).collect();
    // Volume #2 of some set: `is_split_before` on its only member, and
    // volumes #0 and #1 are nowhere.
    fixtures::rar5_volume_n(&[("orphan.mkv", 300_000, &body, true, true)], 2)
}

/// THE case: a complete obfuscated set that unpacks perfectly, and one
/// unusable stray middle volume sitting in the same directory. The job
/// SUCCEEDS - the payload was delivered - and the stray is left alone.
///
/// The sweep collects candidates by `Rar!` MAGIC, not by extension, so
/// any stray with a RAR head became a set of its own, failed (a middle
/// volume has no first part), and failed the entire job with "an
/// archive in the output directory could not be unpacked". Reached in
/// the field 22 Aug 2026 through par2cmdline's leftover `<name>.1`
/// backup - see `tests/integration/stream_repair.rs`'s
/// `an_external_repair_of_a_volume_set_still_admits_the_child`, whose
/// FINDING (a) is that SOURCE, fixed separately in
/// `repair::purge_par2_backups`. This is the generic half: a user's own
/// file, a partial from an interrupted external tool, or a `.rev`-shaped
/// payload the parser latches onto all reproduce it.
#[test]
fn a_stray_mid_set_volume_does_not_fail_a_job_whose_set_unpacked() {
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
        .collect();
    let vols = reex_vols(&total);
    let stray = mid_set_fragment();
    for depth in [0usize, 1] {
        let dir = reex_dir(&format!("obf-stray-{depth}"));
        std::fs::write(dir.join("b7d1e4a05c93f28610ab77de"), &vols[0]).unwrap();
        std::fs::write(dir.join("29fc0b6e83d417a95c20ee31"), &vols[1]).unwrap();
        std::fs::write(dir.join("f04a91cd2b7e635018df44ba"), &stray).unwrap();

        assert!(
            obf_extract_at(&dir, depth),
            "depth {depth}: one unusable stray middle volume failed a job \
             whose own set extracted correctly"
        );
        assert_eq!(
            std::fs::read(dir.join("film.mkv")).unwrap(),
            total,
            "depth {depth}: payload"
        );
        // Never eaten and never swept: whatever the fragment belongs to,
        // it is not the set we just spent. Forgiving its failure AND
        // deleting it is the one combination that loses a file.
        assert_eq!(
            std::fs::read(dir.join("f04a91cd2b7e635018df44ba")).unwrap(),
            stray,
            "depth {depth}: the stray was altered or removed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The field shape itself: the job's own set is already unpacked and
/// gone (a named set the ladder above spent, or par2's `<name>.1` left
/// beside the repaired payload), so the stray is the ONLY `Rar!`-magic
/// file the nested pass sees. It must still not fail the job.
///
/// Distinct from the test above because it also covers the "no
/// extractor claimed it" backstop at the bottom of `extract_one_level`:
/// an arm that stayed silent here would leave the level unclaimed, and
/// that backstop reads the stray's RAR head and returns `Failed` - the
/// same job failure through a different door.
#[test]
fn a_stray_mid_set_volume_alone_beside_the_payload_does_not_fail_the_job() {
    let dir = reex_dir("obf-stray-alone");
    let payload: Vec<u8> = (0..250_000u32).map(|i| (i as u8) ^ 0x33).collect();
    std::fs::write(dir.join("movie.mkv"), &payload).unwrap();
    let stray = mid_set_fragment();
    std::fs::write(dir.join("movie.mkv.1"), &stray).unwrap();

    assert!(
        obf_extract_at(&dir, 1),
        "a leftover mid-set volume beside the delivered payload failed the job"
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), payload);
    assert_eq!(
        std::fs::read(dir.join("movie.mkv.1")).unwrap(),
        stray,
        "the stray was altered or removed"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// …and the guarantee that keeps the forgiveness honest, which outranks
/// both: a directory whose obfuscated content is NOTHING BUT fragments
/// has no payload to point at, so `ObfReport::ok` - what
/// `repair::reextract_dir` and `rarfix` read, where the volumes on disk
/// ARE the job's own payload - still says no. A job that quietly
/// succeeds while leaving real payload packed is the worse failure.
#[test]
fn fragments_with_nothing_extracted_beside_them_still_fail() {
    let dir = reex_dir("obf-frag-only");
    let stray = mid_set_fragment();
    std::fs::write(dir.join("3ab19f7c05e2d846b1cc90fa"), &stray).unwrap();
    let obf = crate::unpack::collect_obfuscated_rar_volumes(&dir).unwrap();
    assert_eq!(obf.len(), 1, "the fragment must be collected by magic");

    let report = crate::unpack::extract_obfuscated_rar(&dir, &obf, None, 1);
    assert!(
        !report.strays.is_empty() && !report.produced && !report.failed,
        "expected a stray-only verdict, got {report:?}"
    );
    assert!(
        !report.ok(),
        "a directory of nothing but mid-set fragments reported the payload delivered"
    );
    assert_eq!(
        std::fs::read(dir.join("3ab19f7c05e2d846b1cc90fa")).unwrap(),
        stray,
        "the fragment was altered or removed"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A memberless `.rev`-shaped set beside a headless fragment: the
/// recovery volume extracts as a no-op and must not count as "a set
/// extracted", or the fragment is forgiven and the caller greens a
/// directory that published nothing (Codex F-23).
#[test]
fn a_memberless_recovery_volume_does_not_forgive_a_lone_fragment() {
    let dir = reex_dir("obf-rev-plus-frag");
    let rev = rev_shaped_file();
    let frag = mid_set_fragment();
    std::fs::write(dir.join("0f1e2d3c4b5a69788796a5b4"), &rev).unwrap();
    std::fs::write(dir.join("3ab19f7c05e2d846b1cc90fa"), &frag).unwrap();
    let obf = crate::unpack::collect_obfuscated_rar_volumes(&dir).unwrap();
    assert_eq!(obf.len(), 2, "both files must be collected by magic");

    let report = crate::unpack::extract_obfuscated_rar(&dir, &obf, None, 1);
    assert!(
        !report.produced && !report.failed && report.strays.len() == 1,
        "expected a stray-only verdict, got {report:?}"
    );
    assert!(!report.ok(), "a memberless set forgave a stray fragment");
    assert_eq!(
        std::fs::read(dir.join("0f1e2d3c4b5a69788796a5b4")).unwrap(),
        rev
    );
    assert_eq!(
        std::fs::read(dir.join("3ab19f7c05e2d846b1cc90fa")).unwrap(),
        frag
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A `.rev` recovery volume rides along with the obfuscated set, is
/// collected by the same `Rar!` magic test, and parses as a memberless
/// set of its own. The real set is swept; the recovery volume is not.
///
/// Depth 1 is the sharp end. Sweeping the volumes leaves the `.rev`
/// as the only `Rar!`-magic file at the level, and `sweep_spent_entry`
/// then reads one `release_stem` as "exactly one release set present,
/// therefore spent" - so the new sweep must not be allowed to feed it
/// a directory the extraction already emptied.
#[test]
fn obfuscated_sweep_never_touches_a_memberless_rar_file() {
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(19))
        .collect();
    let vols = reex_vols(&total);
    let rev = rev_shaped_file();
    for depth in [0usize, 1] {
        let dir = reex_dir(&format!("obf-rev-{depth}"));
        std::fs::write(dir.join("f9a2c7b1049e6d3358ff20aa"), &vols[0]).unwrap();
        std::fs::write(dir.join("18cc4d0e6b7a92f1d3e05581"), &vols[1]).unwrap();
        std::fs::write(dir.join("5b3e91da77c0416f8a2d99e4"), &rev).unwrap();

        let _ = obf_extract_at(&dir, depth);
        // The payload came out, and the volumes that made it are gone
        // at depth >= 1 (at depth 0 nothing is swept at all - the
        // user's own set is finalize/policy's call).
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        let swept = depth >= 1;
        assert_eq!(
            !dir.join("f9a2c7b1049e6d3358ff20aa").exists(),
            swept,
            "depth {depth}"
        );
        assert_eq!(
            !dir.join("18cc4d0e6b7a92f1d3e05581").exists(),
            swept,
            "depth {depth}"
        );
        // …and at EVERY depth the recovery volume is byte-for-byte
        // where it was. This is the property that must not bend: it is
        // what a repair reads, and emptying the set around it must
        // never make some other guard think it is spent.
        assert_eq!(
            std::fs::read(dir.join("5b3e91da77c0416f8a2d99e4")).unwrap(),
            rev,
            "depth {depth}: a memberless Rar!-magic file (the .rev shape) was swept"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The same property, with §101's volume-eating mode ARMED.
///
/// The test above passes with eating off, which is the default and
/// is also the only way it has ever run - so it could not see that
/// eating deletes from INSIDE the extractor, before
/// `sweep_spent_obfuscated` is reached at all. Every one of that
/// sweep's three refusals, `has_member` first among them, sits after
/// the point where the file was already gone.
///
/// Both halves matter here: the real volumes must still be eaten
/// (the mode has to keep working), and the memberless recovery
/// volume must still be untouched.
#[test]
fn eating_volumes_never_swallows_a_memberless_rar_file() {
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(19))
        .collect();
    let vols = reex_vols(&total);
    let rev = rev_shaped_file();
    let dir = reex_dir("obf-rev-eating");
    std::fs::write(dir.join("f9a2c7b1049e6d3358ff20aa"), &vols[0]).unwrap();
    std::fs::write(dir.join("18cc4d0e6b7a92f1d3e05581"), &vols[1]).unwrap();
    std::fs::write(dir.join("5b3e91da77c0416f8a2d99e4"), &rev).unwrap();

    {
        // Armed for this thread only, restored on drop.
        let _arm = crate::eatvol::EatArm::new(true);
        let _ = obf_extract_at(&dir, 1);
    }

    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    // The mode still does its job: the volumes that made the payload
    // went during extraction rather than after it.
    assert!(
        !dir.join("f9a2c7b1049e6d3358ff20aa").exists(),
        "the eating mode did not consume the first volume"
    );
    assert!(
        !dir.join("18cc4d0e6b7a92f1d3e05581").exists(),
        "the eating mode did not consume the second volume"
    );
    // …and the recovery volume is byte-for-byte where it was.
    assert_eq!(
        std::fs::read(dir.join("5b3e91da77c0416f8a2d99e4")).unwrap(),
        rev,
        "the volume-eating mode swallowed a memberless Rar!-magic file (the .rev shape)"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The fallback ladder's own entry point must see an obfuscated set.
///
/// When an obfuscated download demotes WITH a recorded reason (a
/// compressed payload, the held-bytes cap, an in-stream CRC gate), the
/// ladder calls `try_unrar` and FAILS the job when it answers false.
/// `try_unrar` used to look for a `.rar` extension, then a numeric one -
/// a hash name has neither, so it answered false on a set that unpacks
/// perfectly, and the job died with its payload still packed on disk.
///
/// The second half is the reason the fix cannot simply unpack and walk
/// away: every caller hands the SAME directory to the depth-1 nested
/// pass straight afterwards. A named set is fenced off there by
/// `outer_vol_stems`; hash names carry no stem, so spent volumes left
/// behind would be extracted a SECOND time and published beside the
/// real payload as `extracted-1-film.mkv`.
#[test]
fn demoted_obfuscated_set_unpacks_through_the_fallback_ladder() {
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
        .collect();
    let vols = reex_vols(&total);
    let dir = reex_dir("obf-fallback");
    std::fs::write(dir.join("a3f19c07d2b845e6"), &vols[0]).unwrap();
    std::fs::write(dir.join("0e7bd4128c9a63f5"), &vols[1]).unwrap();

    assert!(
        try_unrar(&dir, None),
        "the fallback ladder could not unpack an obfuscated set - the job fails here"
    );
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);

    // …and the pass the ladder runs next must find nothing left to do.
    assert!(
        matches!(extract_nested(&dir, None, 1), Ok(NestOutcome::Produced)),
        "the nested pass that follows the ladder failed"
    );
    assert_eq!(
        names_in(&dir),
        vec!["film.mkv".to_string()],
        "the payload was published twice (or a spent volume survived)"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `reextract_dir` must never report success for a pass that extracted
/// nothing. Its collector is name-gated, so on a RESUMED obfuscated job
/// it found zero volumes and returned `Ok(true)` - a silent success that
/// left the payload packed. Today a later nested pass happens to rescue
/// it; `smart::unlock` has no such pass behind it, and reorder or skip
/// that one and the job exits 0 with no payload at all.
///
/// The property asserted is the honest one: when it says success, the
/// payload IS on disk.
#[test]
fn reextract_dir_success_means_the_payload_is_on_disk() {
    let total: Vec<u8> = (0..300_000u32)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(11))
        .collect();
    let vols = reex_vols(&total);
    let dir = reex_dir("obf-reextract");
    std::fs::write(dir.join("cd8140b7e2a95f36"), &vols[0]).unwrap();
    std::fs::write(dir.join("41b0f9c635de7a28"), &vols[1]).unwrap();

    assert!(
        reextract_dir(&dir, None).unwrap(),
        "resumed obfuscated set must re-extract"
    );
    assert!(
        dir.join("film.mkv").exists(),
        "reextract_dir reported success having extracted nothing"
    );
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    assert_eq!(
        names_in(&dir),
        vec!["film.mkv".to_string()],
        "spent volumes survived a successful re-extraction"
    );
    std::fs::remove_dir_all(&dir).unwrap();

    // …and a directory with nothing packed in it is still a legitimate
    // no-op, not a failure: the par-only "recreated bare payload" flow
    // depends on it.
    let bare = reex_dir("obf-reextract-bare");
    std::fs::write(bare.join("film.mkv"), &total).unwrap();
    assert!(
        reextract_dir(&bare, None).unwrap(),
        "a bare payload is a no-op, not a failure"
    );
    assert_eq!(std::fs::read(bare.join("film.mkv")).unwrap(), total);
    std::fs::remove_dir_all(&bare).unwrap();
}

// -- nested password-chain auto-unlock -------------------------------

fn chain_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-pwchain-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A single non-volume RAR5 store archive holding `files`, each its own
/// AES stream under one shared `pw` - the real multi-file encrypted
/// store shape (`rar -m0 -p`).
fn enc_store(pw: &str, files: &[(&str, &[u8])], seed: u8) -> Vec<u8> {
    use nzbkit::rar::fixtures;
    let encs: Vec<fixtures::EncFile> = files
        .iter()
        .enumerate()
        .map(|(i, (_, b))| fixtures::encrypt_file(pw, b, seed.wrapping_add((i as u8) * 7 + 1)))
        .collect();
    let pieces: Vec<(&str, &fixtures::EncFile, std::ops::Range<usize>, bool, bool)> = files
        .iter()
        .zip(&encs)
        .map(|((name, _), f)| (*name, f, 0..f.cipher.len(), false, false))
        .collect();
    fixtures::rar5_volume_enc(&pieces, None)
}

/// Recursively find the first file named `name` under `dir`.
fn find_file(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n == name) {
                return Some(p);
            }
        }
    }
    None
}

/// The gauntlet: a 3-level encrypted chain where each level carries the
/// NEXT level's password in a sibling text file. From only the outermost
/// password on disk, the whole stack auto-extracts with zero manual
/// unlocks and byte-exact final output.
#[test]
fn password_chain_auto_unlocks_three_levels() {
    let dir = chain_dir("unlock");
    let payload: Vec<u8> = (0..120_000u32)
        .map(|i| (i as u8).wrapping_mul(53).wrapping_add(9))
        .collect();
    // Innermost first, then wrap outward.
    let stage3 = enc_store("charlie", &[("movie.mkv", &payload)], 40);
    let stage2 = enc_store(
        "bravo",
        &[("stage3.rar", &stage3), ("pw3.txt", b"charlie\n")],
        20,
    );
    let stage1 = enc_store(
        "alpha",
        &[("stage2.rar", &stage2), ("pw2.txt", b"bravo\n")],
        10,
    );
    // On disk, as if the level above had just produced them.
    std::fs::write(dir.join("stage1.rar"), &stage1).unwrap();
    std::fs::write(dir.join("pw1.txt"), b"alpha\n").unwrap();

    // No job password: every level's key must come from the chain.
    let ok = extract_nested(&dir, None, 0).expect("extract_nested");
    assert!(
        ok.produced(),
        "3-level password chain must auto-extract (rc=0), zero parks"
    );

    let found = find_file(&dir, "movie.mkv").expect("final payload produced");
    assert_eq!(
        std::fs::read(&found).unwrap(),
        payload,
        "payload bytes differ"
    );

    // A clean nest leaves ONLY the final payload plus the extracted
    // siblings the chain rode in on (the password notes) - the spent
    // intermediate archives must not litter the output dir.
    assert!(
        find_file(&dir, "stage2.rar").is_none(),
        "consumed intermediate stage2.rar must be swept"
    );
    assert!(
        find_file(&dir, "stage3.rar").is_none(),
        "consumed intermediate stage3.rar must be swept"
    );
    // Legitimately-extracted siblings survive the sweep.
    assert!(
        find_file(&dir, "pw2.txt").is_some(),
        "extracted sibling pw2.txt kept"
    );
    assert!(
        find_file(&dir, "pw3.txt").is_some(),
        "extracted sibling pw3.txt kept"
    );
    // The outer downloaded archive (in `before`, not produced by the
    // nest) is out of scope for this sweep - stage1.rar is the ONLY
    // archive that may remain.
    let leftover_archives: Vec<String> = {
        let mut v = Vec::new();
        let mut stack = vec![dir.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| {
                    let x = x.to_ascii_lowercase();
                    x == "rar" || x == "7z"
                }) {
                    v.push(p.file_name().unwrap().to_string_lossy().into_owned());
                }
            }
        }
        v.sort();
        v
    };
    assert_eq!(
        leftover_archives,
        vec!["stage1.rar".to_string()],
        "only the outer downloaded archive may remain, got {leftover_archives:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative: when no harvested candidate matches, the level fails loudly
/// (rc=1 -> the daemon parks for a manual 🔑) exactly as before this
/// feature, and never writes garbage output.
#[test]
fn password_chain_parks_when_no_candidate_matches() {
    let dir = chain_dir("nomatch");
    let payload = vec![0x5au8; 48_000];
    let locked = enc_store("password-not-on-disk", &[("movie.mkv", &payload)], 12);
    std::fs::write(dir.join("stage1.rar"), &locked).unwrap();
    // A decoy sidecar that does not contain the password.
    std::fs::write(
        dir.join("readme.nfo"),
        b"enjoy the release\nripped by nobody\n",
    )
    .unwrap();

    let ok = extract_nested(&dir, None, 0).expect("extract_nested");
    assert_eq!(
        ok,
        NestOutcome::Failed,
        "unmatched password must fail loudly, not exit 0"
    );
    // The extractor may create-then-abort an output file on a wrong
    // password, but it must never yield the real plaintext (rc=1 tells
    // the daemon to park and keep the volumes for a manual 🔑).
    if let Some(p) = find_file(&dir, "movie.mkv") {
        assert_ne!(
            std::fs::read(&p).unwrap(),
            payload,
            "must not decrypt without the key"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A store chain deeper than the cap must NOT hard-fail (the old rc=1
/// bug). The disk post-pass unpacks to the cap, leaves the deepest
/// reached archive materialized on disk, and returns success (rc=0) -
/// the design guarantee that a too-deep chain degrades, never fails.
#[test]
fn nested_chain_deeper_than_cap_materializes_rc0() {
    use nzbkit::rar::fixtures;
    let cap = nzbkit::extract::nested_depth_cap();
    assert_eq!(cap, 5, "test assumes the default cap; env override active?");
    let dir = chain_dir("deepcap");
    let payload: Vec<u8> = (0..80_000u32)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
        .collect();
    let wrap = |name: &str, inner: &[u8]| {
        fixtures::rar5_volume(&[(name, inner.len() as u64, inner, false, false)])
    };
    // a1 < a2 < a3 < a4 < a5 < a6 < payload: 6 store levels, one deeper
    // than the cap. Extracting akN yields ak(N+1).
    let a6 = wrap("payload.bin", &payload);
    let a5 = wrap("a6.rar", &a6);
    let a4 = wrap("a5.rar", &a5);
    let a3 = wrap("a4.rar", &a4);
    let a2 = wrap("a3.rar", &a3);
    let a1 = wrap("a2.rar", &a2);
    std::fs::write(dir.join("release.rar"), &a1).unwrap();

    let ok = extract_nested(&dir, None, 0).expect("extract_nested");
    assert!(
        ok.produced(),
        "a chain deeper than the cap must exit rc=0, not fail"
    );
    // The deepest reached layer (a6.rar = wrap of the payload) is left
    // materialized as a healthy archive; the payload itself is NOT
    // produced (that needs a deeper cap), but the job did not fail.
    let left = find_file(&dir, "a6.rar").expect("deepest layer left materialized");
    assert_eq!(
        std::fs::read(&left).unwrap(),
        a6,
        "materialized archive must be byte-exact"
    );
    assert!(
        find_file(&dir, "payload.bin").is_none(),
        "payload is past the cap - not yet produced"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Harvest is bounded: a sidecar with far more lines than the cap yields
/// at most MAX_PW_CANDIDATES candidates, and the job password leads.
#[test]
fn harvest_password_candidate_cap() {
    let dir = chain_dir("cap");
    let mut big = String::new();
    for i in 0..500 {
        big.push_str(&format!("candidate-{i}\n"));
    }
    std::fs::write(dir.join("list.txt"), big).unwrap();
    let cands = harvest_password_candidates(&dir, Some("job-pw"));
    assert!(
        cands.len() <= MAX_PW_CANDIDATES,
        "harvest exceeded cap: {}",
        cands.len()
    );
    assert_eq!(cands[0].value, "job-pw");
    assert_eq!(cands[0].source, "job password");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Harvest reads sidecar lines (raw AND label-stripped), dedupes, and
/// includes the release/sibling stems.
#[test]
fn harvest_reads_lines_labels_and_stems() {
    let dir = chain_dir("harvest");
    std::fs::write(dir.join("password.txt"), b"Password: hunter2\n").unwrap();
    std::fs::write(
        dir.join("The.Release.Name.rar"),
        b"Rar!\x1a\x07\x01\x00junk",
    )
    .unwrap();
    // Oversized sidecar is ignored (payload, not a hint).
    std::fs::write(
        dir.join("big.txt"),
        vec![b'x'; (PW_SIDECAR_MAX + 1) as usize],
    )
    .unwrap();
    let cands = harvest_password_candidates(&dir, None);
    let vals: Vec<&str> = cands.iter().map(|c| c.value.as_str()).collect();
    assert!(vals.contains(&"Password: hunter2"), "raw line: {vals:?}");
    assert!(vals.contains(&"hunter2"), "label-stripped value: {vals:?}");
    assert!(
        cands.iter().any(|c| c.source == "release/sibling stem"),
        "stems harvested: {vals:?}"
    );
    assert!(
        !vals.iter().any(|v| v.starts_with("xxxx")),
        "oversized sidecar must be skipped"
    );
    let mut uniq = vals.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(uniq.len(), vals.len(), "candidates must be deduped");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The provided password, when it already works, is kept as-is: no
/// harvest, no override.
#[test]
fn resolve_keeps_working_provided_password() {
    let dir = chain_dir("provided");
    let vol = enc_store("rightpw", &[("a.bin", b"data bytes")], 30);
    std::fs::write(dir.join("s.rar"), &vol).unwrap();
    assert_eq!(resolve_level_password(&dir, Some("rightpw")), None);
    // A wrong provided password with a matching sidecar gets corrected.
    std::fs::write(dir.join("key.txt"), b"rightpw\n").unwrap();
    assert_eq!(
        resolve_level_password(&dir, Some("wrongpw")).as_deref(),
        Some("rightpw")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep 13 Aug R2: a RAR whose signature block was damaged
/// before posting sniffs as Plain (`plain_by_sniff`) - the TODO 160
/// admission then patched the signature back through the Plain writer,
/// nothing re-sniffed, and the corrected archive retired PACKED as the
/// payload of a Completed job. Damage over the sniff window must
/// decline the in-place lane and take the materialize + `repair_dir` +
/// `reextract_dir` path, which re-extracts what it repairs.
#[test]
fn head_damage_disqualifies_the_in_place_plain_patch() {
    // Block 0 covers the sniff window at every block size.
    assert!(!plain_patch_keeps_sniff(&[0], 4096));
    assert!(!plain_patch_keeps_sniff(&[0], 4));
    // A tiny block size leaves the window spanning block 1 too.
    assert!(!plain_patch_keeps_sniff(&[1], 4));
    // Damage clear of the window keeps the one-pass win (TODO 160).
    assert!(plain_patch_keeps_sniff(&[1], 4096));
    assert!(plain_patch_keeps_sniff(&[2], 4));
    assert!(plain_patch_keeps_sniff(&[], 4096));
}

/// ...and end to end through the gate: a plain-by-sniff slot whose bad
/// block is the head block declines the whole mapped call, leaving the
/// posted bytes for the disk lane to repair and re-extract.
#[tokio::test]
async fn head_damaged_plain_slot_declines_the_mapped_lane() {
    let dir = tdir("sniffhead");
    let ex = nzbkit::extract::Extractor::new(&dir, 1, true);
    // Posted bytes with NO archive magic at offset 0: the slot sniffs
    // Plain, by sniff, exactly like a signature-damaged volume.
    let posted = vec![0x11u8; 8192];
    ex.write(0, "v.rar", 8192, 0, &posted).unwrap();
    assert!(ex.is_plain_patchable(0), "premise: the slot is admissible");
    let set = pset(vec![pfile("v.rar", 8192)]);
    let report = nzbkit::live::SlotReport {
        par2_name: Some("v.rar".to_string()),
        total_blocks: 2,
        bad_blocks: vec![0],
        live_blocks: 1,
        readback_blocks: 0,
        length: 8192,
    };
    assert!(
        !mapped_verdict_with_reports(&dir, &ex, &set, &[], &[(0, report)]).await,
        "head damage on a sniffed-plain slot must decline to the disk lane"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The purge that keeps par2cmdline's leftover `<name>.1` backups from
/// failing a repaired job (22 Aug 2026, see `purge_par2_backups`).
///
/// Everything here is about what it REFUSES to delete: it runs after a
/// successful repair, in the user's own output directory, so each guard
/// is a file somebody would be entitled to be angry about losing.
#[test]
fn the_par2_backup_purge_takes_only_the_backups_this_run_made() {
    let dir = tdir("par2purge");
    let write = |name: &str| std::fs::write(dir.join(name), b"x").unwrap();
    let there = |name: &str| dir.join(name).exists();

    // Predates the run: par2 did not make it, so it is not ours.
    write("r.part1.rar.1");
    let before = dir_entry_names(&dir).expect("a readable directory snapshots");

    // par2's own backups of two damaged volumes - the whole point.
    write("r.part2.rar.1");
    write("r.part3.rar.2");
    // The repaired targets themselves.
    write("r.part1.rar");
    write("r.part2.rar");
    write("r.part3.rar");
    // A target that IS `.<digits>`-named: the set declares it, so it
    // survives however much it looks like a backup of `odd.rar`.
    write("odd.rar.1");
    // Not a backup of anything the set names.
    write("stranger.rar.1");
    // A `.N` sibling of a real target, but N is not a number.
    write("r.part2.rar.bak");
    // A directory that matches the pattern exactly.
    std::fs::create_dir(dir.join("r.part1.rar.9")).unwrap();

    let targets: Vec<(String, u64)> = ["r.part1.rar", "r.part2.rar", "r.part3.rar", "odd.rar.1"]
        .iter()
        .map(|n| ((*n).to_string(), 1))
        .collect();
    purge_par2_backups(&dir, &targets, &before);

    assert!(!there("r.part2.rar.1"), "par2's backup was not purged");
    assert!(!there("r.part3.rar.2"), "a `.2` backup was not purged");
    for kept in [
        "r.part1.rar.1",
        "r.part1.rar",
        "r.part2.rar",
        "r.part3.rar",
        "odd.rar.1",
        "stranger.rar.1",
        "r.part2.rar.bak",
        "r.part1.rar.9",
    ] {
        assert!(
            there(kept),
            "the purge took {kept}, which is not its to take"
        );
    }

    // No targets at all (an obfuscated set we never named) purges nothing.
    let before = dir_entry_names(&dir).unwrap();
    write("r.part2.rar.3");
    purge_par2_backups(&dir, &[], &before);
    assert!(there("r.part2.rar.3"), "an empty target list purged a file");

    // An unreadable directory snapshots as None, so the caller skips the
    // purge entirely (Codex F-06): a missing or partial snapshot must not
    // make every pre-existing `.N` look freshly made.
    assert!(dir_entry_names(&dir.join("does-not-exist")).is_none());

    std::fs::remove_dir_all(&dir).unwrap();
}

// The row-26 in-place chase repair went default-ON on 22 Aug 2026, so
// the switch that matters is now the one that turns it OFF. This is the
// PURE half of it: reading the process environment here would race the
// parallel test runner, which is why `chase_repair_on` is a two-line
// wrapper over a value parser (the `nzbkit::extract::config` pattern).
//
// The teeth are the middle two cases. A near-miss value must NOT disarm
// - a job that quietly takes the 3.05x materialize route because a shell
// exported `NZBFAST_NO_CHASE_REPAIR=true` would look like a performance
// regression with no fingerprint in the log.
#[test]
fn only_an_exact_one_disarms_the_chase_repair() {
    assert!(
        chase_repair_on_value(None),
        "unset must be ON after the flip"
    );
    assert!(
        !chase_repair_on_value(Some("1")),
        "the kill switch must bite"
    );
    assert!(
        chase_repair_on_value(Some("")),
        "empty is not the kill switch"
    );
    assert!(
        chase_repair_on_value(Some("true")),
        "only `1` is the kill switch"
    );
    assert!(
        chase_repair_on_value(Some("0")),
        "`0` is not the kill switch"
    );
}
