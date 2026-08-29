//! §94 A: a resumed job maps in-stream. Restored spans replay through
//! the normal `Extractor::write` path before the pool opens, so the
//! mappers re-derive their state from replayed headers and the run
//! continues one-pass instead of materializing every volume and
//! extracting from disk afterwards.
//!
//! A sibling-dir child module (the `e2e_repair` pattern, harness reached
//! through `super::*`) so `e2e.rs` stays inside its size-gate baseline.
//!
//! These legs run the DEFAULT - the replay has been on since 21 Aug
//! 2026 - so none of them sets an env var. `the_kill_switch_puts_a_
//! resumed_job_back_on_the_disk_path` is the twin that pins the escape
//! hatch, and it is the one that fails if `NZBFAST_NO_RESUME_MAP` stops
//! being honoured.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Run 1 of a kill+resume leg: start `nzbfast get`, wait until the mock
/// server has served `frac` of `total_articles` AND the journal carries a
/// line starting with `rec` (so run 2 has real placements to restore
/// from), then SIGKILL. `rec: None` waits on the served fraction alone -
/// for the shapes that journal nothing mid-flight. Returns the served
/// count at the kill.
///
/// The pacing lives in the caller's `Chaos { delay_ms }`: an unpaced
/// server on a busy box can finish the whole set before the poll loop
/// ever sees the threshold, and a kill after completion leaves nothing to
/// resume.
async fn kill9_run1(
    cfg: &Path,
    nzb: &Path,
    out: &Path,
    served: &Arc<AtomicU64>,
    total_articles: u64,
    frac: (u64, u64),
    rec: Option<&'static str>,
    extra_args: &[&str],
) -> u64 {
    let (cfg, nzb, out, served2) = (
        cfg.to_path_buf(),
        nzb.to_path_buf(),
        out.to_path_buf(),
        served.clone(),
    );
    let extra: Vec<String> = extra_args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_OPEN", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("get")
            .arg(&nzb)
            .arg("--out")
            .arg(&out)
            .arg("--connections")
            .arg("2")
            .arg("--window")
            .arg("2");
        for a in &extra {
            cmd.arg(a);
        }
        let mut child = cmd.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let journal = out.join(".nzbfast.journal");
        while served2.load(Ordering::Relaxed) < total_articles * frac.0 / frac.1
            || rec.is_some_and(|rec| {
                !std::fs::read_to_string(&journal)
                    .is_ok_and(|s| s.lines().any(|line| line.starts_with(rec)))
            })
        {
            if std::time::Instant::now() > deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        child.kill().unwrap(); // SIGKILL
        let _ = child.wait();
    })
    .await
    .unwrap();
    let n = served.load(Ordering::Relaxed);
    assert!(
        n >= total_articles * frac.0 / frac.1,
        "run 1 made no progress ({n}/{total_articles})"
    );
    n
}

/// §94 A: the same kill+resume as
/// `kill9_resume_direct_extract_refetches_little`, but run 2 must resume
/// INTO mapped mode - restored spans replay through the normal write
/// path, the mappers re-derive their state from replayed headers, and
/// the run stays one-pass: shape line says so, and no volume files exist
/// at exit (nothing materialized, nothing re-extracted from disk).
#[tokio::test(flavor = "multi_thread")]
async fn kill9_resume_map_resumes_into_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("resume-map");
    let inner = payload(3_000_000, 47);
    let n_vols = 4;
    let per = inner.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    let mut pos = 0usize;
    for i in 0..n_vols {
        let len = if i == 0 {
            per + 1
        } else if i < n_vols - 1 {
            per
        } else {
            inner.len() - pos
        };
        let part = &inner[pos..pos + len];
        pos += len;
        let vol = fixtures::rar5_volume_n(
            &[("movie.mkv", inner.len() as u64, part, i > 0, i < n_vols - 1)],
            i as u64,
        );
        let name = format!("r.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    {
        let names: Vec<&str> = vol_names.iter().map(String::as_str).collect();
        assert!(fx.add_par2(20, &names, 25_000), "par2 create failed");
    }
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 10,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Run 1: the kill can land either side of classification; what
    // matters is a journal with real placements.
    let served_run1 = kill9_run1(
        &cfg,
        &nzb,
        &out,
        &served,
        total_articles,
        (2, 5),
        Some("R "),
        &[],
    )
    .await;

    // Run 2: replay + map. One-pass all the way to a clean finish.
    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "{log}");
    assert!(
        log.contains("[resume] replayed"),
        "no replay banner:\n{log}"
    );
    assert!(
        log.contains("one-pass"),
        "resumed run did not map in-stream:\n{log}"
    );
    // The old resume path's disk re-extraction must NOT have run.
    assert!(
        !log.contains("resumed job: the verified volumes"),
        "took the disk re-extract path:\n{log}"
    );
    // Refetch stays bounded to the un-journaled remainder (+1 slack).
    let journal_txt = std::fs::read_to_string(fx.dir.join("out/.nzbfast.journal")).ok();
    let refetched = served.load(Ordering::Relaxed) - served_run1;
    assert!(
        refetched <= total_articles,
        "replay refetched more than the whole set ({refetched}); journal: {journal_txt:?}"
    );
    // §94 A residual (22 Aug 2026): the replay READ those bytes from
    // the output, so the extractor must have found nearly all of them
    // already where this run's map puts them and left them in place -
    // only the header bytes inside the spans (consumed by the mapper,
    // never placed) are outside the count.
    let (replayed_mb, in_place_mb) = replay_banner(&log);
    assert!(replayed_mb > 0.5, "nothing meaningful replayed:\n{log}");
    assert!(
        in_place_mb >= replayed_mb * 0.9,
        "the replay wrote back {:.2} of the {replayed_mb} MB it read from the output - \
         the in-place match is not reaching the pwrites:\n{log}",
        replayed_mb - in_place_mb
    );
    // End state: extracted output byte-identical, no volume files (the
    // replayed sources are removed after the fully-good finish, and the
    // map never materialized any), journal gone.
    assert_eq!(std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(), inner);
    for v in &vol_names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} left behind under resume replay:\n{log}"
        );
    }
    assert!(!fx.dir.join("out/.nzbfast.journal").exists());
    // ...and byte-identical to a COLD run of the same post, read off
    // disk rather than against the fixture's idea of the payload.
    let cold = fx.dir.join("cold");
    let (log2, ok) = {
        let (cfg, nzb, cold) = (cfg.clone(), nzb.clone(), cold.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &cold, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "{log2}");
    assert_eq!(
        std::fs::read(cold.join("movie.mkv")).unwrap(),
        std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(),
        "resumed output differs from a cold run's"
    );
}

/// Parse "[resume] replayed N restored file(s) (X.Y MB) through the
/// one-pass path, Z.W MB left in place" into `(X.Y, Z.W)`.
fn replay_banner(log: &str) -> (f64, f64) {
    let tail = log
        .split("[resume] replayed ")
        .nth(1)
        .unwrap_or_else(|| panic!("no replay banner:\n{log}"));
    let replayed: f64 = tail
        .split_once(" MB)")
        .and_then(|(head, _)| head.rsplit_once('(').map(|(_, n)| n.to_string()))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no replayed byte count in the banner:\n{log}"));
    let in_place: f64 = tail
        .split_once(" MB left in place")
        .and_then(|(head, _)| head.rsplit_once(", ").map(|(_, n)| n.to_string()))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no in-place byte count in the banner:\n{log}"));
    (replayed, in_place)
}

/// The in-place skip's own kill switch: `NZBFAST_NO_RESUME_INPLACE=1`
/// makes the replay write every byte back, as it did before 22 Aug
/// 2026, and the output is byte-identical either way - the switch
/// changes the I/O, not the outcome. This is the arm a disk
/// measurement compares against with one binary.
#[tokio::test(flavor = "multi_thread")]
async fn the_in_place_kill_switch_writes_the_replay_back() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("resume-inplace-off");
    let inner = payload(3_000_000, 83);
    let n_vols = 4;
    let per = inner.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    let mut pos = 0usize;
    for i in 0..n_vols {
        let len = if i < n_vols - 1 {
            per
        } else {
            inner.len() - pos
        };
        let part = &inner[pos..pos + len];
        pos += len;
        let vol = fixtures::rar5_volume_n(
            &[("movie.mkv", inner.len() as u64, part, i > 0, i < n_vols - 1)],
            i as u64,
        );
        let name = format!("r.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    {
        let names: Vec<&str> = vol_names.iter().map(String::as_str).collect();
        assert!(fx.add_par2(20, &names, 25_000), "par2 create failed");
    }
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 10,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    kill9_run1(
        &cfg,
        &nzb,
        &out,
        &served,
        total_articles,
        (2, 5),
        Some("R "),
        &[],
    )
    .await;

    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || {
            run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_RESUME_INPLACE", "1")])
        })
        .await
        .unwrap()
    };
    assert!(ok, "{log}");
    assert!(log.contains("one-pass"), "did not map in-stream:\n{log}");
    let (replayed_mb, in_place_mb) = replay_banner(&log);
    assert!(replayed_mb > 0.5, "nothing meaningful replayed:\n{log}");
    assert_eq!(
        in_place_mb, 0.0,
        "the kill switch did not stop the in-place skip:\n{log}"
    );
    assert_eq!(std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(), inner);
    assert!(!fx.dir.join("out/.nzbfast.journal").exists());
}

/// The plan's resumed-encrypted-set leg, password present. An encrypted
/// RAR5 store set assembles CIPHERTEXT at plain store offsets and one AES
/// pass at finish decrypts it, so run 1's journal describes plaintext-once
/// outputs (D/E/K/T records). `restore()` re-encrypts those bytes back
/// into posted volume form, which means the replay sees exactly what the
/// wire would have delivered - and the in-stream decrypt arm, which
/// `resume_map` is what re-enables, re-derives its keys from the replayed
/// headers plus the job password.
///
/// No PAR2 on purpose: the restored-and-re-encrypted bytes must be right
/// on their own, and the payload equality at the end is the whole proof.
#[tokio::test(flavor = "multi_thread")]
async fn kill9_resume_map_encrypted_store_set_resumes_into_one_pass() {
    let mut fx = Fixture::new("resume-map-enc");
    let inner = payload(6_000_000, 93);
    let enc = fixtures::encrypt_file("hunter2", &inner, 29);
    let cipher = enc.cipher.clone();
    let n_vols = 3;
    let per = cipher.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    for i in 0..n_vols {
        let end = if i == n_vols - 1 {
            cipher.len()
        } else {
            (i + 1) * per
        };
        let vol = fixtures::rar5_volume_enc(
            &[("movie.mkv", &enc, i * per..end, i > 0, i < n_vols - 1)],
            Some(i as u64),
        );
        let name = format!("e.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 10,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Wait for a D record, not an R one: the plaintext-once grammar is
    // what this leg resumes from.
    let served_run1 = kill9_run1(
        &cfg,
        &nzb,
        &out,
        &served,
        total_articles,
        (3, 5),
        Some("D "),
        &["--password", "hunter2"],
    )
    .await;

    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || {
            // `--password` is a `get` argument, not a global one, so this
            // leg builds its own command rather than using run_get_args
            // (which prepends its extras ahead of the subcommand).
            let o = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--password")
                .arg("hunter2")
                .arg("--connections")
                .arg("4")
                .arg("--window")
                .arg("3")
                .output()
                .unwrap();
            (
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
                o.status.success(),
            )
        })
        .await
        .unwrap()
    };
    assert!(ok, "{log}");
    assert!(
        log.contains("[resume] replayed"),
        "no replay banner:\n{log}"
    );
    assert!(
        log.contains("one-pass"),
        "resumed encrypted set did not map in-stream:\n{log}"
    );
    assert!(
        !log.contains("resumed job: the verified volumes"),
        "took the disk re-extract path:\n{log}"
    );
    let refetched = served.load(Ordering::Relaxed) - served_run1;
    assert!(
        refetched <= total_articles,
        "replay refetched more than the whole set ({refetched})"
    );
    assert_eq!(std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(), inner);
    for v in &vol_names {
        assert!(
            !fx.dir.join("out").join(v).exists(),
            "volume {v} left behind under resume replay:\n{log}"
        );
    }
    assert!(!fx.dir.join("out/.nzbfast.journal").exists());
}

/// The plan's resumed-7z-chase and resumed-zip-chase legs, and what
/// measuring them actually found: **a top-level chase journals nothing**,
/// so there is no restored span for the replay to feed and run 2 is a
/// FRESH run that maps in-stream because every fresh run does.
///
/// The mechanism is `chase.rs`'s own note on the header stash - "an
/// article whose stash stays in RAM just refetches on resume, which was
/// its record before too". A chased container's bytes live in the
/// frontier buffer until the decoder consumes them, so the articles park
/// as `Persist::Held` and never complete into an `R` record; probed at
/// 40% of a 3 MB zip and again at 40% of a 36 MiB one over a 64 MB
/// mem-limit, the journal carried nothing but its header line either
/// time. §94 A neither helps nor hurts this shape: it costs a full
/// refetch on resume, and that is a JOURNAL-coverage gap, not a mapping
/// one.
///
/// What this pins is the part that could regress: a resumed chase must
/// not fall into the materialize-and-unpack-from-disk path. Both
/// container formats, one body.
#[tokio::test(flavor = "multi_thread")]
async fn kill9_of_a_top_level_chase_has_nothing_to_replay_and_stays_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let movie = incompressible(3_000_000, 53);
    let sevenz = sevenz_container(&[("movie.mkv", &movie)]);
    let zip =
        nzbkit::zip::fixtures::zip_of(&[nzbkit::zip::fixtures::Spec::stored("movie.mkv", &movie)]);
    for (tag, container, badge) in [
        ("7z", ("release.7z", &sevenz), "7z · one-pass"),
        ("zip", ("release.zip", &zip), "zip · one-pass"),
    ] {
        let (arch_name, arch) = container;
        let mut fx = Fixture::new(&format!("resume-map-chase-{tag}"));
        fx.add_file(arch_name, arch, 25_000);
        assert!(fx.add_par2(20, &[arch_name], 25_000), "par2 create failed");
        let total_articles = fx.articles.len() as u64;
        let srv = MockServer::start(
            fx.articles.clone(),
            Chaos {
                delay_ms: 30,
                ..Chaos::default()
            },
        )
        .await;
        let served = srv.served.clone();
        let cfg = fx.write_config(&[&srv]);
        let nzb = fx.write_nzb();
        let out = fx.dir.join("out");

        // No journal predicate: there is nothing to wait for, which is
        // the point. The served fraction alone puts the kill mid-flight.
        kill9_run1(&cfg, &nzb, &out, &served, total_articles, (2, 5), None, &[]).await;

        // The finding, asserted rather than assumed: not one placement
        // record after 40% of a chased container was served.
        let journal = std::fs::read_to_string(out.join(".nzbfast.journal")).unwrap_or_default();
        let placements = journal
            .lines()
            .filter(|l| l.starts_with("R ") || l.starts_with("D "))
            .count();
        assert_eq!(
            placements, 0,
            "{tag}: a chase journaled placements - the resumed-chase leg is \
             reachable after all and wants a replay assertion:\n{journal}"
        );

        let (log, ok) = {
            let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
            tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
                .await
                .unwrap()
        };
        assert!(ok, "{tag}:\n{log}");
        assert!(
            log.contains(badge),
            "{tag}: the run after a killed chase did not map in-stream:\n{log}"
        );
        assert!(
            !log.contains("resumed job: the verified volumes"),
            "{tag}: took the disk re-extract path:\n{log}"
        );
        assert_eq!(
            std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(),
            movie,
            "{tag}: payload differs"
        );
        assert!(
            !fx.dir.join("out").join(arch_name).exists(),
            "{tag}: the container was left on disk:\n{log}"
        );
        assert!(!fx.dir.join("out/.nzbfast.journal").exists(), "{tag}");
    }
}

/// §94 A, the memory half: a resumed job must not HOLD what it replays.
///
/// `journal::restore` hands its seeds back from a `HashMap`, so their
/// order is arbitrary and differs every process run. Replayed in that
/// order, a volume whose predecessors have not been seen has no
/// resolved base offset and every byte of it parks in `holds` until
/// `reresolve` drains it - so the held PEAK ran to 100% of the replayed
/// bytes, which is what the held-bytes cap is judged against. Sorting
/// the replay into volume order (`get/rig.rs replay_order`) is the fix,
/// and this is its end-to-end pin: enough volumes that an unsorted
/// driver could not plausibly draw a sorted order, and an assertion on
/// the `holds peak` the run prints.
///
/// The nzbkit twin
/// (`a_replayed_store_set_places_only_in_volume_order_and_only_with_its_head`)
/// pins the extractor behaviour this rests on; the unit tests beside
/// `replay_order` pin the sort itself. This one pins that they are
/// actually wired together.
#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_run_places_its_replay_instead_of_holding_it() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("resume-map-holds");
    let inner = payload(8_000_000, 61);
    let n_vols = 8;
    let per = inner.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    let mut pos = 0usize;
    for i in 0..n_vols {
        let len = if i < n_vols - 1 {
            per
        } else {
            inner.len() - pos
        };
        let part = &inner[pos..pos + len];
        pos += len;
        let vol = fixtures::rar5_volume_n(
            &[("movie.mkv", inner.len() as u64, part, i > 0, i < n_vols - 1)],
            i as u64,
        );
        let name = format!("r.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    {
        let names: Vec<&str> = vol_names.iter().map(String::as_str).collect();
        assert!(fx.add_par2(20, &names, 25_000), "par2 create failed");
    }
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 10,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    kill9_run1(
        &cfg,
        &nzb,
        &out,
        &served,
        total_articles,
        (1, 2),
        Some("R "),
        &[],
    )
    .await;

    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "{log}");
    assert!(log.contains("one-pass"), "did not map in-stream:\n{log}");
    // "[resume] replayed N restored file(s) (X.Y MB) through the one-pass path"
    let replayed_mb: f64 = log
        .split("[resume] replayed ")
        .nth(1)
        .and_then(|t| t.split_once(" MB)"))
        .and_then(|(head, _)| head.rsplit_once('(').map(|(_, n)| n.to_string()))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no replay banner to read a byte count from:\n{log}"));
    assert!(replayed_mb > 1.0, "nothing meaningful replayed:\n{log}");
    // "mem: … · holds peak N MB · …"
    let holds_mb: f64 = log
        .split("holds peak ")
        .nth(1)
        .and_then(|t| t.split_once(" MB"))
        .and_then(|(n, _)| n.parse().ok())
        .unwrap_or_else(|| panic!("no holds peak in the mem line:\n{log}"));
    // Generous on purpose: the claim is "it places rather than holds",
    // not a byte-exact ceiling. Unsorted, this ran to ~100%.
    assert!(
        holds_mb < replayed_mb / 4.0,
        "the replay HELD {holds_mb} MB of the {replayed_mb} MB it replayed - \
         volume ordering is not reaching the replay:\n{log}"
    );
    assert_eq!(std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(), inner);
    for v in &vol_names {
        assert!(!fx.dir.join("out").join(v).exists(), "{v} left behind");
    }
    assert!(!fx.dir.join("out/.nzbfast.journal").exists());
}

/// Bug sweep 22 Aug 2026: the PLAIN twin of the test above. A plain
/// payload's offset-0 article is journaled as a placement (only a RAR
/// head journals as Held), so on resume it sits in `completed` and the
/// pool never refetches it - which means no fresh offset-0 write ever
/// triggers the replay for that slot. The seed then waited for the
/// network drain while every fresh article of the slot was HELD, up to
/// the unclassified spill. The seed carries its own sniff: it must be
/// fed up front, and the resumed run must hold nothing of note.
#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_plain_file_replays_before_its_fresh_articles_arrive() {
    let mut fx = Fixture::new("resume-map-plain");
    let inner = payload(8_000_000, 67);
    fx.add_file("movie.mkv", &inner, 25_000);
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 10,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    kill9_run1(
        &cfg,
        &nzb,
        &out,
        &served,
        total_articles,
        (1, 2),
        Some("R "),
        &[],
    )
    .await;

    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "{log}");
    let replayed_mb: f64 = log
        .split("[resume] replayed ")
        .nth(1)
        .and_then(|t| t.split_once(" MB)"))
        .and_then(|(head, _)| head.rsplit_once('(').map(|(_, n)| n.to_string()))
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no replay banner to read a byte count from:\n{log}"));
    assert!(replayed_mb > 1.0, "nothing meaningful replayed:\n{log}");
    let holds_mb: f64 = log
        .split("holds peak ")
        .nth(1)
        .and_then(|t| t.split_once(" MB"))
        .and_then(|(n, _)| n.parse().ok())
        .unwrap_or_else(|| panic!("no holds peak in the mem line:\n{log}"));
    assert!(
        holds_mb < 0.5,
        "the resumed plain slot HELD {holds_mb} MB - its own offset-0 seed \
         was not fed before the fresh articles arrived:\n{log}"
    );
    assert_eq!(std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(), inner);
    assert!(!fx.dir.join("out/.nzbfast.journal").exists());
}

/// The escape hatch. Every other leg here exercises the default, so
/// this is the one that would notice `NZBFAST_NO_RESUME_MAP` quietly
/// ceasing to work - and a kill switch nobody exercises is not a kill
/// switch. With it set, a resumed job must take exactly the path it
/// took before §94 A: volumes materialize, PAR2 verifies them on disk,
/// and the extraction happens afterwards from those files.
#[tokio::test(flavor = "multi_thread")]
async fn the_kill_switch_puts_a_resumed_job_back_on_the_disk_path() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("resume-killswitch");
    let inner = payload(3_000_000, 77);
    let n_vols = 4;
    let per = inner.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    let mut pos = 0usize;
    for i in 0..n_vols {
        let len = if i < n_vols - 1 {
            per
        } else {
            inner.len() - pos
        };
        let part = &inner[pos..pos + len];
        pos += len;
        let vol = fixtures::rar5_volume_n(
            &[("movie.mkv", inner.len() as u64, part, i > 0, i < n_vols - 1)],
            i as u64,
        );
        let name = format!("r.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    {
        let names: Vec<&str> = vol_names.iter().map(String::as_str).collect();
        assert!(fx.add_par2(20, &names, 25_000), "par2 create failed");
    }
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 10,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    kill9_run1(
        &cfg,
        &nzb,
        &out,
        &served,
        total_articles,
        (2, 5),
        Some("R "),
        &[],
    )
    .await;

    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || {
            run_get(&cfg, &nzb, &out, &[("NZBFAST_NO_RESUME_MAP", "1")])
        })
        .await
        .unwrap()
    };
    assert!(ok, "{log}");
    assert!(
        log.contains("article(s) already on disk"),
        "no resume banner:\n{log}"
    );
    assert!(
        !log.contains("[resume] replayed"),
        "the kill switch did not stop the replay:\n{log}"
    );
    // Byte-exact either way - the switch changes the route, not the
    // outcome.
    assert_eq!(std::fs::read(fx.dir.join("out/movie.mkv")).unwrap(), inner);
    assert!(!fx.dir.join("out/.nzbfast.journal").exists());
}

/// §159's side finding, filed as TODO 252 (22 Aug 2026): a retry over a
/// post whose volumes MATERIALIZED on disk must restore their bytes, not
/// refetch the post. The advG shape from torture round 4: a RAR5 store
/// set, one volume's offset-0 (header) article never posted, no
/// recovery data. Run 1 cannot map that volume, so at end of download
/// the whole group demotes ("incomplete mapping") and every volume is
/// reconstructed on disk from held spans and extracted bytes; the job
/// then fails and quarantines the four volumes as `*.nzbfast-partial`.
/// Run 2, against a server that now has the article, must pull ONLY
/// what run 1 could not vouch for. The oracle is the second server's
/// body log against run 1's journal, not wall time, so this is the
/// assertion the 13 Aug fix (37e629359: the `M` journal line) was
/// measured by - 34.6 MB -> 0 bodies on the pynntp rig - pinned against
/// the current tree. Measured 22 Aug 2026 on this rig: run 2 puts 1
/// body / 25,921 bytes on the wire for a 25,918-byte victim; the
/// control (same binary, the `M` lines stripped from the journal
/// between runs, which is bit-for-bit the pre-fix read path) refetches
/// 88 of 124 bodies, 2.28 MB of 3.1 - 87 of which the journal vouches
/// for, which is what the clause below counts (re-measured 22 Aug 2026
/// against this assertion).
///
/// The oracle is stated against the JOURNAL rather than against a byte
/// count, and that is history worth keeping: a byte bound on this shape
/// cost a flake on 22 Aug 2026. Run 1 used to leave 0 or 1 articles
/// unjournaled depending on a race, and which article it was varied (a
/// volume's header article, or a mid-volume payload one), so the second
/// body measured 51,844-51,848 wire bytes against a `2 * victim_wire`
/// ceiling of 51,836 - over by 8 to 12 bytes, every time it appeared.
/// Articles are not all one size, and a byte ceiling that means to
/// admit "one more article" cannot say so.
///
/// That race is CLOSED as of 23 Aug 2026 (TODO 252), so the count is
/// pinned exactly below. The demote reconstructs each volume with
/// `refeed_active` raised so a parked article's bytes surface as
/// identity placements and its `R` record completes - but the read-back
/// copies only ranges the destination has ALREADY written
/// (`extract::settle`), and an article whose write lands by another
/// route afterwards (the post-write re-route in `Extractor::write`, the
/// forward-delivery re-check) reached the volume unreported and stayed
/// parked for the life of the job. Measured on this box before the fix:
/// 2 of 24 runs standalone and 5 of 60 across four concurrent loops,
/// always exactly one extra article (a volume's header article in some
/// captures, a mid-volume payload one in others); after it, 0 of 192
/// the same two ways. `flush_pending_r` now completes such an article
/// off the MATERIALIZED volume's own coverage map
/// (`Extractor::materialized_span_on_disk`) - the same claim the slot's
/// `M` line makes - and refuses the moment a byte of the span is
/// unwritten, so a hole still refetches.
///
/// Both clauses stay: the journal oracle is the one that does not
/// depend on which article lost a race, and it is what would survive
/// this shape growing a new one. A parallel session reached the same
/// diagnosis from the byte side and landed 7e76d1af3 first, bounding
/// the count at 2 bodies and the bytes at victim + LARGEST article;
/// with the race closed, the exact id set below subsumes both.
#[tokio::test(flavor = "multi_thread")]
async fn a_retry_over_materialized_volumes_fetches_only_the_missing_article() {
    let mut fx = Fixture::new("resume-matvol");
    let inner = payload(3_000_000, 91);
    let n_vols = 4;
    let per = inner.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    let mut pos = 0usize;
    for i in 0..n_vols {
        let len = if i < n_vols - 1 {
            per
        } else {
            inner.len() - pos
        };
        let part = &inner[pos..pos + len];
        pos += len;
        let vol = fixtures::rar5_volume_n(
            &[("movie.mkv", inner.len() as u64, part, i > 0, i < n_vols - 1)],
            i as u64,
        );
        let name = format!("r.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    // Volume 2's first article carries its RAR headers: without it the
    // mapper can place nothing from that volume and the group demotes.
    let victim = fx
        .articles
        .keys()
        .find(|k| k.contains("r_part2_rar") && k.ends_with("-1@mock>"))
        .unwrap()
        .clone();
    let victim_wire = fx.articles[&victim].len() as u64;
    let total_wire: u64 = fx.articles.values().map(|a| a.len() as u64).sum();
    let total_articles = fx.articles.len();

    let srv1 = MockServer::start(
        fx.articles.clone(),
        Chaos {
            missing: [victim.clone()].into(),
            echo_missing_id: true,
            ..Chaos::default()
        },
    )
    .await;
    let cfg = fx.write_config(&[&srv1]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log1, ok1) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(
        !ok1,
        "run 1 must fail with the header article missing:\n{log1}"
    );
    assert!(
        log1.contains("direct extraction fell back") && log1.contains("volumes on disk"),
        "run 1 did not demote to materialized volumes:\n{log1}"
    );
    let journal = out.join(".nzbfast.journal");
    let journal_txt = std::fs::read_to_string(&journal).expect("journal survives a failed run");
    assert!(
        journal_txt.lines().any(|l| l.starts_with("M ")),
        "no M record after materialization:\n{journal_txt}"
    );
    for v in &vol_names {
        let q = out.join(format!("{v}{}", nzbkit::journal::PARTIAL_SUFFIX));
        assert!(
            q.exists(),
            "{v} not quarantined after the failed run:\n{log1}"
        );
    }
    let run1_bytes = srv1.bytes_out.load(Ordering::Relaxed);
    assert!(
        run1_bytes >= total_wire - victim_wire,
        "run 1 did not pull the servable articles ({run1_bytes} of {total_wire})"
    );
    drop(srv1);

    // Run 2: the article is on the wire now. Restore must claim every
    // byte the quarantined volumes hold, so the refetch is one article.
    let srv2 = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg2 = fx.write_config(&[&srv2]);
    let (log2, ok2) = {
        let (cfg, nzb, out) = (cfg2.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(ok2, "{log2}");
    assert!(
        log2.contains("[resume] restored"),
        "no restore banner:\n{log2}"
    );
    let run2_bytes = srv2.bytes_out.load(Ordering::Relaxed);
    let run2_bodies = srv2.served.load(Ordering::Relaxed);
    let run2_ids: Vec<String> = srv2.body_log.lock().unwrap().clone();
    // The oracle, stated against the journal rather than against a byte
    // count: run 2 may fetch the victim, and may fetch an article run 1
    // never journaled - but it must not fetch one the journal vouches
    // for. That is exactly what the `M` record buys, and it does not
    // depend on which articles won a race in run 1.
    //
    // The trailing token of an `R` line is its message-id (see the
    // grammar in `nzbkit::journal`).
    let journaled: std::collections::HashSet<&str> = journal_txt
        .lines()
        .filter(|l| l.starts_with("R "))
        .filter_map(|l| l.rsplit(' ').next())
        .collect();
    let refetched_journaled: Vec<&String> = run2_ids
        .iter()
        .filter(|id| journaled.contains(id.as_str()))
        .collect();
    assert!(
        refetched_journaled.is_empty(),
        "retry refetched {} article(s) the journal already vouched for: {refetched_journaled:?}\n\
         journal after run 1:\n{journal_txt}\n{log2}",
        refetched_journaled.len()
    );
    // ...and the journal has to vouch for the whole post but the one
    // article run 1 never saw, or the clause above is satisfied by a
    // journal that recorded nothing. Exact since TODO 252 closed the
    // parked-hold race: the victim is the only article run 1 could not
    // vouch for.
    let unjournaled = total_articles.saturating_sub(journaled.len());
    assert_eq!(
        unjournaled,
        1,
        "run 1 journaled {} of {total_articles} article(s) - only the victim may be missing:\n\
         {journal_txt}",
        journaled.len()
    );
    // The count, exactly: one body, and it is the victim. This subsumes
    // the byte belt it replaces (same ids, same bytes) and says the
    // thing the byte belt could only approximate - the pre-fix control
    // refetches 88 of 124 bodies, and the race that made this
    // nondeterministic put a second, varying article on the wire.
    assert_eq!(
        run2_ids,
        vec![victim.clone()],
        "retry refetched the materialized volumes: {run2_bodies} bodies / {run2_bytes} bytes \
         on the wire, against one {victim_wire}-byte victim:\n{log2}"
    );
    assert_eq!(std::fs::read(out.join("movie.mkv")).unwrap(), inner);
    for v in &vol_names {
        assert!(!out.join(v).exists(), "volume {v} left behind:\n{log2}");
        assert!(
            !out.join(format!("{v}{}", nzbkit::journal::PARTIAL_SUFFIX))
                .exists(),
            "quarantined {v} left behind:\n{log2}"
        );
    }
    assert!(!journal.exists());
}

/// The id on a placement line (`R <slot> <frags> <id>` / `D ...`): the
/// last whitespace-separated token.
fn placement_id(line: &str) -> Option<(char, &str)> {
    let letter = line.chars().next()?;
    if letter != 'R' && letter != 'D' {
        return None;
    }
    Some((letter, line.rsplit(' ').next()?))
}

/// TODO 158 item 2, the belt-and-braces half (23 Aug 2026): §94 A's
/// replay feeds run 1's restored spans back through the extractor and
/// must RE-JOURNAL each article under the route run 2 actually took -
/// before this the replay dropped the `Persist`, so a resumed run's
/// journal kept describing run 1's placements whatever run 2 did with
/// the bytes (the route seed is what makes that safe; this makes the
/// record true regardless). Three runs: run 1 is killed with real `R`
/// records; run 2 is killed once its journal tail carries run-2-written
/// `R` lines for ids run 1 wrote and the restore admitted - ids the
/// pool never refetches, so only the replay can have written them; run
/// 3's parse must admit those ids from run 2's records and finish
/// byte-identical to a cold run.
#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_run_rejournals_the_articles_it_replays() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("resume-rejournal");
    let inner = payload(3_000_000, 53);
    let n_vols = 4;
    let per = inner.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    let mut pos = 0usize;
    for i in 0..n_vols {
        let len = if i == 0 {
            per + 1
        } else if i < n_vols - 1 {
            per
        } else {
            inner.len() - pos
        };
        let part = &inner[pos..pos + len];
        pos += len;
        let vol = fixtures::rar5_volume_n(
            &[("movie.mkv", inner.len() as u64, part, i > 0, i < n_vols - 1)],
            i as u64,
        );
        let name = format!("r.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    {
        let names: Vec<&str> = vol_names.iter().map(String::as_str).collect();
        assert!(fx.add_par2(20, &names, 25_000), "par2 create failed");
    }
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 20,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let journal_path = out.join(".nzbfast.journal");

    // Run 1: killed with real placements journaled.
    kill9_run1(
        &cfg,
        &nzb,
        &out,
        &served,
        total_articles,
        (2, 5),
        Some("R "),
        &[],
    )
    .await;
    let run1 = std::fs::read_to_string(&journal_path).unwrap();
    let run1_lines = run1.lines().count();
    let run1_r: std::collections::HashSet<String> = run1
        .lines()
        .filter_map(placement_id)
        .filter(|(l, _)| *l == 'R')
        .map(|(_, id)| id.to_string())
        .collect();
    assert!(!run1_r.is_empty(), "run 1 journaled no R record:\n{run1}");
    // What run 2 will restore (and so never refetch): the same parse
    // and admission run 2's plan performs, over the run-1 journal.
    let nzb_bytes = std::fs::read(&nzb).unwrap();
    let restored: std::collections::HashSet<String> = {
        let (j, state) = nzbkit::journal::Journal::open(&out, &nzb_bytes).unwrap();
        let r = nzbkit::journal::restore_for(&out, &state, None, false);
        drop(j);
        r.ids.into_iter().filter(|id| run1_r.contains(id)).collect()
    };
    assert!(
        !restored.is_empty(),
        "nothing restorable after run 1:\n{run1}"
    );

    // Run 2: killed once its journal tail carries R lines for restored
    // ids - the replay re-recording them. The tail is everything past
    // run 1's last line; run 1 was SIGKILLed, so its last line may be
    // torn, and the tail start is taken by line count to stay clear
    // of that.
    let rerecorded: Vec<(char, String)> = {
        let (cfg, nzb, out, jp, restored) = (
            cfg.clone(),
            nzb.clone(),
            out.clone(),
            journal_path.clone(),
            restored.clone(),
        );
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--connections")
                .arg("2")
                .arg("--window")
                .arg("2")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let tail = |txt: &str| -> Vec<(char, String)> {
                txt.lines()
                    .skip(run1_lines)
                    .filter_map(placement_id)
                    .filter(|(_, id)| restored.contains(*id))
                    .map(|(l, id)| (l, id.to_string()))
                    .collect()
            };
            let mut seen = Vec::new();
            while std::time::Instant::now() < deadline {
                if let Ok(txt) = std::fs::read_to_string(&jp) {
                    seen = tail(&txt);
                    if seen.len() >= 3 {
                        break;
                    }
                }
                if !jp.exists() && seen.is_empty() {
                    // Journal removed = run 2 finished before the
                    // replay re-recorded anything visible to us.
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            child.kill().unwrap(); // SIGKILL
            let _ = child.wait();
            std::fs::read_to_string(&jp)
                .map(|t| tail(&t))
                .unwrap_or(seen)
        })
        .await
        .unwrap()
    };
    assert!(
        rerecorded.len() >= 3,
        "run 2 re-journaled {} of the {} replayed articles (want >= 3): {rerecorded:?}",
        rerecorded.len(),
        restored.len()
    );
    // A plain store set: every replayed article is wire-domain, so the
    // letter it re-records under is R. A D here would be the mixed
    // route the seed forbids.
    for (letter, id) in &rerecorded {
        assert_eq!(*letter, 'R', "replayed {id} re-recorded as {letter}");
    }
    // Run 3's parse, run here: the ids run 2 re-recorded are admitted
    // from the run-2 records (last R/D per id wins), with the article
    // ids carried into the seeds the next replay would feed.
    {
        let (j, state) = nzbkit::journal::Journal::open(&out, &nzb_bytes).unwrap();
        let r = nzbkit::journal::restore_for(&out, &state, None, false);
        drop(j);
        for (_, id) in &rerecorded {
            assert!(r.ids.contains(id), "run 3 does not admit re-recorded {id}");
            assert!(
                r.seeds
                    .iter()
                    .any(|s| s.article_ids.iter().any(|a| &**a == id.as_str())),
                "run 3's seeds carry no article id for {id}"
            );
        }
        for s in &r.seeds {
            assert_eq!(
                s.article_ids.len(),
                s.spans.len(),
                "article_ids not parallel"
            );
        }
    }

    // Run 3: finishes one-pass, output byte-identical to a cold run.
    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "{log}");
    assert!(
        log.contains("[resume] replayed"),
        "no replay banner:\n{log}"
    );
    assert_eq!(std::fs::read(out.join("movie.mkv")).unwrap(), inner);
    for v in &vol_names {
        assert!(!out.join(v).exists(), "volume {v} left behind:\n{log}");
    }
    assert!(!journal_path.exists());
    let cold = fx.dir.join("cold");
    let (log2, ok) = {
        let (cfg, nzb, cold) = (cfg.clone(), nzb.clone(), cold.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &cold, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "{log2}");
    assert_eq!(
        std::fs::read(cold.join("movie.mkv")).unwrap(),
        std::fs::read(out.join("movie.mkv")).unwrap(),
        "resumed output differs from a cold run's"
    );
}

/// The plaintext-once twin of the test above (TODO 158 item 2, the
/// `D` letter): an encrypted RAR5 store set with the password present
/// routes plaintext-once, so every article the replay feeds lands
/// through the crypto arm and must re-journal as `D`, not `R`. Same
/// three runs and the same proof. One trap shapes the kill condition:
/// the replay's `Persist::PlacedCrypto` is PARKED in `pending_d` until
/// `crypto_span_on_disk` says the seam slivers are down (usually one
/// neighbouring article later), so the record lands on the decode
/// consumer's flush pass, not when the replay banner prints - the
/// watcher waits for the tail LINES, never for the banner. The set
/// also needs the password on every run: with none it never routes at
/// all (the blocker demotes first) and there is no `D` to re-record.
#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_run_rejournals_the_plaintext_once_articles_it_replays() {
    let mut fx = Fixture::new("resume-rejournal-d");
    let inner = payload(6_000_000, 97);
    let enc = fixtures::encrypt_file("hunter2", &inner, 31);
    let cipher = enc.cipher.clone();
    let n_vols = 3;
    let per = cipher.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    for i in 0..n_vols {
        let end = if i == n_vols - 1 {
            cipher.len()
        } else {
            (i + 1) * per
        };
        let vol = fixtures::rar5_volume_enc(
            &[("movie.mkv", &enc, i * per..end, i > 0, i < n_vols - 1)],
            Some(i as u64),
        );
        let name = format!("d.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 20,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let journal_path = out.join(".nzbfast.journal");
    let pw = ["--password", "hunter2"];

    // Run 1: killed with real D placements journaled.
    kill9_run1(
        &cfg,
        &nzb,
        &out,
        &served,
        total_articles,
        (2, 5),
        Some("D "),
        &pw,
    )
    .await;
    let run1 = std::fs::read_to_string(&journal_path).unwrap();
    let run1_lines = run1.lines().count();
    let run1_d: std::collections::HashSet<String> = run1
        .lines()
        .filter_map(placement_id)
        .filter(|(l, _)| *l == 'D')
        .map(|(_, id)| id.to_string())
        .collect();
    assert!(!run1_d.is_empty(), "run 1 journaled no D record:\n{run1}");
    // What run 2 restores: the plan's own parse, with the password, over
    // the run-1 journal - D articles admit only against a proven check.
    let nzb_bytes = std::fs::read(&nzb).unwrap();
    let restored: std::collections::HashSet<String> = {
        let (j, state) = nzbkit::journal::Journal::open(&out, &nzb_bytes).unwrap();
        let r = nzbkit::journal::restore_for(&out, &state, Some("hunter2"), false);
        drop(j);
        r.ids.into_iter().filter(|id| run1_d.contains(id)).collect()
    };
    assert!(
        !restored.is_empty(),
        "nothing restorable after run 1:\n{run1}"
    );

    // Run 2: killed once its journal tail carries placement lines for
    // restored ids. Tail start by line count, as above: run 1's last
    // line may be torn.
    let rerecorded: Vec<(char, String)> = {
        let (cfg, nzb, out, jp, restored) = (
            cfg.clone(),
            nzb.clone(),
            out.clone(),
            journal_path.clone(),
            restored.clone(),
        );
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .env("NZBFAST_OPEN", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--password")
                .arg("hunter2")
                .arg("--connections")
                .arg("2")
                .arg("--window")
                .arg("2")
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let tail = |txt: &str| -> Vec<(char, String)> {
                txt.lines()
                    .skip(run1_lines)
                    .filter_map(placement_id)
                    .filter(|(_, id)| restored.contains(*id))
                    .map(|(l, id)| (l, id.to_string()))
                    .collect()
            };
            let mut seen = Vec::new();
            while std::time::Instant::now() < deadline {
                if let Ok(txt) = std::fs::read_to_string(&jp) {
                    seen = tail(&txt);
                    if seen.len() >= 3 {
                        break;
                    }
                }
                if !jp.exists() && seen.is_empty() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            child.kill().unwrap(); // SIGKILL
            let _ = child.wait();
            std::fs::read_to_string(&jp)
                .map(|t| tail(&t))
                .unwrap_or(seen)
        })
        .await
        .unwrap()
    };
    assert!(
        rerecorded.len() >= 3,
        "run 2 re-journaled {} of the {} replayed articles (want >= 3): {rerecorded:?}",
        rerecorded.len(),
        restored.len()
    );
    // Plaintext-once on every run: the letter is D. An R here would be
    // the mixed route the seed forbids (wire bytes over plaintext).
    for (letter, id) in &rerecorded {
        assert_eq!(*letter, 'D', "replayed {id} re-recorded as {letter}");
    }
    // Run 3's parse: the re-recorded ids admit from run 2's records.
    {
        let (j, state) = nzbkit::journal::Journal::open(&out, &nzb_bytes).unwrap();
        let r = nzbkit::journal::restore_for(&out, &state, Some("hunter2"), false);
        drop(j);
        for (_, id) in &rerecorded {
            assert!(r.ids.contains(id), "run 3 does not admit re-recorded {id}");
            assert!(
                r.seeds
                    .iter()
                    .any(|s| s.article_ids.iter().any(|a| &**a == id.as_str())),
                "run 3's seeds carry no article id for {id}"
            );
        }
    }

    // Run 3: finishes one-pass, output byte-identical to a cold run.
    let get_pw = |out: PathBuf| {
        let (cfg, nzb) = (cfg.clone(), nzb.clone());
        async move {
            tokio::task::spawn_blocking(move || {
                let o = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                    .env("NZBFAST_OPEN", "1")
                    .arg("--config")
                    .arg(&cfg)
                    .arg("get")
                    .arg(&nzb)
                    .arg("--out")
                    .arg(&out)
                    .arg("--password")
                    .arg("hunter2")
                    .arg("--connections")
                    .arg("4")
                    .arg("--window")
                    .arg("3")
                    .output()
                    .unwrap();
                (
                    format!(
                        "{}{}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    ),
                    o.status.success(),
                )
            })
            .await
            .unwrap()
        }
    };
    let (log, ok) = get_pw(out.clone()).await;
    assert!(ok, "{log}");
    assert!(
        log.contains("[resume] replayed"),
        "no replay banner:\n{log}"
    );
    assert!(
        log.contains("one-pass"),
        "resumed encrypted set did not map in-stream:\n{log}"
    );
    assert_eq!(std::fs::read(out.join("movie.mkv")).unwrap(), inner);
    for v in &vol_names {
        assert!(!out.join(v).exists(), "volume {v} left behind:\n{log}");
    }
    assert!(!journal_path.exists());
    let cold = fx.dir.join("cold");
    let (log2, ok) = get_pw(cold.clone()).await;
    assert!(ok, "{log2}");
    assert_eq!(
        std::fs::read(cold.join("movie.mkv")).unwrap(),
        std::fs::read(out.join("movie.mkv")).unwrap(),
        "resumed output differs from a cold run's"
    );
}

/// TODO 309(b), 28 Aug 2026: when something outside nzbfast shortens a
/// job's partial output between the pause and the unpause, the resume
/// SAYS the bytes went back on the wire.
///
/// The refusal itself has always been right and is pinned in
/// `nzbkit::journal` (`a source too short for its span must drop its
/// article`): an article whose recorded bytes are no longer there
/// refetches, which is the only safe answer. What was wrong is that it
/// was invisible. `[resume] restored N article(s)` reports what
/// SUCCEEDED, so a resume that silently put a gigabyte back on the wire
/// - on a metered line, the most expensive thing in this whole section
/// - read exactly like an ordinary resume with less on disk.
///
/// Two halves, and the second is the one that makes the first worth
/// having: the line fires AND the job still finishes byte-identical.
/// Dropping an article is a bandwidth cost, never a correctness one, and
/// a disclosure that arrived alongside a corrupted payload would be
/// telling the user about the wrong problem.
#[tokio::test(flavor = "multi_thread")]
async fn a_shortened_partial_output_says_its_articles_are_fetched_again() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("resume-shortened");
    let inner = payload(3_000_000, 61);
    let n_vols = 4;
    let per = inner.len() / n_vols;
    let mut vol_names: Vec<String> = Vec::new();
    let mut pos = 0usize;
    for i in 0..n_vols {
        let len = if i == 0 {
            per + 1
        } else if i < n_vols - 1 {
            per
        } else {
            inner.len() - pos
        };
        let part = &inner[pos..pos + len];
        pos += len;
        let vol = fixtures::rar5_volume_n(
            &[("movie.mkv", inner.len() as u64, part, i > 0, i < n_vols - 1)],
            i as u64,
        );
        let name = format!("r.part{}.rar", i + 1);
        fx.add_file(&name, &vol, 25_000);
        vol_names.push(name);
    }
    {
        let names: Vec<&str> = vol_names.iter().map(String::as_str).collect();
        assert!(fx.add_par2(20, &names, 25_000), "par2 create failed");
    }
    let total_articles = fx.articles.len() as u64;
    let srv = MockServer::start(
        fx.articles.clone(),
        Chaos {
            delay_ms: 10,
            ..Chaos::default()
        },
    )
    .await;
    let served = srv.served.clone();
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    // Run 1: kill with real placements recorded, exactly as the
    // one-pass resume legs above do.
    kill9_run1(
        &cfg,
        &nzb,
        &out,
        &served,
        total_articles,
        (2, 5),
        Some("R "),
        &[],
    )
    .await;

    // The user action this test is about, in the only form a test can
    // stage it: something outside nzbfast shortened the file the
    // placements point into. Half, so SOME articles survive - a run
    // where everything drops proves less, because the interesting
    // claim is that one bad article is not a failed resume.
    let payload_out = out.join("movie.mkv");
    let before = std::fs::metadata(&payload_out)
        .unwrap_or_else(|e| panic!("run 1 wrote no direct-extract output to truncate: {e}"))
        .len();
    assert!(before > 0, "run 1's output is empty - nothing to shorten");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&payload_out)
        .unwrap()
        .set_len(before / 2)
        .unwrap();

    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || run_get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    assert!(ok, "{log}");
    assert!(
        log.contains("their bytes are no longer there"),
        "the resume dropped articles for a shortened source and said nothing:\n{log}"
    );
    // The other cause must NOT be claimed: nothing here is encrypted,
    // and a resume that blamed the password would send the reader
    // hunting for a problem they do not have.
    assert!(
        !log.contains("without the archive password"),
        "a shortened file was reported as a password problem:\n{log}"
    );
    // And the point of the whole design: refetching is SAFE.
    assert_eq!(
        std::fs::read(&payload_out).unwrap(),
        inner,
        "a resume over a shortened output did not rebuild the payload"
    );
    assert!(!out.join(".nzbfast.journal").exists());
}
