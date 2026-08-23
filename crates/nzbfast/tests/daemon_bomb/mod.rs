//! TODO 222: a decompression-bomb refusal must reach the JOB's own
//! failure message, on every route into the unpack ladder.
//!
//! fab580ea made the ladder's two in-ladder refusals - the native
//! pass's `if bombed` and `preflight::unrar_would_bomb` - carry
//! `nzbkit::disk::BOMB_VERDICT` out to the job failure, so a user whose
//! disk is too small for the archive reads about the disk instead of
//! "encrypted or damaged?". It was proved by hand on 22 Aug 2026 with a
//! 2 GB-of-zeros RAR5 on a 1.5 GB APFS sparse image, and the record was
//! a memory note: nothing in CI watched it, and `ladder_tests.rs` can
//! only assert the message COMPOSITION, because both rungs measure the
//! real filesystem.
//!
//! `NZBFAST_TEST_FREE_BYTES` (see `serve::disk::free_bytes_override`) is
//! what closes that gap: the guard is a FREE-SPACE test, so reaching it
//! means being on a disk too small for the archive, and a chosen-size
//! filesystem needs root on Linux and `hdiutil` on macOS - portable to
//! neither CI container nor the Windows runners. Injecting the ANSWER is
//! portable everywhere and moves the very number the whole ladder reads.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.

use super::*;

/// What every daemon here is told the disk holds.
///
/// Under `rarfix::EXTRACT_RESERVE` (256 MiB) on purpose, which is the
/// tight-disk shape both rungs already document: `BombBudget::fixed`
/// saturates to a limit of 0, so `BombGuardWriter` aborts on the first
/// byte of any set at all, and `declared_exceeds_free` compares against
/// a post-reserve free of 0, so any declared size at all is refused.
/// The alternative - a budget the 64 KB fixture only just exceeds -
/// would pin the test to the fixture's exact byte count.
const FAKE_FREE: &str = "200000000";

/// The min-free floor these daemons run with: ARMED, and a quarter of
/// [`FAKE_FREE`], so the queue guard is live and standing down.
///
/// This is one of the three invariants of the 22 Aug repro and the one
/// that is easiest to lose: a bomb must not read as a full disk, or the
/// job is requeued to wait for space that would never be enough (see
/// `diag::bomb_failure`). Running with `--min-free 0` would disable the
/// guard by configuration and prove nothing about it.
const MIN_FREE: &str = "50000000";

/// A real WinRAR compressed volume (`m3_default.rar`, one 64 KB member),
/// posted under `name`.
///
/// Compressed rather than stored, for the reason `daemon_retry` uses the
/// same fixture: a store set extracts in-stream and never reaches the
/// disk ladder at all.
fn fixture_nzb(name: &str, tag: &str, articles: &mut HashMap<String, Vec<u8>>) -> String {
    let segs = make_file_articles(
        &format!("{name}.rar"),
        &compressed_fixture(),
        1_500,
        tag,
        articles,
    );
    nzb_xml(&[(format!("{name}.rar"), segs)])
}

/// The fixture bytes themselves.
fn compressed_fixture() -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar"),
    )
    .expect("m3_default.rar fixture")
}

/// An nzb over posted files, each already turned into articles.
fn nzb_xml(files: &[(String, Vec<(String, u64, u32)>)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in files {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    xml
}

/// Upload `xml` and return the job's terminal history row.
fn add_and_settle(port: u16, name: &str, xml: &str) -> serde_json::Value {
    let boundary = "----nzbfastbomb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{name}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let ctype = format!("multipart/form-data; boundary={boundary}");
    let r = http(
        port,
        "/api?mode=addfile&apikey=sekrit&output=json",
        Some((&ctype, &body)),
    );
    assert!(r.contains("nzo_ids"), "{r}");

    for _ in 0..300 {
        let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
        if let Some(slot) = serde_json::from_str::<serde_json::Value>(&h)
            .ok()
            .and_then(|v| v["history"]["slots"].as_array().cloned())
            .and_then(|s| {
                s.iter()
                    .find(|s| {
                        s["name"] == name && (s["status"] == "Failed" || s["status"] == "Completed")
                    })
                    .cloned()
            })
        {
            return slot;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    panic!(
        "{name} never settled; history: {}",
        http(port, "/api?mode=history&apikey=sekrit&output=json", None)
    )
}

/// The three invariants of the 22 Aug repro, read off the API the way a
/// user reads them: the job's own message names the DISK, the volumes
/// are all still there to retry with, and nothing was held for free
/// space.
fn assert_refused(port: u16, name: &str, slot: &serde_json::Value, log: &str) {
    let msg = slot["fail_message"].as_str().unwrap_or_default();
    assert_eq!(slot["status"], "Failed", "{slot}\n--- log ---\n{log}");
    assert!(
        nzbkit::disk::bomb_verdict(msg),
        "the job blamed something other than the disk: {msg:?}\n--- log ---\n{log}"
    );
    // The whole sentence `diag::bomb_failure` composes, not just the
    // matcher's tail: the KEEP half is the half a user acts on, and a
    // refusal that stopped saying it would still pass the matcher.
    // A PREFIX, because the failing tail appends its own clause and the
    // build stamp ("… - the verified files are still in the output
    // directory [nzbfast x.y.z]"); what fab580ea decides is the `why`
    // this sentence opens with, and that is what is pinned.
    assert!(
        msg.starts_with(
            "extraction exceeded available disk space (possible decompression bomb) \
             - the verified volumes were kept"
        ),
        "the ladder's own verdict did not reach the job: {msg:?}\n--- log ---\n{log}"
    );

    // Kept, so freeing space and retrying costs no refetch. A filled
    // disk leaves the user nothing to retry WITH, which is the whole
    // reason the ladder refuses rather than trying the next rung.
    let storage = PathBuf::from(slot["storage"].as_str().unwrap_or_default());
    assert!(
        storage.join(format!("{name}.rar")).exists(),
        "a refused unpack must keep its volumes: {storage:?}\n--- log ---\n{log}"
    );

    // …and the min-free hold - armed at MIN_FREE, and standing over a
    // disk this daemon believes holds FAKE_FREE - never took the job
    // back into the queue.
    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    let nzo = slot["nzo_id"].as_str().unwrap_or_default();
    assert!(
        !q.contains(nzo),
        "the job was requeued instead of failed: {q}\n--- log ---\n{log}"
    );
    assert!(
        !log.contains("downloads paused"),
        "a bomb armed the min-free hold:\n{log}"
    );

    // And the seam really was armed in the spawned process, rather than
    // this box happening to have 200 MB free.
    assert!(
        log.contains("NZBFAST_TEST_FREE_BYTES is set"),
        "the free-space seam never announced itself:\n{log}"
    );
}

/// Rung one: the disk native pass. `NZBFAST_NO_TOP_RAR_CHASE=1` demotes
/// the compressed set to the disk ladder, where `BombGuardWriter` aborts
/// the vendored engine on a budget of zero - and `try_unrar_spent_why`
/// then refuses to hand the same set to the unrar subprocess, which
/// carries no budget of any kind, and names the disk in the job failure.
///
/// The second leg is the control, and it is what makes the first one
/// mean anything: the SAME nzb, the SAME switches, the seam unset. It
/// completes and publishes its payload, so the refusal above is the
/// injected free space and not the fixture, the route, or the rig.
#[tokio::test(flavor = "multi_thread")]
async fn a_bomb_on_the_native_pass_reaches_the_job_message() {
    let dir = std::env::temp_dir().join(format!("nzbfast-bombnative-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let xml = fixture_nzb("Bomb.Native.2026", "bn", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // Demote the compressed set to the disk ladder…
            .env("NZBFAST_NO_TOP_RAR_CHASE", "1")
            // …onto a disk too small to unpack anything at all.
            .env("NZBFAST_TEST_FREE_BYTES", FAKE_FREE)
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--min-free")
            .arg(MIN_FREE)
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let logpath = d.log_path();

    let xml2 = xml.clone();
    tokio::task::spawn_blocking(move || {
        let slot = add_and_settle(port, "Bomb.Native.2026", &xml2);
        let log = std::fs::read_to_string(&logpath).unwrap_or_default();
        assert_refused(port, "Bomb.Native.2026", &slot, &log);
        // The route, so a refusal that moved rungs is not read as this
        // one: the native engine ran and was the thing that refused.
        assert!(
            log.contains("unpacking archive natively"),
            "the native pass never ran:\n{log}"
        );
        assert!(
            log.contains("not retrying with unrar, volumes kept"),
            "the ladder ran on past the bomb verdict:\n{log}"
        );
    })
    .await
    .unwrap();
    drop(d);

    // The control: same nzb, same switches, real free space.
    //
    // Its OWN directory, and so its own config, spool and history. A
    // second daemon over the first one's state restores the first one's
    // Failed row - same job name - and the row this leg reads back is
    // then the refusal it is supposed to be the control for.
    let ctl_dir = dir.join("ctl");
    std::fs::create_dir_all(&ctl_dir).unwrap();
    let ctl_cfg = ctl_dir.join("config.json");
    std::fs::copy(&cfg, &ctl_cfg).unwrap();
    let ctl = serve(&ctl_dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_NO_TOP_RAR_CHASE", "1")
            .arg("--config")
            .arg(&ctl_cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--min-free")
            .arg(MIN_FREE)
            .arg("--out")
            .arg(ctl_dir.join("complete"));
        c
    })
    .await;
    let cport = ctl.port;
    let ctl_log = ctl.log_path();
    let cdir = ctl_dir.join("complete");
    tokio::task::spawn_blocking(move || {
        let slot = add_and_settle(cport, "Bomb.Native.2026", &xml);
        let log = std::fs::read_to_string(&ctl_log).unwrap_or_default();
        assert_eq!(
            slot["status"], "Completed",
            "the fixture must unpack on a roomy disk, or the refusal \
             above proves nothing: {slot}\n--- log ---\n{log}"
        );
        assert!(
            !log.contains("decompression bomb"),
            "the guard refused a set that fits:\n{log}"
        );
        assert!(
            find_named(&cdir, "bigtext_64k.bin"),
            "unpacked payload missing:\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The route a user is actually on: no switches at all.
///
/// The top-level RAR chase runs, its in-stream extractor carries the
/// same budget (`vrig::instream_extract_budget`, floored at what the
/// post itself declared), and a compressed set that unpacks to more than
/// it posted trips it - which is the 22 Aug repro's own shape, where the
/// demote reason read `chase failed: {BOMB_VERDICT}`. That reason is
/// carried out by `diag::bomb_fallback` rather than by either in-ladder
/// refusal, so this leg pins the THIRD site of the one contract
/// `ladder_tests.rs` can only assert as composition: a demote whose
/// reason names the disk must not be handed to the disk ladder's
/// unbudgeted rungs, and the job must say so.
#[tokio::test(flavor = "multi_thread")]
async fn a_bomb_on_the_default_chase_route_reaches_the_job_message() {
    let dir = std::env::temp_dir().join(format!("nzbfast-bombchase-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let xml = fixture_nzb("Bomb.Chase.2026", "bc", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_TEST_FREE_BYTES", FAKE_FREE)
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--min-free")
            .arg(MIN_FREE)
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let logpath = d.log_path();

    tokio::task::spawn_blocking(move || {
        let slot = add_and_settle(port, "Bomb.Chase.2026", &xml);
        let log = std::fs::read_to_string(&logpath).unwrap_or_default();
        assert_refused(port, "Bomb.Chase.2026", &slot, &log);
        // The route: the in-stream chase is what refused, and its
        // reason reached the demote wearing the verdict.
        assert!(
            log.lines()
                .any(|l| l.contains("direct extraction fell back")
                    && l.contains("chase failed:")
                    && nzbkit::disk::bomb_verdict(l)),
            "the chase did not demote with the verdict:\n{log}"
        );
        assert!(
            log.contains(
                "unpacking this archive needs more space than the disk has \
                 (possible decompression bomb) - the verified volumes were kept"
            ),
            "`diag::bomb_fallback` never spoke:\n{log}"
        );
        // …and the ladder it foreclosed never ran. This is the half the
        // 22 Aug repro measured on a real disk: the third rung is an
        // unrar subprocess with no budget of any kind, and reaching it
        // fills the volume the guard refused to fill.
        assert!(
            !log.contains("unpacking archive natively"),
            "a demote carrying the verdict was handed to the disk ladder:\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rung two: the free-space preflight in front of the unrar spawn, on
/// the `prefer_external_unrar` route - where the budgeted native pass
/// never runs, so nothing else has measured this set against the disk
/// and the subprocess below will not, at any point, for any archive.
///
/// The refusal happens BEFORE the spawn, which is why this leg needs no
/// `unrar` on the box and runs everywhere (its sibling in
/// `daemon_unpackroute`, which proves the preflight lets a set that fits
/// through, has to skip without one). `NZBFAST_TEST_FORBID_UNRAR` is
/// deliberately NOT set: the canary sits one rung ABOVE the preflight
/// since 22 Aug 2026, so setting it would refuse first and hide the very
/// guard under test. The proof that no subprocess ran is the log - the
/// preflight says so on its way out, and none of the spawn's own
/// verdicts appear.
#[tokio::test(flavor = "multi_thread")]
async fn a_bomb_in_the_unrar_preflight_reaches_the_job_message() {
    let dir = std::env::temp_dir().join(format!("nzbfast-bombpre-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let xml = fixture_nzb("Bomb.Preflight.2026", "bp", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_TEST_FREE_BYTES", FAKE_FREE)
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--min-free")
            .arg(MIN_FREE)
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let logpath = d.log_path();

    tokio::task::spawn_blocking(move || {
        // Live over the API, no restart - the same way a user flips it,
        // and the same way `daemon_unpackroute` drives the route that
        // this one is the refusing half of.
        let r = http(
            port,
            "/api?mode=config&name=prefer_external_unrar&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(!r.contains("error"), "setting rejected: {r}");

        let slot = add_and_settle(port, "Bomb.Preflight.2026", &xml);
        let log = std::fs::read_to_string(&logpath).unwrap_or_default();
        assert_refused(port, "Bomb.Preflight.2026", &slot, &log);
        assert_preflight_refused_before_the_spawn(&log);
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same rung reached by the OTHER chooser: `NZBFAST_NO_NATIVE_UNRAR`,
/// the env override beside the setting in
/// `nzbkit::extract::prefer_external_unrar`.
///
/// Not a duplicate of the leg above, and not folded into it: the two
/// choosers are an `||` of two independent sources, one of which cannot
/// be set on a running daemon and so cannot share its process. A route
/// that reaches an unbudgeted subprocess is exactly the thing this guard
/// exists for, so both ways in are asserted rather than one plus a grep.
#[tokio::test(flavor = "multi_thread")]
async fn a_bomb_in_the_unrar_preflight_reaches_it_by_the_env_route_too() {
    let dir = std::env::temp_dir().join(format!("nzbfast-bombpreenv-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let mut articles = HashMap::new();
    let xml = fixture_nzb("Bomb.Preflight.Env.2026", "be", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_NO_NATIVE_UNRAR", "1")
            .env("NZBFAST_TEST_FREE_BYTES", FAKE_FREE)
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--min-free")
            .arg(MIN_FREE)
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let logpath = d.log_path();

    tokio::task::spawn_blocking(move || {
        let slot = add_and_settle(port, "Bomb.Preflight.Env.2026", &xml);
        let log = std::fs::read_to_string(&logpath).unwrap_or_default();
        assert_refused(port, "Bomb.Preflight.Env.2026", &slot, &log);
        assert_preflight_refused_before_the_spawn(&log);
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The fifth route of the 22 Aug repro, and the last one that reaches
/// the ladder from a distance of its own: `repair::reextract_dir_why`,
/// run after a PAR2 repair has just put the volumes right.
///
/// The sentence that arm falls back to blames the repair ("PAR2 repair
/// succeeded but re-extraction failed"), so this is the one route where
/// the verdict has to WIN a composition rather than simply travel:
/// `diag::unpack_failure` prefers the ladder's own reason, and a user
/// who repaired a perfectly good archive on a disk too small to unpack
/// it must read about the disk.
///
/// `NZBFAST_NO_NATIVE_REPAIR=1` is load-bearing rather than incidental.
/// The native mapped repair rebuilds damaged blocks straight into the
/// live output and never puts the volumes on disk, so the re-extract it
/// runs afterwards finds no archive and succeeds as a no-op - a real
/// route, but not this one. Materializing for repair is what leaves the
/// volumes for the re-extract to work on, which is the shape the 22 Aug
/// repro was in.
///
/// Needs the external `par2` binary - to build the recovery set here,
/// and to do the repair itself on that path - so it skips where there
/// is none - it is not on every box. `NZBFAST_REQUIRE_PAR2` makes that skip
/// a failure on the runners that install one, for the reason
/// `have_par2` states: a silent skip reads exactly like a green run.
#[tokio::test(flavor = "multi_thread")]
async fn a_bomb_after_a_par2_repair_reaches_the_job_message() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-bombrepair-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // The compressed set again, with recovery blocks over it and one
    // article that always comes back corrupt - so every refetch fails
    // its yEnc CRC, the damage survives to the PAR2 stage, and the
    // repair is what puts the volume right before the re-extract.
    //
    // The chase is left ON. It bombs and demotes, which materializes
    // the volume on disk - and a set that was rar-chased is claimed for
    // the post-repair re-extract precisely because its demote reason is
    // excluded from the unrar ladder on the promise that this path
    // re-extracts what it materialized. That is the ordering the 22 Aug
    // repro ran into and the reason this route exists at all.
    let name = "Bomb.Repair.2026";
    let build = dir.join("fixture");
    std::fs::create_dir_all(&build).unwrap();
    std::fs::write(build.join(format!("{name}.rar")), compressed_fixture()).unwrap();
    let st = Command::new("par2")
        .args(["create", "-r40", "-q", "testset", &format!("{name}.rar")])
        .current_dir(&build)
        .status()
        .expect("par2 create");
    assert!(st.success(), "par2 create failed: {st}");

    let mut articles = HashMap::new();
    let mut files: Vec<(String, Vec<(String, u64, u32)>)> = Vec::new();
    let segs = make_file_articles(
        &format!("{name}.rar"),
        &compressed_fixture(),
        1_500,
        "br",
        &mut articles,
    );
    assert!(
        segs.len() > 3,
        "want a multi-article set, got {}",
        segs.len()
    );
    // A middle article: the head carries the RAR headers, and holing
    // those is a different failure from a holed payload block.
    let corrupt_id = segs[segs.len() / 2].0.clone();
    files.push((format!("{name}.rar"), segs));
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&build)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "par2"))
        .collect();
    par2s.sort();
    assert!(!par2s.is_empty(), "par2 create produced no recovery files");
    for (i, p) in par2s.iter().enumerate() {
        let pname = p.file_name().unwrap().to_string_lossy().to_string();
        let data = std::fs::read(p).unwrap();
        let segs = make_file_articles(&pname, &data, 4_000, &format!("bp{i}"), &mut articles);
        files.push((pname, segs));
    }
    let xml = nzb_xml(&files);

    let chaos = Chaos {
        corrupt: [format!("<{corrupt_id}>")].into_iter().collect(),
        ..Chaos::default()
    };
    let srv = MockServer::start(articles, chaos).await;

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_NO_NATIVE_REPAIR", "1")
            .env("NZBFAST_TEST_FREE_BYTES", FAKE_FREE)
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--min-free")
            .arg(MIN_FREE)
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let logpath = d.log_path();

    tokio::task::spawn_blocking(move || {
        let slot = add_and_settle(port, name, &xml);
        let log = std::fs::read_to_string(&logpath).unwrap_or_default();
        assert_refused(port, name, &slot, &log);
        // The premise: this really is the post-repair re-extract, not a
        // job that failed before PAR2 ever ran and not the plain disk
        // ladder with a repair in front of it.
        assert!(
            log.contains("repair complete"),
            "the repair never finished, so this is not the re-extract route:\n{log}"
        );
        assert!(
            log.contains("re-extracting 1 repaired volume(s)"),
            "`reextract_dir_why` never ran:\n{log}"
        );
        // And the composition: the ladder's reason beat the sentence
        // this arm would otherwise have blamed the repair with.
        assert!(
            !slot["fail_message"]
                .as_str()
                .unwrap_or_default()
                .contains("re-extraction failed"),
            "the repair took the blame for the disk: {slot}\n--- log ---\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Is the external `par2` binary runnable here?
///
/// A copy of `e2e.rs`'s, `NZBFAST_REQUIRE_PAR2` assertion included: the
/// daemon target has none of its own, and the callers of this SKIP,
/// which is the shape that reads as a green run with silently reduced
/// coverage.
fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run - the PAR2 test \
         here would have skipped and the run would have looked green"
    );
    ok
}

/// What the log has to show on either preflight leg: the guard spoke,
/// the native engine was not what refused, and no subprocess ever ran.
///
/// The absence list is every verdict the spawn arm can print, the
/// not-installed one included - on a box with no `unrar` that sentence
/// IS the proof of a spawn attempt, and it is the sentence a preflight
/// that stopped refusing would leave behind here.
fn assert_preflight_refused_before_the_spawn(log: &str) {
    assert!(
        log.contains("so unrar was not run and the volumes were kept"),
        "the preflight never refused:\n{log}"
    );
    assert!(
        !log.contains("unpacking archive natively"),
        "the native engine ran, so this is not the preflight's refusal:\n{log}"
    );
    for spoke in [
        "unrar complete",
        "unrar exited",
        "unrar is not installed",
        "unrar not runnable",
    ] {
        assert!(
            !log.contains(spoke),
            "the subprocess was reached despite the preflight ({spoke:?}):\n{log}"
        );
    }
}

/// Is `name` anywhere under `dir`?
fn find_named(dir: &Path, name: &str) -> bool {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| {
            let p = e.path();
            if p.is_dir() {
                find_named(&p, name)
            } else {
                p.file_name().is_some_and(|n| n == name)
            }
        })
}
