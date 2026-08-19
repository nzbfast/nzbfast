//! §129 4a: the pre-queue hook against a real daemon - rewrite,
//! reject-to-history and the fail-open timeout. A sibling-dir child of
//! daemon.rs (the daemon_chip6 pattern) so the parent stays inside its
//! size-gate baseline; harness via `super::*`.
//!
//! Unix-only: these hooks are shell scripts, and the Windows leg of the
//! script contract is already exercised by the post-proc `.cmd` test.

#![cfg(unix)]

use super::*;

fn hook_nzb(name: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
         <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/1)\">\n    \
         <groups><group>alt.binaries.hook</group></groups>\n    <segments>\n      \
         <segment bytes=\"5000\" number=\"1\">{name}-seg@test</segment>\n    \
         </segments>\n  </file>\n</nzb>\n"
    )
}

fn write_hook(dir: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let hook = dir.join("prequeue.sh");
    std::fs::write(&hook, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    hook
}

fn upload_named(port: u16, name: &str, xml: &str, query_extra: &str) -> String {
    let boundary = "----prequeue";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"nzbfile\"; \
             filename=\"{name}.nzb\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http(
        port,
        &format!("/api?mode=addfile&apikey=sekrit&output=json{query_extra}"),
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    )
}

async fn hook_daemon(dir: &Path) -> Daemon {
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    serve(dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await
}

fn set_cfg(port: u16, name: &str, value: &str) {
    let value: String = value
        .bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~/".contains(&b) {
                vec![b as char]
            } else {
                format!("%{b:02X}").chars().collect()
            }
        })
        .collect();
    let r = http(
        port,
        &format!("/api?mode=config&apikey=sekrit&output=json&name={name}&value={value}"),
        None,
    );
    assert!(r.contains("\"status\":true"), "set {name}: {r}");
}

/// Accept with a full rewrite: rename, pp, recategorize, reprioritize -
/// and the SAB argument contract on the way in.
#[tokio::test(flavor = "multi_thread")]
async fn pre_queue_hook_rewrites_the_add() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prequeue-rw-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let hook = write_hook(
        &dir,
        // Record the contract, then answer: accept, rename, pp 2,
        // category tv, keep script, priority 1.
        "printf 'args:%s|%s|%s|%s|%s|%s\\nenv:%s|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" \"$5\" \"$6\" \
         \"$7\" \"$SAB_FILENAME\" \"$SAB_PP\" \"$SAB_CAT\" \"$SAB_GROUPS\" \
         > \"$(dirname \"$0\")/prequeue.out\"\n\
         printf '1\\nRenamed.Job\\n2\\ntv\\n\\n1\\n'\n",
    );
    let d = hook_daemon(&dir).await;
    let port = d.port;
    // Paused, so the runner never picks the job and the queue row is
    // stable to assert on.
    http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
    set_cfg(port, "pre_queue_script", &hook.to_string_lossy());

    let r = upload_named(
        port,
        "Original.Name",
        &hook_nzb("Original.Name"),
        "&cat=movies&pp=3",
    );
    assert!(r.contains("\"status\":true"), "{r}");

    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    let v: serde_json::Value = serde_json::from_str(&q).unwrap();
    let slot = &v["queue"]["slots"][0];
    assert_eq!(slot["filename"], "Renamed.Job", "{slot}");
    assert_eq!(slot["cat"], "tv", "{slot}");
    // SAB priority 1 = High.
    assert_eq!(slot["priority"], "High", "{slot}");
    // The add asked for pp=3, the hook answered 2, and the hook's
    // answer outranks the request (record_add_params fills, never
    // clobbers).
    assert_eq!(slot["unpackopts"], "2", "{slot}");

    // The contract the script saw: name, the pp the add requested
    // (L6 - this used to be ""), category, priority (-100 = default
    // at hook time), size, first group, and the SAB_* env.
    let out = std::fs::read_to_string(dir.join("prequeue.out")).expect("hook ran");
    assert!(
        out.contains("args:Original.Name|3|movies|-100|5000|alt.binaries.hook"),
        "{out}"
    );
    assert!(
        out.contains("env:Original.Name.nzb|3|movies|alt.binaries.hook"),
        "{out}"
    );
}

/// Reject: the job files to history as Failed with the reason, the
/// spool .nzb survives, and a retry (which deliberately does NOT re-run
/// the hook) brings it back to the queue.
#[tokio::test(flavor = "multi_thread")]
async fn pre_queue_hook_rejects_to_history_and_retry_escapes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prequeue-rj-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let hook = write_hook(&dir, "printf '0\\n'\n");
    let d = hook_daemon(&dir).await;
    let port = d.port;
    http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
    set_cfg(port, "pre_queue_script", &hook.to_string_lossy());

    let r = upload_named(port, "Unwanted.Post", &hook_nzb("Unwanted.Post"), "");
    assert!(r.contains("\"status\":true"), "{r}");
    let v: serde_json::Value = serde_json::from_str(&r).unwrap();
    let nzo = v["nzo_ids"][0].as_str().expect("nzo id").to_string();

    // Never queued; filed to history as Failed with the reason.
    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    let qv: serde_json::Value = serde_json::from_str(&q).unwrap();
    assert_eq!(qv["queue"]["noofslots"], 0, "{q}");
    let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
    let hv: serde_json::Value = serde_json::from_str(&h).unwrap();
    let slot = &hv["history"]["slots"][0];
    assert_eq!(slot["status"], "Failed", "{slot}");
    assert!(
        slot["fail_message"]
            .as_str()
            .is_some_and(|m| m.contains("pre-queue")),
        "the reason names the hook: {slot}"
    );

    // The escape hatch: retry re-queues it (and does not consult the
    // hook again - this hook rejects everything, so being back in the
    // queue IS the proof).
    let rr = http(
        port,
        &format!("/api?mode=retry&apikey=sekrit&output=json&value={nzo}"),
        None,
    );
    assert!(rr.contains("\"status\":true"), "{rr}");
    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    let qv: serde_json::Value = serde_json::from_str(&q).unwrap();
    assert_eq!(qv["queue"]["noofslots"], 1, "retry re-queued: {q}");
}

/// A hook that outlives its budget is killed and the add proceeds
/// untouched - fail-open, with the job's original name.
#[tokio::test(flavor = "multi_thread")]
async fn pre_queue_hook_timeout_fails_open() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prequeue-to-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let hook = write_hook(&dir, "sleep 30\nprintf '0\\n'\n");
    let d = hook_daemon(&dir).await;
    let port = d.port;
    http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
    set_cfg(port, "pre_queue_script", &hook.to_string_lossy());
    set_cfg(port, "pre_queue_timeout_secs", "1");

    let r = upload_named(port, "Patient.Post", &hook_nzb("Patient.Post"), "");
    assert!(r.contains("\"status\":true"), "{r}");
    let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
    let v: serde_json::Value = serde_json::from_str(&q).unwrap();
    assert_eq!(v["queue"]["noofslots"], 1, "{q}");
    assert_eq!(
        v["queue"]["slots"][0]["filename"], "Patient.Post",
        "accepted untouched: {q}"
    );
}

/// The two knobs survive a restart - the third of the "three places"
/// (write arm, table row, restore path) the settings doctrine demands,
/// and the one that fails silently. String + number, so the boolean
/// sweep in settings_catalogue cannot cover them.
#[tokio::test(flavor = "multi_thread")]
async fn pre_queue_settings_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prequeue-rs-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let hook = write_hook(&dir, "printf '1\\n'\n");
    {
        let d = hook_daemon(&dir).await;
        set_cfg(d.port, "pre_queue_script", &hook.to_string_lossy());
        set_cfg(d.port, "pre_queue_timeout_secs", "7");
    }
    let d = hook_daemon(&dir).await;
    let c = http(
        d.port,
        "/api?mode=get_config&apikey=sekrit&output=json",
        None,
    );
    let v: serde_json::Value = serde_json::from_str(&c).unwrap();
    let m = &v["config"]["nzbfast"];
    assert_eq!(
        m["pre_queue_script"].as_str(),
        Some(&*hook.to_string_lossy()),
        "{m}"
    );
    assert_eq!(m["pre_queue_timeout_secs"], 7, "{m}");
}

/// The post-processing script has FINISHED by the time the job appears
/// in history as Completed.
///
/// That word is a contract, not a status line: Sonarr's SABnzbd client
/// imports a release the moment history reports it, and the pp-script
/// is the step of post-processing most likely to still be moving the
/// payload - a sorter, a renamer, a library filer. The hook used to be
/// dispatched to the blocking pool while `park` filed the row anyway,
/// with nothing ordering the two: on this machine the script landed
/// 105-313 ms after the row, which is the *arr importing a directory
/// that is still being rewritten, and on a loaded box the gap has no
/// ceiling at all.
///
/// It is also where `sonarr_style_cycle`'s "hook never ran"
/// intermittent came from - the suite asserted this contract and the
/// product met it by luck. Pinned with a script that takes two seconds
/// so the race is not a race: pre-fix this reads an absent hook file at
/// the first Completed, every time.
#[tokio::test(flavor = "multi_thread")]
async fn the_post_processing_script_finishes_before_history_says_completed() {
    let dir = std::env::temp_dir().join(format!("nzbfast-postjob-order-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(120_000, 7);
    let mut articles = HashMap::new();
    let segs = make_file_articles("episode.bin", &data, 40_000, "pj", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;episode.bin&quot; yEnc (1/4)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    // Two seconds of work, then the marker. The sleep is the whole
    // instrument: it turns "did park wait for the script" into a
    // question a single poll can answer.
    let hook = {
        use std::os::unix::fs::PermissionsExt;
        let hook = dir.join("postjob.sh");
        std::fs::write(
            &hook,
            "#!/bin/sh\nsleep 2\nprintf 'ran:%s\\n' \"$SAB_FINAL_NAME\" \
             > \"$(dirname \"$0\")/postjob.out\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        hook
    };

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
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--script")
            .arg(&hook)
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let marker = dir.join("postjob.out");
    tokio::task::spawn_blocking(move || {
        let r = upload_named(port, "episode", &xml, "&cat=tv");
        assert!(r.contains("\"status\":true"), "{r}");

        // Polled tightly, because the claim is about the FIRST sighting
        // of the word: a lazy poll would let the script finish inside
        // the gap and report green against the very code this pins.
        let mut seen = None;
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                seen = Some(std::fs::read_to_string(&marker).unwrap_or_default());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let at_completed = seen.expect("the job never reached history as Completed");
        assert!(
            at_completed.contains("ran:episode"),
            "history said Completed while the post-processing script was still running \
             (marker at that moment: {at_completed:?}) - a SAB client imports on that word, \
             and the script is what moves the payload"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Build the `<nzb>` for one multi-segment file.
fn seg_nzb(name: &str, segs: &[(String, u64, u32)], date: i64) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"{date}\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    );
    for (id, bytes, num) in segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

/// A hook that takes two seconds and then leaves a marker. The sleep is
/// the instrument: it turns "did park wait for the script" into a
/// question a single read can answer.
fn slow_marker_hook(dir: &Path, stem: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let hook = dir.join(format!("{stem}.sh"));
    let marker = dir.join(format!("{stem}.out"));
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nsleep 2\nprintf 'ran:%s\\n' \"$SAB_FINAL_NAME\" > \"{}\"\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    (hook, marker)
}

/// Poll history tightly for `status` and read `marker` at the FIRST
/// sighting of it.
///
/// Tightly on purpose: the claim is about the first moment the word is
/// visible, and a lazy poll would let a two-second script finish inside
/// the gap and report green against the very code this pins.
fn marker_at_first(port: u16, status: &str, marker: &Path) -> String {
    for _ in 0..600 {
        let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
        if h.contains(&format!("\"{status}\"")) {
            return std::fs::read_to_string(marker).unwrap_or_default();
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("the job never reached history as {status}");
}

/// The same contract as
/// [`the_post_processing_script_finishes_before_history_says_completed`],
/// on the completion that never downloads: the M14i metadata-only
/// library pick.
///
/// It is a separate case because it is a separate code path with a
/// separate answer. That one is the post-processing lane's own tail,
/// which can simply await the script; this one is decided on the queue
/// RUNNER's loop, where awaiting a user script would stall the picker
/// for every other job in the queue - which is exactly why the arm was
/// left unordered when the lane tail was fixed. The runner hands the
/// tail to the lane instead (`PostprocLane::submit_hooks_only`), so the
/// wait is paid in post-processing capacity, where it belongs.
///
/// The contract is the same because the word is the same: this arm
/// reaches `Completed` and writes a `.strm` pointer, Sonarr imports on
/// that word, and the pp-script is what may still be moving the file it
/// names.
///
/// The zero-bodies assertion is load-bearing, not colour: it is what
/// proves the job went through the metadata-only arm at all rather than
/// down the ordinary pipeline, whose tail was already ordered and would
/// pass this test for the wrong reason.
#[tokio::test(flavor = "multi_thread")]
async fn a_metadata_only_job_finishes_its_script_before_history_says_completed() {
    let dir = std::env::temp_dir().join(format!("nzbfast-libpostjob-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(120_000, 9);
    let mut articles = HashMap::new();
    let segs = make_file_articles("episode.bin", &data, 40_000, "mo", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let xml = seg_nzb("episode.bin", &segs, 0);

    let (hook, marker) = slow_marker_hook(&dir, "metaonly");
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
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--script")
            .arg(&hook)
            .arg("--library-cats")
            .arg("library")
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;
    let served = srv.served.clone();

    tokio::task::spawn_blocking(move || {
        let r = upload_named(port, "episode", &xml, "&cat=library");
        assert!(r.contains("\"status\":true"), "{r}");

        let at_completed = marker_at_first(port, "Completed", &marker);
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "this job downloaded article bodies, so it did not take the \
             metadata-only arm - the test is not pinning what it claims to"
        );
        assert!(
            at_completed.starts_with("ran:"),
            "history said Completed while the post-processing script was still running \
             (marker at that moment: {at_completed:?}) - a SAB client imports on that word, \
             and the script is what moves what it points at"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same ordering on the word `Failed`, through the second of the
/// three runner arms: the §138 give-up on a post no configured server
/// can supply.
///
/// `Failed` is acted on as surely as `Completed` is - an *arr blocklists
/// the release and searches again - and a user's failure script runs
/// here exactly as it does on a download that failed the long way
/// round, where the lane has ordered it since 16 Aug. Pinning it stops
/// the three arms drifting back apart: they share one call, and this is
/// the leg that would notice if the failing half of it were quietly
/// dropped. (The third arm, the opt-in pre-flight Impossible verdict,
/// is the same statement on the same line and is left to these two.)
///
/// The queue is paused while the health verdict is gathered, because
/// the runner is the seam that decides: unpaused, this post would be
/// picked and fail the ordinary way, down the already-ordered lane tail,
/// and the test would pass without touching the arm it names.
#[tokio::test(flavor = "multi_thread")]
async fn a_health_giveup_finishes_its_script_before_history_says_failed() {
    let dir = std::env::temp_dir().join(format!("nzbfast-giveuppostjob-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(60_000, 13);
    let mut articles = HashMap::new();
    let segs = make_file_articles("dead.bin", &data, 20_000, "gv", &mut articles);
    // Gone everywhere, to STAT and BODY alike: one server, and it says
    // so, which is what makes the fleet unanimous.
    let missing: std::collections::HashSet<String> =
        segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let srv = MockServer::start(
        articles,
        Chaos {
            missing,
            ..Default::default()
        },
    )
    .await;
    // 30 days old: past GONE_MIN_AGE_DAYS, so propagation is no longer
    // an explanation and the verdict may reach red at all.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let xml = seg_nzb("dead.bin", &segs, now - 30 * 86_400);

    let (hook, marker) = slow_marker_hook(&dir, "giveup");
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
            .env("NZBFAST_HEALTH_TICK_SECS", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--script")
            .arg(&hook)
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        set_cfg(port, "post_health_fail", "1");
        http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        let r = upload_named(port, "dead", &xml, "");
        assert!(r.contains("\"status\":true"), "{r}");

        // Wait for the evidence the give-up is decided from: every
        // configured server asked, and every one of them answered.
        let mut scored = false;
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&q).unwrap_or_default();
            let slot = v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.first().cloned())
                .unwrap_or_default();
            if slot["health"]["bucket"] == "red"
                && slot["health"]["answered"] == 1
                && slot["health"]["servers"] == 1
            {
                scored = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            scored,
            "the post never scored red with every server agreeing"
        );

        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        let at_failed = marker_at_first(port, "Failed", &marker);
        assert!(
            at_failed.starts_with("ran:"),
            "history said Failed while the post-processing script was still running \
             (marker at that moment: {at_failed:?}) - an *arr blocklists and re-searches \
             on that word"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 192: an ORDERED CHAIN of NZBGet-contract scripts, and the env
/// each link actually saw.
///
/// The point of the test is the SHAPE, not the plumbing. A chain that
/// runs both scripts in the right order but spells `NZBPP_SCRIPTSTATUS`
/// differently, or omits `NZBOP_SCRIPTDIR`, is broken for the whole
/// forum catalogue and every assertion about files on disk stays green:
/// `if 'NZBOP_SCRIPTDIR' not in os.environ: sys.exit(...)` is the first
/// line of most NZBGet extensions, so a missing variable makes them all
/// decline silently. So each link writes down exactly what it was given
/// and this asserts on that.
///
/// Three properties beyond the names:
///
///  - Link 1 exits 93 (POSTPROCESS_SUCCESS) and link 2 sees
///    `NZBPP_SCRIPTSTATUS=SUCCESS`, where link 1 saw `NONE`. That is the
///    running aggregate, and it is what lets a notifier placed last say
///    "the sorter before me failed".
///  - Link 1's `[NZB] FINALDIR=` and `[NZB] NZBPR_stage=` reach link 2
///    as `NZBPP_FINALDIR` and `NZBPR_stage`. Without that a chain is
///    just two independent scripts, and the second one notifies about
///    the directory the first one moved the payload OUT of.
///  - Link 2 exits 95 (POSTPROCESS_NONE) and the chain still reports
///    SUCCESS: NONE never demotes, which is NZBGet's own fold and not
///    "the last one wins".
#[tokio::test(flavor = "multi_thread")]
async fn an_ordered_script_chain_runs_in_order_with_the_nzbget_contract() {
    let dir = std::env::temp_dir().join(format!("nzbfast-ppchain-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(120_000, 11);
    let mut articles = HashMap::new();
    let segs = make_file_articles("episode.bin", &data, 40_000, "ch", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;episode.bin&quot; yEnc (1/4)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    // Each link dumps the variables it was handed, one per line, then
    // appends its own name to `order.out` so the ORDER is asserted from
    // the runs themselves rather than from timestamps.
    let link = |name: &str, extra: &str, code: &str| -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(format!("{name}.sh"));
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\nd=$(dirname \"$0\")\n\
                 {{ echo \"SCRIPTSTATUS=$NZBPP_SCRIPTSTATUS\"\n\
                 echo \"SCRIPTDIR=$NZBOP_SCRIPTDIR\"\n\
                 echo \"DESTDIR=$NZBOP_DESTDIR\"\n\
                 echo \"CONTROLPORT=$NZBOP_CONTROLPORT\"\n\
                 echo \"CONTROLIP=$NZBOP_CONTROLIP\"\n\
                 echo \"OPVERSION=$NZBOP_VERSION\"\n\
                 echo \"OPVERSION_CAMEL=$NZBOP_Version\"\n\
                 echo \"TOTALSTATUS=$NZBPP_TOTALSTATUS\"\n\
                 echo \"HEALTH=$NZBPP_HEALTH\"\n\
                 echo \"NZBID=$NZBPP_NZBID\"\n\
                 echo \"FINALDIR=$NZBPP_FINALDIR\"\n\
                 echo \"STAGE=$NZBPR_stage\"\n\
                 echo \"STAGE_UPPER=$NZBPR_STAGE\"; }} > \"$d/{name}.out\"\n\
                 echo \"{name}\" >> \"$d/order.out\"\n\
                 {extra}\n\
                 exit {code}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    };
    let sorted = dir.join("sorted");
    // Link 1 answers with NZBGet's own success code, and speaks the
    // command channel on its LAST lines - which is where a real sorter
    // says them, and why the daemon sieves stdout rather than keeping a
    // head of it.
    let first = link(
        "first",
        &format!(
            "echo 'ordinary progress chatter'\n\
             echo '[NZB] NZBPR_stage=one'\n\
             echo '[NZB] FINALDIR={}'",
            sorted.display()
        ),
        "93",
    );
    // Link 2 declines. NONE must not demote the chain's SUCCESS.
    let second = link("second", "true", "95");

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
    // The chain as ONE setting value, which is how NZBGet spells it and
    // how the settings row stores it.
    let chain = format!("{},{}", first.display(), second.display());
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--script")
            .arg(&chain)
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // The setting round-trips as the chain, not as one path: this is
        // what the settings row shows and what a restart reloads.
        let cfgj = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&cfgj).unwrap();
        assert_eq!(v["config"]["nzbfast"]["script"], chain, "{cfgj}");
        // Both links are offered to a client's dropdown by basename -
        // the vocabulary an add's `script=` sends back. A chain that
        // published only its first link would break the round trip on
        // the second.
        let sc = http(
            port,
            "/api?mode=get_scripts&apikey=sekrit&output=json",
            None,
        );
        assert!(sc.contains("\"first.sh\""), "{sc}");
        assert!(sc.contains("\"second.sh\""), "{sc}");

        let r = upload_named(port, "episode", &xml, "&cat=tv");
        assert!(r.contains("\"status\":true"), "{r}");

        let order = dir2.join("order.out");
        let mut seen = String::new();
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                seen = std::fs::read_to_string(&order).unwrap_or_default();
                if seen.lines().count() == 2 {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Order is the LIST's, which is the whole difference between a
        // chain and a set: a sorter has to run before the notifier that
        // announces where it put things.
        assert_eq!(
            seen.lines().collect::<Vec<_>>(),
            vec!["first", "second"],
            "the chain did not run both links in order (order.out: {seen:?})"
        );

        let read = |n: &str| -> std::collections::HashMap<String, String> {
            std::fs::read_to_string(dir2.join(format!("{n}.out")))
                .unwrap_or_else(|e| panic!("{n} never wrote its env: {e}"))
                .lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let a = read("first");
        let b = read("second");

        // The gate every NZBGet extension opens with: present, and
        // naming the folder the scripts actually live in.
        assert_eq!(a["SCRIPTDIR"], dir2.to_string_lossy(), "{a:?}");
        assert_eq!(
            a["DESTDIR"],
            dir2.join("complete").to_string_lossy(),
            "{a:?}"
        );
        assert_eq!(a["CONTROLPORT"], port.to_string(), "{a:?}");
        // Loopback rather than the bind address: a script builds a
        // callback URL from this, and NZBGet's own 0.0.0.0 is a bind
        // wildcard that every script has to special-case back.
        assert_eq!(a["CONTROLIP"], "127.0.0.1", "{a:?}");
        // Both of NZBGet's spellings of every option.
        assert_eq!(a["OPVERSION"], "21.0", "{a:?}");
        assert_eq!(a["OPVERSION_CAMEL"], "21.0", "{a:?}");
        assert_eq!(a["TOTALSTATUS"], "SUCCESS", "{a:?}");
        assert_eq!(a["HEALTH"], "1000", "{a:?}");
        assert!(!a["NZBID"].is_empty(), "{a:?}");

        // The first link starts from nothing: no earlier script has run,
        // and none has moved anything.
        assert_eq!(a["SCRIPTSTATUS"], "NONE", "{a:?}");
        assert_eq!(a["FINALDIR"], "", "{a:?}");
        assert_eq!(a["STAGE"], "", "{a:?}");

        // The second link sees all three of the first one's effects.
        assert_eq!(
            b["SCRIPTSTATUS"], "SUCCESS",
            "exit 93 must reach the next link as SUCCESS ({b:?})"
        );
        assert_eq!(
            b["FINALDIR"],
            dir2.join("sorted").to_string_lossy(),
            "[NZB] FINALDIR= must reach the next link ({b:?})"
        );
        assert_eq!(b["STAGE"], "one", "{b:?}");
        assert_eq!(
            b["STAGE_UPPER"], "one",
            "a parameter is exported under both of NZBGet's spellings ({b:?})"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
