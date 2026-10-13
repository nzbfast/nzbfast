//! Two failure shapes a downloader can have, asked of nzbfast on the
//! daemon path (measured 11 Oct 2026; the numbers live in the research
//! record that names this module).
//!
//! A. A job that was downloading when the daemon restarted resumes at a
//!    small fraction of line rate for the rest of its life - the shape a
//!    run-ahead bound for resumed jobs produces when it is measured
//!    against the contiguous prefix of a scattered file and never
//!    releases.
//! B. A dead post takes minutes to fail, where the verdict the *arr
//!    acts on could have been reached sooner.
//!
//! A sibling-dir child of daemon.rs for the reason every sibling here is
//! one: a top-level file would be its own target and fall out of the
//! serial daemon gate. Harness via `super::*`.

use super::*;
use crate::harness::wait_until;
use crate::payloads::unique_payload;

/// Per-BODY service time on the mock. With it fixed, a connection
/// serves at most one article per `BODY_MS`, so the BODY ARRIVAL RATE
/// across the run divided by `1000 / BODY_MS` is the number of
/// connections the client is keeping busy - the quantity shape A is
/// about (a stuck job keeps one to three of dozens busy).
const BODY_MS: u64 = 40;
/// Connections configured for the one server.
const CONNS: usize = 8;
const ART: usize = 100_000;

/// One post: payload files split into articles, optional ghosts. The
/// NZB `date` is a parameter because the daemon's auto-retry is gated on
/// POST AGE (`diag::GONE_MIN_AGE_DAYS`), which reads it.
struct Post {
    files: Vec<(String, Vec<(String, u64, u32)>)>,
    date: u64,
}

impl Post {
    fn new(date: u64) -> Post {
        Post {
            files: Vec::new(),
            date,
        }
    }
    fn add(
        &mut self,
        name: &str,
        data: &[u8],
        art: usize,
        tag: &str,
        articles: &mut HashMap<String, Vec<u8>>,
    ) {
        let segs = make_file_articles(name, data, art, tag, articles);
        self.files.push((name.to_string(), segs));
    }
    fn xml(&self) -> String {
        let mut x = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (name, segs) in &self.files {
            x.push_str(&format!(
                "  <file poster=\"x\" date=\"{}\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
                self.date,
                segs.len()
            ));
            for (id, bytes, num) in segs {
                x.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
                ));
            }
            x.push_str("    </segments>\n  </file>\n");
        }
        x.push_str("</nzb>\n");
        x
    }
    fn ids(&self) -> Vec<String> {
        self.files
            .iter()
            .flat_map(|(_, s)| s.iter().map(|(id, _, _)| format!("<{id}>")))
            .collect()
    }
}

fn add_nzb(port: u16, xml: &str, filename: &str) -> String {
    let boundary = "----resumerateb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{filename}\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let added = http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    added
        .split("\"nzo_ids\":[\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or_else(|| panic!("no nzo_id in {added}"))
        .to_string()
}

fn write_cfg(cfg: &Path, ports: &[u16], conns: usize) {
    let servers: Vec<String> = ports
        .iter()
        .map(|p| {
            format!("{{\"host\":\"127.0.0.1\",\"port\":{p},\"tls\":false,\"connections\":{conns}}}")
        })
        .collect();
    std::fs::write(cfg, format!("{{\"servers\":[{}]}}", servers.join(","))).unwrap();
}

fn build(cfg: PathBuf, out: PathBuf, conns: usize) -> impl Fn(u16) -> Command {
    move |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1").env("NZBFAST_OPEN", "1");
        c.arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(&out)
            .arg("--connections")
            .arg(conns.to_string());
        c
    }
}

/// Poll history until `nzo` has a row; return (row, seconds waited).
fn wait_history(port: u16, nzo: &str, within_s: u64) -> (serde_json::Value, f64) {
    let t0 = std::time::Instant::now();
    loop {
        let h = http(port, "/api?mode=history&output=json", None);
        let slot = history_slot(&h, nzo);
        if !slot.is_null() {
            return (slot, t0.elapsed().as_secs_f64());
        }
        assert!(
            t0.elapsed().as_secs() < within_s,
            "{nzo} reached no history row in {within_s}s"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Steady BODY arrival rate (requests/s) over one run's slice of the
/// mock's log, trimmed of its first and last 10% so connection ramp-up
/// and the tail's drain do not read as the rate. Returns (rate, n).
fn steady_rate(times: &[std::time::Duration]) -> (f64, usize) {
    let n = times.len();
    if n < 20 {
        return (0.0, n);
    }
    let (a, b) = (n / 10, n - n / 10 - 1);
    let span = (times[b] - times[a]).as_secs_f64();
    ((b - a) as f64 / span.max(1e-6), n)
}

/// Peak number of BODY arrivals inside any `BODY_MS` window - the most
/// connections seen busy at once, read off the arrival stamps.
fn peak_busy(times: &[std::time::Duration]) -> usize {
    let w = std::time::Duration::from_millis(BODY_MS);
    let mut best = 0;
    let mut lo = 0;
    for hi in 0..times.len() {
        while times[hi] - times[lo] >= w {
            lo += 1;
        }
        best = best.max(hi - lo + 1);
    }
    best
}

/// The three fixture shapes the restart probe runs.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// One large plain file and four small ones, nothing withheld.
    Plain,
    /// `Plain`, with the large file's first two articles STALLED on
    /// their first request - so at the stop point that file has a zero
    /// contiguous prefix and most of its bytes written beyond it. This
    /// is the shape a prefix-measured run-ahead bound sticks on.
    Scattered,
    /// A ten-volume RAR set (one-pass extraction, its own frontier),
    /// with the first article of volume 1 - the archive header - stalled
    /// the same way, so the extractor runs with everything after it
    /// parked.
    RarScattered,
}

/// The post for `shape`, the (name, bytes) a finished job must hold at
/// its storage path, and the ids to stall on first request.
fn big_post(
    shape: Shape,
    articles: &mut HashMap<String, Vec<u8>>,
) -> (Post, Vec<(String, Vec<u8>)>, Vec<String>) {
    let mut post = Post::new(0);
    match shape {
        Shape::Plain | Shape::Scattered => {
            let mut files = vec![("big.bin".to_string(), unique_payload(400 * ART, 101))];
            for i in 0..4u64 {
                files.push((format!("side{i}.bin"), unique_payload(60 * ART, 200 + i)));
            }
            for (i, (name, data)) in files.iter().enumerate() {
                post.add(name, data, ART, &format!("wv{i}"), articles);
            }
            let stall = if matches!(shape, Shape::Scattered) {
                vec!["<wv0-1@mock>".to_string(), "<wv0-2@mock>".to_string()]
            } else {
                Vec::new()
            };
            (post, files, stall)
        }
        Shape::RarScattered => {
            let movie = unique_payload(400 * ART, 303);
            let vols = rarfixtures::compressed_volume_set_at_effort(
                &[rarfixtures::Member::unix(b"movie.mkv", &movie)],
                4_000_000,
                Some(1),
            );
            for (i, v) in vols.iter().enumerate() {
                post.add(
                    &format!("movie.part{:02}.rar", i + 1),
                    v,
                    ART,
                    &format!("wr{i}"),
                    articles,
                );
            }
            (
                post,
                vec![("movie.mkv".to_string(), movie)],
                vec!["<wr0-1@mock>".to_string()],
            )
        }
    }
}

async fn mock_for(shape: Shape) -> (MockServer, Post, Vec<(String, Vec<u8>)>) {
    let mut articles = HashMap::new();
    let (post, files, stall) = big_post(shape, &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: BODY_MS,
            stall: stall.into_iter().collect(),
            ..Chaos::default()
        },
    )
    .await;
    (srv, post, files)
}

/// Every expected file byte-exact somewhere under the job's storage.
fn assert_delivered(tag: &str, row: &serde_json::Value, files: &[(String, Vec<u8>)], log: &str) {
    let storage = PathBuf::from(row["storage"].as_str().unwrap_or_default());
    for (name, data) in files {
        assert!(
            std::fs::read(storage.join(name)).unwrap_or_default() == *data,
            "{tag}: {name} not byte-exact at {storage:?}\n{row}\n{log}"
        );
    }
}

/// What one restart leg measured.
struct Leg {
    total_s: f64,
    rate: f64,
    busy: f64,
    peak: usize,
    asked: usize,
    /// Run-2 requests for ids run 1 had already been answered on (0 on
    /// a fresh leg): bytes a restart threw away.
    refetched: usize,
    status: String,
}

fn report(label: &str, l: &Leg) -> String {
    format!(
        "{label}: {:.2}s add/restart->history, {} BODY asked ({} refetched), steady {:.1} req/s = {:.2} of {CONNS} conns busy (peak {}), status {}",
        l.total_s, l.asked, l.refetched, l.rate, l.busy, l.peak, l.status
    )
}

/// The control: the same post, fresh daemon, fresh directory, no
/// restart. Its steady rate is the number a resumed job has to match.
async fn fresh_leg(tag: &str, shape: Shape) -> Leg {
    let dir = std::env::temp_dir().join(format!("nzbfast-rr-{tag}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (out, cfg) = (dir.join("complete"), dir.join("config.json"));
    let (srv, post, files) = mock_for(shape).await;
    write_cfg(&cfg, &[srv.addr.port()], CONNS);
    let d = serve(&dir, build(cfg, out, CONNS)).await;
    let port = d.port;
    let xml = post.xml();
    let t0 = std::time::Instant::now();
    let (row, total_s, log) = tokio::task::spawn_blocking(move || {
        let nzo = add_nzb(port, &xml, "Resume.Fresh.nzb");
        let (row, s) = wait_history(port, &nzo, 300);
        (row, s, d.log())
    })
    .await
    .unwrap();
    let times: Vec<_> = srv
        .body_log
        .lock()
        .unwrap()
        .timeline(t0)
        .into_iter()
        .map(|(_, t)| t)
        .collect();
    let (rate, asked) = steady_rate(&times);
    assert_delivered(tag, &row, &files, &log);
    Leg {
        total_s,
        rate,
        busy: rate * BODY_MS as f64 / 1000.0,
        peak: peak_busy(&times),
        asked,
        refetched: 0,
        status: row["status"].as_str().unwrap_or("?").to_string(),
    }
}

/// Run 1 to ~`at` of the post's articles, stop the daemon (`graceful`:
/// SIGTERM and let it wind down; else SIGKILL), restart in the same
/// directory and measure run 2 alone.
async fn restart_leg(tag: &str, shape: Shape, graceful: bool, at: f64) -> (Leg, usize, String) {
    let dir = std::env::temp_dir().join(format!("nzbfast-rr-{tag}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (out, cfg) = (dir.join("complete"), dir.join("config.json"));
    let (srv, post, files) = mock_for(shape).await;
    let n_ids = post.ids().len();
    write_cfg(&cfg, &[srv.addr.port()], CONNS);
    let d = serve(&dir, build(cfg.clone(), out.clone(), CONNS)).await;
    let port = d.port;
    let xml = post.xml();
    let log_handle = srv.body_log.clone();
    let stop_at = (n_ids as f64 * at) as usize;
    let nzo = tokio::task::spawn_blocking(move || {
        let nzo = add_nzb(port, &xml, "Resume.Restart.nzb");
        wait_until(
            "run 1 to reach the stop point",
            std::time::Duration::from_secs(120),
            || log_handle.lock().unwrap().len() >= stop_at,
        );
        if graceful {
            sigterm(d.pid());
            wait_until(
                "the daemon to close its port on SIGTERM",
                std::time::Duration::from_secs(60),
                || TcpStream::connect(("127.0.0.1", port)).is_err(),
            );
        }
        let _log = d.stop();
        nzo
    })
    .await
    .unwrap();
    let asked_run1 = srv.body_log.lock().unwrap().len();

    let d = serve(&dir, build(cfg, out, CONNS)).await;
    let port = d.port;
    let t0 = std::time::Instant::now();
    let (row, total_s, log) = {
        let nzo = nzo.clone();
        tokio::task::spawn_blocking(move || {
            let (row, s) = wait_history(port, &nzo, 300);
            (row, s, d.log())
        })
        .await
        .unwrap()
    };
    let tl = srv.body_log.lock().unwrap().timeline(t0);
    let times: Vec<_> = tl[asked_run1..].iter().map(|(_, t)| *t).collect();
    let run1: std::collections::HashSet<&String> =
        tl[..asked_run1].iter().map(|(id, _)| id).collect();
    let refetched = tl[asked_run1..]
        .iter()
        .filter(|(id, _)| run1.contains(id))
        .count();
    let (rate, asked) = steady_rate(&times);
    assert_delivered(tag, &row, &files, &log);
    (
        Leg {
            total_s,
            rate,
            busy: rate * BODY_MS as f64 / 1000.0,
            peak: peak_busy(&times),
            asked,
            refetched,
            status: row["status"].as_str().unwrap_or("?").to_string(),
        },
        asked_run1,
        log,
    )
}

/// Measure one shape: a fresh control, then the restart legs.
async fn restart_round(shape: Shape, signals: &[bool]) -> Vec<String> {
    let t = format!("{shape:?}").to_lowercase();
    let fresh = fresh_leg(&format!("{t}-fresh"), shape).await;
    let mut lines = vec![report(&format!("{shape:?} fresh"), &fresh)];
    for &graceful in signals {
        let sig = if graceful { "SIGTERM" } else { "SIGKILL" };
        let (l, r1, log) =
            restart_leg(&format!("{t}-{}", sig.to_lowercase()), shape, graceful, 0.4).await;
        lines.push(format!(
            "{} (run 1 asked {r1})",
            report(&format!("{shape:?} {sig} @40%"), &l)
        ));
        eprintln!("RESUME-RATE\n  {}", lines.join("\n  "));
        assert_eq!(l.status, "Completed", "{}\n{log}", lines.join("\n"));
        // Shape A leaves one to three of dozens of connections busy for
        // the rest of the job. Here that would read as 1-2 of 8 against a fresh
        // 5-6.6, a ratio of 0.15-0.3; measured healthy resumes are
        // 0.95-1.4 of fresh (the fresh leg pays the stalled head, the
        // resumed one does not). 0.4 sits between the two with margin
        // for a loaded box on either side.
        assert!(
            l.rate >= fresh.rate * 0.4,
            "a resumed job runs at {:.1} req/s against {:.1} fresh - a resumed job stuck behind a bound\n  {}\n--- log ---\n{log}",
            l.rate,
            fresh.rate,
            lines.join("\n  ")
        );
    }
    lines
}

/// A graceful stop, for the SIGTERM arm of the ignored grid only - the
/// pin itself stops with SIGKILL through `Child::kill`, which every
/// platform has.
#[cfg(unix)]
fn sigterm(pid: u32) {
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
}

#[cfg(not(unix))]
fn sigterm(_pid: u32) {
    panic!("the SIGTERM arm of the restart grid is unix-only");
}

/// Shape A: a job SIGKILLed mid-download and picked
/// up by the next daemon must run at the same rate as the same job run
/// fresh. Pinned on the two shapes the defect needs - a large file whose
/// contiguous prefix is zero at the kill, and a RAR set whose extractor
/// is parked behind its header - and held at a third of the cost of
/// the full probe by leaving out the plain shape and SIGTERM, which
/// measured the same (`measure_restart_rate_every_shape`).
#[tokio::test(flavor = "multi_thread")]
async fn a_job_resumed_across_a_restart_runs_at_the_fresh_rate() {
    for shape in [Shape::Scattered, Shape::RarScattered] {
        restart_round(shape, &[false]).await;
    }
}

/// The full grid behind the pin above, for the research record.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement probe - prints the table its research record carries"]
async fn measure_restart_rate_every_shape() {
    let mut all = Vec::new();
    for shape in [Shape::Plain, Shape::Scattered, Shape::RarScattered] {
        all.extend(restart_round(shape, &[false, true]).await);
    }
    eprintln!("RESUME-RATE-GRID\n  {}", all.join("\n  "));
}

/// What one dead-post leg measured.
struct DeadLeg {
    secs: f64,
    status: String,
    fail: String,
    asked: Vec<usize>,
}

/// Build a post of `nfiles` files x `parts` articles, make
/// `dead_frac` of every file's articles 430 on every server, optionally
/// with a PAR2 set at `par2_pct` redundancy (whose own articles stay
/// alive), and measure add -> first history row.
async fn dead_leg(
    tag: &str,
    nservers: usize,
    dead_frac: f64,
    par2_pct: Option<u32>,
    date: u64,
    missing_ms: u64,
) -> DeadLeg {
    let dir = std::env::temp_dir().join(format!("nzbfast-rrd-{tag}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (out, cfg) = (dir.join("complete"), dir.join("config.json"));
    let art = 20_000;
    let (nfiles, parts) = (12usize, 25usize);
    let files: Vec<(String, Vec<u8>)> = (0..nfiles)
        .map(|i| {
            (
                format!("dead.part{:02}.bin", i + 1),
                unique_payload(art * parts, 900 + i as u64),
            )
        })
        .collect();
    let mut articles = HashMap::new();
    let mut post = Post::new(date);
    for (i, (name, data)) in files.iter().enumerate() {
        post.add(name, data, art, &format!("dd{i}"), &mut articles);
    }
    // Kill `dead_frac` of each file's articles, spread across the file.
    let mut dead = std::collections::HashSet::new();
    for (_, segs) in &post.files {
        let n = segs.len();
        let k = ((n as f64) * dead_frac).round() as usize;
        for j in 0..k {
            let idx = j * n / k.max(1);
            dead.insert(format!("<{}>", segs[idx].0));
        }
    }
    if let Some(pct) = par2_pct {
        let build_dir = dir.join("par2build");
        std::fs::create_dir_all(&build_dir).unwrap();
        for (name, data) in &files {
            std::fs::write(build_dir.join(name), data).unwrap();
        }
        // `-c` (a block COUNT), never `-r{pct}`: par2cmdline 0.8.1 -
        // apt's, which nightly installs - refuses any `-r` over 100
        // ("Invalid redundancy option: -r120"), where the pinned 1.3.0
        // on the per-push jobs accepts it, so the 120% leg was red on
        // every nightly and green on every push. The block size equals
        // the article size, so the source is `nfiles * parts` blocks.
        let blocks = (nfiles * parts) as u64 * u64::from(pct) / 100;
        let st = Command::new("par2")
            .arg("create")
            .arg(format!("-s{art}"))
            .arg(format!("-c{blocks}"))
            .arg("-q")
            .arg("dead")
            .args(files.iter().map(|(n, _)| n))
            .current_dir(&build_dir)
            .status();
        assert!(st.is_ok_and(|s| s.success()), "par2 create failed");
        let mut p2: Vec<_> = std::fs::read_dir(&build_dir)
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                let n = p.file_name()?.to_string_lossy().to_string();
                n.ends_with(".par2")
                    .then(|| (n, std::fs::read(&p).unwrap()))
            })
            .collect();
        p2.sort();
        for (i, (n, b)) in p2.iter().enumerate() {
            post.add(n, b, art, &format!("pp{i}"), &mut articles);
        }
    }
    for id in &dead {
        articles.remove(id);
    }
    let mut srvs = Vec::new();
    for _ in 0..nservers {
        srvs.push(
            MockServer::start(
                articles.clone(),
                Chaos {
                    missing_delay_ms: missing_ms,
                    ..Chaos::default()
                },
            )
            .await,
        );
    }
    let ports: Vec<u16> = srvs.iter().map(|s| s.addr.port()).collect();
    write_cfg(&cfg, &ports, CONNS);
    let d = serve(&dir, build(cfg, out, CONNS)).await;
    let port = d.port;
    let xml = post.xml();
    let (row, secs, log) = tokio::task::spawn_blocking(move || {
        let nzo = add_nzb(port, &xml, "Dead.Post.2026.nzb");
        let (row, s) = wait_history(port, &nzo, 600);
        (row, s, d.log())
    })
    .await
    .unwrap();
    drop(log);
    DeadLeg {
        secs,
        status: row["status"].as_str().unwrap_or("?").to_string(),
        fail: row["fail_message"].as_str().unwrap_or("").to_string(),
        asked: srvs
            .iter()
            .map(|s| s.body_log.lock().unwrap().len())
            .collect(),
    }
}

/// Shape B: a dead post must reach a Failed
/// row the *arr can act on, saying why - and a post that is just as
/// short but carries enough PAR2 must NOT. That second half is the
/// misfire guard any early refusal added later has to pass: the 90%-dead
/// arm is exactly what a first-article sample would call dead.
///
/// Time is printed, not asserted: on this 300-article post every arm is
/// ~3 s, and the cost that matters is how it SCALES, which is
/// `measure_dead_post_time_to_fail_scaling` (linear, ~6 ms an article
/// on two servers at a 50 ms refusal).
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_post_fails_saying_so_and_a_repairable_one_completes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let old = now - 30 * 86_400;
    let legs = [
        ("all-dead-old", dead_leg("a", 2, 1.0, None, old, 25).await),
        (
            "all-dead-fresh",
            dead_leg("b", 2, 1.0, None, now - 600, 25).await,
        ),
        (
            "90pct-dead-nopar",
            dead_leg("c", 2, 0.9, None, old, 25).await,
        ),
        (
            "90pct-dead-par2-120",
            dead_leg("d", 2, 0.9, Some(120), old, 25).await,
        ),
    ];
    let lines: Vec<String> = legs
        .iter()
        .map(|(l, d)| {
            format!(
                "{l}: {:.2}s to history, {}, BODY asked per server {:?}, fail_message {:?}",
                d.secs, d.status, d.asked, d.fail
            )
        })
        .collect();
    let all = lines.join("\n  ");
    eprintln!("DEAD-POST\n  {all}");
    let leg = |name: &str| &legs.iter().find(|(l, _)| *l == name).unwrap().1;
    // An old post with nothing on any server: Failed, and the message
    // says the post is gone rather than hedging about propagation.
    let d = leg("all-dead-old");
    assert_eq!(d.status, "Failed", "{all}");
    assert!(d.fail.contains("post is gone"), "{all}");
    // The same post minutes old: still Failed (the *arr moves on), but
    // the message must keep the propagation hedge - memory
    // `nzbfast-retry-propagation-trap`.
    let d = leg("all-dead-fresh");
    assert_eq!(d.status, "Failed", "{all}");
    assert!(d.fail.contains("brand new"), "{all}");
    // 90% short with no recovery: Failed, naming the age.
    let d = leg("90pct-dead-nopar");
    assert_eq!(d.status, "Failed", "{all}");
    assert!(d.fail.contains("day(s) old"), "{all}");
    // 90% short WITH enough PAR2: repaired, Completed. The misfire guard.
    let d = leg("90pct-dead-par2-120");
    assert_eq!(d.status, "Completed", "{all}");
}

fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run"
    );
    ok
}

/// A wholly-dead post of `files` x `parts` DECLARED articles, none of
/// them on any server (no bytes are minted at all), 30 days old, on
/// `nservers` servers of `conns` connections each answering every BODY
/// with a 430 after `missing_ms`. Returns (seconds to history, status,
/// BODY asked per server).
async fn ghost_leg(
    tag: &str,
    files: usize,
    parts: usize,
    nservers: usize,
    conns: usize,
    missing_ms: u64,
) -> (f64, String, Vec<usize>) {
    let dir = std::env::temp_dir().join(format!("nzbfast-rrg-{tag}-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (out, cfg) = (dir.join("complete"), dir.join("config.json"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut post = Post::new(now - 30 * 86_400);
    for f in 0..files {
        let segs = (1..=parts as u32)
            .map(|n| (format!("gh{f}-{n}@mock"), 716_800u64, n))
            .collect();
        post.files
            .push((format!("ghost.part{:03}.rar", f + 1), segs));
    }
    let mut srvs = Vec::new();
    for _ in 0..nservers {
        srvs.push(
            MockServer::start(
                HashMap::new(),
                Chaos {
                    missing_delay_ms: missing_ms,
                    ..Chaos::default()
                },
            )
            .await,
        );
    }
    let ports: Vec<u16> = srvs.iter().map(|s| s.addr.port()).collect();
    write_cfg(&cfg, &ports, conns);
    let d = serve(&dir, build(cfg, out, conns)).await;
    let port = d.port;
    let xml = post.xml();
    let (row, secs) = tokio::task::spawn_blocking(move || {
        let nzo = add_nzb(port, &xml, "Ghost.Post.2026.nzb");
        let r = wait_history(port, &nzo, 1200);
        drop(d);
        r
    })
    .await
    .unwrap();
    (
        secs,
        row["status"].as_str().unwrap_or("?").to_string(),
        srvs.iter()
            .map(|s| s.body_log.lock().unwrap().len())
            .collect(),
    )
}

/// How time-to-fail on a wholly-dead post SCALES with its size: if it
/// is linear in the article count, a real-sized dead post is minutes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement probe - prints the table its research record carries"]
async fn measure_dead_post_time_to_fail_scaling() {
    let mut lines = Vec::new();
    for (files, parts) in [(10usize, 50usize), (20, 100), (40, 100)] {
        let (s, st, asked) = ghost_leg(&format!("{files}x{parts}"), files, parts, 2, 20, 50).await;
        lines.push(format!(
            "{} articles ({files} files x {parts}), 2 servers x 20 conns, 430 after 50 ms: {s:.2}s to history, {st}, BODY asked per server {asked:?}",
            files * parts
        ));
    }
    eprintln!("DEAD-POST-SCALE\n  {}", lines.join("\n  "));
}
