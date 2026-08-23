//! Harsh-network playback rig for the /stream path ("test preview").
//!
//! Plays a store-mode rar'd movie through the daemon's /stream endpoint
//! while the in-process chaos mock injects the TODO 111 fault matrix,
//! and records what a player would feel: time-to-first-byte, rebuffer
//! count and duration, recovery after fault onset, seek latency.
//!
//! Two kinds of test live here:
//!   - `chaos_matrix_*`: the MEASUREMENT harness, `#[ignore]`d because a
//!     full pass takes minutes. Run explicitly (release, single thread):
//!       NZBFAST_NO_ENRICH=1 cargo test -p nzbfast --test daemon --release \
//!         -- --ignored chaos_matrix --test-threads=1 --nocapture
//!     Each scenario prints one `MEASURE {json}` line; the numbers land
//!     in research/STREAM-HARDENING-2026-08.md.
//!   - plain `#[tokio::test]`s: chaos regression tests for specific
//!     fixed faults, part of the normal daemon gate.
//!
//! The player model: a client that reads the response greedily (VLC and
//! browser fetch both do), so the arrival curve at the client IS the
//! availability curve the daemon can serve. Playback stats are computed
//! from that curve afterwards for a player of a given bitrate and
//! prebuffer - deterministic, and one recorded run answers "how would
//! this have played" for any bitrate.

use super::*;
use nzbkit::rar::fixtures;

/// Media bitrate the playback model assumes: 8 Mbps, a typical 1080p
/// encode - 1 MB/s of file bytes.
const BITRATE_BPS: u64 = 1_000_000;
/// Seconds of media a player buffers before starting/resuming playback.
const PREBUFFER_SECS: f64 = 2.0;

/// One recorded playback: when each contiguous chunk of the body arrived.
struct ArrivalCurve {
    /// (seconds since the request was written, cumulative body bytes).
    samples: Vec<(f64, u64)>,
    /// Total body bytes expected (Content-Length).
    expect: u64,
    /// Seconds from request write to the first BODY byte.
    ttfb: Option<f64>,
    /// The HTTP status line.
    status: String,
    /// True when the read loop gave up (wall cap) before the body ended.
    truncated: bool,
    /// The body bytes as received (for content assertions).
    body: Vec<u8>,
}

/// Stalls a player of `bitrate` with `prebuffer` seconds of startup
/// buffer would have felt, simulated over the arrival curve.
#[derive(Debug, Default)]
struct PlayStats {
    /// Seconds from request to playback start (ttfb + prebuffer fill).
    start_delay: f64,
    rebuffers: usize,
    rebuffer_total: f64,
    rebuffer_longest: f64,
    /// Seconds of media actually played by the end of the recording.
    played_secs: f64,
}

fn simulate_playback(curve: &ArrivalCurve, bitrate: u64, prebuffer: f64) -> PlayStats {
    let mut st = PlayStats::default();
    if curve.samples.is_empty() {
        return st;
    }
    let need_start = (bitrate as f64 * prebuffer) as u64;
    let end_t = curve.samples.last().unwrap().0;
    let total = curve.samples.last().unwrap().1;
    // When does cumulative coverage first reach `bytes`? (samples are
    // monotonic in both fields)
    let arrival_of = |bytes: u64| -> Option<f64> {
        if bytes == 0 {
            return Some(curve.ttfb.unwrap_or(0.0));
        }
        curve
            .samples
            .iter()
            .find(|(_, b)| *b >= bytes)
            .map(|(t, _)| *t)
    };
    let start_target = need_start.min(curve.expect.max(1));
    let Some(start_t) = arrival_of(start_target.min(total.max(1))) else {
        // Never buffered enough to start at all.
        st.start_delay = end_t;
        return st;
    };
    st.start_delay = start_t;
    // Walk playback: playhead in media-bytes, clock in seconds.
    let mut clock = start_t;
    let mut played: u64 = 0;
    loop {
        // How far could we play before hitting a byte that hadn't
        // arrived by the time we needed it?
        let horizon = curve
            .samples
            .iter()
            .rev()
            .find(|(t, _)| *t <= clock)
            .map(|(_, b)| *b)
            .unwrap_or(0);
        if horizon <= played {
            // Nothing buffered right now: rebuffer immediately.
            let resume_bytes = (played + (bitrate as f64 * prebuffer) as u64).min(curve.expect);
            match arrival_of(resume_bytes) {
                Some(t) if t > clock => {
                    let dur = t - clock;
                    st.rebuffers += 1;
                    st.rebuffer_total += dur;
                    if dur > st.rebuffer_longest {
                        st.rebuffer_longest = dur;
                    }
                    clock = t;
                    continue;
                }
                Some(_) => {
                    // Already there (can happen at exact boundaries):
                    // treat as playable.
                }
                None => {
                    // Never arrives in the recording: the player is
                    // stuck from `clock` to the end of the recording.
                    let dur = (end_t - clock).max(0.0);
                    st.rebuffers += 1;
                    st.rebuffer_total += dur;
                    if dur > st.rebuffer_longest {
                        st.rebuffer_longest = dur;
                    }
                    break;
                }
            }
        }
        // Play until the buffered horizon runs out (or the file ends).
        let runway_bytes = horizon - played;
        let runway_secs = runway_bytes as f64 / bitrate as f64;
        let next_clock = clock + runway_secs;
        played = horizon;
        clock = next_clock;
        if played >= curve.expect {
            break;
        }
        // Re-check what has arrived by the new clock; if more landed
        // while we played, loop continues without a stall.
        let new_horizon = curve
            .samples
            .iter()
            .rev()
            .find(|(t, _)| *t <= clock)
            .map(|(_, b)| *b)
            .unwrap_or(0);
        if new_horizon <= played && clock >= end_t {
            break;
        }
    }
    st.played_secs = played as f64 / bitrate as f64;
    st
}

/// Gaps of >= 1 s between arrivals - the raw stall timeline, with
/// timestamps so onset-style faults can be read off the log.
fn arrival_gaps(curve: &ArrivalCurve) -> Vec<(f64, f64)> {
    let mut gaps = Vec::new();
    let mut prev = match curve.ttfb {
        Some(t) => t,
        None => return gaps,
    };
    for (t, _) in &curve.samples {
        if *t - prev >= 1.0 {
            gaps.push((prev, *t - prev));
        }
        prev = *t;
    }
    gaps
}

/// GET `path` on the daemon and record the body's arrival curve.
/// `wall_cap` bounds the whole read; a stream that stops moving for
/// `idle_cap` seconds is abandoned (records what a player saw: a hang).
fn record_stream(port: u16, path: &str, wall_cap: f64, idle_cap: f64) -> ArrivalCurve {
    use std::io::{Read as _, Write as _};
    let started = std::time::Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_nodelay(true).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_millis(250)))
        .unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();

    let mut curve = ArrivalCurve {
        samples: Vec::new(),
        expect: 0,
        ttfb: None,
        status: String::new(),
        truncated: false,
        body: Vec::new(),
    };
    let mut buf = vec![0u8; 256 * 1024];
    let mut head = Vec::new();
    let mut body_bytes: u64 = 0;
    let mut header_done = false;
    let mut last_progress = std::time::Instant::now();
    loop {
        let now = started.elapsed().as_secs_f64();
        if now > wall_cap || last_progress.elapsed().as_secs_f64() > idle_cap {
            curve.truncated = curve.expect == 0 || body_bytes < curve.expect;
            break;
        }
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                last_progress = std::time::Instant::now();
                let t = started.elapsed().as_secs_f64();
                let mut payload = &buf[..n];
                if !header_done {
                    head.extend_from_slice(payload);
                    if let Some(p) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                        let txt = String::from_utf8_lossy(&head[..p]).to_string();
                        curve.status = txt.lines().next().unwrap_or("").to_string();
                        for l in txt.lines() {
                            if let Some(v) = l
                                .to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().to_string())
                            {
                                curve.expect = v.parse().unwrap_or(0);
                            }
                        }
                        let body_start = p + 4;
                        let already = head.len() - body_start;
                        header_done = true;
                        if already > 0 {
                            curve.ttfb = Some(t);
                            body_bytes = already as u64;
                            curve.body.extend_from_slice(&head[body_start..]);
                            curve.samples.push((t, body_bytes));
                        }
                        payload = &[];
                    } else {
                        payload = &[];
                    }
                }
                if header_done && !payload.is_empty() {
                    if curve.ttfb.is_none() {
                        curve.ttfb = Some(t);
                    }
                    body_bytes += payload.len() as u64;
                    curve.body.extend_from_slice(payload);
                    curve.samples.push((t, body_bytes));
                }
                if curve.expect > 0 && body_bytes >= curve.expect {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
    curve
}

/// The corpus: a `movie.mkv` of `size` bytes inside a 3-volume
/// store-mode RAR5 set (the shape the one-pass pipeline maps 1:1), as
/// (nzb xml, article map, the inner payload).
fn movie_corpus(size: usize) -> (String, HashMap<String, Vec<u8>>, Vec<u8>) {
    let inner = payload(size, 7);
    let (a, b) = (size / 3, 2 * size / 3);
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", size as u64, &inner[..a], false, true)], 0),
        fixtures::rar5_volume_n(&[("movie.mkv", size as u64, &inner[a..b], true, true)], 1),
        fixtures::rar5_volume_n(&[("movie.mkv", size as u64, &inner[b..], true, false)], 2),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("sc{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    (xml, articles, inner)
}

/// The article ids of the corpus in NZB (file, part) order - for
/// choosing deterministic mid-file fault victims.
fn corpus_ids(articles: &HashMap<String, Vec<u8>>) -> Vec<String> {
    let mut ids: Vec<String> = articles.keys().cloned().collect();
    // make_file_articles ids embed "<seed>p<part>"; sort by (volume seed,
    // numeric part) so "mid-file" means what it says.
    ids.sort_by_key(|id| {
        let inner = id.trim_matches(['<', '>']);
        let (stem, _) = inner.split_once('@').unwrap_or((inner, ""));
        let (seed, part) = stem.rsplit_once('p').unwrap_or((stem, "0"));
        (seed.to_string(), part.parse::<u64>().unwrap_or(0))
    });
    ids
}

/// Upload the NZB over the daemon API.
fn upload_nzb(port: u16, xml: &str) {
    let boundary = "----chaosb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
}

/// Wait until /stream answers 206 for the head range, then hand back.
/// Returns seconds waited (the "job added -> stream exists" latency).
fn wait_stream_up(port: u16, wall_cap: f64) -> f64 {
    let started = std::time::Instant::now();
    loop {
        let raw = raw(
            port,
            b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=0-1023\r\nConnection: close\r\n\r\n",
        );
        if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n")
            && String::from_utf8_lossy(&raw[..p]).contains("206")
        {
            return started.elapsed().as_secs_f64();
        }
        if started.elapsed().as_secs_f64() > wall_cap {
            panic!("stream never came up within {wall_cap}s");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Spawn a daemon against `servers` (host:port pairs) and return it.
async fn chaos_daemon(dir: &Path, cfg: &Path, servers: &[std::net::SocketAddr]) -> Daemon {
    let servers_json = servers
        .iter()
        .map(|a| {
            format!(
                "{{\"host\":\"{}\",\"port\":{},\"tls\":false}}",
                a.ip(),
                a.port()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(cfg, format!("{{\"servers\":[{servers_json}]}}")).unwrap();
    let cfg = cfg.to_path_buf();
    let out = dir.join("complete");
    serve(dir, move |port| {
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
            .arg("--out")
            .arg(&out)
            .arg("--connections")
            .arg("4");
        c
    })
    .await
}

/// One measured scenario: shared setup, per-scenario chaos, one line of
/// output. `after_start` runs once the daemon is up (fault scheduling,
/// oscillators). `seek_at` optionally plays from the start for that many
/// seconds, then drops the connection and seeks to 60% (a fresh Range
/// request), recording the seek's own arrival curve instead.
struct Scenario {
    name: &'static str,
    movie_mb: usize,
    chaos: Chaos,
    twin: Option<Chaos>,
    wall_cap: f64,
    idle_cap: f64,
    seek_at: Option<f64>,
}

impl Default for Scenario {
    fn default() -> Self {
        Scenario {
            name: "",
            movie_mb: 36,
            chaos: Chaos::default(),
            twin: None,
            wall_cap: 120.0,
            idle_cap: 45.0,
            seek_at: None,
        }
    }
}

async fn run_scenario(sc: Scenario, oscillate: bool) -> serde_json::Value {
    let dir =
        std::env::temp_dir().join(format!("nzbfast-chaos-{}-{}", sc.name, std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (xml, articles, _inner) = movie_corpus(sc.movie_mb * 1_000_000);
    let srv = MockServer::start(articles.clone(), sc.chaos.clone()).await;
    let twin = match &sc.twin {
        Some(c) => Some(MockServer::start(articles.clone(), c.clone()).await),
        None => None,
    };
    let mut addrs = vec![srv.addr];
    if let Some(t) = &twin {
        addrs.push(t.addr);
    }
    let cfg = dir.join("config.json");
    let d = chaos_daemon(&dir, &cfg, &addrs).await;
    let port = d.port;

    // Bandwidth oscillation: 6 s at the configured line, 6 s at a
    // quarter of the playback bitrate, forever.
    let osc_handle = oscillate.then(|| {
        let line = srv.line_control();
        let base = sc.chaos.throttle.line_bps;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                line.set_line_bps(BITRATE_BPS / 4);
                tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                line.set_line_bps(base);
            }
        })
    });

    let name = sc.name;
    let wall_cap = sc.wall_cap;
    let idle_cap = sc.idle_cap;
    let seek_at = sc.seek_at;
    let movie_bytes = (sc.movie_mb * 1_000_000) as u64;
    let out = tokio::task::spawn_blocking(move || {
        let t_add = std::time::Instant::now();
        upload_nzb(port, &xml);
        let up_secs = wait_stream_up(port, 60.0);
        let _ = t_add;

        let (curve, seek_curve) = match seek_at {
            None => (record_stream(port, "/stream", wall_cap, idle_cap), None),
            Some(play_secs) => {
                // Play from the head for `play_secs`, then abandon that
                // request (players close the old one) and seek to 60%.
                use std::io::{Read as _, Write as _};
                let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
                s.set_read_timeout(Some(std::time::Duration::from_millis(250)))
                    .unwrap();
                s.write_all(b"GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .unwrap();
                let head_start = std::time::Instant::now();
                let mut buf = vec![0u8; 256 * 1024];
                while head_start.elapsed().as_secs_f64() < play_secs {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(_) => break,
                    }
                }
                drop(s);
                let pos = movie_bytes * 3 / 5;
                let path = "/stream";
                let started = std::time::Instant::now();
                let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
                s.set_read_timeout(Some(std::time::Duration::from_millis(250)))
                    .unwrap();
                let req = format!(
                    "GET {path} HTTP/1.1\r\nHost: x\r\nRange: bytes={pos}-\r\nConnection: close\r\n\r\n"
                );
                s.write_all(req.as_bytes()).unwrap();
                // Record the seek stream's curve by hand off this socket.
                let mut curve = ArrivalCurve {
                    samples: Vec::new(),
                    expect: 0,
                    ttfb: None,
                    status: String::new(),
                    truncated: false,
                    body: Vec::new(),
                };
                let mut headbuf = Vec::new();
                let mut header_done = false;
                let mut body: u64 = 0;
                let mut last_progress = std::time::Instant::now();
                loop {
                    let now = started.elapsed().as_secs_f64();
                    if now > wall_cap || last_progress.elapsed().as_secs_f64() > idle_cap {
                        curve.truncated = true;
                        break;
                    }
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            last_progress = std::time::Instant::now();
                            let t = started.elapsed().as_secs_f64();
                            let mut payload = &buf[..n];
                            if !header_done {
                                headbuf.extend_from_slice(payload);
                                if let Some(p) =
                                    headbuf.windows(4).position(|w| w == b"\r\n\r\n")
                                {
                                    let txt =
                                        String::from_utf8_lossy(&headbuf[..p]).to_string();
                                    curve.status =
                                        txt.lines().next().unwrap_or("").to_string();
                                    for l in txt.lines() {
                                        if let Some(v) = l
                                            .to_ascii_lowercase()
                                            .strip_prefix("content-length:")
                                        {
                                            curve.expect = v.trim().parse().unwrap_or(0);
                                        }
                                    }
                                    let already = headbuf.len() - (p + 4);
                                    header_done = true;
                                    if already > 0 {
                                        curve.ttfb = Some(t);
                                        body = already as u64;
                                        curve.samples.push((t, body));
                                    }
                                }
                                payload = &[];
                            }
                            if header_done && !payload.is_empty() {
                                if curve.ttfb.is_none() {
                                    curve.ttfb = Some(t);
                                }
                                body += payload.len() as u64;
                                curve.samples.push((t, body));
                            }
                            if curve.expect > 0 && body >= curve.expect {
                                break;
                            }
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    }
                }
                (curve, Some(started.elapsed().as_secs_f64()))
            }
        };
        (up_secs, curve, seek_curve)
    })
    .await
    .unwrap();
    if let Some(h) = osc_handle {
        h.abort();
    }
    let (up_secs, curve, _seek_dur) = out;
    let stats = simulate_playback(&curve, BITRATE_BPS, PREBUFFER_SECS);
    let gaps = arrival_gaps(&curve);
    let gaps_json: Vec<serde_json::Value> = gaps
        .iter()
        .map(|(at, dur)| serde_json::json!({"at": (at * 10.0).round() / 10.0, "dur": (dur * 10.0).round() / 10.0}))
        .collect();
    let r1 = |v: f64| (v * 100.0).round() / 100.0;
    let m = serde_json::json!({
        "scenario": name,
        "status": curve.status,
        "stream_up_secs": r1(up_secs),
        "ttfb": curve.ttfb.map(r1),
        "bytes": curve.samples.last().map(|(_, b)| *b).unwrap_or(0),
        "expect": curve.expect,
        "truncated": curve.truncated,
        "start_delay": r1(stats.start_delay),
        "rebuffers": stats.rebuffers,
        "rebuffer_total": r1(stats.rebuffer_total),
        "rebuffer_longest": r1(stats.rebuffer_longest),
        "played_secs": r1(stats.played_secs),
        "gaps": gaps_json,
    });
    println!("MEASURE {m}");
    m
}

// ---------------------------------------------------------------------------
// The measurement matrix (#[ignore]d - run explicitly, see module docs)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement harness - minutes long, run explicitly"]
async fn chaos_matrix_low_bandwidth_below_bitrate() {
    // Line capped at 0.6x the playback bitrate: playback CANNOT keep up;
    // the question is how the pain is distributed (few long rebuffers vs
    // constant stutter) and how fast play starts.
    run_scenario(
        Scenario {
            name: "low_below",
            chaos: Chaos {
                throttle: nzbkit::mock::Throttle {
                    line_bps: BITRATE_BPS * 6 / 10,
                    ..Default::default()
                },
                ..Default::default()
            },
            movie_mb: 24,
            wall_cap: 90.0,
            ..Default::default()
        },
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement harness - minutes long, run explicitly"]
async fn chaos_matrix_low_bandwidth_just_above() {
    // Line at 1.3x bitrate: playback CAN keep up if buffering is smart.
    run_scenario(
        Scenario {
            name: "low_above",
            chaos: Chaos {
                throttle: nzbkit::mock::Throttle {
                    line_bps: BITRATE_BPS * 13 / 10,
                    ..Default::default()
                },
                ..Default::default()
            },
            movie_mb: 24,
            wall_cap: 60.0,
            ..Default::default()
        },
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement harness - minutes long, run explicitly"]
async fn chaos_matrix_oscillating_bandwidth() {
    // 6 s at 2x bitrate, 6 s at bitrate/4 - the congested-evening shape.
    // Long-run average = 1.125x bitrate, so smart buffering can survive.
    run_scenario(
        Scenario {
            name: "oscillate",
            chaos: Chaos {
                throttle: nzbkit::mock::Throttle {
                    line_bps: BITRATE_BPS * 2,
                    ..Default::default()
                },
                ..Default::default()
            },
            movie_mb: 24,
            wall_cap: 90.0,
            ..Default::default()
        },
        true,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement harness - minutes long, run explicitly"]
async fn chaos_matrix_per_connection_stalls() {
    // Dead-air articles mid-queue + one degraded session: the shape
    // adaptive timeouts + race_stragglers exist for. Healthy line rate.
    let (_, articles, _) = movie_corpus(24_000_000);
    let ids = corpus_ids(&articles);
    let victims: std::collections::HashSet<String> = ids
        .iter()
        .skip(ids.len() * 3 / 10)
        .step_by(7)
        .take(10)
        .cloned()
        .collect();
    run_scenario(
        Scenario {
            name: "stalls",
            chaos: Chaos {
                stall_pre: victims,
                slow_conn: Some((2, 40_000)),
                throttle: nzbkit::mock::Throttle {
                    line_bps: BITRATE_BPS * 3,
                    ..Default::default()
                },
                ..Default::default()
            },
            movie_mb: 24,
            wall_cap: 90.0,
            ..Default::default()
        },
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement harness - minutes long, run explicitly"]
async fn chaos_matrix_connection_drops() {
    // Server drops every connection after 12 bodies: constant reconnect
    // churn on a line just above bitrate.
    run_scenario(
        Scenario {
            name: "drops",
            chaos: Chaos {
                drop_after: 12,
                throttle: nzbkit::mock::Throttle {
                    line_bps: BITRATE_BPS * 3 / 2,
                    ..Default::default()
                },
                ..Default::default()
            },
            movie_mb: 24,
            wall_cap: 90.0,
            ..Default::default()
        },
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement harness - minutes long, run explicitly"]
async fn chaos_matrix_high_latency() {
    // 400 ms before every body on a fat line - the far-away-server
    // shape. Per-connection throughput = article/delay; the pool's
    // pipelining is what keeps this fast, and stream mode caps the
    // pipeline, so this is the scenario that prices stream_window=1.
    run_scenario(
        Scenario {
            name: "latency",
            chaos: Chaos {
                delay_ms: 400,
                ..Default::default()
            },
            movie_mb: 24,
            wall_cap: 90.0,
            ..Default::default()
        },
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement harness - minutes long, run explicitly"]
async fn chaos_matrix_brownout_with_clean_twin() {
    // Faulty server goes permanently mute after 40% of its bodies; a
    // clean twin holds everything. Measures failover recovery time.
    let (_, articles, _) = movie_corpus(24_000_000);
    let n = articles.len() as u64;
    run_scenario(
        Scenario {
            name: "brownout_twin",
            chaos: Chaos {
                brownout_after: n * 2 / 5,
                throttle: nzbkit::mock::Throttle {
                    line_bps: BITRATE_BPS * 2,
                    ..Default::default()
                },
                ..Default::default()
            },
            twin: Some(Chaos {
                throttle: nzbkit::mock::Throttle {
                    line_bps: BITRATE_BPS * 2,
                    ..Default::default()
                },
                ..Default::default()
            }),
            movie_mb: 24,
            wall_cap: 90.0,
            ..Default::default()
        },
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement harness - minutes long, run explicitly"]
async fn chaos_matrix_missing_articles() {
    // A handful of articles 430 everywhere (single server, no par2):
    // unrecoverable bytes inside the played file. Today's behaviour is
    // the baseline this scenario exists to expose.
    let (_, articles, _) = movie_corpus(24_000_000);
    let ids = corpus_ids(&articles);
    let missing: std::collections::HashSet<String> =
        ids.iter().skip(ids.len() / 2).take(3).cloned().collect();
    run_scenario(
        Scenario {
            name: "missing",
            chaos: Chaos {
                missing,
                throttle: nzbkit::mock::Throttle {
                    line_bps: BITRATE_BPS * 3,
                    ..Default::default()
                },
                ..Default::default()
            },
            movie_mb: 24,
            wall_cap: 90.0,
            idle_cap: 30.0,
            ..Default::default()
        },
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement harness - minutes long, run explicitly"]
async fn chaos_matrix_seek_under_low_bandwidth() {
    // Play 8 s from the head on a line just above bitrate, then seek to
    // 60% - the number reported is the seek stream's TTFB (how long the
    // viewer stares at a spinner after scrubbing).
    run_scenario(
        Scenario {
            name: "seek_low",
            chaos: Chaos {
                throttle: nzbkit::mock::Throttle {
                    line_bps: BITRATE_BPS * 13 / 10,
                    ..Default::default()
                },
                ..Default::default()
            },
            movie_mb: 24,
            wall_cap: 90.0,
            seek_at: Some(8.0),
            ..Default::default()
        },
        false,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Chaos regression tests (part of the normal daemon gate)
// ---------------------------------------------------------------------------

/// A blocked read stops holding out for the full 16 MB runway once the
/// cursor bytes have landed: on a line where 16 MB takes over a minute,
/// the head of the file must reach the player within seconds, not after
/// the runway drains (measured 31 s at 0.6 MB/s before the wait cap).
#[tokio::test(flavor = "multi_thread")]
async fn stream_runway_wait_is_time_capped_on_slow_lines() {
    let dir = std::env::temp_dir().join(format!("nzbfast-runwaycap-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    // 250 KB/s line: the old behavior waits 16 MB / 250 KB/s = 64 s
    // before the first blocked read returns; the capped wait returns
    // after ~3 s with whatever landed.
    let (xml, articles, inner) = movie_corpus(8_000_000);
    let srv = MockServer::start(
        articles,
        Chaos {
            throttle: nzbkit::mock::Throttle {
                line_bps: 250_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cfg = dir.join("config.json");
    let d = chaos_daemon(&dir, &cfg, &[srv.addr]).await;
    let port = d.port;
    let log = d.log_path();
    tokio::task::spawn_blocking(move || {
        upload_nzb(port, &xml);
        wait_stream_up(port, 60.0);
        let started = std::time::Instant::now();
        let curve = record_stream(port, "/stream", 40.0, 30.0);
        let daemon_log = std::fs::read_to_string(&log).unwrap_or_default();
        // The proof is the first megabyte's arrival time, not the whole
        // body: 1 MB needs ~4 s of line plus the capped wait. 20 s is a
        // 2x margin over the worst honest path and a 3x improvement on
        // the uncapped wait, so it cannot pass by accident.
        let mb_at = curve
            .samples
            .iter()
            .find(|(_, b)| *b >= 1_000_000)
            .map(|(t, _)| *t)
            .unwrap_or(f64::MAX);
        // On failure, the arrival timeline is the diagnosis.
        let timeline: Vec<String> = curve
            .samples
            .iter()
            .step_by(4.max(curve.samples.len() / 24))
            .map(|(t, b)| format!("{t:.1}s:{}K", b / 1000))
            .collect();
        assert!(
            mb_at < 20.0,
            "first MB took {mb_at:.1}s (uncapped-runway behavior); status={} started={:?} timeline={}\n--- daemon log tail ---\n{}",
            curve.status,
            started.elapsed(),
            timeline.join(" "),
            &daemon_log[daemon_log.len().saturating_sub(4000)..]
        );
        // And the bytes that did arrive are the real payload.
        let n = curve.samples.last().map(|(_, b)| *b).unwrap_or(0) as usize;
        assert!(n >= 1_000_000, "only {n} bytes arrived");
        let _ = inner;
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The zero-fill contract, shared by the two tests below: the body
/// completed, everything outside the hole is the real payload, and the
/// hole itself is zeros - never garbage, never a truncated response.
/// `log` is the daemon's log path - its tail is the diagnosis when the
/// contract fails.
fn assert_zero_filled_body(curve: &ArrivalCurve, inner: &[u8], log: &Path) {
    let daemon_log = std::fs::read_to_string(log).unwrap_or_default();
    let tail = &daemon_log[daemon_log.len().saturating_sub(4000)..];
    let got = curve.samples.last().map(|(_, b)| *b).unwrap_or(0);
    assert_eq!(
        got, curve.expect,
        "stream truncated at {got}/{} (status={})\n--- daemon log tail ---\n{tail}",
        curve.expect, curve.status
    );
    assert_eq!(curve.body.len(), inner.len(), "body/payload length");
    let mut wrong = 0u64;
    let (mut first_bad, mut last_bad) = (usize::MAX, 0usize);
    for (i, (g, w)) in curve.body.iter().zip(inner.iter()).enumerate() {
        if g != w {
            assert_eq!(*g, 0, "non-zero garbage at {i}: {g:#x} (want {w:#x})");
            wrong += 1;
            first_bad = first_bad.min(i);
            last_bad = i;
        }
    }
    // Two 300 KB articles went missing; the zero-filled hole must be in
    // their neighbourhood and bounded - not a wholesale zeroing.
    assert!(wrong > 0, "no hole at all - the fault never engaged");
    assert!(
        wrong <= 1_200_000,
        "zeroed {wrong} bytes - far more than the missing articles"
    );
    assert!(
        first_bad > inner.len() / 4 && last_bad < inner.len() * 9 / 10,
        "hole [{first_bad}, {last_bad}] not where the missing articles were"
    );
}

/// Articles that are terminally missing inside a played file zero-fill
/// after a bounded wait instead of stalling the reader for 5 minutes:
/// degraded playback beats a hang for a preview. Throttled so the fetch
/// run is still attached when the reader reaches the hole - this is the
/// mid-run verdict (nothing pending or in flight carries the span).
#[tokio::test(flavor = "multi_thread")]
async fn stream_zero_fills_terminally_missing_articles() {
    let dir = std::env::temp_dir().join(format!("nzbfast-zerofill-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (xml, articles, inner) = movie_corpus(8_000_000);
    let ids = corpus_ids(&articles);
    // Two mid-file articles 430 on the only server: unrecoverable.
    let missing: std::collections::HashSet<String> =
        ids.iter().skip(ids.len() / 2).take(2).cloned().collect();
    let srv = MockServer::start(
        articles,
        Chaos {
            missing,
            throttle: nzbkit::mock::Throttle {
                line_bps: 400_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cfg = dir.join("config.json");
    let d = chaos_daemon(&dir, &cfg, &[srv.addr]).await;
    let port = d.port;
    let log = d.log_path();
    tokio::task::spawn_blocking(move || {
        upload_nzb(port, &xml);
        wait_stream_up(port, 60.0);
        // 8 MB at 400 KB/s = a ~20 s fetch; the reader meets the hole
        // around 10 s in, votes for ~7 s, and the rest streams - all
        // far inside the old 300 s stall.
        let curve = record_stream(port, "/stream", 120.0, 60.0);
        assert_zero_filled_body(&curve, &inner, &log);
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same hole met AFTER the fetch run has drained and detached: no
/// pool can answer for the span any more, so the reader gives
/// settle-side repair a bounded window (shrunk via env here) and then
/// zero-fills. Without the window logic this is a 300 s stall per read.
#[tokio::test(flavor = "multi_thread")]
async fn stream_zero_fills_after_the_run_detaches() {
    let dir = std::env::temp_dir().join(format!("nzbfast-zerofill2-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let (xml, articles, inner) = movie_corpus(6_000_000);
    let ids = corpus_ids(&articles);
    let missing: std::collections::HashSet<String> =
        ids.iter().skip(ids.len() / 2).take(2).cloned().collect();
    let srv = MockServer::start(
        articles,
        Chaos {
            missing,
            ..Default::default()
        },
    )
    .await;
    let cfg = dir.join("config.json");
    let servers_json = format!(
        "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
        srv.addr.ip(),
        srv.addr.port()
    );
    std::fs::write(&cfg, servers_json).unwrap();
    let cfg2 = cfg.clone();
    let out = dir.join("complete");
    let d = serve(&dir, move |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // Shrink the repair window so the test does not sit through
            // the 15 s default; the mechanism is the same.
            .env("NZBFAST_STREAM_DEAD_GRACE_MS", "3000")
            .arg("--config")
            .arg(&cfg2)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(&out)
            .arg("--connections")
            .arg("4");
        c
    })
    .await;
    let port = d.port;
    let log = d.log_path();
    tokio::task::spawn_blocking(move || {
        upload_nzb(port, &xml);
        wait_stream_up(port, 60.0);
        // Unthrottled: the fetch drains in a couple of seconds, so the
        // reader is parked at the hole with NO pool attached. It must
        // come back zero-filled within grace+votes, not at 300 s.
        let curve = record_stream(port, "/stream", 90.0, 45.0);
        assert_zero_filled_body(&curve, &inner, &log);
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
