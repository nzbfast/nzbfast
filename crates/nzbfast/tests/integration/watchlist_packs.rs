#![cfg(feature = "indexer")]
//! M23e end to end: the two shapes of post a watchlist item used to be
//! blind to, driven through a real daemon over its own API.
//!
//! Both are decided inside `watchlist_pass`, a private function over the
//! live index, so the only honest test is a daemon with a seeded index:
//! set a watch item, ask for a pass, and read the queue it built.
//!
//! - A SEASON PACK ("Show.S02.1080p.WEB") fills the season's slot, and
//!   the single episodes it covers stand down rather than being
//!   downloaded a second time.
//! - A DAILY show ("The.Daily.Show.2026.07.21") gets one slot per night.
//!   Before the date reached the slot key these posts filled no slot at
//!   all, so a watched daily show quietly grabbed nothing forever.
//!
//! The harness is the shape tests/integration/pull_search.rs uses -
//! copied, not shared, because nzbfast is a binary-only crate and
//! integration tests cannot import from each other.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::{Daemon, serve};

use nzbkit::nntp::OverEntry;

/// (status, body) of a GET; connection refusals retried, answers never.
fn http_get(port: u16, req: &str) -> (u16, String) {
    let msg = format!("GET {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, &msg) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

fn http_once(port: u16, msg: &str) -> std::io::Result<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(msg.as_bytes())?;
    let mut out = String::new();
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    let status: u16 = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((
        status,
        out.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    ))
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn over(number: u64, subject: &str, msgid: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        message_id: msgid.into(),
        bytes,
        date: 1_700_000_000,
    }
}

/// One complete release: the payload and its par2 sidecar, which is what
/// the indexer needs to call a release complete - and the watchlist only
/// ever considers complete releases.
fn release(n: u64, stem: &str) -> Vec<OverEntry> {
    vec![
        over(
            n,
            &format!("\"{stem}.rar\" yEnc (1/1)"),
            &format!("<p{n}@x>"),
            40_000,
        ),
        over(
            n + 1,
            &format!("\"{stem}.par2\" yEnc (1/1)"),
            &format!("<q{n}@x>"),
            400,
        ),
    ]
}

/// A daemon over a seeded index and a dead news server: grabs reach the
/// queue, which is what these tests read, and never leave it.
fn daemon_cmd(dir: &Path, cfg: &Path, db: &Path, port: u16) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    c.env("NZBFAST_OPEN", "1")
        .env("NZBFAST_NO_ENRICH", "1")
        .arg("--config")
        .arg(cfg)
        .arg("serve")
        // Loopback only - see tests/integration/newznab.rs on the macOS
        // firewall.
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--out")
        .arg(dir.join("complete"))
        .arg("--index-db")
        .arg(db);
    c
}

/// Seed an index, start a daemon on it, and install `items` as the
/// watchlist. Returns the running daemon.
async fn watching(dir: &Path, seed: &[OverEntry], items: &str) -> Daemon {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest("alt.binaries.teevee", seed, 1_700_000_000)
            .unwrap();
    }
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    // These cases drive the watchlist's LOCAL leg against a seeded
    // index, and the built-in indexer's master switch defaults OFF -
    // with it off the daemon will not open that database at all. So say
    // so; settings.json lives beside the config file.
    std::fs::write(
        cfg.with_file_name("settings.json"),
        "{\"index_enabled\": true}",
    )
    .unwrap();
    let d = serve(dir, |port| daemon_cmd(dir, &cfg, &db, port)).await;
    let port = d.port;
    let items = items.to_string();
    tokio::task::spawn_blocking(move || {
        let (_, r) = http_get(
            port,
            &format!(
                "/api?mode=config&name=watchlist&value={}&output=json",
                pct(&items)
            ),
        );
        assert!(r.contains("true"), "watchlist not accepted: {r}");
        http_get(port, "/api?mode=watchlist_check_now&output=json");
    })
    .await
    .unwrap();
    d
}

/// Everything the daemon has been asked to download: the queue AND the
/// history. It has to be both - the news server these tests point at is
/// dead, so a grab can fail out of the queue and into history before the
/// next poll, and "is it in the queue right now" is a race.
fn grabbed(port: u16) -> String {
    let (_, q) = http_get(port, "/api?mode=queue&output=json");
    let (_, h) = http_get(port, "/api?mode=history&output=json");
    format!("{q}\n{h}")
}

/// Wait until every needle has been grabbed, then return what the daemon
/// has - so a caller can also assert on what is NOT there. Needles are
/// accumulated across polls, not required to be present at one instant.
fn grabbed_all(port: u16, needles: &[&str]) -> String {
    let mut seen = vec![false; needles.len()];
    let mut last = String::new();
    for _ in 0..60 {
        last = grabbed(port);
        for (i, n) in needles.iter().enumerate() {
            seen[i] |= last.contains(n);
        }
        if seen.iter().all(|s| *s) {
            return last;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    for (i, n) in needles.iter().enumerate() {
        assert!(seen[i], "{n} was never grabbed:\n{last}");
    }
    last
}

/// The watchlist's own record of what it has: the durable answer, and
/// the one that survives a job moving on to history.
fn slots(port: u16) -> String {
    http_get(port, "/api?mode=watchlist_status&output=json").1
}

/// The slot record, once every named slot is in it. Polled, because the
/// watcher publishes its state at the END of a pass: the jobs it grabbed
/// are in the queue for a moment before the slots that own them are
/// visible, and reading once caught the pass's opening snapshot.
fn slots_with(port: u16, needles: &[&str]) -> String {
    let mut last = String::new();
    for _ in 0..60 {
        last = slots(port);
        if needles.iter().all(|n| last.contains(n)) {
            return last;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    for n in needles {
        assert!(
            last.contains(n),
            "no slot for {n} was ever recorded: {last}"
        );
    }
    last
}

/// A season pack fills the whole season, and the single episodes it
/// covers are NOT downloaded on top of it. Before packs had a slot the
/// pack was invisible to the watchlist and only the 720p single was
/// grabbed - a worse copy of one episode instead of the season.
#[tokio::test(flavor = "multi_thread")]
async fn a_season_pack_fills_the_season_and_its_episodes_stand_down() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlpack-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mut seed = release(1, "Wanted.Show.S02.1080p.WEB");
    seed.extend(release(10, "Wanted.Show.S02E05.720p.HDTV"));
    let d = watching(
        &dir,
        &seed,
        r#"[{"id":1,"kind":"tv","title":"Wanted Show","seasons":"","episodes":"",
             "min_quality":"any","target_quality":"1080p","enabled":true}]"#,
    )
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        grabbed_all(port, &["Wanted.Show.S02.1080p.WEB"]);
        // The season's slot is what the pack filled, not an episode's.
        let st = slots_with(port, &["\"slot\":\"s02\""]);
        assert!(
            !st.contains("s02e05"),
            "the covered episode took a slot of its own: {st}"
        );
        // Give the pass room to make the second (wrong) decision too, so
        // this cannot pass merely by reading the queue too early.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let seen = grabbed(port);
        assert!(
            !seen.contains("S02E05"),
            "an episode the pack already covers was downloaded again:\n{seen}"
        );
    })
    .await
    .unwrap();
}

/// A daily show gets one slot per night, so every night is grabbed.
/// Keyed on the title alone (no episode marker exists) these posts
/// filled no slot at all and the item grabbed nothing, ever.
#[tokio::test(flavor = "multi_thread")]
async fn a_daily_show_grabs_every_night() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wldaily-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mut seed = release(1, "The.Daily.Show.2026.07.21.1080p.WEB.h264-GRP");
    seed.extend(release(10, "The.Daily.Show.2026.07.22.1080p.WEB.h264-GRP"));
    let d = watching(
        &dir,
        &seed,
        r#"[{"id":1,"kind":"tv","title":"The Daily Show","seasons":"","episodes":"",
             "min_quality":"any","target_quality":"1080p","enabled":true}]"#,
    )
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        grabbed_all(port, &["2026.07.21", "2026.07.22"]);
        // Two nights, two slots - not one slot grabbed twice.
        slots_with(port, &["d:20260721", "d:20260722"]);
    })
    .await
    .unwrap();
}
