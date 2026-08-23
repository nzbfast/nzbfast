//! Opt-in indexing, end to end: the answer a user gives the setup wizard
//! (or the settings card) becomes a scan list, and never anything else.
//!
//! The property under test is a promise made to users: nzbfast indexes
//! NOTHING it was not asked to index. So the interesting assertions here
//! are the negative ones - an untouched install scans nothing, an
//! unrecognised answer resolves to nothing, and unticking removes only
//! what ticking added.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::Daemon;

/// Response body of a request to the daemon (headers stripped).
///
/// A request that produced NO bytes at all is retried. tiny_http's honest
/// answer when it cannot start a thread for a new connection is to drop
/// the socket unread, and with our request still sitting in its receive
/// buffer the kernel turns that into an RST - which arrives here as
/// ECONNRESET, not as a clean EOF. A full `cargo test -p nzbfast` runs
/// this suite alongside every other daemon suite, so
/// `thread::Builder::spawn` really does hit EAGAIN: this file was failing
/// `ticking_and_unticking_are_symmetric` on the read below, roughly 1 run
/// in 8, on a refusal to serve rather than on anything it asserts.
///
/// Once a byte has come back it is an answer and is returned exactly as it
/// arrived - a truncated response must never be retried away. Same rule as
/// daemon.rs's helper; see [[nzbfast-daemon-test-harness]].
///
/// DELIBERATELY DOES NOT DE-CHUNK, which is only safe because of what this
/// file asks for. tiny_http switches to `Transfer-Encoding: chunked` above
/// 32 KB, and a chunked body read as one blob keeps its hex chunk headers
/// inline. Every request here is a small `/api?mode=config` or
/// `mode=get_config` - measured at 27 and 3355 bytes, both answered with a
/// Content-Length - so nothing chunks. Add a request that returns anything
/// big (the dashboard `/` is ~490 KB and DOES chunk) and this helper must
/// grow the de-chunking that http_wedge.rs's did, or the body silently
/// gains chunk headers. Reading into bytes and going through
/// `from_utf8_lossy` also keeps the related hazard away: `read_to_string`
/// over a chunked response dies on "stream did not contain valid UTF-8"
/// when a chunk header splits a multi-byte character.
fn http(port: u16, req: &str) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req) {
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

/// One attempt. Err ONLY when the daemon produced nothing at all.
fn http_once(port: u16, req: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )?;
    let mut out = Vec::new();
    // Zero bytes back is a refusal to serve, however the peer phrased it:
    // an RST (Err) when our request was never read off the receive buffer,
    // a plain FIN (Ok) when it was read and then dropped unanswered.
    // Neither carries anything to judge, so both are retried.
    let read = s.read_to_end(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    let out = String::from_utf8_lossy(&out).to_string();
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn api(port: u16, q: &str) -> serde_json::Value {
    let body = http(port, &format!("/api?output=json&apikey=sekrit&{q}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{body}"))
}

fn set(port: u16, name: &str, value: &str) {
    let enc: String = value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    let r = api(port, &format!("mode=config&name={name}&value={enc}"));
    assert_eq!(r["status"], true, "set {name}={value}: {r}");
}

fn groups(port: u16) -> Vec<String> {
    api(port, "mode=get_config")["config"]["nzbfast"]["index_groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect()
}

/// A scratch install whose group catalogue is already "fetched": the
/// daemon loads `groups.tsv` beside the index db at startup, which is
/// the same cache a real fetch writes. That is what lets this test
/// resolve interests without a provider.
fn scratch(name: &str, carried: &[&str], settings: &str) -> scratch::ScratchDir {
    let dir = std::env::temp_dir().join(format!("nzbfast-interests-{}-{name}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    std::fs::write(dir.join("settings.json"), settings).unwrap();
    let mut tsv = String::from("#nzbfast-groups\t3\t1700000000\n");
    for g in carried {
        tsv.push_str(&format!("{g}\t1000000\t1700000000\ty\t\n"));
    }
    std::fs::write(dir.join("groups.tsv"), tsv).unwrap();
    dir
}

fn serve(dir: &Path) -> Daemon {
    crate::harness::serve_blocking(dir, |port| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        cmd.env("NZBFAST_NO_ENRICH", "1")
            .env_remove("NZBFAST_OPEN")
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(dir.join("index.db"));
        cmd
    })
}

/// Wait for the startup task to turn the stored answer into groups. It
/// runs off a background task, so poll rather than sleep a fixed time.
fn wait_groups(port: u16, want: usize) -> Vec<String> {
    for _ in 0..100 {
        let g = groups(port);
        if g.len() >= want {
            return g;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    groups(port)
}

/// settings.json as it stands on disk right now.
fn saved(dir: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(dir.join("settings.json")).unwrap_or_default();
    serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
}

/// Poll settings.json until `key` is present, or give up. Applying an
/// interest runs off a background task, so this is a rendezvous, not a
/// sleep - and it is bounded, so a daemon that never writes fails the
/// assertion instead of hanging the suite.
fn wait_saved(dir: &Path, key: &str) -> serde_json::Value {
    for _ in 0..100 {
        let v = saved(dir);
        if !v[key].is_null() {
            return v;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    saved(dir)
}

/// The whole promise in one test: an install nobody has answered for
/// scans nothing at all, no matter how long it runs.
#[test]
fn an_unanswered_install_indexes_nothing() {
    let dir = scratch(
        "unanswered",
        &["alt.binaries.teevee", "alt.binaries.moovee"],
        "{}",
    );
    let d = serve(&dir);
    // Give the startup path the same window the answered case needs.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(
        groups(d.port).is_empty(),
        "something was indexed without being asked for"
    );
    let j = api(d.port, "mode=interests");
    assert!(j["chosen"].as_array().unwrap().is_empty());
    // Every option is offered with the groups it stands for, so a UI can
    // show them before the user agrees to anything.
    let opts = j["options"].as_array().unwrap();
    assert!(opts.len() >= 5, "{j}");
    let linux = opts
        .iter()
        .find(|o| o["key"] == "linux")
        .expect("linux offered");
    assert!(!linux["groups"].as_array().unwrap().is_empty());
    assert_eq!(linux["scanning"], 0);
}

/// The wizard's answer, applied at startup from a catalogue that is
/// already on disk - the first-run order of events, since the wizard
/// runs before the daemon has ever connected.
#[test]
fn a_stored_answer_becomes_a_scan_list() {
    let dir = scratch(
        "answered",
        // The provider carries two of the four Linux groups and one of
        // the sport ones. Nothing else may be subscribed.
        &[
            "alt.binaries.linux.iso",
            "alt.binaries.linux",
            "alt.binaries.multimedia.sports",
            "alt.binaries.teevee",
        ],
        r#"{"index_interests":"linux,sports"}"#,
    );
    let d = serve(&dir);
    let g = wait_groups(d.port, 3);
    assert!(g.contains(&"alt.binaries.linux.iso".to_string()), "{g:?}");
    assert!(g.contains(&"alt.binaries.linux".to_string()), "{g:?}");
    assert!(
        g.contains(&"alt.binaries.multimedia.sports".to_string()),
        "{g:?}"
    );
    // Not the groups this provider does not carry...
    assert!(
        !g.contains(&"a.b.cd.image.linux".to_string()),
        "a dead group was subscribed: {g:?}"
    );
    // ...and emphatically not a TV group nobody asked for, even though
    // the provider has it and it is what the old one-click shortcut
    // would have picked.
    assert!(!g.contains(&"alt.binaries.teevee".to_string()), "{g:?}");
}

/// Ticking and unticking from the settings card, including the part
/// that matters most: unticking must not take a hand-typed group with
/// it, and answering "nothing" must leave nothing behind.
#[test]
fn ticking_and_unticking_are_symmetric() {
    let dir = scratch(
        "symmetric",
        &[
            "alt.binaries.linux.iso",
            "alt.binaries.multimedia.sports",
            "alt.binaries.mine",
        ],
        "{}",
    );
    let d = serve(&dir);
    set(d.port, "index_groups", "alt.binaries.mine");

    set(d.port, "index_interests", "linux");
    let g = wait_groups(d.port, 2);
    assert!(g.contains(&"alt.binaries.linux.iso".to_string()), "{g:?}");

    set(d.port, "index_interests", "linux,sports");
    let g = wait_groups(d.port, 3);
    assert!(
        g.contains(&"alt.binaries.multimedia.sports".to_string()),
        "{g:?}"
    );

    // Unticking sport stops scanning sport, and only sport.
    set(d.port, "index_interests", "linux");
    std::thread::sleep(std::time::Duration::from_millis(400));
    let g = groups(d.port);
    assert!(
        !g.contains(&"alt.binaries.multimedia.sports".to_string()),
        "{g:?}"
    );
    assert!(g.contains(&"alt.binaries.linux.iso".to_string()), "{g:?}");
    assert!(
        g.contains(&"alt.binaries.mine".to_string()),
        "a hand-picked group was removed: {g:?}"
    );

    // Answering "nothing at all" leaves only what the user typed.
    set(d.port, "index_interests", "");
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert_eq!(groups(d.port), vec!["alt.binaries.mine".to_string()]);

    // An unrecognised answer resolves to nothing rather than to
    // something - the failure direction that matters.
    set(d.port, "index_interests", "everything,all,*");
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert_eq!(groups(d.port), vec!["alt.binaries.mine".to_string()]);
    assert!(
        api(d.port, "mode=interests")["chosen"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// What ticking an interest has to leave on disk. The scan list, the
/// record of which groups the preset owns, and the marker saying the
/// answer has been applied are one state: the marker means "these two
/// are already correct". Written separately, a failure between them
/// leaves a marker with no groups behind it, and the answer is then
/// never reconsidered - the interest is silently dropped for good.
#[test]
fn ticking_an_interest_records_groups_provenance_and_marker_together() {
    let dir = scratch(
        "persisted",
        &["alt.binaries.linux.iso", "alt.binaries.mine"],
        "{}",
    );
    let d = serve(&dir);
    set(d.port, "index_groups", "alt.binaries.mine");
    set(d.port, "index_interests", "linux");
    assert!(wait_groups(d.port, 2).contains(&"alt.binaries.linux.iso".to_string()));

    let s = wait_saved(&dir, "index_interests_applied");
    assert_eq!(s["index_interests_applied"], "linux", "{s}");
    let listed = |k: &str| -> Vec<String> {
        s[k].as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect()
    };
    assert!(
        listed("index_groups").contains(&"alt.binaries.linux.iso".to_string()),
        "the scan list must be on disk beside its marker: {s}"
    );
    assert_eq!(
        listed("index_interest_groups"),
        vec!["alt.binaries.linux.iso".to_string()],
        "the preset's provenance must be on disk beside the same marker - \
         without it the next untick has nothing to remove: {s}"
    );
    assert!(
        !listed("index_interest_groups").contains(&"alt.binaries.mine".to_string()),
        "a hand-picked group must never be recorded as preset-owned: {s}"
    );
}

/// An install from before provenance was recorded. Its groups really did
/// come from a preset, but nothing on disk says so, and unticking used to
/// remove NOTHING - re-ticking did not repair it either, because a group
/// that is already present is skipped and so never enters the owned set.
/// The only escape was hand-editing the settings file.
#[test]
fn an_upgrade_with_no_recorded_provenance_can_still_untick() {
    let dir = scratch(
        "upgrade",
        &["alt.binaries.linux.iso", "alt.binaries.mine"],
        // Answered and applied, groups in place, provenance key absent -
        // exactly what an upgrading install brings with it.
        r#"{"index_interests":"linux","index_interests_applied":"linux",
            "index_groups":["alt.binaries.linux.iso","alt.binaries.mine"]}"#,
    );
    let d = serve(&dir);
    assert_eq!(
        wait_groups(d.port, 2).len(),
        2,
        "the stored scan list is carried over"
    );
    // Startup reconstructs what the preset owns, conservatively: the
    // preset's groups intersected with what is actually being indexed.
    let s = wait_saved(&dir, "index_interest_groups");
    assert_eq!(
        s["index_interest_groups"],
        serde_json::json!(["alt.binaries.linux.iso"]),
        "{s}"
    );

    // And now the untick works, which is the whole point.
    set(d.port, "index_interests", "");
    for _ in 0..100 {
        if groups(d.port).len() < 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(
        groups(d.port),
        vec!["alt.binaries.mine".to_string()],
        "unticking a preset on an upgraded install must remove its groups, \
         and only its groups"
    );
}
