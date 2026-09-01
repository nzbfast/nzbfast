//! NZBLNK gate: paste a link, get a queued job.
//!
//! An `nzblnk:?h=…` carries no NZB and no article ids at all - the
//! German and Dutch boards hand out a HEADER and expect the client to
//! resolve it. Both rungs of our ladder are exercised here with no
//! network beyond loopback:
//!
//! - rung 1, our own header index: a seeded release is found by its
//!   header and the NZB is rebuilt from stored segment ids;
//! - rung 2, the user's indexers: one nzbfast plays the indexer over its
//!   own Newznab facade while a second, with an EMPTY local index,
//!   resolves the same header through it.
//!
//! Also pinned: `p=` reaches the job's password (the durable record is
//! the evidence), `t=` names the job, and junk is refused.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::serve;

#[cfg(feature = "indexer")]
use nzbkit::nntp::OverEntry;

/// How long [`settle_index`] will wait for the daemon's startup index
/// open to finish.
///
/// Generous on purpose, and it is a CEILING rather than a cost: the loop
/// only waits while the daemon is actually answering busy, and each such
/// answer has already cost it `PREMIGRATION_INDEX_WAIT` (2 s) before it
/// was written. MEASURED 30 Aug 2026, the probe instrumented to report
/// its own wait, under eight concurrent copies of this binary on a box
/// also carrying other lanes' builds: the longest settle of forty was
/// 5.2 s, most were 3 to 5 s, and a quiet box is single-digit
/// milliseconds. So 60 s is an 11x margin and is only ever spent by an
/// index that is not coming back, at which point nothing asserted below
/// would mean anything anyway. nextest's own `terminate-after` for this
/// profile is 600 s, so this cannot be what a wedged test hits first.
const SETTLE_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// How many times a link lookup is re-asked while the daemon reports
/// the index busy - see [`addnzblnk_get`].
///
/// Three, and the ceiling is not arbitrary: `NZBLNK_EXTERNAL_MAX` is 6,
/// so past a peer's sixth resolution in the window the ladder degrades
/// to local-only and never reaches the indexers at all. The worst case
/// in this module is `a_link_we_cannot_resolve_locally_goes_to_the_indexers`,
/// whose two lookups share one peer bucket, so 3 each is exactly 6 - the
/// last attempt may still ask the indexers, and no retry here can turn a
/// rung-2 test into a rung-1 test. Raise this and that stops being true.
///
/// This is the BELT, not the wait: [`settle_index`] does the waiting on
/// an endpoint the nzblnk rate gate never sees, so these tries are there
/// for a pool that goes busy again afterwards, not for startup. It was
/// the only mechanism for one revision of this fix and that is measurably
/// too tight - under a heavy box it was exhausted four times in five
/// concurrent runs, which is why the waiting moved off the gated
/// endpoint rather than the count going up.
const BUSY_TRIES: usize = 3;

/// Block until the daemon's index will answer a read.
///
/// Rung 1 of the nzblnk ladder goes through `Daemon::index_read_checked`,
/// which before the daemon's first read-write open falls back to the
/// write mutex on a BOUNDED 2 s wait and REPORTS
/// `{"busy":true,"error":"the index is busy - try again in a moment"}`
/// rather than parking an HTTP worker on it (TODO 143's second half,
/// TODO 166). On a loaded box that open is still running when a test's
/// first lookup arrives, so `mode=addnzblnk` has TWO legal non-auth
/// answers and the assertions below admit one. The daemon must NOT be
/// relaxed to wait it out; that is the http_wedge class of bug.
///
/// `mode=index_search` and not `mode=addnzblnk`, which is the whole
/// point of a separate probe: it reaches the SAME seam and reports the
/// same refusal, and the nzblnk rate gate never sees it. Waiting on the
/// gated endpoint spends `NZBLNK_MAX` and, worse, pushes `nth_for_peer`
/// past `NZBLNK_EXTERNAL_MAX`, at which point the ladder quietly stops
/// asking the indexers - so a long enough wait there would turn a rung-2
/// test into a rung-1 test without failing.
///
/// `key` is the `&apikey=...` this daemon needs, or empty where it has
/// none. An auth refusal PANICS rather than returning: a probe the
/// daemon answers "API Key Incorrect" carries no `busy` flag, so it
/// would exit the loop at once and disable the settle in silence.
///
/// Without the `indexer` feature `index_search` is not a mode at all,
/// the answer carries no `busy`, and this returns immediately - which is
/// correct, because rung 1 does not exist there either and no lookup can
/// be refused as busy.
fn settle_index(port: u16, key: &str) {
    let started = std::time::Instant::now();
    loop {
        let last = http_get(
            port,
            &format!("/api?mode=index_search&q=nzbfastsettleprobe{key}&output=json"),
        )
        .1;
        assert!(
            !last.contains("API Key"),
            "the settle probe was refused, so it was never settling anything:\n{last}"
        );
        let v: serde_json::Value = serde_json::from_str(&last).unwrap_or_default();
        if v["busy"] != true {
            return;
        }
        assert!(
            started.elapsed() < SETTLE_BUDGET,
            "the index never settled in {SETTLE_BUDGET:?}:\n{last}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// `http_get` for an answer that must not be the daemon's index-busy
/// refusal, re-asking while it is.
///
/// The belt behind [`settle_index`], whose header carries the mechanism:
/// the index can go busy again after it has settled (every read
/// connection lent out, a schema change under the reader), and a lookup
/// that hits one of those is still a legal refusal this module's
/// assertions do not admit.
///
/// Re-asking is what the refusal itself tells a client to do, so this
/// models the shipped contract rather than working around it. Bounded,
/// and exhaustion PANICS with the body: a test that only ever saw a busy
/// answer proved nothing, and saying so is better than passing. That is
/// a strengthening as well as a fix - `a_failed_grab_must_not_echo_the_indexer_apikey`
/// asserts an ABSENCE, which a busy body satisfies without the request
/// ever reaching the indexer it is about.
///
/// `IndexBusy::TooSlow` renders the same `busy` flag and is deliberately
/// NOT transient, which is the other reason this is bounded and reports
/// the body instead of looping: an unbounded retry on that one would
/// hang rather than fail.
fn addnzblnk_get(port: u16, req: &str) -> (u16, String) {
    let started = std::time::Instant::now();
    let mut last = (0u16, String::new());
    for attempt in 1..=BUSY_TRIES {
        last = http_get(port, req);
        // A body that is not JSON at all parses to `Null`, whose "busy"
        // is `Null` too, so anything unexpected is handed straight back
        // to the assertion that asked for it.
        let v: serde_json::Value = serde_json::from_str(&last.1).unwrap_or_default();
        if v["busy"] != true {
            return last;
        }
        if attempt < BUSY_TRIES {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    panic!(
        "the index was still busy after {BUSY_TRIES} tries over {:?} of {req}:\n{}",
        started.elapsed(),
        last.1
    );
}

/// (status, body) of a GET; connection refusals retried, answers never.
/// (See tests/integration/newznab.rs for why zero-bytes-back is retried.)
///
/// A caller that asserts on the SHAPE of an `addnzblnk` answer wants
/// [`addnzblnk_get`] instead, which also re-asks a busy index.
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

#[cfg(feature = "indexer")]
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

/// Standard daemon command against a dead news server.
fn daemon_cmd(dir: &Path, cfg: &Path, db: &Path, port: u16, extra: &[&str]) -> Command {
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
    for a in extra {
        c.arg(a);
    }
    c
}

/// The header a board would hand out: the whole posting is named after
/// it, and nothing in the name says what the release is.
const HEADER: &str = "7f3ac91e88a2";

#[cfg(feature = "indexer")]
fn obfuscated_post() -> Vec<OverEntry> {
    vec![
        over(
            1,
            &format!("\"{HEADER}.part01.rar\" yEnc (1/2)"),
            "<o1@x>",
            4_000_000,
        ),
        over(
            2,
            &format!("\"{HEADER}.part01.rar\" yEnc (2/2)"),
            "<o2@x>",
            4_000_000,
        ),
        over(
            3,
            &format!("\"{HEADER}.part02.rar\" yEnc (1/1)"),
            "<o3@x>",
            3_000_000,
        ),
        over(
            4,
            &format!("\"{HEADER}.par2\" yEnc (1/1)"),
            "<o4@x>",
            400_000,
        ),
    ]
}

/// Rung 1: the link resolves against our own scan data, offline, and the
/// NZB is rebuilt from the segment ids the index already holds.
#[cfg(feature = "indexer")]
#[tokio::test(flavor = "multi_thread")]
async fn a_pasted_link_resolves_from_our_own_index() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lnk-local-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest("alt.binaries.boneless", &obfuscated_post(), 1_700_000_000)
            .unwrap();
    }
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    std::fs::write(
        cfg.with_file_name("settings.json"),
        "{\"index_enabled\": true}",
    )
    .unwrap();
    let d = serve(&dir, |port| daemon_cmd(&dir, &cfg, &db, port, &[])).await;
    let port = d.port;
    let spool = cfg.with_file_name(".spool");

    tokio::task::spawn_blocking(move || {
        // Before anything is asserted: rung 1 is refused as busy while
        // the daemon's own startup index open still holds the write
        // mutex, and this test demands the other answer.
        settle_index(port, "");

        // Exactly what a board publishes, password and all.
        let link =
            format!("nzblnk:?t=Der+Grosse+Film+2024&h={HEADER}&g=alt.binaries.boneless&p=v4c4t10n");
        let (_, r) = addnzblnk_get(
            port,
            &format!("/api?mode=addnzblnk&link={}&output=json", pct(&link)),
        );
        let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_default();
        assert_eq!(v["status"], true, "{r}");
        assert_eq!(
            v["via"], "index",
            "the local rung should have answered: {r}"
        );
        assert_eq!(v["partial"], false, "{r}");
        assert_eq!(v["nzo_ids"].as_array().map(Vec::len), Some(1), "{r}");

        // t= is the job name, not the header.
        let (_, q) = http_get(port, "/api?mode=queue&output=json");
        assert!(
            q.contains("Der Grosse Film 2024"),
            "the title did not name the job:\n{q}"
        );
        assert!(
            !q.contains(HEADER),
            "the header leaked into the job name:\n{q}"
        );

        // p= reached the job's password, so the existing password-chain
        // unlock opens the archive with nothing more from the user. The
        // durable record is the evidence - the API deliberately reports
        // only that a password exists, never its value.
        let mut saved = String::new();
        for _ in 0..40 {
            saved = std::fs::read_to_string(spool.join("queue.json")).unwrap_or_default();
            if saved.contains("v4c4t10n") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            saved.contains("\"password\": \"v4c4t10n\""),
            "password not stored:\n{saved}"
        );
        assert!(
            saved.contains("\"origin\": \"nzblnk\""),
            "origin not recorded:\n{saved}"
        );

        // A header nothing answers for fails with a reason, not a job.
        let (_, miss) = addnzblnk_get(
            port,
            "/api?mode=addnzblnk&link=nzblnk%3A%3Fh%3Dnothinghere99&output=json",
        );
        let mv: serde_json::Value = serde_json::from_str(&miss).unwrap_or_default();
        assert_eq!(mv["status"], false, "{miss}");
        assert!(
            mv["error"].as_str().unwrap_or("").contains("nothing found"),
            "{miss}"
        );

        // Junk is refused by the parser, before any lookup.
        for bad in [
            "https%3A%2F%2Fexample.invalid%2Fx.nzb",
            "nzblnk%3A%3Ft%3Donly+a+title",
        ] {
            let (_, j) = http_get(port, &format!("/api?mode=addnzblnk&link={bad}&output=json"));
            assert!(j.contains("\"status\":false"), "{bad} was accepted: {j}");
        }

        // The rate gate. Registering `nzblnk:` with the OS puts this
        // endpoint one browser prompt away from any web page, so a page
        // in a loop must run out of road. Everything above already spent
        // part of the window, so this only has to push past the cap.
        let mut refused = String::new();
        for i in 0..40 {
            let (_, r) = http_get(
                port,
                &format!("/api?mode=addnzblnk&link=nzblnk%3A%3Fh%3Dflood{i}abcd&output=json"),
            );
            if r.contains("\"toofast\"") {
                refused = r;
                break;
            }
        }
        assert!(!refused.is_empty(), "the endpoint never rate-limited");
        let rv: serde_json::Value = serde_json::from_str(&refused).unwrap_or_default();
        assert_eq!(rv["status"], false, "{refused}");
        assert!(
            rv["error"]
                .as_str()
                .unwrap_or("")
                .contains("too many links"),
            "the refusal should say what to do: {refused}"
        );
    })
    .await
    .unwrap();
}

/// Rung 2: nothing in our own index, so the same header goes out to the
/// user's configured indexers and the winning NZB is fetched from there.
#[cfg(feature = "indexer")]
#[tokio::test(flavor = "multi_thread")]
async fn a_link_we_cannot_resolve_locally_goes_to_the_indexers() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lnk-pull-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Peer A holds the posting and publishes it over its own facade.
    let dir_a = dir.join("a");
    std::fs::create_dir_all(&dir_a).unwrap();
    let db_a = dir_a.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db_a).unwrap();
        ix.ingest("alt.binaries.boneless", &obfuscated_post(), 1_700_000_000)
            .unwrap();
    }
    let cfg_a = dir_a.join("config.json");
    std::fs::write(
        &cfg_a,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    std::fs::write(
        cfg_a.with_file_name("settings.json"),
        "{\"index_enabled\": true}",
    )
    .unwrap();
    let a = serve(&dir_a, |port| daemon_cmd(&dir_a, &cfg_a, &db_a, port, &[])).await;
    let port_a = a.port;

    // B has no index at all (the switch stays at its default off), which
    // is the ordinary new install.
    let dir_b = dir.join("b");
    std::fs::create_dir_all(&dir_b).unwrap();
    let cfg_b = dir_b.join("config.json");
    std::fs::write(
        &cfg_b,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    let db_b = dir_b.join("index.db");
    let b = serve(&dir_b, |port| daemon_cmd(&dir_b, &cfg_b, &db_b, port, &[])).await;
    let port_b = b.port;

    tokio::task::spawn_blocking(move || {
        // Both peers, and A is not decoration: B reaches it over A's own
        // Newznab facade, which answers off the SAME seam, so an A that
        // is still opening its index hands B an <error> and B honestly
        // reports having found nothing - with no `busy` flag of its own
        // for the retry below to see.
        settle_index(port_a, "");
        settle_index(port_b, "");

        // With no indexers configured yet, the link has nowhere to go -
        // and says so rather than reporting a queued job.
        //
        // `addnzblnk_get` even though the assertion below would pass on a
        // busy body anyway (it carries `"status":false` too): that would
        // be a pass proving nothing, and re-asking here is also what
        // settles the index before the rung-2 leg below, which does NOT
        // tolerate one.
        let link = format!("nzblnk:?h={HEADER}&t=Ein+Anderer+Film");
        let (_, none) = addnzblnk_get(
            port_b,
            &format!("/api?mode=addnzblnk&link={}&output=json", pct(&link)),
        );
        assert!(none.contains("\"status\":false"), "{none}");

        let entry =
            format!(r#"[{{"name":"peer","url":"http://127.0.0.1:{port_a}/api","apikey":"x"}}]"#);
        let (_, r) = http_get(
            port_b,
            &format!(
                "/api?mode=config&name=indexers&value={}&output=json",
                pct(&entry)
            ),
        );
        assert!(r.contains("true"), "{r}");

        let (_, r) = addnzblnk_get(
            port_b,
            &format!("/api?mode=addnzblnk&link={}&output=json", pct(&link)),
        );
        let v: serde_json::Value = serde_json::from_str(&r).unwrap_or_default();
        assert_eq!(v["status"], true, "{r}");
        assert_eq!(
            v["via"], "peer",
            "the indexer rung should have answered: {r}"
        );

        let (_, q) = http_get(port_b, "/api?mode=queue&output=json");
        assert!(
            q.contains("Ein Anderer Film"),
            "the job is not in the queue:\n{q}"
        );
    })
    .await
    .unwrap();
}

/// A mock indexer that answers a header search with ONE result whose NZB
/// link carries an apikey, and then refuses to serve that link in a way
/// that makes `fetch_url` name the URL in its error.
///
/// `SearchResult::link` is documented "carries the user's apikey - never
/// serialize this to a browser or a log", which is the whole reason M35
/// hands the UI opaque tokens. This proves whether the nzblnk ladder
/// honours that when the fetch FAILS.
fn leaky_indexer(secret: &str) -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let secret = secret.to_string();
    std::thread::spawn(move || {
        for stream in l.incoming() {
            let Ok(mut s) = stream else { break };
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap_or(0);
            let line = String::from_utf8_lossy(&buf[..n])
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            let body = if line.contains("/getnzb") {
                // Declare a body far over FETCH_MAX_BYTES so fetch_url
                // refuses it before reading, naming the URL as it does.
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\
                     Content-Type: application/x-nzb\r\nConnection: close\r\n\r\n"
                );
                continue;
            } else {
                format!(
                    r#"<?xml version="1.0"?><rss xmlns:newznab="http://www.newznab.com/DTD/2010/feeds/attributes/"><channel>
<item><title>{HEADER}</title><guid>leak-1</guid>
<enclosure url="http://127.0.0.1:{port}/getnzb/leak-1?apikey={secret}" length="900" type="application/x-nzb"/>
<newznab:attr name="category" value="2000"/></item></channel></rss>"#
                )
            };
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/rss+xml\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

/// The user's indexer apikey must never reach the browser, including on
/// the failure path. A leak here is worse than it looks: the dashboard
/// shows `notes` verbatim, and the same string is what a support
/// screenshot would carry.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_grab_must_not_echo_the_indexer_apikey() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lnk-leak-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    const SECRET: &str = "sUpErSeCrEtApIkEy1234";
    let mock = leaky_indexer(SECRET);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    let db = dir.join("index.db");
    let d = serve(&dir, |port| daemon_cmd(&dir, &cfg, &db, port, &[])).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // This test asserts an ABSENCE, so a busy rung 1 would satisfy
        // it without the request ever reaching the indexer it is about.
        settle_index(port, "");

        let entry = format!(
            r#"[{{"name":"leaky","url":"http://127.0.0.1:{mock}/api","apikey":"{SECRET}"}}]"#
        );
        let (_, r) = http_get(
            port,
            &format!(
                "/api?mode=config&name=indexers&value={}&output=json",
                pct(&entry)
            ),
        );
        assert!(r.contains("true"), "{r}");

        let link = format!("nzblnk:?h={HEADER}&t=Leak+Probe");
        let (_, body) = addnzblnk_get(
            port,
            &format!("/api?mode=addnzblnk&link={}&output=json", pct(&link)),
        );
        assert!(
            !body.contains(SECRET),
            "the indexer apikey reached the browser:\n{body}"
        );
    })
    .await
    .unwrap();
}

/// The add-only `nzbkey` must not reach `addnzblnk`.
///
/// This is a security property expressed as an ABSENCE - `addnzblnk` is
/// simply not in the `add_only` mode allowlist in serve/http.rs - so
/// nothing fails if a later refactor "helpfully" adds it beside
/// `addfile|addurl|version`. The reason it is excluded: resolving a
/// header spends the user's metered indexer quota, which an add-only
/// credential has no business doing.
///
/// The addurl leg is what makes this test mean anything: it proves the
/// nzbkey is live and correct, so the addnzblnk refusal is the tier
/// rule and not a typo in the fixture.
#[tokio::test(flavor = "multi_thread")]
async fn the_add_only_key_cannot_spend_indexer_quota() {
    let dir = std::env::temp_dir().join(format!("nzbfast-lnk-tier-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}",
    )
    .unwrap();
    let db = dir.join("index.db");
    let d = serve(&dir, |port| {
        let mut c = daemon_cmd(&dir, &cfg, &db, port, &[]);
        c.arg("--apikey")
            .arg("fullkey")
            .arg("--nzbkey")
            .arg("addkey");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The full key, because this daemon has one and an auth-refused
        // probe settles nothing - `settle_index` refuses that outright.
        settle_index(port, "&apikey=fullkey");

        let link = "nzblnk%3A%3Fh%3Dtierprobe99%26t%3DTier+Probe";

        // The add-only key is REFUSED, in the exact SAB phrasing.
        let (_, denied) = http_get(
            port,
            &format!("/api?mode=addnzblnk&apikey=addkey&link={link}&output=json"),
        );
        assert!(
            denied.contains("API Key Incorrect"),
            "the add-only key reached addnzblnk:\n{denied}"
        );

        // ...but it IS a working add-only key, or the assertion above
        // would pass for the wrong reason.
        let (_, allowed) = http_get(
            port,
            "/api?mode=addurl&apikey=addkey&name=http%3A%2F%2F127.0.0.1%3A1%2Fx.nzb&output=json",
        );
        assert!(
            !allowed.contains("API Key Incorrect"),
            "the fixture's nzbkey is not actually valid:\n{allowed}"
        );

        // The full key gets through to the ladder - which then answers
        // honestly that it found nothing, having no index and no
        // indexers. Any auth phrase here would mean the mode is gated
        // wrongly in the other direction.
        //
        // `addnzblnk_get`, because "nothing found" is not the daemon's
        // only honest answer: a lookup that arrives while the startup
        // index open still holds the write mutex is REFUSED as busy, and
        // this test demanded the other one. The assertion below is
        // deliberately unchanged - it is what proves the mode is not
        // gated the wrong way, and weakening it to the absence check
        // alone would give that up.
        let (_, full) = addnzblnk_get(
            port,
            &format!("/api?mode=addnzblnk&apikey=fullkey&link={link}&output=json"),
        );
        assert!(
            !full.contains("API Key"),
            "the full key was refused:\n{full}"
        );
        assert!(full.contains("nothing found"), "{full}");
    })
    .await
    .unwrap();
}
