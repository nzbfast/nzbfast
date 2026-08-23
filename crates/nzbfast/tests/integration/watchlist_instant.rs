#![cfg(feature = "indexer")]
//! TODO §74 end to end: a watched show is grabbed SECONDS after it is
//! posted, not at the next periodic watchlist pass.
//!
//! Everything here runs against a real daemon and a real (mock) news
//! server, because the claim is about the seam between three moving
//! parts: the tip watcher noticing a new article, the arrival watch
//! inside the index reporting it, and the ordinary watchlist pass being
//! woken by that report. A seeded database cannot test any of it - the
//! post has to ARRIVE.
//!
//! What each case pins:
//!
//! - `an_arriving_release_is_grabbed_without_waiting_for_the_pass`: the
//!   headline. The daemon's periodic pass is 60 s away; the job is in the
//!   queue long before that, and the watchlist's own record says it was
//!   grabbed because it arrived.
//! - `a_post_still_going_up_is_not_grabbed_until_it_is_complete`: the
//!   completeness gate. A release seen at +6 s is usually half-posted, and
//!   half a post is not a download. It is grabbed once the rest lands -
//!   once, not once per batch.
//! - `the_quality_ladder_still_applies_on_the_instant_path`: the whole
//!   design constraint. The instant path grabs through the SAME pass, so
//!   a worse encode arriving later cannot preempt the better one already
//!   in hand.
//! - `an_arrival_the_full_scan_pass_ingests_still_reaches_the_instant_path`:
//!   the OTHER ingest leg. The tip watcher is not the only thing that
//!   reads new articles - it stands down for the whole of every download
//!   - and an arrival the full pass picks up instead has to reach the
//!   instant path just the same. The three cases above cannot see this:
//!   with both legs live, which one gets to the post first is a race,
//!   and this one switches the tip watcher off to settle it.
//!
//! The harness is the shape tests/integration/watchlist_packs.rs uses -
//! copied, not shared, because nzbfast is a binary-only crate and
//! integration tests cannot import from each other.

use crate::scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use crate::harness::{Daemon, serve};

use nzbkit::mock::{Chaos, MockServer, OverRow};

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

const GROUP: &str = "alt.binaries.teevee";

/// The article numbers these tests post at. The index is seeded with a
/// high-water mark of [`SEEDED_MARK`], so everything at or above
/// `SEEDED_MARK + 1` is, to the tip watcher, a post that has just
/// arrived.
const SEEDED_MARK: u64 = 100;

fn row(number: u64, subject: &str, msgid: &str, bytes: u64) -> OverRow {
    OverRow {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        message_id: format!("<{msgid}>"),
        bytes,
    }
}

/// One complete release as it appears on the wire: the payload and its
/// par2 sidecar. A release is complete when every file it has shown has
/// all its parts, which is what the watchlist requires before grabbing.
fn release(n: u64, stem: &str) -> Vec<OverRow> {
    vec![
        row(
            n,
            &format!("\"{stem}.rar\" yEnc (1/1)"),
            &format!("p{n}@x"),
            40_000,
        ),
        row(
            n + 1,
            &format!("\"{stem}.par2\" yEnc (1/1)"),
            &format!("q{n}@x"),
            400,
        ),
    ]
}

/// The first half of a two-part file: seen, matched, but NOT complete.
fn half_release(n: u64, stem: &str) -> Vec<OverRow> {
    vec![row(
        n,
        &format!("\"{stem}.rar\" yEnc (1/2)"),
        &format!("p{n}@x"),
        40_000,
    )]
}

fn other_half(n: u64, stem: &str) -> Vec<OverRow> {
    vec![row(
        n,
        &format!("\"{stem}.rar\" yEnc (2/2)"),
        &format!("p{n}b@x"),
        40_000,
    )]
}

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

/// [`watching`] with the tip watcher at its 5 s floor - what every case
/// about the tip leg wants.
async fn watching(dir: &Path, mock: &MockServer, items: &str) -> Daemon {
    watching_tip(dir, mock, items, 5).await
}

/// A daemon watching a live group on `mock`, with `items` as the
/// watchlist and an index that already knows the group (so the tip
/// watcher, which never seeds a group itself, will follow it).
///
/// `tip_secs` is the tip watcher's interval, and 0 switches it off
/// outright - which is how the scan-leg case below gets the full pass to
/// be the only leg that can reach the post.
async fn watching_tip(dir: &Path, mock: &MockServer, items: &str, tip_secs: u64) -> Daemon {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let db = dir.join("index.db");
    let host = mock.addr.ip().to_string();
    {
        // The tip watcher follows each group's chosen PRIMARY and only
        // groups a full pass has already scanned: it reads the primary
        // out of kv and refuses a group whose high-water mark is 0
        // (seeding needs a backfill the tip leg does not do). Both are
        // written here so the watcher starts from a group that looks
        // scanned, with everything above the mark still to come.
        let ix = nzbkit::index::Index::open(&db).unwrap();
        let key = nzbkit::index::Index::server_key(&host);
        ix.kv_set(&format!("scan_primary:{GROUP}"), &key).unwrap();
        ix.set_high_water(GROUP, &key, SEEDED_MARK).unwrap();
    }
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{host}\",\"port\":{},\"tls\":false,\"connections\":4}}]}}",
            mock.addr.port()
        ),
    )
    .unwrap();
    // index_enabled: the local leg needs the database open at all.
    // index_tip_secs at its 5 s floor so a tick is a test's worth of
    // waiting rather than the 20 s default. The periodic watchlist pass
    // is 60 s and is NOT configurable - which is exactly what makes
    // these assertions about the instant path and not about it.
    //
    // The watchlist goes in the SETTINGS FILE, not through
    // `mode=config&name=watchlist` after startup, and that is
    // load-bearing rather than tidier. An edit WAKES A PASS
    // (`set_watchlist` -> `watch_now.notify_one()`), and that pass runs
    // concurrently with everything these cases then do - so a release
    // published into the index while it is still running is grabbed BY
    // IT, with the arrival hint still unpublished, and the grab is
    // recorded as an ordinary periodic one. That is not hypothetical:
    // it is the nightly armv7-cross red of 17 Aug 2026, where the
    // emulator stretched the setup pass into exactly that window on
    // every attempt. `spawn_watchlist_watcher` loads this key at
    // startup and its loop sleeps FIRST, so with the list here the only
    // thing that can run a pass inside a test's 40-45 s budget is an
    // arrival kick - which is the whole claim.
    std::fs::write(
        cfg.with_file_name("settings.json"),
        format!(
            "{{\"index_enabled\": true, \"index_tip_secs\": {tip_secs}, \
              \"index_groups\": [\"{GROUP}\"], \"watchlist_instant\": true, \
              \"watchlist\": {items}}}"
        ),
    )
    .unwrap();
    let d = serve(dir, |port| daemon_cmd(dir, &cfg, &db, port)).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        // Pause the queue BEFORE anything can be grabbed. These mocks
        // serve overview rows but no article bodies, so an unpaused job
        // starts, finds nothing, and fails into history within a second -
        // and a FAILED watchlist grab correctly frees its slot for
        // another release, which would quietly undo the very state these
        // tests are about. Paused, a grab stays a grab.
        http_get(port, "/api?mode=pause&output=json");
        // The list loaded, and loaded as a LIST: a settings key the
        // daemon could not parse is a warning in its log and an empty
        // watchlist here, which would otherwise read as "the instant
        // path never fired". This endpoint only reports state - unlike
        // the config setter it replaces, it wakes nothing.
        let st = status(port);
        assert!(
            st.contains("\"id\":1"),
            "the watchlist in settings.json was not loaded: {st}"
        );
    })
    .await
    .unwrap();
    d
}

/// Everything the daemon has been asked to download: the queue AND the
/// history. It has to be both - these mocks serve no bodies for the
/// synthesized NZB, so a grab can fail out of the queue and into history
/// before the next poll.
fn grabbed(port: u16) -> String {
    let (_, q) = http_get(port, "/api?mode=queue&output=json");
    let (_, h) = http_get(port, "/api?mode=history&output=json");
    format!("{q}\n{h}")
}

/// Poll until `needle` has been grabbed, or give up after `secs`.
fn wait_grabbed(port: u16, needle: &str, secs: u64) -> Option<String> {
    for _ in 0..(secs * 4) {
        let seen = grabbed(port);
        if seen.contains(needle) {
            return Some(seen);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    None
}

/// How many JOBS carry this name, across queue and history. Counted on
/// the name FIELD rather than by substring: a failure detail quotes the
/// release name a dozen times over. Two field names, because the SAB
/// queue calls it `filename` and the history calls it `name` - counting
/// only one of them reads a real job as none at all.
fn jobs_named(blob: &str, stem: &str) -> usize {
    blob.matches(&format!("\"filename\":\"{stem}\"")).count()
        + blob.matches(&format!("\"name\":\"{stem}\"")).count()
}

fn status(port: u16) -> String {
    http_get(port, "/api?mode=watchlist_status&output=json").1
}

/// Wait for a line in the daemon's OWN log - the same file
/// [`wait_ready`] watches, named after the port it bound.
///
/// Used to wait out the startup scan pass rather than sleeping a guessed
/// number of seconds at it: the scan is what a case about the scan leg
/// has to be on the far side of, and the pass says so itself.
fn wait_log(dir: &Path, port: u16, needle: &str, secs: u64) -> bool {
    let log = dir.join(format!("daemon-{port}.log"));
    for _ in 0..(secs * 10) {
        if std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains(needle)
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

/// The headline: a watched release is posted while the daemon is
/// running, and it is grabbed within a tip tick - long before the 60 s
/// periodic pass would have looked. The watchlist's own `instant` record
/// is what proves WHICH path grabbed it: only an arrival sets it.
#[tokio::test(flavor = "multi_thread")]
async fn an_arriving_release_is_grabbed_without_waiting_for_the_pass() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlinst-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mock = MockServer::start_full(
        Default::default(),
        Default::default(),
        Vec::new(),
        Chaos::default(),
    )
    .await;
    let d = watching(
        &dir,
        &mock,
        r#"[{"id":1,"kind":"tv","title":"Wanted Show","seasons":"","episodes":"",
             "min_quality":"any","target_quality":"1080p","enabled":true}]"#,
    )
    .await;
    let port = d.port;
    // Nothing is posted yet, so nothing can be grabbed. THEN it arrives.
    mock.post_overview(release(
        SEEDED_MARK + 1,
        "Wanted.Show.S01E01.1080p.WEB.h264-GRP",
    ));
    let started = std::time::Instant::now();
    tokio::task::spawn_blocking(move || {
        let seen = wait_grabbed(port, "Wanted.Show.S01E01", 45).unwrap_or_else(|| {
            panic!("the arriving release was never grabbed:\n{}", grabbed(port))
        });
        assert!(
            seen.contains("Wanted.Show.S01E01.1080p.WEB.h264-GRP"),
            "grabbed under the wrong name: {seen}"
        );
        // The record the instant path writes, and the periodic one never
        // does. Polled: the pass publishes its state at the END, so the
        // job is visible in the queue before the record is.
        let mut st = String::new();
        for _ in 0..40 {
            st = status(port);
            if st.contains("\"instant\"") && st.contains("Wanted.Show.S01E01") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        assert!(
            st.contains("Wanted.Show.S01E01"),
            "the grab was not recorded as an arrival - it came from the \
             periodic pass, not the instant path: {st}"
        );
        assert!(
            st.contains("\"instant_on\":true"),
            "the instant path reports itself off: {st}"
        );
    })
    .await
    .unwrap();
    // A guard on the claim itself rather than on the machinery: the
    // periodic pass is 60 s, so anything at or past that proves nothing
    // even if every assertion above passed.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(55),
        "grabbed only after the periodic pass would have run ({:?}) - \
         this test can no longer tell the two paths apart",
        started.elapsed()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The completeness gate. A post seen seconds after it starts going up is
/// usually half there, and half a post is not a download - the watchlist
/// waits. When the rest lands it is grabbed, once.
#[tokio::test(flavor = "multi_thread")]
async fn a_post_still_going_up_is_not_grabbed_until_it_is_complete() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlinst-part-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mock = MockServer::start_full(
        Default::default(),
        Default::default(),
        Vec::new(),
        Chaos::default(),
    )
    .await;
    let d = watching(
        &dir,
        &mock,
        r#"[{"id":1,"kind":"tv","title":"Wanted Show","seasons":"","episodes":"",
             "min_quality":"any","target_quality":"1080p","enabled":true}]"#,
    )
    .await;
    let port = d.port;
    let stem = "Wanted.Show.S01E02.1080p.WEB.h264-GRP";
    // Part one of two: the uploader is still going.
    mock.post_overview(half_release(SEEDED_MARK + 1, stem));
    let mock = std::sync::Arc::new(mock);
    let m2 = mock.clone();
    tokio::task::spawn_blocking(move || {
        // Two tip ticks' worth of silence. The release is in the index
        // and matches the item; grabbing it now would download half a
        // file and call it an episode.
        std::thread::sleep(std::time::Duration::from_secs(13));
        let seen = grabbed(port);
        assert!(
            !seen.contains("Wanted.Show.S01E02"),
            "a post that is still going up was grabbed:\n{seen}"
        );
        // The rest of it lands.
        m2.post_overview(other_half(SEEDED_MARK + 3, stem));
        wait_grabbed(port, "Wanted.Show.S01E02", 45)
            .unwrap_or_else(|| panic!("the completed post was never grabbed:\n{}", grabbed(port)));
        // Once. Two arrivals of the same release (the half, then the
        // rest) must not become two jobs - the slot the pass fills is
        // what stops it, the same as any other grab. Counted on the job
        // NAME field: the blob also carries the stem in paths and log
        // lines, so a naive substring count says eleven.
        std::thread::sleep(std::time::Duration::from_secs(2));
        let seen = grabbed(port);
        assert_eq!(
            jobs_named(&seen, stem),
            1,
            "the release was grabbed more than once:\n{seen}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The design constraint: the instant path does not grab anything - it
/// wakes the ordinary pass, which applies the whole ladder. So a worse
/// encode arriving after a better one is skipped exactly as it would be
/// on the periodic path.
#[tokio::test(flavor = "multi_thread")]
async fn the_quality_ladder_still_applies_on_the_instant_path() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlinst-q-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mock = MockServer::start_full(
        Default::default(),
        Default::default(),
        Vec::new(),
        Chaos::default(),
    )
    .await;
    let d = watching(
        &dir,
        &mock,
        r#"[{"id":1,"kind":"tv","title":"Wanted Show","seasons":"","episodes":"",
             "min_quality":"any","target_quality":"1080p","enabled":true,"upgrade":true}]"#,
    )
    .await;
    let port = d.port;
    mock.post_overview(release(
        SEEDED_MARK + 1,
        "Wanted.Show.S01E03.1080p.WEB.h264-GRP",
    ));
    let mock = std::sync::Arc::new(mock);
    let m2 = mock.clone();
    tokio::task::spawn_blocking(move || {
        wait_grabbed(port, "Wanted.Show.S01E03.1080p", 45)
            .unwrap_or_else(|| panic!("the 1080p arrival was never grabbed:\n{}", grabbed(port)));
        // A worse encode of the same episode arrives next.
        m2.post_overview(release(
            SEEDED_MARK + 10,
            "Wanted.Show.S01E03.720p.HDTV.x264-GRP",
        ));
        std::thread::sleep(std::time::Duration::from_secs(13));
        let seen = grabbed(port);
        assert!(
            !seen.contains("720p.HDTV"),
            "an arriving WORSE encode preempted the one already in hand - \
             the instant path is not going through the quality ladder:\n{seen}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// §74's OTHER ingest leg. The tip watcher is not the only thing that
/// reads new articles: it stands down for the whole of every download
/// (and for every full pass, and while the indexer is paused), and what
/// covers the range it missed is the next FULL scan pass. An arrival is
/// an arrival whichever leg happens to read it, so the instant path has
/// to see it either way - otherwise "grabbed seconds after it was
/// posted" quietly becomes "grabbed at the next 60 s pass" depending on
/// which leg won a race nobody can see.
///
/// The tip watcher is switched off outright here (`index_tip_secs: 0`),
/// which leaves the full pass as the only way the post can reach the
/// index at all. That is what makes this deterministic where the three
/// cases above are not: with both legs live, whichever one gets to the
/// group first decides, and the startup pass usually wins.
#[tokio::test(flavor = "multi_thread")]
async fn an_arrival_the_full_scan_pass_ingests_still_reaches_the_instant_path() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlinst-scan-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mock = MockServer::start_full(
        Default::default(),
        Default::default(),
        Vec::new(),
        Chaos::default(),
    )
    .await;
    let d = watching_tip(
        &dir,
        &mock,
        r#"[{"id":1,"kind":"tv","title":"Wanted Show","seasons":"","episodes":"",
             "min_quality":"any","target_quality":"1080p","enabled":true}]"#,
        0,
    )
    .await;
    let port = d.port;
    let stem = "Wanted.Show.S01E04.1080p.WEB.h264-GRP";
    let dir2 = dir.clone();
    let mock = std::sync::Arc::new(mock);
    let m2 = mock.clone();
    tokio::task::spawn_blocking(move || {
        // The startup scan pass has to be BEHIND us before anything is
        // posted - otherwise IT could be what ingested the release, and
        // this case would be reading its own setup back. The pass says
        // so itself, so it is waited for rather than slept at. (The
        // other setup pass this used to race, the watchlist pass an
        // edit wakes, no longer exists: `watching_tip` puts the list in
        // settings.json.)
        assert!(
            wait_log(
                &dir2,
                port,
                &format!("{GROUP}: up to date (high {SEEDED_MARK})"),
                60
            ),
            "the startup scan pass never reported the group up to date"
        );
        // NOW it arrives, with the tip watcher off: the next full pass
        // is the only thing that can read it.
        m2.post_overview(release(SEEDED_MARK + 1, stem));
        http_get(port, "/api?mode=index_scan_now&output=json");
        let seen = wait_grabbed(port, "Wanted.Show.S01E04", 40).unwrap_or_else(|| {
            panic!(
                "the arrival the SCAN pass ingested was never grabbed - \
                 nothing woke the watchlist, so it is waiting for the \
                 periodic pass:\n{}",
                grabbed(port)
            )
        });
        assert!(seen.contains(stem), "grabbed under the wrong name: {seen}");
        // The claim itself: grabbed BECAUSE it arrived. Polled for the
        // same reason the headline case polls - the pass publishes its
        // state at the end, so the job reaches the queue first.
        let mut st = String::new();
        for _ in 0..40 {
            st = status(port);
            if st.contains("\"instant\":{") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        // The RECORD, not the stem loose in the blob: the slot carries
        // the same stem, and a bare containment would read a periodic
        // grab as an instant one.
        let record = st
            .split("\"instant\":{")
            .nth(1)
            .and_then(|r| r.split('}').next())
            .unwrap_or("");
        assert!(
            record.contains(stem),
            "the scan leg ingested the arrival without reporting it, so \
             the grab was not recorded as an arrival: {st}"
        );
    })
    .await
    .unwrap();
}
