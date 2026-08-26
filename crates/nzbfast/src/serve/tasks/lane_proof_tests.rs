//! TODO 161 items 2 and 3: end-to-end proof for the two indexer lanes
//! that ship OFF and had therefore never run anywhere - the parity
//! scoreboard sampler and the correlation-confirm lane.
//!
//! Both lanes talk to "the user's own newznab account", which is why
//! neither had ever been exercised: arming them needs a real indexer
//! and a real key. A newznab account is only an HTTP endpoint that
//! answers `t=search` with RSS and serves an NZB at the enclosure URL,
//! so a loopback fixture is a complete stand-in for the whole contract
//! - and the SSRF guard deliberately permits loopback, so the real
//! agent, the real search and the real fetch all run here.
//!
//! What these two tests pin is exactly what nobody could answer before:
//! a `scoreboard_samples` row appears and says something true about
//! the index it scored against, and a `pre_corr` suggestion reaches
//! `confirmed` with the name applied to the release.

use super::*;
use std::io::{Read, Write};

/// A loopback newznab account. `paths()` stops the server and hands
/// back what the lane actually asked for, so a test can assert the
/// calls it spent.
struct Fixture {
    port: u16,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<Vec<String>>>,
}

impl Fixture {
    /// Stop accepting and collect the request paths.
    ///
    /// The server polls rather than blocking in `accept`, and this
    /// never waits for a request that is not coming: a lane that
    /// stops early (no exact listing, a refusal) must fail its
    /// assertions, not hang the suite. An earlier cut joined a
    /// fixed-count thread and a deliberately broken lane wedged the
    /// run for ten minutes instead of failing in two seconds.
    fn paths(&mut self) -> Vec<String> {
        self.stop.store(true, Ordering::SeqCst);
        self.server
            .take()
            .map(|h| h.join().unwrap())
            .unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Serve requests with `answer(path, port) -> body`, one thread, no
/// keep-alive, until the test collects the paths. `port` is handed to
/// the answer because a listing's enclosure URL has to point back at
/// this same socket - a cross-origin private target is refused,
/// correctly.
fn fixture(answer: impl Fn(&str, u16) -> String + Send + 'static) -> Fixture {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let server = std::thread::spawn(move || {
        let mut paths = Vec::new();
        while !flag.load(Ordering::SeqCst) {
            let (mut sock, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            };
            // Blocking again for the exchange itself: only the accept
            // needs to be interruptible.
            let _ = sock.set_nonblocking(false);
            // One read is enough: these are short GETs and ureq writes
            // the whole request in one go.
            let mut buf = [0u8; 8192];
            let n = sock.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = head
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let body = answer(&path, port);
            let _ = sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
            paths.push(path);
        }
        paths
    });
    Fixture {
        port,
        stop,
        server: Some(server),
    }
}

/// The fixture account, wired into the daemon's indexer list under
/// `name` - both lanes resolve their source by NAME against that list.
fn account(d: &Arc<Daemon>, name: &str, port: u16) {
    *d.indexers.lock_ok() = vec![crate::newznab::IndexerConfig {
        kind: Default::default(),
        nzbindex: Default::default(),
        name: name.to_string(),
        url: format!("http://127.0.0.1:{port}"),
        apikey: "fixture-key".to_string(),
        enabled: true,
        priority: 0,
        hits_per_day: 0,
        grabs_per_day: 0,
    }];
}

/// One RSS `<item>` in the shape `parse_results` reads: title, guid,
/// and an enclosure carrying the NZB link and the announced size.
fn item(title: &str, guid: &str, size: u64, posted: i64, link: &str) -> String {
    format!(
        "<item><title>{title}</title><guid>{guid}</guid>\
         <enclosure url=\"{link}\" length=\"{size}\" type=\"application/x-nzb\"/>\
         <newznab:attr name=\"usenetdate\" value=\"{}\"/></item>",
        rfc2822(posted)
    )
}

fn rss(items: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <rss version=\"2.0\" xmlns:newznab=\"http://www.newznab.com/DTD/2010/feeds/attributes/\">\
         <channel>{items}</channel></rss>"
    )
}

/// Seconds since the epoch as the RFC 2822 date newznab publishes.
/// Hand-rolled rather than pulled in: the fixture only has to produce
/// a date the client's own parser reads back unchanged, and the lag
/// assertion in the scoreboard test is what enforces that.
fn rfc2822(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // 1970-01-01 was a Thursday.
    const DOW: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let leap = |y: i64| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let (mut y, mut left) = (1970i64, days);
    loop {
        let len = if leap(y) { 366 } else { 365 };
        if left < len {
            break;
        }
        left -= len;
        y += 1;
    }
    let mlen = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0usize;
    while left >= mlen[m] {
        left -= mlen[m];
        m += 1;
    }
    format!(
        "{}, {:02} {} {y} {:02}:{:02}:{:02} +0000",
        DOW[(days.rem_euclid(7)) as usize],
        left + 1,
        MON[m],
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn tdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-lane-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn over(subject: &str, msgid: &str, posted: i64, bytes: u64) -> nzbkit::nntp::OverEntry {
    nzbkit::nntp::OverEntry {
        number: 0,
        subject: subject.to_string(),
        from: "poster@example".to_string(),
        message_id: msgid.to_string(),
        bytes,
        date: posted,
    }
}

const T: i64 = 1_700_000_000;

/// TODO 161 item 2, the whole lane: a reference account answers one
/// category, and the sampler turns that answer into stored samples
/// whose verdicts are true of the index they scored against.
///
/// `scoreboard_samples` was empty on every install that ever ran this
/// build, so "does a sample ever appear, and does it say anything
/// true" was genuinely open. Here it is answered: two references - one
/// we hold under its real name, one we do not hold at all - come back
/// have_named (with the lag we really took to see it) and missing.
#[test]
fn the_scoreboard_sampler_stores_true_verdicts_from_a_reference_account() {
    let dir = tdir("sb");
    let d = crate::serve::testutil::test_daemon(&dir);
    // The index the sample is scored against: we hold the first
    // release, named, seen two hours after the reference posted it.
    {
        let mut ix = nzbkit::index::Index::open(&d.index_db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[over(
                r#""Some.Show.S01E02.1080p.WEB-GRP.rar" yEnc (1/1)"#,
                "<held-1@example>",
                T,
                4_000_000_000,
            )],
            T + 7_200,
        )
        .unwrap();
    }
    let mut f = fixture(|path, _| {
        assert!(path.starts_with("/api?t=search"), "unexpected path {path}");
        assert!(path.contains("cat=5000"), "the tv category only: {path}");
        assert!(path.contains("limit=100"), "one page: {path}");
        rss(&format!(
            "{}{}",
            item(
                "Some.Show.S01E02.1080p.WEB-GRP",
                "guid-held",
                3_900_000_000,
                T,
                "http://reference.invalid/nzb?id=held"
            ),
            item(
                "Never.Posted.Here.S09E09.2160p.WEB-NOPE",
                "guid-absent",
                2_000_000_000,
                T,
                "http://reference.invalid/nzb?id=absent"
            )
        ))
    });
    account(&d, "reference", f.port);
    *d.scoreboard_source.lock_ok() = "reference".to_string();
    // One category, so the run costs one request and 2 s of pacing
    // rather than four and 8 s. The dial is REDUCE-only by design
    // (memory nzbfast-scoreboard-cost-control), which is what makes it
    // safe to narrow here.
    *d.scoreboard_cats.lock_ok() = vec!["tv".to_string()];
    d.scoreboard_enabled.store(true, Ordering::Relaxed);

    let msg = super::scoreboard::run(&d).expect("the sample run must complete");
    let paths = f.paths();
    assert_eq!(paths.len(), 1, "one category, one request: {paths:?}");
    assert!(
        msg.contains("2 sample(s) stored") && msg.contains("1 named, 1 present of 2"),
        "run summary was {msg:?}"
    );

    // The stored rows are the KPI, read back the way the dashboard
    // card reads them.
    let cats = d
        .with_index(|ix| ix.scoreboard_stats(T - 86_400).ok())
        .expect("the samples must be readable back");
    assert_eq!(cats.len(), 1, "one measured category: {cats:?}");
    assert_eq!(cats[0].category, "tv");
    assert_eq!(
        (
            cats[0].total,
            cats[0].have_named,
            cats[0].have_unnamed,
            cats[0].missing
        ),
        (2, 1, 0, 1),
        "the verdicts must describe the index the sampler scored against"
    );
    assert_eq!(
        cats[0].lag_median_secs, 7_200,
        "lag is measured from our own first_seen"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The corr rig: a dark row of three articles, a title-only pre for
/// the same release, and the STRONG suggestion the real correlation
/// walk makes of the pair. Returns the release id and its message-ids.
fn seed_corr_suggestion(d: &Arc<Daemon>, title: &str) -> (i64, [&'static str; 3]) {
    let msgids = [
        "<0f1e2d3c4b5a@nyuu>",
        "<1f1e2d3c4b5a@nyuu>",
        "<2f1e2d3c4b5a@nyuu>",
    ];
    let mut ix = nzbkit::index::Index::open(&d.index_db).unwrap();
    // The pre feed's title-only line (the live public relay shape)
    // and, an hour later, the obfuscated post within 3% of the
    // announced size: the design's own worked example, which scores
    // STRONG.
    ix.predb_store(
        &[nzbkit::predb::PreLine {
            kind: nzbkit::predb::PreKind::New,
            title: title.to_string(),
            category: "X264-HD".to_string(),
            size: 4_900_000_000,
            date: T,
            source: "PRE".to_string(),
            ..Default::default()
        }],
        T,
    )
    .unwrap();
    // Three articles of one obfuscated file: three is exactly
    // MSGID_KEYS_PER_FILE, so the row holds the quorum floor and not
    // one key more - the tightest shape the join can succeed on.
    let entries: Vec<_> = msgids
        .iter()
        .enumerate()
        .map(|(i, m)| {
            over(
                &format!(r#""aQ3xY7Bm2ZpK4L.part01.rar" yEnc ({}/3)"#, i + 1),
                m,
                T + 3_600,
                1_666_666_667,
            )
        })
        .collect();
    ix.ingest("alt.binaries.x264", &entries, T + 4_000).unwrap();
    // Suggest-only: the walk stores a candidate and names nothing.
    let (examined, suggested, applied) = ix.predb_corr_backlog(100, 0, false, T + 4_000).unwrap();
    assert_eq!(
        (examined, suggested, applied),
        (1, 1, 0),
        "the correlation walk must produce exactly the suggestion under test"
    );
    let rid = ix.search("", 10).unwrap()[0].id;
    let picks = ix.corr_confirm_pick(10).unwrap();
    assert_eq!(
        picks.iter().map(|(r, _, _, _)| *r).collect::<Vec<_>>(),
        vec![rid],
        "and it must be STRONG enough for the confirm lane to pick"
    );
    (rid, msgids)
}

/// The NZB the fixture serves for that rig, listing the same ids.
fn corr_nzb(ids: &[&str]) -> String {
    let segs: String = ids
        .iter()
        .enumerate()
        .map(|(i, m)| {
            format!(
                "<segment bytes=\"1666666667\" number=\"{}\">{}</segment>",
                i + 1,
                m.trim_matches(['<', '>'])
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"p@e\" date=\"{}\" \
         subject=\"&quot;aQ3xY7Bm2ZpK4L.part01.rar&quot; yEnc (1/3)\">\
         <groups><group>alt.binaries.x264</group></groups>\
         <segments>{segs}</segments></file></nzb>",
        T + 3_600
    )
}

/// TODO 161 item 3, the whole lane: a STRONG correlation suggestion
/// that no byte probe can reach is settled by the user's own indexer.
///
/// This is the path the 13 Aug audit found structurally unreachable
/// (949 suggested / 12 rejected / 0 confirmed): the correlation
/// population deliberately excludes probe-reachable rows, so the
/// download-time byte oracle almost never fires on one. PR #28 added
/// this lane as the answer and then deployed it inert, so nobody knew
/// whether it worked. It does: search, NZB fetch, msgid quorum join,
/// `apply_proven_name` - and the suggestion comes out `confirmed`
/// with the release wearing the name.
///
/// The suggestion is made by the REAL correlation walk over a real
/// ingested post, not hand-written into `pre_corr`: the population
/// rule is half of what is under test.
#[test]
fn a_correlation_suggestion_reaches_confirmed_through_the_indexer_lane() {
    let dir = tdir("corr");
    let d = crate::serve::testutil::test_daemon(&dir);
    let title = "Some.Film.2026.1080p.WEB.H264-GRP";
    let (rid, msgids) = seed_corr_suggestion(&d, title);
    // The account: one search, then one NZB grab from the same origin.
    let want = title.to_string();
    let ids = msgids;
    let mut f = fixture(move |path, port| {
        if path.starts_with("/api?t=search") {
            assert!(
                path.contains(&crate::newznab::urlenc(&want)),
                "the search must ask for the suggested title: {path}"
            );
            return rss(&item(
                &want,
                "guid-1",
                4_900_000_000,
                T,
                &format!("http://127.0.0.1:{port}/getnzb?id=1"),
            ));
        }
        assert!(path.starts_with("/getnzb"), "unexpected path {path}");
        corr_nzb(&ids)
    });
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb_corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        super::indexer::corr_confirm_once(&d),
        "an armed lane with a pick and a live account must spend an attempt"
    );
    let paths = f.paths();
    assert_eq!(paths.len(), 2, "one search and one grab: {paths:?}");

    let row = d
        .with_index(|ix| ix.search("", 10).ok())
        .expect("the index must still read")
        .into_iter()
        .find(|r| r.id == rid)
        .expect("the release must still be there");
    assert_eq!(
        row.pre_title, title,
        "the release must wear the proven name"
    );
    assert!(
        row.pre_source.contains("nzb-indexer") || row.pre_source.contains("msgid"),
        "the provenance must name the proof, got {:?}",
        row.pre_source
    );
    let hints = d.with_index(|ix| ix.pre_hints(&[rid]).ok()).unwrap();
    assert_eq!(
        hints.iter().map(|h| h.5.clone()).collect::<Vec<_>>(),
        vec!["confirmed".to_string()],
        "the suggestion must settle CONFIRMED - the verdict the audit \
         found unreachable by waiting"
    );
    // The lane must also retire the suggestion from its own pick, or
    // one suggestion could cost the user's quota twice.
    let picks = d
        .with_index(|ix| ix.corr_confirm_pick(10).ok())
        .unwrap_or_default();
    assert!(picks.is_empty(), "a checked suggestion must not re-pick");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The pivot this lane shipped with, closed: an NZB link the far end
/// CHOSE may not reach a private address that is not the account's own
/// socket.
///
/// Found while proving TODO 161 item 3. Every other lane that follows
/// a response-supplied link - indexer grabs, the RSS poller, the
/// watchlist, the scoreboard's own calibration - fetches through
/// `fetch_url_from`, bound to where the search answered (M12 / TODO
/// 135). This one fetched through the plain indexer agent, whose SSRF
/// guard deliberately permits loopback and the LAN so that a
/// self-hosted Prowlarr stays reachable - so a hostile or compromised
/// account could name any other service on the user's own box and have
/// the daemon GET it, up to CONFIRM_PER_DAY times a day.
///
/// The neighbour here is a second loopback socket that must never be
/// touched.
#[test]
fn the_confirm_grab_refuses_a_link_pointing_at_the_service_next_door() {
    let dir = tdir("corr-ssrf");
    let d = crate::serve::testutil::test_daemon(&dir);
    let title = "Some.Film.2026.1080p.WEB.H264-GRP";
    let (rid, msgids) = seed_corr_suggestion(&d, title);
    // The neighbour: same host, different port, nothing to do with the
    // indexer. It would answer a perfectly good NZB if it were ever
    // asked, so only the refusal can keep the name off the release.
    let ids = msgids;
    let mut neighbour = fixture(move |_, _| corr_nzb(&ids));
    let victim_port = neighbour.port;
    let want = title.to_string();
    let mut f = fixture(move |path, _| {
        assert!(path.starts_with("/api?t=search"), "unexpected path {path}");
        rss(&item(
            &want,
            "guid-1",
            4_900_000_000,
            T,
            &format!("http://127.0.0.1:{victim_port}/getnzb?id=1"),
        ))
    });
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb_corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    // The attempt is still spent - the lane looked, and the suggestion
    // is stamped - but the grab must not happen.
    assert!(super::indexer::corr_confirm_once(&d));
    assert_eq!(f.paths().len(), 1, "the search, and nothing else");
    assert!(
        neighbour.paths().is_empty(),
        "the service next door must never be asked"
    );
    let row = d
        .with_index(|ix| ix.search("", 10).ok())
        .expect("the index must still read")
        .into_iter()
        .find(|r| r.id == rid)
        .expect("the release must still be there");
    assert_eq!(row.pre_title, "", "a refused fetch must not name anything");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex M6: the dashboard nests the confirm lane under the
/// correlation switch, so correlation OFF greys every confirm control
/// out - but the worker used to gate on its own flag alone and kept
/// spending up to CONFIRM_PER_DAY indexer lookups a day on a lane the
/// user could no longer see or reach. With the parent off, an armed
/// child with a pending STRONG suggestion and a live account must
/// spend nothing: no HTTP request, no quota increment, no checked_at
/// stamp. The suggestion stays pickable for when correlation returns.
#[test]
fn confirm_stands_down_when_correlation_is_off_even_with_the_child_armed() {
    let dir = tdir("corr-parent-off");
    let d = crate::serve::testutil::test_daemon(&dir);
    let title = "Some.Film.2026.1080p.WEB.H264-GRP";
    let (_rid, _msgids) = seed_corr_suggestion(&d, title);
    let mut f = fixture(move |path, _| panic!("no request may leave the daemon, got {path}"));
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb_corr_enabled.store(false, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        !super::indexer::corr_confirm_once(&d),
        "with correlation off the lane must report no attempt spent"
    );
    assert!(f.paths().is_empty(), "zero confirmation HTTP requests");
    let spent = d
        .with_index(|ix| ix.kv_get("corr_confirm_spent"))
        .unwrap_or_default();
    assert!(
        spent.is_empty() || spent == "0",
        "the daily budget must not move, got {spent:?}"
    );
    // No checked_at stamp: the suggestion must still pick, so turning
    // correlation back on resumes exactly where the user left off.
    let picks = d
        .with_index(|ix| ix.corr_confirm_pick(10).ok())
        .unwrap_or_default();
    assert_eq!(
        picks.len(),
        1,
        "the suggestion must remain unchecked and pickable"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
