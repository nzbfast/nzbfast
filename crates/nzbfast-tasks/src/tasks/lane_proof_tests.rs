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

fn harvest_exact_seeds(d: &Arc<Daemon>) -> crate::seed_harvest::HarvestReport {
    let mut state = crate::seed_harvest::HarvestState::new(d.index_era());
    crate::seed_harvest::tick(d, &mut state)
}

fn settle_exact_seed_names(d: &Arc<Daemon>) -> nzbkit::index::NzbSeedReplayStats {
    d.with_index_mut_retiring_ddl(|index| {
        index
            .nzb_seed_reconcile(crate::epoch_secs() as i64 + 3_600, 64)
            .ok()
    })
    .expect("settle exact seed names after the quiet window")
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
    let d = crate::testutil::test_daemon(&dir);
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
    *d.scoreboard.source.lock_ok() = "reference".to_string();
    // One category, so the run costs one request and 2 s of pacing
    // rather than four and 8 s. The dial is REDUCE-only by design
    // (memory nzbfast-scoreboard-cost-control), which is what makes it
    // safe to narrow here.
    *d.scoreboard.cats.lock_ok() = vec!["tv".to_string()];
    d.scoreboard.enabled.store(true, Ordering::Relaxed);

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
    let d = crate::testutil::test_daemon(&dir);
    let title = "Some.Film.2026.1080p.WEB.H264-GRP";
    let (rid, msgids) = seed_corr_suggestion(&d, title);
    // The account: one search, then one NZB grab from the same origin.
    let want = title.to_string();
    let ids = msgids;
    let mut f = fixture(move |path, port| {
        if path.starts_with("/api?t=search") {
            assert!(
                path.contains(&crate::netfetch::urlenc(&want)),
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
    // The account's user-facing name deliberately collides with the reserved
    // public source. Commercial provenance must use its internal namespace,
    // not inherit this configurable label and become shadow-only.
    account(&d, "posted-nzb", f.port);
    *d.corr_confirm_source.lock_ok() = "posted-nzb".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        super::indexer::corr_confirm_once(&d),
        "an armed lane with a pick and a live account must spend an attempt"
    );
    let harvested = harvest_exact_seeds(&d);
    assert_eq!((harvested.stored, harvested.named), (1, 0), "{harvested:?}");
    let settled = settle_exact_seed_names(&d);
    assert_eq!(settled.claims_applied, 1, "{settled:?}");
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

/// The expectation oracle, end to end: an
/// episode the TVmaze calendar says AIRED is searched by show and
/// SxxEyy token, the matching listing is grabbed, and the msgid join
/// names the dark release with the LISTING's full title - the name the
/// indexer was handed with the upload, which no calendar and no
/// correlation could supply. A same-code listing from a DIFFERENT show
/// is served first and must be skipped: the episode token alone is not
/// identity, show plus token is.
#[test]
fn an_expected_episode_is_grabbed_and_named_by_its_listing() {
    let dir = tdir("expected");
    let d = crate::testutil::test_daemon(&dir);
    let full_title = "Some.Show.S01E05.1080p.WEB.h264-GRP";
    let msgids = [
        "<e0f1a2b3c4d5@sess>",
        "<e1f1a2b3c4d5@sess>",
        "<e2f1a2b3c4d5@sess>",
    ];
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        let mut ix = nzbkit::index::Index::open(&d.index_db).unwrap();
        // The dark quarry: one obfuscated three-article file, no pre
        // row, nothing for the corr pick.
        let entries: Vec<_> = msgids
            .iter()
            .enumerate()
            .map(|(i, m)| {
                over(
                    &format!(r#""pQ4rS5tU6vW7xY8z.part01.rar" yEnc ({}/3)"#, i + 1),
                    m,
                    T + 3_600,
                    1_666_666_667,
                )
            })
            .collect();
        ix.ingest("alt.binaries.tv", &entries, T + 4_000).unwrap();
        assert!(ix.corr_confirm_pick(10).unwrap().is_empty());
        // The oracle's state, driven directly: one aired episode
        // queued, both sweeps throttled so the test fetches nothing
        // from TVmaze and falls through to no seed sweep either.
        ix.kv_set("expected_at", &wall.to_string()).unwrap();
        ix.kv_set("seed_listing_at", &wall.to_string()).unwrap();
        ix.kv_set(
            "expected_queue_v1",
            r#"[{"Tv":{"show":"Some Show","season":1,"episode":5}}]"#,
        )
        .unwrap();
    }
    let want_q = crate::netfetch::urlenc("Some Show S01E05");
    let ids = msgids;
    let full = full_title.to_string();
    let mut f = fixture(move |path, port| {
        if path.starts_with("/api?t=search") {
            assert!(
                path.contains(&want_q),
                "the search must carry show plus episode token: {path}"
            );
            // A decoy with the RIGHT code but the WRONG show comes
            // first; the pick must pass over it.
            return rss(&format!(
                "{}{}",
                item(
                    "Other.Show.S01E05.720p.WEB.h264-BAD",
                    "g-decoy",
                    2_000_000_000,
                    T,
                    &format!("http://127.0.0.1:{port}/getnzb?id=9")
                ),
                item(
                    &full,
                    "g-real",
                    5_000_000_000,
                    T,
                    &format!("http://127.0.0.1:{port}/getnzb?id=1")
                )
            ));
        }
        assert!(
            path.starts_with("/getnzb?id=1"),
            "only the matching listing may be grabbed: {path}"
        );
        corr_nzb(&ids)
    });
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        super::indexer::corr_confirm_once(&d),
        "an expected pick spends the attempt"
    );
    let harvested = harvest_exact_seeds(&d);
    assert_eq!((harvested.stored, harvested.named), (1, 0), "{harvested:?}");
    let settled = settle_exact_seed_names(&d);
    assert_eq!(settled.claims_applied, 1, "{settled:?}");
    assert!(
        !super::indexer::corr_confirm_once(&d),
        "queue drained, both sweeps throttled - the lane stands down"
    );
    let paths = f.paths();
    assert_eq!(paths.len(), 2, "one search and one grab: {paths:?}");

    let row = d
        .with_index(|ix| ix.search("pQ4rS5tU6vW7xY8z", 10).ok())
        .expect("index must read")
        .into_iter()
        .next()
        .expect("the dark release is still there");
    assert_eq!(
        row.pre_title, full_title,
        "named with the LISTING's full release title"
    );
    assert_eq!(row.pre_source, "proven:msgid-set:external-nzb:nzb-indexer");
    let done = d
        .with_index(|ix| ix.kv_get("expected_done_v1"))
        .unwrap_or_default();
    assert!(
        done.contains("tvsomeshows01e05"),
        "the episode is rung, one shot only: {done}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The seed pick, end to end (research/SEEDJOIN-PROBE-2026-09-01.md
/// build item 1): with NO correlation suggestion on file - the state
/// research/NAMECORR-PRECISION-2026-09-01.md leaves the lane in
/// permanently - the confirm lane samples the reference's own newest
/// listings, screens out what the index already holds readably, grabs
/// the one new listing, and the message-id join names a dark release
/// nothing header-side could ever touch. Proof-grade, same dial, same
/// budget. The matching articles deliberately arrive only after the
/// paid grab, proving that the saved NZB survives and replays later.
#[test]
fn the_seed_pick_names_a_dark_release_without_any_suggestion() {
    let dir = tdir("seed");
    let d = crate::testutil::test_daemon(&dir);
    let title = "Seeded.Show.S01E01.1080p.WEB.H264-GRP";
    let held = "Already.Held.2026.1080p.WEB.H264-GRP";
    let msgids = [
        "<a0b1c2d3e4f5@sess>",
        "<a1b1c2d3e4f5@sess>",
        "<a2b1c2d3e4f5@sess>",
    ];
    {
        let mut ix = nzbkit::index::Index::open(&d.index_db).unwrap();
        // A release the index already holds READABLY under the
        // decoy listing's exact name: the sweep's screen must skip it
        // rather than spend the grab budget re-fetching what header
        // ingest already named.
        for pn in 1..=2u32 {
            ix.ingest(
                "alt.binaries.x264",
                &[over(
                    &format!(r#""{held}.part01.rar" yEnc ({pn}/2)"#),
                    &format!("<held-{pn}@x>"),
                    T + 3_600,
                    700_000,
                )],
                T + 4_000,
            )
            .unwrap();
        }
        assert!(
            ix.corr_confirm_pick(10).unwrap().is_empty(),
            "no suggestion exists - the seed is the only pick source"
        );
    }
    // Park the expected oracle too: its queue is empty, but pinning
    // the throttle documents the pick order this test relies on -
    // seed fires only when no expected episode is waiting.
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    d.with_index(|ix| ix.kv_set("expected_at", &wall.to_string()).ok());
    let reqs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reqs2 = reqs.clone();
    let want = title.to_string();
    let decoy = held.to_string();
    let ids = msgids;
    let mut f = fixture(move |path, port| {
        let n = reqs2.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            // First request: the newest-listing sweep.
            assert!(path.starts_with("/api?t=search"), "sweep first: {path}");
            // A newest-listing sweep carries NO `q` at all. Sending an
            // empty one is what DrunkenSlug answers `201 (q must not be
            // empty)` to, which took the seed pick off the air for a
            // whole live window on a real account - see
            // `an_empty_query_is_omitted_rather_than_sent_empty`.
            assert!(
                !path.contains("q="),
                "an empty q is omitted, never sent: {path}"
            );
            // The control arm for the category screen below: this
            // daemon was never told an interest, so the sweep must go
            // out exactly as wide as it did before the screen existed.
            assert!(
                !path.contains("cat="),
                "no interest chosen - the sweep must not narrow: {path}"
            );
            return rss(&format!(
                "{}{}",
                item(
                    &decoy,
                    "g-held",
                    1_400_000,
                    T + 3_600,
                    &format!("http://127.0.0.1:{port}/getnzb?id=9")
                ),
                item(
                    &want,
                    "",
                    5_000_000_000,
                    T + 3_600,
                    &format!("http://127.0.0.1:{port}/getnzb?id=1&amp;apikey=fixture-key")
                )
            ));
        }
        if n == 1 {
            assert!(
                path.contains(&crate::netfetch::urlenc(&want)),
                "then the exact-title search: {path}"
            );
            return rss(&item(
                &want,
                "",
                5_000_000_000,
                T + 3_600,
                &format!("http://127.0.0.1:{port}/getnzb?id=1&amp;apikey=fixture-key"),
            ));
        }
        assert!(path.starts_with("/getnzb"), "then the grab: {path}");
        corr_nzb(&ids)
    });
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        super::indexer::corr_confirm_once(&d),
        "a seed pick spends the attempt like any other"
    );
    let first_harvest = harvest_exact_seeds(&d);
    assert_eq!(first_harvest.stored, 1, "{first_harvest:?}");
    assert_eq!(first_harvest.named, 0, "{first_harvest:?}");
    let before = d
        .with_index(|ix| ix.nzb_seed_inventory().ok())
        .expect("the joinless fetch must already be durable");
    assert_eq!(before.sets, 1);
    assert_eq!(before.assertions, 1);
    assert_eq!(before.named_release_edges, 0);
    {
        let mut ix = nzbkit::index::Index::open(&d.index_db).unwrap();
        // The dark quarry reaches header ingest only after the reference
        // grab. Its random subject still has no correlation suggestion.
        let entries: Vec<_> = msgids
            .iter()
            .enumerate()
            .map(|(i, m)| {
                over(
                    &format!(r#""zX9qW8eR7tY6uI0o.part01.rar" yEnc ({}/3)"#, i + 1),
                    m,
                    T + 3_600,
                    1_666_666_667,
                )
            })
            .collect();
        ix.ingest("alt.binaries.x264", &entries, T + 4_000).unwrap();
        assert!(
            ix.corr_confirm_pick(10).unwrap().is_empty(),
            "the random subject still supplies no suggestion"
        );
    }
    // A second tick straight after: the queue is drained and the sweep
    // is hour-throttled, so it must replay locally without an API call.
    assert!(
        !super::indexer::corr_confirm_once(&d),
        "drained queue plus throttled sweep must not spend"
    );
    let replay = harvest_exact_seeds(&d);
    assert_eq!(replay.named, 0, "a fresh manifest must wait: {replay:?}");
    let settled = settle_exact_seed_names(&d);
    assert_eq!(settled.claims_applied, 1, "{settled:?}");
    let paths = f.paths();
    assert_eq!(paths.len(), 3, "sweep, title search, grab: {paths:?}");

    let row = d
        .with_index(|ix| ix.search("zX9qW8eR7tY6uI0o", 10).ok())
        .expect("the index must still read")
        .into_iter()
        .next()
        .expect("the dark release must still be there");
    assert_eq!(row.pre_title, title, "the join named the dark release");
    assert_eq!(
        row.pre_source, "proven:msgid-set:external-nzb:nzb-indexer",
        "provenance names the durable replay proof and its source"
    );
    let inventory = d
        .with_index(|ix| ix.nzb_seed_inventory().ok())
        .expect("the fetched NZB must remain as durable identity evidence");
    assert_eq!(inventory.sets, 1);
    assert_eq!(inventory.assertions, 1);
    assert_eq!(inventory.named_release_edges, 1);
    assert_eq!(inventory.fan_out(), 1.0);
    let proof_xml = corr_nzb(&msgids);
    let expected_guid = crate::nzb_sha(proof_xml.as_bytes());
    let duplicate = d
        .with_index_mut_retiring_ddl(|ix| {
            Some(ix.nzb_seed_store_xml(
                nzbkit::index::NzbSeedSpec {
                    source: crate::seed_harvest::INDEXER_SOURCE,
                    source_guid: &expected_guid,
                    name: title,
                    category: "0",
                    posted: T + 3_600,
                    bytes: 5_000_000_000,
                },
                proof_xml.as_bytes(),
                T + 5_000,
            ))
        })
        .expect("the index must be available")
        .expect("the digest assertion must store");
    assert!(
        !duplicate.new_assertion,
        "the fetched XML must have been stored once under its content digest"
    );
    // The attempted ring holds the seeded title, so a joinless repeat
    // could never re-grab it; and both spends were persisted.
    let (ring, spent) = d
        .with_index(|ix| {
            Some((
                ix.kv_get("seed_recent_v1").unwrap_or_default(),
                ix.kv_get("corr_confirm_spent").unwrap_or_default(),
            ))
        })
        .unwrap();
    assert!(
        ring.contains(&nzbkit::predb::match_key(title)),
        "the seeded title is ringed: {ring}"
    );
    assert_eq!(spent, "2", "one sweep hit plus one attempt");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The category screen on the same sweep (6c of
/// research/SEED-LANE-LIVE-2026-09-02.md): the user's own stated
/// interests reach the wire as a `cat=` on the newest-listing request.
///
/// This is what the screen exists to stop. Measured over 247 real
/// grabs, 48% of the UNscreened feed was category 6000, against 123
/// `adult` rows in 67 million here - the index scans none of the groups
/// that content is posted to, so every one of those grabs was quota
/// spent on something that could never join. The same one hit with
/// `cat=2000,5000` came back 88 TV and 12 movies.
///
/// The control arm is in the test above: with no interest chosen the
/// sweep must carry no `cat=` at all, because narrowing a user who
/// never answered the setup question would be a decision nobody asked
/// for. The two together are the whole rule.
#[test]
fn the_seed_sweep_asks_only_for_the_categories_the_user_chose() {
    let dir = tdir("seedcat");
    let d = crate::testutil::test_daemon(&dir);
    // Stored out of order and with a key no build offers, which is the
    // shape a hand-edited settings.json takes: the unknown one is
    // dropped and the rest come back in the offered order, so the
    // request is comparable rather than whatever was typed.
    *d.index_interests.lock_ok() = "tv, aliens ,movies".to_string();
    let mut f = fixture(move |path, _port| {
        assert!(path.starts_with("/api?t=search"), "the sweep: {path}");
        assert!(
            path.contains("&cat=2000,5000&"),
            "the chosen interests must reach the wire, and nothing else \
             - no 6000: {path}"
        );
        rss("")
    });
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);
    assert!(
        super::indexer::corr_confirm_once(&d),
        "the sweep hit is spent even when it queues nothing"
    );
    assert_eq!(f.paths().len(), 1, "the sweep alone - nothing to grab");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A reference that REFUSES to list newest is asked once, ever - not
/// once an hour forever.
///
/// The live defect, found 2 Sep 2026 on a running daemon and the reason
/// this test exists: `seed_next` sent `q=` empty on the stated
/// assumption that any newznab-kind site lists newest for it, and
/// DrunkenSlug answers `<error code="201" description="Incorrect
/// parameter (q must not be empty)"/>`. The sweep charges its quota hit
/// and stamps its hourly throttle BEFORE the request - deliberately, so
/// a broken account is not hammered once a minute - so every refusal is
/// a hit paid for an error, and the seed queue could never fill on that
/// account. What it actually cost, measured rather than assumed: the
/// sweep ran ONCE in the 3 h 17 m the lane was up, so one wasted hit and
/// a seeded pick 100% off the air. (An earlier reading of "24 a day" was
/// the hourly-throttle CEILING quoted as a rate; `seed_next` is reached
/// only when the expected and corr picks both yield nothing, so it never
/// got near it.) `search_url` no longer sends the shape
/// that provoked it, but the SOURCE of the assumption is what had no
/// coverage: the next indexer will refuse something else.
///
/// The throttle is cleared between the two ticks on purpose. Leaving it
/// would prove only that the hourly timer works, which was never in
/// doubt; clearing it puts the second tick in exactly the position the
/// live daemon was in an hour later.
#[test]
fn a_reference_that_refuses_the_newest_listing_is_asked_once_not_hourly() {
    let dir = tdir("seed-refusal");
    let d = crate::testutil::test_daemon(&dir);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Park the expected oracle: the seed sweep must be the only thing
    // that can reach the fixture.
    d.with_index(|ix| {
        ix.kv_set("expected_at", &wall.to_string()).ok()?;
        assert!(ix.corr_confirm_pick(10).unwrap().is_empty());
        Some(())
    })
    .unwrap();

    let mut f = fixture(move |path, _port| {
        assert!(path.starts_with("/api?t=search"), "the sweep only: {path}");
        // Newznab reports this with HTTP 200 and an error document.
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <error code=\"201\" description=\"Incorrect parameter (q must not be empty)\"/>"
            .to_string()
    });
    account(&d, "refuses-listing", f.port);
    *d.corr_confirm_source.lock_ok() = "refuses-listing".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        super::indexer::corr_confirm_once(&d),
        "the first ask is charged like any other - the tick SPENT a hit"
    );
    assert!(
        d.indexer_rt
            .lock_ok()
            .no_listing
            .contains(&d.indexers.lock_ok()[0].identity()),
        "the refusal is latched against the FAR END, not the label"
    );

    // An hour later, as far as the throttle is concerned.
    d.with_index(|ix| ix.kv_set("seed_listing_at", "0").ok());
    assert!(!super::indexer::corr_confirm_once(&d));
    d.with_index(|ix| ix.kv_set("seed_listing_at", "0").ok());
    assert!(!super::indexer::corr_confirm_once(&d));

    let paths = f.paths();
    assert_eq!(
        paths.len(),
        1,
        "asked once and never again, throttle or no throttle: {paths:?}"
    );
    // And the daily budget is charged for that one ask and nothing
    // more. This is the number the defect burned 24 of a day.
    let spent = d
        .with_index(|ix| ix.kv_get("corr_confirm_spent"))
        .unwrap_or_default();
    assert_eq!(spent, "1", "one hit spent in total, not one per tick");
    let _ = std::fs::remove_dir_all(&dir);
}

/// F25 and the seed-replay branch's `search_reserved` backstop fix the
/// same defect from opposite ends, and this proves the composition.
///
/// The defect: a listing sweep is one API hit whose whole product is a
/// POPPED title - `seed_pop` takes it out of the queue and rings its key
/// so the hourly sweep will not offer it again - and the confirm search
/// that title needs is a hit of its own. Spending the LAST hit on the
/// sweep therefore consumed a queued title with no search behind it, and
/// it never came back.
///
/// F25 (main, 1 Sep 2026) closes it at the front: `seed_next` asks
/// `hits_left(cfg, 2)`, so with exactly one hit left the sweep never
/// runs and the hit is never spent. That is what this test now asserts,
/// and it is strictly cheaper than the alternative - nothing is
/// requested at all.
///
/// The branch's `search_reserved` arm stays as the BACKSTOP, because
/// `Usage` is daemon-wide: a watchlist or *arr burst can take the
/// second hit between `seed_next`'s check-and-charge and the
/// reservation, and then the popped title has to be put back. That path
/// is a race this end-to-end shape cannot construct, and it keeps its
/// own coverage in `indexer/posted_seed_tests.rs`
/// (`a_committed_requeue_with_an_uncleared_journal_replays_idempotently`
/// and the nine retry-journal tests beside it).
///
/// This test asserted the requeue end-to-end until 2 Sep 2026, when F25
/// made the scenario it built unreachable. Retargeted rather than
/// deleted: the guarantee is the same one, proved at the cheaper end.
#[test]
fn the_final_hit_is_never_spent_on_a_listing_whose_search_cannot_follow() {
    let dir = tdir("seed-final-hit");
    let d = crate::testutil::test_daemon(&dir);
    let title = "Final.Hit.Show.S01E01.1080p.WEB.H264-GRP";
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    d.with_index(|ix| {
        ix.kv_set("expected_at", &wall.to_string()).ok()?;
        assert!(ix.corr_confirm_pick(10).unwrap().is_empty());
        Some(())
    })
    .unwrap();

    let listing_title = title.to_string();
    let mut f = fixture(move |path, port| {
        // Reaching the fixture at all is the failure: with one hit left
        // the sweep must not run.
        assert!(path.starts_with("/api?t=search"), "listing only: {path}");
        rss(&item(
            &listing_title,
            "final-hit-guid",
            5_000_000_000,
            T + 3_600,
            &format!("http://127.0.0.1:{port}/getnzb?id=1"),
        ))
    });
    account(&d, "confirm-src", f.port);
    {
        let mut indexers = d.indexers.lock_ok();
        indexers[0].hits_per_day = 1;
        indexers[0].grabs_per_day = 1;
    }
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        !super::indexer::corr_confirm_once(&d),
        "one hit cannot cover a sweep AND the search it exists to feed"
    );
    assert!(
        !super::indexer::corr_confirm_once(&d),
        "the second tick stands down the same way"
    );
    let paths = f.paths();
    assert!(paths.is_empty(), "nothing was requested: {paths:?}");
    let usage = d.indexer_rt.lock_ok().usage.clone();
    assert_eq!(
        usage.hits.get("confirm-src").copied().unwrap_or(0),
        0,
        "the final hit is still there for a tick that can finish"
    );
    assert_eq!(usage.grabs.get("confirm-src").copied().unwrap_or(0), 0);
    let (queue, recent, spent) = d
        .with_index(|ix| {
            Some((
                ix.kv_get("seed_queue_v1").unwrap_or_default(),
                ix.kv_get("seed_recent_v1").unwrap_or_default(),
                ix.kv_get("corr_confirm_spent").unwrap_or_default(),
            ))
        })
        .unwrap();
    assert!(
        queue.is_empty(),
        "no sweep ran, so nothing was queued: {queue}"
    );
    assert!(
        !recent.contains(&nzbkit::predb::match_key(title)),
        "no title was rung: {recent}"
    );
    assert!(
        spent.is_empty() || spent == "0",
        "no budget spent: {spent:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_newest_listing_still_reports_its_spent_request() {
    let dir = tdir("seed-empty-listing-spend");
    let d = crate::testutil::test_daemon(&dir);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    d.with_index(|ix| ix.kv_set("expected_at", &wall.to_string()).ok());
    let mut f = fixture(move |path, _| {
        assert!(path.starts_with("/api?t=search"), "listing only: {path}");
        rss("")
    });
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        super::indexer::corr_confirm_once(&d),
        "the return contract reports the empty listing request as spent"
    );
    assert!(!super::indexer::corr_confirm_once(&d));
    assert_eq!(f.paths().len(), 1);
    assert_eq!(
        d.with_index(|ix| ix.kv_get("corr_confirm_spent"))
            .unwrap_or_default(),
        "1"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two suggestion rows carrying ONE title (a pre line with two dark
/// posts inside its size band - the everyday shape) must cost ONE
/// search and one grab, not two of each: the first attempt lands the
/// title in the recent ring, and the sibling suggestion is stamped
/// without a lookup on the next tick. Measured live before the fix:
/// one title, three grabs, three minutes (beta 4, 1 Sep 2026).
#[test]
fn a_sibling_suggestion_with_the_same_title_is_stamped_not_rebought() {
    let dir = tdir("corr-dup-title");
    let d = crate::testutil::test_daemon(&dir);
    let title = "Some.Film.2026.1080p.WEB.H264-GRP";
    let (_rid, msgids) = seed_corr_suggestion(&d, title);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        let mut ix = nzbkit::index::Index::open(&d.index_db).unwrap();
        // The live shape (beta 4, 15:50-15:52Z): ONE pre, several dark
        // posts inside its size band. The pick surfaces the BEST
        // candidate per pre, so the sibling only becomes pickable
        // after the first is stamped - the duplicate arrives
        // SEQUENTIALLY, tick after tick, not in one batch.
        let extra = [
            "<7a8b9c0d1e2f@nyuu>",
            "<8a8b9c0d1e2f@nyuu>",
            "<9a8b9c0d1e2f@nyuu>",
        ];
        let entries: Vec<_> = extra
            .iter()
            .enumerate()
            .map(|(i, m)| {
                over(
                    &format!(r#""zW9vU8tS7rQ6pN.part01.rar" yEnc ({}/3)"#, i + 1),
                    m,
                    T + 3_700,
                    1_666_666_667,
                )
            })
            .collect();
        ix.ingest("alt.binaries.movies", &entries, T + 4_000)
            .unwrap();
        let picks = ix.corr_confirm_pick(10).unwrap();
        assert_eq!(
            picks.len(),
            1,
            "best-per-pre: one pickable now, the sibling after the stamp: {picks:?}"
        );
        // Park the other pick sources so the second tick's outcome is
        // the ring's doing alone.
        ix.kv_set("expected_at", &wall.to_string()).unwrap();
        ix.kv_set("seed_listing_at", &wall.to_string()).unwrap();
    }
    let ids = msgids;
    let want = title.to_string();
    let mut f = fixture(move |path, port| {
        if path.starts_with("/api?t=search") {
            return rss(&item(
                &want,
                "guid-1",
                4_900_000_000,
                T,
                &format!("http://127.0.0.1:{port}/getnzb?id=1"),
            ));
        }
        corr_nzb(&ids)
    });
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        super::indexer::corr_confirm_once(&d),
        "the first suggestion buys its lookup"
    );
    let harvested = harvest_exact_seeds(&d);
    assert_eq!((harvested.stored, harvested.named), (1, 0), "{harvested:?}");
    let settled = settle_exact_seed_names(&d);
    assert_eq!(settled.claims_applied, 1, "{settled:?}");
    assert!(
        !super::indexer::corr_confirm_once(&d),
        "the sibling is stamped off the ring and no other source is due"
    );
    let paths = f.paths();
    assert_eq!(
        paths.len(),
        2,
        "one search and one grab TOTAL across both ticks: {paths:?}"
    );
    let left = d
        .with_index(|ix| ix.corr_confirm_pick(10).ok())
        .unwrap_or_default();
    assert!(
        left.is_empty(),
        "both suggestions are stamped - attempted or ring-stamped: {left:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A queue polluted with dailies (season = the calendar year, the
/// TVmaze encoding for Morning Joe and friends) must drain them at
/// ZERO attempt cost: the first pop rings both dailies and hands back
/// the weekly behind them, and the weekly is what gets searched.
/// Measured before the filter: the oracle's first 13 live picks were
/// 13 daily news shows, 0 listings.
#[test]
fn dailies_drain_from_the_expected_queue_without_spending_attempts() {
    let dir = tdir("expected-dailies");
    let d = crate::testutil::test_daemon(&dir);
    let full_title = "Real.Show.S02E03.1080p.WEB.h264-GRP";
    let msgids = [
        "<d0e1f2a3b4c5@sess>",
        "<d1e1f2a3b4c5@sess>",
        "<d2e1f2a3b4c5@sess>",
    ];
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        let mut ix = nzbkit::index::Index::open(&d.index_db).unwrap();
        let entries: Vec<_> = msgids
            .iter()
            .enumerate()
            .map(|(i, m)| {
                over(
                    &format!(r#""kJ2hG3fD4sA5pO.part01.rar" yEnc ({}/3)"#, i + 1),
                    m,
                    T + 3_600,
                    1_666_666_667,
                )
            })
            .collect();
        ix.ingest("alt.binaries.tv", &entries, T + 4_000).unwrap();
        ix.kv_set("expected_at", &wall.to_string()).unwrap();
        ix.kv_set("seed_listing_at", &wall.to_string()).unwrap();
        // Three dailies ahead of the one weekly, covering BOTH live
        // encodings: season = the calendar year, and a plausible
        // season with the episode counter in the hundreds.
        ix.kv_set(
            "expected_queue_v1",
            r#"[{"Tv":{"show":"Morning Joe","season":2026,"episode":173}},
                {"Tv":{"show":"Bloomberg Brief","season":2026,"episode":174}},
                {"Tv":{"show":"First Take","season":20,"episode":237}},
                {"Tv":{"show":"Real Show","season":2,"episode":3}}]"#,
        )
        .unwrap();
    }
    let want_q = crate::netfetch::urlenc("Real Show S02E03");
    let ids = msgids;
    let full = full_title.to_string();
    let mut f = fixture(move |path, port| {
        if path.starts_with("/api?t=search") {
            assert!(
                path.contains(&want_q),
                "only the weekly may be searched - a daily leaked: {path}"
            );
            return rss(&item(
                &full,
                "g-1",
                5_000_000_000,
                T,
                &format!("http://127.0.0.1:{port}/getnzb?id=1"),
            ));
        }
        corr_nzb(&ids)
    });
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(
        super::indexer::corr_confirm_once(&d),
        "one attempt - the weekly's"
    );
    let harvested = harvest_exact_seeds(&d);
    assert_eq!((harvested.stored, harvested.named), (1, 0), "{harvested:?}");
    let settled = settle_exact_seed_names(&d);
    assert_eq!(settled.claims_applied, 1, "{settled:?}");
    assert!(
        !super::indexer::corr_confirm_once(&d),
        "queue empty, sweeps parked - the lane stands down"
    );
    let paths = f.paths();
    assert_eq!(
        paths.len(),
        2,
        "the weekly's search and grab ONLY: {paths:?}"
    );
    let row = d
        .with_index(|ix| ix.search("kJ2hG3fD4sA5pO", 10).ok())
        .expect("index reads")
        .into_iter()
        .next()
        .expect("the dark release is there");
    assert_eq!(row.pre_title, full_title);
    let done = d
        .with_index(|ix| ix.kv_get("expected_done_v1"))
        .unwrap_or_default();
    assert!(
        done.contains("tvmorningjoes2026e173") && done.contains("tvrealshows02e03"),
        "dailies rung on the way out, weekly rung by its attempt: {done}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The movie half of the expectation oracle: a film TMDB says landed
/// at home is searched by title+year, and the msgid join names the
/// dark release. A same-TITLE listing from a DIFFERENT year (a remake)
/// is served first and must be skipped - title alone is not identity,
/// title plus year is.
#[test]
fn an_expected_movie_is_grabbed_and_named_by_its_listing() {
    let dir = tdir("expected-movie");
    let d = crate::testutil::test_daemon(&dir);
    let full_title = "Some.Film.2026.1080p.WEB.H264-GRP";
    let msgids = [
        "<f0a1b2c3d4e5@sess>",
        "<f1a1b2c3d4e5@sess>",
        "<f2a1b2c3d4e5@sess>",
    ];
    {
        let mut ix = nzbkit::index::Index::open(&d.index_db).unwrap();
        let entries: Vec<_> = msgids
            .iter()
            .enumerate()
            .map(|(i, m)| {
                over(
                    &format!(r#""mN7bV6cX5zA4sD3f.part01.rar" yEnc ({}/3)"#, i + 1),
                    m,
                    T + 3_600,
                    1_666_666_667,
                )
            })
            .collect();
        ix.ingest("alt.binaries.movies", &entries, T + 4_000)
            .unwrap();
        assert!(ix.corr_confirm_pick(10).unwrap().is_empty());
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        ix.kv_set("expected_at", &wall.to_string()).unwrap();
        ix.kv_set("seed_listing_at", &wall.to_string()).unwrap();
        ix.kv_set(
            "expected_queue_v1",
            r#"[{"Movie":{"title":"Some Film","year":2026}}]"#,
        )
        .unwrap();
    }
    let want_q = crate::netfetch::urlenc("Some Film 2026");
    let ids = msgids;
    let full = full_title.to_string();
    let mut f = fixture(move |path, port| {
        if path.starts_with("/api?t=search") {
            assert!(path.contains(&want_q), "title plus year: {path}");
            // A 1998 remake with the same title comes first; the
            // year gate must pass over it.
            return rss(&format!(
                "{}{}",
                item(
                    "Some.Film.1998.1080p.BluRay.x264-OLD",
                    "g-remake",
                    5_000_000_000,
                    T,
                    &format!("http://127.0.0.1:{port}/getnzb?id=9")
                ),
                item(
                    &full,
                    "g-real",
                    5_000_000_000,
                    T,
                    &format!("http://127.0.0.1:{port}/getnzb?id=1")
                )
            ));
        }
        assert!(
            path.starts_with("/getnzb?id=1"),
            "only the right year: {path}"
        );
        corr_nzb(&ids)
    });
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    assert!(super::indexer::corr_confirm_once(&d));
    let harvested = harvest_exact_seeds(&d);
    assert_eq!((harvested.stored, harvested.named), (1, 0), "{harvested:?}");
    let settled = settle_exact_seed_names(&d);
    assert_eq!(settled.claims_applied, 1, "{settled:?}");
    let paths = f.paths();
    assert_eq!(paths.len(), 2, "search and grab: {paths:?}");
    let row = d
        .with_index(|ix| ix.search("mN7bV6cX5zA4sD3f", 10).ok())
        .expect("index reads")
        .into_iter()
        .next()
        .expect("the dark film is there");
    assert_eq!(row.pre_title, full_title, "named by the listing title");
    assert_eq!(row.pre_source, "proven:msgid-set:external-nzb:nzb-indexer");
    let done = d
        .with_index(|ix| ix.kv_get("expected_done_v1"))
        .unwrap_or_default();
    assert!(done.contains("mvsomefilm2026"), "movie rung: {done}");
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
/// the daemon GET it, up to the daily confirm budget times a day.
///
/// The neighbour here is a second loopback socket that must never be
/// touched.
#[test]
fn the_confirm_grab_refuses_a_link_pointing_at_the_service_next_door() {
    let dir = tdir("corr-ssrf");
    let d = crate::testutil::test_daemon(&dir);
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
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
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
/// spending up to the daily confirm budget in indexer lookups on a lane the
/// user could no longer see or reach. With the parent off, an armed
/// child with a pending STRONG suggestion and a live account must
/// spend nothing: no HTTP request, no quota increment, no checked_at
/// stamp. The suggestion stays pickable for when correlation returns.
#[test]
fn confirm_stands_down_when_correlation_is_off_even_with_the_child_armed() {
    let dir = tdir("corr-parent-off");
    let d = crate::testutil::test_daemon(&dir);
    let title = "Some.Film.2026.1080p.WEB.H264-GRP";
    let (_rid, _msgids) = seed_corr_suggestion(&d, title);
    let mut f = fixture(move |path, _| panic!("no request may leave the daemon, got {path}"));
    account(&d, "confirm-src", f.port);
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(false, Ordering::Relaxed);
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

/// A quota-refused tick must not CONSUME a queued candidate (bug
/// sweep, 1 Sep 2026). Both queue-backed pick sources destroy their
/// candidate as they pick it - `seed_pop` removes the title and rings
/// its match_key, `expected::pop` removes the pick and rings its key -
/// so the wall that refuses the attempt has to stand in front of the
/// pick, not behind it. With one grab a day already spent by another
/// lane (`Usage` is daemon-wide) and the confirm lane's own budget
/// untouched, every tick used to burn one queued title with no search
/// behind it: 40 minutes to empty the seed queue, and the burned keys
/// left in the recent ring so the hourly sweep would not re-queue them
/// after the quota reset. Two ticks here must leave both queues and
/// both rings exactly as they were, and must not touch the network.
///
/// AND THE PRE-CHECK ALONE IS NOT ENOUGH, which is the second half
/// below: `seed_next`'s listing sweep SPENDS A HIT OF ITS OWN and its
/// whole product is a popped, rung title. With exactly one hit left the
/// pre-check passes, the sweep takes that hit, pops a title - and the
/// authoritative wall behind the pick then refuses, so the title is
/// consumed with no search behind it and the ring stops the hourly
/// sweep re-queueing it. The sweep therefore asks for TWO hits.
#[test]
fn an_exhausted_quota_refuses_before_it_consumes_a_queued_candidate() {
    let dir = tdir("quotarefuse");
    let d = crate::testutil::test_daemon(&dir);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let queued =
        r#"["Seeded.One.S01E01.1080p.WEB.H264-GRP","Seeded.Two.S01E02.1080p.WEB.H264-GRP"]"#;
    {
        let ix = nzbkit::index::Index::open(&d.index_db).unwrap();
        // No suggestion on file, so the corr pick cannot fire and the
        // two queue-backed sources are the only candidates there are.
        assert!(ix.corr_confirm_pick(10).unwrap().is_empty());
        ix.kv_set("seed_queue_v1", queued).unwrap();
        ix.kv_set(
            "expected_queue_v1",
            r#"[{"Tv":{"show":"Some Show","season":1,"episode":5}}]"#,
        )
        .unwrap();
        // Both sweeps throttled: this test is about the pick, not
        // about refilling.
        ix.kv_set("expected_at", &now.to_string()).unwrap();
        ix.kv_set("seed_listing_at", &now.to_string()).unwrap();
    }
    // The fixture records anything that reaches it and answers with an
    // empty listing; a refusal must leave it with nothing recorded.
    let mut f = fixture(|_path, _port| rss(""));
    account(&d, "confirm-src", f.port);
    d.indexers.lock_ok()[0].grabs_per_day = 1;
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(now);
        rt.usage.count_grab("confirm-src");
    }
    *d.corr_confirm_source.lock_ok() = "confirm-src".to_string();
    d.predb.corr_enabled.store(true, Ordering::Relaxed);
    d.corr_confirm_enabled.store(true, Ordering::Relaxed);

    for tick in 1..=2 {
        assert!(
            !super::indexer::corr_confirm_once(&d),
            "tick {tick}: the grab quota is spent, so the lane must refuse"
        );
    }
    let paths = f.paths();
    assert!(
        paths.is_empty(),
        "a refused tick spends no API call: {paths:?}"
    );
    let (queue, ring, expected_queue, done) = d
        .with_index(|ix| {
            Some((
                ix.kv_get("seed_queue_v1").unwrap_or_default(),
                ix.kv_get("seed_recent_v1").unwrap_or_default(),
                ix.kv_get("expected_queue_v1").unwrap_or_default(),
                ix.kv_get("expected_done_v1").unwrap_or_default(),
            ))
        })
        .unwrap();
    assert_eq!(queue, queued, "both seeded titles are still queued");
    assert!(
        !ring.contains("seeded"),
        "no seeded title was ringed as attempted: {ring}"
    );
    assert!(
        expected_queue.contains("Some Show"),
        "the expected episode is still queued: {expected_queue}"
    );
    assert!(
        !done.contains("tvsomeshows01e05"),
        "the expected episode was not rung either: {done}"
    );
    // `paths()` above already stopped the first fixture.

    // SECOND HALF: one HIT left, the grab quota clear, nothing queued,
    // and the listing throttle open - so the only candidate this tick
    // could have is one `seed_next` would sweep for. The sweep is a hit
    // and the confirm search behind it is another, so one hit is not
    // enough for the pair and the lane must not start.
    {
        let ix = nzbkit::index::Index::open(&d.index_db).unwrap();
        ix.kv_set("seed_queue_v1", "[]").unwrap();
        ix.kv_set("expected_queue_v1", "[]").unwrap();
        ix.kv_set("expected_at", &now.to_string()).unwrap();
        // Wide open: the throttle must not be what refuses.
        ix.kv_set("seed_listing_at", &(now - 7_200).to_string())
            .unwrap();
    }
    // A listing with one grabbable title in it, so an unguarded sweep
    // really would queue and pop something.
    let mut f2 = fixture(move |_path, port| {
        rss(&item(
            "Sweep.Title.S01E01.1080p.WEB.H264-GRP",
            "sweep-guid",
            700_000_000,
            0,
            &format!("http://127.0.0.1:{port}/nzb/sweep"),
        ))
    });
    account(&d, "confirm-src", f2.port);
    d.indexers.lock_ok()[0].hits_per_day = 1;
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage = Default::default();
        rt.usage.roll(now);
    }
    assert!(
        !super::indexer::corr_confirm_once(&d),
        "one hit cannot pay for a sweep AND the search it pops a title for"
    );
    let paths2 = f2.paths();
    assert!(
        paths2.is_empty(),
        "the sweep must not spend the last hit: {paths2:?}"
    );
    let (queue2, ring2, listing_at) = d
        .with_index(|ix| {
            Some((
                ix.kv_get("seed_queue_v1").unwrap_or_default(),
                ix.kv_get("seed_recent_v1").unwrap_or_default(),
                ix.kv_get("seed_listing_at").unwrap_or_default(),
            ))
        })
        .unwrap();
    assert_eq!(queue2, "[]", "nothing was queued and nothing popped");
    assert!(
        !ring2.to_lowercase().contains("sweep"),
        "no title was rung as attempted, so the hourly sweep can still \
         offer it once the quota resets: {ring2}"
    );
    assert_eq!(
        listing_at,
        (now - 7_200).to_string(),
        "and the throttle stamp is untouched, so the sweep runs the \
         moment there is quota for the pair"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
