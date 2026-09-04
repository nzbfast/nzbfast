//! End-to-end coverage for [`super::spot_resolve_pass`]'s concurrent
//! fetch (`bbaeaff19`, 1 Sep 2026 - design record
//! `research/SPOT-RESOLVER-CONCURRENT-FETCH-2026-09-01.md`).
//!
//! The resolver is the largest naming source in the system - two thirds
//! of every name in the index - and when the serial `for s in &pending`
//! loop became a fan-out over a shared cursor, THREE pieces of per-pass
//! state were replaced by something with different semantics. Each
//! replacement is a deliberate judgement, each was measured on a live
//! daemon, and each is the kind of thing a later tidy-up puts back
//! "the obvious way" because the obvious way is what the serial loop
//! did. That is what these tests hold:
//!
//! 1. the breaker is `3 + fetchers` consecutive failures, read in
//!    COMPLETION order, not a flat `>= 3`;
//! 2. a STAT that fails drops the STAT session ALONE - the pass keeps
//!    fetching, where the old per-pass `desynced` flag ended it (that
//!    fired 8 times in 8 hours live, truncating about one pass in
//!    eight for a reason nothing to do with fetching);
//! 3. `stop()` is polled AFTER a result is folded, so a stop raised
//!    mid-pass still lands the result already off the wire.
//!
//! Plus the two cheaper invariants the fan-out introduced: a worker
//! that cannot open a session must not CONSUME a spot (it would burn a
//! `nzb_tried` retry on a spot the server was never asked about, and
//! three of those retire the spot permanently), and the shared cursor
//! must hand every pending spot to exactly one worker.
//!
//! Everything runs against `nzbkit::mock` on loopback: a real socket,
//! the real client stack, real HEAD/BODY/STAT. The spots are seeded
//! through `Index::insert_spots` - the same call `scan_spots` makes -
//! via the `#[doc(hidden)]` `Spot::for_test` constructor, because
//! `Spot::verified` is `pub(crate)` and the only other door into the
//! table demands a real RSA signature that only nzbkit's own
//! `#[cfg(test)]` helper can mint.
//!
//! EVERY TEST HERE IS `multi_thread`, DELIBERATELY. The default
//! `#[tokio::test]` runtime is current-thread, which runs the fan-out
//! cooperatively on one thread - the workers interleave at await points
//! and never actually run at the same instant. That is a weaker
//! machine than the daemon's, and the whole subject of this file is
//! what N sessions in flight do to state that used to be per pass. The
//! deterministic tests below stay deterministic under it: the breaker
//! pair pins one fetcher (`connections = 2`), so completion order is
//! dispatch order, and the fan-out breaker test makes every result a
//! failure, so no arrival order can reset the counter.
//!
//! HOW EACH OF THESE WAS CHECKED. A green test proves nothing about
//! what it would catch, so every assertion below was verified by
//! reverting the behaviour in `scan.rs` and watching the named test go
//! red: `breaker = 3` (the three breaker tests), the stop check moved
//! to the top of the receive loop (the stop test), `|| stat_dead` added
//! to the break condition - the old per-pass flag - (the STAT test),
//! and the cursor claim moved in front of the connect (the retry-burn
//! test). The one mutation NOT caught is written up at
//! `every_pending_spot_is_fetched_exactly_once`.

use super::*;
use nzbkit::index::Spot;
use nzbkit::mock::{Chaos, MockServer, PostChaos};
use std::collections::HashMap;

/// A resolver rig: a mock server holding `n` spots' worth of articles,
/// a scratch index seeded with those spots, and a config file pointing
/// at the mock.
struct Rig {
    // FIELD ORDER IS LOAD-BEARING. Rust drops fields in declaration
    // order, so the index's SQLite connection has to close BEFORE the
    // scratch guard removes the directory holding it: SQLite opens
    // without FILE_SHARE_DELETE and Windows refuses to remove a
    // directory that still has an open handle in it (os error 32),
    // where unix unlinks it quite happily and hides the mistake. Same
    // rule `scan_pass_tests::teardown` spells out at length.
    ix: nzbkit::index::Index,
    srv: MockServer,
    cfg: std::path::PathBuf,
    _dir: crate::testscratch::ScratchDir,
}

/// The spot article's message-id. `spots_unresolved` orders by `date`
/// descending, and [`Rig::build`] dates spot `i` one second behind spot
/// `i - 1`, so the pending list comes back in index order and a
/// single-fetcher pass completes in that order too.
fn spot_id(i: usize) -> String {
    format!("<spot{i}@spot.net>")
}

/// The release's own head article - what `release_head_article` hands
/// the corroborating STAT once the spot has been promoted.
fn head_id(i: usize) -> String {
    format!("<data{i}@x>")
}

/// The NZB a promoted spot `i` turns into: one file, one segment.
fn nzb_xml(i: usize) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file \
         poster=\"p@x\" date=\"0\" subject=\"&quot;movie{i}.mkv&quot; yEnc \
         (1/1)\">\n    <groups><group>alt.binaries.misc</group></groups>\n\
         \x20   <segments>\n      <segment bytes=\"1000\" number=\"1\">\
         data{i}@x</segment>\n    </segments>\n  </file>\n</nzb>\n"
    )
}

impl Rig {
    /// `n` spots in the index. Every spot whose index is in `dead` is
    /// seeded WITHOUT its spot article, so its HEAD is answered 430 and
    /// the fetch fails - a server that answers and refuses, which is
    /// exactly the half of the old breaker the fan-out had to keep.
    async fn build(tag: &str, n: usize, dead: &[usize], conns: u32, chaos: Chaos) -> Rig {
        let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
        let mut headers: HashMap<String, Vec<u8>> = HashMap::new();
        for i in 0..n {
            // The release's head article, so the corroborating STAT has
            // something to find (223 rather than 430 - a 430 is a
            // perfectly good STAT answer and would still count as
            // `checked`, but then `gone` could not be asserted at 0).
            articles.insert(head_id(i), b"payload\r\n".to_vec());
            if dead.contains(&i) {
                continue;
            }
            // The armored-deflate NZB, on its own alt.binaries.ftd
            // article, exactly as a real spot carries it.
            let mut packed = nzbkit::spot::special_zip(nzb_xml(i).as_bytes());
            packed.extend_from_slice(b"\r\n");
            articles.insert(format!("<nzbseg{i}@ftd>"), packed);
            let title = format!("Spot Title Number {i}");
            let xml = format!(
                "<Spotnet><Posting><Title>{title}</Title><Size>1048576</Size>\
                 <Category>01<Sub>a09</Sub></Category><NZB>\
                 <Segment>nzbseg{i}@ftd</Segment></NZB></Posting></Spotnet>"
            );
            // X-XML continuation headers, chunked the way spotweb
            // writes them: the resolver concatenates them and never
            // touches the body, so this is the one-HEAD shape.
            let mut head = format!("From: TestPoster <p@x>\r\nSubject: {title}\r\n");
            for chunk in xml.as_bytes().chunks(60) {
                head.push_str(&format!(
                    "X-XML: {}\r\n",
                    std::str::from_utf8(chunk).unwrap()
                ));
            }
            headers.insert(spot_id(i), head.into_bytes());
        }

        let srv = MockServer::start_full(articles, headers, Vec::new(), chaos).await;
        let dir = crate::testscratch::ScratchDir::attach(
            &std::env::temp_dir().join(format!("nzbfast-spotresolve-{tag}-{}", std::process::id())),
        );
        let mut ix = nzbkit::index::Index::open(&dir.join("index.db")).unwrap();
        let spots: Vec<Spot> = (0..n)
            .map(|i| {
                Spot::for_test(
                    &spot_id(i),
                    &format!("Header Title Number {i}"),
                    1_700_000_000 - i as i64,
                )
            })
            .collect();
        assert_eq!(ix.insert_spots(&spots).unwrap(), n, "seeded {n} spots");

        let mut sc = srv.server_config();
        sc.connections = conns;
        let cfg = dir.join("config.json");
        std::fs::write(&cfg, serde_json::json!({ "servers": [sc] }).to_string()).unwrap();
        Rig {
            ix,
            srv,
            cfg,
            _dir: dir,
        }
    }

    /// Run one pass, under a wall-clock ceiling: every assertion below
    /// is about a pass that RETURNS, and a fan-out that deadlocks on
    /// its channel would otherwise hang the suite (which nextest
    /// retries and can report as a flake rather than a wedge).
    async fn pass(
        &mut self,
        budget: u32,
        stop: impl Fn() -> bool,
    ) -> Result<super::SpotResolveSummary> {
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            super::spot_resolve_pass(&self.cfg, &mut self.ix, budget, stop),
        )
        .await
        .expect("the resolver pass must not hang")
    }

    fn still_pending(&self) -> Vec<String> {
        self.ix
            .spots_unresolved(1000)
            .unwrap()
            .into_iter()
            .map(|s| s.msgid)
            .collect()
    }
}

/// THE BREAKER, LOWER HALF: three failures in a row no longer end the
/// pass.
///
/// The serial rule was `consecutive_failures >= 3`, and on the live
/// daemon it cut a healthy 500-budget pass short at 473 fetches and
/// another at SIXTEEN - three independent missing articles that
/// happened to land together, on a server that was answering
/// perfectly. With one fetcher (`connections = 2`) completion order is
/// dispatch order, so this is the exact shape that used to end the
/// pass: three refusals, then work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_failures_in_a_row_no_longer_end_the_pass() {
    let mut rig = Rig::build("breaker-lo", 8, &[0, 1, 2], 2, Chaos::default()).await;
    let sum = rig.pass(100, || false).await.unwrap();
    assert_eq!(sum.failed, 3, "the three dead spots were tried");
    assert_eq!(
        sum.fetched, 5,
        "and the pass carried on into all five live ones"
    );
    assert_eq!(sum.promoted, 5);
    assert_eq!(
        rig.still_pending(),
        vec![spot_id(0), spot_id(1), spot_id(2)],
        "only the refused spots stay pending"
    );
}

/// THE BREAKER, UPPER HALF: at `3 + fetchers` it still trips.
///
/// Widening the rule is not licence to remove it. One fetcher makes
/// the threshold exactly 4 and makes completion order deterministic, so
/// the fourth consecutive failure must end the pass with the four live
/// spots behind it untouched - a server refusing everything must not
/// cost a whole budget of round trips.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_breaker_still_trips_at_three_plus_the_fan_out() {
    let mut rig = Rig::build("breaker-hi", 8, &[0, 1, 2, 3], 2, Chaos::default()).await;
    let sum = rig.pass(100, || false).await.unwrap();
    assert_eq!(sum.failed, 4, "tripped ON the fourth, not after the fifth");
    assert_eq!(sum.fetched, 0, "and nothing past it was folded");
    assert_eq!(
        rig.still_pending(),
        (0..8).map(spot_id).collect::<Vec<_>>(),
        "nothing was promoted: the four refused spots are still pending on          their first retry, and the four live ones behind the breaker were          never reached"
    );
}

/// THE `+ fetchers` TERM: a run one short of the threshold, at a real
/// fan-out, fetches every spot it was given.
///
/// This is the term the flat `>= 3` could not have: with N fetches in
/// flight, N independent misses land back to back purely because they
/// were dispatched together, and "consecutive in completion order"
/// means something different from "consecutive in the backlog". Four
/// fetchers (`connections = 8`) puts the breaker at 7; six spots, ALL
/// of them refused, is one short of it. Deterministic despite the
/// concurrency precisely because every result is a failure - there is
/// no live result whose arrival order could reset the counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_shorter_than_the_widened_breaker_tries_every_spot() {
    let dead: Vec<usize> = (0..6).collect();
    let mut rig = Rig::build("breaker-fanout", 6, &dead, 8, Chaos::default()).await;
    let sum = rig.pass(100, || false).await.unwrap();
    assert_eq!(
        sum.failed, 6,
        "every spot was tried; the old flat rule would have stopped at three"
    );
    assert_eq!(sum.fetched, 0);
}

/// A STAT THAT FAILS DROPS THE STAT SESSION AND NOTHING ELSE.
///
/// `desynced` used to be a per-PASS flag: one unanswerable STAT and the
/// whole pass ended, mid-backlog, having spent its connections. The
/// live daemon logged that 8 times in the 8 hours to 07:04Z on 1 Sep
/// 2026 - about one pass in eight truncated by something with no
/// bearing on fetching at all. The STATs now have a session of their
/// own and the flag is per session.
///
/// Both arms run the same fixture so the control is exact: with STATs
/// answered, six spots are promoted and all six corroborated; with the
/// STAT session severed, six spots are STILL promoted and none are
/// corroborated.
///
/// STATED LIMIT: the injected fault is `PostChaos::stat_dies` (the
/// server reads the STAT and severs the connection), not the 20-second
/// timeout that fired live. Both reach `stat_one`'s single `Err(_)`
/// arm, which is the branch under test, and a genuine timeout would
/// cost this suite 20 seconds of wall clock to reach the same line.
/// What this therefore does NOT pin is the timeout's own hazard - that
/// a TIMED-OUT session is still open and still owes us a status line,
/// so it must be dropped rather than reused or quit()ed. `stat_one`'s
/// doc comment carries that rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_severed_stat_session_does_not_stop_the_fetching() {
    // Control: STATs answered.
    let mut rig = Rig::build("stat-ok", 6, &[], 2, Chaos::default()).await;
    let sum = rig.pass(100, || false).await.unwrap();
    assert_eq!((sum.fetched, sum.promoted), (6, 6));
    assert_eq!(sum.checked, 6, "every fresh card was corroborated");
    assert_eq!(sum.gone, 0);

    // The same pass with the STAT session severed on first use.
    let mut rig = Rig::build(
        "stat-dies",
        6,
        &[],
        2,
        Chaos {
            post: PostChaos {
                stat_dies: true,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let sum = rig.pass(100, || false).await.unwrap();
    assert_eq!(
        (sum.fetched, sum.promoted),
        (6, 6),
        "the pass fetched and folded every spot - a per-pass desync flag \
         would have ended it on the first promotion"
    );
    assert_eq!(sum.checked, 0, "and nothing was corroborated");
    assert_eq!(sum.failed, 0, "the fetching itself never failed");
    assert!(rig.still_pending().is_empty());
}

/// `stop()` IS POLLED AFTER THE FOLD, NOT BEFORE IT.
///
/// A result that is already off the wire costs one index write to keep
/// and a whole re-fetch next pass to throw away, so the preemption
/// check sits at the END of the receive loop. A stop that is true from
/// the very first poll must therefore still land exactly one result -
/// the one in hand - and stop there.
///
/// A `fetched` of 0 is the regression this pins: move the check back to
/// the top of the loop and the pass returns having fetched a spot,
/// discarded it, and left it pending for a re-fetch it had already
/// paid for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_raised_mid_pass_still_lands_the_result_in_hand() {
    let mut rig = Rig::build("stop-folds", 6, &[], 2, Chaos::default()).await;
    let sum = rig.pass(100, || true).await.unwrap();
    assert_eq!(sum.fetched, 1, "the result in hand was kept, not thrown");
    assert_eq!(sum.promoted, 1);
    assert_eq!(
        rig.still_pending().len(),
        5,
        "and it is no longer pending - the re-fetch was saved"
    );
}

/// A WORKER THAT CANNOT OPEN A SESSION MUST NOT CONSUME A SPOT.
///
/// The fan-out connects BEFORE it claims off the shared cursor. Claim
/// first and an account at its connection limit - or a server down for
/// an hour - charges `nzb_tried` against spots the server was never
/// asked about, and `SPOT_NZB_TRIES` of those retire a spot from the
/// backlog for good. That is silent, permanent loss of a name, so the
/// pass is run one more time than the retry cap allows for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_cannot_connect_does_not_burn_a_spots_retries() {
    let mut rig = Rig::build("no-session", 4, &[], 2, Chaos::default()).await;
    // Point the config at a port nothing is listening on: bind one,
    // read its number, drop it. Every worker's `connect` is refused.
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut sc = rig.srv.server_config();
    sc.port = dead_port;
    sc.connections = 2;
    std::fs::write(&rig.cfg, serde_json::json!({ "servers": [sc] }).to_string()).unwrap();

    for attempt in 0..=nzbkit::index::SPOT_NZB_TRIES {
        let e = rig
            .pass(100, || false)
            .await
            .expect_err("a pass that opened no session at all must report it");
        assert!(
            e.to_string().contains("no connection to fetch spot NZBs"),
            "attempt {attempt}: {e}"
        );
        assert_eq!(
            rig.still_pending().len(),
            4,
            "attempt {attempt}: an unasked spot must not be charged a retry"
        );
    }
}

/// THE SHARED CURSOR HANDS EVERY SPOT TO EXACTLY ONE WORKER.
///
/// Eight fetchers over a 24-spot backlog. A cursor that skipped would
/// leave `fetched < 24`; one that handed a spot to two workers would
/// show up as a repeated BODY at the server and as an Upgraded rather
/// than a Promoted fold at the index. All three readings are asserted,
/// so neither direction can hide.
///
/// STATED LIMIT, measured rather than assumed: replacing the
/// `fetch_add` with the classic racy `load` then `store` does NOT turn
/// this test red - not on the current-thread runtime, and not on this
/// four-worker one either, over repeated runs. There is no await
/// between the two halves, so the window is a couple of instructions
/// wide and 24 spots never land in it. That is what a test can and
/// cannot do: this pins the OBSERVABLE contract (nothing skipped,
/// nothing fetched twice) and detects a cursor that is wrong by
/// construction; it is not, and cannot be, a proof of atomicity. Only
/// reading the `fetch_add` is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_pending_spot_is_fetched_exactly_once() {
    let mut rig = Rig::build("cursor", 24, &[], 100, Chaos::default()).await;
    let sum = rig.pass(100, || false).await.unwrap();
    assert_eq!(sum.fetched, 24, "no spot was skipped");
    assert_eq!(sum.promoted, 24, "and none was folded twice");
    assert_eq!((sum.upgraded, sum.unusable, sum.failed), (0, 0, 0));
    assert!(rig.still_pending().is_empty());
    assert_eq!(
        rig.srv.refetched(),
        Vec::new(),
        "no article was asked for twice"
    );
}

/// The budget is the pass's ceiling on FETCHES, and the fan-out must
/// not spend past it: `spots_unresolved(budget)` is what bounds the
/// work, and the cursor walks that list and stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_budget_still_bounds_a_fanned_out_pass() {
    let mut rig = Rig::build("budget", 12, &[], 100, Chaos::default()).await;
    let sum = rig.pass(5, || false).await.unwrap();
    assert_eq!(sum.fetched, 5);
    assert_eq!(rig.still_pending().len(), 7);
}
