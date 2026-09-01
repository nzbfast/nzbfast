//! `gates::CONN_DARK`'s pins: the masks, the three gates that read
//! them, and the `next_work` scan rig with its control arm.
//!
//! A child of `unit_tests` rather than a `mod tests` inside gates.rs,
//! and the reason is one of that file's own invariants:
//! `only_missing_cause_decides_a_terminal_refusals_cause` scans gates.rs
//! as PRODUCTION for the string `MissingCause::Unasked`, so a rig in
//! there that asserts the verdict would read as a second site naming a
//! cause. The rig asserts exactly that verdict on purpose - the fix must
//! not quietly upgrade "we could not ask" into "the post is gone" - so
//! the rig moved and the invariant kept its meaning. `ConnDark::go_dark`
//! is the one seam that costs.
//!
//! DETERMINISTIC THROUGHOUT: the deadline is an absolute run-clock
//! instant, so "dark" is a store at any clock. Nothing here sleeps,
//! polls, or retries.

use super::super::*;
use super::{fresh, server, work};

/// Three level-0 servers: `a` holding a session, `b` and `c` alive
/// with no socket between them - the shape of the 30 Aug 2026 dump,
/// where the two dark servers carried thirty-four workers.
fn fleet(dark_window: Duration, ids: &[&str]) -> (Arc<Shared>, Vec<(ServerConfig, PoolConfig)>) {
    let servers: Vec<_> = ["a", "b", "c"]
        .iter()
        .map(|h| {
            (
                server(h),
                PoolConfig {
                    conn_dark: dark_window,
                    ..Default::default()
                },
            )
        })
        .collect();
    let (sh, _) = Shared::new(fresh(ids), &servers);
    for si in 0..3 {
        sh.alive[si].store(1, Ordering::Relaxed);
        sh.connected[si].store(true, Ordering::Relaxed);
    }
    // a holds a session right now; b and c are past their deadline.
    sh.sessions[0].store(1, Ordering::Relaxed);
    sh.conn_dark.go_dark(1);
    sh.conn_dark.go_dark(2);
    (sh, servers)
}

/// The defect, at the mask. `alive[si] > 0` counted a server whose
/// seventeen workers were all parked after failing to dial, so an
/// article it had never refused could not reach `tried_430 & live ==
/// live` and no other server could take it either.
#[test]
fn a_server_holding_no_session_leaves_the_live_mask() {
    let (sh, _) = fleet(CONN_DARK, &["<a@x>"]);
    assert_eq!(
        sh.live_mask_at(0),
        server_bit(0),
        "only the server actually holding a session may decide a verdict"
    );
}

/// The knob at zero is the pre-30-Aug-2026 shape, which
/// `NZBFAST_CONN_DARK_SECS=0` asks for by hand and which the control
/// arm of the scan rig below runs. Same fixture, opposite answer:
/// that is what makes the rig a test of this bound and not of
/// something else in the fixture.
#[test]
fn the_bound_switched_off_counts_every_alive_server() {
    let (sh, _) = fleet(Duration::ZERO, &["<a@x>"]);
    assert_eq!(
        sh.live_mask_at(0),
        server_bit(0) | server_bit(1) | server_bit(2)
    );
}

/// A session held RIGHT NOW keeps a server in every mask however
/// long that session lives. [`ConnDark`] is stamped only as a
/// session begins and ends, so without this arm a healthy backbone
/// serving one uninterrupted three-minute session would drop out of
/// its own verdict.
#[test]
fn a_held_session_outranks_an_expired_deadline() {
    let (sh, _) = fleet(CONN_DARK, &["<a@x>"]);
    sh.sessions[1].store(1, Ordering::Relaxed);
    assert_eq!(sh.live_mask_at(0), server_bit(0) | server_bit(1));
}

/// A FLAPPING server must not thrash the mask, which is the one
/// thing a clock here has to get right: the window is measured from
/// the last SESSION and not from the last dial, so a server granted
/// one session every thirty seconds inside a two-minute window never
/// leaves. Driven deterministically - four grants, four reads, no
/// sleeping and no retry loop.
#[test]
fn a_server_reconnecting_inside_the_window_never_leaves_the_mask() {
    let (sh, _) = fleet(CONN_DARK, &["<a@x>"]);
    let window = CONN_DARK.as_millis() as u64;
    for round in 0..4u64 {
        let t = round * (window / 4);
        sh.conn_dark.note_session(1, t);
        // The session ends immediately; only the deadline carries it.
        assert!(
            sh.serving_at(1, t + window / 4),
            "a grant at {t} ms must still count a quarter-window later"
        );
    }
    // ...and one whole window after the last grant, it does leave.
    assert!(!sh.serving_at(1, 3 * (window / 4) + window));
}

/// THE FLOOR. A filter that empties the mask makes `tried_430 & live
/// == live` true of EVERY queued article at once (`0 & 0 == 0`), so
/// a transient outage reaching the whole fleet would write the rest
/// of the queue off as Missing in a single scan - worse than the
/// wedge this bounds. When nothing is serving there is nothing to
/// unblock, so the pre-fix reading stands.
#[test]
fn a_wholly_dark_fleet_falls_back_to_the_alive_mask() {
    let (sh, _) = fleet(CONN_DARK, &["<a@x>"]);
    sh.sessions[0].store(0, Ordering::Relaxed);
    sh.conn_dark.go_dark(0);
    assert_eq!(
        sh.live_mask_at(0),
        server_bit(0) | server_bit(1) | server_bit(2),
        "no verdict is owed to a fleet that is wholly dark - it is owed a retry"
    );
    // A server with no workers left is still out, dark or not: this
    // floor restores the OLD reading, it does not invent a new one.
    sh.alive[2].store(0, Ordering::Relaxed);
    assert_eq!(sh.live_mask_at(0), server_bit(0) | server_bit(1));
}

/// The same defect on the dispatch side: a level-0 primary that is
/// alive and dialling nothing files no refusal, so the fill gate it
/// holds shut is one nothing can open and the level-1 tier watches a
/// queue it may look at and not touch.
#[test]
fn a_dark_lower_tier_stops_holding_the_fill_gate_shut() {
    let servers: Vec<_> = ["primary", "backup"]
        .iter()
        .enumerate()
        .map(|(si, h)| {
            let mut sc = server(h);
            sc.level = si as u32;
            (sc, PoolConfig::default())
        })
        .collect();
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    sh.alive[0].store(1, Ordering::Relaxed);
    sh.alive[1].store(1, Ordering::Relaxed);
    sh.sessions[0].store(1, Ordering::Relaxed);
    assert_eq!(
        sh.required_mask_at(1, 0),
        server_bit(0),
        "a serving primary still gates its backup"
    );
    sh.sessions[0].store(0, Ordering::Relaxed);
    sh.conn_dark.go_dark(0);
    assert_eq!(
        sh.required_mask_at(1, 0),
        0,
        "a primary that cannot dial cannot keep the backup off the queue"
    );
}

/// The third face: `next_work` steps a transport-failed article PAST
/// this server when some other server can take it, so a dark server
/// counted here turns "somebody else will take it" into a rotation
/// nobody ends.
#[test]
fn a_dark_server_is_not_somewhere_else_to_send_a_failed_article() {
    let (sh, _) = fleet(CONN_DARK, &["<a@x>"]);
    let mut w = work("<a@x>");
    w.tried_fail = server_bit(0);
    assert!(
        !sh.other_can_take(&w, 0),
        "b and c hold no socket, so the server that failed it retakes it"
    );
    sh.sessions[1].store(1, Ordering::Relaxed);
    assert!(sh.other_can_take(&w, 0), "b is serving again and can");
}

/// [`Shared::faster_can_take`] leaves a promoted (seek) article for a
/// measurably faster server. A dark one is not faster - its windowed
/// rate is the memory of a better minute - and leaving the article
/// there strands exactly the article a player is waiting on.
#[test]
fn a_dark_server_is_never_the_faster_one_to_leave_a_seek_for() {
    let (sh, _) = fleet(CONN_DARK, &["<a@x>"]);
    let w = work("<a@x>");
    // b is a hundred times server a's rate on the windowed judgement.
    sh.note_srv_bytes(0, 100_000);
    sh.note_srv_bytes(1, 10_000_000);
    assert!(
        !sh.faster_can_take(&w, 0),
        "b has no socket, so its rate is history and not an offer"
    );
    sh.sessions[1].store(1, Ordering::Relaxed);
    assert!(sh.faster_can_take(&w, 0));
}

/// The window has to clear an ordinary reconnect and still land
/// inside the caller's own stall watchdog, or it is either a fleet
/// that thrashes or a bound nobody ever sees fire. The dial ladder
/// is `max_connect_attempts` 5 over a doubling `connect_backoff` of
/// 2 s (~62 s for one worker); the download stall watchdog aborts at
/// 180 s with no progress, which is what ended the incident run.
#[test]
fn the_shipped_window_sits_between_the_dial_ladder_and_the_watchdog() {
    let d = PoolConfig::default();
    assert!(d.conn_dark > Duration::from_secs(62), "{:?}", d.conn_dark);
    assert!(d.conn_dark < Duration::from_secs(180), "{:?}", d.conn_dark);
    assert!(
        d.conn_dark < d.outage_budget.expect("shipped default"),
        "the only thing that reached this before was the outage budget, \
         and it reached it by killing the server"
    );
}

/// The clock is stamped from exactly one site - `SessionTally`'s `Drop`
/// - so that site is worth a pin of its own: without it every arm above
/// still passes on a fleet whose deadlines never move again.
///
/// WHAT THIS CANNOT PIN, said rather than left to be found: the ORDER.
/// The stamp lands before the live count drops so that a reader between
/// the two never sees a server with no session and a stale deadline,
/// and a single-threaded test cannot observe an interleaving. The
/// reasoning is at the `Drop` itself.
#[test]
fn ending_a_session_pushes_that_server_deadline_back_out() {
    let (sh, _) = fleet(CONN_DARK, &["<a@x>"]);
    assert!(!sh.serving_at(1, 0), "b starts dark");
    {
        let _tally = SessionTally::up(&sh, 1);
        assert!(sh.serving_at(1, 0), "a held session answers on its own");
    }
    assert!(
        sh.serving_at(1, 0),
        "and the session it just finished holding buys a fresh window"
    );
    assert!(
        !sh.serving_at(1, 2 * CONN_DARK.as_millis() as u64),
        "one window, not for ever"
    );
}

/// THE INCIDENT, driven through the scan that wedged on it. One
/// article refused by the only server holding a socket, two servers
/// alive with none between them: today that article reaches no
/// terminal verdict and no other server may take it, so it rotates
/// for the life of the run - 399 of them did, at t=210 s, until the
/// caller's stall watchdog killed the job.
///
/// BOTH ARMS ARE ASSERTED and the control is the proof of the rig:
/// with the bound off, the same fixture rotates the article and
/// reports nothing, so it can only be this bound that retires it.
#[tokio::test]
async fn a_dark_server_no_longer_pins_an_article_it_never_refused() {
    for bound in [CONN_DARK, Duration::ZERO] {
        let (sh, servers) = fleet(bound, &["<lost@x>", "<ok@x>"]);
        // Server a - the one still serving - has refused it. b and c
        // never saw it and cannot be asked.
        sh.queue.lock().await.front_mut().unwrap().tried_430 = server_bit(0);
        let (tx, mut rx) = mpsc::channel(4);
        let w = next_work(&sh, ctx_for(&servers, 0), &tx, Pipeline::payload(0))
            .await
            .expect("the healthy article is picked either way");
        assert_eq!(&*w.id, "<ok@x>");
        let held = sh.queue.lock().await.iter().any(|q| &*q.id == "<lost@x>");
        match (bound, rx.try_recv()) {
            (b, Ok(FetchOutcome::Missing { id, cause })) if b == CONN_DARK => {
                assert_eq!(&*id, "<lost@x>");
                assert_eq!(
                    cause,
                    MissingCause::Unasked {
                        takedown: false,
                        dark: 2
                    },
                    "and the REPORT stays honest: both dark servers served \
                     earlier in this run, so `participation_mask` still holds \
                     them and the verdict says the fleet went dark past this \
                     article - never that the post is gone"
                );
                assert!(!held, "the article is out of the queue, not rotating in it");
            }
            (b, other) if b == CONN_DARK => {
                panic!("expected the article's Missing report, got {other:?}")
            }
            // The control: the pre-30-Aug-2026 shape wedges.
            (_, other) => {
                assert!(
                    matches!(other, Err(mpsc::error::TryRecvError::Empty)),
                    "with the bound off nothing may go terminal, got {other:?}"
                );
                assert!(held, "with the bound off the article rotates for ever");
            }
        }
    }
}
