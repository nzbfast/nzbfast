//! Connection-tuner replication suite: conn_ladder against a mock
//! provider with a REAL bandwidth shape - a per-socket cap (why more
//! connections help) and a line cap (why they stop helping) - plus the
//! one-time transient dip that produced the field failure (a Mac tuned
//! to 6 connections of a configured 18, downloading at a third of the
//! link for a week).
//!
//! These run real 2-3 s ladder rungs over localhost, so the suite costs
//! ~1 min of wall clock. That is the point: the tuner's failure was a
//! MEASUREMENT failure, and only a measured replication protects it.

use nzbkit::mock::{Chaos, MockServer, OverRow, Throttle};
use std::collections::HashMap;

const MB: u64 = 1_000_000;

/// A group of ~600 KB articles (the size sysbench's supply model
/// assumes) with overview rows, so discover_ids finds them.
fn bench_group(n: usize) -> (HashMap<String, Vec<u8>>, Vec<OverRow>) {
    let mut articles = HashMap::new();
    let mut rows = Vec::new();
    // One shared payload: the ladder measures transfer, not content.
    let data: Vec<u8> = (0..600_000u32).map(|i| (i * 31 % 251) as u8).collect();
    for i in 0..n {
        let art = nzbkit::yenc::encode("t.bin", data.len() as u64, None, 1, &data);
        let id = format!("<tune-{i}@mock>");
        rows.push(OverRow {
            number: i as u64 + 1,
            subject: format!("tune article {i}"),
            from: "bench@mock".into(),
            message_id: id.clone(),
            bytes: art.len() as u64,
        });
        articles.insert(id, art);
    }
    (articles, rows)
}

async fn ladder_against(
    throttle: Throttle,
    max_conns: usize,
    ceiling: usize,
    secs_per_step: u64,
) -> Vec<nzbkit::sysbench::LadderStep> {
    let (articles, rows) = bench_group(220);
    let srv = MockServer::start_full(
        articles,
        HashMap::new(),
        rows,
        Chaos {
            throttle,
            ..Chaos::default()
        },
    )
    .await;
    let cfg = srv.server_config();
    // The daemon discovers real-article ids before laddering; the mock's
    // overview rows stand in for a history NZB here.
    let ids = nzbkit::sysbench::discover_ids(&cfg, "alt.binaries.bench", 8_000)
        .await
        .expect("mock group yields ids");
    let out = nzbkit::sysbench::conn_ladder(
        &cfg,
        ids,
        max_conns,
        ceiling,
        secs_per_step,
        // The harness does not watch progress and never cancels; the
        // prober's own tests cover the phases. `true` = keep going.
        |_, _, _| true,
    )
    .await
    .expect("ladder ran");
    // Always dump the ladder, not only on failure: this harness measures
    // real throughput against a mock paced on real Instants, so when it
    // does wobble the rungs are the only way to tell a bad THRESHOLD from
    // a bad MACHINE MOMENT.
    eprintln!(
        "LADDER {:?}",
        out.iter()
            .map(|s| format!("{}c={:.4}", s.connections, s.gbps))
            .collect::<Vec<_>>()
    );
    out
}

/// The knee-pick the daemon and the dashboard both apply to a ladder.
///
/// A DUPLICATE of `nzbfast::conntune::knee_of`, because nzbkit cannot
/// depend on nzbfast - so it has to be kept in step by hand, and it was
/// not: this still read "smallest rung reaching 90% of the peak" after
/// the real rule had stopped scanning from the bottom (a knee must not
/// be read across a dip) and after the bar moved to 98%. A harness that
/// asserts against a stale copy of the rule is asserting nothing.
fn recommended(steps: &[nzbkit::sysbench::LadderStep]) -> usize {
    let mut v: Vec<&nzbkit::sysbench::LadderStep> =
        steps.iter().filter(|s| s.gbps.is_finite()).collect();
    v.sort_by_key(|s| s.connections);
    let Some(peak_at) = (0..v.len()).max_by(|&a, &b| v[a].gbps.total_cmp(&v[b].gbps)) else {
        return 8;
    };
    let bar = v[peak_at].gbps * 0.95; // keep in step with conntune::LADDER_BAR
    let mut i = peak_at;
    while i > 0 && v[i - 1].gbps >= bar {
        i -= 1;
    }
    let pick = v[i];
    if pick.granted > 0 && pick.granted + 2 < pick.connections {
        pick.granted
    } else {
        pick.connections
    }
}

/// A provider shaped 1 MB/s per socket under an 8 MB/s line has its
/// knee at 8: the ladder must find it (not stop short of it, not
/// recommend far past it) and the knee rung must SOAK the line - the
/// whole point of tuning is that the recommended count saturates what
/// the path can give.
#[tokio::test(flavor = "multi_thread")]
async fn ladder_finds_the_knee_and_soaks_the_line() {
    let steps = ladder_against(
        Throttle {
            per_conn_bps: MB,
            line_bps: 8 * MB,
            ..Throttle::default()
        },
        20,
        // 0 = no reopen check; this test is about the climb itself.
        0,
        6,
    )
    .await;
    let rungs: Vec<String> = steps
        .iter()
        .map(|s| format!("{}c {:.3}", s.connections, s.gbps))
        .collect();
    let best = recommended(&steps);
    assert!(
        (7..=12).contains(&best),
        "knee should land at ~8 (1 MB/s per conn, 8 MB/s line), got {best}: {rungs:?}"
    );
    // The ladder must have tested PAST the knee to know it is one.
    assert!(
        steps.iter().any(|s| s.connections > 10),
        "never probed past the knee: {rungs:?}"
    );
    // And the knee rung soaks the line: >= ~80% of 8 MB/s (0.064 Gbps),
    // slack for pacing granularity and the connect ramp.
    let peak = steps.iter().map(|s| s.gbps).fold(0.0, f64::max);
    assert!(
        peak >= 0.051,
        "peak {peak:.3} Gbps does not soak the 0.064 Gbps line: {rungs:?}"
    );
}

/// The field failure, replayed end to end: a healthy 1 MB/s-per-socket
/// provider with a line far above the tested rungs, EXCEPT the first
/// sample at 8 connections hits a transient (line dips to 3 MB/s for
/// exactly that rung). The old ladder believed the one bad sample:
/// 8 read below 4, the climb stopped, and the 4..8 bisect recommended
/// ~6 - James's number. The re-race must see through it and keep
/// climbing to the top of the ladder.
#[tokio::test(flavor = "multi_thread")]
async fn transient_dip_does_not_fake_a_knee() {
    let steps = ladder_against(
        Throttle {
            per_conn_bps: MB,
            line_bps: 32 * MB,
            // Fires when the 8-conn rung comes up and dies with those
            // sockets - swallowing that one sample, wherever the rung's
            // boundaries land in real time.
            dip_at_conns: 8,
            dip_to_bps: 3 * MB,
            ..Throttle::default()
        },
        16,
        0,
        6,
    )
    .await;
    let rungs: Vec<String> = steps
        .iter()
        .map(|s| format!("{}c {:.3}", s.connections, s.gbps))
        .collect();
    let best = recommended(&steps);
    assert!(
        best >= 12,
        "the transient dip faked a knee at {best} (the field bug recommended 6): {rungs:?}"
    );
    assert!(
        steps.iter().any(|s| s.connections >= 16),
        "the climb stopped at the dip instead of re-racing through it: {rungs:?}"
    );
}

/// Control for the dip test: the SAME shape with a genuine knee (line
/// capped at 4 MB/s, so 4 sockets saturate it). The re-race must NOT
/// turn a real knee into an endless climb - a genuine flat reproduces
/// and the ladder stops, recommending near 4.
#[tokio::test(flavor = "multi_thread")]
async fn a_genuine_knee_still_stops_the_climb() {
    /// The account's allowance, and the ladder's own limit - named
    /// because two assertions below are ABOUT it, and a bare 20 in
    /// three places is how the reopen assertion came to be written
    /// against the wrong quantity in the first place.
    const CEILING: usize = 20;
    let steps = ladder_against(
        Throttle {
            per_conn_bps: MB,
            line_bps: 4 * MB,
            ..Throttle::default()
        },
        CEILING,
        // A ceiling well above where 4 sockets soak the line: a
        // 4-of-20 answer is exactly the shape that has been wrong in the
        // field, and when the climb does stop down there it has to be
        // CONFIRMED rather than assumed.
        CEILING,
        6,
    )
    .await;
    let rungs: Vec<String> = steps
        .iter()
        .map(|s| format!("{}c {:.3}", s.connections, s.gbps))
        .collect();
    let best = recommended(&steps);
    // Asserted on SPEED, not on the rung number, and that is not a
    // widened margin - it is the only thing this shape can honestly
    // assert. With the line capped at 4 MB/s every rung from 4 upward is
    // the SAME physical speed, and repeated samples of it spread by ~6%
    // (measured here: 4c=0.031, 8c=0.033, 10c=0.033, 12c=0.031,
    // 16c=0.032). Which of those identical rungs wins is therefore a
    // coin toss inside the noise, and pinning a number would be pinning
    // the coin. What must hold is that the answer SOAKS the line and
    // does not wander off toward the ceiling chasing nothing.
    let at_best = steps
        .iter()
        .find(|s| s.connections == best)
        .map(|s| s.gbps)
        .unwrap_or(0.0);
    let peak = steps.iter().map(|s| s.gbps).fold(0.0, f64::max);
    assert!(
        at_best >= peak * 0.95,
        "the knee gives up speed: {best}c does {at_best:.4} of a {peak:.4} peak: {rungs:?}"
    );
    // NOT `best <= 10`. The comment above already says which rung wins
    // is a coin toss inside the noise, and then the old assertion went
    // ahead and pinned the coin anyway: 12c took the peak often enough
    // to fail this test roughly half the time on a quiet machine. The
    // property that survives the toss is the one the FIELD failure was
    // about - a tuner that marches to whatever the account allows. It
    // must not end up at the allowance when a fraction of it already
    // soaks the line.
    assert!(
        best < CEILING,
        "the tuner took the account's allowance on a 4 MB/s line: {rungs:?}"
    );
    // The reopen check is gated on where the CLIMB stopped, not on where
    // the knee landed: `worth_reopening(top, ceiling)` goes false once
    // the climb has got within half the allowance, and sysbench has a
    // unit test saying exactly that ("close to the ceiling: trust it").
    // On this shape every rung from 4c up measures the same physical
    // 4 MB/s line, so whether the climb stalls at 8c or wanders on to
    // 16c is noise - and asserting the probe happened UNCONDITIONALLY
    // was asserting that noise. Twice in five runs the climb reached
    // 16c, no probe was due, and the test failed on correct behaviour.
    //
    // What must hold is the implication, not the consequent: if the
    // climb did stop far below the allowance, it must have asked the
    // allowance directly rather than assuming.
    //
    // The rule is CALLED, not restated. Writing `climb_top * 2 <
    // CEILING` here worked, but it put a second copy of the predicate in
    // a file that cannot see the first - so changing `worth_reopening`
    // would leave this asserting the old band, which is the same defect
    // as the original in a form that is harder to spot.
    //
    // The filter is load-bearing, not tidying: the CEILING rung IS the
    // reopen probe. Counting it would pin `climb_top` at the ceiling,
    // make the guard permanently false, and retire this assertion in
    // silence.
    let climb_top = steps
        .iter()
        .map(|s| s.connections)
        .filter(|c| *c != CEILING)
        .max()
        .unwrap_or(0);
    if nzbkit::sysbench::worth_reopening(climb_top, CEILING) {
        assert!(
            steps.iter().any(|s| s.connections == CEILING),
            "the climb stopped at {climb_top}c of {CEILING} and never asked \
             the ceiling: {rungs:?}"
        );
    }
    // …and having asked, it must not be TALKED INTO the ceiling: the
    // line really is capped at 4 MB/s, so 20 sockets buy nothing and the
    // recommendation stays down where the knee is (asserted above).
    // What must not happen is the climb continuing past the check.
    assert!(
        steps.len() <= 9,
        "the reopen check turned into another climb: {rungs:?}"
    );
}

/// Cancel has to actually stop it, and hand back only WHOLE rungs.
///
/// A cancelled ladder is not a short ladder that can be read: it stopped
/// wherever the user's patience ran out. What this pins is the two
/// mechanical promises - it really stops, and what comes back is the
/// rungs that finished rather than a half-measured one.
#[tokio::test(flavor = "multi_thread")]
async fn cancel_stops_the_ladder_between_rungs() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (articles, rows) = bench_group(220);
    let srv = MockServer::start_full(
        articles,
        HashMap::new(),
        rows,
        Chaos {
            throttle: Throttle {
                per_conn_bps: MB,
                line_bps: 32 * MB,
                ..Throttle::default()
            },
            ..Chaos::default()
        },
    )
    .await;
    let cfg = srv.server_config();
    // "Press Cancel" once two rungs have landed.
    let seen = Arc::new(AtomicUsize::new(0));
    let s2 = seen.clone();
    let ids = nzbkit::sysbench::discover_ids(&cfg, "alt.binaries.bench", 8_000)
        .await
        .expect("mock group yields ids");
    let out = nzbkit::sysbench::conn_ladder(&cfg, ids, 64, 0, 3, move |_, _, steps| {
        s2.store(steps.len(), Ordering::Relaxed);
        steps.len() < 2
    })
    .await
    .expect("a cancelled ladder still returns what it measured");
    assert!(
        out.len() <= 3,
        "cancel did not stop the climb - {} rungs came back",
        out.len()
    );
    assert!(!out.is_empty(), "the rungs already measured must survive");
    // Whole rungs only: every one carries a real rate.
    assert!(
        out.iter().all(|s| s.gbps > 0.0),
        "a half-measured rung came back: {out:?}",
        out = out
            .iter()
            .map(|s| (s.connections, s.gbps))
            .collect::<Vec<_>>()
    );
}

/// The STAT gate the real-article supply rides on: presence answers
/// come back in input order, misses read false, and the sweep is one
/// pipelined connection - the property that makes gating 300+ ids
/// cheap enough to run before every ladder.
#[tokio::test(flavor = "multi_thread")]
async fn stat_presence_reports_misses_in_order() {
    let (articles, rows) = bench_group(6);
    let srv = MockServer::start_full(articles, HashMap::new(), rows, Chaos::default()).await;
    let cfg = srv.server_config();
    let ids = vec![
        "<tune-0@mock>".to_string(),
        "<gone-a@mock>".to_string(),
        "<tune-3@mock>".to_string(),
        "<gone-b@mock>".to_string(),
        "<tune-5@mock>".to_string(),
    ];
    let present = nzbkit::sysbench::stat_presence(&cfg, &ids)
        .await
        .expect("STAT sweep ran");
    assert_eq!(present, vec![true, false, true, false, true]);
    // An empty sample is a clean empty answer, not a hang.
    let none = nzbkit::sysbench::stat_presence(&cfg, &[])
        .await
        .expect("empty");
    assert!(none.is_empty());
}
