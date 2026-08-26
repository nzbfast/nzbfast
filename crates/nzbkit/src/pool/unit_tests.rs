//! Lib-level unit tests for pool internals (coverage ratchet, 5 Aug).
//!
//! The tail-optimization campaign landed pool code that the daemon and
//! chaos integration suites exercise heavily - but `cargo llvm-cov -p
//! nzbkit --lib` cannot see integration coverage, so the nightly floor
//! read the campaign as a regression. These tests pin the pure helpers,
//! state machines and control-surface paths directly. A child module of
//! `pool` (not an entry in the inline `tests` mod) so pool.rs itself
//! stays inside its size-gate entry while the private internals remain
//! reachable through `super::*`.

use super::*;
use crate::config::ServerConfig;
use crate::mock::{Chaos, MockServer, make_file_articles};

// The §122.5 `next_work` scan-ladder tests, out under the size gate
// (TODO 106). `cfg(test)` is redundant inside a test module but is what
// size-gate.py's CFG_TEST_MOD resolver keys on to score the child as
// test code rather than gate it at the production fn ceiling; the
// child resolves to unit_tests/next_work_tests.rs because this module
// is reached by a plain `mod unit_tests;`, not a `#[path]`.
#[cfg(test)]
mod next_work_tests;

pub(super) fn server(host: &str) -> ServerConfig {
    ServerConfig {
        host: host.into(),
        port: 119,
        tls: false,
        username: None,
        password: None,
        connections: 1,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: None,
        block_account: false,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
        address_family: Default::default(),
        tls_hostname: None,
    }
}

pub(super) fn fresh(ids: &[&str]) -> Vec<ArticleReq> {
    ids.iter().map(|id| ArticleReq::fresh(*id)).collect()
}

pub(super) fn work(id: &str) -> Work {
    Work {
        age_days: 0,
        part: 0,
        file: u32::MAX,
        ord: 0,
        id: id.into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
        fenced: false,
        rearms: 0,
        ladder: false,
        probe: false,
    }
}

#[test]
fn flap_window_trims_old_deaths_before_judging() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    for _ in 0..FLAP_DEATHS - 1 {
        sh.note_flap(0);
    }
    assert!(
        !sh.is_flapping(0),
        "one under the threshold is a rough patch, not a flap"
    );
    sh.note_flap(0);
    assert!(sh.is_flapping(0));
    // A lone server is never clamped: churn beats zero throughput when
    // there is no alternative.
    assert!(!sh.other_live(0));
    sh.note_cap_bounce(0, sh.sessions[0].load(Ordering::Acquire));
    assert_eq!(
        sh.flap_keeper_target(0, &PoolConfig::default()),
        1,
        "no session was held at bounce time, so no cap was observed"
    );
    sh.sessions[0].store(2, Ordering::Release);
    sh.note_cap_bounce(0, sh.sessions[0].load(Ordering::Acquire));
    // Pinned, not defaulted: Default reads NZBFAST_FLAP_CAP_KEEPERS
    // (TODO 121.3), and this test is about the target math, not the env.
    let cfg = PoolConfig {
        flap_cap_keepers: true,
        connections: 8,
        ..Default::default()
    };
    assert_eq!(
        sh.flap_keeper_target(0, &cfg),
        2,
        "an observed accept cap widens the clamp past one keeper"
    );
    assert_eq!(
        sh.flap_keeper_target(
            0,
            &PoolConfig {
                flap_cap_keepers: true,
                connections: 1,
                ..Default::default()
            }
        ),
        1,
        "never above the per-server budget, where account limits already landed"
    );
    let off = PoolConfig {
        flap_cap_keepers: false,
        connections: 8,
        ..Default::default()
    };
    assert_eq!(
        sh.flap_keeper_target(0, &off),
        1,
        "knob off keeps the shipped answer"
    );
}

#[test]
fn auth_state_keeps_the_servers_own_words_for_the_first_refusal_only() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    let auth = &sh.auth[0];
    assert_eq!(auth.reason(), None);
    assert!(auth.note(crate::nntp::AuthRefusal::Permanent, "502 no thanks"));
    assert!(!auth.note(crate::nntp::AuthRefusal::Permanent, "502 said twice"));
    assert!(auth.is_rejected());
    assert_eq!(
        auth.reason().as_deref(),
        Some("502 no thanks"),
        "the dashboard shows what the provider actually said, once"
    );
}

#[test]
fn ctx_for_unions_mirror_group_bits() {
    let mut a = server("a");
    a.group = Some("eu".into());
    let mut b = server("b");
    b.group = Some("eu".into());
    let c = server("c");
    let servers = vec![
        (a, PoolConfig::default()),
        (b, PoolConfig::default()),
        (c, PoolConfig::default()),
    ];
    let ctx = ctx_for(&servers, 0);
    assert_eq!(ctx.idx, 0);
    assert_eq!(ctx.bit, 0b001);
    assert_eq!(
        ctx.group_bits, 0b011,
        "a 430 is authoritative for the whole mirror group"
    );
    assert_eq!(ctx.level, 0);
    let lone = ctx_for(&servers, 2);
    assert_eq!(
        lone.group_bits, 0b100,
        "no group means the server answers for itself"
    );
}

/// Codex F-13: every routing decision in the pool is a `u32` bitmask
/// and `server_bit` answers 0 past `MAX_SERVERS`, so servers 33 and up
/// would share the empty bit - invisible to each other's 430 ledger,
/// tier gate and dup guard, and able to drive an article terminal
/// `Missing` before the last server was ever asked. The config loader
/// refuses this (`ConfigError::TooManyServers`), but the pool's public
/// entries are a library surface a caller reaches without it, so the
/// refusal has to live at the one place all of them funnel through.
///
/// `Shared::new` is that place: `fetch_all_multi`, `fetch_all_multi_ctl`
/// and `fetch_all_sharded` each call it before a socket is opened.
#[test]
#[should_panic(expected = "exceeds MAX_SERVERS")]
fn one_server_past_the_bitmask_is_refused_rather_than_mis_routed() {
    let servers: Vec<(ServerConfig, PoolConfig)> = (0..=MAX_SERVERS)
        .map(|i| (server(&format!("s{i}")), PoolConfig::default()))
        .collect();
    let _ = Shared::new(fresh(&["<a@x>"]), &servers);
}

/// And the boundary itself is a SUPPORTED configuration: the assert is
/// `<=`, so an off-by-one tightening of it would refuse the largest
/// fleet the config loader accepts. Paired with the panic above so
/// neither direction can move alone.
#[test]
fn exactly_the_bitmask_width_is_accepted() {
    let servers: Vec<(ServerConfig, PoolConfig)> = (0..MAX_SERVERS)
        .map(|i| (server(&format!("s{i}")), PoolConfig::default()))
        .collect();
    let (sh, unservable) = Shared::new(fresh(&["<a@x>"]), &servers);
    assert!(unservable.is_empty());
    assert_eq!(
        sh.alive.len(),
        MAX_SERVERS,
        "32 servers is the widest fleet the u32 mask can distinguish"
    );
}

#[test]
fn shared_new_seeds_age_and_part_onto_work_for_the_pool_paths_that_read_them() {
    let reqs = vec![
        ArticleReq {
            id: "<aged@x>".into(),
            age_days: 30,
            part: 2,
            file: u32::MAX,
        },
        ArticleReq::fresh("<plain@x>"),
    ];
    let (sh, unservable) = Shared::new(reqs, &[(server("s"), PoolConfig::default())]);
    assert!(unservable.is_empty(), "an unlimited server serves any age");
    let q = sh.queue.try_lock().unwrap();
    let aged = q.iter().find(|w| &*w.id == "<aged@x>").unwrap();
    assert_eq!(
        aged.part, 2,
        "the CRC gate needs the requested part to catch split-brain swaps"
    );
    assert_eq!(aged.age_days, 30);
    let plain = q.iter().find(|w| &*w.id == "<plain@x>").unwrap();
    assert_eq!(plain.part, 0, "part 0 means no declared part");
    assert_eq!(plain.age_days, 0);
}

#[test]
fn transport_failure_steering_asks_who_else_could_take_the_work() {
    let servers = vec![
        (server("p"), PoolConfig::default()),
        (server("q"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let mut w = work("<a@x>");
    assert!(
        !sh.other_can_take(&w, 0),
        "a server with no live workers can never take the retry"
    );
    sh.alive[1].store(1, Ordering::Relaxed);
    assert!(sh.other_can_take(&w, 0));
    w.tried_fail = 0b10;
    assert!(
        !sh.other_can_take(&w, 0),
        "a server that already transport-failed this article is not an elsewhere"
    );
    // Cold start: no rate difference is measurable, so promoted work is
    // never stranded waiting for a faster server.
    let w2 = work("<a@x>");
    assert!(!sh.faster_can_take(&w2, 0));
}

#[test]
fn buf_pool_reuses_small_buffers_and_frees_oversized_ones() {
    let pool = BufPool::new(1);
    let mut a = pool.take();
    assert!(a.is_empty(), "a fresh take is an empty buffer");
    a.extend_from_slice(b"body bytes");
    drop(a); // the guard IS the give
    let b = pool.take();
    assert!(b.is_empty(), "give() clears before parking");
    // At max_held 1, a second parked buffer is dropped, not stored.
    pool.give(Vec::with_capacity(1024));
    pool.give(Vec::with_capacity(2048));
    // Bound, not `let _`: a bare `_` drops the guard on the spot, which
    // would hand the buffer straight back and defeat the point.
    let _popped = pool.take();
    let refilled = pool.take();
    assert_eq!(
        refilled.capacity(),
        800 * 1024,
        "the surplus give was dropped, so this take allocated fresh"
    );
    // A buffer grown past the 4 MB keep-cap must not pin its allocation
    // in the pool for the rest of the run.
    pool.give(Vec::with_capacity(5 * 1024 * 1024));
    assert!(
        pool.take().capacity() < 5 * 1024 * 1024,
        "an oversized buffer is freed, not parked"
    );
}

#[test]
fn stream_window_defaults_to_one() {
    // The env knob is unset in the test environment, so the OnceLock
    // resolves the shipped default.
    assert_eq!(stream_window(), 1);
}

#[test]
fn ttfb_suspicion_bound_floors_at_one_second_then_tracks_the_ewma() {
    let floor = TTFB_SUSPECT_MIN.as_millis() as u64;
    assert_eq!(
        ttfb_suspect_ms(0),
        floor,
        "unmeasured suspects at the floor"
    );
    assert_eq!(ttfb_suspect_ms(400), floor, "2x a fast EWMA stays floored");
    assert_eq!(
        ttfb_suspect_ms(600),
        1200,
        "a slow honest server pushes the bound out instead of hedging everything"
    );
}

#[test]
fn ttfb_suspect_after_reads_the_servers_own_ewma() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    assert_eq!(
        sh.ttfb_suspect_after(0),
        TTFB_SUSPECT_MIN,
        "no history means no reason to wait"
    );
    sh.note_ttfb(0, Duration::from_secs(2));
    assert_eq!(
        sh.ttfb_suspect_after(0),
        Duration::from_millis(4000),
        "first sample seeds the EWMA whole, and the bound is 2x it"
    );
}

// TODO 208.2: the share-aware stall bound's arithmetic, pinned at the
// three lines the 21 Aug shaped legs measured. One share of a 750 KB
// body across 360 connections: 1 Gbps = ~2.2 s (floor runs), 250 Mbit
// = ~8.6 s (x2 = ~17 s), 100 Mbit = ~21.6 s (x2 = ~43 s).
#[test]
fn share_aware_stall_bound_floors_on_fast_lines_and_stretches_on_slow_ones() {
    let floor = ADAPTIVE_STALL.as_millis() as u64;
    let ceiling = ADAPTIVE_STALL_MAX.as_millis() as u64;
    let body = 750_000;
    // 1 Gbps and 10 GbE: one share moves the body in ~2 s / ~0.2 s, so
    // the floor is the bound - never sooner than the flat deadline,
    // never later either.
    assert_eq!(share_aware_stall_ms(body, 125_000_000, 360), floor);
    assert_eq!(share_aware_stall_ms(body, 1_250_000_000, 360), floor);
    // 250 Mbit: 31.25 MB/s / 360 = 86.8 KB/s, 750 KB takes 8.64 s,
    // x2 = 17.28 s.
    let ms = share_aware_stall_ms(body, 31_250_000, 360);
    assert!((17_000..=17_500).contains(&ms), "250 Mbit bound {ms} ms");
    // 100 Mbit: 12.5 MB/s / 360 = 34.7 KB/s, 750 KB takes 21.6 s,
    // x2 = 43.2 s - under the ceiling, so the line sets it.
    let ms = share_aware_stall_ms(body, 12_500_000, 360);
    assert!((43_000..=43_500).contains(&ms), "100 Mbit bound {ms} ms");
    // 20 Mbit: 2.5 MB/s / 360 = 6.9 KB/s, 108 s x2 = 216 s - the ceiling holds.
    assert_eq!(share_aware_stall_ms(body, 2_500_000, 360), ceiling);
    // Monotone in the connection count at a fixed line: more sharers,
    // longer bound.
    assert!(
        share_aware_stall_ms(body, 12_500_000, 100) < share_aware_stall_ms(body, 12_500_000, 360)
    );
    // Untrained in any input keeps the flat bound.
    assert_eq!(share_aware_stall_ms(0, 12_500_000, 360), floor);
    assert_eq!(share_aware_stall_ms(body, 0, 360), floor);
    assert_eq!(share_aware_stall_ms(body, 12_500_000, 0), floor);
    // A pathological body size cannot wrap past the ceiling.
    assert_eq!(share_aware_stall_ms(u64::MAX, 1, 1), ceiling);
}

#[test]
fn stall_bound_is_flat_until_the_line_peak_and_a_body_are_trained() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    assert_eq!(
        sh.stall_bound(),
        ADAPTIVE_STALL,
        "cold pool: the shipped flat bound"
    );
    // One body trains the size EWMA but the saturation gauge needs half
    // a time constant of evidence before it calls anything a peak - so
    // the bound is still flat, exactly as shipped for a run's first
    // seconds.
    sh.workers_live.store(360, Ordering::Relaxed);
    sh.note_srv_bytes(0, 750_000);
    assert_eq!(sh.body_bytes_ewma.load(Ordering::Relaxed), 750_000);
    assert_eq!(sh.sat.peak_bps(), 0);
    assert_eq!(sh.stall_bound(), ADAPTIVE_STALL, "no peak yet: still flat");
}

/// TODO 277: the share the deadline sizes is one PER DIALLING WORKER.
/// A fleet that spawns the line-cap curve's ceiling and runs at its
/// floor parks the surplus holding nothing, and counting those parked
/// slots here would stretch the deadline in proportion - which is the
/// §208.2 rescue a wedged last-article depends on being made twice as
/// slow to fire, silently, on every install.
#[test]
fn stall_bound_shares_the_line_among_the_workers_actually_dialling() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    sh.body_bytes_ewma.store(750_000, Ordering::Relaxed);
    sh.sat.set_peak_bps(12_500_000); // 100 Mbit, the §208.2 rig's line
    sh.pending.store(10_000, Ordering::Relaxed);
    // The §112 shape at its widest: 720 slots spawned, half of them
    // parked at the live target. The line is split 360 ways, which is
    // the count the 21 Aug bound was measured on.
    sh.workers_live.store(720, Ordering::Relaxed);
    sh.parked_total.store(360, Ordering::Relaxed);
    assert_eq!(sh.workers_dialling(), 360);
    let dialling = Duration::from_millis(share_aware_stall_ms(750_000, 12_500_000, 360));
    assert_eq!(sh.stall_bound(), dialling);
    // The spawned count is a genuinely different answer - the whole
    // 720-way share runs into the 60 s ceiling - so this test would not
    // pass with the two confused for one another.
    sh.parked_total.store(0, Ordering::Relaxed);
    let spawned = Duration::from_millis(share_aware_stall_ms(750_000, 12_500_000, 720));
    assert_eq!(sh.stall_bound(), spawned);
    assert_ne!(dialling, spawned);
}

#[test]
fn stall_bound_shares_the_line_among_the_fewer_of_workers_and_articles_left() {
    // Seed a trained state by hand - the gauge's peak needs wall-clock
    // evidence, so the test drives the inputs `stall_bound` reads.
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    sh.body_bytes_ewma.store(750_000, Ordering::Relaxed);
    sh.sat.set_peak_bps(12_500_000); // 100 Mbit
    sh.workers_live.store(360, Ordering::Relaxed);
    // Mid-run: a deep queue, 360 sharers, the 100 Mbit bound (~43 s).
    sh.pending.store(1_000, Ordering::Relaxed);
    let mid = sh.stall_bound();
    assert_eq!(
        mid,
        Duration::from_millis(share_aware_stall_ms(750_000, 12_500_000, 360))
    );
    assert!(mid > Duration::from_secs(40), "mid-run bound {mid:?}");
    // Queue dry, one article left in the pool's books (the seeded one
    // is queued, nothing in flight): one sharer owns the whole line,
    // so the bound is back at the flat floor for the last article.
    sh.pending.store(1, Ordering::Relaxed);
    assert_eq!(
        sh.stall_bound(),
        ADAPTIVE_STALL,
        "tail: one sharer, flat bound"
    );
}

// The same sharer count, with articles actually IN FLIGHT. `pending`
// is every non-terminal article - queued AND in flight - so it is the
// whole count on its own; `stall_bound` used to add `inflight.len()`
// on top of it and judge the tail against about twice the work that
// was left (found by the drain-tail note 21 Aug, fixed in the 22 Aug
// bug sweep). Nothing pinned the fix: the tail case above happens to
// have an EMPTY inflight map, so it reads the same either way.
#[test]
fn stall_bound_counts_an_in_flight_article_once_and_not_twice() {
    let ids: Vec<String> = (0..100).map(|i| format!("<a{i}@x>")).collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let (sh, _) = Shared::new(fresh(&refs), &[(server("s"), PoolConfig::default())]);
    sh.body_bytes_ewma.store(750_000, Ordering::Relaxed);
    sh.sat.set_peak_bps(12_500_000); // 100 Mbit
    // More workers than articles left, so `left` alone picks the share.
    sh.workers_live.store(360, Ordering::Relaxed);
    assert_eq!(sh.pending.load(Ordering::Relaxed), 100);
    // Thirty of the hundred are on the wire. `pending` does not move -
    // an in-flight article is still non-terminal - so neither may the
    // bound.
    let before = sh.stall_bound();
    for id in ids.iter().take(30) {
        sh.register_inflight(&work(id), 0);
    }
    assert_eq!(sh.inflight.lock_ok().len(), 30);
    assert_eq!(sh.pending.load(Ordering::Relaxed), 100);
    assert_eq!(
        sh.stall_bound(),
        before,
        "dispatching an article may not lengthen the bound"
    );
    assert_eq!(
        before,
        Duration::from_millis(share_aware_stall_ms(750_000, 12_500_000, 100)),
        "the share is the 100 articles left, not 130"
    );
    // And the two are far enough apart to be distinguishable: the
    // double-counted figure is a different, longer bound, not the same
    // number reached twice.
    assert_ne!(
        before,
        Duration::from_millis(share_aware_stall_ms(750_000, 12_500_000, 130))
    );
}

// TODO 208.2 warm-up: before the run has trained a peak, the bound
// divides the daemon's link anchor (the figure the §208.1 seed was
// sized from), and the run's own peak takes over the moment it exists.
#[test]
fn stall_bound_takes_the_daemons_anchor_until_the_runs_own_peak_trains() {
    let cfg = PoolConfig {
        line_anchor_bps: 12_500_000, // 100 Mbit, persisted from a prior job
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), cfg)]);
    sh.workers_live.store(360, Ordering::Relaxed);
    sh.pending.store(1_000, Ordering::Relaxed);
    assert_eq!(
        sh.stall_bound(),
        ADAPTIVE_STALL,
        "no body delivered yet: nothing to size a share of"
    );
    // The first delivered body seeds the size EWMA whole, and from that
    // moment the anchor carries the bound - no 7 s plateau wait.
    sh.note_srv_bytes(0, 750_000);
    assert_eq!(sh.sat.peak_bps(), 0, "the gauge has not trained");
    let warm = sh.stall_bound();
    assert_eq!(
        warm,
        Duration::from_millis(share_aware_stall_ms(750_000, 12_500_000, 360))
    );
    assert!(warm > Duration::from_secs(40), "anchor-fed bound {warm:?}");
    // The run's own reading wins over the stamp once there is one, in
    // either direction: a faster line than the anchor tightens it.
    sh.sat.set_peak_bps(31_250_000);
    assert_eq!(
        sh.stall_bound(),
        Duration::from_millis(share_aware_stall_ms(750_000, 31_250_000, 360))
    );
}

// Without an anchor (a CLI run, or the daemon's first job) the gauge's
// provisional reading fills the gap from a quarter time constant of
// evidence - about 3.6 s after the first body - instead of the 7.2 s
// the peak waits for.
#[test]
fn stall_bound_takes_the_gauges_provisional_reading_without_an_anchor() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    sh.workers_live.store(360, Ordering::Relaxed);
    sh.pending.store(1_000, Ordering::Relaxed);
    sh.body_bytes_ewma.store(750_000, Ordering::Relaxed);
    // Drive the gauge directly: 1 MB at t=0 and again 4 s later. The
    // peak needs 7.2 s of age, the provisional reading 3.6 s.
    sh.sat.note_bytes(0, 1_000_000, false);
    assert_eq!(
        sh.sat.line_estimate_bps(2_000),
        0,
        "2 s: too little evidence"
    );
    sh.sat.note_bytes(4_000, 1_000_000, false);
    let est = sh.sat.line_estimate_bps(4_000);
    assert!(est > 0, "4 s: the slow window has a corrected rate");
    assert_eq!(sh.sat.peak_bps(), 0, "and it is still not a peak");
    // That estimate is a slow line (2 MB over 4 s ~ 0.5 MB/s read
    // through the warm-up correction), so 360 sharers stretch the
    // bound to its ceiling.
    let bound = sh.stall_bound_at(4_000);
    assert!(
        bound > ADAPTIVE_STALL,
        "provisional bound {bound:?} is off the floor"
    );
    assert_eq!(
        bound,
        Duration::from_millis(share_aware_stall_ms(750_000, est, 360)).min(ADAPTIVE_STALL_MAX)
    );
}

#[test]
fn mark_suspect_flags_a_live_entry_and_ignores_a_finished_one() {
    let cfg = PoolConfig {
        ttfb_hedge: true,
        adaptive_timeout: true,
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), cfg)]);
    // The timer races the read's own completion: the entry may already
    // be gone, and that must be a no-op, not a panic or a stuck flag.
    sh.mark_suspect("<gone@x>");
    assert!(!sh.suspect_pending.load(Ordering::Acquire));
    sh.register_inflight(&work("<a@x>"), 0);
    sh.mark_suspect("<a@x>");
    assert!(sh.suspect_pending.load(Ordering::Acquire));
    assert!(sh.inflight.lock_ok().get("<a@x>").unwrap().suspect);
}

/// The suspect-dup gate ladder, in the order the code checks it: dark
/// flag, fill level, busy picker, no pending suspicion, issue-rate cap,
/// per-server once, and the empty-scan fast-path flag clear.
#[test]
fn pick_suspect_dup_walks_its_gate_ladder() {
    let hedge_cfg = PoolConfig {
        ttfb_hedge: true,
        adaptive_timeout: true,
        ..Default::default()
    };
    // Dark flag: a pool built without the knob never races, suspicion
    // or not.
    let (dark, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    dark.register_inflight(&work("<a@x>"), 0);
    dark.mark_suspect("<a@x>");
    assert!(dark.pick_suspect_dup(0b01, 0b01, 0, 0).is_none());

    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("p"), hedge_cfg.clone()), (server("q"), hedge_cfg)],
    );
    sh.register_inflight(&work("<a@x>"), 0);
    // No suspicion yet: the fast-path flag keeps the scan free.
    assert!(sh.pick_suspect_dup(0b10, 0b10, 0, 0).is_none());
    sh.mark_suspect("<a@x>");
    // Fill servers never spend block bytes on speculation, and a busy
    // picker's dup would displace queued work.
    assert!(sh.pick_suspect_dup(0b10, 0b10, 1, 0).is_none());
    assert!(sh.pick_suspect_dup(0b10, 0b10, 0, 3).is_none());
    // The hedge issue-rate cap prices jitter: over it, the budget path
    // still rescues, but no new dup is issued. §17c: it is the TTFB
    // rule's OWN purse - a spent STALE purse must not starve it.
    sh.ttfb_hedges_issued.store(1_000, Ordering::Relaxed);
    assert!(sh.pick_suspect_dup(0b10, 0b10, 0, 0).is_none());
    sh.ttfb_hedges_issued.store(0, Ordering::Relaxed);
    sh.hedges_issued.store(1_000, Ordering::Relaxed);

    let dup = sh
        .pick_suspect_dup(0b10, 0b10, 0, 0)
        .expect("an idle primary races the suspect even with the stale purse spent");
    assert_eq!(&*dup.id, "<a@x>");
    assert!(dup.dup, "raced copy is a duplicate, never an owner");
    assert_eq!(sh.ttfb_hedges_issued.load(Ordering::Relaxed), 1);
    assert_eq!(
        sh.hedges_issued.load(Ordering::Relaxed),
        1_000,
        "the TTFB rescue never draws down the straggler budget"
    );
    sh.hedges_issued.store(0, Ordering::Relaxed);
    {
        let inf = sh.inflight.lock_ok();
        let e = inf.get("<a@x>").unwrap();
        assert_eq!(e.dups, 1);
        assert_eq!(
            e.dup_servers & 0b10,
            0b10,
            "this server is spent for this article"
        );
    }
    // dups >= 1 filters the entry for every later picker, so the scan
    // comes up empty and clears the fast-path flag until a NEW
    // suspicion fires.
    assert!(sh.pick_suspect_dup(0b01, 0b01, 0, 0).is_none());
    assert!(
        !sh.suspect_pending.load(Ordering::Acquire),
        "an empty scan stops paying for itself"
    );
}

#[test]
fn required_mask_counts_only_live_lower_levels() {
    let mut fill = server("f");
    fill.level = 1;
    let servers = vec![
        (server("p0"), PoolConfig::default()),
        (server("p1"), PoolConfig::default()),
        (fill, PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    sh.alive[0].store(1, Ordering::Relaxed);
    sh.alive[2].store(1, Ordering::Relaxed);
    assert_eq!(
        sh.live_mask(),
        0b101,
        "only servers with running workers count"
    );
    assert_eq!(
        sh.required_mask(1),
        0b001,
        "a fill server waits on live primaries only - a dead one can never 430"
    );
    assert_eq!(sh.required_mask(0), 0, "level 0 answers to nobody");
}

/// M5: the fill gate is written in 430s, and a primary that kills the
/// same article's connection on every attempt never files one. Before
/// this, the deeper tier stayed locked out for the whole run and the
/// failing primary read `other_can_take` as "nobody else can have it",
/// so it retook its own casualty until the budget was gone and the
/// article was reported lost while a healthy server held it.
#[test]
fn a_spent_budget_opens_the_fill_gate_without_forging_a_refusal() {
    let mut fill = server("fill");
    fill.level = 1;
    let servers = vec![
        (server("prime"), PoolConfig::default()),
        (fill, PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    sh.alive[0].store(1, Ordering::Relaxed);
    sh.alive[1].store(1, Ordering::Relaxed);
    let mut w = work("<a@x>");
    w.tried_fail = server_bit(0);
    assert!(
        !sh.other_can_take(&w, 0),
        "transport failures alone leave the fill server gated"
    );
    assert!(
        sh.note_spent(&w, server_bit(0)),
        "the fill server has never had a go at this article"
    );
    assert_eq!(sh.spent_mask("<a@x>"), server_bit(0));
    assert!(
        sh.other_can_take(&w, 0),
        "a spent primary satisfies the gate, so the retry goes down a level"
    );
    assert_eq!(
        w.tried_430, 0,
        "spent is routing, never evidence - no refusal is invented"
    );
    assert_ne!(
        w.tried_430 & sh.live_mask(),
        sh.live_mask(),
        "and no unanimous Missing is manufactured for an article a server holds"
    );
    assert!(
        !sh.note_spent(&w, server_bit(0)),
        "one re-arm per server is what bounds the ladder"
    );
    // A terminal article takes its routing state with it.
    assert!(sh.claim_done("<a@x>", w.ord));
    assert_eq!(sh.spent_mask("<a@x>"), 0);
}

#[test]
fn wire_cap_note_marks_the_graph_once_per_window() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let cfg = PoolConfig {
        live: Some(live.clone()),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), cfg)]);
    assert!(!sh.wire_over_cap(0), "cap 0 is uncapped");
    sh.charge_wire();
    assert!(sh.wire_over_cap(1), "one charge trips a 1-byte cap");
    sh.note_wire_cap();
    sh.note_wire_cap();
    let wires = live
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.kind == "wire")
        .count();
    assert_eq!(
        wires, 1,
        "an engaged cap answers every top-up; the ring must not"
    );
    sh.release_wire(1);
    assert!(
        !sh.wire_over_cap(1),
        "release undoes exactly what dispatch charged"
    );
    // Without live stats the note is a no-op, not a panic - CLI runs
    // have no ring.
    let (bare, _) = Shared::new(fresh(&["<b@x>"]), &[(server("s"), PoolConfig::default())]);
    bare.note_wire_cap();
}

#[test]
fn race_burst_note_opens_its_window_before_ever_marking() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let cfg = PoolConfig {
        live: Some(live.clone()),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), cfg)]);
    sh.note_race_burst();
    sh.note_race_burst();
    let racing = live
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.kind == "racing")
        .count();
    assert_eq!(
        racing, 0,
        "the endgame of a healthy job issues a handful of dups and must not mark the graph"
    );
    // No ring, no work - the early return, not a panic.
    let (bare, _) = Shared::new(fresh(&["<b@x>"]), &[(server("s"), PoolConfig::default())]);
    bare.note_race_burst();
}

#[test]
fn any_live_answers_from_inflight_then_queue_then_absence() {
    let ctl = QueueControl::default();
    assert_eq!(
        ctl.any_live(&["<a@x>".into()]),
        None,
        "before attach there is no pool to ask"
    );
    let (sh, _) = Shared::new(
        fresh(&["<q1@x>", "<q2@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    assert_eq!(ctl.any_live(&[]), Some(true), "no ids is vacuously live");
    assert_eq!(
        ctl.any_live(&["<q1@x>".into()]),
        Some(true),
        "still queued means still live"
    );
    assert_eq!(
        ctl.any_live(&["<nope@x>".into()]),
        Some(false),
        "unknown everywhere is the negative verdict"
    );
    sh.register_inflight(&work("<w@x>"), 0);
    assert_eq!(
        ctl.any_live(&["<w@x>".into()]),
        Some(true),
        "in flight answers without touching the queue lock"
    );
}

#[test]
fn requeue_rolls_back_when_the_run_is_over_or_aborted() {
    assert_eq!(
        QueueControl::default().requeue(&["<a@x>".into()]),
        0,
        "no pool attached, nothing to resurrect"
    );
    // Finished-run rollback: cancel the last pending article, complete
    // the other, then try to resurrect - the fleet is winding down and
    // nothing would ever fetch it, so the stash keeps it and the caller
    // keeps its accounting.
    let ctl = QueueControl::default();
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    // The finished watch only latches with a subscriber alive - workers
    // hold one in production, so the test must too.
    let finished = sh.finished.subscribe();
    let mut cancel_ids = HashSet::new();
    cancel_ids.insert("<a@x>".into());
    assert_eq!(ctl.cancel(&cancel_ids), vec!["<a@x>".into()]);
    assert!(sh.claim_done("<b@x>", 1));
    sh.complete_one();
    assert!(
        *finished.borrow(),
        "the cancelled+completed pair drained the run"
    );
    assert_eq!(ctl.requeue(&["<a@x>".into()]), 0);
    assert!(
        sh.cancelled.lock_ok().contains_key("<a@x>"),
        "rollback re-stashes, so a later retry is still possible"
    );
    assert_eq!(
        sh.pending.load(Ordering::Acquire),
        0,
        "the probe count was undone"
    );
    // Unknown ids never count toward the return value.
    assert_eq!(ctl.requeue(&["<never@x>".into()]), 0);
    // Aborted-run refusal, before any stash lookup.
    let ctl2 = QueueControl::default();
    let (sh2, _) = Shared::new(
        fresh(&["<c@x>", "<d@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl2.attach(&sh2);
    let mut ids2 = HashSet::new();
    ids2.insert("<c@x>".into());
    assert_eq!(ctl2.cancel(&ids2), vec!["<c@x>".into()]);
    assert!(ctl2.abort());
    assert_eq!(ctl2.requeue(&["<c@x>".into()]), 0);
}

/// The drained verdict vs a concurrent requeue, interleaved at the exact
/// gap: the last completion's fetch_sub has landed `pending` on zero but
/// the finished-send decision has not run yet (the barrier seam holds it
/// there), and a requeue arrives inside that window. The requeue must
/// win cleanly: it re-raises `pending`, the held completion then sees
/// the revived count and stays silent, and the requeued article's own
/// completion is what ends the run. Before `finish_gate`, both sides
/// lost - the raise came after the zero-crossing, the finished check
/// read the not-yet-sent watch, and the send then fired anyway over a
/// queue that had just been given work no worker would ever pop.
#[test]
fn requeue_inside_the_drain_gap_keeps_the_run_alive() {
    let ctl = QueueControl::default();
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    let finished = sh.finished.subscribe();
    let mut cancel_ids = HashSet::new();
    cancel_ids.insert("<a@x>".into());
    assert_eq!(ctl.cancel(&cancel_ids), vec!["<a@x>".into()]);
    // Arm the seam, then complete the last real article on a second
    // thread: it parks between the zero-crossing and the verdict.
    let entered = Arc::new(std::sync::Barrier::new(2));
    let released = Arc::new(std::sync::Barrier::new(2));
    *sh.drain_send_barrier.lock_ok() = Some((entered.clone(), released.clone()));
    let sh2 = sh.clone();
    let completer = std::thread::spawn(move || {
        assert!(sh2.claim_done("<b@x>", 1));
        sh2.complete_one();
    });
    entered.wait(); // the crossing has happened, the verdict has not
    *sh.drain_send_barrier.lock_ok() = None; // one trip only
    assert_eq!(
        ctl.requeue(&["<a@x>".into()]),
        1,
        "a requeue landing inside the gap is honoured, not lost"
    );
    released.wait();
    completer.join().unwrap();
    assert!(
        !*finished.borrow(),
        "the held completion saw the revived count and stayed silent"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 1);
    assert!(
        sh.queue
            .try_lock()
            .unwrap()
            .iter()
            .any(|w| &*w.id == "<a@x>"),
        "the requeued article is queued for a fleet that is still running"
    );
    // The requeued article's own completion now ends the run.
    assert!(sh.claim_done("<a@x>", 0));
    sh.complete_one();
    assert!(
        *finished.borrow(),
        "the revived run still drains to a real end"
    );
}

/// The on-demand pool-state dump (stall watchdog, NZBFAST_POOL_DEBUG's
/// idle branch). The throttle static admits one dump per 5 s of a
/// pool's lifetime and the clock is the pool's own age, so this test
/// pays real seconds - that is the price of covering a diagnostic whose
/// whole job is to fire from a hung run in the field.
#[test]
fn dump_state_survives_a_held_queue_and_then_prints_it() {
    let ctl = QueueControl::default();
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    sh.register_inflight(&work("<w@x>"), 0);
    // Detached ctl: a dump on a dead pool is a no-op.
    QueueControl::default().dump_state();
    std::thread::sleep(Duration::from_millis(5_100));
    {
        // A busy queue must degrade to "lock busy", never block the
        // watchdog that is trying to diagnose a hang.
        let _held = sh.queue.try_lock().expect("test owns the queue");
        ctl.dump_state();
    }
    std::thread::sleep(Duration::from_millis(5_100));
    ctl.dump_state(); // queue free: the full queue + inflight listing
    ctl.dump_state(); // and the once-per-5s throttle swallows this one
}

/// A fleet that exhausted with a handed body outstanding never sends
/// `finished`: the handed id sits in `done`, so pending never lands on
/// zero and `seal_run` skips the send. A requeue arriving after that
/// used to be honoured, queueing work no worker would ever pop - the run
/// then sat until its own give-up timer. `finished` alone cannot see it
/// and `workers_live == 0` alone is also every run before its first
/// worker is BORN, where refusing would drop work racing fleet birth.
/// The pair is the question (Fable sweep 15 Aug, TODO 170).
#[test]
fn requeue_into_an_exhausted_fleet_is_refused_but_a_newborn_one_is_not() {
    let ctl = QueueControl::default();
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    let mut cancel_ids = HashSet::new();
    cancel_ids.insert("<a@x>".into());
    assert_eq!(ctl.cancel(&cancel_ids), vec!["<a@x>".into()]);

    // Before any worker exists - the fleet is still arriving, and this
    // is the interleaving the naive guard broke.
    assert_eq!(
        ctl.requeue(&["<a@x>".into()]),
        1,
        "a requeue racing fleet birth must be honoured, not dropped"
    );

    // Now the fleet lives and then dies out entirely.
    assert_eq!(ctl.cancel(&cancel_ids), vec!["<a@x>".into()]);
    sh.workers_born.store(4, Ordering::Release);
    sh.workers_live.store(0, Ordering::Release);
    assert_eq!(
        ctl.requeue(&["<a@x>".into()]),
        0,
        "reviving into a fleet that has no workers left queues work nobody can pop"
    );
}

/// M2 (read-only sweep 2): the fleet-dead check and the queue insert
/// were not one critical section. `requeue` clears `finish_gate` with a
/// worker still live, that worker then retires - `WorkerLife::retire`
/// decrements `workers_live` under no gate at all - and the terminal
/// seal drains a queue the insert has not reached yet. The old code
/// then queued the article behind a fleet that was gone and returned
/// non-zero, so the caller reversed its deferred accounting for an
/// outcome nobody would ever send.
///
/// Both directions, because a fix that simply refuses more often would
/// pass the first half alone: with the fleet still alive across the
/// very same seam the requeue must still be honoured.
#[test]
fn requeue_refuses_when_the_last_worker_retires_inside_the_gate_window() {
    // The fleet dies inside the window.
    let ctl = Arc::new(QueueControl::default());
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    let (tx, mut rx) = mpsc::channel(8);
    sh.workers_born.store(1, Ordering::Release);
    sh.workers_live.store(1, Ordering::Release);
    let mut cancel_ids = HashSet::new();
    cancel_ids.insert("<a@x>".into());
    assert_eq!(ctl.cancel(&cancel_ids), vec!["<a@x>".into()]);

    let entered = Arc::new(std::sync::Barrier::new(2));
    let released = Arc::new(std::sync::Barrier::new(2));
    *sh.requeue_gate_barrier.lock_ok() = Some((entered.clone(), released.clone()));
    let ctl2 = ctl.clone();
    let requeuer = std::thread::spawn(move || ctl2.requeue(&["<a@x>".into()]));
    entered.wait(); // past the gate check, queue lock not taken yet
    *sh.requeue_gate_barrier.lock_ok() = None; // one trip only
    // The last worker leaves and seals what it can see - which does not
    // include the article still in flight through `requeue`.
    sh.workers_live.store(0, Ordering::Release);
    assert_eq!(
        seal_run_blocking(&sh, &tx, FailCode::FleetExhausted),
        1,
        "the seal drains the queue it can see: <b@x> only"
    );
    released.wait();
    assert_eq!(
        requeuer.join().unwrap(),
        0,
        "resurrecting into a fleet that retired inside the window must be refused"
    );
    assert!(
        sh.cancelled.lock_ok().contains_key("<a@x>"),
        "the refusal re-stashes, so the caller keeps its deferred accounting"
    );
    assert!(
        !sh.queue
            .try_lock()
            .unwrap()
            .iter()
            .any(|w| &*w.id == "<a@x>"),
        "nothing was published behind the departed fleet"
    );
    assert!(
        sh.done.lock_ok().contains(0), // <a@x>'s ordinal
        "the article is terminal again, exactly as `cancel` left it"
    );
    assert_eq!(
        sh.pending.load(Ordering::Acquire),
        0,
        "the probe count was undone, so the run can still reach its end"
    );
    let mut failed = Vec::new();
    while let Ok(FetchOutcome::Failed { id, .. }) = rx.try_recv() {
        failed.push(id);
    }
    assert_eq!(failed, vec!["<b@x>".into()]);

    // Same seam, fleet still alive: the requeue must go through.
    let ctl = Arc::new(QueueControl::default());
    let (sh, _) = Shared::new(
        fresh(&["<c@x>", "<d@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    sh.workers_born.store(1, Ordering::Release);
    sh.workers_live.store(1, Ordering::Release);
    let mut cancel_ids = HashSet::new();
    cancel_ids.insert("<c@x>".into());
    assert_eq!(ctl.cancel(&cancel_ids), vec!["<c@x>".into()]);
    let entered = Arc::new(std::sync::Barrier::new(2));
    let released = Arc::new(std::sync::Barrier::new(2));
    *sh.requeue_gate_barrier.lock_ok() = Some((entered.clone(), released.clone()));
    let ctl2 = ctl.clone();
    let requeuer = std::thread::spawn(move || ctl2.requeue(&["<c@x>".into()]));
    entered.wait();
    *sh.requeue_gate_barrier.lock_ok() = None;
    released.wait();
    assert_eq!(
        requeuer.join().unwrap(),
        1,
        "a live fleet still gets its work back - the recheck is not a teardown"
    );
    assert!(
        sh.queue
            .try_lock()
            .unwrap()
            .iter()
            .any(|w| &*w.id == "<c@x>"),
        "and the article really is queued for it"
    );
    assert_eq!(sh.pending.load(Ordering::Acquire), 2);
    assert!(
        !sh.done.lock_ok().contains(0), // <c@x>'s ordinal
        "un-terminal again, so its own outcome can still land"
    );
}

/// Codex F-07 (22 Aug 2026): `requeue` used to clear the revived
/// articles' `done` bits BEFORE its refusal points, and its rollback
/// re-claimed them on the way out. A lingering duplicate dispatch
/// completing inside that window took the cleared bit as a fresh
/// completion and subtracted `pending` - and the rollback, which does
/// not know the claim happened, subtracted the same revival AGAIN. Two
/// articles, one still unresolved, and the run fired `finished`:
/// cancel A (2 -> 1), revive (-> 2), duplicate completes A (-> 1),
/// rollback (-> 0). The fix clears the bits only under the queue lock,
/// past the last refusal, so a duplicate in the window meets a bit that
/// is still terminal and claims nothing.
///
/// The staging: the test HOLDS the queue lock, so the requeue spins its
/// whole bounded try_lock ladder and then rolls back - the exact
/// refusal the audit's ledger walked. The gate barrier only sequences
/// entry into that wait; the duplicate's completion is placed inside it
/// by polling for the moment the pre-fix code exposes (the bit going
/// un-terminal mid-wait), a moment the fixed code never produces.
#[test]
fn a_duplicate_completing_inside_the_requeue_window_is_not_subtracted_twice() {
    let ctl = Arc::new(QueueControl::default());
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    sh.workers_born.store(1, Ordering::Release);
    sh.workers_live.store(1, Ordering::Release);
    let mut cancel_ids = HashSet::new();
    cancel_ids.insert("<a@x>".into());
    assert_eq!(ctl.cancel(&cancel_ids), vec!["<a@x>".into()]);
    assert_eq!(sh.pending.load(Ordering::Acquire), 1);

    let entered = Arc::new(std::sync::Barrier::new(2));
    let released = Arc::new(std::sync::Barrier::new(2));
    *sh.requeue_gate_barrier.lock_ok() = Some((entered.clone(), released.clone()));
    let ctl2 = ctl.clone();
    let requeuer = std::thread::spawn(move || ctl2.requeue(&["<a@x>".into()]));
    entered.wait(); // pending raised to 2, queue lock not taken yet
    *sh.requeue_gate_barrier.lock_ok() = None; // one trip only
    // Contend the queue so the requeue lives out its bounded wait and
    // rolls back with the fleet still alive.
    let q = sh.queue.try_lock().expect("nobody else holds the queue");
    released.wait();
    // The lingering duplicate delivers its body INSIDE the wait -
    // exactly what a dup dispatch does on completion: claim, and
    // complete if it won. The poll waits out the instant the pre-fix
    // code un-terminals the bit mid-wait; on the fixed code that
    // instant never comes (the bit is cleared only past the lock), the
    // deadline lapses well inside the requeue's own wait, and the
    // claim below meets a bit that is still terminal.
    let cleared_at = std::time::Instant::now();
    while sh.done.lock_ok().contains(0)
        && cleared_at.elapsed() < std::time::Duration::from_millis(8)
    {
        std::thread::yield_now();
    }
    if sh.claim_done("<a@x>", 0) {
        sh.complete_one();
    }
    assert_eq!(
        requeuer.join().unwrap(),
        0,
        "a requeue that cannot take the queue must refuse, not publish blind"
    );
    drop(q);
    assert_eq!(
        sh.pending.load(Ordering::Acquire),
        1,
        "only the rollback's own subtract may land - <b@x> is still owed its outcome"
    );
    assert!(
        !*sh.finished.borrow(),
        "the run must not read as finished with <b@x> unresolved"
    );
    assert!(
        sh.done.lock_ok().contains(0),
        "the revived article is terminal again, exactly as cancel left it"
    );
    assert!(
        sh.cancelled.lock_ok().contains_key("<a@x>"),
        "the refusal re-stashes, so the caller keeps its deferred accounting"
    );
}

#[tokio::test]
async fn fetch_all_serves_one_server_end_to_end() {
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i * 3) as u8).collect();
    let segs = make_file_articles("w.bin", &payload, 8_000, "one", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n = reqs.len();
    let cfg = PoolConfig {
        connections: 1,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::channel(64);
    let stats = tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all(&srv.server_config(), &cfg, reqs, tx),
    )
    .await
    .expect("run hung");
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(done, n);
    assert!(stats.ever_connected);
    assert!(
        stats.bytes > 0,
        "the single-server wrapper reports its own stats"
    );
}

/// The daemon's production entry point: shard threads with their own
/// runtimes, one shared queue, the blocking seal after the join. Runs
/// on a plain test thread exactly like the daemon calls it.
#[test]
fn sharded_fetch_serves_everything_across_shards() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..60_000u32).map(|i| (i * 7) as u8).collect();
    let segs = make_file_articles("s.bin", &payload, 8_000, "shard", &mut articles);
    // The mock's accept loop lives on this runtime; it must stay alive
    // for the whole blocking fetch below.
    let srv = rt.block_on(MockServer::start(articles, Chaos::default()));
    let mut server = srv.server_config();
    server.retention_days = 10;
    server.connections = 3;
    let mut reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n_fresh = reqs.len();
    // Outside the only server's retention: Missing without a request,
    // reported on the sharded path's own blocking send.
    reqs.push(ArticleReq {
        id: "<ancient@x>".into(),
        age_days: 400,
        part: 0,
        file: u32::MAX,
    });
    let cfg = PoolConfig {
        connections: 3,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let ctl = QueueControl::default();
    let (tx, mut rx) = mpsc::channel(1024);
    let stats = fetch_all_sharded(vec![(server, cfg)], reqs, tx, 2, Some(&ctl));
    let mut done = 0;
    let mut retention = 0;
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            FetchOutcome::Missing {
                cause: MissingCause::Retention,
                ..
            } => retention += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(
        done, n_fresh,
        "every servable article lands across both shards"
    );
    assert_eq!(retention, 1);
    assert_eq!(stats.len(), 1);
    assert!(stats[0].ever_connected);
    assert!(stats[0].bytes > 0);
    assert!(stats[0].connects >= 1, "the shard plans actually dialled");
    assert_eq!(
        ctl.any_live(&[]),
        None,
        "the ctl holds a Weak - a finished run detaches it, it never leaks the pool"
    );
}

/// The sharded path's head-counts must be complete BEFORE any shard
/// thread starts. Shards come up in OS-scheduler order, and births that
/// happened inside each shard let an early shard read a partial fleet:
/// a 430 there became a premature unanimous Missing (`live_mask`), and
/// a fill server could take queued work against `required_mask == 0`.
/// `deal_shard_plans` births every life at deal time; an unspawned plan
/// releases them on drop.
#[test]
fn shard_plans_are_born_before_any_thread() {
    let mut primary = server("a.example");
    primary.connections = 3;
    let mut fill = server("b.example");
    fill.connections = 2;
    fill.level = 1;
    let servers = vec![
        (
            primary,
            PoolConfig {
                connections: 3,
                ..Default::default()
            },
        ),
        (
            fill,
            PoolConfig {
                connections: 2,
                ..Default::default()
            },
        ),
    ];
    let (shared, unservable) = Shared::new(fresh(&["<a@x>", "<b@x>"]), &servers);
    assert!(unservable.is_empty());
    let plans = deal_shard_plans(&shared, &servers, 2);
    assert_eq!(plans.iter().map(|p| p.len()).sum::<usize>(), 5);
    // Both servers are live and the fill gate sees the primary before a
    // single shard thread (or worker task) exists.
    assert_eq!(shared.live_mask(), server_bit(0) | server_bit(1));
    assert_eq!(shared.required_mask(1), server_bit(0));
    assert_eq!(shared.workers_live.load(Ordering::Acquire), 5);
    // A plan dropped unspawned (its shard runtime failed to build)
    // releases its lives like workers dying.
    drop(plans);
    assert_eq!(shared.live_mask(), 0);
    assert_eq!(shared.workers_live.load(Ordering::Acquire), 0);
}

/// BOTH entry paths must deal the fleet through the one dealer, and
/// this is a source scan because the defect it refuses is an
/// INTERLEAVING: nothing a rig can assert distinguishes
/// "born then spawned" from "born and spawned server by server"
/// except by winning a race.
///
/// `fetch_all_multi_ctl` used to birth each server's lives inside the
/// same pass that spawned them, and claimed to pin the invariant "by
/// counting from spawn". That closes the CONNECT ramp and not the
/// birth loop: `tokio::spawn` hands the task to another runtime thread
/// immediately, so server 0's workers could pop work while every
/// server after it still read `alive == 0`. `required_mask` then
/// returned 0 and a DEMOTED fill server took queued work off the front
/// of the FIFO, and `live_mask` did not hold the primary, so that
/// server's 430 read as UNANIMOUS and the article went terminal
/// `Missing::Gone` with the server that had the bytes never asked.
/// Measured 25 Aug 2026 with a 200 ms gap wedged between the two
/// servers of `nzbfast`'s `plan_route_rig` A/B: 48 of 48 articles lost
/// on a run whose second server held every one of them. It reached CI
/// as a flake of that rig under `unit-one-process` load (34 lost, 14
/// completed).
///
/// So: exactly one production birth site, and it is inside
/// [`deal_shard_plans`], whose own contract
/// (`shard_plans_are_born_before_any_thread` above) is that the whole
/// fleet is counted before it returns. Fix a failure here by dealing
/// through that function, never by relaxing this test - and never by
/// moving the birth into a spawn loop, whichever path.
#[test]
fn every_worker_life_is_born_by_the_one_dealer() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/pool.rs"))
        .expect("pool.rs must be readable - an unread source is not a passing scan");
    let dealer = src
        .find("fn deal_shard_plans(")
        .expect("the dealer must still be named `deal_shard_plans`");
    // Item bodies in this file close on a column-zero brace.
    let end = src[dealer..]
        .find("\n}\n")
        .map(|o| dealer + o)
        .expect("the dealer's body must be findable");
    let sites: Vec<usize> = src
        .match_indices("WorkerLife::birth(")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        sites.len(),
        1,
        "pool.rs must hold exactly ONE birth site (found {}) - every worker's \
         life belongs to `deal_shard_plans`, so that `alive` counts the whole \
         fleet before any worker runs",
        sites.len()
    );
    assert!(
        (dealer..end).contains(&sites[0]),
        "the birth site must live inside `deal_shard_plans`, not in a spawn loop"
    );
}

/// Shards degraded to zero built runtimes still owe every article a
/// terminal outcome - the blocking seal is the only seller left.
#[test]
fn sharded_fetch_with_zero_shard_clamp_still_reports() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..8_000u32).map(|i| i as u8).collect();
    let segs = make_file_articles("z.bin", &payload, 8_000, "zero", &mut articles);
    let srv = rt.block_on(MockServer::start(articles, Chaos::default()));
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n = reqs.len();
    // connections 0 and window 0 are configuration nonsense the daemon
    // can hand us mid-edit; the sharded clamp must turn both into 1.
    let cfg = PoolConfig {
        connections: 0,
        window: 0,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::channel(64);
    let stats = fetch_all_sharded(vec![(srv.server_config(), cfg)], reqs, tx, 0, None);
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(
        done, n,
        "shards.max(1) and connections.max(1) kept the run alive"
    );
    assert!(stats[0].bytes > 0);
}

/// Codex 5 Aug M4: `drain()` sets ONLY `draining` - no `finished`, no
/// abort - so a filler that watches just those two loops forever after a
/// graceful pause, pinning `Arc<Shared>` and an authenticated provider
/// session. The filler must notice the flag on its own tick and quit
/// whatever it parked.
#[tokio::test]
async fn spare_filler_exits_on_graceful_drain_and_quits_its_spare() {
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..4_000u32).map(|i| (i * 5) as u8).collect();
    make_file_articles("d.bin", &payload, 2_000, "drain", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let (sh, _) = Shared::new(
        fresh(&["<a@x>"]),
        &[(srv.server_config(), PoolConfig::default())],
    );
    let task = tokio::spawn(spare_filler(sh.clone(), srv.server_config(), 0));
    let parked = async {
        while sh.spares[0].lock_ok().is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(10), parked)
        .await
        .expect("the filler never parked a spare against a live server");
    sh.draining.store(true, Ordering::Release);
    // The 500 ms tick is the exit-latency bound; 5 s is generous.
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the filler ignored a graceful drain")
        .unwrap();
    assert!(
        sh.spares[0].lock_ok().is_none(),
        "the parked spare must be quit, not leaked, on drain"
    );
}

/// TODO 121.1: the per-article pre-byte ladder - server budget
/// untouched at zero expiries, then the adaptive ceiling doubling
/// upward, capped at the article ceiling; a wider server budget (or
/// env-lifted ceiling) stays dominant.
#[test]
fn prebyte_expiries_escalate_the_articles_own_budget() {
    let base = Duration::from_secs(2);
    assert_eq!(article_prebyte_budget(base, 0), base);
    assert_eq!(article_prebyte_budget(base, 1), Duration::from_secs(10));
    assert_eq!(article_prebyte_budget(base, 2), Duration::from_secs(20));
    assert_eq!(article_prebyte_budget(base, 3), Duration::from_secs(30));
    assert_eq!(
        article_prebyte_budget(base, 4),
        Duration::from_secs(30),
        "the article ceiling holds"
    );
    let wide = Duration::from_secs(25);
    assert_eq!(
        article_prebyte_budget(wide, 1),
        wide,
        "a wider server budget is never narrowed"
    );
}

/// TODO 121.2: an adaptive pre-byte expiry is OUR budget choice, not a
/// session death - FLAP_DEATHS of them must not clamp the server. A
/// genuine mid-flow stall on an established session still counts, and
/// a session that never served a byte still counts nothing.
#[test]
fn prebyte_expiries_are_not_flap_deaths_but_midflow_stalls_are() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    let mut w = work("<a@x>");
    for _ in 0..FLAP_DEATHS {
        note_read_stall(&sh, 0, 1_000_000, true, Some(&mut w));
    }
    assert!(
        !sh.is_flapping(0),
        "a heavy-tailed but healthy provider must not be keeper-clamped"
    );
    assert_eq!(
        w.prebyte_expiries, FLAP_DEATHS as u8,
        "each expiry escalates the article's own next attempt"
    );
    for _ in 0..FLAP_DEATHS {
        note_read_stall(&sh, 0, 1_000_000, false, Some(&mut w));
    }
    assert!(sh.is_flapping(0), "mid-flow stalls remain deaths");
    let (sh2, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    note_read_stall(&sh2, 0, 0, false, None);
    assert!(
        !sh2.is_flapping(0),
        "a byteless session was never established"
    );
}

/// TODO 121.4: with `arrival_ack` the handoff leaves the `done_ok`
/// liveness entry in place - the article stays visible to the
/// dead-span verdict through the channel buffer and the consumer's
/// in-hand batch - until the consumer's note_settled lands after
/// decode+write. Ack-less pools and undelivered bodies settle at the
/// handoff exactly as before.
#[test]
fn arrival_ack_holds_done_ok_until_the_consumer_settles() {
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>", "<c@x>", "<d@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    let ctl = QueueControl::default();
    ctl.attach(&sh);
    // Empty the seeded queue: this test watches the done_ok arm of
    // any_live, and a queued copy of the id would keep it live for
    // its own (correct) reason.
    sh.queue.try_lock().expect("no workers hold it").clear();
    // Ack-less pool: the handoff settles immediately.
    sh.done_ok.lock_ok().insert("<a@x>".into());
    sh.settle_handoff(false, false, true, "<a@x>");
    assert!(!sh.done_ok.lock_ok().contains("<a@x>"));
    // Acking pool: the entry survives the handoff, keeps the span
    // live, and leaves only on the consumer's ack.
    sh.done_ok.lock_ok().insert("<b@x>".into());
    sh.settle_handoff(false, true, true, "<b@x>");
    assert!(
        sh.done_ok.lock_ok().contains("<b@x>"),
        "held through the channel buffer and decode batch"
    );
    assert_eq!(ctl.any_live(&["<b@x>".into()]), Some(true));
    ctl.note_settled("<b@x>");
    assert!(!sh.done_ok.lock_ok().contains("<b@x>"));
    assert_eq!(ctl.any_live(&["<b@x>".into()]), Some(false));
    // An undelivered body (channel closed) has no consumer left to
    // ack it - settles at the handoff.
    sh.done_ok.lock_ok().insert("<c@x>".into());
    sh.settle_handoff(false, true, false, "<c@x>");
    assert!(!sh.done_ok.lock_ok().contains("<c@x>"));
}

/// §122 coverage + the flap clamp's own contract: on a flapping server
/// with a healthy sibling, the keeper slots go to the first claimants
/// and every later worker loses the claim and bows out - the branch
/// the ignored wall-clock rigs used to be the only visitors of.
#[tokio::test]
async fn flap_keeper_claim_admits_the_target_and_bows_the_rest_out() {
    let servers = vec![
        (server("flappy"), PoolConfig::default()),
        (server("steady"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    // Six established-session deaths inside the window: flapping.
    for _ in 0..FLAP_DEATHS {
        sh.note_flap(0);
    }
    // A healthy sibling is what licenses the clamp at all.
    sh.alive[1].fetch_add(1, Ordering::AcqRel);
    let cfg = PoolConfig::default();
    let ctx = ctx_for(&servers, 0);
    // No observed accept cap: the keeper target is the shipped one.
    assert_eq!(sh.flap_keeper_target(0, &cfg), 1);
    let mut first_keeper = false;
    let mut none = None;
    assert!(
        claim_flap_keeper(&cfg, ctx, &sh, &mut first_keeper, &mut none).await,
        "the first claimant keeps the light on"
    );
    assert!(first_keeper);
    let mut second_keeper = false;
    assert!(
        !claim_flap_keeper(&cfg, ctx, &sh, &mut second_keeper, &mut none).await,
        "a second worker loses the claim and bows out"
    );
    assert!(!second_keeper);
    // An existing keeper re-entering the top of a session is never
    // re-judged - its own claim stands.
    let mut still_keeper = true;
    assert!(claim_flap_keeper(&cfg, ctx, &sh, &mut still_keeper, &mut none).await);
    // A lone server (no live sibling) is never clamped: churn beats
    // zero throughput when there is no alternative.
    sh.alive[1].store(0, Ordering::Release);
    let mut lone = false;
    assert!(claim_flap_keeper(&cfg, ctx, &sh, &mut lone, &mut none).await);
    assert!(!lone, "no clamp means no keeper slot spent");
}

/// §122.5 recycle arm (reactive): back-to-back race losses in the
/// normal phase shed the pipeline and ask for a redial; endgame losses
/// are exempt because the fan-out makes losing routine there.
#[tokio::test]
async fn recycle_slow_sheds_after_consecutive_race_losses() {
    let cfg = PoolConfig {
        recycle_slow: true,
        ..Default::default()
    };
    let servers = vec![(server("s"), cfg.clone())];
    // Enough pending to stay clear of the endgame exemption (> 64).
    let ids: Vec<String> = (0..70).map(|i| format!("<l{i}@x>")).collect();
    let id_refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
    let (sh, _) = Shared::new(fresh(&id_refs), &servers);
    let ctx = ctx_for(&servers, 0);
    let (tx, mut rx) = mpsc::channel(8);
    // A duplicate dispatch won both of the first two articles already.
    assert!(sh.claim_done("<l0@x>", 0));
    assert!(sh.claim_done("<l1@x>", 1));
    let mut inflight: VecDeque<Work> = [
        work("<l0@x>"),
        Work {
            ord: 1,
            ..work("<l1@x>")
        },
        Work {
            ord: 2,
            ..work("<l2@x>")
        },
    ]
    .into_iter()
    .collect();
    for _ in 0..inflight.len() {
        sh.charge_wire();
    }
    let mut losses = 0u32;
    let mut bytes = 0u64;
    let started = Instant::now();
    // First loss: evidence noted, no recycle yet.
    let step = handle_body(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        &mut losses,
        &mut bytes,
        started,
    )
    .await;
    assert!(matches!(step, BodyStep::Proceed));
    assert_eq!(losses, 1);
    // Second consecutive loss: the session has proven slow - shed and
    // redial, counter reset, the innocent in-flight article requeued.
    let step = handle_body(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        &mut losses,
        &mut bytes,
        started,
    )
    .await;
    assert!(matches!(step, BodyStep::Recycle));
    assert_eq!(losses, 0, "a recycle spends the evidence");
    assert!(inflight.is_empty(), "the shed empties the pipeline");
    assert_eq!(
        sh.queue.lock().await.front().map(|w| &*w.id),
        Some("<l2@x>"),
        "the shed article requeues at the front, uncharged"
    );
    assert!(rx.try_recv().is_err(), "a lost race emits no outcome");
    // Endgame: same two losses, but with the queue nearly drained the
    // fan-out makes losing normal - no evidence is charged.
    let (sh2, _) = Shared::new(fresh(&["<e0@x>", "<e1@x>"]), &servers);
    assert!(sh2.claim_done("<e0@x>", 0));
    let mut inflight2: VecDeque<Work> = [work("<e0@x>")].into_iter().collect();
    sh2.charge_wire();
    let mut losses2 = 0u32;
    let step = handle_body(
        &cfg,
        ctx,
        &sh2,
        &tx,
        &mut inflight2,
        PooledBuf::unpooled(Vec::new()),
        &mut losses2,
        &mut bytes,
        started,
    )
    .await;
    assert!(matches!(step, BodyStep::Proceed));
    assert_eq!(losses2, 0, "endgame losses are not evidence");
}

/// §122.5 recycle arm (proactive): a session whose own delivery rate
/// collapsed against the fleet's per-worker average redials before it
/// strands a tail article - checked only on a completed article, and
/// only once the session has had 10 s to prove itself.
#[tokio::test]
async fn recycle_slope_redials_a_collapsed_session() {
    let cfg = PoolConfig {
        recycle_slope: true,
        ..Default::default()
    };
    let servers = vec![(server("s"), cfg.clone())];
    let ids: Vec<String> = (0..70).map(|i| format!("<s{i}@x>")).collect();
    let id_refs: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
    let (sh, _) = Shared::new(fresh(&id_refs), &servers);
    let ctx = ctx_for(&servers, 0);
    // The fleet at large is fast: bytes land against a near-zero run
    // age (clamped to 0.5 s), one live worker shares them.
    sh.bytes[0].store(64_000_000, Ordering::Release);
    let (tx, mut rx) = mpsc::channel(8);
    let mut inflight: VecDeque<Work> = [
        work("<s0@x>"),
        Work {
            ord: 1,
            ..work("<s1@x>")
        },
    ]
    .into_iter()
    .collect();
    for _ in 0..inflight.len() {
        sh.charge_wire();
    }
    let mut losses = 0u32;
    // This session: 11 s old, nothing delivered until now.
    let mut session_bytes = 0u64;
    let started = Instant::now()
        .checked_sub(Duration::from_secs(11))
        .expect("host has been up longer than 11 s");
    let step = handle_body(
        &cfg,
        ctx,
        &sh,
        &tx,
        &mut inflight,
        PooledBuf::unpooled(Vec::new()),
        &mut losses,
        &mut session_bytes,
        started,
    )
    .await;
    // The article itself was WON and delivered - the slope verdict is
    // about the session, never the outcome.
    match rx.try_recv() {
        Ok(FetchOutcome::Done { id, .. }) => assert_eq!(&*id, "<s0@x>"),
        other => panic!("expected the won article delivered, got {other:?}"),
    }
    assert!(matches!(step, BodyStep::Recycle));
    assert!(inflight.is_empty());
    assert_eq!(
        sh.queue.lock().await.front().map(|w| &*w.id),
        Some("<s1@x>"),
        "the shed sibling requeues"
    );
}

/// §122.5 capacity-bounce handling, end to end: a provider that accepts
/// exactly one session greets every extra dial with the 502 capacity
/// refusal. The bounced workers yield and park (issue #16), the one
/// accepted session carries the whole job, and the run still finishes.
#[tokio::test]
async fn capacity_bounce_parks_the_extras_and_the_run_finishes() {
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..64_000u32).map(|i| (i * 5) as u8).collect();
    make_file_articles("cap.bin", &payload, 8_000, "cap", &mut articles);
    let n = articles.len();
    let srv = MockServer::start(
        articles.clone(),
        Chaos {
            accept_cap: Some(1),
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        connections: 4,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(50),
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all(&srv.server_config(), &cfg, reqs, tx),
    )
    .await
    .expect("run hung against a capacity-capped server");
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(done, n, "the one admitted session delivers everything");
    assert!(
        srv.accepted.load(Ordering::Relaxed) >= 2,
        "the fleet actually provoked the cap (extra dials were greeted and bounced)"
    );
}

/// §122.5 promote shed, end to end: a seek promote mid-run engages
/// stream mode, the worker's deep pipeline is over the shallow stream
/// window at the next response boundary, and the whole pipeline is
/// abandoned for a fresh dial - the redial is the observable.
#[tokio::test]
async fn a_promote_mid_pipeline_sheds_to_a_fresh_session() {
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..120_000u32).map(|i| (i * 9) as u8).collect();
    let segs = make_file_articles("st.bin", &payload, 4_000, "st", &mut articles);
    let n = segs.len();
    // Every BODY costs 25 ms server-side, so the run is comfortably
    // still going when the promote lands ~100 ms in.
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 25,
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        connections: 1,
        window: 8,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    // Promote the tail of the file - guaranteed still queued at 100 ms
    // with only the first window's worth in flight.
    let seek: Vec<Arc<str>> = segs[n - 3..]
        .iter()
        .map(|(id, _, _)| Arc::from(format!("<{id}>")))
        .collect();
    let ctl = std::sync::Arc::new(QueueControl::default());
    let promoter = {
        let ctl = ctl.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            ctl.promote(&seek)
        })
    };
    let (tx, mut rx) = mpsc::channel(256);
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi_ctl(&[(srv.server_config(), cfg)], reqs, tx, Some(&ctl)),
    )
    .await
    .expect("run hung after the promote shed");
    assert!(
        promoter.await.expect("promoter task") >= 1,
        "the promote landed while the tail was still queued"
    );
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(
        done, n,
        "every article lands despite the abandoned pipeline"
    );
    assert!(
        srv.accepted.load(Ordering::Relaxed) >= 2,
        "the shed shows up as a redial: the deep pipeline was abandoned, not drained"
    );
}

// The five rigs below moved verbatim from pool.rs's inline `tests`
// mod (6 Aug): the resilience-chip landings regrew pool.rs past its
// size-gate entry, and the gate's rule is that test code moves into
// a child module. Self-contained rigs only - they use the mock and
// `super::*`, none of the inline mod's shared helpers.
/// Issue #16, both halves: a restart's ghost sessions hold the
/// account cap for a while (every dial bounces off the capacity
/// refusal), then the lease expires. The fleet must SURVIVE the
/// window - the old ladder retired every worker in ~5 bounces and
/// failed the job inside it - and it must come back at full width
/// when the window clears, not crawl the rest of the job on the
/// lone prober. Margins are structural: completion inside the
/// bound needs the parked fleet back (one connection cannot move
/// the corpus in time), and the pre-fix behaviour is a hard job
/// failure, not a slow number.
#[tokio::test(flavor = "multi_thread")]
async fn cap_ghost_window_parks_the_fleet_then_rejoins() {
    use crate::mock::{Chaos, MockServer, Throttle};
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("gw.bin", &data, 20_000, "gw", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            cap_ghost_ms: 1_500,
            throttle: Throttle {
                per_conn_bps: 100_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let mut server = srv.server_config();
    server.username = Some("u".into());
    server.password = Some("p".into());
    const CONNS: usize = 6;
    let cfg = PoolConfig {
        connections: CONNS,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(100),
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on the ghost-cap window");
    let wall = t0.elapsed();
    let (mut done, mut other) = (0usize, 0usize);
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            _ => other += 1,
        }
    }
    assert_eq!(
        done,
        ids.len(),
        "articles failed across a 1.5 s ghost window ({other} non-Done outcomes)"
    );
    // 1.2 MB at 100 KB/s per connection: the full fleet clears it
    // in ~2 s after the window, the lone prober would need ~12 s.
    // 10 s = window + full-width finish + generous suite-load
    // slack, still far under the crawl.
    assert!(
        wall < Duration::from_secs(10),
        "fleet did not rejoin after the ghost window cleared ({wall:?})"
    );
}

/// The outage keeper: a transient TOTAL outage (wifi drop, VPN
/// reconnect, router reboot) shows up as hard connect failures -
/// every accepted connection dies before the greeting, nothing to
/// classify. The old ladder retired every worker after
/// `max_connect_attempts` and failed or stranded the whole job
/// inside the window; the keeper parks the fleet behind one paced
/// prober (the issue #16 machinery) and rejoins at full width on
/// the first successful connect. Same margins as the ghost-cap
/// twin above: completion inside the bound needs the parked fleet
/// back, and the pre-fix behaviour is a hard job failure.
#[tokio::test(flavor = "multi_thread")]
async fn hard_outage_window_parks_the_fleet_then_rejoins() {
    use crate::mock::{Chaos, MockServer, Throttle};
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("ow.bin", &data, 20_000, "ow", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            refuse_connect_ms: 1_500,
            throttle: Throttle {
                per_conn_bps: 100_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let server = srv.server_config();
    const CONNS: usize = 6;
    // A tight ladder so the fleet exhausts its connect attempts and
    // parks WELL INSIDE the 1.5 s window - the pre-fix behaviour
    // (every worker retired for good) is what this must rule out.
    let cfg = PoolConfig {
        connections: CONNS,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(50),
        max_connect_attempts: 3,
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on the outage window");
    let wall = t0.elapsed();
    let (mut done, mut other) = (0usize, 0usize);
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            _ => other += 1,
        }
    }
    assert_eq!(
        done,
        ids.len(),
        "articles failed across a 1.5 s hard outage ({other} non-Done outcomes)"
    );
    // 1.2 MB at 100 KB/s per connection: the full fleet clears it
    // in ~2 s after the window, the lone prober would need ~12 s.
    // 10 s = window + full-width finish + generous suite-load
    // slack, still far under the crawl.
    assert!(
        wall < Duration::from_secs(10),
        "fleet did not rejoin after the outage cleared ({wall:?})"
    );
}

/// Codex 7 Aug M1: during a from-the-start outage the prober's paced
/// bounce ladder decodes nothing and resolves nothing, so none of the
/// stall watchdog's three signals moved and its 180 s default aborted
/// jobs squarely inside the ladder's promised ~10 min horizon. Each
/// bounce now ticks the `deferred` liveness counter - prove it climbs
/// DURING the refuse window, before anything resolves.
#[tokio::test(flavor = "multi_thread")]
async fn outage_prober_bounces_tick_watchdog_liveness() {
    use crate::mock::{Chaos, MockServer};
    let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("lv.bin", &data, 20_000, "lv", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            refuse_connect_ms: 2_500,
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        connections: 3,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(50),
        max_connect_attempts: 3,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let qc = std::sync::Arc::new(QueueControl::default());
    let (tx, mut rx) = mpsc::channel(64);
    let run = {
        let qc = qc.clone();
        let server = srv.server_config();
        tokio::spawn(
            async move { fetch_all_multi_ctl(&[(server, cfg)], reqs, tx, Some(&qc)).await },
        )
    };
    // Sample liveness inside the outage window: the fleet parks within
    // a few hundred ms, then only the prober moves. Its bounces must
    // read as life on the counter the watchdog polls.
    let mut ticked = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if qc.deferred().unwrap_or(0) > 0 {
            ticked = true;
            break;
        }
    }
    assert!(
        ticked,
        "prober bounces left the watchdog's liveness counter frozen - \
         a 180 s watchdog would abort inside the recovery ladder"
    );
    tokio::time::timeout(Duration::from_secs(30), run)
        .await
        .expect("run hung on the outage window")
        .expect("pool task panicked");
    let mut done = 0usize;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(
        done,
        segs.len(),
        "the job must still complete after recovery"
    );
}

#[tokio::test]
async fn mute_quit_server_cannot_hang_a_finished_run() {
    // Regression (the 190 GB exit-path hang): a provider that swallows
    // QUIT - TCP up, no goodbye - parked the worker's unbounded goodbye
    // read forever, and the fleet join with it, AFTER every byte was on
    // disk. quit() is now hard-bounded, so the run must return alone.
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    make_file_articles("f.bin", &payload, 8_000, "mq", &mut articles);
    let n = articles.len();
    let srv = MockServer::start(
        articles.clone(),
        Chaos {
            mute_quit: true,
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        connections: 3,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a mute-QUIT server");
    // Well under EXIT_GRACE: the bounded quit alone frees the join.
    assert!(
        t0.elapsed() < Duration::from_secs(4),
        "took {:?}",
        t0.elapsed()
    );
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(done, n);
}

#[tokio::test]
async fn mute_greeting_straggler_does_not_hold_a_finished_run() {
    // §35: a server that accepts and never greets parks its worker
    // inside the dial. This used to cost the run a full EXIT_GRACE -
    // join_fleet's backstop was the ONLY thing that ended it, because
    // the dial itself never watched the run. Measured on the farm at
    // 5.0 s added to a 1.1 s job, on every job, for as long as the
    // unreachable entry stayed in the config. The dial now races the
    // finish, so the straggler leaves with everyone else and the
    // grace window is never entered.
    use crate::mock::{Chaos, MockServer, make_file_articles};
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 7) as u8).collect();
    make_file_articles("g.bin", &payload, 8_000, "mg", &mut articles);
    let n = articles.len();
    let healthy = MockServer::start(articles.clone(), Chaos::default()).await;
    let mute = MockServer::start(
        std::collections::HashMap::new(),
        Chaos {
            mute_greeting: true,
            ..Default::default()
        },
    )
    .await;
    let fast = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let one = PoolConfig {
        connections: 1,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(
            &[(healthy.server_config(), fast), (mute.server_config(), one)],
            reqs,
            tx,
        ),
    )
    .await
    .expect("run hung on a never-greeting server");
    let el = t0.elapsed();
    // Comfortably inside the grace window, not at the end of it: the
    // straggler is released by the finish, not abandoned by the join.
    assert!(
        el < EXIT_GRACE,
        "run waited out the dial of a server nobody needed: {el:?}"
    );
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(done, n);
}

/// §35, reached through the WARM path instead of the dial.
///
/// Claiming a parked connection validates it with a DATE round-trip
/// bounded by `warmpool::VALIDATE_TIMEOUT` - 8 s, against EXIT_GRACE's
/// 5 s. A worker validating a peer that has gone mute therefore could
/// not return before `join_fleet` gave up on it, so the run paid the
/// whole grace window exactly as an unanswered SYN used to make it.
/// Latent while the warm pool ships off by default, which is the
/// reason to pin it now: TODO 36 turns it on per server.
#[tokio::test(flavor = "multi_thread")]
async fn a_mute_parked_connection_does_not_hold_a_finished_run() {
    use crate::mock::{Chaos, MockServer, make_file_articles};
    // Greets, then never another word, every socket held open with no
    // RST or FIN - the shape a CGNAT idle eviction leaves behind, and
    // the one DATE validation exists to catch. Blocking std sockets on
    // their own thread so the peer keeps working regardless of what
    // the async runtime is doing.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::Write as _;
        let mut held = Vec::new();
        while let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"200 mock ready\r\n");
            let _ = s.flush();
            held.push(s);
        }
    });
    let mute = ServerConfig {
        host: addr.ip().to_string(),
        port: addr.port(),
        tls: false,
        username: None,
        password: None,
        connections: 1,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: None,
        block_account: false,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
        address_family: Default::default(),
        tls_hostname: None,
    };

    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 3) as u8).collect();
    make_file_articles("w.bin", &payload, 8_000, "wp", &mut articles);
    let n = articles.len();
    let healthy = MockServer::start(articles.clone(), Chaos::default()).await;

    // Park a live connection to the mute peer, exactly as the previous
    // job in a queue would have left one.
    let warm = crate::warmpool::WarmPool::new(crate::warmpool::DEFAULT_MAX_IDLE, 4);
    let (c, _) = Connection::connect(&mute).await.expect("greeting");
    warm.give(&mute, c).await;
    assert_eq!(
        warm.idle_count().await,
        1,
        "the claim must have something to claim"
    );

    let fast = PoolConfig {
        connections: 2,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let warmed = PoolConfig {
        connections: 1,
        ramp_delay: Duration::ZERO,
        warm: Some(warm.clone()),
        ..Default::default()
    };
    let reqs: Vec<ArticleReq> = articles
        .keys()
        .map(|id| ArticleReq::fresh(id.clone()))
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(healthy.server_config(), fast), (mute, warmed)], reqs, tx),
    )
    .await
    .expect("run hung claiming a parked connection from a mute peer");
    let el = t0.elapsed();
    assert!(
        el < EXIT_GRACE,
        "run waited out the validation of a connection nobody needed: {el:?}"
    );
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(
        done, n,
        "the healthy server still had to deliver every article"
    );
}

// Moved verbatim from pool/rig_tests.rs (6 Aug, size-gate): its own
// baseline had no room for the desync rig. Deterministic, not a
// wall-clock payout leg, so it belongs with the unit rigs anyway.
/// Desync (echoed-id verification): the mock silently withholds every
/// Nth BODY response while consuming the request, so every later
/// response on that connection answers one pipeline slot ahead of
/// what positional attribution assumes. Without the echoed-id check
/// each shifted 222 is filed under the FRONT article - a fully valid
/// body for the wrong id, whose own pcrc32 passes - and the job
/// "completes" corrupt, with the skipped article's real bytes never
/// delivered by anyone. With the check, the first shifted response
/// reads as a session-level protocol error (IdMismatch): the session
/// is dropped and the pipeline requeued (front charged, mates
/// uncharged - the same requeue_or_fail exit every protocol error
/// takes), and the job completes byte-perfect via the refetch. Both
/// read paths are covered: flat (read_timeout) and adaptive.
#[tokio::test(flavor = "multi_thread")]
async fn desync_echoed_id_cuts_the_session_and_completes_byte_perfect() {
    for adaptive in [false, true] {
        let data: Vec<u8> = (0..400_000u32).map(|i| (i >> 2) as u8).collect();
        let mut articles = std::collections::HashMap::new();
        let segs = crate::mock::make_file_articles("d.bin", &data, 8_000, "dsy", &mut articles);
        let parts: std::collections::HashMap<String, u32> = segs
            .iter()
            .map(|(id, _, part)| (format!("<{id}>"), *part))
            .collect();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        let n = ids.len();
        let srv = crate::mock::MockServer::start(
            articles,
            crate::mock::Chaos {
                skip_nth_response: 10,
                ..Default::default()
            },
        )
        .await;
        let cfg = PoolConfig {
            window: 4,
            read_timeout: Duration::from_secs(5),
            adaptive_timeout: adaptive,
            ..Default::default()
        };
        // payout_server(&srv, 2, cfg) inlined: rig_tests' helpers
        // cannot cross into this module.
        let servers = vec![{
            let mut sc = srv.server_config();
            sc.connections = 2;
            (
                sc,
                PoolConfig {
                    connections: 2,
                    ramp_delay: Duration::from_millis(0),
                    ..cfg
                },
            )
        }];
        let (tx, mut rx) = mpsc::channel(64);
        let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
        // Collect and DECODE every owned body: the desync damage is a
        // valid article under the wrong id, so identity (declared part
        // number) and full-payload reassembly are the only honest
        // verdicts - done-counting alone would pass the broken build.
        let want = data.clone();
        let collect = tokio::spawn(async move {
            let mut rebuilt = vec![0u8; want.len()];
            let mut covered = vec![false; want.len()];
            let (mut done, mut wrong_part) = (0usize, 0usize);
            let mut scratch = Vec::new();
            while let Some(o) = rx.recv().await {
                if let FetchOutcome::Done { id, raw } = o {
                    done += 1;
                    let (meta, _) =
                        crate::yenc_simd::decode_into_integrity(&raw, &mut scratch, true)
                            .expect("desync leg delivered an undecodable body");
                    if meta.part != parts.get(&*id).copied() {
                        wrong_part += 1;
                        continue;
                    }
                    let at = (meta.begin - 1) as usize;
                    rebuilt[at..at + scratch.len()].copy_from_slice(&scratch);
                    covered[at..at + scratch.len()]
                        .iter_mut()
                        .for_each(|c| *c = true);
                }
            }
            let holes = covered.iter().filter(|c| !**c).count();
            (done, wrong_part, holes, rebuilt)
        });
        tokio::time::timeout(Duration::from_secs(120), fetch)
            .await
            .expect("desync leg hung")
            .unwrap();
        let (done, wrong_part, holes, rebuilt) = collect.await.unwrap();
        let accepted = srv.accepted.load(Ordering::Relaxed);
        println!(
            "desync leg (adaptive={adaptive}): {done}/{n} done, {wrong_part} wrong-part, \
             {holes} uncovered bytes, {accepted} sessions accepted"
        );
        assert_eq!(done, n, "every article must reach a Done outcome");
        assert_eq!(
            wrong_part, 0,
            "a shifted response was filed under the wrong article"
        );
        assert_eq!(holes, 0, "a skipped article's real bytes never arrived");
        assert_eq!(rebuilt, data, "reassembled payload must be byte-perfect");
        // The whole point: a desynced connection must be CUT, not
        // ridden - 2 workers on a clean run accept exactly 2 sessions,
        // so any reconnect proves the cut happened.
        assert!(
            accepted > 2,
            "no session was ever cut on a desyncing server ({accepted} accepts)"
        );
    }
}

/// §123 chip 6, heal-after: the brownout that ENDS. Every prior
/// brownout rig models a frontend that never returns and hands the
/// job to a healthy twin; this one has no twin - the same server
/// browns out mid-run and recovers 1.5 s later, which is what a
/// frontend restart looks like from outside. The client must cut the
/// dead air (TTFB budget), keep the fleet alive through the mute
/// window, and finish on the recovered server - a heal nobody
/// retries into is indistinguishable from the permanent shape.
#[tokio::test(flavor = "multi_thread")]
async fn brownout_that_heals_resumes_on_the_same_server() {
    use crate::mock::Throttle;
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = make_file_articles("bh.bin", &data, 20_000, "bh", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            brownout_after: 20,
            brownout_heal_ms: 1_500,
            throttle: Throttle {
                per_conn_bps: 100_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let server = srv.server_config();
    let cfg = PoolConfig {
        connections: 6,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(100),
        // Belt for the TTFB braces: even if the adaptive budget never
        // arms (too few samples), a hung read dies in 3 s, well
        // inside the assertion bound.
        read_timeout: Duration::from_secs(3),
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(40),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung across the brownout heal");
    let wall = t0.elapsed();
    let (mut done, mut other) = (0usize, 0usize);
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            _ => other += 1,
        }
    }
    assert_eq!(
        done,
        ids.len(),
        "articles failed across a healed brownout ({other} non-Done outcomes)"
    );
    // Window 1.5 s + one read_timeout of hung reads + ~2 s full-width
    // transfer at 100 KB/s x 6. 20 s = that plus generous suite-load
    // slack; a client that never re-tries the healed server rides
    // read_timeout cycles to the 40 s hang guard instead.
    assert!(
        wall < Duration::from_secs(20),
        "fleet did not resume after the brownout healed ({wall:?})"
    );
}

/// §123 chip 6, vanish-after-serving: a takedown lands mid-job and
/// the whole post leaves the spool - every id refuses from that
/// moment, including ones served seconds earlier. The client's job
/// is an honest, FAST terminal verdict for the remainder (each 430
/// requeues once for a confirming repeat, then declares Missing) -
/// a mid-job vanish must never read as a wedged pool, which is
/// exactly the shape the stall watchdog's third signal (`deferred`)
/// was added for.
#[tokio::test(flavor = "multi_thread")]
async fn mid_job_takedown_declares_the_tail_missing_fast() {
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = make_file_articles("vn.bin", &data, 20_000, "vn", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            vanish_after: 30,
            ..Default::default()
        },
    )
    .await;
    let server = srv.server_config();
    let cfg = PoolConfig {
        connections: 4,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on a mid-job takedown");
    let wall = t0.elapsed();
    let (mut done, mut missing, mut failed) = (0usize, 0usize, 0usize);
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            FetchOutcome::Missing { .. } => missing += 1,
            FetchOutcome::Failed { .. } => failed += 1,
        }
    }
    assert_eq!(
        done + missing + failed,
        ids.len(),
        "every article must reach a terminal outcome"
    );
    assert!(
        done >= 30 / 2,
        "the pre-takedown half should mostly land ({done} done)"
    );
    assert!(
        missing > 0 && failed == 0,
        "the vanished tail is MISSING (a content verdict), not Failed \
         (a transport verdict) - got {missing} missing / {failed} failed"
    );
    // 430s are instant on loopback and the confirming repeat doubles
    // them; anything near the hang guard means the tail wedged.
    assert!(
        wall < Duration::from_secs(10),
        "takedown tail took {wall:?} to reach a verdict"
    );
}

/// §123 chip 6, the auth blip - pinning a DESIGN, not a recovery.
/// One 481 "authentication failed" is indistinguishable from a wrong
/// password, and hammering a provider over a bad credential is worse
/// than failing, so the pool retires the server on the first
/// permanent-shaped refusal and says so (§35). This rig heals the
/// auth at 1.5 s to prove the failure is already terminal by then:
/// FAST and honest, never a hang, and nothing dials the server back
/// in. If auth blips ever earn an episode/prober treatment like
/// capacity refusals did, this test is the one that changes sides.
#[tokio::test(flavor = "multi_thread")]
async fn auth_blip_fails_fast_and_honest_by_design() {
    let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = make_file_articles("ab.bin", &data, 20_000, "ab", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            auth_reject_ms: 1_500,
            ..Default::default()
        },
    )
    .await;
    let mut server = srv.server_config();
    server.username = Some("u".into());
    server.password = Some("p".into());
    let cfg = PoolConfig {
        connections: 4,
        ramp_delay: Duration::ZERO,
        connect_backoff: Duration::from_millis(50),
        ..Default::default()
    };
    let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(256);
    let t0 = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_all_multi(&[(server, cfg)], reqs, tx),
    )
    .await
    .expect("run hung on an auth blip");
    let wall = t0.elapsed();
    let mut done = 0usize;
    let mut terminal = 0usize;
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            _ => terminal += 1,
        }
    }
    assert_eq!(
        done, 0,
        "nothing can download through a refused login ({done} done)"
    );
    assert_eq!(
        terminal,
        ids.len(),
        "every article must still reach a terminal outcome"
    );
    // The refusal lands on the FIRST dial of each worker; everything
    // after is bookkeeping. 5 s is an eternity for it - and well
    // under the 1.5 s heal + any retry ladder, so a client that
    // secretly redials into the healed server would also trip this.
    assert!(
        wall < Duration::from_secs(5),
        "an auth refusal must fail the job fast, not grind ({wall:?})"
    );
}

/// Codex sweep 5, L6: a recorded ceiling must not outlive proof that it
/// is wrong. Session memory deliberately survives a job so the next one
/// does not rediscover a cap - but after a plan upgrade a fleet that
/// holds MORE than the old number has disproven it, and the row was
/// still saying "capped at 38 of 100" while showing "using 100".
#[test]
fn a_live_fleet_larger_than_the_cap_retires_it() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let s = &live.servers[0];
    s.budget.store(100, Ordering::Relaxed);
    s.note_cap(38);
    assert_eq!(s.granted_hi.load(Ordering::Acquire), 38);
    assert_ne!(s.capped_at.load(Ordering::Acquire), 0, "a cap was recorded");

    // Idling below the cap proves nothing and must not clear it.
    s.retire_cap_if_exceeded(12);
    assert_ne!(
        s.capped_at.load(Ordering::Acquire),
        0,
        "an idle provider below its ceiling is not evidence"
    );

    // Actually holding more than the ceiling is evidence.
    s.retire_cap_if_exceeded(64);
    assert_eq!(
        s.capped_at.load(Ordering::Acquire),
        0,
        "the cap is disproven and retired"
    );
    assert_eq!(s.granted_hi.load(Ordering::Acquire), 64);
    assert_eq!(s.capped_since.load(Ordering::Acquire), 0);
}

/// Lock-order pin for `deregister_inflight_done`. The park's `set`
/// holds `files` + `groups` and asks `inflight_of`, which takes the
/// in-flight map; the done path takes the in-flight map and then calls
/// `note_left`, which takes the park's own maps. If the done path
/// holds its guard across `note_left` - which an `if let` on the
/// removal DOES in
/// edition 2024 - the two orders are AB/BA and the pool wedges.
///
/// Staged rather than hammered: the park thread parks first and stalls
/// inside `inflight_of`, the done thread is given time to reach
/// `note_left`, and only then is the park let go. Before the fix the
/// done thread is sitting on the in-flight map at that instant and
/// neither side ever moves; the harness times out here instead.
#[test]
fn a_done_deregistration_never_holds_the_inflight_map_into_the_park() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    let mut w = work("<a@x>");
    w.file = 7;
    sh.register_inflight(&w, 0);
    sh.park
        .set(&[7], Some(EST_BODY_BYTES * 4), |_| vec![w.id.clone()]);

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let parker = {
        let sh = sh.clone();
        std::thread::spawn(move || {
            // A file this park has not seen, so `inflight_of` is asked.
            sh.park.set(&[9], Some(EST_BODY_BYTES * 4), |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                sh.inflight.lock_ok().keys().cloned().collect()
            });
        })
    };
    entered_rx.recv().unwrap();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let doner = {
        let sh = sh.clone();
        std::thread::spawn(move || {
            sh.deregister_inflight_done(&w);
            done_tx.send(()).unwrap();
        })
    };
    // Long enough for the done thread to reach `note_left` and block on
    // the park's `files` map, which the parker is holding.
    std::thread::sleep(Duration::from_millis(100));
    release_tx.send(()).unwrap();

    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the done path deadlocked against a concurrent park");
    parker.join().unwrap();
    doner.join().unwrap();
    assert!(sh.inflight.lock_ok().is_empty(), "the entry was retired");
}

// --- BufPool gauge accounting and the PooledBuf guard -----------------
//
// `BufPool::new_gauged` had no test of any kind before 26 Aug 2026, and
// its charge/release pairing is the whole reason a missed give is worse
// than a lost recycle: a lost recycle costs one allocation, a lost
// release climbs the outstanding gauge for the rest of the run and the
// memory floor reads it as resident bytes nobody can attribute. These
// pin the accounting, and the last one pins what the guard buys.
//
// Every one of these takes `one_gauge_test_at_a_time()` as its FIRST
// statement, so it drops LAST: `memgauge`'s `CUR`/`PEAK` are process-
// global, so under `cargo test` (and the `unit-one-process` job) a
// neighbour moving the same gauge would be read as this test's own
// charge. It is the same lock `memgauge`'s own tests take - one of our
// own would serialize us against nobody.

use crate::memgauge::{Sub, cur, one_gauge_test_at_a_time, reset_for_tests};

#[test]
fn a_gauged_take_charges_outstanding_and_only_a_pooled_buffer_leaves_the_free_list() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new_gauged(4, Sub::RawFree, Sub::RawOut);

    // A fresh buffer was never on the free list, so only outstanding moves.
    let a = pool.take();
    let cap = a.capacity() as u64;
    assert_eq!(cur(Sub::RawOut), cap);
    assert_eq!(cur(Sub::RawFree), 0);

    // Back to the pool: the charge moves from outstanding to the free list.
    drop(a);
    assert_eq!(cur(Sub::RawOut), 0);
    assert_eq!(cur(Sub::RawFree), cap);

    // A POPPED buffer leaves the free list as it becomes outstanding.
    let b = pool.take();
    assert_eq!(cur(Sub::RawOut), cap);
    assert_eq!(cur(Sub::RawFree), 0);
    drop(b);
}

#[test]
fn a_gauged_give_releases_outstanding_before_every_early_return() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    // max_held 1, so the second give has nowhere to park.
    let pool = BufPool::new_gauged(1, Sub::OutFree, Sub::OutOut);

    // Over the keep-cap: `give` returns early WITHOUT parking, and the
    // outstanding release has to have happened before that return.
    let mut big = pool.take();
    big.reserve(5 * 1024 * 1024);
    assert!(big.capacity() > 4 * 1024 * 1024);
    drop(big);
    assert_eq!(
        cur(Sub::OutOut),
        0,
        "the oversized early return must not skip the outstanding release"
    );
    assert_eq!(
        cur(Sub::OutFree),
        0,
        "an oversized buffer is freed, never parked, so the free list is untouched"
    );

    // Past max_held: released from outstanding, not added to the free list.
    let x = pool.take();
    let y = pool.take();
    let xc = x.capacity() as u64;
    drop(x);
    assert_eq!(cur(Sub::OutFree), xc);
    drop(y);
    assert_eq!(
        cur(Sub::OutOut),
        0,
        "a surplus give releases outstanding even though the buffer is dropped"
    );
    assert_eq!(
        cur(Sub::OutFree),
        xc,
        "the surplus buffer was dropped, so the free list did not grow"
    );
}

#[test]
fn a_dying_gauged_pool_hands_back_its_whole_free_list() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new_gauged(4, Sub::RawFree, Sub::RawOut);
    let a = pool.take();
    let b = pool.take();
    let held = a.capacity() as u64 + b.capacity() as u64;
    drop(a);
    drop(b);
    assert_eq!(cur(Sub::RawFree), held);
    drop(pool);
    assert_eq!(
        cur(Sub::RawFree),
        0,
        "a job's pool dies with its free list - without this the gauge \
         carries the dead pool's bytes into the next job forever"
    );
}

#[test]
fn an_ungauged_pool_charges_nothing() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new(2);
    drop(pool.take());
    let snap = crate::memgauge::snapshot();
    for s in [Sub::RawFree, Sub::RawOut, Sub::OutFree, Sub::OutOut] {
        assert_eq!(snap.cur_of(s), 0, "{} moved on an ungauged pool", s.name());
    }
}

#[test]
fn a_guarded_buffer_comes_back_from_an_early_return_and_a_panic() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new_gauged(4, Sub::RawFree, Sub::RawOut);
    let cap = {
        let b = pool.take();
        b.capacity() as u64
    };

    // The shape the bare take/give pair could not defend: a consumer
    // that leaves between the two halves. `?` on a fresh buffer.
    fn early_return(pool: &BufPool) -> Result<(), ()> {
        let _b = pool.take();
        Err(())
    }
    assert!(early_return(&pool).is_err());
    assert_eq!(cur(Sub::RawOut), 0, "an early return returns the buffer");
    assert_eq!(cur(Sub::RawFree), cap);

    // And an unwind, which no amount of remembering can cover.
    let hit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _b = pool.take();
        panic!("consumer blew up mid-article");
    }));
    assert!(hit.is_err());
    assert_eq!(cur(Sub::RawOut), 0, "an unwind returns the buffer");
    assert_eq!(cur(Sub::RawFree), cap);
}

#[test]
fn into_vec_disarms_the_guard_and_adopt_re_arms_it() {
    let _g = one_gauge_test_at_a_time();
    reset_for_tests();
    let pool = BufPool::new_gauged(4, Sub::RawFree, Sub::RawOut);
    let b = pool.take();
    let cap = b.capacity() as u64;

    // Handing the bytes down the outcome channel: the guard stops
    // guarding, and the outstanding charge travels WITH the buffer.
    let raw = b.into_vec();
    assert_eq!(cur(Sub::RawOut), cap, "the charge follows the bytes");
    assert_eq!(cur(Sub::RawFree), 0);

    // The far end re-guards it. `adopt` charges nothing - these bytes
    // were charged by the `take` that minted them - and its drop is the
    // one matching release.
    let readopted = pool.adopt(raw);
    assert_eq!(cur(Sub::RawOut), cap, "adopt must not double-charge");
    drop(readopted);
    assert_eq!(cur(Sub::RawOut), 0);
    assert_eq!(cur(Sub::RawFree), cap);
}
