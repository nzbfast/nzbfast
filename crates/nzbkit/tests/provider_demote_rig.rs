//! §129 3d phase 1: the reproduction the per-job provider-demotion item
//! is gated on. "Evidence before adaptive behavior" - before anything
//! learns to deprioritize a provider mid-job, there has to be a rig that
//! shows the damage, and a recorded baseline of what current main pays.
//!
//! The two target shapes, both against a CLEAN TWIN that holds every
//! article (so "go elsewhere" is always possible):
//!
//! - **freshmiss**: the faulty server answers 430 to most of a post the
//!   NZB declares hours old - a provider that did not take the feed.
//!   Its safety twin, **oldmiss**, is the identical fault on a post over
//!   a year old, where 430s are ordinary retention loss and mean nothing
//!   about the provider (memory nzbfast-retry-propagation-trap).
//! - **corruptstorm**: the faulty server stays connected and answers
//!   with damaged bodies at a fixed rate, job-scale.
//!
//! The decisive question each leg asks is not "how bad is the fault" but
//! **is the faulty server net-negative** - does the job finish SLOWER
//! with it in the fleet than with the clean twin alone? A provider that
//! 430s four articles in five and still pays its way must not be
//! demoted; one that makes the job slower than its own absence is what
//! demotion would be for.
//!
//! Wall-clock legs are `#[ignore]`d (house rule for measurement rigs -
//! they are timing-sensitive under suite load); the structural legs,
//! which is where the phase-1 finding actually comes from, run in CI.
//!
//! **§129 3f** then reused the rig to price the one inefficiency 3d
//! measured: the `soft_430` confirming repeat, which asks a
//! bare-refusing provider TWICE for every article it does not have.
//! Same gate, same answer - the doubling is exact and costs +0.2% wall
//! over 16 samples, so it was not built. Its safety leg
//! (`a_desynced_bare_refusing_server_never_declares_a_present_article_missing`)
//! is the third shape here: a solo server that is both DESYNCED and
//! bare-refusing, where positional attribution can misfile a refusal
//! onto an article the server actually holds.
//!
//! **§129 3g** is the defect that safety leg found on the way, and the
//! rate sweep below is now its regression test. Two things came out of
//! it, in this order, because the first was measured to be not enough:
//! the confirming repeat is WINDOWED rather than a one-time pass for
//! the whole run (a session that shows it was reading responses off by
//! one voids the refusals it handed out), and dispatches to a provider
//! that refuses bare carry an alignment FENCE so the misattribution
//! cannot happen in the first place. Both columns of the sweep assert
//! zero now, at every rate.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use nzbkit::config::ServerConfig;
use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};
use nzbkit::pool::{
    ArticleReq, DecodeAck, DecodeReport, FetchOutcome, LiveStats, PoolConfig, QueueControl,
    fetch_all_multi_ctl,
};
use tokio::sync::mpsc;

/// Payload bytes per article - the mock's own default shape.
const ART: usize = 8_000;
/// Articles in the rig corpus. Job scale for the storm means "enough
/// that a fixed damage rate produces dozens of events", not 300 MB.
const N_ARTICLES: usize = 600;
/// Per-connection ceiling on BOTH servers, bytes/sec. Equal ceilings are
/// the point: the faulty server is not slow, it is wrong, so any wall
/// difference is attributable to the fault and not to bandwidth.
const PER_CONN_BPS: u64 = 500_000;
/// Connections per server.
const CONNS: usize = 4;
/// Per-leg hang cap. A leg that has not finished by here is wedged, not
/// slow: the whole rig runs at 500 KB/s per connection over loopback.
const LEG_CAP: Duration = Duration::from_secs(180);
/// The desync sweep's own cap. Its top rates are DELIBERATELY past what
/// any real provider does, and before §129 3g's fence every desync
/// event cost the connection that met it a whole read budget of dead
/// air, so the wall grew with the fault rate rather than with the
/// corpus (1-in-5, 120 articles: 84 s, and 270 s before the legs were
/// moved onto the shipped adaptive budget). The fence finds the same
/// event at the next response and those legs now run in under a
/// second. The cap stays generous anyway: it exists for the shape that
/// WEDGES - 1-in-3 does, on any of these builds - and a contended box
/// runs the rig several times slower.
const DESYNC_SWEEP_CAP: Duration = Duration::from_secs(300);

/// What one leg cost, per server and overall.
#[derive(Debug, Clone)]
struct Cost {
    label: String,
    wall: Duration,
    /// Articles the collector accepted as final.
    done: usize,
    /// Bodies the consumer OWNED that failed their yEnc CRC (damage
    /// delivered, not steered away).
    owned_bad: usize,
    /// Ids the pool declared terminally Missing, and terminally Failed.
    /// The counts alone are enough for the 430 legs, but the desync
    /// safety leg needs the NAMES: its whole assertion is that this set
    /// is exactly the set of articles the server genuinely does not
    /// have, and a false Missing is only visible as an id that should
    /// not be in it.
    missing_ids: Vec<Arc<str>>,
    failed_ids: Vec<Arc<str>>,
    /// Bodies that decoded cleanly but arrived under the WRONG id - the
    /// yEnc part number in the payload disagrees with the id the pool
    /// filed it against. This is the OTHER half of a desync's damage:
    /// not a lost article but a silently swapped one, which no CRC can
    /// catch because both bodies are individually perfect.
    misfiled: usize,
    servers: Vec<SrvCost>,
}

/// Per-server costs. Everything here is PER SERVER on purpose - the 430
/// family is exactly a per-server question, since an absent article is
/// asked of each server on its own ladder.
///
/// **A refetch, though, is a FLEET-WIDE quantity and counting it here
/// would silently read as zero.** A CRC steer takes the article to the
/// OTHER server, so neither server ever sees the id twice: this file's
/// own corrupt-storm leg dispatches 300 + 400 = 700 for 600 articles -
/// about 100 fleet-wide refetches - while no per-server counter goes
/// above 600. Count `sum(tried)` against the article count, never a
/// single server's `tried`. (Learned from the §129 3c contract suite,
/// whose refetch clause is fleet-wide for this reason; its per-server
/// repeat counts read 0 while the fleet had refetched 12 articles.)
/// If a future phase-2 demotion ever adds a cross-server retry path,
/// the fleet-wide count is the one that would catch an unbounded loop
/// and the per-server one is the one that would miss it.
#[derive(Debug, Clone)]
struct SrvCost {
    host: String,
    /// Dispatches sent to this server (retries and dups each count).
    tried: u64,
    /// 430/423 answers from this server.
    missing: u64,
    /// Raw bytes this server delivered.
    bytes: u64,
    /// BODY requests the server itself logged - the rig-side check on
    /// the client-side `tried` number.
    body_requests: usize,
}

impl Cost {
    fn srv(&self, host_idx: usize) -> &SrvCost {
        &self.servers[host_idx]
    }

    fn line(&self) -> String {
        let per = self
            .servers
            .iter()
            .map(|s| {
                format!(
                    "{}: {} tried / {} missing / {:.2} MB",
                    s.host,
                    s.tried,
                    s.missing,
                    s.bytes as f64 / 1e6
                )
            })
            .collect::<Vec<_>>()
            .join(" · ");
        format!(
            "{:<22} wall {:>6.2}s  done {:>4}  owned-bad {:>3}  [{}]",
            self.label,
            self.wall.as_secs_f64(),
            self.done,
            self.owned_bad,
            per
        )
    }
}

/// A corpus and the requests for it, at a declared age.
fn corpus(age_days: u32) -> (HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    corpus_of(age_days, N_ARTICLES)
}

fn corpus_of(age_days: u32, n: usize) -> (HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    let data: Vec<u8> = (0..(n * ART) as u32).map(|i| (i >> 3) as u8).collect();
    let mut articles = HashMap::new();
    let segs = make_file_articles("rig.bin", &data, ART, "pd", &mut articles);
    let reqs = segs
        .iter()
        .map(|(id, _, part)| ArticleReq {
            id: format!("<{id}>").into(),
            age_days,
            part: *part,
        })
        .collect();
    (articles, reqs)
}

/// Every id in NZB order (the mock map is unordered, the fault set is
/// not - a propagation hole is spread over the post, not clustered).
fn ids_in_order(reqs: &[ArticleReq]) -> Vec<Arc<str>> {
    reqs.iter().map(|r| r.id.clone()).collect()
}

/// `count` ids spread evenly over the whole corpus - the same selection
/// `chaos_serve.rs::stride_positions` makes for the standalone profile,
/// so in-process and standalone numbers describe the same fault.
fn stride(ids: &[Arc<str>], count: usize) -> std::collections::HashSet<String> {
    let n = ids.len();
    if n == 0 || count == 0 {
        return Default::default();
    }
    let count = count.min(n);
    (0..count).map(|k| ids[k * n / count].to_string()).collect()
}

fn healthy() -> Throttle {
    Throttle {
        per_conn_bps: PER_CONN_BPS,
        ..Default::default()
    }
}

fn server_conns(srv: &MockServer, conns: usize, cfg: PoolConfig) -> (ServerConfig, PoolConfig) {
    let mut sc = srv.server_config();
    sc.connections = conns as u32;
    (
        sc,
        PoolConfig {
            connections: conns,
            ramp_delay: Duration::from_millis(0),
            window: 3,
            ..cfg
        },
    )
}

fn server(srv: &MockServer, cfg: PoolConfig) -> (ServerConfig, PoolConfig) {
    server_conns(srv, CONNS, cfg)
}

/// Run one leg to completion and price it. The collector plays the
/// decode consumer, so `crc_steer` legs exercise the real seam: a body
/// that fails its CRC is reported back and may be taken away from us.
async fn leg(
    label: &str,
    servers: Vec<(ServerConfig, PoolConfig)>,
    mocks: &[&MockServer],
    reqs: Vec<ArticleReq>,
) -> Cost {
    leg_capped(label, servers, mocks, reqs, LEG_CAP).await
}

/// [`leg`] with the per-leg hang cap under test. Only the desync sweep
/// needs a different one: see [`DESYNC_SWEEP_CAP`].
async fn leg_capped(
    label: &str,
    servers: Vec<(ServerConfig, PoolConfig)>,
    mocks: &[&MockServer],
    reqs: Vec<ArticleReq>,
    cap: Duration,
) -> Cost {
    let live = LiveStats::for_servers(&servers);
    let hosts: Vec<String> = servers
        .iter()
        .map(|(s, _)| format!("{}:{}", s.host, s.port))
        .collect();
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let ctl = Arc::new(QueueControl::default());
    let (tx, mut rx) = mpsc::channel(64);
    let ctl_fetch = ctl.clone();
    // The part number each id is SUPPOSED to carry, so the collector can
    // tell a body filed under the wrong article from a correct one.
    let expected_part: HashMap<Arc<str>, u32> =
        reqs.iter().map(|r| (r.id.clone(), r.part)).collect();
    let t0 = Instant::now();
    let fetch =
        tokio::spawn(
            async move { fetch_all_multi_ctl(&servers, reqs, tx, Some(&ctl_fetch)).await },
        );
    let collect = tokio::spawn(async move {
        let (mut done, mut owned_bad, mut misfiled) = (0usize, 0usize, 0usize);
        let (mut missing_ids, mut failed_ids) = (Vec::new(), Vec::new());
        let mut scratch = Vec::new();
        while let Some(o) = rx.recv().await {
            // A Missing/Failed article is a terminal outcome too, and is
            // deliberately NOT counted into `done` - a leg that loses
            // data must never be able to read as a fast one.
            match &o {
                FetchOutcome::Missing { id, .. } => missing_ids.push(id.clone()),
                FetchOutcome::Failed { id, .. } => failed_ids.push(id.clone()),
                FetchOutcome::Done { .. } => {}
            }
            if let FetchOutcome::Done { id, raw } = o {
                match nzbkit::yenc_simd::decode_into_integrity(&raw, &mut scratch, true) {
                    Err(_) => {
                        if ctl.note_decoded(
                            &id,
                            DecodeReport::Bad {
                                why: "yEnc decode/CRC failed",
                            },
                        ) == DecodeAck::Steered
                        {
                            continue;
                        }
                        done += 1;
                        owned_bad += 1;
                    }
                    Ok((meta, _)) => {
                        if ctl.note_decoded(&id, DecodeReport::Clean { part: meta.part })
                            == DecodeAck::Steered
                        {
                            continue;
                        }
                        // Owned, so the job would keep it. If the part
                        // in the payload is not the part this id was
                        // requested for, the pool has just filed one
                        // article's bytes under another's name.
                        if let (Some(want), Some(got)) = (expected_part.get(&*id), meta.part)
                            && *want != got
                        {
                            misfiled += 1;
                        }
                        done += 1;
                    }
                }
            }
        }
        (done, owned_bad, misfiled, missing_ids, failed_ids)
    });
    tokio::time::timeout(cap, fetch)
        .await
        .unwrap_or_else(|_| panic!("leg {label} hung"))
        .unwrap();
    let wall = t0.elapsed();
    let (done, owned_bad, misfiled, missing_ids, failed_ids) = collect.await.unwrap();
    let servers = hosts
        .iter()
        .enumerate()
        .map(|(i, host)| SrvCost {
            host: host.clone(),
            tried: live.servers[i].articles_tried.load(Ordering::Relaxed),
            missing: live.servers[i].articles_missing.load(Ordering::Relaxed),
            bytes: live.servers[i].bytes.load(Ordering::Relaxed),
            body_requests: mocks[i].body_log.lock().map(|l| l.len()).unwrap_or(0),
        })
        .collect();
    Cost {
        label: label.to_string(),
        wall,
        done,
        owned_bad,
        missing_ids,
        failed_ids,
        misfiled,
        servers,
    }
}

/// Faulty server + clean twin, one leg. `age_days` is what the NZB
/// declares, `chaos` what the faulty server does.
async fn twin_leg(label: &str, age_days: u32, mk_chaos: impl Fn(&[Arc<str>]) -> Chaos) -> Cost {
    twin_leg_conns(label, age_days, CONNS, mk_chaos).await
}

/// `twin_leg` with the faulty server's connection count under test - the
/// knob that tells a cost paid in REFUSAL RATE from one paid in refusals.
async fn twin_leg_conns(
    label: &str,
    age_days: u32,
    a_conns: usize,
    mk_chaos: impl Fn(&[Arc<str>]) -> Chaos,
) -> Cost {
    twin_leg_sized(label, age_days, a_conns, N_ARTICLES, mk_chaos).await
}

/// The default posture for these legs is `PoolConfig::default()` and
/// that is DELIBERATE, not an oversight: it is the pessimistic arm.
///
/// What the daemon ships is `PoolConfig::shipped()` - "Race slow
/// articles" ON, which is four knobs whose entire job is to take work
/// away from a provider that is holding it up. Measuring "does this
/// faulty server pay its way" with the racer already armed would answer
/// a question about the racer. These legs ask what the fault costs
/// BEFORE anything mitigates it, so a demotion's case is made against
/// the worst number rather than the flattered one.
///
/// The legs that need the shipped posture take it explicitly and say
/// why: the two `adaptive_timeout: true` sites below (dead air is what
/// they price, and a flat 30 s bound prices the rig instead), and
/// `a_crawling_provider_holds_the_tail_hostage_until_the_racer_takes_it_back`,
/// which runs BOTH arms because the gap between them is its finding.
async fn twin_leg_sized(
    label: &str,
    age_days: u32,
    a_conns: usize,
    n: usize,
    mk_chaos: impl Fn(&[Arc<str>]) -> Chaos,
) -> Cost {
    twin_leg_cfg(
        label,
        age_days,
        a_conns,
        n,
        PoolConfig {
            crc_steer: true,
            ..Default::default()
        },
        mk_chaos,
    )
    .await
}

/// `twin_leg_sized` with the pool config under test. The one knob that
/// needs it is `desync_fence`: §146 charges a FENCED bare refusal on
/// arrival, so with the fence armed the confirming repeat no longer
/// scales with the article count - and the only way to still exercise
/// the repeat is to take the fence away.
async fn twin_leg_cfg(
    label: &str,
    age_days: u32,
    a_conns: usize,
    n: usize,
    cfg: PoolConfig,
    mk_chaos: impl Fn(&[Arc<str>]) -> Chaos,
) -> Cost {
    let (arts_a, reqs) = corpus_of(age_days, n);
    let (arts_b, _) = corpus_of(age_days, n);
    let ids = ids_in_order(&reqs);
    let a = MockServer::start(arts_a, mk_chaos(&ids)).await;
    let b = MockServer::start(
        arts_b,
        Chaos {
            throttle: healthy(),
            ..Default::default()
        },
    )
    .await;
    let servers = vec![server_conns(&a, a_conns, cfg.clone()), server(&b, cfg)];
    leg(label, servers, &[&a, &b], reqs).await
}

/// The control: the clean twin ALONE. Every "is the faulty server
/// paying its way" question is asked against this number.
async fn solo_leg(label: &str, age_days: u32) -> Cost {
    solo_leg_of(label, age_days, N_ARTICLES).await
}

async fn solo_leg_of(label: &str, age_days: u32, n: usize) -> Cost {
    let (arts, reqs) = corpus_of(age_days, n);
    let b = MockServer::start(
        arts,
        Chaos {
            throttle: healthy(),
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        crc_steer: true,
        ..Default::default()
    };
    let servers = vec![server(&b, cfg)];
    leg(label, servers, &[&b], reqs).await
}

/// The SAFETY shape for anything that would ever trust a bare 430: ONE
/// server, no twin, that is both bare-refusing AND desynced.
///
/// `Chaos::skip_nth_response` withholds every Nth BODY response while
/// consuming and logging the request, so every later response on that
/// connection answers one pipeline slot EARLY. A present article's read
/// then collects the refusal belonging to the article behind it, and
/// folding that refusal straight into `tried_430` would declare a
/// perfectly good article Missing - with no second server to contradict
/// it, that is silent data loss rather than a slowdown.
///
/// The window in which a desync is INVISIBLE is exactly a run of
/// consecutive BARE refusals: the mock echoes the id on every hit
/// (`222 0 <id>`), and `check_echoed_id` turns the first misaligned hit
/// into `IdMismatch`, a session-level failure. So the fault has to be
/// mostly-missing to be dangerous at all, which is what `missing` sets
/// up here.
///
/// Single server on purpose: `crc_steer` and the twin are what absorb
/// this shape on a two-provider fleet, and the whole question is what
/// happens when neither exists.
///
/// Returns the leg and the ids the server genuinely does not have - the
/// only ids that may legitimately come back Missing.
async fn desync_bare_leg(
    label: &str,
    missing: usize,
    skip_nth: u64,
) -> (Cost, std::collections::HashSet<String>) {
    desync_bare_leg_sized(label, N_ARTICLES, missing, skip_nth).await
}

async fn desync_bare_leg_sized(
    label: &str,
    n: usize,
    missing: usize,
    skip_nth: u64,
) -> (Cost, std::collections::HashSet<String>) {
    desync_leg_sized(label, n, missing, skip_nth, false, LEG_CAP).await
}

/// `desync_bare_leg_sized` with the refusal shape under test. The
/// `echo` arm is the control: an echoing provider's misaligned refusal
/// carries the wrong id, `check_echoed_id` cuts the session on the
/// spot, and no misattribution is possible at all. Any damage that
/// appears only in the bare arm is damage the bare shape is
/// responsible for.
async fn desync_leg_sized(
    label: &str,
    n: usize,
    missing: usize,
    skip_nth: u64,
    echo: bool,
    cap: Duration,
) -> (Cost, std::collections::HashSet<String>) {
    let (arts, reqs) = corpus_of(0, n);
    let ids = ids_in_order(&reqs);
    let absent = stride(&ids, missing);
    let a = MockServer::start(
        arts,
        Chaos {
            missing: absent.clone(),
            echo_missing_id: echo,
            skip_nth_response: skip_nth,
            throttle: healthy(),
            ..Default::default()
        },
    )
    .await;
    // The one leg family that must NOT take `PoolConfig::default()`'s
    // flat read timeout, because before the fence the read budget WAS
    // this fault's discovery path. What ships is the two-phase adaptive
    // budget trained on the server's own TTFB: `get/fleet.rs` resolves
    // it from settings.json's `adaptive_timeouts`, default true (the
    // daemon's own default is true as well), overridable per knob with
    // NZBFAST_ADAPTIVE_TIMEOUT. Testing the fault at a flat 30 s
    // measured the rig's default rather than the product and tripled
    // the wall of every bare leg (1-in-5: 270 s against 78 s).
    //
    // The setting is the user's to turn off, so the fix may not depend
    // on it - and does not: re-run with `adaptive_timeout: false` and
    // the fenced bare arm is still zero at every rate and still under a
    // second, because a fence is checked at the next response instead
    // of waiting for a budget to expire. Only the unfenced ECHOED
    // control pays the flat bound (30 s at 1-in-5), which is the tail
    // stall of a desynced connection and the fault showing, not us.
    let cfg = PoolConfig {
        crc_steer: true,
        adaptive_timeout: true,
        ..Default::default()
    };
    let servers = vec![server(&a, cfg)];
    (leg_capped(label, servers, &[&a], reqs, cap).await, absent)
}

/// The other real fleet shape: the faulty provider is the LEVEL-0
/// primary and the healthy one is a level-1 block/backup account. The
/// fill-server gate (M14e) means the backup may only take an article
/// every live lower-level server has already 430'd, so here the whole
/// job is serialized behind the faulty primary's refusals - the worst
/// case this item could have, and a very ordinary way to be configured.
async fn backup_leg(label: &str, age_days: u32, mk_chaos: impl Fn(&[Arc<str>]) -> Chaos) -> Cost {
    let (arts_a, reqs) = corpus(age_days);
    let (arts_b, _) = corpus(age_days);
    let ids = ids_in_order(&reqs);
    let a = MockServer::start(arts_a, mk_chaos(&ids)).await;
    let b = MockServer::start(
        arts_b,
        Chaos {
            throttle: healthy(),
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        crc_steer: true,
        ..Default::default()
    };
    let primary = server(&a, cfg.clone());
    let mut backup = server(&b, cfg);
    backup.0.level = 1;
    leg(label, vec![primary, backup], &[&a, &b], reqs).await
}

fn miss_chaos(ids: &[Arc<str>], count: usize) -> Chaos {
    Chaos {
        missing: stride(ids, count),
        throttle: healthy(),
        ..Default::default()
    }
}

/// The same fault from a provider that ECHOES the message-id on its
/// refusal line. The pool can then charge the 430 to the article on the
/// spot instead of requeueing it uncharged for a confirming repeat, so
/// this is the cheap half of the shape.
fn miss_chaos_echoing(ids: &[Arc<str>], count: usize) -> Chaos {
    Chaos {
        echo_missing_id: true,
        ..miss_chaos(ids, count)
    }
}

// ---------------------------------------------------------------------
// Structural legs (CI): what current main actually does, in counts that
// do not depend on wall-clock.
// ---------------------------------------------------------------------

/// THE phase-1 finding, first half: the wasted work a provider that
/// 430s 80% of a FRESH post costs is BOUNDED, and the bound is set by
/// whether it echoes the message-id on its refusal line.
///
/// - **echoing** provider: the 430 is authoritative on arrival, the
///   `tried_430` bitmask retires it for that article immediately, and
///   the cost is exactly ONE wasted dispatch per absent article.
/// - **bare** provider (the mock's default, and the harder half): the
///   first refusal per article is positional-only evidence and the
///   article is requeued UNCHARGED for a confirming repeat
///   (`Work::soft_430`), so the cost is up to TWO. It lands under 2x in
///   practice because the twin often wins the requeued article before
///   the faulty server can ask again.
///
/// Either way it cannot compound: every article completes, from the
/// twin, and nothing re-asks a server that has been charged. This is the
/// bound a demotion has to beat, and it is why the phase-1 gate exists -
/// "it keeps asking a bad provider forever" is simply not true.
#[tokio::test(flavor = "multi_thread")]
async fn freshmiss_wasted_dispatches_are_bounded_by_the_refusal_shape() {
    let missing = N_ARTICLES * 4 / 5;
    let bare = twin_leg("freshmiss (bare 430)", 0, |ids| miss_chaos(ids, missing)).await;
    let echo = twin_leg("freshmiss (echoed 430)", 0, |ids| {
        miss_chaos_echoing(ids, missing)
    })
    .await;
    println!("{}\n{}", bare.line(), echo.line());
    for c in [&bare, &echo] {
        assert_eq!(c.done, N_ARTICLES, "{} lost articles", c.label);
        assert_eq!(c.owned_bad, 0, "no damage in this shape");
    }
    // Both arms: the fault has to actually bite, or the rig proves
    // nothing. (It never reaches `missing` exactly - the twin serves
    // some absent-here articles before the faulty server picks them, so
    // it never gets to refuse those at all.)
    for c in [&bare, &echo] {
        assert!(
            (c.srv(0).missing as usize) > missing / 2,
            "{}: only {} refusals for {missing} absent articles - the \
             faulty server barely took part",
            c.label,
            c.srv(0).missing
        );
    }
    // Echoing: charged on arrival, so at most one refusal per absent
    // article and at most one dispatch per article overall.
    assert!(
        echo.srv(0).missing as usize <= missing,
        "an echoed 430 must be charged on arrival: {} refusals for \
         {missing} absent articles",
        echo.srv(0).missing
    );
    assert!(
        echo.srv(0).tried <= N_ARTICLES as u64,
        "echoing: {} dispatches for {N_ARTICLES} articles",
        echo.srv(0).tried
    );
    // Bare: exactly one confirming repeat on top, never a third ask.
    assert!(
        bare.srv(0).missing as usize <= 2 * missing,
        "a bare 430 must cost at most ONE confirming repeat, saw {} for \
         {missing} absent articles",
        bare.srv(0).missing
    );
    assert!(
        bare.srv(0).tried <= 2 * N_ARTICLES as u64,
        "bare: {} dispatches for {N_ARTICLES} articles",
        bare.srv(0).tried
    );
    // The confirming repeat USED to be the whole difference between the
    // two families, and this assertion used to read `bare > echo`. §146
    // changed that on purpose: a bare refusal read off a FENCED socket
    // has had its position proven one response later, which is exactly
    // what the repeat was buying, so it is charged on arrival. The
    // repeat now costs one dispatch for the whole RUN - the first bare
    // refusal, the one that arms the fence - instead of one per absent
    // article. So the two families now cost the same, and the honest
    // pin is that the bare arm is no longer SYSTEMATICALLY dearer.
    //
    // (Stated as a band rather than equality: which server reaches an
    // article first varies per run, so both counts drift by a few
    // either way. What must not come back is the old ~2x.)
    let (b_miss, e_miss) = (bare.srv(0).missing as i64, echo.srv(0).missing as i64);
    assert!(
        (b_miss - e_miss).abs() <= (missing as i64) / 10,
        "the fenced bare arm ({b_miss}) should now cost about what the \
         echoed one does ({e_miss}) for {missing} absent articles - a \
         gap this size means the per-article confirming repeat is back"
    );

    // …and the repeat must still be there when the fence is NOT, which
    // is the half that keeps §129 3g's armor honest: a provider that
    // never answers a fence has it retired by `note_fence_dud`, and a
    // deployment can turn it off outright. Both land here.
    let unfenced = twin_leg_cfg(
        "freshmiss (bare 430, no fence)",
        0,
        CONNS,
        N_ARTICLES,
        PoolConfig {
            crc_steer: true,
            desync_fence: false,
            ..Default::default()
        },
        |ids| miss_chaos(ids, missing),
    )
    .await;
    println!("{}", unfenced.line());
    assert_eq!(unfenced.done, N_ARTICLES, "unfenced arm lost articles");
    assert!(
        unfenced.srv(0).missing > echo.srv(0).missing,
        "with no fence to prove position, a bare 430 must still buy its \
         confirming repeat: {} refusals against the echoed arm's {}",
        unfenced.srv(0).missing,
        echo.srv(0).missing
    );
    assert!(
        unfenced.srv(0).missing as usize <= 2 * missing,
        "still at most ONE confirming repeat, saw {} for {missing} \
         absent articles",
        unfenced.srv(0).missing
    );
}

/// **The safety gate for §129 3f, and the CI half of §129 3g**: a server
/// that is BOTH desynced AND bare-refusing must never produce a false
/// Missing.
///
/// Positional attribution is what makes a bare refusal ambiguous. With
/// a response withheld, a present article's read collects the refusal
/// meant for the article behind it; charging that to `tried_430` on a
/// single-server run declares a good article gone, and nothing
/// downstream can tell that verdict from a real one. `soft_430`'s
/// confirming repeat is the thing standing between this fault and that
/// outcome, so this leg is the one any learned-trust rule has to keep
/// green - measured BEFORE the rule exists, so the number is not a
/// post-hoc justification.
///
/// Deliberately single-server: on a fleet the twin answers whatever
/// this server wrongly refuses, so the shape is invisible. Alone, it is
/// data loss.
#[tokio::test(flavor = "multi_thread")]
async fn a_desynced_bare_refusing_server_never_declares_a_present_article_missing() {
    // Mostly-missing, because a desync only hides inside a RUN of bare
    // refusals - the first misaligned hit echoes its id and
    // `check_echoed_id` kills the session. 80% absent leaves runs long
    // enough to misattribute, and 120 present articles to lose.
    //
    // 1-in-60 is the shipped `desync` chaos profile's own default rate.
    // The rate used to matter enormously here: it set both the wall (a
    // desynced session was only found when its read budget expired -
    // this leg cost 30 s) and, past roughly 1-in-10, the CORRECTNESS,
    // because the confirming repeat was a one-time pass per (article,
    // group) and two desync events on one article walked through it
    // (§129 3g). Both are fixed - the fence finds the slip at the next
    // response, and this leg now runs in under a second - and the whole
    // dose-response curve up to 1-in-5 is asserted in
    // `desync_rate_sweep_bare_vs_echoed`. This is the cheap one that
    // guards it on every push.
    let (c, absent) = desync_bare_leg("desync+bare (solo)", N_ARTICLES * 4 / 5, 60).await;
    println!("{}", c.line());
    println!(
        "  absent {} · reported missing {} · failed {} · misfiled {} · \
         server logged {} BODY requests for {N_ARTICLES} articles",
        absent.len(),
        c.missing_ids.len(),
        c.failed_ids.len(),
        c.misfiled,
        c.srv(0).body_requests
    );

    // The rig has to be measuring something: a desync forces the
    // session to die and its work to be redone, so the server must see
    // strictly more BODY requests than there are articles.
    assert!(
        c.srv(0).body_requests > N_ARTICLES,
        "the server logged only {} BODY requests for {N_ARTICLES} \
         articles - the desync never bit and this leg proves nothing",
        c.srv(0).body_requests
    );

    // THE assertion. Every id the pool gave up on must be one the
    // server genuinely does not have.
    let falsely_missing: Vec<&Arc<str>> = c
        .missing_ids
        .iter()
        .filter(|id| !absent.contains(&***id))
        .collect();
    assert!(
        falsely_missing.is_empty(),
        "{} present article(s) were declared Missing by a desynced \
         bare-refusing server - that is silent data loss, e.g. {:?}",
        falsely_missing.len(),
        &falsely_missing[..falsely_missing.len().min(5)]
    );

    // The other half of a desync's damage: a body that decodes
    // perfectly but belongs to a different article. Both copies pass
    // their own CRC, so identity is the only check that can catch it.
    assert_eq!(
        c.misfiled, 0,
        "the consumer owned {} body/bodies filed under the wrong id",
        c.misfiled
    );

    // And the run must still finish the job it can finish: every
    // present article delivered, every absent one accounted for.
    assert_eq!(
        c.done,
        N_ARTICLES - absent.len(),
        "{} present articles, {} delivered ({} failed)",
        N_ARTICLES - absent.len(),
        c.done,
        c.failed_ids.len()
    );
}

/// **The dose-response curve §129 3g was found on, now its regression
/// test.** The safety leg above runs at one rate; this one walks the
/// withheld-response rate up until the fault is absurd, in both refusal
/// shapes, and demands that no present article is ever declared Missing
/// at any of them.
///
/// What it measured before 3g was fixed (8 Aug 2026, 120 articles, 80%
/// genuinely absent, solo server) - `soft_430`'s confirming repeat was
/// a ONE-TIME pass per (article, server group) for the whole run rather
/// than a windowed confirmation, so an article that caught a
/// misattributed bare refusal TWICE, from two unrelated desync events,
/// was declared Missing while the server held it:
///
/// | withheld | false Missing, BARE | false Missing, ECHOED |
/// |---|---|---|
/// | 1-in-30, 1-in-15 | 0 | 0 |
/// | 1-in-10 | 0, 2 | 0 |
/// | 1-in-7 | 1, 1, 1, 1 | 0 |
/// | 1-in-5 | 1, 3, 2, 5 | 0 |
/// | 1-in-4 | 4 | - |
///
/// The ECHO arm was the control and stayed at zero throughout: a
/// misaligned refusal that carries an id fails `check_echoed_id` and
/// cuts the session before it can be misfiled, so the entire risk
/// surface was the bare shape - and closing it came down to giving a
/// bare-refusing provider the same checkable response stream, which is
/// what the fence does. Both columns are zero now, and this leg asserts
/// it rather than printing it - which is only honest because the same
/// run also proves the pool still RESOLVES: `done` and `missing` are
/// checked against the corpus, so a pool that bought a clean
/// false-Missing column by never giving up on anything fails here too.
///
/// Wall and dispatch counts are printed and deliberately not bounded.
/// They tell the two halves of the fix apart: re-arming alone left the
/// wall in tens of seconds per rate (a desynced session is only found
/// when its read budget expires) and still leaked, while the fence
/// finds it at the very next response - which is why the walls here are
/// now fractions of a second, and why the request counts climb instead.
/// A fenced session dies the moment the stream slips, so its whole
/// pipeline is re-dispatched: at 1-in-5 that is 4,400 requests for 120
/// articles, done in under a second and losing nothing. Dispatches are
/// the currency this rig has always found to be cheap (3f: a refusal
/// costs a round trip the job was going to spend anyway); a lost
/// article is not.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "diagnostic sweep - run with --ignored"]
async fn desync_rate_sweep_bare_vs_echoed() {
    const N: usize = 120;
    for echo in [false, true] {
        println!(
            "\n  {} refusals, {N} articles, 80% absent, solo server:",
            if echo { "ECHOED" } else { "BARE" }
        );
        for skip in [30u64, 15, 10, 7, 5] {
            let (c, absent) = desync_leg_sized(
                &format!("desync 1-in-{skip}"),
                N,
                N * 4 / 5,
                skip,
                echo,
                DESYNC_SWEEP_CAP,
            )
            .await;
            let false_missing = c
                .missing_ids
                .iter()
                .filter(|id| !absent.contains(&***id))
                .count();
            println!(
                "  1-in-{skip:<4} wall {:>6.2}s  done {:>3}/{:<3} missing {:>3} \
                 (FALSE {false_missing}) failed {:>3} misfiled {} · {} BODY reqs",
                c.wall.as_secs_f64(),
                c.done,
                N - absent.len(),
                c.missing_ids.len(),
                c.failed_ids.len(),
                c.misfiled,
                c.srv(0).body_requests
            );
            // §129 3g. A present article declared Missing is silent data
            // loss on a single-server run: nothing downstream can tell
            // that verdict from a real one.
            assert_eq!(
                false_missing,
                0,
                "1-in-{skip} {}: {false_missing} present article(s) \
                 declared Missing by a server that HOLDS them",
                if echo { "echoed" } else { "bare" }
            );
            // The other half of a desync's damage - a body that decodes
            // perfectly under the wrong article's name. Closed by the
            // echoed-id check on hits plus the part-identity gate, and
            // it has to stay closed.
            assert_eq!(c.misfiled, 0, "1-in-{skip}: body filed under the wrong id");
            // ... and the run still has to finish the job it can finish,
            // or the two assertions above are trivially satisfiable by a
            // pool that resolves nothing.
            assert_eq!(
                c.done,
                N - absent.len(),
                "1-in-{skip}: {} present articles, {} delivered",
                N - absent.len(),
                c.done
            );
            // Every absent article is accounted for - but not always as
            // Missing. At these rates an article can spend its whole
            // transport retry budget on sessions that stall out from
            // under it and resolve Failed instead, which is honest
            // ("no answer") rather than the false claim about the
            // server that Missing would be. Both are non-delivery of an
            // article that genuinely is not there; what may never
            // happen is a PRESENT article in either set, which is what
            // the `done` and false-Missing assertions above pin.
            assert_eq!(
                c.missing_ids.len() + c.failed_ids.len(),
                absent.len(),
                "1-in-{skip}: {} absent articles, {} Missing + {} Failed",
                absent.len(),
                c.missing_ids.len(),
                c.failed_ids.len()
            );
            let false_failed = c
                .failed_ids
                .iter()
                .filter(|id| !absent.contains(&***id))
                .count();
            assert_eq!(
                false_failed, 0,
                "1-in-{skip}: {false_failed} present article(s) given up on as Failed"
            );
        }
    }
}

/// **The payout side of §129 3f**: what the confirming repeat actually
/// COSTS in wall, as opposed to in dispatch counts.
///
/// The saving on offer is real in counts - a bare-refusing provider is
/// asked twice per absent article, an echoing one once. This leg asks
/// whether that shows up in the only currency that matters. Same fault,
/// same corpus, the ONLY difference being whether the refusal line
/// echoes the id, across sizes so a fixed cost can be told from a rate.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock measurement - run with --ignored"]
async fn what_the_soft_430_confirming_repeat_costs_in_wall() {
    println!(
        "\n§129 3f: the soft_430 confirming repeat priced in WALL. \
         Same fault, only the refusal SHAPE differs.\n"
    );
    for n in [600usize, 1800, 5400] {
        for &(what, frac) in &[("80% absent", 4.0 / 5.0), ("100% absent", 1.0)] {
            let missing = (n as f64 * frac) as usize;
            // Samples are interleaved bare/echoed rather than run in
            // blocks, so a machine that gets busy halfway through
            // cannot masquerade as a result. Four at the small size,
            // where the first round showed the only apparent gap.
            let samples = if n == 600 { 4 } else { 2 };
            for sample in 1..=samples {
                let bare = twin_leg_sized(&format!("{n} {what} bare"), 0, CONNS, n, |ids| {
                    miss_chaos(ids, missing)
                })
                .await;
                let echo = twin_leg_sized(&format!("{n} {what} echoed"), 0, CONNS, n, |ids| {
                    miss_chaos_echoing(ids, missing)
                })
                .await;
                assert_eq!(bare.done, n, "bare arm lost articles");
                assert_eq!(echo.done, n, "echoed arm lost articles");
                let (b, e) = (bare.wall.as_secs_f64(), echo.wall.as_secs_f64());
                println!(
                    "  {n:>5} art {what:<12} #{sample}  bare {b:>6.2}s / \
                     {:>5} refusals   echoed {e:>6.2}s / {:>5} refusals   \
                     bare is {:+.1}% wall for {:.2}x the refusals",
                    bare.srv(0).missing,
                    echo.srv(0).missing,
                    (b / e - 1.0) * 100.0,
                    bare.srv(0).missing as f64 / echo.srv(0).missing.max(1) as f64,
                );
            }
        }
    }
}

/// THE phase-1 finding, second half - and the trap the whole item is
/// built around. The SAME fault on a year-old post produces the SAME
/// numbers: current main has no age-sensitive reaction at all, which is
/// why it cannot get the old-post case wrong, and why any phase-2
/// behavior has to earn its safety here rather than inherit it.
#[tokio::test(flavor = "multi_thread")]
async fn oldmiss_is_indistinguishable_from_freshmiss_to_current_main() {
    let missing = N_ARTICLES * 4 / 5;
    let fresh = twin_leg("freshmiss", 0, |ids| miss_chaos_echoing(ids, missing)).await;
    let old = twin_leg("oldmiss", 400, |ids| miss_chaos_echoing(ids, missing)).await;
    println!("{}\n{}", fresh.line(), old.line());
    assert_eq!(old.done, N_ARTICLES);
    assert_eq!(fresh.done, N_ARTICLES);
    // Today the pool routes on `tried_430` alone and never reads the
    // age, so the two arms come out on top of each other. That is the
    // recorded baseline AND the safety assertion: a phase-2 change that
    // starts treating them differently must move the fresh arm and
    // leave this one where it is.
    let (o, f) = (old.srv(0), fresh.srv(0));
    assert!(
        o.bytes > 0,
        "the old-post arm's provider served nothing - it has been \
         demoted for 430s that are ordinary retention loss"
    );
    let ratio = o.bytes as f64 / f.bytes.max(1) as f64;
    assert!(
        (0.6..=1.7).contains(&ratio),
        "old-post arm served {:.2} MB against the fresh arm's {:.2} MB \
         ({ratio:.2}x) - current main has no age input, so these must \
         track each other",
        o.bytes as f64 / 1e6,
        f.bytes as f64 / 1e6
    );
    assert!(o.tried <= N_ARTICLES as u64);
}

/// A provider that took NONE of the feed - the strongest form of the
/// shape, since it can contribute nothing and everything it costs is
/// pure waste. It still terminates: once every article carries its bit
/// the queue holds nothing it may take, so it goes quiet rather than
/// spinning. The bound is the refusal shape's (1x echoed, 2x bare), and
/// it serves zero bytes either way.
#[tokio::test(flavor = "multi_thread")]
async fn a_provider_with_none_of_the_post_asks_a_bounded_number_of_times() {
    let c = twin_leg("freshmiss-100%", 0, |ids| {
        miss_chaos_echoing(ids, ids.len())
    })
    .await;
    println!("{}", c.line());
    assert_eq!(c.done, N_ARTICLES, "the twin must carry the whole job");
    let a = c.srv(0);
    assert!(
        (a.missing as usize) > N_ARTICLES / 2,
        "the faulty server refused only {} of {N_ARTICLES} - it barely \
         took part",
        a.missing
    );
    assert!(
        a.missing as usize <= N_ARTICLES,
        "an echoed 430 must be charged on arrival: {} refusals",
        a.missing
    );
    assert_eq!(a.bytes, 0, "it served nothing");
    assert!(
        a.tried <= N_ARTICLES as u64,
        "asked {} times for {N_ARTICLES} articles it has none of",
        a.tried
    );
    // The mock's own log is the independent witness: the client-side
    // counter and the server-side one must agree about how much work
    // was thrown away.
    assert!(
        a.body_requests <= N_ARTICLES,
        "server logged {} BODY requests for {N_ARTICLES} articles",
        a.body_requests
    );
}

/// The corrupt storm at job scale, through the shipped CRC retry-
/// elsewhere seam. Unlike a 430, a damaged body is NOT remembered
/// per-article-per-server by a bitmask - the machinery that saves the
/// job is `crc_steer`, which refetches from a peer. The cost is
/// therefore paid in BYTES, not in one cheap refusal, and it is the
/// arm where a demotion has something real to save.
#[tokio::test(flavor = "multi_thread")]
async fn corrupt_storm_is_paid_for_in_wasted_bytes_not_cheap_refusals() {
    let c = twin_leg("corruptstorm", 0, |_| Chaos {
        corrupt_every: 3,
        throttle: healthy(),
        ..Default::default()
    })
    .await;
    println!("{}", c.line());
    assert_eq!(c.done, N_ARTICLES, "every article must complete");
    assert_eq!(
        c.owned_bad, 0,
        "the consumer must never own a corrupt body when a twin holds a \
         clean copy"
    );
    let a = c.srv(0);
    assert!(
        a.bytes > 0,
        "the storm never bit - the faulty server served nothing"
    );
    // Every third body it serves is thrown away, and each throw-away is
    // a full article's bytes twice over (its copy, then the twin's).
    // Nothing bounds how many it serves, so unlike the 430 shape the
    // damage scales with how MUCH of the job it wins.
    assert_eq!(a.missing, 0, "no 430s in this shape");
    // What DOES bound it: `Shared::crc_retried` steers each id at most
    // once, so however much damage arrives, the fleet can never dispatch
    // more than one refetch per article. This is the assertion behind
    // "crc_steer already bounds the damage" - without it the leg would
    // only be showing that the damage was caught, not that catching it
    // terminates. Counted FLEET-WIDE (see `SrvCost`): a steer asks the
    // OTHER server, so neither per-server counter ever sees an id twice
    // and a per-server bound here would pass while looping.
    let fleet: u64 = c.servers.iter().map(|s| s.tried).sum();
    let refetches = fleet.saturating_sub(N_ARTICLES as u64);
    println!("  corrupt storm: {refetches} fleet-wide refetches of {N_ARTICLES}");
    assert!(
        refetches > 0,
        "no refetch happened at all - the storm or the steer is not \
         wired up ({fleet} dispatches for {N_ARTICLES} articles)"
    );
    assert!(
        refetches <= N_ARTICLES as u64,
        "{refetches} refetches for {N_ARTICLES} articles - the steer is \
         firing more than once per id, which is a loop"
    );
}

// ---------------------------------------------------------------------
// Measurement leg (wall-clock; #[ignore] like the other payout rigs).
// ---------------------------------------------------------------------

/// The baseline table for the TODO note: is the faulty provider
/// net-negative? Each fault arm is priced against the clean twin ALONE,
/// which is exactly what demoting the faulty server to zero would give
/// us. If the fault arm is not slower than the solo arm, demotion has
/// nothing to win and the item closes.
///
/// Run: `cargo test -p nzbkit --test provider_demote_rig -- --ignored
/// --nocapture --test-threads=1`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock baseline measurement - run with --ignored"]
async fn baseline_cost_of_a_badly_answering_provider() {
    let missing = N_ARTICLES * 4 / 5;
    let mut table = Vec::new();
    table.push(solo_leg("twin alone (control)", 0).await);
    table.push(
        twin_leg("both clean", 0, |_| Chaos {
            throttle: healthy(),
            ..Default::default()
        })
        .await,
    );
    table.push(twin_leg("freshmiss 80% bare", 0, |ids| miss_chaos(ids, missing)).await);
    table.push(
        twin_leg("freshmiss 80% echoed", 0, |ids| {
            miss_chaos_echoing(ids, missing)
        })
        .await,
    );
    table.push(
        twin_leg("oldmiss 80% echoed", 400, |ids| {
            miss_chaos_echoing(ids, missing)
        })
        .await,
    );
    table.push(twin_leg("freshmiss 100% bare", 0, |ids| miss_chaos(ids, ids.len())).await);
    table.push(
        twin_leg("freshmiss 100% echoed", 0, |ids| {
            miss_chaos_echoing(ids, ids.len())
        })
        .await,
    );
    table.push(
        twin_leg("corruptstorm 1-in-3", 0, |_| Chaos {
            corrupt_every: 3,
            throttle: healthy(),
            ..Default::default()
        })
        .await,
    );
    // The fill-gate shape: faulty PRIMARY, clean backup behind it.
    table.push(
        backup_leg("primary 100% miss", 0, |ids| {
            miss_chaos_echoing(ids, ids.len())
        })
        .await,
    );
    table.push(
        backup_leg("primary 100% miss bare", 0, |ids| {
            miss_chaos(ids, ids.len())
        })
        .await,
    );

    println!(
        "\n§129 3d phase 1 baseline (current main), {N_ARTICLES} articles \
              x {ART} B, {CONNS} conns/server at {PER_CONN_BPS} B/s:"
    );
    for c in &table {
        println!("  {}", c.line());
    }
    let solo = table[0].wall.as_secs_f64();
    println!(
        "\n  vs the clean twin alone ({solo:.2}s) - over 1.00 means the \
              faulty server made the job SLOWER than its own absence:"
    );
    for c in table.iter().skip(1) {
        println!(
            "    {:<22} {:.2}x",
            c.label,
            c.wall.as_secs_f64() / solo.max(0.001)
        );
    }
    for c in &table {
        assert_eq!(c.done, N_ARTICLES, "{} lost articles", c.label);
    }
}

/// §109's hunt: the shapes 3d's own reopener clause names. 3d closed on
/// "every shape raced here is bounded by `tried_430` or by `crc_steer`'s
/// once-per-id steer - if one turns up that is NOT remembered per
/// (article, server) AND is net-negative, the rig is the place to add
/// it". These are those candidates, and they are deliberately the ones
/// the 430 family cannot cover, because a 430 is REMEMBERED and each of
/// these is not:
///
/// - **corrupt 100% / 1-in-2**: 3d priced the storm at 1-in-3 only, and
///   found it strongly net-POSITIVE. That is a rate, not a verdict: a
///   cache node serving nothing but damage spends real bandwidth and
///   real decode to deliver zero good bytes, and the steer's memory is
///   per (article, server), so the SECOND article is asked of it just
///   as innocently as the first. If the shape ever goes negative it
///   goes negative here.
/// - **bodyerror forever**: connects, authenticates, and answers every
///   BODY with a non-body status. The session dies on the protocol
///   error and the article is requeued with nothing charged to anyone -
///   the purest "connected but useless" provider there is.
/// - **cgnat mute**: every connection goes permanently silent after a
///   few bodies. The client learns nothing until its read bound fires,
///   so the cost is paid in dead air rather than in refusals - and dead
///   air is the one currency the 430 legs could not measure.
/// - **crawl**: a provider that is not wrong at all, just 25x slower
///   than its twin for the whole run. Nothing here is a fault the pool
///   can remember, because nothing it says is untrue.
/// - **flap** (`drop_after`) is the control, not a candidate: it is the
///   shape the existing breaker owns, and its row is here so the table
///   shows containment beside the shapes that have none.
///
/// Run: `cargo test -p nzbkit --release --test provider_demote_rig --
/// --ignored --nocapture --test-threads=1`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock measurement - run with --ignored"]
async fn hunting_a_net_negative_provider() {
    // The shipped shape of the knobs these legs run into: adaptive
    // timeouts decide what dead air COSTS, and the whole cgnat leg is a
    // dead-air measurement. Racing it against the flat 30 s default
    // would price a timeout nobody ships.
    let cfg = || PoolConfig {
        crc_steer: true,
        adaptive_timeout: true,
        ..Default::default()
    };
    let hunt = |label: &'static str, mk: fn() -> Chaos| async move {
        twin_leg_cfg(label, 0, CONNS, N_ARTICLES, cfg(), move |_| mk()).await
    };

    let mut table = vec![solo_leg("twin alone (control)", 0).await];
    table.push(
        hunt("corrupt 100%", || Chaos {
            corrupt_every: 1,
            throttle: healthy(),
            ..Default::default()
        })
        .await,
    );
    table.push(
        hunt("corrupt 1-in-2", || Chaos {
            corrupt_every: 2,
            throttle: healthy(),
            ..Default::default()
        })
        .await,
    );
    table.push(
        hunt("bodyerror forever", || Chaos {
            body_error: Some(u64::MAX),
            throttle: healthy(),
            ..Default::default()
        })
        .await,
    );
    table.push(
        hunt("cgnat mute every 3", || Chaos {
            mute_after_bodies: 3,
            throttle: healthy(),
            ..Default::default()
        })
        .await,
    );
    table.push(
        hunt("crawl (1/25 rate)", || Chaos {
            throttle: Throttle {
                per_conn_bps: PER_CONN_BPS / 25,
                ..Default::default()
            },
            ..Default::default()
        })
        .await,
    );
    table.push(
        hunt("flap: drop every 2 (control)", || Chaos {
            drop_after: 2,
            throttle: healthy(),
            ..Default::default()
        })
        .await,
    );

    println!(
        "\n§109 hunt for a net-negative provider, {N_ARTICLES} articles \
              x {ART} B, {CONNS} conns/server, twin at {PER_CONN_BPS} B/s:"
    );
    for c in &table {
        println!("  {}", c.line());
    }
    let solo = table[0].wall.as_secs_f64();
    println!(
        "\n  vs the clean twin alone ({solo:.2}s) - over 1.00 means the \
              faulty server made the job SLOWER than its own absence:"
    );
    for c in table.iter().skip(1) {
        println!(
            "    {:<28} {:.2}x   {} dispatches, {:.2} MB served, {} owned-bad",
            c.label,
            c.wall.as_secs_f64() / solo.max(0.001),
            c.srv(0).tried,
            c.srv(0).bytes as f64 / 1e6,
            c.owned_bad
        );
    }
    for c in &table {
        assert_eq!(c.done, N_ARTICLES, "{} lost articles", c.label);
    }
}

/// The one mechanism left by which a connected-but-degraded provider
/// can be net-negative, and the reason the hunt table above cannot show
/// it: HOSTAGE ARTICLES AT THE TAIL.
///
/// Mid-run a slow provider is self-limiting - one shared FIFO, workers
/// self-clock, so it simply claims less (the crawl row takes 36
/// dispatches where the twin takes 576, without anything deciding that
/// it should). At the FINISH that reverses: the last articles are
/// claimed, and one of them sitting behind a crawling session gates the
/// whole job no matter how idle the rest of the fleet is. The hunt
/// table's articles are 8 kB, so even a 25x crawl hands one back in
/// 0.4 s and the effect hides inside the noise. Here the crawl is made
/// catastrophic (1/200) so a hostage article costs seconds, which is
/// what a 740 kB article behind a genuinely sick session costs on a real
/// line.
///
/// The arms are the shipped setting, not a hypothesis: "Race slow
/// articles" (`race_stragglers`, ON by default) resolves to
/// `tail_fanout` + `tail_fanout_early` + `hedge` + `recycle_slope` in
/// `get/fleet.rs` - which is what `PoolConfig::shipped()` returns, and
/// what `PoolConfig::default()` has all four OFF of, so every other leg
/// in this file is deliberately measuring the pessimistic pool (see
/// `twin_leg_sized`). If the OFF arm is net-negative and the ON arm is
/// not, then the hostage cost is real AND already paid for, and a
/// demotion would be buying a second time what one setting already
/// bought.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock measurement - run with --ignored"]
async fn a_crawling_provider_holds_the_tail_hostage_until_the_racer_takes_it_back() {
    /// Slow enough that one hostage article is seconds, not milliseconds.
    const CRAWL_DIVISOR: u64 = 200;
    let crawl = || Chaos {
        throttle: Throttle {
            per_conn_bps: PER_CONN_BPS / CRAWL_DIVISOR,
            ..Default::default()
        },
        ..Default::default()
    };
    let arm = |label: &'static str, race: bool, n: usize| async move {
        // The ON arm is the shipped posture in one token; the OFF arm is
        // the same fleet with the setting unticked. `adaptive_timeout`
        // is forced on in BOTH so the only moving part is the racer.
        let base = if race {
            PoolConfig::shipped()
        } else {
            PoolConfig::default()
        };
        twin_leg_cfg(
            label,
            0,
            CONNS,
            n,
            PoolConfig {
                crc_steer: true,
                adaptive_timeout: true,
                ..base
            },
            move |_| crawl(),
        )
        .await
    };

    let solo = solo_leg("twin alone (control)", 0).await;
    let off = arm("crawl 1/200, racer OFF", false, N_ARTICLES).await;
    let on = arm("crawl 1/200, racer ON (ships)", true, N_ARTICLES).await;

    println!(
        "\n§109 hostage tail: a provider {CRAWL_DIVISOR}x slower than its \
         twin, {N_ARTICLES} articles x {ART} B:"
    );
    for c in [&solo, &off, &on] {
        println!("  {}", c.line());
    }
    let base = solo.wall.as_secs_f64().max(0.001);
    for c in [&off, &on] {
        println!(
            "    {:<30} {:.2}x the twin-alone control",
            c.label,
            c.wall.as_secs_f64() / base
        );
    }

    // Is the hostage cost a CONSTANT or a RATE? The crawler above took
    // 12 dispatches - exactly one pipeline fill (conns x window) - and
    // delivered none of them, which predicts a fixed cost that a longer
    // job amortizes away. A demotion is worth building for a rate and
    // not for a constant, so the answer is the whole decision.
    println!("\n  the same fault over a growing corpus (racer ON, as shipped):");
    for n in [N_ARTICLES, N_ARTICLES * 3] {
        let base = solo_leg_of("solo", 0, n).await;
        let with = arm("crawl", true, n).await;
        let (b, w) = (base.wall.as_secs_f64(), with.wall.as_secs_f64());
        println!(
            "    {n:>5} articles: solo {b:>6.2}s → with a crawling provider \
             {w:>6.2}s  (+{:.2}s, {:.2}x, {} dispatches to the crawler)",
            w - b,
            w / b.max(0.001),
            with.srv(0).tried
        );
    }

    for c in [&solo, &off, &on] {
        assert_eq!(c.done, N_ARTICLES, "{} lost articles", c.label);
    }
}

/// Follow-up to the baseline: WHERE does a refusing provider's wall cost
/// come from? It serves no bytes, so it cannot be stealing bandwidth.
/// Two candidates, and they want different fixes:
///
/// - the refusals themselves (each article makes an extra queue round
///   trip before the twin can have it) - a demotion fixes this;
/// - the RATE of them (a refusal is nearly free, so the faulty server's
///   workers pull work off the shared queue far faster than they can
///   usefully serve it, scanning and re-rotating the queue under its
///   lock while the twin waits its turn) - a demotion fixes this too,
///   but so would anything that slows the useless picker down, and the
///   distinction decides how a phase-2 threshold should be shaped.
///
/// Both knobs here slow the faulty server's picking WITHOUT changing how
/// many articles it refuses: fewer connections, and a delay per refusal.
/// If wall falls back toward the twin-alone control under either, the
/// cost is dominated by the rate.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock diagnostic - run with --ignored"]
async fn where_the_refusing_providers_wall_cost_comes_from() {
    let solo = solo_leg("twin alone (control)", 0).await;
    let mut table = vec![solo.clone()];
    table.push(
        twin_leg_conns("100% miss, 4 conns", 0, 4, |ids| {
            miss_chaos_echoing(ids, ids.len())
        })
        .await,
    );
    table.push(
        twin_leg_conns("100% miss, 1 conn", 0, 1, |ids| {
            miss_chaos_echoing(ids, ids.len())
        })
        .await,
    );
    table.push(
        twin_leg_conns("100% miss, 50ms refusals", 0, 4, |ids| Chaos {
            missing_delay_ms: 50,
            ..miss_chaos_echoing(ids, ids.len())
        })
        .await,
    );
    println!(
        "\n§129 3d phase 1 diagnostic - the same 100% refusal rate, \
              picked at different speeds:"
    );
    for c in &table {
        println!("  {}", c.line());
    }
    let s = solo.wall.as_secs_f64();
    for c in table.iter().skip(1) {
        println!(
            "    {:<26} {:.2}x the twin-alone control",
            c.label,
            c.wall.as_secs_f64() / s.max(0.001)
        );
    }
    for c in &table {
        assert_eq!(c.done, N_ARTICLES, "{} lost articles", c.label);
    }

    // Second question: is the penalty PROPORTIONAL to the job (a real
    // job-scale cost) or a FIXED tail (seconds, which a 300 MB job would
    // never notice)? Same fault at 1x and 3x the corpus - if the
    // absolute overhead holds still while the wall triples, it is a tail
    // effect and the item is much smaller than it looks.
    println!("\n  scaling - the same fault over a 3x corpus:");
    for n in [N_ARTICLES, N_ARTICLES * 3, N_ARTICLES * 9] {
        let solo = solo_leg_of("solo", 0, n).await;
        let hurt = twin_leg_sized("faulty+twin", 0, CONNS, n, |ids| {
            miss_chaos_echoing(ids, ids.len())
        })
        .await;
        assert_eq!(solo.done, n);
        assert_eq!(hurt.done, n);
        let (s, h) = (solo.wall.as_secs_f64(), hurt.wall.as_secs_f64());
        println!(
            "    {n:>5} articles: solo {s:>5.2}s → with a useless provider \
             {h:>5.2}s  (+{:.2}s, {:.2}x)",
            h - s,
            h / s.max(0.001)
        );
    }
}
