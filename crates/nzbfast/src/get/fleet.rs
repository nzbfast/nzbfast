//! The buffer pools and the server fleet (TODO 106 phase 2.1, cut 9):
//! race-stragglers knobs, connection auto-tune caps, the warm-pool
//! reconcile, per-server PoolConfigs with live gauges, and the M29
//! oracle sink. Body is a verbatim move from the orchestrator.

use crate::*;
use nzbkit::pool::{BufPool, PoolConfig};
use std::path::Path;
use tracing::info;

/// The wired fleet. Field names match the local bindings the inline
/// code used.
pub(super) struct Fleet {
    pub(super) buf_pool: Arc<BufPool>,
    pub(super) out_pool: Arc<BufPool>,
    pub(super) servers: Vec<(ServerConfig, PoolConfig)>,
}

/// Does any enabled server have a peer it could steer a CRC-failed
/// article to: same LEVEL, different host, and not an explicit mirror of
/// the same backbone?
///
/// Level matters because a deeper server's pickup gate demands the
/// shallower one's 430 bit, so a primary + fill pair can never steer.
/// That makes this sensitive to the M29 routing demotion in plan.rs
/// (`demote_predicted_gone`): sinking servers to a new bottom tier can
/// leave a survivor alone on level 0, which correctly turns the steer
/// off rather than paying its forced CRC for a peer that cannot take
/// the article.
pub(super) fn has_steer_peer(servers: &[ServerConfig]) -> bool {
    let on: Vec<_> = servers.iter().filter(|s| s.enabled).collect();
    on.iter().enumerate().any(|(i, a)| {
        on.iter().enumerate().any(|(j, b)| {
            i != j
                && a.level == b.level
                && a.host != b.host
                && (a.group.is_none() || b.group.is_none() || a.group != b.group)
        })
    })
}

#[expect(clippy::too_many_arguments)]
pub(super) async fn build_fleet(
    cfg_all: &Config,
    config: &Path,
    connections: usize,
    window: usize,
    hub: &Option<Arc<StreamHub>>,
    job_posted: Option<i64>,
    job_family: &str,
    budget: &nzbkit::mem::MemBudget,
) -> Fleet {
    let buf_pool = BufPool::new_gauged(
        budget.bufpool_bufs(),
        nzbkit::memgauge::Sub::RawFree,
        nzbkit::memgauge::Sub::RawOut,
    );
    // Decoded-payload buffers, recycled the same way as the network-side
    // `buf_pool` - the decoder writes each article's bytes into a buffer
    // taken from here and the consumer returns it after write+verify, so
    // the hot path does no per-article ~800 KB payload allocation.
    let out_pool = BufPool::new_gauged(
        budget.bufpool_bufs(),
        nzbkit::memgauge::Sub::OutFree,
        nzbkit::memgauge::Sub::OutOut,
    );
    let FleetKnobs {
        read_timeout,
        adaptive_timeout,
        tail_fanout,
        tail_fanout_early,
        hedge,
        ttfb_hedge,
        outage_budget,
        recycle_slope,
        recycle_slow,
        hot_spare,
        steer_depth,
        tail_taper,
        race_envelope,
        race_sat_pct,
        race_escape,
        stall_live,
        peak_arrivals,
        flap_cap_keepers,
        crc_steer,
    } = read_knobs(cfg_all, config);
    // Per-server budget: the CLI --connections is a ceiling; a server's
    // config `connections` (its account limit) caps its own pool; a
    // fresh auto-tuned knee (conntune.json, M7b.1) caps below that -
    // over-asking a provider measured 3-4× SLOWER than the knee.
    // Two knees are NOT applied: any knee while the auto_connections
    // toggle is off (off must mean off - the user's escape hatch from a
    // bad probe), and a `suspect` one (a low knee awaiting a second
    // probe's corroboration) even while it's on.
    let tuned = if crate::conntune::enabled(config) {
        crate::conntune::load(config)
    } else {
        Default::default()
    };
    // Say what the cap IS and what it is capping, not just a bare
    // number. `connection auto-tune: news.example.com 6` was the entire
    // explanation a v1.0.14 tester had for why the 24 he had typed into
    // Settings never took effect, and it read as a status line rather
    // than as "something overrode you". Name the asked-for count and
    // the switch that turns it off.
    // Whether the live epoch controller is in charge for this run (the
    // `live_tune` setting mirrored on the hub, or the dev override).
    // Computed here because the cap note below must not print when the
    // knee is not capping.
    let live_tune = hub.as_ref().is_some_and(|h| {
        h.live_tune.load(std::sync::atomic::Ordering::Relaxed) || crate::conntune::live_tune_on()
    });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Would a stored knee cap this host, and how old is the number doing
    // it? Both notes below need the same answer, so it is computed once.
    // A pinned server is not capped, so it must not be announced as
    // capped - these lines are the ONLY explanation a user gets for a
    // number they did not choose, and printing one for a number they DID
    // choose is worse than printing nothing.
    let cap_state = |s: &nzbkit::config::ServerConfig| {
        let t = tuned.get(&s.host)?;
        let asked = crate::conntune::effective_limit(connections, s.connections);
        (!s.pin_connections && !t.suspect && t.connections > 0 && t.connections < asked).then_some(
            (
                t,
                asked,
                crate::conntune::age_str(crate::conntune::age_secs(t, now)),
            ),
        )
    };
    let tuned_note: Vec<String> = cfg_all
        .servers
        .iter()
        .filter_map(|s| {
            let (t, asked, age) =
                cap_state(s).filter(|(t, ..)| !crate::conntune::is_expired(t, now))?;
            // Name the sample's AGE, always. This line used to end
            // "(measured sweet spot)", which reads as the provider's
            // verdict rather than as our own probe of it - and a knee is
            // exactly as good as it is recent. A bench leg spent an hour
            // on 23 Aug 2026 working out why a provider was granting 32
            // before finding a fifteen-day-old entry saying so; the age
            // was on disk the whole time and nothing ever printed it.
            let overdue = match crate::conntune::is_stale(t, now) {
                true => ", overdue for re-measurement",
                false => "",
            };
            Some(format!(
                "{} capped at {} of {asked}, probed {age} ago{overdue}",
                s.host, t.connections
            ))
        })
        .collect();
    // With the live controller on, the knee SEEDS instead of capping -
    // announcing a cap that is not being applied is the same lie the
    // pinned-server exclusion exists to avoid.
    if !live_tune && !tuned_note.is_empty() {
        let note = tuned_note.join(" · ");
        info!(target: "tune", "connection auto-tune: {note} (our own probe of this \
             provider, not a limit it stated; Settings → Auto-tune connections turns \
             this off)");
    }
    // The other half of the same honesty: a knee old enough to have
    // stopped applying (`conntune::EXPIRE_SECS`) leaves the job on the
    // user's own count. That is the right number and a SILENT change to
    // one, so say which cap went away and how old it was - otherwise the
    // next person to read conntune.json derives a cap that no longer
    // governs, which is the mirror image of the trap above.
    let expired_note: Vec<String> = cfg_all
        .servers
        .iter()
        .filter_map(|s| {
            let (t, asked, age) =
                cap_state(s).filter(|(t, ..)| crate::conntune::is_expired(t, now))?;
            Some(format!(
                "{} measured {} connections {age} ago and nothing has re-measured it \
                 since, so it is no longer capping: this job uses the {asked} you set",
                s.host, t.connections
            ))
        })
        .collect();
    if !live_tune && !expired_note.is_empty() {
        let note = expired_note.join(" · ");
        info!(target: "tune", "connection auto-tune: {note}");
    }
    // Config is reloaded for every daemon job, while the warm pool lives
    // across jobs. Reconcile the cache before building the new fleet so
    // sessions authenticated with a removed password/user, proxy or bind
    // address stop occupying the provider's connection cap immediately.
    if let Some(warm) = hub.as_ref().and_then(|h| h.warm()) {
        warm.retain_servers(&cfg_all.servers).await;
        // Idle release is settled PER SERVER and read straight off the
        // config this job is about to use, so a provider added, removed
        // or re-tuned since the last job is reflected before any of its
        // connections are parked.
        warm.set_release_policies(&cfg_all.servers);
    }
    // Sidecar connection borrowing: caps a host's pool below its normal
    // budget when this hub is a prefetch sidecar borrowing from a server
    // that is busy on the active job. Empty on every other hub.
    let host_caps = hub
        .as_ref()
        .map(|h| h.host_conn_caps.lock_ok().clone())
        .unwrap_or_default();
    // §96.5: remaining prepaid bytes per host, computed by the daemon at
    // job start. Threaded into each server's pool config so the pool can
    // release a server whose block runs out MID-RUN - the job-boundary
    // exclusion above this (excluded_hosts) only helps the next job.
    // Empty on a CLI run, which has no usage ledger to budget from.
    let host_budgets = hub
        .as_ref()
        .map(|h| h.host_byte_budgets.lock_ok().clone())
        .unwrap_or_default();
    // TODO 112: with live tuning on (the `live_tune` setting, or
    // NZBFAST_LIVE_TUNE=1 as the dev override), the fleet is SPAWNED at
    // the ceiling and run at a live target the epoch controller moves.
    // The target starts at the SEED - the current time-of-day bucket
    // when it carries evidence, else the trusted knee, else the
    // configured count (conn-tuning design §5.1) - and the stored knee
    // does not cap the job: with the controller in charge, measurements
    // seed and only typed numbers cap. A pinned server keeps the old
    // shape: its number is a statement, not a state.
    //
    // Seeding reads the store directly rather than through `tuned`:
    // that map is emptied when auto_connections is off, but that toggle
    // governs the OFFLINE prober and its knee caps - a live-tune seed
    // is not a cap, and bucket evidence stays useful either way.
    let seed_store = if live_tune {
        crate::conntune::load(config)
    } else {
        Default::default()
    };
    // TODO 208 item 1: the fleet cap (`nzbkit::pool::linecap` has the
    // measurements). The SEED half: the whole fleet is capped at a
    // small CONSTANT, split equally across the servers and still under
    // each account's own number. Enters as a `min` on `base`, the same
    // seam `host_caps` uses, so a pin still wins and a knee or a live
    // seed still only lowers it. It binds on every run now that the cap
    // is no longer divided out of the line: a CLI run and a daemon's
    // first job, which have no `anchor`, are capped here like any
    // other. The anchor is still stamped on every server's pool config
    // - the in-run shed stands down without one
    // (`Shared::line_cap_tick`), and the stall bound sizes an article's
    // share from it.
    let anchor_bps = hub
        .as_ref()
        .map(|h| h.line_anchor_bps.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0);
    // TODO 277: the fleet is a curve on that anchor now, not a flat
    // constant. An anchor of 0 - a CLI run, a sidecar, a daemon that
    // has not finished a job yet - is the curve's floor, which is the
    // number that shipped, so nothing about those runs changes.
    let line_cap = crate::conntune::line_cap_fleet(anchor_bps);
    let line_share = crate::conntune::line_cap_share(cfg_all.servers.len(), anchor_bps);
    // TODO 277: the seed SPAWNS slots for a bigger fleet than it runs,
    // and parks the surplus, so that the in-run governor's raise has
    // somewhere to land - a `ConnTarget` above the spawned fleet wakes
    // nothing. `conntune::line_cap_headroom_fleet` carries the whole
    // argument and the three scoping rules.
    let headroom_share = nzbkit::pool::linecap::server_share(
        crate::conntune::line_cap_headroom_fleet(line_cap, crate::conntune::line_cap_is_auto()),
        cfg_all.servers.len(),
    );
    let seed_bucket = crate::conntune::bucket_of(crate::conntune::local_hour());
    let mut servers: Vec<_> = cfg_all
        .servers
        .iter()
        .map(|s| {
            let mut base = connections.min(s.connections.max(1) as usize);
            if let Some(cap) = host_caps.get(&s.host) {
                base = base.min((*cap).max(1));
            }
            // What this server's own ceilings allow, before the fleet
            // cap takes its share out: the bound TODO 277's spawn
            // headroom is held to below, so that parking a surplus can
            // never ask an account for more than it grants.
            let uncapped = base;
            if let Some(share) = line_share
                && !s.pin_connections
                && share < base
            {
                // §275 item 2: the escape this line names must be one a
                // user can actually reach. It used to name only
                // NZBFAST_LINE_CAP=0, an env var that needs a daemon
                // restart; the designed per-server escape is the pin
                // (it bypasses this cap, the conntune knee AND the live
                // walker, all three guard on `pin_connections`), and it
                // is a dashboard edit. Found the hard way on a
                // giganews-only box whose 25-socket cap WAS the rate:
                // cold giganews serves ~10-13 Mbps per connection, so
                // the fleet cap held ~0.35 Gbps on a line that had
                // recorded a 2.5 Gbps peak the same half hour.
                // The head of this line - through `across N servers` -
                // is parsed POSITIONALLY by the bench rig's fleet guard
                // (it stamps `linecap=<fleet>:<allowed>of<asked>` on a
                // leg line from it), so TODO 277's line reading is
                // APPENDED after it and nothing before it moves.
                info!(target: "tune", "line cap: {} {share} of {base} (fleet cap {line_cap} \
                       across {} servers, sized from a {:.0} Mbit line; pin this server's \
                       connections in Settings to lift it for that server, or \
                       NZBFAST_LINE_CAP=0 turns it off)",
                      s.host, cfg_all.servers.len(), anchor_bps as f64 * 8.0 / 1e6);
                base = share;
            }
            let applied = crate::conntune::applied_connections(
                base,
                s.pin_connections,
                tuned.get(&s.host),
                now,
            );
            let (conns, live_target) = match (live_tune && !s.pin_connections && base > 1, hub) {
                (true, Some(h)) => {
                    let seed = crate::conntune::seed_connections(
                        seed_store.get(&s.host),
                        seed_bucket,
                        now,
                        base,
                    );
                    let t = h
                        .live_targets
                        .lock_ok()
                        .entry(s.host.clone())
                        .or_insert_with(|| nzbkit::pool::ConnTarget::new(seed))
                        .clone();
                    // A ceiling that moved between jobs clamps the
                    // surviving belief; a belief the controller earned
                    // above the prior survives the job boundary.
                    if t.get() > base {
                        t.set(base);
                    }
                    (base, Some(t))
                }
                // The in-run shed needs a target to move. A pinned
                // server gets none (its number is a statement), and a
                // single connection has nowhere to go. Per job, not on
                // the hub: with no walker there is no belief to carry
                // across jobs, and the seed above re-derives it.
                // Handed out anchor or not: a mid-run one finds it.
                _ => {
                    let target = (line_cap > 0 && !s.pin_connections && applied > 1)
                        .then(|| nzbkit::pool::ConnTarget::new(applied));
                    // TODO 277's spawn headroom, and only where there
                    // IS a target to raise: a pinned server, a single
                    // connection and a cap turned off all keep the old
                    // shape exactly, spawning what they run.
                    let spawn = match &target {
                        None => applied,
                        Some(_) => crate::conntune::line_cap_spawn_slots(
                            applied,
                            headroom_share,
                            uncapped,
                            s.pin_connections,
                            tuned.get(&s.host),
                            now,
                        ),
                    };
                    (spawn, target)
                }
            };
            // Cross-job hand-over: this host's slice of the daemon's
            // connection budget, sized to exactly the fleet spawned
            // here, and the run's idle signal. Both absent off the
            // daemon hub (CLI, sidecar), where no successor exists.
            //
            // SPAWNED and not dialled (TODO 277): the cap has to cover
            // every slot the in-run governor may wake, or a raise would
            // find its new workers blocked on `acquire` rather than on
            // the line. It is still bounded by the account's own
            // number, which is the limit this lease exists to hold two
            // runs inside.
            let lease = hub
                .as_ref()
                .and_then(|h| h.conn_budget.get())
                .map(|b| b.lease(&nzbkit::pool::handoff::ConnBudget::key(s), conns));
            let handoff = hub.as_ref().and_then(|h| h.handoff.lock_ok().clone());
            let cfg = PoolConfig {
                connections: conns,
                live_target,
                lease,
                handoff,
                line_cap_fleet: line_cap,
                line_cap_auto: crate::conntune::line_cap_is_auto(),
                line_anchor_bps: anchor_bps,
                window,
                // The get pipeline's drain releases this charge
                // (drain_outcome_batch); see the field doc for why only
                // a releasing consumer may set it.
                channel_gauge: Some(nzbkit::memgauge::Sub::Channel),
                buf_pool: Some(buf_pool.clone()),
                read_timeout,
                adaptive_timeout,
                tail_fanout,
                tail_fanout_early,
                steer_depth,
                tail_taper,
                race_envelope,
                race_sat_pct,
                race_escape,
                stall_live,
                peak_arrivals,
                // §5.7, and the one place the setting meets the pool:
                // per-server, never OR-folded across the fleet, because
                // the whole point of the flag is that one account's
                // billing says nothing about another's.
                block_account: s.block_account,
                budget_bytes: host_budgets.get(&s.host).copied(),
                hedge,
                ttfb_hedge,
                recycle_slow,
                recycle_slope,
                hot_spare,
                flap_cap_keepers,
                outage_budget,
                crc_steer,
                // TODO 121.4: the decode consumers ack every Done id
                // (note_settled / note_decoded), so the pool holds
                // each article's liveness entry until its bytes are
                // written - the dead-span verdict sees the whole pipe.
                arrival_ack: true,
                rate: hub.as_ref().map(|h| h.rate.clone()),
                // B3: wire-side in-flight bytes are budget-exempt (window
                // × connections × ~800 KB); this cap throttles pipeline
                // top-up globally when the budget is small. Shared uses
                // the same value in every server's config - the counter
                // it gates lives on the pool's Shared state.
                inflight_cap: budget.inflight_cap(),
                // Daemon only (`hub` is absent for a one-shot CLI `get`,
                // which has no next job to hand connections to), and only
                // for a server the user has switched ON. §36: the pool is
                // off by default and settled PER SERVER, because whether
                // it helps is a property of the link - worth -19.5% on a
                // controlled 50 ms path, and indistinguishable from
                // nothing on a real jittery one. `mode=warm_bench`
                // measures this server and recommends.
                warm: match s.warm_pool {
                    true => hub.as_ref().and_then(|h| h.warm()),
                    false => None,
                },
                ..PoolConfig::default()
            };
            (s.clone(), cfg)
        })
        .collect();
    // Per-server live gauges for the dashboard (workers update, API reads).
    let pool_live = nzbkit::pool::LiveStats::for_servers(&servers);
    for (_, cfg) in servers.iter_mut() {
        cfg.live = Some(pool_live.clone());
    }
    if let Some(h) = &hub {
        *h.pool_live.lock_ok() = Some(pool_live.clone());
    }
    // M29 oracle: every server pool records per-article hit/430 outcomes
    // into the daemon's per-job sink (in-memory; flushed to the ledger at
    // net-drain). Context = pool host order + the NZB's dominant group's
    // family. Undated jobs are skipped (job_posted is None): their outcomes
    // have no reliable age bucket, so recording them would pollute the
    // fresh buckets and skew the takedown fingerprint.
    if let Some(sink) = hub
        .as_ref()
        .filter(|_| job_posted.is_some())
        .and_then(|h| h.oracle.lock_ok().clone())
    {
        sink.set_context(
            servers.iter().map(|(s, _)| s.host.clone()).collect(),
            job_family.to_string(),
        );
        for (_, cfg) in servers.iter_mut() {
            cfg.oracle = Some(sink.clone());
        }
    }
    Fleet {
        buf_pool,
        out_pool,
        servers,
    }
}

#[path = "fleet_knobs.rs"]
mod fleet_knobs;
use fleet_knobs::*;

#[cfg(test)]
mod shipped_defaults {
    use super::*;

    /// `PoolConfig::shipped()` must BE what this builder resolves for a
    /// user who has touched nothing.
    ///
    /// nzbkit's rigs build their fleets from a `PoolConfig`, and the
    /// obvious constructor - `default()` - has the whole speculation
    /// layer dark, because the library's neutral posture is not the
    /// product's. `shipped()` exists so a rig can say "the pool as the
    /// daemon ships it" in one token; this test is what stops that
    /// claim from quietly becoming false. The two `unwrap_or`s in
    /// `read_knobs` read their default OUT of `shipped()`, so the values
    /// cannot drift - what this catches is the other direction: a sixth knob
    /// added to one side and not the other, or a switch that stops
    /// fanning out to all four of its fields.
    #[tokio::test]
    async fn shipped_matches_the_daemons_own_defaults() {
        // The bench suite A/Bs single knobs through the environment;
        // under one of those shells the daemon is deliberately not
        // shipped-shaped and this test has nothing to say.
        for k in [
            "NZBFAST_TAIL_FANOUT",
            "NZBFAST_HEDGE",
            "NZBFAST_RECYCLE_SLOPE",
            "NZBFAST_ADAPTIVE_TIMEOUT",
            "NZBFAST_RACE_ESCAPE",
            "NZBFAST_STALL_LIVE",
            "NZBFAST_PEAK_ARRIVALS",
        ] {
            if std::env::var_os(k).is_some() {
                eprintln!("skipped: {k} overrides the shipped posture");
                return;
            }
        }
        let cfg: Config = serde_json::from_str(r#"{"servers":[{"host":"ship.example"}]}"#).unwrap();
        let dir = std::env::temp_dir().join(format!("nzbfast-shipped-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        // No settings.json in this directory - the fresh-install case.
        let fleet = build_fleet(
            &cfg,
            &dir.join("config.local.json"),
            4,
            4,
            &None,
            None,
            "",
            &nzbkit::mem::MemBudget::with_total(1 << 30),
        )
        .await;
        let got = &fleet.servers[0].1;
        let want = PoolConfig::shipped();
        let knobs = |c: &PoolConfig| {
            [
                ("adaptive_timeout", c.adaptive_timeout),
                ("tail_fanout", c.tail_fanout),
                ("tail_fanout_early", c.tail_fanout_early),
                ("hedge", c.hedge),
                ("recycle_slope", c.recycle_slope),
                // TODO 202 §17: on by default, so it belongs with the
                // shipped posture rather than the dark list below.
                ("race_escape", c.race_escape),
                ("stall_live", c.stall_live),
                ("peak_arrivals", c.peak_arrivals),
            ]
        };
        assert_eq!(
            knobs(got),
            knobs(&want),
            "PoolConfig::shipped() no longer describes what this builder \
             ships - fix whichever side moved, and re-check the rigs that \
             build their fleets from it"
        );
        // And the dark knobs stay dark on both sides: `shipped()` is the
        // default posture, not "everything on".
        let dark = |c: &PoolConfig| {
            [
                ("steer_depth", c.steer_depth),
                ("race_envelope", c.race_envelope),
                ("ttfb_hedge", c.ttfb_hedge),
                ("recycle_slow", c.recycle_slow),
                ("hot_spare", c.hot_spare),
            ]
        };
        assert!(
            dark(&want).iter().all(|(_, v)| !v),
            "a dark knob was armed in PoolConfig::shipped(): {:?}",
            dark(&want)
        );
        assert_eq!(dark(got), dark(&want), "dark-knob posture diverged");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod block_account_wiring {
    use super::*;

    /// §5.7: the setting reaches the pool, PER SERVER.
    ///
    /// This one line is the whole join between a checkbox in the server
    /// editor and the racing gates in pool.rs, and neither side's own
    /// tests can see it: nzbkit pins that a flagged PoolConfig never
    /// races, and nzbkit::config pins that the field parses, but nothing
    /// else would notice if the wire between them were dropped in a
    /// refactor of this builder.
    ///
    /// Per-server and never OR-folded: one account's billing says
    /// nothing about another's, so a mixed fleet must come out mixed.
    #[tokio::test]
    async fn the_setting_reaches_the_pool_per_server() {
        let cfg: Config = serde_json::from_str(
            r#"{"servers":[
                 {"host":"flat.example"},
                 {"host":"metered.example","block_account":true}
               ]}"#,
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("nzbfast-ba-wire-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let fleet = build_fleet(
            &cfg,
            &dir.join("config.local.json"),
            4,
            4,
            &None,
            None,
            "",
            &nzbkit::mem::MemBudget::with_total(1 << 30),
        )
        .await;
        let flags: Vec<(String, bool)> = fleet
            .servers
            .iter()
            .map(|(s, p)| (s.host.clone(), p.block_account))
            .collect();
        assert_eq!(
            flags,
            vec![
                ("flat.example".to_string(), false),
                ("metered.example".to_string(), true),
            ],
            "the flag must ride each server's own PoolConfig, not the fleet's"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod line_cap_seed {
    use super::*;

    /// Each server as `(host, SPAWNED slots, live target)`, which since
    /// TODO 277 are three different facts rather than two. The spawn
    /// count is the fleet curve's CEILING share, so the in-run governor
    /// has slots to wake; the target is the curve's own number, which
    /// is what the run dials; a pinned server keeps its configured
    /// number AND gets no target at all (a statement, not a state).
    async fn build(
        cfg: &Config,
        hub: &Option<Arc<StreamHub>>,
    ) -> Vec<(String, usize, Option<usize>)> {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-linecap-{}-{}",
            std::process::id(),
            hub.is_some()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let fleet = build_fleet(
            cfg,
            &dir.join("config.local.json"),
            100,
            4,
            hub,
            None,
            "",
            &nzbkit::mem::MemBudget::with_total(1 << 30),
        )
        .await;
        let _ = std::fs::remove_dir_all(&dir);
        fleet
            .servers
            .iter()
            .map(|(s, p)| {
                (
                    s.host.clone(),
                    p.connections,
                    p.live_target.as_ref().map(|t| t.get()),
                )
            })
            .collect()
    }

    fn five() -> Config {
        serde_json::from_str(
            r#"{"servers":[
                 {"host":"a.example","connections":100},
                 {"host":"b.example","connections":100},
                 {"host":"c.example","connections":100},
                 {"host":"d.example","connections":100},
                 {"host":"e.example","connections":100,"pin_connections":true}
               ]}"#,
        )
        .unwrap()
    }

    /// The curve's FLOOR is fleet 25 over five servers = 5 each at
    /// 100 Mbit, and the pinned server keeps the number it was given.
    /// The spawn is ten apiece - the ceiling's share, TODO 277 - so the
    /// four capped servers run at 5 with 5 parked behind each.
    #[tokio::test]
    async fn the_curves_floor_dials_five_per_server_and_a_pin_wins() {
        let hub = Arc::new(StreamHub {
            line_anchor_bps: std::sync::atomic::AtomicU64::new(12_500_000),
            ..Default::default()
        });
        let got = build(&five(), &Some(hub)).await;
        let want: Vec<(String, usize, Option<usize>)> = ["a", "b", "c", "d"]
            .iter()
            .map(|h| (format!("{h}.example"), 10, Some(5)))
            .chain(std::iter::once(("e.example".to_string(), 100, None)))
            .collect();
        assert_eq!(got, want);
    }

    /// TODO 277's whole point: a run whose seed sees NO line still
    /// spawns the ceiling's worth of slots, so the in-run governor has
    /// somewhere to put a raise. Before this the surplus did not exist
    /// and a raised `ConnTarget` woke nothing (`ConnTarget::set`), which
    /// is why a `nzbfast get` on a 10 GbE line dialled 25 for ever.
    #[tokio::test]
    async fn an_anchorless_run_still_spawns_the_ceiling_to_grow_into() {
        for hub in [None, Some(Arc::new(StreamHub::default()))] {
            let got = build(&five(), &hub).await;
            assert!(
                got.iter().all(|(h, spawned, target)| if h == "e.example" {
                    *spawned == 100 && target.is_none()
                } else {
                    *spawned == 10 && *target == Some(5)
                }),
                "{got:?}"
            );
        }
    }

    /// A line already at the curve's ceiling has nothing to grow into,
    /// so the spawn and the target are the same number - the shape that
    /// shipped, reached from the other end.
    #[tokio::test]
    async fn a_ten_gig_anchor_spawns_exactly_what_it_dials() {
        let hub = Arc::new(StreamHub {
            // 10 Gbit/s in bytes/s: past `fleet_for_line`'s ceiling.
            line_anchor_bps: std::sync::atomic::AtomicU64::new(1_250_000_000),
            ..Default::default()
        });
        let got = build(&five(), &Some(hub)).await;
        assert!(
            got.iter().all(|(h, spawned, target)| if h == "e.example" {
                *spawned == 100 && target.is_none()
            } else {
                *spawned == 10 && *target == Some(10)
            }),
            "{got:?}"
        );
    }

    /// The retired 720 Mbit stand-down: a gigabit anchor used to hand
    /// the fleet back whole. §208 measured fleet 20 a second AHEAD of
    /// fleet 360 on an unshaped 1 GbE line, so it no longer does - it
    /// is still on the curve's floor, and still dials 5.
    #[tokio::test]
    async fn a_gigabit_anchor_is_capped_as_well() {
        let hub = Arc::new(StreamHub {
            line_anchor_bps: std::sync::atomic::AtomicU64::new(125_000_000),
            ..Default::default()
        });
        let got = build(&five(), &Some(hub)).await;
        assert!(
            got.iter()
                .all(|(h, _, target)| *target == if h == "e.example" { None } else { Some(5) }),
            "{got:?}"
        );
    }
}
