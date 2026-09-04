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

/// Everything the last job taught this hub about the line, for the
/// fleet rules below: the link anchor in bytes/s, whether that anchor
/// was MEASURED rather than typed into Settings (TODO 275 item 1
/// part 1), and the per-socket carry the last job actually held (part
/// 2). All three are `0` / false off the daemon hub - a CLI `get`, a
/// prefetch sidecar - which is the no-evidence case every rule below
/// already treats as the behaviour that shipped.
///
/// The runner writes all three at job start, together, so they describe
/// one moment; reading them in one place is what keeps them describing
/// one moment here too.
fn line_evidence(hub: &Option<Arc<StreamHub>>) -> (u64, bool, u64) {
    use std::sync::atomic::Ordering;
    let Some(h) = hub.as_ref() else {
        return (0, false, 0);
    };
    (
        h.line_anchor_bps.load(Ordering::Relaxed),
        h.line_anchor_measured.load(Ordering::Relaxed),
        h.line_carry_bps.load(Ordering::Relaxed),
    )
}

/// TODO 112: the live connection tuner's handle for ONE server ROW,
/// minted on the hub the first time that row is built and reused by
/// every job after it - which is the whole point of the map living on
/// the hub rather than per job: the epoch controller's belief has to
/// survive a job boundary.
///
/// KEYED BY THE ROW, NEVER BY `s.host`. Two accounts on one provider
/// are supported and tested (`nzbkit`'s
/// `duplicate_host_entries_edge_trigger_independently`) - a flat-rate
/// account beside a small block fill at the same host is the ordinary
/// shape - and keyed by host this map handed both rows ONE
/// `ConnTarget`. The `ceiling` clamp below then pulled the shared
/// target down to whichever row was built last, so a 24-connection
/// account parked at 4 sockets; one epoch controller advanced on two
/// accounts' measurements; and configuration ORDER decided whose
/// pin/ceiling/block policy governed both. Re-applied on every build,
/// so a walk-up earned during job N was undone at the start of job
/// N+1. The shape that reintroduces it is any `entry()` here or in
/// `tasks/tuner.rs` taking a hostname. See
/// `nzbkit::pool::row_keys` for how the key is minted and why
/// `handoff::ConnBudget::key` will not do.
fn live_target_for_row(
    hub: &StreamHub,
    row_key: &str,
    seed: usize,
    ceiling: usize,
) -> Arc<nzbkit::pool::ConnTarget> {
    let t = hub
        .live_targets
        .lock_ok()
        .entry(row_key.to_string())
        .or_insert_with(|| nzbkit::pool::ConnTarget::new(seed))
        .clone();
    // A ceiling that moved between jobs clamps the surviving belief; a
    // belief the controller earned above the prior survives the job
    // boundary.
    if t.get() > ceiling {
        t.set(ceiling);
    }
    t
}

/// What the FLEET CAP is allowed to cut from this server, for
/// `PoolConfig::line_cap_uncapped` - which is the sum
/// `linecap::seed_uncapped` folds into
/// `LiveStats::line_cap_configured`, whose only consumer is whyslow's
/// `fleet_bound`.
///
/// 0 FOR A PINNED SERVER, and that is the fix rather than a shortcut.
/// That arm fires on `configured > cap`, i.e. "the cap is taking
/// sockets away". `pin_connections` is the documented escape FROM the
/// cap - the builder skips `line_share` for it entirely and keeps the
/// user's own number - so the cap takes nothing from a pinned account,
/// and counting its ceiling in the sum told a user whose single server
/// is pinned to 50 that a fleet cap of 25 was holding them back, and
/// offered to raise the very cap their pin had already lifted.
///
/// `uncapped` itself is NOT zeroed at the call site:
/// `conntune::line_cap_spawn_slots` needs the account's real ceiling to
/// bound TODO 277's spawn headroom with, so parking a surplus can never
/// ask an account for more than it grants. The shape that reintroduces
/// the defect is stamping that number into the field unconditionally.
///
/// An all-pinned fleet therefore sums to 0, which `fleet_bound`'s first
/// line already reads as "no claim" and never as "you configured
/// nothing".
fn cap_exposed(pinned: bool, uncapped: usize) -> usize {
    match pinned {
        true => 0,
        false => uncapped,
    }
}

/// Say that the FLEET CAP is what lowered this server, and name the
/// three ways out of it.
///
/// Hoisted out of `build_fleet` when TODO 312 item 7 took that function
/// past its 500-line ceiling; the reasoning below travels with the
/// message it is about, which is the point of moving both together.
///
/// §275 item 2: the escape this line names must be one a user can
/// actually reach. It used to name only NZBFAST_LINE_CAP=0, an env var
/// that needs a daemon restart; the designed per-server escape is the
/// pin (it bypasses this cap, the conntune knee AND the live walker,
/// all three guard on `pin_connections`), and it is a dashboard edit.
/// Found the hard way on a box with one provider whose 25-socket cap
/// WAS the rate: that route serves ~10-13 Mbps per connection cold, so
/// the fleet cap held ~0.35 Gbps on a line that had recorded a 2.5 Gbps
/// peak the same half hour.
///
/// The head of this line - through `across N servers` - is parsed
/// POSITIONALLY by the bench rig's fleet guard (it stamps
/// `linecap=<fleet>:<allowed>of<asked>` on a leg line from it), so TODO
/// 277's line reading is APPENDED after it and nothing before it moves.
/// TODO 312 item 1 named the Settings escape first.
fn note_line_cap(
    host: &str,
    share: usize,
    base: usize,
    line_cap: usize,
    n_servers: usize,
    evidence: (u64, bool, u64),
    curve_fleet: usize,
) {
    let (anchor_bps, anchor_measured, carry_bps) = evidence;
    info!(target: "tune", "line cap: {host} {share} of {base} (fleet cap {line_cap} \
           across {n_servers} servers, {}; set the fleet size in \
           Settings to name your own, pin this server's connections to lift it \
           for that server, or NZBFAST_LINE_CAP=0 turns it off)",
          seed_evidence(anchor_bps, anchor_measured, carry_bps, curve_fleet));
}

/// TODO 275 item 9: what the seed SIZED FROM, in the words a person
/// diagnosing a GH #62-shaped report needs.
///
/// The fleet size is on the line already and it is the one thing that
/// cannot be attributed from itself: `conntune::line_cap_resolve` takes
/// the larger of two candidates - what the LINE asks for
/// (`fleet_for_line`) and what the last job's measured per-socket carry
/// asks for (`fleet_for_carry`) - and the winner leaves no trace. So a
/// reader given only "fleet cap 50" cannot tell a fleet the curve
/// produced from one a banked carry lifted, nor a good banked number
/// from a stale one, and the report that motivated all of §275 arrived
/// with exactly that ambiguity in it.
///
/// **It reports INPUTS and never a verdict, which is the one design
/// rule here.** Naming a winner would be a second spelling of the
/// resolve, and the day a third candidate joins it that spelling is the
/// one nobody updates - this file has paid for that shape before. What
/// this prints is the anchor, the carry, and the number the line ALONE
/// asks for; the fleet beside them is bigger than `curve_fleet`
/// whenever something other than the line moved it, and a reader can
/// see that without this function having an opinion.
///
/// The anchor's PROVENANCE rides along because since TODO 275 item 7 it
/// decides a ceiling, and until now it appeared only in the in-run
/// governor's raise line - which a run that never raises does not
/// print. A reader looking at a fleet that stopped at 50 needs to know
/// whether 50 was even the ceiling.
///
/// Appended AFTER `across N servers` on purpose. The benchmark
/// harness's fleet guard matches this line's HEAD and splits it by
/// FIELD POSITION - it is how a leg records the fleet budget in force
/// against what the seed allowed - so a clause inserted anywhere before
/// `servers` silently changes the numbers a round reports. Everything
/// new goes behind it and nothing before it moves;
/// `the_evidence_never_reaches_the_head_the_bench_guard_parses` is what
/// holds that, since the harness itself runs elsewhere and a drift here
/// would surface weeks later in a leg table.
fn seed_evidence(
    anchor_bps: u64,
    anchor_measured: bool,
    carry_bps: u64,
    curve_fleet: usize,
) -> String {
    let mbit = |b: u64| b as f64 * 8.0 / 1e6;
    // A typed fleet pins both halves of the rule, so neither candidate
    // ran and neither number would be describing this fleet.
    if curve_fleet == 0 {
        return "the fleet size you named".to_string();
    }
    let anchor = format!(
        "sized from a {:.0} Mbit {} line",
        mbit(anchor_bps),
        match anchor_measured {
            true => "measured",
            false => "typed",
        }
    );
    let carry = match carry_bps {
        0 => ", no per-socket carry banked yet".to_string(),
        c => format!(", one socket last measured at {:.1} Mbit", mbit(c)),
    };
    format!("{anchor}{carry}, where the line alone wants {curve_fleet}")
}

/// How many config rows each host carries.
///
/// The conntune store is host-keyed on disk, so its one bucket cannot
/// say WHICH account's target it recorded, and `seed_connections` caps
/// but never raises - seeding both rows of a duplicated host from it
/// starts the 24-connection account at the 4-connection one's learned
/// target, every job. A row whose host counts more than one here seeds
/// from its own typed number instead; the tuner skips the write-back
/// for such hosts too (`tasks/tuner.rs::flush_bucket`).
fn host_row_counts(servers: &[ServerConfig]) -> std::collections::HashMap<&str, usize> {
    let mut host_rows: std::collections::HashMap<&str, usize> = Default::default();
    for s in servers {
        *host_rows.entry(s.host.as_str()).or_default() += 1;
    }
    host_rows
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
    // TODO 313: this build's targets replace the last one's wholesale.
    // Cleared here rather than appended to, so a job that ends leaves
    // nothing behind for the governor to walk down - and NOT cleared by
    // a spilled lane, which must leave the head's in place (the field's
    // own doc carries why).
    if let Some(h) = hub.as_ref()
        && h.spill.lock_ok().as_ref().map(|sp| sp.role)
            != Some(nzbkit::pool::handoff::SpillRole::Lane)
    {
        h.job_targets.lock_ok().clear();
    }
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
        surge_max,
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
    // Whether the live epoch controller is in charge for this run (the
    // `live_tune` setting mirrored on the hub, or the dev override).
    // Computed here because the cap note below must not print when the
    // knee is not capping.
    let live_tune = hub.as_ref().is_some_and(|h| {
        h.live_tune.load(std::sync::atomic::Ordering::Relaxed) || crate::conntune::live_tune_on()
    });
    // Resolved HERE rather than beside the server map below, because
    // the knee notes underneath need `line_share` to say whether the
    // knee they are announcing is the thing that actually binds. Both
    // reads are of `hub` and of settings.json + the environment, so
    // nothing between here and the map can change either answer.
    let (anchor_bps, anchor_measured, carry_bps) = line_evidence(hub);
    let LineCapPlan {
        line_cap,
        line_cap_auto,
        line_share,
        headroom_share,
        curve_fleet,
    } = line_cap_plan(
        config,
        anchor_bps,
        anchor_measured,
        carry_bps,
        cfg_all.servers.len(),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    announce_knee_caps(
        &cfg_all.servers,
        &tuned,
        connections,
        now,
        line_share,
        line_cap,
        live_tune,
    );
    let (host_caps, host_budgets) = hub_host_limits(hub, &cfg_all.servers).await;
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
    let seed_bucket = crate::conntune::bucket_of(crate::conntune::local_hour());
    // The per-ROW identity of this fleet, in fleet order. Two accounts
    // on one hostname are supported, so `s.host` is not an identity -
    // see `nzbkit::pool::row_keys`, which carries the whole argument and
    // is the SAME function `LiveStats::for_servers` mints
    // `ServerLive::row_key` with, off this same list in this same order.
    let row_keys = nzbkit::pool::row_keys(cfg_all.servers.iter().map(|s| s.host.as_str()));
    let host_rows = host_row_counts(&cfg_all.servers);
    let mut servers: Vec<_> = cfg_all
        .servers
        .iter()
        .enumerate()
        .map(|(row, s)| {
            let mut base = connections.min(s.connections.max(1) as usize);
            if let Some(cap) = host_caps.get(&s.host) {
                base = base.min((*cap).max(1));
            }
            // What this server's own ceilings allow, before the fleet
            // cap takes its share out: the bound TODO 277's spawn
            // headroom is held to below, so that parking a surplus can
            // never ask an account for more than it grants.
            let uncapped = base;
            // The same ceilings with the knee applied, which is a
            // different number answering a different question; see
            // `conntune::dialable_ceiling`.
            let dialable = crate::conntune::dialable_ceiling(
                uncapped,
                s.pin_connections,
                live_tune,
                tuned.get(&s.host),
                now,
            );
            if let Some(share) = line_share
                && !s.pin_connections
                && share < base
            {
                note_line_cap(
                    &s.host,
                    share,
                    base,
                    line_cap,
                    cfg_all.servers.len(),
                    (anchor_bps, anchor_measured, carry_bps),
                    curve_fleet,
                );
                base = share;
            }
            let applied = crate::conntune::applied_connections(
                base,
                s.pin_connections,
                tuned.get(&s.host),
                now,
            );
            // TODO 312 item 7: what a STALE knee is costing this
            // server, the evidence behind whyslow's `Knee` verdict.
            // Asked of `base` AFTER the cap's share, so the figure is
            // what lifting the knee would really buy; `stale_knee` has
            // the rest, including why a FRESH knee is not this.
            let line_cap_knee = crate::conntune::stale_knee(
                base,
                s.pin_connections,
                live_tune,
                tuned.get(&s.host),
                now,
            );
            let (conns, live_target) = match (live_tune && !s.pin_connections && base > 1, hub) {
                (true, Some(h)) => {
                    let tune = (host_rows.get(s.host.as_str()) == Some(&1))
                        .then(|| seed_store.get(&s.host))
                        .flatten();
                    let seed = crate::conntune::seed_connections(tune, seed_bucket, now, base);
                    let t = live_target_for_row(h, &row_keys[row], seed, base);
                    // TODO 277's spawn headroom belongs on THIS arm too
                    // (sweep 9, finding 6). It was only ever written on
                    // the `_` arm below, on the reading that live_tune
                    // is off by default - but the setting ships, and
                    // when it is on the WALKER is the in-run governor
                    // that raises this same target. Its clamp is
                    // `desired.min(ceiling).min(line_share)`
                    // (`tasks/tuner.rs`), and `line_share` is
                    // sized from the CURRENT link anchor: it grows
                    // mid-job when the learner reads a faster line, or
                    // when a server drops and the per-server share of
                    // the fleet cap widens. A `ConnTarget` above the
                    // spawned fleet wakes nothing, so those raises used
                    // to buy exactly zero sockets while the dashboard's
                    // "using M of N" - which reads the target - said
                    // the fleet had grown.
                    //
                    // Seeded at `base` all the same: the headroom is
                    // slots PARKED in `wait_for_slot`, never dialled,
                    // and `workers_dialling` subtracts them.
                    //
                    // `None` for the knee, unlike the `_` arm: this arm
                    // deliberately runs `base` rather than `applied`
                    // because a live-tune seed is not a knee cap (see
                    // `seed_store` above), and the walker's own clamp
                    // never reads the knee either. Holding the SPAWN to
                    // it would leave a knee'd account with the very
                    // gap this closes - a raise the walker may ask for
                    // and no slot to land it in. Capacity pressure is
                    // what teaches the walker its real limit here.
                    let spawn = crate::conntune::line_cap_spawn_slots(
                        base,
                        headroom_share,
                        uncapped,
                        s.pin_connections,
                        None,
                        now,
                    );
                    (spawn, Some(t))
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
            // TODO 313 item 10: a SPILLED lane is sized by what it can
            // ABSORB, and this is where that ceiling lands. A small job
            // is article-bound rather than socket-bound - twelve
            // articles cannot hold thirty-two sockets however many they
            // are offered - so the governor sized this lane at
            // `min(its remaining articles, what is left of the slice)`
            // and the residue stays with the head or passes to the next
            // job down the queue. The smaller of the two numbers wins,
            // so this can only ever narrow a fleet.
            let conns = match hub.as_ref().and_then(|h| h.spill.lock_ok().clone()) {
                Some(sp) if sp.role == nzbkit::pool::handoff::SpillRole::Lane && sp.sockets > 0 => {
                    conns.min(sp.sockets)
                }
                _ => conns,
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
            // TODO 313: this run's side of a queue spill, installed on
            // the hub by the runner a moment ago for exactly the same
            // reason `handoff` below is. `None` on every install with
            // the switch off, which is every install today.
            let spill = hub.as_ref().and_then(|h| h.spill.lock_ok().clone());
            // A SPILLED lane borrows the account's cap rather than
            // re-pointing it at its own absorption-sized fleet, which
            // would collapse the number in force to one or two and
            // block every acquire on the account (see
            // `ConnBudget::lease_borrowed`). Every other run states the
            // cap, exactly as before.
            let lease = hub
                .as_ref()
                .and_then(|h| h.conn_budget.get())
                .and_then(|b| {
                    let key = nzbkit::pool::handoff::ConnBudget::key(s);
                    match spill.as_ref().map(|sp| sp.role) {
                        Some(nzbkit::pool::handoff::SpillRole::Lane) => b
                            .lease_borrowed(&key)
                            .or_else(|| Some(b.lease(&key, conns))),
                        _ => Some(b.lease(&key, conns)),
                    }
                });
            let handoff = hub.as_ref().and_then(|h| h.handoff.lock_ok().clone());
            // A spilled lane takes its permits as a class that YIELDS to
            // the head reclaiming them (`handoff::LeaseClass::Spill`).
            // Read off the seat rather than passed in beside it, so the
            // class and the role can never disagree about which job
            // this is.
            let lease_class = match spill.as_ref().map(|sp| sp.role) {
                Some(nzbkit::pool::handoff::SpillRole::Lane) => {
                    nzbkit::pool::handoff::LeaseClass::Spill
                }
                _ => nzbkit::pool::handoff::LeaseClass::Download,
            };
            // TODO 313: publish this row's target so the spill governor
            // can reach it. A LANE publishes nothing - see the field.
            if let (Some(h), Some(t)) = (hub.as_ref(), live_target.as_ref())
                && spill.as_ref().map(|sp| sp.role) != Some(nzbkit::pool::handoff::SpillRole::Lane)
            {
                h.job_targets.lock_ok().push(t.clone());
            }
            let cfg = PoolConfig {
                connections: conns,
                live_target,
                lease,
                lease_class,
                spill,
                handoff,
                line_cap_fleet: line_cap,
                line_cap_auto,
                // Only what the fleet cap may cut, so a pinned server
                // contributes nothing: see `cap_exposed`. The value it
                // wraps is `dialable`, the knee-INCLUDED counterfactual
                // (28 Aug 2026), not the pre-knee `uncapped` the spawn
                // headroom asks for.
                line_cap_uncapped: cap_exposed(s.pin_connections, dialable),
                line_cap_knee,
                line_anchor_bps: anchor_bps,
                line_anchor_measured: anchor_measured,
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
                // §5.7, and the one place the economics meet the pool:
                // per-server, never OR-folded across the fleet, because
                // the whole point of the setting is that one account's
                // billing says nothing about another's.
                //
                // `may_spend_on_measurement()` and NOT the bare
                // `block_account` flag, which is what this read until
                // 27 Aug 2026. Every other spend decision in the tree
                // asks that predicate - `check.rs::probe_order`,
                // `nettools`' capability probes, `scan`'s header sweep -
                // and it honours BOTH the explicit flag and the older
                // inference from a configured prepaid block, which the
                // config's own test states outright ("a configured block
                // is metered even without the flag"). The pool asked the
                // narrower question, so a server declared only by its
                // Block size reached the racing gates as UNMETERED: it
                // was protected from header scans and connection ladders
                // and then raced for duplicate BODIES at per-gigabyte
                // rates, which is the expensive half. Measured on
                // origin/main that day - `{"block_bytes":500000000000}`
                // came out of this builder with `may_spend_on_measurement
                // = false` beside `block_account = false`.
                //
                // That config is the one the server editor's own hint
                // asks for ("Block size (GB) ... give it a tier of 1 or
                // more"), and a tier is the only thing that was actually
                // stopping the spend - `speculative_blocked` is
                // `level > 0 || flagged`, so a block account left at the
                // default level 0 had neither guard. Design and the
                // routing half that is NOT fixed here:
                // research/BLOCK-ACCOUNT-ECONOMICS-2026-08-27.md.
                block_account: !s.may_spend_on_measurement(),
                // TODO 313 item 7: a WHOLE-FLEET allowance, so every
                // server carries the same number and `Surge::new`
                // MAX-folds it - the fleet cap's own shape. Never a
                // per-server row: the question the surge answers ("a
                // socket is stuck and nothing is idle to race it") is
                // asked of the fleet, and the loan is bounded by the
                // fleet's own spawn ceilings wherever it lands.
                surge_max,
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
                // the same value in every server's config...
                inflight_cap: budget.inflight_cap(),
                // TODO 275 item 10: the consumer-pressure ceiling the
                // fleet governor refuses to grow past the first fleet
                // ceiling against. Same shape as `inflight_cap` above:
                // a process-wide budget figure, read once at build.
                holds_cap: budget.holds_cap() as u64,
                // ...and the ledger it is compared against is the
                // PROCESS's, not this fleet's. The cap is one slice of
                // one budget, while two fleets run concurrently as
                // ordinary business: the queue hand-over dials job N+1
                // while job N drains, and the prefetch sidecar runs
                // beside the active job. Charged per pool, each was
                // correctly under "the" cap while the wire held twice
                // it (TODO 313 item 1).
                wire_charge: nzbkit::pool::process_wire_charge(),
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
    attach_live_and_oracle(&mut servers, hub, job_posted, job_family);
    Fleet {
        buf_pool,
        out_pool,
        servers,
    }
}

/// Say what the cap IS and what it is capping, not just a bare
/// number. `connection auto-tune: news.example.com 6` was the entire
/// explanation a v1.0.14 tester had for why the 24 he had typed into
/// Settings never took effect, and it read as a status line rather
/// than as "something overrode you". Name the asked-for count and
/// the switch that turns it off.
///
/// Split out of [`build_fleet`] under the size gate's 500-line function
/// ceiling (31 Aug 2026), body verbatim. One subject: everything the log
/// says about a knee, and nothing that decides one - `cap_state` is
/// private to the two notes and was never read anywhere else.
///
/// Silent under `live_tune`, both notes, for the reason each carries: a
/// knee SEEDS rather than caps there, and announcing a cap that is not
/// being applied is the same lie the pinned-server exclusion avoids.
fn announce_knee_caps(
    servers: &[ServerConfig],
    tuned: &std::collections::HashMap<String, crate::conntune::Tuned>,
    connections: usize,
    now: u64,
    line_share: Option<usize>,
    line_cap: usize,
    live_tune: bool,
) {
    // Would a stored knee cap this host, and how old is the number doing
    // it? Both notes below need the same answer, so it is computed once.
    // A pinned server is not capped, so it must not be announced as
    // capped - these lines are the ONLY explanation a user gets for a
    // number they did not choose, and printing one for a number they DID
    // choose is worse than printing nothing.
    let cap_state = |s: &ServerConfig| {
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
    let tuned_note: Vec<String> = servers
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
            // And say when this knee, not the fleet cap, is the thing
            // that binds; see `conntune::knee_under_cap_note`.
            let under_cap =
                crate::conntune::knee_under_cap_note(t.connections, line_share, line_cap);
            Some(format!(
                "{} capped at {} of {asked}, probed {age} ago{overdue}{under_cap}",
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
    let expired_note: Vec<String> = servers
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
}

/// TODO 313 item 8: say when the standing reserve is not the number the
/// user configured.
///
/// "The configured count is a REQUEST bounded by the available gap, not
/// a guarantee" - and the precedent for saying so out loud is the memory
/// topic `nzbfast-redeploy-resets-server-enables`: a setting quietly
/// different from what somebody configured is how they lose an evening
/// working out why. Silent when the two agree, and silent when nothing
/// was asked for, so an install with the feature off never sees a word
/// of it.
///
/// Reads the LAST tick's report, which on the first job of a daemon's
/// life is empty - the reserve has not run yet and has nothing to
/// report. That is the right silence: a shortfall nobody has measured is
/// not a shortfall.
fn announce_warm_reserve(reserve: &nzbkit::warmreserve::WarmReserve) {
    let note: Vec<String> = reserve
        .status()
        .into_iter()
        .filter(nzbkit::warmreserve::ReserveStatus::shortfall)
        .map(|s| {
            format!(
                "{}: {} of the {} warm spare connections you asked for ({})",
                s.host,
                s.effective,
                s.configured,
                s.note.as_str()
            )
        })
        .collect();
    if !note.is_empty() {
        info!(target: "tune", "warm reserve: {}", note.join(" · "));
    }
}

/// Bring the warm cache in line with this job's config, then read the
/// per-host caps and budgets the hub carries for it.
///
/// Split out of [`build_fleet`] under the size gate's 500-line function
/// ceiling (31 Aug 2026), body verbatim. The reconcile has to happen
/// FIRST and in the same step, which is why one function: both maps
/// below are read off the same hub the reconcile has just settled, and a
/// job that read them before retiring the stale sessions would size its
/// pools against a provider cap those sessions still occupy.
///
/// Both maps are empty off a CLI run, which has no hub.
async fn hub_host_limits(
    hub: &Option<Arc<StreamHub>>,
    servers: &[ServerConfig],
) -> (
    std::collections::HashMap<String, usize>,
    std::collections::HashMap<String, u64>,
) {
    // Config is reloaded for every daemon job, while the warm pool lives
    // across jobs. Reconcile the cache before building the new fleet so
    // sessions authenticated with a removed password/user, proxy or bind
    // address stop occupying the provider's connection cap immediately.
    if let Some(warm) = hub.as_ref().and_then(|h| h.warm()) {
        warm.retain_servers(servers).await;
        // Idle release is settled PER SERVER and read straight off the
        // config this job is about to use, so a provider added, removed
        // or re-tuned since the last job is reflected before any of its
        // connections are parked.
        warm.set_release_policies(servers);
    }
    // TODO 313 item 8: and the standing warm reserve is pointed at the
    // same config, at the same seam and for the same reason - a server
    // removed, disabled or switched to a block account since the last
    // job must stop being held warm before this job's fleet is sized
    // against an account those spares are occupying.
    //
    // Created on first use here rather than at boot, because it is
    // exactly the two things this seam already has: the hub's warm pool
    // and its connection budget. It is inert on every install that has
    // configured no reserve, which is every install by default.
    if let Some(reserve) = hub.as_ref().and_then(|h| h.warm_reserve()) {
        reserve.set_servers(servers);
        announce_warm_reserve(&reserve);
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
    (host_caps, host_budgets)
}

/// Hang the per-server live gauges and the M29 outcome sink on a built
/// fleet.
///
/// Split out of [`build_fleet`] under the size gate's 500-line function
/// ceiling (31 Aug 2026), body verbatim. Last, and after every pool
/// config is settled: `LiveStats::for_servers` mints each row's key off
/// this list in this order, and the oracle's context is the same host
/// order.
fn attach_live_and_oracle(
    servers: &mut [(ServerConfig, PoolConfig)],
    hub: &Option<Arc<StreamHub>>,
    job_posted: Option<i64>,
    job_family: &str,
) {
    // Per-server live gauges for the dashboard (workers update, API reads).
    let pool_live = nzbkit::pool::LiveStats::for_servers(servers);
    for (_, cfg) in servers.iter_mut() {
        cfg.live = Some(pool_live.clone());
    }
    if let Some(h) = hub {
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

    /// A server declared ONLY by its Block size is metered to the pool
    /// too, and this is the case that was wrong until 27 Aug 2026.
    ///
    /// `ServerConfig::may_spend_on_measurement` is the tree's one answer
    /// to "do these bytes cost money", and it deliberately honours two
    /// things: the explicit `block_account` flag, and the older
    /// inference from a configured prepaid block. Every other spend
    /// decision asks it. This builder asked for the FLAG alone, so a
    /// `{"block_bytes": 500e9}` server with no flag reached the racing
    /// gates as an unlimited backbone - kept off header scans and
    /// connection ladders by the predicate, and then raced for duplicate
    /// BODIES at per-gigabyte rates by the gate that never saw it.
    /// `speculative_blocked` is `level > 0 || flagged`, so at the
    /// default level 0 that config had NEITHER guard, and it is exactly
    /// the config the server editor's Block size hint asks a user to
    /// create.
    ///
    /// The flat server in the same fleet is the other half of the
    /// assertion: this must stay a reading of each server's own
    /// economics, never an OR-fold that a single block account drags the
    /// whole fleet into.
    #[tokio::test]
    async fn a_block_size_alone_reaches_the_pool_as_metered() {
        let cfg: Config = serde_json::from_str(
            r#"{"servers":[
                 {"host":"flat.example"},
                 {"host":"blockonly.example","block_bytes":500000000000},
                 {"host":"flagged.example","block_account":true}
               ]}"#,
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("nzbfast-ba-size-{}", std::process::id()));
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
                ("blockonly.example".to_string(), true),
                ("flagged.example".to_string(), true),
            ],
            "a configured block is metered to the pool even without the flag"
        );
        // The pool's reading and the predicate every other spend
        // decision asks must not be able to part company again.
        for (s, p) in fleet.servers.iter() {
            assert_eq!(
                p.block_account,
                !s.may_spend_on_measurement(),
                "{}: the pool must read metered exactly as the rest of \
                 the tree does",
                s.host
            );
        }
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

    /// TODO 275 item 7, OWED 3: the SEED half of the second ceiling has
    /// never run measured. Same config, same line as
    /// `a_ten_gig_anchor_spawns_exactly_what_it_dials`, one bit
    /// flipped - `line_anchor_measured` true - so
    /// `line_cap_headroom_fleet` follows `LINE_CAP_SUPPLY_MAX_FLEET`
    /// (100) rather than `LINE_CAP_MAX_FLEET` (50):
    /// `server_share(100, 5)` is 20 where `server_share(50, 5)` is 10.
    /// The TARGET must not move - `fleet_for_carry` still clamps the
    /// seed at the first ceiling - only the spawn widens, so the in-run
    /// governor has a parked slot to wake if it ever raises this fleet
    /// past 50.
    #[tokio::test]
    async fn a_measured_ten_gig_anchor_spawns_the_supply_ceilings_headroom() {
        let hub = Arc::new(StreamHub {
            line_anchor_bps: std::sync::atomic::AtomicU64::new(1_250_000_000),
            line_anchor_measured: std::sync::atomic::AtomicBool::new(true),
            ..Default::default()
        });
        let got = build(&five(), &Some(hub)).await;
        assert!(
            got.iter().all(|(h, spawned, target)| if h == "e.example" {
                *spawned == 100 && target.is_none()
            } else {
                *spawned == 20 && *target == Some(10)
            }),
            "{got:?}"
        );
    }

    /// Sweep 9, finding 6: the SETTING's arm gets the same headroom.
    ///
    /// `live_tune` on takes an arm of its own in this builder - it
    /// seeds a hub-shared `ConnTarget` from the time-of-day store
    /// rather than minting one per job - and TODO 277's spawn headroom
    /// was only ever written on the other arm, on the reading that the
    /// setting is off by default. It ships, though, and when it is on
    /// the in-run governor is the epoch WALKER, whose clamp
    /// (`tasks/tuner.rs`) is sized from the CURRENT link anchor:
    /// it grows mid-job when the learner reads a faster line or a
    /// server drops out of the fleet. Every one of those raises landed
    /// on a target above the spawned fleet and woke nothing.
    ///
    /// Same numbers as `the_curves_floor_dials_five_per_server_and_a_pin_wins`
    /// deliberately: the two arms must seed and spawn alike, and the
    /// pinned server must still escape both.
    #[tokio::test]
    async fn the_live_tune_arm_spawns_the_ceiling_too() {
        let hub = Arc::new(StreamHub {
            line_anchor_bps: std::sync::atomic::AtomicU64::new(12_500_000),
            live_tune: std::sync::atomic::AtomicBool::new(true),
            ..Default::default()
        });
        let got = build(&five(), &Some(hub)).await;
        let want: Vec<(String, usize, Option<usize>)> = ["a", "b", "c", "d"]
            .iter()
            .map(|h| (format!("{h}.example"), 10, Some(5)))
            .chain(std::iter::once(("e.example".to_string(), 100, None)))
            .collect();
        assert_eq!(
            got, want,
            "the live_tune arm must spawn the ceiling's share and dial the curve's"
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

#[cfg(test)]
mod seed_evidence_tests {
    use super::*;

    fn mbit(m: u64) -> u64 {
        m * 1_000_000 / 8
    }

    /// TODO 275 item 9: the seed's cap line has to say what it sized
    /// from, because the fleet size cannot be attributed from itself.
    ///
    /// Four regimes, and the pair that matters is the last two: the
    /// SAME line and the SAME fleet, one reached by the curve alone and
    /// one lifted by a banked carry. Before this, those two printed
    /// identical lines, which is the whole of the item - a
    /// GH #62-shaped report arrives with a fleet size and no way to
    /// tell a good banked number from a stale one.
    #[test]
    fn the_cap_line_says_what_the_seed_sized_from() {
        // A typed fleet: neither candidate ran, so neither number is
        // about this fleet and the line must not offer one.
        let typed = seed_evidence(mbit(1_000), true, mbit(10), 0);
        assert_eq!(typed, "the fleet size you named");
        assert!(
            !typed.contains("wants") && !typed.contains("Mbit"),
            "a typed fleet must not be described by numbers that lost nothing: {typed}"
        );

        // No carry banked yet - a fresh install, or a daemon whose
        // first job has not finished. Said out loud rather than left as
        // a missing clause, which reads as a carry of zero.
        let fresh = seed_evidence(mbit(1_000), true, 0, 25);
        assert!(fresh.contains("no per-socket carry banked yet"), "{fresh}");
        assert!(fresh.contains("the line alone wants 25"), "{fresh}");

        // The two that used to be indistinguishable. Same line, same
        // resulting fleet, different reason.
        let curve_only = seed_evidence(mbit(9_000), true, mbit(200), 50);
        let carry_lifted = seed_evidence(mbit(1_000), true, mbit(10), 25);
        assert_ne!(
            curve_only, carry_lifted,
            "the two candidates must not print the same sentence"
        );
        assert!(
            curve_only.contains("the line alone wants 50"),
            "{curve_only}"
        );
        assert!(
            carry_lifted.contains("the line alone wants 25"),
            "and a reader compares that against the fleet on the same line: {carry_lifted}"
        );
        assert!(
            carry_lifted.contains("one socket last measured at 10.0 Mbit"),
            "{carry_lifted}"
        );

        // The anchor's provenance, which decides a ceiling since item 7
        // and appears nowhere else on a run that never raises.
        assert!(seed_evidence(mbit(1_000), true, 0, 25).contains("measured line"));
        assert!(seed_evidence(mbit(1_000), false, 0, 25).contains("typed line"));
    }

    /// The bench rig's fleet guard matches the line's HEAD and splits it
    /// by field position, so everything this item added has to sit
    /// behind `across N servers`.
    ///
    /// Asserted here rather than left to the harness, because the
    /// harness runs elsewhere and this file is what a lane edits: a
    /// round that silently stopped recording the fleet budget would be
    /// discovered by whoever next read a leg table, weeks later.
    #[test]
    fn the_evidence_never_reaches_the_head_the_bench_guard_parses() {
        for (measured, carry, curve) in [(true, mbit(10), 25), (false, 0, 50), (true, 0, 0)] {
            let ev = seed_evidence(mbit(1_000), measured, carry, curve);
            // The guard's regex ends at `servers`; anything this
            // function emits is appended after it, so it must not carry
            // a fragment that could be mistaken for that head.
            assert!(
                !ev.contains("fleet cap") && !ev.contains(" of "),
                "the evidence clause must not restate the guard's head: {ev}"
            );
        }
    }
}

#[cfg(test)]
mod row_identity {
    use super::*;

    /// One temp directory per case, and no settings.json in it - so
    /// every knob resolves to the shipped default and no conntune store
    /// exists to seed a live target from.
    async fn build(cfg: &Config, hub: &Option<Arc<StreamHub>>, tag: &str) -> Fleet {
        let dir = std::env::temp_dir().join(format!("nzbfast-rowid-{tag}-{}", std::process::id()));
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
    }

    /// TWO ACCOUNTS ON ONE PROVIDER GET TWO LIVE TARGETS.
    ///
    /// `hub.live_targets` was keyed by `s.host`, and two rows on one
    /// hostname are supported and tested
    /// (`nzbkit`'s `duplicate_host_entries_edge_trigger_independently`) -
    /// a big flat-rate account beside a small block fill at the same
    /// provider is the ordinary shape. So the second row found the
    /// first's handle, and the `t.get() > base` clamp just below the
    /// `entry()` call then pulled the SHARED target down to the smaller
    /// account's ceiling: the 24-connection account parked at 4 sockets.
    /// Re-applied on every job build, so a walk-up the epoch controller
    /// earned during job N was undone at the start of job N+1.
    ///
    /// The 10 Gbit anchor is here to keep the fleet cap out of the way -
    /// its per-server share at two servers is well above 24 - so the
    /// only thing that can move these numbers is the aliasing.
    ///
    /// Asserted by Arc IDENTITY as well as by value, per the house rule:
    /// an equality-only test passes on the copying implementation, and
    /// the defect here IS sharing.
    #[tokio::test]
    async fn two_accounts_on_one_host_do_not_share_a_live_target() {
        let cfg: Config = serde_json::from_str(
            r#"{"servers":[
                 {"host":"dup.example","connections":24},
                 {"host":"dup.example","connections":4}
               ]}"#,
        )
        .unwrap();
        let hub = Arc::new(StreamHub {
            line_anchor_bps: std::sync::atomic::AtomicU64::new(1_250_000_000),
            live_tune: std::sync::atomic::AtomicBool::new(true),
            ..Default::default()
        });
        let fleet = build(&cfg, &Some(hub.clone()), "dup").await;
        let targets: Vec<Arc<nzbkit::pool::ConnTarget>> = fleet
            .servers
            .iter()
            .map(|(s, p)| {
                p.live_target
                    .clone()
                    .unwrap_or_else(|| panic!("{} got no live target", s.host))
            })
            .collect();
        assert!(
            !Arc::ptr_eq(&targets[0], &targets[1]),
            "the two accounts must not share one ConnTarget"
        );
        assert_eq!(
            targets.iter().map(|t| t.get()).collect::<Vec<_>>(),
            vec![24, 4],
            "each account keeps its own base - the small one must not \
             clamp the large one"
        );
        assert_eq!(
            hub.live_targets.lock_ok().len(),
            2,
            "one entry per configured account, not per hostname"
        );
        // And the identity really is the row: the same fleet rebuilt on
        // the same hub reuses both handles rather than minting new ones,
        // which is the whole reason the map lives on the hub.
        let again = build(&cfg, &Some(hub.clone()), "dup2").await;
        for (i, (_, p)) in again.servers.iter().enumerate() {
            assert!(
                Arc::ptr_eq(p.live_target.as_ref().unwrap(), &targets[i]),
                "row {i}'s belief must survive the job boundary"
            );
        }
        assert_eq!(hub.live_targets.lock_ok().len(), 2);
    }

    /// A PINNED SERVER IS NOT SOMETHING THE FLEET CAP CAN CUT.
    ///
    /// `line_cap_uncapped` is summed by `linecap::seed_uncapped` into
    /// `LiveStats::line_cap_configured`, whose only consumer is
    /// whyslow's `fleet_bound`, and that arm fires on `configured >
    /// cap` - i.e. "the cap is taking sockets away". `pin_connections`
    /// is the documented escape from the cap (this builder skips
    /// `line_share` for it and keeps the user's own number), so a
    /// pinned account's ceiling in that sum was a claim the cap was
    /// cutting something it had never touched: one server pinned to 50
    /// under a fleet typed to 25 got reported as held back by the cap
    /// the pin had already lifted, with an offer to raise it.
    ///
    /// The unpinned rows in the same fleet are the other half of the
    /// assertion - this must stay a reading of each row's own exposure
    /// to the cap, never a fleet-wide fold.
    #[tokio::test]
    async fn a_pinned_server_is_not_something_the_cap_can_cut() {
        let hub = Arc::new(StreamHub {
            line_anchor_bps: std::sync::atomic::AtomicU64::new(12_500_000),
            ..Default::default()
        });
        // `line_cap_seed::five()`'s shape, spelled out here rather than
        // reached for across the module wall: four ordinary accounts and
        // one pinned, all at 100.
        let cfg: Config = serde_json::from_str(
            r#"{"servers":[
                 {"host":"a.example","connections":100},
                 {"host":"b.example","connections":100},
                 {"host":"c.example","connections":100},
                 {"host":"d.example","connections":100},
                 {"host":"e.example","connections":100,"pin_connections":true}
               ]}"#,
        )
        .unwrap();
        let fleet = build(&cfg, &Some(hub), "pin").await;
        let got: Vec<(String, usize)> = fleet
            .servers
            .iter()
            .map(|(s, p)| (s.host.clone(), p.line_cap_uncapped))
            .collect();
        let want: Vec<(String, usize)> = ["a", "b", "c", "d"]
            .iter()
            .map(|h| (format!("{h}.example"), 100))
            .chain(std::iter::once(("e.example".to_string(), 0)))
            .collect();
        assert_eq!(
            got, want,
            "only what the cap is ALLOWED to cut belongs in the sum"
        );
        // The whole point of the field: the fleet's own claim. Four
        // unpinned accounts at 100 apiece, and the pin contributing
        // nothing.
        assert_eq!(got.iter().map(|(_, n)| n).sum::<usize>(), 400);
    }
}

#[cfg(test)]
mod knee_under_the_fleet_cap {
    use super::*;

    /// A knee UNDER the fleet cap's share must not leave the pool
    /// publishing a fleet nothing was ever going to dial.
    ///
    /// `PoolConfig::line_cap_uncapped` is a counterfactual - what this
    /// server would dial with the fleet cap taking nothing out - and it
    /// is the denominator of TODO 312 item 3's whyslow verdict, which
    /// fires on `configured > cap`. Fed the ceilings WITHOUT the knee it
    /// answers 40 here while the pool dials 20 and would still dial 20
    /// with the cap switched off entirely: the cap costs this server
    /// nothing, and the number said it cost twenty sockets.
    ///
    /// The fixture is the shape TODO 275's 5 Gbit ladder hit
    /// (`research/KNEE-UNDER-FLEET-CAP-2026-08-28.md`), reduced so the
    /// knee sits under the cap rather than over it: rungs of 50, 77 and
    /// 100 all ran 32 sockets and landed within 0.4 MB/s of each other,
    /// and every instrument read clean while it happened.
    #[tokio::test]
    async fn a_knee_below_the_cap_share_is_in_the_published_ceiling() {
        // The fleet cap arm is selected by the environment on every
        // §208-family bench leg, and it outranks the setting this
        // fixture writes; under one of those shells the fixture is not
        // the configuration under test. Same for live tuning, where the
        // knee seeds instead of capping.
        for k in ["NZBFAST_LINE_CAP", "NZBFAST_LIVE_TUNE"] {
            if std::env::var_os(k).is_some() {
                eprintln!("skipped: {k} overrides the fixture");
                return;
            }
        }
        let dir = std::env::temp_dir().join(format!("nzbfast-knee-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.local.json");
        // Written, never inherited: an absent config sends
        // `Config::load` hunting for a SABnzbd install in $HOME, which
        // is this box and not this test (tools/host-config-gate.py).
        std::fs::write(
            &config,
            r#"{"servers":[{"host":"knee.example","connections":40}]}"#,
        )
        .unwrap();
        // A fleet cap of 25 for one server: a 25-socket share, above
        // the knee below it.
        std::fs::write(
            config.with_file_name("settings.json"),
            r#"{"line_cap_fleet":25}"#,
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Fresh, corroborated, and well inside EXPIRE_SECS: this is a
        // knee the product applies, not a stale one being argued about.
        std::fs::write(
            config.with_file_name("conntune.json"),
            format!(
                r#"{{"knee.example":{{"connections":20,"granted":20,"gbps":1.0,"checked":{now},"source":"manual"}}}}"#
            ),
        )
        .unwrap();
        let cfg: Config = serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
        let fleet = build_fleet(
            &cfg,
            &config,
            40,
            4,
            &None,
            None,
            "",
            &nzbkit::mem::MemBudget::with_total(1 << 30),
        )
        .await;
        let got = &fleet.servers[0].1;
        assert_eq!(
            got.connections, 20,
            "the knee is what this fleet dials; the fixture is wrong if it is not"
        );
        assert_eq!(
            got.line_cap_uncapped, 20,
            "line_cap_uncapped must be what this server would dial with the FLEET CAP \
             taking nothing out, which still has the knee in it - published as {} it \
             convicts our own cap of holding back sockets the account never granted",
            got.line_cap_uncapped
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One fixture for the two `line_cap_knee` cases below: one server
    /// at 40 connections under a fleet cap of 25, with whatever
    /// `conntune.json` the caller wants, built into its own directory.
    ///
    /// Written and never inherited, like the two cases above: an absent
    /// config sends `Config::load` hunting for a SABnzbd install in
    /// $HOME, which is this box and not this test
    /// (`tools/host-config-gate.py`).
    async fn built_with(tag: &str, conntune: &str) -> nzbkit::pool::PoolConfig {
        let dir = std::env::temp_dir().join(format!("nzbfast-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.local.json");
        std::fs::write(
            &config,
            r#"{"servers":[{"host":"knee.example","connections":40}]}"#,
        )
        .unwrap();
        std::fs::write(
            config.with_file_name("settings.json"),
            r#"{"line_cap_fleet":25}"#,
        )
        .unwrap();
        std::fs::write(config.with_file_name("conntune.json"), conntune).unwrap();
        let cfg: Config = serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
        let fleet = build_fleet(
            &cfg,
            &config,
            40,
            4,
            &None,
            None,
            "",
            &nzbkit::mem::MemBudget::with_total(1 << 30),
        )
        .await;
        let got = fleet.servers[0].1.clone();
        let _ = std::fs::remove_dir_all(&dir);
        got
    }

    /// A `conntune.json` whose one knee of 20 was measured `age_secs`
    /// ago, so a case can name the age it is really about rather than a
    /// timestamp a reader has to do arithmetic on.
    fn knee_json(age_secs: u64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let checked = now - age_secs;
        format!(
            r#"{{"knee.example":{{"connections":20,"granted":20,"gbps":1.0,"checked":{checked},"source":"manual"}}}}"#
        )
    }

    /// TODO 312 item 7: a STALE knee under the cap's share must reach
    /// the pool as one, with the figure lifting it would really buy.
    ///
    /// THE NUMBER IS 5 AND NOT 20, which is the whole point of measuring
    /// `takes` against the POST-cap ceiling. The account allows 40, the
    /// fleet cap's share is 25, the knee is 20: lifting the knee gets
    /// this server to 25, not to 40, and the larger figure would be a
    /// promise the product cannot keep. `takes > 0` is also the only
    /// statement whyslow's `knee_bound` needs of the ordering - it IS
    /// "the knee, not the cap, is the lower of the two".
    #[tokio::test]
    async fn a_stale_knee_reaches_the_pool_with_what_lifting_it_would_buy() {
        for k in ["NZBFAST_LINE_CAP", "NZBFAST_LIVE_TUNE"] {
            if std::env::var_os(k).is_some() {
                eprintln!("skipped: {k} overrides the fixture");
                return;
            }
        }
        let got = built_with(
            "stale-knee",
            &knee_json(crate::conntune::STALE_SECS + 86_400),
        )
        .await;
        assert_eq!(
            got.connections, 20,
            "the knee is what this fleet dials; the fixture is wrong if it is not"
        );
        let k = got
            .line_cap_knee
            .expect("a knee eight days past its re-probe appointment is stale");
        assert_eq!(k.at, 20, "the knee itself, as the Providers card shows it");
        assert_eq!(
            k.takes, 5,
            "sockets lifting the knee would really buy: the cap's share of 25 \
             less the knee of 20, never the account's 40 less the knee"
        );
        assert!(
            k.age_secs >= crate::conntune::STALE_SECS,
            "the age travels with it: {}",
            k.age_secs
        );
    }

    /// The negative control, and the one this arm cannot do without: the
    /// SAME knee, same cap, same account, measured an hour ago. It is
    /// still what the fleet dials - `connections` is 20 either way - and
    /// it must reach the pool as NO claim, because a fresh knee is
    /// auto-tune doing its job and convicting it would train users to
    /// switch the thing off. See `conntune::stale_knee` for the argument.
    #[tokio::test]
    async fn a_fresh_knee_is_not_a_claim_however_hard_it_binds() {
        for k in ["NZBFAST_LINE_CAP", "NZBFAST_LIVE_TUNE"] {
            if std::env::var_os(k).is_some() {
                eprintln!("skipped: {k} overrides the fixture");
                return;
            }
        }
        let got = built_with("fresh-knee", &knee_json(3_600)).await;
        assert_eq!(got.connections, 20, "it still binds - that is the point");
        assert!(
            got.line_cap_knee.is_none(),
            "a knee inside its re-probe appointment is a measurement we stand by"
        );
    }

    /// The other direction, so the assertion above cannot be satisfied
    /// by a builder that simply reports the number it dialled: with no
    /// knee on file the ceiling is the account's own number, ABOVE the
    /// cap that is holding the fleet down, and the difference between
    /// the two is the claim TODO 312 item 3 exists to make.
    #[tokio::test]
    async fn with_no_knee_the_published_ceiling_is_still_above_the_cap() {
        for k in ["NZBFAST_LINE_CAP", "NZBFAST_LIVE_TUNE"] {
            if std::env::var_os(k).is_some() {
                eprintln!("skipped: {k} overrides the fixture");
                return;
            }
        }
        let dir = std::env::temp_dir().join(format!("nzbfast-nokneecap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.local.json");
        std::fs::write(
            &config,
            r#"{"servers":[{"host":"knee.example","connections":40}]}"#,
        )
        .unwrap();
        std::fs::write(
            config.with_file_name("settings.json"),
            r#"{"line_cap_fleet":25}"#,
        )
        .unwrap();
        let cfg: Config = serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
        let fleet = build_fleet(
            &cfg,
            &config,
            40,
            4,
            &None,
            None,
            "",
            &nzbkit::mem::MemBudget::with_total(1 << 30),
        )
        .await;
        let got = &fleet.servers[0].1;
        assert_eq!(
            got.connections, 25,
            "the fleet cap's share is what binds here"
        );
        assert_eq!(
            got.line_cap_uncapped, 40,
            "with nothing else capping, the published ceiling is the account's own number"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
