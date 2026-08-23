//! The settings.json + env-var knob reads that `build_fleet` folds into
//! every server's `PoolConfig`. Hoisted out of `fleet.rs` verbatim on
//! 22 Aug 2026 because `fn build_fleet` sat five lines under the size
//! gate's 500-line function ceiling, so the next knob anyone added would
//! have reddened main (TODO 106 pattern, as `check_sweep.rs`,
//! `check_tests.rs` and `extract/names.rs`). Behaviour unchanged: this is
//! `build_fleet`'s own child module, glob-imported back, and every read
//! keeps its precedence (env overrides setting PER KNOB, "1"/"2" arms),
//! its default and its comment block exactly as they were - only the
//! bindings became struct fields.

use super::*;

/// One run's resolved knobs, in the order `build_fleet` used to bind
/// them. Field names match the local bindings the inline code used, so
/// `build_fleet` destructures this and the `PoolConfig` literal reads
/// as it always did.
pub(super) struct FleetKnobs {
    pub(super) read_timeout: std::time::Duration,
    pub(super) adaptive_timeout: bool,
    pub(super) tail_fanout: bool,
    pub(super) tail_fanout_early: bool,
    pub(super) hedge: bool,
    pub(super) ttfb_hedge: bool,
    pub(super) outage_budget: Option<std::time::Duration>,
    pub(super) recycle_slope: bool,
    pub(super) recycle_slow: bool,
    pub(super) hot_spare: bool,
    pub(super) steer_depth: bool,
    pub(super) tail_taper: bool,
    pub(super) race_envelope: bool,
    pub(super) race_sat_pct: u8,
    pub(super) race_escape: bool,
    pub(super) stall_live: bool,
    pub(super) peak_arrivals: bool,
    pub(super) flap_cap_keepers: bool,
    pub(super) crc_steer: bool,
}

/// An on-by-default A/B knob: unset, or anything but `0`, is on.
fn env_knob_on(var: &str) -> bool {
    std::env::var(var).ok().is_none_or(|v| v != "0")
}

/// Read every settings.json + env knob `build_fleet` feeds into
/// `PoolConfig`. The comment blocks inside carry the measured findings
/// and graduation rules for each knob; they moved with their reads.
pub(super) fn read_knobs(cfg_all: &Config, config: &Path) -> FleetKnobs {
    // Stall-detection timeout; env override exists for the chaos suite
    // (a mock stall shouldn't cost a test 30 wall-clock seconds).
    let read_timeout = std::env::var("NZBFAST_READ_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or_else(|| PoolConfig::default().read_timeout);
    // Both tail knobs read the one settings.json the dashboard writes
    // (same loader as conntune::enabled, so the daemon and the CLI
    // agree); the env vars override PER KNOB in either direction - the
    // bench suite A/Bs single knobs against a live setting ("1"/"2"
    // arms, anything else disarms).
    let saved = crate::persist::load_json_with_backup(&config.with_file_name("settings.json"));
    // The unset-setting defaults for both switches come from
    // `PoolConfig::shipped()`, so "what the daemon ships" has ONE
    // definition that test fleets can build from as well - a rig that
    // takes `PoolConfig::default()` measures a pool with the whole
    // speculation layer dark.
    let ship = PoolConfig::shipped();
    // "Adaptive connection timeouts" (setting adaptive_timeouts, ON by
    // default): two-phase adaptive read bounds in place of the flat
    // whole-response timeout. Fault rigs (research/SPECULATION-
    // EXPERIMENTS-2026-08-04.md rounds 5/5b/5c): 4x on dead-air
    // stalls, stacks on brownout, zero false kills on jitter.
    let adaptive = saved
        .as_ref()
        .and_then(|v| v.get("adaptive_timeouts").and_then(|v| v.as_bool()))
        .unwrap_or(ship.adaptive_timeout);
    let adaptive_timeout = std::env::var("NZBFAST_ADAPTIVE_TIMEOUT")
        .ok()
        .map_or(adaptive, |v| v == "1");
    // "Race slow articles" (setting race_stragglers, ON by default).
    // Covers the three speculation knobs with measured payouts: early
    // tail fan-out (farm: tail 1.66 s -> 0.60 s), adaptive hedging
    // (rig: 12-13 s -> 6-8 s on a stalled article), and slope recycle
    // (rig: 45 s -> 25 s on one degraded session).
    let race = saved
        .as_ref()
        .and_then(|v| v.get("race_stragglers").and_then(|v| v.as_bool()))
        .unwrap_or(ship.tail_fanout);
    let tf = std::env::var("NZBFAST_TAIL_FANOUT").ok();
    let tail_fanout = tf.as_deref().map_or(race, |v| v == "1" || v == "2");
    let tail_fanout_early = tf.as_deref().map_or(race, |v| v == "2");
    let hedge = std::env::var("NZBFAST_HEDGE")
        .ok()
        .map_or(race, |v| v == "1");
    // TODO 115 (dark, env-only): dup-race an article after ~1 s of
    // pre-byte silence instead of waiting out the adaptive TTFB budget
    // (its floor is 2 s, paid serially per stall - the deadair matrix
    // residual). Rides the adaptive read path, so it is inert with
    // adaptive_timeouts off. Graduates the race_stragglers way only
    // with the jitter safety leg and the greet-delay rigs green.
    let ttfb_hedge = std::env::var("NZBFAST_TTFB_HEDGE").is_ok_and(|v| v == "1");
    // "Give up on a dead server after" (setting server_outage_mins,
    // 0 = never). Read from the same settings.json as the knobs above so
    // the CLI and the daemon agree; the env override is for tests, which
    // cannot afford to wait out fifteen real minutes.
    let outage_budget = std::env::var("NZBFAST_SERVER_OUTAGE_MINS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| {
            saved
                .as_ref()
                .and_then(|v| v.get("server_outage_mins").and_then(|v| v.as_u64()))
        })
        .map_or(ship.outage_budget, |m| {
            (m > 0).then(|| std::time::Duration::from_secs(m * 60))
        });
    let recycle_slope = std::env::var("NZBFAST_RECYCLE_SLOPE")
        .ok()
        .map_or(race, |v| v == "1");
    // Still dark (env-only): the race-loss recycle (subsumed by the
    // slope recycle in practice) and the hot spare (needs cap-aware
    // gating first - at an exact provider cap the spare would steal a
    // worker slot). NZBFAST_KEEPALIVE is read directly in the nntp dial
    // path (NZBFAST_DIAL_RACE was too, until §129 3c priced it out).
    let recycle_slow = std::env::var("NZBFAST_RECYCLE_SLOW").is_ok_and(|v| v == "1");
    let hot_spare = std::env::var("NZBFAST_HOT_SPARE").is_ok_and(|v| v == "1");
    // M7b.2 depth steering (dark, env-only): a server whose windowed
    // per-conn rate falls under 1/4 of the best other live server's
    // runs shallow pipelines (depth 1) instead of parking `window`
    // articles behind each slow session. Graduates the race_stragglers
    // way only with the steering rig's A/B and the real-line legs green
    // (research/DESIGN-PROVIDER-STEERING-RACING-2026-08-08.md §7).
    let steer_depth = std::env::var("NZBFAST_STEER_DEPTH").is_ok_and(|v| v == "1");
    // TODO 208 item 3 endgame depth taper (dark, env-only): as the run's
    // remaining work falls toward one article per connection, cap the
    // top-up depth so the fleet reaches queue-dry holding ~1 article
    // each instead of `window` each. The drain after queue-dry is that
    // in-flight set emptying - 1.13-1.62 GB on every banked 1 GbE bench
    // leg, i.e. 16 s at 1 Gbps and 44-46 s at 250 Mbit. That stretch
    // carries payload, not idle time (measured: with the §202 gate
    // armed the drain runs FASTER than the run's pre-dry rate), so this
    // is a robustness bound - the tail is the window in which a wedged
    // connection or an uncapped speculative rule costs the wall, and a
    // quarter-length tail is a quarter-size window. Vacuous until the
    // queue falls under `window x conns`, so the steady state that
    // earns the 10 GbE margins is untouched. Graduates on a measured
    // 1 GbE leg, the race_stragglers way.
    let tail_taper = std::env::var("NZBFAST_TAIL_TAPER").is_ok_and(|v| v == "1");
    // M7b.2 envelope racing (dark, env-only): per-owner hedge bounds,
    // the idle-picker envelope race, and the fleet-wide dup-spend
    // hygiene cap; the whole-run 2x slow-owner rule retires while
    // armed. Same graduation route as steer_depth. The per-server
    // block_account setting (design 5.7) is LANDED and wired into
    // PoolConfig::block_account below, so the economics no longer rest
    // on the level > 0 inference alone.
    let race_envelope = std::env::var("NZBFAST_RACE_ENVELOPE").is_ok_and(|v| v == "1");
    // TODO 202: the line-saturation gate on speculative racing, ON by
    // default at 70% of the run's observed peak (priced on the 1 GbE
    // rig: 425-728 MB of duplicate bodies per 6.5 GB job at 1 Gbps and
    // 250 Mbit, all of it line time on a saturated pipe). 0 = off, the
    // pre-202 behaviour, for A/B legs. Shipped at 80 on 21 Aug from the
    // physics; the TODO 208 item 4 ladder (22 Aug, 250 Mbit, three reps
    // per rung on one binary) moved it to 70: 90 is a cliff (the
    // now-rate cannot hold within 10% of peak on a shaped line's
    // jitter, so racing reopens and gives back 15 of the 24 s §202
    // won), 70 and 80 both sit on the floor with 70 at the bottom of
    // the band and spending least, and the 10 GbE apollo guard reads
    // the two within 0.15 s. 80 is the tested upper margin, not a
    // second default.
    let race_sat_pct = std::env::var("NZBFAST_RACE_SAT_PCT")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .filter(|v| *v <= 100)
        .unwrap_or(ship.race_sat_pct);
    // TODO 202 §17: the gate's per-article escape - an article whose
    // owner has moved NO bytes is raced even while the fleet reads
    // saturated, because it is not competing for the line. ON by
    // default; 0 turns it off. Separate from the knob above on purpose:
    // `race_sat_pct=0` prices the GATE and cannot price the escape (at
    // 0 there is no gate to escape), so pricing the escape needs this
    // arm at `race_sat_pct=80`, on one binary.
    let race_escape = std::env::var("NZBFAST_RACE_ESCAPE")
        .ok()
        .is_none_or(|v| v != "0");
    // TODO 208.2 warm-up: the stall bound is consulted during a
    // silence against whatever line evidence exists, instead of being
    // the flat floor until the run's own peak trains (7 s after the
    // FIRST body, which a 100 Mbit line under 360 connections delivers
    // 10-27 s in). ON by default; 0 is the A/B arm.
    let stall_live = std::env::var("NZBFAST_STALL_LIVE")
        .ok()
        .is_none_or(|v| v != "0");
    // TODO 208.2 over-read: the line gauge is fed per arriving chunk
    // rather than per delivered body, so the first wave's bodies are
    // not credited in a clump to a window that has barely opened (the
    // trained `line peak` over-read the line by 10-35% on every banked
    // shaped leg, and by 74% on the rig). ON by default; 0 is the A/B
    // arm, the per-body fold byte for byte.
    let peak_arrivals = env_knob_on("NZBFAST_PEAK_ARRIVALS");
    // TODO 115, graduated 5 Aug: cap-aware flap keepers - a
    // flap-clamped server whose accept cap was OBSERVED (dials bounced
    // off a capacity refusal) holds min(cap, budget) keepers instead of
    // one, so a provider willing to serve two sessions is not clamped
    // to half of that. Redials stay death-driven and bounce-paced, so
    // dials remain in the single-keeper's order - not the 217-dial
    // hammering the fault matrix measured from NZBGet on this shape.
    // Priced on the standalone chaos flap leg (one box, one corpus):
    // 43/43 s at 24 dials off, 40/40 s at 36 dials on - ties the best
    // competitor's wall at a sixth of its dials. Env overrides either
    // way.
    let flap_cap_keepers = std::env::var("NZBFAST_FLAP_CAP_KEEPERS")
        .ok()
        .is_none_or(|v| v == "1");
    // TODO 111/114 CRC retry-elsewhere, graduated to the consumer seam
    // 6 Aug: on a yEnc CRC failure (or a wrong-article body) the
    // article is refetched from a DIFFERENT server once, instead of
    // letting the damage ride to PAR2 repair - the corrupt-storm
    // matrix leg goes DNF -> byte-perfect, and every competitor
    // already does this. Detection is the decode consumer's EXISTING
    // pass (QueueControl::note_decoded), so the old pool-side second
    // decode - ~25% CPU at the loopback ceiling, the reason slow-CPU
    // boxes were priced out - is gone: the m1 full-rate A/B has the
    // steer at off-parity user CPU (9.3 vs the pool decode's 14.3
    // cpu-s per 8 GB) with equal walls, and the only remaining cost
    // is the forced per-article CRC where M32 delegation would have
    // skipped it (+4.5% user on a PAR2 full-MD5 job, wall parity).
    //
    // Default ON where an elsewhere exists. "2+ enabled servers" is
    // necessary but not sufficient: the steer marks tried_fail, and a
    // fill server's pickup gate demands the primary's 430 bit - so a
    // primary + fill pair can never steer, and a same-host (or same
    // explicit group) sibling serves the same wrong copy. Pay the
    // forced CRC only where a same-LEVEL peer on a different
    // host/backbone exists; the delivery-time other_can_take check
    // enforces the same rule live. Single-server configs pay nothing
    // at all. NZBFAST_CRC_STEER overrides both ways (the chaos rig's
    // same-host twins depend on =1); NZBFAST_CRC_RETRY is honored as
    // an alias - it named the same feature while the detection lived
    // in the pool, and the rig drivers still set it.
    let multi_server = has_steer_peer(&cfg_all.servers);
    let crc_steer = std::env::var("NZBFAST_CRC_STEER")
        .or_else(|_| std::env::var("NZBFAST_CRC_RETRY"))
        .map_or(multi_server, |v| v == "1");
    FleetKnobs {
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
    }
}
