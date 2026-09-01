//! Speed signals for provider steering and racing (M7b.2, §129 perf
//! lane) - the windowed per-server evidence the design doc
//! (research/DESIGN-PROVIDER-STEERING-RACING-2026-08-08.md §3) builds
//! depth steering and envelope racing on. A child module of `pool`
//! (the `pacing.rs` pattern) so pool.rs stays inside its size-gate
//! entry.
//!
//! Two per-server EWMAs, both fed from code paths that already hold
//! the sample - no probes, no threads, no extra clock reads:
//!
//! - `srv_rate`: windowed delivered-byte throughput (~10 s half-life).
//!   The whole-run `rate()` judges "is this owner slow" with evidence
//!   as stale as the run is long - shaping varies by the hour (the
//!   8 Aug Giganews ladder), and on a 30-minute queue the old rule
//!   could still call a recovered provider slow, or miss shaping that
//!   started mid-run entirely.
//! - `srv_art_ms`: the same dispatch-to-done EWMA the global `art_ms`
//!   trains, indexed by the server that OWNED the article.
//!
//! Both feed exclusively from delivered real-content bytes (the
//! `bytes[]` / `deregister_inflight_done` paths), never from probes or
//! synthetic groups: the connladder's synthetic probe group
//! undermeasured xsnews 17x (0.20 vs 3.52 Gbps on real articles, same
//! box, same minute), so a signal that ever mixed probe observations
//! would steer AWAY from the fleet's fastest provider. And no refusal
//! counts anywhere: a 430 storm is legitimate for old posts, and 3f
//! closed refusal-derived state. Speed evidence is bytes and time,
//! nothing else.
//!
//! The mirrors in [`ServerLive`] (`srv_rate`, `srv_rate_at`,
//! `srv_art_ms`, `steered`) are a published contract: the live
//! connection tuner (tuner-v2 design, §4.3 of the steering doc) reads
//! them to tell demand-driven rate drops from shaping knees. Do not
//! rename or filter them - delivered-byte gauges stay demand-inclusive.

use super::*;

/// Half-life of the windowed per-server throughput signal. Long enough
/// that one slow article cannot swing a verdict, short enough to see
/// shaping that starts mid-run (the Giganews ladder decays hour-scale;
/// this reacts in tens of seconds).
const SRV_RATE_HALF_LIFE_MS: u64 = 10_000;

/// The exponential-decay time constant: half-life / ln 2. The
/// accumulator holds delivered bytes convolved with exp(-age/tau), so
/// at a steady delivery rate r it converges to r x tau and
/// `accumulator / tau` reads back r in B/s.
const SRV_RATE_TAU_MS: f64 = SRV_RATE_HALF_LIFE_MS as f64 / std::f64::consts::LN_2;

/// Depth-steering arm threshold: clamp when this server's windowed
/// per-conn rate falls below `arm x` the best OTHER live server's.
/// An engineering guess pending the rig curve (steering design open
/// question 9.3) - env-tunable so the measured value can be found
/// without a rebuild, then hard-coded.
fn steer_arm() -> f64 {
    static V: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_STEER_ARM")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v: &f64| *v > 0.0 && *v < 1.0)
            .unwrap_or(0.25)
    })
}

/// How often [`Shared::note_art_gauges`] may put an article-time sample
/// in the log, in ms. 0 turns the line off entirely (the `RaceLive`
/// mirror still updates - that costs two relaxed stores and is what the
/// daemon's diagnostics read).
///
/// 5 s by default. The gauge is an EWMA over a ~5-sample half-life, so
/// it settles in COMPLETIONS rather than in seconds: on a fleet
/// finishing a hundred articles a second there is nothing a faster
/// sample could show, and on one finishing four an hour there is
/// nothing to sample. 5 s puts a dozen readings inside a 60 s bench
/// leg, which is enough to separate the run from the drain - the whole
/// point of reading it mid-run.
fn art_gauge_ms() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_ART_GAUGE_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5_000)
    })
}

/// Depth-steering disarm threshold (hysteresis - a boundary server must
/// not flap): unclamp when the ratio recovers above this.
fn steer_disarm() -> f64 {
    static V: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_STEER_DISARM")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v: &f64| *v > 0.0 && *v <= 1.0)
            .unwrap_or(0.5)
    })
}

/// The pipeline depth a clamped server tops up to. 1 is the design
/// value (the stream-mode precedent runs the whole fleet there);
/// tunable for the rig's depth curve only.
fn steer_floor() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_STEER_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&w| w >= 1)
            .unwrap_or(1)
    })
}

/// TODO 208 item 3: the depth the endgame taper walks down to. 1 is the design
/// value - one article in service per connection is the shallowest
/// pipeline that still keeps every socket busy - and 2 is the
/// conservative rung (a queued successor hides the round trip outright).
/// Env-tunable so the payout round can price 1 against 2 on one binary.
fn tail_window_min() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_TAIL_WINDOW_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&w| w >= 1)
            .unwrap_or(1)
    })
}

/// Envelope-race age multiplier: race an article once it has cost this
/// many fleet-fastest article times. 3 is the design value; env-tunable
/// because the rig showed the bound and depth steering overlap - a
/// depth-1 shaped article's serve time sits just under 3x on the rig
/// shape, so a real-line sweep decides the value before any default
/// flip.
fn race_age_mult() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_RACE_AGE_MULT")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v| v >= 1)
            .unwrap_or(3)
    })
}

/// Hygiene-cap floor in MB (design 5.2: "a few percent of job size,
/// floor 32 MB" - sized so the excess stays unremarkable in a
/// provider's own volume panel). Env-tunable for the rig only.
fn dup_cap_floor() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_DUP_CAP_MB")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| *v >= 0.0)
            .map(|v| (v * 1e6) as u64)
            .unwrap_or(32_000_000)
    })
}

/// Hygiene-cap percentage of delivered bytes (default 2: a few percent
/// keeps the excess unremarkable on an unlimited account; the rig's
/// wall-per-duplicate-MB curve tunes it before graduation).
fn dup_cap_pct() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_DUP_CAP_PCT")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v| v > 0 && v <= 100)
            .unwrap_or(2)
    })
}

/// Run-level racing gauges, carried by [`LiveStats`] for the daemon's
/// diagnostics surfaces (the pool log line, the "Why is this slow?"
/// panel). Mirrors of the pool's own fleet-wide counters, bumped at
/// the same sites.
#[derive(Default)]
pub struct RaceLive {
    /// Duplicate dispatches issued (all rules, hedges included).
    pub dups_issued: AtomicU64,
    /// Duplicates that won their race (emitted the outcome).
    pub dup_wins: AtomicU64,
    /// Bytes of LOSING copies - winner bytes are the job's own. The
    /// usage ledger still bills every byte to the server that moved it
    /// (the wire was really used); this is the wall-currency audit of
    /// what racing SPENT.
    pub dup_bytes_lost: AtomicU64,
    /// Latched true once the hygiene cap stopped speculative arming.
    pub dup_capped: AtomicBool,
    /// The fleet-wide dispatch-to-done EWMA in ms, AS OF NOW - the
    /// mid-run value of the same gauge the `[pool]` line prints once at
    /// the end. The two are not the same reading and must not be
    /// compared as if they were: the end-of-run print is taken while
    /// the in-flight set drains, so it tracks the DRAIN duration
    /// (measured 0.84-1.57x of it across 17 legs, and 8.1x apart on two
    /// reps of one job - research/NOTE-2026-08-21-art-ms-semantics.md
    /// §10). This is the value hedging actually consults while the job
    /// runs. 0 = untrained.
    pub art_ms: AtomicU64,
    /// What [`Shared::hedge_stale_bound`] computes from it right now,
    /// in ms - the age past which the stale arm of `pick_dup` races an
    /// article. Mirrored rather than recomputed by readers so the clamp
    /// lives in exactly one place.
    pub hedge_bound_ms: AtomicU64,
    /// The §202 gauge's trained line peak in B/s, as of the last
    /// completion (`Saturation::peak_bps`; 0 until it trains). What
    /// the share-aware stall bound divides, the saturation gate
    /// compares against and the §208.1 cap is sized from - so the one
    /// reading a rig needs to pin an over-read of the line (TODO
    /// 208.2) without parsing the `[pool]` line out of a log.
    pub line_peak_bps: AtomicU64,
}

/// §5.7: the per-server block-account mask, computed at pool build.
/// Free function (not a method) so `Shared::new` can call it before
/// the struct exists.
pub(super) fn block_bits(servers: &[(crate::config::ServerConfig, PoolConfig)]) -> u32 {
    servers
        .iter()
        .enumerate()
        .filter(|(_, (_, c))| c.block_account)
        .fold(0, |m, (i, _)| m | server_bit(i))
}

/// Decay an accumulator by `dt_ms` of silence. Pure so the arithmetic
/// is unit-testable without a clock.
fn ewma_decay(val: u64, dt_ms: u64) -> u64 {
    if dt_ms == 0 {
        return val;
    }
    (val as f64 * (-(dt_ms as f64) / SRV_RATE_TAU_MS).exp()) as u64
}

/// Read an accumulator (already decayed to `now`) as a rate in B/s.
fn ewma_rate(val: u64) -> f64 {
    val as f64 / (SRV_RATE_TAU_MS / 1000.0)
}

impl Shared {
    /// Fold delivered bytes into the server's windowed throughput
    /// accumulator. Called beside the `bytes[]` bump on the 222 body
    /// path - the ONLY feeder, so the signal can never see probe
    /// traffic (module doc).
    ///
    /// Lock-free and deliberately approximate: the `swap` on the stamp
    /// claims the decay interval (exactly one bumper decays any given
    /// span of silence), while a load/store race on the value can drop
    /// the odd article's bytes. An undercount of one ~800 KB body
    /// against a multi-second accumulator moves no gate; a mutex here
    /// would put contention on every delivered article instead.
    pub(super) fn note_srv_bytes(&self, si: usize, n: u64) {
        let (Some(val), Some(at)) = (self.srv_rate_val.get(si), self.srv_rate_at.get(si)) else {
            return;
        };
        let now = self.start.elapsed().as_millis() as u64;
        let prev = at.swap(now, Ordering::Relaxed);
        let dt = if prev == u64::MAX {
            0 // first sample: nothing to decay
        } else {
            now.saturating_sub(prev)
        };
        let folded = ewma_decay(val.load(Ordering::Relaxed), dt).saturating_add(n);
        val.store(folded, Ordering::Relaxed);
        // TODO 202: the fleet-wide twin - fed here per body on the A/B
        // arm, per arriving chunk (`note_arrival`) when shipped, which
        // is the 208.2 over-read fix; this path then only carries the
        // tail latch across to it.
        let tail = self.tail_started.lock_ok().is_some();
        if self.sat.arrivals {
            self.sat.note_body_tail(tail);
        } else {
            self.sat.note_bytes(now, n, tail);
        }
        // TODO 208 item 1: the line-aware shed rides the same fold. The
        // tail bit rides along so the supply arm can sit out a queue-dry
        // tail (F6, 27 Aug sweep).
        self.line_cap_tick(now, tail);
        // TODO 208.2: the mean delivered body, for the share-aware
        // stall bound. Same 1/8 fold as `art_ms`; a load/store race
        // drops one sample, which moves nothing.
        let old = self.body_bytes_ewma.load(Ordering::Relaxed);
        let folded_bytes = if old == 0 { n } else { old - old / 8 + n / 8 };
        self.body_bytes_ewma
            .store(folded_bytes.max(1), Ordering::Relaxed);
        // Published mirror for the tuner and the dashboard: the rate as
        // of this fold, and a wall-clock stamp so a reader can tell a
        // fresh number from one going stale on a server that stopped
        // delivering (the value itself only decays when touched).
        if let Some(l) = &self.live
            && let Some(sl) = l.servers.get(si)
        {
            sl.srv_rate
                .store(ewma_rate(folded) as u64, Ordering::Relaxed);
            sl.srv_rate_at.store(now_ms(), Ordering::Relaxed);
        }
    }

    /// Average delivery rate of a server since the run started, B/s.
    ///
    /// This is a server's SHARE of the job, not its speed: a server given
    /// four times the connections delivers roughly four times the bytes at
    /// identical per-connection speed. Comparisons that mean "is this one
    /// slower" want [`Self::rate_per_worker`].
    ///
    /// Hoisted here from `pool.rs` under the size gate, to sit with the
    /// windowed twins below that every consumer actually reads.
    pub(super) fn rate(&self, server: usize) -> f64 {
        let el = self.start.elapsed().as_secs_f64().max(0.5);
        self.bytes[server].load(Ordering::Relaxed) as f64 / el
    }

    /// [`Self::rate`] divided by the server's dialling workers: what
    /// one of its connections is actually managing, which is the
    /// comparable quantity across servers with different connection
    /// counts.
    ///
    /// DIALLING and not alive since TODO 277: a parked worker delivers
    /// nothing, so counting it reads the server as slower per
    /// connection than it is.
    ///
    /// (This block's first paragraph is its ORIGINAL doc, recovered
    /// from `pool.rs`, where a hoist had stranded it above
    /// `session_ends` - one of the abutments in doc-gate's baseline.)
    pub(super) fn rate_per_worker(&self, server: usize) -> f64 {
        self.rate(server) / self.workers_dialling_on(server).unwrap_or(0).max(1) as f64
    }

    /// Windowed delivered rate for a server, B/s, decayed to now.
    /// `None` until the server has delivered its first body this run -
    /// callers fall back to the whole-run average (or skip the gate),
    /// so a cold fleet behaves exactly as before this signal existed.
    pub(super) fn srv_rate(&self, si: usize) -> Option<f64> {
        let (val, at) = (self.srv_rate_val.get(si)?, self.srv_rate_at.get(si)?);
        let prev = at.load(Ordering::Relaxed);
        if prev == u64::MAX {
            return None;
        }
        let now = self.start.elapsed().as_millis() as u64;
        let decayed = ewma_decay(val.load(Ordering::Relaxed), now.saturating_sub(prev));
        Some(ewma_rate(decayed))
    }

    /// [`Self::srv_rate`] divided by the server's live workers: the
    /// windowed twin of [`Self::rate_per_worker`], and the comparable
    /// quantity across servers with different connection counts.
    pub(super) fn srv_rate_per_worker(&self, si: usize) -> Option<f64> {
        // DIALLING, not alive, for the reason `rate_per_worker` gives:
        // a parked worker delivers nothing, so it must not divide a
        // delivered rate.
        let live = self.workers_dialling_on(si)?.max(1) as f64;
        Some(self.srv_rate(si)? / live)
    }

    /// The per-worker speed a steering or racing gate should judge by:
    /// windowed when trained, the whole-run average until then. The
    /// fallback keeps every consumer total - `faster_can_take` and
    /// `pick_dup` behave exactly as shipped for the seconds before a
    /// server's first delivery.
    pub(super) fn steer_rate_per_worker(&self, si: usize) -> f64 {
        self.srv_rate_per_worker(si)
            .unwrap_or_else(|| self.rate_per_worker(si))
    }

    /// Train the owner's per-server article-time EWMA. Called from the
    /// Done-path deregistration only, mirroring the global `art_ms`
    /// exactly (same 1/8 fold, same "requeues never train" rule): a
    /// requeue's age is not a completion time, and a 430 answers with
    /// no body. The index is the entry's OWNER - when a dup wins, the
    /// elapsed time still describes how long the owner sat on the
    /// article, which is precisely the drag this signal measures.
    pub(super) fn note_srv_art(&self, si: usize, ms: u64) {
        let Some(slot) = self.srv_art_ms.get(si) else {
            return;
        };
        let old = slot.load(Ordering::Relaxed);
        let new = if old == 0 { ms } else { old - old / 8 + ms / 8 };
        slot.store(new.max(1), Ordering::Relaxed);
        if let Some(l) = &self.live
            && let Some(sl) = l.servers.get(si)
        {
            sl.srv_art_ms.store(new.max(1), Ordering::Relaxed);
        }
    }

    /// Per-server article-time EWMA in ms. 0 = untrained; callers keep
    /// the global `art_ms` as the fleet-wide fallback and clamp source.
    pub(super) fn srv_art(&self, si: usize) -> u64 {
        self.srv_art_ms
            .get(si)
            .map_or(0, |s| s.load(Ordering::Relaxed))
    }

    /// Publish the article-time gauges: mirror the fleet EWMA and the
    /// staleness bound it produces into [`RaceLive`], and emit a
    /// rate-limited sample of both to the log.
    ///
    /// Why this exists. `hedge_stale_bound()` is a threshold computed
    /// from `art_ms` on every idle picker walk, and until this method
    /// there was no way to read either one WHILE a job ran: the
    /// `[pool]` line prints `art` once, at the end, where it reads the
    /// drain rather than the run (§10 of the art_ms note), and
    /// `srv_art_ms` was mirrored into `ServerLive` and read by nothing
    /// anywhere. Every value banked to date is therefore a drain
    /// sample, so nobody could say whether the bound sits clamped at
    /// its 8 s ceiling (inert - every in-flight article always "stale")
    /// or somewhere under it (a threshold that still discriminates).
    /// That question has to be settled before the constant is tuned.
    ///
    /// Called from the Done-path deregistration, right after the fold,
    /// so the sample is always the value a picker on the next walk
    /// would see. The mirror is unconditional (two relaxed stores); the
    /// log line is gated to one per [`art_gauge_ms`] so a fleet
    /// completing a hundred articles a second cannot turn its own log
    /// into telemetry.
    ///
    /// `debug`, not `info`: it is a rig instrument, off under the
    /// default filter and turned on with
    /// `NZBFAST_LOG=info,pool=debug`. The counts travel with it because
    /// a bare EWMA cannot be placed in the run - `in flight` falling
    /// with `pending` already at zero IS the drain, and a sample taken
    /// there is the very reading §10 warns against quoting.
    pub(super) fn note_art_gauges(&self) {
        let art = self.art_ms.load(Ordering::Relaxed);
        let bound = self.hedge_stale_bound().as_millis() as u64;
        if let Some(l) = &self.live {
            l.race.art_ms.store(art, Ordering::Relaxed);
            l.race.hedge_bound_ms.store(bound, Ordering::Relaxed);
            l.race
                .line_peak_bps
                .store(self.sat.peak_bps(), Ordering::Relaxed);
        }
        // Everything past this point exists to build ONE log line, so
        // skip it whole when nothing is listening. This runs on the
        // completion path of a fleet that can finish a hundred articles
        // a second, and under the default `info` filter - which is
        // every shipped run - the mirror above is the entire cost.
        if !tracing::enabled!(target: "pool", tracing::Level::DEBUG) {
            return;
        }
        let every = art_gauge_ms();
        if every == 0 {
            return;
        }
        // `art_note_at` doubles as the have-I-ever-emitted flag, so the
        // stamp must never be the 0 sentinel: a first completion inside
        // the run's opening millisecond would otherwise leave the gate
        // open and log every completion until the clock moved on.
        let now = (self.start.elapsed().as_millis() as u64).max(1);
        let last = self.art_note_at.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < every {
            return;
        }
        // Whoever wins the swap emits; a loser has nothing to say that
        // the winner did not already say for this window.
        if self
            .art_note_at
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let clamp = match bound {
            b if b == HEDGE_STALE_MAX.as_millis() as u64 => " (ceiling)",
            b if b == TAIL_FANOUT_MIN_AGE.as_millis() as u64 => " (floor)",
            _ => "",
        };
        let per_server = (0..self.srv_art_ms.len())
            .map(|si| {
                let host = self
                    .live
                    .as_ref()
                    .and_then(|l| l.servers.get(si))
                    .map_or_else(|| format!("s{si}"), |s| s.host.clone());
                match self.srv_art(si) {
                    0 => format!("{host} untrained"),
                    ms => format!("{host} {ms} ms"),
                }
            })
            .collect::<Vec<_>>()
            .join(" · ");
        debug!(
            target: "pool",
            "art gauge at {:.1}s · art {art} ms · stale bound {bound} ms{clamp} · \
             in flight {} · pending {} · {per_server}",
            now as f64 / 1000.0,
            self.inflight.lock_ok().len(),
            self.pending.load(Ordering::Relaxed),
        );
    }

    /// The per-OWNER staleness bound (design 5.1): 3x the owner's own
    /// `srv_art_ms`, same clamp family as the global hedge bound, global
    /// EWMA when the owner is untrained. The global bound goes blind
    /// exactly when a whole provider is shaped - its own slow
    /// completions drag the fleet EWMA up until nothing looks stale.
    fn hedge_stale_bound_for(&self, owner: usize) -> Duration {
        if !self.hedge {
            return HEDGE_STALE_MAX;
        }
        let ewma = match self.srv_art(owner) {
            0 => self.art_ms.load(Ordering::Relaxed),
            a => a,
        };
        match ewma {
            0 => HEDGE_STALE_MAX,
            e => Duration::from_millis((e * 3).clamp(
                TAIL_FANOUT_MIN_AGE.as_millis() as u64,
                HEDGE_STALE_MAX.as_millis() as u64,
            )),
        }
    }

    /// The fastest trained per-server article time among live servers,
    /// 0 = nobody trained. The envelope race's age currency: an article
    /// older than 3x this has already cost more than a fast server's
    /// whole round trip.
    fn fleet_fastest_art(&self) -> u64 {
        let mut fastest = 0u64;
        for si in 0..self.alive.len() {
            if self.alive[si].load(Ordering::Relaxed) == 0 {
                continue;
            }
            match self.srv_art(si) {
                0 => {}
                a if fastest == 0 || a < fastest => fastest = a,
                _ => {}
            }
        }
        fastest
    }

    /// Envelope-race age bound: `race_age_mult()` x the fleet-fastest
    /// article time, clamped to the hedge family's [floor, ceiling];
    /// the global EWMA (or the flat ceiling) until anything trains.
    fn envelope_age_bound(&self) -> Duration {
        let ms = match self.fleet_fastest_art() {
            0 => self.art_ms.load(Ordering::Relaxed),
            a => a,
        };
        match ms {
            0 => HEDGE_STALE_MAX,
            m => Duration::from_millis((m * race_age_mult()).clamp(
                TAIL_FANOUT_MIN_AGE.as_millis() as u64,
                HEDGE_STALE_MAX.as_millis() as u64,
            )),
        }
    }

    /// Is this owner under the envelope-race rate gate - windowed
    /// per-conn rate below `steer_arm()` (the same 1/4 family as depth
    /// steering; one threshold family, not two) of the best other live
    /// server's? Untrained anywhere = no.
    fn envelope_slow(&self, owner: usize) -> bool {
        match (
            self.srv_rate_per_worker(owner),
            self.fleet_best_other(owner),
        ) {
            (Some(mine), Some(best)) if best > 0.0 => mine < steer_arm() * best,
            _ => false,
        }
    }

    /// M7b.2 speculative arming (design 5.1), the one decision point
    /// `pick_dup`'s normal phase consults. Returns None = no dup;
    /// Some(stale_only) = arm, with `stale_only` marking a pick that
    /// must count against the hedge issue-rate cap.
    ///
    /// Flag OFF: the shipped rules verbatim - whole-run 2x slow-owner,
    /// flat/global staleness bound, no cap.
    ///
    /// Flag ON: the slow-owner rule RETIRES (one rule, one threshold
    /// family). Its replacement, the envelope race, arms only for an
    /// IDLE picker (empty pipeline - the TTFB round measured +6-15%
    /// wall when busy pickers joined) whose target's owner is under
    /// 1/4 of fleet-best (windowed) AND whose age exceeds 3x the
    /// fleet-fastest article time. The staleness hedge keeps its
    /// shipped gates but judges by the OWNER's article time. Both stop
    /// arming at the hygiene cap.
    pub(super) fn speculative_arm(
        &self,
        inf: &Inflight,
        window_used: usize,
        my_rate: f64,
        owner_rate: f64,
        flat_stale_bound: Duration,
        capped: bool,
    ) -> Option<bool> {
        if !self.race_envelope {
            let slow_owner = my_rate > 2.0 * owner_rate;
            let stale = inf.dispatched.elapsed() > flat_stale_bound;
            return (slow_owner || stale).then_some(!slow_owner);
        }
        if capped {
            return None;
        }
        let age = inf.dispatched.elapsed();
        let envelope =
            window_used == 0 && self.envelope_slow(inf.server) && age > self.envelope_age_bound();
        if envelope {
            return Some(false);
        }
        (age > self.hedge_stale_bound_for(inf.server)).then_some(true)
    }

    /// §5.7: may this server spend bytes speculatively? Level > 0 is
    /// the historical inference (fill accounts bill per byte); the
    /// block_account flag states it outright at any level.
    pub(super) fn speculative_blocked(&self, bit: u32, level: u32) -> bool {
        level > 0 || self.block_bits & bit != 0
    }

    /// The hygiene cap check (design 5.2): dup losses against
    /// max(floor, pct% of delivered bytes). Delivered-so-far stands in
    /// for "job payload" - the pool never learns the NZB's total, the
    /// two converge as the job runs, and early on the 32 MB floor
    /// dominates either way. Enforcement only exists under
    /// race_envelope; the counter itself always accrues (diagnostics).
    pub(super) fn dup_spend_capped(&self) -> bool {
        if !self.race_envelope {
            return false;
        }
        let delivered: u64 = self.bytes.iter().map(|b| b.load(Ordering::Relaxed)).sum();
        let cap = (delivered / 100 * dup_cap_pct()).max(dup_cap_floor());
        let capped = self.dup_bytes_lost.load(Ordering::Relaxed) >= cap;
        if capped
            && let Some(l) = &self.live
            && !l.race.dup_capped.swap(true, Ordering::Relaxed)
            && std::env::var_os("NZBFAST_POOL_DEBUG").is_some()
        {
            info!(
                target: "race-cap",
                "dup spend reached {} B (cap {cap} B) at {:?} - speculative pickers off",
                self.dup_bytes_lost.load(Ordering::Relaxed),
                self.start.elapsed()
            );
        }
        capped
    }

    /// Charge a losing copy's actual bytes (winner bytes are the job's
    /// own). Called wherever a completed transfer loses its claim.
    pub(super) fn charge_dup_loss(&self, n: u64) {
        self.dup_bytes_lost.fetch_add(n, Ordering::Relaxed);
        if let Some(l) = &self.live {
            l.race.dup_bytes_lost.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Mirrors for the LiveStats race gauges, bumped beside the pool's
    /// own counters.
    pub(super) fn mirror_dup_issued(&self) {
        if let Some(l) = &self.live {
            l.race.dups_issued.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn mirror_dup_win(&self) {
        if let Some(l) = &self.live {
            l.race.dup_wins.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The dup-spend fragment of `report_diagnostics`' line: empty
    /// until anything was spent, so clean runs keep their exact log
    /// shape.
    pub(super) fn dup_spend_line(&self) -> String {
        let lost = self.dup_bytes_lost.load(Ordering::Relaxed);
        if lost == 0 {
            return String::new();
        }
        if self.race_envelope {
            let delivered: u64 = self.bytes.iter().map(|b| b.load(Ordering::Relaxed)).sum();
            let cap = (delivered / 100 * dup_cap_pct()).max(dup_cap_floor());
            format!(
                " · dup spend {:.1} MB of {:.0} MB budget",
                lost as f64 / 1e6,
                cap as f64 / 1e6
            )
        } else {
            format!(" · dup spend {:.1} MB", lost as f64 / 1e6)
        }
    }

    /// The best windowed per-conn rate among the OTHER live servers.
    /// Excluding `me` is the never-strand guarantee: a lone server (or
    /// a fleet whose others are dead or untrained) gets `None` and is
    /// never clamped, mirroring `faster_can_take`'s no-clear-winner
    /// posture.
    fn fleet_best_other(&self, me: usize) -> Option<f64> {
        let mut best: Option<f64> = None;
        for si in 0..self.alive.len() {
            if si == me || self.alive[si].load(Ordering::Relaxed) == 0 {
                continue;
            }
            if let Some(r) = self.srv_rate_per_worker(si) {
                best = Some(best.map_or(r, |b| b.max(r)));
            }
        }
        best
    }

    /// M7b.2 depth steering (design §4.1): the pipeline depth this
    /// server's workers should TOP UP to, given `base` (the configured
    /// window, already min'd with the stream-mode cap by the caller -
    /// steering composes with stream mode, never fights it).
    ///
    /// Called per top-up, not per scan (the scan already has a throttle
    /// discipline of its own). When the server's windowed per-conn rate
    /// is under `steer_arm()` x the best other live server's, workers
    /// stop parking `window` articles behind each slow session and run
    /// at depth `steer_floor()` (1); the clamp lifts at `steer_disarm()`
    /// x (hysteresis). Cost, priced in the design: at the live shape a
    /// shaped article serves in ~430 ms against ~40 ms of RTT, so depth
    /// was hiding <10% there - and the gate never fires on a fast
    /// server, where the ratio inverts.
    ///
    /// Untrained rates anywhere leave `base` untouched: a cold fleet
    /// behaves exactly as shipped. The per-server hysteresis bit is
    /// mirrored into `ServerLive::steered` - the tuner's contamination
    /// signal (§4.3): while set, this server's delivered-rate drop is
    /// our own demand steering, not a provider knee.
    pub(super) fn steer_window(&self, si: usize, base: usize) -> usize {
        if !self.steer_depth {
            return base;
        }
        let Some(flag) = self.steer_clamped.get(si) else {
            return base;
        };
        let was = flag.load(Ordering::Relaxed);
        let clamped = match (self.srv_rate_per_worker(si), self.fleet_best_other(si)) {
            (Some(mine), Some(best)) if best > 0.0 => {
                let bound = if was { steer_disarm() } else { steer_arm() };
                mine < bound * best
            }
            _ => false,
        };
        if clamped != was {
            flag.store(clamped, Ordering::Relaxed);
            if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
                info!(
                    target: "steer-depth",
                    "server {si} {} at {:?}",
                    if clamped { "clamped" } else { "restored" },
                    self.start.elapsed()
                );
            }
        }
        if let Some(l) = &self.live
            && let Some(sl) = l.servers.get(si)
        {
            sl.steered.store(clamped, Ordering::Relaxed);
        }
        if clamped {
            steer_floor().min(base)
        } else {
            base
        }
    }

    /// TODO 208 item 3 endgame depth taper: the top-up bound implied by how
    /// much work the RUN has left, so the fleet reaches queue-dry
    /// holding about one article per connection instead of `window`.
    ///
    /// **Why the tail is worth attacking at all.** The stretch between
    /// queue-dry and drained is the in-flight set emptying, and its
    /// size is `conns x window` articles - measured directly on every
    /// banked 1 GbE bench leg as 1.13-1.62 GB of payload still to arrive at
    /// queue-dry, invariant across a 6.8x change in job size, a 4x
    /// change in line speed and both connection profiles, because
    /// `360 x 4` never changed. That is 16 s at 1 Gbps and 65 s at
    /// 250 Mbit. It is NOT dead time: on legs with the TODO 202
    /// saturation gate armed the drain delivers its payload FASTER than
    /// the run's pre-dry rate, so there is no line-idle slack in it at
    /// all. (On older legs there appears to be - 15-19 s at 250 Mbit -
    /// but that is duplicate bodies on the wire, which the decoded-byte
    /// gauge cannot see, and §202 removed them.)
    ///
    /// So this is a ROBUSTNESS bound, not a throughput one, and it is
    /// off by default. The tail is the window in which a wedged
    /// connection or an uncapped speculative rule can cost the wall -
    /// work parked behind a slow session cannot be handed to a fast one
    /// that has gone idle, and racing it is what the tail fan-out
    /// spends duplicate bytes on. A fleet that arrives at queue-dry one
    /// article deep has a quarter of that window and needs none of
    /// those dups.
    ///
    /// **The rule.** `pending / (2 x live workers)`, clamped to
    /// `[tail_window_min(), base]`. `pending` is queued + in flight, so
    /// with every connection at depth `d` it reads
    /// `(queued/live + d) / 2` - a contraction whose fixed point is
    /// exactly `queued / live`, the depth at which the work still to be
    /// handed out is one article per connection. It converges from
    /// above, one rung per step, and it is vacuous until `queued` falls
    /// below `base x live` (1,440 articles on the bench fleet, the last
    /// ~13 s at 1 Gbps and ~1 s at 10 GbE), so the steady state - where
    /// deep pipelining earns the 10 GbE margins - is untouched by
    /// construction.
    ///
    /// Two atomics both already read on this path and no queue lock:
    /// deriving the queue depth from `pending - inflight` was the
    /// obvious alternative and is worse, because `inflight` counts
    /// speculative dups, which are concentrated in exactly this phase.
    ///
    /// **Cost.** At depth 1 a connection pays one round trip between a
    /// completion and its next BODY. An article serves in 3.1 s at
    /// 1 Gbps and 0.31 s at 10 GbE against ~20 ms of RTT, so the
    /// exposure is 0.6% and 6% of the tapered stretch respectively -
    /// and at 10 GbE that stretch is ~1 s of a 33 s leg.
    ///
    /// TOP-UP only, exactly like [`Shared::steer_window`]: the caller
    /// keeps judging its shed against `base_win`, so a taper step never
    /// sheds a pipeline or drops a connection.
    pub(super) fn tail_window(&self, base: usize) -> usize {
        if !self.tail_taper {
            return base;
        }
        // DIALLING, not live: the taper's whole arithmetic is about
        // the depth each WORKING connection is holding, and a parked
        // worker holds no pipeline at all. See
        // `Shared::workers_dialling`.
        let live = self.workers_dialling().max(1);
        let left = self.pending.load(Ordering::Acquire);
        let win = base.min(left / (2 * live)).max(tail_window_min().min(base));
        // Evidence for the leg, not a control input. Guarded on
        // `win < base` so the steady state - where the taper is vacuous
        // by construction - never touches the atomic at all.
        if win < base && win < self.taper_min.load(Ordering::Relaxed) {
            self.taper_min.fetch_min(win, Ordering::Relaxed);
        }
        win
    }
}

impl ServerLive {
    /// This server's published windowed delivery rate right now, B/s,
    /// or `None` while it has never delivered a body this run.
    ///
    /// Lives here rather than beside [`ServerLive::down_secs`] because
    /// it is the READ half of [`Shared::note_srv_bytes`] a few lines
    /// above, and the two have to stay in step: that fold stores the
    /// rate ALREADY divided by tau (`ewma_rate(folded)`), so this reader
    /// must decay it and must not divide again. Dividing twice reads a
    /// 100 MB/s provider as 7 MB/s and looks entirely plausible.
    ///
    /// DECAYED BY HAND, and that is the whole reason this is a method
    /// and not a field read. The mirror only moves when it is TOUCHED,
    /// so a server that stopped delivering keeps its last fold forever -
    /// a Servers pane reading the field raw would report a provider that
    /// went silent ten minutes ago at full speed. `srv_rate_at` is
    /// stamped beside the value for exactly this, and it is a WALL-CLOCK
    /// stamp (`now_ms`), unlike the [`Shared::srv_rate`] twin's, which
    /// is against the run clock - a reader outside the pool has no run
    /// clock to ask.
    ///
    /// 0 is the never-folded sentinel, so an untrained server is `None`
    /// rather than a confident zero: `for_servers` starts the stamp at
    /// 0 and the fold only ever writes a real `now_ms`.
    ///
    /// THE TWIN'S SENTINEL IS A DIFFERENT VALUE, and that asymmetry is
    /// the one thing to know before writing a third reader of this
    /// quantity. [`Shared::srv_rate`] one screen up gates on
    /// `prev == u64::MAX`, because `Shared::new` initialises its own
    /// `srv_rate_at` vector to `u64::MAX`; the published mirror beside
    /// it starts at 0. Both are correct where they are, and both are
    /// pinned by a test, so nothing on the tree is wrong today - what
    /// is easy is copying one gate into the other's reader, which is
    /// SILENT and answers `Some(0.0)` where `None` is owed, in BOTH
    /// directions. The mirror given `u64::MAX` reads an untrained
    /// stamp of 0 as trained and decays a colossal `dt` to zero; the
    /// Shared reader given `0` reads `u64::MAX` as trained and
    /// `saturating_sub` floors `dt` at zero. The second is the one
    /// with teeth: `steer_rate_per_worker` falls back to the whole-run
    /// average PRECISELY when `srv_rate` is `None`, so a `Some(0.0)`
    /// hands the depth clamp and the racing gates a cold fleet dressed
    /// as a 0 B/s provider. Take the sentinel from the initialiser of
    /// the stamp you are actually reading, never from the neighbour.
    pub fn srv_rate_bps(&self) -> Option<f64> {
        let at = self.srv_rate_at.load(Ordering::Relaxed);
        if at == 0 {
            return None;
        }
        let dt = now_ms().saturating_sub(at);
        Some(ewma_decay(self.srv_rate.load(Ordering::Relaxed), dt) as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    fn server(host: &str) -> ServerConfig {
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

    fn fresh(ids: &[&str]) -> Vec<ArticleReq> {
        ids.iter().map(|id| ArticleReq::fresh(*id)).collect()
    }

    /// A `Shared` armed for the TODO 208 item 3 taper, with `n` articles
    /// queued so `pending` starts there.
    fn tapered_shared(n: usize) -> Arc<Shared> {
        let cfg = PoolConfig {
            tail_taper: true,
            ..PoolConfig::default()
        };
        let ids: Vec<ArticleReq> = (0..n)
            .map(|i| ArticleReq::fresh(format!("<t{i}@x>")))
            .collect();
        Shared::new(ids, &[(server("a"), cfg)]).0
    }

    /// The taper is vacuous until the queue falls under `base x live`,
    /// and then walks one rung per step down to the floor. Driven by
    /// hand over `pending`, so it asserts the RULE, not a schedule.
    ///
    /// The fleet here is the bench fleet: 360 workers at window 4, so
    /// the in-flight set at queue-dry is the 1,440 articles measured on
    /// every banked 1 GbE bench leg.
    #[test]
    fn the_tail_taper_is_inert_until_the_queue_runs_low_then_walks_to_one() {
        let live = 360usize;
        let base = 4usize;
        let sh = tapered_shared(8_000);
        sh.workers_live.store(live, Ordering::Relaxed);

        // Mid-run: thousands queued, full pipelining, untouched.
        for left in [8_000, 5_000, base * live * 2] {
            sh.pending.store(left, Ordering::Release);
            assert_eq!(sh.tail_window(base), base, "tapered mid-run at {left} left");
        }

        // The trigger: `pending / (2 x live)` reaches `base` at exactly
        // `queued = base x live`, i.e. the last in-flight set's worth.
        sh.pending.store(2 * base * live, Ordering::Release);
        assert_eq!(sh.tail_window(base), base, "tapered one article early");
        sh.pending.store(2 * base * live - 1, Ordering::Release);
        assert_eq!(sh.tail_window(base), base - 1, "no taper at the trigger");

        // Each rung: with every connection at depth d, pending reads
        // `queued + live x d`, so the rule returns `(queued/live + d)/2`
        // - a contraction on d whose fixed point is `queued / live`.
        for (queued, depth, want) in [
            (3 * live, 4, 3),
            (3 * live, 3, 3), // fixed point: stays
            (2 * live, 3, 2),
            (2 * live, 2, 2), // fixed point
            (live, 2, 1),
            (live, 1, 1),     // fixed point
            (live / 2, 1, 1), // fewer queued than connections
            (0, 1, 1),        // queue dry: the floor keeps work moving
        ] {
            sh.pending.store(queued + live * depth, Ordering::Release);
            assert_eq!(
                sh.tail_window(base),
                want,
                "queued {queued} at depth {depth} should top up to {want}"
            );
        }
    }

    /// TODO 277: a fleet that spawns above its live target and parks
    /// the surplus tapers on the workers actually holding a pipeline,
    /// not on the slot count. Parked workers hold NO pipeline, so
    /// counting them would halve the depth at which the taper starts
    /// biting - a run dialling 360 with 360 more parked behind it would
    /// begin tapering at 2,880 queued rather than 1,440, for no reason
    /// any measurement knows about.
    #[test]
    fn the_tail_taper_counts_the_workers_that_hold_a_pipeline() {
        let live = 360usize;
        let base = 4usize;
        let sh = tapered_shared(8_000);
        // Twice the fleet spawned, half of it parked: the dialling
        // count is the 360 the taper was measured on.
        sh.workers_live.store(2 * live, Ordering::Relaxed);
        sh.parked_total.store(live, Ordering::Relaxed);
        assert_eq!(sh.workers_dialling(), live);
        // The trigger sits where it does with a fleet of 360 spawned
        // flat, and NOT where 720 sharers would put it.
        sh.pending.store(2 * base * live, Ordering::Release);
        assert_eq!(sh.tail_window(base), base, "tapered one article early");
        sh.pending.store(2 * base * live - 1, Ordering::Release);
        assert_eq!(sh.tail_window(base), base - 1);
        // What the spawned count would have said at the same depth: a
        // 720-way share is already down at the floor, three rungs
        // below. So this test would not pass with the two confused for
        // one another.
        sh.parked_total.store(0, Ordering::Relaxed);
        assert_eq!(sh.tail_window(base), 1);
    }

    /// Disarmed, the rule is the identity at every queue depth - a
    /// shipped run behaves exactly as it does today.
    #[test]
    fn the_tail_taper_is_the_identity_while_disarmed() {
        let sh = two_server_shared();
        sh.workers_live.store(64, Ordering::Relaxed);
        for left in [0, 1, 64, 512, 100_000] {
            sh.pending.store(left, Ordering::Release);
            assert_eq!(sh.tail_window(4), 4, "disarmed taper moved at {left}");
        }
    }

    /// The floor never exceeds the caller's own window: a run dialled
    /// `--window 1` must not be tapered UP to 2 by the env knob, and a
    /// fleet whose head-count has not registered yet (live 0) must not
    /// divide by zero.
    #[test]
    fn the_tail_taper_never_raises_the_callers_window_or_divides_by_zero() {
        let sh = tapered_shared(10);
        sh.workers_live.store(0, Ordering::Relaxed);
        sh.pending.store(10, Ordering::Release);
        assert_eq!(sh.tail_window(1), 1);
        assert_eq!(sh.tail_window(4), 4, "10 left over a 1-worker floor");
        sh.pending.store(0, Ordering::Release);
        assert_eq!(sh.tail_window(1), 1, "floor raised a window-1 run");
    }

    fn two_server_shared() -> Arc<Shared> {
        let servers = vec![
            (server("a"), PoolConfig::default()),
            (server("b"), PoolConfig::default()),
        ];
        Shared::new(fresh(&["<a@x>"]), &servers).0
    }

    #[test]
    fn decay_halves_the_accumulator_at_the_half_life() {
        let v = ewma_decay(1_000_000, SRV_RATE_HALF_LIFE_MS);
        assert!(
            (499_000..=501_000).contains(&v),
            "one half-life should halve the accumulator, got {v}"
        );
        // Zero silence is the identity - the same-millisecond fast path.
        assert_eq!(ewma_decay(1_000_000, 0), 1_000_000);
    }

    #[test]
    fn steady_delivery_reads_back_as_the_delivery_rate() {
        // Feed 1 MB per simulated 100 ms long enough to converge, then
        // the accumulator over tau must read ~10 MB/s. Driven through
        // the pure helpers - the Shared methods add only clock reads.
        let mut acc: u64 = 0;
        for _ in 0..2000 {
            acc = ewma_decay(acc, 100).saturating_add(100_000);
        }
        let rate = ewma_rate(acc);
        let expect = 1_000_000.0; // 100 KB per 100 ms = 1 MB/s
        assert!(
            (rate - expect).abs() < expect * 0.05,
            "steady-state rate should read ~{expect} B/s, got {rate}"
        );
    }

    #[test]
    fn published_srv_rate_is_untrained_decays_and_is_not_divided_twice() {
        // Built by hand rather than driven through `note_srv_bytes`:
        // that fold only writes the mirror when the pool carries a
        // `LiveStats`, and `PoolConfig::default()` carries none - so a
        // rig test would be asserting on a field nothing had written.
        let sl = ServerLive::default();
        assert_eq!(
            sl.srv_rate_bps(),
            None,
            "0 is the never-folded sentinel, not a confident zero"
        );

        // The fold stores B/s. The reader must hand that back, NOT
        // divide by tau a second time - which would read a 100 MB/s
        // provider as ~7 MB/s and look entirely plausible.
        //
        // THE BANDS BELOW ARE DELIBERATELY WIDE, and that is the same
        // lesson `per_worker_rate_divides_by_live_workers` records a
        // few tests down: this reader re-decays against `now_ms()` at
        // the instant it is called, so the gap between STORING the
        // stamp and READING it is whatever the scheduler gave, and a
        // tight band is a bound on the scheduler rather than on the
        // answer. A 1% band here would have failed on any gap over
        // 145 ms, which a loaded Windows shard or the qemu armv7 leg
        // can produce; a floor of half the value tolerates a full ten
        // seconds. Neither mutation survives the widening - the double
        // division answers 6.93 M against a 50 M floor, and no decay
        // at all answers 100 M against a 60 M ceiling.
        sl.srv_rate.store(100_000_000, Ordering::Relaxed);
        sl.srv_rate_at.store(now_ms(), Ordering::Relaxed);
        let now = sl.srv_rate_bps().expect("trained once the stamp is set");
        assert!(
            (50_000_000.0..=100_000_001.0).contains(&now),
            "a fresh fold reads back as itself, not divided by tau twice (that is 6.93 M); got {now}"
        );

        // Silence decays it. One half-life of it halves the number, so
        // a provider that went quiet cannot go on reporting full speed.
        sl.srv_rate_at.store(
            now_ms().saturating_sub(SRV_RATE_HALF_LIFE_MS),
            Ordering::Relaxed,
        );
        let half = sl.srv_rate_bps().expect("still trained");
        assert!(
            (40_000_000.0..=60_000_000.0).contains(&half),
            "one half-life of silence halves the published rate (no decay would be 100 M); got {half}"
        );
    }

    #[test]
    fn srv_rate_is_untrained_until_the_first_body() {
        let sh = two_server_shared();
        assert_eq!(sh.srv_rate(0), None);
        assert_eq!(sh.srv_rate_per_worker(0), None);
        // The steering read falls back to the whole-run average, which
        // with zero bytes is 0.0 - exactly what the shipped gates saw.
        assert_eq!(sh.steer_rate_per_worker(0), 0.0);
        sh.note_srv_bytes(0, 800_000);
        let r = sh.srv_rate(0).expect("trained after one body");
        assert!(r > 0.0);
        // Server 1 saw nothing and stays untrained.
        assert_eq!(sh.srv_rate(1), None);
    }

    #[test]
    fn per_worker_rate_divides_by_live_workers() {
        let sh = two_server_shared();
        sh.alive[0].store(4, Ordering::Relaxed);
        sh.note_srv_bytes(0, 8_000_000);
        let whole = sh.srv_rate(0).unwrap();
        let per = sh.srv_rate_per_worker(0).unwrap();
        // RELATIVE, and it has to be. Both readers re-decay the EWMA
        // against `start.elapsed()` at the instant they are called, so
        // the two reads above are of two different moments and the gap
        // between them is whatever the scheduler gave. An absolute
        // 1.0 B/s tolerance on a ~554 kB/s rate is therefore a bound on
        // the SCHEDULER, and the nightly armv7-cross run of 28 Aug 2026
        // lost it: 554517.74 / 4 against 138619.82, out by 9.6 B/s -
        // TRY 1 FAIL, TRY 2 PASS, reported as a flake. 1% still refuses
        // every wrong divisor (dividing by 1, 2 or 8 is off by 100% or
        // more), which is the whole of what this case claims.
        assert!(
            (whole / 4.0 - per).abs() < whole * 0.01,
            "per-worker should be rate/alive: {whole} / 4 vs {per}"
        );
    }

    #[test]
    fn srv_art_trains_per_server_and_mirrors_the_global_fold() {
        let sh = two_server_shared();
        assert_eq!(sh.srv_art(0), 0);
        sh.note_srv_art(0, 800);
        assert_eq!(sh.srv_art(0), 800, "first sample seeds the EWMA");
        sh.note_srv_art(0, 1600);
        // Same 1/8 fold as the global art_ms: 800 - 100 + 200 = 900.
        assert_eq!(sh.srv_art(0), 900);
        assert_eq!(sh.srv_art(1), 0, "other servers stay untrained");
    }

    /// A hedging fleet with the live view attached - what `shipped()`
    /// builds and what the gauge mirror needs a destination for.
    fn hedging_shared_with_live() -> Arc<Shared> {
        let mut servers = vec![
            (
                server("a"),
                PoolConfig {
                    hedge: true,
                    ..PoolConfig::default()
                },
            ),
            (
                server("b"),
                PoolConfig {
                    hedge: true,
                    ..PoolConfig::default()
                },
            ),
        ];
        let live = LiveStats::for_servers(&servers);
        for (_, cfg) in servers.iter_mut() {
            cfg.live = Some(live.clone());
        }
        Shared::new(fresh(&["<a@x>"]), &servers).0
    }

    /// The mid-run pair the note asked for: the fleet EWMA as it stands
    /// NOW, and the staleness bound derived from it, both readable off
    /// `LiveStats` while the job runs. Before this the EWMA was
    /// observable only in the end-of-run `[pool]` line - a drain
    /// reading - and the bound was observable nowhere at all.
    #[test]
    fn the_art_gauges_publish_the_ewma_and_the_bound_it_produces() {
        let sh = hedging_shared_with_live();
        let live = sh.live.clone().expect("live view attached");
        // Untrained: the bound falls back to the flat ceiling, which is
        // what `hedge_stale_bound` answers with a zero EWMA.
        sh.note_art_gauges();
        assert_eq!(live.race.art_ms.load(Ordering::Relaxed), 0);
        assert_eq!(
            live.race.hedge_bound_ms.load(Ordering::Relaxed),
            HEDGE_STALE_MAX.as_millis() as u64,
        );
        // 1,000 ms of article time is 3,000 ms of bound - inside the
        // clamp, so this is the regime where the bound still says
        // something about an article's age.
        sh.art_ms.store(1_000, Ordering::Relaxed);
        sh.note_art_gauges();
        assert_eq!(live.race.art_ms.load(Ordering::Relaxed), 1_000);
        assert_eq!(live.race.hedge_bound_ms.load(Ordering::Relaxed), 3_000);
        // Past 2,667 ms of article time, 3x overshoots the 8 s ceiling
        // and the bound pins there. That is the state the whole
        // question is about: pinned, every in-flight article reads
        // stale, and the threshold has stopped discriminating.
        sh.art_ms.store(5_000, Ordering::Relaxed);
        sh.note_art_gauges();
        assert_eq!(live.race.art_ms.load(Ordering::Relaxed), 5_000);
        assert_eq!(
            live.race.hedge_bound_ms.load(Ordering::Relaxed),
            HEDGE_STALE_MAX.as_millis() as u64,
        );
    }

    /// The mirror is unconditional; only the LOG line is rate-limited.
    /// A test that asserted through the rate limiter would be asserting
    /// on a wall clock, and the mirror is the half the daemon reads.
    #[test]
    fn the_gauge_mirror_ignores_the_log_rate_limit() {
        let sh = hedging_shared_with_live();
        let live = sh.live.clone().expect("live view attached");
        for ms in [400u64, 900, 1_500] {
            sh.art_ms.store(ms, Ordering::Relaxed);
            sh.note_art_gauges();
            assert_eq!(live.race.art_ms.load(Ordering::Relaxed), ms);
        }
        // Three calls inside one window; at most one of them logged,
        // and the published value is still the last one folded.
        assert_eq!(live.race.hedge_bound_ms.load(Ordering::Relaxed), 4_500);
    }

    /// A pool with no live view (the bare CLI paths) must not panic or
    /// pay for a destination it does not have.
    #[test]
    fn the_art_gauges_are_inert_without_a_live_view() {
        let sh = two_server_shared();
        assert!(sh.live.is_none());
        sh.art_ms.store(1_234, Ordering::Relaxed);
        sh.note_art_gauges();
    }

    #[test]
    fn out_of_range_indices_are_inert() {
        let sh = two_server_shared();
        sh.note_srv_bytes(99, 1);
        sh.note_srv_art(99, 1);
        assert_eq!(sh.srv_rate(99), None);
        assert_eq!(sh.srv_art(99), 0);
    }

    fn two_server_shared_steering() -> Arc<Shared> {
        let cfg = PoolConfig {
            steer_depth: true,
            ..PoolConfig::default()
        };
        let servers = vec![(server("a"), cfg.clone()), (server("b"), cfg)];
        let sh = Shared::new(fresh(&["<a@x>"]), &servers).0;
        sh.alive[0].store(1, Ordering::Relaxed);
        sh.alive[1].store(1, Ordering::Relaxed);
        sh
    }

    #[test]
    fn depth_clamp_arms_below_quarter_and_restores_above_half() {
        let sh = two_server_shared_steering();
        // Untrained: never clamped, base window untouched.
        assert_eq!(sh.steer_window(0, 4), 4);
        // Server 0 at ~1/30th of server 1: clamps to depth 1. Server 1,
        // the fast one, keeps its window - the ratio inverts.
        sh.note_srv_bytes(0, 1_000_000);
        sh.note_srv_bytes(1, 30_000_000);
        assert_eq!(sh.steer_window(0, 4), 1);
        assert_eq!(sh.steer_window(1, 4), 4);
        // Recovery into the hysteresis band (between 1/4 and 1/2):
        // stays clamped - a boundary server must not flap.
        sh.note_srv_bytes(0, 9_500_000); // ~10.5 vs 30 = 0.35
        assert_eq!(sh.steer_window(0, 4), 1, "hysteresis band keeps the clamp");
        // Recovery past the disarm bound: restored.
        sh.note_srv_bytes(0, 10_000_000); // ~20.5 vs 30 = 0.68
        assert_eq!(sh.steer_window(0, 4), 4, "past 1/2 the clamp lifts");
    }

    #[test]
    fn depth_clamp_never_fires_without_a_trained_faster_other() {
        // Lone server: no other to compare against, never clamped.
        let servers = vec![(
            server("solo"),
            PoolConfig {
                steer_depth: true,
                ..PoolConfig::default()
            },
        )];
        let sh = Shared::new(fresh(&["<a@x>"]), &servers).0;
        sh.alive[0].store(1, Ordering::Relaxed);
        sh.note_srv_bytes(0, 10);
        assert_eq!(sh.steer_window(0, 4), 4);
        // Two servers, only me trained: still never clamped.
        let sh = two_server_shared_steering();
        sh.note_srv_bytes(0, 10);
        assert_eq!(sh.steer_window(0, 4), 4);
        // Other trained but DEAD (no live workers): not a comparator.
        sh.note_srv_bytes(1, 30_000_000);
        sh.alive[1].store(0, Ordering::Relaxed);
        assert_eq!(sh.steer_window(0, 4), 4);
    }

    #[test]
    fn depth_clamp_is_inert_when_the_flag_is_off() {
        let sh = two_server_shared();
        sh.alive[0].store(1, Ordering::Relaxed);
        sh.alive[1].store(1, Ordering::Relaxed);
        sh.note_srv_bytes(0, 10);
        sh.note_srv_bytes(1, 30_000_000);
        assert_eq!(sh.steer_window(0, 4), 4, "dark flag off = shipped behavior");
    }

    fn fresh_n(n: usize) -> Vec<ArticleReq> {
        (0..n)
            .map(|i| ArticleReq::fresh(format!("<a{i}@x>")))
            .collect()
    }

    /// Two servers, envelope racing armed, enough queue for the NORMAL
    /// phase (pending > ENDGAME_MAX), fast server 0 / slow server 1.
    fn racing_shared(block0: bool) -> Arc<Shared> {
        let cfg = |block| PoolConfig {
            race_envelope: true,
            hedge: true,
            block_account: block,
            ..PoolConfig::default()
        };
        let servers = vec![(server("a"), cfg(block0)), (server("b"), cfg(false))];
        let sh = Shared::new(fresh_n(100), &servers).0;
        sh.alive[0].store(1, Ordering::Relaxed);
        sh.alive[1].store(1, Ordering::Relaxed);
        // Windowed rates: server 1 at 1/30th of server 0 (under 1/4),
        // and a trained fast article time so the envelope age bound
        // sits at its 500 ms floor.
        sh.note_srv_bytes(0, 30_000_000);
        sh.note_srv_bytes(1, 1_000_000);
        sh.note_srv_art(0, 100);
        sh
    }

    /// An in-flight entry owned by `server`, dispatched `age` ago.
    fn inflight_entry(sh: &Shared, id: &str, server: usize, age: Duration) {
        sh.inflight.lock_ok().insert(
            id.into(),
            Inflight {
                age_days: 0,
                part: 0,
                file: u32::MAX,
                ord: 0,
                server,
                dispatched: Instant::now() - age,
                dups: 0,
                tried_430: 0,
                dup_servers: 0,
                tried_fail: 0,
                suspect: false,
                found: 0,
            },
        );
    }

    #[test]
    fn envelope_race_arms_only_for_idle_pickers_on_slow_old_articles() {
        let sh = racing_shared(false);
        inflight_entry(&sh, "<old@x>", 1, Duration::from_secs(1));
        // Busy picker (window_used 1): the envelope arm is idle-only,
        // and at 1 s the article is not stale either (owner untrained,
        // global untrained -> flat 8 s bound). No dup.
        assert!(sh.pick_dup(0, 1, 1, 0, Pipeline::payload(1), 0).is_none());
        // Idle picker: owner under 1/4 fleet-best, age past 3x the
        // fastest article time (clamped to the 500 ms floor) - race.
        let w = sh
            .pick_dup(0, 1, 1, 0, Pipeline::payload(0), 0)
            .expect("envelope race fires");
        assert_eq!(&*w.id, "<old@x>");
        assert!(w.dup);
    }

    #[test]
    fn envelope_race_spares_young_articles_and_not_slow_enough_owners() {
        let sh = racing_shared(false);
        // Young article on the slow owner: under the age bound.
        inflight_entry(&sh, "<young@x>", 1, Duration::from_millis(100));
        assert!(sh.pick_dup(0, 1, 1, 0, Pipeline::payload(0), 0).is_none());
        // Old article, but the owner recovers to ~1/3 of fleet-best:
        // above the 1/4 arm. The OLD whole-run 2x rule would have raced
        // this - its retirement is the point (one rule, one family).
        sh.note_srv_bytes(1, 9_000_000); // 10 vs 30 = 1/3
        inflight_entry(&sh, "<old@x>", 1, Duration::from_secs(1));
        assert!(sh.pick_dup(0, 1, 1, 0, Pipeline::payload(0), 0).is_none());
    }

    #[test]
    fn hygiene_cap_chokes_speculation_but_never_the_ladder() {
        let sh = racing_shared(false);
        sh.dup_bytes_lost.store(u64::MAX / 2, Ordering::Relaxed);
        // A perfect envelope candidate: choked by the cap.
        inflight_entry(&sh, "<old@x>", 1, Duration::from_secs(1));
        assert!(sh.pick_dup(0, 1, 1, 0, Pipeline::payload(0), 0).is_none());
        // The endgame 430 ladder is exempt: it carries a Missing
        // verdict, and choking it re-opens the unanimity tails M2c.4
        // closed. Endgame-scale pool, article 430'd on its owner.
        let cfg = PoolConfig {
            race_envelope: true,
            ..PoolConfig::default()
        };
        let servers = vec![(server("a"), cfg.clone()), (server("b"), cfg)];
        let sh = Shared::new(fresh_n(4), &servers).0;
        sh.alive[0].store(1, Ordering::Relaxed);
        sh.alive[1].store(1, Ordering::Relaxed);
        sh.dup_bytes_lost.store(u64::MAX / 2, Ordering::Relaxed);
        sh.inflight.lock_ok().insert(
            "<laddered@x>".into(),
            Inflight {
                age_days: 0,
                part: 0,
                file: u32::MAX,
                ord: 0,
                server: 1,
                dispatched: Instant::now(),
                dups: 0,
                tried_430: server_bit(1),
                dup_servers: 0,
                tried_fail: 0,
                suspect: false,
                found: 0,
            },
        );
        let w = sh
            .pick_dup(0, 1, 1, 0, Pipeline::payload(0), 0)
            .expect("the verdict ladder is never throttled by the cap");
        assert_eq!(&*w.id, "<laddered@x>");
    }

    /// TODO 96.4: the block-account exemption stops at the ladder, and
    /// this pins where. A flagged server never races on SPEED (the test
    /// below), but the endgame 430 ladder is exempt from
    /// `speculative_blocked` because its dispatch buys a verdict, and a
    /// verdict is worth metered bytes in a way a second copy of a body
    /// is not. So a level-0 block account DOES fan out - which is the
    /// one shape where the duplicate bodies §96 item 4 is about are
    /// paid for per gigabyte rather than spent on an idle line.
    ///
    /// A level>0 fill server cannot reach the same shape: `required`
    /// holds it until every live lower level has refused, so by then
    /// its body is the delivery rather than a copy. It takes a block
    /// account sharing level 0 with servers that hold the article.
    #[test]
    fn the_endgame_ladder_spends_a_block_accounts_bytes_where_speed_may_not() {
        let sh = racing_shared(true); // server 0 flagged block_account
        // Endgame-scale remainder, article in flight on server 1 and
        // already refused there: the ladder shape exactly.
        sh.pending.store(4, Ordering::Release);
        sh.inflight.lock_ok().insert(
            "<laddered@x>".into(),
            Inflight {
                age_days: 0,
                part: 0,
                file: u32::MAX,
                ord: 0,
                server: 1,
                dispatched: Instant::now(),
                dups: 0,
                tried_430: server_bit(1),
                dup_servers: 0,
                tried_fail: 0,
                suspect: false,
                found: 0,
            },
        );
        let w = sh
            .pick_dup(0, 1, 1, 0, Pipeline::payload(0), 0)
            .expect("the verdict ladder is exempt from the block gate");
        assert_eq!(&*w.id, "<laddered@x>");
        assert!(w.ladder, "a ladder pick must be classified as one");
        assert!(
            !w.probe,
            "stat_probe is off here, so the dispatch is a BODY - the \
             metered copy this test exists to record"
        );
    }

    /// TODO 96.4: with the probe armed, that same metered dispatch asks
    /// with STAT instead, so the block account answers the verdict
    /// question for one line rather than one article.
    #[test]
    fn a_stat_probe_turns_the_metered_ladder_dispatch_into_a_question() {
        let cfg = |block| PoolConfig {
            race_envelope: true,
            hedge: true,
            block_account: block,
            stat_probe: true,
            ..PoolConfig::default()
        };
        let servers = vec![(server("a"), cfg(true)), (server("b"), cfg(false))];
        let sh = Shared::new(fresh_n(100), &servers).0;
        sh.alive[0].store(1, Ordering::Relaxed);
        sh.alive[1].store(1, Ordering::Relaxed);
        sh.pending.store(4, Ordering::Release);
        sh.inflight.lock_ok().insert(
            "<laddered@x>".into(),
            Inflight {
                age_days: 0,
                part: 0,
                file: u32::MAX,
                ord: 0,
                server: 1,
                dispatched: Instant::now(),
                dups: 0,
                tried_430: server_bit(1),
                dup_servers: 0,
                tried_fail: 0,
                suspect: false,
                found: 0,
            },
        );
        let w = sh
            .pick_dup(0, 1, 1, 0, Pipeline::payload(0), 0)
            .expect("the verdict ladder still fires under the probe");
        assert!(w.ladder && w.probe, "the metered racer must ask with STAT");
        // And a holder found by a probe ends the fan-out: no further
        // backbone is asked a question whose answer is already known.
        sh.note_found("<laddered@x>", 1);
        assert!(
            sh.pick_dup(0, 1, 1, 0, Pipeline::payload(0), 0).is_none(),
            "the ladder kept asking after a probe found a holder"
        );
    }

    #[test]
    fn a_block_account_picker_never_races_on_speed() {
        let sh = racing_shared(true); // server 0 flagged block_account
        inflight_entry(&sh, "<old@x>", 1, Duration::from_secs(1));
        assert!(
            sh.pick_dup(0, 1, 1, 0, Pipeline::payload(0), 0).is_none(),
            "a flagged server's bytes are never spent speculatively (5.7)"
        );
    }

    #[test]
    fn stale_hedge_judges_by_the_owners_article_time() {
        let sh = racing_shared(false);
        // Train the OWNER's article time to 400 ms: its per-owner bound
        // is 1.2 s. An article at 2 s is stale by the owner's own
        // clock even though the global EWMA is untrained (flat 8 s) -
        // the shaped-provider blindness the per-server bound fixes.
        sh.note_srv_art(1, 400);
        inflight_entry(&sh, "<stale@x>", 1, Duration::from_secs(2));
        // Busy picker allowed: the stale rule keeps its shipped gates.
        let before = sh.hedges_issued.load(Ordering::Relaxed);
        let w = sh
            .pick_dup(0, 1, 1, 0, Pipeline::payload(1), 0)
            .expect("per-owner stale fires");
        assert_eq!(&*w.id, "<stale@x>");
        assert_eq!(
            sh.hedges_issued.load(Ordering::Relaxed),
            before + 1,
            "a stale-only pick counts against the hedge issue-rate cap"
        );
    }

    /// A2 dup-path trap, `pick_dup` flavour (the suspect-race twin
    /// lives in pool/unit_tests.rs): the stale-owner dup is a fresh
    /// Work seeded from the inflight entry, and must inherit the
    /// original's age and part or a dup-delivered body trains the
    /// oracle at age 0 and slips the split-brain part gate.
    #[test]
    fn a_stale_race_dup_inherits_the_originals_age_and_part() {
        let sh = racing_shared(false);
        sh.note_srv_art(1, 400);
        inflight_entry(&sh, "<stale@x>", 1, Duration::from_secs(2));
        {
            let mut inf = sh.inflight.lock_ok();
            let e = inf.get_mut("<stale@x>").unwrap();
            e.age_days = 30;
            e.part = 2;
            e.ord = 5;
        }
        let w = sh
            .pick_dup(0, 1, 1, 0, Pipeline::payload(1), 0)
            .expect("per-owner stale fires");
        assert!(w.dup);
        assert_eq!(w.age_days, 30, "a dup delivery charges the TRUE age");
        assert_eq!(w.part, 2, "a dup delivery still faces the part gate");
        assert_eq!(w.ord, 5, "a dup claims the original's completion bit");
    }

    #[test]
    fn faster_can_take_judges_by_the_windowed_rate() {
        let sh = two_server_shared();
        sh.alive[0].store(1, Ordering::Relaxed);
        sh.alive[1].store(1, Ordering::Relaxed);
        let w = Work {
            age_days: 0,
            part: 0,
            file: u32::MAX,
            ord: 0,
            id: "<a@x>".into(),
            attempts: 0,
            promoted: true,
            tried_430: 0,
            tried_fail: 0,
            dup: false,
            prebyte_expiries: 0,
            soft_430: 0,
            recheck_430: 0,
            recheck_at: 0,
            fenced: false,
            rearms: 0,
            ladder: false,
            probe: false,
        };
        // Untrained everywhere: no clear winner, everyone takes it.
        assert!(!sh.faster_can_take(&w, 0));
        // Server 1 windowed-fast, server 0 windowed-slow: 0 leaves it.
        sh.note_srv_bytes(0, 100_000);
        sh.note_srv_bytes(1, 10_000_000);
        assert!(sh.faster_can_take(&w, 0));
        assert!(!sh.faster_can_take(&w, 1));
    }
}
