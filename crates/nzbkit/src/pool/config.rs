//! What the pool is TOLD to do: every knob, its neutral default, and
//! the posture the daemon actually ships.
//!
//! Pure configuration - a `Clone` data type, a `Default`, and one named
//! profile. Nothing here is state and nothing here does work: the live
//! per-server dial that moves mid-run is [`super::ConnTarget`], which
//! says so at its own site and deliberately stays in the parent.
//!
//! Split out of pool.rs for the size gate (TODO 106); `pool::PoolConfig`
//! is re-exported, so no caller anywhere spells a new path.

use std::sync::Arc;
use std::time::Duration;

use super::{
    BufPool, CAP_PROBE_BOUNCES, CONN_DARK, ConnTarget, LiveStats, OUTAGE_BUDGET, RECHECK_430_HOLD,
    RECHECK_430_MAX, RateLimit, handoff, linecap,
};

#[derive(Clone)]
pub struct PoolConfig {
    /// Memory-floor gauge for bodies queued in this pool's outcome
    /// channel (memgauge, instrument-first). None (the default) charges
    /// nothing: only a consumer that RELEASES the charge on receive may
    /// set this - a fire-and-forget consumer (sidefetch, post checks,
    /// nettools probes) would leak the gauge upward monotonically. The
    /// get pipeline sets `Sub::Channel` and releases in its drain.
    pub channel_gauge: Option<crate::memgauge::Sub>,
    pub connections: usize,
    /// Pipelined BODY commands in flight per connection.
    pub window: usize,
    /// Stagger between connection spawns (connect-burst avoidance).
    pub ramp_delay: Duration,
    /// Transport-failure attempts per article before reporting Failed.
    pub article_retries: u8,
    /// Per-response read timeout (stall detection).
    pub read_timeout: Duration,
    /// TODO 96.1, graduated to the "Adaptive connection timeouts"
    /// setting (adaptive_timeouts, ON by default; env
    /// NZBFAST_ADAPTIVE_TIMEOUT overrides in either direction):
    /// replace the flat whole-response `read_timeout` with a two-phase
    /// bound - an adaptive pre-byte budget from the server's TTFB EWMA
    /// (dead connections detected in 2-10 s instead of 30) plus a
    /// progress-rolling stall deadline on the body (a slow-but-alive
    /// transfer is never killed for exceeding a flat cap).
    pub adaptive_timeout: bool,
    /// Backoff after a failed connect, doubled per consecutive failure.
    pub connect_backoff: Duration,
    /// Consecutive connect failures before a worker gives up.
    pub max_connect_attempts: u32,
    /// Paced dials the elected prober rides before declaring a parked
    /// server dead (see [`CAP_PROBE_BOUNCES`], the shipped default).
    /// Configurable for tests only: the ladder is paced off
    /// `connect_backoff`, so a test that shrinks the backoff to keep
    /// the suite quick is left paying 75 REAL connect attempts, and
    /// what one of those costs is the platform's business, not ours -
    /// a refused loopback connect is microseconds on macOS and ~2 s on
    /// Windows, where its SYN is retried. 75 x 2 s outlasted the seal
    /// test's whole budget and read as a pool hang on Windows alone.
    /// Production never notices: at the default 8 s backoff the ladder
    /// is backoff-dominated and a slow refusal is noise.
    pub cap_probe_bounces: u32,
    /// Total time a server may spend granting NO sessions during one run
    /// before it is retired for the rest of that run; `None` = never
    /// give up on it.
    ///
    /// The ceiling `cap_probe_bounces` cannot be. That ladder counts
    /// CONSECUTIVE bounces and any granted session resets it, so a
    /// provider at its account cap that frees one slot every few minutes
    /// renews the ~10 minute horizon indefinitely and the run never
    /// reaches a terminal - the job simply sits at zero bytes. This
    /// budget accumulates across episodes and cannot be rewound, so the
    /// pathological case is bounded while an ordinary reconnect costs
    /// its own seconds and nothing more.
    ///
    /// Retiring is not a verdict about the POST: the articles that only
    /// that server carried end up transport-failed, which the daemon
    /// classifies `FailKind::Transport` - auto-retried from the journal,
    /// and never reported to an indexer as a dead post.
    ///
    /// `None` is a real configuration, not a disabled feature: a user
    /// who would rather a job wait all night than come back as failed
    /// sets it, and the queue row now says which provider it is waiting
    /// on for the whole wait.
    ///
    /// It stands `cap_probe_bounces` down as well, because otherwise it
    /// would not deliver what it promises: a wholly unreachable server
    /// would still be retired on that ladder at ~10 minutes and the job
    /// would still come back failed. With it `None` the pool waits, and
    /// the run does not end on its own - by request. The auto-defer
    /// watchdog is what keeps the rest of the queue moving.
    pub outage_budget: Option<Duration>,
    /// Shared body-buffer pool; None = allocate per article.
    pub buf_pool: Option<Arc<BufPool>>,
    /// Live per-server gauges for dashboards (M14h); None = don't track.
    pub live: Option<Arc<LiveStats>>,
    /// TODO 112: live connection target for THIS server; None = every
    /// spawned worker runs, the old behaviour. See [`ConnTarget`].
    pub live_target: Option<Arc<ConnTarget>>,
    /// TODO 208 item 1: the whole fleet's connection budget the in-run
    /// shed walks `live_target` down to its share of (see
    /// `pool::linecap`); 0 = off. MAX-folded across the fleet, like the
    /// gauge's `pct`. A flat constant between 23 and 24 Aug 2026; since
    /// TODO 277 it is the SEED of a curve on the line rate, which the
    /// governor may grow during the run when `line_cap_auto`.
    pub line_cap_fleet: usize,
    /// TODO 277: is `line_cap_fleet` the curve's own number (true) or
    /// one somebody typed (false)? Only the first may be grown in-run -
    /// a leg that typed `NZBFAST_LINE_CAP=40` is asking for 40 sockets,
    /// not for a floor of 40. ALL-folded across the fleet, unlike
    /// everything else here, because one typed number pins the arm.
    pub line_cap_auto: bool,
    /// TODO 312 item 3: what THIS server would dial if the fleet cap
    /// took nothing out - the `--connections` dial, the account's own
    /// number, any host cap AND any applied auto-tune knee, with only
    /// the fleet cap left out. 0 = nothing here for the cap to take,
    /// which is both "the builder did not say" and the PINNED case.
    ///
    /// Carried so a surface can answer "is our own cap the binding
    /// constraint" with the number the cap was actually measured
    /// against, rather than by re-deriving it from a config the pool
    /// cannot see. `budget` is the number in FORCE and says nothing
    /// about what was given up to reach it; the difference between the
    /// two is the whole claim.
    ///
    /// TWO THINGS LAND HERE ON 28 Aug 2026, both argued at their
    /// producer: THE KNEE IS IN IT (`conntune::dialable_ceiling`) and A
    /// PINNED SERVER STAMPS 0 (`cap_exposed` in `get/fleet.rs`).
    pub line_cap_uncapped: usize,
    /// TODO 312 item 7: the STALE auto-tune knee holding this server
    /// under its own ceiling, `None` when nothing here is. Rule in
    /// [`linecap::ServerKnee`], producer `conntune::stale_knee`.
    pub line_cap_knee: Option<linecap::ServerKnee>,
    /// TODO 208 item 1: the line rate in bytes/s the daemon has seen
    /// this link sustain (its persisted link anchor), 0 = none. The cap
    /// no longer divides it, but the in-run shed still stands down
    /// without it, and the stall bound sizes an article's share from
    /// it. MAX-folded across the fleet.
    pub line_anchor_bps: u64,
    /// TODO 275 item 1 part 1: was `line_anchor_bps` MEASURED on this
    /// link, or is it the line speed a user TYPED into Settings?
    /// `linkpeak::Core::effective` has always answered both questions
    /// and the daemon threw the second away at
    /// `tasks/runner.rs`, so the pool sized fleets off a number
    /// whose provenance it could not see.
    ///
    /// ALL-folded across the fleet, like `line_cap_auto` and for the
    /// same shape of reason: one server carrying a typed anchor makes
    /// the whole fleet's reading typed, because the fold is a claim
    /// about the LINE and the weakest evidence is what the claim is
    /// worth.
    ///
    /// **Since 2 Sep 2026 one rule DOES read it** - the second fleet
    /// ceiling (TODO 275 item 7), through
    /// `linecap::supply_ceiling`. It exists because
    /// `fleet_for_supply`'s safety case rests entirely on
    /// `LINE_CAP_MAX_FLEET` being a rung TODO 208 measured free, which
    /// is what lets that arm run on an anchor it cannot prove: raising
    /// the ceiling for the slow-carry regime means keeping today's
    /// ceiling for a typed anchor, and this word is what makes the two
    /// separable. It is the ONE thing it licenses. Anything else
    /// branching on it is a second decision and wants its own
    /// measurement - see `supply_ceiling`'s doc for what this word does
    /// and does not prove.
    pub line_anchor_measured: bool,
    /// Shared pool-level speed limiter; None = unlimited.
    pub rate: Option<Arc<RateLimit>>,
    /// M29 availability oracle: per-article hit/430 outcomes accumulate
    /// here (in memory - the daemon flushes to the ledger per job).
    /// None = don't record.
    pub oracle: Option<Arc<crate::oracle::OracleSink>>,
    /// B3 wire-cap: global in-flight body byte ceiling across the whole
    /// pool (see MemBudget::inflight_cap). Over it, workers stop topping
    /// up their pipeline beyond one request in flight. 0 = uncapped.
    pub inflight_cap: u64,
    /// TODO 275 item 10: the extractor's held-span ceiling in bytes
    /// (`MemBudget::holds_cap`), which the fleet governor reads as a
    /// CONSUMER-pressure signal. 0 = no claim, and the gate is inert.
    ///
    /// The fleet buys a REORDER WINDOW, and a sequential consumer has
    /// to buffer everything that arrives out of order. Measured 2 Sep
    /// 2026 on a 10 GbE cold route: at 100 sockets the holds ledger
    /// pins at its cap and the job runs 3.31x longer per GB than the
    /// same job at 50, where holds reach a quarter of the cap. So the
    /// pool needs the ceiling to know when it is close to it - see
    /// `Shared::line_cap_tick`, which is the only reader.
    ///
    /// A process-wide budget rather than this job's share, like the
    /// gauge it is compared against.
    pub holds_cap: u64,
    /// The ledger [`inflight_cap`](Self::inflight_cap) is compared
    /// against: `None` = this pool alone, `Some` = shared with every
    /// other pool holding the same handle.
    ///
    /// The cap is a slice of ONE process budget, so the charge has to
    /// be shared by everything drawing on that budget or the ceiling is
    /// per pipeline and there are two of them at every queue boundary
    /// (TODO 313 item 1 - see [`crate::pool::WireCharge`]). Production
    /// passes [`crate::pool::process_wire_charge`]; `None` keeps a
    /// private counter, which is the identical number for a run that is
    /// the only pipeline in its process.
    pub wire_charge: Option<std::sync::Arc<crate::pool::WireCharge>>,
    /// Connections that outlive this run (see [`crate::warmpool`]).
    /// None = the old behaviour, connect per run and QUIT at the end,
    /// which is still right for a one-shot CLI `get`.
    pub warm: Option<Arc<crate::warmpool::WarmPool>>,
    /// Cross-job hand-over (see [`handoff`]): this server's connection
    /// cap as a lease shared with the NEXT job's run. A worker takes a
    /// permit before it claims or dials and holds it while it has a
    /// socket; an idle worker after queue-dry hands its socket back when
    /// a successor is waiting on the lease. None = no successor can ever
    /// be waiting, which is the CLI and every test that does not opt in.
    pub lease: Option<Arc<handoff::HostLease>>,
    /// Which class this pool's workers take [`Self::lease`] permits as
    /// (see [`handoff::LeaseClass`]). `Download` (the default) stops one
    /// short of the account's cap so a `PostProcess` side pool always has
    /// a permit; `PostProcess` may take that reserved one.
    ///
    /// Set by `repair::sidefetch::strip_side_pool_seams`, which is the
    /// one driver EVERY side-fetch goes through - so a caller that
    /// clones the download's configs cannot land a post-processing pool
    /// in the download's own class and starve itself.
    pub lease_class: handoff::LeaseClass,
    /// TODO 313 items 2 and 10: this pool's seat in a queue SPILL - the
    /// shared gate the daemon's governor opens for a live episode, and
    /// which side of it this run is on. `None` is every pool that is
    /// not on that path at all, which is the CLI, every test that does
    /// not opt in, and every job on an install with `queue_spill` off.
    ///
    /// Nothing here is a second connection budget: what a run may hold
    /// is still [`Self::lease`]'s answer and nobody else's. This only
    /// decides whether a HEAD's parked worker gives its permit back
    /// while it is parked, and whether a LANE may hand a socket over
    /// before its own queue is dry.
    pub spill: Option<handoff::SpillSeat>,
    /// Per-run latch the caller awaits to start the next job: latched
    /// the first time a primary worker finds itself idle after queue-dry.
    pub handoff: Option<Arc<handoff::HandoffSignal>>,
    /// Tail fan-out prototype (off by default, env NZBFAST_TAIL_FANOUT=1):
    /// in the endgame, an IDLE primary connection races a healthy
    /// in-flight article too - same server included - instead of only
    /// the 430-laddering ones. First completion wins, the loser's read
    /// is abandoned, so the waste is bounded to bytes-in-flight at win
    /// time. See `pick_dup` for the exact gates.
    pub tail_fanout: bool,
    /// TODO 208 item 3 endgame depth taper (dark, env NZBFAST_TAIL_TAPER=1):
    /// as the work left in the run falls toward one article per
    /// connection, cap the TOP-UP depth so the fleet arrives at
    /// queue-dry holding roughly one article each instead of `window`
    /// each. The drain that follows queue-dry is exactly the in-flight
    /// set emptying - `conns x window` articles, measured at 1.13-1.62
    /// GB on every banked 1 GbE bench leg regardless of fixture, line
    /// speed or the §202 gate. That stretch is not line-idle - it is
    /// payload arriving - so this is a ROBUSTNESS bound, not a
    /// throughput one: a connection that grabbed four of the last
    /// articles cannot hand them back when a faster one goes idle, and
    /// the tail is where one wedged session is the wall. Tapering
    /// leaves that work in the QUEUE, where it can still be
    /// rebalanced, and costs only the round trip between a completion
    /// and the next BODY at depth 1. See [`Shared::tail_window`].
    pub tail_taper: bool,
    /// M7b.2 depth steering (dark, env NZBFAST_STEER_DEPTH=1): a server
    /// whose windowed per-conn rate falls below 1/4 of the best other
    /// live server's tops its pipelines up to depth 1 instead of
    /// `window`, restoring above 1/2 (hysteresis; thresholds env-tunable
    /// while open question 9.3 of the steering design collects measured
    /// values). Full participation at bounded commitment - never a
    /// demotion (§129 3d): the server keeps every connection fetching,
    /// it just stops parking `window` articles behind each slow session.
    /// The clamp gates TOP-UP only; an already-deep pipeline drains
    /// naturally (no shed - that would be a different, gated feature).
    pub steer_depth: bool,
    /// M7b.2 envelope racing (dark, env NZBFAST_RACE_ENVELOPE=1):
    /// per-owner hedge bounds, the idle-picker envelope-race arm, and
    /// the fleet-wide dup-spend hygiene cap; the whole-run 2x
    /// slow-owner rule retires while armed. See `steer::speculative_arm`.
    pub race_envelope: bool,
    /// TODO 202: speculative racing stands down while the fleet's
    /// now-rate is within this percent of the run's observed line peak
    /// - on a saturated line a duplicate can only displace payload.
    /// 0 = gate off. See `pool/saturation.rs`. Env NZBFAST_RACE_SAT_PCT.
    /// 70 since 22 Aug 2026 (TODO 208 item 4 ladder: 90 is a cliff,
    /// 70 ties 80 on wall and spends less; the why is in `get/fleet.rs`).
    pub race_sat_pct: u8,
    /// TODO 202 §17: the per-ARTICLE escape from the gate above, ON by
    /// default - an article whose owner has moved NO bytes is raced
    /// even while the fleet reads saturated, because it is not
    /// competing for the line. Rationale and the arithmetic that forces
    /// it: `Shared::not_using_the_line`. Env NZBFAST_RACE_ESCAPE (0 =
    /// off), which is the arm that prices the escape on ONE binary -
    /// `race_sat_pct` 0-vs-80 prices the GATE and cannot price this,
    /// since at 0 there is no gate to escape from.
    pub race_escape: bool,
    /// TODO 208.2 warm-up: the stall bound is re-read DURING a silence
    /// and fed before the peak trains (see `Shared::stall_bound`). ON
    /// by default; env NZBFAST_STALL_LIVE (0 = off) is the A/B arm;
    /// fleet-wide, `any`-folded like `race_escape`.
    pub stall_live: bool,
    /// TODO 208.2 over-read: gauge fed per arriving chunk (`pool/saturation.rs`); env NZBFAST_PEAK_ARRIVALS (0 = off).
    pub peak_arrivals: bool,
    /// Steering design §5.7: every byte on this server costs money -
    /// spend none deliberately. Excludes it from all speculative dup
    /// pickers; the endgame verdict ladder and the CRC-steer refetch
    /// stay eligible (last-resort/only-source). Per-server, never
    /// OR-folded; wired from the server's block_account setting.
    pub block_account: bool,
    /// TODO 313 item 7: how many EXTRA sockets a temporary surge may
    /// hold across the whole fleet while a stuck article has no idle
    /// connection to be raced on. 0 = OFF, which is every install
    /// today; `shipped()` deliberately does not set it.
    ///
    /// MAX-folded across the fleet by `pool::surge::Surge::new` and
    /// clamped there to [`super::SURGE_MAX_CLAMP`], because it is a
    /// WHOLE-FLEET socket allowance in the same currency as the fleet
    /// cap - one server asking for it is the fleet asking for it. Wired
    /// from settings.json `surge_conns` (env NZBFAST_SURGE), never from
    /// a per-server row.
    pub surge_max: usize,
    /// §96.5 mid-run block cap: bytes this server may still spend on
    /// THIS run (its prepaid block minus the lifetime already billed),
    /// seeded by the daemon at fleet build. When the run's own
    /// per-server byte counter crosses it, the server's workers drain
    /// what is in flight and bow out for good - nothing is shed, and
    /// the shared queue hands its remaining articles to the other
    /// servers. None or Some(0) = unlimited, matching the config
    /// convention that a zero block means "no block configured" (an
    /// ALREADY-spent block never reaches here - the daemon's job-start
    /// exclusion rules the host out of the fleet entirely).
    pub budget_bytes: Option<u64>,
    /// Hedged-request experiment (off by default, env NZBFAST_HEDGE=1):
    /// replace the flat 8 s staleness bound in the dup race with an
    /// adaptive one - 3x the trained dispatch-to-done article-time EWMA,
    /// clamped to [500 ms, 8 s] - so a mid-run straggler is raced after
    /// roughly three article-times instead of a flat 8 s. Hedge issue
    /// rate is capped (see `pick_dup`) so jitter cannot turn into a
    /// duplicate storm.
    pub hedge: bool,
    /// TTFB-suspicion hedge (TODO 115, off by default, env
    /// NZBFAST_TTFB_HEDGE=1): when an adaptive-path read has sat in
    /// PRE-BYTE silence past a suspicion bound (~1 s, or 2x the
    /// server's TTFB EWMA if that is larger), the article is marked
    /// suspect and any topping-up worker dup-races it IMMEDIATELY -
    /// same server included - instead of waiting out the full adaptive
    /// pre-byte budget (floor 4 s) plus a requeue round-trip. First
    /// answer wins, the owner's read is never killed, and every
    /// suspect dup counts against the hedge issue-rate cap so jitter
    /// cannot turn suspicion into a duplicate storm. Only meaningful
    /// with `adaptive_timeout` (the flat read has no pre-byte phase).
    pub ttfb_hedge: bool,
    /// Slow-connection recycle experiment (off by default, env
    /// NZBFAST_RECYCLE_SLOW=1): a connection whose articles keep LOSING
    /// dup races is a degraded TCP session - after
    /// [`RECYCLE_RACE_LOSSES`] consecutive losses it sheds its pipeline
    /// and redials instead of continuing to lose. Racing fixes the
    /// symptom per article; this fixes the cause. Endgame losses never
    /// count: the tail fan-out races every straggler, and losing a
    /// speculative race is not degradation evidence (TODO 111).
    pub recycle_slow: bool,
    /// Slope-recycle experiment (off by default, env
    /// NZBFAST_RECYCLE_SLOPE=1): a session whose own delivery rate sits
    /// below a quarter of its server's per-worker average after 10 s is
    /// a degraded TCP session - redial it proactively, before it loses
    /// races or strands a tail article. The reactive `recycle_slow`
    /// waits for the damage; this watches the slope.
    pub recycle_slope: bool,
    /// Hot-spare experiment (off by default, env NZBFAST_HOT_SPARE=1):
    /// keep ONE authenticated spare connection parked per server during
    /// the run; a worker whose session dies claims it instantly instead
    /// of paying dial + TLS + auth in its critical path, and a filler
    /// task re-dials the spare in the background. The spare is +1 over
    /// the configured budget - a provider at its cap simply refuses it,
    /// which costs nothing.
    pub hot_spare: bool,
    /// Early fan-out experiment (env NZBFAST_TAIL_FANOUT=2, which also
    /// implies `tail_fanout`): arm the endgame dup rules from the
    /// moment the queue runs dry (the pool's tail latch) instead of
    /// waiting for pending <= ENDGAME_MAX. With a big fleet the queue
    /// dries with far more than 64 articles in flight - 48 connections
    /// at window 4 is ~190 - and that whole stretch has idle capacity
    /// the endgame gate refuses to spend. Earlier than queue-dry is
    /// meaningless by construction: no worker is idle before it.
    pub tail_fanout_early: bool,
    /// Flap breaker (ON by default): a server whose ESTABLISHED
    /// sessions keep dying - an external party burning its IP cap, a
    /// provider throttling the account - is clamped to ONE keeper
    /// connection for the rest of the run, as long as another server is
    /// live. The keeper retries (and serves, whenever the provider lets
    /// it in); the rest of the fleet stops churning through
    /// shed-pipeline/redial cycles and its capacity flows to healthy
    /// servers through the shared queue. Without this, a
    /// flapping-but-occasionally-working server never quiets down: the
    /// occasional good session clears the failure counters that retire
    /// a DEAD one.
    pub flap_breaker: bool,
    /// Cap-aware flap keepers (ON by default since the 5 Aug
    /// graduation, env NZBFAST_FLAP_CAP_KEEPERS overrides either way,
    /// TODO 115): when the flap breaker
    /// clamps a server whose accept cap we have OBSERVED (dials bounced
    /// off a capacity refusal while N sessions were established), hold
    /// min(observed cap, configured connections) keepers instead of a
    /// flat one. The eweka IP-cap shape allows two sessions; a single
    /// keeper leaves the second slot - throughput the provider is
    /// willing to give us - on the table (fault matrix 5 Aug: NZBGet
    /// takes it, but with 217 dials of hammering; ours stays in the
    /// tens because keepers redial only when their own session dies and
    /// back off paced on any capacity bounce, never a tight loop).
    /// Never exceeds the per-server connection budget, which is where
    /// account limits (and max_source_ips-derived caps) already landed.
    /// Graduation evidence (standalone chaos flap leg, one box, one
    /// corpus): 43/43 s at 24 dials off, 40/40 s at 36 dials on - a
    /// wall that ties the best competitor while dialling a refusing
    /// provider 6x less than it does.
    pub flap_cap_keepers: bool,
    /// Consumer-triggered CRC retry-elsewhere (TODO 111/114): a body
    /// that fails its own yEnc pcrc32 - or decodes to a different part
    /// than the segment asked for (split-brain; its CRC passes) - is
    /// requeued to a DIFFERENT server exactly once instead of riding
    /// to PAR2 repair. Detection is the decode consumer's EXISTING
    /// pass, reported back through [`QueueControl::note_decoded`]: a
    /// Done outcome defers its `complete_one` and parks its Work in
    /// `Shared::handed` until the verdict, and a bad body is requeued
    /// after claim, the clean refetch re-claiming through the normal
    /// arbitration. (The first cut validation-decoded in the pool -
    /// ~25% CPU at the loopback ceiling; the consumer seam priced at
    /// off-parity CPU, which is why the multi-server pricing gate
    /// could go.) Requires a consumer that actually calls
    /// `note_decoded` for every Done it receives; the download
    /// pipeline's decode consumers do, the other pool users (repair,
    /// nettools, post) leave this off.
    pub crc_steer: bool,
    /// §129 3g: follow every BODY to a provider that has answered a
    /// refusal with no message-id with an alignment fence - a DATE,
    /// pipelined behind it, whose answer cannot be mistaken for a
    /// BODY's ([`Connection::send_fence`]). It is what makes positional
    /// attribution CHECKABLE on a provider that gives us nothing to
    /// check: without it a response dropped upstream is invisible, and
    /// a present article silently collects the refusal meant for the
    /// article behind it.
    ///
    /// On by default, off with `NZBFAST_DESYNC_FENCE=0`. It costs one
    /// six-byte command and one short answer per article, only against
    /// providers that refuse bare, and no round trips - the fence rides
    /// the same pipeline. What it buys is in `provider_demote_rig`:
    /// re-arming the confirming repeat alone still leaked a present
    /// article once in 11 runs at 1-in-7 withheld responses, because
    /// the proof of a desync can arrive AFTER the verdict it should
    /// have stopped. The fence removes the misattribution instead of
    /// undoing it.
    pub desync_fence: bool,
    /// TODO 315: hold the refusal that would make an article terminal,
    /// requeue the article at the queue MIDPOINT, and let the LAST live
    /// backbone answer once more before the Missing verdict is emitted;
    /// on by default, off with `NZBFAST_RECHECK_430=0`. The measurement
    /// that says an echoed refusal is not proof it is gone, and every
    /// design decision behind this, are at [`Shared::take_recheck`].
    ///
    /// It said BACK until 29 Aug 2026 and the doc said so until 30 Aug;
    /// the back is not a delay, it is the end of the run, and the two
    /// e2e tests that caught it are at [`recheck_slot`].
    pub recheck_430: bool,
    /// TODO 315: ceiling on articles holding a late re-ask at one time.
    /// `NZBFAST_RECHECK_430_MAX` overrides it; what it bounds, and why
    /// it is not simply large, is at [`RECHECK_430_MAX`].
    pub recheck_430_max: usize,
    /// TODO 315: how long one late re-ask may keep an article out of a
    /// terminal verdict. `NZBFAST_RECHECK_430_HOLD_SECS` overrides it
    /// (0 disables the bound, which is what the tests that want the old
    /// unbounded shape ask for); what it bounds, why the bound has to
    /// exist at all, and why it deliberately does NOT inherit
    /// [`PoolConfig::outage_budget`], are at [`RECHECK_430_HOLD`].
    pub recheck_430_hold: std::time::Duration,
    /// How long a server may hold no session at all before it stops
    /// blocking a terminal verdict for articles it has never refused,
    /// and stops holding the fill gate shut over them.
    /// `NZBFAST_CONN_DARK_SECS` overrides it (0 disables the bound,
    /// which is what the tests that want the pre-30-Aug-2026 shape ask
    /// for); what it bounds, why the bound has to exist at all, why two
    /// minutes, and why it deliberately does NOT inherit
    /// [`PoolConfig::outage_budget`], are at [`CONN_DARK`].
    pub conn_dark: std::time::Duration,
    /// TODO 121.4: the consumer acks every Done id (`note_settled`, or
    /// `note_decoded` under `crc_steer`), so the pool keeps the
    /// article's `done_ok` liveness entry until the body is DECODED
    /// AND WRITTEN, not merely accepted by the outcome channel. That
    /// closes the dead-span verdict's last blind window - a body
    /// sitting in the channel buffer or a decode worker's in-hand
    /// batch under disk backpressure - which could outlast the
    /// grace-plus-votes threshold and let /stream zero-fill bytes it
    /// already had. Same contract as `crc_steer`: only turn this on
    /// for pools whose consumer really acks every Done (the download
    /// pipeline's decode consumers); an ack-less consumer would leak
    /// the set and pin every span "live" forever.
    pub arrival_ack: bool,
    /// TODO 96.4: issue the endgame ladder's FAN-OUT dispatches as STAT
    /// rather than BODY. A fan-out dup exists to buy a verdict, and on
    /// an article that is merely absent from one backbone every racer
    /// that HAS it delivers a whole body for a claim only one of them
    /// can win. STAT answers the same question - the refusal codes are
    /// identical, so `handle_missing`'s unanimity is unchanged - and
    /// the hit costs one line instead of an article.
    ///
    /// It buys that with a round trip: a 223 is not bytes, so an
    /// article the fan-out would have DELIVERED now has to be fetched
    /// after the probe. Off by default because the phase this runs in
    /// is the one §146 measured to be round-trip-bound with the wire
    /// idle - see the §96 item 4 write-up for the A/B that says so.
    /// `NZBFAST_STAT_PROBE=1` turns it on.
    pub stat_probe: bool,
    /// Where to report that this pool is HOLDING an article's terminal
    /// verdict back (TODO 315's late re-ask, and §129's confirming
    /// repeat for a bare refusal that would otherwise be the last
    /// evidence the article needs).
    ///
    /// None everywhere but the `get` pipeline, which points it at the
    /// job's own extractor. What reads it and why nothing else can
    /// answer the question in time is
    /// [`crate::lossdoubt::LossDoubt`]'s own doc: the extractor's
    /// terminal-verdict flag is the drop-behind trim's veto, and it
    /// lands after the pile has built, so a chase under the holds park
    /// can drop a prefix a repair then needs. A store and nothing more -
    /// the pool never reads it back, and a `None` here is exactly the
    /// behaviour every caller had before the field existed.
    pub loss_doubt: Option<Arc<crate::lossdoubt::LossDoubt>>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            channel_gauge: None,
            connections: 6,
            window: 3,
            ramp_delay: Duration::from_millis(150),
            article_retries: 3,
            read_timeout: Duration::from_secs(30),
            adaptive_timeout: false,
            connect_backoff: Duration::from_secs(2),
            max_connect_attempts: 5,
            cap_probe_bounces: CAP_PROBE_BOUNCES,
            outage_budget: Some(OUTAGE_BUDGET),
            buf_pool: None,
            live: None,
            live_target: None,
            lease: None,
            lease_class: handoff::LeaseClass::Download,
            spill: None,
            handoff: None,
            line_cap_fleet: 0,
            line_cap_auto: false,
            line_cap_uncapped: 0,
            line_cap_knee: None,
            line_anchor_bps: 0,
            line_anchor_measured: false,
            rate: None,
            oracle: None,
            inflight_cap: 0,
            holds_cap: 0,
            wire_charge: None,
            warm: None,
            tail_fanout: false,
            tail_taper: false,
            steer_depth: false,
            race_envelope: false,
            race_sat_pct: 70,
            race_escape: true,
            stall_live: true,
            peak_arrivals: true,
            block_account: false,
            surge_max: 0,
            budget_bytes: None,
            hedge: false,
            ttfb_hedge: false,
            recycle_slow: false,
            recycle_slope: false,
            hot_spare: false,
            tail_fanout_early: false,
            flap_breaker: true,
            // The env override lives HERE, not only in build_fleet, so
            // every pool - nettools probes, post_cmd, warm-pool rigs -
            // honors NZBFAST_FLAP_CAP_KEEPERS=0 (TODO 121.3; before
            // this, a default-built pool ignored the knob entirely).
            flap_cap_keepers: std::env::var("NZBFAST_FLAP_CAP_KEEPERS")
                .ok()
                .is_none_or(|v| v == "1"),
            crc_steer: false,
            arrival_ack: false,
            // §129 3g. Default ON, with the kill switch HERE rather than
            // only in build_fleet for the same reason `flap_cap_keepers`
            // has it here: every pool must honor it.
            desync_fence: std::env::var("NZBFAST_DESYNC_FENCE")
                .ok()
                .is_none_or(|v| v == "1"),
            // TODO 315. Default ON with the kill switch HERE rather
            // than only in build_fleet, for `desync_fence`'s reason
            // directly above: every pool must honor it.
            recheck_430: std::env::var("NZBFAST_RECHECK_430")
                .ok()
                .is_none_or(|v| v == "1"),
            recheck_430_max: std::env::var("NZBFAST_RECHECK_430_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(RECHECK_430_MAX),
            // TODO 315. A mistyped knob falls back to the shipped
            // window rather than to zero: zero DISABLES the bound, so
            // `NZBFAST_RECHECK_430_HOLD_SECS=abc` silently restoring the
            // unbounded hold is the one reading this must not have.
            recheck_430_hold: std::env::var("NZBFAST_RECHECK_430_HOLD_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map_or(RECHECK_430_HOLD, std::time::Duration::from_secs),
            // A mistyped knob falls back to the shipped window rather
            // than to zero, for the reason directly above: zero DISABLES
            // the bound, so `NZBFAST_CONN_DARK_SECS=abc` silently
            // restoring the deadlock is the one reading this must not
            // have.
            conn_dark: std::env::var("NZBFAST_CONN_DARK_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map_or(CONN_DARK, std::time::Duration::from_secs),
            // TODO 96.4. Default OFF; same "every pool honors the knob"
            // placement as the two above.
            stat_probe: std::env::var("NZBFAST_STAT_PROBE")
                .ok()
                .is_some_and(|v| v == "1"),
            loss_doubt: None,
        }
    }
}

impl PoolConfig {
    /// The pool AS THE DAEMON SHIPS IT - the posture a measurement rig
    /// wants unless it is deliberately measuring something else.
    ///
    /// [`PoolConfig::default()`] is the library's neutral posture, with
    /// every speculation knob off. It is not what runs: `nzbfast`'s
    /// `get/fleet.rs` resolves two dashboard settings, both ON by
    /// default, into five of these fields.
    ///
    /// * "Race slow articles" (`race_stragglers`) -> [`Self::tail_fanout`],
    ///   [`Self::tail_fanout_early`], [`Self::hedge`],
    ///   [`Self::recycle_slope`].
    /// * "Adaptive connection timeouts" (`adaptive_timeouts`) ->
    ///   [`Self::adaptive_timeout`], in place of the flat
    ///   [`Self::read_timeout`].
    ///
    /// A fleet built from `default()` therefore has the whole endgame
    /// speculation layer and the adaptive read budget switched off, and
    /// a rig that tunes against it is tuning a fleet nobody runs. Build
    /// from this instead wherever those knobs are load-bearing:
    ///
    /// ```ignore
    /// PoolConfig { connections, ramp_delay: Duration::ZERO, ..PoolConfig::shipped() }
    /// ```
    ///
    /// Opting out is fine when it is the POINT - `tls_chaos` pins the
    /// flat 30 s read timeout it exists to test, and the demote rig's
    /// non-hostage legs stay pessimistic on purpose - but say so at the
    /// call site. The knobs that are still dark (`steer_depth`,
    /// `race_envelope`, `ttfb_hedge`, `recycle_slow`, `hot_spare`) are
    /// env-only in the daemon too, so they stay off here.
    ///
    /// Two fields the daemon also sets are deliberately NOT here,
    /// because neither is a property of the fleet alone.
    /// [`Self::crc_steer`] depends on fleet SHAPE (a same-level peer on
    /// another host must exist for a refetch-elsewhere to mean
    /// anything), and [`Self::arrival_ack`] is a contract with a
    /// consumer that calls `note_settled` - switching it on under a
    /// collector that never acks would leave every delivered article
    /// looking live. Rigs that want either one ask for it by name.
    ///
    /// Kept honest by `nzbfast`'s
    /// `get::fleet::tests::shipped_matches_the_daemons_own_defaults`,
    /// which reads the same two defaults out of `build_fleet`'s
    /// resolution path.
    pub fn shipped() -> Self {
        PoolConfig {
            adaptive_timeout: true,
            tail_fanout: true,
            tail_fanout_early: true,
            hedge: true,
            recycle_slope: true,
            ..PoolConfig::default()
        }
    }
}
