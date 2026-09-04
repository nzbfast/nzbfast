//! §129 4b: "Why is this slow?" - live per-job attribution.
//!
//! The layer that owns a shortfall, decided from signals the daemon
//! already collects, and asserted only when a window of evidence
//! agrees. The honesty rule is load-bearing: "unknown" is a valid and
//! expected verdict, and every asserted verdict travels with the
//! numbers that produced it. Design: research/
//! DESIGN-2026-08-08-129-4b-whyslow.md.
//!
//! Signals and their limits (each shaped by a prior lesson):
//!
//! - `blocked_ms` alone is NEVER evidence (§108/3e): a healthy fast
//!   download parks its workers almost continuously, because the
//!   fetch->decode channel is meant to fill when the network outruns
//!   decode. Blocking only discriminates AFTER a shortfall against the
//!   link anchor is established - and then it only says "downstream of
//!   the sockets", never which stage, because one counter covers
//!   decode, verify and the disk together.
//! - the split downstream therefore needs independent witnesses:
//!   sustained all-core CPU saturation condemns compute, a storage
//!   pause in force condemns the volume (slowstore probed it with a
//!   real write+fsync), and NEITHER witness condemning yields
//!   "client" - our pipeline, named plainly, not a guess at hardware.
//! - per-provider shaping is asserted only relatively and with the
//!   numbers shown: host X delivers this much per connection while
//!   host Y delivers that much, same box, same window. No claim about
//!   why.
//!
//! Like linkpeak §125 next door, the decision core is pure - driven
//! one tick per second with plain numbers, no IO, no clocks - so tests
//! can replay any regime a real line could produce.

use serde_json::{Value, json};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;

use super::job::WhyVerdict;
use crate::tools::MutexExt;

/// The vote window: one classification per second, verdicts need a
/// majority of it. Long enough that a two-second wobble cannot flip
/// the answer, short enough that a real regime change (a provider
/// browning out, a cap engaging) is named within half a minute.
pub const WINDOW: usize = 20;

/// Ticks of the window a layer must win before it is asserted. 60%:
/// an honest majority, not a plurality of noise.
const MAJORITY: usize = 12;

/// Achieved at or above this fraction of the link anchor IS line
/// speed - a TLS-overhead's air under the linkpeak confirm bar (0.9),
/// so the two surfaces never disagree about a link riding its peak.
const LINE_BAR: f64 = 0.88;

/// Achieved at or above this fraction of an active speed limit means
/// the limit is what's in charge.
const LIMIT_BAR: f64 = 0.90;

/// Fraction of total worker-time spent parked on the full
/// fetch->decode channel above which the bottleneck is downstream of
/// the sockets. Far above the parking noise a healthy download shows,
/// and only consulted after the shortfall gate - see the module note.
const BLOCKED_BAR: f64 = 0.40;

/// Sustained all-core CPU% that condemns compute for the downstream
/// case. All cores, not one: decode and verify are parallel.
const CPU_BAR: f64 = 85.0;

/// Fraction of the articles asked for that came back missing, above
/// which the POST is the shortfall rather than any layer of the stack.
///
/// A miss costs a full request round-trip and yields no bytes, so a
/// post full of holes reads on every other instrument exactly like a
/// slow provider: connections sit under budget with nothing fetchable
/// to put in them, and per-connection rates collapse fleet-wide.
/// Gary's 16 Aug job had 1,965 of 4,506 segments missing (44%) and ran
/// at 7 MB/s against a link that had done 61 the night before - and
/// the verdict named a host as "the limit", which was false. A fifth
/// is well clear of the handful of holes a healthy post carries and
/// well under any regime where this is arguable.
const MISSING_BAR: f64 = 0.20;

/// Articles the fleet must have asked for before the rate above means
/// anything. Three misses out of four early requests is noise.
const MISSING_MIN_TRIED: u64 = 200;

/// How young a post may be and still be PROPAGATING rather than gone.
///
/// Deliberately [`crate::diag::GONE_MIN_AGE_DAYS`] and not a fourth
/// opinion about how long propagation takes: the failure summary, the
/// `fail_hint` copy and the M32 auto-retry gate all already draw the
/// line there, and a live verdict that drew it somewhere else would
/// tell the user one thing while the download ran and the opposite
/// thing the moment it failed.
const YOUNG_MAX_SECS: i64 = crate::diag::GONE_MIN_AGE_DAYS as i64 * 86_400;

/// Distinct BACKBONES that must each have seen the shortfall on their
/// own numbers before this surface may say "no provider has these".
///
/// Five resellers of one backbone are ONE opinion - the rule
/// [`crate::diag::LossCauses::backbones`] exists to enforce - and the
/// claim being made here is the strong one: waiting will not help, so
/// the release is worth abandoning. One backbone's word is not enough
/// for that, however emphatic it is; a single upstream can be missing
/// a spool that another carries in full.
const GONE_MIN_BACKBONES: usize = 2;

/// Articles a single backbone must have been asked for before its own
/// miss rate counts as one of the opinions above. A backup server that
/// saw a dozen requests has an opinion about a dozen articles.
const BACKBONE_MIN_TRIED: u64 = 50;

/// A server persistently holding under this fraction of its
/// connection budget is being capped by the provider (the 481
/// max-simultaneous-IP shape), if it isn't refusing outright.
const CONN_SHORTFALL: f64 = 0.75;

/// A server whose per-connection rate sits under this fraction of the
/// fleet's best per-connection rate, with its whole budget connected
/// and busy, is being shaped. Giganews measured ~15 Mbps/conn beside
/// UsenetExpress at ~165 on the same box - a 0.09 ratio; the bar sits
/// well above noise and well below any healthy spread.
const SHAPED_RATIO: f64 = 0.25;

/// Reconnects across the window at or above half the fleet's
/// connections = sessions are dying and redialling; the wire time
/// they lose is the provider's.
const CHURN_FRACTION: f64 = 0.5;

/// Verdict-change ring cap: enough for a long job's whole story, small
/// enough that the payload stays bounded.
const TIMELINE_CAP: usize = 40;

/// The layer a verdict names. Order here is meaningless; precedence
/// lives in `classify`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub(super) enum Layer {
    /// A speed cap is in force and achieved rides it.
    Limit,
    /// Achieved rides the link anchor: nothing is slow.
    Line,
    /// A storage pause is engaging - slowstore probed the volume and
    /// it failed. (While one is fully in force the queue is paused and
    /// no job owns the wire, so this mostly names the transition.)
    Disk,
    /// Downstream of the sockets with all-core CPU sustained high.
    Cpu,
    /// Downstream of the sockets, CPU and disk both healthy: our
    /// pipeline. Self-blame, stated plainly.
    Client,
    /// The sockets can't fill the pipe: refusals, connection caps,
    /// churn, or plain flat delivery. Detail names a host when one
    /// host owns the evidence.
    Provider,
    /// TODO 312 item 3: OUR OWN fleet cap is the binding constraint -
    /// the line has headroom, the sockets we opened are each carrying
    /// less than the cap's own plan assumes, and the cap is holding the
    /// fleet under what the user configured.
    ///
    /// This used to land in [`Layer::Provider`], which is defensible
    /// and useless: it names something the reader cannot act on while
    /// saying nothing about the one lever that would fix it. GH #62's
    /// reporter has two accounts at 50 connections each and gets 25
    /// sockets, and the only thing anybody could tell them to do was
    /// turn the rule off with an environment variable.
    ///
    /// It is deliberately NOT a claim that the cap is WRONG. The cap is
    /// a measured rule (`nzbkit::pool::linecap`) and §208 measured what
    /// happens without it; what this verdict asserts is only that it is
    /// what is binding right now, with the numbers, so the reader can
    /// decide.
    Fleet,
    /// TODO 312 item 7: OUR OWN STALE MEASUREMENT is the binding
    /// constraint - an auto-tune knee is holding a server below what it
    /// would otherwise dial, and nothing has re-measured it since its
    /// re-probe appointment came and went.
    ///
    /// It is neither of the two layers either side of it, which is why
    /// it is its own. [`Layer::Provider`] covers a provider REFUSING
    /// sockets (`a_conn_capped_host_is_named`, granted below budget)
    /// and [`Layer::Fleet`] covers OUR OWN FLEET CAP taking them
    /// (`configured > cap`). A knee is our own MEASUREMENT of what the
    /// provider was fastest at, taken once and applied ever since: the
    /// provider is refusing nothing and the cap is taking nothing.
    ///
    /// Folding it into `Fleet` was the tempting move and is the one
    /// thing that must not happen. That verdict's remedy is the
    /// connection-budget setting, and on a fleet a knee is holding down
    /// that setting is INERT - changing it buys exactly nothing. The
    /// same evidence read as `Provider` before this variant existed,
    /// which is the failure `Fleet`'s own doc records one level up:
    /// naming something the reader cannot act on while saying nothing
    /// about the lever that would fix it. Measured on a 5 Gbit bench
    /// box, 28 Aug 2026 - rungs of 50, 77 and 100 all ran 32 sockets
    /// under a 19-day-old knee, and every instrument read clean
    /// (`research/KNEE-UNDER-FLEET-CAP-2026-08-28.md`).
    ///
    /// Detail is the HOST, exactly as `Provider`'s is, so the page can
    /// compose the sentence and the remedy can land on that server.
    Knee,
    /// TODO 318: ONE server holds this post and the PROVIDER has it at
    /// a stated connection cap - so the post is completable and the
    /// thing in the way is that server's ceiling, not the post.
    ///
    /// It is a refinement of [`Layer::Missing`] and sits in front of
    /// it, because that verdict reads the fleet-wide miss rate and the
    /// fleet-wide rate is an AVERAGE over servers that do not all hold
    /// the same spool. Measured on a live three-provider install,
    /// 29 Aug 2026: giganews 98% missing, usenet.farm 47%, vipernews
    /// 0.1% - 85.1% in aggregate, two backbones agreeing, so the
    /// surface said `missing`/`gone`,
    /// which means "waiting will not help, abandon it". The post was
    /// 99.9% present on vipernews, which was pinned at its account's
    /// own ceiling (`502 connection limit (40) reached`) and holding
    /// 1-7 sessions. Every word of the published verdict was false
    /// about the operative constraint, and the pool had already logged
    /// the true one - "any article only this server carries is waiting
    /// on it" - where nothing carried it here.
    ///
    /// It is deliberately NOT [`Layer::Provider`], which is the layer
    /// this evidence lands in once the sole-source part is dropped, and
    /// the difference is the reader's move. `Provider` says a host is
    /// the limit, which invites switching away from it; here the
    /// capped host is the ONLY one that has the content, so switching
    /// away finishes nothing. The remedy is that server's connection
    /// allowance - a second slot on the account, or fewer sockets spent
    /// elsewhere on it - and the sentence has to say which server and
    /// what it said.
    ///
    /// Nor is it [`Layer::Fleet`] or [`Layer::Knee`] next door: both of
    /// those are OUR OWN number holding the fleet down and are fixed on
    /// this page. This is the PROVIDER's number, heard from the
    /// provider, and no setting here lifts it.
    ///
    /// Detail is the HOST, as `Provider`'s and `Knee`'s are, so the
    /// page composes the sentence and the remedy lands on that server.
    SoleCap,
    /// Neither: most of what the run is asking for is not on the
    /// servers. The wire time goes on requests that return nothing,
    /// and no layer of the stack is at fault. See `MISSING_BAR`.
    ///
    /// Detail splits the two situations that produce this identical
    /// picture - `young` (still propagating) and `gone` (no backbone
    /// has it), empty when neither is evidenced. See `missing_case`.
    Missing,
    /// Not enough, or conflicting, evidence. The default.
    #[default]
    Unknown,
}

impl Layer {
    pub fn token(self) -> &'static str {
        match self {
            Layer::Limit => "limit",
            Layer::Line => "line",
            Layer::Disk => "disk",
            Layer::Cpu => "cpu",
            Layer::Client => "client",
            Layer::Provider => "provider",
            Layer::Fleet => "fleet",
            Layer::Knee => "knee",
            Layer::SoleCap => "solecap",
            Layer::Missing => "missing",
            Layer::Unknown => "unknown",
        }
    }

    /// The reverse, for a verdict read back off a history record. An
    /// unrecognised token - a future layer, or a corrupted line - is
    /// None, which reads as no verdict rather than as a wrong one.
    /// `unknown` is deliberately not accepted: it IS the absence of a
    /// verdict, and TODO 207's rule is that absence stays absence.
    pub fn from_token(t: &str) -> Option<Layer> {
        [
            Layer::Limit,
            Layer::Line,
            Layer::Disk,
            Layer::Cpu,
            Layer::Client,
            Layer::Provider,
            Layer::Fleet,
            Layer::Knee,
            Layer::SoleCap,
            Layer::Missing,
        ]
        .into_iter()
        .find(|l| l.token() == t)
    }
}

/// One server's cumulative counters at a tick, as read from
/// `ServerLive`. The core differences them itself (and forgives a
/// counter that restarted, e.g. a new pool mid-tail).
pub struct ServerTick {
    pub host: String,
    pub connected: usize,
    pub budget: usize,
    pub bytes: u64,
    pub blocked_ms: u64,
    pub reconnects: u64,
    pub refused: bool,
    pub tried: u64,
    pub missing: u64,
    /// The pool's per-server dispatch-to-done EWMA in ms
    /// (`ServerLive::srv_art_ms`), 0 = untrained. A LEVEL, not a
    /// cumulative counter, so the core stores it rather than
    /// differencing it. Carried for display only: no verdict reads it,
    /// because article time is a queueing quantity (it folds the wait
    /// behind pipeline-mates on purpose) and a fleet running deep
    /// pipelines has a big one while behaving perfectly.
    pub art_ms: u64,
    /// TODO 318: unix ms of the FIRST capacity refusal this host gave
    /// us this run, 0 while it has never capped us
    /// ([`nzbkit::pool::ServerLive::capped_since`]).
    ///
    /// This is the STATED-cap gate and nothing else may stand in for
    /// it. `connected < budget` is satisfied by every idle provider,
    /// and inferring a cap from it is the mistake `granted_hi`'s own
    /// doc records. It is also self-retiring - the pool clears it the
    /// moment the fleet holds more sessions than the recorded ceiling
    /// (`retire_cap_if_exceeded`) - so a live non-zero value means the
    /// cap has been heard AND has not since been disproven, which is
    /// the whole of what a verdict here needs to assert.
    pub capped_since: u64,
    /// The most sessions this provider was serving US at the instant it
    /// refused another one ([`nzbkit::pool::ServerLive::granted_hi`]).
    pub granted_hi: usize,
    /// What we were ASKING for at that instant
    /// ([`nzbkit::pool::ServerLive::capped_at`]).
    ///
    /// Both are high-waters of the same measurement, and the PAIR is
    /// what says a cap is binding rather than merely heard: the pool's
    /// response to a cap is to yield slots, so the live `budget` falls
    /// toward the granted count and `connected < budget` stops being
    /// true exactly when the cap is most binding. `capped_at >
    /// granted_hi` does not decay that way.
    pub capped_at: usize,
    /// The server's own sentence about the cap, verbatim and possibly
    /// empty - `ServerLive::refusal`'s line while that refusal stands,
    /// else a `capacity` outage's detail. Carried for display only: no
    /// verdict reads it, because it is provider prose and every claim
    /// this surface makes has to stay translatable.
    pub cap_said: String,
}

/// Everything one second of observation carries into the core.
pub struct Tick {
    /// The job owning the wire (`active_stream`), or None when idle.
    pub owner: Option<String>,
    /// Wall clock, unix ms - passed in so the core stays pure.
    pub at_ms: u64,
    pub achieved_bps: f64,
    pub throttle_bps: u64,
    /// The linkpeak anchor (`effective`), 0 = unknown.
    pub anchor_bps: u64,
    /// All-core CPU%, 0-100.
    pub cpu_pct: f64,
    /// A slowstore pause engaging/in force.
    pub storage: bool,
    /// §108 option 2: no pause, but slowstore's diagnostic probes have
    /// found the output volume answering slowly. Same instrument as the
    /// pause's confirming probe, needing consecutive slow answers, and
    /// it only runs while this core is asking (see `wants_disk_answer`)
    /// - so this is never a background opinion, only the reply to a
    /// question this tick's own evidence raised.
    pub storage_suspect: bool,
    /// Unix seconds of the youngest article in the running job's post,
    /// 0 = unknown. See [`crate::streamhub::StreamHub::post_unix`] -
    /// unknown is NOT "posted just now" and never reads as young here.
    pub post_unix: i64,
    /// TODO 312 item 3: the fleet cap in FORCE this second, in sockets
    /// (`nzbkit::pool::LiveStats::line_cap_fleet`); 0 = the rule is off.
    /// The cap in force and never the seed - the in-run governor moves
    /// it, and a verdict about a cap the run left behind three rungs ago
    /// would be about nothing.
    pub fleet_cap: usize,
    /// TODO 312 item 3: what the fleet would dial with the cap taking
    /// nothing out - the `--connections` dial, each account's own
    /// number and any host cap, all applied. 0 = no claim, which is what
    /// a pool built by a rig or the CLI reports and which must never
    /// read as "no sockets configured".
    pub fleet_configured: usize,
    /// TODO 312 item 3: is the cap the curve's own number, so the in-run
    /// governor may still grow it? A cap that is about to fix itself is
    /// not a binding constraint - see `fleet_bound`.
    pub fleet_auto: bool,
    /// TODO 275 item 7: the ceiling the in-run governor may walk this
    /// fleet's cap to (`nzbkit::pool::LiveStats::line_cap_ceiling`), in
    /// sockets. 0 = no claim, from a pool that publishes no gauges at
    /// all, and `fleet_bound` reads that as the first ceiling - which is
    /// what every such pool could reach before this field existed.
    ///
    /// It is what "the cap cannot fix itself" has to be asked against.
    /// On an install whose anchor was MEASURED the governor may raise
    /// past `LINE_CAP_MAX_FLEET`, so convicting a cap of 50 there would
    /// name a rule that is three ticks from raising itself - the exact
    /// error the auto arm exists to avoid, one ceiling up.
    pub fleet_ceiling: usize,
    /// TODO 275 item 7: has a provider refused this account for
    /// capacity at any point this job
    /// (`nzbkit::pool::LiveStats::line_cap_refused`)? Latched for the
    /// run, and false on a pool that publishes no gauges.
    ///
    /// It is not an input to the verdict - the stood-down
    /// `fleet_ceiling` above already carries the cap's inability to fix
    /// itself, and asking the same thing twice is how two arms come to
    /// disagree about one second. It is a RECEIPT, and the one that
    /// matters most here: without it the panel names our own connection
    /// budget as the constraint and offers to raise it, on the one
    /// install where raising it dials straight back into an account
    /// that has already said no.
    pub fleet_refused: bool,
    /// TODO 312 item 7: the STALE auto-tune knee holding this fleet
    /// under its own ceiling, `None` when none is
    /// (`nzbkit::pool::LiveStats::line_cap_knee`). Fixed when the fleet
    /// was built, unlike the three above it, which is why the gauge it
    /// comes from is not an atomic.
    pub fleet_knee: Option<nzbkit::pool::linecap::FleetKnee>,
    /// Sockets the DRAINING predecessor still holds during a cross-job
    /// hand-over, 0 whenever the drain slot is empty (which is nearly
    /// always, and every rig).
    ///
    /// It exists because `achieved_bps` is `Daemon::current_speed_bps`,
    /// which deliberately ADDS the drainer's bytes so the queue's speed
    /// readout does not dip at a hand-over boundary. `fleet_bound`
    /// divides that rate by connected sockets to get a per-socket carry,
    /// and `servers` below is the SUCCESSOR's fleet alone - so during a
    /// hand-over the numerator was whole-wire and the denominator was
    /// not. The carry read high, the implied fleet fell, `implied > cap`
    /// failed, and a genuinely binding cap went unreported for the whole
    /// window. Added into the divisor here rather than subtracted from
    /// the numerator because the hand-over LEASE holds both runs inside
    /// one job's connection budget, so whole-wire over whole-wire is the
    /// coherent pair.
    ///
    /// Fed ONLY into `fleet_bound`, never into `blocked_pct`: that arm's
    /// numerator is the successor's own parked-worker milliseconds, so
    /// widening its denominator would dilute it the other way.
    pub drain_connected: usize,
    pub servers: Vec<ServerTick>,
}

/// TODO 312 item 3: the working behind a [`Layer::Fleet`] verdict.
///
/// `cap`, `configured` and `auto` are configuration and are refreshed
/// every tick; `carry_bps` and `implied` are MEASUREMENTS and are only
/// refreshed on a tick where the supply gate was actually open, so the
/// panel keeps showing the numbers that produced the published verdict
/// rather than blinking to zero on the first second the gate shuts.
/// The verdict itself is majority-held over [`WINDOW`], so those two
/// clocks already differ.
#[derive(Clone, Copy, Default)]
struct FleetEvidence {
    cap: usize,
    configured: usize,
    auto: bool,
    /// TODO 275 item 7: the ceiling the governor could have walked this
    /// cap to. Equal to `LINE_CAP_MAX_FLEET` for every install with a
    /// typed or absent line anchor, and higher - bounded by the
    /// account's own grant - for one whose anchor was MEASURED.
    ///
    /// Published so a reader can tell the two apart. An automatic cap
    /// that stopped at 50 is at its ceiling on one install and three
    /// ticks short of raising itself on another, and the four numbers
    /// beside it cannot say which.
    ceiling: usize,
    /// TODO 275 item 7: has a provider refused this account for
    /// capacity this job? `Tick::fleet_refused`, so the sentence can
    /// say why the budget stopped where it did instead of leaving the
    /// reader with a number.
    ///
    /// Usually that is the ceiling above being stood down, and on a
    /// TYPED cap it is not - there is no ceiling arm in that regime -
    /// which is why this is the refusal itself and not a claim about
    /// the ceiling. The remedy the panel withholds on it is the same
    /// either way.
    ///
    /// Set from the tick in `Core::refresh` like `cap`, `configured`,
    /// `auto` and `ceiling` beside it; the copy `fleet_bound` puts in
    /// its return value is written for symmetry with those four and is
    /// discarded the same way. Only `carry_bps` and `implied` reach the
    /// panel through the evidence, because only those two are held back
    /// to the tick that produced the verdict.
    refused: bool,
    /// Bytes/s one connected socket is carrying, measured.
    carry_bps: u64,
    /// Sockets this line would want at that carry
    /// (`linecap::sockets_for_carry`), UNCLAMPED. See that function for
    /// why it is unclamped and why nothing may seed a pool from it.
    implied: usize,
}

/// TODO 312 item 7: the working behind a [`Layer::Knee`] verdict.
///
/// The same two clocks as [`FleetEvidence`] and for the same reason:
/// `host`, `at`, `takes` and `age_secs` are CONFIGURATION and are
/// refreshed every tick, while `carry_bps` and `implied` are
/// MEASUREMENTS and are only refreshed on a tick where the supply gate
/// was actually open - so the panel keeps showing the numbers that
/// produced the published verdict rather than blinking to zero on the
/// first second the gate shuts.
#[derive(Clone, Default)]
struct KneeEvidence {
    /// The server the reader is being sent to: the stalest knee'd one
    /// (`linecap::seed_knee`). Empty when no knee is applied.
    pub host: String,
    /// That server's knee - the connection count the measurement
    /// settled on.
    pub at: usize,
    /// Sockets the stale knees are taking off the fleet, cap included.
    pub takes: usize,
    /// How long ago the named server's knee was measured.
    pub age_secs: u64,
    /// Bytes/s one connected socket is carrying, measured.
    pub carry_bps: u64,
    /// Sockets this line would want at that carry, as
    /// [`FleetEvidence::implied`].
    pub implied: usize,
}

impl KneeEvidence {
    /// Refresh the CONFIGURATION half from this tick, leaving the two
    /// measurements where they are. Clearing to empty when the tick
    /// carries no knee is deliberate and matches `FleetEvidence`'s
    /// unconditional assignment of a cap of 0: a fleet with no knee has
    /// no host to name, and a stale host would send a reader to a
    /// server that is no longer the story.
    pub fn refresh(&mut self, k: Option<&nzbkit::pool::linecap::FleetKnee>) {
        self.host = k.map(|k| k.host.clone()).unwrap_or_default();
        self.at = k.map_or(0, |k| k.at);
        self.takes = k.map_or(0, |k| k.takes);
        self.age_secs = k.map_or(0, |k| k.age_secs);
    }
}

/// TODO 318: the working behind a [`Layer::SoleCap`] verdict.
///
/// No two-clock split, unlike [`FleetEvidence`] and [`KneeEvidence`]:
/// see [`Core::sole_capped`], which computes this fresh every time it
/// is asked.
#[derive(Clone)]
struct SoleEvidence {
    /// The server that HAS the post - the one the reader is being sent
    /// to. Full, never trimmed for display: the panel's remedy button
    /// hands it to `landOnServer`, which matches the server list by
    /// exact host.
    host: String,
    /// That server's OWN miss rate, 0-100. The number that refutes the
    /// fleet-wide one.
    missing_pct: f64,
    /// The most sessions it was serving us when it refused another.
    granted_hi: usize,
    /// What we were asking for at that moment.
    capped_at: usize,
    /// Its own words, verbatim, possibly empty.
    said: String,
}

/// Whether OUR OWN fleet cap is what is holding this second, and the
/// numbers if so. Pure, so the regimes below can be replayed in a test
/// without a pool.
///
/// Five conditions, none of them optional:
///
/// * **the rule is on** (`cap > 0`) and **it is taking sockets away**
///   (`configured > cap`). A cap above what the accounts allow is not
///   binding anything, and a `configured` of 0 is a pool that made no
///   claim - a rig, a CLI run - which must read as "cannot say", never
///   as "you configured nothing".
/// * **the line has headroom**: achieved under
///   [`LINE_CAP_SUPPLY_PCT`]% of the anchor. This is
///   `fleet_for_supply`'s own gate, deliberately the same constant and
///   not a fourth opinion, and it is what keeps this verdict away from
///   the LINE-bound regime §208 measured - where more sockets cost wall
///   and this sentence would be advice to make things worse.
/// * **the sockets are under the cap's own plan**: carry below
///   [`LINE_CAP_SOCKET_BPS`]. At or above it the curve's assumption is
///   holding and the curve owns the answer.
/// * **more sockets would help**: the fleet the measured carry implies
///   is bigger than the cap in force.
/// * **the cap cannot fix itself**: it is either TYPED (the governor is
///   pinned) or already at [`LINE_CAP_MAX_FLEET`]. An automatic cap
///   below the ceiling with the gate open is three ticks from raising
///   itself, and convicting it would be reporting a rule mid-stride.
///
/// `dialling` is CONNECTED sockets and not the budget: the budget is
/// what we intend, and dividing the achieved rate by an intention
/// over-states nothing in the safe direction - fewer sockets means a
/// higher measured carry, which means a SMALLER implied fleet and a
/// gate that shuts sooner.
///
/// It is also EVERY socket on the wire, the draining predecessor's
/// included (`Tick::drain_connected`), because `t.achieved_bps` is
/// `current_speed_bps` and that figure adds the drainer's bytes on
/// purpose. Passing the successor's own count alone put a whole-wire
/// numerator over a part-wire divisor, which inflated the apparent
/// carry, shrank `implied`, and let a genuinely binding cap fall
/// through the gate for the length of every hand-over. The shape that
/// brings it back is any caller passing a count taken from
/// `Tick::servers` alone.
///
/// **The stated limit: this is only ever as good as the anchor**, and
/// the anchor may be a figure the user TYPED (`linkpeak::Core::effective`
/// hands back "line" whenever the measured peak is under the declared
/// line speed). An install that typed 10 Gbit on a 1 Gbit line holds
/// this gate open for ever and gets told its own cap is binding when it
/// is not.
///
/// Requiring a MEASURED anchor was considered and is WRONG here, which
/// is worth knowing before anyone tightens it: a measured peak is an
/// achieved rate, so a fleet the cap is holding down measures its own
/// cap, and `effective` then returns "line" for exactly the install
/// this verdict exists for. GH #62's reporter reads "line", not
/// "measured". The typed anchor is the only independent evidence such
/// an install has that its line is bigger than what it is getting.
///
/// What bounds the damage is that this verdict spends nothing. The
/// supply arm (`linecap::fleet_for_supply`) already sizes real SOCKETS
/// off this same typed anchor and is held safe by its clamp; a sentence
/// with its numbers beside it, under a bar labelled with the anchor's
/// own provenance, is strictly less than that. And the alternative is
/// not silence: before this arm existed the identical evidence read as
/// `Provider`, which is equally wrong on a lying anchor and useless on
/// an honest one.
fn fleet_bound(t: &Tick, dialling: usize) -> Option<FleetEvidence> {
    use nzbkit::pool::linecap::LINE_CAP_MAX_FLEET;
    if t.fleet_cap == 0 || t.fleet_configured <= t.fleet_cap {
        return None;
    }
    // TODO 275 item 7: the ceiling in FORCE for this install, which is
    // the first ceiling for everyone whose anchor was typed or absent
    // and the second for one that measured its line. A tick carrying no
    // claim (0) reads as the first, which is what such a pool could
    // reach before the second ceiling existed.
    let ceiling = t.fleet_ceiling.max(LINE_CAP_MAX_FLEET);
    if t.fleet_auto && t.fleet_cap < ceiling {
        return None;
    }
    let (carry_bps, implied) = supply_room(t, dialling)?;
    (implied > t.fleet_cap).then_some(FleetEvidence {
        cap: t.fleet_cap,
        configured: t.fleet_configured,
        auto: t.fleet_auto,
        ceiling,
        refused: t.fleet_refused,
        carry_bps,
        implied,
    })
}

/// The MEASUREMENT both socket verdicts rest on: the line has headroom
/// the sockets are failing to use, one socket is carrying less than the
/// cap's own plan assumes, and here is the fleet that measured carry
/// implies for this line. `None` when this second says nothing.
///
/// Three of [`fleet_bound`]'s five conditions live here - the two bars
/// its own doc states at length plus the guards that make the division
/// meaningful - and the fourth and fifth stay with each caller, because
/// what `implied` has to exceed is the thing that verdict convicts.
///
/// FACTORED OUT rather than copied when [`knee_bound`] joined it (TODO
/// 312 item 7). Two spellings of one quantity is this repo's most
/// repeated defect, and the one that would matter here is two verdicts
/// about the SAME SECOND disagreeing about whether the line had room -
/// which is not a wrong number on a panel, it is two contradictory
/// sentences shown to one reader.
///
/// Pure, like both its callers, so the regimes can be replayed in a
/// test without a pool.
fn supply_room(t: &Tick, dialling: usize) -> Option<(u64, usize)> {
    use nzbkit::pool::linecap::{LINE_CAP_SOCKET_BPS, LINE_CAP_SUPPLY_PCT, sockets_for_carry};
    if dialling == 0 || t.anchor_bps == 0 {
        return None;
    }
    let now_bps = t.achieved_bps.max(0.0) as u64;
    if now_bps.saturating_mul(100) >= t.anchor_bps.saturating_mul(LINE_CAP_SUPPLY_PCT) {
        return None;
    }
    let carry_bps = now_bps / dialling as u64;
    if carry_bps == 0 || carry_bps >= LINE_CAP_SOCKET_BPS {
        return None;
    }
    Some((carry_bps, sockets_for_carry(t.anchor_bps, carry_bps)))
}

/// Whether OUR OWN STALE MEASUREMENT is what is holding this second,
/// and the numbers if so. Pure, like [`fleet_bound`] beside it, so the
/// regimes below can be replayed in a test without a pool.
///
/// Four conditions, and only two of them are written here because the
/// other two were already decided upstream and must not be asked twice:
///
/// * **a stale knee is lowering some server** - `Tick::fleet_knee`.
///   `conntune::stale_knee` owns every part of that judgement (it
///   applies, it is past its re-probe appointment, and it is really
///   taking sockets off what the server would otherwise dial), and
///   `linecap::seed_knee` owns the fold.
/// * **the knee, and not the fleet cap, is the lower of the two.** This
///   is NOT a second comparison here, and that is the point:
///   `ServerKnee::takes` is measured against the POST-cap ceiling, so
///   `takes > 0` already IS that statement. Asking `configured` against
///   `cap` a second time would be a spelling of the same thing that can
///   disagree with the first. `knee_under_cap_note` states the same
///   rule for the log line: two sentences claiming to explain one
///   number is worse than one.
/// * **the fleet made a claim at all** (`configured > 0`). A pool built
///   by a rig or the CLI reports 0, which must read as "cannot say" and
///   never as "you configured nothing" - `fleet_bound`'s own rule.
/// * **more sockets would help**: the fleet the measured carry implies
///   is bigger than the ceiling we are dialling under. That comparand
///   is `fleet_configured`, the knee-included counterfactual, which on
///   a fleet where the cap is also cutting a DIFFERENT server sits
///   above what is really dialled - the conservative direction, so the
///   gate shuts sooner rather than later.
///
/// PRECEDENCE IS SETTLED AT THE CALLER, not here. On a single server
/// this arm and [`fleet_bound`] are mutually exclusive by construction,
/// but on a mixed fleet - one server under a stale knee, another under
/// the cap's share - both are TRUE, and `classify` takes the cap first:
/// it is the bigger and fleet-wide lever, and one number gets one
/// sentence.
fn knee_bound(t: &Tick, dialling: usize) -> Option<KneeEvidence> {
    let k = t.fleet_knee.as_ref()?;
    if t.fleet_configured == 0 {
        return None;
    }
    let (carry_bps, implied) = supply_room(t, dialling)?;
    (implied > t.fleet_configured).then(|| KneeEvidence {
        host: k.host.clone(),
        at: k.at,
        takes: k.takes,
        age_secs: k.age_secs,
        carry_bps,
        implied,
    })
}

/// Per-server state the window keeps: last cumulative readings plus
/// the deltas of the most recent tick.
#[derive(Default, Clone)]
struct ServerState {
    last_bytes: u64,
    last_blocked: u64,
    last_reconnects: u64,
    // This tick's deltas (recomputed every tick).
    d_bytes: u64,
    d_blocked: u64,
    // Per-tick reconnect deltas of the last WINDOW ticks, plus their
    // running sum. The sum must age out with the window: a job-lifetime
    // total let two routine redials from an hour earlier convict the
    // provider on every later quiet second.
    recon_ring: VecDeque<u64>,
    win_reconnects: u64,
    connected: usize,
    budget: usize,
    refused: bool,
    tried: u64,
    missing: u64,
    art_ms: u64,
    // TODO 318: the provider's own connection ceiling, as
    // `ServerTick`'s doc describes it. Levels, not counters, so they
    // are stored rather than differenced.
    capped_since: u64,
    granted_hi: usize,
    capped_at: usize,
    cap_said: String,
}

/// A verdict change, for the per-job timeline.
#[derive(Clone)]
struct Change {
    pub at_ms: u64,
    pub layer: Layer,
    pub detail: String,
}

/// The pure decision core. All state is per-owner: a new job on the
/// wire starts from nothing.
#[derive(Default)]
pub struct Core {
    owner: Option<String>,
    /// Rolling per-tick classifications, newest at the back.
    votes: VecDeque<(Layer, String)>,
    servers: HashMap<String, ServerState>,
    /// The currently published verdict (starts Unknown).
    verdict: (Layer, String),
    verdict_since_ms: u64,
    /// Consecutive ticks without any layer holding a majority. A short
    /// stretch is a regime CHANGING (hold the verdict through it); a
    /// long one is evidence that genuinely disagrees with itself
    /// (publish Unknown, honestly).
    no_majority: usize,
    timeline: VecDeque<Change>,
    /// TODO 207: how long each (layer, detail) has been the published
    /// verdict this run, banked as the verdict changes. The timeline
    /// next door cannot answer this - it is capped at
    /// [`TIMELINE_CAP`] changes, so a job that flapped for an hour has
    /// lost its early spans by the time anyone asks - and the whole
    /// point of the persisted verdict is that it is the LONGEST-held
    /// one, over the whole run.
    held_ms: HashMap<(Layer, String), u64>,
    /// Best whole-fleet delivery seen this run on an uncapped,
    /// unblocked tick: the live envelope estimate.
    envelope_bps: u64,
    /// This tick's diagnostic numbers, kept for the payload.
    last_blocked_pct: f64,
    last_cpu_pct: f64,
    /// The running job's post date as of the last tick, 0 = unknown.
    /// Kept so the payload can ship the number the verdict rests on -
    /// the module's rule is that an asserted verdict travels with its
    /// evidence, and "waiting will not help" rests entirely on this.
    last_post_unix: i64,
    /// §108 option 2: this tick reached the downstream fork with the
    /// breaker not in force, so the volume is the open question.
    disk_question: bool,
    /// TODO 312 item 3: the fleet cap's working. See [`FleetEvidence`]
    /// for which of its fields track the tick and which track the last
    /// tick that had something to measure.
    fleet: FleetEvidence,
    /// Whether THIS tick's evidence licenses a [`Layer::Fleet`] vote.
    /// Kept apart from [`Core::fleet`] because that struct deliberately
    /// remembers, and a vote must not.
    fleet_now: bool,
    /// TODO 312 item 7: the stale knee's working, and the same split of
    /// clocks. See [`KneeEvidence`].
    knee: KneeEvidence,
    /// Whether THIS tick's evidence licenses a [`Layer::Knee`] vote,
    /// kept apart from [`Core::knee`] for [`Core::fleet_now`]'s reason.
    knee_now: bool,
}

impl Core {
    /// Feed one second. The published verdict after the call is
    /// `verdict()`.
    pub fn tick(&mut self, t: Tick) {
        let Some(owner) = t.owner.as_deref() else {
            // Idle seconds are not evidence of anything; a fresh job
            // must not inherit a dead one's window.
            self.reset(None, t.at_ms);
            return;
        };
        if self.owner.as_deref() != Some(owner) {
            self.reset(Some(owner.to_string()), t.at_ms);
        }

        // Difference the cumulative counters. A counter that went
        // BACKWARDS restarted (new pool, new fleet) - forgive it and
        // measure from the new base next tick.
        let mut fleet_bytes = 0u64;
        let mut fleet_blocked = 0u64;
        let mut fleet_connected = 0usize;
        for s in &t.servers {
            let st = self.servers.entry(s.host.clone()).or_default();
            let fresh = s.bytes < st.last_bytes
                || s.blocked_ms < st.last_blocked
                || s.reconnects < st.last_reconnects;
            st.d_bytes = if fresh { 0 } else { s.bytes - st.last_bytes };
            st.d_blocked = if fresh {
                0
            } else {
                s.blocked_ms - st.last_blocked
            };
            let d_recon = if fresh {
                0
            } else {
                s.reconnects - st.last_reconnects
            };
            st.recon_ring.push_back(d_recon);
            st.win_reconnects += d_recon;
            if st.recon_ring.len() > WINDOW {
                st.win_reconnects -= st.recon_ring.pop_front().unwrap_or(0);
            }
            st.last_bytes = s.bytes;
            st.last_blocked = s.blocked_ms;
            st.last_reconnects = s.reconnects;
            st.connected = s.connected;
            st.budget = s.budget;
            st.refused = s.refused;
            st.tried = s.tried;
            st.missing = s.missing;
            st.art_ms = s.art_ms;
            st.capped_since = s.capped_since;
            st.granted_hi = s.granted_hi;
            st.capped_at = s.capped_at;
            st.cap_said = s.cap_said.clone();
            fleet_bytes += st.d_bytes;
            fleet_blocked += st.d_blocked;
            fleet_connected += s.connected;
        }
        let _ = fleet_bytes;

        // Fraction of total worker-time this second spent parked on
        // the full downstream channel.
        let blocked_pct = if fleet_connected > 0 {
            (fleet_blocked as f64 / (1000.0 * fleet_connected as f64)).min(1.0) * 100.0
        } else {
            0.0
        };
        self.last_blocked_pct = blocked_pct;
        self.last_cpu_pct = t.cpu_pct;
        self.last_post_unix = t.post_unix;
        // TODO 312 item 3. Configuration is refreshed unconditionally
        // and the two MEASUREMENTS only when there was something to
        // measure, so the panel keeps the numbers that produced the
        // published verdict - see `FleetEvidence`.
        self.fleet.cap = t.fleet_cap;
        self.fleet.configured = t.fleet_configured;
        self.fleet.auto = t.fleet_auto;
        self.fleet.ceiling = t.fleet_ceiling;
        self.fleet.refused = t.fleet_refused;
        // WHOLE-WIRE over WHOLE-WIRE. `t.achieved_bps` already carries
        // the draining predecessor's bytes (`current_speed_bps`), so the
        // divisor has to carry its sockets too or the per-socket carry
        // reads high through every hand-over and a binding cap goes
        // unreported. See `Tick::drain_connected`; `blocked_pct` above
        // deliberately does NOT get this, its numerator being the
        // successor's alone.
        let dialling = fleet_connected + t.drain_connected;
        let bound = fleet_bound(&t, dialling);
        self.fleet_now = bound.is_some();
        if let Some(e) = bound {
            self.fleet.carry_bps = e.carry_bps;
            self.fleet.implied = e.implied;
        }
        // TODO 312 item 7, the same shape one layer over: our own stale
        // measurement. The same `dialling` divisor, because the two
        // verdicts must never disagree about what the wire was doing.
        self.knee.refresh(t.fleet_knee.as_ref());
        let kneed = knee_bound(&t, dialling);
        self.knee_now = kneed.is_some();
        if let Some(e) = kneed {
            self.knee.carry_bps = e.carry_bps;
            self.knee.implied = e.implied;
        }

        // The live envelope estimate: what the fleet delivered on a
        // tick where nothing of ours held it back - no user cap and no
        // downstream parking. (A capped or blocked tick measures the
        // cap or us, not the providers.)
        if t.throttle_bps == 0 && blocked_pct < BLOCKED_BAR * 100.0 {
            self.envelope_bps = self.envelope_bps.max(t.achieved_bps as u64);
        }

        let vote = self.classify(&t, blocked_pct);
        // Keep asking while the CONDITIONS hold, not while the answer is
        // still "client". A Disk vote with no pause in force IS the
        // diagnostic's answer, and closing the question on it would stop
        // the probes, stale the latch, and drop the verdict straight
        // back to Client - a flip-flop on a minute's cycle. A real pause
        // closes it instead: the breaker owns the volume from there.
        self.disk_question = !t.storage && matches!(vote.0, Layer::Client | Layer::Disk);
        self.votes.push_back(vote);
        if self.votes.len() > WINDOW {
            self.votes.pop_front();
        }
        self.publish(t.at_ms);
    }

    /// Classify one instant. Precedence is the decision order from the
    /// design doc: caps, then line, then downstream, then upstream.
    fn classify(&self, t: &Tick, blocked_pct: f64) -> (Layer, String) {
        let bps = t.achieved_bps;
        if bps <= 0.0 {
            // No bytes moved. With redial churn or a fleet that never
            // connected the wire time is the provider's; otherwise
            // this second proves nothing by itself (the stall tracker
            // narrates stalls; attribution needs movement to measure).
            let churn: u64 = self.servers.values().map(|s| s.win_reconnects).sum();
            let connected: usize = self.servers.values().map(|s| s.connected).sum();
            let budget: usize = self.servers.values().map(|s| s.budget).sum();
            // `never_fed` distinguishes a fleet that CANNOT connect
            // (dial failures, refusals - the provider's problem) from
            // one that finished and hung up: after net-drain the
            // connections close and the speed reads zero, and blaming
            // the provider for a download that is busy FINISHING was a
            // real verdict this emitted before the guard (caught on
            // the live rig, 8 Aug).
            let never_fed = self.servers.values().all(|s| s.last_bytes == 0);
            if connected == 0 && budget > 0 && never_fed {
                return (Layer::Provider, self.worst_refusal());
            }
            // Churn is only evidence while the fleet is still trying:
            // a fleet that hung up after delivering redials nothing,
            // and its window of past redials proves nothing about now.
            if connected > 0 && churn as f64 >= (connected as f64) * CHURN_FRACTION {
                return (Layer::Provider, String::new());
            }
            return (Layer::Unknown, String::new());
        }
        if t.throttle_bps > 0
            && bps >= t.throttle_bps as f64 * LIMIT_BAR
            && (t.anchor_bps == 0 || t.throttle_bps < t.anchor_bps)
        {
            return (Layer::Limit, String::new());
        }
        if t.anchor_bps > 0 && bps >= t.anchor_bps as f64 * LINE_BAR {
            return (Layer::Line, String::new());
        }
        if t.anchor_bps == 0 {
            // No anchor: "slow" is undefined. Never invent a ceiling.
            return (Layer::Unknown, String::new());
        }
        // Established shortfall. Downstream or upstream of the sockets?
        if blocked_pct >= BLOCKED_BAR * 100.0 {
            // A pause in force is the strongest form of the same claim.
            // `storage_suspect` is the weaker one that gets here first:
            // the breaker needs three quarters of a three-minute window
            // before it acts, and a volume that is merely BAD - parked
            // and delivering a fifth of the line, for days - never
            // reaches that bar at all. Without this the same evidence
            // fell through to Client, which is honest about the three
            // candidates but sends nobody to look at their drive.
            if t.storage || t.storage_suspect {
                return (Layer::Disk, String::new());
            }
            if t.cpu_pct >= CPU_BAR {
                return (Layer::Cpu, String::new());
            }
            return (Layer::Client, String::new());
        }
        // Upstream: the sockets could not fill the pipe. But FIRST ask
        // whether there was anything to put in it. A post full of holes
        // starves the pool - connections idle for want of fetchable
        // work - and every downstream instrument then reports the shape
        // of a capped or shaped provider: budgets unfilled, per-
        // connection rates flat and low across the whole fleet. So this
        // is checked ahead of `worst_refusal`, which would otherwise
        // convict a host for a shortfall the post caused, and ahead of
        // `shaped_host`, whose comparison is between rates the misses
        // are themselves holding down.
        //
        // TODO 318: and before reading that fleet-wide rate, ask
        // whether the misses are EVERYWHERE. The rate is an average
        // over servers that do not all hold the same spool, so a post
        // one provider has in full and two others have lost averages
        // out to a post that reads as gone - which is the opposite of
        // the truth and invites the reader to delete a completable job.
        // `sole_capped` is the narrow case where that average is not
        // only wrong but has a named, actionable cause; it asserts
        // nothing unless a single server holds the post AND its
        // provider has stated a cap on it.
        if let Some(e) = self.sole_capped() {
            return (Layer::SoleCap, e.host);
        }
        if let Some(rate) = self.fleet_missing()
            && rate >= MISSING_BAR
        {
            return (Layer::Missing, self.missing_case(t));
        }
        // Name a host when one host owns the evidence.
        let refusal = self.worst_refusal();
        if !refusal.is_empty() {
            return (Layer::Provider, refusal);
        }
        let churn: u64 = self.servers.values().map(|s| s.win_reconnects).sum();
        let connected: usize = self.servers.values().map(|s| s.connected).sum();
        if connected > 0 && churn as f64 >= (connected as f64) * CHURN_FRACTION {
            return (Layer::Provider, String::new());
        }
        // TODO 312 item 3: before blaming the providers for flat
        // delivery, ask whether we opened the sockets the user gave us.
        //
        // PRECEDENCE, and it is the whole of what this placement
        // decides. It sits AFTER `worst_refusal` and the churn arm
        // because both of those are the provider actively failing -
        // opening more sockets into a 481 or into sessions that keep
        // dying makes things worse, not better - and after `Missing`
        // for the reason that check already carries: a post full of
        // holes starves the pool, so every socket reads as
        // under-carrying and this arm would convict our own cap for the
        // post's gaps. It sits BEFORE `shaped_host`, which is the arm
        // that swallowed this case until now: with the fleet held under
        // what the user configured, naming a host as "the limit" is the
        // same false claim `MISSING_BAR`'s own comment records making
        // about Gary's 16 Aug job.
        if self.fleet_now {
            return (Layer::Fleet, String::new());
        }
        // TODO 312 item 7: and then OUR OWN STALE MEASUREMENT, which is
        // neither the provider refusing nor the cap taking. It sits
        // AFTER the cap deliberately: on a single server the two are
        // mutually exclusive by construction (`ServerKnee::takes` is
        // measured against the POST-cap ceiling), but on a mixed fleet -
        // one server under a stale knee, another under the cap's share -
        // both are true at once, and the cap is the bigger and
        // fleet-wide lever. It sits BEFORE `shaped_host` for the reason
        // the arm above it does: with the fleet held under what the user
        // configured, naming a host as "the limit" is a false claim, and
        // here it is false about the very server whose knee WE applied.
        if self.knee_now {
            return (Layer::Knee, self.knee.host.clone());
        }
        (Layer::Provider, self.shaped_host())
    }

    /// Fraction of the articles the whole fleet asked for that came
    /// back missing, or None until the sample is worth reading.
    ///
    /// Fleet-wide and not per-host on purpose: a missing article is
    /// missing everywhere the post is, so one host's rate is a sample
    /// of the post, not a fact about that host. The per-server column
    /// in the panel shows the same counters split out, which is where
    /// a genuine single-host anomaly would be visible.
    fn fleet_missing(&self) -> Option<f64> {
        let tried: u64 = self.servers.values().map(|s| s.tried).sum();
        let missing: u64 = self.servers.values().map(|s| s.missing).sum();
        (tried >= MISSING_MIN_TRIED).then(|| missing as f64 / tried as f64)
    }

    /// Which of the two situations a `Missing` verdict is looking at,
    /// as a token the page turns into a sentence (`""` = neither is
    /// evidenced). The whole point of the split: a post nobody carries
    /// YET and a post nobody carries ANY MORE produce the identical
    /// picture from in here - requests going out and nothing coming
    /// back - and the reader's move is opposite in the two cases. Wait,
    /// or give up. One sentence covering both told Gary neither.
    ///
    /// Language-neutral by construction, like the host names the
    /// `Provider` detail carries: the numbers ride in the payload and
    /// the sentence is composed in the page, so this stays translatable.
    ///
    /// The bar is asymmetric on purpose. "Not here yet" costs a wait if
    /// it is wrong; "no provider has this" invites the user to delete a
    /// job that a retry in the morning would have finished, which is the
    /// exact failure `Layer::Missing` was created to stop. So the
    /// pessimistic arm needs BOTH the calendar and independent
    /// backbones, and anything short of that falls back to the plain
    /// statement of fact - which is not a hedge, it is what we know.
    fn missing_case(&self, t: &Tick) -> String {
        // No usable date: state the shortfall, claim no cause. An
        // undated NZB reads as 0 here and must never read as "brand
        // new" (see `StreamHub::post_unix`).
        if t.post_unix <= 0 {
            return String::new();
        }
        let age = (t.at_ms / 1000) as i64 - t.post_unix;
        // A post dated in the future is a clock or a mis-stamped NZB,
        // not evidence about anything. Say nothing rather than call it
        // fresh, which would promise a wait that may never end.
        if age < 0 {
            return String::new();
        }
        if age < YOUNG_MAX_SECS {
            return "young".into();
        }
        // TODO 318: a qualified server whose own miss rate is under the
        // bar HAS this post, and "waiting will not help" is then false
        // however many other backbones have lost it - the fleet-wide
        // rate that opened this case is an average, and the two
        // backbones corroborating each other are corroborating a fact
        // about THEMSELVES. This is the third refutation the asymmetric
        // bar above asks for, and it is the one that was missing on
        // the live install above: 98% and 47% agreed, and the third server
        // had 99.9% of the post. Falling back to the plain statement of
        // fact is not a hedge - "much of this post is missing" is
        // exactly what is known once "gone" is off the table.
        //
        // The YOUNG arm above is deliberately left alone: one backbone
        // holding a post the others have not received yet IS
        // propagation, so a holder corroborates that claim rather than
        // refuting it.
        if self.best_missing().is_some_and(|(_, r)| r < MISSING_BAR) {
            return String::new();
        }
        match self.missing_backbones() >= GONE_MIN_BACKBONES {
            true => "gone".into(),
            // Old, but only one upstream has said so. That is a fact
            // about the providers configured here, not about the post.
            false => String::new(),
        }
    }

    /// Distinct backbones that are EACH seeing this shortfall on their
    /// own numbers - the count behind a "no provider has these" claim.
    ///
    /// Per backbone and not per host because resellers of one upstream
    /// read the same spool: the misses agree because there is one
    /// opinion, not five. A backbone qualifies only once it has been
    /// asked enough to have an opinion and its own miss rate clears the
    /// same bar the fleet's did - a fill server that saw two misses out
    /// of six hundred is corroborating nothing.
    ///
    /// A server addressed by IP names no backbone (`backbone_of` gives
    /// back a digit label) and sits the count out, exactly as it does in
    /// `take_census`: it cannot support a claim about independent
    /// opinions either way.
    fn missing_backbones(&self) -> usize {
        let mut per: HashMap<String, (u64, u64)> = HashMap::new();
        for (host, s) in &self.servers {
            let bb = nzbkit::oracle::backbone_of(host);
            if !bb.chars().any(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            let e = per.entry(bb).or_insert((0, 0));
            e.0 += s.tried;
            e.1 += s.missing;
        }
        per.values()
            .filter(|&&(tried, missing)| {
                tried >= BACKBONE_MIN_TRIED && missing as f64 / tried as f64 >= MISSING_BAR
            })
            .count()
    }

    /// TODO 318: the server with the LOWEST miss rate of its own, and
    /// that rate.
    ///
    /// [`Core::fleet_missing`] above is an AVERAGE over servers that do
    /// not all hold the same spool, and averaging is the whole of what
    /// went wrong on the live install [`Layer::SoleCap`] records: 98%,
    /// 47% and 0.1% average to 85.1%, and 85.1% reads as a post nobody
    /// has. This answers the different question the reader actually
    /// needs - is this post COMPLETABLE anywhere - and it is the number
    /// the "waiting will not help" claim next door has to survive.
    ///
    /// Qualified by [`BACKBONE_MIN_TRIED`], which is the bar this file
    /// already uses for "this server has an opinion of its own": a fill
    /// server that saw six requests and missed none of them is not
    /// evidence that it holds the post, and without the bar it would be
    /// the best server on every run. Ties break on the host name so the
    /// answer is stable across ticks - a HashMap iteration order that
    /// picked a different one of two identical servers each second
    /// would flap the verdict's detail without changing the evidence.
    fn best_missing(&self) -> Option<(&String, f64)> {
        self.servers
            .iter()
            .filter(|(_, s)| s.tried >= BACKBONE_MIN_TRIED)
            .map(|(h, s)| (h, s.missing as f64 / s.tried as f64))
            .min_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(b.0)))
    }

    /// TODO 318: is ONE server holding this post while the PROVIDER
    /// caps it, and the numbers if so. See [`Layer::SoleCap`] for the
    /// incident and for why this is not the layer either side of it.
    ///
    /// Four conditions, none of them optional:
    ///
    /// * **somebody has it** - a qualified server's own miss rate is
    ///   under [`MISSING_BAR`]. Under the same bar the fleet-wide rate
    ///   is read against, deliberately: this file already says that
    ///   above it the POST is the shortfall, so under it the post is
    ///   not, and a fourth opinion about how many holes are too many
    ///   would be a number nobody could defend against the other three.
    /// * **it is the ONLY one** - every other qualified server is at or
    ///   above that bar. Two holders and a cap on one of them binds
    ///   nothing, because the other carries what the capped one cannot;
    ///   the claim being made here rests entirely on there being no
    ///   second source.
    /// * **there IS another server to be short of it** - at least one
    ///   other qualified server. On a single-provider install "only
    ///   this server has it" is true of every post ever downloaded and
    ///   says nothing, and the honest verdict there is the plain
    ///   provider one.
    /// * **the provider stated a cap and it is binding** -
    ///   `capped_since` is live (a real capacity refusal, not yet
    ///   disproven by the pool's own retirement) AND it granted fewer
    ///   than were asked for. See [`ServerTick::capped_since`] and
    ///   [`ServerTick::capped_at`] for why neither half stands alone,
    ///   and in particular why `connected < budget` is NOT the test:
    ///   the pool yields slots to match a cap, so that comparison goes
    ///   false exactly when the cap is most binding.
    ///
    /// Computed fresh rather than banked the way [`FleetEvidence`] and
    /// [`KneeEvidence`] are, because every input is either cumulative
    /// (the article census) or sticky (the cap gauges) - there is no
    /// per-tick measurement here to go blank on a quiet second, so the
    /// two-clock split those two need would buy nothing.
    fn sole_capped(&self) -> Option<SoleEvidence> {
        let (host, rate) = self.best_missing()?;
        if rate >= MISSING_BAR {
            return None;
        }
        let mut others = 0usize;
        for (h, s) in &self.servers {
            if h == host || s.tried < BACKBONE_MIN_TRIED {
                continue;
            }
            if (s.missing as f64 / s.tried as f64) < MISSING_BAR {
                return None;
            }
            others += 1;
        }
        if others == 0 {
            return None;
        }
        let s = self.servers.get(host)?;
        (s.capped_since > 0 && s.capped_at > s.granted_hi).then(|| SoleEvidence {
            host: host.clone(),
            missing_pct: rate * 100.0,
            granted_hi: s.granted_hi,
            capped_at: s.capped_at,
            said: s.cap_said.clone(),
        })
    }

    /// A host refusing outright, or persistently capped under its
    /// budget - the strongest single-host evidence there is.
    fn worst_refusal(&self) -> String {
        let mut hosts: Vec<(&String, &ServerState)> = self.servers.iter().collect();
        hosts.sort_by(|a, b| a.0.cmp(b.0));
        for (host, s) in &hosts {
            if s.refused {
                return (*host).clone();
            }
        }
        for (host, s) in &hosts {
            if s.budget > 0 && (s.connected as f64) < s.budget as f64 * CONN_SHORTFALL {
                return (*host).clone();
            }
        }
        String::new()
    }

    /// The host being shaped, if the fleet's own numbers convict one:
    /// whole budget connected and busy, yet delivering under
    /// SHAPED_RATIO of the fleet's best per-connection rate. Relative
    /// evidence only - both rates ship in the payload.
    fn shaped_host(&self) -> String {
        let per_conn = |s: &ServerState| -> Option<f64> {
            (s.connected >= 2 && s.d_bytes > 0).then(|| s.d_bytes as f64 / s.connected as f64)
        };
        let best = self
            .servers
            .values()
            .filter_map(per_conn)
            .fold(0.0f64, f64::max);
        if best <= 0.0 {
            return String::new();
        }
        let mut hosts: Vec<(&String, &ServerState)> = self.servers.iter().collect();
        hosts.sort_by(|a, b| a.0.cmp(b.0));
        for (host, s) in hosts {
            let full = s.budget > 0 && s.connected as f64 >= s.budget as f64 * 0.9;
            if full && per_conn(s).is_some_and(|r| r < best * SHAPED_RATIO) {
                return host.clone();
            }
        }
        String::new()
    }

    /// The window votes; a majority publishes. Without one, the
    /// current verdict holds through a short transition (a clean
    /// regime change spends a few seconds with the old majority gone
    /// and the new one not yet in), but evidence that stays split
    /// falls to Unknown - a verdict may not outlive its majority by
    /// more than the transition a flip mathematically needs.
    fn publish(&mut self, at_ms: u64) {
        let mut counts: HashMap<Layer, usize> = HashMap::new();
        for (l, _) in &self.votes {
            *counts.entry(*l).or_default() += 1;
        }
        let winner = match counts
            .iter()
            .filter(|&(_, &n)| n >= MAJORITY)
            .max_by_key(|&(_, &n)| n)
            .map(|(&l, _)| l)
        {
            Some(l) => {
                self.no_majority = 0;
                l
            }
            None => {
                self.no_majority += 1;
                if self.no_majority > WINDOW - MAJORITY {
                    Layer::Unknown
                } else {
                    return;
                }
            }
        };
        // The detail is the modal detail among the winning layer's
        // votes, so a host name only surfaces when it, too, is what
        // the window kept seeing.
        let detail = if winner == Layer::Unknown {
            String::new()
        } else {
            let mut d: HashMap<&str, usize> = HashMap::new();
            for (l, det) in &self.votes {
                if *l == winner {
                    *d.entry(det.as_str()).or_default() += 1;
                }
            }
            d.into_iter()
                .max_by_key(|&(_, n)| n)
                .map(|(s, _)| s.to_string())
                .unwrap_or_default()
        };
        if (winner, detail.as_str()) != (self.verdict.0, self.verdict.1.as_str()) {
            self.close_span(at_ms);
            self.verdict = (winner, detail.clone());
            self.timeline.push_back(Change {
                at_ms,
                layer: winner,
                detail,
            });
            if self.timeline.len() > TIMELINE_CAP {
                self.timeline.pop_front();
            }
        }
    }

    fn reset(&mut self, owner: Option<String>, at_ms: u64) {
        *self = Core {
            owner,
            verdict: (Layer::Unknown, String::new()),
            verdict_since_ms: at_ms,
            ..Core::default()
        };
    }

    pub(super) fn verdict(&self) -> (Layer, &str) {
        (self.verdict.0, &self.verdict.1)
    }

    /// Bank the time the standing verdict has been up, and restart its
    /// clock at `at_ms`. Called at every verdict change and once more
    /// where the run is summarised, so the banked spans tile the whole
    /// run with no gap and no double count.
    fn close_span(&mut self, at_ms: u64) {
        let held = at_ms.saturating_sub(self.verdict_since_ms);
        *self
            .held_ms
            .entry((self.verdict.0, self.verdict.1.clone()))
            .or_default() += held;
        self.verdict_since_ms = at_ms;
    }

    /// TODO 207: this run's verdict for the record, as of `now_ms`.
    ///
    /// The LONGEST-HELD layer, which is the honest summary of where the
    /// time went and the one that matches how the live panel is read.
    /// The last verdict before the job left the wire would be cheaper
    /// and would call a job that was provider-bound for ten minutes a
    /// disk problem on the strength of its final seconds.
    ///
    /// `Unknown` is excluded rather than allowed to win: it is the
    /// absence of a verdict, so a run that mostly could not be judged
    /// reports the layer that WAS judged - with `total_secs` beside it
    /// saying how much of the run that layer actually covers, which is
    /// what stops the shorter claim from reading as the whole story.
    /// A span under a second is not a verdict anyone held; it rounds to
    /// "for 0s" on every surface and is refused here instead.
    fn summary(&self, now_ms: u64) -> Option<WhyVerdict> {
        let mut held = self.held_ms.clone();
        *held
            .entry((self.verdict.0, self.verdict.1.clone()))
            .or_default() += now_ms.saturating_sub(self.verdict_since_ms);
        let total: u64 = held.values().sum();
        // Longest-held LAYER first, then the longest-held detail inside
        // it: two hosts named by the same layer are one finding about
        // that layer, and picking the pair outright would let a third
        // layer that never held as long win on the split.
        //
        // Ties break on the token, never on HashMap order - a verdict
        // that changed with the iteration seed would be untestable and
        // would differ between two reads of the same run.
        let mut per_layer: HashMap<Layer, u64> = HashMap::new();
        for ((l, _), ms) in &held {
            *per_layer.entry(*l).or_default() += ms;
        }
        let (layer, layer_ms) = per_layer
            .into_iter()
            .filter(|(l, _)| *l != Layer::Unknown)
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.token().cmp(a.0.token())))?;
        if layer_ms < 1_000 {
            return None;
        }
        let detail = held
            .iter()
            .filter(|((l, _), _)| *l == layer)
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.1.cmp(&a.0.1)))
            .map(|(k, _)| k.1.clone())
            .unwrap_or_default();
        Some(WhyVerdict {
            layer: layer.token().to_string(),
            detail,
            held_secs: layer_ms / 1000,
            total_secs: total / 1000,
        })
    }
}

/// TODO 210 item (d): the anchor this surface treats as 100%, with the
/// LOCAL LINK folded in.
///
/// `linkpeak` resolves measured-against-typed and knows nothing about
/// the LAN between this machine and the modem. A 710 Mbit line reached
/// over a 1200 Mbps Wi-Fi link can deliver about 660, so a run riding
/// that link at 660 was drawn against a 710 mark and classified as a
/// shortfall - the graph showed a gap that nothing could close and the
/// verdict blamed the providers for the access point. Same rule as
/// `update_tune_hint`'s yardstick, so the two surfaces cannot disagree
/// about what this machine can carry.
///
/// Only the TYPED arm is clamped. A `measured` anchor is a rate this
/// machine actually sustained, which is direct evidence about the whole
/// path; overriding it with an estimate of one hop would be arguing
/// with the link's own answer. `link` names the clamp when it bites, so
/// the panel can label the mark honestly rather than calling the LAN a
/// line speed setting.
fn link_capped(anchor: (u64, &'static str), link_ceiling: Option<u64>) -> (u64, &'static str) {
    match link_ceiling {
        Some(c) if anchor.1 == "line" && c < anchor.0 => (c, "link"),
        _ => anchor,
    }
}

/// [`link_capped`] over what the daemon currently holds.
pub fn anchor(d: &super::daemon::Daemon, line_bps: u64) -> (u64, &'static str) {
    let ceiling = d
        .local_link
        .lock_ok()
        .as_ref()
        .and_then(|l| l.ceiling_bps());
    link_capped(d.link_peak.effective(line_bps), ceiling)
}

/// One second of observation, gathered from the daemon and fed to the
/// core. Called from the linkpeak ticker with the readings that loop
/// already took - one ticker, one reading of the shared speed window,
/// so the learner, the readout and the attribution can never disagree
/// about what the link was doing.
pub fn feed(d: &std::sync::Arc<super::daemon::Daemon>, bps: f64, throttle_bps: u64, line_bps: u64) {
    use std::sync::atomic::Ordering;
    // `active_stream` deliberately outlives its job so playback keeps
    // working after completion; attribution must not inherit that.
    // Only a job still downloading owns the wire - without this filter
    // the ticker keeps voting on a finished job's ghost indefinitely
    // and the queue payload never returns to null.
    let owner = d.active_stream.lock_ok().clone();
    let owner = owner.filter(|id| {
        super::daemon::find_job(d.queue.lock_ok().iter(), id)
            .is_some_and(|j| j.lock_ok().state == super::job::JobState::Downloading)
    });
    let (anchor_bps, _) = anchor(d, line_bps);
    // TODO 312 item 3: the fleet cap's own gauges, read under the SAME
    // lock as the per-server ones so the cap and the sockets it applies
    // to can never come from two different instants.
    let mut fleet_cap = 0usize;
    let mut fleet_configured = 0usize;
    let mut fleet_auto = false;
    let mut fleet_ceiling = 0usize;
    let mut fleet_refused = false;
    let mut fleet_knee = None;
    let servers: Vec<ServerTick> = d
        .hub
        .pool_live
        .lock_ok()
        .as_ref()
        .map(|l| {
            fleet_cap = l.line_cap_fleet.load(Ordering::Relaxed);
            fleet_configured = l.line_cap_configured.load(Ordering::Relaxed);
            fleet_auto = l.line_cap_auto.load(Ordering::Relaxed);
            fleet_ceiling = l.line_cap_ceiling.load(Ordering::Relaxed);
            fleet_refused = l.line_cap_refused.load(Ordering::Relaxed);
            fleet_knee = l.line_cap_knee.clone();
            l.servers
                .iter()
                .map(|s| ServerTick {
                    host: s.host.clone(),
                    connected: s.connected.load(Ordering::Relaxed),
                    budget: s.budget.load(Ordering::Relaxed),
                    bytes: s.bytes.load(Ordering::Relaxed),
                    blocked_ms: s.blocked_ms.load(Ordering::Relaxed),
                    reconnects: s.reconnects.load(Ordering::Relaxed),
                    refused: s.refusal.lock().map(|r| r.is_some()).unwrap_or(false),
                    tried: s.articles_tried.load(Ordering::Relaxed),
                    missing: s.articles_missing.load(Ordering::Relaxed),
                    art_ms: s.srv_art_ms.load(Ordering::Relaxed),
                    // TODO 318: the provider's own connection ceiling.
                    // The LIVE gauges only, never `Daemon::capped_hosts`
                    // alongside them the way the Providers card's
                    // `cap_payload` merges the two: that store is
                    // session memory that outlives the pool which
                    // measured it, and this module's rule is that a
                    // verdict is asserted only from evidence a window of
                    // THIS run agrees on. A card describing a provider
                    // can afford last hour's ceiling; a sentence about
                    // why this download is slow cannot.
                    capped_since: s.capped_since.load(Ordering::Relaxed),
                    granted_hi: s.granted_hi.load(Ordering::Relaxed),
                    capped_at: s.capped_at.load(Ordering::Relaxed),
                    // Its own words: the standing refusal's line while
                    // one stands (a capacity refusal is noted whether or
                    // not the account is also serving), else a capacity
                    // outage's detail. `down_reason` alone would be
                    // silent for exactly the host this verdict is about
                    // - the outage gauge is guarded on holding NO
                    // sessions, and a server granting 1 of 40 is capped
                    // and not down.
                    cap_said: s
                        .refusal
                        .lock()
                        .ok()
                        .and_then(|r| r.as_ref().filter(|r| !r.permanent).map(|r| r.line.clone()))
                        .or_else(|| {
                            s.down_reason.lock().ok().and_then(|d| {
                                d.as_ref()
                                    .filter(|d| d.kind == "capacity")
                                    .map(|d| d.detail.clone())
                            })
                        })
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();
    // The draining predecessor's sockets, for `Tick::drain_connected`.
    // Taken AFTER the `pool_live` guard above has gone - the way
    // `Daemon::fire_drain` and `stall::watched` do it, cloning the
    // handle OUT and letting the slot lock go before touching the pool -
    // because this runs on the 1 s ticker and must never hold two of the
    // daemon's locks at once. The two readings are therefore a
    // hair apart in time, which is the right trade: a socket count that
    // moved between them changes an implied fleet size by one.
    let drain_live = d
        .drain_dl
        .lock_ok()
        .as_ref()
        .and_then(|s| s.pool_live.clone());
    let drain_connected: usize = drain_live.map_or(0, |l| {
        l.servers
            .iter()
            .map(|s| s.connected.load(Ordering::Relaxed))
            .sum()
    });
    let at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0);
    d.whyslow.tick(Tick {
        owner,
        at_ms,
        achieved_bps: bps,
        throttle_bps,
        anchor_bps,
        cpu_pct: d.cpu_pct(),
        storage: d.slow_storage.paused(),
        storage_suspect: d.slow_storage.suspect(nzbkit::pool::now_ms()),
        post_unix: d.hub.post_unix.load(Ordering::Relaxed),
        fleet_cap,
        fleet_configured,
        fleet_auto,
        fleet_ceiling,
        fleet_refused,
        fleet_knee,
        drain_connected,
        servers,
    });
    // §108 option 2: publish the question the tick just raised, so the
    // slowstore watcher knows whether to spend a probe. Set AFTER the
    // tick, from the tick's own conclusion - the watcher runs on its own
    // clock and simply reads the latest answer.
    d.slow_storage.set_want_diag(d.whyslow.wants_disk_answer());
}

/// The daemon-facing wrapper: the core behind a lock, plus the payload
/// builder and a small cache of the last bench-history reading (so the
/// 1 s queue poll never re-reads the file).
pub struct WhySlow {
    pub core: Mutex<Core>,
    /// (bench_last it was read at, network bps, ts) - refreshed only
    /// when `Daemon::bench_last` moves.
    pub bench: Mutex<(u64, u64, u64)>,
}

impl Default for WhySlow {
    fn default() -> Self {
        WhySlow {
            core: Mutex::new(Core::default()),
            bench: Mutex::new((0, 0, 0)),
        }
    }
}

impl WhySlow {
    pub fn tick(&self, t: Tick) {
        self.core.lock_ok().tick(t);
    }

    /// Whether the core is at its disk-vs-client fork and wants the
    /// volume tested. Read by the slowstore watcher, which is the only
    /// thing that touches the volume.
    pub fn wants_disk_answer(&self) -> bool {
        self.core.lock_ok().disk_question
    }

    /// Is the STANDING verdict `client` - our own pipeline downstream
    /// of the sockets? TODO 313 item 5's first mandatory stand-down: a
    /// downstream bottleneck is SHARED, so lending sockets to a second
    /// job makes it worse rather than better.
    ///
    /// The published majority verdict and never a single tick's
    /// classification, which is the whole point of the window - and the
    /// answer a spill needs, since it is about to act on a belief that
    /// has to be steady for twelve of the last twenty seconds anyway.
    pub fn blames_client(&self) -> bool {
        self.core.lock_ok().verdict().0 == Layer::Client
    }

    /// TODO 207: this job's verdict for its history record, or None if
    /// the core is not judging it or judged nothing.
    ///
    /// Ownership is checked rather than assumed: the core judges
    /// whoever owns the wire, so asking for a job that is not the one
    /// being judged must yield nothing at all, never the current
    /// job's verdict under another name.
    pub fn capture(&self, nzo_id: &str, now_ms: u64) -> Option<WhyVerdict> {
        let c = self.core.lock_ok();
        match c.owner.as_deref() == Some(nzo_id) {
            true => c.summary(now_ms),
            false => None,
        }
    }

    /// The queue payload's `whyslow` block - null when no job owns the
    /// wire. `d` supplies the bench corroboration and the live server
    /// list; everything judged comes from the core.
    pub fn payload(&self, d: &super::daemon::Daemon) -> Value {
        use std::sync::atomic::Ordering;
        // Bench corroboration, cached against bench_last so the poll
        // never touches the file unless a new bench ran. Read BEFORE
        // taking the core lock: this is the one file read in the whole
        // surface, and holding the core mutex across it would park the
        // 1 s ticker behind a slow spool.
        let (bench_net_bps, bench_ts) = {
            let last = d.bench_last.load(Ordering::Relaxed);
            let mut b = self.bench.lock_ok();
            if b.0 != last && last != 0 {
                let (net, ts) = d
                    .bench_history()
                    .iter()
                    .rev()
                    .find_map(|e| {
                        let g = e.get("network_gbps")?.as_f64()?;
                        let ts = e.get("ts")?.as_u64()?;
                        Some(((g * 125_000_000.0) as u64, ts))
                    })
                    .unwrap_or((0, 0));
                *b = (last, net, ts);
            }
            (b.1, b.2)
        };
        let line = d.line_speed.load(Ordering::Relaxed);
        let (anchor_bps, anchor_src) = anchor(d, line);
        // The hardware ceiling: the best independent evidence held
        // about this link, its source named. The anchor already
        // resolves measured-vs-typed; a bench probe that beat both is
        // the better witness.
        let (hardware_bps, hardware_src) = if bench_net_bps > anchor_bps {
            (bench_net_bps, "bench")
        } else {
            (anchor_bps, anchor_src)
        };
        // The pool's article-time pair, read BEFORE the core lock for
        // the same reason the bench file above is: this surface never
        // holds the core mutex across another lock.
        //
        // `art_ms` here is the MID-RUN fleet EWMA - the value
        // `hedge_stale_bound` is consulting right now - and
        // `hedge_bound_ms` is what it currently computes from it. That
        // is deliberately not the `art` figure in the end-of-run
        // `[pool]` log line, which is sampled while the in-flight set
        // drains and therefore tracks the drain's duration rather than
        // an article's (research/NOTE-2026-08-21-art-ms-semantics.md
        // §10, where two reps of one job printed values 8.1x apart).
        // Reported, not judged: article time folds queueing behind
        // pipeline-mates on purpose, so a deep pipeline has a large one
        // while nothing at all is wrong, and no verdict may rest on it.
        let (pool_art_ms, hedge_bound_ms) = d
            .hub
            .pool_live
            .lock_ok()
            .as_ref()
            .map(|l| {
                (
                    l.race.art_ms.load(Ordering::Relaxed),
                    l.race.hedge_bound_ms.load(Ordering::Relaxed),
                )
            })
            .unwrap_or((0, 0));
        let c = self.core.lock_ok();
        let Some(owner) = c.owner.clone() else {
            return Value::Null;
        };
        let (layer, detail) = c.verdict();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_millis() as u64)
            .unwrap_or(0);
        let servers: Vec<Value> = {
            let mut hosts: Vec<(&String, &ServerState)> = c.servers.iter().collect();
            hosts.sort_by(|a, b| a.0.cmp(b.0));
            hosts
                .into_iter()
                .map(|(host, s)| {
                    json!({
                        "host": host,
                        "conns": s.connected,
                        "budget": s.budget,
                        "bps": s.d_bytes,
                        "per_conn_bps": if s.connected > 0 { s.d_bytes / s.connected as u64 } else { 0 },
                        "refused": s.refused,
                        "missing_pct": if s.tried > 0 {
                            100.0 * s.missing as f64 / s.tried as f64
                        } else { 0.0 },
                        "reconnects": s.win_reconnects,
                        "art_ms": s.art_ms,
                    })
                })
                .collect()
        };
        // TODO 318, both computed before the literal because `json!`
        // is a macro and a `let` inside one reads badly; `best` borrows
        // `c`, so it must outlive the literal too.
        let best = c.best_missing();
        let sole = c.sole_capped();
        let timeline: Vec<Value> = c
            .timeline
            .iter()
            .rev()
            .map(|ch| {
                json!({
                    "at_ms": ch.at_ms,
                    "layer": ch.layer.token(),
                    "detail": ch.detail,
                })
            })
            .collect();
        json!({
            "nzo_id": owner,
            "layer": layer.token(),
            "detail": detail,
            "secs": now_ms.saturating_sub(c.verdict_since_ms) / 1000,
            "achieved_bps": d.current_speed_bps() as u64,
            "anchor_bps": anchor_bps,
            "anchor_src": anchor_src,
            "throttle_bps": d.hub.rate.get(),
            "blocked_pct": (c.last_blocked_pct * 10.0).round() / 10.0,
            "cpu_pct": (c.last_cpu_pct * 10.0).round() / 10.0,
            "storage": d.slow_storage.paused(),
            // §108 option 2: when the disk is named WITHOUT a pause in
            // force, this is the number that named it - the module's
            // rule is that every asserted verdict travels with the
            // evidence that produced it, and "storage is not keeping
            // up" is a claim about someone's hardware. 0 when the
            // diagnostic is not what is talking.
            "storage_probe_ms": match c.verdict().0 == Layer::Disk && !d.slow_storage.paused() {
                true => d.slow_storage.diag_ms(),
                false => 0,
            },
            "envelope_bps": c.envelope_bps,
            // TODO 313 items 2 and 10: is a queue SPILL live right now,
            // and how many of this job's connections are working on the
            // jobs behind it?
            //
            // A daemon fact rather than a judged one, so it is read
            // straight off `d` here and not folded into the window
            // above - the governor has its own twenty-second window and
            // its own bar, and this panel's job is to SAY what is
            // happening, not to re-decide it. Always shipped, like
            // every other receipt: a user watching a download go slower
            // than usual is owed the sentence "some of its connections
            // are on the jobs behind it" whichever layer is talking,
            // and that sentence is a fact about this daemon whatever
            // whyslow currently blames.
            //
            // 0 when no episode is live, which is every install with
            // the switch off.
            "spill_lent": d.spill.lent(),
            // The receipts behind a `missing` verdict, always shipped so
            // the panel can show the working whichever arm is talking:
            // the post's own date (0 = we have none, which is why the
            // sentence hedges), the fleet-wide miss rate that opened the
            // case, and how many INDEPENDENT backbones are seeing it -
            // the number that does or does not license "no provider has
            // these articles".
            "post_unix": c.last_post_unix,
            "missing_pct": (c.fleet_missing().unwrap_or(0.0) * 1000.0).round() / 10.0,
            "missing_backbones": c.missing_backbones(),
            // TODO 318: and the BEST single server's own miss rate,
            // which is the number that says whether the post is
            // completable at all. Shipped beside the fleet-wide one
            // rather than instead of it, because they answer different
            // questions and the reader needs both: 85.1% of the
            // requests came back empty AND one provider has 99.9% of
            // it. `missing_best_host` is empty when no server has been
            // asked enough to have an opinion (`BACKBONE_MIN_TRIED`),
            // which is what the page gates on - a percentage with no
            // host is 0.0 and would read as "some server has all of
            // it".
            "missing_best_host": best.map(|(h, _)| h.as_str()).unwrap_or(""),
            "missing_best_pct": best.map_or(0.0, |(_, r)| (r * 1000.0).round() / 10.0),
            // ...and the DECISION that pair licenses, made here rather
            // than on the page: that server's own miss rate is under
            // the bar, so this post is completable there. The bar is
            // `MISSING_BAR` and it lives in one place - the page cannot
            // be handed a percentage and asked to decide what counts as
            // "most of it", which is how a fourth opinion about how
            // many holes are too many gets born. It is the same
            // decision `missing_case` makes when it declines to say
            // `gone`, shipped so the panel can say WHY it declined.
            "missing_completable": best.is_some_and(|(_, r)| r < MISSING_BAR),
            // TODO 318: the receipts behind a `solecap` verdict - which
            // server has the post, how little of it that server is
            // missing, what its provider granted against what was
            // asked, and the provider's own words. Always shipped, like
            // the three blocks above, so the panel can show the working
            // whichever arm is talking.
            //
            // `sole_host` EMPTIES the moment the conditions stop
            // holding, while the verdict - majority-held over the
            // window - can still read `solecap` for a few more seconds.
            // That is deliberate and is `knee_host`'s contract exactly:
            // the page gates its remedy button on this field rather
            // than on the layer, because offering to open a server's
            // settings over a cap that has just been lifted is worse
            // than offering nothing, while the SENTENCE still names the
            // host either way because it reads `detail`, which travels
            // with the held verdict.
            "sole_host": sole.as_ref().map(|e| e.host.as_str()).unwrap_or(""),
            "sole_missing_pct": sole.as_ref().map_or(0.0, |e| (e.missing_pct * 10.0).round() / 10.0),
            "sole_granted": sole.as_ref().map_or(0, |e| e.granted_hi),
            "sole_asked": sole.as_ref().map_or(0, |e| e.capped_at),
            "sole_said": sole.as_ref().map(|e| e.said.as_str()).unwrap_or(""),
            // TODO 312 item 3: the receipts behind a `fleet` verdict -
            // the cap in force, what the accounts would have allowed,
            // the per-socket carry that was measured and the fleet that
            // carry implies for this line. Always shipped, like the
            // `missing` block above, so the panel can show the working
            // whichever arm is talking; the two measurements are 0 until
            // a tick has had something to measure.
            "fleet_cap": c.fleet.cap,
            "fleet_configured": c.fleet.configured,
            "fleet_auto": c.fleet.auto,
            "fleet_ceiling": c.fleet.ceiling,
            // TODO 275 item 7: and whether that ceiling is one a
            // provider's capacity refusal stood down. Shipped so the
            // panel can say WHY the cap stopped where it did - the
            // number alone cannot, since a ceiling of 50 on an account
            // granting 50 and one stood down from 100 are the same
            // number - and so the page can withhold the remedy button,
            // which on this install would send the reader to raise a
            // budget into an account that has already refused it.
            "fleet_refused": c.fleet.refused,
            "fleet_carry_bps": c.fleet.carry_bps,
            "fleet_implied": c.fleet.implied,
            // TODO 312 item 7: the receipts behind a `knee` verdict, on
            // the same always-shipped rule as the two blocks above -
            // which server our own auto-tune measured, what it settled
            // on, how many sockets that is costing the fleet right now,
            // and how old the measurement is. `knee_host` is shipped in
            // FULL and separately from `detail`, which carries the same
            // host trimmed for display: the panel's remedy button hands
            // it to `landOnServer`, which matches the server list by
            // exact host and finds nothing if the sentence's tidied
            // version is passed instead.
            //
            // It EMPTIES when the current tick carries no knee, while
            // the verdict - majority-held over the window - can still
            // read `knee` for a few more seconds. That is why the page
            // gates the two remedy buttons on this field rather than on
            // the layer: offering to open a server's settings for a
            // knee that is no longer applied is worse than offering
            // nothing, and the sentence still names the host either
            // way, because it reads `detail`, which travels with the
            // held verdict.
            "knee_host": c.knee.host,
            "knee_at": c.knee.at,
            "knee_takes": c.knee.takes,
            "knee_age_secs": c.knee.age_secs,
            "knee_carry_bps": c.knee.carry_bps,
            "knee_implied": c.knee.implied,
            "art_ms": pool_art_ms,
            "hedge_bound_ms": hedge_bound_ms,
            "hardware_bps": hardware_bps,
            "hardware_src": hardware_src,
            "bench_ts": bench_ts,
            "servers": servers,
            "timeline": timeline,
        })
    }
}

/// TODO 207: stamp this run's verdict onto the record, at network-drain.
///
/// WHEN, and why it is here and not one step later: the core judges
/// whoever owns the wire, so network-drain is both the last instant the
/// verdict exists and the last instant it is about this job. The lane
/// marks the record `Finishing` up to a few seconds later - through
/// `settle_job_tail` and the sidecar wind-down - and the ticker keeps
/// voting for all of it on a fleet that has already hung up, which is
/// exactly the shape `classify`'s `never_fed` guard exists to keep out
/// of a live verdict; banking those seconds into the held-time totals
/// would put the same fiction into the persisted one.
///
/// This is deliberately the verdict for the NETWORK leg alone. A job
/// that flew down the wire and then sat ten minutes in its tail is not
/// a slow download and has no verdict here - `Job::postproc_secs` is
/// the number that answers for the tail, and conflating the two would
/// give the tail a layer name it was never judged on.
///
/// Stamped on the record rather than carried on the postproc ticket so
/// that a job which FAILED on the wire keeps it too: every exit from
/// the network phase, clean or not, passes through here.
pub fn stamp(d: &super::daemon::Daemon, nzo_id: &str) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_millis() as u64)
        .unwrap_or(0);
    let Some(v) = d.whyslow.capture(nzo_id, now_ms) else {
        return;
    };
    // History as well as the queue: a delete verb files a still-
    // downloading record into history and the fetch then errors its way
    // through here, so the record this is about is no longer where it
    // started. One container lock at a time, and the record itself is
    // locked only after `queue_job` / `history_job` has returned -
    // "locking a Job while holding the queue is how this tree
    // deadlocks".
    if let Some(job) = d.queue_job(nzo_id).or_else(|| d.history_job(nzo_id)) {
        job.lock_ok().whyslow = Some(v);
    }
}

/// The persisted form. Written by `job_json`, and read back by
/// [`verdict_from_json`] - the pair lives here, next to the token
/// table it has to agree with.
pub(crate) fn verdict_json(v: &WhyVerdict) -> Value {
    json!({
        "layer": v.layer,
        "detail": v.detail,
        "held_secs": v.held_secs,
        "total_secs": v.total_secs,
    })
}

/// ...and back, defensively. TODO 207's rule: every record written
/// before this field existed must read as ABSENT - not as `unknown`,
/// and not as `line`. That is the whole of it, because absence is the
/// only thing such a record can truthfully say, and both of those
/// tokens are claims. So there is no default anywhere on this path: a
/// missing key, a key of the wrong shape, and a layer token this build
/// does not know all yield None.
pub(crate) fn verdict_from_json(v: Option<&Value>) -> Option<WhyVerdict> {
    let v = v?;
    let layer = Layer::from_token(v.get("layer")?.as_str()?)?;
    Some(WhyVerdict {
        layer: layer.token().to_string(),
        detail: v
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        held_secs: v.get("held_secs").and_then(Value::as_u64).unwrap_or(0),
        total_secs: v.get("total_secs").and_then(Value::as_u64).unwrap_or(0),
    })
}

#[cfg(test)]
#[path = "whyslow_tests.rs"]
mod tests;
