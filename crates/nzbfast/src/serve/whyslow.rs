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
use crate::MutexExt;

/// The vote window: one classification per second, verdicts need a
/// majority of it. Long enough that a two-second wobble cannot flip
/// the answer, short enough that a real regime change (a provider
/// browning out, a cap engaging) is named within half a minute.
const WINDOW: usize = 20;

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
    pub(super) fn token(self) -> &'static str {
        match self {
            Layer::Limit => "limit",
            Layer::Line => "line",
            Layer::Disk => "disk",
            Layer::Cpu => "cpu",
            Layer::Client => "client",
            Layer::Provider => "provider",
            Layer::Missing => "missing",
            Layer::Unknown => "unknown",
        }
    }

    /// The reverse, for a verdict read back off a history record. An
    /// unrecognised token - a future layer, or a corrupted line - is
    /// None, which reads as no verdict rather than as a wrong one.
    /// `unknown` is deliberately not accepted: it IS the absence of a
    /// verdict, and TODO 207's rule is that absence stays absence.
    fn from_token(t: &str) -> Option<Layer> {
        [
            Layer::Limit,
            Layer::Line,
            Layer::Disk,
            Layer::Cpu,
            Layer::Client,
            Layer::Provider,
            Layer::Missing,
        ]
        .into_iter()
        .find(|l| l.token() == t)
    }
}

/// One server's cumulative counters at a tick, as read from
/// `ServerLive`. The core differences them itself (and forgives a
/// counter that restarted, e.g. a new pool mid-tail).
pub(super) struct ServerTick {
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
}

/// Everything one second of observation carries into the core.
pub(super) struct Tick {
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
    pub servers: Vec<ServerTick>,
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
}

/// A verdict change, for the per-job timeline.
#[derive(Clone)]
struct Change {
    at_ms: u64,
    layer: Layer,
    detail: String,
}

/// The pure decision core. All state is per-owner: a new job on the
/// wire starts from nothing.
#[derive(Default)]
pub(super) struct Core {
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
}

impl Core {
    /// Feed one second. The published verdict after the call is
    /// `verdict()`.
    pub(super) fn tick(&mut self, t: Tick) {
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
fn anchor(d: &super::daemon::Daemon, line_bps: u64) -> (u64, &'static str) {
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
pub(super) fn feed(
    d: &std::sync::Arc<super::daemon::Daemon>,
    bps: f64,
    throttle_bps: u64,
    line_bps: u64,
) {
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
    let servers: Vec<ServerTick> = d
        .hub
        .pool_live
        .lock_ok()
        .as_ref()
        .map(|l| {
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
                })
                .collect()
        })
        .unwrap_or_default();
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
pub(super) struct WhySlow {
    core: Mutex<Core>,
    /// (bench_last it was read at, network bps, ts) - refreshed only
    /// when `Daemon::bench_last` moves.
    bench: Mutex<(u64, u64, u64)>,
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
    pub(super) fn tick(&self, t: Tick) {
        self.core.lock_ok().tick(t);
    }

    /// Whether the core is at its disk-vs-client fork and wants the
    /// volume tested. Read by the slowstore watcher, which is the only
    /// thing that touches the volume.
    pub(super) fn wants_disk_answer(&self) -> bool {
        self.core.lock_ok().disk_question
    }

    /// TODO 207: this job's verdict for its history record, or None if
    /// the core is not judging it or judged nothing.
    ///
    /// Ownership is checked rather than assumed: the core judges
    /// whoever owns the wire, so asking for a job that is not the one
    /// being judged must yield nothing at all, never the current
    /// job's verdict under another name.
    pub(super) fn capture(&self, nzo_id: &str, now_ms: u64) -> Option<WhyVerdict> {
        let c = self.core.lock_ok();
        match c.owner.as_deref() == Some(nzo_id) {
            true => c.summary(now_ms),
            false => None,
        }
    }

    /// The queue payload's `whyslow` block - null when no job owns the
    /// wire. `d` supplies the bench corroboration and the live server
    /// list; everything judged comes from the core.
    pub(super) fn payload(&self, d: &super::daemon::Daemon) -> Value {
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
pub(super) fn stamp(d: &super::daemon::Daemon, nzo_id: &str) {
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
pub(in crate::serve) fn verdict_json(v: &WhyVerdict) -> Value {
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
pub(in crate::serve) fn verdict_from_json(v: Option<&Value>) -> Option<WhyVerdict> {
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
mod tests {
    use super::*;

    /// The rigs' wall clock: a real unix millisecond stamp, not a
    /// small number. `missing_case` measures the post's age against
    /// `at_ms`, so a toy epoch would put every plausible post date in
    /// the future and quietly suppress the arm under test.
    const T0: u64 = 1_755_000_000_000;

    fn srv(host: &str, connected: usize, budget: usize, bytes: u64, blocked: u64) -> ServerTick {
        ServerTick {
            host: host.into(),
            connected,
            budget,
            bytes,
            blocked_ms: blocked,
            reconnects: 0,
            refused: false,
            tried: 100,
            missing: 0,
            art_ms: 0,
        }
    }

    /// Drive `n` seconds of a steady regime; cumulative counters
    /// advance by the per-tick deltas given.
    struct Rig {
        core: Core,
        t: u64,
        bytes: HashMap<String, u64>,
        blocked: HashMap<String, u64>,
        recon: HashMap<String, u64>,
        /// What slowstore's diagnostic probes are currently saying. A
        /// field rather than another positional argument: `run` is
        /// already at the clippy limit, and every existing case wants
        /// the default (no diagnostic verdict).
        suspect: bool,
        /// Per-server (tried, missing) for the article census, when a
        /// case is about the post rather than the link. Same reasoning
        /// as `suspect`: every other case wants `srv`'s default of 100
        /// tried and none missing.
        miss: Option<(u64, u64)>,
        /// The running post's date, as `StreamHub::post_unix` publishes
        /// it. 0 (the default every other case wants) is UNKNOWN, which
        /// asserts neither propagation nor a takedown.
        post_unix: i64,
    }

    impl Rig {
        fn new() -> Rig {
            Rig {
                core: Core::default(),
                t: T0,
                bytes: HashMap::new(),
                blocked: HashMap::new(),
                recon: HashMap::new(),
                suspect: false,
                miss: None,
                post_unix: 0,
            }
        }

        #[expect(clippy::too_many_arguments)]
        fn run(
            &mut self,
            n: usize,
            bps: f64,
            throttle: u64,
            anchor: u64,
            cpu: f64,
            storage: bool,
            // (host, connected, budget, d_bytes, d_blocked, d_recon, refused)
            servers: &[(&str, usize, usize, u64, u64, u64, bool)],
        ) {
            for _ in 0..n {
                self.t += 1000;
                let sv = servers
                    .iter()
                    .map(|&(h, c, b, db, dbl, dr, refused)| {
                        let bytes = self.bytes.entry(h.into()).or_default();
                        *bytes += db;
                        let blocked = self.blocked.entry(h.into()).or_default();
                        *blocked += dbl;
                        let recon = self.recon.entry(h.into()).or_default();
                        *recon += dr;
                        let (tried, missing) = self.miss.unwrap_or((100, 0));
                        ServerTick {
                            refused,
                            reconnects: *recon,
                            tried,
                            missing,
                            ..srv(h, c, b, *bytes, *blocked)
                        }
                    })
                    .collect();
                self.core.tick(Tick {
                    owner: Some("job1".into()),
                    at_ms: self.t,
                    achieved_bps: bps,
                    throttle_bps: throttle,
                    anchor_bps: anchor,
                    cpu_pct: cpu,
                    storage,
                    storage_suspect: self.suspect,
                    post_unix: self.post_unix,
                    servers: sv,
                });
            }
        }
    }

    #[test]
    fn unknown_until_the_window_fills() {
        let mut r = Rig::new();
        r.run(
            MAJORITY - 1,
            100e6,
            0,
            1_000_000_000,
            20.0,
            false,
            &[("a", 8, 8, 100_000_000, 0, 0, false)],
        );
        assert_eq!(
            r.core.verdict().0,
            Layer::Unknown,
            "no verdict before a majority"
        );
    }

    /// §210 (d). The clamp itself, over the four cases that decide it.
    #[test]
    fn the_local_link_caps_the_typed_line_and_nothing_else() {
        const LINE: u64 = 710 * 125_000;
        // Gary's shape: a 1200 Mbps Wi-Fi link carries ~660, so 660 is
        // the mark the graph draws 100% at - and it names the link
        // rather than calling the LAN a line speed setting.
        let wifi = 82_500_000;
        assert_eq!(
            link_capped((LINE, "line"), Some(wifi)),
            (wifi, "link"),
            "the LAN is lower, so the LAN is the ceiling"
        );
        // A link that covers the line changes nothing.
        assert_eq!(
            link_capped((LINE, "line"), Some(200_000_000)),
            (LINE, "line")
        );
        // A MEASURED anchor is a rate this machine actually sustained -
        // direct evidence about the whole path, including this hop.
        // An estimate of one hop may not argue with it.
        assert_eq!(
            link_capped((LINE, "measured"), Some(wifi)),
            (LINE, "measured")
        );
        // A tunnel, or an interface the OS would not rate, gives no
        // ceiling at all: nothing to clamp with.
        assert_eq!(link_capped((LINE, "line"), None), (LINE, "line"));
        // And no anchor stays no anchor - never invent one from a link.
        assert_eq!(link_capped((0, ""), Some(wifi)), (0, ""));
    }

    /// ...and what the clamp is FOR. Gary's own numbers only move the
    /// 100% mark (660 of 710 still rides the line bar), so this takes
    /// the shape that also moves the VERDICT: an 866 Mbps Wi-Fi 5 link
    /// carries ~476 Mbit under a gigabit line, and a run at that
    /// ceiling was being blamed on the providers.
    #[test]
    fn riding_the_local_link_is_not_a_provider_shortfall() {
        const LINE: u64 = 1000 * 125_000;
        let capped = link_capped((LINE, "line"), Some(59_537_500));
        assert_eq!(capped, (59_537_500, "link"));
        let mut r = Rig::new();
        r.run(
            WINDOW,
            58e6,
            0,
            capped.0,
            30.0,
            false,
            &[("a", 8, 8, 58_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Line);
        // Against the unclamped line the same run reads as a shortfall
        // the reader can do nothing about, and names a host that is
        // delivering everything the LAN will carry.
        let mut r = Rig::new();
        r.run(
            WINDOW,
            58e6,
            0,
            LINE,
            30.0,
            false,
            &[("a", 8, 8, 58_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Provider);
    }

    #[test]
    fn riding_the_anchor_is_line_speed() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            950e6,
            0,
            1_000_000_000,
            50.0,
            false,
            &[("a", 8, 8, 950_000_000, 900_000, 0, false)],
        );
        // Note the huge blocked_ms: a healthy download parks workers.
        // That must NOT read as a client problem (the §108 lesson).
        assert_eq!(r.core.verdict().0, Layer::Line);
    }

    #[test]
    fn a_binding_cap_is_the_limit() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            99e6,
            100_000_000,
            1_000_000_000,
            20.0,
            false,
            &[("a", 8, 8, 99_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Limit);
    }

    #[test]
    fn shortfall_with_idle_sockets_is_the_provider() {
        let mut r = Rig::new();
        // Half the anchor, workers not parked: upstream.
        r.run(
            WINDOW,
            500e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 500_000_000, 100, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Provider);
    }

    /// Gary's 16 Aug regime: 44% of the articles are not on the
    /// servers, so the pool spends its wire time on requests that
    /// return nothing and the fleet delivers a fraction of the anchor.
    /// Every other instrument reads this as a shaped or capped
    /// provider - the sockets ARE idle - and the verdict used to name
    /// a host that was behaving perfectly.
    #[test]
    fn a_post_full_of_holes_is_not_the_provider() {
        let mut r = Rig::new();
        r.miss = Some((2253, 982)); // 4506 tried, 1965 missing across two
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("a", 8, 8, 35_000_000, 100, 0, false),
                ("b", 8, 8, 35_000_000, 100, 0, false),
            ],
        );
        assert_eq!(r.core.verdict().0, Layer::Missing);
    }

    /// ...and the same shortfall with an intact post still convicts
    /// the provider. The layer above must not swallow the case it was
    /// inserted in front of.
    #[test]
    fn a_shortfall_on_an_intact_post_is_still_the_provider() {
        let mut r = Rig::new();
        r.miss = Some((2253, 20)); // under 1%
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("a", 8, 8, 35_000_000, 100, 0, false),
                ("b", 8, 8, 35_000_000, 100, 0, false),
            ],
        );
        assert_eq!(r.core.verdict().0, Layer::Provider);
    }

    /// The articles may not be available YET, or may have been taken
    /// down. A release grabbed the hour it pre'd 430s everywhere while
    /// the backbones fill in, and from in here that is pixel-for-pixel
    /// a takedown. The calendar is the only thing that separates them,
    /// so the young arm says so and nothing else does.
    #[test]
    fn a_brand_new_post_full_of_holes_is_still_propagating() {
        let mut r = Rig::new();
        r.miss = Some((2253, 982));
        // Two hours old, against the rig's own wall clock.
        r.post_unix = (r.t / 1000) as i64 - 2 * 3600;
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
                ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
            ],
        );
        assert_eq!(r.core.verdict(), (Layer::Missing, "young"));
    }

    /// The other side of the same regime: old enough that propagation
    /// is finished, and two independent backbones each saying so. Only
    /// here may the surface tell a user that waiting will not help.
    #[test]
    fn an_old_post_two_backbones_agree_is_gone() {
        let mut r = Rig::new();
        r.miss = Some((2253, 982));
        r.post_unix = (r.t / 1000) as i64 - 9 * 86_400;
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
                ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
            ],
        );
        assert_eq!(r.core.verdict(), (Layer::Missing, "gone"));
    }

    /// Five resellers of ONE backbone are one opinion. The same old
    /// post, the same misses, every server behind the same upstream:
    /// the shortfall is asserted, the takedown is NOT.
    #[test]
    fn one_backbone_however_emphatic_cannot_say_gone() {
        let mut r = Rig::new();
        r.miss = Some((2253, 982));
        r.post_unix = (r.t / 1000) as i64 - 9 * 86_400;
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                // Same brand, two hostnames: `backbone_of` folds them.
                ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
                ("reader.alpha.com", 8, 8, 35_000_000, 100, 0, false),
            ],
        );
        assert_eq!(r.core.verdict(), (Layer::Missing, ""));
    }

    /// An NZB with no usable date reads as post_unix 0, and 0 is
    /// UNKNOWN, not "posted this second". Calling it young would
    /// promise a wait that may never end.
    #[test]
    fn an_undated_post_claims_neither_cause() {
        let mut r = Rig::new();
        r.miss = Some((2253, 982));
        r.post_unix = 0;
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
                ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
            ],
        );
        assert_eq!(r.core.verdict(), (Layer::Missing, ""));
    }

    /// A post dated in the future - a wrong clock, a mis-stamped NZB -
    /// is not evidence of freshness. Neither arm may fire on it.
    #[test]
    fn a_post_dated_in_the_future_claims_neither_cause() {
        let mut r = Rig::new();
        r.miss = Some((2253, 982));
        r.post_unix = (r.t / 1000) as i64 + 30 * 86_400;
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
                ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
            ],
        );
        assert_eq!(r.core.verdict(), (Layer::Missing, ""));
    }

    /// The boundary itself, walked both sides. `GONE_MIN_AGE_DAYS` is
    /// where this project already draws the propagation line and this
    /// surface must not draw a fourth one of its own.
    #[test]
    fn the_young_gone_boundary_is_gone_min_age_days() {
        for (age_secs, want) in [
            (YOUNG_MAX_SECS - 60, "young"),
            (YOUNG_MAX_SECS, "gone"),
            (YOUNG_MAX_SECS + 86_400, "gone"),
        ] {
            let mut r = Rig::new();
            r.miss = Some((2253, 982));
            r.post_unix = (r.t / 1000) as i64 - age_secs;
            r.run(
                WINDOW,
                70e6,
                0,
                1_000_000_000,
                30.0,
                false,
                &[
                    ("news.alpha.com", 8, 8, 35_000_000, 100, 0, false),
                    ("news.beta.com", 8, 8, 35_000_000, 100, 0, false),
                ],
            );
            assert_eq!(
                r.core.verdict(),
                (Layer::Missing, want),
                "post {age_secs}s old"
            );
        }
    }

    /// A backbone that saw a handful of requests is not one of the
    /// independent opinions "gone" needs, even at a 100% miss rate on
    /// its own tiny sample. Under `BACKBONE_MIN_TRIED` it sits out.
    #[test]
    fn a_barely_used_backbone_is_not_a_second_opinion() {
        let mut r = Rig::new();
        r.post_unix = (r.t / 1000) as i64 - 9 * 86_400;
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("news.alpha.com", 8, 8, 35_000_000, 100, 0, false)],
        );
        // The rig's `miss` is fleet-uniform, so the small server is
        // built by hand: 4000 tried / 1900 missing on alpha, 10/10 on
        // the fill host. Fleet-wide that clears MISSING_BAR; the fill
        // host's own sample does not clear BACKBONE_MIN_TRIED.
        let mut core = Core::default();
        for i in 0..WINDOW {
            core.tick(Tick {
                owner: Some("job1".into()),
                at_ms: T0 + (i as u64 + 1) * 1000,
                achieved_bps: 70e6,
                throttle_bps: 0,
                anchor_bps: 1_000_000_000,
                cpu_pct: 30.0,
                storage: false,
                storage_suspect: false,
                post_unix: (T0 / 1000) as i64 - 9 * 86_400,
                servers: vec![
                    ServerTick {
                        tried: 4000,
                        missing: 1900,
                        ..srv("news.alpha.com", 8, 8, 35_000_000 * (i as u64 + 1), 100)
                    },
                    ServerTick {
                        tried: 10,
                        missing: 10,
                        ..srv("news.beta.com", 8, 8, 35_000_000 * (i as u64 + 1), 100)
                    },
                ],
            });
        }
        assert_eq!(core.verdict(), (Layer::Missing, ""));
    }

    /// A handful of misses in the first seconds of a run is not a
    /// verdict about the post: under `MISSING_MIN_TRIED` the rate is
    /// not read at all, however bad it looks.
    #[test]
    fn a_tiny_sample_of_misses_convicts_nothing() {
        let mut r = Rig::new();
        r.miss = Some((20, 19)); // 95% missing, 40 articles fleet-wide
        r.run(
            WINDOW,
            70e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("a", 8, 8, 35_000_000, 100, 0, false),
                ("b", 8, 8, 35_000_000, 100, 0, false),
            ],
        );
        assert_ne!(r.core.verdict().0, Layer::Missing);
    }

    #[test]
    fn shortfall_with_parked_workers_and_hot_cpu_is_cpu() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            300e6,
            0,
            1_000_000_000,
            95.0,
            false,
            // 8 conns * 1000 ms = 8000 worker-ms; 6000 blocked = 75%.
            &[("a", 8, 8, 300_000_000, 6000, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Cpu);
    }

    #[test]
    fn shortfall_with_parked_workers_and_cool_cpu_is_the_client() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            300e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 300_000_000, 6000, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Client);
    }

    #[test]
    fn a_storage_pause_engaging_is_disk() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            50e6,
            0,
            1_000_000_000,
            30.0,
            true,
            &[("a", 8, 8, 50_000_000, 7000, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Disk);
    }

    /// §108 option 2. The volume that is BAD but not bad enough to trip
    /// the breaker: parked on the write side, delivering a twentieth of
    /// the line, for as long as you care to watch. The breaker needs
    /// three quarters of a three-minute window and never fires here, so
    /// before the diagnostic this read as Client - honest about the
    /// three candidates, but it sends nobody to look at their drive.
    #[test]
    fn a_slow_volume_is_named_before_the_breaker_trips() {
        let mut r = Rig::new();
        let regime = |r: &mut Rig| {
            r.run(
                WINDOW,
                50e6,
                0,
                1_000_000_000,
                30.0,
                false,
                &[("a", 8, 8, 50_000_000, 7000, 0, false)],
            )
        };
        // No answer yet: the probes have not run, or have come back
        // fast. We do not guess.
        regime(&mut r);
        assert_eq!(
            r.core.verdict().0,
            Layer::Client,
            "with no disk answer the honest verdict is our own pipeline"
        );
        assert!(
            r.core.disk_question,
            "...and the fork must be ASKING, or no probe ever runs"
        );

        // slowstore's probes come back slow, twice: now it is the disk,
        // with no pause anywhere in sight.
        r.suspect = true;
        regime(&mut r);
        assert_eq!(r.core.verdict().0, Layer::Disk);
        assert!(
            r.core.disk_question,
            "the question stays open on a Disk vote - closing it would \
             stop the probes, stale the answer and flip back to Client"
        );

        // The volume recovers: a fast probe drops the suspicion and the
        // verdict goes back to naming us, not the hardware.
        r.suspect = false;
        regime(&mut r);
        assert_eq!(r.core.verdict().0, Layer::Client);
    }

    /// The question is only asked where an answer would change the
    /// verdict. Everywhere else, probing a volume would be work for its
    /// own sake - and this feature's whole licence is that it never
    /// touches a healthy daemon's disk.
    #[test]
    fn the_disk_question_is_asked_only_at_the_fork() {
        // Riding the line: nothing is slow.
        let mut r = Rig::new();
        r.run(
            WINDOW,
            950e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 950_000_000, 900, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Line);
        assert!(!r.core.disk_question, "a healthy line asks nothing");

        // Short of the line, but the sockets could not fill the pipe -
        // upstream, so the volume is not the question.
        let mut r = Rig::new();
        r.run(
            WINDOW,
            50e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 50_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Provider);
        assert!(!r.core.disk_question, "a provider shortfall asks nothing");

        // Downstream, but CPU owns it: a witness already condemned.
        let mut r = Rig::new();
        r.run(
            WINDOW,
            50e6,
            0,
            1_000_000_000,
            97.0,
            false,
            &[("a", 8, 8, 50_000_000, 7000, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Cpu);
        assert!(!r.core.disk_question, "CPU is its own witness");

        // The breaker is in force: it owns the volume from here, and
        // its probes are already running on the paused cadence.
        let mut r = Rig::new();
        r.run(
            WINDOW,
            50e6,
            0,
            1_000_000_000,
            30.0,
            true,
            &[("a", 8, 8, 50_000_000, 7000, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Disk);
        assert!(
            !r.core.disk_question,
            "a real pause closes the question - the breaker owns it"
        );
    }

    #[test]
    fn a_refusing_host_is_named() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            400e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("fast.example", 8, 8, 400_000_000, 0, 0, false),
                ("refusing.example", 0, 8, 0, 0, 0, true),
            ],
        );
        let (l, d) = r.core.verdict();
        assert_eq!(l, Layer::Provider);
        assert_eq!(d, "refusing.example");
    }

    #[test]
    fn a_conn_capped_host_is_named() {
        let mut r = Rig::new();
        // 26 granted of a 32 budget - the Giganews shape.
        r.run(
            WINDOW,
            400e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("capped.example", 20, 32, 40_000_000, 0, 0, false),
                ("fast.example", 8, 8, 360_000_000, 0, 0, false),
            ],
        );
        let (l, d) = r.core.verdict();
        assert_eq!(l, Layer::Provider);
        assert_eq!(d, "capped.example");
    }

    #[test]
    fn a_shaped_host_is_convicted_by_relative_rates() {
        let mut r = Rig::new();
        // Full budget connected on both; one delivers ~2 MB/s/conn,
        // the other ~45 MB/s/conn (the measured 8 Aug shape).
        r.run(
            WINDOW,
            420e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("shaped.example", 26, 26, 52_000_000, 0, 0, false),
                ("fast.example", 8, 8, 360_000_000, 0, 0, false),
            ],
        );
        let (l, d) = r.core.verdict();
        assert_eq!(l, Layer::Provider);
        assert_eq!(d, "shaped.example");
    }

    #[test]
    fn healthy_spread_convicts_nobody() {
        let mut r = Rig::new();
        // Both hosts busy at comparable per-conn rates: provider
        // verdict, but no host named - the fleet is just full.
        r.run(
            WINDOW,
            500e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[
                ("a.example", 10, 10, 300_000_000, 0, 0, false),
                ("b.example", 10, 10, 200_000_000, 0, 0, false),
            ],
        );
        let (l, d) = r.core.verdict();
        assert_eq!(l, Layer::Provider);
        assert_eq!(d, "");
    }

    #[test]
    fn no_anchor_means_unknown_not_a_guess() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            100e6,
            0,
            0,
            30.0,
            false,
            &[("a", 8, 8, 100_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Unknown);
    }

    #[test]
    fn a_dead_fleet_with_a_budget_is_the_provider() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            0.0,
            0,
            1_000_000_000,
            5.0,
            false,
            &[("a", 0, 8, 0, 0, 0, false)],
        );
        let (l, d) = r.core.verdict();
        assert_eq!(l, Layer::Provider);
        assert_eq!(d, "a");
    }

    #[test]
    fn a_drained_job_in_its_tail_is_not_blamed_on_the_provider() {
        let mut r = Rig::new();
        // A healthy run at line speed...
        r.run(
            WINDOW,
            950e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 950_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Line);
        // ...then net-drain: the connections hang up, speed reads
        // zero, bytes stop advancing. The dead-fleet rule must not
        // fire - the fleet DELIVERED; it is the tail, not an outage.
        r.run(
            WINDOW,
            0.0,
            0,
            1_000_000_000,
            60.0,
            false,
            &[("a", 0, 8, 0, 0, 0, false)],
        );
        assert_eq!(
            r.core.verdict().0,
            Layer::Unknown,
            "a finished wire is not provider evidence"
        );
    }

    #[test]
    fn yesterdays_reconnects_do_not_convict_a_drained_fleet() {
        let mut r = Rig::new();
        // A healthy run at line speed that weathered a routine redial
        // every tick - churn while the bytes flow convicts nobody.
        r.run(
            WINDOW,
            950e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 950_000_000, 0, 1, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Line);
        // Net-drain tail: the sockets hang up and nothing redials. The
        // job-lifetime redial history must not turn the tail into a
        // Provider verdict - this is the churn counterpart of the
        // drained-tail guard above, and it regressed on the live rig
        // when the sum never aged out.
        r.run(
            WINDOW,
            0.0,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 0, 8, 0, 0, 0, false)],
        );
        assert_eq!(
            r.core.verdict().0,
            Layer::Unknown,
            "a hung-up fleet's redial history is not evidence"
        );
    }

    /// TODO 207: the verdict a finished job carries into history is the
    /// LONGEST-HELD layer of its run, not the last one before it left
    /// the wire. A job that was provider-bound for most of an hour and
    /// spent its final half-minute on a busy CPU was a provider
    /// problem, and "last verdict" - the cheap option - says the
    /// opposite of the truth about exactly that job.
    #[test]
    fn the_captured_verdict_is_the_longest_held_layer_not_the_last() {
        let mut r = Rig::new();
        // Forty seconds shy of the anchor with the pipeline idle: the
        // sockets could not fill the pipe.
        r.run(
            40,
            500e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 500_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Provider);
        // ...then the run ends with the machine's own cores pegged and
        // the workers parked on a full channel, which is a different
        // layer and IS the last thing that was true.
        r.run(
            20,
            500e6,
            0,
            1_000_000_000,
            95.0,
            false,
            &[("a", 8, 8, 500_000_000, 8_000, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Cpu, "the LAST verdict");
        let v = r.core.summary(r.t).expect("a judged run has a verdict");
        assert_eq!(v.layer, "provider", "but the longest-held one is kept");
        assert!(
            v.held_secs > v.total_secs / 2,
            "and it carries its own weight: {v:?}"
        );
        assert!(
            (58..=61).contains(&v.total_secs),
            "the whole observed run, not just the winning span: {v:?}"
        );
    }

    /// ...and the honest half of the same rule: `Unknown` is the
    /// ABSENCE of a verdict, so a run nothing could be said about
    /// persists nothing at all. Anything else and every fast little
    /// download in history would carry "still gathering evidence".
    #[test]
    fn a_run_nothing_could_judge_persists_no_verdict() {
        let mut r = Rig::new();
        // No anchor: "slow" is undefined, so every tick votes Unknown.
        r.run(
            30,
            500e6,
            0,
            0,
            30.0,
            false,
            &[("a", 8, 8, 500_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Unknown);
        assert!(r.core.summary(r.t).is_none());
        // A verdict that never held a whole second is not one either -
        // it rounds to "for 0s" on every surface that renders it.
        let mut r = Rig::new();
        r.run(
            WINDOW,
            950e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 950_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Line);
        let v = r
            .core
            .summary(r.t)
            .expect("line is a verdict like any other");
        assert_eq!(v.layer, "line");
        assert!(r.core.summary(r.core.verdict_since_ms + 999).is_none());
    }

    /// The capture is ownership-checked, for the same reason the live
    /// payload is: the core judges whoever owns the wire, so asking it
    /// about any other job must yield nothing rather than this job's
    /// verdict filed under somebody else's name.
    #[test]
    fn a_capture_for_another_job_is_never_this_ones_verdict() {
        let w = WhySlow::default();
        for i in 1..=WINDOW as u64 {
            w.tick(Tick {
                owner: Some("job1".into()),
                at_ms: T0 + i * 1000,
                achieved_bps: 500e6,
                throttle_bps: 0,
                anchor_bps: 1_000_000_000,
                cpu_pct: 30.0,
                storage: false,
                storage_suspect: false,
                post_unix: 0,
                servers: vec![srv("a", 8, 8, 500_000_000 * i, 0)],
            });
        }
        let at = T0 + WINDOW as u64 * 1000;
        assert!(w.capture("job2", at).is_none(), "not job2's verdict");
        assert_eq!(
            w.capture("job1", at).map(|v| v.layer),
            Some("provider".to_string())
        );
    }

    /// The persisted form, both ways. The reading half is where TODO
    /// 207's absence rule lives, so every shape that is not a verdict
    /// this build understands has to come back as no verdict.
    #[test]
    fn the_verdict_wire_form_round_trips_and_refuses_everything_else() {
        let v = WhyVerdict {
            layer: "provider".into(),
            detail: "news.example.invalid".into(),
            held_secs: 640,
            total_secs: 900,
        };
        assert_eq!(verdict_from_json(Some(&verdict_json(&v))), Some(v));
        assert!(verdict_from_json(None).is_none());
        for bad in [
            json!({}),
            json!({"layer": "unknown"}),
            json!({"layer": "line "}),
            json!({"detail": "news.example.invalid"}),
        ] {
            assert!(verdict_from_json(Some(&bad)).is_none(), "{bad}");
        }
        // ...and a verdict missing only its numbers is still a verdict:
        // the layer is the claim, the seconds are its weight.
        assert_eq!(
            verdict_from_json(Some(&json!({"layer": "line"}))).map(|v| v.held_secs),
            Some(0)
        );
    }

    #[test]
    fn owner_change_resets_everything() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            500e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 500_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Provider);
        // New owner: one tick under the new job must not inherit the
        // old evidence.
        r.core.tick(Tick {
            owner: Some("job2".into()),
            at_ms: r.t + 1000,
            achieved_bps: 500e6,
            throttle_bps: 0,
            anchor_bps: 1_000_000_000,
            cpu_pct: 30.0,
            storage: false,
            storage_suspect: false,
            post_unix: 0,
            servers: vec![srv("a", 8, 8, 500_000_000, 0)],
        });
        assert_eq!(r.core.verdict().0, Layer::Unknown);
        assert!(r.core.timeline.is_empty());
    }

    #[test]
    fn a_flap_cannot_flip_the_verdict() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            950e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 950_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Line);
        // Five slow seconds inside a line-speed run: not a majority,
        // verdict holds.
        r.run(
            5,
            300e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 300_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Line);
    }

    #[test]
    fn evidence_that_stays_split_falls_to_unknown() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            950e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 950_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.verdict().0, Layer::Line);
        // Alternate line-speed and half-speed seconds indefinitely:
        // neither layer can hold a majority, and past the transition
        // allowance the stale verdict must yield to Unknown rather
        // than keep asserting a regime the window no longer shows.
        for _ in 0..WINDOW {
            r.run(
                1,
                950e6,
                0,
                1_000_000_000,
                30.0,
                false,
                &[("a", 8, 8, 950_000_000, 0, 0, false)],
            );
            r.run(
                1,
                300e6,
                0,
                1_000_000_000,
                30.0,
                false,
                &[("a", 8, 8, 300_000_000, 0, 0, false)],
            );
        }
        assert_eq!(r.core.verdict().0, Layer::Unknown);
    }

    #[test]
    fn the_timeline_records_each_regime_change_once() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            950e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 950_000_000, 0, 0, false)],
        );
        r.run(
            WINDOW,
            300e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 300_000_000, 0, 0, false)],
        );
        let layers: Vec<Layer> = r.core.timeline.iter().map(|c| c.layer).collect();
        assert_eq!(layers, vec![Layer::Line, Layer::Provider]);
    }

    #[test]
    fn envelope_tracks_only_uncapped_unblocked_ticks() {
        let mut r = Rig::new();
        // Capped ticks must not set the envelope.
        r.run(
            WINDOW,
            100e6,
            100_000_000,
            1_000_000_000,
            20.0,
            false,
            &[("a", 8, 8, 100_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.envelope_bps, 0);
        // Uncapped: the best delivery becomes the envelope estimate.
        r.run(
            5,
            600e6,
            0,
            1_000_000_000,
            20.0,
            false,
            &[("a", 8, 8, 600_000_000, 0, 0, false)],
        );
        assert_eq!(r.core.envelope_bps, 600_000_000);
    }

    #[test]
    fn counter_restart_is_forgiven() {
        let mut r = Rig::new();
        r.run(
            WINDOW,
            500e6,
            0,
            1_000_000_000,
            30.0,
            false,
            &[("a", 8, 8, 500_000_000, 0, 0, false)],
        );
        // The pool restarted: cumulative bytes fall. One tick with a
        // smaller reading must not underflow or convict anyone.
        r.core.tick(Tick {
            owner: Some("job1".into()),
            at_ms: r.t + 1000,
            achieved_bps: 500e6,
            throttle_bps: 0,
            anchor_bps: 1_000_000_000,
            cpu_pct: 30.0,
            storage: false,
            storage_suspect: false,
            post_unix: 0,
            servers: vec![srv("a", 8, 8, 1000, 0)],
        });
        assert_eq!(
            r.core.verdict().0,
            Layer::Provider,
            "verdict survives the restart"
        );
    }
}
