//! M7b.1 - per-provider connection auto-tuning state.
//!
//! Measured 21 Jul 2026 (BENCHMARKS/PLAN §M7b): asking a provider for more
//! sockets than it wants to grant is 3-4× SLOWER than asking for the knee
//! (connect-flood defense) - connection count is the sharpest single knob
//! in the product, and it punishes the intuitive "more is faster"
//! direction. The daemon probes each provider's ladder while idle
//! (tasks/tuner.rs) and stores the knee here; every job build then
//! caps each server's connections at min(configured, knee).
//!
//! State lives in `conntune.json` NEXT TO the config file (like
//! settings.json), so plain CLI `nzbfast get` runs benefit from the
//! daemon's probes too. The stored knee is the RAW recommendation; the
//! configured per-server `connections` (the account limit) stays the
//! hard cap at application time - a knee above it is surfaced as a
//! suggestion, never applied silently.

use crate::tools::MutexExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Re-probe a provider after this long (knees move with provider policy).
pub const STALE_SECS: u64 = 7 * 86_400;

/// Re-probe a SUSPECT knee after this long instead - soon enough to
/// confirm or clear it within a day, far enough that the second sample
/// sees a different hour (a one-time provider or link issue at probe
/// time shouldn't survive corroboration).
pub const SUSPECT_STALE_SECS: u64 = 6 * 3600;

/// How long a stored knee may go UNREFRESHED before jobs stop capping
/// with it.
///
/// [`STALE_SECS`] is the re-probe appointment, and until 23 Aug 2026 the
/// re-prober was the only thing that read it (tasks/tuner.rs).
/// Nothing consulted it where the knee is APPLIED, so on a box where the
/// idle prober never runs - a plain CLI `nzbfast get`, or a daemon whose
/// queue is never idle - one ladder capped every future job forever.
/// Measured on a bench box that day: a `granted: 32` entry written
/// FIFTEEN days earlier was still capping a leg that asked for 48, and
/// the same account handed out 64 the moment the knee was pinned away
/// with no refusals at all. The account's real grant had moved and
/// nothing in the product could ever notice.
///
/// FOUR missed appointments, written as a multiple of the clock the
/// prober already keeps rather than as a number of its own - it is not a
/// new measurement claim, it is "nobody has re-measured this four times
/// running". A daemon that probes never reaches it, because it refreshes
/// at the first appointment; so this only lifts the cap on the boxes
/// that have no prober, and what it lifts them to is the count the user
/// typed, which is the state every never-probed install already ships
/// in.
///
/// Deliberately NOT one appointment. A daemon that spent a week busy,
/// paused or switched off holds a knee that is merely DUE, not
/// disproven, and dropping a correct cap costs real speed: asking a
/// provider for more sockets than it will grant measured 3-4x SLOWER
/// than asking for the knee (module header). Between one appointment and
/// four the knee still caps, and every surface that shows it says how
/// old it is instead of presenting it as the provider's own verdict.
pub const EXPIRE_SECS: u64 = STALE_SECS * 4;

/// A live-tuner bucket expires after this long unread by fresh
/// evidence (conn-tuning design §4). Expired buckets are ignored for
/// seeding - they fall through to an adjacent bucket, then the ladder
/// knee, then the configured count - but retained for history.
pub const BUCKET_STALE_SECS: u64 = 14 * 86_400;

/// Clean epochs a bucket needs before its target outranks the ladder
/// knee at seed time. Below this the bucket is a hint, not evidence -
/// the seed logic prefers a corroborated knee over a 2-epoch bucket.
pub const BUCKET_MIN_EPOCHS: u64 = 10;

/// Stamped on every entry this build writes.
///
/// v0 = written before the `suspect` guard existed, so a low knee in a
/// v0 entry has never been corroborated by anything - it is one 5 s
/// ladder's opinion, which is exactly the sample that capped James at 6
/// of 18 and held him there. Guards that only run at RECORD time cannot
/// help an install whose bad knee is already on disk: nothing re-reads
/// it until the 7-day stale clock expires. The version lets
/// [`reopen_low_knees`] tell "measured under the old rules" from
/// "measured and corroborated under the new ones" exactly once.
///
/// v1 = measured on the SYNTHETIC PROBE GROUP. The 8 Aug three-layer
/// gap round showed that group undermeasuring a provider 17x (xsnews:
/// 0.20 Gbps on the probe group vs 3.52 on real articles, same minute)
/// because per-group backends differ - a deterministic false low that
/// suspect, corroboration and jagged all wave through, since a re-probe
/// of the same wrong population reproduces it exactly. v2 entries are
/// measured on real-content articles from the install's own downloads
/// (design doc 12.1); every pre-v2 knee is retired for re-measurement
/// by the same one-time sweep.
pub const SCHEMA: u32 = 2;

/// The slowest ladder peak worth believing, in Gbps.
///
/// A ladder every rung of which moved essentially nothing did not
/// measure a knee - it measured a provider that would not serve bodies.
/// `discover_ids` only needs GROUP/OVER, so an account that answers
/// those and then 430s or 502s every BODY, or a link that drops in the
/// seconds after discovery, produces a full set of 0.00 Gbps rungs.
///
/// Recorded, that reads as a knee of 2: the selection is "smallest rung
/// within 90% of the peak", and with a peak of 0.0 the test `gbps >=
/// peak * 0.9` is `0.0 >= 0.0`, which the FIRST rung passes. Worse, the
/// cause is usually structural rather than transient, so the re-probe
/// reproduces it exactly and CORROBORATES it - `suspect` clears and
/// every job on that provider is capped at 2 connections for good.
/// Corroboration defends against a one-time bad sample; it cannot
/// defend against a deterministic one. So: no throughput, no knee.
pub const MIN_LADDER_GBPS: f64 = 0.01;

/// Fraction of the ladder's peak a rung must reach to be worth
/// recommending.
///
/// This was 0.9, on the reasoning that 6% more speed is not worth twice
/// the sockets. That is a sane trade for a machine and the wrong trade
/// for this product: losing a benchmark by 5% is losing it, and the
/// sockets cost the user nothing they can feel. A tester measured 32,
/// 36 and 40 connections at 4m52s, 4m37s and 4m37s on the same file and
/// was auto-tuned to 32 - a real 5% given away by design (4 Aug).
///
/// Not tighter than the measurement, though. 0.98 was tried and is
/// false precision: in the replication harness a provider whose line
/// caps at 4 MB/s reads 0.032 at 4 sockets and 0.033 at 8 - the same
/// speed twice, 3% apart because that is what repeated samples of a
/// network path do - and a 2% bar duly "found" a knee at 8. Tightening
/// past the noise floor does not buy accuracy, it buys tie-breaking by
/// luck, and it does it in the direction of always recommending more
/// sockets than the line can use.
///
/// 5% is the width this can actually defend, and it is only worth
/// having because `conn_ladder` runs a run-off first, re-measuring every
/// rung near the top at double the window - so a 5% gap that survives is
/// far more likely to be real. The 5% a tester lost was not lost here
/// anyway: it was lost by the CLIMB stopping early, which is fixed at
/// its own threshold rather than by pretending to a precision the
/// samples do not have.
pub const LADDER_BAR: f64 = 0.95;

/// How far under the peak a rung has to fall to count as CONTRADICTING
/// the rungs around it.
///
/// Deliberately its own number rather than [`LADDER_BAR`], which it used
/// to share. Those two constants answer different questions - "is this
/// rung fast enough to recommend" and "is this curve physically
/// possible" - and tying them meant tightening the selection quietly
/// disarmed the noise detector: at a 5% bar the field curve
/// (16c 30, 24c 25, 28c 20, 32c 32 MB/s) stopped registering as jagged
/// at all, because 16c no longer cleared the bar, so nothing "crossed it
/// twice". The ladder that started this work would have been read as
/// clean, re-measured never, and recorded as trusted.
///
/// 10% is a shape test, and shapes are not close calls: a rung sitting a
/// tenth below two rungs that bracket it is not a throughput curve.
pub const JAGGED_BAR: f64 = 0.90;

/// The knee a ladder measured.
pub struct Knee {
    /// The count to recommend, clamped to the sockets the provider
    /// actually granted at that rung.
    pub connections: usize,
    /// The rung the knee was read off, BEFORE the granted clamp. Once
    /// clamped the recommendation may match no rung at all, and the UI
    /// still has to know which row to mark.
    pub asked: usize,
    /// The fastest rung - the other half of the comparison the whole
    /// verdict rests on.
    pub peak_at: usize,
    /// Ladder peak (Gbps).
    pub gbps: f64,
    /// The rate curve crossed the bar more than once: a rung BETWEEN
    /// the cheapest one clearing it and the peak read below it. Real
    /// throughput curves do not do that, so this ladder is noise.
    pub jagged: bool,
    /// Rungs to re-measure to settle a jagged ladder (empty otherwise).
    /// See [`merge_samples`].
    pub contested: Vec<usize>,
}

/// Fold a second sample of some rungs back into a ladder.
///
/// The BETTER of the two readings wins, which is not the cowardly
/// choice it looks like. Every mechanism that makes a rung mis-measure
/// on this path pushes the rate DOWN: competing traffic, packet loss, a
/// provider throttling a burst, an article supply that drained before
/// the window closed. Nothing makes a socket count read faster than it
/// can actually go - the one upward artifact, provider-side caching, is
/// already excluded by giving every step distinct articles. So of two
/// disagreeing samples of the same rung, the higher is the one less
/// interfered with, and averaging them just splits the difference with
/// a known-bad measurement.
///
/// It also stops the confirmation pass being theatre. A rung that read
/// 20 against a bar of 28 cannot be rehabilitated by averaging even if
/// it re-reads at a full 31 - the mean is 25.5, still under the bar -
/// so every jagged ladder would stay jagged no matter what the second
/// sample said, and the probes would be spent to change nothing.
///
/// The asymmetry this would otherwise create is handled by which rungs
/// get re-measured, not by the estimator: the peak is in the contested
/// set precisely because the climb's flat re-check already gave it a
/// best-of-two, so every rung in the comparison ends up sampled the
/// same way.
///
/// Bytes SUM: both transfers really happened and the usage ledger is
/// owed all of them. `granted` takes the larger; `saturated` comes from
/// whichever sample won, since it describes that measurement.
pub fn merge_samples(
    steps: &[nzbkit::sysbench::LadderStep],
    extra: &[nzbkit::sysbench::LadderStep],
) -> Vec<nzbkit::sysbench::LadderStep> {
    steps
        .iter()
        .map(|s| {
            let Some(e) = extra.iter().find(|e| e.connections == s.connections) else {
                return s.clone();
            };
            // A non-finite sample carries no information; keep the one
            // that does rather than letting it win a comparison it
            // cannot lose.
            let win_e = e.gbps.is_finite() && (!s.gbps.is_finite() || e.gbps > s.gbps);
            let better = if win_e { e } else { s };
            nzbkit::sysbench::LadderStep {
                connections: s.connections,
                granted: s.granted.max(e.granted),
                gbps: better.gbps,
                bytes: s.bytes.saturating_add(e.bytes),
                saturated: better.saturated,
            }
        })
        .collect()
}

/// Read a ladder's knee.
///
/// `None` when the ladder moved essentially nothing (see
/// [`MIN_LADDER_GBPS`]) - the caller must record NOTHING in that case,
/// leaving the provider untuned rather than capped.
///
/// The finiteness filter is not decoration: a NaN peak fails every `>=`
/// it is given, so a plain comparison would fall through and the rung
/// scan below would then match nothing (or, written the other way
/// round, match rung one) - the same wrong answer this guard exists to
/// stop. An infinite rate is nonsense from a timer that read zero, and
/// belongs on the same side of the door. Non-finite rungs are dropped
/// rather than allowed to set the peak: `total_cmp` sorts NaN ABOVE
/// every real rate, so one garbage sample picked as the peak would
/// throw away a ladder whose other rungs measured fine. Drop them all
/// and an all-NaN ladder still leaves nothing to pick from, which is
/// the `None` this guard wanted.
///
/// Given a peak worth believing, two rules pick the rung:
///
/// 1. The knee is the CHEAPEST rung reaching [`LADDER_BAR`] of the peak.
///    Half the sockets for 94% of the rate is a good trade.
/// 2. But it has to hold that rate all the way UP to the peak rung.
///    Scanning from the bottom and taking the first rung over the bar
///    picks, on a jittery link, a low rung that got one lucky sample -
///    and ignores the refinement probes that already measured the rungs
///    above it BELOW the bar. A measured ladder on a domestic line -
///    16c→30, 24c→25, 28c→20, 32c→32 MB/s - answered 16, while the
///    bisection had just priced 24 and 28 under the bar. Walking DOWN
///    from the peak costs nothing extra and cannot cross a dip.
///
/// Then the pick is clamped to the sockets the provider actually
/// GRANTED at that rung. Asking for more than a provider grants
/// measured 3-4× slower (connect-flood defense), so answering "32" when
/// the account ceiling is 21 would point the user the wrong way down
/// the sharpest knob in the product.
pub fn knee_of(steps: &[nzbkit::sysbench::LadderStep]) -> Option<Knee> {
    let mut v: Vec<&nzbkit::sysbench::LadderStep> =
        steps.iter().filter(|s| s.gbps.is_finite()).collect();
    v.sort_by_key(|s| s.connections);
    let peak_at = (0..v.len()).max_by(|&a, &b| v[a].gbps.total_cmp(&v[b].gbps))?;
    let peak = v[peak_at].gbps;
    if peak < MIN_LADDER_GBPS {
        return None;
    }
    let bar = peak * LADDER_BAR;
    // Walk down from the peak while the rate holds: the lowest rung of
    // that unbroken run is the cheapest one that is genuinely as fast.
    let mut i = peak_at;
    while i > 0 && v[i - 1].gbps >= bar {
        i -= 1;
    }
    // Where a bottom-up scan WOULD have stopped. Lower than where we
    // landed means the curve dipped back under the bar in between.
    // The shape test runs on its OWN bar (see JAGGED_BAR): a curve that
    // dips a tenth below its neighbours is impossible whatever tolerance
    // the recommendation happens to use.
    let jbar = peak * JAGGED_BAR;
    let first_over = v.iter().position(|s| s.gbps >= jbar).unwrap_or(i);
    let jagged = (first_over..=peak_at).any(|k| v[k].gbps < jbar);
    let pick = v[i];
    // `granted + 2 < asked` is the same "the provider is refusing
    // sockets" test the climb and the dashboard's ceiling note use - a
    // socket or two short of the ask is ordinary timing, not a ceiling.
    let connections = if pick.granted > 0 && pick.granted + 2 < pick.connections {
        pick.granted
    } else {
        pick.connections
    };
    Some(Knee {
        connections,
        asked: pick.connections,
        peak_at: v[peak_at].connections,
        gbps: peak,
        jagged,
        contested: if jagged {
            // The rungs whose readings are what make this curve
            // impossible: everything under the bar between the cheap
            // rung that cleared it and the peak, plus the peak itself.
            //
            // The peak is in the list because it SETS the bar, and it
            // is the one rung the climb already sampled twice, keeping
            // the better of the two (the flat re-check) - so it sits
            // high by construction while every other rung is a single
            // sample. Re-measuring it is what makes the comparison
            // fair.
            v[first_over..=peak_at]
                .iter()
                .filter(|s| s.gbps < jbar || s.connections == v[peak_at].connections)
                .map(|s| s.connections)
                .collect()
        } else {
            Vec::new()
        },
    })
}

/// Whether auto connection tuning is enabled in the dashboard settings
/// (settings.json next to the config; absent key = the default, ON).
/// The toggle gates APPLICATION as well as probing: switching it off
/// must lift a stored knee from the very next job, not keep capping
/// with stale state the user has disowned.
///
/// Through the same backup-aware loader every other settings read uses
/// (Codex sweep 2, 3 Aug ML3). A bare `read` + parse treats a torn or
/// half-written settings.json as "no setting", which for this key means
/// the default - ON. The daemon meanwhile loads the .bak and correctly
/// knows the user turned it OFF, so the two authorities disagreed and
/// every new job re-applied stored knees the user had disowned. One
/// loader, one answer.
pub fn enabled(config: &Path) -> bool {
    crate::persist::load_json_with_backup(&config.with_file_name("settings.json"))
        .and_then(|v| v.get("auto_connections").and_then(|v| v.as_bool()))
        .unwrap_or(true)
}

/// One time-of-day bucket of live-tuner evidence (design §4): where
/// the epoch controller settled during real downloads in this window
/// recently, and what one socket was actually delivering then. Four
/// per host, 6 h of LOCAL time each - the coarsest split that
/// separates night from evening peak without starving for samples on
/// a box that downloads a few times a week.
///
/// None of these numbers is a cap. A bucket SEEDS the live controller
/// at job start; the only numbers that cap are typed by the user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bucket {
    /// Bucket index: local hour / 6 (0 = 00-06 ... 3 = 18-24).
    pub b: u8,
    /// The controller's kept connection count last time it ran clean
    /// in this window.
    pub target: usize,
    /// Delivered rate / connected sockets, median over the bucket's
    /// recent clean epochs - the decay reference (design §6). An
    /// envelope observation, not a promise.
    pub per_conn_bps: f64,
    /// Median delivered rate over the same epochs, for the dashboard.
    pub rate_bps: f64,
    /// Clean-epoch evidence weight; see [`BUCKET_MIN_EPOCHS`].
    pub epochs: u64,
    /// Unix time of the last write; 0 or older than
    /// [`BUCKET_STALE_SECS`] means expired-for-seeding.
    pub checked: u64,
    /// The ceiling in force when written - the boot sweep invalidates
    /// any bucket whose target is under half a RAISED ceiling, the
    /// James rule applied to the new store from day one.
    pub limit: usize,
    /// "live" (epoch write-back) | "ladder" | "manual" (a ladder run
    /// refreshing the current bucket's seed).
    #[serde(default)]
    pub source: String,
}

/// The decay flag (design §6): this host's live per-connection rate
/// fell below half of its bucket reference for a sustained, multi-
/// stretch quorum. "Recently fell", not "worse than the best week
/// ever" - a fresh ladder reference clears it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shaped {
    /// Unix time the flag was raised.
    pub since: u64,
    /// The per-connection rate it fell FROM - the recovery bar (80% of
    /// this) and the dashboard's "it managed ~X on <date>" figure.
    pub ref_per_conn_bps: f64,
}

/// A provider's connection cap as this DAEMON SESSION has seen it -
/// the row's window (see [`CapSeen`] for the lifetime one).
///
/// Session, not lifetime, on purpose: a cap Giganews lifts next week
/// must not haunt the Providers row for months. A row that lies is
/// worse than a row that is quiet.
///
/// In memory only. It describes this daemon's run, and the first
/// capacity refusal of the next run rebuilds it within seconds.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Capped {
    /// The most sessions this provider was serving us at the moment it
    /// refused another - the ceiling it actually grants.
    pub granted_hi: usize,
    /// The connection count we were asking for when it refused.
    pub capped_at: usize,
    /// Unix ms of the first refusal this session.
    pub since: u64,
    /// The episode already written to the lifetime ledger, as its
    /// `capped_since` stamp. The watchdog re-reads a STICKY gauge every
    /// tick, so banking on every read turned one Monday refusal on an
    /// idle daemon into a 30-of-30-day support record. Banking an
    /// EPISODE once is the fix (Codex sweep 5, M7).
    pub banked: u64,
}

impl Capped {
    /// Has a fleet that HELD `held` sessions disproven this ceiling?
    ///
    /// The session twin of [`ServerLive::retire_cap_if_exceeded`], and
    /// keyed on the same evidence: sessions we actually GOT. Every idle
    /// provider sits below its ceiling and says nothing either way, so
    /// only a count above it is proof.
    ///
    /// Needed separately because the pool's gauge can only retire a cap
    /// IT recorded - the next job starts with an empty one, so a fleet
    /// that quietly holds 100 after a plan upgrade left the row reading
    /// "using 100 of 38" until the daemon restarted (Codex sweep 6, N4).
    ///
    /// [`ServerLive::retire_cap_if_exceeded`]: nzbkit::pool::ServerLive::retire_cap_if_exceeded
    pub fn disproven_by(&self, held: usize) -> bool {
        self.granted_hi > 0 && held > self.granted_hi
    }
}

/// The LIFETIME cap ledger for one host: "capped on 14 of the last 20
/// days" is evidence for a support ticket, which is a different job
/// from the row's, and it belongs where somebody has gone looking for
/// it rather than on the card everybody sees.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapSeen {
    /// The largest ceiling ever observed - the best this account has
    /// been given.
    pub granted_hi: usize,
    /// The smallest, which is the number a support ticket is about.
    pub granted_lo: usize,
    /// Unix secs first and last observed.
    pub first: u64,
    pub last: u64,
    /// Days on which this host capped us, as whole days since the unix
    /// epoch (UTC - a support window of weeks does not care which side
    /// of local midnight a refusal landed). Ascending, distinct,
    /// trimmed to the most recent [`CAP_DAYS`].
    pub days: Vec<u32>,
    /// The lowest ceiling observed on each of those days, index for
    /// index with `days`.
    ///
    /// `granted_lo` is a LIFETIME low and nothing raises it when old
    /// days drain, so the chip - which filters `days` to the last 30
    /// calendar days - read "capped at 10 today" off a refusal a
    /// hundred days old while today's was 38. A number that old,
    /// presented as today's observation, is the opposite of the
    /// evidence this ledger exists to be (Codex sweep 6, N7).
    ///
    /// `default` so a ledger written before this field existed still
    /// loads; a length that does not match `days` means exactly that,
    /// and those days carry `DAY_LO_UNKNOWN` once the column is
    /// aligned. Handing them the lifetime figure instead would have
    /// re-told exactly the lie above, permanently and in a column that
    /// now claims to be per-day (Codex sweep 7, H1b).
    #[serde(default)]
    pub day_lo: Vec<usize>,
}

/// A day recorded before this ledger kept a per-day figure. Zero is a
/// real observation here - the account was in use elsewhere and we were
/// granted nothing at all - so the unknown has to sit at the other end.
/// Readers show the day and not a number for it.
pub const DAY_LO_UNKNOWN: usize = usize::MAX;

/// How much of the cap ledger is kept. A month is long enough to show a
/// pattern to a provider and short enough that the file cannot grow.
pub const CAP_DAYS: usize = 30;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tuned {
    /// Recommended connection count (smallest reaching ≥90% of the
    /// ladder's peak rate).
    pub connections: usize,
    /// Most sockets the provider actually granted during the probe.
    pub granted: usize,
    /// The rung the knee was read off, BEFORE the granted clamp - the
    /// persisted twin of [`Knee::asked`].
    ///
    /// Stored because `connections` alone cannot be read back: it is
    /// already clamped to the sockets the provider granted at that rung,
    /// so `asked` is the other half of "32 asked, 21 granted" and the
    /// only thing that makes an account-tier ceiling visible after the
    /// fact. It also keeps the line-speed tip honest: comparing granted
    /// against the CONFIGURED count claimed "granted only 16 of the 20
    /// connections asked for" on a ladder that stopped at the knee and
    /// never requested 20 - a statement about the user's account built
    /// from a number nothing ever asked for, made exactly when they are
    /// short of their line speed and looking for a reason to pay for a
    /// higher tier. 0 on an entry written before this field existed,
    /// which reads as "unknown" and says nothing rather than guessing.
    #[serde(default)]
    pub asked: usize,
    /// Peak rate observed on the ladder (Gbps).
    pub gbps: f64,
    /// Unix time of the probe.
    pub checked: u64,
    /// "auto" (idle probe) or "manual" (dashboard ladder run).
    #[serde(default)]
    pub source: String,
    /// The knee would cut the configured connection count substantially
    /// and no earlier probe agrees yet - a single 5 s-per-rung ladder on
    /// a jittery link can fake a knee far below the true one (James: 6
    /// of 18). A suspect knee is NOT applied to jobs and is re-probed on
    /// the short clock; a second probe landing in the same place clears
    /// the flag (and, hours apart, samples a different time of day).
    #[serde(default)]
    pub suspect: bool,
    /// The ceiling in force when this knee was measured: the smaller of
    /// the global connections setting and the server's own configured
    /// count. Stored because the ceiling is an INPUT to the ladder (it
    /// sets how far the rungs climb), so raising it invalidates the
    /// measurement - see [`reopen_low_knees`]. 0 on a v0 entry.
    #[serde(default)]
    pub limit: usize,
    /// Schema version of this entry; see [`SCHEMA`].
    #[serde(default)]
    pub v: u32,
    /// The last measurement that was NOT trusted enough to apply, kept
    /// so the next probe has something to agree with.
    ///
    /// Without it a suspect result had only two possible fates, and both
    /// were wrong: replace the applied knee (which un-applies a working
    /// cap - see [`record`]) or be discarded (in which case a knee that
    /// really HAS moved can never be corroborated, because every future
    /// probe is compared against the stale applied value it disagrees
    /// with). Holding the observation separately lets the cap stay up
    /// while the candidate waits for a second opinion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<usize>,
    /// Live-tuner evidence by time-of-day bucket (design §4). Serde-
    /// defaulted both ways so builds before this field parse files
    /// carrying it and vice versa; the knee half above is untouched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buckets: Vec<Bucket>,
    /// The decay flag; see [`Shaped`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shaped: Option<Shaped>,
    /// The lifetime cap ledger; see [`CapSeen`]. Written only by
    /// [`note_capped`], and only ever off a capacity-classified auth
    /// refusal from this host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capped: Option<CapSeen>,
}

/// The connection ceiling a job would actually hand this server: the
/// global setting and the server's own configured count are both caps,
/// and the tuner has to reason about the smaller one. Judging a knee
/// against the server's number alone called 6 "suspiciously low" on an
/// install whose global setting was 6 - it was simply the ceiling.
/// Connections a job will really open on one server.
///
/// `base` is what the user's own settings allow (the global count capped
/// by this server's own, and by any sidecar borrowing). The knee may
/// only ever lower that, never raise it.
///
/// A PINNED server takes `base` untouched. That is the whole point of
/// the pin and it is checked first, so no future ordering question can
/// put a measurement in front of an instruction: the tuner is a guess
/// about the link, the pin is a statement from the person watching it,
/// and the person wins.
///
/// A SUSPECT knee is not applied either - it is a low reading still
/// waiting for a second probe to agree with it.
///
/// Nor is an EXPIRED one; see [`EXPIRE_SECS`] for why a
/// measurement nothing has refreshed in four re-probe intervals stops
/// counting as one, and why the fallback is the user's own number rather
/// than some decayed fraction of the knee.
pub fn applied_connections(base: usize, pinned: bool, tuned: Option<&Tuned>, now: u64) -> usize {
    if pinned {
        return base;
    }
    match tuned {
        Some(t) if knee_applies(t, now) => base.min(t.connections),
        _ => base,
    }
}

/// What a server would DIAL if the fleet cap took nothing out: its own
/// ceilings ([`applied_connections`]'s `base`) with any applied knee
/// still in them, and only the fleet cap left out.
///
/// This is `PoolConfig::line_cap_uncapped`, and it is a different
/// question from the `uncapped` binding beside its call site even
/// though both are asked of the same ceilings. That one bounds TODO
/// 277's spawn headroom, and [`line_cap_spawn_slots`] takes the knee
/// separately and applies it itself, so pre-knee is right there. This
/// one is a COUNTERFACTUAL, and in the world it describes a stored knee
/// still caps - so answering it pre-knee overstates the fleet by
/// exactly the knee.
///
/// That is not cosmetic. It is the denominator of TODO 312 item 3's
/// whyslow verdict (`serve/whyslow.rs::fleet_bound` gates on
/// `configured > cap`), and with a knee UNDER the cap's share the
/// pre-knee number convicts OUR OWN FLEET CAP of holding back sockets
/// the account was never going to grant: knee 20, share 25, account 40
/// dials 20 either way, so lifting the cap buys nothing at all and the
/// verdict said it would. Measured on a 5 Gbit bench box, 28 Aug 2026;
/// `research/KNEE-UNDER-FLEET-CAP-2026-08-28.md` has the round and why
/// the ORDERING that produces it is nonetheless right.
///
/// `base` is the PRE-CAP ceiling and the arm condition is asked of it
/// too, deliberately: with the fleet cap taking nothing out the pre-cap
/// and post-cap ceilings are equal, so a post-cap `1` that only the
/// cap's share produced must not decide which arm this hypothetical
/// server would have taken. Under live tuning the knee SEEDS rather
/// than caps (`get::fleet`'s `seed_store`), so there the honest answer
/// is the bare ceiling.
pub fn dialable_ceiling(
    base: usize,
    pinned: bool,
    live_tune: bool,
    tuned: Option<&Tuned>,
    now: u64,
) -> usize {
    match live_tune && !pinned && base > 1 {
        true => base,
        false => applied_connections(base, pinned, tuned, now),
    }
}

/// The STALE knee holding this server under its own ceiling, `None`
/// when nothing here is holding it: no measurement on file, one that
/// does not apply, one still inside its re-probe appointment, or one
/// that is not actually lowering anything.
///
/// This is [`nzbkit::pool::PoolConfig::line_cap_knee`]'s producer, and
/// the third question asked of the same ceilings after
/// [`applied_connections`] and [`dialable_ceiling`]. It derives the
/// number this server really dials THROUGH `dialable_ceiling` rather
/// than taking a second one from the caller, so the pin, the
/// live-tune case and the expiry rule are each spelled once - under
/// live tuning the knee SEEDS rather than caps, so there is nothing
/// here to convict, and that falls out of the shared derivation
/// instead of being written a second time and left to drift.
///
/// `base` is the POST-cap ceiling, which is what the caller has by the
/// time it reaches this and is deliberately not what `dialable_ceiling`
/// documents for itself. The two agree here: the only thing that
/// differs between a pre-cap and a post-cap `base` is that function's
/// `base > 1` arm, and a server the fleet cap has already cut to one
/// socket has no knee cost either way. Taking the POST-cap number is
/// the whole of what makes [`nzbkit::pool::linecap::ServerKnee::takes`]
/// a promise the product can keep - with a cap of 35 on an account of
/// 40 and a knee of 32, lifting the knee buys 3 sockets, not 8.
///
/// WHY IT REQUIRES STALENESS, which is the whole of what this predicate
/// decides. A knee inside [`STALE_SECS`] is a measurement the prober
/// stands by, and a verdict convicting it would be reporting a rule
/// mid-stride - the same objection `whyslow.rs`'s `fleet_bound`
/// makes to convicting an automatic cap that is three ticks from
/// raising itself. It also bounds the damage: a fresh knee that binds
/// is auto-tune doing exactly its job, and telling a user their own
/// measurement is holding them back every time it works would train
/// them to switch it off - which is the "advice to make things worse"
/// that verdict's supply gate exists to avoid. Past the appointment
/// nothing re-probes on its own for a `manual` knee, and the live
/// tuner does not own one either, so it caps for as long as it sits
/// there: measured at 19 days on a 5 Gbit bench box, 28 Aug 2026, where
/// rungs of 50, 77 and 100 all ran 32 sockets and landed within
/// 0.4 MB/s of each other
/// (`research/KNEE-UNDER-FLEET-CAP-2026-08-28.md`).
pub fn stale_knee(
    base: usize,
    pinned: bool,
    live_tune: bool,
    tuned: Option<&Tuned>,
    now: u64,
) -> Option<nzbkit::pool::linecap::ServerKnee> {
    let t = tuned?;
    // An entry with no probe time at all cannot be aged, so it cannot
    // be reported with one. A belt rather than a live case: `checked: 0`
    // reads as expired to [`knee_applies`], so `dialable_ceiling` below
    // would decline to apply it anyway.
    let age_secs = age_secs(t, now)?;
    if !is_stale(t, now) {
        return None;
    }
    let takes = base.saturating_sub(dialable_ceiling(base, pinned, live_tune, tuned, now));
    (takes > 0).then_some(nzbkit::pool::linecap::ServerKnee {
        at: t.connections,
        takes,
        age_secs,
    })
}

/// The clause the auto-tune note carries when the KNEE, and not the
/// fleet cap, is what is holding a server down. Empty otherwise, which
/// includes the fleet cap being off (`share` is `None`).
///
/// TODO 275's ladder on a 5 Gbit bench box asked for fleets of 50, 77 and 100,
/// ran 32 every time and landed within 0.4 MB/s of itself, because a
/// 19-day-old knee of 32 sat under every rung. Two lines were printed
/// and neither said so: this note named the knee without mentioning the
/// fleet cap, and `get::fleet`'s "line cap" line prints only when the
/// CAP is what lowers a server, which it was not.
/// `research/KNEE-UNDER-FLEET-CAP-2026-08-28.md` has the round.
///
/// APPENDED to that note and never spliced into it: the bench rig's
/// fleet guard matches `<host> capped at <n> of <N>` positionally for
/// its `autotune=` field, so nothing before this may move.
pub fn knee_under_cap_note(knee: usize, share: Option<usize>, line_cap: usize) -> String {
    match share {
        Some(share) if knee < share => format!(
            "; that is under the {share} the fleet cap of {line_cap} allows this server, so \
             the fleet size is not what is holding it back"
        ),
        _ => String::new(),
    }
}

/// Age of a stored measurement, or `None` when the entry carries no
/// probe time at all.
///
/// `checked: 0` is not "just now". It is an entry no ladder ever
/// timestamped - one [`note_capped`] created for a provider that has
/// never been probed, or a hand-written file. Those carry
/// `connections: 0` and are ignored by every knee consumer anyway, but
/// an untimestamped entry that DID carry a number could not be vouched
/// for as fresh, so the readers below treat unknown as expired rather
/// than as new.
pub fn age_secs(t: &Tuned, now: u64) -> Option<u64> {
    (t.checked > 0).then(|| now.saturating_sub(t.checked))
}

/// Past its re-probe appointment ([`STALE_SECS`]) but still applied.
/// Every surface that shows such a knee says how old it is.
pub fn is_stale(t: &Tuned, now: u64) -> bool {
    age_secs(t, now).is_none_or(|a| a > STALE_SECS)
}

/// Past [`EXPIRE_SECS`]: no longer applied to jobs at all.
pub fn is_expired(t: &Tuned, now: u64) -> bool {
    age_secs(t, now).is_none_or(|a| a > EXPIRE_SECS)
}

/// Whether a stored knee is one a job may cap with: it has a number, it
/// is not still awaiting corroboration, and it has been re-measured
/// recently enough to still be a statement about this provider.
///
/// The dashboard mirrors this predicate in JS (the Providers card and
/// the Settings server row both decide whether to say "auto-tuned"
/// with it), so a term added here has to be added there too or a row
/// announces a cap that no longer exists.
pub fn knee_applies(t: &Tuned, now: u64) -> bool {
    t.connections > 0 && !t.suspect && !is_expired(t, now)
}

/// A stored knee's age, for a log line or a chip.
///
/// Whole days once it is past one, hours below that, and never a bare
/// count of seconds: the question a reader has is "is this number about
/// my provider TODAY", and that is a question about days.
pub fn age_str(age: Option<u64>) -> String {
    match age {
        None => "unknown age".to_string(),
        Some(s) if s < 3_600 => format!("{}m", s / 60),
        Some(s) if s < 86_400 => format!("{}h", s / 3_600),
        Some(s) => format!("{}d", s / 86_400),
    }
}

pub fn effective_limit(global: usize, server_connections: u32) -> usize {
    global.max(1).min((server_connections.max(1)) as usize)
}

/// TODO 208 item 1: the whole fleet's connection budget for the fleet
/// cap (`nzbkit::pool::linecap`), read from `NZBFAST_LINE_CAP`, else
/// from the `line_cap_fleet` setting (TODO 312 item 1), else TODO 277's
/// curve on `anchor_bps` - the best line reading this process has at job
/// build (0 = none, which is the curve's floor and the flat constant
/// that shipped). From either dial `0` (or, from the env var, anything
/// that is not a whole number) = off, which is the bench drivers' A/B
/// arm. Read once per job build, not per epoch, so an arm is one whole
/// leg.
///
/// [`line_cap_resolve`] carries the precedence and why the env var has
/// to win.
///
/// An explicit number is a FIXED fleet at every rate and at every
/// moment of the run - see [`line_cap_auto_resolve`], which is what tells
/// the in-run governor to leave a typed arm alone.
///
/// The UNIT changed with the rule on 23 Aug 2026: this was connections
/// per Mbit of the measured line, so a box still exporting the old
/// `0.5` no longer parses and reads as OFF - the control arm, which is
/// the safe direction, and it shows as an empty `line cap` in the
/// `[pool]` line rather than as a fleet of one. TODO 277 did NOT put
/// that unit back: what moves with the line now is a fleet SIZE off a
/// measured curve with a floor and a ceiling, never a multiplier.
///
/// **TODO 275 item 1 part 2: `carry_bps` is the per-socket carry a
/// previous job MEASURED on this link**, bytes/s, 0 = none, which is
/// exactly the behaviour that shipped. Two candidates and the bigger
/// wins, the same shape `fleet_step` uses in-run: the curve asks what
/// the line needs at the carry it ASSUMES, and `fleet_for_carry` asks
/// what it needs at the carry last MEASURED. Both are monotone, both
/// clamp into the same window, so the max of them is too and no seed
/// can exceed `LINE_CAP_MAX_FLEET`. A TYPED fleet - from either dial -
/// is untouched by it, the same rule [`line_cap_auto_resolve`] states
/// for the governor: somebody who typed a fleet size is asking for that
/// fleet, not for a floor.
///
/// There is deliberately no carry-free spelling of this function. Every
/// caller reports or clamps to the fleet the next build will OPEN, and
/// one left on a carry-free form would promise a smaller fleet than the
/// job opens - which is the defect the dashboard card's own comment
/// already warns about one anchor up.
pub fn line_cap_fleet(config: &Path, anchor_bps: u64, carry_bps: u64) -> usize {
    line_cap_resolve(
        line_cap_env().as_deref(),
        line_cap_setting(config),
        anchor_bps,
        carry_bps,
    )
}

/// TODO 312 item 1: the dashboard's own fleet-cap override
/// (settings.json next to the config; absent key = the automatic
/// curve). `Some(0)` = the rule off, `Some(n)` = a fixed fleet of n.
///
/// Through the same backup-aware loader `enabled` and `read_knobs` use,
/// for the reason written up there: a bare read treats a torn
/// settings.json as "no setting", the daemon meanwhile loads the .bak
/// and knows better, and the two authorities then disagree about the
/// fleet a job dials.
///
/// Read at every job build rather than latched at launch, which is the
/// whole point of the setting existing beside `NZBFAST_LINE_CAP`: the
/// env var needs a daemon restart, and this takes effect on the next
/// download. It does NOT move a job already running - the cap is a seed
/// the pool builds its `LineCap` from, and the in-run governor only
/// ever raises the curve's own number.
///
/// NO CLAMP, deliberately, and it is the same decision `NZBFAST_LINE_CAP`
/// already ships: the number the user types IS the number in force, and
/// a dial whose value silently becomes some other value cannot be
/// reasoned about by the person turning it. TODO 312 item 4 is the
/// question this does not answer - whether the AUTOMATIC ceiling
/// (`LINE_CAP_MAX_FLEET`) should move for everyone - and it stays
/// separate precisely because a number the user typed is their own
/// claim about their own line, where the automatic one is a judgement
/// about what every install spends.
pub fn line_cap_setting(config: &Path) -> Option<usize> {
    crate::persist::load_json_with_backup(&config.with_file_name("settings.json"))
        .and_then(|v| v.get("line_cap_fleet").and_then(|v| v.as_u64()))
        .map(|n| n as usize)
}

/// `NZBFAST_LINE_CAP` as the two resolvers below see it.
fn line_cap_env() -> Option<String> {
    std::env::var("NZBFAST_LINE_CAP").ok()
}

/// The whole precedence rule, PURE so a test can pin it without writing
/// the process environment - the same reason [`line_cap_spawn_slots`] is
/// split out, and the same race it avoids.
///
/// **The env var wins, and that is load-bearing rather than a
/// tie-break.** Every §208-family bench driver exports
/// `NZBFAST_LINE_CAP` per leg to select its A/B arm, and the rig
/// library's own fleet guard reads the value back off the environment
/// to decide whether to warn. A setting that overrode it would silently
/// re-point every round on every bench box that happens to have the
/// dashboard's own number saved, and nothing in a round log would say
/// so.
pub fn line_cap_resolve(
    env: Option<&str>,
    setting: Option<usize>,
    anchor_bps: u64,
    carry_bps: u64,
) -> usize {
    match (env, setting) {
        (Some(v), _) => v.trim().parse::<usize>().unwrap_or(0),
        (None, Some(n)) => n,
        (None, None) => {
            let curve = nzbkit::pool::linecap::fleet_for_line(anchor_bps);
            curve.max(nzbkit::pool::linecap::fleet_for_carry(
                anchor_bps, carry_bps, curve,
            ))
        }
    }
}

/// TODO 277: is the fleet above the curve's own number, so the in-run
/// governor may grow it? False the moment `NZBFAST_LINE_CAP` is set to
/// anything at all, including the `0` that turns the rule off - a leg
/// that typed a fleet size wants that fleet for the whole leg.
///
/// TODO 312 item 1: and false for the SETTING too, for the identical
/// reason. A number typed into the dashboard is a fleet size, not a
/// floor, and a governor that grew it would mean the user could not
/// hold their install at the number they chose.
///
/// Pure, and there is no path-taking wrapper beside it the way
/// [`line_cap_fleet`] wraps [`line_cap_resolve`]: the one production
/// caller (`get::fleet_knobs::line_cap_plan`) needs this answer beside
/// the fleet size and reads the setting once for both, so a wrapper
/// here would only exist to open settings.json a second time.
pub fn line_cap_auto_resolve(env: Option<&str>, setting: Option<usize>) -> bool {
    env.is_none() && setting.is_none()
}

/// TODO 277: the fleet the seed SPAWNS slots for, which is not the
/// fleet it runs at. `line_cap` is the cap in force and `auto` is
/// [`line_cap_auto_resolve`].
///
/// The in-run governor may raise the cap during the run, and a
/// `ConnTarget` above the SPAWNED fleet has nothing to wake
/// (`nzbkit::pool::ConnTarget::set`) - so a curve that starts at its
/// floor could never reach its ceiling, which is what left an
/// anchorless run (a CLI `get`, a sidecar, a daemon's first job) pinned
/// at the floor whatever its line. The seed therefore spawns this many
/// slots and parks the surplus, TODO 112's shape.
///
/// The CEILING and never the raw `--connections` dial: that is 500
/// sockets on a five-provider box, and §208 measured what a fleet that
/// size does to a line. The most the rule will EVER ask for at any rate
/// is the most headroom that can ever be used.
///
/// **TODO 275 item 7: `anchor_measured` is what makes that ceiling two
/// numbers rather than one**, and this is the SEED half of it. The
/// in-run governor may now walk a measured-anchor fleet past
/// `LINE_CAP_MAX_FLEET` to `linecap::supply_ceiling`, and a raise that
/// finds no parked slot buys exactly nothing - the TODO 277 trap this
/// whole function exists for, one ceiling higher. So the headroom
/// follows the ceiling the governor is allowed to reach.
///
/// It is still bounded per server by the account's own grant, in
/// [`line_cap_spawn_slots`], so a wider headroom can never ask a
/// provider for more than it sells; what it costs is parked tokio tasks
/// at ~6.3 KB each, holding no socket, measured 27 Aug 2026 - about
/// 0.3 MB a job across the whole fleet.
///
/// A leg that TYPED a fleet size gets none: it pinned the governor too,
/// so there is no raise to make room for, and spawning past its rung
/// would move the shard layout of every A/B arm on every §208 ladder.
pub fn line_cap_headroom_fleet(line_cap: usize, auto: bool, anchor_measured: bool) -> usize {
    match (auto, anchor_measured) {
        (false, _) => line_cap,
        (true, false) => nzbkit::pool::linecap::LINE_CAP_MAX_FLEET,
        // Not `supply_ceiling`'s grant `min` here, on purpose: that
        // bound is per SERVER and is applied per server, one function
        // down. Handing this a fleet-wide sum would take the headroom
        // off servers that are not the ones with the small account.
        (true, true) => nzbkit::pool::linecap::LINE_CAP_SUPPLY_MAX_FLEET,
    }
}

/// How many worker slots to SPAWN for a server that will RUN at
/// `applied` connections, given its share of
/// [`line_cap_headroom_fleet`] and `uncapped` - what this server's own
/// ceilings (the `--connections` dial, the account's number, a host
/// cap) allow before the fleet cap takes its share out.
///
/// Held to those ceilings AND to the measured knee, since the knee is
/// what the account was seen to refuse above and a slot spawned past it
/// is one the governor could only ever wake into a refusal. Never below
/// what the run already dials.
///
/// Pure, and split out for the reason `disk::storage_override` and
/// `nntp::set_extra_ca` are: the inputs come from `NZBFAST_LINE_CAP`,
/// and a test that wrote the environment to reach this would race every
/// other test in the process.
pub fn line_cap_spawn_slots(
    applied: usize,
    headroom_share: usize,
    uncapped: usize,
    pinned: bool,
    tuned: Option<&Tuned>,
    now: u64,
) -> usize {
    applied_connections(headroom_share.min(uncapped), pinned, tuned, now).max(applied)
}

/// The per-server share of the fleet cap for a fleet of `n_servers`.
/// `None` = nothing to cap with, i.e. the rule is off. Callers `min`
/// this into the server's own ceiling; a pinned server is theirs to
/// skip.
///
/// `anchor_bps` is the line reading the curve sizes from, in bytes/s;
/// 0 = none, which is the floor. The seed binds on every install
/// either way, including a CLI run and a daemon's first job, which used
/// to escape it for want of a link anchor - those two just get the
/// floor, since the floor is what a reading of nothing yields.
///
/// `carry_bps` is TODO 275 item 1 part 2's measured per-socket carry -
/// see [`line_cap_fleet`], which is where the fold and the reason there
/// is only one spelling of it both live.
pub fn line_cap_share(
    config: &Path,
    n_servers: usize,
    anchor_bps: u64,
    carry_bps: u64,
) -> Option<usize> {
    nzbkit::pool::linecap::fleet_cap(line_cap_fleet(config, anchor_bps, carry_bps))
        .map(|f| nzbkit::pool::linecap::server_share(f, n_servers))
}

/// TODO 112: the live epoch controller's dev override. The real gate
/// is the `live_tune` setting (default OFF until the §129 real-line
/// gate passes); this env var force-enables it for rigs and bench
/// legs regardless of settings. Callers OR the two. Independent of
/// `auto_connections` on purpose: that toggle governs the OFFLINE
/// prober; the per-server escape from live tuning is
/// `pin_connections`, exactly as it is for applied knees.
pub fn live_tune_on() -> bool {
    std::env::var("NZBFAST_LIVE_TUNE").is_ok_and(|v| v == "1")
}

/// Whether a freshly measured knee should be withheld from jobs until a
/// second probe agrees with it.
///
/// ONE rule for both paths. It used to live only in the auto probe,
/// while the dashboard's Test button - the one a user actually presses,
/// and the only one that runs while the link is busy with whatever else
/// they are doing - wrote its result as trusted and capped their jobs
/// from the next download. That is backwards: a hand-triggered run is
/// the LESS controlled measurement of the two, because the auto probe at
/// least waits for an idle queue and an idle scan first.
///
/// "The user saw every rung, so it is their call" was the old
/// justification, and it does not survive contact with the screenshots:
/// what a user sees is a verdict sentence and an Apply button, not a
/// judgement about whether 6 of 50 is metrologically sound.
///
/// `prior` is the knee already on file for this host, if any.
pub fn is_suspect(best: usize, ceiling: usize, jagged: bool, prior: Option<&Tuned>) -> bool {
    // A knee that would cut the allowance to less than half, or a ladder
    // whose rungs contradict each other, is unproven until a second
    // probe lands in the same place - hours apart, so it samples a
    // different time of day.
    let unproven = jagged || best.saturating_mul(2) <= ceiling;
    // Through `corroborates`, which knows to compare against a PARKED
    // reading when there is one - inlining the comparison here would
    // quietly re-introduce the frozen-cap bug it exists to avoid.
    unproven && !corroborates(prior, best)
}

pub fn path_for(config: &Path) -> PathBuf {
    config.with_file_name("conntune.json")
}

pub fn load(config: &Path) -> HashMap<String, Tuned> {
    std::fs::read(path_for(config))
        .ok()
        .and_then(|b| serde_json::from_slice::<HashMap<String, Tuned>>(&b).ok())
        .unwrap_or_default()
}

/// Serializes every read-modify-write of conntune.json. The daemon's
/// probe loop, a manual ladder run and a settings edit all live in THIS
/// process: without the lock, two concurrent writers each load the old
/// map and the second write drops the first host's update - and both
/// used the same `.conntune.<pid>.tmp` path, tearing the file. The lock
/// removes the lost update; write_atomic (process-wide temp counter)
/// removes the torn write.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn save(config: &Path, map: &HashMap<String, Tuned>) {
    if let Ok(bytes) = serde_json::to_vec_pretty(map) {
        let _ = crate::persist::write_atomic(&path_for(config), &bytes);
    }
}

/// Does a fresh reading agree with the one already on file?
///
/// Against `pending` when there is one. That is the whole point of
/// parking it: the applied value is precisely the number the pending
/// reading disagreed with, so corroborating against it could only ever
/// fail, and a knee that has genuinely moved would be re-measured and
/// re-rejected forever.
pub fn corroborates(prev: Option<&Tuned>, best: usize) -> bool {
    prev.is_some_and(|p| {
        // A retired entry carries no yardstick at all (the sweep zeroes
        // `connections` precisely so it cannot serve as one), and
        // `max(1)` would otherwise turn that absence into a knee of 1
        // that a 1-connection ladder agrees with.
        let a = p.pending.unwrap_or(p.connections);
        if a == 0 {
            return false;
        }
        let a = a as f64;
        let b = best.max(1) as f64;
        (a - b).abs() <= a.max(b) * 0.25
    })
}

/// Merge one host's probe result in and persist.
pub fn record(config: &Path, host: &str, t: Tuned) {
    record_at(config, host, t, bucket_of(local_hour()));
}

/// [`record`] with the time-of-day bucket made explicit, so tests can
/// pin the refresh without depending on the wall clock.
pub fn record_at(config: &Path, host: &str, t: Tuned, bucket: u8) {
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    let was_shaped = map.get(host).is_some_and(|p| p.shaped.is_some());
    // The MEASUREMENT's own verdict, captured before reconcile: the
    // parking arm deliberately returns `suspect: false` (the applied half
    // stays trusted while the new reading waits in `pending`), so gating
    // the refresh below on the reconciled entry ran it for readings that
    // were just ruled untrusted - overwriting the bucket seed and, on a
    // shaped host, zeroing the decay reference while the flag stayed set,
    // after which the shaping-clear quorum judged recovery against the
    // shaped rate itself.
    let incoming_suspect = t.suspect;
    let mut t = reconcile(map.get(host), t);
    // A trusted ladder result also refreshes the current bucket's SEED
    // (design §4, `source`): a user-run Test must never be ignored by
    // the live layer, which would otherwise keep seeding from a bucket
    // the user has just measured to be wrong. Evidence weight is left
    // alone - a ladder measures a curve, not an epoch stream.
    if !incoming_suspect && !t.suspect && t.connections > 0 {
        let seed = t.connections;
        let (checked, limit) = (t.checked, t.limit);
        let source = if t.source == "manual" {
            "manual"
        } else {
            "ladder"
        };
        let b = bucket_entry(&mut t.buckets, bucket);
        b.target = seed;
        b.checked = checked;
        b.limit = limit;
        b.source = source.to_string();
        // A trusted ladder on a SHAPED host is the confirmation run:
        // besides clearing the flag (reconcile), it retires the old
        // per-connection reference so the live layer re-learns one at
        // the confirmed rate - "the decayed rate, once confirmed,
        // BECOMES the reference" (design §6). Routine ladders on a
        // healthy host leave the reference alone.
        if was_shaped {
            b.per_conn_bps = 0.0;
        }
    }
    map.insert(host.to_string(), t);
    save(config, &map);
}

/// The bucket for `idx`, created empty in place if absent. Keeps the
/// vec sorted by index so the file diffs stay readable.
fn bucket_entry(buckets: &mut Vec<Bucket>, idx: u8) -> &mut Bucket {
    if !buckets.iter().any(|b| b.b == idx) {
        buckets.push(Bucket {
            b: idx,
            ..Default::default()
        });
        buckets.sort_by_key(|b| b.b);
    }
    buckets.iter_mut().find(|b| b.b == idx).unwrap()
}

/// The machine's local hour (0-23); UTC where localtime is not
/// available. Local on purpose: diurnal provider load follows the
/// clock the install's traffic follows (same choice as the
/// scheduler's `local_minute_of_week`).
pub fn local_hour() -> u8 {
    #[cfg(unix)]
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as libc::time_t;
        // SAFETY: `libc::tm` is a plain C struct of integers and a
        // pointer, so an all-zero bit pattern is a valid (if meaningless)
        // value for it - and it is overwritten wholesale below before
        // anything is read out of it.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: localtime_r's contract is that both pointers are valid
        // and non-overlapping for the call. `&t` and `&mut tm` are live
        // locals of exactly the expected types, and the exclusive borrow
        // rules out overlap.
        if !unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
            return tm.tm_hour as u8;
        }
    }
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 86_400
        / 3600) as u8
}

/// Which of the four 6 h buckets a local hour falls in.
pub fn bucket_of(hour: u8) -> u8 {
    (hour / 6).min(3)
}

/// Unexpired, per [`BUCKET_STALE_SECS`].
pub fn bucket_fresh(b: &Bucket, now: u64) -> bool {
    b.checked > 0 && now.saturating_sub(b.checked) < BUCKET_STALE_SECS
}

/// Where the live controller starts for a host (design §5.1): the
/// current bucket's target when it is unexpired and carries real
/// evidence, an adjacent unexpired bucket next (the evening is better
/// predicted by the afternoon than by nothing), then the trusted
/// ladder knee, then the configured count. Always clamped to
/// `configured` - a seed is a starting belief, never a licence to
/// exceed the ceiling the user typed.
pub fn seed_connections(tuned: Option<&Tuned>, bucket: u8, now: u64, configured: usize) -> usize {
    let configured = configured.max(1);
    if let Some(t) = tuned {
        for bi in [bucket, (bucket + 3) % 4, (bucket + 1) % 4] {
            if let Some(b) = t.buckets.iter().find(|b| b.b == bi)
                && bucket_fresh(b, now)
                && b.epochs >= BUCKET_MIN_EPOCHS
                && b.target > 0
            {
                return b.target.clamp(1, configured);
            }
        }
        if t.connections > 0 && !t.suspect {
            return t.connections.clamp(1, configured);
        }
    }
    configured
}

/// One throttled write-back from the live controller's epoch loop
/// (design §5.2): the kept target and this window's clean-epoch
/// medians, folded into the host's bucket under the same LOCK +
/// write_atomic path every other conntune writer uses.
pub struct BucketUpdate {
    pub target: usize,
    pub per_conn_bps: f64,
    pub rate_bps: f64,
    /// Clean epochs observed since the last write-back.
    pub epochs_add: u64,
    pub limit: usize,
    pub now: u64,
}

pub fn update_bucket(config: &Path, host: &str, idx: u8, u: BucketUpdate) {
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    // A host with no ladder entry still learns buckets: the entry's
    // knee half stays zeroed (connections 0 = no knee), which every
    // knee consumer already treats as "nothing recorded".
    let t = map.entry(host.to_string()).or_insert_with(|| Tuned {
        connections: 0,
        granted: 0,
        asked: 0,
        gbps: 0.0,
        checked: 0,
        source: "live".into(),
        suspect: false,
        limit: 0,
        v: SCHEMA,
        pending: None,
        buckets: Vec::new(),
        shaped: None,
        capped: None,
    });
    let b = bucket_entry(&mut t.buckets, idx);
    // Evidence does not accumulate across an expiry gap: a bucket
    // coming back from the dead restarts its count rather than
    // borrowing weight from a fortnight-old regime.
    if !bucket_fresh(b, u.now) {
        b.epochs = 0;
        b.per_conn_bps = 0.0;
    }
    b.target = u.target;
    // The per-connection figure doubles as the decay REFERENCE (design
    // §6), so a median that would itself trip the raise bar must not
    // become the reference: it is evidence FOR the detector, not a new
    // normal. Without this, a long decayed stretch quietly walks the
    // reference down to the live value before the two-stretch quorum
    // can fill, and the flag never raises. Falls above the bar (the
    // 20% dip, a genuine gradual slowdown) still track; the decayed
    // rate becomes the reference only through the confirmation ladder
    // ([`record_at`]) - which is the design's own rule.
    if u.per_conn_bps > 0.0
        && !(b.per_conn_bps > 0.0
            && u.per_conn_bps < b.per_conn_bps * nzbkit::shaping::SHAPE_RAISE_FRAC)
    {
        b.per_conn_bps = u.per_conn_bps;
    }
    if u.rate_bps > 0.0 {
        b.rate_bps = u.rate_bps;
    }
    b.epochs = b.epochs.saturating_add(u.epochs_add);
    b.checked = u.now;
    b.limit = u.limit;
    b.source = "live".into();
    save(config, &map);
}

/// Raise or clear the decay flag (design §6). `reprobe` on a raise
/// zeroes the knee's clock so the idle prober runs ONE confirmation
/// ladder at its next window - the curve answers whether more sockets
/// recover the aggregate or the shaping is per-account. The caller
/// passes `reprobe: false` for block accounts, where an unasked-for
/// ladder would spend the user's own bytes (rule §7.7).
pub fn set_shaped(config: &Path, host: &str, shaped: Option<Shaped>, reprobe: bool) {
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    let Some(t) = map.get_mut(host) else { return };
    if shaped.is_some() && reprobe && t.connections > 0 {
        t.checked = 0;
    }
    t.shaped = shaped;
    save(config, &map);
}

/// Bank one host's observed connection ceiling in the lifetime ledger.
///
/// `granted` is the sessions the provider was serving us when it
/// refused another; `now` is unix seconds. Called only off a
/// CAPACITY-classified refusal - never off `connected < configured`,
/// which is true of every idle provider and would fill this ledger with
/// days nothing was wrong.
///
/// Returns true when the file was written. A no-op when the day is
/// already recorded and the ceiling has not moved, because the caller
/// runs on a 30 s tick for the whole length of a download and a
/// read-modify-write of conntune.json per tick is a disk write per tick
/// for a fact that changes once.
///
/// Creates the host's entry if no ladder has ever run against it: a
/// provider capping us is exactly the kind that never got a clean
/// probe. The synthetic entry carries `connections: 0`, which every
/// consumer of a knee already reads as "nothing measured" - the probe
/// scheduler's verdict for it is identical to the one it gives a host
/// with no entry at all.
pub fn note_capped(config: &Path, host: &str, granted: usize, now: u64) -> bool {
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    let t = map.entry(host.to_string()).or_insert_with(|| Tuned {
        v: SCHEMA,
        ..Default::default()
    });
    let day = (now / 86_400) as u32;
    let c = t.capped.get_or_insert_with(|| CapSeen {
        granted_hi: granted,
        granted_lo: granted,
        first: now,
        ..Default::default()
    });
    let fresh_day = c.days.last() != Some(&day);
    // An older ledger has no per-day column at all. Align it, but mark
    // those days unknown: the lifetime low is not what any of them was
    // granted, and writing it here would preserve that misattribution
    // for as long as the day is retained (Codex sweep 7, H1b).
    if c.day_lo.len() != c.days.len() {
        c.day_lo = vec![DAY_LO_UNKNOWN; c.days.len()];
    }
    // A lower ceiling on a day already recorded still has to land, even
    // when the LIFETIME low does not move - that day's own number is
    // what the windowed chip reads (Codex sweep 6, N7).
    let day_moved = !fresh_day && c.day_lo.last().is_some_and(|&lo| granted < lo);
    let moved = granted > c.granted_hi || granted < c.granted_lo;
    if !fresh_day && !moved && !day_moved {
        return false;
    }
    c.granted_hi = c.granted_hi.max(granted);
    // `min` against a zeroed low would pin every ledger at 0 forever,
    // and 0 is a real observation (the account is in use elsewhere, so
    // we were granted nothing at all) - seed it instead of comparing.
    c.granted_lo = match c.days.is_empty() {
        true => granted,
        false => c.granted_lo.min(granted),
    };
    c.last = now;
    if fresh_day {
        c.days.push(day);
        c.day_lo.push(granted);
        let over = c.days.len().saturating_sub(CAP_DAYS);
        c.days.drain(..over);
        c.day_lo.drain(..over);
    } else if let Some(lo) = c.day_lo.last_mut() {
        *lo = (*lo).min(granted);
    }
    save(config, &map);
    true
}

/// What actually gets stored, given what was already there.
///
/// A SUSPECT measurement must never replace an APPLIED one. Jobs skip
/// suspect entries entirely, so overwriting a corroborated `{8, applied}`
/// with an unproven `{21, suspect}` does not merely change the cap - it
/// removes it, and the provider runs at the full configured count in the
/// over-asking direction the whole feature exists to prevent. That is a
/// worse state than either number, it lasts until two more probes agree,
/// and the UI meanwhile says "nothing has been applied" while something
/// has just been un-applied.
///
/// So the old entry keeps applying and the new reading is parked in
/// `pending`, where the next probe can corroborate it. Two probes still
/// move a knee that has genuinely changed; one noisy evening moves
/// nothing.
///
/// A trusted measurement replaces outright and clears `pending` - it has
/// already been corroborated, and there is nothing left to wait for.
fn reconcile(prev: Option<&Tuned>, new: Tuned) -> Tuned {
    match prev {
        Some(p) if new.suspect && !p.suspect && p.connections > 0 => Tuned {
            // The applied half stays exactly as it was...
            connections: p.connections,
            suspect: false,
            granted: p.granted,
            asked: p.asked,
            limit: p.limit,
            // ...and the new observation is what the clock now runs for.
            pending: Some(new.connections),
            gbps: new.gbps,
            checked: new.checked,
            source: new.source,
            v: SCHEMA,
            // The live half rides along untouched: a ladder verdict on
            // the knee says nothing about the buckets' live evidence.
            buckets: p.buckets.clone(),
            shaped: p.shaped.clone(),
            // A ladder verdict says nothing about the cap ledger
            // either: it is a record of what the PROVIDER refused, and
            // only a refusal may write it.
            capped: p.capped.clone(),
        },
        _ => {
            let mut t = new;
            if let Some(p) = prev {
                // Ladder writers construct entries without the live
                // half; replacing the entry must not wipe what the
                // epoch controller has learned.
                if t.buckets.is_empty() {
                    t.buckets = p.buckets.clone();
                }
                // A TRUSTED ladder is a fresh reference, which clears
                // the decay flag (design §6) - the decayed rate, once
                // confirmed by a ladder, becomes the new normal. A
                // suspect one decided nothing and clears nothing.
                t.shaped = if t.suspect { p.shaped.clone() } else { None };
                // The cap ledger is the provider's record, not the
                // ladder's: a fresh knee neither proves nor disproves
                // that the account was refused connections last week,
                // so it carries across unchanged.
                t.capped = p.capped.clone();
            }
            t
        }
    }
}

/// What a [`reopen_low_knees`] sweep changed, so the caller can log
/// each host with the reason that actually applies to it.
#[derive(Debug, Default, PartialEq)]
pub struct Reopened {
    /// (host, stored knee, new ceiling): the user's raised ceiling
    /// outgrew the knee, so the knee stopped applying and re-measures.
    pub raised: Vec<(String, usize, usize)>,
    /// Hosts whose pre-v2 knee was retired because it was measured on
    /// the synthetic probe group (see [`SCHEMA`]).
    pub retired: Vec<String>,
}

/// Put low knees back up for corroboration, and report which hosts moved.
///
/// A stored knee is a measurement taken under a ceiling - the ladder
/// only climbs as far as the configured count allows - so when the user
/// raises that ceiling the old measurement no longer answers the
/// question they are now asking. Until now nothing re-read the file on
/// that event, and the field report is unambiguous: James set 22, then
/// 24, restarted the app, tried a fresh NZB, and every job still ran at
/// the stored knee of 6 with the dashboard showing a flat `6/6`. The
/// number he typed had no effect and no way to have one.
///
/// So: for each host the user has configured, if the ceiling is now
/// higher than the one the knee was measured under AND the knee is less
/// than half of it, mark the entry `suspect` (jobs stop applying it, so
/// the user's number takes effect from the very next download) and zero
/// `checked` (the idle prober re-measures at its next opportunity, and
/// the corroboration rule decides). A knee that was right comes back
/// within one probe; a knee that was one bad 5 s sample does not.
///
/// v0 entries carry `limit: 0`, so this also sweeps the pre-guard files
/// already sitting on testers' disks the first time a new build runs -
/// which is the only thing that unsticks an install like James's.
/// Every entry seen is stamped to the current [`SCHEMA`], so the sweep
/// is once per entry, not once per call.
///
/// The v2 half: every pre-v2 entry with a recorded knee is RETIRED -
/// marked suspect with `checked: 0` and its parked `pending` cleared
/// (that reading was probe-group data too, and it must not become the
/// corroboration yardstick for the first real-article probe). Jobs stop
/// applying the old knee at once, the prober re-measures on the short
/// clock, and corroboration decides: a knee that was right (the
/// account-level-shaping case, where probe group and real articles
/// agree) comes back in one probe. Unconfigured hosts are left
/// unstamped on purpose, so a server that is re-added later still gets
/// its retirement sweep then.
pub fn reopen_low_knees(config: &Path, limit_for: impl Fn(&str) -> Option<usize>) -> Reopened {
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    let mut out = Reopened::default();
    let mut dirty = false;
    for (host, t) in map.iter_mut() {
        let Some(limit) = limit_for(host) else {
            continue; // not a server this install has configured
        };
        if t.v < 2 && t.connections > 0 {
            t.suspect = true;
            t.checked = 0;
            t.pending = None;
            // The retired knee must not survive as a yardstick either:
            // `corroborates` falls back to `connections` when `pending`
            // is None, so a probe-group number left here would agree
            // with the first low real-article ladder and promote it on
            // the spot - the exact corroboration this retirement exists
            // to withhold. Zero is safe: reconcile's parking arm needs
            // `p.connections > 0`, and jobs already skip suspect
            // entries, so nothing applies it in the meantime.
            t.connections = 0;
            out.retired.push(host.clone());
            dirty = true;
        } else if limit > t.limit && t.connections > 0 && t.connections * 2 <= limit && !t.suspect {
            t.suspect = true;
            t.checked = 0;
            out.raised.push((host.clone(), t.connections, limit));
            dirty = true;
        }
        // Record the ceiling this entry has now been judged against,
        // so the same raise never reopens it twice.
        if t.limit != limit || t.v != SCHEMA {
            t.limit = limit;
            t.v = SCHEMA;
            dirty = true;
        }
        // The same James rule for the live half (design §4 `limit`): a
        // bucket learned under a lower ceiling stops seeding once the
        // user raises it well past the stored target. Invalidated, not
        // deleted - `checked: 0` drops it from seeding (the controller
        // starts from the knee or the configured count and re-learns
        // within one download) while the row stays for history.
        for b in t.buckets.iter_mut() {
            if limit > b.limit && b.target > 0 && b.target * 2 <= limit && b.checked != 0 {
                b.checked = 0;
                b.epochs = 0;
                dirty = true;
            }
            if b.limit != limit {
                b.limit = limit;
                dirty = true;
            }
        }
    }
    if dirty {
        save(config, &map);
    }
    out.retired.sort();
    out.raised.sort();
    out
}

/// [`reopen_low_knees`] for a whole install: reads the server list off
/// disk and judges every stored knee against that server's effective
/// ceiling. Logs what it reopened, because a connection count silently
/// changing under the user is precisely the thing that took a support
/// round-trip to explain last time.
pub fn reopen_for_install(config: &Path, global: usize) {
    let Ok(cfg) = nzbkit::config::Config::load(config) else {
        return;
    };
    let limits: HashMap<&str, usize> = cfg
        .servers
        .iter()
        .map(|s| (s.host.as_str(), effective_limit(global, s.connections)))
        .collect();
    let swept = reopen_low_knees(config, |h| limits.get(h).copied());
    for (host, knee, limit) in swept.raised {
        println!(
            "[tune] {host}: your connection setting is now {limit}, well above the \
             measured {knee} - jobs will use {limit} while that measurement is \
             re-taken"
        );
    }
    for host in swept.retired {
        println!(
            "[tune] {host}: the stored connection measurement was taken on a \
             synthetic article group, which can misread a provider badly - jobs \
             use your configured count while it is re-measured on articles from \
             your own downloads"
        );
    }
}

#[cfg(test)]
#[path = "conntune_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "conntune_fleet_cap_tests.rs"]
mod fleet_cap_tests;
