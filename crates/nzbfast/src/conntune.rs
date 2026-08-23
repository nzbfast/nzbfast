//! M7b.1 - per-provider connection auto-tuning state.
//!
//! Measured 21 Jul 2026 (BENCHMARKS/PLAN §M7b): asking a provider for more
//! sockets than it wants to grant is 3-4× SLOWER than asking for the knee
//! (connect-flood defense) - connection count is the sharpest single knob
//! in the product, and it punishes the intuitive "more is faster"
//! direction. The daemon probes each provider's ladder while idle
//! (serve/tasks/tuner.rs) and stores the knee here; every job build then
//! caps each server's connections at min(configured, knee).
//!
//! State lives in `conntune.json` NEXT TO the config file (like
//! settings.json), so plain CLI `nzbfast get` runs benefit from the
//! daemon's probes too. The stored knee is the RAW recommendation; the
//! configured per-server `connections` (the account limit) stays the
//! hard cap at application time - a knee above it is surfaced as a
//! suggestion, never applied silently.

use crate::MutexExt;
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
pub fn applied_connections(base: usize, pinned: bool, tuned: Option<&Tuned>) -> usize {
    if pinned {
        return base;
    }
    match tuned {
        Some(t) if t.connections > 0 && !t.suspect => base.min(t.connections),
        _ => base,
    }
}

pub fn effective_limit(global: usize, server_connections: u32) -> usize {
    global.max(1).min((server_connections.max(1)) as usize)
}

/// TODO 208 item 1: the whole fleet's connection budget for the fleet
/// cap (`nzbkit::pool::linecap`), read from `NZBFAST_LINE_CAP`. Unset =
/// the measured constant; `0` (or anything that is not a whole number)
/// = off, which is the bench drivers' A/B arm. Read once per job build,
/// not per epoch, so an arm is one whole leg.
///
/// The UNIT changed with the rule on 23 Aug 2026: this was connections
/// per Mbit of the measured line, so a box still exporting the old
/// `0.5` no longer parses and reads as OFF - the control arm, which is
/// the safe direction, and it shows as an empty `line cap` in the
/// `[pool]` line rather than as a fleet of one.
pub fn line_cap_fleet() -> usize {
    match std::env::var("NZBFAST_LINE_CAP") {
        Err(_) => nzbkit::pool::linecap::LINE_CAP_DEFAULT_FLEET,
        Ok(v) => v.trim().parse::<usize>().unwrap_or(0),
    }
}

/// The per-server share of the fleet cap for a fleet of `n_servers`.
/// `None` = nothing to cap with, i.e. the rule is off. Callers `min`
/// this into the server's own ceiling; a pinned server is theirs to
/// skip.
///
/// It takes no line rate: since the cap became a constant the seed
/// binds on every install, including a CLI run and a daemon's first
/// job, which used to escape it for want of a link anchor.
pub fn line_cap_share(n_servers: usize) -> Option<usize> {
    nzbkit::pool::linecap::fleet_cap(line_cap_fleet())
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
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
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
mod tests {
    use super::*;

    fn bucket(b: u8, target: usize, epochs: u64, checked: u64) -> Bucket {
        Bucket {
            b,
            target,
            per_conn_bps: 10e6,
            rate_bps: 100e6,
            epochs,
            checked,
            limit: 24,
            source: "live".into(),
        }
    }

    const NOW: u64 = 1_754_600_000;

    /// The seed order of design §5.1: an evidenced unexpired bucket
    /// outranks the knee, a thin or expired one does not, and with
    /// nothing usable the configured count stands.
    #[test]
    fn seeding_prefers_evidence_in_the_designed_order() {
        // No entry at all: configured.
        assert_eq!(seed_connections(None, 2, NOW, 16), 16);
        // Trusted knee, no buckets: the knee.
        let t = entry(8, false);
        assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 8);
        // A SUSPECT knee is a low reading awaiting corroboration and
        // must not seed - the configured count stands.
        let t = entry(8, true);
        assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 16);
        // An evidenced bucket beats the knee.
        let mut t = entry(8, false);
        t.buckets = vec![bucket(2, 14, 40, NOW - 3600)];
        assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 14);
        // ...but a 2-epoch bucket is a hint, and the knee wins.
        t.buckets = vec![bucket(2, 14, 2, NOW - 3600)];
        assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 8);
        // An expired bucket falls through to an adjacent unexpired one.
        t.buckets = vec![
            bucket(2, 14, 40, NOW - BUCKET_STALE_SECS - 1),
            bucket(1, 11, 40, NOW - 3600),
        ];
        assert_eq!(seed_connections(Some(&t), 2, NOW, 16), 11);
        // The seed never exceeds the ceiling the user typed.
        t.buckets = vec![bucket(2, 14, 40, NOW - 3600)];
        assert_eq!(seed_connections(Some(&t), 2, NOW, 6), 6);
    }

    /// The live half writes back through the same file, accumulates
    /// evidence, and never manufactures a knee: a host that has only
    /// ever been live-tuned must not start capping jobs.
    #[test]
    fn bucket_write_back_learns_without_capping() {
        let dir = std::env::temp_dir().join(format!("nzbfast-buckets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        let upd = |target, epochs_add, now| BucketUpdate {
            target,
            per_conn_bps: 12e6,
            rate_bps: 120e6,
            epochs_add,
            limit: 20,
            now,
        };
        update_bucket(&cfg, "live.example.com", 1, upd(10, 6, NOW));
        update_bucket(&cfg, "live.example.com", 1, upd(12, 6, NOW + 60));
        let m = load(&cfg);
        let t = &m["live.example.com"];
        let b = t.buckets.iter().find(|b| b.b == 1).unwrap();
        assert_eq!(b.target, 12, "latest kept target wins");
        assert_eq!(b.epochs, 12, "evidence accumulates");
        assert_eq!(b.checked, NOW + 60);
        // The knee half stays empty, so nothing here can cap a job.
        assert_eq!(t.connections, 0);
        assert_eq!(applied_connections(20, false, Some(t)), 20);
        // ...and the ceiling sweep has nothing to reopen on it.
        assert_eq!(reopen_low_knees(&cfg, |_| Some(40)), Reopened::default());
        // Evidence does not survive an expiry gap: a bucket coming
        // back after a fortnight restarts its count.
        update_bucket(
            &cfg,
            "live.example.com",
            1,
            upd(9, 3, NOW + 60 + BUCKET_STALE_SECS + 1),
        );
        let m = load(&cfg);
        let b = m["live.example.com"]
            .buckets
            .iter()
            .find(|b| b.b == 1)
            .unwrap();
        assert_eq!(b.epochs, 3, "expired evidence must not carry weight");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A trusted ladder refreshes the current bucket's seed (a user-run
    /// Test must never be ignored by the live layer) and clears the
    /// decay flag (a fresh reference). A parked suspect reading does
    /// neither, and the live half survives every ladder verdict.
    #[test]
    fn a_ladder_refreshes_the_seed_and_clears_the_flag() {
        let dir = std::env::temp_dir().join(format!("nzbfast-refresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        // Live evidence first: an evidenced bucket 14 and a raised flag.
        update_bucket(
            &cfg,
            "h.example.com",
            2,
            BucketUpdate {
                target: 14,
                per_conn_bps: 10e6,
                rate_bps: 100e6,
                epochs_add: 40,
                limit: 24,
                now: NOW,
            },
        );
        set_shaped(
            &cfg,
            "h.example.com",
            Some(Shaped {
                since: NOW,
                ref_per_conn_bps: 140e6,
            }),
            false,
        );
        assert!(load(&cfg)["h.example.com"].shaped.is_some());
        // A SUSPECT ladder result parks and touches neither half.
        let mut sus = entry(4, true);
        sus.checked = NOW + 100;
        record_at(&cfg, "h.example.com", sus, 2);
        let t = &load(&cfg)["h.example.com"];
        assert!(t.shaped.is_some(), "a suspect ladder is not a reference");
        let b = t.buckets.iter().find(|b| b.b == 2).unwrap();
        assert_eq!(b.target, 14, "a suspect ladder must not touch the seed");
        assert_eq!(b.epochs, 40, "live evidence survives");
        // A TRUSTED ladder refreshes the bucket seed and clears shaped.
        let mut ok = entry(9, false);
        ok.checked = NOW + 200;
        ok.source = "manual".into();
        record_at(&cfg, "h.example.com", ok, 2);
        let t = &load(&cfg)["h.example.com"];
        assert!(t.shaped.is_none(), "a trusted ladder is a fresh reference");
        let b = t.buckets.iter().find(|b| b.b == 2).unwrap();
        assert_eq!(b.target, 9, "the user-run Test seeds the live layer");
        assert_eq!(b.source, "manual");
        assert_eq!(b.epochs, 40, "a ladder measures a curve, not epochs");
        assert_eq!(
            b.per_conn_bps, 0.0,
            "a confirmation ladder retires the fallen-from reference"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The decay reference must not erode into the decayed rate it is
    /// supposed to expose: a write-back median that would itself trip
    /// the raise bar is evidence for the detector, not a new normal.
    /// Milder falls (the 20% dip, gradual slowdowns) still track.
    #[test]
    fn a_decayed_median_never_becomes_the_reference() {
        let dir = std::env::temp_dir().join(format!("nzbfast-refkeep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        let upd = |per_conn: f64, now: u64| BucketUpdate {
            target: 12,
            per_conn_bps: per_conn,
            rate_bps: per_conn * 12.0,
            epochs_add: 10,
            limit: 20,
            now,
        };
        update_bucket(&cfg, "h.example.com", 1, upd(100e6, NOW));
        // A decayed stretch writes back a 12% median: frozen out.
        update_bucket(&cfg, "h.example.com", 1, upd(12e6, NOW + 600));
        let per = |cfg: &Path| {
            load(cfg)["h.example.com"]
                .buckets
                .iter()
                .find(|b| b.b == 1)
                .unwrap()
                .per_conn_bps
        };
        assert_eq!(
            per(&cfg),
            100e6,
            "the reference must survive the decay it measures"
        );
        // An 80% median is ordinary weather and tracks.
        update_bucket(&cfg, "h.example.com", 1, upd(80e6, NOW + 1200));
        assert_eq!(per(&cfg), 80e6);
        // Recovery above the old figure tracks freely too.
        update_bucket(&cfg, "h.example.com", 1, upd(110e6, NOW + 1800));
        assert_eq!(per(&cfg), 110e6);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The James rule generalized to the live half: raising the ceiling
    /// well past a stored bucket target invalidates that bucket for
    /// seeding - once, not on every sweep.
    #[test]
    fn a_raised_ceiling_invalidates_low_buckets_once() {
        let dir = std::env::temp_dir().join(format!("nzbfast-bsweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        update_bucket(
            &cfg,
            "h.example.com",
            0,
            BucketUpdate {
                target: 6,
                per_conn_bps: 10e6,
                rate_bps: 60e6,
                epochs_add: 30,
                limit: 12,
                now: NOW,
            },
        );
        reopen_low_knees(&cfg, |_| Some(24));
        let t = &load(&cfg)["h.example.com"];
        let b = t.buckets.iter().find(|b| b.b == 0).unwrap();
        assert_eq!(
            b.checked, 0,
            "a low bucket under a raised ceiling stops seeding"
        );
        assert_eq!(b.epochs, 0);
        assert_eq!(b.limit, 24, "judged against the ceiling now in force");
        assert_eq!(b.target, 6, "retained for history");
        assert_eq!(
            seed_connections(Some(t), 0, NOW, 24),
            24,
            "the invalidated bucket must not seed"
        );
        // Write fresh evidence under the new ceiling: the same ceiling
        // must not invalidate it again.
        update_bucket(
            &cfg,
            "h.example.com",
            0,
            BucketUpdate {
                target: 6,
                per_conn_bps: 10e6,
                rate_bps: 60e6,
                epochs_add: 15,
                limit: 24,
                now: NOW + 60,
            },
        );
        reopen_low_knees(&cfg, |_| Some(24));
        let t = &load(&cfg)["h.example.com"];
        let b = t.buckets.iter().find(|b| b.b == 0).unwrap();
        assert_eq!(b.checked, NOW + 60, "same ceiling, no second sweep");
        assert_eq!(b.epochs, 15);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Files written before the live half existed still parse, and the
    /// new fields stay off the wire while empty (an old build reading a
    /// new file must see the shape it knows).
    #[test]
    fn bucketless_files_round_trip() {
        let t: Tuned = serde_json::from_str(
            r#"{"connections":6,"granted":6,"asked":6,"gbps":0.2,
                "checked":1754000000,"source":"auto"}"#,
        )
        .unwrap();
        assert!(t.buckets.is_empty());
        assert!(t.shaped.is_none());
        let s = serde_json::to_string(&t).unwrap();
        assert!(
            !s.contains("buckets"),
            "empty live half stays off the wire: {s}"
        );
        assert!(!s.contains("shaped"));
    }

    fn entry(n: usize, suspect: bool) -> Tuned {
        Tuned {
            connections: n,
            granted: n,
            asked: n,
            gbps: 1.0,
            checked: 100,
            source: "auto".into(),
            suspect,
            pending: None,
            buckets: Vec::new(),
            shaped: None,
            capped: None,
            limit: 24,
            v: SCHEMA,
        }
    }

    /// M6: a parked reading is an OUTSTANDING QUESTION, and the TTL
    /// picker has to see it. `reconcile` deliberately leaves `suspect`
    /// false on these - the old knee stays in force - so a picker that
    /// only reads `suspect` puts the second opinion on the seven-day
    /// clock and the parked candidate is never resolved.
    #[test]
    fn a_parked_candidate_is_an_open_question() {
        let applied = entry(8, false);
        let held = reconcile(Some(&applied), entry(21, true));
        assert!(!held.suspect, "the cap must stay applied");
        assert_eq!(held.pending, Some(21));
        // What the TTL picker in tasks.rs asks. Both halves matter: this
        // entry is NOT suspect, so `pending` is the only thing that can
        // put it back on the short clock.
        let short = held.suspect || held.pending.is_some();
        assert!(short, "a parked candidate must re-probe on the SHORT clock");
        // …and a settled entry stays on the long one.
        let settled = reconcile(Some(&applied), entry(9, false));
        assert!(
            !(settled.suspect || settled.pending.is_some()),
            "a corroborated knee must not re-probe every six hours"
        );
    }

    /// The regression the jagged term introduced: an unproven reading
    /// must not be able to REMOVE a cap that is currently working.
    ///
    /// Jobs skip suspect entries, so overwriting an applied {8} with a
    /// suspect {21} does not change the cap - it deletes it, and the
    /// provider runs at the full configured count in the over-asking
    /// direction the feature exists to prevent.
    #[test]
    fn a_suspect_reading_never_unapplies_a_working_cap() {
        let applied = entry(8, false);
        let mut noisy = entry(21, true);
        noisy.checked = 999;
        let out = reconcile(Some(&applied), noisy);
        assert_eq!(out.connections, 8, "the working cap must survive");
        assert!(!out.suspect, "and must still be applied");
        assert_eq!(
            out.pending,
            Some(21),
            "the new reading waits for a second opinion"
        );
        assert_eq!(
            out.checked, 999,
            "on the short clock, so it is re-probed soon"
        );
    }

    /// …but a knee that really has moved still gets there, in two
    /// probes. The second reading is compared against the PARKED one,
    /// not against the applied value it disagreed with - otherwise
    /// corroboration could only ever fail and the cap would be frozen
    /// forever.
    #[test]
    fn a_parked_reading_can_still_win_on_the_next_probe() {
        let mut held = entry(8, false);
        held.pending = Some(21);
        assert!(
            corroborates(Some(&held), 21),
            "a repeat of the parked reading agrees"
        );
        assert!(corroborates(Some(&held), 19), "and so does one within 25%");
        assert!(
            !corroborates(Some(&held), 8),
            "the applied value is not the yardstick now"
        );
        // Corroborated, so the caller records it trusted - which replaces
        // outright and clears the parking space.
        let out = reconcile(Some(&held), entry(21, false));
        assert_eq!(out.connections, 21);
        assert!(!out.suspect);
        assert_eq!(out.pending, None, "nothing left to wait for");
    }

    /// With nothing applied yet there is nothing to protect, and a
    /// suspect reading is stored as-is so it can be corroborated.
    #[test]
    fn a_suspect_reading_stands_when_no_cap_is_in_force() {
        let out = reconcile(None, entry(6, true));
        assert_eq!(out.connections, 6);
        assert!(out.suspect);
        // Replacing one suspect entry with another is fine too: neither
        // is applied, so nothing is lost.
        let out = reconcile(Some(&entry(6, true)), entry(9, true));
        assert_eq!(out.connections, 9);
    }

    fn knee(n: usize, suspect: bool) -> Tuned {
        Tuned {
            connections: n,
            granted: n,
            asked: n,
            gbps: 1.0,
            checked: 0,
            source: "auto".into(),
            suspect,
            limit: 50,
            v: SCHEMA,
            pending: None,
            buckets: Vec::new(),
            shaped: None,
            capped: None,
        }
    }

    /// The escape hatch, and the only reason it exists: a knee the user
    /// has measured to be wrong must not be able to touch them.
    #[test]
    fn a_pinned_server_ignores_the_knee() {
        let low = knee(6, false);
        assert_eq!(
            applied_connections(40, false, Some(&low)),
            6,
            "unpinned: capped"
        );
        assert_eq!(
            applied_connections(40, true, Some(&low)),
            40,
            "pinned: the user wins"
        );
    }

    /// Pinning is not a licence to exceed the account: it makes the
    /// user's OWN number authoritative, and that number is already the
    /// global setting capped by this server's limit.
    #[test]
    fn a_pin_does_not_raise_the_ceiling() {
        assert_eq!(applied_connections(8, true, Some(&knee(30, false))), 8);
        assert_eq!(applied_connections(8, true, None), 8);
    }

    /// Unpinned behaviour is untouched, including the suspect rule.
    #[test]
    fn an_unpinned_server_still_obeys_a_trusted_knee_only() {
        assert_eq!(
            applied_connections(40, false, Some(&knee(6, true))),
            40,
            "suspect: not applied"
        );
        assert_eq!(
            applied_connections(40, false, Some(&knee(0, false))),
            40,
            "no knee recorded"
        );
        assert_eq!(applied_connections(40, false, None), 40);
    }

    fn step(connections: usize, gbps: f64) -> nzbkit::sysbench::LadderStep {
        nzbkit::sysbench::LadderStep {
            connections,
            granted: connections,
            gbps,
            bytes: 0,
            saturated: false,
        }
    }

    /// A ladder that moved nothing is NOT a knee of 2.
    ///
    /// `gbps >= peak * 0.9` with a peak of 0.0 is `0.0 >= 0.0`, which the
    /// first rung passes - so an all-zero ladder used to record a knee of
    /// 2 and cap every job on that provider. The auto path called that
    /// `suspect` and waited for a second probe, but the cause (an account
    /// that answers GROUP/OVER and then serves no bodies) is structural,
    /// so the re-probe reproduced it exactly and CORROBORATED it. The
    /// manual path wrote `suspect: false` and applied it immediately.
    #[test]
    fn a_ladder_that_moved_nothing_yields_no_knee() {
        let dead = [step(2, 0.0), step(4, 0.0), step(8, 0.0)];
        assert!(
            knee_of(&dead).is_none(),
            "an all-zero ladder is not a knee of 2"
        );

        // A trickle is the same story: still far below anything a real
        // provider serves, and it would pick rung one just as readily.
        let trickle = [step(2, 0.0001), step(4, 0.0002)];
        assert!(knee_of(&trickle).is_none());

        // An empty ladder has no peak at all.
        assert!(knee_of(&[]).is_none());

        // NaN must not sail through the comparison into rung one.
        assert!(knee_of(&[step(2, f64::NAN), step(4, f64::NAN)]).is_none());
    }

    /// One unusable rung must not throw away the rungs that measured
    /// fine: `total_cmp` ranks NaN above every real rate, so a NaN
    /// allowed to set the peak would discard the whole ladder.
    #[test]
    fn a_single_nan_rung_does_not_discard_the_ladder() {
        let steps = [step(2, 1.0), step(4, 2.0), step(8, 4.0), step(16, f64::NAN)];
        let k = knee_of(&steps).expect("a NaN rung sank a usable ladder");
        assert_eq!(k.connections, 8);
        assert_eq!(k.peak_at, 8);
    }

    /// The real behaviour is untouched: smallest rung within 90% of the
    /// peak, which is the point of the ladder.
    #[test]
    fn a_real_ladder_still_finds_its_knee() {
        let steps = [step(2, 1.0), step(4, 2.0), step(8, 4.0), step(16, 4.1)];
        let k = knee_of(&steps).expect("a real ladder has a knee");
        assert_eq!(k.connections, 8);
        assert_eq!(k.gbps, 4.1);
        assert!(!k.jagged);

        // A flat-from-the-start ladder genuinely knees at its first rung,
        // and that must still be reported - the guard is about zero
        // throughput, not about low connection counts.
        let flat = [step(2, 3.0), step(4, 3.05), step(8, 3.1)];
        let k = knee_of(&flat).expect("a flat ladder still knees at rung one");
        assert_eq!(k.connections, 2);
        assert_eq!(k.gbps, 3.1);
    }

    /// MB/s as the dashboard shows it → a ladder step with its own
    /// granted count.
    fn rung(connections: usize, granted: usize, mbps: f64) -> nzbkit::sysbench::LadderStep {
        nzbkit::sysbench::LadderStep {
            connections,
            granted,
            gbps: mbps * 8.0 / 1000.0,
            bytes: 0,
            saturated: false,
        }
    }

    /// The ladder that started this: 16c read 30 MB/s, then
    /// 24c and 28c read 25 and 20, then 32c - on only 21 granted sockets
    /// - read 32. The bottom-up scan answered 16: it took the first rung
    /// over the bar and never looked at the two refinement probes that
    /// had just priced the rungs above it UNDER the bar.
    #[test]
    fn the_knee_is_not_read_across_a_dip() {
        let steps = [
            rung(2, 2, 7.0),
            rung(4, 4, 13.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(24, 24, 25.0),
            rung(28, 28, 20.0),
            rung(32, 21, 32.0),
        ];
        let k = knee_of(&steps).expect("a ladder this fast has a knee");
        // 30 clears 0.9×32=28.8, but 24c and 28c sit under it - the knee
        // cannot reach down past that dip to claim them.
        assert_eq!(k.asked, 32, "the knee was read across a dip");
        // …and that rung only ever ran on 21 sockets, so 21 is the
        // number. Asking for 32 is the 3-4×-slower direction.
        assert_eq!(k.connections, 21, "the knee was not clamped to granted");
        assert!(k.jagged, "a curve crossing the bar twice is jagged");
    }

    /// The cheap-rung trade still has to work: on a clean curve the knee
    /// is the LOWEST rung within 10% of the peak, not the peak itself.
    #[test]
    fn a_clean_curve_still_knees_at_the_cheapest_fast_rung() {
        let steps = [
            rung(2, 2, 7.0),
            rung(4, 4, 13.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(32, 32, 31.0),
        ];
        let k = knee_of(&steps).expect("a clean ladder has a knee");
        assert_eq!(k.connections, 16);
        assert_eq!(k.peak_at, 32);
        assert!(!k.jagged, "a monotonic curve must not read as jagged");
    }

    /// The contested list is exactly the rungs whose readings make the
    /// curve impossible - the sub-bar dip, plus the peak that sets the
    /// bar and is the one rung the climb already sampled twice keeping
    /// the better. Re-measuring the pick and the peak alone would not
    /// settle anything: what makes this curve jagged is 24c and 28c.
    #[test]
    fn a_jagged_ladder_nominates_the_rungs_that_disagree() {
        let steps = [
            rung(2, 2, 7.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(24, 24, 25.0),
            rung(28, 28, 20.0),
            rung(32, 21, 32.0),
        ];
        let k = knee_of(&steps).expect("a ladder this fast has a knee");
        assert_eq!(k.contested, vec![24, 28, 32]);

        // A clean ladder pays nothing: nothing to re-measure.
        let clean = [rung(2, 2, 7.0), rung(8, 8, 19.0), rung(16, 16, 30.0)];
        assert!(knee_of(&clean).expect("clean ladder").contested.is_empty());
    }

    /// A second sample of the dip settles it. Re-measured free of
    /// whatever was interfering, 24c and 28c clear the bar, the curve
    /// stops contradicting itself, and the cheap rung is honestly the
    /// knee - the answer the single jittery sample only guessed at.
    #[test]
    fn a_settled_dip_hands_back_the_cheap_rung() {
        let steps = [
            rung(2, 2, 7.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(24, 24, 25.0),
            rung(28, 28, 20.0),
            rung(32, 21, 32.0),
        ];
        // The dip was noise: it re-reads in line with its neighbours.
        let extra = [rung(24, 24, 31.0), rung(28, 28, 31.0), rung(32, 21, 31.0)];
        let merged = merge_samples(&steps, &extra);
        let k = knee_of(&merged).expect("a merged ladder still has a knee");
        assert!(
            !k.jagged,
            "the dip was re-measured away but still reads jagged"
        );
        // 24, not the 16 this expected while the bar was 10%. Settled,
        // the curve reads 16c 30, 24c 31, 28c 31, 32c 32 MB/s - and 16c
        // is 6% off the best, which is precisely the gap the tightened
        // bar exists to stop giving away. The cheap rung wins when it is
        // genuinely as fast; this one is not.
        assert_eq!(
            k.connections, 24,
            "a settled curve must yield the cheapest FAST rung"
        );
    }

    /// A dip that reproduces is real, and the knee stays on the safe
    /// side of it rather than reaching down past a rate the line
    /// genuinely does not hold.
    #[test]
    fn a_dip_that_reproduces_keeps_the_conservative_knee() {
        let steps = [
            rung(2, 2, 7.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(24, 24, 25.0),
            rung(28, 28, 20.0),
            rung(32, 21, 32.0),
        ];
        let extra = [rung(24, 24, 24.0), rung(28, 28, 21.0), rung(32, 21, 32.0)];
        let merged = merge_samples(&steps, &extra);
        let k = knee_of(&merged).expect("a merged ladder still has a knee");
        assert!(k.jagged, "a reproducing dip is still a dip");
        assert_eq!(k.connections, 21);
    }

    /// Bytes from BOTH samples are owed to the usage ledger, and the
    /// rate is the less-interfered-with of the two.
    #[test]
    fn merging_takes_the_better_rate_and_sums_the_bytes() {
        let mut a = rung(16, 16, 30.0);
        a.bytes = 1_000;
        let mut b = rung(16, 14, 20.0);
        b.bytes = 700;
        let m = merge_samples(&[a], &[b]);
        assert_eq!(m[0].bytes, 1_700, "the ledger is owed both transfers");
        assert_eq!(m[0].granted, 16);
        assert!(
            (m[0].gbps - 30.0 * 8.0 / 1000.0).abs() < 1e-9,
            "rate is the better sample"
        );

        // A NaN re-read must not win a comparison it cannot lose.
        let m = merge_samples(&[rung(16, 16, 30.0)], &[rung(16, 16, f64::NAN)]);
        assert!((m[0].gbps - 30.0 * 8.0 / 1000.0).abs() < 1e-9);

        // A rung with no second sample is passed through untouched.
        let solo = merge_samples(&[rung(8, 8, 19.0)], &[rung(16, 16, 30.0)]);
        assert_eq!(solo.len(), 1);
        assert_eq!(solo[0].connections, 8);
        assert!((solo[0].gbps - 19.0 * 8.0 / 1000.0).abs() < 1e-9);
    }

    /// Sockets a provider refuses by ones and twos are ordinary timing,
    /// not an account ceiling - don't ratchet the knee down for them.
    #[test]
    fn a_socket_short_of_the_ask_is_not_a_ceiling() {
        let steps = [rung(2, 2, 7.0), rung(8, 8, 19.0), rung(16, 15, 30.0)];
        let k = knee_of(&steps).expect("a real ladder has a knee");
        assert_eq!(k.connections, 16);
    }

    /// The lifetime cap ledger: one row per DAY, the worst ceiling
    /// kept, and no disk write when nothing moved.
    ///
    /// The last part is not tidiness. The caller folds on a watchdog
    /// tick for the whole length of a download, so a ledger that
    /// rewrote itself on every call would be a read-modify-write of
    /// conntune.json a second, forever, for a fact that changes once a
    /// day.
    #[test]
    fn cap_ledger_banks_a_day_at_a_time() {
        let dir = std::env::temp_dir().join(format!("nzbfast-capledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        let day = 20_000u64 * 86_400;
        // First sighting creates the host entry outright: a provider
        // that caps us is exactly the kind no clean ladder ever ran
        // against.
        assert!(note_capped(&cfg, "gn.example.com", 38, day + 3_600));
        // Same day, same ceiling - nothing to say, nothing written.
        assert!(!note_capped(&cfg, "gn.example.com", 38, day + 7_200));
        // A WORSE ceiling the same day is news even though the day is not.
        assert!(note_capped(&cfg, "gn.example.com", 21, day + 9_000));
        assert!(note_capped(&cfg, "gn.example.com", 40, day + 86_400));

        let c = load(&cfg)["gn.example.com"].capped.clone().expect("ledger");
        assert_eq!(
            c.days,
            vec![20_000, 20_001],
            "one row per day, not per call"
        );
        assert_eq!(c.granted_hi, 40);
        // The low is the number a support ticket is about.
        assert_eq!(c.granted_lo, 21);
        assert_eq!(c.first, day + 3_600);
        assert_eq!(c.last, day + 86_400);
        // The knee half stays empty, which every knee consumer already
        // reads as "nothing measured" - the ledger must not fabricate
        // a connection count nothing ever probed.
        assert_eq!(load(&cfg)["gn.example.com"].connections, 0);

        // The window is bounded, oldest dropped.
        for d in 2..40u64 {
            note_capped(&cfg, "gn.example.com", 38, day + d * 86_400);
        }
        let c = load(&cfg)["gn.example.com"].capped.clone().expect("ledger");
        assert_eq!(c.days.len(), CAP_DAYS);
        assert_eq!(*c.days.last().unwrap(), 20_039);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex sweep 6, N7: the chip shows a WINDOW of days, so the
    /// number beside it has to come from the same window.
    ///
    /// `granted_lo` is a lifetime minimum and nothing raises it when old
    /// days drain out of the ledger's 30-event retention, and the
    /// dashboard then filters that list to the last 30 CALENDAR days.
    /// A refusal at 10 a hundred days ago plus one at 38 today therefore
    /// rendered "capped at 10 today" - the oldest number in the file,
    /// presented as this morning's observation, on the one row that
    /// exists to be evidence.
    #[test]
    fn each_capped_day_carries_its_own_low() {
        let dir = std::env::temp_dir().join(format!("nzbfast-capdaylo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        let d0 = 20_000u64;

        // A hundred days ago: refused at 10.
        assert!(note_capped(&cfg, "gn.example.com", 10, d0 * 86_400));
        // Today: refused at 38, then at 30 - the same day's own low
        // moves even though the LIFETIME low (10) does not.
        assert!(note_capped(&cfg, "gn.example.com", 38, (d0 + 100) * 86_400));
        assert!(
            note_capped(&cfg, "gn.example.com", 30, (d0 + 100) * 86_400 + 3_600),
            "a lower ceiling on a day already recorded is still news"
        );

        let c = load(&cfg)["gn.example.com"].capped.clone().expect("ledger");
        assert_eq!(c.days, vec![d0 as u32, d0 as u32 + 100]);
        assert_eq!(
            c.day_lo,
            vec![10, 30],
            "index for index with the days the chip filters"
        );
        assert_eq!(c.granted_lo, 10, "the lifetime figure is unchanged");

        // The two columns stay aligned when the window trims.
        for d in 101..140u64 {
            note_capped(
                &cfg,
                "gn.example.com",
                20 + (d % 5) as usize,
                (d0 + d) * 86_400,
            );
        }
        let c = load(&cfg)["gn.example.com"].capped.clone().expect("ledger");
        assert_eq!(c.days.len(), CAP_DAYS);
        assert_eq!(c.day_lo.len(), c.days.len(), "trimmed in lockstep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A ledger written before the per-day column existed still loads,
    /// and the days already in it are marked unknown rather than given
    /// a number none of them was observed at.
    ///
    /// Codex sweep 7, H1b: backfilling those days with the LIFETIME low
    /// told N7's lie again, in a column that from then on claims to be
    /// per-day - so the invented figure outlived the transitional state
    /// that produced it and was believed by every later reader.
    #[test]
    fn an_older_cap_ledger_gains_the_per_day_column() {
        let dir = std::env::temp_dir().join(format!("nzbfast-capdayold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        let d0 = 20_000u64;
        // Long ago and far lower than anything since: the lifetime low.
        note_capped(&cfg, "h", 10, d0 * 86_400);
        note_capped(&cfg, "h", 22, (d0 + 1) * 86_400);

        // Strip the column, as a ledger from before 1.1.5 has it.
        {
            let mut m = load(&cfg);
            let c = m.get_mut("h").unwrap().capped.as_mut().unwrap();
            c.day_lo.clear();
            save(&cfg, &m);
        }
        assert!(note_capped(&cfg, "h", 38, (d0 + 2) * 86_400));
        let c = load(&cfg)["h"].capped.clone().expect("ledger");
        assert_eq!(
            c.day_lo,
            vec![DAY_LO_UNKNOWN, DAY_LO_UNKNOWN, 38],
            "unknown for what was never recorded, per day from here on"
        );
        assert_eq!(
            c.granted_lo, 10,
            "the lifetime figure is still the lifetime figure"
        );
        assert!(
            !c.day_lo[..2].contains(&c.granted_lo),
            "the lifetime low must not be presented as any day's own observation"
        );

        // A second refusal on a day that is only there as unknown takes
        // the real number: `min` against the sentinel is the observation.
        assert!(note_capped(&cfg, "h", 31, (d0 + 2) * 86_400 + 3_600));
        let c = load(&cfg)["h"].capped.clone().expect("ledger");
        assert_eq!(c.day_lo, vec![DAY_LO_UNKNOWN, DAY_LO_UNKNOWN, 31]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A ladder verdict says nothing about what the provider refused
    /// last week, so it must not erase the ledger on its way past.
    #[test]
    fn a_ladder_result_does_not_wipe_the_cap_ledger() {
        let dir = std::env::temp_dir().join(format!("nzbfast-capkeep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        note_capped(&cfg, "h", 38, 20_000 * 86_400);
        record(
            &cfg,
            "h",
            Tuned {
                connections: 12,
                granted: 12,
                asked: 16,
                gbps: 4.0,
                checked: 9,
                source: "auto".into(),
                limit: 20,
                v: SCHEMA,
                ..Default::default()
            },
        );
        let t = &load(&cfg)["h"];
        assert_eq!(t.connections, 12, "the ladder result landed");
        assert_eq!(
            t.capped.as_ref().map(|c| c.granted_hi),
            Some(38),
            "the ladder wiped a record only a refusal may write"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("nzbfast-conntune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        assert!(load(&cfg).is_empty());
        record(
            &cfg,
            "news.example.com",
            Tuned {
                connections: 12,
                granted: 12,
                asked: 12,
                gbps: 4.9,
                checked: 1,
                source: "auto".into(),
                suspect: false,
                limit: 20,
                v: SCHEMA,
                pending: None,
                buckets: Vec::new(),
                shaped: None,
                capped: None,
            },
        );
        record(
            &cfg,
            "fill.example.com",
            Tuned {
                connections: 4,
                granted: 4,
                asked: 4,
                gbps: 0.8,
                checked: 2,
                source: "manual".into(),
                suspect: true,
                limit: 8,
                v: SCHEMA,
                pending: None,
                buckets: Vec::new(),
                shaped: None,
                capped: None,
            },
        );
        let m = load(&cfg);
        assert_eq!(m.len(), 2);
        assert_eq!(m["news.example.com"].connections, 12);
        assert!(!m["news.example.com"].suspect);
        assert_eq!(m["fill.example.com"].source, "manual");
        assert!(m["fill.example.com"].suspect);
        // No settings.json in the dir: the toggle defaults ON.
        assert!(enabled(&cfg));
        std::fs::write(
            cfg.with_file_name("settings.json"),
            br#"{"auto_connections":false}"#,
        )
        .unwrap();
        assert!(!enabled(&cfg));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The v1.0.14 field case, end to end on the file.
    ///
    /// A pre-guard entry (v0, no `suspect`, no `limit`) holding a knee
    /// of 6 must stop capping the moment the sweep sees it, and must be
    /// queued for a re-probe rather than deleted - if 6 really is this
    /// provider's knee, one probe puts it back. Since SCHEMA 2 the v0
    /// entry retires under the probe-group rule (it was measured there
    /// too), which subsumes the old ceiling-raise reason.
    #[test]
    fn a_raised_ceiling_reopens_a_low_pre_guard_knee() {
        let dir = std::env::temp_dir().join(format!("nzbfast-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        // Exactly the shape v1.0.14 wrote: no `suspect`, no `limit`, no `v`.
        std::fs::write(
            path_for(&cfg),
            br#"{"news.newsdemon.com":{"connections":6,"granted":6,"gbps":0.24,
                 "checked":1754000000,"source":"auto"}}"#,
        )
        .unwrap();
        let before = load(&cfg);
        assert!(!before["news.newsdemon.com"].suspect, "v0 entry applies");
        assert_eq!(before["news.newsdemon.com"].v, 0);

        let moved = reopen_low_knees(&cfg, |_| Some(24));
        assert_eq!(moved.retired, vec!["news.newsdemon.com".to_string()]);
        assert!(moved.raised.is_empty(), "retirement, not a ceiling raise");
        let after = load(&cfg);
        let t = &after["news.newsdemon.com"];
        assert!(t.suspect, "a reopened knee must stop capping jobs");
        assert_eq!(t.checked, 0, "and must be eligible for an immediate probe");
        assert_eq!(t.limit, 24, "judged against the ceiling now in force");
        assert_eq!(t.v, SCHEMA);
        // And the retired number is gone rather than left as the
        // yardstick the next probe would be measured against - see
        // `corroborates`, which falls back to `connections`.
        assert_eq!(t.connections, 0);

        // Idempotent: the same ceiling must not reopen it a second time
        // (a settings save, or every daemon restart, would otherwise
        // re-arm a knee the probe loop had just cleared).
        assert_eq!(reopen_low_knees(&cfg, |_| Some(24)), Reopened::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The SCHEMA 2 sweep, end to end on the file: a v1 entry - healthy
    /// knee, corroborated, applied, exactly what a v1.0.15+ build wrote
    /// after the James fixes - was still measured on the synthetic probe
    /// group, which is known to misread a provider 17x. It must be
    /// retired ONCE: suspect (jobs stop applying it), checked zeroed
    /// (the prober re-measures on the short clock), and BOTH readings
    /// dropped - parked pending and applied knee alike, because
    /// `corroborates` falls back to `connections` when `pending` is
    /// None, so a surviving probe-group number would agree with the
    /// first low real-article ladder and promote it on the spot. The
    /// retirement exists to withhold exactly that agreement.
    #[test]
    fn a_probe_group_knee_is_retired_once_for_real_articles() {
        let dir = std::env::temp_dir().join(format!("nzbfast-retire-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        // The exact shape a v1 build persisted: applied knee, a parked
        // pending reading, judged limit, v:1.
        std::fs::write(
            path_for(&cfg),
            br#"{"reader.xsnews.nl":{"connections":8,"granted":8,"asked":8,
                 "gbps":0.20,"checked":1754600000,"source":"auto",
                 "suspect":false,"limit":24,"v":1,"pending":21},
                "news.eweka.nl":{"connections":20,"granted":20,"asked":20,
                 "gbps":2.2,"checked":1754600000,"source":"manual",
                 "suspect":false,"limit":24,"v":1}}"#,
        )
        .unwrap();

        let moved = reopen_low_knees(&cfg, |_| Some(24));
        assert_eq!(
            moved.retired,
            vec!["news.eweka.nl".to_string(), "reader.xsnews.nl".to_string()],
            "EVERY pre-v2 knee retires, healthy-looking ones included - \
             the 17x error is invisible from the stored numbers"
        );
        assert!(moved.raised.is_empty());
        let after = load(&cfg);
        for host in ["reader.xsnews.nl", "news.eweka.nl"] {
            let t = &after[host];
            assert!(t.suspect, "{host}: jobs must stop applying the old knee");
            assert_eq!(t.checked, 0, "{host}: re-probe on the short clock");
            assert_eq!(t.pending, None, "{host}: probe-group pending cleared");
            assert_eq!(t.v, SCHEMA, "{host}: stamped, so the sweep is one-time");
            assert_eq!(
                t.connections, 0,
                "{host}: the probe-group knee must not stay as a yardstick"
            );
            assert!(
                !corroborates(Some(t), 8),
                "{host}: a retired entry corroborates nothing"
            );
        }

        // One-time means one-time: nothing moves on the next call.
        assert_eq!(reopen_low_knees(&cfg, |_| Some(24)), Reopened::default());

        // A v2 entry the prober has since written back is never touched
        // again, even by a later restart.
        record(&cfg, "reader.xsnews.nl", entry(20, false));
        assert_eq!(reopen_low_knees(&cfg, |_| Some(24)), Reopened::default());
        assert!(!load(&cfg)["reader.xsnews.nl"].suspect);

        // An UNCONFIGURED host is left alone AND unstamped, so a server
        // that is re-added later still gets its retirement then.
        std::fs::write(
            path_for(&cfg),
            br#"{"news.oldfill.com":{"connections":4,"granted":4,"gbps":0.1,
                 "checked":1754600000,"source":"auto","suspect":false,
                 "limit":8,"v":1}}"#,
        )
        .unwrap();
        assert_eq!(reopen_low_knees(&cfg, |_| None), Reopened::default());
        assert_eq!(load(&cfg)["news.oldfill.com"].v, 1, "unstamped while gone");
        let back = reopen_low_knees(&cfg, |_| Some(8));
        assert_eq!(back.retired, vec!["news.oldfill.com".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The retirement has to survive the very next ladder: a retired
    /// entry is not evidence, so a real-article knee that happens to
    /// land on the same low number as the retired probe-group one is
    /// still the FIRST reading and must be parked for a second opinion.
    /// While `connections` survived the sweep, `corroborates` compared
    /// against it (its fallback when `pending` is None) and promoted
    /// that first reading immediately - the 17x probe-group error
    /// laundering itself into a trusted knee in one step.
    #[test]
    fn a_retired_entry_does_not_corroborate_the_next_low_ladder() {
        let dir = std::env::temp_dir().join(format!("nzbfast-retire-corr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        std::fs::write(
            path_for(&cfg),
            br#"{"news.eweka.nl":{"connections":6,"granted":6,"asked":6,
                 "gbps":0.2,"checked":1754600000,"source":"auto",
                 "suspect":false,"limit":24,"v":1}}"#,
        )
        .unwrap();
        assert_eq!(
            reopen_low_knees(&cfg, |_| Some(24)).retired,
            vec!["news.eweka.nl".to_string()]
        );

        let retired = load(&cfg);
        let prior = retired.get("news.eweka.nl");
        assert!(
            !corroborates(prior, 6),
            "the retired number must not agree with a knee that matches it"
        );
        // ...so the ladder result is unproven and parks, exactly as it
        // would on a host with no history at all.
        assert!(is_suspect(6, 24, false, prior));

        let mut fresh = entry(6, true);
        fresh.checked = 1754700000;
        record(&cfg, "news.eweka.nl", fresh);
        let after = &load(&cfg)["news.eweka.nl"];
        assert!(
            after.suspect,
            "the first real-article reading must wait for a second one, \
             and stays out of jobs until it lands"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Knees the user's ceiling has NOT outgrown are left alone: a knee
    /// at or near the ceiling is the tuner agreeing with the user, and a
    /// host that isn't a configured server is none of this code's
    /// business.
    #[test]
    fn reopen_leaves_settled_knees_alone() {
        let dir = std::env::temp_dir().join(format!("nzbfast-reopen2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        let mk = |c: usize, limit: usize| Tuned {
            connections: c,
            granted: c,
            asked: c,
            gbps: 1.0,
            checked: 9,
            source: "auto".into(),
            suspect: false,
            limit,
            v: SCHEMA,
            pending: None,
            buckets: Vec::new(),
            shaped: None,
            capped: None,
        };
        record(&cfg, "near.example.com", mk(20, 24)); // 20 of 24: agrees
        record(&cfg, "low.example.com", mk(6, 24)); // already judged at 24
        record(&cfg, "gone.example.com", mk(2, 24)); // no longer configured
        let moved = reopen_low_knees(&cfg, |h| (h != "gone.example.com").then_some(24));
        assert_eq!(moved, Reopened::default(), "nothing should have moved");
        let m = load(&cfg);
        assert!(m.values().all(|t| !t.suspect));
        assert_eq!(m["gone.example.com"].checked, 9);

        // But raise the ceiling past the one they were judged at and the
        // low knee - and only the low knee - reopens: 20 of 26 is still
        // the tuner agreeing with the user, 6 of 26 is not.
        let moved = reopen_low_knees(&cfg, |h| (h != "gone.example.com").then_some(26));
        assert_eq!(moved.raised, vec![("low.example.com".into(), 6, 26)]);
        assert!(moved.retired.is_empty(), "v2 entries never retire");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
