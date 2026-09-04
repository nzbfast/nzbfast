//! Pre-flight availability check (design: M2): pipelined STAT sweeps build
//! a per-article × per-server availability matrix before any body bytes
//! are spent. STAT is ~50 bytes per article per server; with deep
//! pipelining thousands of articles check in a couple of seconds.
//!
//! The verdict is advisory (the live ledger during download remains
//! authoritative) but it lets an impossible NZB abort in seconds having
//! downloaded nothing.
//!
//! **A clean sweep is not a clean post, and never treat it as one.**
//! STAT answers exactly one question - does the server hold something
//! under this message-id - and a small number of providers implement a
//! takedown by REPLACING the article with a dummy body rather than
//! deleting it. STAT still answers 223, the matrix fills with
//! [`Avail::Have`], and the fake is only caught later, at the body's
//! own yEnc CRC. So every verdict built on this sweep has a FALSE
//! GREEN mode on a post that is gone, and no amount of extra STATs
//! closes it. This is the trap that makes SABnzbd's pre-check
//! unreliable against takedowns (their forum threads t=11214 and
//! t=16658); it is documented here so nobody re-derives a "the sweep
//! said it was fine" shortcut. The real download is the backstop, not
//! this: a body that fails its CRC is corrupt-class evidence there
//! (`Work::tried_fail`), steered to another server once and otherwise
//! left to PAR2 repair. Corrupt-class evidence is deliberately kept
//! out of the refusal machinery - it never opens the TODO 146 tail
//! give-up - so widening it here would be the same conflation one
//! layer up.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use crate::config::ServerConfig;
use crate::nntp::Connection;
use crate::par2::Par2Set;

/// Availability of one article on one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Avail {
    Unknown,
    Have,
    Missing,
}

const UNKNOWN: u8 = 0;
const HAVE: u8 = 1;
const MISSING: u8 = 2;

/// What a sweep is allowed to skip, and when it may stop.
///
/// The default is the exhaustive matrix every caller got before these
/// existed: ask every server about every id, and stop only when the last
/// one answers. `check`'s human report needs that, because its
/// per-server "% available" line is a claim about each server
/// individually. The daemon does not - it consumes `Impossible` and
/// discards every other verdict - so it takes the two shortcuts below.
#[derive(Debug, Clone)]
pub struct SweepPlan {
    /// Per server.
    pub connections: usize,
    /// Pipelined STAT depth.
    pub window: usize,
    /// Once ANY server answers `Have` for an article, stop asking the
    /// others about it.
    ///
    /// Free by [`SweepResult::union_missing`]'s own rule: an article
    /// counts as missing only when EVERY server says `Missing`, so one
    /// `Have` settles it permanently and no later answer can move it.
    /// The skipped cells stay `Unknown`, which is the value that already
    /// means "not evidence of absence" - so this can never manufacture a
    /// missing article, only decline to re-confirm a present one.
    ///
    /// It is off by default because it guts `server_counts`: a server
    /// that skipped 90% of the sample is not 10% available, it was
    /// asked 10% of the questions.
    pub settle_on_have: bool,
    /// Stop the whole sweep once articles missing on every server
    /// outweigh the recovery budget. See [`AbortBudget`].
    pub abort_over: Option<AbortBudget>,
}

/// The deficit at which a sweep's verdict is already decided.
///
/// Pre-flight exists to abort an impossible job in seconds. Once the
/// payload confirmed missing on EVERY server outweighs what the
/// recovery volumes could hold, no further STAT can change the answer:
/// the deficit only grows. Every query after that point is spent
/// refining a number nobody reads - and on a miss-heavy post those are
/// the expensive queries, 0.4-2.2 s each.
///
/// An abort can never manufacture a verdict, only stop paying for one:
/// the caller recomputes the verdict from the finished matrix either
/// way, and a truncated sweep has strictly FEWER articles proved missing
/// everywhere. So the failure mode of firing too eagerly is a softer
/// answer reached on less evidence, never a false `Impossible`.
#[derive(Debug, Clone)]
pub struct AbortBudget {
    /// How much each sampled id adds to the deficit, in whatever unit
    /// [`AbortRule`] compares. Ids whose loss does not decide the
    /// verdict (Usenet furniture, and the recovery volumes themselves)
    /// carry `0.0`, so they can never trip the abort.
    pub weights: Vec<f64>,
    /// What the accumulated deficit is weighed against.
    pub rule: AbortRule,
}

/// How sharply the caller can state the budget the sweep is racing.
///
/// Both variants weigh payload BYTES, because that is the only unit a
/// pre-flight verdict is reached in: an article is not a block and never
/// was, and the comparison that pretended otherwise - missing ARTICLES
/// against slice counts read off volume filenames - was deleted from
/// `check::verdict_of` on 16 Aug for over-claiming damage on every post
/// whose blocks are larger than its articles. An abort armed in that
/// unit stands the sweep down at a point unrelated to the answer, so
/// this enum never offers it.
///
/// What the two variants differ in is whether the set's block size is in
/// hand. With it, the deficit can be floored into blocks per volume, the
/// sharpest form. Without it, the same rule divided through by the block
/// size very nearly cancels - `floor(margined / bs) > sum(floor(V_i /
/// bs))` becomes `margined > sum(V_i)` - and that costs no probe at all.
#[derive(Debug, Clone)]
pub enum AbortRule {
    /// Weights are payload BYTES, weighed against the recovery volumes'
    /// own encoded bytes. No block size, no probe, no network.
    ///
    /// The block-size-free shape of [`Self::Blocks`], and deliberately
    /// the SAME comparison as `check::block_size_could_condemn`: a sweep
    /// that stands down on this rule leaves a deficit that still
    /// satisfies the gate in front of the block-size probe, so standing
    /// down cannot cost the post its measured verdict. The residue
    /// against the real rule is the per-volume flooring, at most one
    /// block per volume, and it runs the safe way - see that function.
    Bytes {
        /// How much of the sampled deficit to lean on. Applied exactly
        /// as the final verdict applies it.
        margin: f64,
        ceiling_bytes: u64,
    },
    /// Weights are payload BYTES; the deficit becomes blocks the same
    /// way the measured verdict makes it - margined, converted from
    /// encoded bytes to raw ones ([`crate::par2::min_raw_bytes`]), then
    /// floored over the set's block size - and is weighed against a
    /// ceiling in blocks.
    ///
    /// `ceiling` must be one no later sweep result can raise: the caller
    /// sums every recovery volume the NZB carries with none struck off,
    /// because striking a volume off needs a sweep that has not happened
    /// yet and can only make the final ceiling SMALLER. A deficit that
    /// clears this one clears that one.
    Blocks {
        block_size: u64,
        /// How much of the sampled deficit to lean on, since it came off
        /// a stratified sample and has error in both directions. Applied
        /// here exactly as the final verdict applies it.
        margin: f64,
        /// u64, like every other block count: `usize` is 32 bits on the
        /// shipped armv7 build and a count that wraps is a false verdict
        /// on the side that stops a download (see `max_recovery_blocks`).
        ceiling: u64,
    },
}

impl AbortRule {
    /// Is a deficit of `total` (in this rule's own units) already past
    /// the point where more STATs cannot change the answer?
    fn decided(&self, total: f64) -> bool {
        match *self {
            AbortRule::Bytes {
                margin,
                ceiling_bytes,
            } => {
                // Floored to whole bytes before the margin, for the same
                // reason the block rule does it in that order: the gate
                // this mirrors computes it that way, and the two must
                // not disagree about a boundary case.
                //
                // ...and converted encoded -> raw after it, for the same
                // reason again. `check::block_size_could_condemn` takes
                // its deficit from `margined_deficit_raw_bytes`, which
                // applies `min_raw_bytes`, while leaving the volumes at
                // their full encoded size. Skipping the conversion here
                // made this rule's deficit the yEnc overhead LARGER than
                // the gate's, so the sweep could stand down at a point
                // the gate would not have condemned from - which is
                // exactly what the doc above promises cannot happen.
                let bytes =
                    crate::par2::min_raw_bytes((total.max(0.0) as u64 as f64 * margin) as u64);
                bytes > ceiling_bytes
            }
            AbortRule::Blocks {
                block_size,
                margin,
                ceiling,
            } => {
                // Floored to whole bytes before the margin, and
                // converted from the NZB's yEnc-ENCODED bytes to raw
                // ones after it, because that is the order the measured
                // verdict does it in and the two must not disagree
                // about a boundary case. The conversion is what keeps
                // this comparable to `block_size` at all: the weights
                // are encoded sizes and a PAR2 block size is raw.
                let bytes =
                    crate::par2::min_raw_bytes((total.max(0.0) as u64 as f64 * margin) as u64);
                crate::par2::min_damaged_blocks(bytes, block_size) > ceiling
            }
        }
    }
}

impl SweepPlan {
    /// The exhaustive sweep: every server asked about every id.
    pub fn full(connections: usize, window: usize) -> Self {
        SweepPlan {
            connections,
            window,
            settle_on_have: false,
            abort_over: None,
        }
    }
}

/// How far ahead a settling leg may commit, in time rather than count.
///
/// With `settle_on_have` everything already on the wire is committed: a
/// settle landing a microsecond later cannot recall it. A flat window of
/// 50 on the slowest live provider is 50 x 2.2 s of unrecallable waste,
/// which would eat most of what the skip just saved. So a settling leg
/// holds only as many queries as it has actually DRAINED in this much
/// time - measured, not predicted.
///
/// Measuring the drain rather than the latency is the point, and it took
/// three tries to learn why. A leg's first reply can arrive in 20 ms on
/// a server whose every later reply costs 265 ms, so any estimator fed
/// single reply gaps - a mean, or a decaying peak - reads that one
/// sample as "fast", lifts the cap to 50, and commits 50 queries that
/// then cost 13 s. Counting replies inside a window cannot be fooled
/// that way: to hold 50 in flight a leg must have genuinely delivered 50
/// in the last two seconds. It is self-limiting, so it needs no ramp.
const DRAIN_BUDGET: Duration = Duration::from_secs(2);

/// The floor under the drain cap: a leg that has drained nothing yet
/// still has to send something, or it would never start.
const SETTLE_START_WINDOW: usize = 4;

/// Why one leg of a sweep stopped.
///
/// Preflight's wall time is the SLOWEST leg's, never the mean, so the
/// only useful question about a 120 s sweep is which leg was still
/// running at 120 s and what it was waiting for. A leg that dies early
/// costs nothing but leaves `Unknown` cells; a leg that grinds to the
/// end costs everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegOutcome {
    /// Every assigned id answered.
    Done,
    /// `Connection::connect` failed - no cell on this leg was ever set.
    DialFailed,
    /// The socket refused a STAT write.
    SendFailed,
    /// The peer closed or spoke nonsense mid-sweep.
    ReadFailed,
    /// No reply inside the per-read timeout.
    ReadTimeout,
    /// Another leg proved the verdict while this one was working, so it
    /// stood down with ids unasked (see [`AbortBudget`]).
    Stopped,
}

/// One connection's leg of a sweep, timed.
///
/// `gaps_us` is the inter-arrival series in reply order: with a window
/// of 50 outstanding commands a healthy server answers in a burst of
/// near-zero gaps, so a flat 250 ms series is the signature of a peer
/// serialising STATs regardless of how deeply we pipeline. Distinguishing
/// those two is the whole reason this record exists - the aggregate
/// "ms per STAT" cannot.
#[derive(Debug, Clone)]
pub struct LegStats {
    pub server: usize,
    pub conn: usize,
    /// Ids this leg owns (its stride of the sample).
    pub assigned: usize,
    pub sent: usize,
    pub recv: usize,
    /// Ids this leg never asked about because another server had already
    /// answered `Have` for them.
    pub skipped: usize,
    /// Dial, TLS handshake, greeting and AUTHINFO.
    pub connect: Duration,
    /// Post-connect wait for the FIRST reply - the cost of one round
    /// trip plus whatever queueing the peer does before it starts.
    pub first_reply: Option<Duration>,
    /// The whole leg, connect included. The slowest of these is the sweep.
    pub total: Duration,
    pub outcome: LegOutcome,
    /// Inter-reply gaps in microseconds, in arrival order (the first
    /// entry is `first_reply`).
    pub gaps_us: Vec<u32>,
    /// The same gaps split by what the reply SAID. A miss costs a
    /// backend a negative lookup - it has to prove absence, where a hit
    /// is one index probe - so on most providers these two are different
    /// distributions by an order of magnitude, and a single median over
    /// both just reports the post's miss ratio. Preflight's whole cost
    /// model turns on which of the two it is paying for.
    pub hit_us: Vec<u32>,
    pub miss_us: Vec<u32>,
}

impl LegStats {
    fn new(server: usize, conn: usize, assigned: usize) -> Self {
        LegStats {
            server,
            conn,
            assigned,
            sent: 0,
            recv: 0,
            skipped: 0,
            connect: Duration::ZERO,
            first_reply: None,
            total: Duration::ZERO,
            outcome: LegOutcome::Done,
            gaps_us: Vec::new(),
            hit_us: Vec::new(),
            miss_us: Vec::new(),
        }
    }

    /// Nearest-rank percentile of the inter-reply gaps, in milliseconds.
    /// `p` is 0..=100. Zero replies has no distribution: `0.0`.
    pub fn gap_pct_ms(&self, p: u8) -> f64 {
        Self::pct_ms(&self.gaps_us, p)
    }

    /// The same percentile over hit replies only, then miss replies only.
    pub fn hit_pct_ms(&self, p: u8) -> f64 {
        Self::pct_ms(&self.hit_us, p)
    }

    pub fn miss_pct_ms(&self, p: u8) -> f64 {
        Self::pct_ms(&self.miss_us, p)
    }

    fn pct_ms(series: &[u32], p: u8) -> f64 {
        if series.is_empty() {
            return 0.0;
        }
        let mut v = series.to_vec();
        v.sort_unstable();
        let rank = ((p.min(100) as usize * v.len()).div_ceil(100)).clamp(1, v.len());
        v[rank - 1] as f64 / 1000.0
    }

    /// Replies per second over the STAT phase (connect excluded).
    pub fn stats_per_sec(&self) -> f64 {
        let secs = self.total.saturating_sub(self.connect).as_secs_f64();
        if secs <= 0.0 {
            0.0
        } else {
            self.recv as f64 / secs
        }
    }
}

/// Per-server result of a sweep: `matrix[server][article]`.
pub struct SweepResult {
    pub(crate) matrix: Vec<Vec<Avail>>,
    pub elapsed: Duration,
    /// One entry per (server, connection), in spawn order.
    pub legs: Vec<LegStats>,
    /// The sweep stood down early: the deficit had already cleared the
    /// recovery budget, so the verdict was `Impossible` whatever the
    /// unasked ids would have said. The matrix is DELIBERATELY partial.
    pub stopped_early: bool,
}

impl SweepResult {
    /// Articles unavailable on every server that answered. An `Unknown`
    /// (sweep error) counts as available - pre-flight must not produce
    /// false IMPOSSIBLE verdicts.
    ///
    /// The bias runs one way on purpose, and the cost is the false
    /// GREEN in the module doc: an empty result means nothing the
    /// sweep asked about was refused everywhere, NOT that the post is
    /// intact. A takedown served as dummy bodies answers 223 and
    /// leaves this empty.
    pub fn union_missing(&self) -> Vec<usize> {
        let n = self.matrix.first().map_or(0, |m| m.len());
        (0..n)
            .filter(|&i| {
                self.matrix.iter().all(|m| m[i] == Avail::Missing) && !self.matrix.is_empty()
            })
            .collect()
    }

    /// (have, missing, unknown) counts for one server.
    pub fn server_counts(&self, s: usize) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for a in &self.matrix[s] {
            match a {
                Avail::Have => c.0 += 1,
                Avail::Missing => c.1 += 1,
                Avail::Unknown => c.2 += 1,
            }
        }
        c
    }
}

/// STAT every id on every server. `connections` are per server; `window`
/// is the pipelined STAT depth (responses are single lines, so a deep
/// window is safe and fast).
pub async fn stat_sweep(
    servers: &[ServerConfig],
    ids: &[String],
    connections: usize,
    window: usize,
) -> SweepResult {
    stat_sweep_with(servers, ids, &SweepPlan::full(connections, window)).await
}

/// [`stat_sweep`] with the skips and the stop condition spelled out.
pub async fn stat_sweep_with(
    servers: &[ServerConfig],
    ids: &[String],
    plan: &SweepPlan,
) -> SweepResult {
    let t0 = std::time::Instant::now();
    // A zero here is not a configuration, it is a hang - the same reason
    // pool.rs clamps its own window and connection counts in the library
    // rather than at each CLI call site. `check --window 0` made the send
    // loop's `sent - recv < window` guard false on the first iteration:
    // not one STAT went out, every worker then blocked on a reply that
    // could never come until the 20 s timeout, every cell stayed Unknown,
    // and `union_missing` (which needs Missing on EVERY server) counted
    // none of them - so a fully unavailable NZB was reported "COMPLETE -
    // every sampled article present".
    let window = plan.window.max(1);
    let nconn = plan.connections.max(1);
    let ids: Arc<Vec<String>> = Arc::new(ids.to_vec());
    // Every leg reads every server's column, not just its own: an
    // article joins the deficit on the LAST server to call it missing,
    // and only a leg holding all the columns can see that happen.
    let cells: Arc<Vec<Arc<Vec<AtomicU8>>>> = Arc::new(
        servers
            .iter()
            .map(|_| Arc::new((0..ids.len()).map(|_| AtomicU8::new(UNKNOWN)).collect()))
            .collect(),
    );
    let settled: Arc<Vec<AtomicBool>> =
        Arc::new((0..ids.len()).map(|_| AtomicBool::new(false)).collect());
    // One article must reach the deficit ONCE. Two servers can call the
    // same id missing at the same instant and both then see a full
    // column of MISSING, so the charge is claimed by compare-exchange
    // rather than by whoever looked second.
    let charged: Arc<Vec<AtomicBool>> =
        Arc::new((0..ids.len()).map(|_| AtomicBool::new(false)).collect());
    // Milli-segments: the deficit is fractional (a sampled id stands for
    // `total / sampled` real segments) and there is no atomic f64.
    let deficit = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();

    for si in 0..servers.len() {
        for c in 0..nconn {
            let server = servers[si].clone();
            let ids = ids.clone();
            let cells = cells.clone();
            let settled = settled.clone();
            let charged = charged.clone();
            let deficit = deficit.clone();
            let stop = stop.clone();
            let plan = plan.clone();
            let nservers = servers.len();
            tasks.push(tokio::spawn(async move {
                // Stride partition: connection c handles ids[c], ids[c+n], …
                let mine: Vec<usize> = (c..ids.len()).step_by(nconn).collect();
                let mut st = LegStats::new(si, c, mine.len());
                let leg = std::time::Instant::now();
                let dial = std::time::Instant::now();
                let Ok((mut conn, _)) = Connection::connect(&server).await else {
                    st.connect = dial.elapsed();
                    st.total = leg.elapsed();
                    st.outcome = LegOutcome::DialFailed;
                    return st;
                };
                st.connect = dial.elapsed();
                // Ids on the wire and not yet answered, oldest first:
                // pipelined replies are attributed POSITIONALLY, so a
                // skipped id must leave the sequence at send time rather
                // than be counted out of it afterwards.
                let mut pending: VecDeque<usize> = VecDeque::new();
                let mut next = 0usize;
                let mut mark = std::time::Instant::now();
                // Reply arrival times inside `DRAIN_BUDGET`, capped at
                // `window` entries because the cap never exceeds it.
                let mut drained: VecDeque<std::time::Instant> = VecDeque::new();
                loop {
                    if stop.load(Ordering::Relaxed) {
                        st.outcome = LegOutcome::Stopped;
                        break;
                    }
                    // Outstanding work is capped by count AND, when
                    // other servers can settle ids underneath us, by how
                    // long this leg would take to drain it.
                    let cap = if plan.settle_on_have {
                        while drained.front().is_some_and(|t| t.elapsed() > DRAIN_BUDGET) {
                            drained.pop_front();
                        }
                        drained.len().clamp(SETTLE_START_WINDOW.min(window), window)
                    } else {
                        window
                    };
                    while next < mine.len() && pending.len() < cap {
                        let id = mine[next];
                        next += 1;
                        if plan.settle_on_have && settled[id].load(Ordering::Acquire) {
                            st.skipped += 1;
                            continue;
                        }
                        if conn.send_stat(&ids[id]).await.is_err() {
                            st.outcome = LegOutcome::SendFailed;
                            st.total = leg.elapsed();
                            return st;
                        }
                        st.sent += 1;
                        pending.push_back(id);
                    }
                    let Some(id) = pending.pop_front() else {
                        break; // nothing outstanding and nothing left to ask
                    };
                    if conn.flush().await.is_err() {
                        st.outcome = LegOutcome::SendFailed;
                        st.total = leg.elapsed();
                        return st;
                    }
                    // `read_stat_checked`, never `read_stat`: `pending` is
                    // a POSITIONAL queue, so a leg that lost one reply
                    // upstream would file every later reply against the
                    // article behind it - a shifted 430 marks a present
                    // article MISSING across the union and can drive a
                    // false Impossible fast-abort on a healthy post. The
                    // check runs BEFORE any store below, so a mismatch
                    // takes the ReadFailed exit with this cell and every
                    // remaining cell on the leg still Unknown, and
                    // Unknown never condemns an article. A server that
                    // echoes no id at all still passes - that is most of
                    // them on a 430.
                    let read = tokio::time::timeout(
                        Duration::from_secs(20),
                        conn.read_stat_checked(Some(ids[id].as_str())),
                    )
                    .await;
                    match read {
                        Ok(Ok(have)) => {
                            // SeqCst, not Relaxed: `charge_deficit` has
                            // two legs store their own cell and then
                            // read each other's, and only a single total
                            // order guarantees at least one of them sees
                            // the other's store. Under Relaxed both can
                            // miss it and the article never joins the
                            // deficit at all - which would quietly
                            // disable the abort in the miss-heavy case
                            // it exists for. Once per reply; free.
                            cells[si][id]
                                .store(if have { HAVE } else { MISSING }, Ordering::SeqCst);
                            if have && plan.settle_on_have {
                                settled[id].store(true, Ordering::Release);
                            }
                            if !have && let Some(b) = plan.abort_over.as_ref() {
                                charge_deficit(&cells, &charged, id, nservers, b, &deficit, &stop);
                            }
                            st.recv += 1;
                            let gap = mark.elapsed();
                            mark = std::time::Instant::now();
                            st.first_reply.get_or_insert(gap);
                            let us = gap.as_micros().min(u32::MAX as u128) as u32;
                            st.gaps_us.push(us);
                            if have {
                                st.hit_us.push(us)
                            } else {
                                st.miss_us.push(us)
                            }
                            if plan.settle_on_have {
                                drained.push_back(std::time::Instant::now());
                                if drained.len() > window {
                                    drained.pop_front();
                                }
                            }
                        }
                        // Remaining cells stay Unknown. The two failures
                        // are recorded apart because they mean opposite
                        // things: a timeout is a peer still thinking, a
                        // read error is a peer gone.
                        Ok(Err(_)) => {
                            st.outcome = LegOutcome::ReadFailed;
                            st.total = leg.elapsed();
                            return st;
                        }
                        Err(_) => {
                            st.outcome = LegOutcome::ReadTimeout;
                            st.total = leg.elapsed();
                            return st;
                        }
                    }
                }
                st.total = leg.elapsed();
                conn.quit().await;
                st
            }));
        }
    }
    let mut legs = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(st) = t.await {
            legs.push(st);
        }
    }

    let matrix = cells
        .iter()
        .map(|sc| {
            sc.iter()
                .map(|a| match a.load(Ordering::Relaxed) {
                    HAVE => Avail::Have,
                    MISSING => Avail::Missing,
                    _ => Avail::Unknown,
                })
                .collect()
        })
        .collect();
    SweepResult {
        matrix,
        elapsed: t0.elapsed(),
        legs,
        stopped_early: stop.load(Ordering::Relaxed),
    }
}

/// One article has just been called missing by one server. If that was
/// the LAST server still to answer for it, the article is missing
/// everywhere: charge its bytes to the shared deficit and, if that
/// clears the byte budget, tell every leg to stand down.
///
/// Where the threshold sits, and why it is not simply the budget, is
/// [`AbortRule`]'s - the two provenances round differently.
fn charge_deficit(
    cells: &[Arc<Vec<AtomicU8>>],
    charged: &[AtomicBool],
    id: usize,
    nservers: usize,
    budget: &AbortBudget,
    deficit: &AtomicU64,
    stop: &AtomicBool,
) {
    if nservers == 0
        || !cells
            .iter()
            .all(|col| col[id].load(Ordering::SeqCst) == MISSING)
    {
        return;
    }
    let w = budget.weights.get(id).copied().unwrap_or(0.0);
    if w <= 0.0 {
        return;
    }
    // Claim the article, or leave it to the leg that already did.
    if charged[id]
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    // Milli-units: a weight is fractional either way (a sampled id
    // stands for `total / sampled` segments, or for that share of its
    // file's bytes) and there is no atomic f64.
    let milli = (w * 1000.0).round().max(0.0) as u64;
    let total = deficit.fetch_add(milli, Ordering::Relaxed) + milli;
    if budget.rule.decided(total as f64 / 1000.0) {
        stop.store(true, Ordering::Relaxed);
    }
}

/// Ceiling on the bytes one block-size probe may spend. Two articles of
/// a par2 index is a few tens of KB; two of a recovery volume is ~1.5 MB.
/// The cap is what stops a poster-controlled `bytes=` from turning a
/// STAT-only pass into a download - which means it has to bound the READ
/// (`Connection::body_capped`), not just the loop around it.
const MAX_PROBE_BYTES: usize = 8 << 20;

/// How many servers may DELIVER probe bytes before the probe gives up.
///
/// [`MAX_PROBE_BYTES`] is per-server, and it is initialised inside the
/// server loop, so a fleet at the supported ceiling of 32 could spend it
/// 32 times over - and the caller probes two candidates, so ~512 MiB of
/// accepted body in the worst case. The bytes only ever materialise if
/// the servers actually serve them, i.e. against a hostile or badly
/// corrupt post, but nothing bounded the aggregate.
///
/// Counted in SERVERS THAT DELIVERED, deliberately, rather than as a
/// shared byte allowance. A shared allowance with a per-server floor was
/// the obvious shape and it is the wrong one twice over: article size is
/// poster-chosen, so a floor large enough to be useful refuses honest
/// posts with big articles, and a floor small enough to be safe lets
/// four servers serving decodable-but-Main-less bodies starve the fifth
/// that holds the real index. Either way `probe_recovery_set` answers
/// `None` and the caller's fallback is a FULL DOWNLOAD - the exact cost
/// the probe exists to avoid. Counting deliverers bounds the aggregate
/// at 3 x 8 MiB while leaving every single-server path byte-for-byte as
/// it was.
///
/// A `430` costs nothing and must not count: a post whose par2 lives
/// only on the fifth provider has to stay reachable.
///
/// Residue worth stating: this bounds BYTES, not wall clock. A fleet of
/// servers that connect and then stall still pays up to
/// [`PROBE_TIMEOUT`] each. Bounding that too would need a budget across
/// the whole list, and a budget that expires before reaching the one
/// provider holding the set turns a cheap probe into a full download -
/// so it is left alone until something measures it.
const MAX_PROBE_SERVERS: usize = 3;

/// Wall-clock ceiling on one server's whole probe. `Connection::connect`
/// bounds its own dial, but `BODY` does not bound the read - and a
/// pre-flight that hangs is worse than one that shrugs, because every
/// caller's fallback is already "carry on and download". Same reason
/// `stat_sweep` puts a timeout round its reply reads.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// What one probe could read out of the PAR2 bytes it actually fetched.
///
/// The block size is the whole set's, so a single valid Main packet
/// settles it - and where the fetched bytes covered MORE than one
/// recovery set it is the LARGEST set's, because this type states one
/// figure and its consumer states one back (see `probe_recovery_set`
/// for what makes that safe). The file lengths are NOT: a probe
/// fetches one or two
/// articles, so it sees whatever FileDesc packets happened to land in
/// them, and [`crate::par2::Par2Set::parse`] silently drops every file
/// whose FileDesc was not among them. A caller reading that list as
/// "the set's files" would conclude that a payload file is not covered
/// by the recovery set when all it really knows is that it did not
/// download the packet describing it - and "not covered" is precisely
/// the inference that makes damage unrepairable.
///
/// So the list is not exposed. The only question this answers is
/// [`ProbedSet::described_length`], whose `None` says WE DID NOT SEE
/// ONE and never says the file is absent from the set. Every caller
/// therefore has to write its own fallback for the unknown case, which
/// is the point.
#[derive(Debug, Clone)]
pub struct ProbedSet {
    /// The recovery set's slice size, from a Main packet whose MD5
    /// verified. Always non-zero.
    pub block_size: u64,
    /// Lowercased member-file name -> its EXACT length, for the files
    /// the fetched bytes described, across EVERY recovery set they
    /// covered. `None` value = two of those files share this name up to
    /// case and their lengths disagree - whether they are members of
    /// one set or of two - so the name does not identify one file.
    described: std::collections::HashMap<String, Option<u64>>,
}

impl ProbedSet {
    /// The EXACT length of the set member posted under `name`, when the
    /// fetched bytes carried its FileDesc packet.
    ///
    /// `None` means only that this probe did not read a description of
    /// it - never that the recovery set does not cover it. See
    /// [`ProbedSet`].
    pub fn described_length(&self, name: &str) -> Option<u64> {
        *self.described.get(&name.to_ascii_lowercase())?
    }

    /// How many member files the fetched bytes described. For callers
    /// that want to report the probe's reach; it is a count of packets
    /// SEEN, not of files in the set.
    pub fn described_files(&self) -> usize {
        self.described.len()
    }
}

/// Fetch the recovery set's BLOCK SIZE - and whatever member-file
/// lengths came with it - by pulling a couple of articles of one
/// `.par2` file and reading its packets.
///
/// The one fact pre-flight cannot infer. A recovery volume named
/// `.vol-NN.par2` states its ordinal and not its slice count, so its
/// budget can only be sized from its BYTES - and bytes mean nothing
/// without the set's block size, which is written down in exactly one
/// place: the PAR2 Main packet. `ids` are message-ids in bracketed form,
/// tried in order and accumulated; two is the useful number (the head of
/// the file, then its tail, since a volume interleaves its critical
/// packets between recovery slices and a par2 index carries the Main
/// packet in its first bytes).
///
/// Servers are tried in turn and the first that answers wins. `None` for
/// every failure - unreachable server, article missing everywhere,
/// undecodable body, no valid Main packet in what came back - because
/// the caller's fallback is to keep saying it does not know, which is
/// the honest answer and the safe one.
///
/// The Main packet is MD5-verified by [`crate::par2::Par2Set::parse`]
/// before its block size is believed. That bar is deliberate: the figure
/// goes on to license an IMPOSSIBLE verdict that stops a download, and a
/// recovery-slice packet header - which also states the block size, in
/// its length field - is not covered by any digest we could check from a
/// partial file. Every FileDesc length clears the same bar - the parser
/// digests EVERY packet it keeps - which is what lets a caller place a
/// member file's block grid on a number it did not have to estimate.
pub async fn probe_recovery_set(servers: &[ServerConfig], ids: &[String]) -> Option<ProbedSet> {
    let sets = probe_par2_sets(servers, ids).await?;
    // Keyed by lowercased name because the NZB subject and the
    // FileDesc packet are two records of one filename, written
    // by different tools. Two set members whose names collide
    // there are recorded as ambiguous rather than as either
    // one: a length attached to the wrong file would misplace
    // that file's block grid.
    //
    // TODO 311's last box: the UNION across every adopted set, and the
    // choice is made by what this map is FOR rather than by copying the
    // live path. `described` answers one question - how long is the
    // member posted under this name - and that question has the same
    // answer whichever recovery set describes it, so a post with one
    // set per track (GH #63's shape) describes eighteen files here
    // exactly as a single eighteen-file set would. Taking only the
    // largest set instead would answer `None` for seventeen of them,
    // which `check_sweep::escalate_repairable` reads as "no FileDesc
    // seen" and falls back from - correct but blind, and blind for a
    // reason that is not true.
    //
    // The collapse rule needs no widening to carry it: two sets that
    // disagree about a name's length collapse to `None` by exactly the
    // rule two members of ONE set already do, which is the answer that
    // keeps a length off the wrong file's block grid. That is the whole
    // of what a union has to get right here, and it is why a union is
    // safe at THIS consumer where it would not be at the donation ones
    // (see the call sites in `get::donor` and `get::dupefill`).
    //
    // A STRAY set - another release's `.par2` left in the NZB, the
    // shape `db70451e4` and section G of the §311 handoff document -
    // costs this map nothing, and the reason is that it is keyed by
    // NAME. `escalate_repairable` looks a name up out of the NZB's own
    // `filename_hint`, so a stray's members are simply never asked
    // about; the only way one can be heard from at all is a name the
    // post ALSO carries, at a length the stray disagrees about, and
    // that is the collapse above - `None`, the caller keeps the byte
    // figure, which is what it does for an undescribed file anyway.
    // The union cannot make that file's answer worse, only unknown.
    let mut described: std::collections::HashMap<String, Option<u64>> =
        std::collections::HashMap::new();
    for f in sets.iter().flat_map(|s| &s.files) {
        described
            .entry(f.name.to_ascii_lowercase())
            .and_modify(|v| {
                if *v != Some(f.length) {
                    *v = None;
                }
            })
            .or_insert(Some(f.length));
    }
    Some(ProbedSet {
        // One representative figure, and there is no honest alternative:
        // `ProbedSet` states a single block size because its consumer
        // states a single one back. `pick_sets` orders largest first
        // (ties by set id, so it does not depend on which `.par2`
        // article came back first), so this is the same set the
        // pre-union code adopted and the answer does not move on a
        // single-set post. What makes it SAFE on a multi-set one is
        // `check::multiple_par2_sets`, which drops the declared-count
        // cap whenever the NZB carries more than one set - and that cap
        // is the only rule a foreign block size could flip a verdict
        // through, because `measured_verdict`'s own comparison divides
        // by the block size on both sides and cancels it out. That
        // covers the stray-set case too, and by construction rather
        // than by luck: a stray declaring MORE files than the real
        // release becomes `sets[0]` here, and the same `.par2` in the
        // NZB is what makes `multiple_par2_sets` true.
        block_size: sets[0].block_size,
        described,
    })
}

/// The probe underneath [`probe_recovery_set`], handing back the WHOLE
/// parsed sets rather than the two facts pre-flight wants from them.
///
/// §293's plan-side arm is the second caller and the reason this is its
/// own door: donating a predecessor's file to a successor turns on the
/// FileDesc packet's `md5`/`md5_16k`/`length`, which `ProbedSet`
/// deliberately throws away. Every guarantee above is this function's -
/// the per-server byte cap, the three-server allowance, the timeout, and
/// the MD5 bar `Par2Set::parse` holds every kept packet to - so a caller
/// that skips a download on what comes back is standing on the same
/// digests the repair engine does.
///
/// # Why this is plural, and what the caller now owes
///
/// It answered `Option<Par2Set>` until TODO 311's last box, through a
/// bare `Par2Set::parse(&views).ok()?` - and `parse` refuses the whole
/// input the moment two packets carry different recovery-set ids. So
/// the instant the articles this probe accumulated covered two
/// recovery sets, every consumer here was told "I know nothing about
/// this post", when what had actually happened is that it knew about
/// two sets instead of one. Nothing was WRONG on disk and no job
/// failed for it - pre-flight degrades an optimisation, not a verdict,
/// which is why the live path was fixed first and this was left - but
/// the run then plans against a post it could have measured. Read the
/// limit below before concluding anything about how a caller reaches
/// that: on today's callers it is latent, and the paragraph says why.
///
/// [`crate::live::pick_sets`] is the same adoption the live path takes,
/// and it is a no-op on the single-set input that very nearly every
/// real post is: one set in, one set out, byte for byte the answer
/// `parse` gave before. Largest first, ties by set id, so a caller that
/// wants ONE representative reads a stable one that does not depend on
/// which article came back first.
///
/// A caller that takes only `sets[0]` is choosing to, and must say so:
/// the union is right for a name-to-length map (see
/// [`probe_recovery_set`]) and is NOT automatically right for a caller
/// whose own duplicate rail is scoped to one `Par2Set`.
///
/// # The limit, stated rather than left to be found
///
/// `pick_sets` groups at the granularity of one INPUT VIEW, keyed on
/// [`crate::par2::Par2Set::set_id_of`], whose own doc records the
/// assumption the whole scheme rests on: one posted file is one set. So
/// a single view whose bytes cover two sets is still refused, exactly
/// as `Par2Set::parse` refuses it, and no arm here splits packets to
/// take it apart.
///
/// That is not a hole today and the reason is worth writing down,
/// because it is also what says when it becomes one. A view here is one
/// ARTICLE, and every caller passes ids belonging to exactly one posted
/// `.par2` file - `check::block_size_probe` its first and last segment,
/// `get::donor` and `get::dupefill` every segment of the NZB's Par2Main
/// - so the views of any one call are byte ranges of one file, and one
/// file is one set. What this fix reaches is therefore the case where
/// the accumulated articles span TWO par2 files, which is what a caller
/// probing more than one seed does. Widen a caller that way and this
/// door already answers; hand it a genuinely concatenated multi-set
/// upload and it will decline, and the fix then is packet-granular
/// grouping inside `pick_sets`, which would want measuring first
/// (it copies where the borrow path does not, and #63's real shape -
/// many one-set files - takes the borrow path).
///
/// `None` for every failure, and the zero-block-size rejection lives
/// here rather than in the caller: a set that divides every consumer by
/// zero is not one anybody posted. It now drops THAT set and keeps the
/// rest, which is the same judgement one rung finer - and if nothing
/// survives it, `None` again, so the server loop still tries the NEXT
/// server instead of settling for it.
pub async fn probe_par2_sets(servers: &[ServerConfig], ids: &[String]) -> Option<Vec<Par2Set>> {
    let mut delivering = 0usize;
    for server in servers {
        if delivering >= MAX_PROBE_SERVERS {
            break;
        }
        // Set from inside the body loop, read after the future is done.
        // Atomic rather than `Cell` only because this future has to stay
        // `Send` for the timeout wrapper; there is no contention.
        let served = std::sync::atomic::AtomicBool::new(false);
        let one = async {
            let (mut conn, _) = Connection::connect(server).await.ok()?;
            let mut parts: Vec<Vec<u8>> = Vec::new();
            let mut spent = 0usize;
            for id in ids {
                // The allowance has to reach the READ, not just gate the
                // next iteration: checked only here, the cap is a
                // post-hoc audit of bytes already buffered, and the FIRST
                // id is never gated at all (spent is 0). The wire bound
                // behind a plain `body` is 256 MiB, so one well-formed
                // giant article was 32x over budget and was then decoded
                // into a second body-sized Vec beside it. `body_capped`
                // stops the read at what is left instead.
                let left = MAX_PROBE_BYTES.saturating_sub(spent);
                if left == 0 {
                    break;
                }
                match conn.body_capped(id, left).await {
                    Ok(Some(raw)) => {
                        served.store(true, std::sync::atomic::Ordering::Relaxed);
                        spent += raw.len();
                        if let Ok(dec) = crate::yenc::decode(&raw) {
                            parts.push(dec.data);
                        }
                    }
                    // A missing article is this server's answer, not the
                    // set's: keep asking for the rest, then let the next
                    // server try what this one could not produce.
                    Ok(None) => {}
                    // TooLarge means the read ran all the way to what
                    // was left of MAX_PROBE_BYTES and stopped there.
                    // Those bytes came off the wire, so this server DID
                    // deliver its allowance and must count against the
                    // three-server aggregate - leaving `served` false
                    // let a fleet of 32 hostile providers spend the
                    // per-server cap 32 times over, twice, which is the
                    // ~512 MiB the aggregate exists to prevent (Codex
                    // sweep 5, L1).
                    Err(crate::nntp::NntpError::TooLarge(_)) => {
                        served.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    Err(_) => break,
                }
            }
            conn.quit().await;
            let views: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
            let mut sets = crate::live::pick_sets(&views).ok()?;
            // A zero block size divides every consumer by zero and is
            // not a set anyone posted. A BELT, and measured to be one:
            // `par2::parse_main` refuses a zero slice size outright, so
            // no `Par2Set` reaching here can carry one and this retain
            // has nothing to drop today - it is kept because this door
            // is `pub` and the promise ("always non-zero", which
            // `ProbedSet` states to its own callers) has to be held
            // somewhere that a change to the parser cannot quietly
            // undo. Per set rather than for the whole answer, so if it
            // ever does fire, one bad Main packet riding along with
            // good ones costs only itself.
            sets.retain(|s| s.block_size != 0);
            if sets.is_empty() {
                return None;
            }
            Some(sets)
        };
        if let Ok(Some(probed)) = tokio::time::timeout(PROBE_TIMEOUT, one).await {
            return Some(probed);
        }
        // Only a server that actually handed over bytes and still failed
        // to yield a set spends one of the allowance - see
        // `MAX_PROBE_SERVERS`.
        if served.load(std::sync::atomic::Ordering::Relaxed) {
            delivering += 1;
        }
    }
    None
}

/// Stratified sample of `n` segment indexes out of `total`, edges
/// first: takedowns nuke the HEAD of a post and truncated uploads lose
/// the TAIL, so with the budget for it the first three and last two
/// indexes are always sampled - a single flaky STAT on a lone edge
/// probe must not be the only witness to a head nuke - and the
/// remainder spreads evenly across the interior. Deterministic on
/// purpose: a re-probe STATs the identical indexes, so a later Green
/// means the previously missing articles appeared, not a lucky
/// re-roll (the §77 re-probe overwrite leans on this).
pub fn stratified_sample(total: usize, n: usize) -> Vec<usize> {
    if total == 0 {
        return Vec::new();
    }
    if n >= total {
        return (0..total).collect();
    }
    let n = n.max(2).min(total);
    // Edge redundancy only once the budget covers it; tiny budgets keep
    // one probe per edge.
    let (head, tail) = if n >= 5 { (3, 2) } else { (1, 1) };
    let mut out: Vec<usize> = (0..head).collect();
    out.extend((total - tail)..total);
    let mid = n - out.len();
    let (lo, hi) = (head, total - tail);
    for i in 0..mid {
        out.push(lo + (i + 1) * (hi - lo) / (mid + 1));
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M1: the byte abort rule must convert encoded -> raw exactly as
    /// the gate it stands in for does.
    ///
    /// `check::block_size_could_condemn` takes its deficit from
    /// `margined_deficit_raw_bytes` (which applies `min_raw_bytes`) and
    /// leaves the volumes at their full ENCODED size. This rule skipped
    /// the conversion, so its deficit ran the yEnc overhead larger than
    /// the gate's and the sweep could stand down at a point the gate
    /// would not have condemned from - the one thing `AbortRule::Bytes`
    /// documents as impossible. The band between the two conversions is
    /// where the two disagreed.
    #[test]
    fn the_byte_abort_rule_converts_encoded_to_raw_like_its_gate() {
        // Sits ABOVE the ceiling encoded, BELOW it once converted: the
        // exact band the missing conversion got wrong.
        const CEILING: u64 = 1_000_000;
        let encoded = 1_020_000f64;
        assert!(
            crate::par2::min_raw_bytes(encoded as u64) < CEILING,
            "fixture is not in the disagreement band"
        );
        let rule = AbortRule::Bytes {
            margin: 1.0,
            ceiling_bytes: CEILING,
        };
        assert!(
            !rule.decided(encoded),
            "raw deficit is under the ceiling, so the sweep must keep going"
        );
        // And it still fires once the RAW figure clears the ceiling, so
        // the fix delays the abort rather than disabling it.
        assert!(
            rule.decided(2_000_000.0),
            "a deficit twice the ceiling is decided at any conversion"
        );
    }

    use crate::mock::{Chaos, MockServer, make_file_articles};

    /// Three present ids and two the server has never heard of, swept
    /// over one mock. The matrix is the whole point of the pass: a cell
    /// per (server, article), and the verdict helpers read only it.
    #[tokio::test]
    async fn a_sweep_fills_one_cell_per_article_and_names_the_absent_ones() {
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..24_000u32).map(|i| i as u8).collect();
        let segs = make_file_articles("p.bin", &payload, 8_000, "pf", &mut articles);
        let srv = MockServer::start(articles, Chaos::default()).await;
        let mut ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
        let present = ids.len();
        ids.push("<gone-1@mock>".into());
        ids.push("<gone-2@mock>".into());

        let out = tokio::time::timeout(
            Duration::from_secs(20),
            stat_sweep(&[srv.server_config()], &ids, 2, 4),
        )
        .await
        .expect("sweep hung");

        assert_eq!(out.matrix.len(), 1, "one row per server");
        assert_eq!(out.matrix[0].len(), ids.len());
        assert_eq!(out.server_counts(0), (present, 2, 0));
        assert_eq!(
            out.union_missing(),
            vec![present, present + 1],
            "only the ids no server could produce"
        );
    }

    /// `check --window 0` sent not one STAT and then waited out the
    /// 20 s reply timeout with every cell Unknown, which `union_missing`
    /// reads as COMPLETE. Both counts clamp to one inside the sweep.
    #[tokio::test]
    async fn zero_window_and_zero_connections_still_sweep() {
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..16_000u32).map(|i| (i * 5) as u8).collect();
        let segs = make_file_articles("w.bin", &payload, 8_000, "win", &mut articles);
        let srv = MockServer::start(articles, Chaos::default()).await;
        let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();

        let out = tokio::time::timeout(
            Duration::from_secs(10),
            stat_sweep(&[srv.server_config()], &ids, 0, 0),
        )
        .await
        .expect("a zero window hung the sweep again");
        assert_eq!(out.server_counts(0), (ids.len(), 0, 0));
        assert!(out.union_missing().is_empty());
    }

    /// A server that cannot be dialled leaves its row Unknown - and an
    /// Unknown must never be counted as evidence of absence, or an
    /// unreachable server alone would condemn a healthy NZB.
    #[tokio::test]
    async fn an_undialable_server_leaves_unknowns_that_never_condemn_an_article() {
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..8_000u32).map(|i| i as u8).collect();
        let segs = make_file_articles("d.bin", &payload, 8_000, "dead", &mut articles);
        let srv = MockServer::start(articles, Chaos::default()).await;
        let mut dead = srv.server_config();
        // Bound and then closed by the mock's own listener choice: a
        // port nothing is listening on refuses immediately.
        dead.port = 1;
        dead.host = "127.0.0.1".into();
        let mut ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
        ids.push("<absent@mock>".into());

        let out = tokio::time::timeout(
            Duration::from_secs(20),
            stat_sweep(&[srv.server_config(), dead], &ids, 1, 8),
        )
        .await
        .expect("sweep hung");

        assert_eq!(out.matrix.len(), 2);
        assert_eq!(out.server_counts(1), (0, 0, ids.len()), "row never dialled");
        assert!(
            out.union_missing().is_empty(),
            "Missing on the live server plus Unknown on the dead one is not a verdict"
        );
        assert!(out.elapsed > Duration::ZERO);
    }

    /// The two verdict helpers, off a matrix built by hand - the shapes
    /// a sweep cannot be made to produce on demand.
    #[test]
    fn union_missing_needs_every_server_to_agree() {
        let none = SweepResult {
            matrix: Vec::new(),
            elapsed: Duration::ZERO,
            legs: Vec::new(),
            stopped_early: false,
        };
        assert!(
            none.union_missing().is_empty(),
            "no server answered: nothing is provably absent"
        );

        use Avail::{Have, Missing, Unknown};
        let r = SweepResult {
            matrix: vec![
                vec![Missing, Missing, Have, Missing],
                vec![Missing, Have, Have, Unknown],
            ],
            elapsed: Duration::from_millis(3),
            legs: Vec::new(),
            stopped_early: false,
        };
        assert_eq!(r.union_missing(), vec![0]);
        assert_eq!(r.server_counts(0), (1, 3, 0));
        assert_eq!(r.server_counts(1), (2, 1, 1));
    }

    /// Build `n` single-segment articles with predictable ids.
    fn ids_n(n: usize) -> (std::collections::HashMap<String, Vec<u8>>, Vec<String>) {
        let mut articles = std::collections::HashMap::new();
        let mut ids = Vec::new();
        for i in 0..n {
            let id = format!("<a{i}@mock>");
            articles.insert(id.clone(), b"x".to_vec());
            ids.push(id);
        }
        (articles, ids)
    }

    /// The first `Have` settles an article, so the servers behind it
    /// never ask. Measured 15 Aug: a miss costs 9-31x a hit on five of
    /// six real providers and a healthy post is nearly all hits, so
    /// this is where a 119 s sweep goes.
    #[tokio::test]
    async fn a_have_on_one_server_stops_the_others_asking() {
        let (articles, ids) = ids_n(24);
        let fast = MockServer::start(articles.clone(), Chaos::default()).await;
        // The measured shape: this one does not carry the articles and
        // charges 100 ms to say so, where `fast` answers instantly. Left
        // alone it would decide the sweep's whole wall time.
        let slow = MockServer::start(
            articles.clone(),
            Chaos {
                missing: ids.iter().cloned().collect(),
                missing_delay_ms: 100,
                ..Chaos::default()
            },
        )
        .await;
        let plan = SweepPlan {
            settle_on_have: true,
            ..SweepPlan::full(1, 4)
        };
        let out = tokio::time::timeout(
            Duration::from_secs(30),
            stat_sweep_with(&[fast.server_config(), slow.server_config()], &ids, &plan),
        )
        .await
        .expect("sweep hung");

        let asked = slow.stats.load(Ordering::Relaxed);
        assert!(
            asked < ids.len() as u64,
            "the slow server asked about all {} ids despite every one being settled ({asked})",
            ids.len()
        );
        // Skipped cells are Unknown, and Unknown is the value that
        // already means "not evidence of absence".
        assert!(
            out.union_missing().is_empty(),
            "settling on Have condemned an article that a server HAD"
        );
        assert!(
            out.legs.iter().any(|l| l.skipped > 0),
            "nothing was skipped"
        );
        assert!(!out.stopped_early);
    }

    /// The safety property. A server skipping an id must never let that
    /// id be counted absent, and an id nobody has must still be counted.
    #[tokio::test]
    async fn settling_never_invents_a_missing_article() {
        let (articles, mut ids) = ids_n(8);
        let has = MockServer::start(articles.clone(), Chaos::default()).await;
        // Same ids, all refused: the pair a false IMPOSSIBLE would come
        // from if a skip were ever read as absence.
        let hasnt = MockServer::start(
            articles,
            Chaos {
                missing: ids.iter().cloned().collect(),
                ..Chaos::default()
            },
        )
        .await;
        let orphan = ids.len();
        ids.push("<nobody-has-this@mock>".into());

        let plan = SweepPlan {
            settle_on_have: true,
            ..SweepPlan::full(2, 4)
        };
        let out = tokio::time::timeout(
            Duration::from_secs(30),
            stat_sweep_with(&[has.server_config(), hasnt.server_config()], &ids, &plan),
        )
        .await
        .expect("sweep hung");

        assert_eq!(
            out.union_missing(),
            vec![orphan],
            "only the id NEITHER server has is missing everywhere"
        );
    }

    /// Once the missing payload outweighs everything the recovery
    /// volumes could hold, more refusals cannot move the answer, so the
    /// sweep stops rather than paying for them.
    #[tokio::test]
    async fn the_sweep_stops_once_the_deficit_clears_the_recovery_budget() {
        let (articles, ids) = ids_n(60);
        let dead = MockServer::start(
            articles,
            Chaos {
                missing: ids.iter().cloned().collect(),
                ..Chaos::default()
            },
        )
        .await;
        let plan = SweepPlan {
            settle_on_have: true,
            abort_over: Some(AbortBudget {
                weights: vec![100_000.0; ids.len()],
                rule: AbortRule::Bytes {
                    margin: 1.0,
                    ceiling_bytes: 200_000,
                },
            }),
            ..SweepPlan::full(1, 4)
        };
        let out = tokio::time::timeout(
            Duration::from_secs(30),
            stat_sweep_with(&[dead.server_config()], &ids, &plan),
        )
        .await
        .expect("sweep hung");

        assert!(
            out.stopped_early,
            "the verdict was decided and it kept going"
        );
        let asked = dead.stats.load(Ordering::Relaxed);
        assert!(
            asked < ids.len() as u64,
            "swept all {} ids after the verdict was locked ({asked})",
            ids.len()
        );
        assert!(out.legs.iter().any(|l| l.outcome == LegOutcome::Stopped));
    }

    /// Furniture carries weight 0 (#23: a missing `.nfo` is not a
    /// repair the recovery set was ever going to make), so a post whose
    /// only absences are furniture must sweep to the end rather than
    /// abort on them.
    #[tokio::test]
    async fn zero_weight_absences_never_trip_the_abort() {
        let (articles, ids) = ids_n(12);
        let dead = MockServer::start(
            articles,
            Chaos {
                missing: ids.iter().cloned().collect(),
                ..Chaos::default()
            },
        )
        .await;
        let plan = SweepPlan {
            abort_over: Some(AbortBudget {
                weights: vec![0.0; ids.len()],
                rule: AbortRule::Bytes {
                    margin: 1.0,
                    ceiling_bytes: 1,
                },
            }),
            ..SweepPlan::full(1, 4)
        };
        let out = tokio::time::timeout(
            Duration::from_secs(30),
            stat_sweep_with(&[dead.server_config()], &ids, &plan),
        )
        .await
        .expect("sweep hung");
        assert!(!out.stopped_early);
        assert_eq!(out.server_counts(0), (0, ids.len(), 0));
    }

    /// Two servers can call the same id missing at the same instant and
    /// both then see a full column of MISSING. The charge is claimed by
    /// compare-exchange, so the id reaches the deficit exactly once - a
    /// double count would abort the sweep on a deficit it never had.
    #[test]
    fn an_article_reaches_the_deficit_exactly_once() {
        let cells: Vec<Arc<Vec<AtomicU8>>> = (0..2)
            .map(|_| Arc::new((0..1).map(|_| AtomicU8::new(MISSING)).collect()))
            .collect();
        let charged: Vec<AtomicBool> = vec![AtomicBool::new(false)];
        let budget = AbortBudget {
            weights: vec![10_000.0],
            rule: AbortRule::Bytes {
                margin: 1.0,
                ceiling_bytes: 15_000,
            },
        };
        let deficit = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        for _ in 0..5 {
            charge_deficit(&cells, &charged, 0, 2, &budget, &deficit, &stop);
        }
        assert_eq!(
            deficit.load(Ordering::Relaxed),
            10_000_000,
            "charged more than once"
        );
        assert!(
            !stop.load(Ordering::Relaxed),
            "10 KB does not clear a budget of 15 KB"
        );
    }

    /// The threshold is the caller's byte budget, passed strictly - no
    /// article-shaped slack, because there are no articles in this
    /// arithmetic any more, and strict because the gate it mirrors
    /// (`check::block_size_could_condemn`) is strict too. At the budget
    /// the sweep runs on; past it the sweep stands down.
    ///
    /// The fixtures are stated in ENCODED bytes - which is what the
    /// weights are - and the boundary sits where they land after
    /// `min_raw_bytes`. They used to sit either side of the ceiling
    /// unconverted, which pinned the rule comparing encoded deficit to
    /// encoded ceiling while the gate compared RAW deficit to encoded
    /// ceiling; the rule therefore stood the sweep down inside a band
    /// the gate would not have condemned from, which is the one thing
    /// `AbortRule::Bytes`'s own doc promises cannot happen. Converting
    /// here moved the boundary up by the yEnc overhead; it did not
    /// loosen the strictness this test exists for, which is still
    /// asserted on both sides.
    #[test]
    fn the_abort_fires_past_the_byte_budget_and_not_before() {
        const CEILING: u64 = 2_000_000;
        // 2_100_000 encoded -> 1_995_000 raw: under.
        const UNDER: f64 = 2_100_000.0;
        // 2_120_000 encoded -> 2_014_000 raw: over.
        const OVER: f64 = 2_120_000.0;
        assert!(
            crate::par2::min_raw_bytes(UNDER as u64) <= CEILING
                && crate::par2::min_raw_bytes(OVER as u64) > CEILING,
            "fixtures must straddle the ceiling AFTER conversion, or this proves nothing"
        );

        let cells: Vec<Arc<Vec<AtomicU8>>> = vec![Arc::new(vec![AtomicU8::new(MISSING)])];
        let budget = AbortBudget {
            weights: vec![UNDER],
            rule: AbortRule::Bytes {
                margin: 1.0,
                ceiling_bytes: CEILING,
            },
        };
        let charged = vec![AtomicBool::new(false)];
        let deficit = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        charge_deficit(&cells, &charged, 0, 1, &budget, &deficit, &stop);
        assert!(
            !stop.load(Ordering::Relaxed),
            "short of the budget is not a settled verdict"
        );

        let cells: Vec<Arc<Vec<AtomicU8>>> = vec![Arc::new(vec![AtomicU8::new(MISSING)])];
        let budget = AbortBudget {
            weights: vec![OVER],
            rule: AbortRule::Bytes {
                margin: 1.0,
                ceiling_bytes: CEILING,
            },
        };
        let charged = vec![AtomicBool::new(false)];
        let deficit = AtomicU64::new(0);
        charge_deficit(&cells, &charged, 0, 1, &budget, &deficit, &stop);
        assert!(
            stop.load(Ordering::Relaxed),
            "past the budget is the point of no more evidence"
        );
    }

    /// The other provenance: no volume name declares a slice count, so
    /// the budget arrived as a measured ceiling in BLOCKS and the
    /// deficit is the missing payload's bytes. The abort has to speak
    /// that pair, because a post shaped this way is exactly the one
    /// with no segment budget to arm the other rule with.
    ///
    /// Every discount is asserted because each exists to lean away from
    /// impossibility: the margin halves a deficit that came off a
    /// sample, the encoded-to-raw conversion takes the yEnc overhead
    /// back off, and the block count floors rather than ceils.
    #[test]
    fn the_block_rule_weighs_margined_bytes_against_the_measured_ceiling() {
        let rule = AbortRule::Blocks {
            block_size: 1_000,
            margin: 0.5,
            ceiling: 2,
        };
        assert!(
            !rule.decided(4_000.0),
            "4,000 encoded bytes is 4 blocks before anything, 2 after the margin and 1 \
             after the raw conversion, and 1 does not clear 2"
        );
        assert!(
            !rule.decided(6_000.0),
            "the block count floors, so 2,850 raw margined bytes is still 2 blocks"
        );
        assert!(rule.decided(6_400.0), "3 blocks clears a ceiling of 2");
        assert!(
            !AbortRule::Blocks {
                block_size: 0,
                margin: 0.5,
                ceiling: 0,
            }
            .decided(1e12),
            "an unknown block size sizes nothing and may not abort anything"
        );
    }

    /// And it reaches the same stop flag through the same charge path -
    /// once per article, furniture still weightless.
    #[test]
    fn a_bytes_armed_abort_stops_the_sweep() {
        let cells: Vec<Arc<Vec<AtomicU8>>> = vec![Arc::new(vec![AtomicU8::new(MISSING)])];
        let budget = AbortBudget {
            weights: vec![6_400.0],
            rule: AbortRule::Blocks {
                block_size: 1_000,
                margin: 0.5,
                ceiling: 2,
            },
        };
        let charged = vec![AtomicBool::new(false)];
        let deficit = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        charge_deficit(&cells, &charged, 0, 1, &budget, &deficit, &stop);
        assert!(stop.load(Ordering::Relaxed));
        assert_eq!(deficit.load(Ordering::Relaxed), 6_400_000, "milli-BYTES");
    }

    /// An `Unknown` row cannot condemn, so a leg that stood down early
    /// leaves the verdict more conservative, never less. This is the
    /// same rule a per-server deadline would lean on.
    #[test]
    fn a_stopped_leg_only_ever_softens_the_verdict() {
        use Avail::{Missing, Unknown};
        let r = SweepResult {
            matrix: vec![vec![Missing, Missing], vec![Missing, Unknown]],
            elapsed: Duration::ZERO,
            legs: Vec::new(),
            stopped_early: true,
        };
        assert_eq!(r.union_missing(), vec![0]);
    }

    /// The fetch that closed the 15 Aug gap: the set's block size read
    /// off one small article instead of guessed at from a filename.
    ///
    /// `testset.par2` is a real par2 index - Main packet at offset 0,
    /// 4,096-byte slices - posted here as a single yEnc article. The
    /// verdict path calls this only when volume names left the budget
    /// unsizable, so the whole cost of sharpening that verdict is the
    /// one BODY this test performs.
    #[tokio::test]
    async fn one_article_yields_the_recovery_sets_block_size() {
        const INDEX: &[u8] = include_bytes!("../../nzbkit-base/tests/fixtures/par2/testset.par2");
        let mut articles = std::collections::HashMap::new();
        let segs = make_file_articles("testset.par2", INDEX, 64_000, "idx", &mut articles);
        assert_eq!(segs.len(), 1, "the fixture is one article");
        let srv = MockServer::start(articles, Chaos::default()).await;
        let ids = vec![format!("<{}>", segs[0].0)];

        let probed = tokio::time::timeout(
            Duration::from_secs(20),
            probe_recovery_set(&[srv.server_config()], &ids),
        )
        .await
        .expect("probe hung")
        .expect("one article carries the whole index");
        assert_eq!(probed.block_size, 4_096);
    }

    /// The lengths that ride along with the block size, and the one
    /// thing they may never be read as saying.
    ///
    /// A FileDesc packet states a member file's EXACT length, which is
    /// what lets a caller lay the set's block grid over a file whose
    /// only other measure is the NZB's approximate encoded `bytes=`.
    /// But the packets that arrive are whatever the fetched articles
    /// happened to contain, so `described_length` answering `None` has
    /// to mean "not seen" and never "not in the set" - the second
    /// reading would call a covered file unrepairable.
    #[tokio::test]
    async fn described_lengths_ride_along_and_never_deny_membership() {
        const INDEX: &[u8] = include_bytes!("../../nzbkit-base/tests/fixtures/par2/testset.par2");
        let truth = crate::par2::Par2Set::parse(&[INDEX]).expect("fixture parses");
        assert!(!truth.files.is_empty(), "the fixture describes files");

        let mut articles = std::collections::HashMap::new();
        let segs = make_file_articles("testset.par2", INDEX, 64_000, "idx", &mut articles);
        let srv = MockServer::start(articles, Chaos::default()).await;
        let ids = vec![format!("<{}>", segs[0].0)];
        let probed = tokio::time::timeout(
            Duration::from_secs(20),
            probe_recovery_set(&[srv.server_config()], &ids),
        )
        .await
        .expect("probe hung")
        .expect("the index parses");

        for f in &truth.files {
            assert_eq!(
                probed.described_length(&f.name),
                Some(f.length),
                "{} was described by the fetched bytes",
                f.name
            );
            // Case is the NZB subject's business, not the packet's.
            assert_eq!(
                probed.described_length(&f.name.to_ascii_uppercase()),
                Some(f.length)
            );
        }
        assert_eq!(probed.described_files(), truth.files.len());
        assert_eq!(
            probed.described_length("a-file-this-set-never-heard-of.mkv"),
            None,
            "an undescribed name is UNKNOWN, and the caller must fall back"
        );
    }

    /// Every failure is the same answer: None, so the caller keeps
    /// saying it does not know. An article no server has, a body that is
    /// not yEnc, a par2 file carrying no Main packet, and a server that
    /// cannot be dialled at all - none of them may hand back a block
    /// size, because a wrong one licenses a verdict that stops a
    /// download.
    #[tokio::test]
    async fn nothing_the_probe_cannot_verify_becomes_a_block_size() {
        // A volume with its critical packets stripped: real PAR2 bytes,
        // real recovery slices, no Main packet anywhere in them.
        const VOL: &[u8] =
            include_bytes!("../../nzbkit-base/tests/fixtures/par2/testset.vol0+4.par2");
        let slices_only: Vec<u8> = VOL[..4_164].to_vec();
        assert!(
            crate::par2::Par2Set::parse(&[&slices_only]).is_err(),
            "the fixture prefix must genuinely lack a Main packet"
        );

        let mut articles = std::collections::HashMap::new();
        let vol = make_file_articles("v.par2", &slices_only, 64_000, "vol", &mut articles);
        let junk = make_file_articles(
            "j.bin",
            b"not a par2 file at all",
            64_000,
            "jnk",
            &mut articles,
        );
        let srv = MockServer::start(articles, Chaos::default()).await;
        let live = srv.server_config();

        let probe = |server: ServerConfig, ids: Vec<String>| async move {
            tokio::time::timeout(Duration::from_secs(20), probe_recovery_set(&[server], &ids))
                .await
                .expect("probe hung")
                .map(|p| p.block_size)
        };

        assert_eq!(
            probe(live.clone(), vec![format!("<{}>", vol[0].0)]).await,
            None,
            "recovery slices without a Main packet do not state the block size"
        );
        assert_eq!(
            probe(live.clone(), vec![format!("<{}>", junk[0].0)]).await,
            None,
            "a body that is not a par2 file is not a block size"
        );
        assert_eq!(
            probe(live.clone(), vec!["<never-posted@mock>".into()]).await,
            None,
            "an article no server has cannot be read"
        );
        assert_eq!(
            probe(live, vec![]).await,
            None,
            "nothing asked, nothing known"
        );

        let mut dead = srv.server_config();
        dead.host = "127.0.0.1".into();
        dead.port = 1;
        assert_eq!(
            probe(dead, vec!["<anything@mock>".into()]).await,
            None,
            "an undialable server answers nothing"
        );
    }

    /// A minimal PAR2 blob: one Main packet and one FileDesc per member.
    ///
    /// Local to this module on purpose, and the duplication is stated
    /// rather than hidden. `live/tests.rs` and `index/pesto.rs` each
    /// carry their own builder, both of them inside a `mod tests` this
    /// one cannot reach, and both build more than the two packet types
    /// the probe reads (an IFSC list, real per-block checksums) for
    /// questions that are not asked here. What this needs is exactly
    /// the pair of facts `ProbedSet` is made of - a block size from the
    /// Main packet, and a name and a length per FileDesc - with the SET
    /// ID as a free parameter, which is the one thing no fixture on
    /// disk gives: `tests/fixtures/par2/` holds two files of ONE set.
    ///
    /// Every packet carries a real MD5 over its own bytes, because
    /// `Par2Set::parse` drops any packet whose digest does not check
    /// out - a builder that skipped it would hand the probe an empty
    /// set and this test would pass against a gate that had gone dead.
    fn par2_blob(set_id: u8, block_size: u64, files: &[(&str, u64)]) -> Vec<u8> {
        use crate::md5fast::{Digest, Md5};
        let sid = [set_id; 16];
        let pkt = |ptype: &[u8; 16], body: &[u8]| -> Vec<u8> {
            let mut p = Vec::new();
            p.extend_from_slice(crate::par2::MAGIC);
            p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
            p.extend_from_slice(&[0u8; 16]);
            p.extend_from_slice(&sid);
            p.extend_from_slice(ptype);
            p.extend_from_slice(body);
            let md5: [u8; 16] = Md5::digest(&p[32..]).into();
            p[16..32].copy_from_slice(&md5);
            p
        };
        // File ids must be unique WITHIN a set and are keyed on the set
        // id too, so two sets describing one name stay two files.
        let fid = |i: usize| -> [u8; 16] {
            let mut f = [set_id; 16];
            f[0] = i as u8 + 1;
            f
        };
        let mut main = Vec::new();
        main.extend_from_slice(&block_size.to_le_bytes());
        main.extend_from_slice(&(files.len() as u32).to_le_bytes());
        for i in 0..files.len() {
            main.extend_from_slice(&fid(i));
        }
        let mut out = pkt(crate::par2::TYPE_MAIN, &main);
        for (i, (name, length)) in files.iter().enumerate() {
            let mut desc = Vec::new();
            desc.extend_from_slice(&fid(i));
            desc.extend_from_slice(&[0u8; 16]); // whole-file md5
            desc.extend_from_slice(&[0u8; 16]); // md5-16k
            desc.extend_from_slice(&length.to_le_bytes());
            let mut n = name.as_bytes().to_vec();
            while !n.len().is_multiple_of(4) {
                n.push(0);
            }
            desc.extend_from_slice(&n);
            out.extend(pkt(crate::par2::TYPE_FILEDESC, &desc));
        }
        out
    }

    /// Serve one article per blob and probe them together.
    ///
    /// One article each, because that is how the door sees more than
    /// one set: `parts` accumulates one decoded body per id and hands
    /// them to the parser as separate VIEWS, which is the granularity
    /// [`crate::live::pick_sets`] groups at.
    async fn probe_blobs(blobs: &[&[u8]]) -> Option<ProbedSet> {
        let mut articles = std::collections::HashMap::new();
        let ids: Vec<String> = blobs
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let segs = make_file_articles(
                    &format!("s{i}.par2"),
                    b,
                    200_000,
                    &format!("p{i}"),
                    &mut articles,
                );
                format!("<{}>", segs[0].0)
            })
            .collect();
        let srv = MockServer::start(articles, Chaos::default()).await;
        tokio::time::timeout(
            Duration::from_secs(20),
            probe_recovery_set(&[srv.server_config()], &ids),
        )
        .await
        .expect("probe hung")
    }

    /// TODO 311's last box: bytes covering more than one recovery set
    /// are PLANNED against, not declined.
    ///
    /// `Par2Set::parse` refuses the whole input the moment two packets
    /// carry different set ids, and this probe swallowed that with
    /// `.ok()?` - so a `.par2` upload holding the indexes of a
    /// per-file-set post (GH #63's shape, concatenated into one file)
    /// made pre-flight answer "I know nothing about this post" when
    /// what had really happened is that it knew about two sets.
    ///
    /// The union is what `described` wants and the assertion says why:
    /// how long is the member posted under this name has ONE answer
    /// whichever set describes it, so every member of every set is
    /// described here exactly as a single set naming all of them would
    /// be. The block size is the LARGEST set's, which is a
    /// representative and not a union, so it is pinned in both
    /// concatenation orders - it must not depend on which article of
    /// the index came back first.
    #[tokio::test]
    async fn articles_covering_two_recovery_sets_are_planned_against() {
        let a = par2_blob(0xA1, 4_096, &[("a-one.bin", 1_000), ("a-two.bin", 2_000)]);
        let b = par2_blob(0xB2, 8_192, &[("b-one.bin", 3_000)]);

        // The fixture is genuinely the refused shape, and this is what
        // the door did with it: `.ok()?`, so `None`, so every caller
        // was told the post carried no set to plan against.
        assert!(
            matches!(
                crate::par2::Par2Set::parse(&[&a, &b]),
                Err(crate::par2::Par2Error::MixedRecoverySets)
            ),
            "the fixture must be the input the old door declined"
        );

        let probed = probe_blobs(&[&a, &b]).await.expect("both sets are adopted");
        assert_eq!(probed.described_files(), 3, "every member, not one set's");
        assert_eq!(probed.described_length("a-one.bin"), Some(1_000));
        assert_eq!(probed.described_length("a-two.bin"), Some(2_000));
        assert_eq!(
            probed.described_length("b-one.bin"),
            Some(3_000),
            "the smaller set's member is described too - this is the one \
             the pre-union code answered None for"
        );
        assert_eq!(probed.block_size, 4_096, "the largest set's, not the last");

        // Which article came back first is download order and must
        // decide nothing.
        let other = probe_blobs(&[&b, &a])
            .await
            .expect("order is not a verdict");
        assert_eq!(other.block_size, 4_096);
        assert_eq!(other.described_files(), 3);
    }

    /// Two rules the union may not lose.
    ///
    /// A zero block size divides every consumer by zero and is not a
    /// set anybody posted, and `ProbedSet::block_size` promises its
    /// callers it is never one. `par2::parse_main` is what actually
    /// holds that - it refuses a zero slice size, so such a Main packet
    /// never becomes a set at all - and this pins the promise at the
    /// door rather than at the parser, because the door is what the
    /// caller reads. The retain inside `probe_par2_sets` is the belt
    /// behind it and cannot fire today, which is stated at its own site
    /// rather than dressed up as a live check here. And a name two SETS
    /// describe with different lengths
    /// identifies no single file, exactly as a name two MEMBERS of one
    /// set disagree about does: the caller must be told nothing rather
    /// than one of the two, because a length attached to the wrong file
    /// misplaces that file's block grid.
    #[tokio::test]
    async fn the_union_keeps_the_zero_block_and_ambiguous_name_rules() {
        let good = par2_blob(0x11, 4_096, &[("keep.bin", 100), ("shared.bin", 500)]);
        let zero = par2_blob(0x22, 0, &[("divides-by-zero.bin", 200)]);

        let probed = probe_blobs(&[&good, &zero])
            .await
            .expect("the good set survives");
        assert_eq!(probed.block_size, 4_096, "never a zero block size");
        assert_eq!(probed.described_length("keep.bin"), Some(100));
        assert_eq!(
            probed.described_length("divides-by-zero.bin"),
            None,
            "no set, so nothing of it reaches the union either"
        );

        // Nothing left once that is all there was: `None`, so the
        // caller's loop moves on to the NEXT server rather than
        // settling for a block size no consumer could divide by.
        assert!(
            probe_blobs(&[&zero]).await.is_none(),
            "a lone zero-block set is no answer at all"
        );

        // Two sets, one name, two lengths.
        let rival = par2_blob(0x33, 4_096, &[("shared.bin", 999)]);
        let probed = probe_blobs(&[&good, &rival])
            .await
            .expect("both sets adopted");
        assert_eq!(
            probed.described_length("shared.bin"),
            None,
            "two sets disagreeing about a name identify neither"
        );
        assert_eq!(
            probed.described_length("keep.bin"),
            Some(100),
            "and the disagreement is scoped to the name, not the probe"
        );
    }

    /// The second id is not decoration: a recovery volume interleaves
    /// its critical packets between slices, so the Main copy can sit
    /// megabytes past the first article. The probe passes head AND tail
    /// and `Par2Set::parse` takes them as separate inputs, so a Main
    /// packet found in either one settles it.
    #[tokio::test]
    async fn the_tail_article_answers_when_the_head_does_not() {
        const VOL: &[u8] =
            include_bytes!("../../nzbkit-base/tests/fixtures/par2/testset.vol0+4.par2");
        let mut articles = std::collections::HashMap::new();
        // Head: slices only, no Main. Tail: the rest, which carries it.
        let head = make_file_articles("v.par2", &VOL[..4_164], 64_000, "h", &mut articles);
        let tail = make_file_articles("v.par2", &VOL[4_164..], 64_000, "t", &mut articles);
        let srv = MockServer::start(articles, Chaos::default()).await;

        let ids = vec![format!("<{}>", head[0].0), format!("<{}>", tail[0].0)];
        let bs = tokio::time::timeout(
            Duration::from_secs(20),
            probe_recovery_set(&[srv.server_config()], &ids),
        )
        .await
        .expect("probe hung")
        .map(|p| p.block_size);
        assert_eq!(bs, Some(4_096));
    }

    #[test]
    fn stratified_edges() {
        assert_eq!(stratified_sample(10, 2), vec![0, 9]);
        assert_eq!(stratified_sample(5, 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(stratified_sample(5, 100), vec![0, 1, 2, 3, 4]);
        assert_eq!(stratified_sample(0, 3), Vec::<usize>::new());
        let s = stratified_sample(1000, 100);
        assert_eq!(s[0], 0);
        assert_eq!(*s.last().unwrap(), 999);
        assert!(s.len() >= 99 && s.len() <= 100);
    }

    #[test]
    fn stratified_edge_redundancy() {
        // With budget >= 5 the head gets three probes and the tail two,
        // so one flaky edge answer cannot blind a verdict.
        let s = stratified_sample(10_000, 8);
        assert_eq!(s.len(), 8);
        assert!(s.starts_with(&[0, 1, 2]));
        assert!(s.ends_with(&[9_998, 9_999]));
        // Interior points stay strictly between the edge blocks.
        assert!(s[3..6].iter().all(|&i| i > 2 && i < 9_998));
        // Deterministic: the identical call samples the identical
        // indexes (the re-probe overwrite depends on it).
        assert_eq!(s, stratified_sample(10_000, 8));
        // Tight budgets keep one probe per edge.
        assert_eq!(stratified_sample(100, 3)[0], 0);
        assert_eq!(*stratified_sample(100, 3).last().unwrap(), 99);
        // n one over the edge-block size still covers both edges.
        let s = stratified_sample(10, 6);
        assert!(s.starts_with(&[0, 1, 2]) && s.ends_with(&[8, 9]));
    }

    /// The probe's byte budget has to bound the READ.
    ///
    /// `MAX_PROBE_BYTES` was checked before `Connection::body` and
    /// incremented only after the whole response was buffered, so the
    /// first article was never gated at all and the only real bound was
    /// the wire's `MAX_MULTILINE_BYTES` - 256 MiB, 32x the budget - and
    /// a successful body was then decoded into a second body-sized Vec
    /// beside it. `body_capped` stops the read at the caller's
    /// allowance instead, which is what makes the budget a budget on the
    /// NAS and Pi builds this ships to.
    #[tokio::test]
    async fn a_capped_body_stops_reading_at_the_caller_s_allowance() {
        let mut articles = std::collections::HashMap::new();
        let big: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let segs = make_file_articles("big.bin", &big, 200_000, "cap", &mut articles);
        let id = format!("<{}>", segs[0].0);
        let posted = segs[0].1 as usize;
        assert!(
            posted > 100_000,
            "the fixture must outrun the cap under test"
        );

        let srv = MockServer::start(articles, Chaos::default()).await;
        let cfg = srv.server_config();

        // Under the allowance: the whole article comes back.
        let (mut conn, _) = Connection::connect(&cfg).await.unwrap();
        let got = conn.body_capped(&id, posted * 2).await.unwrap();
        assert_eq!(got.map(|b| b.len()), Some(posted));
        conn.quit().await;

        // Over it: refused mid-body rather than buffered whole and
        // audited afterwards.
        let (mut conn, _) = Connection::connect(&cfg).await.unwrap();
        let err = conn.body_capped(&id, 8_192).await.unwrap_err();
        assert!(
            matches!(err, crate::nntp::NntpError::TooLarge(8_192)),
            "expected the read to stop at the cap, got {err:?}"
        );
        conn.quit().await;
    }

    /// A leg whose replies are SHIFTED by one must leave every cell
    /// Unknown, never file the wrong verdict against the article behind
    /// the one that went unanswered.
    ///
    /// The pipelined sweep tracks its ids in a positional queue, and
    /// until 28 Aug 2026 it read them with the bare `read_stat`, which
    /// returns the verdict and validates nothing. A server or an
    /// upstream frontend that under-replies once puts every later reply
    /// on that leg against the wrong article for the rest of the leg -
    /// so a 430 the server meant for id 1 is filed as MISSING against
    /// id 0, `union_missing` names articles the server actually holds,
    /// and on a big enough post that is a false Impossible fast-abort.
    /// `read_stat_checked` catches it on the first reply, before any
    /// store, so the cell it was reading and every cell behind it stay
    /// Unknown - and an Unknown never condemns an article.
    ///
    /// The mock cannot express this (its STAT arm always answers, and
    /// always echoes), so the server here is a bespoke listener that
    /// swallows the first STAT, answers the rest with an echoing 430,
    /// and then closes. Reverting the call site to `read_stat` fails
    /// this test with three MISSING cells and a `union_missing` naming
    /// ids 0 to 2.
    #[tokio::test]
    async fn a_leg_whose_replies_are_shifted_leaves_unknowns_and_never_condemns() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        // The fixture's id count, known to both ends: the listener
        // closes once it has consumed them all rather than sitting on
        // the last unanswered slot, so the leg ends on a read error in
        // seconds instead of on the sweep's 20 s reply timeout. That
        // matters for the PRE-FIX behaviour too - reverting the call
        // site must fail this test fast, not after a stall.
        const NIDS: usize = 4;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            w.write_all(b"200 shifted mock ready\r\n").await.unwrap();
            let mut seen = 0usize;
            let mut line = String::new();
            while {
                line.clear();
                r.read_line(&mut line).await.unwrap_or(0) > 0
            } {
                let Some(id) = line.trim().strip_prefix("STAT ") else {
                    continue;
                };
                seen += 1;
                // The under-reply: the first STAT is consumed and never
                // answered, so every reply after it lands one slot early.
                if seen == 1 {
                    continue;
                }
                // Echoing the id is what makes the desync detectable at
                // all; a provider that echoes nothing is invisible here
                // and is exactly why a missing id must not be an error.
                if w.write_all(format!("430 no such article {id}\r\n").as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                if seen == NIDS {
                    return;
                }
            }
        });

        // A template config for a listener the mock never started: the
        // sweep needs every field, and only the address differs.
        let template = MockServer::start(Default::default(), Chaos::default()).await;
        let mut cfg = template.server_config();
        cfg.host = addr.ip().to_string();
        cfg.port = addr.port();

        let ids: Vec<String> = (0..NIDS).map(|i| format!("<shift-{i}@mock>")).collect();
        let out = tokio::time::timeout(
            Duration::from_secs(20),
            stat_sweep(&[cfg], &ids, 1, ids.len()),
        )
        .await
        .expect("the shifted sweep hung");

        assert_eq!(
            out.server_counts(0),
            (0, 0, ids.len()),
            "a desynced leg may not bank a single verdict"
        );
        assert!(
            out.union_missing().is_empty(),
            "a shifted refusal must never condemn an article"
        );
    }
}
