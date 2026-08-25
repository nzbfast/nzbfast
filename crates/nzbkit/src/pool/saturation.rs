// TODO 202: line-speed-aware racing, and the pool's racing ledger.
//
// THE PROBLEM, measured on a 1 GbE M1 Ultra rig (release-tv4, 21 Aug
// 2026). Every speculative dup the pool issues - tail fan-out, the
// slow-owner race, the staleness hedge - buys a second copy of a body
// somebody else is already delivering. That is a good trade when the
// line has spare capacity: the copy rides idle wire and the earlier of
// the two answers closes the tail. It is a straight loss when the line
// is the bottleneck: the copy displaces payload byte for byte, and the
// job finishes LATER by exactly the duplicate's transfer time. Priced:
//
//   line      dups   won   dup spend    at line rate   wall over floor
//   1 Gbps    ~660   ~100  425-540 MB   ~3.8 s         +6 s
//   250 Mbit  ~870   ~400  522-728 MB   ~22 s          +18 s
//
// The "won" column is the trap. At 250 Mbit nearly half the dups won
// their race - a fresh connection is first in its own pipeline while
// the owner's copy sits four deep - so every per-article rule reads
// racing as a success, while the fleet as a whole moves ~700 MB it
// throws away, on a pipe that was full the whole time. The loser's
// body still has to be read (NNTP has no cancel short of closing the
// socket), so a win here is a copy, never a saving.
//
// None of the per-article gates can see this. Staleness judges one
// article's age; slow-owner judges two servers' shares; fan-out judges
// one worker's idleness. Whether the LINE has room is a fleet-level
// question, and the pool is the only place it can be asked from - the
// daemon's `linkpeak` anchor is a dashboard quantity the CLI never has.
//
// THE GATE. Two fleet-wide delivered-byte EWMAs, fed from the 222 body
// path only (so probe traffic never trains them): a 10 s half-life
// whose run-best value is the line's observed peak, and a 1 s
// half-life that says what the fleet is doing NOW.
//
// WHAT FEEDS THEM, and why it is the chunk and not the body (TODO
// 208.2, the over-read). Until 22 Aug 2026 both windows were folded
// once per DELIVERED body, beside the per-server steering EWMA. A
// body is credited at the instant it completes, but its bytes crossed
// the line over the whole transfer before that - and the gauge's age
// starts at its first fold. So every body in flight at that instant
// (on a fleet dialled together, every connection's first body) landed
// in a clump credited to a window that had barely opened. Measured: a
// `line peak` of 695 KB/s for a 400 KB/s line on the fault rig with
// eight connections dialled at once (+74%), 37.3 MB/s through a
// 248 Mbit (31 MB/s) pipe and 15.7-16.9 MB/s at fleet 360 through
// 99 Mbit against 13.6 at fleet 50 on the banked shaped legs - rising
// with the fleet, as a clump would. The peak is a run max, so the
// over-read persisted: every share-aware stall bound short by that
// share, the gate reading LESS saturated against an inflated peak
// (66-71% at fleet 360 against 91-92% at fleet 25 on the 100 Mbit
// ladder), and the §208.1 cap sized from it.
//
// Aging the gauge from an earlier origin (pool start, the first dial,
// the first fold less the first body's transfer) cures the clump and
// exposes its mirror: bytes in flight at the READING instant are
// invisible to a per-body fold, so against a longer age the peak
// under-reads by the pipeline's fill (N x body / 2 over the age - half
// the line at the first training on a 360-socket 100 Mbit fleet)
// until the EWMA forgets it ~45 s later, and `line_cap_tick`, which
// reads `max(anchor, peak)`, would shed a CLI fleet on that dip and
// re-dial it. The exact fix is to credit bytes when they land: the
// body reader reports every chunk it takes off the wire
// (`nntp::Arrivals`, `Shared::note_arrival`), so nothing is in flight
// at either instant, the first fold IS the first byte, and a
// supply-bound 10 GbE short job sees its first chunk milliseconds
// after the first dispatch - the same origin the first-fold rule gave
// it, which is what that rule was chosen for. `PoolConfig::
// peak_arrivals` (env NZBFAST_PEAK_ARRIVALS=0) restores the per-body
// fold as the A/B arm. The per-server steering EWMA, the §208.1 tick
// and the body-size EWMA still ride the delivered body; they are
// per-server ratios and once-a-second readers, not line gauges.
// While the now-rate is within `race_sat_pct` of the peak the line is
// saturated and every SPECULATIVE picker stands down; the endgame 430
// ladder is exempt (its bytes buy a verdict, not a copy). Both EWMAs
// are bias-corrected for warm-up, so a 7 s job at 10 GbE trains a
// true peak instead of a 40%-of-true one that would read the whole
// run as saturated.
//
// Why this opens at the right moment, and closes at the right one. On
// a line-bound tail the remaining connections speed up as their
// neighbours finish, so the now-rate HOLDS near peak until the last
// few articles - racing stays off through the 50 s of pipeline
// backlog a 360-connection fleet drains at 250 Mbit, and comes back
// for the stragglers at the very end, where the pipe has room and a
// sibling session really does beat a starved one. On a supply-bound
// tail (10 GbE, where the providers and not the port set the ceiling)
// each finished connection takes its share of the rate with it, so
// the now-rate falls with the connection count and the gate opens
// within the first second of the drain - which is where the fan-out's
// measured payout (farm: tail 1.66 s -> 0.60 s) lives.
//
// Also here: the pool's racing ledger (`report_diagnostics`, the
// `[pool]` summary line the bench legs are read from) and the burst
// marker, moved out of pool.rs under the size gate - they are what
// racing REPORTS, one subject with the gate that decides it.

use super::*;

/// Half-life of the peak-tracking accumulator: the same ~10 s as the
/// per-server steering signal, long enough that a sustained plateau
/// and not a burst defines "what this line can do".
const SAT_SLOW_HALF_MS: u64 = 10_000;
/// Half-life of the now-rate accumulator. One second follows a tail's
/// taper within the drain at 10 GbE (~1.5 s end to end) while still
/// averaging a dozen article arrivals at 100 Mbit.
const SAT_FAST_HALF_MS: u64 = 1_000;

fn tau_ms(half_ms: u64) -> f64 {
    half_ms as f64 / std::f64::consts::LN_2
}

/// Decay an accumulator by `dt_ms` of silence.
fn decay(val: u64, dt_ms: u64, half_ms: u64) -> u64 {
    if dt_ms == 0 {
        return val;
    }
    (val as f64 * (-(dt_ms as f64) / tau_ms(half_ms)).exp()) as u64
}

/// Read an accumulator (already decayed to now) as B/s, corrected for
/// warm-up: an EWMA fed for `age_ms` has only filled `1 - e^(-age/tau)`
/// of its window, and dividing by that fraction recovers the true
/// mean rate over the span actually observed. `None` under a quarter
/// of a time constant - too little evidence to correct.
fn corrected_rate(val: u64, age_ms: u64, half_ms: u64) -> Option<f64> {
    let tau = tau_ms(half_ms);
    if (age_ms as f64) < tau / 4.0 {
        return None;
    }
    let fill = 1.0 - (-(age_ms as f64) / tau).exp();
    Some(val as f64 / (tau / 1000.0) / fill)
}

/// One windowed accumulator with its last-fold stamp (ms since pool
/// start; u64::MAX = never fed).
struct Window {
    val: AtomicU64,
    at: AtomicU64,
    half_ms: u64,
}

impl Window {
    const fn new(half_ms: u64) -> Self {
        Window {
            val: AtomicU64::new(0),
            at: AtomicU64::new(u64::MAX),
            half_ms,
        }
    }

    /// Fold `n` bytes at `now`. Lock-free and approximate exactly like
    /// `Shared::note_srv_bytes`: the stamp swap claims the decay span,
    /// a load/store race can drop the odd body, and an ~800 KB
    /// undercount against a multi-second window moves no gate.
    fn fold(&self, now: u64, n: u64) -> u64 {
        let prev = self.at.swap(now, Ordering::Relaxed);
        let dt = if prev == u64::MAX {
            0
        } else {
            now.saturating_sub(prev)
        };
        let v = decay(self.val.load(Ordering::Relaxed), dt, self.half_ms).saturating_add(n);
        self.val.store(v, Ordering::Relaxed);
        v
    }

    /// The accumulator decayed to `now`, without folding.
    fn read(&self, now: u64) -> u64 {
        let prev = self.at.load(Ordering::Relaxed);
        if prev == u64::MAX {
            return 0;
        }
        decay(
            self.val.load(Ordering::Relaxed),
            now.saturating_sub(prev),
            self.half_ms,
        )
    }
}

/// Which picker issued a dup - the ledger's per-rule columns. The
/// index order is the summary line's order.
#[derive(Clone, Copy)]
pub(super) enum Rule {
    Fanout = 0,
    SlowOwner = 1,
    Stale = 2,
    Ladder = 3,
}

impl Rule {
    pub(super) fn from_name(rule: &str) -> Self {
        match rule {
            "ladder" => Rule::Ladder,
            "stale" => Rule::Stale,
            "fanout" => Rule::Fanout,
            _ => Rule::SlowOwner, // "slow-owner" and its envelope twin
        }
    }
}

/// The fleet-level line gauge and the racing ledger. One per pool,
/// held by `Shared`; every field is atomic so the hot paths that feed
/// it take no lock.
pub(super) struct Saturation {
    slow: Window,
    fast: Window,
    /// ms-since-start of the first fold (u64::MAX = untrained).
    first_ms: AtomicU64,
    /// Run-best corrected slow-window rate, B/s. 0 = no peak yet.
    peak_bps: AtomicU64,
    /// Gate threshold, percent of peak. 0 = gate off.
    pct: u8,
    /// TODO 208.2 warm-up: [`PoolConfig::stall_live`], fleet-wide.
    pub(super) stall_live: bool,
    /// TODO 208.2 over-read: [`PoolConfig::peak_arrivals`], fleet-wide.
    /// On, the windows are fed per arriving chunk through
    /// [`Shared::note_arrival`] and the per-body fold only mirrors the
    /// tail latch; off, the per-body fold feeds them (module doc).
    pub(super) arrivals: bool,
    /// The queue-dry latch as the per-body path last saw it, so the
    /// per-chunk fold reads a bool instead of taking the latch's mutex
    /// on every socket read.
    tail: AtomicBool,
    /// ms the run spent saturated, total and with the tail latched -
    /// the ledger's "how long the gate held" columns, accumulated at
    /// fold time as a proxy for the picker's view.
    sat_ms: AtomicU64,
    sat_tail_ms: AtomicU64,
    /// Dups issued per [`Rule`].
    by_rule: [AtomicU64; 4],
    /// TODO 202 §17: dups the per-article escape let through a SHUT
    /// gate - see [`Shared::not_using_the_line`].
    escapes: AtomicU64,
}

impl Saturation {
    /// The gate's threshold is the fleet MAX of `race_sat_pct`; the
    /// stall bound's liveness is `any`-folded like `race_escape`.
    pub(super) fn new(servers: &[(ServerConfig, PoolConfig)]) -> Self {
        Saturation {
            slow: Window::new(SAT_SLOW_HALF_MS),
            fast: Window::new(SAT_FAST_HALF_MS),
            first_ms: AtomicU64::new(u64::MAX),
            peak_bps: AtomicU64::new(0),
            pct: servers
                .iter()
                .map(|(_, c)| c.race_sat_pct)
                .max()
                .unwrap_or(0),
            stall_live: servers.iter().any(|(_, c)| c.stall_live),
            arrivals: servers.iter().any(|(_, c)| c.peak_arrivals),
            tail: AtomicBool::new(false),
            sat_ms: AtomicU64::new(0),
            sat_tail_ms: AtomicU64::new(0),
            by_rule: [const { AtomicU64::new(0) }; 4],
            escapes: AtomicU64::new(0),
        }
    }

    /// Test seam: a gauge at a threshold, with no fleet behind it.
    #[cfg(test)]
    pub(super) fn with_pct(pct: u8) -> Self {
        let mut s = Saturation::new(&[]);
        s.pct = pct;
        s
    }

    fn age_ms(&self, now: u64) -> Option<u64> {
        match self.first_ms.load(Ordering::Relaxed) {
            u64::MAX => None,
            f => Some(now.saturating_sub(f)),
        }
    }

    /// The per-body path's half of the arrivals arm: the fold itself
    /// happens per chunk in [`Shared::note_arrival`], and this only
    /// mirrors the tail latch for it.
    pub(super) fn note_body_tail(&self, tail: bool) {
        self.tail.store(tail, Ordering::Relaxed);
    }

    /// Fold a chunk of `n` bytes that arrived on one connection over
    /// `[prev, now]` (ms since pool start; `prev` = that connection's
    /// previous chunk, or its read's start). The gauge's origin is its
    /// first fold, and only the part of the span AFTER the origin is
    /// credited - the first fold itself credits nothing, because all
    /// of its bytes arrived before the instant that opened the window.
    /// That is what keeps a fleet dialled together (the fault rigs; a
    /// queue hand-over onto idle sockets) from landing every
    /// connection's first chunk as one clump at age 0: `conns x chunk`
    /// is a small clump, +14% on the rig's eight 64 KB chunks, but it
    /// is the same shape as the body-sized one this arm exists to
    /// remove, and the chunk's own interval is enough to spread it.
    pub(super) fn note_chunk(&self, now: u64, prev: u64, n: u64, tail: bool) {
        let origin = match self.first_ms.compare_exchange(
            u64::MAX,
            now,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => now,
            Err(o) => o,
        };
        let credit = if prev >= origin {
            n
        } else if now <= origin {
            0
        } else {
            // prev < origin < now, so the divisor is positive; n is one
            // chunk through a 256 KiB buffer, the product fits easily.
            n * (now - origin) / (now - prev)
        };
        self.note_bytes(now, credit, tail);
    }

    /// Fold `n` bytes at `now` (ms since pool start) - a delivered
    /// body, or through [`Self::note_chunk`] a chunk as it lands;
    /// `tail` = the queue-dry latch is set. Trains the peak once the
    /// slow window has half a time constant of evidence - a plateau,
    /// not the first burst.
    pub(super) fn note_bytes(&self, now: u64, n: u64, tail: bool) {
        let _ = self
            .first_ms
            .compare_exchange(u64::MAX, now, Ordering::Relaxed, Ordering::Relaxed);
        let prev_at = self.fast.at.load(Ordering::Relaxed);
        let was_sat = self.saturated(now);
        let slow = self.slow.fold(now, n);
        self.fast.fold(now, n);
        if let Some(age) = self.age_ms(now)
            && age as f64 >= tau_ms(SAT_SLOW_HALF_MS) / 2.0
            && let Some(r) = corrected_rate(slow, age, SAT_SLOW_HALF_MS)
        {
            self.peak_bps.fetch_max(r as u64, Ordering::Relaxed);
        }
        if was_sat && prev_at != u64::MAX {
            let dt = now.saturating_sub(prev_at);
            self.sat_ms.fetch_add(dt, Ordering::Relaxed);
            if tail {
                self.sat_tail_ms.fetch_add(dt, Ordering::Relaxed);
            }
        }
    }

    /// The fleet's now-rate in B/s (1 s half-life, warm-up corrected),
    /// `None` until trained.
    pub(super) fn now_rate(&self, now: u64) -> Option<f64> {
        corrected_rate(self.fast.read(now), self.age_ms(now)?, SAT_FAST_HALF_MS)
    }

    /// Is the line saturated - no spare capacity for a speculative copy
    /// to ride? False while the gate is off, before a peak is trained,
    /// or whenever the now-rate has fallen under `pct`% of it.
    pub(super) fn saturated(&self, now: u64) -> bool {
        if self.pct == 0 {
            return false;
        }
        let peak = self.peak_bps.load(Ordering::Relaxed);
        if peak == 0 {
            return false;
        }
        match self.now_rate(now) {
            Some(r) => r * 100.0 >= peak as f64 * self.pct as f64,
            None => false,
        }
    }

    /// The trained line peak in B/s, 0 until the slow window has half a
    /// time constant of evidence. Monotone over the run.
    pub(super) fn peak_bps(&self) -> u64 {
        self.peak_bps.load(Ordering::Relaxed)
    }

    /// TODO 208.2 (warm-up): the best line estimate available for the
    /// stall bound RIGHT NOW. The trained peak once there is one;
    /// before that, the slow window's own corrected rate as soon as it
    /// has a quarter time constant of evidence (~3.6 s after the first
    /// body, against the ~7.2 s the peak waits for a plateau). The
    /// provisional figure is safe in the direction that matters: it is
    /// a rate measured THROUGH the line, so it cannot sit above the
    /// line for long, and the bound it yields is clamped to the same
    /// floor and ceiling as the trained one. 0 = no evidence yet.
    pub(super) fn line_estimate_bps(&self, now: u64) -> u64 {
        match self.peak_bps.load(Ordering::Relaxed) {
            0 => self
                .age_ms(now)
                .and_then(|age| corrected_rate(self.slow.read(now), age, SAT_SLOW_HALF_MS))
                .map_or(0, |r| r as u64),
            p => p,
        }
    }

    /// Test seam: set the trained peak directly (training needs
    /// wall-clock evidence the unit tests cannot wait for).
    #[cfg(test)]
    pub(super) fn set_peak_bps(&self, bps: u64) {
        self.peak_bps.store(bps, Ordering::Relaxed);
    }

    /// TODO 202 §17: dups the per-article escape let through a shut
    /// gate, for the ledger and its guards.
    pub(super) fn escapes(&self) -> u64 {
        self.escapes.load(Ordering::Relaxed)
    }

    pub(super) fn tally(&self, rule: Rule) {
        self.by_rule[rule as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The ledger's gate fragment of the `[pool]` line: empty until a
    /// peak trained, so short runs keep their exact log shape.
    fn summary(&self, run_ms: u64, tail_ms: Option<u64>) -> String {
        let peak = self.peak_bps.load(Ordering::Relaxed);
        if peak == 0 {
            return String::new();
        }
        let pct = |num: u64, den: u64| (num * 100).checked_div(den).unwrap_or(0);
        let sat = self.sat_ms.load(Ordering::Relaxed);
        let mut s = format!(
            " · line peak {:.1} MB/s · saturated {}% of run",
            peak as f64 / 1e6,
            pct(sat, run_ms.max(1)),
        );
        if let Some(t) = tail_ms {
            s.push_str(&format!(
                " {}% of tail",
                pct(self.sat_tail_ms.load(Ordering::Relaxed), t)
            ));
        }
        let esc = self.escapes();
        if esc > 0 {
            s.push_str(&format!(" · {esc} stalled-article escapes"));
        }
        s
    }

    fn rules_line(&self) -> String {
        let r = |i: usize| self.by_rule[i].load(Ordering::Relaxed);
        format!(
            "fanout {} slow-owner {} stale {} ladder {}",
            r(0),
            r(1),
            r(2),
            r(3)
        )
    }
}

impl Shared {
    /// TODO 208.2 over-read: `n` bytes just came off a 222 body's wire
    /// (the reader's [`crate::nntp::Arrivals`] sink, one call per chunk
    /// through its 256 KiB buffer). Folds them into the line gauge at
    /// this instant, which is what makes the peak a measure of the
    /// LINE rather than of when bodies happen to complete (module
    /// doc). `last` is the calling read's own stamp of its previous
    /// chunk (seeded with the read's start), so the gauge knows the
    /// span the chunk arrived over. Lock-free: a swap on that stamp,
    /// two relaxed atomics per window and a tail bool.
    pub(super) fn note_arrival(&self, n: u64, last: &AtomicU64) {
        let now = self.start.elapsed().as_millis() as u64;
        let prev = last.swap(now, Ordering::Relaxed);
        self.sat
            .note_chunk(now, prev, n, self.sat.tail.load(Ordering::Relaxed));
    }

    /// Is the line saturated right now? The speculative pickers'
    /// fleet-level gate (see the module doc).
    pub(super) fn line_saturated(&self, now_ms: u64) -> bool {
        self.sat.saturated(now_ms)
    }

    /// TODO 202 §17: the per-ARTICLE escape from that gate.
    ///
    /// The gate's argument is "on a saturated line the copy displaces
    /// payload byte for byte". That is true of a SLOW owner and false
    /// of a STALLED one: an article whose read has sat in PRE-BYTE
    /// silence past the suspicion bound has moved no bytes at all, so
    /// its owner is not competing for the line and the copy displaces
    /// nothing. Racing it costs the line one dup and saves the read
    /// timeout - 30 s of a tail article going nowhere.
    ///
    /// The escape exists because the gate is a FLEET aggregate and
    /// hedging answers a per-article question. Measured (§17b): feed
    /// the gauge a plateau from `n` connections and stall exactly one,
    /// and the gate opens only at `n` under 5 - one stall of `n`
    /// leaves `(n-1)/n` of the rate, and `(n-1)/n < 0.80` needs
    /// `n < 5` (at the shipped 70, `n < 4` - stricter still, so the
    /// conclusion only firms up). `PoolConfig::default()` is 6
    /// connections, installs run
    /// ~100 and the bench runs 360, so at every fleet size that ships,
    /// one wedged connection is invisible to the gauge. That is the
    /// exact shape the rescue exists for, and the aggregate is
    /// structurally incapable of seeing it.
    ///
    /// This does NOT reopen racing on a saturated line generally. On a
    /// healthy one the status line arrives in tens of milliseconds and
    /// nothing is ever marked, so the gate stands intact; and the
    /// escape can only ever restore a dup the pre-gate code would
    /// already have issued, on the narrow subset of articles that have
    /// proven they are delivering nothing.
    ///
    /// [`PoolConfig::race_escape`] switches it off, so the escape's own
    /// payout is an A/B on ONE binary rather than two builds.
    pub(super) fn not_using_the_line(&self, inf: &Inflight) -> bool {
        self.race_escape && inf.suspect
    }

    /// Ledger: a speculative dup that the per-article escape above let
    /// through a shut gate. Counted so a leg can tell "the gate held
    /// and nothing needed rescuing" from "the gate held and the
    /// stragglers were rescued anyway".
    pub(super) fn note_line_gate_escape(&self) {
        self.sat.escapes.fetch_add(1, Ordering::Relaxed);
    }

    /// Called after each duplicate dispatch is issued. Emits at most one
    /// run-level `racing` marker per [`BURST_WINDOW_MS`], and only for a
    /// window holding at least [`RACE_BURST`] dups+hedges - the endgame
    /// of a healthy job issues a handful and must not mark the graph.
    pub(super) fn note_race_burst(&self) {
        let Some(live) = &self.live else {
            return;
        };
        let total = self.dups_issued.load(Ordering::Relaxed)
            + self.hedges_issued.load(Ordering::Relaxed)
            + self.ttfb_hedges_issued.load(Ordering::Relaxed);
        let now = now_ms();
        let opened = self.race_note_at.load(Ordering::Relaxed);
        if opened == 0 {
            if self
                .race_note_at
                .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.races_at_note
                    .store(total.saturating_sub(1), Ordering::Relaxed);
            }
            return;
        }
        if now.saturating_sub(opened) < BURST_WINDOW_MS {
            return;
        }
        if self
            .race_note_at
            .compare_exchange(opened, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let since = total.saturating_sub(self.races_at_note.swap(total, Ordering::Relaxed));
        if since >= RACE_BURST {
            live.note_run(
                "racing",
                format!(
                    "{since} duplicate fetches issued in the last {} seconds - \
                     racing slow articles so the job can finish",
                    BURST_WINDOW_MS / 1000
                ),
            );
        }
    }

    /// TODO 208.2: the mid-body stall bound for the next read, from the
    /// fleet's trained line peak shared across every live worker and
    /// the run's mean delivered body size. See
    /// [`super::pacing::share_aware_stall_ms`] for the arithmetic and
    /// why the peak rather than the now-rate feeds it.
    ///
    /// The sharer count is the live workers OR the articles still to
    /// deliver (queued + in flight), whichever is fewer. Mid-run they
    /// are the same number; at the queue-dry tail the second one falls
    /// with every completion, the implied share rises, and the bound
    /// walks back down to the flat floor. That matters because on a
    /// saturated slow line the §202 gate has stood the dup races down
    /// (research/TODO-202 note §17: a fleet gauge cannot see one wedged
    /// connection), so this deadline is the only rescue a wedged
    /// last-article has - and the tail is where one wedge is the wall.
    ///
    /// The line rate it divides (TODO 208.2 warm-up, behind
    /// [`PoolConfig::stall_live`]): the run's trained peak once
    /// there is one; until then the daemon's persisted link anchor
    /// (`PoolConfig::line_anchor_bps`, stamped per job from the second
    /// job on a fresh install - the same figure the §208.1 seed was
    /// sized from), and failing that the gauge's provisional reading
    /// ([`Saturation::line_estimate_bps`]). Before this the bound was
    /// the flat floor until the peak trained - 7.2 s after the FIRST
    /// delivered body, which on a 100 Mbit line under 360 connections
    /// lands 10-27 s into the run - so the whole first wave of bodies,
    /// read during the fleet's slow-start storm, was judged by the
    /// 8 s floor. Sampled before every socket wait (`StallBound::Live`
    /// in the nntp reader), not once per read, for the same reason.
    pub(super) fn stall_bound(&self) -> Duration {
        self.stall_bound_at(self.start.elapsed().as_millis() as u64)
    }

    /// [`Self::stall_bound`] at a given pool instant (ms since start).
    pub(super) fn stall_bound_at(&self, now: u64) -> Duration {
        // DIALLING, not live: a fleet that spawns above its live target
        // and parks the surplus (TODO 112's walker, TODO 277's fleet
        // headroom) is not splitting the line that many ways, and
        // counting the parked workers here would stretch this deadline
        // in proportion. See `Shared::workers_dialling`.
        let live = self.workers_dialling();
        // `pending` is every non-terminal article - queued AND in
        // flight (see `Shared::pending`) - so it is the sharer count on
        // its own. Adding `inflight.len()` counted the in-flight ones
        // twice and held the tail bound off its floor for longer than
        // the arithmetic says (bug sweep 22 Aug 2026).
        let left = self.pending.load(Ordering::Relaxed);
        let line = match self.sat.peak_bps() {
            0 if self.sat.stall_live => {
                let anchor = self.line_cap.anchor_bps;
                if anchor > 0 {
                    anchor
                } else {
                    self.sat.line_estimate_bps(now)
                }
            }
            p => p,
        };
        Duration::from_millis(super::pacing::share_aware_stall_ms(
            self.body_bytes_ewma.load(Ordering::Relaxed),
            line,
            live.min(left),
        ))
    }

    /// The `[pool]` summary line. The bench drivers read dups, hedges,
    /// dup spend and the tail timings straight off it, so its shipped
    /// prefix is stable; the TODO 202 columns (per-rule split, line
    /// peak, saturated share) append after it.
    pub(super) fn report_diagnostics(&self) {
        let dups = self.dups_issued.load(Ordering::Relaxed);
        let wins = self.dup_wins.load(Ordering::Relaxed);
        // `hedges` is the STALE tally alone - the leg-log decoder relies
        // on `dups - hedges` being the fan-out plus slow-owner arms.
        // The TTFB purse (§17c) prints beside it only when it spent.
        let hedges = self.hedges_issued.load(Ordering::Relaxed);
        let art = self.art_ms.load(Ordering::Relaxed);
        let mut spend = self.dup_spend_line();
        let ttfb = self.ttfb_hedges_issued.load(Ordering::Relaxed);
        if ttfb > 0 {
            spend = format!(" · {ttfb} ttfb hedges{spend}");
        }
        let ts = *self.tail_started.lock_ok();
        let da = *self.drained_at.lock_ok();
        let run = self.start.elapsed().as_secs_f64();
        let run_ms = self.start.elapsed().as_millis() as u64;
        let tail_ms = ts.map(|t| t.elapsed().as_millis() as u64);
        let rules = self.sat.rules_line();
        let sat = self.sat.summary(run_ms, tail_ms);
        // TODO 208 item 3: proof the taper arm took, and how far it
        // walked. Absent when disarmed; `never bit` when armed on a job
        // whose queue never fell under `window x conns` (a short job, or
        // a fleet that never held its depth), which is a legitimate
        // outcome and NOT the same as an env var that failed to arrive.
        let taper = if self.tail_taper {
            match self.taper_min.load(Ordering::Relaxed) {
                usize::MAX => " · taper armed, never bit".to_string(),
                d => format!(" · taper armed, min depth {d}"),
            }
        } else {
            String::new()
        };
        // Part-mismatch steers are NOT dups: each is a full extra BODY
        // that no other tally shows, which is how tv4-rot1's 2x stayed
        // invisible across five releases. Printed only when it fired.
        let steers = match self.part_latch.steers.load(Ordering::Relaxed) {
            0 => String::new(),
            n if self.part_latch.any_off() => {
                format!(" · {n} part steers (gate stood down)")
            }
            n => format!(" · {n} part steers"),
        };
        // TODO 208 item 1: the line cap the run settled on and how many
        // times the in-run shed moved a target. Same rule as the taper
        // arm: absent when disarmed, so the A/B's off arm is unchanged.
        let taper = format!("{taper}{steers}{}", self.line_cap_summary());
        match (ts, da) {
            (Some(t), Some(d)) => info!(
                target: "pool",
                "run {run:.2}s · queue dry at {:.2}s · drained at {:.2}s · {dups} dups ({wins} won) · {hedges} hedges · art {art} ms{spend} · {rules}{sat}{taper}",
                (t - self.start).as_secs_f64(),
                (d - self.start).as_secs_f64(),
            ),
            _ => info!(
                target: "pool",
                "run {run:.2}s · no tail · {dups} dups ({wins} won) · {hedges} hedges · art {art} ms{spend} · {rules}{sat}{taper}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_is_off_at_zero_percent_and_before_a_peak_trains() {
        let s = Saturation::with_pct(0);
        for t in 0..40 {
            s.note_bytes(t * 1000, 1_000_000, false);
        }
        assert!(!s.saturated(40_000));
        let s = Saturation::with_pct(80);
        s.note_bytes(0, 1_000_000, false);
        s.note_bytes(1000, 1_000_000, false);
        assert!(!s.saturated(1000), "no peak can train in 1 s");
    }

    /// Steady 1 MB/s for a minute: the peak is ~1 MB/s, the now-rate
    /// reads the same, and the line is saturated.
    #[test]
    fn a_steady_plateau_reads_as_saturated() {
        let s = Saturation::with_pct(80);
        for t in 0..600 {
            s.note_bytes(t * 100, 100_000, false);
        }
        let now = 60_000;
        let peak = s.peak_bps.load(Ordering::Relaxed) as f64;
        assert!((0.9e6..1.1e6).contains(&peak), "peak {peak}");
        let r = s.now_rate(now).unwrap();
        assert!((0.9e6..1.1e6).contains(&r), "now {r}");
        assert!(s.saturated(now));
        assert!(s.sat_ms.load(Ordering::Relaxed) > 40_000);
    }

    /// Warm-up correction: a 7 s run at a constant rate trains a peak
    /// near the true rate, not the ~40% a raw 14 s-tau EWMA would hold.
    #[test]
    fn warm_up_is_corrected_so_short_runs_train_a_true_peak() {
        let s = Saturation::with_pct(80);
        for t in 0..75 {
            s.note_bytes(t * 100, 100_000, false);
        }
        let peak = s.peak_bps.load(Ordering::Relaxed) as f64;
        assert!((0.9e6..1.15e6).contains(&peak), "peak {peak}");
    }

    /// A supply-bound taper: the plateau ends and the rate falls to a
    /// third. Within two seconds the gate opens; the saturated share of
    /// the tail is well under that of the run.
    #[test]
    fn a_falling_rate_opens_the_gate_within_seconds() {
        let s = Saturation::with_pct(80);
        for t in 0..600 {
            s.note_bytes(t * 100, 100_000, false);
        }
        assert!(s.saturated(60_000));
        let mut now = 60_000;
        for _ in 0..30 {
            now += 300;
            s.note_bytes(now, 100_000, true); // 0.33 MB/s
        }
        assert!(
            !s.saturated(now),
            "gate still closed at {:?}",
            s.now_rate(now)
        );
        // find when it opened
        let mut open_at = None;
        let probe = Saturation::with_pct(80);
        for t in 0..600 {
            probe.note_bytes(t * 100, 100_000, false);
        }
        let mut n = 60_000;
        for _ in 0..30 {
            n += 300;
            probe.note_bytes(n, 100_000, true);
            if open_at.is_none() && !probe.saturated(n) {
                open_at = Some(n - 60_000);
            }
        }
        assert!(
            open_at.is_some_and(|o| o <= 2000),
            "opened at {open_at:?} ms"
        );
    }

    /// A line-bound drain: the rate HOLDS while the fleet thins, so the
    /// gate stays shut until the rate actually gives way.
    #[test]
    fn a_held_rate_keeps_the_gate_shut_through_the_drain() {
        let s = Saturation::with_pct(80);
        for t in 0..600 {
            s.note_bytes(t * 100, 100_000, false);
        }
        let mut now = 60_000;
        for _ in 0..200 {
            now += 100;
            s.note_bytes(now, 100_000, true);
        }
        assert!(s.saturated(now));
        assert!(s.sat_tail_ms.load(Ordering::Relaxed) >= 19_000);
    }

    /// Feed a 1 MB/s plateau delivered by `n` connections, then stall
    /// exactly one of them: the fleet keeps `(n-1)/n` of the rate.
    /// Returns the now-rate as a percent of the trained peak, and the
    /// gate. Measured here, matching the note's own table to a point:
    /// 52.4 / 68.9 / 77.1 open at n = 2/3/4, then 82.1 / 85.4 / 92.0 /
    /// 100.9 / 101.6 shut at n = 5/6/10/100/360.
    fn gate_after_one_connection_of(n: u64) -> (f64, bool) {
        let s = Saturation::with_pct(80);
        for t in 0..600 {
            s.note_bytes(t * 100, 100_000, false);
        }
        let mut now = 60_000;
        for _ in 0..50 {
            now += 100;
            s.note_bytes(now, 100_000 * (n - 1) / n, true);
        }
        let peak = s.peak_bps.load(Ordering::Relaxed) as f64;
        (s.now_rate(now).unwrap() * 100.0 / peak, s.saturated(now))
    }

    /// TODO 202 §17b: the gauge is a FLEET aggregate, and one stalled
    /// connection is invisible to it at every fleet size that ships.
    ///
    /// `saturated()` holds while `now >= pct * peak`; the rig pins 80
    /// (the 21 Aug value) as the LOOSER bound: one stall out of `n`
    /// leaves `(n-1)/n` of the rate, under 0.80 only when `n < 5`, and
    /// under the shipped 0.70 only when `n < 4`, so whatever holds at
    /// 80 holds at 70. `PoolConfig::default()` is 6 connections, real
    /// installs run ~100 and the bench runs 360 - so the condition
    /// hedging exists to rescue (one wedged connection, its article
    /// going nowhere, the rest of the fleet healthy) can never open
    /// this gate on its own.
    ///
    /// This is the guard the per-article escape rests on: it says the
    /// aggregate is structurally incapable of seeing a single stall, so
    /// the escape has to come from the ARTICLE
    /// (`Shared::not_using_the_line`) and not from a threshold tweak.
    /// It also disqualifies the obvious empirical A/B: the wall-clock
    /// rig `payout_hedge_rescues_stalls_in_under_a_second_not_eight`
    /// runs a FOUR-connection fleet, the one size below where this
    /// table turns, so it passes at `NZBFAST_RACE_SAT_PCT=80` and at
    /// `=0` alike and says nothing about production.
    #[test]
    fn one_stalled_connection_of_many_never_opens_the_gate() {
        for n in 2..=4 {
            let (pct, shut) = gate_after_one_connection_of(n);
            assert!(
                !shut,
                "{n} conns: one stall leaves {pct:.1}% of peak and the gate stayed shut"
            );
        }
        for n in [5, 6, 10, 100, 360] {
            let (pct, shut) = gate_after_one_connection_of(n);
            assert!(
                shut,
                "{n} conns: one stall left {pct:.1}% of peak and opened the gate - \
                 if the threshold moved, the escape's premise moved with it"
            );
        }
        // Above ~50 connections the now-rate does not fall at all: one
        // connection of many going quiet is inside the settling error.
        let (pct, _) = gate_after_one_connection_of(100);
        assert!(
            pct >= 100.0,
            "100 conns: one stall moved the rate to {pct:.1}%"
        );
    }

    /// `conns` connections dialled together into a line of `conns x
    /// per_conn` B/s, moving `body`-byte bodies for `secs`, fed to two
    /// gauges: one per DELIVERED body (every body lands at `k x body
    /// time`, the A/B arm), one per 64 KB chunk as it arrives through
    /// `note_chunk` (shipped). Returns (per-body peak, per-chunk peak).
    fn peaks_of_a_fleet_dialled_together(
        conns: u64,
        per_conn: u64,
        body: u64,
        secs: u64,
    ) -> (u64, u64) {
        let by_body = Saturation::with_pct(80);
        let body_ms = body * 1000 / per_conn;
        let mut t = body_ms;
        while t <= secs * 1000 {
            for _ in 0..conns {
                by_body.note_bytes(t, body, false);
            }
            t += body_ms;
        }
        let by_chunk = Saturation::with_pct(80);
        let chunk = body.min(65_536);
        let chunk_ms = chunk * 1000 / per_conn;
        let (mut t, mut prev) = (chunk_ms, 0);
        while t <= secs * 1000 {
            for _ in 0..conns {
                by_chunk.note_chunk(t, prev, chunk, false);
            }
            prev = t;
            t += chunk_ms;
        }
        (by_body.peak_bps(), by_chunk.peak_bps())
    }

    /// TODO 208.2 over-read, pinned. Fed per delivered body, a fleet
    /// dialled together lands its whole first wave in one clump at the
    /// gauge's first fold - bodies that spent `body / per_conn` seconds
    /// on the wire BEFORE the window opened - so the corrected rate
    /// reads the line at roughly `1 + body time / window` times the
    /// truth, and the peak is a run max, so it never comes back down.
    /// The fault rig's shape (eight connections at 50 KB/s, 400 KB
    /// bodies: measured 695 KB/s for a 400 KB/s line before its dial
    /// ramp hid the clump) reads over 1.5x here; the 360-socket 100 Mbit
    /// fleet's shape (21.6 s first wave) over 2x - measured 2.05x and
    /// 2.36x. Fed per arriving chunk the same traffic reads the line
    /// within 10% on both (1.05x and 1.07x; what is left is chunk
    /// discretisation, a chunk folding at its end rather than across
    /// its span, `chunk time / 2 tau` with 64 KB at a 35-50 KB/s share,
    /// and shrinks with the chunk: 16 KB TLS records read 1.6%).
    #[test]
    fn a_fleet_dialled_together_over_reads_the_line_per_body_and_not_per_chunk() {
        for (conns, per_conn, body) in [(8, 50_000, 400_000), (360, 34_722, 750_000)] {
            let line = conns * per_conn;
            let (by_body, by_chunk) = peaks_of_a_fleet_dialled_together(conns, per_conn, body, 180);
            assert!(
                by_body as f64 >= line as f64 * 1.5,
                "{conns} conns: per-body peak {by_body} B/s for a {line} B/s line - the \
                 clump the arrivals arm exists to remove is not there"
            );
            let ratio = by_chunk as f64 / line as f64;
            assert!(
                (0.9..=1.1).contains(&ratio),
                "{conns} conns: per-chunk peak {by_chunk} B/s for a {line} B/s line ({ratio:.2}x)"
            );
        }
    }

    /// The first fold opens the window and credits nothing (its bytes
    /// arrived before the instant that opened it); a chunk whose span
    /// straddles the origin credits the part after it; a later chunk
    /// credits whole. This is what spreads the mini-clump of a fleet's
    /// simultaneous FIRST chunks, which on the fault rig's 64 KB chunks
    /// is the same +14% shape in miniature.
    #[test]
    fn a_chunk_is_credited_only_for_the_span_after_the_origin() {
        let s = Saturation::with_pct(80);
        s.note_chunk(1000, 0, 1000, false);
        assert_eq!(s.slow.read(1000), 0, "the first fold credits nothing");
        assert_eq!(s.first_ms.load(Ordering::Relaxed), 1000);
        s.note_chunk(1500, 0, 1000, false);
        let v = s.slow.read(1500);
        assert!(
            (300..=340).contains(&v),
            "straddling chunk credited {v}, want ~333"
        );
        s.note_chunk(2000, 1500, 1000, false);
        let v = s.slow.read(2000);
        assert!(
            (1300..=1340).contains(&v),
            "whole chunk credited on top: {v}"
        );
        // A simultaneous first wave: eight 64 KB chunks at the same
        // instant, from reads begun together, credit nothing at all.
        let s = Saturation::with_pct(80);
        for _ in 0..8 {
            s.note_chunk(1310, 0, 65_536, false);
        }
        assert_eq!(s.slow.read(1310), 0);
    }

    #[test]
    fn rules_are_tallied_by_name() {
        let s = Saturation::with_pct(80);
        for r in [
            "fanout",
            "slow-owner",
            "envelope",
            "stale",
            "ladder",
            "ladder",
        ] {
            s.tally(Rule::from_name(r));
        }
        assert_eq!(s.rules_line(), "fanout 1 slow-owner 2 stale 1 ladder 2");
    }
}
