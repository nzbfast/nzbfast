//! Who may take this article: the fill gate and the masks that open it.
//!
//! A level-N server is held off queued work until every live server
//! below it is done with the article. "Done" is two different things,
//! and conflating them was M5 of the 14 Aug sweep: `tried_430` is a
//! server ANSWERING that it does not have the article, while `spent`
//! records a server that answered nothing at all and simply ran out of
//! attempts - resets, stalls, protocol errors. Only the first is
//! evidence. `tried_430` feeds unanimous-Missing, the M29 oracle's miss
//! ledger and the §146 give-up census, so a bit forged there invents a
//! `Gone` for an article some backbone still holds. But BOTH must open
//! the gate, because a primary that kills the same article's connection
//! every time never 430s it, and until this split the healthy demoted
//! tier stayed locked out by `required_mask` and watched the article
//! die on the one server that had proved it could not fetch it.
//!
//! Split out of `pool.rs` whole (TODO 106 size gate) - the code is
//! verbatim, only visibility changed. A child module, so `Shared`,
//! `Work` and `server_bit` stay in scope as they were inline;
//! `pub(super)` reads "pub in pool", which puts these back in front of
//! pool.rs AND its other children (pool/queue.rs calls
//! `other_can_take`) exactly as the private ones were.
//!
//! `live_mask` / `participation_mask` / `missing_cause` joined them on
//! 28 Aug 2026 (27 Aug sweep finding 8), because they are the same
//! subject one step further on: the fill gate asks WHO MAY TAKE this
//! article, and those three answer when the pool may stop asking and
//! what the silence meant. The defect that brought them here is the one
//! the paragraph above already names - a mask that reads as unanimous
//! invents a `Gone` for an article some backbone still holds - reached
//! by a different route, so they belong beside it and not a file away.

use super::*;

/// Shipped default for [`PoolConfig::conn_dark`]: how long a server may
/// go without holding ONE session before it stops blocking a terminal
/// verdict for articles it has never refused.
///
/// WITHOUT A BOUND HERE THERE IS NONE, and that is the whole reason this
/// constant exists rather than the fleet being trusted to shrink on its
/// own. [`Shared::live_mask`] used to read `alive[si] > 0` - workers
/// ALIVE, not workers CONNECTED - so a server whose workers are all
/// parked in `park_or_probe` after failing to dial kept its bit. The
/// terminal test is `tried_430 & live == live`, so an article that
/// server never refused can never reach it, and no OTHER server may
/// take it either: every other bit is already set, so `next_work`'s
/// pickup gate steps them all past it. `gates.rs` has stated the
/// consequence in writing since it was split out - "an item nothing can
/// serve rotates in the queue forever and deadlocks the run" - and that
/// is exactly what it did.
///
/// MEASURED, on a live three-provider desktop install, 30 Aug 2026:
///
/// ```text
/// 04:04:45Z [pool-debug] t=210s pending=399 alive=[9, 17, 17]
/// 04:04:45Z [pool-debug]   q <...> tried_430=000001 ... x399
/// 04:04:45Z [get] <second backbone>  no usable connection for the entire run
/// 04:04:45Z [get] <third backbone>   no usable connection for the entire run
/// ```
///
/// Thirty-four live workers holding no socket between them, and 399
/// articles pinned on their silence after the one backbone that WAS
/// serving had refused every one of them. The `sessions=` and `live=`
/// fields beside `alive=` on that first line were added by this fix -
/// the dump that recorded the wedge could not say that thirty-four of
/// those workers held nothing.
///
/// THIS IS NOT TODO 315's LATE RE-ASK wearing a different log line, and
/// the dump above is what rules it out: at t=210 s no hold can have been
/// taken, and `tried_430=000001` says exactly one server ever answered.
/// [`RECHECK_430_HOLD`] bounds a suppressed refusal; this bounds a
/// refusal that was never made.
///
/// TWO MINUTES, and both sides of it are read off this tree rather than
/// chosen. Below: a legitimate reconnect must not cross it, and the dial
/// ladder is [`PoolConfig::max_connect_attempts`] 5 attempts over a
/// doubling [`PoolConfig::connect_backoff`] of 2 s, ~62 s for ONE
/// worker - and a whole fleet of them going that long without a single
/// grant is a server that is not serving us. Above: the caller's own
/// stall watchdog aborts a download after 180 s with no progress, which
/// is what ended the incident run at t=210 s, so a window that does not
/// clear the queue before then unwedges nothing anybody sees. It sits
/// deliberately far below [`OUTAGE_BUDGET`]'s 15 minutes, which is the
/// only thing that reached this today and only by killing the server
/// outright.
///
/// IT DOES NOT INHERIT [`PoolConfig::outage_budget`], for
/// [`RECHECK_430_HOLD`]'s reason, which transfers wholesale: sharing the
/// number would be tidy, sharing the OPTION would not. `outage_budget:
/// None` is the shipped `server_outage_mins = 0` setting, whose own doc
/// promises to "wait instead, for as long as it takes", and that is a
/// promise about FETCHING. Withholding a VERDICT for ever is a different
/// thing, and under that setting it is what happens: `outage_budget_blown`
/// and `ladder_exhausted` are both false for the life of the run, so the
/// elected prober never publishes `CapEpisode::Dead`, `alive` never falls
/// to zero, and the wedge is PERMANENT rather than merely long.
pub(super) const CONN_DARK: Duration = Duration::from_secs(120);

/// Per-server darkness clock for [`CONN_DARK`]: the run-clock
/// millisecond at which each server stops counting as able to serve,
/// unless it holds a session at the moment it is asked.
///
/// A DEADLINE AND NOT A LAST-SEEN STAMP, which is a testability decision
/// as much as an arithmetic one: a unit test runs at run-clock zero, so
/// "now - last_seen >= window" cannot express a dark server there at all
/// and every pin of this would have to advance a real clock. A deadline
/// of 0 says "dark, now", at any clock, with nothing to wait for - the
/// chip that commissioned this asked for a deterministic test and this
/// is what makes one possible.
pub(super) struct ConnDark {
    /// Per server: `now_ms + window_ms` as of the last moment a session
    /// was known to be held. Seeded to `window_ms` so the run opens with
    /// one whole window of grace, which is the window before any dial
    /// can have landed.
    at: Vec<AtomicU64>,
    /// [`PoolConfig::conn_dark`] in ms, MAX-folded across the fleet;
    /// 0 = no bound (the pre-30-Aug-2026 shape). MAX-folded like
    /// [`Shared::recheck_hold_ms`] and for the same reason: the most
    /// generous window any member asked for is the only reading that
    /// cannot shorten a wait somebody deliberately lengthened.
    window_ms: u64,
    /// One warning per run. The failure this bounds was silent, and a
    /// count nobody prints is that silence with a counter behind it.
    noted: AtomicBool,
}

impl ConnDark {
    pub(super) fn new(servers: &[(ServerConfig, PoolConfig)]) -> Self {
        let window_ms = servers
            .iter()
            .map(|(_, c)| c.conn_dark.as_millis().min(u64::MAX as u128) as u64)
            .max()
            .unwrap_or(0);
        ConnDark {
            at: (0..servers.len())
                .map(|_| AtomicU64::new(window_ms))
                .collect(),
            window_ms,
            noted: AtomicBool::new(false),
        }
    }

    /// This server was holding a session as of `now_ms`: push its
    /// deadline a whole window out.
    ///
    /// ONE CALLER, [`SessionTally`]'s `Drop`, and its own comment has
    /// the argument for why the matching stamp at the other end was
    /// deleted rather than kept as a belt.
    pub(super) fn note_session(&self, si: usize, now_ms: u64) {
        if self.window_ms == 0 {
            return;
        }
        if let Some(a) = self.at.get(si) {
            a.store(now_ms.saturating_add(self.window_ms), Ordering::Relaxed);
        }
    }

    /// This server's deadline has passed - at any clock, including the
    /// zero a unit test runs at. The one door into `at` from outside
    /// this file, and the reason the deadline is stored as an absolute
    /// instant rather than a last-seen stamp: a rig for this bound has
    /// to be able to say "dark, now" without advancing a real clock.
    #[cfg(test)]
    pub(super) fn go_dark(&self, si: usize) {
        self.at[si].store(0, Ordering::Relaxed);
    }
}

/// The routing bit for a server index.
///
/// This used to be spelled `1u32 << si.min(31)`, which ALIASED every server
/// from index 31 upward onto bit 31. Server 31 returning 430 therefore set
/// the bit that server 32 reads as "I already tried here", so once servers
/// 0-31 had missed, an article could go terminal Missing without server 32
/// ever being sent a BODY - even when it held the article. A hostile or
/// merely broken provider at index 31 could suppress the last healthy one.
///
/// Returning 0 for an unrepresentable index is defence in depth only: no bit
/// is strictly safer than another server's bit, but the config cap above is
/// what actually keeps this reachable.
#[inline]
pub(super) fn server_bit(si: usize) -> u32 {
    debug_assert!(si < MAX_SERVERS, "server index {si} has no routing bit");
    if si < MAX_SERVERS { 1u32 << si } else { 0 }
}

pub(super) fn servers_mask(n: usize) -> u32 {
    if n >= MAX_SERVERS {
        u32::MAX
    } else {
        (1u32 << n) - 1
    }
}

impl Shared {
    /// This run's clock in milliseconds - the currency every window in
    /// this module is measured in, and the one `next_work` already has
    /// in hand for its scan throttle.
    pub(super) fn run_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Can this server still SERVE, as opposed to merely existing? A
    /// worker that is alive is not a worker that has a connection, and
    /// [`CONN_DARK`] is the whole write-up of what conflating the two
    /// cost. Three tiers, cheapest first:
    ///
    /// * the bound switched off - the pre-30-Aug-2026 shape, which
    ///   `NZBFAST_CONN_DARK_SECS=0` asks for by hand;
    /// * a session held RIGHT NOW, which is what keeps a healthy server
    ///   in every mask however long its sockets live, since
    ///   [`ConnDark`] is only stamped as a session starts and ends;
    /// * otherwise the deadline, which a FLAPPING server refreshes on
    ///   every grant. That is the point of measuring the window from
    ///   the last session rather than from the last DIAL: a server
    ///   reconnecting every thirty seconds inside a two-minute window
    ///   never leaves a mask, so nothing here thrashes.
    pub(super) fn serving_at(&self, si: usize, now_ms: u64) -> bool {
        self.conn_dark.window_ms == 0
            || self.sessions[si].load(Ordering::Relaxed) > 0
            || now_ms < self.conn_dark.at[si].load(Ordering::Relaxed)
    }

    /// Bits of every server that still has at least one worker running
    /// AND can still serve with it ([`Self::serving_at`]).
    /// A server whose workers all bowed out (connect exhaustion) can never
    /// answer for its untried articles - terminal decisions must be made
    /// against this mask, not the full server set.
    ///
    /// It answers WHEN the pool may stop asking, and nothing else.
    /// [`Self::participation_mask`] answers the other half - what the
    /// silence MEANT - and the two must not be confused: this one shrinks
    /// under the verdict's feet by design.
    ///
    /// THE FLOOR IS NOT DECORATION. A mask this filter empties would make
    /// `tried_430 & live == live` true of EVERY queued article at once
    /// (`0 & 0 == 0`), so a transient outage that reached the whole fleet
    /// would write the entire remaining queue off as Missing in one scan
    /// - a far worse answer than the wedge this is fixing. When nothing
    /// is serving, nobody can take the article whatever the mask says, so
    /// there is nothing to unblock and the pre-fix reading stands. That
    /// also makes the shrink strictly conditional on some OTHER server
    /// being live and serving, which is the incident's own shape.
    ///
    /// IT CAN NOW GROW BACK, which is the one thing it never used to do:
    /// `alive` only ever falls, so before 30 Aug 2026 this mask was
    /// monotone and a dark server rejoins it the moment it is granted a
    /// session. Nothing needs it monotone. An article a scan has retired
    /// is gone from the queue whether or not the fleet recovers
    /// afterwards, which is exactly the trade already made for a server
    /// whose workers bow out, and [`Self::missing_cause`] is what keeps
    /// the REPORT honest about it - `participation_mask` latches, so a
    /// server that served and then went dark still counts as one that
    /// could have answered and the verdict reads `Unasked`, never
    /// `Gone`.
    pub(super) fn live_mask(&self) -> u32 {
        self.live_mask_at(self.run_ms())
    }

    /// [`Self::live_mask`] on a caller's clock. `next_work` reads it this
    /// way so its whole scan - the [`recheck::expire_hold`] window, the
    /// fill gate and the terminal test - judges one instant.
    pub(super) fn live_mask_at(&self, now_ms: u64) -> u32 {
        let mut alive = 0u32;
        let mut serving = 0u32;
        for (si, a) in self.alive.iter().enumerate() {
            if a.load(Ordering::Relaxed) > 0 {
                alive |= server_bit(si);
                if self.serving_at(si, now_ms) {
                    serving |= server_bit(si);
                }
            }
        }
        if serving == 0 {
            return alive;
        }
        if serving != alive && !self.conn_dark.noted.swap(true, Ordering::Relaxed) {
            warn!(
                target: "pool",
                "a server has held no session for {}s while another is serving - \
                 it no longer blocks a terminal verdict for articles it never \
                 refused (dark: {:06b}, serving: {serving:06b})",
                self.conn_dark.window_ms / 1000,
                alive & !serving,
            );
        }
        serving
    }

    /// Bits of every server that COULD have been asked: one that has held
    /// a usable connection at some point in this run, plus (for the
    /// window before the first dial lands) anything still live. Latching,
    /// never shrinking - which is exactly what [`Self::live_mask`] is not.
    ///
    /// The 27 Aug 2026 sweep's finding 8: the terminal test is
    /// `tried_430 & live == live`, so the instant a server's LAST worker
    /// leaves mid-run its bit drops out of `live` and the survivors'
    /// refusals read as unanimous. The article is written off having been
    /// refused by everyone who was asked and never offered to the server
    /// that might have held it. `note_server_dark` latched `left_mid_run`
    /// for the failure summary and fed no verdict at all.
    ///
    /// A frozen mask CANNOT replace `live` in that test - the comment
    /// above the verdict in `next_work` is the reason: an item nothing
    /// can serve rotates in the queue forever and deadlocks the run. So
    /// the fix splits the question in two. Terminality still asks `live`
    /// (unchanged, and the run still ends). This mask decides what the
    /// terminal report SAYS: unanimous over the servers that could answer
    /// ([`MissingCause::Gone`]), or forced by a fleet that shrank
    /// ([`MissingCause::Unasked`]).
    ///
    /// The population is "ever held a usable connection" and not "ever
    /// had a worker", deliberately. A server that never got a socket up
    /// - a typo'd host, a refused login - was never a candidate for any
    /// article, and counting it would downgrade EVERY verdict of every
    /// run that carries one misconfigured entry, which is the noise that
    /// gets a distinction ignored. That server already has its own line
    /// in the failure summary ("no usable connection for the entire
    /// run"), off the same `connected` latch this reads.
    pub(super) fn participation_mask(&self) -> u32 {
        let mut m = self.live_mask();
        for (si, c) in self.connected.iter().enumerate() {
            if c.load(Ordering::Relaxed) {
                m |= server_bit(si);
            }
        }
        m
    }

    /// The terminal cause for an article whose `tried_430` has just gone
    /// unanimous over [`Self::live_mask`]. THE ONE PLACE that judgement
    /// is made: three sites reach a unanimous verdict (the `next_work`
    /// queue scan and both 430 paths in `session`), and a rule spelled
    /// out three times is one that holds in two of them.
    ///
    /// `dark` is the participating servers this article was never
    /// refused by - by construction the ones that went out without
    /// seeing it, since live-unanimity means every live server is
    /// already in `tried_430`.
    pub(super) fn missing_cause(&self, tried_430: u32, takedown: bool) -> MissingCause {
        let dark = (self.participation_mask() & !tried_430).count_ones();
        if dark == 0 {
            MissingCause::Gone { takedown }
        } else {
            MissingCause::Unasked { takedown, dark }
        }
    }

    /// Bits a level-L server must see in tried_430 before it may take
    /// queued work: every live SERVING server on a lower level, judged
    /// on the caller's clock (see [`Self::live_mask_at`] for why a scan
    /// reads one instant).
    ///
    /// The serving half is [`CONN_DARK`]'s defect on the dispatch side
    /// rather than the verdict side, and it is the same deadlock: a
    /// primary that is alive and dialling nothing files no refusal, so
    /// the gate it holds shut is one nothing can ever open, and the fill
    /// tier watches a queue it is allowed to look at and not touch. No
    /// floor here, unlike [`Self::live_mask`]: an empty required mask is
    /// an OPEN gate, which is the safe direction - a backup free to take
    /// work its primary cannot is what a backup is for, and the gate
    /// closes again the moment the primary grants a session.
    ///
    /// There is deliberately no clock-reading `required_mask(level)`
    /// beside it, the way [`Self::live_mask`] sits beside
    /// [`Self::live_mask_at`]: every caller here already holds `now_ms`,
    /// so a wrapper would be a second spelling that only tests reach.
    pub(super) fn required_mask_at(&self, level: u32, now_ms: u64) -> u32 {
        let mut m = 0u32;
        for (si, &l) in self.levels.iter().enumerate() {
            if l < level
                && self.alive[si].load(Ordering::Relaxed) > 0
                && self.serving_at(si, now_ms)
            {
                m |= server_bit(si);
            }
        }
        m
    }

    /// Bits of the servers that have spent their whole retry budget on
    /// this article (see [`Shared::spent`]). One atomic load when
    /// nothing ever exhausted a budget, which is every healthy run.
    pub(super) fn spent_mask(&self, id: &str) -> u32 {
        if self.spent_n.load(Ordering::Acquire) == 0 {
            return 0;
        }
        self.spent.lock_ok().get(id).copied().unwrap_or(0)
    }

    /// M8 (sweep 8): put back the `spent` bits [`Shared::claim_done`]
    /// dropped when a body was provisionally claimed, because the
    /// decode verdict has now sent that article back into the queue.
    /// The article is not terminal after all, so the evidence that
    /// opened its fill tier has to be live again before a worker can
    /// adopt the requeue - `next_work`'s pickup gate reads the same map
    /// (`tried_430 | spent_mask`), so without this the steer's chosen
    /// server is admitted by `other_can_take` and then gated out at the
    /// pick. Caller holds the steer inbox, which is what keeps the
    /// restore ahead of any adoption.
    pub(super) fn restore_spent(&self, id: &str, bits: u32) {
        if bits == 0 {
            return;
        }
        let mut m = self.spent.lock_ok();
        *m.entry(Arc::from(id)).or_insert(0) |= bits;
        self.spent_n.store(m.len(), Ordering::Release);
    }

    /// M5: the server this `bit` belongs to just used the last of
    /// `article_retries` on this article without ever being answered:
    /// every attempt died in transport, so `tried_430` is still empty
    /// and `required_mask` holds the article on the one tier that has
    /// demonstrably failed to fetch it.
    ///
    /// Records the bit and answers whether the ladder has somewhere
    /// left to go: some LIVE server that has neither refused this
    /// article, nor killed it in transport, nor spent a budget of its
    /// own on it. True means the caller re-arms `attempts` and requeues
    /// instead of declaring the article lost while a healthy server
    /// still holds it.
    ///
    /// Termination is structural, not a hope: the re-arm is granted
    /// only the FIRST time a given server exhausts itself here, so the
    /// whole article costs at most (article_retries + 1) attempts per
    /// configured server before a Failed, the same bound the 430 ladder
    /// has always carried.
    pub(super) fn note_spent(&self, w: &Work, bit: u32) -> bool {
        let (fresh, spent) = {
            let mut m = self.spent.lock_ok();
            let e = m.entry(w.id.clone()).or_insert(0);
            let fresh = *e & bit == 0;
            *e |= bit;
            let spent = *e;
            self.spent_n.store(m.len(), Ordering::Release);
            (fresh, spent)
        };
        if !fresh {
            return false;
        }
        let touched = w.tried_430 | w.tried_fail | spent;
        // DELIBERATELY `alive` AND NOT [`Shared::serving_at`], unlike the
        // four gates around it. [`CONN_DARK`] bounds how long a silent
        // server may WITHHOLD A VERDICT or BLOCK a dispatch; this
        // decides whether to keep FETCHING, and `RECHECK_430_HOLD` makes
        // the same split for the same reason - `outage_budget: None`
        // promises to wait for a server to fetch for as long as it
        // takes, and that promise is not this bound's to break. A dark
        // server counted here only ever grants one more re-arm, which
        // the fresh-once rule above bounds anyway.
        self.alive
            .iter()
            .enumerate()
            .any(|(si, a)| a.load(Ordering::Relaxed) > 0 && touched & server_bit(si) == 0)
    }

    /// True when some OTHER live server could take this work item: it
    /// hasn't 430'd it, hasn't transport-failed it, and its fill gate (if
    /// any) is satisfied. Used to steer a transport-failed article's retry
    /// away from the server that just failed it.
    pub(super) fn other_can_take(&self, w: &Work, me: usize) -> bool {
        self.other_can_take_with(w, me, 0)
    }

    /// [`Shared::other_can_take`] with routing evidence the live map no
    /// longer holds folded in.
    ///
    /// M8 (sweep 8): a provisional `claim_done` drops the article's
    /// `spent` entry at HANDOFF, before the decode verdict that may yet
    /// send the article back down the ladder - so the bad-body steer
    /// asked this question with the exact evidence that opened the fill
    /// tier already erased, and refused an otherwise valid retry. The
    /// steer carries the pre-claim mask on its stashed `Handed` record
    /// and passes it here; every other caller reads the live map alone
    /// and passes 0.
    /// A DARK server is not an answer to this question, and that is
    /// [`CONN_DARK`] reaching the third face of the same deadlock.
    /// `next_work` steps a transport-failed article PAST this server
    /// when the answer is true, so a server that is alive and dialling
    /// nothing turns "somebody else will take it" into a rotation
    /// nobody ends. Answering false instead makes the server that just
    /// failed it retake its own casualty, which is bounded by the
    /// article's retry budget and is the pre-tier behaviour.
    pub(super) fn other_can_take_with(&self, w: &Work, me: usize, extra_spent: u32) -> bool {
        // A spent lower tier counts toward the gate exactly as a 430
        // does: it is done with this article either way, and without
        // that the failing primary reads "nobody else can have it" and
        // retakes its own casualty until the budget is gone.
        let evidence = w.tried_430 | self.spent_mask(&w.id) | extra_spent;
        let now_ms = self.run_ms();
        for (si, &level) in self.levels.iter().enumerate() {
            if si == me
                || self.alive[si].load(Ordering::Relaxed) == 0
                || !self.serving_at(si, now_ms)
            {
                continue;
            }
            let bit = server_bit(si);
            if w.tried_430 & bit != 0 || w.tried_fail & bit != 0 {
                continue;
            }
            let required = if level > 0 {
                self.required_mask_at(level, now_ms)
            } else {
                0
            };
            if evidence & required == required {
                return true;
            }
        }
        false
    }

    /// M11 stream mode: should this server LEAVE a promoted (seek) item
    /// for a faster one? Seek latency is per-article latency - a slow
    /// backbone's connection sitting on a playhead article costs the
    /// player seconds. Mirror of the tried_fail steering: skip only when
    /// some LIVE, eligible server is measurably faster per worker (>2x),
    /// so promoted work is never stranded - with no clear winner (cold
    /// start, single server) everyone takes it. Judged on the WINDOWED
    /// per-conn rate (steer module) since M7b.2: the whole-run average
    /// answered "was this server slow at some point", and shaping that
    /// starts or lifts mid-run flipped that answer wrongly for the rest
    /// of the run.
    ///
    /// Moved here from pool.rs on 30 Aug 2026 under the size gate, and
    /// it belongs at this address rather than that one: this file's own
    /// header says it answers WHO MAY TAKE THIS ARTICLE, which is the
    /// question, and it is the fourth reader of [`Self::serving_at`].
    /// Dark is not "faster" - a server that granted no session is one
    /// whose windowed rate is the memory of a better minute, and
    /// leaving a promoted article for it strands exactly the article a
    /// player is waiting on.
    pub(super) fn faster_can_take(&self, w: &Work, me: usize) -> bool {
        let mine = self.steer_rate_per_worker(me);
        let evidence = w.tried_430 | self.spent_mask(&w.id);
        let now_ms = self.run_ms();
        for (si, &level) in self.levels.iter().enumerate() {
            if si == me
                || self.alive[si].load(Ordering::Relaxed) == 0
                || !self.serving_at(si, now_ms)
            {
                continue;
            }
            let bit = server_bit(si);
            if w.tried_430 & bit != 0 || w.tried_fail & bit != 0 {
                continue;
            }
            let required = if level > 0 {
                self.required_mask_at(level, now_ms)
            } else {
                0
            };
            if evidence & required != required {
                continue;
            }
            if self.steer_rate_per_worker(si) > 2.0 * mine {
                return true;
            }
        }
        false
    }
}
