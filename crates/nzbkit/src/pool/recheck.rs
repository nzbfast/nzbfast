//! TODO 315: the late re-ask, and why a refusal that named its own
//! article is not the end of it.
//!
//! Split out of pool.rs under the size gate (TODO 106). The mechanism
//! is two methods on [`Shared`] plus one bound; the per-article
//! bookkeeping is `Work::recheck_430` and the site that acts on all of
//! it is the terminal-verdict arm of `session::handle_missing`.

use super::*;

/// TODO 315: default ceiling on articles holding a late re-ask at once
/// ([`PoolConfig::recheck_430_max`]).
///
/// It bounds two different costs and the second is the reason it is not
/// simply large. A held verdict is damage the CONSUMER cannot see yet,
/// and the speculative par2 prefetch is what reads that damage in order
/// to overlap recovery-block fetching with the download - deferring
/// every verdict to the end of a run is the 7 Aug 2026 nightly red,
/// written up at `Work::soft_430`'s own front-insert. Past this many
/// holds the refusals go terminal immediately, so a genuinely dead post
/// reports its damage on schedule after a fixed prefix, while a run
/// losing a percent of a slice - which is what the measured fault looks
/// like - is covered whole.
///
/// Sized off that measurement (250 losses in 23,103 segments, 1.08%)
/// with headroom. A first cut, not a number anything has optimised.
pub(super) const RECHECK_430_MAX: usize = 4096;

/// TODO 315: default window a late re-ask may keep an article out of a
/// terminal verdict ([`PoolConfig::recheck_430_hold`]).
///
/// WITHOUT A BOUND HERE THE HOLD HAS NONE AT ALL, and that is the whole
/// reason this constant exists rather than the mechanism being trusted
/// to end on its own. [`Shared::take_recheck`] answering true makes
/// `handle_missing` clear the re-asked group's `tried_430` bit, and
/// `next_work` states the consequence plainly: "unanimity simply cannot
/// be reached while the held group's own bit is down, which is the
/// point." So the article is terminable ONLY by that group leaving
/// `live_mask`, and dispatchable only by that group as well - every
/// other server's bit is set, so `next_work`'s pickup gate steps them
/// all past it. Whether that group ever comes back is not this pool's
/// to decide, and nothing anywhere was asking the question.
///
/// MEASURED, on a live three-provider desktop install, 30 Aug 2026 (the
/// log is quoted in `research/WEDGE-THOR-REPAIRING-SLOT-2026-08-30.md`).
/// A fleet of three whose last backbone dialled 1001 times and lost 1000
/// of those sessions to the pre-byte budget retired about 600 held
/// articles at one every ~17 s: `run 20783.37s . queue dry at 11.20s . drained at
/// 20783.22s`, a download tail of 5 h 46 m, with a 40-minute window
/// inside it that produced ONE verdict. The recovery side-fetch of the
/// job behind it was queued on the cross-job connection lease and did
/// nothing whatever for 5 h 41 m (`run 20488.67s . no tail . 0 dups .
/// art 0 ms . fanout 0`), which is what put a queue row at "Repairing
/// 100%" with nothing repairing and stood the indexer down for twelve
/// hours saying a download was running.
///
/// THE GROUP DOES NOT HAVE TO BE DEAD, which is the part worth reading
/// twice before touching this. The obvious reading of that incident -
/// and the one it was chipped out with - is that the held group granted
/// no connection, so a guard that released the hold when its group had
/// no socket right now would cover it. It would not have fired once:
/// that server held a thousand sessions during the wedge. A group that
/// is merely SLOW pins every held article to its own refusal rate, and
/// with 600 articles held against one server managing a refusal every
/// 17 s the arithmetic is hours. A clock covers the slow group, the
/// dead group and the flapping one with a single thing to reason about,
/// so there is deliberately no second dispatchability guard beside it.
///
/// IT DOES NOT INHERIT [`PoolConfig::outage_budget`], and that is a
/// decision rather than an oversight. Sharing the number would be
/// tidy - both are "how long will this pool wait on one server" - but
/// sharing the OPTION would not: `outage_budget: None` is the shipped
/// `server_outage_mins = 0` setting, whose own doc promises to "wait
/// instead, for as long as it takes", and that is a promise about
/// FETCHING. A verdict withheld for ever is a different thing, and it
/// is the one that wedged: under that setting `outage_budget_blown` and
/// `ladder_exhausted` are both false for the life of the run, so the
/// elected prober never publishes `CapEpisode::Dead`, `alive` never
/// falls to zero, the group never leaves `live_mask` and the hold is
/// permanent - no clock, no ceiling, nothing. So the window is its own
/// setting, on by default whatever the outage budget says.
///
/// Fifteen minutes is [`OUTAGE_BUDGET`]'s horizon reached independently
/// and for a reason of its own: the value being protected is a cold
/// backend serving a refused article on a later pass, measured at 231
/// of 250 nine minutes after the refusal (see [`Shared::take_recheck`]),
/// so the window has to clear nine minutes with room and there is
/// nothing above that it buys. A first cut, not a number anything has
/// optimised - and NOT one to shorten below the measurement it is
/// covering.
pub(super) const RECHECK_430_HOLD: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// TODO 315: [`PoolConfig::recheck_430_hold`] as milliseconds for the
/// whole fleet, MAX-folded - the most generous window any member asked
/// for. See [`Shared::recheck_hold_ms`] for why the fold goes that way
/// and why the value lives on `Shared` at all.
pub(super) fn hold_ms(servers: &[(ServerConfig, PoolConfig)]) -> u64 {
    servers
        .iter()
        .map(|(_, c)| c.recheck_430_hold.as_millis().min(u64::MAX as u128) as u64)
        .max()
        .unwrap_or(0)
}

impl Shared {
    /// TODO 315: may this article hold its one late re-ask, and if so,
    /// charge the budget for it. Called only where the refusal in hand
    /// would otherwise make the article terminal.
    ///
    /// `Work::recheck_430` IS A FIELD OF ITS OWN and not a second
    /// meaning for `soft_430`, because the two doubt different things.
    /// `soft_430` doubts whether a BARE refusal was about this article,
    /// and an echoed message-id settles that. This doubts whether the
    /// refusal was TRUE, which an echoed id does not settle at all.
    /// Folding them together would leave a bare-refusing provider with
    /// no cover here at all, its pass already spent on the other
    /// question.
    ///
    /// IT FIRES ON THE LAST LIVE BACKBONE, whatever the fleet size, and
    /// restricting it to a fleet of ONE was considered and rejected.
    /// Live-unanimity means every backbone refused, so a false refusal
    /// from any one of them loses the article exactly as it does on a
    /// single-provider run - and the terminal verdict's own sentence
    /// already warns that resellers of one backbone answer alike, which
    /// is a fleet whose members share a cold-storage fault as readily
    /// as they share a retention profile. A bigger fleet makes this
    /// fire later and less often, not unnecessary.
    ///
    /// Three conditions, and each is load-bearing. The feature has to
    /// be ON; this GROUP must not already have spent the article's
    /// hold, which is what makes the pass terminate at one extra
    /// dispatch per article per backbone; and the pool-wide budget must
    /// have room, which is what stops a wholly dead post holding every
    /// verdict it has (see [`PoolConfig::recheck_430_max`] for the
    /// trade that bound exists to make).
    ///
    /// Answering true CHARGES the budget. `release_recheck` gives it
    /// back when the re-ask is answered, so the cover is a concurrency
    /// limit and not a quota spent once for the life of the run: a long
    /// run that recovers what it holds keeps its cover for the losses
    /// that come later.
    ///
    /// THE THREE PLACES THAT RELEASE are every place a held article's
    /// Work leaves flight without being requeued: the body it was
    /// re-asked for arriving, the second refusal that ends it, and the
    /// early return for an article a duplicate resolved first. A
    /// requeue - a dead socket, a shed pipeline - keeps the slot,
    /// because the article still holds the bit and will spend it. Miss
    /// one of the three and the budget leaks, which does not fail
    /// loudly: it silently retires the mechanism once
    /// `recheck_430_max` slots are gone.
    ///
    /// THREE MORE HAVE BEEN FOUND SINCE, and the count above is left as
    /// written because that is how the trap reads: the three are the
    /// verdict sites, and every OTHER way a Work can leave the queue for
    /// good is a site too.
    ///
    /// The fourth is `next_work`'s unservable arm, where a fleet
    /// shrinking under a queued hold retires it. The fifth is
    /// [`QueueControl::cancel`](super::QueueControl::cancel), which
    /// claims a queued Work terminal and stashes it whole - reachable
    /// by the §146 tail give-up, the par-race and the in-stream PAR2
    /// sniff, none of which look at `recheck_430` at all.
    /// [`QueueControl::requeue`](super::QueueControl::requeue)
    /// RE-CHARGES what it resurrects, through `recharge_recheck` below,
    /// so a cancel/requeue round trip leaves the budget where it found
    /// it.
    ///
    /// THE SIXTH is inside `runlife`'s own drain, and this list said
    /// nothing about it until 1 Sep 2026 while the site itself has
    /// released all along: an article whose retry budget is spent where
    /// `note_spent` finds no live server still owed a go never returns
    /// to the queue. It is a TERMINAL verdict reached in the
    /// shed/reinsert loop rather than at a session's verdict site, which
    /// is exactly why an enumeration written from the verdict sites
    /// missed it - and why "every way a Work leaves the queue for good"
    /// is the rule to check a new site against, not this list's length.
    pub(super) fn take_recheck(&self, w: &mut Work, cfg: &PoolConfig, group_bits: u32) -> bool {
        if !cfg.recheck_430 || w.recheck_430 & group_bits == group_bits {
            return false;
        }
        // Claim a slot before promising one: two workers reaching a
        // terminal verdict at once would both read a budget with one
        // slot left and both hold, which is how a bound becomes a
        // suggestion. The add is undone on refusal.
        if self.recheck_held.fetch_add(1, Ordering::AcqRel) >= cfg.recheck_430_max {
            self.recheck_held.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        w.recheck_430 |= group_bits;
        // The clock the hold is answerable to. Stamped here rather than
        // at the requeue below because this is the moment the evidence
        // is suppressed, and the suppression is what the window bounds.
        // Saturating rather than wrapping: a run past 49 days would
        // otherwise stamp a hold in the past and expire it instantly,
        // which is a worse answer than never expiring it.
        w.recheck_at = self.start.elapsed().as_millis().min(u32::MAX as u128) as u32;
        true
    }

    /// TODO 315: a held article's re-ask has been answered, however it
    /// was answered - give its slot back. Saturating, because the one
    /// thing this must never do is wrap the budget and disable the
    /// whole mechanism for the rest of the run.
    pub(super) fn release_recheck(&self, w: &Work) {
        if w.recheck_430 == 0 {
            return;
        }
        let _ = self
            .recheck_held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                Some(n.saturating_sub(1))
            });
    }

    /// TODO 315: the exact partner of [`Self::release_recheck`], for the
    /// one path that puts a released Work back in the queue -
    /// `QueueControl::requeue` resurrecting something `cancel` took out.
    ///
    /// UNCONDITIONAL, with no `recheck_430_max` test, and that is not an
    /// oversight: the slot was granted at `take_recheck` and the article
    /// still carries the bit, so refusing here would leave a queued hold
    /// with nothing charged behind it - and its eventual terminal
    /// release would then refund a slot some OTHER article is holding.
    /// The same predicate as the release, so the two cannot drift: a
    /// Work with no hold recorded charges nothing.
    pub(super) fn recharge_recheck(&self, w: &Work) {
        if w.recheck_430 == 0 {
            return;
        }
        self.recheck_held.fetch_add(1, Ordering::AcqRel);
    }
}

/// TODO 315: where in the queue a held article's late re-ask goes, and
/// why it is NOT the back.
///
/// THE BACK IS NOT A DELAY, IT IS THE END OF THE RUN. The queue only
/// ever shrinks, so an item pushed to the back is by construction the
/// last thing dispatched: its second refusal lands as the drain empties,
/// with no download left behind it. That is not "a long delay" - it is
/// the maximum one, on every run, and it is the exact condition
/// `Work::soft_430`'s own front-insert exists to refuse, sixty lines up
/// in `session::handle_missing`: "at the back its verdict lands only as
/// the drain empties - on a long download that defers a terminal Missing
/// by the WHOLE download, and the M2c.5 speculative prefetch never sees
/// the damage while there is still a download to overlap (the 7 Aug
/// nightly red)".
///
/// `recheck_430_max` was reached for to cover that and CANNOT: it bounds
/// how MANY articles hold a verdict at once, and the harm here is about
/// WHEN one lands. A run losing a percent of a slice - which is what the
/// measured fault looks like, and what the bound was sized for - never
/// comes near 4096 holds, so the common case was regressed whole while
/// only the pathological one stayed covered. Measured 29 Aug 2026 on
/// origin/main at `dd325f669`, both deterministic over both nextest
/// attempts and both green again under `NZBFAST_RECHECK_430=0`:
///
///   * `e2e::speculative_prefetch_covers_deficit_and_repair_still_runs`
///     - "speculative prefetch never fired". The verdict landed at
///     `queue dry at 1.97s · drained at 2.43s`, so the watcher's poll
///     saw a deficit of zero for the whole download and repair ran
///     serially afterwards. Correct output, none of the overlap M2c.5
///     exists to buy.
///   * `e2e::e2e_chaserepair::a_paged_out_wedged_chase_repairs_in_place_too`
///     - "the hole was not repaired through the mapped path". Worse than
///     a lost optimisation: a paged-out chase parked on the hole holds
///     its buffers until the verdict frees them, so the longer wait
///     breached the holds cap, `chase trimmed 5 MB (5 dropped)`, and the
///     mapped repair then declined for want of backing data and fell
///     back to materializing volumes on disk plus a second extract. The
///     2G sibling of that test passes, which is what says the harm is
///     the WAIT meeting a budget rather than the re-ask itself.
///
/// THE RULE IS THE MIDPOINT, and it is the largest delay that still
/// leaves the consumer a window: half the remaining queue is dispatched
/// before the re-ask (the time TODO 315 is buying) and half after it (the
/// download the prefetch overlaps, and the bound on how long a chase
/// parks). It is self-scaling in the direction the evidence wants - on
/// the 17 GB slice behind this mechanism half a queue is still minutes,
/// against the nine that recovered 231 of 250 refusals, while on a short
/// run there is neither much time to buy nor much window to protect. The
/// FRONT was already rejected for this mechanism and still is: alignment
/// is not what a cold backend needs, time is.
///
/// Never before the promoted prefix. A promoted article cannot be held
/// at all (`handle_missing` excludes it), but the prefix is other
/// people's playhead work and inserting into it strands a player exactly
/// as the queue back would - the same books every other reinsert on this
/// queue keeps.
///
/// Do NOT "simplify" this back to `push_back`. It reads as the same
/// mechanism with a tidier line and it is the regression above.
pub(super) fn recheck_slot(q: &VecDeque<Work>) -> usize {
    let promoted = q.iter().take_while(|w| w.promoted).count();
    (q.len() / 2).max(promoted).min(q.len())
}

/// TODO 315: is this group's `tried_430` bit down RIGHT NOW because a
/// late re-ask is holding it open?
///
/// Two conditions and both are load-bearing. The group must have spent
/// a hold on this article, and the bit that hold suppressed must still
/// be down - a hold whose re-ask has been ANSWERED leaves `recheck_430`
/// set for ever (that is what makes the pass terminate at one re-ask
/// per group), so asking only the first question calls a settled
/// article held and refuses evidence about it for the rest of the run.
pub(super) fn holding(w: &Work, group_bits: u32) -> bool {
    w.recheck_430 & group_bits == group_bits && w.tried_430 & group_bits != group_bits
}

/// TODO 315: give back the evidence a hold is suppressing, once the
/// window at [`RECHECK_430_HOLD`] is up. True when this call restored a
/// bit, which is exactly once per hold.
///
/// `now_ms` is milliseconds since `Shared::start` - `next_work` already
/// computes it for the scan-futile throttle, so the expiry check costs
/// an integer compare per queued item and no clock read at all. A
/// `hold_ms` of 0 turns the bound off.
///
/// WHAT IS RESTORED IS `recheck_430` ITSELF, and that is not the forged
/// bit `pool/gates.rs` is emphatic about refusing. Every group in that
/// mask 430'd this article - answering was the precondition for taking
/// the hold - so the mask is the evidence, recorded at the moment it
/// was suppressed. Restoring it puts the article back exactly where it
/// stood before the re-ask was bought, which is a live-unanimous
/// verdict its caller has already been waiting on. There is no second
/// "which bits are currently down" field for the same reason: the two
/// masks answer it between them, and a third copy of one fact is a
/// third thing to keep in step.
///
/// Idempotent, so the two callers may both run it on the same item in
/// either order.
pub(super) fn expire_hold(w: &mut Work, now_ms: u64, hold_ms: u64) -> bool {
    if hold_ms == 0 || w.recheck_430 == 0 || w.tried_430 & w.recheck_430 == w.recheck_430 {
        return false;
    }
    if now_ms.saturating_sub(u64::from(w.recheck_at)) < hold_ms {
        return false;
    }
    w.tried_430 |= w.recheck_430;
    true
}

#[cfg(test)]
mod tests {
    use super::super::unit_tests::work;
    use super::*;

    /// A held article whose window has not run out keeps the bit down -
    /// which is the whole mechanism, and the case a bound must not
    /// break.
    #[test]
    fn a_hold_inside_its_window_keeps_the_evidence_suppressed() {
        let mut w = work("<a@x>");
        w.tried_430 = 0b0001;
        w.recheck_430 = 0b0010;
        w.recheck_at = 1_000;
        assert!(!expire_hold(&mut w, 1_999, 1_000));
        assert_eq!(w.tried_430, 0b0001);
        assert!(holding(&w, 0b0010));
    }

    /// The window is inclusive at its edge, and the edge is pinned in
    /// both directions by the case above: one millisecond either side
    /// of it is a different answer.
    #[test]
    fn the_window_expires_at_its_edge_and_restores_exactly_the_held_bits() {
        let mut w = work("<a@x>");
        w.tried_430 = 0b0001;
        w.recheck_430 = 0b0010;
        w.recheck_at = 1_000;
        assert!(expire_hold(&mut w, 2_000, 1_000));
        assert_eq!(w.tried_430, 0b0011, "the suppressed bit, and nothing else");
        assert!(!holding(&w, 0b0010));
    }

    /// Idempotent: the queue scan and the duplicate fold both run it,
    /// and a second call must not report a restore that already
    /// happened - the run-wide counter behind the one-shot warning
    /// reads exactly this return.
    #[test]
    fn expiring_a_hold_twice_reports_the_restore_once() {
        let mut w = work("<a@x>");
        w.tried_430 = 0b0001;
        w.recheck_430 = 0b0010;
        w.recheck_at = 0;
        assert!(expire_hold(&mut w, 9_999, 1_000));
        assert!(!expire_hold(&mut w, 9_999, 1_000));
    }

    /// Zero turns the bound off - the pre-30-Aug shape, which the
    /// wedge rig's control arm runs and which
    /// `NZBFAST_RECHECK_430_HOLD_SECS=0` asks for by hand.
    #[test]
    fn a_zero_window_is_no_bound_at_all() {
        let mut w = work("<a@x>");
        w.tried_430 = 0b0001;
        w.recheck_430 = 0b0010;
        w.recheck_at = 0;
        assert!(!expire_hold(&mut w, u64::MAX, 0));
        assert_eq!(w.tried_430, 0b0001);
    }

    /// An article that never held one is not this mechanism's to touch,
    /// however long the run has been going.
    #[test]
    fn an_article_that_never_held_a_re_ask_is_left_alone() {
        let mut w = work("<a@x>");
        w.tried_430 = 0b0001;
        assert!(!expire_hold(&mut w, u64::MAX, 1_000));
        assert_eq!(w.tried_430, 0b0001);
        assert!(!holding(&w, 0b0010));
    }

    /// A hold whose re-ask was ANSWERED leaves `recheck_430` set for
    /// ever - that is what makes the pass terminate at one re-ask per
    /// group - so neither half may go on calling it held. `holding`
    /// asking only about `recheck_430` is what made the duplicate fold
    /// refuse evidence about a settled article for the rest of the run.
    #[test]
    fn an_answered_hold_is_not_held_any_more() {
        let mut w = work("<a@x>");
        w.tried_430 = 0b0011;
        w.recheck_430 = 0b0010;
        w.recheck_at = 0;
        assert!(!holding(&w, 0b0010));
        assert!(!expire_hold(&mut w, u64::MAX, 1_000));
    }

    /// Only the group whose bit is DOWN is held. A dup arriving from
    /// some other group is ordinary evidence and must still fold - the
    /// point `next_work`'s own note makes about unanimity.
    #[test]
    fn another_groups_evidence_is_never_treated_as_held() {
        let mut w = work("<a@x>");
        w.tried_430 = 0b0001;
        w.recheck_430 = 0b0010;
        assert!(!holding(&w, 0b0100));
    }

    /// The shipped window has to clear the nine minutes the measurement
    /// behind [`Shared::take_recheck`] recovered its articles in, or the
    /// bound is the mechanism switched off rather than bounded.
    #[test]
    fn the_shipped_window_clears_the_measurement_it_is_covering() {
        assert!(RECHECK_430_HOLD >= std::time::Duration::from_secs(9 * 60));
    }
}
