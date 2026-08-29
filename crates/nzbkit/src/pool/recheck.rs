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
