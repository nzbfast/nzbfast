//! The §74 instant watchlist path - how a name that just arrived turns
//! into a grab without waiting for the next watchlist pass. A child
//! module of `daemon` rather than more lines of it (TODO 106, the
//! code-quality refactor).
//!
//! One question at three depths. WHETHER: `watchlist_external_on` says
//! whether the watchlist may spend the user's indexer accounts at all.
//! WHAT MATCHES: `instant_matcher` compiles the live watchlist into the
//! matcher the arrival paths test names against, and answers `None`
//! when there is nothing enabled, so an install with no watchlist pays
//! nothing for the feature. WHAT HAPPENS: `stage_instant_hint` stages
//! the matched names under the hourly allowance and `instant_kick`
//! wakes the pass; they are two functions rather than one because the
//! scan leg stages its arrivals while it still holds the `index` mutex
//! it is republishing under, and everything else wants both.
//!
//! A second `impl Daemon` in a child module of `daemon`, so `Daemon`'s
//! private fields (`watchlist_external`, `watchlist_instant`,
//! `instant_kicks`, `instant_hint`, `watch_now`) stay in scope exactly
//! as they were inline. `pub(super)` became `pub(crate)`
//! here, because `super` is `daemon` from inside a child.
//!
//! No cfg on the module, the same call the indexer-gated siblings make:
//! `watchlist_external_on` is read off the settings path in every
//! build, so the `indexer` gates stay per-item.

use super::*;

impl Daemon {
    /// May the watchlist spend the user's indexer accounts? See
    /// `watchlist_external_set` for why this is a tri-state rather than
    /// the plain bool it reads like.
    pub fn watchlist_external_on(&self) -> bool {
        if self.watchlist_external_set.load(Ordering::Relaxed) {
            self.watchlist_external.load(Ordering::Relaxed)
        } else {
            self.enabled_indexers() > 0
        }
    }

    /// §74: the instant watchlist path, compiled from the live watchlist.
    /// `None` when the feature is off or there is nothing enabled to
    /// match - the callers use that to skip installing an arrival watch
    /// at all, so an install without a watchlist pays nothing.
    #[cfg(feature = "indexer")]
    pub fn instant_matcher(&self) -> Option<nzbfast_meta::watchlist::InstantMatcher> {
        if !self.watchlist_instant.load(Ordering::Relaxed) {
            return None;
        }
        // watch_items: a synced entry gets the instant grab too (§151).
        let m = nzbfast_meta::watchlist::InstantMatcher::compile(&self.watch_items());
        (!m.is_empty()).then_some(m)
    }

    /// §74: wake the watchlist pass because `names` just arrived, unless
    /// this hour's allowance of instant passes is already spent.
    ///
    /// Returns whether the pass was woken. A refusal is not a lost grab:
    /// the periodic pass runs a minute later over the same index and
    /// applies exactly the same rules, so the ceiling only ever costs the
    /// "instant" part.
    #[cfg(feature = "indexer")]
    pub fn instant_kick(&self, names: &[String], now: i64) -> bool {
        let staged = self.stage_instant_hint(names, now);
        if staged {
            self.watch_now.notify_one();
        }
        staged
    }

    /// §74: the hint half of [`Self::instant_kick`], without the wake-up.
    ///
    /// Split out so the scan leg can stage its arrivals while it still
    /// holds the `index` mutex it is republishing under - see
    /// [`Daemon::publish_index_with_arrivals`]. Everything else wants the
    /// two together and calls `instant_kick`.
    ///
    /// Returns whether the names were staged; false means this hour's
    /// allowance is spent and there is nothing to wake anyone for.
    #[cfg(feature = "indexer")]
    pub fn stage_instant_hint(&self, names: &[String], now: i64) -> bool {
        if names.is_empty() {
            return false;
        }
        {
            let mut k = self.instant_kicks.lock_ok();
            if !nzbfast_meta::watchlist::kick_allowed(
                &mut k,
                self.watchlist_instant_max.load(Ordering::Relaxed),
                now,
            ) {
                return false;
            }
        }
        {
            // The pass drains this, so a second arrival landing before it
            // runs joins the same wake-up rather than queueing another.
            let mut hint = self.instant_hint.lock_ok();
            for n in names {
                if !hint.contains(n) {
                    hint.push(n.clone());
                }
            }
            // A watchlist item nobody grabs (below min_quality, say) would
            // otherwise keep re-arriving and grow this without bound.
            const HINT_CAP: usize = 256;
            if hint.len() > HINT_CAP {
                let excess = hint.len() - HINT_CAP;
                hint.drain(..excess);
            }
        }
        true
    }
}
