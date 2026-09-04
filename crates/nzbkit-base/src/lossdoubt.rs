//! The pool-to-extractor doubt flag: one `AtomicBool` the connection
//! pool raises and the extractor's drop-behind trim reads.
//!
//! It sits at the crate root rather than inside either of them because
//! it is exactly the seam BETWEEN them: `pool::PoolConfig` carries an
//! `Option<Arc<LossDoubt>>` and `extract::Extractor` an `Arc<LossDoubt>`,
//! so with the type declared in the extractor the connection pool had to
//! reach up into it for a six-line newtype - the last edge standing
//! between `pool` and `extract` being separable crates (nzbkit split
//! lane 1, 3 Sep 2026). `extract` re-exports it, so
//! `nzbkit::extract::LossDoubt` is unchanged.

use std::sync::atomic::{AtomicBool, Ordering};

/// A doubt the CALLER raises about an article whose terminal verdict it
/// has DEFERRED, and the reason `Inner::lost_articles` is not enough on
/// its own.
///
/// That flag is set from a TERMINAL fetch verdict, and
/// [`Extractor::note_article_lost`] says in its own doc why that lands
/// late: "verdicts typically land AFTER the pile has built (retries
/// exhaust last)". The drop-behind trim reads the flag as its veto -
/// "no lost article anywhere in the job: a demote waiting to happen,
/// and a demote after a drop is a re-download" - so between the pool
/// deciding an article is one refusal from gone and the verdict
/// actually landing, the trim can DROP a prefix a repair will need.
/// Measured 30 Aug 2026 and written up in
/// `research/CHASE-TRIM-DROPS-BEFORE-VERDICT-2026-08-30.md`: under the
/// holds backpressure park (whose arm bypasses the pace and can-finish
/// gates by design) the pass dropped five megabytes of a PAR2-vouched
/// prefix, `try_mapped_repair` then declined for want of backing data,
/// and the set took the disk ladder with a re-fetch on top - the exact
/// three-write route the row-26 chase repair exists to remove.
///
/// So this is the SAME veto, raised EARLIER: the pool raises it at the
/// moment it decides a refusal is the last evidence an article needs
/// and holds the verdict back anyway (TODO 315's late re-ask, and
/// §129's confirming repeat for a bare refusal that would be
/// live-unanimous with this group's bit folded in). It is deliberately
/// NOT raised on every 430 - an article a later server answers is not
/// doubt about the JOB - and it does not arm the stalled-chase paging
/// pass, which does real disk I/O and wants the terminal mark.
///
/// STICKY and never cleared, exactly like the flag it stands in front
/// of. A re-ask that succeeds does not give back a prefix already
/// dropped, so a flag that could fall again would reopen the same
/// window it closes. A clean job cannot raise it at all: nothing here
/// happens without a 430 that has walked the whole live fleet.
#[derive(Debug, Default)]
pub struct LossDoubt(AtomicBool);

impl LossDoubt {
    /// Raise the doubt. Cheap enough for the pool's refusal path: one
    /// relaxed store, no lock - which is the whole reason the flag is
    /// handed out as an `Arc` rather than reported through a method on
    /// the extractor, whose every entry point takes the global mutex.
    pub fn raise(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    /// Has any article's terminal verdict been held back?
    pub fn raised(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}
