//! Held-bytes backpressure, the extractor half (TODO 94 item E,
//! 22 Aug 2026): park a chased group's article pulls near the holds
//! cap instead of demoting the set.
//!
//! What §92 left open was the set whose arrivals run so far ahead of
//! the decode that the live window alone fills the cap, and the
//! single-volume chased archive with no split member to trim behind.
//! Both end the same way today: the budget breaks, the breach ladder
//! in `chase_span` trims what it can, and then forfeits the chase -
//! the volumes materialize and the whole set is unpacked a SECOND time
//! from disk (2.0x of payload in device I/O, measured on the TODO 220
//! rounds). Every byte of that second pass is a byte that arrived
//! before the engine wanted it.
//!
//! So the extractor now says so upstream. At [`park_engage_mark`] it
//! first runs the drop-behind trim once (the engine may be past a
//! prefix nobody has asked to release yet, since that trim only ever
//! ran on a breach), and if the holds are still high it PARKS the
//! chased groups' root slots through the hook the download wired, with
//! an ALLOWANCE: the bytes the group may have in flight, which is the
//! room left under the cap ([`park_allowance`]). The pool admits the
//! group's articles up to that and spends the rest of the connections
//! on the rest of the job (see `pool::park`). Every later arrival and
//! every engine progress mark re-runs the check: the trim releases the
//! consumed prefix as the engine gets there and the allowance is
//! refreshed to the new room, so admission tracks the engine
//! continuously - an earlier on/off design released the whole fleet at
//! a low-water mark and the burst breached the cap on its own. The
//! slots are released when their group stops chasing.
//!
//! Two things fall out of throttling the arrivals rather than the
//! retention. The breach ladder is untouched and still governs an
//! engine that is genuinely stuck (a parked file's trickle still reaches
//! the cap, just slowly), so no case that demoted before can now hang.
//! And the trim's drop-or-spill gate is a PACE ratio (consumed against
//! arrived, `rar_engine_keeping_pace`): with the arrivals held to the
//! engine's pace the chase reads as healthy, so the prefix is dropped
//! for free instead of spilled into the volume file.
//!
//! Root only: pool files are the root's slots. A nested chase charges
//! the same chain budget, and the root slots feeding it are what park -
//! its holds are counted, its group is found through the child.

use super::*;
use crate::sync::MutexExt;

/// `(root slots, allowance)`: the pool parks the pending articles of
/// these slots behind `Some(bytes)` of shared in-flight allowance, or
/// releases them on `None`. Installed by the download on the root
/// extractor ([`Extractor::set_park_hook`]), called off-lock.
pub type ParkHook = Arc<dyn Fn(&[usize], Option<u64>) + Send + Sync>;

/// `(wire, pipeline)`: bytes already on the wire for this job (the
/// pool's charged in-flight BODY estimate) and bytes between the wire
/// and the holds - raw bodies in the fetch->decode channel and decoder
/// hands, decoded payloads queued behind the routing lock. Both land
/// in the holds whatever the park decides, so the engage mark is read
/// against holds plus both, and the allowance is the room left after
/// the pipeline. Without the first a park fired at the mark breached
/// the cap by the wire's worth on the 22 Aug rig (60 connections x
/// window 4 x 700 KB of a 315 MB cap); without the second it engaged
/// at "holds 222 MB + wire 3 MB" with 460 MB already off the wire and
/// waiting to be routed. Read under the routing lock: atomic loads
/// behind a short mutex that nothing holds while calling into the
/// extractor.
pub type WireGauge = Arc<dyn Fn() -> (u64, u64) + Send + Sync>;

/// Escape hatch: `NZBFAST_NO_HOLDS_PARK=1` restores the breach-only
/// behaviour (arrivals never throttled, the set forfeits at the cap).
/// Latched at construction like the other gates.
pub(super) fn holds_park_env_off() -> bool {
    holds_park_env_off_value(std::env::var("NZBFAST_NO_HOLDS_PARK").ok().as_deref())
}

/// Pure parse of the escape-hatch value.
pub(super) fn holds_park_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Where the park engages: three quarters of the cap, read against
/// holds plus wire. Below it a chase is left entirely alone, so a set
/// that fits never pays the per-candidate lookup in `next_work`.
pub(super) fn park_engage_mark(cap: usize) -> usize {
    cap / 4 * 3
}

/// The in-flight allowance for a parked group: the room between the
/// holds plus the decode pipeline and seven eighths of the cap. The
/// eighth held back covers the pool's admission slack and the
/// pre-classification holds of other slots that land in the same
/// budget. Zero is a valid answer - the pool still admits one article
/// to a group with nothing in flight.
pub(super) fn park_allowance(cap: usize, holds: usize, pipeline: u64) -> u64 {
    ((cap / 8 * 7).saturating_sub(holds) as u64).saturating_sub(pipeline)
}

/// Root-side park bookkeeping, under the routing lock.
pub(super) struct ParkState {
    pub(super) hook: Option<ParkHook>,
    pub(super) wire: Option<WireGauge>,
    /// Root slots currently parked at the pool.
    pub(super) parked: Vec<usize>,
    /// The allowance last published for them.
    pub(super) allow: u64,
    /// Hook calls raised under the lock, flushed by
    /// [`Extractor::flush_pending_park`] once it drops.
    pub(super) pending: Vec<(Vec<usize>, Option<u64>)>,
    /// Park episodes this run (diagnostics).
    pub(super) cycles: u64,
    /// Gate (`NZBFAST_NO_HOLDS_PARK`), latched at construction.
    pub(super) on: bool,
}

impl ParkState {
    pub(super) fn new() -> ParkState {
        ParkState {
            hook: None,
            wire: None,
            parked: Vec::new(),
            allow: 0,
            pending: Vec::new(),
            cycles: 0,
            on: !holds_park_env_off(),
        }
    }
}

impl Extractor {
    /// Install the held-bytes backpressure hook (root only; a child's
    /// slots are not pool files). Install before any span arrives, like
    /// the promote hook.
    pub fn set_park_hook(self: &Arc<Self>, hook: ParkHook, wire: Option<WireGauge>) {
        if self.depth != 0 {
            return;
        }
        self.anchor();
        let mut inner = self.inner.lock_ok();
        inner.park.hook = Some(hook);
        inner.park.wire = wire;
    }

    /// `(wire, pipeline)` from the gauge, zeros without one.
    fn park_gauge(inner: &Inner) -> (u64, u64) {
        inner.park.wire.as_ref().map_or((0, 0), |g| g())
    }

    /// Holds plus whatever is already on the wire or in the decode
    /// pipeline for this job: the number the engage mark is read against.
    fn park_pressure(inner: &Inner) -> usize {
        let (wire, pipeline) = Self::park_gauge(inner);
        inner
            .budget
            .len()
            .saturating_add(wire as usize)
            .saturating_add(pipeline as usize)
    }

    /// The chain's root, weakly: where the park lives. A root answers
    /// with itself; a child walks its parent links up, which is the
    /// direction the promote walk already takes.
    pub(super) fn park_root(self: &Arc<Self>) -> Weak<Extractor> {
        let mut cur = self.clone();
        while cur.depth != 0 {
            let Some(p) = cur.parent.upgrade() else { break };
            cur = p;
        }
        Arc::downgrade(&cur)
    }

    /// The engine moved while something was parked (pager thread, woken
    /// by the chase worker's progress mark): re-read the holds and
    /// release what the trim now can. Root only; a no-op when nothing
    /// is parked, so a stray wake costs one lock and one field read.
    pub(super) fn park_progress(&self) {
        if self.depth != 0 {
            return;
        }
        {
            let mut inner = self.inner.lock_ok();
            if inner.park.parked.is_empty() {
                return;
            }
            // A failing trim is a spill write failing; the owning slot
            // sees it again on its next span, where it is reported.
            let _ = self.park_reeval(&mut inner);
        }
        // The trim plans its spills under the lock and writes them
        // here, off it - the same contract the arrival path honours in
        // `flush_pending_fwd`. A parked set with a vouching verifier
        // drops instead and queues nothing.
        let _ = self.flush_pending_spills();
        self.flush_pending_park();
    }

    /// Park episodes raised this run - the number the mem summary
    /// quotes. Zero means the holds never reached the high-water mark
    /// while a group was chased.
    pub fn holds_park_cycles(&self) -> u64 {
        self.inner.lock_ok().park.cycles
    }

    /// Root slots whose articles feed a live chase: every slot of a
    /// group with a RAR chase or in 7z chase mode, and every slot of a
    /// group whose routed inner files feed a chasing child.
    fn chased_root_slots(inner: &Inner) -> Vec<usize> {
        let mut out: Vec<usize> = Vec::new();
        for g in inner.groups.values() {
            if g.fallback {
                continue;
            }
            let own = g.chase.is_some()
                || g.slots
                    .iter()
                    .any(|&s| matches!(inner.slots[s].mode, SlotMode::SevenZ));
            let via_child = !own
                && !g.routed.is_empty()
                && inner.child.as_ref().is_some_and(|c| {
                    let routed: Vec<usize> = g.routed.values().copied().collect();
                    c.has_live_chase(&routed)
                });
            if own || via_child {
                out.extend(g.slots.iter().copied());
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The child half of [`Self::chased_root_slots`]: do any of these
    /// child slots carry a live chase? Takes the child's lock with the
    /// parent's held - the same nesting `relieve_chase_for_parent`
    /// already uses, and safe for the same reason.
    pub(super) fn has_live_chase(&self, slots: &[usize]) -> bool {
        let inner = self.inner.lock_ok();
        slots.iter().any(|&s| {
            inner.slots.get(s).is_some_and(|sl| {
                matches!(sl.mode, SlotMode::SevenZ) || Self::rar_chase_of(&inner, s).is_some()
            })
        })
    }

    /// Re-read the holds against the engage mark and queue whatever
    /// park, refresh or release that calls for. Root only, under the
    /// routing lock, once per arriving article - a gauge read (three
    /// atomics behind a short mutex) and one compare while nothing is
    /// near the cap, which is almost always.
    pub(super) fn park_reeval(&self, inner: &mut Inner) -> io::Result<()> {
        if self.depth != 0 || !inner.park.on || inner.park.hook.is_none() {
            return Ok(());
        }
        let cap = inner.budget.cap();
        if inner.park.parked.is_empty() {
            if Self::park_pressure(inner) < park_engage_mark(cap) {
                return Ok(());
            }
            // The drop-behind only ever ran on a breach: the engine may
            // be well past a prefix that was never asked for. Release
            // that first, and park only what is left.
            self.trim_live_chases(inner)?;
            if Self::park_pressure(inner) < park_engage_mark(cap) {
                return Ok(());
            }
            let targets = Self::chased_root_slots(inner);
            if targets.is_empty() {
                return Ok(());
            }
            let (wire, pipeline) = Self::park_gauge(inner);
            let allow = park_allowance(cap, inner.budget.len(), pipeline);
            tracing::debug!(
                target: "extract",
                "holds backpressure engaged: holds {} MB + wire {} MB + pipeline {} MB against a {} MB cap, {} slot(s) parked behind a {} MB allowance",
                inner.budget.len() >> 20,
                wire >> 20,
                pipeline >> 20,
                cap >> 20,
                targets.len(),
                allow >> 20
            );
            inner.park.cycles += 1;
            inner.park.pending.push((targets.clone(), Some(allow)));
            inner.park.parked = targets;
            inner.park.allow = allow;
            self.park_live.store(true, Ordering::Release);
            return Ok(());
        }
        // Parked: each arrival and each engine progress mark is a report.
        // Trim what the engine has consumed, then refresh the allowance
        // to the room that leaves. Slots whose group stopped chasing
        // meanwhile (a forfeit, a finish) are released - their articles
        // must flow to materialize; a slot that JOINED a parked group
        // since (its header article landed after the mark was crossed)
        // parks with the rest.
        self.trim_live_chases(inner)?;
        let still = Self::chased_root_slots(inner);
        let (keep, gone): (Vec<usize>, Vec<usize>) =
            inner.park.parked.iter().partition(|s| still.contains(s));
        let joined: Vec<usize> = still
            .iter()
            .copied()
            .filter(|s| !keep.contains(s))
            .collect();
        if !gone.is_empty() {
            inner.park.pending.push((gone, None));
        }
        inner.park.parked = keep;
        inner.park.parked.extend(joined.iter().copied());
        let allow = park_allowance(cap, inner.budget.len(), Self::park_gauge(inner).1);
        if !inner.park.parked.is_empty() && (allow != inner.park.allow || !joined.is_empty()) {
            inner.park.allow = allow;
            inner
                .park
                .pending
                .push((inner.park.parked.clone(), Some(allow)));
        }
        self.park_live
            .store(!inner.park.parked.is_empty(), Ordering::Release);
        Ok(())
    }

    /// One drop-behind pass over every live RAR chase at this level.
    fn trim_live_chases(&self, inner: &mut Inner) -> io::Result<()> {
        let ctls: Vec<Arc<ChaseCtl>> = inner
            .groups
            .values()
            .filter_map(|g| g.chase.clone())
            .collect();
        for ctl in &ctls {
            self.rar_trim_set(inner, ctl, true)?;
        }
        Ok(())
    }

    /// Deliver the park calls queued under the lock. Off-lock: the hook
    /// reaches into the pool's queue control.
    pub(super) fn flush_pending_park(&self) {
        let (hook, queued) = {
            let mut inner = self.inner.lock_ok();
            if inner.park.pending.is_empty() {
                return;
            }
            (
                inner.park.hook.clone(),
                std::mem::take(&mut inner.park.pending),
            )
        };
        let Some(hook) = hook else { return };
        for (slots, allow) in queued {
            hook(&slots, allow);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_off_parses_only_the_literal_one() {
        assert!(holds_park_env_off_value(Some("1")));
        assert!(!holds_park_env_off_value(Some("0")));
        assert!(!holds_park_env_off_value(Some("")));
        assert!(!holds_park_env_off_value(None));
    }

    #[test]
    fn the_allowance_is_the_room_under_the_cap_and_never_overshoots() {
        for cap in [HOLDS_CAP_FLOOR, 315 << 20, 1 << 30, 7 << 30] {
            let engage = park_engage_mark(cap);
            assert!(engage < cap, "cap {cap}: engage {engage}");
            // At the engage mark there is still room; at the cap none;
            // a full pipeline eats the room too.
            assert!(park_allowance(cap, engage, 0) > 0);
            assert_eq!(park_allowance(cap, cap, 0), 0);
            assert_eq!(park_allowance(cap, cap / 8 * 7, 0), 0);
            assert_eq!(park_allowance(cap, engage, cap as u64), 0);
            // Holds plus pipeline plus the allowance never pass seven
            // eighths.
            for holds in [0, cap / 3, engage] {
                for pipeline in [0u64, (cap / 16) as u64] {
                    assert!(
                        holds as u64 + pipeline + park_allowance(cap, holds, pipeline)
                            <= (cap / 8 * 7) as u64
                    );
                }
            }
        }
    }
}
