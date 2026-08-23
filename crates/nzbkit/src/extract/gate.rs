//! §94 B for a ROUTED child (shape-coverage row 27): the verify gate a
//! nested chase waits on.
//!
//! The root's chase buffers key straight into the PAR2 watermark by
//! slot. A child chase's volume is not a PAR2 file at all - it is an
//! entry the parent's store mapping carved out of SEVERAL parent
//! volumes (`Group::bases` says which piece of which volume lands
//! where), so the only honest watermark for it is a translation: the
//! child offset up to which every contributing parent piece is vouched
//! for. Before this existed the child slot never claimed, its cell read
//! `u64::MAX`, and the inner decode consumed poster-damaged bytes long
//! before settle's mapped repair corrected the outer - whereupon the
//! corrected span routed into the child frontier behind its decode and
//! the chase forfeited with `"repair rewrote chased bytes"`, at
//! 2.55x payload of disk I/O against 0.99x clean (22 Aug 2026,
//! M3 Ultra, loopback). Gated, the decode parks at the damaged block,
//! the repair lands on bytes nothing has read, and the chase finishes
//! one-pass.
//!
//! Lock discipline: the decode thread calls [`ChildGate::watermark`]
//! with NO lock held (the frontier drops its state lock first). The
//! walk takes the parent's routing lock only to copy the pieces out,
//! releases it, and then asks each contributing slot for its own mark -
//! which for a root slot is the `VerifyGate` cell and for a deeper
//! level recurses through that level's parent the same way. Parent and
//! child locks are never nested, in either order, which is the
//! invariant every routing path in `mod.rs` already keeps.

use super::*;
use crate::sync::MutexExt;

/// One contributing parent piece of a routed child slot, in child
/// (entry) offsets: `[base, base + len)` of the child is
/// `[data_off, data_off + len)` of parent volume `slot`.
#[derive(Clone, Copy)]
struct Piece {
    slot: usize,
    data_off: u64,
    len: u64,
    base: u64,
}

/// [`crate::live::ChaseGate`] for a routed child slot. Holds the parent
/// weakly, like everything else that reaches across a level: a dropped
/// job must not be pinned by its own chase worker. A dead parent reads
/// as ungated - the decode then behaves exactly as it did before the
/// gate existed, and the frontier's conflict tripwire still stands
/// behind it.
pub(super) struct ChildGate {
    parent: Weak<Extractor>,
    /// The child slot this gate guards, in the child's slot space.
    slot: usize,
    /// Last limit computed. Monotonic by construction (watermarks only
    /// advance, pieces only resolve), so a read below it is answered
    /// without touching the parent at all - the engine's reads are
    /// small and many, the walk is per-read otherwise.
    cached: Mutex<u64>,
}

impl ChildGate {
    pub(super) fn new(parent: Weak<Extractor>, slot: usize) -> ChildGate {
        ChildGate {
            parent,
            slot,
            cached: Mutex::new(0),
        }
    }
}

impl crate::live::ChaseGate for ChildGate {
    fn watermark(&self) -> u64 {
        let Some(p) = self.parent.upgrade() else {
            return u64::MAX;
        };
        let lim = p.routed_vouched_to(self.slot);
        let mut c = self.cached.lock_ok();
        *c = (*c).max(lim);
        *c
    }

    fn wait_past(&self, offset: u64, timeout: std::time::Duration) {
        if *self.cached.lock_ok() > offset {
            return;
        }
        if let Some(p) = self.parent.upgrade() {
            p.gate_wait_any(timeout);
        }
    }
}

impl Extractor {
    /// The gate a chase buffer for `slot` waits on, or None for an
    /// ungated decode (feature off, or nothing at any level to wait
    /// for). Root level: the slot's own [`crate::live::VerifyGate`]
    /// cell. A nested level: a [`ChildGate`] through the parent, which
    /// needs the chain anchored (`ensure_child` hands every child its
    /// parent's self-handle; the root's comes from `anchor()`) - an
    /// unanchored root leaves the child ungated, as it always was.
    pub(super) fn chase_gate(
        &self,
        inner: &Inner,
        slot: usize,
    ) -> Option<Arc<dyn crate::live::ChaseGate>> {
        if !inner.verify_gate_waits {
            return None;
        }
        if let Some(g) = inner.verify_gate.clone() {
            return Some(Arc::new(crate::live::SlotGate { gate: g, slot }));
        }
        if self.depth == 0 || self.parent.upgrade().is_none() {
            return None;
        }
        Some(Arc::new(ChildGate::new(self.parent.clone(), slot)))
    }

    /// Bytes of this level's `slot` below this offset are PAR2-vouched.
    /// Root: the gate cell (unengaged reads `u64::MAX`, exactly as the
    /// root buffers see it). Nested: translated through the parent. No
    /// lock held on entry, none on exit.
    fn slot_vouched_to(&self, slot: usize) -> u64 {
        let gate = self.inner.lock_ok().verify_gate.clone();
        if let Some(g) = gate {
            return g.watermark(slot);
        }
        match self.parent.upgrade() {
            Some(p) if self.depth > 0 => p.routed_vouched_to(slot),
            _ => u64::MAX,
        }
    }

    /// The child offset up to which every parent piece routed into
    /// child slot `cs` is vouched for. Walks the pieces in child-offset
    /// order and stops at the first that is not wholly vouched (or not
    /// yet resolved - a base the routing has not placed cannot have
    /// routed bytes either, so stopping there withholds nothing that
    /// has arrived). A slot no group routes to - a chase sink, a plain
    /// child file - is not PAR2 data and reads as ungated.
    pub(super) fn routed_vouched_to(&self, cs: usize) -> u64 {
        let pieces = {
            let inner = self.inner.lock_ok();
            let mut found: Option<Vec<Piece>> = None;
            for g in inner.groups.values() {
                let Some((name, _)) = g.routed.iter().find(|&(_, &s)| s == cs) else {
                    continue;
                };
                let mut v: Vec<Piece> = g
                    .bases
                    .iter()
                    .filter_map(|(&(slot, ei), &base)| {
                        let e = inner.slots[slot].mapper.as_ref()?.entries.get(ei)?;
                        (e.name == *name && !e.is_dir).then_some(Piece {
                            slot,
                            data_off: e.data_off,
                            len: e.data_len,
                            base,
                        })
                    })
                    .collect();
                v.sort_by_key(|p| p.base);
                found = Some(v);
                break;
            }
            match found {
                Some(v) => v,
                None => return u64::MAX,
            }
        };
        let mut lim = 0u64;
        for p in pieces {
            if p.base != lim {
                // A hole in the resolved pieces (or a duplicate base):
                // nothing past it can be vouched for yet.
                break;
            }
            let w = self.slot_vouched_to(p.slot);
            if w >= p.data_off.saturating_add(p.len) {
                lim = p.base + p.len;
                continue;
            }
            lim = p.base + w.saturating_sub(p.data_off).min(p.len);
            break;
        }
        lim
    }

    /// Park until any watermark at the root may have moved, bounded.
    /// What [`ChildGate::wait_past`] stands on: it cannot name one cell,
    /// so it wakes on every advance and recomputes. No gate anywhere
    /// (the chain is ungated, or unanchored above this level) sleeps
    /// the bound out - the caller's loop re-checks everything after it.
    fn gate_wait_any(&self, timeout: std::time::Duration) {
        let gate = self.inner.lock_ok().verify_gate.clone();
        match (gate, self.parent.upgrade()) {
            (Some(g), _) => g.wait_any(timeout),
            (None, Some(p)) if self.depth > 0 => p.gate_wait_any(timeout),
            _ => std::thread::sleep(timeout),
        }
    }
}
