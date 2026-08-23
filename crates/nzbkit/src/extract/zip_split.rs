//! §94 D, the nested half: a byte-split zip (`inner.zip.001` ...)
//! INSIDE a store RAR, declared to the child extractor from the outer
//! archive's entry list.
//!
//! A zip split cannot be sized from its own bytes - no part carries a
//! container-sizing header, unlike 7z - so the chase needs a part COUNT
//! from whoever can see the whole file list. At depth 0 that is `get`,
//! reading the NZB (`declare_zip_split`). At depth > 0 there is no NZB
//! list; what there is instead is the outer archive's entry sequence,
//! which the parent level parses header by header as its volumes
//! arrive. That sequence IS the file list, and this module is the
//! wiring that reads the count off it.
//!
//! The shape of the problem fixes the shape of the wiring. A store RAR
//! lays its entries out one after another, so the header that FOLLOWS
//! the last sibling is the first thing that proves no `.004` is coming
//! - and that header sits behind every byte of the split. There is no
//! earlier oracle: nothing in a RAR header says "this is the last file
//! of its name", and the zip's own directory (which would say how big
//! the container is) is the one thing the split hides until the set
//! resolves. So the count always arrives AFTER the set's bytes have
//! passed through, and the set holds them meanwhile - a nested split
//! one-passes only when it fits the chase budget, and a larger one
//! forfeits to the disk pass exactly as an undeclared set did before
//! this module existed (the disk pass's `zip::scan` joins `.zip.001`
//! sets at any depth). That bound is structural, not a gap to close.
//! Measured 22 Aug 2026 (`zip_split_tests.rs`, the two budget pins):
//! the line is the holds cap less the outer volume's own header bytes
//! (149 for three parts and a readme), the peak held is the whole set
//! plus those headers, and a second, per-PART line sits at a quarter
//! of the cap for a part whose first byte arrives late - the TODO §94 D
//! note has the ladder.
//!
//! Three moments, two of them on the parent:
//!
//! 1. OPEN - `open_zip_split`, from `route_dest` as the first sibling
//!    routes into the child: the child's declaration map gets the base
//!    with count `None`, BEFORE the first forwarded byte reaches it
//!    (the same set-before-spans discipline as the NZB declaration),
//!    and the group remembers the base as open.
//! 2. CLOSE - `close_zip_splits`, from `reresolve` every time the
//!    group's entry list advances: walk the entries in volume order
//!    from part 1's first piece; a non-sibling entry behind the run,
//!    with no unparsed gap between, counts the set. A run whose indices
//!    are not exactly `1..=n` is REFUSED instead (the parts are not a
//!    set anyone can join; they materialize and the disk pass judges
//!    them). At the parent's `finish` every byte is in, so a set the
//!    archive ends on closes on what the walk collected.
//! 3. RESOLVE - on the child, `declare_zip_split_closed` /
//!    `refuse_zip_split`, delivered OFF the parent's lock
//!    (`pending_child_decl`, flushed beside the promotes): the count
//!    resolves the pending set and raises its tail promote.
//!
//! Why the walk insists on the gap rule rather than trusting a
//! resolved base: `reresolve_recompute` places volume ISLANDS on their
//! own (a season pack's later episodes resolve before its opening
//! volumes arrive), so "this entry has a base" does not mean every
//! entry before it has been seen. The walk only ever steps from a
//! COMPLETE mapper to the volume whose index is exactly one higher, so
//! a `.zip.003` sitting in a volume that has not parsed yet can never
//! be walked past.
//!
//! The negative control is free: a single `inner.zip` matches neither
//! part grammar, so it never opens a set and takes the single-container
//! attach it always took.

use super::*;
use crate::sync::MutexExt;
use std::collections::BTreeSet;

/// `(lowercased base, 1-based index)` when `name` is a zip split part
/// under either grammar the stream accepts - the SAME pair the child's
/// attach arm derives from its slot name, so both levels key one set
/// identically.
pub(super) fn part_of(name: &str) -> Option<(String, u32)> {
    crate::zip::split_part_name(name).or_else(|| crate::zip::numeric_split_part_name(name))
}

/// What the entry walk found for one base.
enum Walk {
    /// A non-sibling entry (with no unparsed gap) follows the run, or
    /// the walk has not found part 1's first piece yet. The set holds
    /// every index seen in the run.
    Closed(BTreeSet<u32>),
    /// The run may still continue: the next header is in bytes not yet
    /// parsed. Carries what has been seen so far, for the finish-time
    /// close.
    Open(BTreeSet<u32>),
}

impl Extractor {
    /// Moment 1: `key` (a raw entry name this group just routed into
    /// `child`) is a zip split part - open its set on the child and
    /// remember it here. Idempotent per base; a second sibling routing
    /// finds the set already open.
    pub(super) fn open_zip_split(
        &self,
        inner: &mut Inner,
        gk: &str,
        child: &Arc<Extractor>,
        key: &str,
    ) {
        let Some((base, _)) = part_of(key) else {
            return;
        };
        let Some(group) = inner.groups.get_mut(gk) else {
            return;
        };
        if group.zip_splits_open.contains(&base) {
            return;
        }
        group.zip_splits_open.push(base.clone());
        // Parent-then-child is the chain's lock order (`route_dest`
        // takes the child's lock for `preclaimed` on this same path).
        // `entry` keeps an NZB-style count already there - only the
        // depth-0 `get` path declares counts up front, and a child never
        // has one, but the discipline costs nothing.
        child
            .inner
            .lock_ok()
            .zip_split_decl
            .entry(base)
            .or_insert(None);
    }

    /// Moment 2, per entry-list advance: try to count every open set of
    /// group `key`. Returns immediately for a group with none.
    pub(super) fn close_zip_splits(&self, inner: &mut Inner, key: &str) {
        if inner.groups[key].zip_splits_open.is_empty() {
            return;
        }
        let bases = inner.groups[key].zip_splits_open.clone();
        for base in bases {
            if let Walk::Closed(seen) = self.walk_zip_split(inner, key, &base) {
                self.settle_zip_split(inner, key, &base, seen);
            }
        }
    }

    /// Moment 2, at finish: every byte is in, so what the walk has
    /// collected for a still-open set is the whole run whether or not a
    /// header follows it. Off-lock delivery follows, as the chain's
    /// promote discipline requires.
    pub(super) fn close_zip_splits_at_finish(&self) {
        {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            let keys: Vec<String> = inner
                .groups
                .iter()
                .filter(|(_, g)| !g.zip_splits_open.is_empty())
                .map(|(k, _)| k.clone())
                .collect();
            for key in keys {
                let bases = inner.groups[&key].zip_splits_open.clone();
                for base in bases {
                    let seen = match self.walk_zip_split(inner, &key, &base) {
                        Walk::Closed(s) | Walk::Open(s) => s,
                    };
                    self.settle_zip_split(inner, &key, &base, seen);
                }
            }
        }
        self.flush_pending_promote();
    }

    /// Count or refuse `base` from the walked run, queue the verdict for
    /// the child, and take the base off the open list.
    fn settle_zip_split(&self, inner: &mut Inner, key: &str, base: &str, seen: BTreeSet<u32>) {
        let n = seen.len() as u32;
        let contiguous =
            n > 0 && seen.iter().next() == Some(&1) && seen.iter().next_back() == Some(&n);
        inner
            .pending_child_decl
            .push((base.to_string(), contiguous.then_some(n)));
        inner
            .groups
            .get_mut(key)
            .unwrap()
            .zip_splits_open
            .retain(|b| b != base);
    }

    /// The entry walk. Volumes in archive order (the same index rule as
    /// `reresolve_recompute`: RAR5 volume numbers when every volume has
    /// one, else the name's number), entries in header order within
    /// each; start at part 1's FIRST piece and step forward, crossing
    /// from a complete mapper only into the volume numbered exactly one
    /// higher.
    fn walk_zip_split(&self, inner: &Inner, key: &str, base: &str) -> Walk {
        let slots = &inner.groups[key].slots;
        let all_numbered = slots.iter().all(|&si| {
            inner.slots[si]
                .mapper
                .as_ref()
                .is_some_and(|m| m.volume_number.is_some())
        });
        let mut vols: Vec<(u64, usize)> = slots
            .iter()
            .filter_map(|&si| {
                let m = inner.slots[si].mapper.as_ref()?;
                let idx = if all_numbered {
                    m.volume_number?
                } else {
                    // `reresolve_recompute` has run for this group, so
                    // the key is set; computing it here keeps the walk
                    // correct even if the order of those two ever moves.
                    match inner.slots[si].sort_key.as_ref() {
                        Some((n, _)) if *n != u64::MAX => *n,
                        Some(_) => return None,
                        None => {
                            let (n, _) = vol_sort_key(&inner.slots[si].name);
                            if n == u64::MAX {
                                return None;
                            }
                            n
                        }
                    }
                };
                Some((idx, si))
            })
            .collect();
        vols.sort_unstable();
        let mapper = |si: usize| inner.slots[si].mapper.as_ref().unwrap();
        let is_part = |e: &crate::rar::FileEntry| -> Option<u32> {
            if e.is_dir {
                return None;
            }
            part_of(&e.name).filter(|(b, _)| b == base).map(|(_, i)| i)
        };
        // Part 1's first piece anchors the run. Without it (not arrived,
        // or the archive opens mid-file) nothing has been seen: an empty
        // run is "refuse" at finish and "open" until then.
        let mut start = None;
        'find: for (vi, &(_, si)) in vols.iter().enumerate() {
            for (ei, e) in mapper(si).entries.iter().enumerate() {
                if is_part(e) == Some(1) && !e.split_before {
                    start = Some((vi, ei));
                    break 'find;
                }
            }
        }
        let mut seen = BTreeSet::new();
        let Some((mut vi, mut ei)) = start else {
            return Walk::Open(seen);
        };
        loop {
            let (idx, si) = vols[vi];
            let m = mapper(si);
            while let Some(e) = m.entries.get(ei) {
                if !e.is_dir {
                    match is_part(e) {
                        Some(i) => {
                            seen.insert(i);
                        }
                        None => return Walk::Closed(seen),
                    }
                }
                ei += 1;
            }
            if !m.complete {
                return Walk::Open(seen);
            }
            match vols.get(vi + 1) {
                Some(&(next, _)) if next == idx + 1 => {
                    vi += 1;
                    ei = 0;
                }
                _ => return Walk::Open(seen),
            }
        }
    }

    /// Deliver queued verdicts to the child. Off this level's lock: the
    /// child resolving its set raises a tail promote that walks the
    /// chain's locks upward through this one.
    pub(super) fn flush_pending_child_decl(&self) {
        let (queued, child) = {
            let mut g = self.inner.lock_ok();
            if g.pending_child_decl.is_empty() {
                return;
            }
            (std::mem::take(&mut g.pending_child_decl), g.child.clone())
        };
        let Some(child) = child else {
            return;
        };
        for (base, verdict) in queued {
            match verdict {
                Some(n) => child.declare_zip_split_closed(&base, n),
                None => child.refuse_zip_split(&base),
            }
        }
    }

    /// Moment 3, the count: record it and, when a pending set sits
    /// under `base`, resolve it - the set's geometry is known the moment
    /// every part has registered its size, and the tail promote the
    /// resolve queues is raised here, off the lock. Also the depth-0
    /// path behind `declare_zip_split`, where no set is pending yet and
    /// this is just the record.
    pub(super) fn declare_zip_split_closed(&self, base: &str, n: u32) {
        let r = {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            inner.zip_split_decl.insert(base.to_string(), Some(n));
            match inner.sevenz_sets.get(base).cloned() {
                Some(ctl) if Self::zip_set_pending(inner, &ctl) => {
                    self.zip_try_resolve(inner, &ctl, n)
                }
                _ => Ok(()),
            }
        };
        self.note_zip_split_err(r);
        self.flush_pending_promote();
    }

    /// Moment 3, the refusal: the run is not `1..=n`, so no count can
    /// ever resolve the set - forfeit it now rather than hold its bytes
    /// to finish. Each part materializes byte-exact under its own name,
    /// the disk pass's input.
    pub(super) fn refuse_zip_split(&self, base: &str) {
        let r = {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            inner.zip_split_decl.remove(base);
            match inner.sevenz_sets.get(base).cloned() {
                Some(ctl) if Self::zip_set_pending(inner, &ctl) => {
                    // No entry name in the wording, by the nested-reason
                    // rule: this string reaches the parent's report.
                    self.sevenz_fallback_set(inner, &ctl, "zip split parts are not contiguous")
                }
                _ => Ok(()),
            }
        };
        self.note_zip_split_err(r);
        self.flush_pending_promote();
    }

    /// Is `ctl` an unresolved ZIP set? The set map is shared with the
    /// 7z chase; a 7z base ends in `.7z`, which neither zip grammar
    /// produces, so the format check is belt over braces.
    fn zip_set_pending(inner: &Inner, ctl: &Arc<SevenZCtl>) -> bool {
        !ctl.set.resolved()
            && ctl
                .set
                .member_slots()
                .first()
                .is_some_and(|&s| inner.slots[s].container_fmt == ChaseFormat::Zip)
    }

    /// A verdict's I/O failure (a forfeit that could not materialize)
    /// has no caller to return to; the parts' slots stay pending and
    /// finish - which does have one - demotes the set and surfaces the
    /// error from its own sweep.
    fn note_zip_split_err(&self, r: io::Result<()>) {
        if let Err(e) = r {
            tracing::warn!("[extract] zip split verdict: {e}");
        }
    }
}
