//! The frontier buffer: the arriving-bytes window a chase worker
//! reads through - holes, blocking reads, the drop-behind trim, and
//! the differing-rewrite tripwire.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign.

use super::*;
use crate::sync::MutexExt;

/// In-flight byte store for one chased volume. Spans arrive in any order;
/// readers see a CONTIGUOUS frontier from offset 0 and block for bytes
/// beyond it (the RAR decode is forward-only, so blocking at the frontier
/// is exactly the chase). Out-of-order spans park in a hole map and fold
/// into the frontier as the gaps fill - a late PAR2-rebuilt block enters
/// like any other span and simply unblocks the reader.
pub(super) struct FrontierBuffer {
    pub(super) state: Mutex<FrontierState>,
    pub(super) arrived: Condvar,
    /// §94 B: when Some, reads only serve bytes below the slot's
    /// verified-block watermark - the chase decode consumes nothing the
    /// PAR2 set has not vouched for, so a repair can never rewrite
    /// consumed bytes. None = ungated (no set, unclaimed slot, feature
    /// off): behavior is exactly the pre-gate code. A root buffer's gate
    /// is its slot's [`crate::live::VerifyGate`] cell; a routed child's
    /// translates through the parent's routing map (row 27).
    gate: Option<Arc<dyn crate::live::ChaseGate>>,
    /// The gate was RELEASED: the download is over and every repair has
    /// run, so nothing can rewrite these bytes any more and a reader
    /// still parked on the watermark would wait forever (a slot whose
    /// Bad block no repair could fix never advances). Set by the finish
    /// paths before they join the worker. Sticky.
    gate_released: std::sync::atomic::AtomicBool,
    /// The last limit the gate answered. Watermarks only advance (a
    /// release is an advance to MAX), so a read that ends below this
    /// needs no fresh answer - which matters for a routed child, whose
    /// answer is a walk of the parent's routing map under the parent's
    /// lock, asked once per engine read otherwise.
    gate_cache: std::sync::atomic::AtomicU64,
    /// The chain's holds scratch, when this buffer may page cold spans
    /// out of RAM ([`Self::page_cold`] - the terminally-stalled-chase
    /// spill). None (the 7z/zip chases, tests): nothing ever pages and
    /// every path behaves exactly as before paging existed.
    scratch: Option<Arc<HoldsScratch>>,
    /// The extractor owning this chase, reached weakly so a cancelled
    /// job can drop. The blocking reader wakes its stalled-chase pager
    /// through this when it parks at a hole in a volume marked `lost` -
    /// the one wedge (§156.1) neither a verdict nor an arrival can
    /// announce, because a fully-arrived set sees no more of either.
    pager: Option<Weak<Extractor>>,
}

#[derive(Default)]
pub(super) struct FrontierState {
    /// Volume offset of `data[0]`. Zero until a drop-behind trim moves
    /// it; past that point the bytes below it are no longer in RAM (the
    /// trim spilled them into the slot's own archive file, which is
    /// where a demotion would have put them anyway). Reads below it
    /// fail here and are served by the caller from that file.
    pub(super) base: u64,
    /// Contiguous bytes from volume offset `base`.
    pub(super) data: Vec<u8>,
    /// Spans beyond the frontier, keyed by start offset.
    pub(super) pending: BTreeMap<u64, Vec<u8>>,
    /// Spans paged out to the holds scratch (start offset -> scratch
    /// region offset + length), disjoint among themselves. Created only
    /// by [`FrontierBuffer::page_cold`] on a chase stalled behind
    /// terminally-missing articles; bytes here always AGREE with any
    /// overlapping RAM copy (write_span reconciles every delivery), so
    /// duplicated coverage is harmless everywhere it can arise.
    pub(super) paged: BTreeMap<u64, (u64, usize)>,
    /// Sum of paged span lengths - the scratch live-count this buffer
    /// still owes (released per span on read-back, remainder on Drop).
    pub(super) paged_bytes: usize,
    /// Declared volume size (the level-1 entry's unpacked size).
    pub(super) total: u64,
    /// Retained RAM bytes (frontier + pending; paged spans excluded) -
    /// what the holds budget is charged for.
    pub(super) stored: usize,
    /// Longest span currently in `pending`, in bytes: the search window
    /// [`FrontierState::pending_at`] stands on. Recomputed alongside
    /// `stored`, in the same pass - that walk was already being paid for.
    pending_max_len: usize,
    /// A rewrite arrived whose bytes DIFFERED from what was already
    /// retained for a range the decode had ALREADY READ (below
    /// `served`). Sticky, and never cleared: see
    /// [`FrontierBuffer::write_span`]. A differing rewrite of bytes the
    /// decode has not reached yet is not a conflict - the corrected copy
    /// simply replaces the stale one and the decode reads it first.
    pub(super) conflict: bool,
    /// Lowest offset any differing rewrite has landed on, served or not.
    /// What [`FrontierBuffer::rewritten`] reports; sticky.
    pub(super) rewritten_low: Option<u64>,
    /// One past the highest volume offset the DECODE has read through
    /// the two blocking readers. Materialization, peeks and paging are
    /// not reads of the decode and do not move it. The line a rewrite
    /// is judged against: below it the decoded output may already
    /// depend on the stale bytes.
    pub(super) served: u64,
    pub(super) abort: Option<String>,
    /// §156.1: an article of THIS volume got a terminal verdict (430
    /// everywhere, out of retention, dead transport) - the volume holds
    /// a hole nothing on the wire will fill. Sticky; a later repair
    /// disarms the wedge test not by clearing this but by completing
    /// the coverage (`frontier() == total`). What
    /// [`FrontierBuffer::terminally_wedged`] stands on.
    pub(super) lost: bool,
    /// TODO 94 B / row 26: a mapped repair is patching this volume's
    /// holes right now, so the decode must not advance a single byte
    /// until every rebuilt block has landed. Blocking reads park on
    /// `arrived` while it is set, exactly as they park at a hole; the
    /// abort check runs FIRST, so a pause can never outlive a
    /// cancelled job. Cleared by the repair's own guard on every exit
    /// path - see [`Extractor::pause_chase_reads`].
    ///
    /// Why a pause and not an ordering rule: rebuilt blocks land one
    /// call at a time, and the first one to fill a hole releases the
    /// engine into every byte behind it - including ranges a later
    /// call is still going to rewrite. The pause makes the whole
    /// patch atomic against the decode, which is what lets the
    /// `conflict` tripwire below be read ONCE, afterwards, as the
    /// verdict for the set.
    pub(super) paused: bool,
    /// Set once at finish, when no more bytes will ever be routed here
    /// (the download is over). A read that blocks on a HOLE past this
    /// point can never be served, so it errors instead of parking
    /// forever - the demote materializes whatever did arrive. Unlike
    /// [`Self::abort`] this leaves present bytes readable, so a buffer
    /// that IS complete still serves its worker to a clean finish and
    /// keeps one-pass: only a genuinely missing byte turns into the
    /// error. The 7z/zip chase reader seeks its footer far ahead of the
    /// arrival frontier, so a `release_gates` that unblocks the §94 B
    /// gate could otherwise drop it straight onto the unbounded
    /// hole-wait below with nothing left to wake it (TODO 255).
    pub(super) sealed: bool,
    /// Bytes at the FRONT of `data` that a drop-behind trim has planned
    /// to spill and is writing out with no lock held (TODO 37 item 1).
    /// They are still in RAM, but the holds budget has already been
    /// credited for them, so [`Self::retained`] excludes them; `base`
    /// does not move until [`FrontierBuffer::trim_commit`] proves the
    /// bytes landed, so every read below `base` is still a read of bytes
    /// that are really on disk. Non-zero means a trim is in flight, and
    /// a second plan declines until it settles.
    pub(super) trim_pending: usize,
    /// Count of DIFFERING rewrites ever reconciled into this buffer,
    /// wherever they landed: the in-flight trim's tripwire (see
    /// [`FrontierBuffer::trim_chunk`]). `rewritten_low` cannot serve -
    /// it is a minimum, so a second rewrite above the first leaves it
    /// unchanged.
    pub(super) rewrite_seq: u64,
}

impl FrontierState {
    /// Retained RAM bytes as the holds budget counts them: `stored`
    /// minus the prefix an in-flight trim has already been credited for.
    pub(super) fn retained(&self) -> usize {
        self.stored.saturating_sub(self.trim_pending)
    }

    /// One past the last byte of the contiguous RAM run, in VOLUME
    /// offsets - where `data` ends. Appends, folds and the drop-behind
    /// trim all work on this edge.
    pub(super) fn frontier_ram(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    /// One past the last contiguously-COVERED byte from `base`, in
    /// volume offsets: the RAM run extended through any paged and
    /// parked spans that continue it without a hole. This is the
    /// "arrived" edge - completeness and `known_len` read it, and the
    /// blocking readers can serve every byte below it (paged ones via
    /// pread).
    pub(super) fn frontier(&self) -> u64 {
        // One ascending merge of both maps, NOT a `range(..=f).next_back()`
        // per extension. `paged` is disjoint, so the greatest key at or
        // below the cursor is the only region that can continue the run
        // there - but `pending` is deliberately not disjoint, and a SHORT
        // span at a higher start would hide a LONG one at a lower start
        // (§156.2). Sweeping in key order takes the max end over every
        // span starting at or below the cursor by construction.
        //
        // Cost: each entry is visited at most once and the sweep stops at
        // the first start past the cursor, so it is O(spans below the
        // edge) - strictly less work than the walk it replaces, which
        // re-ran two O(log n) lookups per extension.
        let mut f = self.frontier_ram();
        let mut park = self.pending.iter().peekable();
        let mut page = self.paged.iter().peekable();
        loop {
            let take_park = match (park.peek(), page.peek()) {
                (Some(&(&a, _)), Some(&(&b, _))) => a <= b,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return f,
            };
            // The smallest remaining start in either map. Once that is
            // past the cursor the run has a hole, and nothing later can
            // close it - every remaining span starts higher still.
            let (s, e) = if take_park {
                let (&s, v) = park.next().expect("peeked");
                (s, s + v.len() as u64)
            } else {
                let (&s, &(_, len)) = page.next().expect("peeked");
                (s, s + len as u64)
            };
            if s > f {
                return f;
            }
            f = f.max(e);
        }
    }

    /// The paged span covering `pos`, if any: `(start, region offset,
    /// length)`. A single `next_back()` is sound here and only here:
    /// `paged` regions are kept DISJOINT by construction, so the greatest
    /// start at or below `pos` is the only one that can cover it.
    fn paged_at(&self, pos: u64) -> Option<(u64, u64, usize)> {
        self.paged
            .range(..=pos)
            .next_back()
            .filter(|&(&s, &(_, len))| s + len as u64 > pos)
            .map(|(&s, &(off, len))| (s, off, len))
    }

    /// The parked span covering `pos` that reaches FURTHEST past it, as
    /// `(start, bytes)`.
    ///
    /// `pending` is deliberately NOT disjoint - an overlapping park is
    /// kept as its own span, and paging the data tail lowers the RAM
    /// edge so later arrivals park where they would once have folded -
    /// so [`Self::paged_at`]'s single `next_back()` is WRONG here: a
    /// short span at a higher start hides a long one at a lower start,
    /// and the reader then blocks on bytes it is already holding
    /// (§156.2).
    ///
    /// Bounded, because this is the extract hot path: only starts within
    /// `pending_max_len` of `pos` are considered. A span starting below
    /// that window is shorter than the distance back to it, so it cannot
    /// reach `pos` at all - the walk never depends on `pending.len()`.
    fn pending_at(&self, pos: u64) -> Option<(u64, &Vec<u8>)> {
        let lo = pos.saturating_sub(self.pending_max_len as u64);
        self.pending
            .range(lo..=pos)
            .filter(|&(&s, v)| s + v.len() as u64 > pos)
            .max_by_key(|&(&s, v)| s + v.len() as u64)
            .map(|(&s, v)| (s, v))
    }

    /// Recompute the retained-byte total and the parked-span search
    /// window together, in one pass over `pending`. Every mutation of
    /// `pending` ends here before the lock is released, which is what
    /// keeps `pending_max_len` a true bound rather than a hint.
    fn resync_retained(&mut self) {
        let mut stored = self.data.len();
        let mut max_len = 0usize;
        for v in self.pending.values() {
            stored += v.len();
            max_len = max_len.max(v.len());
        }
        self.stored = stored;
        self.pending_max_len = max_len;
    }
}

impl std::fmt::Debug for FrontierBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.state.lock_ok();
        f.debug_struct("FrontierBuffer")
            .field("base", &st.base)
            .field("frontier", &st.frontier())
            .field("pending", &st.pending.len())
            .field("paged", &st.paged.len())
            .field("total", &st.total)
            .field("abort", &st.abort)
            .finish()
    }
}

impl FrontierState {
    /// Append to the contiguous run WITHOUT the `Vec` growth overshoot.
    ///
    /// `data` used to grow through a bare `extend_from_slice`, whose
    /// reserve doubles: capacity is the doubling ladder of the FIRST
    /// span the buffer ever accepted, so a container landing just past
    /// a rung allocates the whole next one. Measured (the
    /// nested-container-buffer rig): a ~140 MiB container fed through a
    /// parent chase's 64 KiB copy buffer sat on the 65_536 x 2^k ladder
    /// and took a 256 MiB allocation, and the TODO 209 note's
    /// unexplained "512 MiB largest single alloc" is that same rung for
    /// its ~273 MiB container. The holds budget charges `stored` - the
    /// bytes - so every byte of that overshoot was spent outside the
    /// budget that is supposed to bound this buffer.
    ///
    /// The declared container size is the fix: the run can never exceed
    /// `total - base`, so the doubling TARGET is clamped there. Growth
    /// stays geometric (amortized O(n) copying, unchanged), the
    /// reservation is only ever made SMALLER than the bare `Vec` would
    /// have made it, and nothing is ever reserved on the strength of a
    /// declaration alone - so a container declaring a huge size cannot
    /// turn this into a preallocation bomb.
    fn append_run(&mut self, bytes: &[u8]) {
        let want = self.data.len() + bytes.len();
        if self.data.capacity() < want {
            // What this run can ever hold. `total` is the declared
            // container size and `base` is what the drop-behind trim has
            // already spilled; a declaration that does not cover what
            // has actually arrived floors at `want`, which also makes
            // the `clamp` below well-ordered. `try_from` rather than
            // `as`: a bare cast truncates a >4 GiB container on 32-bit
            // (armv7), and a ceiling that lands under `want` would turn
            // every span into its own exact reservation - the one shape
            // that costs O(n^2) memmove.
            let ceiling = usize::try_from(self.total.saturating_sub(self.base))
                .unwrap_or(usize::MAX)
                .max(want);
            let target = self.data.capacity().saturating_mul(2).clamp(want, ceiling);
            self.data.reserve_exact(target - self.data.len());
        }
        self.data.extend_from_slice(bytes);
    }
}

impl FrontierBuffer {
    /// Ungated construction. Production callers all attach the §94 B
    /// watermark gate via [`Self::new_gated`], so this survives for the
    /// tests, which exercise the buffer without a verify pipeline.
    #[cfg(test)]
    pub(super) fn new(total: u64) -> FrontierBuffer {
        Self::new_gated(total, None, None, None)
    }

    /// Construction with an optional §94 B watermark gate attached, an
    /// optional holds scratch that arms [`Self::page_cold`], and an
    /// optional weak extractor handle for the reader-side pager wake.
    pub(super) fn new_gated(
        total: u64,
        gate: Option<Arc<dyn crate::live::ChaseGate>>,
        scratch: Option<Arc<HoldsScratch>>,
        pager: Option<Weak<Extractor>>,
    ) -> FrontierBuffer {
        FrontierBuffer {
            state: Mutex::new(FrontierState {
                total,
                ..Default::default()
            }),
            arrived: Condvar::new(),
            gate,
            gate_released: std::sync::atomic::AtomicBool::new(false),
            gate_cache: std::sync::atomic::AtomicU64::new(0),
            scratch,
            pager,
        }
    }

    /// Stop withholding bytes from the decode: see `gate_released`.
    /// Wakes a parked reader through the frontier condvar, so the
    /// release lands within one bounded gate wait at most.
    pub(super) fn release_gate(&self) {
        self.gate_released
            .store(true, std::sync::atomic::Ordering::Release);
        self.arrived.notify_all();
    }

    /// §156.1: sticky terminal-loss mark - an article of this volume
    /// will never arrive from the wire. See [`FrontierState::lost`].
    pub(super) fn mark_lost(&self) {
        self.state.lock_ok().lost = true;
    }

    /// Finish seal: no more bytes will ever be routed here, so a reader
    /// blocked on a hole must stop waiting (see [`FrontierState::sealed`]
    /// and TODO 255). Sets the flag UNDER the state lock and then wakes
    /// every parked reader, the same lock discipline `abort` keeps, so a
    /// reader that checked `sealed` and is about to park cannot miss the
    /// wake. Present bytes stay readable, so a complete buffer's worker
    /// still runs to a clean finish.
    pub(super) fn seal(&self) {
        {
            let mut st = self.state.lock_ok();
            st.sealed = true;
        }
        self.arrived.notify_all();
    }

    /// §156.1 wedge test: does this volume hold an unfillable hole its
    /// decode cannot pass? True only while a terminal verdict has marked
    /// the volume AND its contiguous coverage stops short of the
    /// declared size - a repair that fills the hole disarms this the
    /// moment the coverage completes, with the sticky mark still set.
    pub(super) fn terminally_wedged(&self) -> bool {
        let st = self.state.lock_ok();
        st.lost && st.frontier() < st.total
    }

    /// The §94 B serving limit: bytes at or past this offset are not yet
    /// PAR2-vouched and must not reach the decode. Ungated = MAX.
    fn gate_limit(&self) -> u64 {
        if self
            .gate_released
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return u64::MAX;
        }
        match &self.gate {
            Some(g) => g.watermark(),
            None => u64::MAX,
        }
    }

    /// [`Self::gate_limit`] for the two blocking readers, which hold the
    /// state lock across their loop: a routed child's gate walks the
    /// PARENT's routing lock, and the parent can hold that lock while
    /// calling into the child, whose writes take this state lock - so
    /// asking with the lock held is a parent -> child -> frontier ->
    /// parent cycle (found by the row 27 test hanging). Ungated or
    /// released buffers answer without giving the lock up at all, and
    /// so does a gated one whose last answer already clears `offset`;
    /// otherwise it drops the lock for the ask and hands back a fresh
    /// guard - the caller's loop re-runs every check against the new
    /// state.
    fn gate_limit_unlocked<'a>(
        &'a self,
        st: std::sync::MutexGuard<'a, FrontierState>,
        offset: u64,
    ) -> (u64, std::sync::MutexGuard<'a, FrontierState>, bool) {
        use std::sync::atomic::Ordering;
        if self.gate.is_none() || self.gate_released.load(Ordering::Acquire) {
            return (u64::MAX, st, false);
        }
        let cached = self.gate_cache.load(Ordering::Acquire);
        if offset < cached {
            return (cached, st, false);
        }
        drop(st);
        let lim = self.gate_limit();
        self.gate_cache.fetch_max(lim, Ordering::AcqRel);
        (lim, self.state.lock_ok(), true)
    }

    /// Park briefly for a watermark advance past `offset`. Bounded so a
    /// gate-blocked reader still observes buffer abort/demote (which
    /// notify [`Self::arrived`], not the gate) on its next loop pass.
    fn gate_wait(&self, offset: u64) {
        if let Some(g) = &self.gate {
            g.wait_past(offset, std::time::Duration::from_millis(100));
        }
    }

    /// Accept one span (any order, duplicates and overlaps tolerated -
    /// routing may deliver a span twice, always with identical bytes).
    /// Returns the retained-byte total afterwards, for budget accounting.
    ///
    /// The one delivery that is NOT a harmless duplicate is a mapped
    /// repair rewrite ([`FwdSpan::repair`]), whose bytes may legitimately
    /// DIFFER from an earlier delivery of the same range - poster-side
    /// damage where the article CRC passes but the PAR2 block does not.
    /// This used to be dropped without a word for anything at or behind
    /// the frontier, which is precisely the range the chase engine has
    /// already decoded, so the corrected bytes went nowhere and nothing
    /// noticed. Now any differing rewrite OVERWRITES the retained copy
    /// (so a demotion materializes the corrected volume, exactly) and,
    /// when it lands on bytes the decode has already READ (`served`),
    /// sets the sticky `conflict` flag, which makes the caller forfeit
    /// the chase. That is the same outcome depth 0 reaches by accident:
    /// `patch_volume_span` refuses a repair on a chased slot, so the
    /// volume demotes to materialized and the disk pass re-extracts it.
    ///
    /// A differing rewrite of bytes the decode has NOT reached is no
    /// conflict at all (row 27, 22 Aug 2026): the stale copy was never
    /// consumed, the corrected one is what the decode will read, and
    /// forfeiting would pay the materialize-and-re-extract ending for
    /// nothing. Under the §94 B gate that is every repair, by
    /// construction - the decode never passes an unverified block.
    ///
    /// Deliberately NOT `abort()`: the retained bytes have to stay
    /// readable for [`Self::pop_span`] to materialize them.
    pub(super) fn write_span(&self, offset: u64, bytes: &[u8]) -> usize {
        let mut st = self.state.lock_ok();
        if st.abort.is_some() {
            return st.retained();
        }
        let end = (offset + bytes.len() as u64).min(st.total);
        if end <= offset {
            return st.retained();
        }
        let bytes = &bytes[..(end - offset) as usize];
        let base = st.base;
        let frontier = st.frontier_ram();
        let mut accepted = false;
        let mut differed = false;
        // Lowest offset this delivery changed a retained byte at.
        let mut diff_low = u64::MAX;
        // Whatever we already retain for this range, the newest delivery
        // wins. Checked against the frontier AND the parked spans: the 7z
        // chase peeks at arbitrary offsets, so a parked span can have been
        // read too, and a rewrite of one is no safer to discard.
        //
        // The sub-range below `base` is not ours to reconcile - it is on
        // disk, not in `data`. The caller spots it for itself (the
        // `offset < base` arm of `patch_volume_span`), overwrites what
        // the trim spilled and forces the forfeit through
        // [`Self::mark_conflict`]; here it is simply skipped, which is
        // why the clip is to `base` and not to `offset`.
        if offset < frontier && end > base {
            let a = offset.max(base);
            let n = (frontier.min(end) - a) as usize;
            let di = (a - base) as usize;
            let si = (a - offset) as usize;
            let dst = &mut st.data[di..di + n];
            if let Some(first) = dst.iter().zip(&bytes[si..si + n]).position(|(d, b)| d != b) {
                dst.copy_from_slice(&bytes[si..si + n]);
                differed = true;
                diff_low = diff_low.min(a + first as u64);
            }
        }
        // Paged spans reconcile too - a delivery overlapping one is
        // either a routing duplicate (identical bytes; the paged copy
        // stands and this part of the span need not be re-retained) or
        // a repair rewrite. Scratch regions are write-once, so a
        // differing rewrite UN-PAGES the region: the corrected copy
        // parks in RAM, where a demotion materializes it exactly, and
        // the sticky conflict below forfeits the chase like any other
        // rewrite. A scratch READ error also flags the conflict: the
        // copies cannot be proven to agree, and the demote's own
        // read-back will surface the I/O error as the job failure.
        if !st.paged.is_empty() && end > base {
            let mut unpaged = false;
            let overlapping: Vec<(u64, u64, usize)> = {
                // A single `next_back()` IS sound here: `paged` regions are
                // disjoint by construction, so only the greatest start at
                // or below `offset` can reach it. The parked walk below
                // cannot, and says why.
                let lo = st
                    .paged
                    .range(..=offset)
                    .next_back()
                    .map(|(&s, _)| s)
                    .unwrap_or(0);
                st.paged
                    .range(lo..end)
                    .filter(|&(&s, &(_, len))| s + len as u64 > offset && s < end)
                    .map(|(&s, &(off, len))| (s, off, len))
                    .collect()
            };
            for (s, po, len) in overlapping {
                let a = offset.max(s);
                let b = end.min(s + len as u64);
                let mut have = vec![0u8; (b - a) as usize];
                let Some(sc) = self.scratch.as_ref() else {
                    debug_assert!(false, "paged span with no scratch");
                    differed = true;
                    diff_low = diff_low.min(a);
                    continue;
                };
                if sc.read(po + (a - s), &mut have).is_err() {
                    differed = true;
                    diff_low = diff_low.min(a);
                    continue;
                }
                let src = &bytes[(a - offset) as usize..(b - offset) as usize];
                if have == src {
                    continue;
                }
                // Read the whole region back BEFORE releasing it (the
                // idle truncate must never beat a read), apply the
                // rewrite, and re-park the corrected bytes in RAM.
                let mut whole = vec![0u8; len];
                if sc.read(po, &mut whole).is_err() {
                    differed = true;
                    diff_low = diff_low.min(a);
                    continue;
                }
                whole[(a - s) as usize..(b - s) as usize].copy_from_slice(src);
                st.paged.remove(&s);
                st.paged_bytes -= len;
                sc.release(len);
                diff_low = diff_low.min(a);
                match st.pending.get_mut(&s) {
                    // A longer same-start park subsumes the region; the
                    // corrected bytes overwrite its copy so every
                    // retained record agrees.
                    Some(old) if old.len() >= whole.len() => {
                        old[..whole.len()].copy_from_slice(&whole);
                    }
                    _ => {
                        st.pending.insert(s, whole);
                    }
                }
                differed = true;
                unpaged = true;
            }
            if unpaged {
                // An un-paged region just entered `pending` and can be
                // the longest park there now. Refresh the bound before
                // the walk below stands on it: a stale (too small)
                // window is the same miss the walk was fixed for.
                st.resync_retained();
            }
        }
        if end > frontier {
            // EVERY parked span overlapping the delivery has to be
            // reconciled, not just the nearest one below it: `pending` is
            // not disjoint, so a short park at a higher start hides a
            // long park at a lower start, and starting the walk at
            // `range(..=offset).next_back()` skipped every span below
            // that hider (§156.2 at the write site). The copy it skipped
            // is the one `pending_at` serves reads from and the fold
            // splices into the frontier, so the miss left the sticky
            // conflict unset on a real rewrite and the pre-repair bytes
            // retained.
            //
            // Unlike the read resolvers this cannot take the
            // furthest-reaching copy and stop: each park is an
            // independent record that can fold, be read or be demoted,
            // and reconciliation's whole job is to make them all agree.
            //
            // Bounded the same way [`FrontierState::pending_at`] is: a
            // span starting below `offset - pending_max_len` is shorter
            // than the distance back to it, so it cannot reach `offset`
            // at all. Below `offset` the walk is one longest-park wide;
            // above it, it visits the spans inside the delivery, which
            // reconciliation must touch anyway. Never `pending.len()`.
            let lo = offset.saturating_sub(st.pending_max_len as u64);
            for (&s, v) in st.pending.range_mut(lo..end) {
                let a = offset.max(s);
                let b = end.min(s + v.len() as u64);
                if a >= b {
                    continue;
                }
                let src = &bytes[(a - offset) as usize..(b - offset) as usize];
                let dst = &mut v[(a - s) as usize..(b - s) as usize];
                if let Some(first) = dst.iter().zip(src).position(|(d, b)| d != b) {
                    dst.copy_from_slice(src);
                    differed = true;
                    diff_low = diff_low.min(a + first as u64);
                }
            }
        }
        if offset <= frontier {
            if end > frontier {
                // The append stops where paged coverage begins: those
                // bytes are already on scratch (reconciled above), and
                // the extended `frontier()` walks straight through them.
                let stop = if st.paged_at(frontier).is_some() {
                    frontier
                } else {
                    st.paged
                        .range(frontier..end)
                        .next()
                        .map(|(&s, _)| s)
                        .unwrap_or(end)
                };
                if stop > frontier {
                    st.append_run(&bytes[(frontier - offset) as usize..(stop - offset) as usize]);
                    accepted = true;
                }
                if end > stop {
                    // The remainder past a paged region parks - unless
                    // the region covers it entirely, in which case it is
                    // a pure duplicate of scratch bytes.
                    let covered = st
                        .paged_at(stop)
                        .is_some_and(|(s, _, len)| s + len as u64 >= end);
                    let keep = !covered
                        && match st.pending.get(&stop) {
                            Some(old) => old.len() < (end - stop) as usize,
                            None => true,
                        };
                    if keep {
                        st.pending
                            .insert(stop, bytes[(stop - offset) as usize..].to_vec());
                        accepted = true;
                    }
                }
            }
            // Fold parked spans the new frontier now reaches. Their
            // overlap with the frontier was reconciled when they were
            // written, so only the tail is new.
            while let Some((&s, _)) = st.pending.first_key_value() {
                let f = st.frontier_ram();
                if s > f {
                    break;
                }
                let v = st.pending.remove(&s).unwrap();
                let ve = s + v.len() as u64;
                if ve > f {
                    st.append_run(&v[(f - s) as usize..]);
                }
            }
        } else {
            // Park it; a shorter duplicate at the same start is subsumed
            // (its bytes were just reconciled into the longer one), and
            // a span one paged region wholly covers is a duplicate of
            // scratch bytes and stays off RAM.
            let covered = st
                .paged_at(offset)
                .is_some_and(|(s, _, len)| s + len as u64 >= end);
            let keep = !covered
                && match st.pending.get(&offset) {
                    Some(old) => old.len() < bytes.len(),
                    None => true,
                };
            if keep {
                st.pending.insert(offset, bytes.to_vec());
                // Parked spans wake waiters too: the 7z chase reads at
                // arbitrary offsets (the promoted footer far past the
                // frontier), unlike the frontier-sequential RAR reader.
                accepted = true;
            }
        }
        if differed {
            st.rewrite_seq += 1;
            st.rewritten_low = Some(st.rewritten_low.map_or(diff_low, |r| r.min(diff_low)));
            // Below `served` the decode may already have built output
            // on the stale copy; at or past it, the corrected copy is
            // simply what it reads next.
            st.conflict |= diff_low < st.served;
        }
        st.resync_retained();
        let stored = st.retained();
        drop(st);
        if accepted {
            self.arrived.notify_all();
        }
        stored
    }

    /// Fail the buffer: every blocked (and future) read errors with
    /// `reason`. Cancel path; retained bytes stay readable via
    /// [`Self::pop_span`] for demotion.
    pub(super) fn abort(&self, reason: &str) {
        let mut st = self.state.lock_ok();
        if st.abort.is_none() {
            st.abort = Some(reason.to_string());
        }
        drop(st);
        self.arrived.notify_all();
    }

    /// Did a rewrite land whose bytes differed from what was already
    /// retained, on a range the decode had ALREADY READ? Sticky. The
    /// retained record now holds the CORRECTED bytes, but what the chase
    /// decoded before the rewrite came from the stale copy, so the
    /// caller must forfeit the chase and materialize instead. See
    /// [`Self::write_span`].
    pub(super) fn conflicted(&self) -> bool {
        self.state.lock_ok().conflict
    }

    /// Did ANY differing rewrite land, read or not? The lowest offset
    /// one did, sticky. Weaker than [`Self::conflicted`]: a rewrite
    /// ahead of the decode is no conflict, but it is still the mark of
    /// a repair having touched this volume, which is what the seed-time
    /// checks in `try_attach_chase` and `try_attach_sevenz` want - at
    /// seed nothing has been READ, so the served-aware `conflicted`
    /// cannot see a repair that landed before the chase attached.
    ///
    /// Those two are the only readers, and the post-forfeit resume
    /// ledger is deliberately NOT one: `drop_resume_ledger` throws the
    /// whole ledger away on any repair span reaching the job, at any
    /// depth, without asking which bytes moved. Its own comment rejects
    /// the per-buffer version of that question as the clever reading
    /// that risks the payload, so do not wire this into it.
    pub(super) fn rewritten(&self) -> Option<u64> {
        self.state.lock_ok().rewritten_low
    }

    /// One past the highest offset the decode has read. Test-only: the
    /// rewrite judgement reads `st.served` under the lock it already
    /// holds, so this accessor exists for the tests and for
    /// `testutil::child_chase_served`.
    #[cfg(test)]
    pub(super) fn served(&self) -> u64 {
        self.state.lock_ok().served
    }

    /// Force the forfeit from outside: used when a span lands below the
    /// trim point, where the buffer cannot compare it against anything
    /// because those bytes are on disk rather than in `data`.
    pub(super) fn mark_conflict(&self) {
        self.state.lock_ok().conflict = true;
    }

    /// Hold the decode still while a mapped repair patches this volume
    /// - see [`FrontierState::paused`]. Idempotent; the resume half
    /// notifies, because a reader parked on the pause is parked on
    /// `arrived` and nothing else will wake it.
    pub(super) fn set_paused(&self, paused: bool) {
        self.state.lock_ok().paused = paused;
        if !paused {
            self.arrived.notify_all();
        }
    }

    /// Frontier progress (bytes contiguous from 0, trimmed prefix
    /// included - those bytes arrived, they just live on disk now) vs
    /// the declared total.
    pub(super) fn is_complete(&self) -> bool {
        let st = self.state.lock_ok();
        st.frontier() >= st.total
    }

    /// The holds scratch this buffer pages to, when it pages at all
    /// ([`Self::page_cold`]). A [`Self::plan_peek`] caller pins THIS
    /// one and preads through its handle, so a deferred plan can never
    /// be resolved against some other chain's scratch file.
    pub(super) fn scratch(&self) -> Option<&Arc<HoldsScratch>> {
        self.scratch.as_ref()
    }

    /// The non-blocking volume-view read's planning half, for the
    /// verifier/repair read-back and the chased-slot reader: copy every
    /// RAM-resident byte of `[off, off+out.len())` (frontier + parked
    /// spans) into `out` under the state lock, and return the paged
    /// sub-ranges as `(out offset, len, scratch region offset)` preads
    /// for the caller to run AFTER its locks drop. Regions are
    /// write-once, so those bytes stay stable for as long as the caller
    /// holds a [`ScratchPin`]. Errors if any hole intersects. A trimmed
    /// prefix reads as a hole - those bytes are on disk, and the
    /// slot-level read splits the request at [`Self::base`] before
    /// getting here.
    pub(super) fn plan_peek(
        &self,
        off: u64,
        out: &mut [u8],
    ) -> io::Result<Vec<(usize, usize, u64)>> {
        let st = self.state.lock_ok();
        let mut deferred: Vec<(usize, usize, u64)> = Vec::new();
        let mut pos = off;
        let end = off + out.len() as u64;
        if pos < st.base {
            return Err(nofile());
        }
        let frontier = st.frontier_ram();
        if pos < frontier {
            let n = (frontier.min(end) - pos) as usize;
            let di = (pos - st.base) as usize;
            out[..n].copy_from_slice(&st.data[di..di + n]);
            pos += n as u64;
        }
        while pos < end {
            // The parked span covering `pos` that reaches furthest - the
            // longest run this call can serve without another lookup.
            if let Some((s, v)) = st.pending_at(pos) {
                let ve = s + v.len() as u64;
                let n = (ve.min(end) - pos) as usize;
                out[(pos - off) as usize..(pos - off) as usize + n]
                    .copy_from_slice(&v[(pos - s) as usize..(pos - s) as usize + n]);
                pos += n as u64;
                continue;
            }
            if let Some((s, po, len)) = st.paged_at(pos) {
                let se = s + len as u64;
                let n = (se.min(end) - pos) as usize;
                deferred.push(((pos - off) as usize, n, po + (pos - s)));
                pos += n as u64;
                continue;
            }
            return Err(nofile());
        }
        Ok(deferred)
    }

    /// Non-blocking volume-view read: [`Self::plan_peek`] plus the
    /// paged preads, with the scratch pinned across the gap so a
    /// concurrent release cannot truncate a planned region. Test-only:
    /// the one production reader (`Extractor::read_at`) calls
    /// `plan_peek` directly and runs the preads off its own lock.
    #[cfg(test)]
    pub(super) fn peek(&self, off: u64, out: &mut [u8]) -> io::Result<()> {
        let mut pin = ScratchPin::none();
        if let Some(sc) = self.scratch.as_ref() {
            pin.pin(sc);
        }
        for (bo, n, po) in self.plan_peek(off, out)? {
            let sc = self.scratch.as_ref().ok_or_else(nofile)?;
            sc.read(po, &mut out[bo..bo + n])?;
        }
        Ok(())
    }

    /// Present sub-ranges of `[off, off+len)` in volume offsets, merged.
    /// A trimmed prefix is absent here by construction; the slot-level
    /// coverage adds the archive file's own intervals for it.
    pub(super) fn intervals(&self, off: u64, len: u64) -> Vec<(u64, u64)> {
        let st = self.state.lock_ok();
        let end = off + len;
        let mut ivs: Vec<(u64, u64)> = Vec::new();
        let frontier = st.frontier_ram();
        let lo = off.max(st.base);
        if lo < frontier && lo < end {
            ivs.push((lo, frontier.min(end)));
        }
        for (&s, v) in st.pending.range(..end) {
            let a = off.max(s);
            let b = end.min(s + v.len() as u64);
            if a < b {
                ivs.push((a, b));
            }
        }
        for (&s, &(_, plen)) in st.paged.range(..end) {
            let a = off.max(s);
            let b = end.min(s + plen as u64);
            if a < b {
                ivs.push((a, b));
            }
        }
        merge_intervals(ivs)
    }

    /// Consume the retained bytes for demotion: the frontier moves out as
    /// one span AT ITS OWN OFFSET, parked spans follow as-is. The buffer
    /// is empty after. A trimmed prefix is not here and does not need to
    /// be: the trim already wrote it to the very file this demotion
    /// materializes into. Test-only: the production demote goes through
    /// [`Self::pop_span`], which also reads paged spans back one at a
    /// time instead of re-inflating the whole set.
    #[cfg(test)]
    pub(super) fn take_spans(&self) -> Vec<(u64, Vec<u8>)> {
        let mut st = self.state.lock_ok();
        debug_assert!(st.paged.is_empty(), "take_spans on a paged buffer");
        let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
        let base = st.base;
        let data = std::mem::take(&mut st.data);
        if !data.is_empty() {
            out.push((base, data));
        }
        for (s, v) in std::mem::take(&mut st.pending) {
            out.push((s, v));
        }
        st.resync_retained();
        out
    }

    /// Consume one retained span for demotion: the contiguous frontier
    /// first (at its own offset), then each paged span - read back off
    /// the scratch with a single pread and released - then the parked
    /// spans. `None` once the buffer is empty. One span in RAM at a
    /// time, which is what keeps a demote of a mostly-paged set from
    /// re-inflating it; a scratch read error deliberately fails the
    /// caller rather than demoting short, because the demote path needs
    /// exactly these bytes to materialize the volume.
    pub(super) fn pop_span(&self) -> io::Result<Option<(u64, Vec<u8>)>> {
        let mut st = self.state.lock_ok();
        if !st.data.is_empty() {
            let base = st.base;
            let data = std::mem::take(&mut st.data);
            st.resync_retained();
            return Ok(Some((base, data)));
        }
        if let Some((&s, &(po, len))) = st.paged.iter().next() {
            let sc = self
                .scratch
                .as_ref()
                .ok_or_else(|| io::Error::other("paged span with no scratch"))?
                .clone();
            let mut b = vec![0u8; len];
            // Read BEFORE release: the idle truncate must never beat a
            // read of a region a span still references.
            sc.read(po, &mut b)?;
            st.paged.remove(&s);
            st.paged_bytes -= len;
            sc.release(len);
            return Ok(Some((s, b)));
        }
        if let Some((s, v)) = st.pending.pop_first() {
            st.resync_retained();
            return Ok(Some((s, v)));
        }
        st.resync_retained();
        Ok(None)
    }

    /// Declared total size (the level-N entry's unpacked size).
    pub(super) fn total(&self) -> u64 {
        self.state.lock_ok().total
    }

    /// Volume offset of the first byte still in RAM. Everything below it
    /// has been trimmed out to the slot's archive file.
    pub(super) fn base(&self) -> u64 {
        self.state.lock_ok().base
    }

    /// The RAM frontier edge (where `data` ends), in volume offsets:
    /// the cut a trim would take at a watermark past it.
    pub(super) fn frontier_ram_edge(&self) -> u64 {
        self.state.lock_ok().frontier_ram()
    }

    /// Bytes currently held in RAM - what the holds budget is charged
    /// for. Re-read after a trim to give the budget its bytes back.
    pub(super) fn stored(&self) -> usize {
        self.state.lock_ok().retained()
    }

    /// One past the last contiguous byte, in volume offsets: what has
    /// ARRIVED in order, trimmed bytes included. The drop-or-spill
    /// decision measures the engine against it.
    pub(super) fn frontier(&self) -> u64 {
        self.state.lock_ok().frontier()
    }

    /// Drop-behind: release the frontier bytes below `watermark` and hand
    /// them back so the caller can spill them into the slot's archive
    /// file. Returns `(offset, bytes)` of what left RAM, or None if there
    /// was nothing to release.
    ///
    /// `watermark` is the lowest offset the decode engine may still ask
    /// for - the READ frontier, not decode progress: MT-LZMA2 prefetches
    /// tens of MB ahead of what it has decoded, so trimming to decode
    /// position would take bytes the prefetcher still wants. Parked spans
    /// are untouched by construction: they all sit ABOVE the frontier.
    ///
    /// Nothing is trimmed while a conflict is pending - that buffer is
    /// about to demote and `pop_span` is the only thing left to run.
    ///
    /// `min_release` is what makes this affordable. The release is a
    /// `Vec::drain` from the front, so it memmoves whatever is still
    /// live; refusing to trim for less than a worthwhile chunk bounds
    /// that work to a constant per arriving byte. It also answers the
    /// case trimming cannot fix - arrivals running far ahead of decode,
    /// where the live window IS the cap - by declining, which demotes.
    pub(super) fn trim_to(&self, watermark: u64, min_release: u64) -> Option<(u64, Vec<u8>)> {
        let mut st = self.state.lock_ok();
        // A spill in flight owns the front of `data` until it settles.
        if st.conflict || st.abort.is_some() || st.trim_pending != 0 {
            return None;
        }
        // The RAM frontier, deliberately: only `data` leaves through a
        // trim. A paged span below the watermark is already off RAM and
        // stays on the scratch until the demote or Drop releases it.
        let cut = watermark.min(st.frontier_ram());
        if cut < st.base + min_release.max(1) {
            return None;
        }
        let n = (cut - st.base) as usize;
        let out = st.data.drain(..n).collect::<Vec<u8>>();
        // Give the drained capacity back. A Vec keeps its high-water
        // allocation across a drain, so every volume's buffer stayed at
        // its largest for the life of the chase - invisible while a
        // breach forfeited the chase and freed them all, and 3.3 GB of
        // "unattributed" footprint on an 8 x 500 MB set once TODO 94 E
        // kept the chase alive to the end. One more copy of what
        // remains, beside the memmove the drain already paid, and
        // bounded by the same min_release spacing.
        if st.data.capacity() > st.data.len() * 2 + (1 << 20) {
            st.data.shrink_to_fit();
        }
        let at = st.base;
        st.base = cut;
        st.resync_retained();
        Some((at, out))
    }

    /// The off-lock half of the drop-behind trim, phase 1 of three
    /// (TODO 37, 23 Aug 2026). Same cut as [`Self::trim_to`] - and the
    /// same refusals - but NOTHING leaves RAM here: the prefix is only
    /// marked `trim_pending`, which credits the holds budget for it
    /// (see [`FrontierState::retained`]) while `base` stays put. The
    /// caller then copies it out in bounded chunks with
    /// [`Self::trim_chunk`], writes each with no lock held, and ends
    /// with [`Self::trim_commit`] - or [`Self::trim_abandon`] if a
    /// write failed, which leaves every byte exactly where it was. The
    /// third element is the rewrite sequence the chunk and commit
    /// re-check.
    ///
    /// Why not `trim_to` and write afterwards: `trim_to` moves `base`,
    /// and from that instant every read below it (the verifier's
    /// `covered`, a `read_at` straddling the split) is answered from
    /// the slot's file - which would not have the bytes yet. And the
    /// old shape drained RAM BEFORE the write could fail, so an ENOSPC
    /// in the spill left a hole with the bytes in neither place (the
    /// `(low)` items under TODO 37's open list). Declines while a trim
    /// is already in flight: one prefix at a time keeps `base == at`
    /// a sufficient commit proof.
    pub(super) fn trim_plan(&self, watermark: u64, min_release: u64) -> Option<(u64, usize, u64)> {
        let mut st = self.state.lock_ok();
        if st.conflict || st.abort.is_some() || st.trim_pending != 0 {
            return None;
        }
        let cut = watermark.min(st.frontier_ram());
        if cut < st.base + min_release.max(1) {
            return None;
        }
        let n = (cut - st.base) as usize;
        st.trim_pending = n;
        Some((st.base, n, st.rewrite_seq))
    }

    /// Phase 2: a copy of `[at + done, at + done + max)` of the planned
    /// prefix, or None if the buffer has moved on (a demote popped the
    /// run, an abort, a conflict, or a differing rewrite landed inside
    /// the prefix since the plan) - in which case the caller abandons.
    /// `seq_before` (from [`Self::rewrite_seq`] at plan time) is the
    /// rewrite tripwire: a rewrite below `served` sets `conflict`
    /// anyway, and one above it is legal, but a copy taken before it
    /// would put the STALE bytes on disk under `base`.
    pub(super) fn trim_chunk(
        &self,
        at: u64,
        done: usize,
        max: usize,
        seq_before: u64,
    ) -> Option<Vec<u8>> {
        let st = self.state.lock_ok();
        let n = st.trim_pending;
        if !Self::trim_consistent(&st, at, n, seq_before) || done >= n {
            return None;
        }
        let end = (done + max).min(n);
        Some(st.data[done..end].to_vec())
    }

    /// Phase 3: the bytes are on disk - drain them and move `base`,
    /// exactly what `trim_to` did in one step. Returns the bytes that
    /// left RAM, or None (and nothing moves) if the buffer has changed
    /// under the spill, in which case the bytes written are a harmless
    /// duplicate of what RAM still holds and a later trim re-spills
    /// them. Clears the pending mark either way.
    pub(super) fn trim_commit(&self, at: u64, seq_before: u64) -> Option<usize> {
        let mut st = self.state.lock_ok();
        let n = std::mem::take(&mut st.trim_pending);
        if n == 0 || !Self::trim_consistent(&st, at, n, seq_before) {
            st.resync_retained();
            return None;
        }
        st.data.drain(..n);
        st.base = at + n as u64;
        st.resync_retained();
        Some(n)
    }

    /// A spill write failed: forget the plan. The prefix never left
    /// RAM, so the holds budget is simply re-charged for it by the
    /// caller (the `stored()` it re-reads grows back by the plan).
    pub(super) fn trim_abandon(&self) {
        let mut st = self.state.lock_ok();
        st.trim_pending = 0;
        st.resync_retained();
    }

    /// Whether a planned prefix `[at, at+n)` is still exactly the bytes
    /// the plan saw: same `base`, the run still holds it, no abort or
    /// conflict, and no differing rewrite since the plan.
    fn trim_consistent(st: &FrontierState, at: u64, n: usize, seq_before: u64) -> bool {
        st.base == at
            && st.data.len() >= n
            && !st.conflict
            && st.abort.is_none()
            && st.rewrite_seq == seq_before
    }

    /// Proactive spill for a chase stalled behind terminally-missing
    /// articles: move up to `need` cold RAM bytes to the holds scratch.
    /// Parked spans go first, newest (highest) offsets first - they are
    /// cold by construction, the forward-only RAR reader cannot reach a
    /// parked span until its gap fills. With `include_data` the tail of
    /// the contiguous run pages too (a volume the engine has not
    /// reached, or is wholly past); the paged span continues coverage
    /// exactly where `data` now ends, so `frontier()` and the blocking
    /// readers see the same bytes, just served by pread. Returns the
    /// bytes that left RAM; the caller re-reads `stored()` and settles
    /// the budget, the same contract as the drop-behind trim. A scratch
    /// refusal (ceiling, dead) just stops - whatever stayed in RAM keeps
    /// riding the cap arbiter exactly as before this spill existed.
    /// §156.3b: no scratch WRITE happens under `state`. Each batch is
    /// pick-and-clone under the lock, append with the lock RELEASED,
    /// then a commit that re-proves the span is still exactly the bytes
    /// written (a differing rewrite in the window sets `conflict` and
    /// the commit walks away; scratch regions are write-once, so an
    /// orphaned one is just released). The bounded per-span preads the
    /// readers and `write_span` do under this lock stay as they were -
    /// the unbounded hold was this pass writing `budget - window` bytes
    /// in one go, and worse, doing it under the extractor lock too (the
    /// caller no longer holds it - see `page_wedged_chase`).
    pub(super) fn page_cold(&self, cap: u64, mut need: usize, include_data: bool) -> usize {
        let Some(sc) = self.scratch.clone() else {
            return 0;
        };
        let mut moved = 0usize;
        // Parked spans first, newest offsets first, in bounded batches:
        // the clone is transient RAM the batch cap keeps small.
        const BATCH: usize = 16 << 20;
        let mut rounds = 0usize;
        while need >= HOLDS_PAGE_MIN {
            // Belt: every round either commits, drops a duplicate, or
            // breaks - but a span whose shape churns under rewrites
            // could in principle re-verify forever.
            rounds += 1;
            if rounds > 64 {
                break;
            }
            let batch: Vec<(u64, Vec<u8>)> = {
                let mut st = self.state.lock_ok();
                // A conflicted or aborted buffer is about to demote;
                // leave its spans where the demote expects them.
                if st.conflict || st.abort.is_some() {
                    return moved;
                }
                let mut picked = Vec::new();
                let mut picked_bytes = 0usize;
                let starts: Vec<u64> = st.pending.keys().rev().copied().collect();
                for s in starts {
                    if need == 0 || picked_bytes >= BATCH {
                        break;
                    }
                    let len = st.pending[&s].len();
                    if len < HOLDS_PAGE_MIN {
                        continue;
                    }
                    let e = s + len as u64;
                    // Overlap with an existing paged region: fully
                    // covered means an agreeing duplicate that re-parked
                    // - drop the RAM copy, no I/O. A same-start longer
                    // span replaces the shorter region below. Any other
                    // partial overlap stays in RAM: paged regions are
                    // kept DISJOINT (every covering lookup is a single
                    // `range(..=pos).next_back()`), and these shapes are
                    // rare re-delivery leftovers, not the pile.
                    //
                    // `range(..e)` finds the greatest paged key BELOW
                    // the span's end, which can start above `s` - a
                    // repair span mapped at a PAR2 block boundary
                    // reaches under a region paged at an article
                    // boundary. Covered means covered at BOTH ends
                    // (`ps <= s`): without that test the prefix `[s,
                    // ps)` is in no map, no scratch region and no file,
                    // and dropping the RAM copy loses bytes that had
                    // already arrived.
                    let overlap = st
                        .paged
                        .range(..e)
                        .next_back()
                        .map(|(&ps, &(_, plen))| (ps, plen))
                        .filter(|&(ps, plen)| ps + plen as u64 > s);
                    match overlap {
                        Some((ps, plen)) if ps <= s && ps + plen as u64 >= e => {
                            st.pending.remove(&s);
                            moved += len;
                            need = need.saturating_sub(len);
                            continue;
                        }
                        Some((ps, _)) if ps != s => continue,
                        _ => {}
                    }
                    picked_bytes += len;
                    picked.push((s, st.pending[&s].clone()));
                }
                st.resync_retained();
                picked
            };
            if batch.is_empty() {
                break;
            }
            let mut written: Vec<(u64, Vec<u8>, u64)> = Vec::with_capacity(batch.len());
            let mut refused = false;
            for (s, v) in batch {
                match sc.append(&v, cap) {
                    Some(off) => written.push((s, v, off)),
                    None => {
                        refused = true;
                        break;
                    }
                }
            }
            {
                let mut st = self.state.lock_ok();
                for (s, v, off) in written {
                    let e = s + v.len() as u64;
                    // Same-length is the whole identity check: rewrites
                    // reconcile in place (a differing one sets the
                    // conflict checked below), and a replacement is
                    // always strictly longer.
                    let intact = !st.conflict
                        && st.abort.is_none()
                        && st.pending.get(&s).is_some_and(|cur| cur.len() == v.len());
                    let overlap = st
                        .paged
                        .range(..e)
                        .next_back()
                        .map(|(&ps, &(_, plen))| (ps, plen))
                        .filter(|&(ps, plen)| ps + plen as u64 > s);
                    let clean = match overlap {
                        // The same-start shorter region is subsumed
                        // (bytes agree; the longer copy covers it).
                        Some((ps, plen)) => ps == s && plen < v.len(),
                        None => true,
                    };
                    if !intact || !clean {
                        sc.release(v.len());
                        continue;
                    }
                    st.pending.remove(&s);
                    if let Some(&(_, old_len)) = st.paged.get(&s) {
                        st.paged_bytes -= old_len;
                        sc.release(old_len);
                    }
                    st.paged_bytes += v.len();
                    moved += v.len();
                    need = need.saturating_sub(v.len());
                    st.paged.insert(s, (off, v.len()));
                }
                st.resync_retained();
            }
            if refused {
                // Scratch refusal (ceiling, dead): whatever stayed in
                // RAM keeps riding the cap arbiter exactly as before
                // this spill existed.
                return moved;
            }
        }
        // The contiguous tail, in bounded chunks from the end backwards
        // (each committed chunk becomes its own paged region, adjacent
        // and disjoint). `frontier_ram() == end` is the tail's identity:
        // an append in the window moves it and the commit walks away
        // (the next round re-clones the new tail); a front trim moves
        // `base` and `data` together and leaves it standing.
        if include_data {
            const TAIL_CHUNK: usize = 8 << 20;
            let mut retries = 0usize;
            while need >= HOLDS_PAGE_MIN && retries < 8 {
                let chunk: Option<(u64, Vec<u8>, u64)> = {
                    let st = self.state.lock_ok();
                    if st.conflict || st.abort.is_some() || st.data.is_empty() {
                        None
                    } else {
                        let end = st.frontier_ram();
                        let take = st.data.len().min(need).min(TAIL_CHUNK);
                        let at = end - take as u64;
                        // A paged region overlapping the tail (a fold
                        // ran through one): leave the tail resident
                        // rather than create overlapping regions - same
                        // disjointness rule as above.
                        let overlap = st
                            .paged
                            .range(..end)
                            .next_back()
                            .is_some_and(|(&ps, &(_, plen))| ps + plen as u64 > at);
                        if take < HOLDS_PAGE_MIN || overlap {
                            None
                        } else {
                            let cut = st.data.len() - take;
                            Some((at, st.data[cut..].to_vec(), end))
                        }
                    }
                };
                let Some((at, bytes, end)) = chunk else {
                    break;
                };
                let Some(off) = sc.append(&bytes, cap) else {
                    break;
                };
                let mut st = self.state.lock_ok();
                let tail_stood_still = !st.conflict
                    && st.abort.is_none()
                    && st.frontier_ram() == end
                    && !st
                        .paged
                        .range(..end)
                        .next_back()
                        .is_some_and(|(&ps, &(_, plen))| ps + plen as u64 > at);
                if !tail_stood_still {
                    drop(st);
                    sc.release(bytes.len());
                    retries += 1;
                    continue;
                }
                let cut = st.data.len() - bytes.len();
                st.data.truncate(cut);
                st.paged_bytes += bytes.len();
                moved += bytes.len();
                need = need.saturating_sub(bytes.len());
                st.paged.insert(at, (off, bytes.len()));
                st.resync_retained();
            }
        }
        moved
    }

    /// Blocking RANDOM-ACCESS read for the 7z chase. The trait method
    /// below blocks on the contiguous frontier (the RAR decode is
    /// forward-only); 7z seeks - its footer must be readable long
    /// before the frontier reaches it. Serves the longest available
    /// run at `offset` from frontier or parked bytes, blocks while
    /// `offset` sits in a hole, `Ok(0)` at the declared end, error
    /// after abort.
    pub(super) fn read_covered_blocking(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut st = self.state.lock_ok();
        loop {
            if let Some(reason) = &st.abort {
                return Err(io::Error::other(format!("chase source aborted: {reason}")));
            }
            // A repair is rewriting this volume's holes: serve nothing
            // until it is done (`FrontierState::paused`). Checked after
            // abort so a cancelled job always wins, and before the
            // end-of-volume `Ok(0)` so a paused reader cannot slip out
            // through the tail either. A finish seal overrides it: the
            // repair pass is over, so an unresumed pause must not strand
            // the reader (TODO 255) - fall through to serve or error.
            if st.paused && !st.sealed {
                st = self.arrived.wait(st).unwrap();
                continue;
            }
            if offset >= st.total {
                return Ok(0);
            }
            // Behind the trim point: those bytes went to disk and the
            // engine promised never to come back for them. A read here
            // means the promise broke, so fail loudly - the chase
            // forfeits and the archive materializes, which is cheap
            // because most of it is already written. Two shapes have
            // come back: BCJ2, which is refused a trim up front, and
            // the RAR5 deferred header walk (§250, 23 Aug 2026), which
            // re-walked from the signature after the chase had trimmed
            // the volume and met this guard at offset 8 on every leg -
            // fixed in rars by resuming the walk at its stop offset,
            // which sits at or above any watermark the engine published.
            if offset < st.base {
                return Err(io::Error::other(format!(
                    "chase source read {offset} behind the trim point {}",
                    st.base
                )));
            }
            // §94 B: nothing at or past the verified watermark may reach
            // the decode. Blocked-by-gate is a different wait from
            // blocked-by-arrival: the bytes are here, the vouching is
            // not - park on the gate (bounded) and re-run every check.
            let (lim, guard, relocked) = self.gate_limit_unlocked(st, offset);
            st = guard;
            // The gate read RELEASED the state lock, so the checks
            // above were made against a state that may have moved
            // since. Re-run the two that end the read - and `abort`
            // is not tidiness, it is the deadlock: an abort landing
            // in that window sets the flag and notifies `arrived`
            // BEFORE this reader is on it, so falling through to the
            // wait below parks forever on a buffer nothing will ever
            // notify again. The chase worker then sleeps for the life
            // of the process and finish()'s join never returns (seen
            // 23 Aug 2026 as an intermittent wedge of
            // `zip_nested_budget_demote_materializes_byte_exact`,
            // which nextest's retry passed in 28 ms and reported as a
            // flake). Re-checked HERE rather than by looping: a
            // `continue` would re-enter the gate read with the cache
            // still at or below `offset` and spin instead of parking
            // on the gate. `paused` needs no re-check - its own wait
            // is on the same `arrived`, which `set_paused` notifies.
            if relocked {
                if let Some(reason) = &st.abort {
                    return Err(io::Error::other(format!("chase source aborted: {reason}")));
                }
                if offset < st.base {
                    return Err(io::Error::other(format!(
                        "chase source read {offset} behind the trim point {}",
                        st.base
                    )));
                }
            }
            if offset >= lim {
                drop(st);
                self.gate_wait(offset);
                st = self.state.lock_ok();
                continue;
            }
            let frontier = st.frontier_ram();
            if offset < frontier {
                let start = (offset - st.base) as usize;
                let take = buf
                    .len()
                    .min(st.data.len() - start)
                    .min((lim - offset) as usize);
                buf[..take].copy_from_slice(&st.data[start..start + take]);
                st.served = st.served.max(offset + take as u64);
                return Ok(take);
            }
            if let Some((s, v)) = st.pending_at(offset) {
                let a = (offset - s) as usize;
                let take = buf.len().min(v.len() - a).min((lim - offset) as usize);
                buf[..take].copy_from_slice(&v[a..a + take]);
                st.served = st.served.max(offset + take as u64);
                return Ok(take);
            }
            if let Some((s, po, len)) = st.paged_at(offset) {
                let take = buf
                    .len()
                    .min(len - (offset - s) as usize)
                    .min((lim - offset) as usize);
                let sc = self
                    .scratch
                    .as_ref()
                    .ok_or_else(|| io::Error::other("paged span with no scratch"))?;
                sc.read(po + (offset - s), &mut buf[..take])?;
                st.served = st.served.max(offset + take as u64);
                return Ok(take);
            }
            // Sealed and still a hole: the download is over, these bytes
            // are never coming, and the 7z/zip reader that seeks its
            // footer ahead of the frontier would otherwise park here
            // forever once `release_gates` cleared the gate above it
            // (TODO 255). Checked only after every serve path so a buffer
            // that IS complete answers the read and keeps one-pass; only
            // a genuinely missing byte becomes the error that demotes.
            if st.sealed {
                return Err(io::Error::other(format!(
                    "chase source sealed at offset {offset}: bytes never arrived"
                )));
            }
            st = self.arrived.wait(st).unwrap();
        }
    }
}

impl Drop for FrontierBuffer {
    /// A buffer dropped with paged spans still in it (a successful
    /// chase, an abandoned slot) hands their scratch live-count back so
    /// the file can truncate; the regions themselves were write-once
    /// and need no other unwind.
    fn drop(&mut self) {
        let st = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.paged_bytes > 0
            && let Some(sc) = &self.scratch
        {
            sc.release(st.paged_bytes);
            st.paged_bytes = 0;
            st.paged.clear();
        }
    }
}

/// The RAR engine reads chased volumes through this: block at the
/// frontier, `Ok(0)` only at the declared end, error after abort.
impl rars::BlockingRangeSource for FrontierBuffer {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut st = self.state.lock_ok();
        loop {
            if let Some(reason) = &st.abort {
                return Err(io::Error::other(format!("chase source aborted: {reason}")));
            }
            // Same repair pause as `read_covered_blocking`.
            if st.paused {
                st = self.arrived.wait(st).unwrap();
                continue;
            }
            // Behind the trim point, the RAR twin of the guard in
            // `read_covered_blocking`: the §92 drop-behind trims a RAR
            // volume to the engine's own watermark, and the rars driver
            // promises strictly-forward packed reads past it. The one
            // RAR read that broke the promise was the deferred header
            // walk re-starting at the signature (§250); it now resumes
            // at its stop offset, so a hit here is a new shape - fail
            // loudly rather than serve the wrong bytes.
            if offset < st.base {
                return Err(io::Error::other(format!(
                    "chase source read {offset} behind the trim point {}",
                    st.base
                )));
            }
            // §94 B: same gate as `read_covered_blocking` - the decode
            // may only consume PAR2-vouched bytes.
            let (lim, guard, relocked) = self.gate_limit_unlocked(st, offset);
            st = guard;
            // Same released-lock window, same lost wakeup, as
            // `read_covered_blocking` above.
            if relocked {
                if let Some(reason) = &st.abort {
                    return Err(io::Error::other(format!("chase source aborted: {reason}")));
                }
                if offset < st.base {
                    return Err(io::Error::other(format!(
                        "chase source read {offset} behind the trim point {}",
                        st.base
                    )));
                }
            }
            if offset >= lim && offset < st.total {
                drop(st);
                self.gate_wait(offset);
                st = self.state.lock_ok();
                continue;
            }
            let frontier = st.frontier_ram();
            if offset < frontier {
                let start = (offset - st.base) as usize;
                let take = buf
                    .len()
                    .min(st.data.len() - start)
                    .min((lim - offset) as usize);
                buf[..take].copy_from_slice(&st.data[start..start + take]);
                st.served = st.served.max(offset + take as u64);
                return Ok(take);
            }
            if offset >= st.total {
                return Ok(0);
            }
            // Beyond the RAM run the coverage may continue through
            // paged spans (served by pread) and the parked spans that
            // follow them. The reader is forward-only, so it can only
            // arrive here through contiguous coverage - serving a
            // parked span early is strictly more bytes, never wrong
            // ones (identical-delivery reconciliation holds for every
            // retained copy).
            if let Some((s, po, len)) = st.paged_at(offset) {
                let take = buf
                    .len()
                    .min(len - (offset - s) as usize)
                    .min((lim - offset) as usize);
                let sc = self
                    .scratch
                    .as_ref()
                    .ok_or_else(|| io::Error::other("paged span with no scratch"))?;
                sc.read(po + (offset - s), &mut buf[..take])?;
                st.served = st.served.max(offset + take as u64);
                return Ok(take);
            }
            if let Some((s, v)) = st.pending_at(offset) {
                let a = (offset - s) as usize;
                let take = buf.len().min(v.len() - a).min((lim - offset) as usize);
                buf[..take].copy_from_slice(&v[a..a + take]);
                st.served = st.served.max(offset + take as u64);
                return Ok(take);
            }
            // §156.1: parking at a hole in a volume marked `lost` IS the
            // wedge - and when the set fully arrived before the engine
            // got here, no verdict and no arrival is coming to announce
            // it. Wake the stalled-chase pager (atomics + a detached
            // thread; nothing here takes another lock).
            if st.lost
                && self.scratch.is_some()
                && let Some(ex) = self.pager.as_ref().and_then(|w| w.upgrade())
            {
                ex.wake_pager();
            }
            st = self.arrived.wait(st).unwrap();
        }
    }

    fn known_len(&self) -> u64 {
        let st = self.state.lock_ok();
        st.frontier()
    }

    fn total_len(&self) -> Option<u64> {
        Some(self.state.lock_ok().total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::testutil::tmpdir;

    fn pat(off: usize, n: usize) -> Vec<u8> {
        (off..off + n).map(|i| (i % 251) as u8).collect()
    }

    /// First volume offset at which `got` (which starts at volume offset
    /// `off`) disagrees with the expected volume image, or `None`. The
    /// overlapping-park tests compare 40 kB copies; a byte-dump
    /// `assert_eq!` on those reports the failure unreadably.
    fn first_diff(off: u64, got: &[u8], want: &[u8]) -> Option<u64> {
        let at = off as usize;
        got.iter()
            .zip(want[at..].iter())
            .position(|(a, b)| a != b)
            .map(|i| off + i as u64)
    }

    /// The repair pause holds BOTH blocking readers still even over
    /// bytes that are fully retained, and releases them again - the
    /// property the row-26 in-place chase repair stands on, because it
    /// is what makes a multi-block patch atomic against the decode.
    ///
    /// Teeth in the negative direction too: the same reads are proved
    /// to succeed on the same buffer once the pause lifts, so a pause
    /// that silently never engaged would fail the first half rather
    /// than pass both.
    #[test]
    fn a_paused_buffer_serves_neither_reader_until_it_resumes() {
        let buf = Arc::new(FrontierBuffer::new(1000));
        buf.write_span(0, &pat(0, 1000));
        buf.set_paused(true);
        for (what, ran) in [("forward", false), ("random-access", true)] {
            let b = Arc::clone(&buf);
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut out = [0u8; 16];
                let r = if ran {
                    b.read_covered_blocking(0, &mut out)
                } else {
                    rars::BlockingRangeSource::read_at(&*b, 0, &mut out)
                };
                let _ = tx.send(r.map(|n| n > 0));
            });
            assert!(
                rx.recv_timeout(std::time::Duration::from_millis(300))
                    .is_err(),
                "the {what} reader served bytes while the buffer was paused"
            );
        }
        buf.set_paused(false);
        let mut out = [0u8; 16];
        assert_eq!(
            within(&buf, "the resumed forward read", |b| {
                let mut o = [0u8; 16];
                let n = rars::BlockingRangeSource::read_at(b, 0, &mut o).unwrap();
                (n, o)
            })
            .0,
            16
        );
        assert_eq!(buf.read_covered_blocking(0, &mut out).unwrap(), 16);
        assert_eq!(out, pat(0, 16)[..]);
    }

    /// Run a read on a worker and FAIL rather than hang if it is still
    /// parked after ten seconds. The blocking readers wait on a condvar
    /// with no timeout, so a regression that blocks at a covered offset
    /// would otherwise wedge the whole suite instead of reporting.
    fn within<T: Send + 'static>(
        buf: &Arc<FrontierBuffer>,
        what: &str,
        f: impl FnOnce(&FrontierBuffer) -> T + Send + 'static,
    ) -> T {
        use std::sync::mpsc::RecvTimeoutError;
        let (tx, rx) = std::sync::mpsc::channel();
        let b = Arc::clone(buf);
        std::thread::spawn(move || {
            let _ = tx.send(f(&b));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(v) => v,
            Err(RecvTimeoutError::Timeout) => {
                // Release the parked worker before failing.
                buf.abort("test timeout");
                panic!("{what} blocked on bytes that are already retained");
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("{what} panicked - its own assertion is the failure")
            }
        }
    }

    /// §156.2: `pending` is deliberately NOT disjoint, so resolving a
    /// parked span with the single `range(..=pos).next_back()` that is
    /// sound for `paged` lets a SHORT span at a higher start hide a LONG
    /// span at a lower start. Paging the data tail is what sets the
    /// shape up: the RAM edge moves BACKWARDS, so arrivals that would
    /// have folded into the frontier park instead, overlapping.
    ///
    /// No corruption is at stake - `pop_span` still ships every span, as
    /// the demote at the end pins - but the reported edge stops short, a
    /// decode read at the gap blocks on bytes already sitting in RAM,
    /// and `chase_finish` can forfeit a set that had every byte. The
    /// cost is the one-pass win, which is the product.
    ///
    /// All four resolvers are exercised deliberately: fixing `frontier()`
    /// alone leaves the reads parked at the very edge it now reports.
    #[test]
    fn overlapping_parks_resolve_to_the_furthest_reaching_span() {
        use rars::BlockingRangeSource as _;
        let dir = tmpdir("frontier-overlap");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let buf = Arc::new(FrontierBuffer::new_gated(
            100_000,
            None,
            Some(sc.clone()),
            None,
        ));
        // A contiguous run, then the stalled-chase spill pages its tail:
        // the RAM edge moves backwards from 40_000 to 20_000 and the
        // paged region carries coverage back up to 40_000.
        buf.write_span(0, &pat(0, 40_000));
        assert_eq!(buf.page_cold(1 << 20, 20_000, true), 20_000);
        assert_eq!(buf.state.lock().unwrap().frontier_ram(), 20_000);
        assert_eq!(buf.frontier(), 40_000, "the paged tail has still arrived");

        // Two later arrivals now park instead of folding, and they
        // OVERLAP. The short one starts higher, so it is exactly what a
        // `range(..=pos).next_back()` lookup finds - and it ends first.
        buf.write_span(25_000, &pat(25_000, 40_000)); // [25_000, 65_000)
        buf.write_span(30_000, &pat(30_000, 15_000)); // [30_000, 45_000)
        assert_eq!(
            buf.state.lock().unwrap().pending.len(),
            2,
            "the shape under test is two OVERLAPPING parks"
        );

        // Coverage runs 0 -> 65_000: data, the paged region, then the
        // long park. Stopping at 45_000 is the short park hiding it.
        assert_eq!(
            buf.frontier(),
            65_000,
            "the longer park at the lower start must set the edge"
        );
        assert_eq!(buf.known_len(), 65_000);

        // Every resolver has to agree with that edge. `peek` is
        // non-blocking and reports a hole outright; the two blocking
        // readers park on the condvar, so they run under a timeout.
        let mut got = vec![0u8; 20_000];
        buf.peek(45_000, &mut got)
            .expect("peek must see the long park");
        assert_eq!(got, pat(45_000, 20_000));

        let n = within(&buf, "read_at", |b| {
            let mut out = vec![0u8; 20_000];
            let n = b.read_at(45_000, &mut out).unwrap();
            assert_eq!(out[..n], pat(45_000, 20_000)[..n]);
            n
        });
        assert_eq!(n, 20_000, "read_at must serve the whole long park");
        let n = within(&buf, "read_covered_blocking", |b| {
            let mut out = vec![0u8; 20_000];
            let n = b.read_covered_blocking(45_000, &mut out).unwrap();
            assert_eq!(out[..n], pat(45_000, 20_000)[..n]);
            n
        });
        assert_eq!(n, 20_000, "the 7z random-access read must serve it too");

        // And the forward-only reader runs the covered region out in one
        // pass, which is the shape the chase actually stands on.
        let streamed = within(&buf, "the forward reader", |b| {
            let mut out = vec![0u8; 65_000];
            let mut pos = 0usize;
            while pos < 65_000 {
                let n = b.read_at(pos as u64, &mut out[pos..]).unwrap();
                assert_ne!(n, 0, "reader starved at {pos} despite full coverage");
                pos += n;
            }
            out
        });
        assert_eq!(streamed, pat(0, 65_000));

        // No corruption was ever at stake here: a demote ships every byte
        // whichever way the edge was reported.
        let mut mat = vec![0u8; 65_000];
        while let Some((off, bytes)) = buf.pop_span().unwrap() {
            mat[off as usize..off as usize + bytes.len()].copy_from_slice(&bytes);
        }
        assert_eq!(mat, pat(0, 65_000), "a demote must materialize every byte");
        assert_eq!(sc.st().live, 0, "scratch live must drain with the pops");
        drop(buf);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TODO 37 med2, the shape the lane that found §156.2 reported
    /// first: a PLAIN buffer - no scratch, nothing paged, `base == 0` -
    /// which is what every RAR chase volume is. Two parks overlap with
    /// the SHORTER one keyed higher, with no paging needed to set it
    /// up: an arrival can simply land inside a span that is already
    /// parked (a PAR2-rebuilt block inside a parked article, a routing
    /// duplicate that was clipped). `range(..=pos).next_back()` finds
    /// the short park and stops short of the long one, so `peek`
    /// reported a hole and `read_covered_blocking` parked on bytes it
    /// was holding, on a range `intervals` reported covered. Pinned
    /// separately from the paging test above so the RAR chase shape
    /// cannot regress behind a fix scoped to the scratch path.
    #[test]
    fn plain_overlapping_parks_serve_the_covering_span() {
        use rars::BlockingRangeSource as _;
        let buf = Arc::new(FrontierBuffer::new(100_000));
        buf.write_span(0, &pat(0, 10_000));
        buf.write_span(25_000, &pat(25_000, 40_000)); // [25_000, 65_000)
        buf.write_span(30_000, &pat(30_000, 15_000)); // [30_000, 45_000)
        {
            let st = buf.state.lock().unwrap();
            assert_eq!(st.base, 0, "the RAR chase shape: nothing trimmed");
            assert!(st.paged.is_empty(), "nothing paged either");
            assert_eq!(st.pending.len(), 2, "two OVERLAPPING parks");
        }
        // `intervals` walks every park and has always reported the
        // range covered; the resolvers must agree with it.
        assert_eq!(buf.intervals(25_000, 40_000), vec![(25_000, 65_000)]);
        let mut got = vec![0u8; 20_000];
        buf.peek(45_000, &mut got)
            .expect("peek must serve the covering park, not the shadowing one");
        assert_eq!(first_diff(45_000, &got, &pat(0, 65_000)), None);
        let n = within(&buf, "read_covered_blocking", |b| {
            let mut out = vec![0u8; 20_000];
            let n = b.read_covered_blocking(45_000, &mut out).unwrap();
            assert_eq!(first_diff(45_000, &out[..n], &pat(0, 65_000)), None);
            n
        });
        assert_eq!(n, 20_000, "the covering park must be served whole");
        // The forward reader parks at the real hole [10_000, 25_000),
        // not at the shadowed edge: fill it and the run completes.
        buf.write_span(10_000, &pat(10_000, 15_000));
        assert_eq!(buf.frontier(), 65_000);
        let n = within(&buf, "read_at", |b| {
            let mut out = vec![0u8; 20_000];
            b.read_at(45_000, &mut out).unwrap()
        });
        assert_eq!(n, 20_000);
    }

    /// §156.2's sibling at the WRITE site: `write_span` reconciled a
    /// delivery against the parked spans starting from
    /// `pending.range(..=offset).next_back()` - the greatest start at or
    /// below the delivery - so every span starting BELOW that one was
    /// never compared at all. `pending` is not disjoint, so a short park
    /// at a higher start hid a long park at a lower start here too, and
    /// the long one is exactly the copy `pending_at` serves reads from
    /// and the fold splices into the frontier.
    ///
    /// Missing it costs more than the edge did. The sticky `conflict`
    /// flag never fires, so nothing forfeits the chase; the hidden copy
    /// keeps its pre-repair bytes; and once the hole below it fills, the
    /// fold appends that copy over the corrected park and then drops the
    /// corrected park as already covered. The fold's own stated
    /// invariant - that a park's overlap with the frontier was
    /// reconciled when it was written - is precisely what the miss
    /// breaks, so the decode goes on to read uncorrected bytes with
    /// nothing flagged.
    ///
    /// Reconciliation wants EVERY overlapping copy, not the
    /// furthest-reaching one `pending_at` returns: each park is an
    /// independent record that can fold, be read, or be demoted. Both
    /// directions are pinned - a genuinely differing rewrite must fire
    /// the flag, an agreeing re-delivery over the same overlap must not.
    ///
    /// What the two shapes below each caught on the old code: the paged
    /// one flagged nothing, kept pre-repair bytes in the hidden park and
    /// served them to `peek`, but still DEMOTED correctly - `pop_span`
    /// ships parks in ascending start order and the hidden copy always
    /// starts below the rewrite, so the corrected one lands last. The
    /// fold shape is where the stale copy wins outright.
    #[test]
    fn overlapping_parks_reconcile_every_retained_copy() {
        // The §156.2 shape: page the data tail so the RAM edge moves
        // BACKWARDS, then park a long span and shorter higher-keyed ones
        // over it.
        let dir = tmpdir("frontier-overlap-rewrite");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let buf = FrontierBuffer::new_gated(100_000, None, Some(sc.clone()), None);
        buf.write_span(0, &pat(0, 40_000));
        assert_eq!(buf.page_cold(1 << 20, 20_000, true), 20_000);
        assert_eq!(buf.state.lock().unwrap().frontier_ram(), 20_000);
        buf.write_span(25_000, &pat(25_000, 40_000)); // [25_000, 65_000)
        buf.write_span(50_000, &pat(50_000, 2_000)); // [50_000, 52_000)
        buf.write_span(55_000, &pat(55_000, 3_000)); // [55_000, 58_000)
        assert!(
            !buf.conflicted(),
            "an agreeing re-delivery over the overlap is not a rewrite"
        );

        // A differing rewrite ABOVE the short parks' ends. The old walk
        // started at the 55_000 park, which does not reach 60_000, and
        // never looked down at the long park that does.
        buf.write_span(60_000, &[0xEE; 3_000]);
        assert_eq!(
            buf.rewritten(),
            Some(60_000),
            "a differing rewrite of the hidden long park must be seen"
        );

        // Every retained copy of the rewritten range has to agree now -
        // that is what makes the demote order below irrelevant.
        let mut want = pat(0, 65_000);
        want[60_000..63_000].fill(0xEE);
        {
            let st = buf.state.lock().unwrap();
            for (&s, v) in st.pending.iter() {
                assert_eq!(
                    first_diff(s, v, &want),
                    None,
                    "the copy parked at {s} kept pre-repair bytes"
                );
            }
        }
        // And the reads with it: `peek` resolves to the furthest-reaching
        // copy, which is the long park - the one the old walk missed.
        let mut got = vec![0u8; 3_000];
        buf.peek(60_000, &mut got)
            .expect("covered by the long park");
        assert_eq!(
            first_diff(60_000, &got, &want),
            None,
            "the repair must win at the reads"
        );

        let mut mat = vec![0u8; 65_000];
        while let Some((off, bytes)) = buf.pop_span().unwrap() {
            mat[off as usize..off as usize + bytes.len()].copy_from_slice(&bytes);
        }
        assert_eq!(
            first_diff(0, &mat, &want),
            None,
            "a demote must materialize the corrected volume"
        );
        assert_eq!(sc.st().live, 0, "scratch live must drain with the pops");
        drop(buf);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();

        // The same miss, followed by the fold. Overlapping parks need no
        // paging at all, just a hole below them: once the hole fills the
        // long park splices into the frontier and the corrected park is
        // dropped as covered, so the stale copy is what the decode reads
        // for the rest of the chase.
        let buf = FrontierBuffer::new(100_000);
        buf.write_span(10_000, &pat(10_000, 40_000)); // [10_000, 50_000)
        buf.write_span(30_000, &pat(30_000, 1_000)); // [30_000, 31_000)
        buf.write_span(35_000, &[0xEE; 2_000]); // the repair rewrite
        assert_eq!(
            buf.rewritten(),
            Some(35_000),
            "the rewrite differs from the long park"
        );
        buf.write_span(0, &pat(0, 10_000)); // fills the hole; the parks fold
        assert_eq!(buf.state.lock().unwrap().frontier_ram(), 50_000);
        let mut want = pat(0, 50_000);
        want[35_000..37_000].fill(0xEE);
        let mut got = vec![0u8; 2_000];
        buf.peek(35_000, &mut got).unwrap();
        assert_eq!(
            first_diff(35_000, &got, &want),
            None,
            "the fold spliced a pre-repair copy into the frontier"
        );
        for (off, bytes) in buf.take_spans() {
            assert_eq!(first_diff(off, &bytes, &want), None, "the span at {off}");
        }
    }

    /// The contiguous run never over-reserves past the container.
    ///
    /// `data` grew through a bare `extend_from_slice`, whose reserve
    /// DOUBLES, so its capacity was the doubling ladder of the first
    /// span the buffer ever saw and a container landing just past a rung
    /// took the whole next one - measured at 1.83x the container
    /// (a ~140 MiB container on the 64 KiB child ladder allocated
    /// 256 MiB), all of it outside the holds budget, which charges the
    /// BYTES. The declared total is the ceiling the clamp stands on.
    ///
    /// Fed in the shape that hurts most: a first span far smaller than
    /// the total, so the doubling ladder starts low and every rung
    /// above it overshoots.
    #[test]
    fn the_contiguous_run_never_reserves_past_the_declared_total() {
        const TOTAL: usize = 300_000;
        let buf = FrontierBuffer::new(TOTAL as u64);
        let mut off = 0usize;
        while off < TOTAL {
            let n = 7_000.min(TOTAL - off);
            buf.write_span(off as u64, &pat(off, n));
            off += n;
            let st = buf.state.lock().unwrap();
            assert!(
                st.data.capacity() <= TOTAL,
                "capacity {} ran past the declared total {TOTAL} at offset {off}",
                st.data.capacity()
            );
        }
        assert_eq!(buf.frontier(), TOTAL as u64);
        // Growth is still geometric, not one reservation per span: a
        // per-span exact reserve would be O(n^2) memmove. 7_000 doubling
        // to the 300_000 ceiling is 6 growth steps, so the capacity must
        // have landed well above one span.
        assert!(
            buf.state.lock().unwrap().data.capacity() >= TOTAL,
            "the final run should hold the whole container"
        );
        let mut got = vec![0u8; TOTAL];
        buf.peek(0, &mut got).unwrap();
        assert_eq!(first_diff(0, &got, &pat(0, TOTAL)), None);
    }

    /// The stalled-chase cold spill end to end at the buffer level:
    /// parked spans and the contiguous tail page to scratch, coverage
    /// stays whole (intervals, peek, completeness), a forward reader
    /// runs the volume out through preads once the gap fills, and a
    /// demotion pops every span back byte-exact with the scratch
    /// live-count fully drained.
    #[test]
    fn stall_paging_serves_paged_spans_and_pops_them_back() {
        use rars::BlockingRangeSource as _;
        let dir = tmpdir("frontier-paged");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let buf = FrontierBuffer::new_gated(40_000, None, Some(sc.clone()), None);
        buf.write_span(0, &pat(0, 10_000)); // contiguous run
        buf.write_span(20_000, &pat(20_000, 10_000)); // parks
        buf.write_span(30_000, &pat(30_000, 10_000)); // parks
        assert_eq!(buf.stored(), 30_000);
        let moved = buf.page_cold(1 << 20, usize::MAX, true);
        assert_eq!(moved, 30_000, "both parks and the data tail must page");
        assert_eq!(buf.stored(), 0);
        // Coverage is intact, just served differently.
        assert_eq!(
            buf.intervals(0, 40_000),
            vec![(0, 10_000), (20_000, 40_000)]
        );
        let mut got = vec![0u8; 10_000];
        buf.peek(25_000, &mut got).unwrap();
        assert_eq!(got, pat(25_000, 10_000), "peek must pread across regions");
        assert!(!buf.is_complete());
        // The gap fills (a retry or a repair landing late): coverage
        // completes and the forward-only reader streams the whole
        // volume, paged regions served by pread.
        buf.write_span(10_000, &pat(10_000, 10_000));
        assert!(buf.is_complete(), "paged coverage must count as arrived");
        let mut out = vec![0u8; 40_000];
        let mut pos = 0usize;
        while pos < 40_000 {
            let n = buf.read_at(pos as u64, &mut out[pos..]).unwrap();
            assert_ne!(n, 0, "reader starved at {pos} despite full coverage");
            pos += n;
        }
        assert_eq!(out, pat(0, 40_000));
        // Demotion consumes one span at a time, byte-exact.
        let mut mat = vec![0u8; 40_000];
        let mut popped = 0;
        while let Some((off, bytes)) = buf.pop_span().unwrap() {
            mat[off as usize..off as usize + bytes.len()].copy_from_slice(&bytes);
            popped += 1;
        }
        assert!(popped >= 3, "expected data + paged spans, got {popped}");
        assert_eq!(mat, pat(0, 40_000));
        assert_eq!(sc.st().live, 0, "scratch live must drain with the pops");
        drop(buf);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TODO §156 item 8(b): `plan_peek` is the half that runs under a
    /// caller's lock, so it must do no disk I/O at all. RAM bytes
    /// (frontier and parked spans alike) memcpy; every paged
    /// sub-range comes back as an `(out offset, len, region offset)`
    /// plan for the caller to pread once its locks are gone.
    ///
    /// The oracle is the scratch's `locked_reads` counter, which only
    /// the under-a-lock `HoldsScratch::read` bumps, plus the output
    /// bytes themselves: a planner that quietly preads would move both,
    /// so this cannot pass on a buffer whose bytes never paged.
    #[test]
    fn plan_peek_defers_every_paged_sub_range() {
        let dir = tmpdir("frontier-planpeek");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let buf = FrontierBuffer::new_gated(40_000, None, Some(sc.clone()), None);
        buf.write_span(0, &pat(0, 10_000)); // contiguous run
        buf.write_span(20_000, &pat(20_000, 10_000)); // parks
        buf.write_span(30_000, &pat(30_000, 10_000)); // parks
        assert_eq!(
            buf.page_cold(1 << 20, usize::MAX, true),
            30_000,
            "the run and both parks must page"
        );
        // The gap fills afterwards, so this one span is RAM-resident
        // and everything around it lives on scratch.
        buf.write_span(10_000, &pat(10_000, 10_000));
        assert_eq!(buf.stored(), 10_000, "only the late span is RAM");

        let reads_before = sc.locked_reads.load(Ordering::Relaxed);
        let mut out = vec![0xABu8; 40_000];
        let plans = buf.plan_peek(0, &mut out).unwrap();
        assert_eq!(
            sc.locked_reads.load(Ordering::Relaxed),
            reads_before,
            "planning read the scratch instead of deferring"
        );
        assert_eq!(
            plans.iter().map(|&(_, n, _)| n).sum::<usize>(),
            30_000,
            "every paged byte must come back as a plan: {plans:?}"
        );
        // The RAM span is served; the planned ranges are untouched -
        // `pat` never repeats a byte value ten thousand times over, so
        // the sentinel surviving means nothing wrote there.
        assert_eq!(out[10_000..20_000], pat(10_000, 10_000));
        for &(bo, n, _) in &plans {
            assert!(
                out[bo..bo + n].iter().all(|&b| b == 0xAB),
                "plan ({bo}, {n}) was served under the lock after all"
            );
        }
        // Resolving the plans off the lock completes the volume view,
        // byte-exact, and matches the test-only `peek` composition.
        let f = sc.handle().expect("scratch file");
        for (bo, n, po) in plans {
            crate::disk::read_exact_at(&f.1, &mut out[bo..bo + n], po).unwrap();
        }
        assert_eq!(out, pat(0, 40_000));
        let mut whole = vec![0u8; 40_000];
        buf.peek(0, &mut whole).unwrap();
        assert_eq!(whole, out);

        drop(buf);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Deliveries overlapping a paged region reconcile exactly like RAM
    /// copies: an identical duplicate is absorbed without re-inflating
    /// RAM or flagging anything, and a DIFFERING rewrite un-pages the
    /// region with the correction applied and trips the sticky conflict
    /// - the demote must materialize the corrected bytes.
    #[test]
    fn paged_span_rewrites_reconcile_and_conflict() {
        let dir = tmpdir("frontier-paged-rw");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let buf = FrontierBuffer::new_gated(30_000, None, Some(sc.clone()), None);
        buf.write_span(10_000, &[3u8; 10_000]);
        assert_eq!(buf.page_cold(1 << 20, usize::MAX, false), 10_000);
        assert_eq!(buf.stored(), 0);
        buf.write_span(10_000, &[3u8; 10_000]);
        assert!(!buf.conflicted(), "an identical duplicate is not a rewrite");
        assert_eq!(buf.stored(), 0, "an agreeing duplicate re-inflated RAM");
        buf.write_span(12_000, &[3u8; 1_000]);
        assert!(!buf.conflicted());
        assert_eq!(buf.stored(), 0);
        buf.write_span(12_000, &[9u8; 1_000]);
        assert_eq!(
            buf.rewritten(),
            Some(12_000),
            "a differing rewrite must not be dropped"
        );
        let mut want = vec![3u8; 10_000];
        want[2_000..3_000].fill(9);
        let mut got = vec![0u8; 10_000];
        buf.peek(10_000, &mut got).unwrap();
        assert_eq!(got, want, "the corrected copy is what a demote ships");
        let mut mat = vec![0u8; 10_000];
        while let Some((off, bytes)) = buf.pop_span().unwrap() {
            let at = (off - 10_000) as usize;
            mat[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        assert_eq!(mat, want);
        assert_eq!(sc.st().live, 0);
        drop(buf);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A parked span reaching UNDER a paged region keeps its uncovered
    /// prefix. `page_cold` finds the overlap with `range(..e).next_back()`
    /// - the greatest paged key below the span's END - so the region it
    /// finds can start above the span's start, which is what a repair
    /// span mapped at a PAR2 block boundary looks like against a region
    /// paged at an article boundary. Treating that as "fully covered"
    /// dropped the prefix into no map, no file and no scratch region:
    /// the frontier could never pass it, and a demote materialized a
    /// volume with a hole at bytes that had already arrived.
    #[test]
    fn page_cold_keeps_the_prefix_a_paged_region_does_not_cover() {
        let dir = tmpdir("frontier-paged-prefix");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let buf = FrontierBuffer::new_gated(30_000, None, Some(sc.clone()), None);
        // A span parks above the frontier and pages out.
        buf.write_span(10_000, &pat(10_000, 10_000));
        assert_eq!(buf.page_cold(1 << 20, usize::MAX, false), 10_000);
        assert_eq!(buf.stored(), 0);
        // A later delivery starts BELOW the paged region and ends inside
        // it: nothing covers [5_000, 10_000), so it parks whole.
        buf.write_span(5_000, &pat(5_000, 10_000));
        assert_eq!(buf.stored(), 10_000);
        // The next spill pass must not mistake it for a duplicate.
        buf.page_cold(1 << 20, usize::MAX, false);
        assert!(!buf.conflicted(), "the bytes agree - no rewrite happened");
        buf.write_span(0, &pat(0, 5_000));
        assert_eq!(
            buf.frontier(),
            20_000,
            "coverage must run through the prefix"
        );
        let mut got = vec![0u8; 20_000];
        buf.peek(0, &mut got).unwrap();
        assert_eq!(got, pat(0, 20_000), "the prefix bytes must still be there");
        let mut mat = vec![0u8; 20_000];
        while let Some((off, bytes)) = buf.pop_span().unwrap() {
            mat[off as usize..off as usize + bytes.len()].copy_from_slice(&bytes);
        }
        assert_eq!(mat, pat(0, 20_000), "a demote must materialize every byte");
        assert_eq!(sc.st().live, 0);
        drop(buf);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// §94 B: a gated buffer serves only PAR2-vouched bytes. Bytes are
    /// PRESENT past the watermark and must still not reach the decode -
    /// serves clamp at the limit, and a fully-advanced gate releases
    /// the rest. Ungated buffers (every other test here) are the teeth
    /// proving the pre-gate behavior is untouched.
    #[test]
    fn gated_reads_clamp_at_the_verified_watermark() {
        let gate = crate::live::VerifyGate::new(1);
        gate.engage(0);
        let buf = FrontierBuffer::new_gated(
            30,
            Some(Arc::new(crate::live::SlotGate {
                gate: gate.clone(),
                slot: 0,
            })),
            None,
            None,
        );
        buf.write_span(0, &[7u8; 30]);
        // Watermark 10: a 16-byte read at 0 serves exactly 10.
        gate.advance(0, 10);
        let mut out = [0u8; 16];
        let n = buf.read_covered_blocking(0, &mut out).unwrap();
        assert_eq!(n, 10, "serve clamps at the watermark");
        // A read AT the watermark parks; an advance releases it.
        let b2 = std::sync::Arc::new(buf);
        let (b3, g3) = (b2.clone(), gate.clone());
        let t = std::thread::spawn(move || {
            let mut out = [0u8; 32];
            b3.read_covered_blocking(10, &mut out).unwrap()
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        g3.advance(0, u64::MAX);
        assert_eq!(t.join().unwrap(), 20, "advance releases the rest");
        // An aborted buffer must not strand a gate-blocked reader.
        let gate2 = crate::live::VerifyGate::new(1);
        gate2.engage(0);
        let b4 = std::sync::Arc::new(FrontierBuffer::new_gated(
            30,
            Some(Arc::new(crate::live::SlotGate {
                gate: gate2,
                slot: 0,
            })),
            None,
            None,
        ));
        b4.write_span(0, &[1u8; 30]);
        let b5 = b4.clone();
        let t = std::thread::spawn(move || {
            let mut out = [0u8; 8];
            b5.read_covered_blocking(0, &mut out)
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        b4.abort("test abort");
        assert!(
            t.join().unwrap().is_err(),
            "abort must reach a gate-blocked reader"
        );
    }

    /// FrontierBuffer contract: out-of-order spans park and fold in as
    /// gaps fill; a blocked reader wakes on exactly the fill; peek and
    /// intervals see parked bytes the blocking reader must not.
    #[test]
    fn frontier_buffer_holes_and_blocking() {
        use rars::BlockingRangeSource as _;
        let buf = Arc::new(FrontierBuffer::new(30));
        // Arrive out of order: [20,30) then [10,20); frontier stays 0.
        buf.write_span(20, &[2u8; 10]);
        buf.write_span(10, &[1u8; 10]);
        assert_eq!(buf.known_len(), 0);
        assert_eq!(buf.intervals(0, 30), vec![(10, 30)]);
        let mut peeked = [0u8; 10];
        buf.peek(15, &mut peeked[..5]).unwrap();
        assert_eq!(&peeked[..5], &[1u8; 5]);
        assert!(buf.peek(5, &mut peeked).is_err(), "hole must not peek");
        // A reader blocks at offset 0 until the head span lands.
        let reader = Arc::clone(&buf);
        let h = std::thread::spawn(move || {
            let mut out = vec![0u8; 30];
            let mut pos = 0usize;
            while pos < 30 {
                let n = reader.read_at(pos as u64, &mut out[pos..]).unwrap();
                assert_ne!(n, 0);
                pos += n;
            }
            out
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        buf.write_span(0, &[9u8; 10]);
        let mut want = vec![9u8; 10];
        want.extend_from_slice(&[1u8; 10]);
        want.extend_from_slice(&[2u8; 10]);
        assert_eq!(h.join().unwrap(), want);
        assert_eq!(buf.known_len(), 30);
        assert!(buf.is_complete());
        // Duplicates and overlaps are absorbed, never doubled - and an
        // IDENTICAL re-delivery is not a conflict, which is the case the
        // routing layer produces constantly.
        let before = buf.write_span(5, &[9u8; 5]);
        assert_eq!(before, 30);
        assert!(!buf.conflicted(), "identical re-delivery is not a rewrite");
        // Abort wakes a blocked reader with an error.
        let buf2 = Arc::new(FrontierBuffer::new(10));
        let r2 = Arc::clone(&buf2);
        let h2 = std::thread::spawn(move || {
            let mut b = [0u8; 4];
            r2.read_at(0, &mut b)
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        buf2.abort("test cancel");
        assert!(h2.join().unwrap().is_err());
    }

    /// A mapped repair whose bytes DIFFER from an earlier delivery used to
    /// vanish silently whenever it landed at or behind the frontier - the
    /// exact range the chase engine has already decoded. Pin both halves
    /// of the fix: the conflict is visible to the caller once the decode
    /// has READ the range (and only then - row 27), and the retained
    /// record ends up holding the CORRECTED bytes, because a demotion
    /// materializes the volume straight out of it.
    #[test]
    fn frontier_buffer_flags_a_differing_rewrite() {
        use rars::BlockingRangeSource as _;
        // Wholly behind the frontier, and wholly READ.
        let buf = FrontierBuffer::new(30);
        buf.write_span(0, &[1u8; 10]);
        buf.write_span(10, &[2u8; 10]);
        assert_eq!(buf.known_len(), 20);
        let mut read = [0u8; 20];
        assert_eq!(buf.read_at(0, &mut read).unwrap(), 20);
        assert_eq!(buf.served(), 20);
        assert!(!buf.conflicted());
        buf.write_span(0, &[7u8; 5]);
        assert!(buf.conflicted(), "a differing rewrite must not be dropped");
        assert_eq!(buf.rewritten(), Some(0));
        let mut got = [0u8; 10];
        buf.peek(0, &mut got).unwrap();
        assert_eq!(&got, &[7, 7, 7, 7, 7, 1, 1, 1, 1, 1], "repair must win");

        // Straddling the frontier: the overlap is reconciled, the tail is
        // appended, and the frontier still advances. Nothing read yet,
        // so this is a rewrite and not a conflict; reading past it
        // afterwards serves the corrected copy and flags nothing.
        let buf = FrontierBuffer::new(30);
        buf.write_span(0, &[1u8; 10]);
        buf.write_span(5, &[8u8; 10]);
        assert!(!buf.conflicted(), "unread bytes cannot conflict");
        assert_eq!(buf.rewritten(), Some(5), "but the rewrite is on record");
        assert_eq!(buf.known_len(), 15);
        let mut read = [0u8; 15];
        assert_eq!(buf.read_at(0, &mut read).unwrap(), 15);
        assert!(
            !buf.conflicted(),
            "reading a corrected range is not a conflict"
        );
        let mut got = [0u8; 15];
        buf.peek(0, &mut got).unwrap();
        assert_eq!(&got[..5], &[1u8; 5]);
        assert_eq!(&got[5..], &[8u8; 10]);

        // Parked, not yet folded. The 7z chase reads at arbitrary
        // offsets, so a parked span can have been read too - and a read
        // one counts.
        let buf = FrontierBuffer::new(30);
        buf.write_span(20, &[3u8; 10]);
        assert_eq!(buf.known_len(), 0);
        let mut read = [0u8; 10];
        assert_eq!(buf.read_covered_blocking(20, &mut read).unwrap(), 10);
        assert!(!buf.conflicted());
        buf.write_span(22, &[4u8; 4]);
        assert!(buf.conflicted(), "a parked rewrite must not be dropped");
        let mut got = [0u8; 10];
        buf.peek(20, &mut got).unwrap();
        assert_eq!(&got, &[3, 3, 4, 4, 4, 4, 3, 3, 3, 3]);
        // And the corrected bytes are what a demotion would materialize.
        // An overlapping park is kept as its own span (only a same-start
        // duplicate is subsumed), so what matters is that the copies now
        // AGREE - materializing them in any order lands the same volume.
        let spans = buf.take_spans();
        let covering = spans.iter().find(|(s, _)| *s == 20).expect("span at 20");
        assert_eq!(&covering.1, &[3, 3, 4, 4, 4, 4, 3, 3, 3, 3]);
        for (s, v) in &spans {
            for (i, b) in v.iter().enumerate() {
                let at = (s + i as u64 - 20) as usize;
                assert_eq!(*b, covering.1[at], "copies disagree at {}", s + i as u64);
            }
        }
    }

    /// Row 27: the served line is what a rewrite is judged against. A
    /// differing rewrite AHEAD of what the decode has read replaces the
    /// stale copy and flags no conflict - the decode then reads the
    /// corrected bytes; the same rewrite one byte into the read range
    /// is a conflict. `served` only moves on the decode's readers:
    /// peeks, pops and materialization leave it alone.
    #[test]
    fn differing_rewrite_conflicts_only_below_the_served_line() {
        use rars::BlockingRangeSource as _;
        let buf = FrontierBuffer::new(100);
        buf.write_span(0, &[1u8; 100]);
        let mut peek = [0u8; 50];
        buf.peek(0, &mut peek).unwrap();
        assert_eq!(buf.served(), 0, "a peek is not a decode read");
        let mut read = [0u8; 40];
        assert_eq!(buf.read_at(0, &mut read).unwrap(), 40);
        assert_eq!(buf.served(), 40);
        // Ahead of the line: corrected, not conflicted.
        buf.write_span(40, &[9u8; 10]);
        assert!(!buf.conflicted());
        assert_eq!(buf.rewritten(), Some(40));
        let mut got = [0u8; 10];
        assert_eq!(buf.read_at(40, &mut got).unwrap(), 10);
        assert_eq!(got, [9u8; 10], "the decode reads the corrected copy");
        assert!(!buf.conflicted());
        // Identical bytes over read range: a duplicate, never a rewrite.
        buf.write_span(0, &[1u8; 40]);
        assert!(!buf.conflicted());
        // One byte into the read range: conflict, sticky.
        let mut one_in = [1u8; 11];
        one_in[0] = 5;
        buf.write_span(49, &one_in);
        assert!(buf.conflicted(), "a rewrite of a read byte must conflict");
        assert_eq!(buf.rewritten(), Some(40), "lowest rewrite offset is sticky");
    }

    /// The blocking random-access read the 7z adapter stands on: parked
    /// tail bytes are readable long before the frontier reaches them,
    /// a hole blocks until its span lands, and abort wakes with an
    /// error.
    #[test]
    fn frontier_buffer_random_access_blocking() {
        let buf = Arc::new(FrontierBuffer::new(30));
        buf.write_span(20, &[7u8; 10]);
        // Parked tail serves immediately - no frontier needed.
        let mut out = [0u8; 10];
        assert_eq!(buf.read_covered_blocking(20, &mut out).unwrap(), 10);
        assert_eq!(out, [7u8; 10]);
        // A hole blocks until the covering span arrives.
        let reader = Arc::clone(&buf);
        let h = std::thread::spawn(move || {
            let mut b = [0u8; 5];
            let n = reader.read_covered_blocking(10, &mut b).unwrap();
            (n, b)
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        buf.write_span(10, &[3u8; 10]);
        let (n, b) = h.join().unwrap();
        assert!(n >= 1 && b[..n] == [3u8; 5][..n]);
        // Past the declared end: clean EOF.
        let mut b = [0u8; 4];
        assert_eq!(buf.read_covered_blocking(30, &mut b).unwrap(), 0);
        // Abort wakes a blocked reader with an error.
        let buf2 = Arc::new(FrontierBuffer::new(10));
        let r2 = Arc::clone(&buf2);
        let h2 = std::thread::spawn(move || {
            let mut b = [0u8; 4];
            r2.read_covered_blocking(0, &mut b)
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        buf2.abort("test cancel");
        assert!(h2.join().unwrap().is_err());
    }
}
