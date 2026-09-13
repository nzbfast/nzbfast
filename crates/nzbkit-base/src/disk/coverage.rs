//! [`FileWriter`]'s COVERAGE LEDGER: which byte ranges of the output are
//! actually written, kept as a sorted disjoint interval list, plus the
//! questions callers ask of it - is this range readable, did anything get
//! rewritten, how far does the contiguous prefix reach.
//!
//! A second `impl FileWriter` block rather than a block inside the one in
//! `disk.rs`, which stood at 3,683 of the size gate's 4,000-line file
//! ceiling on 7 Sep 2026 (claim `debt-split-hot-files-7sep`). The ledger
//! is the one part of the writer that answers only about itself: it
//! touches no handle, takes no lease, and every method here is either the
//! interval arithmetic or a read of it. Verbatim move, dedented one
//! level; the only other rewrite is `fn` -> `pub(super) fn` on the two
//! private helpers `disk.rs` still calls.

use super::*;

impl FileWriter {
    /// Record `[offset, offset+len)` as on-disk without writing - crash
    /// resume seeds the coverage map with spans a previous run persisted.
    ///
    /// `intervals` is kept sorted by start and disjoint (touching runs
    /// merged), so this is a binary-search insert-and-merge: no per-write
    /// allocation and no full re-sort. The old rebuild-and-sort was
    /// O(n log n) + a heap alloc on EVERY span; under heavy out-of-order
    /// arrival (one disjoint region per in-flight connection) every
    /// decoder thread paid that while serialized on this mutex.
    /// Record [offset, offset+len) as written, returning the number of
    /// bytes that were NOT already covered. A rewrite (repair span, or a
    /// duplicate article) returns 0, which is what makes the extraction
    /// budget in `write_at` immune to double-charging a healing file.
    pub fn note_written(&self, offset: u64, len: u64) -> u64 {
        if len == 0 {
            return 0;
        }
        self.written.fetch_add(len, Ordering::Relaxed);
        let fresh = self.merge_span(offset, len);
        self.covered.fetch_add(fresh, Ordering::Relaxed);
        fresh
    }

    /// Merge `[offset, offset+len)` into the coverage map, returning the
    /// bytes that were not already in it. Split out of `note_written` so
    /// [`note_repaired`](FileWriter::note_repaired) can publish spans an
    /// external tool wrote without charging them to `written`.
    pub(super) fn merge_span(&self, offset: u64, len: u64) -> u64 {
        if len == 0 {
            return 0;
        }
        let (s, e) = (offset, offset + len);
        let mut iv = self.intervals.lock_ok();
        // First interval that could touch/overlap on the left (its end
        // reaches `s`), and first that starts beyond `e` (can't touch).
        let lo = iv.partition_point(|&(_, fe)| fe < s);
        let hi = iv.partition_point(|&(fs, _)| fs <= e);
        if lo < hi {
            // Merge the overlapping/adjacent run [lo, hi) into one span.
            // The run's spans are disjoint, so the newly-covered count is
            // the merged length minus what the run already held.
            let held: u64 = iv[lo..hi].iter().map(|&(fs, fe)| fe - fs).sum();
            let ns = s.min(iv[lo].0);
            let ne = e.max(iv[hi - 1].1);
            iv[lo] = (ns, ne);
            iv.drain(lo + 1..hi);
            (ne - ns) - held
        } else {
            iv.insert(lo, (s, e));
            len
        }
    }

    /// True when every byte of [off, off+len) has been written.
    pub fn covered(&self, off: u64, len: u64) -> bool {
        // Coverage is published after the `pwrite`, so a staged span
        // reads as a hole. That is the SAFE direction for every consumer
        // (nobody is told a byte is there when it is not), but a caller
        // waiting for its own bytes would wait for a write nothing has
        // asked for yet - so an overlapping run goes out here.
        //
        // The cost is bounded and it is the same write either way: the
        // relaxed load above answers no for every writer that is not
        // staging, which on the direct-map one-pass path is every volume
        // writer `materialized_span_on_disk` asks about.
        if self.stage_overlaps(off, off + len) {
            let _ = self.flush_stage();
        }
        let iv = self.intervals.lock_ok();
        iv.iter().any(|&(s, e)| s <= off && off + len <= e)
    }

    /// True when some byte range was written MORE THAN ONCE - the total
    /// bytes written exceed the distinct bytes covered. In a well-formed
    /// download every article owns a disjoint byte range, so this stays
    /// false; it turns true only when two writes land on the same range:
    /// a same-article hedge/tail duplicate (identical bytes, harmless) or
    /// - the reason this exists - a MALFORMED post carrying two different
    /// articles for one file range. The second is silent corruption: the
    /// later write overwrites the first on disk, but a block the in-stream
    /// verifier already marked Ok from the first copy is never re-hashed,
    /// so garbage ships as a "clean download". Settle consults this to
    /// force a read-back of such a slot (see `LiveVerifier::force_readback`).
    pub fn had_rewrite(&self) -> bool {
        // Both counters advance when a coalescing run is WRITTEN, so a
        // duplicate still sitting in the open run would read as no
        // rewrite at all - and settle would skip exactly the read-back
        // this answer exists to force. Cold path (settle), so the run
        // goes out first and the comparison is over the whole file.
        let _ = self.flush_stage();
        self.written.load(Ordering::Relaxed) > self.covered.load(Ordering::Relaxed)
    }

    /// The written sub-ranges of [off, off+len), clipped, in file offsets.
    /// Anything not returned is a sparse hole that would pread as zeros -
    /// the extractor's fallback read-back must never copy those.
    pub fn covered_intervals(&self, off: u64, len: u64) -> Vec<(u64, u64)> {
        if self.stage_overlaps(off, off + len) {
            let _ = self.flush_stage();
        }
        self.covered_intervals_raw(off, len)
    }

    /// [`FileWriter::covered_intervals`] with no staging flush - the
    /// door [`FileWriter::gate_enter`] takes, because it is already
    /// inside the gate and the overlap it would flush is the one the
    /// gate has just excluded.
    pub(super) fn covered_intervals_raw(&self, off: u64, len: u64) -> Vec<(u64, u64)> {
        let end = off + len;
        let iv = self.intervals.lock_ok();
        iv.iter()
            .filter_map(|&(s, e)| {
                let cs = s.max(off);
                let ce = e.min(end);
                (cs < ce).then_some((cs, ce))
            })
            .collect()
    }

    /// End of the contiguous prefix starting at 0 (the streaming frontier).
    pub fn contiguous_from_start(&self) -> u64 {
        // The streaming frontier, polled by live readers: a run held
        // behind it would stall a player on bytes we already have.
        let _ = self.flush_stage();
        let iv = self.intervals.lock_ok();
        match iv.first() {
            Some(&(0, e)) => e,
            _ => 0,
        }
    }

    /// Bytes written so far (not necessarily contiguous).
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// Count `n` bytes a PRIOR run left in this file as written, without
    /// claiming coverage of any range. A crash-resume opens an output
    /// that already holds bytes, and the extractor's in-stream decrypt
    /// gate reads this counter as "this output holds ciphertext" (rule 2
    /// of `instream_decrypt_allowed`): a resumed writer that started at
    /// zero let the gate latch plaintext-once over them (TODO 158 item
    /// 2). Coverage stays empty on purpose - the resume replays or
    /// refetches every one of those bytes, and `covered` must keep
    /// answering for THIS run's writes alone.
    pub fn seed_written(&self, n: u64) {
        self.written.fetch_add(n, Ordering::Relaxed);
    }
}
