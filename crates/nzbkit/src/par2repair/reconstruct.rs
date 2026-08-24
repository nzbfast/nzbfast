//! The whole inherent impl of [`Reconstructor`] - construction, the feed
//! and fold paths, and both finish flavours - moved out of par2repair.rs
//! bodily under the size gate (TODO 106). A child module of the defining
//! module, so the struct's private fields and par2repair.rs's private
//! helpers and `use` bindings stay in scope exactly as they were inline.
//! The struct itself, [`Feeder`], and the report types stay in the parent
//! beside their docs.

use super::*;

/// The one place [`MAX_REPAIR_DIM`] is spelled as a refusal, so the two
/// callers cannot drift in wording or in which side of the boundary they
/// admit. [`Reconstructor::new_with_path`] is the backstop every route
/// funnels through; `repair_dir_set_inner` calls it EARLIER, once its
/// missing set is final, because the backstop sits behind
/// `load_selected_recovery`, which pins one `block_size` buffer per
/// missing block - `m x block_size` bytes read and held only to be
/// dropped when the backstop refuses. At the cap that is the 256 MB the
/// constant budgets for; above it, it is whatever the set declares.
pub(super) fn check_repair_dim(m: usize) -> Result<(), RepairError> {
    // See MAX_REPAIR_DIM's docs: a crafted set declaring tens of
    // thousands of missing blocks is a repair-time DoS, not a repair.
    if m > MAX_REPAIR_DIM {
        return Err(RepairError::Malformed(format!(
            "{m} missing blocks exceeds the repair-matrix cap ({MAX_REPAIR_DIM})"
        )));
    }
    Ok(())
}

impl Reconstructor {
    /// `recovery` payloads are only READ here (widened into the u16
    /// syndrome rows before the fold worker spawns), so borrowed slices
    /// into a caller's corpus are as good as owned buffers - the mapped
    /// repair path selects `(u32, &[u8])` pairs to avoid cloning ~m x
    /// block_size of payload it would immediately discard.
    pub fn new<D: AsRef<[u8]>>(
        block_size: usize,
        n_inputs: usize,
        missing: &[usize],
        recovery: &[(u32, D)],
    ) -> Result<Reconstructor, RepairError> {
        Self::new_with_path(block_size, n_inputs, missing, recovery, SyndromePath::Auto)
    }

    #[doc(hidden)]
    pub fn new_with_path<D: AsRef<[u8]>>(
        block_size: usize,
        n_inputs: usize,
        missing: &[usize],
        recovery: &[(u32, D)],
        path: SyndromePath,
    ) -> Result<Reconstructor, RepairError> {
        if block_size == 0 || !block_size.is_multiple_of(2) {
            return Err(RepairError::Malformed(format!(
                "block size {block_size} not a positive multiple of 2"
            )));
        }
        if recovery.len() != missing.len() {
            return Err(RepairError::Malformed(format!(
                "{} recovery slices for {} missing blocks - caller must pass exactly one per",
                recovery.len(),
                missing.len()
            )));
        }
        // The backstop every repair route funnels through - the mapped
        // driver, the disk driver and any direct caller. The disk driver
        // ALSO checks it earlier (see `check_repair_dim`); this one is
        // what makes the cap a property of the engine rather than of
        // whoever remembered to ask.
        check_repair_dim(missing.len())?;
        let base_logs = input_base_logs(n_inputs)?;
        if let Some(&j) = missing.iter().find(|&&j| j >= n_inputs) {
            return Err(RepairError::Malformed(format!(
                "missing index {j} out of range ({n_inputs} inputs)"
            )));
        }
        let t_inv = std::time::Instant::now();
        // Consecutive exponents (both repair paths pick the SMALLEST
        // available, so this is the norm - gaps mean recovery packets
        // were themselves lost) make A a Vandermonde in the bases times
        // a diagonal, whose explicit inverse costs O(m²) instead of
        // Gauss-Jordan's O(m³).
        let consecutive = !recovery.is_empty() && recovery.windows(2).all(|w| w[1].0 == w[0].0 + 1);
        let structured = if consecutive {
            let ks: Vec<u32> = missing.iter().map(|&j| base_logs[j]).collect();
            invert_vandermonde(&ks, recovery[0].0)
        } else {
            None
        };
        let (label, inverse) = match structured {
            Some(inv) => ("vandermonde", inv),
            None => {
                // A[r][c] = g_{missing[c]}^{e_r} = 2^{k·e mod 65535}
                let a: Vec<Vec<u16>> = recovery
                    .iter()
                    .map(|(e, _)| {
                        missing
                            .iter()
                            .map(|&j| gf16::pow2(base_logs[j] as u64 * *e as u64))
                            .collect()
                    })
                    .collect();
                ("gauss-jordan", invert(a)?)
            }
        };
        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
            info!(
                target: "repair-timing",
                "matrix invert ({}x{0}, {label}): {:.2?}",
                missing.len(),
                t_inv.elapsed()
            );
        }
        let words = block_size / 2;
        // Memory-floor gauge: the syndrome rows are the repair's one
        // whole-run allocation - m x block_size, live from here to the
        // back-substitution (610 MB on the first leg that motivated
        // this: 165 recovery blocks x 3.7 MB).
        let syn_charge = crate::memgauge::Charge::new(
            crate::memgauge::Sub::RepairWork,
            (recovery.len() * block_size) as u64,
        );
        let mut exponents = Vec::with_capacity(recovery.len());
        let mut syndromes = Vec::with_capacity(recovery.len());
        for (e, data) in recovery {
            let data = data.as_ref();
            if data.len() != block_size {
                return Err(RepairError::Malformed(format!(
                    "recovery slice (exponent {e}) is {} bytes, block size is {block_size}",
                    data.len()
                )));
            }
            let mut w = vec![0u16; words];
            for (dw, s) in w.iter_mut().zip(data.chunks_exact(2)) {
                *dw = u16::from_le_bytes([s[0], s[1]]);
            }
            exponents.push(*e);
            syndromes.push(w);
        }
        // EXPERIMENTAL NTT dispatch (merged NTT plan Stage 2): when the
        // repair shape clears the measured gates, the worker RETAINS the
        // fed batches - the batch arenas ARE the resident source corpus -
        // and finish() runs the output-pruned NTT instead of having
        // folded along the way. Overflowing the retention budget folds
        // everything retained and reverts to streaming: the fold remains
        // the unconditional fallback, mid-flight.
        let ntt_budget =
            resolve_syndrome_path(path, block_size, n_inputs, missing.len(), &exponents);
        let worker_exponents = exponents.clone();
        // Capacity 4 (was 1): with M2c.2's parallel readers each sender
        // carries a BATCH_BYTES/N-sized batch, so a slightly deeper
        // queue keeps disks busy while a batch folds without growing
        // worst-case in-flight memory beyond the old single-feeder cap.
        let (tx, rx) = std::sync::mpsc::sync_channel::<FeedBatch>(8);
        let fold_trace = std::env::var_os("NZBFAST_FOLD_TRACE").is_some();
        let worker = std::thread::spawn(move || {
            let exponents = worker_exponents;
            let mut syndromes = syndromes;
            let mut retained: Vec<FeedBatch> = Vec::new();
            let mut retained_bytes = 0usize;
            let mut ntt_budget = ntt_budget;
            let mut waited = std::time::Duration::ZERO;
            let mut folded = std::time::Duration::ZERO;
            let mut calls = 0usize;
            let mut bytes = 0usize;
            loop {
                let t_w = std::time::Instant::now();
                let Ok(first) = rx.recv() else { break };
                waited += t_w.elapsed();
                if let Some(budget) = ntt_budget {
                    // Charge the pad the NTT will need for this batch as
                    // well as the batch itself: every SHORT slice (a file
                    // tail) is copied into a zero-padded whole block in
                    // `ntt_syndromes`, so a set of many small files - all
                    // tails - costs up to a second copy of the corpus
                    // that the fed bytes alone never show.
                    let pad = first
                        .slices
                        .iter()
                        .filter(|&&(_, _, len)| len != 0 && len != block_size)
                        .count()
                        * block_size;
                    retained_bytes += first.arena.len() + pad;
                    retained.push(first);
                    if retained_bytes > budget {
                        // Budget blown: fold what we held and stream on.
                        if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                            warn!(
                                target: "repair-timing",
                                "ntt retention over budget \
                                 ({retained_bytes} > {budget} bytes) - fold fallback"
                            );
                        }
                        fold_batches(&exponents, &mut syndromes, &retained);
                        retained.clear();
                        retained_bytes = 0;
                        ntt_budget = None;
                    }
                    continue;
                }
                let mut merged = vec![first];
                // Coalesce whatever the feeders have already queued: the
                // tiled fold walks EVERY syndrome row once per call, so N
                // small batches cost N row sweeps where one merged batch
                // costs one. Parallel feeders split BATCH_BYTES across
                // handles for memory control (M2c.2), which shrank fold
                // units 8x - measured as a repair regression on
                // small-L3 parts.
                //
                // The bound is channel capacity PLUS live senders, not
                // capacity alone: each try_recv that frees a buffered slot
                // immediately unblocks a sender, whose message lands in the
                // buffer and is drained on the next iteration. With
                // sync_channel(4) and up to 8 feeders that is up to 12
                // batches merged, not 5. Harmless at typical block sizes
                // (~48 MB vs the 32 MB BATCH_BYTES design cap), but a feeder
                // batch is one whole block when block_size is large - a set
                // with 16 MB blocks holds ~192 MB in the merged batch. The
                // fold is XOR accumulation, so merging and reordering are
                // exact; this is a memory bound, not a correctness one.
                while let Ok(more) = rx.try_recv() {
                    merged.push(more);
                }
                let t_f = std::time::Instant::now();
                fold_batches(&exponents, &mut syndromes, &merged);
                folded += t_f.elapsed();
                calls += 1;
                let mb: usize = merged.iter().map(|b| b.arena.len()).sum();
                bytes += mb;
                if fold_trace {
                    warn!(
                        target: "fold-trace",
                        "call {calls}: {} srcs, {:.1} MB, {:.2?}",
                        merged.iter().map(|b| b.slices.len()).sum::<usize>(),
                        mb as f64 / 1e6,
                        t_f.elapsed()
                    );
                }
            }
            if fold_trace {
                info!(
                    target: "fold-trace",
                    "total: {calls} calls, {:.1} MB, fold {:.2?}, recv-wait {:.2?}",
                    bytes as f64 / 1e6,
                    folded,
                    waited
                );
            }
            (syndromes, retained)
        });
        Ok(Reconstructor {
            block_size,
            base_logs: std::sync::Arc::new(base_logs),
            missing: missing.to_vec(),
            exponents,
            inverse,
            tx: Some(tx),
            worker: Some(worker),
            batch: FeedBatch::with_capacity(BATCH_BYTES),
            batch_capacity: BATCH_BYTES,
            ntt_selected: ntt_budget.is_some(),
            syn_charge,
            ntt_fault: match path {
                SyndromePath::NttForceCorrupt(_) => NttFault::Corrupt,
                SyndromePath::NttForcePanic(_) => NttFault::Panic,
                _ => NttFault::None,
            },
        })
    }

    /// Whether the dispatcher selected the NTT path at construction.
    /// Not part of the supported API surface.
    #[doc(hidden)]
    pub fn ntt_selected(&self) -> bool {
        self.ntt_selected
    }

    /// Accumulate one present input slice (borrowed - it is packed into
    /// the batch arena, so callers can reuse one read buffer instead of
    /// allocating per slice). `data` may be shorter than the block size
    /// (file tail) - the zero padding contributes nothing.
    pub fn feed(&mut self, input_index: usize, data: &[u8]) {
        debug_assert!(
            !self.missing.contains(&input_index),
            "fed a slice declared missing"
        );
        debug_assert!(data.len() <= self.block_size);
        if self.batch.arena.len() + data.len() > self.batch_capacity {
            self.flush();
        }
        self.batch.push(self.base_logs[input_index], data);
        if self.batch.arena.len() >= self.batch_capacity {
            self.flush();
        }
    }

    /// Hand the pending batch to the fold worker. Blocks only when a
    /// batch is already queued behind the one being folded.
    fn flush(&mut self) {
        if self.batch.slices.is_empty() {
            return;
        }
        let batch = std::mem::replace(
            &mut self.batch,
            FeedBatch::with_capacity(self.batch_capacity),
        );
        // The worker outlives every sender; send can't fail.
        let _ = self
            .tx
            .as_ref()
            .expect("finish() not yet called")
            .send(batch);
    }

    /// A shareable feed handle for parallel producers (M2c.2). Each
    /// reader thread takes its own Feeder; batches from every handle
    /// funnel into the same fold worker, so slices may arrive in any
    /// interleaving (the syndrome fold is order-free XOR accumulation).
    /// `max_batch` bounds the handle's assembly buffer - callers split
    /// [`BATCH_BYTES`] across handles so total in-flight memory stays
    /// what the single-feeder design used. Drop every Feeder (they
    /// flush on drop) BEFORE calling [`Self::finish`], or finish blocks
    /// on the channel.
    pub fn feeder(&self, max_batch: usize) -> Feeder {
        let max_batch = max_batch.max(1 << 20);
        Feeder {
            tx: self.tx.as_ref().expect("finish() not yet called").clone(),
            base_logs: self.base_logs.clone(),
            batch: FeedBatch::with_capacity(max_batch),
            max_batch,
        }
    }

    /// Solve: returns the reconstructed slices (full `block_size` bytes
    /// each, zero-padded past any file tail) in `missing` order.
    pub fn finish(self) -> Vec<Vec<u8>> {
        self.finish_reported().0
    }

    /// [`finish`](Self::finish), also reporting what the syndrome pass
    /// did - the repair drivers' verify-failure fallback needs to know
    /// whether the NTT actually computed the syndromes. Not part of the
    /// supported API surface.
    #[doc(hidden)]
    pub fn finish_reported(mut self) -> (Vec<Vec<u8>>, SyndromeReport) {
        self.flush();
        drop(self.tx.take());
        let (mut syndromes, retained) = self
            .worker
            .take()
            .expect("finish() called once")
            .join()
            .expect("syndrome fold worker panicked");
        let mut report = SyndromeReport {
            ntt_used: false,
            n_present: 0,
        };
        if !retained.is_empty() {
            (report.ntt_used, report.n_present) = self.ntt_syndromes(&mut syndromes, &retained);
        }
        // The retained corpus is dead the moment the syndromes are
        // computed, and it is the single biggest live allocation on the
        // NTT path - it must not still be resident while the m x
        // block_size output below is allocated and then copied out. The
        // worker arenas are already gone (dropped when the scoped
        // threads exited), so this window is the real NTT peak.
        drop(retained);
        let m = self.missing.len();
        let words = self.block_size / 2;
        let mut out: Vec<Vec<u16>> = vec![vec![0u16; words]; m];
        // Memory-floor gauge: the rebuilt output blocks coexist with the
        // syndrome rows through the back-substitution - together they
        // are the repair's true peak window. Released at return (the
        // caller writes the blocks out and drops them promptly).
        let _out_charge =
            crate::memgauge::Charge::new(crate::memgauge::Sub::RepairWork, (m * words * 2) as u64);
        if m > 0 {
            // Same tiled multi-accumulate as the syndrome fold: the
            // m x m back-substitution re-reads every syndrome row per
            // output row, so untiled it costs m x the syndrome set in
            // RAM sweeps (and used to run scalar on top). Shares the
            // row x column scheduler too - with one missing block this
            // solve is a single row, so rows alone would run it on one
            // thread.
            let syn_bytes: Vec<&[u8]> = syndromes.iter().map(|s| gf16::words_as_bytes(s)).collect();
            let inverse = &self.inverse;
            let t_bs = std::time::Instant::now();
            fold_parallel(&mut out, &syn_bytes, &|j, i| inverse[j][i]);
            if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
                info!(target: "repair-timing", "back-substitution: {:.2?}", t_bs.elapsed());
            }
        }
        // Same reason as the retained corpus above: the syndrome rows
        // are consumed by the back-substitution and nothing past it
        // reads them, so they must not stay live across the byte
        // conversion, which briefly holds two copies of the output.
        drop(syndromes);
        self.syn_charge.release_all();
        // On little-endian a word slice already IS its PAR2 byte view,
        // so this is a memcpy per block rather than a per-byte iterator
        // chain over the whole repaired payload.
        let out = out
            .into_iter()
            .map(|w| gf16::words_as_bytes(&w).to_vec())
            .collect();
        (out, report)
    }

    /// EXPERIMENTAL NTT syndrome pass over the retained source corpus
    /// (merged NTT plan Stage 2). XORs each present slice's contribution
    /// into the recovery-initialized syndrome rows via the output-pruned
    /// transform; any shape the plan cannot represent (duplicate feeds,
    /// out-of-range logs) falls back to folding the retained batches -
    /// bit-identical semantics either way, since the fold is pure XOR
    /// accumulation. Returns (ntt actually ran, present slices fed).
    fn ntt_syndromes(&self, syndromes: &mut [Vec<u16>], retained: &[FeedBatch]) -> (bool, usize) {
        let timing = std::env::var_os("NZBFAST_REPAIR_TIMING").is_some();
        let t0 = std::time::Instant::now();
        let words = self.block_size / 2;
        // Slice table: full-length slices point into the batch arenas
        // (the resident corpus); short tails are copied once into a
        // zero-padded side arena so every stripe pointer is readable.
        let mut table: Vec<*const u8> = Vec::new();
        let mut present: Vec<(u32, crate::par2ntt::SrcId)> = Vec::new();
        // Counted up front rather than grown block by block: a set of
        // many small files is nearly all tails, so the doubling Vec
        // would hold up to twice the final pad during a reallocation -
        // and that transient is exactly what the retention backstop's
        // pad charge is trying to bound.
        let n_short = retained
            .iter()
            .flat_map(|b| b.slices.iter())
            .filter(|&&(_, _, len)| len != 0 && len != self.block_size)
            .count();
        let mut pad_arena: Vec<u8> = Vec::new();
        pad_arena.reserve_exact(n_short * self.block_size);
        // Memory-floor gauge: the zero-padded tail arena - up to a
        // second copy of the corpus on a many-small-files set (the same
        // transient the retention backstop's pad term prices).
        let _pad_charge = crate::memgauge::Charge::new(
            crate::memgauge::Sub::RepairWork,
            (n_short * self.block_size) as u64,
        );
        let mut pads: Vec<(usize, usize, usize)> = Vec::new(); // (table idx, pad off, len)
        pads.reserve_exact(n_short);
        for b in retained {
            for &(log, off, len) in &b.slices {
                if len == 0 {
                    continue;
                }
                let id = table.len() as crate::par2ntt::SrcId;
                if len == self.block_size {
                    table.push(b.arena[off..off + len].as_ptr());
                } else {
                    let poff = pad_arena.len();
                    pad_arena.resize(poff + self.block_size, 0);
                    pads.push((table.len(), poff, len));
                    table.push(std::ptr::null()); // patched below
                }
                present.push((log, id));
            }
        }
        // Second pass for the tail copies: pad_arena has its final size
        // now, so pointers taken from it below are stable.
        {
            let mut pi = 0usize;
            let mut ti = 0usize;
            for b in retained {
                for &(_, off, len) in &b.slices {
                    if len == 0 {
                        continue;
                    }
                    if len != self.block_size {
                        let (idx, poff, plen) = pads[pi];
                        debug_assert_eq!(idx, ti);
                        pad_arena[poff..poff + plen].copy_from_slice(&b.arena[off..off + len]);
                        table[ti] = pad_arena[poff..poff + self.block_size].as_ptr();
                        pi += 1;
                    }
                    ti += 1;
                }
            }
            debug_assert_eq!(pi, pads.len());
        }
        let needed = self.exponents.iter().copied().max().unwrap_or(0) as usize + 1;
        let plan = match crate::par2ntt::FlatPlan::build(&present, needed) {
            Ok(p) => p,
            Err(why) => {
                if timing {
                    info!(target: "repair-timing", "ntt plan unbuildable ({why}) - fold fallback");
                }
                fold_batches(&self.exponents, syndromes, retained);
                return (false, 0);
            }
        };
        // Stripe width and worker count: W=512 (1 KiB stripes) holds the
        // measured wall inside the scratch budget (Stage 1 doc); workers
        // pull stripes from a shared queue and XOR their rows into
        // disjoint column ranges of the shared syndrome rows.
        let w: usize = std::env::var("NZBFAST_NTT_W")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v: &usize| v >= 16)
            .unwrap_or(512)
            .min(words.max(16));
        let stripes = words.div_ceil(w);
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        // Same physical-core rule as fold_parallel on hybrid x86.
        #[cfg(all(target_arch = "x86_64", windows))]
        let cores = physical_cores().map_or(cores, |p| p.min(cores));
        let threads = std::env::var("NZBFAST_NTT_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(cores)
            .clamp(1, stripes.max(1));
        struct SynPtrs(Vec<*mut u16>, Vec<usize>);
        // SAFETY: raw pointers into the syndrome rows; workers XOR
        // into disjoint column ranges only (one stripe per atomic
        // fetch_add claim, per the stripe/worker comment above), so
        // sharing them across the scope's threads races nothing.
        unsafe impl Send for SynPtrs {}
        // SAFETY: as above, writes are confined to the claiming
        // worker's stripe columns.
        unsafe impl Sync for SynPtrs {}
        let syn = SynPtrs(
            syndromes.iter_mut().map(|s| s.as_mut_ptr()).collect(),
            self.exponents.iter().map(|&e| e as usize).collect(),
        );
        struct SrcTable(Vec<*const u8>);
        // SAFETY: read-only pointers into the retained batch arenas
        // and the finalized pad arena (stable per the second-pass
        // comment above); neither is mutated while the scope's
        // workers read them.
        unsafe impl Send for SrcTable {}
        // SAFETY: as above, all access through these pointers is
        // read-only.
        unsafe impl Sync for SrcTable {}
        let table = SrcTable(table);
        let next = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            let plan = &plan;
            let syn = &syn;
            let table = &table;
            let next = &next;
            for _ in 0..threads {
                s.spawn(move || {
                    let mut scratch = plan.new_scratch(w);
                    let mut out = vec![0u16; plan.needed * w];
                    loop {
                        let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if c >= stripes {
                            break;
                        }
                        let len = w.min(words - c * w);
                        // SAFETY: every table entry is readable for
                        // block_size bytes (full slices point into the
                        // batch arenas, tails into the zero-padded
                        // side arena, per the slice-table comment
                        // above), and c*w*2 + 2*len <= block_size
                        // because len = w.min(words - c*w), satisfying
                        // transform's src_of contract.
                        let src_of = |id: crate::par2ntt::SrcId| unsafe {
                            table.0[id as usize].add(c * w * 2)
                        };
                        plan.transform(&src_of, len, &mut scratch, &mut out);
                        for (j, &e) in syn.1.iter().enumerate() {
                            // SAFETY: syndrome row j is words long and
                            // c*w + len <= words, so the range is in
                            // bounds; stripe c belongs to this worker
                            // alone (claimed via the atomic queue), so
                            // no other thread touches these columns.
                            let row =
                                unsafe { std::slice::from_raw_parts_mut(syn.0[j].add(c * w), len) };
                            for (d, s) in row.iter_mut().zip(&out[e * len..(e + 1) * len]) {
                                *d ^= *s;
                            }
                        }
                    }
                });
            }
        });
        if timing {
            info!(
                target: "repair-timing",
                "ntt syndromes (m={}, needed={}, n={}, W={w}, threads={threads}): {:.2?}",
                self.exponents.len(),
                plan.needed,
                present.len(),
                t0.elapsed()
            );
        }
        match self.ntt_fault {
            NttFault::None => {}
            // TEST ONLY (NttForceCorrupt): a single flipped word models
            // an NTT correctness bug; whole-file verification must catch
            // it and the fold retry must rescue the repair.
            NttFault::Corrupt => syndromes[0][0] ^= 1,
            // TEST ONLY (NttForcePanic): the retry must survive a panic
            // on the NTT path.
            NttFault::Panic => panic!("injected NTT panic (NttForcePanic test path)"),
        }
        (true, present.len())
    }
}
