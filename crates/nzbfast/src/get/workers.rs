//! The worker tasks get_with_progress spawns: decode consumers, the
//! rate ticker, the deadlock watchdog, the speculative recovery
//! prefetch, and the par-race experiment (TODO 106 phase 2.1, cuts
//! 1-2). Bodies are verbatim moves from the orchestrator; each fn's
//! parameter list is exactly the clone set its spawn site used to
//! build.

use crate::*;
use std::path::Path;
use tracing::{info, warn};

/// Plaintext-once (`D`) journal record parked until its seam bytes are
/// on disk: (slot, article id, name, size, frags).
pub(super) type PendingD = (usize, Arc<str>, String, u64, Vec<nzbkit::extract::Frag>);

/// Article parked on a [`nzbkit::extract::Persist::Held`] return: some
/// of its bytes were parked in the extractor for a later re-feed
/// (typically it arrived before the offset-0 sniff established the
/// store mapper). Kept until the drained placements cover its whole
/// span, at which point it journals like any placed article - without
/// this, a mid-volume payload article that was fully written by the
/// drain never got an `R` record and every crash/ENOSPC resume
/// refetched it for no reason.
pub(super) struct ParkedR {
    pub(super) sidx: usize,
    pub(super) id: Arc<str>,
    pub(super) name: String,
    pub(super) size: u64,
    /// The article's span in volume address space.
    pub(super) off: u64,
    pub(super) len: u64,
    /// Plain fragments already on disk when the article arrived (the
    /// partially-held case; empty for a whole-span hold).
    pub(super) frags: Vec<nzbkit::extract::Frag>,
    /// Journals as a bare `record(id)` like the Placed arm does for the
    /// par2 main, instead of an `R` placement.
    pub(super) par2_main: bool,
}

/// Held-article journal state shared by the decode consumers and the
/// drain pass: parked articles plus the late placements drained from
/// the extractor so far, per slot.
#[derive(Default)]
pub(super) struct PendingR {
    pub(super) parked: Vec<ParkedR>,
    pub(super) late: std::collections::HashMap<usize, Vec<nzbkit::extract::Frag>>,
}

/// Join freshly drained late placements against the parked held
/// articles and journal every article whose span the plain fragments
/// now fully cover. A hold is always a subrange of exactly one
/// article's span, so containment in `[off, off+len)` is the join key.
/// Cheap when nothing is parked (one uncontended lock).
pub(super) fn flush_pending_r(
    pending_r: &std::sync::Mutex<PendingR>,
    extractor: &nzbkit::extract::Extractor,
    journal: &nzbkit::journal::Journal,
) {
    let mut st = pending_r.lock_ok();
    if st.parked.is_empty() {
        return;
    }
    for (slot, frag) in extractor.drain_late_placements() {
        st.late.entry(slot).or_default().push(frag);
    }
    let PendingR { parked, late } = &mut *st;
    let mut done: Vec<(usize, u64, u64)> = Vec::new();
    parked.retain(|p| {
        let end = p.off + p.len;
        let mut frags = p.frags.clone();
        if let Some(slot_late) = late.get(&p.sidx) {
            frags.extend(
                slot_late
                    .iter()
                    .filter(|f| f.vol_off >= p.off && f.vol_off + f.len <= end)
                    .cloned(),
            );
        }
        frags.sort_by_key(|f| f.vol_off);
        let mut covered_to = p.off;
        let mut gap = false;
        for f in &frags {
            if f.vol_off > covered_to {
                gap = true; // a hole the placements do not fill
                break;
            }
            covered_to = covered_to.max(f.vol_off + f.len);
        }
        // TODO 252 (23 Aug 2026): the placement trail is not the only
        // way an article's bytes reach a MATERIALIZED volume, so where
        // it comes up short, ask the volume file itself. The demote
        // reconstruction reports every write it makes (`refeed_active`),
        // but the post-write re-route in `Extractor::write` and the
        // forward-delivery re-check both land their bytes with the flag
        // down and surface nothing - and the read-back skips any range
        // whose pwrite has not landed yet, which is the window those two
        // exist to close. The article then stayed parked for the life of
        // the job and refetched on the next run, ~8% of runs of the e2e
        // resume rig standalone here and ~40% under a loaded suite.
        // `materialized_span_on_disk` makes the same claim the slot's
        // `M` line makes, off the writer's own coverage map rather than
        // off an inference: an unwritten byte anywhere in the span
        // answers `None` and the article stays parked, which is the safe
        // direction.
        let mut on_disk = None;
        if gap || frags.is_empty() || covered_to < end {
            let Some((name, size)) = extractor.materialized_span_on_disk(p.sidx, p.off, p.len)
            else {
                return true; // stays parked
            };
            frags = vec![nzbkit::extract::Frag::identity(&name, p.off, p.len)];
            on_disk = Some((name, size));
        }
        // Every byte of the span is durably on disk (the re-feed writes
        // ran under the extractor's routing lock, before the placements
        // were surfaced) - journal it exactly like a directly-Placed
        // article.
        if p.par2_main {
            journal.record(&p.id);
        } else {
            let widened = on_disk.is_some();
            let slot_file = on_disk.or_else(|| extractor.slot_file_info(p.sidx));
            let mut frags = frags;
            // A parked article completing AFTER its slot demoted may mix
            // identity fragments (the reconstruction's own writes) with
            // fragments naming inner files the fallback just deleted -
            // and its record lands after the slot's `M` line, past the
            // positional rewrite. Same fact, applied at record time: the
            // materialized volume holds every one of these bytes at its
            // final offset.
            // The widened arm above already composed its one fragment
            // that way, from the same locked read that established the
            // coverage.
            if !widened
                && extractor.slot_materialized(p.sidx)
                && let Some((name, _)) = slot_file.as_ref()
            {
                for f in frags.iter_mut() {
                    f.rebase_identity(name);
                }
            }
            journal.record_placed(p.sidx, &p.id, slot_file, &p.name, p.size, &frags);
        }
        done.push((p.sidx, p.off, end));
        false
    });
    // The late fragments a journaled article consumed can never match
    // another article (spans are disjoint) - drop them so the map does
    // not grow for the life of the job.
    if !done.is_empty() {
        for (slot, v) in late.iter_mut() {
            v.retain(|f| {
                !done
                    .iter()
                    .any(|(s, o, e)| s == slot && f.vol_off >= *o && f.vol_off + f.len <= *e)
            });
        }
    }
}

/// One decode consumer's dependency set - exactly the clone list its
/// spawn site builds (TODO 106 phase 2.1, cut 1). The destructure at
/// the top of [`decode_consumer_loop`] keeps the body identical to its
/// pre-extraction text, so the diff is a move, not a rewrite.
pub(super) struct DecodeCtx {
    pub(super) rx: Arc<std::sync::Mutex<tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>>>,
    pub(super) pending_d: Arc<std::sync::Mutex<Vec<PendingD>>>,
    pub(super) pending_r: Arc<std::sync::Mutex<PendingR>>,
    pub(super) pool: Arc<nzbkit::pool::BufPool>,
    pub(super) out_pool: Arc<nzbkit::pool::BufPool>,
    pub(super) slots: Vec<Arc<FileSlot>>,
    /// Shared with the plan and the sibling decoders - an `Arc` clone,
    /// never a deep copy (§A1). Read-only after `build_fetch_plan`, so
    /// no lock; consumers take `&IdSlots` and deref-coerce.
    pub(super) id_to_slot: Arc<crate::unpack::IdSlots>,
    pub(super) seek_names: Arc<SeekCtl>,
    pub(super) decoded_bytes: Arc<AtomicU64>,
    pub(super) fetch_done: Arc<AtomicU64>,
    pub(super) decode_errors: Arc<AtomicU64>,
    pub(super) retention_excluded: Arc<CauseSplit>,
    pub(super) missing_430: Arc<CauseSplit>,
    pub(super) takedown_430: Arc<CauseSplit>,
    pub(super) transport_failed: Arc<CauseSplit>,
    pub(super) transport_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) decode_error_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) disk_full_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) verifier: Arc<nzbkit::live::LiveVerifier>,
    pub(super) extractor: Arc<nzbkit::extract::Extractor>,
    pub(super) shape_said: Arc<std::sync::atomic::AtomicBool>,
    pub(super) par2_outstanding: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) journal: Arc<nzbkit::journal::Journal>,
    pub(super) backfill: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>>,
    pub(super) sniff: Arc<SniffCtl>,
    /// §94 A: the restored files the replay still owes, fed back per
    /// slot the moment that slot's offset-0 article is written - which
    /// is the first moment its mapper can place them. See
    /// `rig::ReplayPending`.
    pub(super) replay: Arc<super::rig::ReplayPending>,
    pub(super) queue_ctl: Arc<nzbkit::pool::QueueControl>,
    pub(super) rt: tokio::runtime::Handle,
    pub(super) throttle_mbps: Option<f64>,
    pub(super) throttle_t0: Instant,
    /// TODO 114 consumer steer: report every Done body's decode
    /// verdict through `queue_ctl.note_decoded`, and force the
    /// integrity pass even where M32 delegation would skip it - the
    /// forced CRC is the endgame's entire marginal cost, and without
    /// it a corrupt body on a delegated slot is invisible until the
    /// verifier's block hash, past steer time.
    pub(super) crc_steer: bool,
}

/// One loss-cause ledger, counted separately for PAYLOAD and RECOVERY
/// articles (sweep 8, M7).
///
/// These counters used to be flat totals over every slot alike, and the
/// diagnosis gates read them as statements about the payload. They are
/// not. One irrelevant 430 on a `.par2` article suppressed
/// `all_transport` and had a release whose payload died entirely in
/// transport reported as missing/gone - to the user, and to the
/// indexer. The mirror image is worse: one transport failure on a
/// recovery article suppressed the wholly-gone verdict for a post that
/// really was gone, so the job waited and re-grabbed instead of saying
/// so. Takedown dominance was distorted the same way, because it is a
/// ratio of two of these.
///
/// So the split is taken at COLLECTION, where the article's slot is
/// still in hand: diagnosis reads `payload`, and `recovery` is repair
/// context. An outcome whose id maps to no slot at all counts as
/// payload - it cannot be shown to be parity, and payload is the
/// conservative side (it blocks the optimistic verdicts rather than
/// licensing them).
#[derive(Default, Debug)]
pub(super) struct CauseSplit {
    payload: AtomicU64,
    recovery: AtomicU64,
}

impl CauseSplit {
    pub(super) fn add(&self, recovery: bool) {
        let c = if recovery {
            &self.recovery
        } else {
            &self.payload
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Losses charged to payload slots - what every diagnosis gate asks.
    pub(super) fn payload(&self) -> u64 {
        self.payload.load(Ordering::Relaxed)
    }

    /// Losses charged to recovery slots - repair context, never a
    /// payload verdict.
    pub(super) fn recovery(&self) -> u64 {
        self.recovery.load(Ordering::Relaxed)
    }

    /// Both - for counts that describe the RUN rather than the payload
    /// (the console census says how many segments went unrequested, and
    /// a `.par2` article that went unrequested still did).
    pub(super) fn total(&self) -> u64 {
        self.payload() + self.recovery()
    }
}

/// Is this article's slot a RECOVERY slot (sweep 8, M7)?
///
/// Unknown ids count as PAYLOAD: a body whose id maps to no slot cannot
/// be shown to be parity, and payload is the conservative side - it
/// blocks the optimistic verdicts (`post_gone`, `all_transport`) rather
/// than licensing them.
fn is_recovery_article(
    id: &str,
    id_to_slot: &crate::unpack::IdSlots,
    slots: &[Arc<FileSlot>],
) -> bool {
    id_to_slot
        .get(id)
        .and_then(|&(sidx, _)| slots.get(sidx as usize))
        .is_some_and(|s| s.is_par2())
}

/// The PAR2 activation race's dependency set (TODO 106 phase 2.1, cut
/// 2). Borrowed, not cloned: it is assembled once per consumer thread
/// from the same locals the loop already holds.
struct Par2Race<'a> {
    slots: &'a [Arc<FileSlot>],
    verifier: &'a Arc<nzbkit::live::LiveVerifier>,
    extractor: &'a Arc<nzbkit::extract::Extractor>,
    par2_outstanding: &'a Arc<std::sync::atomic::AtomicUsize>,
    sniff: &'a Arc<SniffCtl>,
    queue_ctl: &'a Arc<nzbkit::pool::QueueControl>,
    backfill: &'a Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>>,
    rt: &'a tokio::runtime::Handle,
}

impl Par2Race<'_> {
    /// A slot just ran out of outstanding articles. If it was PAR2 -
    /// a static main, or a sniffed bootstrap that owes the counter a
    /// completion the same way (a DEFERRED sniffed slot does not) -
    /// activate the set when this is the one that completes it, and
    /// hand the pre-activation backfill to a blocking thread rather
    /// than running it on the decoder.
    fn slot_drained(&self, sidx: usize) {
        let slot = &self.slots[sidx];
        if !(slot.is_par2_main || (slot.is_par2() && self.sniff.note_completed(sidx)))
            || !maybe_activate_par2(
                self.slots,
                self.verifier,
                self.par2_outstanding,
                self.sniff,
                self.queue_ctl,
                self.extractor,
            )
        {
            return;
        }
        let v = self.verifier.clone();
        let ex = self.extractor.clone();
        let sl = self.slots.to_vec();
        let n = self.slots.len();
        *self.backfill.lock_ok() = Some(self.rt.spawn_blocking(move || {
            let flags: Vec<bool> = sl.iter().map(|s| s.is_par2()).collect();
            backfill_pre_activation(&v, &ex, n, &flags)
        }));
    }

    /// An article that will never arrive - a 430, a retention hole, a
    /// transport failure. Terminal is terminal: it still ends the
    /// fetch's responsibility for those bytes, and leaving them out
    /// would hold the progress bar short of 100% on every damaged set
    /// while repair ran.
    fn article_lost(&self, id: &str, id_to_slot: &crate::unpack::IdSlots, done: &AtomicU64) {
        let Some(&(sidx, nbytes)) = id_to_slot.get(id) else {
            return;
        };
        let sidx = sidx as usize;
        done.fetch_add(nbytes, Ordering::Relaxed);
        // A terminal verdict arms the extractor's stalled-chase spill: a
        // compressed set WEDGED behind this article's gap pages its cold
        // frontier bytes to scratch instead of sitting fully resident to
        // the holds cap. Once per slot, not per article (§156.3a): the
        // marks are sticky and per-volume, so the first verdict says
        // everything - without this gate a pool teardown sealing ~10k
        // outstanding ids as Failed re-ran the paging pass 10k times.
        if self.slots[sidx].missing.fetch_add(1, Ordering::Relaxed) == 0 {
            self.extractor.note_article_lost(sidx);
        }
        if self.slots[sidx].remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.slot_drained(sidx);
        }
    }
}

/// Take up to eight fetch outcomes in one lock hold.
///
/// A batch per lock hold, not one outcome per hold: the futex wake +
/// context switch of a `blocking_recv` handoff is per-batch, not
/// per-article - at loopback article rates (8k+/s) the per-article
/// version tripled sys time on 2 CPUs. At NAS rates the batch is 1 and
/// behavior is identical. Empty means the channel closed and drained.
fn drain_outcome_batch(
    rx: &Arc<std::sync::Mutex<tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>>>,
    journal: &nzbkit::journal::Journal,
) -> Vec<nzbkit::pool::FetchOutcome> {
    let mut batch = Vec::with_capacity(8);
    let mut rx = rx.lock_ok();
    // The journal batches placement records (TODO 30a, Finding 6) and
    // lands them by size or age as records arrive - which means a
    // STALL leaves the last batch queued until the next article. This
    // is the one point every decoder passes on its way to blocking: if
    // the channel is empty right now, land what is queued before
    // waiting on it. Costs one uncontended lock per idle transition and
    // nothing on a busy stream (the try_recv hit skips it).
    let first = match rx.try_recv() {
        Ok(o) => Some(o),
        Err(_) => {
            journal.flush();
            rx.blocking_recv()
        }
    };
    if let Some(first) = first {
        batch.push(first);
        while batch.len() < 8 {
            match rx.try_recv() {
                Ok(o) => batch.push(o),
                Err(_) => break,
            }
        }
    }
    // Memory-floor gauge: these raw bodies just left the fetch->decode
    // channel (they stay charged to RawOut until the pool gets them
    // back). Released by capacity, matching the sender's charge exactly.
    for o in &batch {
        if let nzbkit::pool::FetchOutcome::Done { raw, .. } = o {
            nzbkit::memgauge::sub(nzbkit::memgauge::Sub::Channel, raw.capacity() as u64);
        }
    }
    batch
}

/// Everything one decode consumer thread does: drain outcome batches
/// off the shared channel, yEnc-decode, write through the extractor,
/// feed the verifier, keep the journal and the PAR2 activation race
/// honest. Runs on a dedicated OS thread - decode + pwrite + verify
/// are synchronous CPU/disk work, and inline on tokio workers they
/// starve the socket reactor on 2-4 core boxes (see the spawn site).
pub(super) fn decode_consumer_loop(ctx: DecodeCtx) {
    use nzbkit::pool::FetchOutcome;
    let DecodeCtx {
        rx,
        pending_d,
        pending_r,
        pool,
        out_pool,
        slots,
        id_to_slot,
        seek_names,
        decoded_bytes,
        fetch_done,
        decode_errors,
        retention_excluded,
        missing_430,
        takedown_430,
        transport_failed,
        transport_sample,
        decode_error_sample,
        disk_full_sample,
        verifier,
        extractor,
        shape_said,
        par2_outstanding,
        journal,
        backfill,
        sniff,
        replay,
        queue_ctl,
        rt,
        throttle_mbps,
        throttle_t0,
        crc_steer,
    } = ctx;
    let par2 = Par2Race {
        slots: &slots,
        verifier: &verifier,
        extractor: &extractor,
        par2_outstanding: &par2_outstanding,
        sniff: &sniff,
        queue_ctl: &queue_ctl,
        backfill: &backfill,
        rt: &rt,
    };
    loop {
        let batch = drain_outcome_batch(&rx, &journal);
        if batch.is_empty() {
            break; // channel closed and drained
        }
        for outcome in batch {
            match outcome {
                FetchOutcome::Done { id, raw } => {
                    use nzbkit::pool::{DecodeAck, DecodeReport};
                    let Some(&(sidx, nbytes)) = id_to_slot.get(&id) else {
                        // Not ours to place - but the pool is waiting
                        // on this id's verdict (steer) AND its settle
                        // ack (arrival_ack, TODO 121.4): an Owned
                        // verdict keeps the done_ok liveness entry, so
                        // settle must follow it. After a Steered ack
                        // the settle is a no-op.
                        if crc_steer {
                            queue_ctl.note_decoded(&id, DecodeReport::Clean { part: None });
                        }
                        queue_ctl.note_settled(&id);
                        pool.give(raw);
                        continue;
                    };
                    let sidx = sidx as usize;
                    let slot = &slots[sidx];
                    let mut out = out_pool.take();
                    // M32 perf: once live verify (full-MD5 mode) has
                    // matched this slot to a PAR2 file, the article
                    // CRC is a redundant pass over bytes the verifier
                    // hashes anyway - skip it and feed the span
                    // untrusted. First article per slot (and every
                    // article under fast verify / no PAR2) keeps it.
                    // TODO 114: the consumer steer overrides the skip
                    // - this decode is now also the pool's damage
                    // detector, and a corrupt body it waves through
                    // is not seen again until the verifier's block
                    // hash, past steer time. The forced CRC is the
                    // steer's entire marginal cost.
                    let delegated = verifier.delegates_integrity(sidx) && !crc_steer;
                    match nzbkit::yenc_simd::decode_into_integrity(&raw, &mut out, !delegated) {
                        Ok((dec, integrity)) => {
                            // TODO 114: report the verdict (the pool
                            // does the expected-part comparison). A
                            // steered body is dropped whole: the
                            // refetched copy owns every counter,
                            // including fetch_done - crediting here
                            // would double-count the article when the
                            // clean copy lands.
                            if crc_steer
                                && queue_ctl
                                    .note_decoded(&id, DecodeReport::Clean { part: dec.part })
                                    == DecodeAck::Steered
                            {
                                out_pool.give(out);
                                pool.give(raw);
                                continue;
                            }
                            // This article is now accounted for,
                            // whatever the write below makes of it.
                            fetch_done.fetch_add(nbytes, Ordering::Relaxed);
                            let crc_checked = integrity.crc_checked;
                            // Borrowed, not cloned: this runs per article on
                            // every decode thread, and the only consumers that
                            // need to OWN the name are the two park arms below,
                            // which are rare.
                            let name: &str = if dec.name.is_empty() {
                                &slot.hint
                            } else {
                                &dec.name
                            };
                            // Issue #14: the offset-0 article of a
                            // payload-classified slot decoding to
                            // the PAR2 packet magic identifies
                            // recovery data with certainty (nothing
                            // else starts with it). Reclassify NOW,
                            // before the scheduler fetches any more
                            // of the volume.
                            if !slot.is_par2()
                                && dec.offset() == 0
                                && out.starts_with(nzbkit::par2::MAGIC)
                            {
                                reclassify_sniffed_par2(
                                    &sniff,
                                    &slots,
                                    sidx,
                                    &out,
                                    dec.file_size,
                                    &queue_ctl,
                                    &id_to_slot,
                                    &par2_outstanding,
                                );
                            }
                            // BEFORE the write: the offset-0 probe
                            // fires from inside write_verified and
                            // promotes by this yEnc name - on an
                            // obfuscated set the hint-keyed lookup
                            // alone would miss it.
                            if !slot.is_par2() {
                                seek_names.note_slot_name(sidx, name);
                            }
                            match extractor.write_verified(
                                sidx,
                                name,
                                dec.file_size,
                                dec.offset(),
                                &out,
                                // The checked pcrc32 over exactly these
                                // bytes: a STORE span that is this whole
                                // article composes from it instead of
                                // hashing them again.
                                integrity.verified_article_crc,
                            ) {
                                Err(e) => {
                                    warn!(target: "get", "write {name}: {e}");
                                    decode_error_sample
                                        .lock_ok()
                                        .get_or_insert_with(|| format!("write {name}: {e}"));
                                    decode_errors.fetch_add(1, Ordering::Relaxed);
                                    slot.errors.fetch_add(1, Ordering::Relaxed);
                                    // The storage itself ran out under the
                                    // write (full volume, spent quota, a
                                    // share gone read-only). Refetching
                                    // cannot fix it, and without the halt
                                    // a filled output volume kept the
                                    // download running at line rate with
                                    // EVERY article failing this same way.
                                    // Stop the fetch now; drain_network
                                    // turns the sample into the job's
                                    // out-of-disk-space verdict, and the
                                    // journal keeps what landed for the
                                    // resume.
                                    if note_storage_exhausted_halt(
                                        &e,
                                        name,
                                        &disk_full_sample,
                                        &queue_ctl,
                                    ) {
                                        warn!(
                                            target: "get",
                                            "out of disk space - stopping the download; \
                                             what landed is journaled and a retry resumes \
                                             without refetching it"
                                        );
                                    }
                                }
                                Ok(persist) => {
                                    // §94 A: an offset-0 write is what
                                    // moves a slot from "cannot place"
                                    // to "can" - its own header parses,
                                    // and it may complete the run of
                                    // volumes a later one's base
                                    // resolves through. So every one of
                                    // them re-checks what the replay
                                    // still owes. A no-op on a fresh
                                    // run, on the adopt path, and once
                                    // the replay has drained.
                                    if dec.offset() == 0 && !slot.is_par2() && !replay.is_empty() {
                                        replay.try_drain(&extractor, &verifier);
                                    }
                                    match &persist {
                                        nzbkit::extract::Persist::Placed(frags) => {
                                            if slot.is_par2_main {
                                                journal.record(&id);
                                            } else {
                                                journal.record_placed(
                                                    sidx,
                                                    &id,
                                                    extractor.slot_file_info(sidx),
                                                    name,
                                                    dec.file_size,
                                                    frags,
                                                );
                                            }
                                        }
                                        // Plaintext-once span: parked
                                        // until its seam slivers are on
                                        // disk (usually one neighboring
                                        // article later) - a D record for
                                        // RAM-held bytes would survive a
                                        // kill the bytes did not.
                                        nzbkit::extract::Persist::PlacedCrypto(frags) => {
                                            pending_d.lock_ok().push((
                                                sidx,
                                                id.clone(),
                                                name.to_string(),
                                                dec.file_size,
                                                frags.clone(),
                                            ));
                                        }
                                        // Bytes of this span were parked
                                        // for a later re-feed: keep the
                                        // article's identity and finish
                                        // its record when the drained
                                        // placements cover the span (see
                                        // flush_pending_r).
                                        nzbkit::extract::Persist::Held(frags) => {
                                            if !out.is_empty() {
                                                pending_r.lock_ok().parked.push(ParkedR {
                                                    sidx,
                                                    id: id.clone(),
                                                    name: name.to_string(),
                                                    size: dec.file_size,
                                                    off: dec.offset(),
                                                    len: out.len() as u64,
                                                    frags: frags.clone(),
                                                    par2_main: slot.is_par2_main,
                                                });
                                            }
                                        }
                                        nzbkit::extract::Persist::No => {}
                                    }
                                    flush_pending_r(&pending_r, &extractor, &journal);
                                    // Flush every parked D whose bytes
                                    // have settled; E/K/T facts go first
                                    // so the records they support are
                                    // never orphaned.
                                    {
                                        let mut pd = pending_d.lock_ok();
                                        if !pd.is_empty() {
                                            let ev = extractor.drain_crypto_events();
                                            journal.record_crypto_events(&ev);
                                            pd.retain(|(sidx, id, name, size, frags)| {
                                                if extractor.crypto_span_on_disk(frags) {
                                                    journal.record_placed_crypto(
                                                        *sidx,
                                                        id,
                                                        extractor.slot_file_info(*sidx),
                                                        name,
                                                        *size,
                                                        frags,
                                                        &extractor.crypto_frag_mask(frags),
                                                    );
                                                    false
                                                } else {
                                                    true
                                                }
                                            });
                                        }
                                    }
                                    decoded_bytes.fetch_add(out.len() as u64, Ordering::Relaxed);
                                    if let Some(mbps) = throttle_mbps {
                                        let target = decoded_bytes.load(Ordering::Relaxed) as f64
                                            / (mbps * 1e6);
                                        let actual = throttle_t0.elapsed().as_secs_f64();
                                        if target > actual {
                                            // Dedicated thread: a plain sleep
                                            // stalls only this decoder.
                                            std::thread::sleep(std::time::Duration::from_secs_f64(
                                                (target - actual).min(0.25),
                                            ));
                                        }
                                    }
                                    if slot.is_par2() {
                                        // Par2 main (or the sniffed in-stream
                                        // bootstrap): mirror the bytes in memory
                                        // for mid-download set activation. A
                                        // sniffed slot WITHOUT a capture is a
                                        // deferred volume - its stragglers are
                                        // recovery data, not payload, and stay
                                        // out of the verifier.
                                        //
                                        // `off` is the article's declared yEnc
                                        // `begin - 1`, clamped only to >= 1 -
                                        // never to the file size. Unlike the
                                        // extractor's disk path (a sparse
                                        // write_all_at at a huge offset costs no
                                        // RAM), this resize ZERO-FILLS real
                                        // memory, so one article declaring
                                        // begin=10^15 in a file whose name merely
                                        // contains ".par2" allocated a petabyte
                                        // and aborted the daemon. A main .par2
                                        // packet is small; cap the mirror well
                                        // above any real one and drop the rest -
                                        // an oversized "main" packet is not a
                                        // set we could have activated anyway.
                                        let mut cap = slot.capture.lock_ok();
                                        if let Some(buf) = cap.as_mut() {
                                            let off = dec.offset() as usize;
                                            let end = off.saturating_add(out.len());
                                            if end <= MAX_PAR2_CAPTURE {
                                                if buf.len() < end {
                                                    // Memory-floor gauge:
                                                    // capture growth.
                                                    nzbkit::memgauge::add(
                                                        nzbkit::memgauge::Sub::Par2Capture,
                                                        (end - buf.len()) as u64,
                                                    );
                                                    buf.resize(end, 0);
                                                }
                                                buf[off..end].copy_from_slice(&out);
                                            }
                                        }
                                    } else if crc_checked {
                                        verifier.on_data(
                                            sidx,
                                            &dec.name,
                                            dec.file_size,
                                            dec.offset(),
                                            &out,
                                        );
                                    } else {
                                        // CRC skipped (or absent): not
                                        // decoder-vouched. Full MD5
                                        // under delegation; CRC-only
                                        // under lean (its contract).
                                        verifier.on_data_unverified(
                                            sidx,
                                            &dec.name,
                                            dec.file_size,
                                            dec.offset(),
                                            &out,
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // TODO 114: a failed decode/CRC is exactly
                            // what the steer exists for - refetched
                            // elsewhere, it never becomes an error.
                            if crc_steer
                                && queue_ctl.note_decoded(
                                    &id,
                                    DecodeReport::Bad {
                                        why: "yEnc decode/CRC failed",
                                    },
                                ) == DecodeAck::Steered
                            {
                                out_pool.give(out);
                                pool.give(raw);
                                continue;
                            }
                            fetch_done.fetch_add(nbytes, Ordering::Relaxed);
                            warn!(target: "get", "decode error ({id}): {e}");
                            decode_error_sample
                                .lock_ok()
                                .get_or_insert_with(|| format!("decode error: {e}"));
                            decode_errors.fetch_add(1, Ordering::Relaxed);
                            slot.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    // TODO 121.4: the body is decoded and (where it
                    // was going to be) written - release the pool's
                    // liveness hold. Unconditional: under crc_steer an
                    // Owned verdict deliberately KEPT the done_ok entry
                    // (the write above can outlast the /stream
                    // dead-span verdict), so the release happens here,
                    // after the write. Steered paths continue'd above
                    // and never reach this line.
                    queue_ctl.note_settled(&id);
                    out_pool.give(out);
                    pool.give(raw);
                    if slot.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
                        if extractor.is_mapped(sidx) {
                            let shape = match extractor.archive_shape() {
                                Some(sh) if !shape_said.swap(true, Ordering::Relaxed) => {
                                    format!(" [{}]", sh.display())
                                }
                                _ => String::new(),
                            };
                            info!(target: "get", "✔ {} → extracting in-stream{shape}", slot.hint);
                        } else if extractor.is_chased(sidx) {
                            // A chased slot may own a file since
                            // drop-behind trimming - but it is a
                            // partial spill, not a finished download,
                            // and announcing it as one is a lie.
                            info!(target: "get", "✔ {} → extracting in-stream", slot.hint);
                        } else if let Some(p) = extractor.slot_path(sidx) {
                            info!(
                                target: "get",
                                "✔ {}",
                                p.file_name().unwrap_or_default().to_string_lossy()
                            );
                        }
                        par2.slot_drained(sidx);
                    }
                }
                FetchOutcome::Missing { id, cause } => {
                    // Sweep 8, M7: which SIDE lost this article. Taken
                    // here because here is the only place the slot is
                    // still in hand - see `CauseSplit`.
                    let rec = is_recovery_article(&id, &id_to_slot, &slots);
                    match cause {
                        nzbkit::pool::MissingCause::Retention => {
                            retention_excluded.add(rec);
                        }
                        nzbkit::pool::MissingCause::Gone { takedown } => {
                            missing_430.add(rec);
                            // The hint rides its own counter so the
                            // failure summary can say "removed", and
                            // stays inside missing_430 for everything
                            // else - a takedown is still a refusal.
                            if takedown {
                                takedown_430.add(rec);
                            }
                        }
                    }
                    par2.article_lost(&id, &id_to_slot, &fetch_done);
                }
                FetchOutcome::Failed { id, error } => {
                    transport_failed.add(is_recovery_article(&id, &id_to_slot, &slots));
                    transport_sample.lock_ok().get_or_insert(error);
                    par2.article_lost(&id, &id_to_slot, &fetch_done);
                }
            }
        }
    }
}

/// Memory-floor attribution sampler (250 ms): reads RSS + footprint and,
/// on a new sampled RSS high, stores a coincident snapshot of every
/// memgauge - the "where did the high-water go" record the job summary
/// prints. Two mach task_info calls per tick, microseconds each;
/// deliberately in-process so it cannot wake a sleeping cluster the way
/// an external ps poller does (the 21 Aug cpu_s observer effect).
/// Instrument-first: nothing reads the sample to make a decision.
///
/// Runs through post-processing too (repair and settle read-back can BE
/// the high-water), so it is stopped by token rather than by aborting a
/// held JoinHandle: the summary printer bumps the token when it is done
/// (tail.rs), and a daemon's next job simply spawns a fresh sampler.
///
/// The high-water record is the JOB's, not the process's: the sampler
/// writes into the `PeakRecord` this guard owns, so the next job's
/// spawn cannot wipe a predecessor's attribution while its tail is
/// still running (bug sweep 22 Aug 2026, F-19). The process-wide
/// reader (the daemon's instrument endpoint) is pointed at the newest
/// record here; the gauges themselves stay process-wide, because live
/// charges (a retained free list, a capture) carry across jobs.
///
/// The record is ALSO registered in memgauge's live registry under a
/// label, which is what lets the daemon's instrument endpoint report an
/// overlapping tail's job as well as the newest one; the registry entry
/// goes when this guard drops.
pub(super) fn spawn_mem_sampler(stream_owner: &str, nzb_path: &std::path::Path) -> MemSampler {
    let run = MEM_SAMPLER_RUN.fetch_add(1, Ordering::Relaxed) + 1;
    let record = Arc::new(nzbkit::memgauge::PeakRecord::new());
    nzbkit::memgauge::install_latest_peak_record(record.clone());
    nzbkit::memgauge::register_peak_record(
        run,
        &mem_sampler_label(stream_owner, nzb_path),
        &record,
    );
    let handle = {
        let record = record.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let trace = holds_trace_enabled();
            let mut n: u32 = 0;
            while MEM_SAMPLER_RUN.load(Ordering::Relaxed) == run {
                tick.tick().await;
                record.note_rss_sample();
                n = n.wrapping_add(1);
                if trace && n.is_multiple_of(2) {
                    log_holds_trace(run);
                }
            }
        })
    };
    MemSampler {
        run,
        record,
        handle,
    }
}

/// A live sampler, the generation token it was born with, and the peak
/// record it writes. The token is what [`stop_mem_sampler`] needs:
/// stopping by token rather than by an unconditional bump means a job's
/// stop cannot retire a LATER job's sampler (the daemon overlaps one
/// job's tail with the next's download). The record is what the job's
/// summary reads (tail.rs `print_mem_floor`).
pub(super) struct MemSampler {
    pub(super) run: u64,
    pub(super) record: Arc<nzbkit::memgauge::PeakRecord>,
    // Not #[expect]: the unit tests read the field, so the expectation is
    // unfulfilled under cfg(test).
    #[allow(dead_code)]
    pub(super) handle: tokio::task::JoinHandle<()>,
}

impl Drop for MemSampler {
    fn drop(&mut self) {
        // The guard's life IS the job's, tail included, so dropping it
        // is the one point every path reaches - including an early
        // error return that never prints a summary.
        nzbkit::memgauge::unregister_peak_record(self.run);
    }
}

/// How a job names itself in the memory-floor registry: the daemon's
/// nzo_id, which is what an API reader correlates against the queue,
/// falling back to the NZB's stem for a CLI run (which has no nzo_id and
/// no API reader either, but a named row beats a blank one in a log).
fn mem_sampler_label(stream_owner: &str, nzb_path: &std::path::Path) -> String {
    if !stream_owner.is_empty() {
        return stream_owner.to_string();
    }
    nzb_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "job".to_string())
}

/// `NZBFAST_HOLDS_TRACE` set: the sampler also prints the live
/// process-wide holds gauge at 2 Hz. Read once per process - a
/// `var_os` per tick would be cheap, but a cached bool is free.
fn holds_trace_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NZBFAST_HOLDS_TRACE").is_some())
}

/// One `[holds-trace]` sample: the live `Sub::Holds` gauge NOW, not at
/// any high-water. The bench rig maxes over these to get a true
/// holds-over-time high-water for a leg. The `[mem-floor] ... holds N
/// MB` line in the job summary is NOT that: it is the gauge at the
/// instant the sampled RSS high-water last moved, and under a clamped
/// budget that instant is chosen by allocator retention, not by live
/// bytes (23 Aug 2026: 1118-1152 MB reported against a reconstructed
/// ~1.25-1.35 GB true high-water on the bench box at 2400M). Two overlapping
/// jobs each print the same process-wide figure, tagged by their run
/// token; a max over the file is unaffected.
fn log_holds_trace(run: u64) {
    let g = nzbkit::memgauge::snapshot();
    let holds = g.cur_of(nzbkit::memgauge::Sub::Holds);
    info!(
        target: "holds-trace",
        "holds {} MB ({} B, sampler {})",
        holds / 1_000_000,
        holds,
        run
    );
}

/// Generation token for [`spawn_mem_sampler`]; bumping it retires every
/// live sampler (each loops only while the token still equals the value
/// it was born with).
pub(super) static MEM_SAMPLER_RUN: AtomicU64 = AtomicU64::new(0);

/// Retire the sampler born with `run` (called once the job summary has
/// printed). A no-op when a newer sampler has already taken the token:
/// that one belongs to the next job and must keep running.
pub(super) fn stop_mem_sampler(run: u64) {
    let _ = MEM_SAMPLER_RUN.compare_exchange(run, run + 1, Ordering::Relaxed, Ordering::Relaxed);
}

#[cfg(test)]
#[path = "workers_mem_sampler_tests.rs"]
mod mem_sampler_tests;

/// §282 item 3: the standing inputs the rate ticker needs to project
/// this run's damage forward, gathered once at spawn.
///
/// The projection itself is [`project_damage`]; everything here is
/// either fixed for the run (the NZB, the slot→file map, the recovery
/// blocks the post declares) or read live off the verifier.
pub(super) struct DamageWatch {
    pub(super) nzb: Arc<Nzb>,
    pub(super) slot_file: Vec<usize>,
    pub(super) verifier: Arc<nzbkit::live::LiveVerifier>,
    /// Recovery blocks the NZB's volume NAMES declare, summed over
    /// every volume - [`spec_ladder`]'s own count, which is what the
    /// post PROMISES rather than what has reached disk.
    pub(super) declared_blocks: usize,
}

/// What the run is on course to finish with. §282 item 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DamageProjection {
    /// Payload segments terminally resolved so far, and the plan's
    /// total - the fraction the projection is extrapolated from.
    pub(super) resolved: usize,
    pub(super) planned: usize,
    /// Blocks of the recovery set the damage so far already costs.
    pub(super) now: usize,
    /// Where that lands at the end of the run.
    pub(super) projected: usize,
    /// Recovery blocks the NZB declares, for the comparison.
    pub(super) declared: usize,
}

/// Share of the plan that must have resolved before extrapolating from
/// it means anything. Two terminal misses in the first hundred articles
/// of a 20,000-article post are not a rate.
const PROJECT_MIN_FRACTION: f64 = 0.05;

/// ...and the absolute floor under that, because a 5% sample of a small
/// post is a handful of articles.
const PROJECT_MIN_MISSES: usize = 8;

/// How far past the declared recovery a projection must land before it
/// is worth saying out loud.
///
/// The same 2x the §146 tail give-up prices its trade at, and it is
/// carrying the same uncertainty: `now` is a worst-case ceiling (each
/// slot's misses bounded by its own LARGEST declared segment, see
/// [`par_race_missing_blocks`]), the loss rate is a sample, and
/// `declared` is read off volume names rather than off packets.
///
/// It is also the calibration this item was explicitly warned about.
/// On the two §282 incident jobs a payload projection MUST NOT fire:
/// 0.79% and 0.21% loss against 255 declared recovery blocks project to
/// roughly 270 and 96 damaged blocks, and 270 against 255 is a job that
/// repairs comfortably in practice - it was the recovery set that was
/// fiction, not the payload, which is what item 4's yield gate is for.
/// At 2x neither fires, and that is the test of this number: a
/// projection that fired on those two jobs would be WRONG, not early.
const PROJECT_MARGIN: usize = 2;

/// §282 item 3: is this run on course to be unrepairable?
///
/// The same arithmetic `par_race_missing_blocks` and the tail give-up
/// already do at the END of a run, moved to the middle and made
/// predictive. At payload fraction `f = resolved / planned` the misses
/// so far cost `now` blocks, so the whole run lands near `now / f`,
/// plus whatever in-stream verification has already found bad. Compare
/// that against the recovery blocks the post declares.
///
/// `None` unless the sample is worth extrapolating from AND the answer
/// clears [`PROJECT_MARGIN`]. Held still here, out of the ticker, so
/// the calibration is something a test can drive rather than something
/// a log has to be read for.
pub(super) fn project_damage(
    resolved: usize,
    planned: usize,
    now: usize,
    live_bad: usize,
    declared: usize,
) -> Option<DamageProjection> {
    if planned == 0 || resolved == 0 || now == 0 {
        return None;
    }
    let f = resolved as f64 / planned as f64;
    if f < PROJECT_MIN_FRACTION || now < PROJECT_MIN_MISSES {
        return None;
    }
    // Saturating rather than wrapping: `now / f` on a 1-in-20 sample of
    // a huge post is a large number and the comparison below is the
    // only thing that reads it.
    let projected = ((now as f64 / f).ceil() as usize).saturating_add(live_bad);
    (projected >= declared.saturating_mul(PROJECT_MARGIN)).then_some(DamageProjection {
        resolved,
        planned,
        now,
        projected,
        declared,
    })
}

// Live rate ticker (2 s), driven by the consumer-side decoded counter.
// Missing-article churn shows too: a mostly-taken-down post decodes
// nothing while the pool grinds through 430s, and without the count
// that phase is indistinguishable from a hard stall (seen live on a
// 12k-segment post that flatlined at "0.0 MB/s" for minutes).
pub(super) fn spawn_rate_ticker(
    ticker_bytes: Arc<AtomicU64>,
    ticker_slots: Vec<Arc<FileSlot>>,
    // §282 item 3. The ticker is the home for the projection because it
    // is the one watcher every job gets: the speculative prefetch is
    // gated off whenever a quota is configured and never spawns on a
    // post with no volumes, and a post that cannot be repaired is
    // exactly as worth saying under a quota.
    watch: DamageWatch,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last = 0u64;
        // Said ONCE. The projection is monotone in practice, and an
        // operator who has been told the run is doomed does not need it
        // every two seconds for the next ten minutes.
        let mut doom_said = false;
        // Divide by the REAL elapsed time, and skip missed ticks. The
        // default interval behavior is Burst: a ticker starved of the
        // runtime for N seconds fires every missed tick back-to-back on
        // recovery, and the /2e6 math then printed one impossible rate
        // (the whole gap's bytes over "2 s") followed by a page of
        // 0.0 MB/s lines, all stamped the same microsecond (issue #38
        // saw 24 of them, 1236.4 MB/s on a 0.44 Gbps run). One honest
        // line per wakeup; a gap in the timestamps still shows the
        // starvation to anyone reading the log.
        let mut last_t = Instant::now();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = ticker_bytes.load(Ordering::Relaxed);
            let dt = last_t.elapsed().as_secs_f64().max(0.1);
            last_t = Instant::now();
            let missing: usize = ticker_slots
                .iter()
                .map(|s| s.missing.load(Ordering::Relaxed))
                .sum();
            let miss = if missing > 0 {
                format!("  ({missing} missing)")
            } else {
                String::new()
            };
            info!(
                target: "get",
                "{:>7.1} MB/s ({:.2} Gbps)  written {:.2} GB{miss}",
                (now - last) as f64 / dt / 1e6,
                (now - last) as f64 * 8.0 / dt / 1e9,
                now as f64 / 1e9
            );
            last = now;
            if !doom_said && let Some(p) = watch.project(&ticker_slots) {
                doom_said = true;
                warn!(
                    target: "repair",
                    "projection: {} terminal miss(es) at {:.0}% of the plan damage \
                     {} recovery block(s) and project to about {} by the end, against \
                     the {} block(s) this post declares - it is on course to be \
                     unrepairable from this source",
                    missing,
                    p.resolved as f64 / p.planned as f64 * 100.0,
                    p.now,
                    p.projected,
                    p.declared
                );
            }
        }
    })
}

impl DamageWatch {
    /// This tick's projection, or `None` while the run still looks
    /// survivable.
    ///
    /// `None` until the recovery set activates, which is where the
    /// block size comes from - a damage figure in blocks cannot be
    /// stated before then, and the `[par2] set live: ... block size N`
    /// line is the moment it can. Nothing is lost by waiting: on the
    /// §282 incident that line landed within seconds of the first
    /// article, and the counter it reads climbs for the whole run.
    fn project(&self, slots: &[Arc<FileSlot>]) -> Option<DamageProjection> {
        let set = self.verifier.set()?;
        let block = set.block_size.max(1) as usize;
        // PAYLOAD only, both halves of the fraction. A recovery volume
        // is deferred rather than downloaded on the normal route, so
        // its segments are neither progress nor damage - and a sample
        // the user asked to skip was never queued at all.
        let (mut resolved, mut planned) = (0usize, 0usize);
        for s in slots.iter().filter(|s| !s.is_par2() && !s.sample_skipped) {
            planned += s.total_segments;
            resolved += s
                .total_segments
                .saturating_sub(s.remaining.load(Ordering::Relaxed));
        }
        let now = par_race_missing_blocks(block, slots, &self.slot_file, &self.nzb);
        let (_, live_bad) = self.verifier.live_counts();
        project_damage(
            resolved,
            planned,
            now,
            live_bad as usize,
            self.declared_blocks,
        )
    }
}

/// A storage-exhaustion write error halts the fetch. Classifies
/// via [`nzbkit::disk::storage_exhausted`] (kind-first, raw codes
/// platform-gated - 112 is ERROR_DISK_FULL only on Windows); on the
/// FIRST detection it records the verbatim sample for the job verdict
/// and aborts the pool so the line stops promptly. Returns whether this
/// call was that first detection (callers log the halt once). Later
/// detections - other decode threads racing through in-flight bodies -
/// keep the first sample and re-assert the abort harmlessly.
pub(super) fn note_storage_exhausted_halt(
    e: &std::io::Error,
    name: &str,
    disk_full_sample: &Arc<std::sync::Mutex<Option<String>>>,
    queue_ctl: &nzbkit::pool::QueueControl,
) -> bool {
    if !nzbkit::disk::storage_exhausted(e) {
        return false;
    }
    let first = {
        let mut s = disk_full_sample.lock_ok();
        let was_empty = s.is_none();
        s.get_or_insert_with(|| format!("write {name}: {e}"));
        was_empty
    };
    queue_ctl.abort();
    first
}

// Deadlock watchdog. A pool bug that leaves an article non-terminal
// wedges the whole job AFTER its bytes are downloaded: fetch_all_multi
// never returns, silently, until something external kills it (seen on
// a 190 GB low-memory run - 3 h frozen, download complete, no output).
// Pausing aborts the transfer rather than freezing it, so a job that
// is neither decoding NOR resolving articles, with segments still
// outstanding, is unambiguously the deadlock. When that holds, dump
// the pool state and abort: the stuck slot's blocks then fall into
// PAR2 repair (usually recovered) or fail loud, and the journal makes
// either outcome resume cleanly.
//
// BOTH signals, because decoded bytes alone do not mean "alive". An
// article that goes terminally Missing decodes nothing, and a post
// that is wholly gone decodes NOTHING AT ALL, for however long it
// takes to ask every server for every article - so a dead post is
// byte-frozen by definition while the pool works through its queue
// perfectly. Watching bytes alone, the watchdog aborted exactly that
// (31 Jul, live: a 30-day-old dead post killed mid-ladder, then
// reported as a fault on the user's own machine with most of its
// articles never requested). `remaining` counts down on Hit, Missing
// AND Failed, so it moves whenever the pool resolves anything by any
// route: it is the liveness signal a refusal-only run still has. A
// genuine wedge freezes both, and still fires.
//
// THIRD signal, `QueueControl::deferred`, because "resolves anything by
// any route" stopped covering the pool: it now has paths that consume a
// response and requeue the article for a confirming repeat rather than
// declaring it (the bare-430 desync guard). A wholly dead post takes
// that path for EVERY article before any of them can go terminal, so
// its whole first pass moves neither counter above and 31 Jul's abort
// came straight back. A future defer-a-verdict path ticks that same
// counter instead of growing a fourth signal here.
pub(super) fn spawn_deadlock_watchdog(
    decoded: Arc<AtomicU64>,
    slots: Vec<Arc<FileSlot>>,
    qc: Arc<nzbkit::pool::QueueControl>,
    abort_flag: Arc<std::sync::atomic::AtomicBool>,
    stalled: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let secs: u64 = std::env::var("NZBFAST_STALL_ABORT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(180);
    // Poll several times per stall window (bounded 1..=15 s) so a short
    // override fires promptly in tests and production stays low-churn.
    let poll = (secs / 4).clamp(1, 15);
    tokio::spawn(async move {
        let outstanding_now = |sl: &[Arc<FileSlot>]| -> usize {
            sl.iter().map(|s| s.remaining.load(Ordering::Relaxed)).sum()
        };
        let mut last = decoded.load(Ordering::Relaxed);
        let mut last_outstanding = outstanding_now(&slots);
        let mut last_deferred = qc.deferred().unwrap_or(0);
        let mut frozen = 0u64;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(poll)).await;
            if abort_flag.load(Ordering::Relaxed) {
                return;
            }
            let now = decoded.load(Ordering::Relaxed);
            let outstanding = outstanding_now(&slots);
            let deferred = qc.deferred().unwrap_or(last_deferred);
            if now != last || outstanding != last_outstanding || deferred != last_deferred {
                last = now;
                last_outstanding = outstanding;
                last_deferred = deferred;
                frozen = 0;
                continue;
            }
            frozen += poll;
            if frozen >= secs && outstanding > 0 {
                warn!(
                    target: "stall",
                    "download stalled: no decode progress AND no article \
                     resolved for {frozen}s with {outstanding} segment(s) still \
                     outstanding - the connection pool has wedged. Dumping state \
                     and aborting; the journal keeps what landed, PAR2 fills any \
                     gap, and a retry resumes."
                );
                qc.dump_state();
                stalled.store(true, Ordering::Relaxed);
                qc.abort();
                return;
            }
        }
    })
}

// M2c.5 speculative recovery prefetch: the moment ANY article goes
// terminally Missing/Failed, damage is certain - fetch the smallest
// recovery volume on a tiny side pool (1 conn/server; the main pool
// owns the provider grants) so the post-settle exact-fit pass starts
// with recovery blocks already on disk. The daemon gates this via
// hub.spec_prefetch (off when a quota is configured - mirrors the
// sidecar-prefetch guard); CLI runs opt out with
// NZBFAST_NO_SPEC_PREFETCH=1. Risk is bounded to one small volume of
// possibly-wasted bytes. Skipped when the set bootstraps from a
// volume (one is already inbound) or the NZB ships no volumes.
#[expect(clippy::too_many_arguments)]
pub(super) fn spawn_spec_prefetch(
    allowed: bool,
    has_main: bool,
    nzb: &Arc<Nzb>,
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    slots: &[Arc<FileSlot>],
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
    // §146: the tail give-up's standing order, in recovery SLICES - the
    // 2x ceiling it needs on hand before it may abandon the walkers.
    // Terminal missing is a TRAILING indicator paced by the very ladder
    // the give-up exists to skip, so escalating on it alone always
    // arrives too late; walkers at queue-dry are refused-somewhere
    // articles on an idle wire, and covering them is the same certain-
    // damage bet one rung earlier.
    tail_demand: &Arc<std::sync::atomic::AtomicUsize>,
) -> Option<tokio::task::JoinHandle<()>> {
    let target = (allowed && has_main)
        .then(|| {
            nzb.files
                .iter()
                .enumerate()
                .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
                .min_by_key(|(_, f)| f.bytes())
                .map(|(fi, f)| (fi, f.bytes()))
        })
        .flatten();
    target.map(|_| {
        // Smallest-first ladder of every recovery volume: (fi,
        // declared/estimated slice count, bytes). The watcher escalates
        // one rung at a time while the missing count outruns the blocks
        // already prefetched - missing articles are CERTAIN damage,
        // so cover for the observed count is never wasted bytes.
        //
        // C5: the ladder retains ONLY these three words per volume. A
        // rung's `ArticleReq`s and id map are built by `volume_reqs`
        // at rung selection, from the `Arc<Nzb>` the task holds - the
        // eager form retained ~166 bytes per recovery segment (4.1 MB
        // measured at 25k recovery segments, `c5_spec_ladder_rss_at_
        // field_scale`) for the whole run, and a healthy run read none
        // of it. Healthy runs now build zero recovery requests.
        let ladder = spec_ladder(nzb);
        let nzb2 = Arc::clone(nzb);
        let side_servers = side_pool_servers(servers);
        // §146: the fleet a DEMAND rung runs on. The 1-conn side pool
        // exists so a prefetch never provokes a provider's connection
        // cap while the main fleet holds this account's grants - but a
        // demand rung only fires at queue-dry, when the main fleet is
        // holding those grants IDLE over nothing but refusal walkers.
        // Borrowing up to 8 connections per server (never above the
        // user's own configured budget) fetches hundreds of MB of
        // recovery data in the seconds the give-up needs, instead of
        // trickling it through one connection per server while the
        // ladder it exists to retire walks to completion first. An
        // account genuinely at its cap refuses the extra dials and the
        // capacity machinery parks them - degrading to the old pace,
        // not failing.
        let tail_servers: Vec<(ServerConfig, nzbkit::pool::PoolConfig)> = side_servers
            .iter()
            .map(|(sc, pc)| {
                let mut sc = sc.clone();
                let mut pc = pc.clone();
                let width = servers
                    .iter()
                    .find(|(s, _)| s.host == sc.host && s.port == sc.port)
                    .map(|(s, _)| s.connections.clamp(1, 8))
                    .unwrap_or(1);
                sc.connections = width;
                pc.connections = width as usize;
                (sc, pc)
            })
            .collect();
        let slots2 = slots.to_vec();
        let out2 = out_dir.to_path_buf();
        let bp = buf_pool.clone();
        let vol_cap = volume_prealloc_cap(nzb);
        let pre = prefetched.clone();
        let stop = prefetch_stop.clone();
        let demand = tail_demand.clone();
        tokio::spawn(async move {
            // Codex 5 Aug M3: a rung used to run with no cancellation
            // handle, so a blackholed side provider held drain_network's
            // unconditional await - and with it Cancel/Pause - through
            // the side pool's whole multi-session retry ladder. The
            // latch-plus-re-abort watcher that fixed it now lives in
            // `SideCancel`, inside the one driver every side-fetch goes
            // through (§129 residue 2 needed the same wire for the
            // lane's repair fetches). `over` shares THIS ladder's own
            // stop flag, so the loop below still reads it directly and
            // there is only ever one latch.
            let cancel = crate::repair::SideCancel::over(stop.clone());
            let body = async {
            let mut covered = 0usize;
            let mut ladder = ladder;
            loop {
                if stop.load(Ordering::Acquire) {
                    return; // network phase over - settle takes it from here
                }
                let miss: usize =
                    slots2.iter().map(|s| s.missing.load(Ordering::Relaxed)).sum();
                // The give-up's standing order outranks the terminal
                // count when it is larger - see the parameter doc.
                let want = miss.max(demand.load(Ordering::Acquire));
                if want > covered {
                    let deficit = want - covered;
                    if ladder.is_empty() {
                        return; // every volume already prefetched
                    }
                    let at = pick_rung(&ladder, deficit);
                    let (fi, count, bytes) = ladder.remove(at);
                    // C5: this rung's requests are born here, at
                    // selection - microseconds against a 250 ms poll,
                    // so the loss-to-first-recovery-BODY latency is
                    // unchanged.
                    let mut reqs = Vec::new();
                    let mut idm = std::collections::HashMap::new();
                    crate::repair::volume_reqs(&nzb2, fi, &mut reqs, &mut idm);
                    if want > miss {
                        info!(
                            target: "repair",
                            "{miss} article(s) terminally missing and {want} recovery \
                             block(s) wanted to retire the refusal ladder - prefetching \
                             recovery volume ({:.1} MB)",
                            bytes as f64 / 1e6
                        );
                    } else {
                        info!(
                            target: "repair",
                            "{miss} article(s) terminally missing - prefetching recovery volume ({:.1} MB) alongside the download",
                            bytes as f64 / 1e6
                        );
                    }
                    // A demand rung rides the borrowed-width fleet; an
                    // ordinary terminal-missing rung keeps the polite
                    // 1-conn side pool.
                    let fleet = if want > miss {
                        &tail_servers
                    } else {
                        &side_servers
                    };
                    let fetched = fetch_volume_articles(
                        fleet,
                        reqs,
                        idm,
                        &out2,
                        &bp,
                        vol_cap,
                        Some(&cancel),
                    )
                    .await;
                    if stop.load(Ordering::Acquire) {
                        // The handle aborted this rung mid-flight. An
                        // aborted run's unresolved articles emit NO
                        // outcome, so the failure count can read 0 over
                        // a volume that is actually incomplete - credit
                        // or record it and the whole volume is struck
                        // off the post-settle fetch list with slices
                        // missing (the H2 false-shortfall shape). Leave
                        // the rung unrecorded; unrecorded is always
                        // safe, the post-settle ladder refetches it.
                        return;
                    }
                    match fetched {
                        // One rung is one volume, so the fetch-wide
                        // total and this file's own count are the same
                        // number here - `total()` reads it without
                        // threading the rung's file index in.
                        Ok((f, paths)) if f.total() == 0 && !paths.is_empty() => {
                            covered += count.max(1);
                            pre.lock_ok().push((fi, paths));
                        }
                        Ok((f, paths)) if !paths.is_empty() => {
                            let failures = f.total();
                            // A PARTIAL volume: some articles failed.
                            // Recording its file index would strike the
                            // WHOLE volume off the post-settle fetch
                            // list while its missing slices can never
                            // be refetched - a repairable job then
                            // reports a false shortfall. Leave it
                            // unrecorded and uncredited: the next rung
                            // runs now, and the post-settle ladder can
                            // still fetch this volume in full.
                            info!(
                                target: "repair",
                                "that volume landed partially ({failures} article \
                                 failure(s)) - leaving it fetchable and trying the next rung"
                            );
                        }
                        Ok(_) => {
                            // Not one byte of that volume landed (every
                            // article failed, or it was unwritable).
                            // Claiming its blocks as covered would stall
                            // escalation, and recording the file index
                            // would strike it off the post-settle fetch
                            // list - so do neither and try the next rung.
                            info!(
                                target: "repair",
                                "that volume produced no file - trying the next one"
                            );
                        }
                        Err(e) => {
                            info!(
                                target: "repair",
                                "speculative prefetch failed ({e}) - the post-settle fetch covers it"
                            );
                            return;
                        }
                    }
                    continue; // re-check immediately - miss may have grown
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            };
            body.await;
        })
    })
}

/// The speculative ladder's retained form (C5): one `(file index,
/// declared/estimated slice count, encoded bytes)` triple per recovery
/// volume, smallest first. Requests and the id map are built at rung
/// selection by [`crate::repair::volume_reqs`], never here.
pub(super) fn spec_ladder(nzb: &Nzb) -> Vec<(usize, usize, u64)> {
    let mut ladder: Vec<(usize, usize, u64)> = nzb
        .files
        .iter()
        .enumerate()
        .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
        .map(|(fi, f)| {
            let name = f.filename_hint().unwrap_or(&f.subject);
            // Conservative when the name doesn't declare a count:
            // claim 1 so escalation keeps going rather than stopping
            // on an inflated estimate.
            (fi, vol_count_from_name(name).unwrap_or(1), f.bytes())
        })
        .collect();
    ladder.sort_by_key(|&(_, _, bytes)| bytes);
    ladder
}

/// Exact-fit rung: the smallest unfetched volume covering the whole
/// deficit, else the biggest left - the pure smallest-first ladder
/// over-fetched ~2x once the damage count ran ahead of the rungs.
/// `ladder` is non-empty and sorted smallest-first ([`spec_ladder`]).
pub(super) fn pick_rung(ladder: &[(usize, usize, u64)], deficit: usize) -> usize {
    ladder
        .iter()
        .position(|&(_, count, _)| count >= deficit)
        .unwrap_or(ladder.len() - 1)
}

/// Par-race candidate selection and damage arithmetic (Codex 5 Aug
/// M2), held still where a test can reach it.
pub(super) struct RaceEstimate {
    /// Cancellable ids: only articles of payload files the recovery
    /// set COVERS - repair heals nothing else, so abandoning an
    /// uncovered companion converts a fetchable file into permanent
    /// damage settle then rightly rejects.
    pub(super) want: std::collections::HashSet<Arc<str>>,
    /// id → (slot index, declared segment bytes).
    pub(super) bytes_of: std::collections::HashMap<Arc<str>, (usize, u64)>,
    /// EXPECTED remaining bytes (per-file average) - the eta
    /// estimator, where under-racing is the conservative direction.
    pub(super) out_bytes: u64,
    /// WORST-CASE damage blocks: which `remaining` segments are still
    /// unresolved is the pool's knowledge, not ours, so charge each
    /// file its `remaining` LARGEST declared segments at their exact
    /// bytes. The old per-file average let one 100 MiB straggler hide
    /// behind 99 tiny finished segments.
    pub(super) out_blocks: usize,
}

pub(super) fn par_race_estimate(
    set_names: &std::collections::HashSet<String>,
    block: usize,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
) -> RaceEstimate {
    let mut est = RaceEstimate {
        want: std::collections::HashSet::new(),
        bytes_of: std::collections::HashMap::new(),
        out_bytes: 0,
        out_blocks: 0,
    };
    for (sidx, s) in slots.iter().enumerate() {
        let rem = s.remaining.load(Ordering::Relaxed);
        if s.is_par2() || rem == 0 {
            continue;
        }
        // Same name normalization settle itself uses; an obfuscated
        // alias not yet reconciled simply stays out of the race.
        if !set_names.contains(&nzbkit::disk::sanitize_filename(&s.hint).to_lowercase()) {
            continue;
        }
        let f = &nzb.files[slot_file[sidx]];
        let per = (f.bytes() / f.segments.len().max(1) as u64).max(1);
        est.out_bytes += rem as u64 * per;
        let mut sizes: Vec<u64> = f.segments.iter().map(|seg| seg.bytes).collect();
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        est.out_blocks += sizes
            .iter()
            .take(rem)
            .map(|b| (*b as usize).div_ceil(block) + 1)
            .sum::<usize>();
        for seg in &f.segments {
            // R9: interned here rather than looked up in `id_to_slot`.
            // This census only runs in the tail-stall state (every
            // pending article a refusal-walker) or under the dark
            // par-race flag, so it is not one of the paths the
            // interning was measured on, and reaching the plan's map
            // would mean threading it through four spawn signatures for
            // no steady-state gain. The allocation count is exactly
            // what it was; the handles it hands out are shared from
            // here on.
            let b: Arc<str> = format!("<{}>", seg.message_id).into();
            est.bytes_of.insert(b.clone(), (sidx, seg.bytes));
            est.want.insert(b);
        }
    }
    est
}

/// Worst-case block cost of the articles already terminally missing.
/// WHICH articles went missing is unknown, so bound each slot's share
/// by its own largest declared segment rather than a cross-file
/// average that a big-article file dilutes (Codex 5 Aug M2).
pub(super) fn par_race_missing_blocks(
    block: usize,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    nzb: &Nzb,
) -> usize {
    slots
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.is_par2())
        .map(|(sidx, s)| {
            let m = s.missing.load(Ordering::Relaxed);
            if m == 0 {
                return 0;
            }
            let max_per = nzb.files[slot_file[sidx]]
                .segments
                .iter()
                .map(|seg| seg.bytes)
                .max()
                .unwrap_or(0) as usize;
            m * (max_per.div_ceil(block) + 1)
        })
        .sum()
}

// PAR2-race experiment (dark, NZBFAST_PAR_RACE=1): once the set is
// active, if the recovery blocks already on hand cover the WORST
// CASE of every still-queued payload article being abandoned - with
// 2x margin - and the line is slow enough that the remainder is
// >30 s away, cancel the queued stragglers and let repair finish
// the job: the math beats the network. Conservative on every axis:
// on-hand is the activation count plus prefetched volumes counted
// off disk; per-article damage is the whole-block ceiling plus one
// (the block its edges straddle); in-flight articles are untouched
// (`cancel` only removes QUEUED work) and resolve normally. The
// articles removed get no pool outcome, so this owns the accounting
// exactly as a sniff deferral does: remaining down, abandoned up,
// fetch_done credited. Settle needs no new damage arithmetic - the
// final read-back finds the absent blocks and the repair self-proves
// by re-reading the whole set (the invariant this leans on).
// Fires at most once per run.
#[expect(clippy::too_many_arguments)]
pub(super) fn spawn_par_race(
    slots: &[Arc<FileSlot>],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    fetch_done: &Arc<AtomicU64>,
    decoded_bytes: &Arc<AtomicU64>,
    slot_file: &[usize],
    nzb: &Arc<Nzb>,
) -> Option<tokio::task::JoinHandle<()>> {
    std::env::var("NZBFAST_PAR_RACE")
        .is_ok_and(|v| v == "1")
        .then(|| {
            let slots2 = slots.to_vec();
            let verifier2 = verifier.clone();
            let queue_ctl2 = queue_ctl.clone();
            let stop = prefetch_stop.clone();
            let pre = prefetched.clone();
            let fetch_done2 = fetch_done.clone();
            let bytes_now = decoded_bytes.clone();
            let slot_file2 = slot_file.to_vec();
            let nzb2 = nzb.clone();
            tokio::spawn(async move {
                use std::collections::{HashSet, VecDeque};
                let mut win: VecDeque<(std::time::Instant, u64)> = VecDeque::new();
                loop {
                    if stop.load(Ordering::Acquire) {
                        return; // network phase over - settle owns it now
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let Some(set) = verifier2.set() else { continue };
                    // Rolling 10 s decode-rate window.
                    let now = std::time::Instant::now();
                    win.push_back((now, bytes_now.load(Ordering::Relaxed)));
                    while win
                        .front()
                        .is_some_and(|(t, _)| now.duration_since(*t).as_secs() > 10)
                    {
                        win.pop_front();
                    }
                    let (Some(&(t0, b0)), Some(&(t1, b1))) = (win.front(), win.back()) else {
                        continue;
                    };
                    let span = t1.duration_since(t0).as_secs_f64();
                    if span < 8.0 {
                        continue;
                    }
                    let rate = b1.saturating_sub(b0) as f64 / span;
                    // Candidates + damage arithmetic live in
                    // par_race_estimate / par_race_missing_blocks (the
                    // Codex 5 Aug M2 fixes), where tests can hold them
                    // still.
                    let set_names: HashSet<String> = set
                        .files
                        .iter()
                        .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
                        .collect();
                    let block = set.block_size.max(1) as usize;
                    let est = par_race_estimate(&set_names, block, &slots2, &slot_file2, &nzb2);
                    let (want, bytes_of) = (est.want, est.bytes_of);
                    let (out_bytes, out_blocks) = (est.out_bytes, est.out_blocks);
                    if want.is_empty() {
                        continue;
                    }
                    // The line must be slow enough that repair clearly
                    // wins; a healthy line finishes the remainder before
                    // any repair could start its verify pass.
                    let eta = if rate > 0.0 {
                        out_bytes as f64 / rate
                    } else {
                        f64::INFINITY
                    };
                    if eta < 30.0 {
                        continue;
                    }
                    // Damage ceiling if every unresolved article is lost:
                    // the queued ones we would cancel plus the already
                    // bad or terminally missing.
                    let (_, live_bad) = verifier2.live_counts();
                    let missing_blocks =
                        par_race_missing_blocks(block, &slots2, &slot_file2, &nzb2);
                    let damage_ceiling = out_blocks + live_bad as usize + missing_blocks;
                    let mut on_hand = set.recovery_blocks_seen;
                    for (_, paths) in pre.lock_ok().iter() {
                        for p in paths {
                            if let Ok(bytes) = std::fs::read(p) {
                                on_hand += nzbkit::par2repair::recovery_slice_locators(
                                    &bytes,
                                    &set.recovery_set_id,
                                )
                                .into_iter()
                                .filter(|(_, _, len)| *len == block)
                                .count();
                            }
                        }
                    }
                    if on_hand < damage_ceiling.saturating_mul(2) {
                        continue;
                    }
                    // Race. Cancel is best-effort under queue contention
                    // (bounded try_lock) - same retry shape as the sniff
                    // deferral.
                    let mut removed = Vec::new();
                    for attempt in 0..3 {
                        removed = queue_ctl2.cancel(&want);
                        if !removed.is_empty() {
                            break;
                        }
                        if attempt < 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                        }
                    }
                    if removed.is_empty() {
                        continue; // everything already in flight or done
                    }
                    // The cancel is the first moment the EXACT straggler
                    // set is known - re-run the 2x guard on it with the
                    // ids' declared bytes and a fresh live_bad (damage
                    // can grow in the second between estimate and
                    // cancel). The worst-case estimate above makes a
                    // failure here rare, not impossible.
                    let exact_blocks: usize = removed
                        .iter()
                        .filter_map(|id| bytes_of.get(&**id))
                        .map(|&(_, b)| (b as usize).div_ceil(block) + 1)
                        .sum();
                    let (_, live_bad_now) = verifier2.live_counts();
                    let exact_ceiling = exact_blocks + live_bad_now as usize + missing_blocks;
                    if on_hand < exact_ceiling.saturating_mul(2) {
                        if queue_ctl2.requeue(&removed) > 0 {
                            continue; // rolled back whole - no race this tick
                        }
                        // requeue's all-or-nothing rollback found the run
                        // already winding down, so the cancel is now
                        // irreversible. Fall through to the abandonment
                        // accounting so the bar stays truthful - settle
                        // prices the damage honestly either way.
                        warn!(
                            target: "repair",
                            "par-race: exact damage outgrew the estimate and the rollback \
                             found the run winding down - proceeding with {} abandoned \
                             article(s)",
                            removed.len()
                        );
                    }
                    let mut freed = 0u64;
                    for id in &removed {
                        if let Some(&(sidx, b)) = bytes_of.get(&**id) {
                            slots2[sidx].remaining.fetch_sub(1, Ordering::AcqRel);
                            slots2[sidx].abandoned.fetch_add(1, Ordering::Relaxed);
                            freed += b;
                        }
                    }
                    // No outcome will ever arrive for these - settle the
                    // bar here, exactly like a sniff deferral.
                    fetch_done2.fetch_add(freed, Ordering::Relaxed);
                    info!(
                        target: "repair",
                        "par-race: abandoned {} queued straggler article(s) ({:.1} MB) - \
                         {on_hand} recovery blocks on hand cover the {damage_ceiling}-block \
                         worst case at 2x, and repair beats the ~{eta:.0}s fetch remainder",
                        removed.len(),
                        freed as f64 / 1e6,
                    );
                    return;
                }
            })
        })
}

/// §146 tail give-up, the decision half - held still where a test can
/// reach it. `true` when EVERY walker article belongs to a file the
/// active recovery set covers AND the recovery blocks on hand cover the
/// exact walker set - plus the damage already priced in - at 2x. One
/// uncovered walker vetoes the whole trade: repair rebuilds nothing
/// outside its own set, so abandoning that article would convert a
/// fetchable file into permanent damage.
pub(super) fn tail_giveup_covered(
    walkers: &[nzbkit::pool::Walker],
    est: &RaceEstimate,
    block: usize,
    live_bad: usize,
    missing_blocks: usize,
    on_hand: usize,
) -> bool {
    let mut exact_blocks = 0usize;
    for w in walkers {
        let Some(&(_, b)) = est.bytes_of.get(&*w.id) else {
            return false; // a walker repair cannot rebuild - keep walking
        };
        exact_blocks += (b as usize).div_ceil(block) + 1;
    }
    let ceiling = exact_blocks + live_bad + missing_blocks;
    on_hand >= ceiling.saturating_mul(2)
}

/// §146 tail give-up: recovery slices already decoded into the job dir
/// by the MAIN pool (volumes that were never deferred, so the side
/// prefetch never saw them). Walks `.par2` files up to three levels
/// deep, skips paths the caller already counted, and re-reads a file
/// only when its length has moved since the cached count - a damaged
/// volume's holes simply truncate the packet scan, which undercounts,
/// and undercounting is the safe direction for a 2x margin.
fn disk_recovery_blocks(
    dir: &Path,
    set_id: &[u8; 16],
    block: usize,
    skip: &std::collections::HashSet<PathBuf>,
    cache: &mut std::collections::HashMap<PathBuf, (u64, std::time::SystemTime, usize)>,
) -> usize {
    fn walk(dir: &Path, depth: u8, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                if depth > 0 {
                    walk(&p, depth - 1, out);
                }
            } else if p
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
            {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, 3, &mut files);
    let mut total = 0usize;
    for p in files {
        if skip.contains(&p) {
            continue;
        }
        total += cached_recovery_blocks(&p, set_id, block, cache);
    }
    total
}

/// A file is only trusted into the census cache once it has been QUIET
/// this long. Volume writers preallocate (`set_len`) at creation, so a
/// mid-write file already reports its final length and the length can
/// never invalidate an entry; the file's mtime is what still moves while
/// articles land. Two seconds also rides out coarse-mtime filesystems
/// (FAT stamps at 2 s), where a scan and a later write can share one
/// visible timestamp.
const CENSUS_QUIET: std::time::Duration = std::time::Duration::from_secs(2);

/// Slices of `set_id` at `block` bytes inside one `.par2` file, counted
/// at most once per (length, mtime) the file has held - and only
/// remembered at all once the file has been quiet for [`CENSUS_QUIET`].
///
/// Both census roads share it - the prefetched list and the job-dir walk
/// - so a tick over settled volumes costs a `stat` each rather than
/// re-reading and re-scanning every recovery volume on disk, which is
/// what the 200 ms tail-stall tick was doing for as long as the stall
/// lasted.
///
/// The quiet gate is the R1 lesson (20 Aug 2026), and it took two rounds
/// to learn. Recovery volumes are preallocated to their FULL length at
/// the first article, so "a length that moves invalidates the entry"
/// never held for them: a scan taken while the side-fetch was still
/// writing counted only the slices that had landed (17 of 128 on one
/// traced leg, 6 on another) and that undercount was served for the rest
/// of the job - the 2x margin never cleared, the tail give-up never
/// fired, and damaged posts walked the refusal ladder 32-68% slower with
/// FLAT cpu. The first fix refused to cache only a ZERO scan, and R1
/// step 3 falsified it: a nonzero mid-write undercount is poisoned all
/// the same. What actually separates a scan worth remembering from one
/// that is not is whether the writer might still be active, and mtime is
/// the signal for that: a busy file's scan is returned but never cached
/// (base's re-read-every-tick behavior, self-healing), a quiet file's
/// scan - zero included, the index par2 genuinely has no slices - is
/// cached and costs a stat from then on.
fn cached_recovery_blocks(
    p: &Path,
    set_id: &[u8; 16],
    block: usize,
    cache: &mut std::collections::HashMap<PathBuf, (u64, std::time::SystemTime, usize)>,
) -> usize {
    let Ok(meta) = std::fs::metadata(p) else {
        return 0;
    };
    let len = meta.len();
    let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    if let Some(&(l, t, n)) = cache.get(p)
        && l == len
        && t == mtime
    {
        return n;
    }
    let Ok(bytes) = std::fs::read(p) else {
        return 0;
    };
    let n = nzbkit::par2repair::recovery_slice_locators(&bytes, set_id)
        .into_iter()
        .filter(|(_, _, l)| *l == block)
        .count();
    // An unreadable mtime lands on UNIX_EPOCH, which reads as ancient -
    // deliberately: a filesystem that cannot report mtime cannot feed
    // the quiet gate, and permanent re-reads there would resurrect the
    // cost A5 removed.
    if mtime.elapsed().is_ok_and(|e| e >= CENSUS_QUIET) {
        cache.insert(p.to_path_buf(), (len, mtime, n));
    }
    n
}

// §146 tail give-up (default ON, kill switch NZBFAST_NO_TAIL_GIVEUP=1):
// the zero-throughput tail in front of repair on a damaged post is 60
// articles serially buying "no such article" verdicts from every
// backbone - measured 13-15 s on a real five-provider fleet, FLAT
// across a 10x connection sweep, while the recovery volumes sat
// prefetched and repair itself cost 2.2 s. Those verdicts buy nothing:
// when the recovery blocks on hand already cover every still-walking
// article, repair rebuilds their bytes EXACTLY whether the ladder ends
// in Missing or in a fifth backbone's surprise copy. So the moment the
// pool reports that nothing but 430-walkers remain (verdict_walkers -
// which is also what keeps this OFF the corrupt-body damage class:
// those refetches carry tried_fail, never tried_430) and the coverage
// maths holds at 2x, give the walkers up and let settle start repair
// NOW. Same accounting contract as the par-race above: no outcome ever
// arrives for a given-up article, so the bar is settled here, and the
// repair self-proves by re-reading the whole set. Loops rather than
// firing once - an article that slipped one census (mid-requeue
// between two locks) is caught by the next tick.
pub(super) fn spawn_tail_giveup(
    slots: &[Arc<FileSlot>],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    fetch_done: &Arc<AtomicU64>,
    slot_file: &[usize],
    nzb: &Arc<Nzb>,
    out_dir: &Path,
    // The standing order to the spec prefetch (see its parameter doc):
    // set to the 2x block ceiling whenever the census is open but the
    // margin is short, so the prefetch fetches toward exactly the
    // coverage that lets the give-up fire.
    tail_demand: &Arc<std::sync::atomic::AtomicUsize>,
) -> Option<tokio::task::JoinHandle<()>> {
    if std::env::var_os("NZBFAST_NO_TAIL_GIVEUP").is_some() {
        return None;
    }
    let slots2 = slots.to_vec();
    let verifier2 = verifier.clone();
    let queue_ctl2 = queue_ctl.clone();
    let stop = prefetch_stop.clone();
    let pre = prefetched.clone();
    let fetch_done2 = fetch_done.clone();
    let slot_file2 = slot_file.to_vec();
    let nzb2 = nzb.clone();
    let dir = out_dir.to_path_buf();
    let demand = tail_demand.clone();
    Some(tokio::spawn(async move {
        use std::collections::{HashMap, HashSet};
        // Recovery volumes reach disk by TWO roads and the on-hand
        // census must count both: the M2c.5 side prefetch (the
        // `prefetched` list), and the main pool fetching them INLINE -
        // which is what happens whenever damage shows up early enough
        // that the volumes are never deferred. `recovery_blocks_seen`
        // is frozen at activation (usually the index alone: 0 slices),
        // so without the disk walk the gate read "0 on hand" against a
        // job whose volumes were all sitting decoded in the out dir.
        // Cached by (path -> len, mtime, count), quiet files only - see
        // cached_recovery_blocks. Steady-state ticks cost one readdir.
        let mut disk_cache: HashMap<PathBuf, (u64, std::time::SystemTime, usize)> = HashMap::new();
        let mut cache_key: Option<([u8; 16], usize)> = None;
        // Why the ladder is still being walked, said ONCE per run: a
        // veto here is deliberate (uncovered walker, thin margin), and
        // an operator watching a zero-throughput tail deserves the
        // numbers behind it rather than silence.
        let mut veto_said = false;
        loop {
            if stop.load(Ordering::Acquire) {
                return; // network phase over - settle owns it now
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let Some(set) = verifier2.set() else { continue };
            // The census gates everything: Some only when EVERY pending
            // article is a refusal-walker, which is exactly the state
            // the tail stall consists of. A single clean payload
            // article anywhere keeps this closed.
            let Some(walkers) = queue_ctl2.verdict_walkers() else {
                continue;
            };
            let set_names: HashSet<String> = set
                .files
                .iter()
                .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
                .collect();
            let block = set.block_size.max(1) as usize;
            // Counts are only meaningful for the set and block size they
            // were taken under, so a re-activation onto a different set
            // starts the census from scratch rather than crediting the
            // old set's slices.
            if cache_key != Some((set.recovery_set_id, block)) {
                disk_cache.clear();
                cache_key = Some((set.recovery_set_id, block));
            }
            let est = par_race_estimate(&set_names, block, &slots2, &slot_file2, &nzb2);
            let (_, live_bad) = verifier2.live_counts();
            let missing_blocks = par_race_missing_blocks(block, &slots2, &slot_file2, &nzb2);
            // On hand: blocks the activation saw, plus prefetched
            // volumes, plus inline-fetched volumes decoded into the job
            // dir - deduped by path so a volume on both lists is never
            // counted twice toward the margin.
            let mut on_hand = set.recovery_blocks_seen;
            let mut counted: HashSet<PathBuf> = HashSet::new();
            for (_, paths) in pre.lock_ok().iter() {
                for p in paths {
                    if !counted.insert(p.clone()) {
                        continue;
                    }
                    on_hand +=
                        cached_recovery_blocks(p, &set.recovery_set_id, block, &mut disk_cache);
                }
            }
            on_hand +=
                disk_recovery_blocks(&dir, &set.recovery_set_id, block, &counted, &mut disk_cache);
            if !tail_giveup_covered(
                &walkers,
                &est,
                block,
                live_bad as usize,
                missing_blocks,
                on_hand,
            ) {
                let uncovered = walkers
                    .iter()
                    .filter(|w| !est.bytes_of.contains_key(&*w.id))
                    .count();
                let exact: usize = walkers
                    .iter()
                    .filter_map(|w| est.bytes_of.get(&*w.id))
                    .map(|&(_, b)| (b as usize).div_ceil(block) + 1)
                    .sum();
                // Coverage exists but the margin is short: hand the
                // spec prefetch a standing order for the full 2x
                // ceiling, so the next rungs fetch toward exactly the
                // number that lets this fire. An UNCOVERED walker is a
                // hard veto - no amount of prefetch changes it.
                if uncovered == 0 {
                    let ceiling = exact + live_bad as usize + missing_blocks;
                    demand.store(ceiling.saturating_mul(2), Ordering::Release);
                }
                if !veto_said {
                    veto_said = true;
                    info!(
                        target: "repair",
                        "tail give-up held back: {} walker(s), {uncovered} outside the \
                         recovery set, {exact}+{}+{missing_blocks} blocks against \
                         {on_hand} on hand (needs 2x) - walking the ladder instead",
                        walkers.len(),
                        live_bad,
                    );
                }
                continue; // not covered (or not covered ENOUGH) - the ladder must finish
            }
            let claimed = queue_ctl2.give_up_covered(&walkers);
            if claimed.is_empty() {
                continue;
            }
            let mut freed = 0u64;
            for id in &claimed {
                if let Some(&(sidx, b)) = est.bytes_of.get(&**id) {
                    slots2[sidx].remaining.fetch_sub(1, Ordering::AcqRel);
                    slots2[sidx].abandoned.fetch_add(1, Ordering::Relaxed);
                    freed += b;
                }
            }
            // No outcome will ever arrive for these - settle the bar
            // here, exactly like a sniff deferral or the par-race.
            fetch_done2.fetch_add(freed, Ordering::Relaxed);
            info!(
                target: "repair",
                "tail give-up: parity already covers the last {} article(s) still \
                 walking the refusal ladder ({on_hand} recovery blocks on hand, \
                 {live_bad} bad + {missing_blocks} missing blocks priced in) - \
                 stopped asking and moved to repair",
                claimed.len(),
            );
        }
    }))
}

/// Wind the network phase down: stop the side tasks, join the decode
/// consumers off the reactor, flush the final D records, stop the
/// ticker and watchdog, honor user abort and graceful pause (bailing
/// DROPS net_done, which the daemon reads as network-drained), signal
/// net_done, re-read the late-attach password, and await the M15b
/// backfill. Returns the elapsed network time and the effective
/// password for the disk tail.
#[expect(clippy::too_many_arguments)]
pub(super) async fn drain_network(
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
    spec_prefetch_task: Option<tokio::task::JoinHandle<()>>,
    par_race_task: Option<tokio::task::JoinHandle<()>>,
    tail_giveup_task: Option<tokio::task::JoinHandle<()>>,
    consumers: Vec<std::thread::JoinHandle<()>>,
    pending_d: &Arc<std::sync::Mutex<Vec<PendingD>>>,
    pending_r: &Arc<std::sync::Mutex<PendingR>>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    journal: &Arc<nzbkit::journal::Journal>,
    t0: Instant,
    ticker: tokio::task::JoinHandle<()>,
    watchdog: tokio::task::JoinHandle<()>,
    stalled: &Arc<std::sync::atomic::AtomicBool>,
    abort_flag: &Arc<std::sync::atomic::AtomicBool>,
    disk_full_sample: &Arc<std::sync::Mutex<Option<String>>>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    note_activity: &(dyn Fn(&'static str) + Sync),
    net_done: Option<tokio::sync::oneshot::Sender<std::time::Instant>>,
    hub: &Option<Arc<StreamHub>>,
    stream_owner: &str,
    password: Option<String>,
    backfill: &Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>>,
) -> Result<(std::time::Duration, Option<String>)> {
    // Network phase over: stop a still-waiting watcher, and let a
    // mid-fetch prefetch finish before settle harvests the directory.
    prefetch_stop.store(true, Ordering::Release);
    if let Some(t) = spec_prefetch_task {
        let _ = t.await;
    }
    if let Some(t) = par_race_task {
        let _ = t.await;
    }
    if let Some(t) = tail_giveup_task {
        let _ = t.await;
    }
    // Decode threads exit when the channel closes (fetch dropped tx).
    // Join off the reactor - thread::join blocks.
    let _ = tokio::task::spawn_blocking(move || {
        for c in consumers {
            let _ = c.join();
        }
    })
    .await;
    // Final held-article flush: holds that drained after the last
    // article's own flush pass (settle-triggered reresolves, the tail
    // of an out-of-order set) journal now; anything still parked
    // refetches on resume, which is exactly the truthful record.
    flush_pending_r(pending_r, extractor, journal);
    // The network phase is over: land the placement batch the journal
    // was still holding (the decoders' idle flush covers a stall, this
    // covers the end).
    journal.flush();
    // Final D-record flush: seams that closed after the last article's
    // own flush pass settle now; anything still RAM-held refetches on
    // resume, which is exactly the truthful record.
    {
        let mut pd = pending_d.lock_ok();
        if !pd.is_empty() {
            let ev = extractor.drain_crypto_events();
            journal.record_crypto_events(&ev);
            pd.retain(|(sidx, id, name, size, frags)| {
                if extractor.crypto_span_on_disk(frags) {
                    journal.record_placed_crypto(
                        *sidx,
                        id,
                        extractor.slot_file_info(*sidx),
                        name,
                        *size,
                        frags,
                        &extractor.crypto_frag_mask(frags),
                    );
                    false
                } else {
                    true
                }
            });
        }
    }
    let elapsed = t0.elapsed();
    ticker.abort();
    watchdog.abort();
    if stalled.load(Ordering::Relaxed) {
        warn!(
            target: "stall",
            "recovered from a stalled pool by aborting the tail - \
             verifying and repairing what landed"
        );
    }
    // User cancelled: skip settle/repair/extract on the partial data.
    // The journal keeps what landed - a later retry resumes from it.
    // (Bailing drops net_done, which the daemon reads as network-drained.)
    if abort_flag.load(Ordering::Relaxed) {
        anyhow::bail!("stopped by user");
    }
    // A write hit storage exhaustion mid-download and the consumer
    // halted the fetch (see note_storage_exhausted_halt). Skip
    // settle/repair/extract - they write to the same full volume - and
    // fail with the distinct out-of-disk-space verdict. The opening
    // clause is what `fail_kind`/`disk_full_failure` classify on;
    // everything after it is appended detail, per the incomplete_reason
    // contract. The journal is NOT retired, so freeing space and
    // retrying resumes from what landed without refetching a byte.
    if let Some(sample) = disk_full_sample.lock_ok().take() {
        anyhow::bail!(
            "out of disk space - the output volume filled during the download, \
             so fetching was stopped early; what landed is journaled and kept \
             ({sample})"
        );
    }
    // Graceful pause: the pool admitted no new work and let every in-flight
    // article finish and journal, so a resume re-fetches only the unstarted
    // queue - nothing here is wasted. Park it like an abort (skip settle),
    // but say so: this is a clean wind-down, not a cancel.
    if queue_ctl.is_draining() {
        anyhow::bail!("paused (drained in-flight; queue kept for resume)");
    }
    // Network drained: everything from here is disk/CPU. Tell the daemon
    // so the next queued download can start soaking the line now.
    //
    // The token moves FIRST, and it is what the queue row's status is
    // read from - so by the time the daemon can act on the signal and
    // start the next download, this job has already stopped calling
    // itself a download. Announced here rather than at the verify pass
    // below because the settle read-back, the backfill join and the
    // deferred-payload sweep in between are all part of checking what
    // landed; leaving the token on "fetching" for them is what made a
    // finished transfer read as "downloading, 100%, 0 MB/s" for minutes.
    note_activity("verifying");
    if let Some(tx) = net_done {
        let _ = tx.send(std::time::Instant::now());
    }
    // M24 late attach (C1): a password set via mode=set_password while
    // this job downloaded. The `password` binding above was resolved at
    // start; without this re-read the whole disk tail (re-extraction,
    // recovery-record repair, the unrar ladder, the nested pass) ran with
    // the stale None, parked the job as password_required, and the very
    // password the user had already supplied sat unread until a manual
    // retry. Late wins over captured: a user re-typing mid-download is
    // correcting the one the job started with.
    let password: Option<String> = hub
        .as_ref()
        .and_then(|h| h.late_password_for(stream_owner))
        .or(password);
    // Any pre-activation spans the backfill is still hashing belong to
    // this tail - wait so settle sees final block states (M15b).
    let bf = backfill.lock_ok().take();
    if let Some(h) = bf
        && let Ok(fed) = h.await
        && fed > 0
    {
        info!(
            target: "par2",
            "backfilled {:.1} MB of pre-activation spans during download",
            fed as f64 / 1e6
        );
    }
    Ok((elapsed, password))
}

/// The fetch-outcome channel, the shared progress/error counters and
/// first-error samples, the slow-disk consumer throttle, the M15b
/// backfill cell, and the runtime handle the decode threads use for
/// spawn_blocking. Field names match the local bindings the inline
/// code used.
pub(super) struct Counters {
    pub(super) tx: tokio::sync::mpsc::Sender<nzbkit::pool::FetchOutcome>,
    pub(super) rx: Arc<std::sync::Mutex<tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>>>,
    pub(super) decoded_bytes: Arc<AtomicU64>,
    pub(super) decode_errors: Arc<AtomicU64>,
    pub(super) retention_excluded: Arc<CauseSplit>,
    pub(super) missing_430: Arc<CauseSplit>,
    pub(super) takedown_430: Arc<CauseSplit>,
    pub(super) transport_failed: Arc<CauseSplit>,
    pub(super) transport_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) decode_error_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) disk_full_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) throttle_mbps: Option<f64>,
    pub(super) throttle_t0: Instant,
    pub(super) backfill: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>>,
    pub(super) rt: tokio::runtime::Handle,
}

pub(super) fn build_counters(
    budget: &nzbkit::mem::MemBudget,
    progress: Option<Arc<AtomicU64>>,
    hub: &Option<Arc<StreamHub>>,
    resume_have_bytes: u64,
) -> Counters {
    use nzbkit::pool::FetchOutcome;
    // B2: channel depth scales with the budget - a fixed 256 held up to
    // ~200 MB of raw articles OUTSIDE the budget, more than a small
    // box's entire allowance. See MemBudget::channel_depth.
    let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(budget.channel_depth());
    // Consumers are dedicated OS threads (A6, constrained-CPU): decode +
    // pwrite + verify are all synchronous CPU/disk work, and running them
    // inline on tokio workers starves the socket reactor on 2-4 core
    // boxes (every worker stuck in MD5/pwrite → TCP reads stall →
    // throughput craters). A std Mutex around the receiver is fine
    // between OS threads: the handoff is microseconds against ~800 KB
    // of decode work per article, and no async scheduler hop is involved.
    let rx = Arc::new(std::sync::Mutex::new(rx));
    // The daemon shares this counter to report live queue progress.
    let decoded_bytes = progress.unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
    // Publish what the journal already holds, so the queue row can add
    // it to this counter and pick the bar up where the last run left it.
    // A resume that stopped at 62% otherwise re-drew from 0 and climbed
    // back, which reads as "it started over" however loudly the copy
    // says nothing is re-downloaded - and is what a good share of the
    // reports of a lost journal actually are.
    //
    // Beside the counter rather than added INTO it, deliberately. This
    // one is every consumer's idea of "bytes off the wire this run": the
    // quota ledger bills it, history divides it by network seconds, the
    // resulting average feeds `best_rate_bps` (the stall watchdog's
    // reference for what the line can do), the CLI ticker differences it
    // per 2 s, and the daemon's rolling speed window differences it per
    // sample. Crediting 40 GB of already-downloaded articles into it in
    // one instant would answer all six of those with a number no line
    // has ever run at. The reader that wants "how much of this release
    // is on disk" adds the two; nothing else has to know.
    //
    // The figure is the NZB's encoded segment size, where a fetched
    // article credits its decoded length - so the seeded stretch of the
    // bar runs a few percent generous against an encoded denominator
    // that the fetched stretch runs a few percent shy of. Squaring those
    // two ends is audit #15's job; the percentage is clamped, so neither
    // can overshoot the bar.
    if let Some(h) = &hub {
        h.resume_seeded.store(resume_have_bytes, Ordering::Relaxed);
    }
    let decode_errors = Arc::new(AtomicU64::new(0));
    // Segments the pool never asked anyone for: outside every configured
    // server's retention window. Reported by cause in the failure summary
    // - to the user these were indistinguishable from real takedowns.
    let retention_excluded = Arc::new(CauseSplit::default());
    // The other two loss ledgers the failure summary reads. A real 430
    // verdict and a transport failure demand opposite responses (the
    // post is dead vs the provider flaked), yet both used to land in the
    // same per-slot "missing" count - a flaky provider read as a
    // takedown, all the way to the indexer failure report.
    let missing_430 = Arc::new(CauseSplit::default());
    // Of those, the ones whose refusal SAID the article was removed
    // (a takedown or removal notice) - a hint for the failure summary,
    // never a separate verdict class.
    let takedown_430 = Arc::new(CauseSplit::default());
    let transport_failed = Arc::new(CauseSplit::default());
    // First error of each kind, verbatim, for the failure summary to
    // quote - the counter alone says nothing a bug report can act on.
    let transport_sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
    let decode_error_sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
    // First storage-exhaustion write error, verbatim: its presence IS
    // the halt signal drain_network turns into the out-of-disk-space
    // verdict (see note_storage_exhausted_halt).
    let disk_full_sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
    // Test knob: cap the consumer (decode+write) stage to N MB/s to
    // simulate a slow disk. The correct systemic response - proven by the
    // backpressure test - is that the bounded channel fills, workers stop
    // reading sockets, TCP windows close, and providers slow to match,
    // with RSS flat. Async sleep, so pool I/O tasks stay unstarved.
    let throttle_mbps: Option<f64> = std::env::var("NZBFAST_THROTTLE_WRITE_MBPS")
        .ok()
        .and_then(|v| v.parse().ok());
    if let Some(m) = throttle_mbps {
        warn!(target: "get", "consumer throttle active: {m} MB/s (slow-disk simulation)");
    }
    let throttle_t0 = Instant::now();

    // M15b backfill: filled by whichever consumer wins the activation
    // race; awaited (and reported) before the settle pass.
    let backfill: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>> =
        Arc::new(std::sync::Mutex::new(None));
    // NOTE: the par2 flags for the M15b backfill are computed AT ACTIVATION
    // TIME from the slots themselves (not snapshotted here): the in-stream
    // sniff can flip a slot to recovery data long after this point.

    // Handle for the two par2-activation spawn_blocking sites below -
    // decode threads are plain OS threads with no implicit runtime context.
    let rt = tokio::runtime::Handle::current();
    Counters {
        tx,
        rx,
        decoded_bytes,
        decode_errors,
        retention_excluded,
        missing_430,
        takedown_430,
        transport_failed,
        transport_sample,
        decode_error_sample,
        disk_full_sample,
        throttle_mbps,
        throttle_t0,
        backfill,
        rt,
    }
}

/// Spawn the decode-consumer fleet: one dedicated OS thread per
/// decoder (capped at the core count - more is pure scheduler churn,
/// measured on the 2-CPU cgroup rig), each running
/// [`decode_consumer_loop`] over a DecodeCtx built from these shared
/// handles. Returns the join handles and the shared pending-D cell the
/// drain pass flushes.
#[expect(clippy::too_many_arguments)]
pub(super) fn spawn_decode_consumers(
    decoders: usize,
    rx: &Arc<std::sync::Mutex<tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>>>,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    out_pool: &Arc<nzbkit::pool::BufPool>,
    slots: &[Arc<FileSlot>],
    id_to_slot: &Arc<crate::unpack::IdSlots>,
    seek_names: &Arc<SeekCtl>,
    decoded_bytes: &Arc<AtomicU64>,
    fetch_done: &Arc<AtomicU64>,
    decode_errors: &Arc<AtomicU64>,
    retention_excluded: &Arc<CauseSplit>,
    missing_430: &Arc<CauseSplit>,
    takedown_430: &Arc<CauseSplit>,
    transport_failed: &Arc<CauseSplit>,
    transport_sample: &Arc<std::sync::Mutex<Option<String>>>,
    decode_error_sample: &Arc<std::sync::Mutex<Option<String>>>,
    disk_full_sample: &Arc<std::sync::Mutex<Option<String>>>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    shape_said: &Arc<std::sync::atomic::AtomicBool>,
    par2_outstanding: &Arc<std::sync::atomic::AtomicUsize>,
    journal: &Arc<nzbkit::journal::Journal>,
    backfill: &Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>>,
    sniff: &Arc<SniffCtl>,
    replay: &Arc<super::rig::ReplayPending>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    rt: &tokio::runtime::Handle,
    throttle_mbps: Option<f64>,
    throttle_t0: Instant,
    crc_steer: bool,
) -> (
    Vec<std::thread::JoinHandle<()>>,
    Arc<std::sync::Mutex<Vec<PendingD>>>,
    Arc<std::sync::Mutex<PendingR>>,
) {
    let mut consumers = Vec::new();
    // Plaintext-once D records parked until their seam bytes settle on
    // disk (see the PlacedCrypto arm below). Shared across the decode
    // threads; leftovers at join time simply refetch on resume. Owned
    // by the replay (TODO 158 item 2): a resumed article it re-feeds
    // parks into the same list, and it may feed before these threads
    // exist.
    let pending_d: Arc<std::sync::Mutex<Vec<PendingD>>> = replay.pending_d.clone();
    // Held articles parked until their drained placements cover the
    // span (see ParkedR). Leftovers at drain time refetch on resume.
    let pending_r: Arc<std::sync::Mutex<PendingR>> = replay.pending_r.clone();
    // More decode threads than cores is pure scheduler churn (measured on
    // the 2-CPU cgroup rig): the default 4 stands on big metal, small
    // boxes get one per core.
    let n_decoders = decoders
        .max(1)
        .min(std::thread::available_parallelism().map_or(usize::MAX, |n| n.get()));
    for i in 0..n_decoders {
        let ctx = DecodeCtx {
            rx: rx.clone(),
            pending_d: pending_d.clone(),
            pending_r: pending_r.clone(),
            pool: buf_pool.clone(),
            out_pool: out_pool.clone(),
            slots: slots.to_vec(),
            id_to_slot: Arc::clone(id_to_slot),
            seek_names: seek_names.clone(),
            decoded_bytes: decoded_bytes.clone(),
            fetch_done: fetch_done.clone(),
            decode_errors: decode_errors.clone(),
            retention_excluded: retention_excluded.clone(),
            missing_430: missing_430.clone(),
            takedown_430: takedown_430.clone(),
            transport_failed: transport_failed.clone(),
            transport_sample: transport_sample.clone(),
            decode_error_sample: decode_error_sample.clone(),
            disk_full_sample: disk_full_sample.clone(),
            verifier: verifier.clone(),
            extractor: extractor.clone(),
            shape_said: shape_said.clone(),
            par2_outstanding: par2_outstanding.clone(),
            journal: journal.clone(),
            backfill: backfill.clone(),
            sniff: sniff.clone(),
            replay: replay.clone(),
            queue_ctl: queue_ctl.clone(),
            rt: rt.clone(),
            throttle_mbps,
            throttle_t0,
            crc_steer,
        };
        let thread = std::thread::Builder::new()
            .name(format!("decode-{i}"))
            .spawn(move || decode_consumer_loop(ctx))
            .expect("spawn decode thread");
        consumers.push(thread);
    }
    (consumers, pending_d, pending_r)
}

/// The tail-side watchers as one bundle: the spec-prefetch scratch state
/// (`prefetched` / `prefetch_stop` / `tail_demand`) plus the three
/// spawned tasks that share it. Built by [`spawn_tail_watchers`]; the
/// destructure at the call site keeps every downstream read on the
/// inline names, same as the other phase bundles.
pub(super) struct TailWatchers {
    pub(super) prefetched: Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    pub(super) prefetch_stop: Arc<std::sync::atomic::AtomicBool>,
    pub(super) spec_prefetch_task: Option<tokio::task::JoinHandle<()>>,
    pub(super) par_race_task: Option<tokio::task::JoinHandle<()>>,
    pub(super) tail_giveup_task: Option<tokio::task::JoinHandle<()>>,
}

/// M2c.5 speculative recovery prefetch, the dark PAR2-race experiment,
/// and the §146 tail give-up - the three side tasks that watch the fetch
/// from the recovery side - moved out of `get_with_progress` bodily
/// under the size gate (TODO 106). Behaviour unchanged: each spawn's
/// gate (hub flag / env var) is exactly the inline code's.
#[expect(clippy::too_many_arguments)]
pub(super) fn spawn_tail_watchers(
    hub: &Option<Arc<StreamHub>>,
    has_main: bool,
    nzb: &Arc<Nzb>,
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    slots: &[Arc<FileSlot>],
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    fetch_done: &Arc<AtomicU64>,
    decoded_bytes: &Arc<AtomicU64>,
    slot_file: &[usize],
) -> TailWatchers {
    let prefetched: Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let prefetch_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // §146: the tail give-up's standing order to the spec prefetch, in
    // recovery slices - see the two spawns' parameter docs.
    let tail_demand = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let spec_prefetch_task: Option<tokio::task::JoinHandle<()>> = {
        let allowed = match hub {
            Some(h) => h.spec_prefetch.load(Ordering::Relaxed),
            None => std::env::var_os("NZBFAST_NO_SPEC_PREFETCH").is_none(),
        };
        spawn_spec_prefetch(
            allowed,
            has_main,
            nzb,
            servers,
            slots,
            out_dir,
            buf_pool,
            &prefetched,
            &prefetch_stop,
            &tail_demand,
        )
    };
    // PAR2-race experiment (dark): see spawn_par_race.
    let par_race_task = spawn_par_race(
        slots,
        verifier,
        queue_ctl,
        &prefetch_stop,
        &prefetched,
        fetch_done,
        decoded_bytes,
        slot_file,
        nzb,
    );
    // §146 tail give-up (default on): see spawn_tail_giveup.
    let tail_giveup_task = spawn_tail_giveup(
        slots,
        verifier,
        queue_ctl,
        &prefetch_stop,
        &prefetched,
        fetch_done,
        slot_file,
        nzb,
        out_dir,
        &tail_demand,
    );
    TailWatchers {
        prefetched,
        prefetch_stop,
        spec_prefetch_task,
        par_race_task,
        tail_giveup_task,
    }
}

#[cfg(test)]
mod disk_full_halt_tests {
    use super::*;

    #[test]
    fn storage_exhaustion_records_once_and_halts() {
        let sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
        let qc = nzbkit::pool::QueueControl::default();
        let e = std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            "No space left on device (os error 28)",
        );
        assert!(note_storage_exhausted_halt(&e, "a.r01", &sample, &qc));
        // A second detection (another decode thread racing through its
        // in-flight bodies) keeps the FIRST sample and is not the halt.
        let e2 = std::io::Error::new(std::io::ErrorKind::StorageFull, "No space left on device");
        assert!(!note_storage_exhausted_halt(&e2, "b.r02", &sample, &qc));
        assert!(
            sample
                .lock_ok()
                .as_deref()
                .unwrap()
                .starts_with("write a.r01:")
        );
    }

    #[test]
    fn ordinary_write_errors_do_not_halt() {
        let sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
        let qc = nzbkit::pool::QueueControl::default();
        let e = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        assert!(!note_storage_exhausted_halt(&e, "a.r01", &sample, &qc));
        assert!(sample.lock_ok().is_none());
    }
}

#[cfg(test)]
mod cause_split_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn slot(hint: &str, par2: bool) -> Arc<FileSlot> {
        Arc::new(FileSlot {
            hint: hint.into(),
            is_par2_main: par2,
            sample_skipped: false,
            par2_sniffed: AtomicBool::new(false),
            total_segments: 1,
            remaining: AtomicUsize::new(0),
            missing: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(None),
        })
    }

    /// Sweep 8, M7, the collection half: a loss is charged to the side
    /// that actually lost it, and an id belonging to no slot is charged
    /// to PAYLOAD.
    ///
    /// The unknown-id rule is the conservative one and it is deliberate.
    /// Payload evidence blocks the optimistic verdicts (`post_gone`,
    /// `all_transport`) rather than licensing them, so an outcome we
    /// cannot attribute can at worst make the diagnosis less confident -
    /// never more.
    #[test]
    fn a_loss_is_charged_to_the_side_that_lost_it() {
        let slots = vec![slot("movie.mkv", false), slot("movie.vol00+01.par2", true)];
        let mut map: crate::unpack::IdSlots = Default::default();
        map.insert("<payload@x>".into(), (0, 1000));
        map.insert("<parity@x>".into(), (1, 1000));

        assert!(!is_recovery_article("<payload@x>", &map, &slots));
        assert!(is_recovery_article("<parity@x>", &map, &slots));
        assert!(
            !is_recovery_article("<stranger@x>", &map, &slots),
            "an id that maps to no slot cannot be shown to be parity, and payload \
             is the side that blocks a verdict rather than licensing one"
        );

        // A sniffed recovery slot counts too - `is_par2` is the sniff
        // OR the static main, and a bootstrap sniff lands mid-run.
        slots[0]
            .par2_sniffed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(is_recovery_article("<payload@x>", &map, &slots));

        let c = CauseSplit::default();
        c.add(false);
        c.add(true);
        c.add(true);
        assert_eq!((c.payload(), c.recovery(), c.total()), (1, 2, 3));
    }
}

// The par-race, spec-ladder and pending-R tests, out under the size
// gate (TODO 106): this file is production code and was 35 lines under
// the file ceiling. Children of `workers` (plain `mod`, so they resolve
// to get/workers/), named for their files so size-gate.py's
// CFG_TEST_MOD resolver keeps scoring them as test code. The pending-R
// rigs moved out on 23 Aug 2026, when TODO 252 gave them a second one.
#[cfg(test)]
mod pending_r_tests;

#[cfg(test)]
mod par_race_tests;

#[cfg(test)]
mod spec_ladder_tests;

#[cfg(test)]
mod damage_projection_tests;
