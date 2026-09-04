//! The worker tasks get_with_progress spawns: decode consumers, the
//! rate ticker, the deadlock watchdog, the speculative recovery
//! prefetch, and the par-race experiment (TODO 106 phase 2.1, cuts
//! 1-2). Bodies are verbatim moves from the orchestrator; each fn's
//! parameter list is exactly the clone set its spawn site used to
//! build.
//!
//! The last two of those - plus the §146 tail give-up that shares
//! their recovery-block arithmetic - now live in [`recovery`]. This
//! file still spawns all three; only their bodies moved.

use crate::*;
use std::path::Path;
use tracing::{debug, info, warn};

/// Plaintext-once (`D`) journal record parked until its seam bytes are
/// on disk: (slot, article id, name, size, frags).
/// A parked `D` record: (slot, id, name, size, fragments, content
/// commitment). The last field is X5-02's verified pcrc32, taken at
/// DECODE and carried across the park because the record is written
/// later - once the seam slivers land - and the number is not
/// recoverable by then.
pub(super) type PendingD = (
    usize,
    Arc<str>,
    String,
    u64,
    Vec<nzbkit::extract::Frag>,
    Option<u32>,
);

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
    /// X5-02's content commitment - the verified pcrc32 taken at DECODE.
    /// Carried across the park because the record is written when the
    /// hold drains, which is long after the bytes are gone from RAM.
    pub(super) crc: Option<u32>,
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
    /// Per slot, the drained fragments and whether each landed as
    /// PLAINTEXT in an in-stream-decrypted file - see
    /// [`nzbkit::extract::LatePlacement::crypto`]. The flag decides
    /// which record the completed article gets, and a `true` anywhere
    /// in a span's join makes an `R` record impossible for it.
    pub(super) late: std::collections::HashMap<usize, Vec<(nzbkit::extract::Frag, bool)>>,
    /// Slots that gained a late placement since the last re-attempt
    /// pass. A parked article's fate can only change when its own slot
    /// gains placements, or when the volume file's coverage grows under
    /// it (the widening arm) - so a pass that is not a sweep re-attempts
    /// exactly these slots. See [`flush_pending_r`].
    fresh: std::collections::HashSet<usize>,
    /// When the last SWEEP - a pass that re-attempted parked articles in
    /// slots with no new placements - ran. See [`PENDING_R_SWEEP`].
    last_sweep: Option<std::time::Instant>,
}

/// How stale the widening arm's answer may get: a parked article whose
/// slot gained no new placements is re-attempted at most this often,
/// instead of once per decoded article.
///
/// The article-shaped cost this bounds (small-articles lane, 3 Sep 2026,
/// `research/RAR-PERF-AUDIT-2026-09-02.md` round 23): a parked entry is
/// re-evaluated by EVERY later article's flush, and each entry that
/// reaches the widening arm takes the extractor's routing lock inside
/// [`nzbkit::extract::Extractor::materialized_span_on_disk`]. A set of
/// thousands of small stored members parks about one article per member
/// - the header bytes below the parse cursor are held in RAM and, on the
/// direct-map one-pass path, never land on disk at all - so `parked`
/// grows to about the member count and the flush is O(parked) per
/// article, with a routing-lock acquisition per entry. Measured on the
/// dev Mac at 2,048 x 512 KB members: the decode threads spent 78% of
/// their samples queued on the `pending_r` mutex, and the shape cost 5.2x
/// the instructions per byte of the same bytes as one member.
///
/// Correctness does not rest on the cadence: the final flush after the
/// decoders join passes `force`, and it is also the moment the volume
/// coverage is largest, so a span the sweeps missed completes there. An
/// article still parked past that refetches on resume, which is the same
/// truthful record it had before.
const PENDING_R_SWEEP: std::time::Duration = std::time::Duration::from_millis(25);

/// Join freshly drained late placements against the parked held
/// articles and journal every article whose span the fragments now
/// fully cover. A hold is always a subrange of exactly one article's
/// span, so containment in `[off, off+len)` is the join key. Cheap when
/// nothing is parked (one uncontended lock).
///
/// A span whose fragments include a PLAINTEXT-ONCE one completes into a
/// `D` record rather than an `R` (TODO 27.2, 24 Aug 2026) - see
/// [`complete_crypto`] for what that costs it.
pub(super) fn flush_pending_r(
    pending_r: &std::sync::Mutex<PendingR>,
    extractor: &nzbkit::extract::Extractor,
    journal: &nzbkit::journal::Journal,
    force: bool,
) {
    let mut st = pending_r.lock_ok();
    if st.parked.is_empty() {
        return;
    }
    for lp in extractor.drain_late_placements() {
        st.fresh.insert(lp.slot);
        st.late
            .entry(lp.slot)
            .or_default()
            .push((lp.frag, lp.crypto));
    }
    // Which parked articles this pass re-attempts. A SWEEP takes them
    // all, which is what every pass used to do; otherwise only the slots
    // that just gained placements, because nothing else about an
    // untouched slot has changed since the last look. See
    // [`PENDING_R_SWEEP`] for the cost this bounds and why the cadence
    // cannot lose a record.
    let sweep = force || st.last_sweep.is_none_or(|t| t.elapsed() >= PENDING_R_SWEEP);
    if !sweep && st.fresh.is_empty() {
        return;
    }
    if sweep {
        st.last_sweep = Some(std::time::Instant::now());
    }
    let PendingR {
        parked,
        late,
        fresh,
        ..
    } = &mut *st;
    let mut done: Vec<(usize, u64, u64)> = Vec::new();
    // The materialized-volume oracle, captured ONCE for this pass under
    // ONE routing-lock acquisition. It used to be asked per parked
    // article, and each ask took that lock - so a sweep over `parked`
    // (about one entry per member on a many-member stored set) took it a
    // couple of thousand times in a burst, while holding the `pending_r`
    // mutex every decode thread queues on at the top of this function.
    // Round 26 of research/RAR-PERF-AUDIT-2026-09-02.md read that pair as
    // the two largest waits in the whole profile. Lazy: a pass that never
    // reaches the widening arm does not take the lock at all.
    let mut materialized: Option<nzbkit::extract::MaterializedVolumes> = None;
    // The `E`/`K`/`T` facts every `D` record leans on, drained and
    // written ONCE per pass and before the first `D` of it, so a record
    // is never orphaned ahead of the facts that restore it. Lazy: a
    // pass that completes no crypto article touches the sink at all.
    let mut events_written = false;
    parked.retain(|p| {
        // Off-sweep: only slots that just gained placements can have
        // changed, and re-reading the rest is the O(parked)-per-article
        // walk this gate exists to remove.
        if !sweep && !fresh.contains(&p.sidx) {
            return true;
        }
        let end = p.off + p.len;
        // A `Persist::Held` return carries PLAIN fragments only
        // (`compose_persist` filters the crypto ones out), so the
        // article's own partial view is all `false`.
        let mut frags: Vec<(nzbkit::extract::Frag, bool)> =
            p.frags.iter().cloned().map(|f| (f, false)).collect();
        if let Some(slot_late) = late.get(&p.sidx) {
            frags.extend(
                slot_late
                    .iter()
                    .filter(|(f, _)| f.vol_off >= p.off && f.vol_off + f.len <= end)
                    .cloned(),
            );
        }
        frags.sort_by_key(|(f, _)| f.vol_off);
        let crypto = frags.iter().any(|(_, c)| *c);
        let mut covered_to = p.off;
        let mut gap = false;
        for (f, _) in &frags {
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
            // A crypto span does NOT inherit the widening above it, and
            // that is a decision rather than an omission (TODO 27.2, 24
            // Aug 2026). `materialized_span_on_disk` vouches for the
            // slot's VOLUME file holding these bytes verbatim at their
            // final offsets, and its answer composes ONE identity
            // fragment naming that volume - which is an `R` claim in
            // everything but the letter. Inheriting it would let a span
            // whose bytes reached a plaintext-once file complete off a
            // volume it may only partly have reached, mixing a copy
            // restore with a re-encryption restore over the same range.
            // A crypto span therefore completes ONLY off its own
            // placement trail, and where the trail comes up short the
            // article stays parked and refetches - the safe direction,
            // and no worse than what it did before it journaled at all.
            if crypto {
                return true; // stays parked
            }
            let Some((name, size)) = materialized
                .get_or_insert_with(|| extractor.materialized_volumes())
                .span_on_disk(p.sidx, p.off, p.len)
            else {
                return true; // stays parked
            };
            frags = vec![(nzbkit::extract::Frag::identity(&name, p.off, p.len), false)];
            on_disk = Some((name, size));
        }
        // Every byte of the span is durably on disk (the re-feed writes
        // ran under the extractor's routing lock, before the placements
        // were surfaced) - journal it exactly like a directly-Placed
        // article.
        if p.par2_main {
            journal.record(&p.id);
        } else if crypto {
            if !complete_crypto(p, &frags, extractor, journal, &mut events_written) {
                return true; // plaintext not settled yet - stays parked
            }
        } else {
            let mut frags: Vec<nzbkit::extract::Frag> = frags.into_iter().map(|(f, _)| f).collect();
            let widened = on_disk.is_some();
            let slot_file = on_disk.or_else(|| extractor.slot_file_info(p.sidx));
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
            journal.record_placed(p.sidx, &p.id, slot_file, &p.name, p.size, &frags, p.crc);
        }
        done.push((p.sidx, p.off, end));
        false
    });
    fresh.clear();
    // The late fragments a journaled article consumed can never match
    // another article (spans are disjoint) - drop them so the map does
    // not grow for the life of the job.
    if !done.is_empty() {
        for (slot, v) in late.iter_mut() {
            v.retain(|(f, _)| {
                !done
                    .iter()
                    .any(|(s, o, e)| s == slot && f.vol_off >= *o && f.vol_off + f.len <= *e)
            });
        }
    }
}

/// Complete a parked article whose fragments include plaintext-once
/// bytes: a `D` record, never an `R` (TODO 27.2, 24 Aug 2026). Returns
/// false when the plaintext has not physically landed yet, which leaves
/// the article parked for a later pass exactly as a directly-placed `D`
/// waits in `pending_d`.
///
/// Two things this does that the plain arm does not, both of them the
/// reason the crypto route was left unreported until now:
///
///  * It gates on [`nzbkit::extract::Extractor::crypto_span_on_disk`].
///    A plain re-feed write has landed by the time its placement is
///    surfaced; a crypto one was handed to `CryptoState`, which can
///    still be holding a seam sliver in RAM, and a `D` for RAM-held
///    bytes would survive a kill the bytes did not.
///  * It writes the `E`/`K`/`T` facts first (once per flush pass), so
///    the record can never precede the parameters that restore it.
///
/// The mask is the OR of what the write REPORTED and what the chain
/// says NOW. The reported flag is the ground truth - it was taken at
/// the write, where the route was certain - while the chain's view is
/// what the two direct-path sites use, so taking either as enough is
/// the conservative reading: a fragment marked crypto restores by
/// re-encryption, and one whose facts are missing must FAIL on resume
/// rather than fall through to a copy.
fn complete_crypto(
    p: &ParkedR,
    frags: &[(nzbkit::extract::Frag, bool)],
    extractor: &nzbkit::extract::Extractor,
    journal: &nzbkit::journal::Journal,
    events_written: &mut bool,
) -> bool {
    let bare: Vec<nzbkit::extract::Frag> = frags.iter().map(|(f, _)| f.clone()).collect();
    if !extractor.crypto_span_on_disk(&bare) {
        return false;
    }
    if !*events_written {
        journal.record_crypto_events(&extractor.drain_crypto_events());
        *events_written = true;
    }
    let chain = extractor.crypto_frag_mask(&bare);
    let mask: Vec<bool> = frags
        .iter()
        .enumerate()
        .map(|(i, (_, reported))| *reported || chain.get(i).copied().unwrap_or(false))
        .collect();
    journal.record_placed_crypto(
        p.sidx,
        &p.id,
        extractor.slot_file_info(p.sidx),
        &p.name,
        p.size,
        &bare,
        &mask,
        p.crc,
    );
    true
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
    /// The loss ledgers, as one value: see [`LossLedgers`]. This is the
    /// WRITE end of them - `get::tail` is the read end - and it carries
    /// the bundle for the same reason, `note_missing_cause` below
    /// having taken four of them positionally.
    pub(super) loss: LossLedgers,
    pub(super) unasked_noted: Arc<std::sync::atomic::AtomicBool>,
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
    /// Body-encryption spike: the job's decryption context (password,
    /// per-slot segmentIndex bases, derived-key cache), None unless
    /// `NZBFAST_YENC_CRYPT=1` and the job can support it - see
    /// [`nzbkit::yencrypt::JobCrypt::for_job`] and [`decode_and_decrypt`].
    pub(super) yencrypt: Option<std::sync::Arc<nzbkit::yencrypt::JobCrypt>>,
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
            // ...and the same first verdict starts this slot's
            // self-prove prefix digest. A MISSING article leaves its
            // blocks Pending, so `LiveVerifier` learns nothing about it
            // until settle - by which time the download window that
            // would have paid for the whole-file MD5 is gone. This is
            // the earliest moment anything in the run knows the slot
            // will need a repair (see `nzbkit::live::prefix` and
            // research/DESIGN-2026-09-02-mapped-selfprove-prefix.md).
            self.verifier.arm_prefix(sidx);
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

/// Journal every parked `D` whose plaintext-once bytes have physically
/// settled, leaving the rest parked for a later pass.
///
/// `E`/`K`/`T` facts go FIRST, so a record can never precede the
/// parameters that restore it - an orphaned `D` is unrestorable and
/// refetches, which is safe but is a resume nobody needed to pay for.
///
/// One function because this was written out TWICE, byte-identical: in
/// the decode loop's per-article pass and again at the end of the
/// network phase. They are the same rule at two moments, and a pair of
/// copy-paste siblings is one edit away from disagreeing - which the
/// X5-02 commitment made concrete, since the `crc` field had to be
/// threaded through both. Extracted while adding it, rather than
/// threaded through twice.
fn flush_pending_d(
    pending_d: &std::sync::Mutex<Vec<PendingD>>,
    extractor: &nzbkit::extract::Extractor,
    journal: &nzbkit::journal::Journal,
) {
    let mut pd = pending_d.lock_ok();
    if pd.is_empty() {
        return;
    }
    let ev = extractor.drain_crypto_events();
    journal.record_crypto_events(&ev);
    pd.retain(|(sidx, id, name, size, frags, crc)| {
        if extractor.crypto_span_on_disk(frags) {
            journal.record_placed_crypto(
                *sidx,
                id,
                extractor.slot_file_info(*sidx),
                name,
                *size,
                frags,
                &extractor.crypto_frag_mask(frags),
                *crc,
            );
            false
        } else {
            true
        }
    });
}

/// Clamp the decoded payload to what the article itself declares, then
/// take the X5-02 commitment over what survived. Returns the (possibly
/// cleared) wire CRC for [`nzbkit::extract::Extractor::write_verified`]
/// and the commitment for the journal.
///
/// The two are ONE step because the order between them is the whole
/// correctness of both: the clamp is what invalidates the posted CRC,
/// and the commitment has to be taken AFTER it or it describes bytes
/// that were dropped. Split across the caller, that ordering is a
/// convention; here it is the signature. It also keeps
/// `decode_consumer_loop` under its size ceiling, which is the size
/// gate doing its job rather than an inconvenience.
fn clamp_and_commit(
    out: &mut Vec<u8>,
    dec: &nzbkit::yenc::Meta,
    wire_crc: Option<u32>,
) -> (Option<u32>, u32) {
    let mut article_crc = wire_crc;
    clamp_to_declared_size(out, dec, &mut article_crc);
    (article_crc, content_commitment(article_crc, out))
}

/// X5-02's content commitment for one article: the crc32 the journal
/// records so a resume can tell bytes that ARRIVED from bytes that
/// merely have the right length.
///
/// **Prefer the verified pcrc32, but never depend on there being one.**
/// That distinction is the whole of this function, and getting it wrong
/// is silent: `verified_article_crc` is `None` in three ordinary cases -
/// the post carried no `pcrc32`/`crc32` at all, the CRC check was
/// DELEGATED rather than performed here, or the bare-LF scalar fallback
/// enforced it internally without surfacing the value - and on top of
/// those, [`clamp_to_declared_size`] clears it whenever it truncates,
/// because the posted CRC then covers bytes we did not keep. A journal
/// that recorded `None` in any of those refetches that article on every
/// resume.
///
/// **The delegated case is not a corner, and that is why this function
/// exists.** `LiveVerifier::delegates_integrity` is true exactly when a
/// PAR2 set is active over the slot with full-block MD5 - the ORDINARY
/// shape of a PAR2-backed download - and the decode then skips the
/// pcrc32 pass on purpose (M32 perf) and surfaces no value. Taking the
/// wire number alone would therefore have left every payload article of
/// such a job uncommitted, and turned its resume into a complete
/// refetch. That was the first cut of this change; it was caught by
/// mutation rather than by review, and no fixture in the tree reddens
/// for it - the kill9 resume tests are PAR2-backed and still pass with
/// the fallback removed, because their sets do not reach the delegated
/// path. So the pins are `commitment_tests` below and nzbkit's
/// `an_unverified_article_offers_no_crc_to_reuse`, which is what
/// establishes that `None` is reachable at all. Do not read a green
/// e2e run as evidence this fallback is unnecessary.
///
/// Measured 30 Aug 2026 on the dev Mac at load 25: `crc32fast` runs at
/// 26.5 GB/s over 683 KB buffers, so the fallback is about 4% of ONE
/// core at a 1 GB/s download rate - and it only runs when the wire gave
/// us nothing to reuse. The bytes are already in RAM and already hot.
///
/// Both arms are the same quantity: CRC-32/ISO-HDLC over exactly the
/// decoded payload. `rapidyenc`'s value is compared against the header
/// the poster wrote, and `yenc::decode` checks that same header with
/// `crc32fast`, so the two agree by construction - see
/// `yenc_simd::tests::the_verified_article_crc_is_the_crc32_the_extractor_composes`.
fn content_commitment(article_crc: Option<u32>, out: &[u8]) -> u32 {
    article_crc.unwrap_or_else(|| crc32fast::hash(out))
}

/// Decode, then - body-encryption spike (`NZBFAST_YENC_CRYPT=1`, see
/// `nzbkit::yencrypt`) - decrypt and authenticate an `=yencryption`
/// article in place, so everything downstream of the decode sees
/// plaintext exactly as it would on an unencrypted post. Kept out of
/// `decode_consumer_loop` for its size ceiling, and because the rules
/// here are about the ARTICLE, not the loop:
///   - an encrypted article on a job with no decryption context is a
///     per-article decode error (`EncryptedUnsupported`), which lands on
///     the same refetch/repair machinery as any corrupt body;
///   - a failed Poly1305 tag is `DecryptAuth`, same machinery;
///   - the wire pcrc32 covered the CIPHERTEXT, so its VALUE must not be
///     reused once the buffer is plaintext (`verified_article_crc` goes
///     None and the commitment re-hashes), while `crc_checked` is set -
///     the tag authenticated these exact bytes, which is strictly
///     stronger than the CRC it replaces.
fn decode_and_decrypt(
    raw: &[u8],
    out: &mut Vec<u8>,
    verify_crc: bool,
    crypt: Option<&std::sync::Arc<nzbkit::yencrypt::JobCrypt>>,
    sidx: usize,
    id: &str,
) -> Result<(nzbkit::yenc::Meta, nzbkit::yenc_simd::DecodeIntegrity), nzbkit::yenc::YencError> {
    // Control-lines pre-pass (the same draft's FF1 half): an article
    // whose first line is not `=ybegin` may be a control-encrypted
    // block, and a successful trial decrypt rewrites it into an
    // ordinary article - possibly still body-encrypted - so everything
    // below runs unchanged. None means "not ours to rewrite": the
    // original bytes fall through and fail with the decoder's own
    // named error, same as any malformed article. The segmentIndex
    // comes from the message-id (there is no `=ypart` to read before
    // the rewrite), which is why this needs `id` and not just `sidx`.
    let restored;
    let raw = match crypt.and_then(|c| c.control_decrypt_article(id, raw)) {
        Some(r) => {
            restored = r;
            &restored[..]
        }
        None => raw,
    };
    let (dec, mut integrity) = nzbkit::yenc_simd::decode_into_integrity(raw, out, verify_crc)?;
    if let Some(enc) = dec.encryption {
        let crypt = crypt.ok_or(nzbkit::yenc::YencError::EncryptedUnsupported)?;
        let key = crypt.key_for(&enc.salt);
        let seg = crypt.segment_index(sidx, dec.part);
        if !nzbkit::yencrypt::decrypt_segment(&key, seg, &enc.tag, out) {
            return Err(nzbkit::yenc::YencError::DecryptAuth);
        }
        integrity.verified_article_crc = None;
        integrity.crc_checked = true;
    }
    Ok((dec, integrity))
}

/// Drop any bytes an article writes past its OWN declared file size,
/// truncating `out` in place and returning the article CRC that still
/// applies (`None` once truncated).
///
/// `=ybegin size=` is THIS article's claim of the whole-file length, and
/// its `=ypart` range must fall within it - a legitimate part of a larger
/// file would declare the larger size. A part whose decoded bytes run
/// past its own declared size is self-contradictory: a malformed or
/// hostile post. On the no-set path (no PAR2/FileDesc) nothing downstream
/// truncated the bogus tail, so a rogue trailing part declaring a huge
/// `begin` ballooned the delivered file far past its declared size while
/// the job still reported a clean download. Clamping to the article's own
/// size can never drop legitimate bytes on any path; a truncated span is
/// no longer vouched by the whole-article CRC.
fn clamp_to_declared_size(
    out: &mut Vec<u8>,
    dec: &nzbkit::yenc::Meta,
    article_crc: &mut Option<u32>,
) {
    if dec.file_size == 0 {
        return;
    }
    // Clamp in u64 BEFORE narrowing, the house rule at
    // `nzbkit::live::slotstate::head_want`: `(file_size - offset) as
    // usize` truncates on the shipped 32-bit
    // armv7-unknown-linux-musleabihf target, where the remaining room of
    // any file past 4 GiB wraps modulo 2^32. One article per 4 GiB
    // boundary per file then found a room of a few hundred kilobytes,
    // was cut to it and had its wire CRC discarded - a legitimate part
    // silently truncated, which is the corruption this clamp exists to
    // prevent rather than cause.
    let room = dec.file_size.saturating_sub(dec.offset());
    if out.len() as u64 > room {
        // Only reached once `room` is proved smaller than `out.len()`,
        // which is a `usize`, so this narrowing is exact on any width.
        out.truncate(room as usize);
        *article_crc = None;
    }
}

/// The byte range an article occupies in the in-memory PAR2 capture
/// mirror, or `None` when it runs past [`MAX_PAR2_CAPTURE`] and the
/// mirror must simply not take it.
///
/// A free function rather than three lines at the call site for the
/// reason [`clamp_and_commit`] is one - `decode_consumer_loop` sits at
/// its size ceiling - and because the cap has to be tested in u64
/// BEFORE anything narrows, the house rule at
/// `nzbkit::live::slotstate::head_want`. On the shipped 32-bit
/// `armv7-unknown-linux-musleabihf` build `offset as usize` wraps, so an
/// article at 4 GiB + 16 read as offset 16: it passed the cap it should
/// have failed and was mirrored over the head of the capture, handing
/// set activation a packet assembled from bytes four gigabytes away.
fn par2_capture_range(offset: u64, len: usize) -> Option<(usize, usize)> {
    let end = offset.saturating_add(len as u64);
    if end > MAX_PAR2_CAPTURE as u64 {
        return None;
    }
    // `end` is at most MAX_PAR2_CAPTURE, which is a `usize`, and `offset`
    // is at most `end`, so both narrowings are exact on any word size.
    Some((offset as usize, end as usize))
}

/// One decoded article's identity and geometry, as [`record_placement`]
/// reads it. A bundle rather than seven positional parameters, which is
/// what `clippy::too_many_arguments` (a `-D warnings` lint here) asks
/// for and what the existing [`LossLedgers`] bundle already does.
struct Placement<'a> {
    sidx: usize,
    /// Borrowed rather than cloned: the parking arms below clone it, and
    /// that clone is an `Arc` bump, not an allocation.
    id: &'a std::sync::Arc<str>,
    /// The name the span was WRITTEN under (`slot.write_name`), which is
    /// not always `dec.name` - see the GH #63 note at the call site.
    name: &'a str,
    dec: &'a nzbkit::yenc::Meta,
    out: &'a [u8],
    commitment: u32,
    par2_main: bool,
}

/// Where a placement's durability record goes: the journal, the
/// extractor it reads the slot's file info back from, and the two
/// parking lots for spans whose bytes are not on disk yet.
struct RecordSinks<'a> {
    journal: &'a nzbkit::journal::Journal,
    extractor: &'a nzbkit::extract::Extractor,
    pending_d: &'a std::sync::Mutex<Vec<PendingD>>,
    pending_r: &'a std::sync::Mutex<PendingR>,
}

/// Journal what the extractor made of this article's span: one
/// `Persist` verdict in, one record - or one PARKED record - out.
///
/// Moved verbatim out of [`decode_consumer_loop`]'s `Ok(persist)` arm
/// for the 500-line function ceiling. Every arm, and the order they are
/// tested in, is unchanged.
fn record_placement(
    persist: &nzbkit::extract::Persist,
    p: &Placement<'_>,
    sinks: &RecordSinks<'_>,
) {
    match persist {
        nzbkit::extract::Persist::Placed(frags) => {
            if p.par2_main {
                sinks.journal.record(p.id);
            } else {
                sinks.journal.record_placed(
                    p.sidx,
                    p.id,
                    sinks.extractor.slot_file_info(p.sidx),
                    p.name,
                    p.dec.file_size,
                    frags,
                    Some(p.commitment),
                );
            }
        }
        // Plaintext-once span: parked until its seam slivers are on disk
        // (usually one neighboring article later) - a D record for RAM-held
        // bytes would survive a kill the bytes did not.
        nzbkit::extract::Persist::PlacedCrypto(frags) => {
            sinks.pending_d.lock_ok().push((
                p.sidx,
                p.id.clone(),
                p.name.to_string(),
                p.dec.file_size,
                frags.clone(),
                Some(p.commitment),
            ));
        }
        // Bytes of this span were parked for a later re-feed: keep the
        // article's identity and finish its record when the drained placements
        // cover the span (see flush_pending_r).
        nzbkit::extract::Persist::Held(frags) => {
            if !p.out.is_empty() {
                sinks.pending_r.lock_ok().parked.push(ParkedR {
                    sidx: p.sidx,
                    id: p.id.clone(),
                    name: p.name.to_string(),
                    size: p.dec.file_size,
                    off: p.dec.offset(),
                    len: p.out.len() as u64,
                    frags: frags.clone(),
                    par2_main: p.par2_main,
                    crc: Some(p.commitment),
                });
            }
        }
        nzbkit::extract::Persist::No => {}
    }
}

/// Hand the decoded span on: into the in-memory PAR2 capture mirror for
/// a recovery slot, or into the live verifier for payload.
///
/// Moved verbatim out of [`decode_consumer_loop`] for the 500-line
/// function ceiling. `crc_checked` picks which verifier door, and the
/// capture arm's cap is [`par2_capture_range`] - both keep their
/// comments here.
fn feed_capture_or_verifier(
    slot: &FileSlot,
    sidx: usize,
    dec: &nzbkit::yenc::Meta,
    out: &[u8],
    crc_checked: bool,
    article_crc: Option<u32>,
    verifier: &nzbkit::live::LiveVerifier,
) {
    if slot.is_par2() {
        // Par2 main (or the sniffed in-stream bootstrap): mirror the bytes in
        // memory for mid-download set activation. A sniffed slot WITHOUT a
        // capture is a deferred volume - its stragglers are recovery data, not
        // payload, and stay out of the verifier.
        //
        // `off` is the article's declared yEnc `begin - 1`, clamped only to >=
        // 1 - never to the file size. Unlike the extractor's disk path (a
        // sparse write_all_at at a huge offset costs no RAM), this resize
        // ZERO-FILLS real memory, so one article declaring begin=10^15 in a
        // file whose name merely contains ".par2" allocated a petabyte and
        // aborted the daemon. A main .par2 packet is small; cap the mirror well
        // above any real one and drop the rest - an oversized "main" packet is
        // not a set we could have activated anyway. The cap, and the narrowing
        // it makes safe, are `par2_capture_range`.
        let mut cap = slot.capture.lock_ok();
        if let Some(buf) = cap.as_mut()
            && let Some((off, end)) = par2_capture_range(dec.offset(), out.len())
        {
            if buf.len() < end {
                // Memory-floor gauge: capture growth.
                nzbkit::memgauge::add(nzbkit::memgauge::Sub::Par2Capture, (end - buf.len()) as u64);
                buf.resize(end, 0);
            }
            buf[off..end].copy_from_slice(out);
        }
    } else if crc_checked {
        // The checked pcrc32 over exactly these bytes rides along (None
        // once the clamp above trimmed them): the verifier spends it on
        // the PAR2 blocks this article covers instead of hashing them
        // again (nzbkit::live's reuse section note).
        verifier.on_data_with_crc(
            sidx,
            &dec.name,
            dec.file_size,
            dec.offset(),
            out,
            article_crc,
        );
    } else {
        // CRC skipped (or absent): not decoder-vouched. Full MD5 under
        // delegation; CRC-only under lean (its contract).
        verifier.on_data_unverified(sidx, &dec.name, dec.file_size, dec.offset(), out);
    }
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
        loss,
        unasked_noted,
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
        yencrypt,
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
                    // Re-guard the body the moment it leaves the channel:
                    // the pool charged these bytes to its outstanding
                    // gauge at `take` and this drop is the matching
                    // release, on every one of the arms below. Charges
                    // nothing (the bytes are already outstanding) and
                    // costs no allocation.
                    let raw = pool.adopt(raw);
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
                    match decode_and_decrypt(
                        &raw,
                        &mut out,
                        !delegated,
                        yencrypt.as_ref(),
                        sidx,
                        &id,
                    ) {
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
                                continue;
                            }
                            // This article is now accounted for,
                            // whatever the write below makes of it.
                            fetch_done.fetch_add(nbytes, Ordering::Relaxed);
                            let (article_crc, commitment) =
                                clamp_and_commit(&mut out, &dec, integrity.verified_article_crc);
                            let crc_checked = integrity.crc_checked;
                            // Borrowed, not cloned: this runs per article on
                            // every decode thread, and the only consumers that
                            // need to OWN the name are the two park arms below,
                            // which are rare.
                            //
                            // GH #63: the yEnc header name is NOT
                            // automatically the better of the two. It won
                            // unconditionally here, with the subject as a
                            // fallback for a header carrying no name at all,
                            // and a poster who obfuscates the FILES and leaves
                            // the SUBJECT clean - the opposite polarity to
                            // #43/#47/#55 - therefore lost every name to a
                            // hash it had already read correctly. `write_name`
                            // takes the yEnc name unless it gives up a real
                            // posted name; `dec.name` still goes to the
                            // verifier below as the set-match key.
                            let name: &str = slot.write_name(&dec.name);
                            // M4-70 across a crash: a CONTESTED slot's
                            // tally has to outlive this run, or a resume
                            // rebuilds it empty and the decoy name
                            // stands. Empty for every ordinary slot.
                            journal.record_name_votes(sidx, &slot.contested_records(&dec.name));
                            // Issue #14: the offset-0 article of a
                            // payload-classified slot decoding to
                            // the PAR2 packet magic identifies
                            // recovery data with certainty (nothing
                            // else starts with it). Reclassify NOW,
                            // before the scheduler fetches any more
                            // of the volume. A short PREFIX in front
                            // of the magic does not hide it (M4-65) -
                            // `head_is_packet_file` is the one
                            // predicate the disk walk and the repair
                            // catalog sniff with too.
                            if !slot.is_par2()
                                && dec.offset() == 0
                                && nzbkit::par2::head_is_packet_file(&out)
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
                                // hashing them again. `None` when the span
                                // was clamped above (the CRC covered the
                                // full over-long payload, not the prefix).
                                article_crc,
                            ) {
                                Err(e) => {
                                    warn!(target: "get", "write {name}: {e}");
                                    note_write_fault(&loss.decode_error_sample, name, &e);
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
                                    record_placement(
                                        &persist,
                                        &Placement {
                                            sidx,
                                            id: &id,
                                            name,
                                            dec: &dec,
                                            out: &out,
                                            commitment,
                                            par2_main: slot.is_par2_main,
                                        },
                                        &RecordSinks {
                                            journal: &journal,
                                            extractor: &extractor,
                                            pending_d: &pending_d,
                                            pending_r: &pending_r,
                                        },
                                    );
                                    flush_pending_r(&pending_r, &extractor, &journal, false);
                                    // Flush every parked D whose bytes
                                    // have settled.
                                    flush_pending_d(&pending_d, &extractor, &journal);
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
                                    feed_capture_or_verifier(
                                        slot,
                                        sidx,
                                        &dec,
                                        &out,
                                        crc_checked,
                                        article_crc,
                                        &verifier,
                                    );
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
                                continue;
                            }
                            fetch_done.fetch_add(nbytes, Ordering::Relaxed);
                            warn!(target: "get", "decode error ({id}): {e}");
                            note_corrupt_fault(&loss.decode_error_sample, &e);
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
                    // Both buffers back to their pools HERE rather than at
                    // the end of this arm: the slot bookkeeping below can
                    // run for a while and the pools should be able to
                    // recycle across it.
                    drop(out);
                    drop(raw);
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
                    note_missing_cause(cause, rec, &loss, &unasked_noted);
                    par2.article_lost(&id, &id_to_slot, &fetch_done);
                }
                FetchOutcome::Failed { id, code, error } => {
                    loss.transport_failed
                        .add(is_recovery_article(&id, &id_to_slot, &slots));
                    // TODO 307 item 1: the pool now says WHICH KIND of
                    // failure this was as a value, so a reader no longer
                    // has to parse the sentence to learn it.
                    //
                    // Instrument-first, and deliberately so: nothing
                    // here reads `code` to CHANGE anything, because
                    // every one of these lands in `transport_failed`
                    // today and moving any of them to a different
                    // counter would move the verdict `incomplete_reason`
                    // writes - a policy change, which item 1 is not.
                    //
                    // What it buys now is the only reading of a lost
                    // article that does not go through a sentence.
                    // `fail_kind_of` answers off the CODE, so this line
                    // states the classification as recorded WHERE THE
                    // LOSS HAPPENED - against which the job's eventual
                    // verdict, re-derived from a message opening several
                    // files away, can be read. A log that says
                    // `transport` here and reports the post dead at the
                    // end is the 31 Jul 2026 stall, and until now
                    // nothing anywhere printed the first half. It also
                    // tells a link that failed (`Transport`,
                    // `ReadStall`) from our own fleet winding down under
                    // the run (`FleetExhausted`, `WorkerPanic`), which
                    // the counters cannot say.
                    //
                    // Logged with the sample and not per article: on a
                    // dead link that would be one line per segment.
                    let mut sample = loss.transport_sample.lock_ok();
                    if sample.is_none() {
                        let kind = crate::failkind::fail_kind_of(Some(code), &error);
                        debug!(
                            target: "get",
                            "first article loss: {code:?} ({}) - classified {} where it happened",
                            code.reason(),
                            crate::failkind::fail_kind_token(kind),
                        );
                        *sample = Some(error);
                    }
                    drop(sample);
                    par2.article_lost(&id, &id_to_slot, &fetch_done);
                }
            }
        }
    }
}

/// Charge one Missing article to the counter its cause names, and say
/// the one thing a count cannot.
///
/// A free function rather than three arms inline: `decode_consumer_loop`
/// SAT at its size-gate ceiling when this was hoisted out, and this is
/// the classification of a loss, which is a subject of its own. Past
/// tense on purpose - the hoist is what bought the margin, so a
/// present-tense claim here is false the moment it is written (that
/// function measures 470 of 500 on 31 Aug 2026).
///
/// `Unasked` is counted EXACTLY as `Gone` is, on purpose. `missing_430`
/// is what the repair planner and every verdict gate read, and moving a
/// loss between those counters is a policy change this is not - the
/// same reasoning `FailCode` is instrumented under at the `Failed` arm
/// of `decode_consumer_loop`, and for the same reason. What changes is that the run can now SAY it: the pool used to
/// report a fleet that shrank past an article as `Gone`, i.e. as
/// evidence about the post, when it is evidence about our own fleet
/// (27 Aug sweep finding 8). Wiring that into the failure summary's
/// copy is its own change with its own wording to settle; the typed
/// cause is the only reading of it that does not go through a sentence.
///
/// The ledgers arrive as one value ([`LossLedgers`]) rather than as
/// four `&CauseSplit` in a row, and that is the point: four identical
/// references accept any permutation of themselves without a word from
/// the compiler, and this is the function that DECIDES which ledger a
/// loss lands in. A swap here misfiles the loss at the moment it is
/// charged, so nothing downstream can ever tell.
fn note_missing_cause(
    cause: nzbkit::pool::MissingCause,
    rec: bool,
    loss: &LossLedgers,
    unasked_noted: &std::sync::atomic::AtomicBool,
) {
    let takedown = match cause {
        nzbkit::pool::MissingCause::Retention => {
            loss.retention_excluded.add(rec);
            return;
        }
        nzbkit::pool::MissingCause::Gone { takedown } => takedown,
        nzbkit::pool::MissingCause::Unasked { takedown, dark } => {
            // The share the failure summary needs to tell a departure
            // from a dead post. Charged BESIDE `missing_430` below and
            // never instead of it - see `diag::LossCauses::unasked_430`.
            loss.unasked_430.add(rec);
            // Once per run, not once per article: a post that outlives
            // a server is hundreds of articles wide and this is one
            // fact about the run, not one fact about each of them.
            if !unasked_noted.swap(true, Ordering::Relaxed) {
                warn!(
                    target: "get",
                    "{dark} server(s) stopped serving before some articles reached them. \
                     Those articles count as missing, but no server that could still \
                     answer was asked for them - another attempt once the server is back \
                     may well find them.",
                );
            }
            takedown
        }
    };
    loss.missing_430.add(rec);
    // The hint rides its own counter so the failure summary can say
    // "removed", and stays inside missing_430 for everything else - a
    // takedown is still a refusal.
    if takedown {
        loss.takedown_430.add(rec);
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
    #[cfg(test)]
    assert_mem_sampler_serialized("spawn_mem_sampler");
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
    #[cfg(test)]
    assert_mem_sampler_serialized("stop_mem_sampler");
    let _ = MEM_SAMPLER_RUN.compare_exchange(run, run + 1, Ordering::Relaxed, Ordering::Relaxed);
}

/// Serializes the unit tests that drive [`MEM_SAMPLER_RUN`].
///
/// The token is process-global and the tests assert on its ABSOLUTE
/// value, so two of them on different threads of one process read each
/// other's bumps. nextest cannot see that - it gives every test its own
/// process - but `cargo test -p nzbfast --bin nzbfast` and CI's
/// `unit-one-process` job put ~1850 tests in ONE, and there
/// `stopping_an_old_sampler_leaves_the_new_one_running` failed 73 runs
/// in 200 (24 Aug 2026, mac dev box: `left: 5, right: 4` - a neighbour's
/// spawn landing between this test's own two). Latent since the three
/// tests were written (bug sweep 22 Aug 2026, F-19); the same shape as
/// the `crate::wall` / `crate::ratelimit` cooldown-table collision fixed
/// in a29a8e4cc.
///
/// Take it with [`serialize_mem_sampler_tests`] as the FIRST statement of
/// any test that spawns or stops a sampler. That is not a convention to
/// remember: [`spawn_mem_sampler`] and [`stop_mem_sampler`] assert the
/// guard is held on this thread, so a fourth test that forgets it panics
/// by name on its first call rather than flaking on somebody else's run.
#[cfg(test)]
static MEM_SAMPLER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
thread_local! {
    /// Whether THIS thread is the one holding [`MEM_SAMPLER_TEST_LOCK`].
    ///
    /// The mutex alone cannot answer that - `try_lock` failing means
    /// someone holds it, not that you do - and "you" is the whole
    /// question the assertion asks.
    static MEM_SAMPLER_TEST_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The guard: releases the mutex and clears the thread's flag together,
/// so an assertion inside a test that panics cannot leave the next test
/// looking serialized when it is not.
#[cfg(test)]
pub(crate) struct MemSamplerTestGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for MemSamplerTestGuard {
    fn drop(&mut self) {
        MEM_SAMPLER_TEST_HELD.with(|h| h.set(false));
    }
}

/// Claim [`MEM_SAMPLER_TEST_LOCK`] for this test. Declare it FIRST, so
/// it drops LAST - after every `MemSampler` the test owns, whose own
/// drop unregisters a row the next test is about to census.
///
/// Poison-recovering (`lock_ok`, not `unwrap`): one test failing an
/// assertion must report itself, not turn its two neighbours red too.
#[cfg(test)]
pub(crate) fn serialize_mem_sampler_tests() -> MemSamplerTestGuard {
    use nzbkit::sync::MutexExt;
    let lock = MEM_SAMPLER_TEST_LOCK.lock_ok();
    MEM_SAMPLER_TEST_HELD.with(|h| h.set(true));
    MemSamplerTestGuard { _lock: lock }
}

/// The pin. See [`MEM_SAMPLER_TEST_LOCK`].
#[cfg(test)]
fn assert_mem_sampler_serialized(what: &str) {
    assert!(
        MEM_SAMPLER_TEST_HELD.with(|h| h.get()),
        "{what} touches the process-global MEM_SAMPLER_RUN token, so a unit test \
         that reaches it must serialize against every other one that does: take \
         `let _serial = serialize_mem_sampler_tests();` as the test's first statement"
    );
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
    /// Every recovery volume the NZB declares, as
    /// `(count read off the name, encoded bytes)` - see
    /// [`declared_volumes`]. Summed into a block total in [`Self::project`]
    /// once the set is live, which is what the post PROMISES rather than
    /// what has reached disk.
    pub(super) volumes: Vec<(Option<usize>, u64)>,
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
    // A post that declares NO recovery at all is one whose volumes
    // subject-line classification could not see - obfuscated names, the
    // in-stream magic sniff - not one where any damage is fatal.
    // Without this the comparison below is `projected >= 0`, which is
    // always true, so the warning fires on every such job the moment
    // the sample gates pass.
    if declared == 0 {
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
        // ONE representative set, deliberately (TODO 311): this is a
        // projection stated in blocks, and a post whose sets disagree
        // about block size has no single figure to state it in. The
        // largest set is `sets()[0]` by construction, so a per-file-set
        // post is projected in the block size of the set covering the
        // most of it - the same number this read before every set was
        // adopted, and the fraction it feeds is counted off SEGMENTS
        // rather than off that set's own files.
        let set = self.verifier.sets().into_iter().next()?;
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
        // What the post declares, in blocks. A volume whose NAME does
        // not size it (the `.vol-NN.par2` form) is sized from its bytes
        // instead - the same estimate `repair::recovery_candidates`
        // makes, and never the ladder's floor of 1, which would
        // undercount the cure and fire this warning on a post that
        // repairs comfortably.
        let declared: usize = self
            .volumes
            .iter()
            .map(|&(count, bytes)| {
                count.unwrap_or_else(|| {
                    nzbkit::par2::est_recovery_blocks(bytes, set.block_size).max(1)
                })
            })
            .sum();
        project_damage(resolved, planned, now, live_bad as usize, declared)
    }
}
/// Record the run's FIRST decode-or-write fault, with the fault this
/// site knows it hit rather than the opening words of the sentence it
/// writes. See [`crate::diag::DecodeFault`] for what deriving it from
/// the sentence downstream used to cost.
///
/// The two doors are separate functions rather than one taking a
/// `DecodeFault`, so neither call site can pass the wrong one: `name`
/// is a thing only a write has, and there is no argument at either
/// call that selects between them. First writer wins, so the sample is
/// the run's opening failure and not its last.
fn note_write_fault(
    sample: &crate::diag::DecodeSampleCell,
    name: &str,
    e: &(impl std::fmt::Display + ?Sized),
) {
    sample
        .lock_ok()
        .get_or_insert_with(|| crate::diag::DecodeSample::write(format!("write {name}: {e}")));
}

/// [`note_write_fault`]'s twin for a body that ARRIVED and failed its
/// own yEnc check: the server's copy is wrong, not this machine's disk,
/// and the remedy is a re-fetch (often from a second provider) rather
/// than free space and permissions.
fn note_corrupt_fault(
    sample: &crate::diag::DecodeSampleCell,
    e: &(impl std::fmt::Display + ?Sized),
) {
    sample
        .lock_ok()
        .get_or_insert_with(|| crate::diag::DecodeSample::corrupt(format!("decode error: {e}")));
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

// The recovery-side speculation - the M2c.5 speculative recovery
// prefetch and its ladder, the dark PAR2-race experiment, and the
// §146 tail give-up - is one subject and came out whole (TODO 106,
// 24 Aug 2026). `declared_volumes` is re-exported because get/mod.rs
// prices a job's declared recovery off it by the `workers::` path.
mod recovery;
pub(super) use recovery::declared_volumes;
use recovery::{par_race_missing_blocks, spawn_par_race, spawn_spec_prefetch, spawn_tail_giveup};

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
    // Every open write-coalescing run goes to disk HERE, before the
    // journal lands its last batch and before anything reads an output
    // by name (`FileWriter::flush_staged` says why the readers cannot
    // do it for themselves: settle's read-back, the native repair's
    // PAR2 scan and the unpack step all open the file by PATH). This is
    // the one point in a job where "the download is over" is a fact
    // rather than a guess, and it is deliberately ahead of
    // `journal.flush()` below - a placement record that outlived its
    // bytes would tell a resume that a hole is payload.
    //
    // A failure is reported and not swallowed: it is the same class as
    // any other write failure and settle will fail the file it belongs
    // to on its own read-back, but the log is what says WHY.
    // LOWER THE FEEDING SIGNAL FIRST, THEN FLUSH - the order is
    // load-bearing (round 44, `Extractor::set_feeding`). The other way
    // round leaves a window in which a late article stages bytes into a
    // writer this loop has already passed, and those bytes would then be
    // held for a promise nobody is keeping any more. Lowered here, the
    // worst a straggler can do is take its own positioned write, which
    // is what it did before the window existed.
    extractor.set_feeding(false);
    for (name, w) in extractor.writers_snapshot() {
        if let Err(e) = w.flush_staged() {
            warn!(target: "extract", "{name}: staged bytes failed to land: {e}");
        }
    }
    // Final held-article flush: holds that drained after the last
    // article's own flush pass (settle-triggered reresolves, the tail
    // of an out-of-order set) journal now; anything still parked
    // refetches on resume, which is exactly the truthful record.
    flush_pending_r(pending_r, extractor, journal, true);
    // The network phase is over: land the placement batch the journal
    // was still holding (the decoders' idle flush covers a stall, this
    // covers the end).
    journal.flush();
    // Final D-record flush: seams that closed after the last article's
    // own flush pass settle now; anything still RAM-held refetches on
    // resume, which is exactly the truthful record.
    flush_pending_d(pending_d, extractor, journal);
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

/// The five loss ledgers the failure summary is built from, plus the
/// two first-error samples that illustrate them.
///
/// ONE VALUE, built once in [`build_counters`] and never re-assembled,
/// because all five are `Arc<CauseSplit>` and every consumer of them is
/// a positional argument list. Any two swapped compiles clean and
/// misfiles a whole loss class: a flaky provider reported as a
/// takedown, all the way out to the indexer failure report. That is not
/// a hypothetical - `spawn_decode_consumers` carried exactly that
/// hazard across 32 positional arguments until 31 Aug 2026
/// (`a2529f9ee`), and `get::tail`'s `finish_run` and `finish_job`
/// carried it for another day after that.
///
/// NESTED INSIDE [`Counters`] rather than flat in it, and that is
/// load-bearing rather than tidy: the orchestrator moves `counters.tx`
/// into `run_fetch`, so `&counters` is a borrow of a partially-moved
/// value from there on and cannot be handed to the tail. A borrow of
/// one FIELD still can, which is what lets the bundle reach the two
/// functions that most need it.
///
/// Do NOT explode this back out into positional parameters, and do not
/// re-assemble it field by field at a call site - a hand-built copy
/// puts the swap straight back, just louder.
///
/// `Clone` because the decode fleet takes one per thread; every field
/// is a handle, so a clone shares the same ledgers. `Default` is the
/// all-empty set the `finish_job` cases pass when the ledgers are not
/// what they are about - safe here where a blank `Census` is not,
/// because an empty ledger is a truthful "nothing was charged".
#[derive(Clone, Default)]
pub(super) struct LossLedgers {
    /// Segments the pool never asked anyone for: outside every
    /// configured server's retention window.
    pub(super) retention_excluded: Arc<CauseSplit>,
    /// A real 430 verdict from a complete fleet.
    pub(super) missing_430: Arc<CauseSplit>,
    /// Of those, the ones whose refusal SAID the article was removed.
    pub(super) takedown_430: Arc<CauseSplit>,
    /// And of those, the ones no COMPLETE fleet ever voted on.
    pub(super) unasked_430: Arc<CauseSplit>,
    /// The provider flaked, which is the opposite remedy to a takedown.
    pub(super) transport_failed: Arc<CauseSplit>,
    /// First transport error seen, for the failure summary to quote.
    pub(super) transport_sample: Arc<std::sync::Mutex<Option<String>>>,
    /// First decode error seen, same purpose.
    pub(super) decode_error_sample: crate::diag::DecodeSampleCell,
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
    /// The loss ledgers, nested rather than flat: see [`LossLedgers`].
    pub(super) loss: LossLedgers,
    pub(super) unasked_noted: Arc<std::sync::atomic::AtomicBool>,
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
    // And of those, the ones no COMPLETE fleet ever voted on: a server
    // that had been serving went out before the article reached it, so
    // the survivors' 430s went unanimous over a shrunken quorum
    // (`pool::MissingCause::Unasked`). Its own counter purely so the
    // failure summary can say what the departure cost - it stays inside
    // `missing_430` for every count and verdict, exactly as
    // `takedown_430` does.
    let unasked_430 = Arc::new(CauseSplit::default());
    // Said ONCE per run, not once per article: a post that outlives a
    // server is hundreds of articles wide and the fact is one fact.
    // Separate from the counter above because the counter cannot answer
    // "was this the first" without a race - two decode threads charging
    // it at once would both read zero and both warn.
    let unasked_noted: Arc<std::sync::atomic::AtomicBool> = Default::default();
    let transport_failed = Arc::new(CauseSplit::default());
    // First error of each kind, verbatim, for the failure summary to
    // quote - the counter alone says nothing a bug report can act on.
    let transport_sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
    let decode_error_sample: crate::diag::DecodeSampleCell = Default::default();
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
        loss: LossLedgers {
            retention_excluded,
            missing_430,
            takedown_430,
            unasked_430,
            transport_failed,
            transport_sample,
            decode_error_sample,
        },
        unasked_noted,
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
///
/// [`Counters`] arrives WHOLE rather than field by field, and that is
/// the one thing here worth reading twice (31 Aug 2026). Sixteen of
/// this function's parameters were fields of that one struct, and five
/// of them - `retention_excluded`, `missing_430`, `takedown_430`,
/// `unasked_430`, `transport_failed` - are the same `Arc<CauseSplit>`
/// type, so any two swapped at the call site compiled clean and
/// misfiled a whole loss class in the failure summary. Passing the
/// bundle takes that hazard away entirely, and it is why the
/// orchestrator no longer destructures `Counters` onto inline names the
/// way it does the other phase bundles: the fields it still reads
/// itself are spelled `counters.x` there. Do NOT explode this back out.
///
/// Those five now live one level down, in [`LossLedgers`], so the same
/// bundle can also reach `get::tail`'s `finish_run` and `finish_job` -
/// which took them positionally for another day after this fix landed.
/// The nesting's own reasoning is at that struct.
#[expect(clippy::too_many_arguments)]
pub(super) fn spawn_decode_consumers(
    decoders: usize,
    c: &Counters,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    out_pool: &Arc<nzbkit::pool::BufPool>,
    slots: &[Arc<FileSlot>],
    id_to_slot: &Arc<crate::unpack::IdSlots>,
    seek_names: &Arc<SeekCtl>,
    fetch_done: &Arc<AtomicU64>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    shape_said: &Arc<std::sync::atomic::AtomicBool>,
    par2_outstanding: &Arc<std::sync::atomic::AtomicUsize>,
    journal: &Arc<nzbkit::journal::Journal>,
    sniff: &Arc<SniffCtl>,
    replay: &Arc<super::rig::ReplayPending>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    crc_steer: bool,
    yencrypt: &Option<std::sync::Arc<nzbkit::yencrypt::JobCrypt>>,
) -> (
    Vec<std::thread::JoinHandle<()>>,
    Arc<std::sync::Mutex<Vec<PendingD>>>,
    Arc<std::sync::Mutex<PendingR>>,
) {
    let mut consumers = Vec::new();
    // RAISE THE FEEDING SIGNAL (round 44). This is the point where both
    // halves of what `Extractor::set_feeding` asks a caller to promise
    // become true at once: decode threads are about to start delivering
    // articles to this job's outputs, and nothing will open one of those
    // outputs BY NAME until `finish_workers` lowers this again and
    // flushes every writer's staged runs - which it does ahead of
    // settle's read-back, the native repair's PAR2 scan, the unpack step
    // and the journal's last batch. Raised here rather than at the rig
    // so the two edges sit in one file and a reader can see they pair.
    extractor.set_feeding(true);
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
    // boxes get one per core. `cpu_workers` rather than
    // `available_parallelism` so a launcher that knows better than the
    // core count - a phone, where half the cores are little ones sharing
    // one thermal envelope - can say so (TODO 281 AN4).
    let n_decoders = decoders.max(1).min(nzbkit::mem::cpu_workers());
    for i in 0..n_decoders {
        let ctx = DecodeCtx {
            rx: c.rx.clone(),
            pending_d: pending_d.clone(),
            pending_r: pending_r.clone(),
            pool: buf_pool.clone(),
            out_pool: out_pool.clone(),
            slots: slots.to_vec(),
            id_to_slot: Arc::clone(id_to_slot),
            seek_names: seek_names.clone(),
            decoded_bytes: c.decoded_bytes.clone(),
            fetch_done: fetch_done.clone(),
            decode_errors: c.decode_errors.clone(),
            loss: c.loss.clone(),
            unasked_noted: c.unasked_noted.clone(),
            disk_full_sample: c.disk_full_sample.clone(),
            verifier: verifier.clone(),
            extractor: extractor.clone(),
            shape_said: shape_said.clone(),
            par2_outstanding: par2_outstanding.clone(),
            journal: journal.clone(),
            backfill: c.backfill.clone(),
            sniff: sniff.clone(),
            replay: replay.clone(),
            queue_ctl: queue_ctl.clone(),
            rt: c.rt.clone(),
            throttle_mbps: c.throttle_mbps,
            throttle_t0: c.throttle_t0,
            crc_steer,
            yencrypt: yencrypt.clone(),
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
    // §146 starvation signal: TRUE once the spec-prefetch ladder can
    // never deliver another slice, so the give-up's veto stops being a
    // wait for it. See both spawns' parameter docs.
    let ladder_over = Arc::new(std::sync::atomic::AtomicBool::new(false));
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
            &ladder_over,
        )
    };
    if spec_prefetch_task.is_none() {
        // No ladder exists at all (prefetch disallowed, no main pool,
        // or the post declares no recovery volumes) - nothing will
        // ever raise `on_hand` from this side, and the give-up must
        // not wait for a task that was never spawned.
        ladder_over.store(true, Ordering::Release);
    }
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
        &ladder_over,
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
mod commitment_tests {
    use super::*;

    /// X5-02: EVERY article gets a commitment, whatever the wire gave
    /// us. This is the pin for the gap that nearly shipped - the first
    /// cut recorded `integrity.verified_article_crc` straight through,
    /// and that is `None` for a post with no `pcrc32`, for a delegated
    /// check, for the bare-LF fallback, and for every clamped article.
    /// Each of those would have refetched on every resume, which is the
    /// full-refetch outcome the commitment exists to avoid.
    #[test]
    fn every_article_gets_a_commitment_verified_or_computed() {
        let out: Vec<u8> = (0..9_000u32).map(|i| (i % 251) as u8).collect();
        let own = crc32fast::hash(&out);

        // Nothing from the wire: computed over exactly these bytes.
        assert_eq!(content_commitment(None, &out), own);
        // A verified pcrc32 IS that same quantity, so reusing it and
        // computing it are the same number - which is what makes the
        // fallback safe rather than merely cheap.
        assert_eq!(content_commitment(Some(own), &out), own);
        // And the wire value is preferred when present: a (contrived)
        // disagreement resolves to the wire's, because that is the one
        // the decode actually checked the bytes against.
        assert_eq!(content_commitment(Some(0xDEAD_BEEF), &out), 0xDEAD_BEEF);
    }

    /// A clamped article commits to what was KEPT, not to what the
    /// poster declared. `clamp_to_declared_size` clears the wire CRC
    /// precisely because it no longer describes the bytes on disk, and
    /// the computed fallback is what makes that safe instead of
    /// unresumable.
    #[test]
    fn a_clamped_article_commits_to_the_bytes_it_kept() {
        // A real decode, because `Meta`'s offset fields are nzbkit's own
        // and a hand-built one would be testing a struct literal rather
        // than the path this runs on. The post DECLARES 5 000 bytes and
        // delivers 9 000 - self-contradictory, which is what the clamp
        // exists for.
        let payload: Vec<u8> = (0..9_000u32).map(|i| (i % 251) as u8).collect();
        let art = nzbkit::yenc::encode("a.bin", 5_000, Some((1, 1)), 1, &payload);
        let mut out = Vec::new();
        let (dec, integrity) =
            nzbkit::yenc_simd::decode_into_integrity(&art, &mut out, true).unwrap();
        assert_eq!(out.len(), 9_000, "the over-long payload decodes whole");
        let mut article_crc = integrity.verified_article_crc;
        assert!(
            article_crc.is_some(),
            "the fixture must carry a checked pcrc32, or the clamp has \
             nothing to clear and this test proves nothing"
        );
        clamp_to_declared_size(&mut out, &dec, &mut article_crc);
        assert_eq!(out.len(), 5_000, "the over-long tail is dropped");
        assert_eq!(article_crc, None, "the posted CRC no longer applies");
        assert_eq!(
            content_commitment(article_crc, &out),
            crc32fast::hash(&out),
            "the commitment covers the truncated span, so the article \
             still resumes"
        );
    }

    /// The other side of that clamp, and the one no box on this fleet
    /// can regress: a LEGITIMATE part of a file bigger than 4 GiB keeps
    /// every byte it delivered.
    ///
    /// `(file_size - offset) as usize` narrowed BEFORE the comparison,
    /// and `usize` is 32 bits on the shipped
    /// `armv7-unknown-linux-musleabihf` beta, where nightly's
    /// `armv7-cross` job runs this suite under qemu. The remaining room
    /// of any file past 4 GiB wraps modulo 2^32 there, so exactly one
    /// article per 4 GiB boundary per file - the one whose remaining
    /// room lands in `[2^32, 2^32 + article_len)` - saw a room of a few
    /// bytes, was truncated to it and had its wire CRC cleared. With
    /// PAR2 that silently spends a recovery block per crossing; without
    /// it the span is never written and the job still reports clean.
    ///
    /// The fixture puts the article exactly in that window: a 5 GiB file
    /// with 4 GiB + 16 bytes of room left, delivering 64 KiB. On a
    /// 64-bit host the assertion is a tautology, deliberately so - the
    /// `narrowed` arm below spells the pre-fix arithmetic at 32-bit
    /// width against `u32`, so it is the same statement wherever it
    /// runs, and the target that the order matters on is not left
    /// pinned by nothing.
    ///
    /// It WAS demonstrated to bite, which a tautology otherwise cannot
    /// be: narrowing the site itself to `as u32 as usize` - the word
    /// armv7 actually has - and restoring the pre-fix order failed this
    /// test with 16 bytes kept of 65,536, and the fixed order passed
    /// under that same simulated word. Do not leave that experiment in
    /// the tree; it is how the pin was checked, not what it asserts.
    #[test]
    fn a_legitimate_part_past_four_gibibytes_is_not_clamped() {
        const FILE_SIZE: u64 = 5 << 30;
        const LEN: usize = 64 << 10;
        // Room left = 2^32 + 16: over a 32-bit word, and by less than
        // this article is long, which is the whole trigger window.
        let offset = FILE_SIZE - ((1u64 << 32) + 16);
        let room = FILE_SIZE - offset;

        // What the pre-fix narrowing computed once `usize` is 32 bits.
        let narrowed = (room as u32) as usize;
        assert!(
            narrowed < LEN,
            "the fixture must sit in the wrap window, or it pins nothing \
             ({narrowed} vs {LEN})"
        );

        let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        let art = nzbkit::yenc::encode("big.bin", FILE_SIZE, Some((1, 2)), offset + 1, &payload);
        let mut out = Vec::new();
        let (dec, integrity) =
            nzbkit::yenc_simd::decode_into_integrity(&art, &mut out, true).unwrap();
        assert_eq!(dec.offset(), offset, "the fixture places the part itself");
        assert_eq!(dec.file_size, FILE_SIZE);
        let mut article_crc = integrity.verified_article_crc;
        assert!(
            article_crc.is_some(),
            "the fixture must carry a checked pcrc32, or a cleared CRC \
             proves nothing"
        );

        clamp_to_declared_size(&mut out, &dec, &mut article_crc);

        assert_eq!(
            out.len(),
            LEN,
            "a part that fits inside its own declared size keeps every byte"
        );
        assert_eq!(out, payload, "and they are the bytes that were posted");
        assert!(
            article_crc.is_some(),
            "nothing was dropped, so the posted CRC still describes the span"
        );
    }

    /// The same order rule at the PAR2 capture mirror: the cap is tested
    /// in u64, so an article far past it cannot narrow its way in.
    ///
    /// `dec.offset() as usize` wrapped on a 32-bit target, so an article
    /// at 4 GiB + 16 read as offset 16, passed the 256 MiB cap and was
    /// copied over the HEAD of the capture - the bytes set activation
    /// then parses as the main packet. Packets are MD5-verified, so the
    /// cost is a set that never activates rather than corrupt output,
    /// but the mirror is wrong either way.
    #[test]
    fn the_par2_capture_ignores_an_article_past_four_gibibytes() {
        // The ordinary case is untouched, including the exact boundary.
        assert_eq!(par2_capture_range(0, 4096), Some((0, 4096)));
        let last = MAX_PAR2_CAPTURE as u64 - 4096;
        assert_eq!(
            par2_capture_range(last, 4096),
            Some((last as usize, MAX_PAR2_CAPTURE))
        );
        assert_eq!(par2_capture_range(last, 4097), None, "one byte over is out");

        // The 32-bit shape. Spelled against `u32` so this arm is the
        // same arithmetic wherever it runs: the pre-fix expression would
        // have accepted the article at an offset four gigabytes from the
        // one it named.
        let far = (1u64 << 32) + 16;
        let wrapped = (far as u32) as usize;
        assert!(
            wrapped + 4096 <= MAX_PAR2_CAPTURE,
            "the pre-fix narrowing really did let this one through"
        );
        assert_eq!(
            par2_capture_range(far, 4096),
            None,
            "an article past the cap stays out of the mirror on every width"
        );
        // And a huge declared begin still saturates rather than wrapping,
        // which is the petabyte-resize case the cap was added for.
        assert_eq!(par2_capture_range(u64::MAX, 4096), None);
    }
}

#[cfg(test)]
mod missing_cause_tests {
    use super::*;
    use nzbkit::pool::MissingCause;

    /// The contract `note_missing_cause` carries and no other test can
    /// see: `Unasked` is charged BESIDE `missing_430`, never instead of
    /// it.
    ///
    /// `missing_430` is what the repair planner and every verdict gate
    /// in `diag` read, so moving a loss out of it would be a POLICY
    /// change - the standing rule is the memory topic
    /// `nzbfast-retry-propagation-trap`: say it in the message, keep
    /// the classification. `takedown_430` is the shipped precedent and
    /// is asserted here beside it, because the two ride together on an
    /// `Unasked { takedown: true }`: a server DID name a takedown, it
    /// just was not the whole fleet that refused.
    ///
    /// Without this the summary clause has nothing behind it. Every
    /// other pin on this work drives `diag::incomplete_reason` with a
    /// hand-built `LossCauses`, so a `note_missing_cause` that stopped
    /// charging the counter would leave all of them green and the
    /// clause silent on every real run.
    #[test]
    fn an_unasked_loss_is_charged_beside_the_refusal_it_still_is() {
        // Named fields, so the four ledgers cannot be transposed here
        // either - which is the whole reason the function takes them as
        // one value. `.payload()` is then read off the SAME handle the
        // charge went to.
        let led = LossLedgers::default();
        let (missing, takedown, unasked) = (&led.missing_430, &led.takedown_430, &led.unasked_430);
        let noted = std::sync::atomic::AtomicBool::new(false);
        let note = |cause| note_missing_cause(cause, false, &led, &noted);
        note(MissingCause::Gone { takedown: false });
        note(MissingCause::Unasked {
            takedown: false,
            dark: 1,
        });
        note(MissingCause::Unasked {
            takedown: true,
            dark: 2,
        });
        assert_eq!(missing.payload(), 3, "every one of them is still a refusal");
        assert_eq!(unasked.payload(), 2);
        assert_eq!(
            takedown.payload(),
            1,
            "a takedown named on an unasked loss is still a takedown"
        );
        // Retention is the one cause that is NOT a refusal: it returns
        // before any of the three counters above.
        note_missing_cause(MissingCause::Retention, false, &led, &noted);
        assert_eq!(led.retention_excluded.payload(), 1);
        assert_eq!(missing.payload(), 3);
    }

    /// The recovery/payload split is taken here, where the slot is
    /// still in hand, and `unasked_430`'s recovery half is DISCARDED at
    /// the `LossCauses` literal on purpose (see the field's doc comment
    /// in `diag.rs`). It still has to be counted on the right side, or
    /// a `.par2` article's loss would land in the payload figure the
    /// summary clause prints.
    #[test]
    fn a_recovery_articles_unasked_loss_is_not_payload() {
        let led = LossLedgers::default();
        let noted = std::sync::atomic::AtomicBool::new(false);
        note_missing_cause(
            MissingCause::Unasked {
                takedown: false,
                dark: 1,
            },
            true,
            &led,
            &noted,
        );
        assert_eq!(led.unasked_430.payload(), 0);
        assert_eq!(led.unasked_430.recovery(), 1);
        assert_eq!(led.missing_430.recovery(), 1);
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

    /// The pairing [`note_write_fault`] and [`note_corrupt_fault`]
    /// exist to make un-mistakable: each records the fault its own call
    /// site knows it hit, and the sentence it writes goes with it.
    ///
    /// Before 26 Aug 2026 `diag` rebuilt this from
    /// `sample.starts_with("decode error")`, so an edited opening moved
    /// a machine's disk fault into "the copies on the server are
    /// corrupt" with nothing anywhere going red. The end-to-end proof
    /// that the CORRUPT door really is the one a bad yEnc check reaches
    /// is `e2e_faults` shape 15; this is the doors themselves.
    #[test]
    fn each_decode_fault_door_records_its_own_fault_and_the_first_wins() {
        use crate::diag::DecodeFault;
        let sample: crate::diag::DecodeSampleCell = Default::default();
        note_corrupt_fault(&sample, "pcrc32 mismatch");
        {
            let s = sample.lock_ok();
            let s = s.as_ref().unwrap();
            assert_eq!(s.fault, DecodeFault::Corrupt);
            assert_eq!(s.text, "decode error: pcrc32 mismatch");
        }
        // First writer wins: a later fault of the OTHER kind must not
        // repaint the run's opening failure, or a job that hit one
        // corrupt article and then filled its disk reports the wrong
        // remedy for the wrong one.
        note_write_fault(&sample, "a.r01", "No space left on device");
        assert_eq!(
            sample.lock_ok().as_ref().unwrap().fault,
            DecodeFault::Corrupt
        );

        let other: crate::diag::DecodeSampleCell = Default::default();
        note_write_fault(&other, "a.r01", "Permission denied");
        let s = other.lock_ok();
        let s = s.as_ref().unwrap();
        assert_eq!(s.fault, DecodeFault::Write);
        assert_eq!(s.text, "write a.r01: Permission denied");
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
            hint_is_posted_name: nzbkit::release::stem_is_a_name(hint),
            yenc_votes: Default::default(),
            name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
            is_par2_main: par2,
            sample_skipped: false,
            par2_name_demoted: Default::default(),
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

// Y4: the two recovery-slice COUNTERS against the one selection
// predicate. Here rather than beside either of them because this is the
// only scope that can see both halves at once.
#[cfg(test)]
mod slice_len_tests;
