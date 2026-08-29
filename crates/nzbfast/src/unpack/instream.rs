//! The download-side half of `unpack`: everything here belongs to a job
//! while it is still FETCHING, where the rest of the parent is about the
//! directory once it has finished arriving.
//!
//! Three subjects and one currency between them - what the run knows
//! about its recovery set before that set is live:
//!
//! * [`FileSlot`], the per-file runtime state every decode consumer, the
//!   census, the settle pass and the queue APIs read.
//! * Issue #14's in-stream PAR2 identification - [`SniffCtl`],
//!   [`reclassify_sniffed_par2`], [`reconcile_deferred_payload`] - which
//!   reclassifies a payload-classified slot whose offset-0 article
//!   decoded to the `PAR2\0PKT` magic, defers the rest of the set, and
//!   un-defers whatever the activated FileDesc table proves was payload
//!   after all.
//! * M15b's pre-activation backfill and [`maybe_activate_par2`], which
//!   hash spans decoded before the set went live WHILE the download
//!   continues, rather than in the settle read-back.
//!
//! Plus [`nzb_age_days`], the post-age helper the plan, the census and
//! the retention side-fetch read - the one thing here a job consults
//! before it has fetched anything at all.
//!
//! Split out of `unpack.rs` (TODO 106 size gate) along the seam the
//! parent's own `get - the downloader (PLAN M1)` banner already drew.
//! Callers reach every item through the parent's `pub(crate) use`, so no
//! path outside this file changed.

use super::*;

pub(crate) struct FileSlot {
    pub(crate) hint: String,
    /// GH #63: `hint` came from the POST and is a name worth reading.
    /// Decided at plan time, not sniffed back off `hint`. See
    /// [`slot_name`] for what both of these are for.
    pub(crate) hint_is_posted_name: bool,
    /// Latched answer to "which name is this slot's file written
    /// under" - see [`slot_name`].
    pub(crate) name_choice: std::sync::atomic::AtomicU8,
    pub(crate) is_par2_main: bool,
    /// Issue #14: this slot was posted as payload (hash subject, hash yEnc
    /// name) but its offset-0 article decoded to the `PAR2\0PKT` magic -
    /// it IS recovery data, identified in-stream after the slot was built.
    /// Set once by whichever decode consumer sees the head article; never
    /// cleared.
    pub(crate) par2_sniffed: std::sync::atomic::AtomicBool,
    pub(crate) total_segments: usize,
    pub(crate) remaining: std::sync::atomic::AtomicUsize,
    pub(crate) missing: std::sync::atomic::AtomicUsize,
    /// Decode or write failures charged to THIS slot. The global
    /// `decode_errors` counter says a job hit one; only a per-slot count can
    /// say whether the file a PAR2 repair just healed is the one that hit it.
    pub(crate) errors: std::sync::atomic::AtomicUsize,
    /// Segments never fetched because the slot was identified as a PAR2
    /// volume in-stream and deferred (removed from the pool queue). Kept
    /// apart from `missing`: a deferred article is a choice, not damage.
    pub(crate) deferred: std::sync::atomic::AtomicUsize,
    /// PAR2-race experiment: segments deliberately abandoned mid-run
    /// because recovery blocks on hand already covered them with margin
    /// and repair beats the fetch remainder. A third category next to
    /// `missing` (damage we suffered) and `deferred` (a choice that is
    /// not damage): this is a choice that IS damage - the settle
    /// read-back counts the absent blocks as bad and repair heals them,
    /// so it must exempt the sparse-slot census like a deferral while
    /// still reading as damage evidence for the repair branches.
    pub(crate) abandoned: std::sync::atomic::AtomicUsize,
    /// The user asked for sample files to be skipped and this slot's
    /// posted name plus declared size said it is one
    /// (`smart::skippable_samples`), so NONE of its articles were
    /// queued. Decided once at plan time and never revised: the
    /// segments are booked into `deferred` - a choice, not damage -
    /// exactly as a resume-recognised recovery volume's are, which is
    /// what keeps the census and the uncovered-hole scan from failing
    /// the job over a file nobody wanted. The flag itself is read by
    /// the settle pass, which has to strike the file off the PAR2 set's
    /// missing list as well, or repair would fetch recovery volumes to
    /// rebuild the very bytes the setting declined.
    pub(crate) sample_skipped: bool,
    /// Par2-main slots capture decoded bytes in memory so the recovery set
    /// activates mid-download without re-reading from disk. `Some` from
    /// build time for slots the NZB names as par2; installed at sniff time
    /// for the in-stream bootstrap volume of an obfuscated post.
    pub(crate) capture: std::sync::Mutex<Option<Vec<u8>>>,
}

impl FileSlot {
    /// Recovery data by ANY route - NZB classification or the in-stream
    /// magic sniff. The settle/repair accounting that excludes par2 slots
    /// keys off this, not `is_par2_main` alone.
    pub(crate) fn is_par2(&self) -> bool {
        self.is_par2_main || self.par2_sniffed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Cap on an in-memory par2 capture mirror. `begin` offsets are
/// poster-controlled and the mirror zero-fills REAL memory (unlike the
/// extractor's sparse disk writes), so an absurd declared offset must
/// drop the article rather than allocate a petabyte. A real main .par2
/// (or bootstrap volume) sits far below this.
pub(crate) const MAX_PAR2_CAPTURE: usize = 256 << 20;

/// Issue #14 (in-stream PAR2 identification): runtime state for slots
/// reclassified as recovery data by the offset-0 magic sniff. Built once
/// per download and shared by every decode consumer.
pub(crate) struct SniffCtl {
    pub(crate) nzb: Arc<Nzb>,
    /// Slot index → NZB file index (slots skip NZB-classified volumes,
    /// so the two numberings diverge).
    pub(crate) slot_file: Vec<usize>,
    /// May this run designate an in-stream bootstrap volume? False when
    /// the NZB already names a par2 main (or bootstrap volume) - the
    /// activation counter belongs to those slots, and sniffed volumes
    /// simply defer.
    pub(crate) allow_bootstrap: bool,
    pub(crate) state: std::sync::Mutex<SniffState>,
    pub(crate) deferred_articles: std::sync::atomic::AtomicUsize,
    pub(crate) deferred_bytes: std::sync::atomic::AtomicU64,
    /// The run's fetch-progress counter, so a deferral can settle the
    /// bytes it just cancelled (Codex sweep 2, 3 Aug ML2).
    ///
    /// Every payload-classified article contributes to `fetch_plan` when
    /// the plan is published, and a terminal outcome credits it back -
    /// including the ones that will never arrive, because "terminal is
    /// terminal" and holding the bar short of 100% through the whole
    /// repair is worse than counting a 430 as done. A live deferral is
    /// terminal in exactly that sense (the articles are cancelled and
    /// leave the pool without an outcome), and it was the one such exit
    /// that credited nothing - so the bar and the SAB-compatible
    /// `Remaining` sat short by the deferred bytes for the whole
    /// verify/repair tail. Resume-recognised deferrals have always been
    /// seeded into this counter; this is the live path catching up.
    pub(crate) fetch_done: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Default)]
pub(crate) struct SniffState {
    /// The sniffed slot elected to download in full and activate the set
    /// (the runtime analogue of `bootstrap_vol`). Switches to a smaller
    /// volume while unlocked - hash-named posts arrive in arbitrary size
    /// order, and the biggest volume can be half the recovery set.
    pub(crate) bootstrap: Option<usize>,
    /// Set (under this mutex) when the bootstrap slot completes: from
    /// then on the election is final, because activation is in flight.
    pub(crate) locked: bool,
    /// Every sniffed slot, bootstrap included, in sniff order.
    pub(crate) sniffed: Vec<usize>,
    /// Per sniffed slot: (md5 of the first min(16k, len) bytes, yEnc
    /// declared length). The reconcile pass matches these against the
    /// activated set's FileDesc table - a hit means the "volume" is
    /// really SET-COVERED PAYLOAD (a posted par2 file the set includes)
    /// and must be un-deferred, not recreated from recovery blocks.
    pub(crate) head16: std::collections::HashMap<usize, ([u8; 16], u64)>,
    /// Per deferred slot: the exact ids `cancel` removed (the only ids
    /// `requeue` may resurrect) and their encoded byte sum.
    pub(crate) cancelled_ids: std::collections::HashMap<usize, (Vec<std::sync::Arc<str>>, u64)>,
    /// Slots reconciled back to payload. A later duplicate offset-0
    /// article of such a slot still carries the magic - it must never
    /// re-defer what activation proved is payload.
    pub(crate) reconciled: std::collections::HashSet<usize>,
}

impl SniffCtl {
    pub(crate) fn any_sniffed(&self) -> bool {
        !self.state.lock_ok().sniffed.is_empty()
    }

    pub(crate) fn bootstrap_slot(&self) -> Option<usize> {
        self.state.lock_ok().bootstrap
    }

    /// Every sniffed slot EXCEPT the bootstrap - the deferred volumes.
    pub(crate) fn deferred_slots(&self) -> Vec<usize> {
        let st = self.state.lock_ok();
        st.sniffed
            .iter()
            .filter(|&&s| st.bootstrap != Some(s))
            .copied()
            .collect()
    }

    /// NZB file indexes of every sniffed slot EXCEPT the bootstrap - the
    /// deferred volumes a repair may fetch (exact-fit) later.
    pub(crate) fn deferred_files(&self) -> Vec<usize> {
        self.deferred_slots()
            .into_iter()
            .map(|s| self.slot_file[s])
            .collect()
    }

    /// Deferred slots whose head fingerprint (md5-16k + length) matches a
    /// file the active set COVERS: payload the sniff wrongly deferred.
    /// Read-only - the caller marks each slot reconciled only once it has
    /// actually secured the bytes.
    pub(crate) fn matched_deferred(&self, set: &nzbkit::par2::Par2Set) -> Vec<(usize, u64)> {
        let st = self.state.lock_ok();
        st.sniffed
            .iter()
            .filter(|&&s| st.bootstrap != Some(s))
            .filter_map(|&s| {
                let &(h, len) = st.head16.get(&s)?;
                set.files
                    .iter()
                    .any(|f| f.length == len && f.md5_16k == h)
                    .then_some((s, len))
            })
            .collect()
    }

    /// A matched slot's bytes are secured (requeued live, or side-fetched
    /// after the drain): retire its recovery-data standing for good.
    pub(crate) fn mark_reconciled(&self, sidx: usize) {
        let mut st = self.state.lock_ok();
        st.sniffed.retain(|&s| s != sidx);
        st.reconciled.insert(sidx);
        st.cancelled_ids.remove(&sidx);
        st.head16.remove(&sidx);
    }

    /// Completion hook for a sniffed slot: locks the election if this is
    /// the bootstrap and says whether the caller should run activation.
    pub(crate) fn note_completed(&self, sidx: usize) -> bool {
        let mut st = self.state.lock_ok();
        if st.bootstrap == Some(sidx) {
            st.locked = true;
            true
        } else {
            false
        }
    }
}

/// Article id → (owning slot index, the article's declared byte size from
/// the NZB). The size rides along beside the slot because the queue's
/// fetch-progress counters have to be paid in exactly the unit their
/// denominator is quoted in - declared NZB bytes - and this map is
/// already consulted once per terminal article. A parallel id→bytes map
/// would have duplicated every message-id string (~15 MB on a 128k
/// article job). Full u64 for the size on purpose: `fetch_plan` sums
/// the same declarations in u64, and a skewed NZB declaring a segment
/// past 4 GiB used to truncate here - crediting 1 byte against a 4 GB
/// denominator, wedging the bar short of 100% for the whole job.
pub(crate) type IdSlots = std::collections::HashMap<std::sync::Arc<str>, (u32, u64)>;

/// R9: the interned handle `id_to_slot` already holds for a segment's
/// bracketed id.
///
/// The fetch plan brackets and interns every segment id once
/// (get/plan.rs); a later pass over the same NZB - the in-stream PAR2
/// sniff, the par-race candidate walk - used to `format!` a second full
/// copy of every id it touched just to name articles the pool is
/// already holding. Looking the id up instead hands back the plan's
/// allocation for the price of a hash.
///
/// `buf` is caller-owned scratch reused across the walk, so the lookup
/// itself allocates nothing after the first segment. An id the plan
/// never recorded (a parser-dropped segment) interns fresh, so the
/// caller's set has exactly the members it had before.
pub(crate) fn interned_bracketed(
    buf: &mut String,
    id_to_slot: &IdSlots,
    message_id: &str,
) -> std::sync::Arc<str> {
    use std::fmt::Write;
    buf.clear();
    let _ = write!(buf, "<{message_id}>");
    match id_to_slot.get_key_value(buf.as_str()) {
        Some((interned, _)) => interned.clone(),
        None => std::sync::Arc::from(buf.as_str()),
    }
}

/// The offset-0 article of a payload-classified slot decoded to the
/// `PAR2\0PKT` magic: reclassify it. Elects (or switches) the bootstrap
/// volume, defers everything else by cancelling its still-queued articles,
/// and keeps the slot counters consistent with what will now never arrive.
/// `head` is the decoded offset-0 span, mirrored into the bootstrap's
/// capture so activation can parse it later.
#[expect(clippy::too_many_arguments)]
pub(crate) fn reclassify_sniffed_par2(
    ctl: &SniffCtl,
    slots: &[Arc<FileSlot>],
    sidx: usize,
    head: &[u8],
    file_size: u64,
    queue: &nzbkit::pool::QueueControl,
    id_to_slot: &IdSlots,
    par2_outstanding: &std::sync::atomic::AtomicUsize,
) {
    use std::sync::atomic::Ordering;
    let fbytes = |s: usize| ctl.nzb.files[ctl.slot_file[s]].bytes();
    // Election under the state lock; the queue cancel runs after it drops.
    let (is_bootstrap, demoted) = {
        let mut st = ctl.state.lock_ok();
        // Idempotence: two articles of the same slot can both claim yEnc
        // begin=1 (poster-controlled) and race here on two decode
        // threads; and a slot the reconcile pass proved to be payload
        // must never be re-deferred by a later magic-carrying article.
        if st.sniffed.contains(&sidx) || st.reconciled.contains(&sidx) {
            return;
        }
        slots[sidx].par2_sniffed.store(true, Ordering::Release);
        st.sniffed.push(sidx);
        // Remember the head fingerprint: if the set, once activated,
        // includes this file by md5-16k + length, the sniff was wrong
        // about its ROLE (payload, not recovery) and reconcile un-defers
        // it. None when the head span doesn't cover the 16k prefix.
        if let Some(h) = nzbkit::par2::md5_16k_of_head(head, file_size) {
            st.head16.insert(sidx, (h, file_size));
        }
        let mut demoted = None;
        if ctl.allow_bootstrap {
            match st.bootstrap {
                None => {
                    st.bootstrap = Some(sidx);
                    // First election: the activation counter now owes one
                    // completion (mirrors a static par2-main slot).
                    par2_outstanding.fetch_add(1, Ordering::AcqRel);
                }
                Some(b)
                    if !st.locked
                        && slots[b].remaining.load(Ordering::Acquire) > 0
                        && fbytes(sidx) < fbytes(b) =>
                {
                    // A smaller volume showed up while the current one is
                    // still incomplete: switch. The completion obligation
                    // moves with the election (net zero on the counter),
                    // and the old partial capture is dropped so
                    // recovery_blocks_seen counts exactly the volume the
                    // repair planner is told is already on hand.
                    st.bootstrap = Some(sidx);
                    if let Some(old) = slots[b].capture.lock_ok().take() {
                        // Memory-floor gauge: the demoted bootstrap's
                        // partial capture is freed here.
                        nzbkit::memgauge::sub(nzbkit::memgauge::Sub::Par2Capture, old.len() as u64);
                    }
                    demoted = Some(b);
                }
                Some(_) => {}
            }
        }
        // The capture install stays INSIDE the state lock (order: state →
        // capture, same as the demote arm above). Installing after the
        // lock dropped opened a race: a concurrent sniff could demote
        // this slot and null its capture, and the stale install would
        // resurrect it - a deferred volume whose partial packets then
        // leak into activation and inflate recovery_blocks_seen.
        if st.bootstrap == Some(sidx) {
            let mut cap = slots[sidx].capture.lock_ok();
            let buf = cap.get_or_insert_with(Vec::new);
            if head.len() <= MAX_PAR2_CAPTURE {
                if buf.len() < head.len() {
                    // Memory-floor gauge: capture growth.
                    nzbkit::memgauge::add(
                        nzbkit::memgauge::Sub::Par2Capture,
                        (head.len() - buf.len()) as u64,
                    );
                    buf.resize(head.len(), 0);
                }
                buf[..head.len()].copy_from_slice(head);
            }
        }
        (st.bootstrap == Some(sidx), demoted)
    };
    if is_bootstrap {
        info!(
            target: "par2",
            "recovery volume identified in-stream ({}) - bootstrapping the PAR2 set from it",
            slots[sidx].hint
        );
        // The static path schedules par2-main articles FIRST so the set
        // activates within the first round-trips; a sniffed bootstrap's
        // body articles were queued as ordinary data at its file position
        // - possibly behind the whole payload, which would delay
        // activation (and with it in-stream verification and the live
        // reconcile) to the download's tail. Promote them the way the
        // extractor's offset-0 probe promotes: to the front, without
        // engaging stream mode.
        let mut buf = String::new();
        let promote: Vec<std::sync::Arc<str>> = ctl.nzb.files[ctl.slot_file[sidx]]
            .segments
            .iter()
            .map(|seg| interned_bracketed(&mut buf, id_to_slot, &seg.message_id))
            .filter(|b| id_to_slot.get(&**b).map(|&(s, _)| s as usize) == Some(sidx))
            .collect();
        queue.promote_opts(&promote, false);
    }
    for d in demoted.into_iter().chain((!is_bootstrap).then_some(sidx)) {
        let mb = defer_sniffed_slot(ctl, slots, d, queue, id_to_slot);
        info!(
            target: "par2",
            "recovery volume identified in-stream ({}) - deferring {:.1} MB",
            slots[d].hint, mb
        );
    }
}

/// Cancel a sniffed slot's still-queued articles and account for them as
/// deferred. Articles already in flight resolve normally (their bytes are
/// written and harmless); ids owned by ANOTHER slot (duplicate-id NZBs)
/// are never touched. Returns the MB actually removed from the queue.
fn defer_sniffed_slot(
    ctl: &SniffCtl,
    slots: &[Arc<FileSlot>],
    sidx: usize,
    queue: &nzbkit::pool::QueueControl,
    id_to_slot: &IdSlots,
) -> f64 {
    use std::sync::atomic::Ordering;
    let f = &ctl.nzb.files[ctl.slot_file[sidx]];
    let mut want: std::collections::HashSet<std::sync::Arc<str>> = Default::default();
    let mut bytes_of: std::collections::HashMap<std::sync::Arc<str>, u64> = Default::default();
    let mut buf = String::new();
    for seg in &f.segments {
        let b = interned_bracketed(&mut buf, id_to_slot, &seg.message_id);
        if id_to_slot.get(&*b).map(|&(s, _)| s as usize) == Some(sidx) {
            bytes_of.insert(b.clone(), seg.bytes);
            want.insert(b);
        }
    }
    // `cancel` is best-effort under queue contention (bounded try_lock):
    // an empty answer can mean "nothing queued" OR "lock missed". A few
    // retries make a missed lock recoverable; a genuinely-empty queue
    // just answers empty again, cheaply, on a decode thread.
    let mut removed = Vec::new();
    for attempt in 0..3 {
        removed = queue.cancel(&want);
        if !removed.is_empty() {
            break;
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    if removed.is_empty() {
        return 0.0;
    }
    // Saturating fold, not .sum(): these are attacker-typed NZB byte
    // declarations, and a plain sum panics in debug / wraps in release.
    let bytes: u64 = removed
        .iter()
        .filter_map(|id| bytes_of.get(&**id))
        .fold(0u64, |a, b| a.saturating_add(*b));
    slots[sidx]
        .remaining
        .fetch_sub(removed.len(), Ordering::AcqRel);
    slots[sidx]
        .deferred
        .fetch_add(removed.len(), Ordering::Relaxed);
    ctl.deferred_articles
        .fetch_add(removed.len(), Ordering::Relaxed);
    ctl.deferred_bytes.fetch_add(bytes, Ordering::Relaxed);
    // These bytes will never produce a terminal outcome - the articles
    // left the pool queue - so settle them here or the bar stops short
    // by exactly this much for the rest of the run. Undone by
    // `reconcile_deferred_payload` if they are ever requeued, since
    // then the ordinary outcomes credit them again.
    ctl.fetch_done.fetch_add(bytes, Ordering::Relaxed);
    // The exact removed ids, kept for a possible un-defer: only these may
    // ever be requeued (the pool stashes their Work items whole).
    ctl.state
        .lock_ok()
        .cancelled_ids
        .entry(sidx)
        .and_modify(|(v, b)| {
            v.extend(removed.iter().cloned());
            *b = b.saturating_add(bytes);
        })
        .or_insert_with(|| (removed.clone(), bytes));
    bytes as f64 / 1e6
}

/// Issue #14 reconcile: the sniff classifies by CONTENT (`PAR2\0PKT`),
/// which cannot tell a recovery volume from set-covered payload that
/// happens to BE a par2 file (a posted recovery set as content). Once the
/// set is live its FileDesc table can: any deferred slot whose head
/// fingerprint (md5-16k + length) matches a set file was payload all
/// along - un-defer it (requeue the cancelled articles), hand its head
/// back to the verifier so the slot is claimed and verified in-stream,
/// and drop its recovery-data standing. Failing to do this made the
/// repair recreate (or fail to recreate) a file whose every article was
/// sitting on the server, fetchable.
pub(crate) fn reconcile_deferred_payload(
    ctl: &SniffCtl,
    slots: &[Arc<FileSlot>],
    set: &nzbkit::par2::Par2Set,
    queue: &nzbkit::pool::QueueControl,
    extractor: &nzbkit::extract::Extractor,
    verifier: &nzbkit::live::LiveVerifier,
) {
    use std::sync::atomic::Ordering;
    for (sidx, file_size) in ctl.matched_deferred(set) {
        let (ids, bytes) = ctl
            .state
            .lock_ok()
            .cancelled_ids
            .get(&sidx)
            .cloned()
            .unwrap_or_default();
        // All-or-nothing: a partial resurrection would leave a payload
        // slot short articles nothing will ever fetch. `requeue` itself
        // is all-or-nothing over the stash; ids it no longer holds
        // (never cancelled - e.g. the slot deferred nothing) count as
        // zero and the slot simply stays deferred. A refusal (short
        // post: the pool already wound down) is fine too - the drain
        // fallback in get/settle.rs side-fetches whatever stayed
        // deferred.
        let n = queue.requeue(&ids);
        if n == 0 || n != ids.len() {
            continue;
        }
        ctl.mark_reconciled(sidx);
        slots[sidx].remaining.fetch_add(n, Ordering::AcqRel);
        slots[sidx].deferred.fetch_sub(n, Ordering::Relaxed);
        ctl.deferred_articles.fetch_sub(n, Ordering::Relaxed);
        ctl.deferred_bytes.fetch_sub(bytes, Ordering::Relaxed);
        // Give the deferral's progress credit back: these articles are
        // in the pool again and will credit themselves when they land.
        // Keeping it would take the bar past 100%. The drain fallback
        // in get/settle.rs is the opposite case - it side-fetches
        // OUTSIDE the pool, so no outcome follows and the credit must
        // stand.
        ctl.fetch_done.fetch_sub(bytes, Ordering::Relaxed);
        // Payload again: articles arriving from the requeue take the
        // normal verifier path from here on.
        slots[sidx].par2_sniffed.store(false, Ordering::Release);
        // The head article never refetches (it completed before the
        // cancel), so the verifier would never see offset 0 and could
        // not claim the slot by md5-16k. Feed the on-disk head back:
        // write_verified put it there before the sniff fired. Disk
        // provenance (full-MD5 claims) - nothing in flight vouches for
        // the re-read.
        let want = file_size.min(16384) as usize;
        if want > 0
            && let Some(p) = extractor.slot_path(sidx)
        {
            let mut buf = vec![0u8; want];
            let ok = std::fs::File::open(&p)
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
                .is_ok();
            if ok {
                verifier.on_data_from_disk(sidx, "", file_size, 0, &buf);
            }
        }
        info!(
            target: "par2",
            "{} is payload the recovery set covers - resuming its download \
             ({:.1} MB back on the queue)",
            slots[sidx].hint,
            bytes as f64 / 1e6
        );
    }
}

/// One backfill worker's read buffer. Sized to amortize the pread and
/// the verifier call, and - the load-bearing half - to stay at or above
/// any realistic PAR2 block size: a span that fully contains a block
/// hashes straight out of this buffer, while one shorter than the block
/// has to go through the partials budget instead, where it can spill to
/// settle read-back. Shrinking this to pay for more workers would
/// therefore trade the very read-back the backfill exists to delete.
const BACKFILL_BUF: usize = 4 << 20;

/// How many slots the backfill hashes at once (TODO 129's "the resume/
/// backfill hash path must ride the parallel-MD5 pool").
///
/// Half the machine, capped at 4, because this pass runs WHILE the
/// download does: unlike the settle read-back - which owns the box and
/// takes `min(cores, 12)` in `get/settle.rs` - every core here is one
/// the decoders and the pool are not getting. Four lanes of `md5::soft`
/// is ~2.8 GB/s against ~0.7 serial, which is already at or past what
/// the re-read itself sustains, so the lanes above it would buy
/// contention rather than wall.
///
/// It also bounds the buffers: [`BACKFILL_BUF`] is per worker, so the
/// cap is what keeps this pass's transient RSS at 16 MiB rather than
/// one buffer per core.
const BACKFILL_MAX_WORKERS: usize = 4;

/// When the last outstanding par2-main slot completes, parse the captured
/// packets and switch the verifier to in-stream mode.
/// M15b: hash spans that were decoded before PAR2 activation by reading
/// them back from disk WHILE the download continues - the work that used
/// to be the settle pass's re-read (42 GB on the 87 GB run) overlaps the
/// network phase instead. Coverage-gated: a span not fully on disk yet
/// (or in a still-unclassified slot) is skipped and settles as before.
///
/// Slots run on a small pool, not one after another. The hot loop is
/// `md5::soft` - the same leaf §129's parallel PAR2 verify moved - and
/// on a crash resume `seed_pre_spans` hands this pass the WHOLE restored
/// payload, so serially it was one core hashing tens of GB while the
/// rest of the box idled. Slots are independent by construction:
/// `on_data_inner` claims under the per-slot lock and hashes outside it,
/// and the one piece of cross-slot state - the global partials budget -
/// is already reserve-then-check for concurrent slots (M15). Which
/// blocks lose a budget race can therefore differ from the serial order;
/// that changes only how many blocks settle by read-back, never a
/// verdict, and `backfill_slot` is the seam the differential test drives
/// both ways.
pub(crate) fn backfill_pre_activation(
    verifier: &nzbkit::live::LiveVerifier,
    extractor: &nzbkit::extract::Extractor,
    n_slots: usize,
    par2_slots: &[bool],
) -> u64 {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    let work: Vec<usize> = (0..n_slots).filter(|&i| !par2_slots[i]).collect();
    let workers = (nzbkit::mem::cpu_workers() / 2)
        .clamp(1, BACKFILL_MAX_WORKERS)
        .min(work.len());
    let t0 = std::time::Instant::now();
    let fed = if workers <= 1 {
        let mut buf = vec![0u8; BACKFILL_BUF];
        work.iter()
            .map(|&sidx| backfill_slot(verifier, extractor, sidx, &mut buf))
            .sum()
    } else {
        let next = AtomicUsize::new(0);
        let fed = AtomicU64::new(0);
        let work = &work;
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    let mut buf = vec![0u8; BACKFILL_BUF];
                    while let Some(&sidx) = work.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let n = backfill_slot(verifier, extractor, sidx, &mut buf);
                        fed.fetch_add(n, Ordering::Relaxed);
                    }
                });
            }
        });
        fed.load(Ordering::Relaxed)
    };
    // The A/B this pass was landed without (TODO 129 (c)) needs the PHASE,
    // not just the job: the join in `get/workers.rs` happens after the
    // network drains, so whether any of this reaches wall depends on how
    // much of it outlasts the download. Bytes, lanes and elapsed on one
    // line is what the round parses; `workers` is what tells the two arms
    // apart in a log.
    if fed > 0 {
        info!(
            target: "par2",
            "backfill: {:.1} MB over {} slot(s) on {} worker(s) in {:.0} ms",
            fed as f64 / 1e6,
            work.len(),
            workers,
            t0.elapsed().as_secs_f64() * 1000.0,
        );
    }
    fed
}

/// One slot's share of [`backfill_pre_activation`]: re-read its
/// pre-activation spans from disk and feed them under the source
/// `take_pre_spans` hands back. Returns the bytes fed.
///
/// `pub(crate)` for the differential test, which runs every slot through
/// this on one thread and must reach the identical block verdicts.
pub(crate) fn backfill_slot(
    verifier: &nzbkit::live::LiveVerifier,
    extractor: &nzbkit::extract::Extractor,
    sidx: usize,
    buf: &mut [u8],
) -> u64 {
    // Spans this run decoded keep a fresh span's claim strength, so
    // their boundary blocks compose as CRC parts instead of demanding
    // a block-sized byte buffer each. take_pre_spans decides which
    // spans qualify and hands back the source to feed them under;
    // crash-resume seeds, and pcrc-absent articles outside lean mode,
    // take the full-MD5 disk path.
    let (spans, how) = verifier.take_pre_spans(sidx);
    let mut fed: u64 = 0;
    for (off, len) in spans {
        let mut o = off;
        let end = off + len;
        while o < end {
            let n = nzbkit::disk::chunk_len(end - o, buf.len());
            if !extractor.covered(sidx, o, n as u64) {
                break; // not (yet) on disk - leave for settle
            }
            if extractor.read_at(sidx, o, &mut buf[..n]).is_err() {
                break;
            }
            match how {
                nzbkit::live::PreSpanSrc::Backfill => {
                    verifier.on_data_backfill(sidx, "", 0, o, &buf[..n])
                }
                nzbkit::live::PreSpanSrc::Disk => {
                    verifier.on_data_from_disk(sidx, "", 0, o, &buf[..n])
                }
            }
            fed += n as u64;
            o += n as u64;
        }
    }
    fed
}

pub(crate) fn maybe_activate_par2(
    slots: &[Arc<FileSlot>],
    verifier: &nzbkit::live::LiveVerifier,
    outstanding: &std::sync::atomic::AtomicUsize,
    sniff: &SniffCtl,
    queue: &nzbkit::pool::QueueControl,
    extractor: &nzbkit::extract::Extractor,
) -> bool {
    use std::sync::atomic::Ordering;
    if outstanding.fetch_sub(1, Ordering::AcqRel) != 1 {
        return false;
    }
    let set = {
        let guards: Vec<std::sync::MutexGuard<Option<Vec<u8>>>> =
            slots.iter().map(|s| s.capture.lock_ok()).collect();
        let refs: Vec<&[u8]> = guards
            .iter()
            .filter_map(|g| g.as_ref().map(|v| v.as_slice()))
            .collect();
        verifier.activate(&refs)
    };
    match set {
        Ok(sets) => {
            // TODO 311 item 5, and the reason #63 took a reporter's log
            // to find: this line used to say "set live: 1 file(s)" on a
            // post that had just fetched EIGHTEEN index files, and read
            // as a one-file post rather than as a choice. Every set is
            // adopted now, so the count is the truth - and the line says
            // how many sets that is whenever it is more than one, so a
            // reader can tell an eighteen-set post from an eighteen-file
            // one at a glance.
            //
            // `[par2] set live` stays the literal prefix in BOTH shapes.
            // Three e2e suites and every log reader anchor on it, and a
            // plural that reworded the opening would have gone quietly
            // unmatched on exactly the post this exists for.
            let files: usize = sets.iter().map(|s| s.files.len()).sum();
            let count = if sets.len() == 1 {
                String::new()
            } else {
                format!("{} sets, ", sets.len())
            };
            let mut sizes: Vec<u64> = sets.iter().map(|s| s.block_size).collect();
            sizes.sort_unstable();
            sizes.dedup();
            let block = match sizes.as_slice() {
                [one] => format!("block size {one}"),
                many => format!(
                    "block sizes {}",
                    many.iter()
                        .map(|b| b.to_string())
                        .collect::<Vec<_>>()
                        .join("/")
                ),
            };
            info!(
                target: "par2",
                "set live: {count}{files} file(s), {block} - verifying in-stream"
            );
            // The FileDesc table can now correct the sniff: a deferred
            // slot the set COVERS is payload, not recovery - un-defer it
            // while the run is still live. After the capture guards drop
            // (this reads disk and takes pool locks). Every set: a
            // deferred slot one of them covers is payload whichever one
            // that is.
            for set in &sets {
                reconcile_deferred_payload(sniff, slots, set, queue, extractor, verifier);
            }
            true
        }
        Err(e) => {
            warn!(target: "par2", "activation failed ({e}) - falling back to post-download verify");
            verifier.set_off();
            false
        }
    }
}

/// Age in whole days of an NZB `<file date="…">` unix timestamp. Absent,
/// zero, or future dates count as fresh (0) - retention exclusion must
/// never fire on posts we can't date.
pub(crate) fn nzb_age_days(date: i64) -> u32 {
    if date <= 0 {
        return 0;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    ((now - date).max(0) / 86_400) as u32
}
