//! PLAN M31 stage 1: fill a damaged file's bad blocks from a DUPLICATE
//! POSTING's live articles, before spending a single PAR2 recovery
//! block on them.
//!
//! The arithmetic is [`nzbkit::dupedonor`] and its header carries the
//! mechanism and the §282 finding that decides which donors can ever
//! work. This module is the wire and the disk around it: fetch the
//! donor's recovery index, prove the two postings are of the same
//! bytes, ask for the articles that overlap our holes, and write only
//! what the target's own set vouches for.
//!
//! # Why this half is what M31 still owed, and the disk half is not
//!
//! §293 already gives a switch job's repair the failed predecessor's
//! OUTPUT DIRECTORY, and `nzbkit::par2repair::adopt` already adopts at
//! BLOCK granularity out of it, sliding scan and all. So "two
//! incomplete copies on disk complete each other" has shipped since
//! §293 and this module must not be read as re-doing it.
//!
//! What has no path at all is the case M31 was written for: the bytes
//! are not on anybody's disk, they are in a duplicate posting's
//! ARTICLES, which are alive on the servers precisely where ours are
//! dead. Nothing in the tree fetches those. That is this pass.
//!
//! # Where it sits in the ladder, and what it must never pre-empt
//!
//! After settle's read-back has said which blocks are bad, and before
//! the repair ladder is asked to rebuild them. Both ends are
//! deliberate:
//!
//! * AFTER the read-back, because the bad-block list is the whole input
//!   - a pass that ran earlier would not know what to ask for.
//! * BEFORE repair, because a block borrowed from a duplicate costs
//!   payload bytes and no parity, while the same block rebuilt costs a
//!   recovery slice that a later hole then cannot have. Repair is the
//!   fallback and stays the fallback: a hole this pass does not fill is
//!   left exactly as it was.
//!
//! What the caller then believes is not this pass's word for it. A
//! block is subtracted from a slot's bad-block list only after its
//! rebuilt bytes matched the target set's own MD5 and CRC32 and the
//! positioned write of them returned and synced; a FILE is claimed
//! whole only after being read back and matched against the set's
//! whole-file MD5. See [`FillReport::apply_to`] and
//! [`FillReport::whole_files_proved`] - that second one is the only
//! verdict this pass moves, and it says at length what it rests on.
//!
//! It never pre-empts the whole-release machinery above it either. A
//! dupe promotion or a §284 switch is a decision about which POST to
//! download and is taken by the daemon long before a job reaches
//! settle; this pass only ever runs on the post that is already on
//! disk, and only for the blocks it could not get.
//!
//! # Stated limits of stage 1
//!
//! * **Disk-backed slots only, and there are now TWO chances at that.**
//!   A mapped or chased slot's bytes are in the extractor's frontier
//!   buffer rather than in a file, so [`wanted_files`] skips it. That
//!   made the whole pass INERT on a RAR-payload release - most real
//!   ones - because the settle-time entry point is the only one those
//!   slots ever reached, and it refused them.
//!
//!   M31 handoff item 4 lifted that by running the pass a SECOND time,
//!   from `get::settle::fill_from_duplicates_off_materialized_volumes`,
//!   on the volumes the repair has just materialized: by then the slot
//!   is `SlotMode::RarFallback` with a writer, so it is disk-backed and
//!   nothing here had to change. That function's header carries the
//!   argument for the placement and for what the later moment costs.
//!   What is still out of reach either way is a slot that never
//!   materializes at all, and feeding borrowed bytes into a LIVE
//!   in-stream extraction (`Extractor::patch_volume_span`, the route
//!   `crate::repair`'s mapped arm takes) remains a different piece of
//!   work.
//! * **The donor's members are matched by NAME to its own NZB.** The
//!   recovery index states each member's digest but not which NZB file
//!   posts it, so an OBFUSCATED donor - subjects that are hashes -
//!   maps nothing and donates nothing. Same stated limit, for the same
//!   reason, as §305's plan-side arm next door in `get/donor.rs`.
//! * **First bytes win, WITHIN one donor.** Where two articles offer
//!   the same range the first to arrive is kept, so nothing a block
//!   has already been given can be overwritten and its verdict cannot
//!   depend on which article spoke last. Across donors it is not a
//!   limit: each donor's contribution is judged as soon as that donor
//!   is done, and a block it got WRONG is re-opened EMPTY for the next
//!   one (`BlockHealer::reopen_rejected`), so a donor serving a
//!   corrupt copy of a block no longer poisons that block for the
//!   donors behind it. A block no donor can prove is left for repair,
//!   exactly as before.
//! * **One donor source: the failed PREDECESSOR of a switch job.** The
//!   spares §282 parks against a RUNNING row are equally reachable and
//!   were wired first; with them on, a job with a byte-identical spare
//!   held against it COMPLETES by borrowing a few of that spare's
//!   articles, so §282's promotion rung never fires. That is a better
//!   product and also a decision to retire a shipped escalation path,
//!   which is not a lane's to take - so it is built, measured and
//!   withheld. The whole argument, the measurement and the two test
//!   fixtures it turns red are in
//!   `research/M31-DUPE-DONOR-LADDER-2026-08-28.md`; the switch is
//!   `serve/tasks/worker.rs::predecessor_posting`.

use crate::*;
use nzbkit::dupedonor::{BlockHealer, Placement, SegAnchor, Span};
use nzbkit::nzb::{FileKind, Nzb};
use nzbkit::par2::Par2Set;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Ceiling on the whole pass, which sits between a job's last article
/// and its repair. A donor that has gone unreachable must cost a
/// bounded delay, not three timeouts per donor per file.
const FILL_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);

/// Bytes of donor bodies one pass may pull. A hole is small by
/// definition - a job whose payload is mostly gone is a dupe-promote
/// decision, not a fill - so this is a cost ceiling and not a work
/// estimate.
const MAX_FILL_BYTES: usize = 256 << 20;

/// Slack on the BLIND segment estimate, in bytes. An NZB states encoded
/// sizes only, so a donor segment's placement is estimated until its own
/// yEnc header is read (see `candidate_segments`); one large article's
/// worth either side costs a wasted body at each end of a hole and never
/// a wrong byte.
///
/// It is the FIRST ask's figure and no longer the whole story. A file
/// smaller than this degenerates to "ask for the whole file", which is
/// exactly the over-fetch the arriving articles now correct: every
/// article that passes the placement gate has stated where it sat, and
/// the rest of the plan is re-cut against the nearest such fact through
/// `candidate_segments_anchored`, whose own header carries the
/// arithmetic and what it measured.
const SEG_SLACK: u64 = 1 << 20;

/// What one pass did, for the log line and the job report.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct FillReport {
    /// Blocks rebuilt from donor bytes and proved against the target's
    /// own set.
    pub(super) healed: usize,
    /// Judgements that were fully covered by donor bytes and FAILED
    /// that proof - borrowed bytes this refused. A block one donor got
    /// wrong and the next got right counts here AND in `healed`: this
    /// is attempts refused, not blocks lost.
    pub(super) rejected: usize,
    /// Donor articles that came back.
    pub(super) bodies: usize,
    /// Donor payload bytes accepted into a block, OFF THE WIRE. Bytes
    /// read out of a donor directory are [`FillReport::local_bytes`]
    /// and are deliberately not folded in here: this figure is what the
    /// pass SPENT on the network, and the summary line prints it as
    /// such.
    pub(super) bytes: u64,
    /// Blocks proved out of a donor DIRECTORY - the failed
    /// predecessor's own files - and so never asked for over the wire.
    pub(super) local: usize,
    /// Payload bytes read out of a donor directory.
    pub(super) local_bytes: u64,
    /// Blocks a donor could only PART-serve, completed from the bytes
    /// this download already had, and then PROVED - see
    /// [`stitch_from_the_targets_own_bytes`].
    pub(super) stitched: usize,
    /// Stitched blocks the target's own set then refused. Counted apart
    /// from [`FillReport::rejected`] on purpose: that figure is a fact
    /// about the DONOR, and a stitch mixes the donor's bytes with ours.
    pub(super) stitch_refused: usize,
    /// Slots whose WHOLE FILE was read back off disk after the fill and
    /// matched its recovery-set entry's own MD5 - see
    /// [`FillReport::whole_files_proved`] for what that is allowed to
    /// settle and what it is not.
    pub(super) proven: Vec<usize>,
    /// Per slot, the block indices that are now PROVED GOOD on disk.
    ///
    /// This is what the caller subtracts from that slot's bad-block
    /// list, and it is exactly as trustworthy as the proof behind it: a
    /// block reaches this list only after its rebuilt bytes matched the
    /// target set's own MD5 and CRC32 and the positioned write of those
    /// bytes returned and synced. Re-running the settle read-back
    /// instead would be the same answer at the cost of re-hashing every
    /// file - and that pass renames slots and publishes names, so
    /// running it twice is not a read-only act.
    pub(super) healed_blocks: Vec<(usize, Vec<usize>)>,
}

impl FillReport {
    /// Fold another pass's result into this one.
    ///
    /// TODO 311: a post may ship one recovery set per file, and a
    /// borrowed block is proved against the set that describes its
    /// file, so the pass runs once per set. What the job's log and its
    /// `incomplete` arithmetic want is the sum. `apply_to` is NOT
    /// deferred to the sum - each pass subtracts its own blocks from
    /// the reports as it finishes, so the next set's pass sees holes
    /// that are actually still holes.
    pub(super) fn absorb(&mut self, other: FillReport) {
        self.healed += other.healed;
        self.rejected += other.rejected;
        self.bodies += other.bodies;
        self.bytes += other.bytes;
        self.local += other.local;
        self.local_bytes += other.local_bytes;
        self.stitched += other.stitched;
        self.stitch_refused += other.stitch_refused;
        self.proven.extend(other.proven);
        self.healed_blocks.extend(other.healed_blocks);
    }

    /// Subtract what this pass proved from a settle report's bad-block
    /// list, in place.
    ///
    /// This is the whole of how the pass reaches the verdict, and it is
    /// deliberately a SUBTRACTION rather than a re-verification. Every
    /// block named here matched the target set's own MD5 and CRC32 and
    /// was then written and synced at its own offset; re-reading the
    /// file to be told so again would cost a full hash pass per file
    /// and, worse, the only pass that could do it (`settle_slots`)
    /// renames slots and publishes names as it goes, so it is not
    /// something to run twice for an answer.
    ///
    /// Mapped and chased slots are never in this list - `wanted_files`
    /// refuses them - so a caller's `damage_in_mapped` cannot be stale
    /// after this and is deliberately not recomputed.
    pub(super) fn apply_to(&self, reports: &mut [(usize, nzbkit::live::SlotReport)]) {
        for (sidx, healed) in &self.healed_blocks {
            let Some((_, r)) = reports.iter_mut().find(|(s, _)| s == sidx) else {
                continue;
            };
            r.bad_blocks.retain(|b| !healed.contains(b));
        }
    }

    /// How many of the caller's `incomplete` FILES this pass has since
    /// proved whole off disk.
    ///
    /// **This is the one thing the pass does that changes a verdict, so
    /// read what it rests on.** `incomplete` counts slots that came up
    /// short of ARTICLES, and the settle pass fails a damage-free job on
    /// it outright - deliberately, because "the recovery set found no
    /// damage" is a statement about the bytes it was SHOWN, and the
    /// in-stream verifier is shown bytes as they arrive rather than off
    /// the disk. A file whose write hit ENOSPC after its blocks verified
    /// in flight is the case that rule exists for, and reporting such a
    /// job clean deletes the journal and hands an *arr a short
    /// directory.
    ///
    /// A slot counted here has been read back WHOLE off the disk and
    /// matched the recovery set's own whole-file MD5. That is strictly
    /// stronger evidence than the proxy: the ENOSPC file is short and
    /// fails it, and a file that passes it is byte-exact, which is the
    /// only thing `incomplete` was ever standing in for. It is the same
    /// bar `get/donor.rs` already accepts as licence to not fetch a file
    /// at all.
    ///
    /// Only slots that really were short are counted, so this can never
    /// take `incomplete` below the number of files still missing
    /// articles - a slot whose blocks were bad through CORRUPTION rather
    /// than loss was never in that count and must not be subtracted from
    /// it.
    /// DEDUPED by SLOT, which matters since TODO 311: the pass runs once
    /// per recovery set and `absorb` concatenates, so a slot two passes
    /// both proved could otherwise be subtracted from `incomplete` twice
    /// - and this figure is subtracted from a COUNT OF FILES.
    ///
    /// `wanted_files` now refuses a report belonging to a sibling set, so
    /// one slot reaches exactly one pass and the known route to a double
    /// count is closed at source. The dedup stays anyway and must not be
    /// read as dead: it is the cheaper of the two guards, it is a
    /// statement about `proven` rather than about the caller that filled
    /// it, and `proven` is a plain `Vec` any future caller may append to
    /// twice.
    pub(super) fn whole_files_proved(&self, slots: &[Arc<crate::unpack::FileSlot>]) -> usize {
        let mut seen = std::collections::HashSet::new();
        self.proven
            .iter()
            .filter(|sidx| seen.insert(**sidx))
            .filter(|sidx| {
                slots.get(**sidx).is_some_and(|s| {
                    s.missing.load(std::sync::atomic::Ordering::Relaxed) > 0
                        || s.remaining.load(std::sync::atomic::Ordering::Relaxed) > 0
                })
            })
            .count()
    }
}

/// One target file this pass can work on: a slot with bad blocks, a
/// real file behind it, and an entry in the target's own recovery set.
///
/// The split between resolving these and acting on them is what keeps
/// the network half testable: [`wanted_files`] is the only part that
/// needs a live `Extractor`, and [`fill_wanted`] below - the whole of
/// the wire, the proof and the write - takes nothing but a set, a list
/// of these and some donor NZBs.
pub(super) struct Wanted {
    pub(super) sidx: usize,
    /// Index into `target.files`.
    pub(super) file: usize,
    pub(super) path: PathBuf,
    pub(super) bad: Vec<usize>,
}

/// The donor articles to ask for, for one target file.
struct Ask {
    /// `(segment index in the donor file, message-id)`, in the order
    /// they are to be asked for - nearest a hole first, which is
    /// `ask_order`'s and NOT the file's. The INDEX rides along because
    /// the estimate that chose these is re-cut as articles arrive (see
    /// `SegAnchor`), and a message-id alone says nothing about where in
    /// the file it sits.
    segs: Vec<(usize, String)>,
    /// The donor file's per-segment ENCODED sizes, which is all an NZB
    /// states. Kept so the plan can be re-cut against an arrival.
    enc: Vec<u64>,
    /// The holes this ask was cut for. Constant for the life of the
    /// ask: a block leaves the healer only when `take_healed` judges
    /// it, and that happens after the whole donor is done.
    want: Vec<Span>,
    /// The file length both recovery sets agree on.
    length: u64,
    /// The target file each id is expected to carry bytes of.
    file: usize,
}

/// Fill what the duplicate postings in `donor_nzbs` can fill.
///
/// Returns an empty report and touches nothing when there are no
/// donors, no damage, no recovery set, or no server to ask - which is
/// every ordinary job, the CLI, and every job that verified clean. The
/// first thing this does is establish that, before any I/O.
///
/// `target` is ONE of the job's adopted recovery sets and `set_index` is
/// which one, indexed the way `LiveVerifier::sets` is - see
/// [`wanted_files`] for why the pass may not be handed a set without
/// also being told which set it is.
pub(super) async fn fill_from_duplicate_postings(
    servers: &[nzbkit::config::ServerConfig],
    target: &Par2Set,
    set_index: usize,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    reports: &[(usize, nzbkit::live::SlotReport)],
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<crate::unpack::FileSlot>],
    out_dir: &Path,
    donor_nzbs: &[PathBuf],
    // §293's donor directories - the failed predecessor's own files.
    // Read BEFORE the wire, for the reason `fill_from_donor_dirs`
    // carries: on a switch job these hold, in the ordinary case, the
    // very blocks the donor posting would be asked for.
    donor_dirs: &[PathBuf],
    cancel: Option<&crate::repair::SideCancel>,
) -> FillReport {
    // Cheapest question first, and it is the one that answers for every
    // ordinary job: no held duplicate means no pass at all, without so
    // much as walking the reports.
    if donor_nzbs.is_empty() || servers.is_empty() || target.block_size == 0 {
        return FillReport::default();
    }
    let wanted = wanted_files(
        target, set_index, verifier, reports, extractor, slots, out_dir,
    );
    fill_wanted(servers, target, &wanted, donor_nzbs, donor_dirs, cancel).await
}

/// The pass proper: everything from "these files have these holes" to
/// "these blocks are on disk and the set says they are right".
pub(super) async fn fill_wanted(
    servers: &[nzbkit::config::ServerConfig],
    target: &Par2Set,
    wanted: &[Wanted],
    donor_nzbs: &[PathBuf],
    donor_dirs: &[PathBuf],
    cancel: Option<&crate::repair::SideCancel>,
) -> FillReport {
    let mut out = FillReport::default();
    // `wanted.file` indexes `target.files` three times below and this is
    // the door the tests come in through as well as `wanted_files`, so
    // the range is checked once here rather than trusted three times.
    let wanted: Vec<&Wanted> = wanted
        .iter()
        .filter(|w| w.file < target.files.len() && !w.bad.is_empty())
        .collect();
    if wanted.is_empty() || donor_nzbs.is_empty() || servers.is_empty() || target.block_size == 0 {
        return out;
    }
    let holes: usize = wanted.iter().map(|w| w.bad.len()).sum();
    info!(
        target: "repair",
        "🔎 {holes} bad block(s) across {} file(s) - looking for them in {} duplicate posting(s) \
         before spending recovery blocks",
        wanted.len(),
        donor_nzbs.len()
    );
    let deadline = std::time::Instant::now() + FILL_BUDGET;
    let mut healers: std::collections::BTreeMap<usize, BlockHealer> = wanted
        .iter()
        .map(|w| {
            (
                w.file,
                BlockHealer::new(
                    &target.files[w.file].blocks,
                    target.block_size,
                    target.files[w.file].length,
                    &w.bad,
                ),
            )
        })
        .collect();
    // THE DISK FIRST. Every byte proved here is a donor article this
    // pass does not have to ask for - see `fill_from_donor_dirs` for
    // why the two sources coexist on a switch job and why nothing is
    // offered until it has already proved. It runs BEFORE the loop
    // rather than as a donor inside it because it is not a donor: it
    // asks nobody, and a block it proves is one no posting is asked
    // for. What it leaves open the loop below picks up unchanged.
    fill_from_donor_dirs(target, &wanted, &mut healers, donor_dirs, &mut out);
    // Proved blocks, per set-file index, accumulated across donors.
    // The WRITE is still one pass at the end (below); what has to
    // happen per donor is the JUDGEMENT, because that is what tells a
    // block it was served a corrupt copy - and only a judged block can
    // be re-opened for the donor behind.
    let mut proved: std::collections::BTreeMap<usize, Vec<nzbkit::dupedonor::Healed>> =
        std::collections::BTreeMap::new();
    for donor in donor_nzbs {
        if healers.values().all(BlockHealer::is_satisfied) {
            break;
        }
        if cancel.is_some_and(crate::repair::SideCancel::is_cancelled)
            || std::time::Instant::now() >= deadline
        {
            break;
        }
        one_donor(servers, target, donor, &mut healers, deadline, &mut out).await;
        for (file, h) in healers.iter_mut() {
            let took = h.take_healed();
            if !took.is_empty() {
                proved.entry(*file).or_default().extend(took);
            }
            // Whatever this donor got wrong goes back on the wanted
            // list, empty, for whoever is next. With no donor left this
            // costs nothing: the block simply stays open and unfilled,
            // and an unfilled block is never handed out.
            let back = h.reopen_rejected();
            if back > 0 {
                info!(
                    target: "repair",
                    "{}: {back} borrowed block(s) failed this set's own checksums - \
                     trying the next duplicate posting for them",
                    donor.display()
                );
            }
        }
    }
    // LAST, and only over blocks the loop above left PART-served: the
    // bytes this download already has. Every donor has been asked and
    // judged by now, so nothing here can take a block from a posting
    // that would have served it whole.
    stitch_from_the_targets_own_bytes(target, &wanted, &mut healers, &mut proved, &mut out);
    // The write is the last step and it is per FILE: a block is only
    // ever handed out proved, so what lands on disk is what the set
    // says was there.
    for w in &wanted {
        let Some(h) = healers.get_mut(&w.file) else {
            continue;
        };
        // The loop above judges after every donor, so this only ever
        // picks up a block completed by a donor that then broke off -
        // cancelled, over budget, or out of servers.
        let mut healed = proved.remove(&w.file).unwrap_or_default();
        healed.extend(h.take_healed());
        healed.sort_unstable_by_key(|x| x.block);
        out.rejected += h.rejected();
        if healed.is_empty() {
            continue;
        }
        let (landed, err) = write_healed(&w.path, &healed);
        if let Some(e) = err {
            // Every block that DID land still counts: the write is
            // positioned and per block, so a failure part-way through
            // leaves the earlier ones exactly as proved. What is left
            // is a hole, which is what it was before this pass ran.
            warn!(
                target: "repair",
                "{}: {} borrowed block(s) could not be written ({e}) - repair takes them instead",
                w.path.display(),
                healed.len() - landed.len()
            );
        }
        if landed.len() == w.bad.len() && !landed.is_empty() {
            // This file's LAST hole just closed. Read it back whole and
            // hold it to the set's own whole-file MD5 - the bar §305's
            // plan-side adoption and the repair's own rebuild both use,
            // and the only evidence strong enough for what the caller
            // does with this list. Streaming, because a volume is
            // gigabytes and this must not be a whole-file allocation.
            //
            // A failure here is not an error: it means the file is not
            // whole after all (a short write, a byte the block grid
            // cannot see, a set whose IFSC and FileDesc disagree), and
            // the honest answer is simply not to claim it.
            match std::fs::File::open(&w.path).and_then(|f| {
                nzbkit::par2::verify_file_streaming(
                    &target.files[w.file],
                    target.block_size,
                    std::io::BufReader::new(f),
                )
            }) {
                Ok(v) if v.md5_ok => out.proven.push(w.sidx),
                Ok(_) => warn!(
                    target: "repair",
                    "{}: every borrowed block proved, but the file as a whole does not \
                     match the recovery set - not claiming it whole",
                    w.path.display()
                ),
                Err(e) => warn!(
                    target: "repair",
                    "{}: could not read the filled file back to prove it whole ({e})",
                    w.path.display()
                ),
            }
        }
        if !landed.is_empty() {
            out.healed += landed.len();
            info!(
                target: "repair",
                "✔ {}: {} block(s) borrowed from a duplicate posting - \
                 no recovery block spent on them",
                w.path.file_name().unwrap_or_default().to_string_lossy(),
                landed.len()
            );
            out.healed_blocks.push((w.sidx, landed));
        }
    }
    // `rejected` is what a DONOR's bytes were refused for, and
    // `note_dupefill` says it out loud as such. A stitch judges a block
    // made of the donor's bytes AND our own, so its refusals are
    // counted apart above and taken back out here rather than charged
    // to a posting that may have served its half perfectly.
    out.rejected = out.rejected.saturating_sub(out.stitch_refused);
    out
}

/// The slots this pass can work on. Everything it refuses, it refuses
/// here, so the callers below never have to re-ask.
///
/// `set_index` says WHICH of the job's adopted sets `target` is, indexed
/// the way `LiveVerifier::sets` is, and the first thing this does with
/// each report is ask the verifier whether that report's slot belongs to
/// it. That guard is load-bearing on a per-file-set post (TODO 311) and
/// it is not a tidiness check.
///
/// What went wrong without it: the pairing below is by NAME - the
/// report's `par2_name` looked up in `target.files` - while settle runs
/// this pass once per set over the ONE SHARED report list, subtracting
/// each pass's result from it. Two sets of a per-file-set post routinely
/// name the same file (a duplicate posting, a poster who ran par2create
/// twice over one directory), and `block_size` is PER SET. So a report
/// left over from set A could be resolved inside set B, its bad blocks
/// opened at B's block size - a different byte range of the same file -
/// proved against B's own IFSC checksums, written, and then struck off
/// A's list by `apply_to`, which matches on slot index alone and knows
/// nothing about which set produced the entry. A's real hole then goes
/// unrepaired AND unreported: its damage count is short, and where that
/// hole was its only damage, no repair plan is built for the set at all.
/// A guard that only compared `block_size` would not close it either -
/// two sets of one post routinely share a block size and still have
/// different IFSC tables.
///
/// The predicate is the one settle's own damage loop already charges
/// bad blocks with, `LiveVerifier::slot_set`, so the two cannot drift
/// into disagreeing about which set owns a slot. On a single-set post
/// every report belongs to set 0, so this refuses nothing there.
fn wanted_files(
    target: &Par2Set,
    set_index: usize,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    reports: &[(usize, nzbkit::live::SlotReport)],
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<crate::unpack::FileSlot>],
    out_dir: &Path,
) -> Vec<Wanted> {
    let mut out = Vec::new();
    for (sidx, r) in reports {
        if r.bad_blocks.is_empty() {
            continue;
        }
        // THIS set's reports only - see the doc comment above for what a
        // sibling set's report costs if it gets in here. Deliberately
        // `!= Some(set_index)` and not `is_some_and(..)`: a slot the
        // verifier cannot place in any set has no set vouching for its
        // block grid, so it is nobody's business rather than everybody's.
        if verifier.slot_set(*sidx) != Some(set_index) {
            continue;
        }
        // A mapped or chased slot has no file to patch - see the module
        // docs. Skipped rather than guessed at, and no longer skipped
        // for good: the second entry point runs this same resolver
        // after the repair has materialized those volumes, when the
        // test below is false because the slot owns a file.
        if extractor.is_mapped(*sidx) || extractor.is_chased(*sidx) {
            continue;
        }
        let Some(name) = r.par2_name.as_deref() else {
            continue;
        };
        // The set entry this slot settled against, by the name the
        // report itself carries - so the pairing is the verifier's own
        // and not re-derived here.
        let Some(file) = target.files.iter().position(|f| f.name == name) else {
            continue;
        };
        if target.files[file].blocks.is_empty() {
            continue;
        }
        let path = extractor.slot_path(*sidx).or_else(|| {
            let p = out_dir.join(nzbkit::disk::sanitize_filename(&slots[*sidx].hint));
            p.exists().then_some(p)
        });
        let Some(path) = path.filter(|p| p.is_file()) else {
            continue;
        };
        // One set FILE, one entry. The healers below are keyed by this
        // index, so a second slot claiming the same set member would
        // collapse onto the first one's healer and then have that
        // healer's blocks written to BOTH paths. The verifier claims a
        // set member for one slot, so this should not arise; a claim
        // that cannot be shown to be about distinct files is not one to
        // act on either way.
        if out.iter().any(|w: &Wanted| w.file == file) {
            warn!(
                target: "repair",
                "two slots settled against the same recovery-set member ({name}) -                  not borrowing for either",
            );
            out.retain(|w: &Wanted| w.file != file);
            continue;
        }
        out.push(Wanted {
            sidx: *sidx,
            file,
            path,
            bad: r.bad_blocks.clone(),
        });
    }
    out
}

/// How many donor-directory files one member may be tried against.
///
/// The candidates below are NAME matches, so in every shape this pass
/// was written for there is exactly one. The cap is there because the
/// list is built off a directory listing that nothing here owns: a
/// donor directory holding a hundred spellings of one name must cost a
/// bounded number of reads per hole, not a hundred.
const MAX_DONOR_FILES: usize = 4;

/// The donor-directory files that may hold `name`'s bytes, best first.
///
/// **Matched by NAME, deliberately, and that is a stated limit rather
/// than an oversight.** A failed job's output is quarantined to
/// `<name>.nzbfast-partial` (see [`nzbkit::journal::PARTIAL_SUFFIX`]),
/// so both spellings are tried; anything else is left to §293's repair
/// adoption, whose SLIDING scan is what exists for a donor whose layout
/// does not line up with ours. This pass is only ever the cheap aligned
/// case - same release, same member, same offsets - and a miss here
/// costs nothing but the wire pass that would have run anyway.
///
/// Nothing this returns is trusted: every candidate's bytes are put to
/// the target set's own block MD5 and CRC32 before one of them is used.
fn donor_candidates(dirs: &[PathBuf], name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for d in dirs {
        for spelling in [
            name.to_string(),
            format!("{name}{}", nzbkit::journal::PARTIAL_SUFFIX),
        ] {
            let p = d.join(&spelling);
            if p.is_file() && !out.contains(&p) {
                out.push(p);
            }
            if out.len() >= MAX_DONOR_FILES {
                return out;
            }
        }
    }
    out
}

/// Serve what the failed predecessor's OWN FILES already hold, before a
/// socket is opened for the same bytes.
///
/// # Why this runs at all
///
/// `donor_dirs` and `donor_nzbs` are populated from the SAME `alt_from`
/// in `serve::tasks::worker::start_next`, and on a switch job the two
/// always coexist: a promotion fires only on a GENUINE failure
/// (`daemon_park::promote_held_alternative` refuses a tombstone, which
/// is what a user delete sets), so the predecessor must have RUN - and
/// a posting's live articles are on the disk of the job that fetched
/// them, by definition. So the very blocks this pass can borrow off the
/// wire are, in the ordinary case, blocks the predecessor already wrote
/// down. Measured on the M31 A/B shape (see
/// `research/M31-DUPEFILL-DISK-FIRST-2026-08-28.md`): ALL of the 120,000
/// borrowed payload bytes were already byte-identical in the donor
/// directory, and the donor fetch was 167,782 bytes - half the
/// successor's entire wire traffic for the run.
///
/// # Why it cannot poison a block, which is the constraint that shapes it
///
/// The predecessor's file is SPARSE exactly where its own articles
/// died - which is why it failed - so the tempting version of this
/// pass, offering whatever it reads, would hand the healer a block of
/// zeros. FIRST BYTES WIN inside [`BlockHealer`]: bytes over a range
/// some earlier offer already filled are ignored, so those zeros are
/// what the block would then be judged on.
///
/// M31 item 3 (`BlockHealer::reopen_rejected`) softened that ACROSS
/// donors - a block one donor got wrong is re-opened EMPTY for the next
/// - and it does not rescue this. The poisoned block is fully covered
/// before the loop starts, so `wanted()` no longer names it and the
/// first donor is never asked for it at all; it is only judged, and
/// re-opened, once that donor is spent. With stage 1's single donor
/// source - the failed predecessor - there is no next posting, and the
/// block goes to repair. It would be a REGRESSION, not a saving.
///
/// So nothing is offered until it has already proved. Each block's
/// range is read, put to that block's own MD5 and CRC32 with
/// [`nzbkit::live::check_block`] - the same predicate
/// [`BlockHealer::take_healed`] judges a wire-assembled block by - and
/// only then handed to `offer`. A block the disk cannot prove is left
/// untouched and open, exactly as if this pass had not run.
///
/// # What it does NOT change
///
/// The pass's POPULATION. It runs only where `fill_wanted` was going to
/// run anyway, so a job with donor directories and no donor NZB is
/// still repair's business and still reaches §293's adoption scan
/// unchanged. This is a cheaper SOURCE for a pass that was happening,
/// not a new pass.
///
/// Which also bounds what the measurement above is worth, and the bound
/// has since moved: `wanted_files` skips a mapped or chased slot, so at
/// the settle-time entry point a RAR-payload job still reaches neither
/// half of this pass and none of that saving applies THERE. It reaches
/// both at the second entry point (M31 handoff item 4, `get::settle::
/// fill_from_duplicates_off_materialized_volumes`), by which time the
/// volume is a file - but a materialized volume is the successor's own
/// work rather than the predecessor's, so what this arm reads in the
/// donor DIRECTORY is unchanged and the -49.9% figure is still the
/// plain-file shape's.
fn fill_from_donor_dirs(
    target: &Par2Set,
    wanted: &[&Wanted],
    healers: &mut std::collections::BTreeMap<usize, BlockHealer>,
    donor_dirs: &[PathBuf],
    out: &mut FillReport,
) {
    // `block_size` is the padding width the target's checksums were
    // taken over, which is what `take_healed` hands `check_block` too -
    // the two must agree or a good block reads as bad.
    let bs = nzbkit::disk::chunk_len(target.block_size, usize::MAX);
    if bs == 0 {
        return;
    }
    for w in wanted {
        let Some(h) = healers.get_mut(&w.file) else {
            continue;
        };
        if h.is_empty() || h.is_satisfied() {
            continue;
        }
        let f = &target.files[w.file];
        let cands = donor_candidates(donor_dirs, &f.name);
        if cands.is_empty() {
            continue;
        }
        // Opened once per candidate rather than once per block: a hole
        // is many consecutive blocks and this is a positioned read, so
        // one handle serves all of them.
        let open: Vec<std::fs::File> = cands
            .iter()
            .filter_map(|p| std::fs::File::open(p).ok())
            .collect();
        if open.is_empty() {
            continue;
        }
        let mut buf = vec![0u8; bs];
        for &b in &w.bad {
            if b >= f.blocks.len() {
                continue;
            }
            let off = (b as u64).saturating_mul(target.block_size);
            if off >= f.length {
                continue;
            }
            // The LAST block of a file is short, and its checksum was
            // taken over the padded width - `check_block` does that
            // padding itself, so what it wants is the real length.
            let len = nzbkit::disk::chunk_len(f.length - off, bs);
            for file in &open {
                if nzbkit::disk::read_exact_at(file, &mut buf[..len], off).is_err() {
                    continue;
                }
                if !nzbkit::live::check_block(&f.blocks[b], bs, &buf[..len]) {
                    continue;
                }
                out.local_bytes += h.offer(off, &buf[..len]);
                out.local += 1;
                break;
            }
        }
    }
}

/// Everything one donor posting can contribute.
async fn one_donor(
    servers: &[nzbkit::config::ServerConfig],
    target: &Par2Set,
    donor_path: &Path,
    healers: &mut std::collections::BTreeMap<usize, BlockHealer>,
    deadline: std::time::Instant,
    out: &mut FillReport,
) {
    let Some(donor) = read_nzb(donor_path) else {
        return;
    };
    let Some(set) = donor_set(servers, &donor, deadline).await else {
        return;
    };
    // The gate that decides whether this donor can help AT ALL: the two
    // sets have to agree, digest for digest, that a file is the same
    // bytes. A different encode of the same release agrees about
    // nothing and stops here, having cost one small index fetch.
    let matches = nzbkit::dupedonor::match_by_content(target, &set);
    if matches.is_empty() {
        info!(
            target: "repair",
            "{}: a duplicate posting of a DIFFERENT encode - no byte range in common, \
             nothing to borrow",
            donor_path.display()
        );
        return;
    }
    let by_name = donor_files_by_name(&donor);
    let mut asks: Vec<Ask> = Vec::new();
    for m in &matches {
        let Some(h) = healers.get(&m.target) else {
            continue;
        };
        let want = h.wanted();
        if want.is_empty() {
            continue;
        }
        let Some(&fi) = by_name.get(&fold(&set.files[m.donor].name)) else {
            // An obfuscated donor: the index names the member, the NZB
            // does not. Stated limit, see the module docs.
            continue;
        };
        let enc: Vec<u64> = donor.files[fi].segments.iter().map(|s| s.bytes).collect();
        let segs = nzbkit::dupedonor::candidate_segments(&enc, m.length, &want, SEG_SLACK);
        if segs.is_empty() {
            continue;
        }
        // Nearest a hole first. The first article back is the anchor
        // every later cut of this plan is made against, so asking for
        // the one the fill most likely needs is also asking for the one
        // that calibrates it best - see `ask_order`.
        let segs = nzbkit::dupedonor::ask_order(&enc, m.length, &want, &segs);
        asks.push(Ask {
            segs: segs
                .iter()
                .map(|&i| (i, format!("<{}>", donor.files[fi].segments[i].message_id)))
                .collect(),
            enc,
            want,
            length: m.length,
            file: m.target,
        });
    }
    if asks.is_empty() {
        return;
    }
    fetch_and_offer(servers, &asks, target, healers, deadline, out).await;
}

/// The donor's own recovery index, off the wire. Its FileDesc packets
/// are the only thing that can say the two postings carry the same
/// bytes, and an NZB carries no digest at all.
async fn donor_set(
    servers: &[nzbkit::config::ServerConfig],
    donor: &Nzb,
    deadline: std::time::Instant,
) -> Option<Par2Set> {
    let main = donor
        .files
        .iter()
        .find(|f| f.kind() == FileKind::Par2Main)?;
    let ids: Vec<String> = main
        .segments
        .iter()
        .map(|s| format!("<{}>", s.message_id))
        .collect();
    if ids.is_empty() {
        return None;
    }
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    // The LARGEST set only, deliberately (TODO 311's last box). The
    // probe adopts every set its accumulated articles cover; `match_by_content`
    // pairs target members with donor members one whole `Par2Set` at a
    // time and keeps its `taken` bookkeeping inside that one call, so
    // running it per set would let two donor sets both claim one target
    // member and ask for the same holes twice. `pick_sets` orders
    // largest first, ties by set id, so the pick does not depend on
    // which article came back first.
    //
    // Strictly better than what it replaces, and in the safe direction:
    // a donor member outside the largest set is simply not borrowed
    // from, where the old singular door answered `None` the moment the
    // articles covered two sets and this donor contributed nothing.
    tokio::time::timeout(left, nzbkit::preflight::probe_par2_sets(servers, &ids))
        .await
        .ok()
        .flatten()
        .and_then(|sets| sets.into_iter().next())
}

/// Ask for the donor articles and offer every decoded body to the
/// healer that wanted it.
///
/// Sequential, on one connection per server, deliberately: the whole
/// ask is a handful of articles for a handful of holes, and a pass that
/// built a pool would have to be accounted for against the job's
/// connection budget for no throughput it could use.
async fn fetch_and_offer(
    servers: &[nzbkit::config::ServerConfig],
    asks: &[Ask],
    target: &Par2Set,
    healers: &mut std::collections::BTreeMap<usize, BlockHealer>,
    deadline: std::time::Instant,
    out: &mut FillReport,
) {
    let mut spent = 0usize;
    // Per TARGET FILE, every article of that file whose placement the
    // wire has stated. Outside the server loop deliberately: a donor
    // file's geometry does not change because the next server is being
    // asked. Kept as a LIST rather than the newest one, because the cut
    // below wants the anchor NEAREST the segment it is judging - the
    // calibrated slack is the file's own inflation over the gap back to
    // the anchor, so a nearer one is a tighter guess, and an ask that
    // walks the holes rather than the file has no "newest is nearest".
    let mut anchors: std::collections::BTreeMap<usize, Vec<SegAnchor>> =
        std::collections::BTreeMap::new();
    for server in servers {
        let outstanding: Vec<&Ask> = asks
            .iter()
            .filter(|a| {
                healers
                    .get(&a.file)
                    .is_some_and(|h| !h.is_empty() && !h.is_satisfied())
            })
            .collect();
        if outstanding.is_empty() || spent >= MAX_FILL_BYTES {
            break;
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let one = async {
            let Ok((mut conn, _)) = nzbkit::nntp::Connection::connect(server).await else {
                return;
            };
            for ask in &outstanding {
                for (idx, id) in &ask.segs {
                    let Some(h) = healers.get_mut(&ask.file) else {
                        break;
                    };
                    // The estimate that cut this list is BLIND - an NZB
                    // states encoded sizes and no offsets at all. Every
                    // article that comes back says exactly where it sat,
                    // so the rest of the list is re-cut against the
                    // nearest of those facts instead of against a
                    // proportion assumed of the whole file (see
                    // `candidate_segments_anchored`). A segment the
                    // calibrated cut no longer puts over a hole is not
                    // asked for - `continue` and never `break`, because
                    // a later one in the list can still be wanted.
                    let near = anchors
                        .get(&ask.file)
                        .and_then(|v| v.iter().min_by_key(|a| a.index.abs_diff(*idx)))
                        .copied();
                    if near.is_some()
                        && !nzbkit::dupedonor::candidate_segments_anchored(
                            &ask.enc, ask.length, &ask.want, SEG_SLACK, near,
                        )
                        .contains(idx)
                    {
                        continue;
                    }
                    // `is_satisfied` and not just `is_empty`: a block
                    // stays open until it is PROVED, which happens once
                    // at the end, so without this the estimate's slack
                    // would keep pulling donor bodies for blocks every
                    // byte of which is already in hand.
                    if h.is_empty() || h.is_satisfied() {
                        break;
                    }
                    let room = MAX_FILL_BYTES.saturating_sub(spent);
                    if room == 0 {
                        break;
                    }
                    // A donor that has gone missing here is this
                    // server's answer, not the posting's - keep asking
                    // for the rest and let the next server try.
                    let Ok(Some(raw)) = conn.body_capped(id, room).await else {
                        continue;
                    };
                    spent += raw.len();
                    out.bodies += 1;
                    let Ok(dec) = nzbkit::yenc::decode(&raw) else {
                        continue;
                    };
                    let p = Placement {
                        file_size: dec.file_size,
                        off: dec.offset(),
                        len: dec.data.len() as u64,
                        declared_end: dec.end,
                    };
                    // The cheap gate, before any hashing: an article
                    // whose own account of itself does not fit the file
                    // we are filling is dropped here.
                    if !nzbkit::dupedonor::placement_ok(&p, target.files[ask.file].length) {
                        continue;
                    }
                    out.bytes += h.offer(p.off, &dec.data);
                    // An article that passed the placement gate has
                    // stated its offset and been believed for the bytes
                    // themselves; that same statement is what re-cuts
                    // the rest of the plan.
                    anchors.entry(ask.file).or_default().push(SegAnchor {
                        index: *idx,
                        off: p.off,
                    });
                }
            }
            conn.quit().await;
        };
        // A blackholed donor server must not hold the whole pass; the
        // budget is the sum, not the per-server allowance.
        let _ = tokio::time::timeout(left, one).await;
    }
}

/// Write the proved blocks into the file they belong to, and report
/// which ones LANDED.
///
/// Positioned writes into the existing file, never a rewrite: every
/// other byte of it is what the download placed, and the settle
/// read-back that produced this bad-block list read exactly those.
///
/// Returns the block indices now on disk plus the error that stopped
/// it, rather than one or the other. A partial write is not a failed
/// pass: each block is written at its own offset, so the ones that
/// went down are good and the rest are holes - which is what they were
/// when this pass started. Reporting only the error would throw away
/// blocks that really did heal, and reporting only success would claim
/// blocks that never landed.
/// Complete a block a donor could only PART-serve, out of the bytes
/// this download already has, and judge it.
///
/// # Why a whole-block source is not enough
///
/// The unit of proof is the BLOCK - `check_block` is an MD5 and a
/// CRC32 over one - so every source this pass had until now has to
/// supply a block ENTIRELY or contribute nothing at all. That is fine
/// while an article is at least as wide as a block, because then a lost
/// article costs whole blocks and a donor article buys them back whole.
///
/// It stops being fine the moment the set's block is WIDER than an
/// article, and that is not a corner: it is what `par2create` produces
/// on a large release, where the block count is fixed and the block
/// therefore grows with the payload.
///
/// Measured, on a real store-RAR switch
/// (`research/DONOR-ADOPT-ZERO-ON-STORE-RAR-2026-08-28.md`): a
/// 1,536,000-byte block over 768,000-byte articles is exactly two
/// articles wide, so block `k` covers articles `2k` and `2k+1`. A
/// stride-2 article mask damages one article of every pair in BOTH
/// postings, so neither of them holds one whole block of the damaged
/// range - and the two mechanisms that could have bridged it both got
/// nothing. TODO 293's block adoption took 22 of 290 (the edge blocks),
/// the job stayed `Unrepairable`, and this pass would have healed ZERO
/// had it run at all. Between them the two postings held every byte.
///
/// So: the donor serves the half it has, and the target's own copy -
/// the download that is sitting right there - serves the other.
///
/// # Why this cannot poison a block, which is the constraint
///
/// The target's copy of a bad block is exactly the copy the recovery
/// set already called bad, so offering it is offering bytes at least
/// one of which is known wrong somewhere in the block. FIRST BYTES WIN
/// inside [`BlockHealer`], so getting this the wrong way round would be
/// a REGRESSION and not a saving - the whole argument
/// [`fill_from_donor_dirs`] carries about the predecessor's sparse file
/// applies here with more force, because these bytes are not merely
/// possibly absent, they are provably insufficient.
///
/// Three rules keep it strictly additive, and each is load-bearing:
///
/// - **LAST.** Every donor has been asked and judged before this runs,
///   so a block a posting would have served whole was served whole. The
///   stitch only ever sees what was about to be abandoned to repair.
/// - **PART-SERVED ONLY** ([`BlockHealer::part_filled`]). A block no
///   donor touched is skipped: the target's copy of it is the copy that
///   was called bad, so completing it from our own bytes would buy an
///   MD5 and a CRC32 to be told so again, once per block.
/// - **THE GAPS ONLY.** [`BlockHealer::offer`] writes what is not
///   already filled, so the donor's bytes are never displaced by ours.
///
/// And the proof bar is untouched: a stitched block reaches
/// `healed_blocks` on exactly the evidence a wire-assembled one does -
/// the target set's own MD5 and CRC32 over the finished block, judged
/// by [`BlockHealer::take_healed`], which cannot tell where any byte in
/// it came from and is not asked to.
fn stitch_from_the_targets_own_bytes(
    target: &Par2Set,
    wanted: &[&Wanted],
    healers: &mut std::collections::BTreeMap<usize, BlockHealer>,
    proved: &mut std::collections::BTreeMap<usize, Vec<nzbkit::dupedonor::Healed>>,
    out: &mut FillReport,
) {
    // The padding width the target's checksums were taken over, which
    // is what `take_healed` hands `check_block` too - the two must
    // agree or a good block reads as bad.
    let bs = nzbkit::disk::chunk_len(target.block_size, usize::MAX);
    if bs == 0 {
        return;
    }
    for w in wanted {
        let Some(h) = healers.get_mut(&w.file) else {
            continue;
        };
        let part = h.part_filled();
        if part.is_empty() {
            continue;
        }
        let f = &target.files[w.file];
        // The slot's own file, opened once for every block of it: a
        // hole is many consecutive blocks and these are positioned
        // reads.
        let Ok(file) = std::fs::File::open(&w.path) else {
            continue;
        };
        let mut buf = vec![0u8; bs];
        let before = h.rejected();
        let mut offered = 0usize;
        for b in part {
            if b >= f.blocks.len() {
                continue;
            }
            let off = (b as u64).saturating_mul(target.block_size);
            if off >= f.length {
                continue;
            }
            // The LAST block of a file is short and its checksum was
            // taken over the padded width; `check_block` does that
            // padding itself, so what it wants is the real length.
            let len = nzbkit::disk::chunk_len(f.length - off, bs);
            if nzbkit::disk::read_exact_at(&file, &mut buf[..len], off).is_err() {
                continue;
            }
            // Only the gaps land - the donor's own bytes are already
            // filled and `offer` will not write over them.
            if h.offer(off, &buf[..len]) > 0 {
                offered += 1;
            }
        }
        if offered == 0 {
            continue;
        }
        let took = h.take_healed();
        out.stitched += took.len();
        out.stitch_refused += h.rejected().saturating_sub(before);
        if !took.is_empty() {
            proved.entry(w.file).or_default().extend(took);
        }
    }
}

fn write_healed(
    path: &Path,
    healed: &[nzbkit::dupedonor::Healed],
) -> (Vec<usize>, Option<std::io::Error>) {
    let f = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        Err(e) => return (Vec::new(), Some(e)),
    };
    let mut landed = Vec::new();
    for h in healed {
        if let Err(e) = nzbkit::disk::write_all_at(&f, &h.bytes, h.off) {
            // Same rule as the sync below: the blocks that DID write may
            // only be claimed once they are on the medium. If that sync
            // fails too, claim nothing - the write error is the one
            // reported either way, being the more informative of the two.
            if f.sync_all().is_err() {
                return (Vec::new(), Some(e));
            }
            return (landed, Some(e));
        }
        landed.push(h.block);
    }
    // The subtraction the caller makes from its bad-block list rests on
    // these bytes being on the medium, not in a page cache the extract
    // that follows may or may not see through.
    if let Err(e) = f.sync_all() {
        return (Vec::new(), Some(e));
    }
    (landed, None)
}

/// A donor NZB off disk. Every failure is "this donor contributes
/// nothing" and never a failed job.
fn read_nzb(path: &Path) -> Option<Nzb> {
    let bytes = std::fs::read(path).ok()?;
    Nzb::parse(&bytes).ok()
}

/// Donor NZB data files by folded filename hint - the only bridge from
/// a FileDesc name to the segments that carry it.
fn donor_files_by_name(donor: &Nzb) -> std::collections::HashMap<String, usize> {
    let mut out: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut dup: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (fi, f) in donor.files.iter().enumerate() {
        if f.kind() != FileKind::Data || f.segments.is_empty() {
            continue;
        }
        let Some(hint) = f.filename_hint_lenient() else {
            continue;
        };
        let key = fold(hint);
        if out.insert(key.clone(), fi).is_some() {
            // Two files posting one name identify neither, exactly as
            // §305's `want` map decides it.
            dup.insert(key);
        }
    }
    out.retain(|k, _| !dup.contains(k));
    out
}

/// The name key both sides are compared on: the NZB subject and the
/// FileDesc packet are two records of one filename written by different
/// tools, so case and path separators are not evidence.
fn fold(name: &str) -> String {
    nzbkit::disk::sanitize_filename(name).to_ascii_lowercase()
}

#[cfg(test)]
#[path = "dupefill_tests.rs"]
mod dupefill_tests;

// TODO 311 over M31: which SLOTS one set's pass may work on. Its own
// module because `dupefill_tests` deliberately does not reach
// `wanted_files` - it hands `fill_wanted` a `Wanted` list directly, so
// the resolver had no test of any kind and that is where the cross-set
// defect lived.
#[cfg(test)]
#[path = "dupefill_scope_tests.rs"]
mod dupefill_scope_tests;
