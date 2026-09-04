//! PLAN M31: run the duplicate-donor pass over every recovery set of
//! the job, and say what it did.
//!
//! Two functions and one subject - the caller loop and its summary
//! line - lifted out of settle.rs whole and verbatim (TODO 106, 31 Aug
//! 2026) when the pass budget's own scope fix took that file back over
//! its size-gate ceiling. Same seam shape as [`super::repair`]: one
//! call edge out per function, and the parent's private helpers stay
//! visible here because a child module can see them.
//!
//! `note_dupefill` has TWO callers - `fill_from_duplicates` below, and
//! the SECOND entry point in [`super::repair`], which runs the same
//! pass again over the volumes a repair has just materialized. It is
//! re-exported into settle's own namespace for that reason, so
//! repair.rs's `use super::*` still reaches it.

use super::*;

/// PLAN M31 observability: what the duplicate-donor pass did, in the
/// one place that knows both what it healed and what it refused.
///
/// A pass that healed nothing is SILENT unless it also refused
/// something OR was stopped by a ceiling. Every switch job runs this
/// over every damaged file, and "looked and found nothing" on each one
/// is the log line that gets a whole target switched off; a REFUSAL is
/// different - donor bytes arrived and failed the target's own
/// checksums, which is a fact about the donor worth saying out loud -
/// and so is a TRUNCATION, which is holes never looked for.
pub(super) fn note_dupefill(f: &crate::get::dupefill::FillReport) {
    if f.healed > 0 {
        info!(
            target: "repair",
            "🤝 recovered {} block(s) from a duplicate posting ({} off the \
             predecessor's own files, {} article(s) fetched, {:.1} MB off the \
             wire of which {:.1} MB landed in a block) - no PAR2 \
             recovery block spent on them",
            f.healed,
            f.local,
            f.bodies,
            // The two are DIFFERENT quantities and were one line until
            // 31 Aug 2026, which read the accepted figure as the wire
            // cost: an article refused by the placement gate, or whose
            // block turned out already covered, is in the first and not
            // the second. The first is what `MAX_FILL_BYTES` caps, so
            // it is the one a ceiling round needs off a field install.
            f.wire_bytes as f64 / 1e6,
            f.bytes as f64 / 1e6
        );
    }
    if f.stitched > 0 {
        info!(
            target: "repair",
            "   ...of which {} needed this download's own surviving bytes as \
             well: the set's block is wider than an article, so neither \
             posting held one whole",
            f.stitched
        );
    }
    if f.rejected > 0 {
        warn!(
            target: "repair",
            "{} block(s) offered by a duplicate posting failed this set's own \
             checksums and were discarded - repair covers them instead",
            f.rejected
        );
    }
    // Said apart from the line above, and worded apart: a stitched
    // block is the donor's bytes AND ours, so a refusal here is not a
    // fact about the posting the way `rejected` is.
    if f.stitch_refused > 0 {
        warn!(
            target: "repair",
            "{} block(s) made up from a duplicate posting's bytes plus this \
             download's own failed this set's checksums - repair covers them",
            f.stitch_refused
        );
    }
    // THE ONE ARM NOT GATED ON A COUNTER, and the reason it is not: a
    // pass stopped by a ceiling having healed nothing is exactly the
    // case a calibration lane needs to see, and every arm above needs a
    // success or a refusal, so until 31 Aug 2026 that case logged
    // nothing whatever. The outcome is usually unchanged - repair
    // covers what the pass did not reach - so without this line the
    // cost is invisible from the field.
    if let Some(stop) = f.stopped {
        warn!(
            target: "repair",
            "⏱ the duplicate-posting pass stopped on {} having fetched {} \
             article(s) and {:.1} MB off the wire, so some holes were never \
             looked for - repair covers those instead",
            stop.ceiling(),
            f.bodies,
            f.wire_bytes as f64 / 1e6
        );
    }
    // THE SECOND ARM NOT GATED ON A SUCCESS OR A REFUSAL, and for the
    // same reason as the one above: this is damage the pass never
    // looked at, so every counter it would otherwise be gated on is
    // zero. On a RAR payload that is the whole of the job's damage, and
    // the log then said nothing at all - identical to a job that had no
    // damage to borrow for, which is the opposite fact.
    //
    // `info` and not `warn`: repair covers these blocks and the outcome
    // is usually unchanged, so this is an observation about WHERE the
    // pass can reach today and not a problem with this job. See
    // [`crate::get::dupefill::FillReport::unlooked_slots`] for what it
    // is measuring and for the decision it was added to inform.
    if f.unlooked_slots > 0 {
        info!(
            target: "repair",
            "the duplicate-posting pass left {} damaged block(s) in {} \
             file(s) unexamined - those are still held in the extractor \
             rather than written to disk, so repair covers them instead",
            f.unlooked_blocks,
            f.unlooked_slots
        );
    }
}

/// PLAN M31 stage 1: fill what a duplicate posting can fill, ONE PASS
/// PER RECOVERY SET, and return `incomplete` less whatever the pass
/// proved whole off disk.
///
/// It belongs exactly where the caller puts it: after the read-back
/// has said which blocks are bad, and before anything is allowed to
/// spend a recovery block rebuilding one. A block borrowed from a
/// duplicate posting costs payload bytes and no parity; the same block
/// rebuilt costs a recovery slice that a later hole then cannot have.
///
/// It never pre-empts the whole-release machinery above it either: a
/// dupe promotion or a §284 switch is a decision about which POST to
/// download and was taken by the daemon long before this. This only
/// ever patches the post already on disk, only for blocks it could
/// not get, and only when the two postings' recovery sets agree
/// digest-for-digest that a file is the same bytes.
///
/// What the pass claims is not taken on trust and is not re-derived
/// by hashing either: `apply_to` subtracts exactly the blocks whose
/// rebuilt bytes matched THIS set's own MD5 and CRC32 and were then
/// written and synced. Re-running `settle_slots` would reach the
/// same answer and is the wrong instrument - it renames slots and
/// publishes verified names as it goes, so it is not a read-only
/// act to repeat. `damage_in_mapped` needs no revision for the same
/// reason the pass is safe: it never touches a mapped or chased
/// slot. The SECOND entry point (M31 item 4,
/// [`fill_from_duplicates_off_materialized_volumes`]) does reach
/// those slots, and needs no revision either - it runs after the
/// materialize loop has already set that flag for every one of
/// them.
///
/// PER SET, for TODO 311's own reason one door along: a borrowed
/// block is PROVED against a `BlockCheck`, and those live in the set
/// that describes the file - `block_size` and the IFSC table are per
/// set. A post shipping one set per file therefore gets one pass per
/// set, and each pass must see only the reports whose SLOT that set
/// claimed.
///
/// Which is why the loop index goes in with the set. `wanted_files`
/// pairs a report to a set member BY NAME, and two sets of one post
/// routinely name the same file - so name resolution alone let a
/// leftover report from set A be opened under set B's block size,
/// proved against B's checksums, written, and then struck off A's
/// bad-block list by `apply_to`, which keys on slot index alone. A's
/// hole then went unrepaired and unreported. The index is what lets
/// that pass ask `verifier.slot_set`, the SAME predicate the caller's
/// damage census charges bad blocks with, so the two cannot drift.
///
/// A free function rather than a block inside [`settle_with_set`],
/// which was at 472 of the size gate's 500-line ceiling on 31 Aug
/// 2026, and this is one subject. Nothing about the ordering moved - the caller still
/// invokes it between the read-back and the damage census.
#[expect(clippy::too_many_arguments)]
pub(super) async fn fill_from_duplicates(
    sets: &[Arc<nzbkit::par2::Par2Set>],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<FileSlot>],
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    out_dir: &Path,
    donor_nzbs: &[PathBuf],
    // §293's donor directories, threaded in beside the NZBs they are
    // populated from. Both come off the SAME `alt_from`, so on a switch
    // job the predecessor's own files usually already hold the blocks
    // the donor posting would be asked for - `dupefill` reads them
    // first and opens a socket only for what the disk cannot prove.
    donor_dirs: &[PathBuf],
    cancel: Option<&crate::repair::SideCancel>,
    reports: &mut [(usize, nzbkit::live::SlotReport)],
    incomplete: usize,
) -> usize {
    if donor_nzbs.is_empty() {
        return incomplete;
    }
    let mut incomplete = incomplete;
    let plain: Vec<ServerConfig> = servers.iter().map(|(c, _)| c.clone()).collect();
    let mut filled = crate::get::dupefill::FillReport::default();
    // ONE budget for the whole pass, created OUTSIDE this loop. It was
    // created inside `fill_wanted` until 31 Aug 2026, which made both
    // ceilings per SET: on GH #63's eighteen-set shape an unreachable
    // donor cost eighteen 90-second waits here rather than one. The
    // number of sets is the poster's choice, so that cost was bounded
    // by nothing this end controls - `dupefill::FILL_BUDGET` carries
    // the trade sharing it makes.
    let mut budget = crate::get::dupefill::FillPass::new();
    for (si, set) in sets.iter().enumerate() {
        let one = crate::get::dupefill::fill_from_duplicate_postings(
            &plain,
            set,
            si,
            verifier,
            reports,
            extractor,
            slots,
            out_dir,
            donor_nzbs,
            donor_dirs,
            cancel,
            &mut budget,
        )
        .await;
        one.apply_to(reports);
        filled.absorb(one);
    }
    // A file this pass closed the last hole in has been read back
    // WHOLE and matched the set's own MD5, which is what
    // `incomplete` is a proxy for - see `whole_files_proved` for
    // why that subtraction is sound and where its limit is. Without
    // it the pass can heal every byte of a job and the job still
    // fails on an article count, which is the one outcome that
    // would make borrowing pointless in the case M31 exists for.
    incomplete = incomplete.saturating_sub(filled.whole_files_proved(slots));
    note_dupefill(&filled);
    incomplete
}
