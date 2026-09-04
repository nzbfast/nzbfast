//! Settle verification and the repair ladder (TODO 106 phase 2.1,
//! cut 5): the parallel settle read-back, deobfuscation renames, damage
//! arithmetic, the mapped -> materialized -> RAR-recovery-record repair
//! ladder, and the no-set disk-side fallback. Bodies are verbatim moves
//! from the orchestrator's `match verifier.set()`.

use crate::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use tracing::{info, warn};

/// GH #63: may this FileDesc name replace the name the slot's file
/// already carries?
///
/// "The PAR2 FileDesc name is the real one" is true of an obfuscated
/// post whose set was built BEFORE the rename - #43, #47 and the whole
/// deobfuscation line - and false of one built AFTER it, where the set
/// lists the hashes back and the NZB subject is the truthful record.
/// `nzbfast-par2-name-recovery` measured that the second is the common
/// order; #63 is a post where every file ships its own set in it.
///
/// Refuses ONLY the losing direction, so a slot whose subject said
/// nothing keeps taking its FileDesc name exactly as before.
///
/// WHAT A REFUSAL MEANS AT THE SETTLE SEAM CHANGED ON 31 Aug 2026 and
/// this predicate did not: `settle_slots` no longer LEAVES the file
/// where it is on a no. It takes the set's spelling anyway - so the
/// disk-side repair can find its own member - and gives the better name
/// back after. See [`set_name_loses_to_held`]. The other two callers
/// (`super::sfvname`, `super::publishplan`) are unaffected: neither is
/// the door repair looks a member up through.
pub(super) fn filedesc_name_is_better(slot: &crate::unpack::FileSlot, pname: &str) -> bool {
    !slot.hint_beats(pname)
}

/// Wave-4 row M4-86 (31 Aug 2026): may `held` - the name the slot's file
/// carries right now - come BACK once the set has finished with it?
///
/// `par2::parse_filedesc` decodes the FileDesc name with
/// `String::from_utf8_lossy`, because the spec says the field is
/// ASCII/UTF-8. A poster who writes CP1252 there breaks that, and the
/// lossy decode does not fail, it SUBSTITUTES: `caf\xE9.mkv` comes back
/// `caf\u{FFFD}.mkv`, sanitizes unchanged, and lands on disk as a file
/// with a replacement character in its name - over a yEnc header that
/// spelled the same name well-formed. Measured on the 30 Aug 2026
/// baseline by `e2e_norar::encoding`: the job finished green and renamed
/// the good name to the mojibake one.
///
/// NOTHING IS GUESSED. Reading those bytes back as CP1252 would give
/// `caf\u{e9}.mkv` and is very likely what the poster meant - and it is
/// an ENCODING GUESS, which `nzbkit::par2::parse_unifilen` already ruled
/// out for this exact family in as many words ("a wrong name that LOOKS
/// landed is the one outcome neither answer may produce"). The spec's
/// channel for a non-ASCII name is the Unicode Filename packet, which
/// that function reads; M4-86 is the post that writes CP1252 and ships
/// no UniFileN. So this does not repair the name. It only declines to
/// LEAVE the file under one nobody can read when the post already
/// supplied one that reads.
///
/// # Why this is deferred and not a refusal at the rename
///
/// The obvious fix is to refuse the rename outright, and it was built
/// and MEASURED first: it is WORSE. The set's spelling is what the
/// disk-side repair looks a member up by, so a file left under the
/// readable name is a member the set cannot find - it adopts the bytes
/// by content and then CREATES its own copy beside them. Measured on
/// the damaged fixture: two 220,000-byte files, the good bytes in
/// `caf\u{FFFD}.mkv` and the DAMAGE left in `caf\u{e9}.mkv`, job green.
/// That is issue #9's shape, bought for a cosmetic name. So the rename
/// still happens, the whole repair runs against the name the set knows,
/// and the readable name comes back through `deferred_renames` in
/// `tail::report_extraction` - after `settle_verify_repair` has
/// returned, which is the first moment nothing keys on the set's
/// spelling any more. The chased slots that channel was built for defer
/// their rename for the same reason: a name that cannot be taken YET is
/// not a name to give up.
///
/// # Why `stem_is_a_name`
///
/// It is `hint_beats`'s own test one function up, and the project's
/// single answer to "is this dark?" (`nzbkit::release`). The asymmetry
/// is what keeps this from costing anything: against a HASH in hand the
/// unreadable name is still the better one, because `caf\u{FFFD}.mkv`
/// carries most of a real name and `Kj8sWm3xPd` carries none. Only a
/// readable incumbent takes it back.
pub(super) fn lossy_name_loses_to(pname: &str, held: &str) -> bool {
    pname.contains(char::REPLACEMENT_CHARACTER)
        && !held.contains(char::REPLACEMENT_CHARACTER)
        && nzbkit::release::stem_is_a_name(held)
}

/// Claim `filedesc-refusal-under-damage` (31 Aug 2026): does the set's
/// spelling lose to the name the slot's file carries right NOW - by
/// either of the two rules that have ever said so?
///
/// M4-86 and GH #63 are ONE question at this seam and they had two
/// different answers. M4-86 measured that a REFUSAL is the wrong shape
/// - the set's spelling is what the disk-side repair looks a member up
/// by, so a file left under the better name is a member the set cannot
/// find, and it adopts the bytes by content and CREATES its own copy
/// beside them - and shipped the deferral. #63's arm went on refusing,
/// and its whole e2e coverage (`e2e_norar::honestyear`, `pins.rs`,
/// `wave4d.rs`) is UNDAMAGED, so nothing had ever run it against the
/// case that decided M4-86.
///
/// MEASURED on `honestyear`'s own fixture with one corrupt article
/// (subject `Terminator2.mkv`, FileDesc `KpZ7mQx4TvB9nR2sLdFq.mkv`):
/// `1913 block(s) adopted from Terminator2.mkv` and then `1 recreated`
/// - TWO 220,000-byte files, job green, and the polarity is WORSE than
/// M4-86's. The repaired bytes landed under the set's HASH and the
/// DAMAGE stayed under `Terminator2.mkv`, so the honest name #63 exists
/// to keep is the one the user opens and the one that is corrupt.
///
/// The two arms stay SEPARATE rather than merging into "the readable
/// name always wins", because they refuse different things: M4-86's is
/// a spelling no reader can read, #63's a name the POST supplied. And
/// the #63 arm requires the held leaf to BE a name, because
/// `filedesc_name_is_better` answers about the slot's HINT and a yEnc
/// header can have landed the file under something else entirely - so
/// without it the take-back could hand the file a hash the guard never
/// spoke for. Each arm is held separately rather than one standing in
/// for the other, which is what the fixtures in
/// `e2e_norar::sixtythreedamage` and `e2e_norar::encoding` are for:
/// dropping either arm from this function reddens that arm's fixtures
/// and leaves the other's green.
pub(super) fn set_name_loses_to_held(
    slot: &crate::unpack::FileSlot,
    pname: &str,
    held: &str,
) -> bool {
    lossy_name_loses_to(pname, held)
        || (!filedesc_name_is_better(slot, pname) && nzbkit::release::stem_is_a_name(held))
}

/// The name this slot's payload carries, for [`lossy_name_loses_to`]'s
/// caller: the leaf on disk now, or - for a slot with no file yet - the
/// name its materialization is about to create one under.
///
/// THE SECOND ARM IS NOT A FALLBACK, it is the same question asked of
/// the state a mapped or chased slot is in (claim
/// `materialize-gh63-rename`, 31 Aug 2026, read-only sweep finding 2).
/// Both callers of [`super::publishplan::deferred_name`] want to know
/// what a rename to the set's spelling would COST, and until this arm
/// existed the answer for those slots was structurally `None`: no
/// writer, so [`nzbkit::extract::Extractor::slot_path`] is `None`, so
/// the deferral could never be decided - and `settle_slots`' rename
/// gate fell back to `filedesc_name_is_better` alone, which is exactly
/// the shape [`set_name_loses_to_held`] exists to refuse. A #63 slot
/// (honest subject, hash FileDesc) then kept the honest name, the
/// materialized volume landed under it, and the repair went looking for
/// the FileDesc spelling and reported the set short of a member it was
/// sitting on.
///
/// `None` now means only "no name to lose" - no file and nothing
/// latched - which is where the rename proceeds exactly as it did
/// before M4-86.
///
/// `plan_publish_names` is unaffected by the second arm and cannot be:
/// it `continue`s on `is_mapped() || is_chased()` before it asks, so the
/// only slots this widens are ones that function never judges.
pub(super) fn current_leaf(
    extractor: &Arc<nzbkit::extract::Extractor>,
    sidx: usize,
) -> Option<String> {
    let Some(p) = extractor.slot_path(sidx) else {
        return extractor.pending_slot_name(sidx);
    };
    Some(p.file_name()?.to_string_lossy().into_owned())
}

/// What the extraction tail and the failure summary need to know about
/// how verification and repair ended. Field names match the local
/// bindings the inline code used; the orchestrator destructures them
/// back under the same names.
pub(super) struct SettleVerdict {
    pub(super) all_good: bool,
    pub(super) reextract_failed: Option<String>,
    pub(super) repair_shortfall: Option<crate::repair::RepairShortfall>,
    pub(super) deferred_renames: Vec<(usize, String)>,
    /// The on-disk names this job's verified-name publishes have already
    /// taken, carried past `extractor.finish()` so the deferred renames in
    /// `report_extraction` claim out of the SAME set the settle pass did -
    /// two publish loops, one job, one namespace. See
    /// [`crate::unpack::PublishedNames`].
    pub(super) published_names: crate::unpack::PublishedNames,
    pub(super) sniff_covered: Option<std::collections::HashSet<String>>,
    /// TODO 159 item 1: the slots - BY INDEX - that are the whole reason
    /// this job failed, when that is a claim the pass can honestly make.
    /// `Some` means "the repair itself succeeded and every OTHER slot is
    /// verified or rebuilt; these are the ones still holed", which is
    /// exactly what the failed-job quarantine needs to withhold one
    /// archive's payload without withholding the rest.
    ///
    /// `None` is the answer for every pass that cannot say that, and the
    /// quarantine reads it as "withhold everything" - today's behaviour.
    /// Deliberately not "the slots that took damage": a covered volume
    /// whose corrupt article PAR2 rebuilt has damage counters set and is
    /// perfectly healthy, so a damage-counter test would withhold the
    /// whole job again.
    pub(super) unhealed_slots: Option<Vec<usize>>,
    /// L1 residue (31 Aug 2026): volume-named candidates the payload
    /// rescue BOUGHT and did not publish, by path.
    ///
    /// The failing job's quarantine has no other way to reach them.
    /// `quarantine_failed_payload` covers the extracted payload and
    /// `held_downloaded_files(slots, ..)`, and one of these files is in
    /// neither - it has no slot (`build_fetch_plan` skips a
    /// non-bootstrap `Par2Volume` before a slot exists, which is the
    /// very reason `repair/volpayload.rs` had to be written) and it was
    /// never extracted. Measured at `b30f29813`: on a failed job the one
    /// file that arrived through that side door was the ONLY one left
    /// wearing an importable name, the inversion of the quarantine's own
    /// invariant.
    ///
    /// By PATH and not by name, because these files sit at the name the
    /// POSTER gave them, which is nothing any set can look up. Empty on
    /// every path that never ran the rescue - which is nearly all of
    /// them, the rescue being the last thing tried before a set is lost.
    pub(super) rescue_left: Vec<PathBuf>,
    /// A repair pass ran that may have REWRITTEN bytes on disk.
    ///
    /// One consumer: the chase's resume ledger (`crate::resumeout`). A
    /// forfeited chase leaves in-stream output whose prefix is only
    /// trustworthy while the volumes it decoded from are the volumes it
    /// decoded from. The extractor catches a repair that comes back
    /// through it, but the DISK-side repairs on both settle paths
    /// (`repair_present_or_renamed_sets`, `repair_dir`,
    /// `try_rar_rr_repair`) write to the volume files directly and it
    /// never sees them - so the ladder asks here instead, and declines
    /// to resume anything at all when the answer is yes.
    ///
    /// Deliberately over-approximate: a pass that ran and found nothing
    /// still counts. A repair is rare and the ledger is an I/O
    /// optimisation, so the cost of saying yes too often is one job's
    /// re-extraction, where saying no too often is the payload.
    pub(super) repaired: bool,
}

struct RepairOutcome {
    all_good: bool,
    reextract_failed: Option<String>,
    repair_shortfall: Option<crate::repair::RepairShortfall>,
    unhealed_slots: Option<Vec<usize>>,
}

/// The slot a failure hint names, when exactly one slot answers to it.
///
/// Ambiguity is a refusal, not a guess: two slots posted under the same
/// subject would make a wrong pick attribute one archive's damage to
/// another's payload, and the caller turns `None` into "quarantine the
/// whole job" - the safe direction.
fn slot_by_hint(slots: &[Arc<FileSlot>], hint: &str) -> Option<usize> {
    let mut hits = slots.iter().enumerate().filter(|(_, s)| s.hint == hint);
    let (i, _) = hits.next()?;
    hits.next().is_none().then_some(i)
}

#[expect(clippy::too_many_arguments)]
pub(super) async fn settle_verify_repair(
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    journal: &Arc<nzbkit::journal::Journal>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Arc<Nzb>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    sniff: &Arc<SniffCtl>,
    sniff_bootstrap: Option<usize>,
    bootstrap_vol: Option<usize>,
    resume_vols: &HashMap<usize, PathBuf>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    fast_verify: bool,
    par_cleanup: bool,
    password: Option<&str>,
    incomplete: usize,
    derrs: u64,
    sparse_slots: &[String],
    recovery_errs: u64,
    recovery_missing: u64,
    note_activity: &(dyn Fn(&'static str) + Sync),
    // §129: the owner's recovery-fetch cancel handle, threaded the
    // same way `note_activity` is and for a sibling reason - the
    // repair paths below reach the network, and the tail they run in
    // now outlives the download slot, so a deleted job must be able
    // to stop them. `crate::repair::SideCancel`; None on the CLI.
    cancel: Option<&crate::repair::SideCancel>,
    // §293: directories a switch job's disk repair may adopt blocks
    // from - the failed predecessor's output. Threaded the same way
    // `cancel` is; empty on the CLI and on every non-switch job.
    donor_dirs: &[PathBuf],
    // PLAN M31: duplicate postings of this release whose live articles
    // may fill a bad block the wire could not serve - see
    // `super::dupefill`. Threaded exactly as `donor_dirs` is, and
    // deliberately separate from it: that one is a failed
    // predecessor's BYTES on disk (§293, block adoption, shipped),
    // this one is a duplicate posting's ARTICLES.
    donor_nzbs: &[PathBuf],
) -> Result<SettleVerdict> {
    // Phase marker: the network phase is over, the checks begin. On the
    // chart this is where throughput sits at zero on purpose - without
    // the marker a long repair reads as a download that died. The ring
    // lives on the fleet's shared LiveStats (build_fleet gave every
    // server's cfg the same Arc), so borrow it from the first server.
    if let Some(live) = servers.iter().find_map(|(_, c)| c.live.clone()) {
        live.note_run(
            "settle",
            "download finished - checking the files and repairing if needed",
        );
    }
    // Slots whose offset-0 article never landed are still unclassified,
    // their spans held in memory - flush them to plain files so settle
    // read-back and PAR2 repair see the bytes on disk.
    note_activity("verifying");
    extractor.settle_unclassified()?;
    // A chased set that demoted mid-download after a DROPPING trim has
    // holes where the dropped prefix was: re-fetch those volumes before
    // the read-back below sees them (see get/dropped.rs).
    super::dropped::refetch_dropped_volumes(
        extractor, slot_file, servers, nzb, out_dir, buf_pool, cancel,
    )
    .await?;

    // W4-15: the in-stream sniff elects ONE bootstrap volume for the
    // whole job, so a post carrying a SECOND recovery set had that set
    // deferred and never activated - and which set won was the arrival
    // race. Give the verifier the deferred volumes' bytes now, before
    // anything reads the set list.
    activate_deferred_sets(verifier, extractor, sniff, resume_vols);

    let sets = verifier.sets();
    // Finding F11: a DAMAGED index can activate a set that lost its
    // FileDesc packets ("set live: 0 file(s)"), and the with-set path
    // then has nothing to verify - a fully obfuscated post sailed
    // through "clean" and un-named. A set that names nothing is no
    // set: take the set-less path, whose volume fetch + disk repair
    // reads the file list out of the volumes.
    let sets = if sets.iter().all(|s| s.files.is_empty()) {
        if !sets.is_empty() {
            warn!(
                target: "par2",
                "the activated recovery set names no files (damaged index?) - \
                 falling back to the disk-side pass over the posted volumes"
            );
        }
        Vec::new()
    } else {
        sets
    };
    match sets.is_empty() {
        false => {
            settle_with_set(
                sets,
                verifier,
                extractor,
                journal,
                slots,
                slot_file,
                servers,
                nzb,
                out_dir,
                buf_pool,
                sniff,
                sniff_bootstrap,
                bootstrap_vol,
                resume_vols,
                prefetched,
                fast_verify,
                password,
                incomplete,
                derrs,
                sparse_slots,
                note_activity,
                cancel,
                donor_dirs,
                donor_nzbs,
            )
            .await
        }
        true => {
            // Sweep item 13b, 30 Aug 2026. The set-less arm merges the
            // census's `sparse_slots` hints TWICE below - once in
            // `disk_par2_fallback`, once in `settle_without_set`'s own
            // no-PAR2 arm - and neither carries the skip that
            // `repair::merge_sparse_slots` needs. This assertion is why
            // neither needs one, held mechanically instead of remembered.
            //
            // That skip exists because the census asks `slot_in_set`
            // BEFORE settle while three of the matcher's tiers - the
            // whole-file tier, the twin tier's per-block IFSC evidence
            // and the finish-time name tier - only reach a verdict inside
            // `finish_slot`, so a hint can be stale by the time it is
            // merged. On THIS arm it cannot be, for two independent
            // reasons:
            //
            //  * NO TIER HAS A DESCRIPTOR TO BIND. This arm is entered
            //    only where `verifier.sets()` is empty, or where every
            //    adopted set names ZERO files. `slot_in_set` is
            //    `Plan::Active(_) && slots[i].file.is_some()`, and every
            //    site that sets that `file` - in live.rs,
            //    live/matchref.rs, live/twintier.rs and live/nametier.rs
            //    alike - takes its index out of `Active::files()` or the
            //    by-fold / by-sanitized candidate lists, all three built
            //    from `Par2Set::files` alone. Every set naming nothing
            //    leaves `Active::index` empty, so there is no descriptor
            //    for any tier to bind and `file` stays None; no set at
            //    all is not `Plan::Active` and answers false outright.
            //    `get::vrig` builds a fresh verifier per job, so there is
            //    no restored binding either.
            //  * THE THREE FINISH-TIME TIERS NEVER RUN HERE.
            //    `finish_slot` / `finish_slot_from` has exactly one
            //    production caller, `settle_slots`, and that lives in
            //    `settle_with_set`. Nothing on this arm re-asks the
            //    matcher, so the window a stale census finding could open
            //    in does not exist.
            //
            // And the LATE set - the shape that looked dangerous, because
            // `disk_par2_fallback` repairs from a set discovered after the
            // census ran - is a `nzbkit::par2repair::PacketCatalog` read
            // off disk, not a plan activation: it never touches verifier
            // slot state, so it cannot produce a claim for `slot_in_set`
            // to report. The one `activate` call site is
            // `unpack::instream::maybe_activate_par2`, on the download
            // worker path, and both the census and settle run in the tail
            // after the drain - so the plan cannot change underneath this
            // either.
            //
            // MEASURED as well as reasoned, 30 Aug 2026, because the
            // reasoning above is what was asserted and never checked the
            // first time round. A probe at this line and at both merges,
            // driven over the e2e and daemon suites (436 tests, all
            // green): 345 entries to this arm, 70 merges reached between
            // the two sites, and `in_set` was ZERO on every entry. The
            // merge in `disk_par2_fallback` - the one worth being
            // sceptical of, since its set is discovered late - is reached
            // 3 times by e2e and never by the daemon suite, so it is
            // exercised rather than merely unrefuted.
            //
            // Debug-only - one plan read plus one slot mutex each, which
            // settle's own read-back dwarfs, and test builds are where the
            // e2e and daemon suites drive this arm.
            debug_assert!(
                !(0..slots.len()).any(|i| verifier.slot_in_set(i)),
                "the set-less settle arm ran with a slot the verifier had claimed: the \
                 two sparse_slots merges below now need merge_sparse_slots's skip"
            );
            settle_without_set(
                extractor,
                slots,
                slot_file,
                servers,
                nzb,
                out_dir,
                buf_pool,
                sniff,
                par_cleanup,
                password,
                incomplete,
                derrs,
                sparse_slots,
                recovery_errs,
                recovery_missing,
                note_activity,
                cancel,
            )
            .await
        }
    }
}

/// How much of a deferred recovery volume is read looking for a set
/// DEFINITION. A whole-file read is not affordable here - a deferred
/// volume that happened to land is an ordinary posted file and can be
/// hundreds of megabytes, and there may be twenty of them - while the
/// packets this needs sit at the FRONT of every index and every volume
/// par2cmdline writes: Main, then the FileDescs, then the IFSC blocks.
///
/// 16 MiB is generous against the IFSC, which is what scales with block
/// COUNT: at 20 bytes per block that is ~800k blocks, and a 100 GB post
/// at #63's 716800-byte blocks has 140k. A read that stops mid-packet
/// simply ends the scan at the last complete one, so a cut that lost the
/// Main packet leaves the set unparsed - which is exactly today's
/// behaviour and not a new failure.
///
/// THE IFSC IS NOT THE ONLY PART THAT SCALES, which this said until
/// 31 Aug 2026 and is the half a reader sizing this constant needs.
/// Measured against par2cmdline 1.2.0: a recovery VOLUME opens with a
/// full recovery slice packet and interleaves the critical packets AFTER
/// it, so its first complete packet is `block_size + 68` bytes - 716,868
/// at `-s716800`, 8,388,676 at `-s8388608`, which is half this budget on
/// its own. So the floor here scales with block SIZE as well, and it
/// binds FIRST on a volume: past it there is no complete packet at all,
/// `set_id_of` answers `None`, and the deferred set never activates.
/// That is the W4-15 cost the loop below reports rather than the slower
/// verify it looks like. Reason about both before moving this number;
/// the same measurement sizes [`setid::SET_ID_HEAD`], which is the
/// id-only read and is a separate constant for exactly that reason.
const SET_DEF_HEAD: usize = 16 << 20;

/// The first `cap` bytes of `path`, or `None` if it cannot be read.
/// Short files come back whole; nothing is padded.
fn read_head(path: &Path, cap: usize) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(cap as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

// The bounded reader for the two sites that want a set id and nothing
// else, and the constant it takes - one subject, in its own file because
// settle.rs is inside 100 lines of the size gate's ceiling and
// `settle-rs-size-ceiling` is an open claim on exactly that. `set_id_at`
// is re-exported because settle/repair.rs's `main_par2_for` calls it too.
mod setid;
use setid::{SET_ID_HEAD, set_id_at};

// The other half of the same subject: the reads that CANNOT be bounded,
// because `usable_slices_of` counts slices across the whole volume - and
// what they were missing instead, a `memgauge` charge and the engine's
// own packet-file ceiling. `read_whole_charged` is re-exported because
// `setid::set_id_at`'s whole-file fallback takes it too.
mod volbytes;
use volbytes::{read_volume_for_slices, read_whole_charged};

/// W4-15: activate any recovery set the in-stream sniff DEFERRED, off
/// the bytes those slots already have on disk.
///
/// The sniff elects one bootstrap volume per JOB, so a post carrying two
/// recovery sets only ever activated one - whichever volume was sniffed
/// first, which is an arrival race and nothing more. The consequence is
/// not a slower verify, it is a WRONG one: a damaged member both sets
/// name belongs to the set that won, damage is charged to that set
/// alone, and its sibling's parity is never brought to bear. Measured on
/// two sets over one damaged 200 KB member, the weak one (a single
/// recovery block) winning: `native repair: 2 block(s) damaged, only 1
/// recovery block(s) on disk`, job failed, everything quarantined -
/// while the strong set's five volumes lay on disk beside it.
///
/// # Why the bytes are already here, and why deferring is still right
///
/// The deferral cancels a sniffed slot's still-QUEUED articles; the ones
/// already in flight land, and the offset-0 article is by definition one
/// of them, because it is what sniffed. A set's definition - Main plus
/// the FileDesc and IFSC packets - sits at the front of every index and
/// of every volume par2cmdline writes, so what a sniffed slot holds is
/// usually the whole of what `activate` needs. Nothing is FETCHED here:
/// the deferral's whole point is that recovery data is bought only if a
/// repair needs it, and that is unchanged. A volume too holed to parse
/// is skipped by `pick_sets`, which leaves exactly today's behaviour.
///
/// # Why here and not in the sniff
///
/// The obvious fix - elect a bootstrap per SET rather than per job - was
/// built and MEASURED and is wrong twice over. At sniff time all this
/// run knows is that a file carries PAR2 packets, which does not
/// separate a second recovery set from PAYLOAD the live set covers: the
/// chain shape (an outer set naming the inner PAR2 files) is entirely
/// the second, and electing those made every inner file a bootstrap the
/// reconcile could no longer reach, so the outer set priced all of them
/// wholly missing. And keying the election by set id breaks the
/// switch-to-the-smallest-volume rule across sets, which is what stops a
/// post whose biggest volume is half the recovery set from downloading
/// it. Here, after the download, the FileDesc tables exist and the
/// reconcile has already run: nothing has to be guessed.
///
/// # Only sets that OVERLAP a live one
///
/// A deferred set is activated only when it names a file a live set also
/// names, by the identity a FileDesc carries (length + whole-file MD5).
/// That is the whole of W4-15's shape - two sets over one member, and
/// ownership of it decided by a race - and the narrowness is not
/// caution, it is the row's neighbours: a set naming NOTHING this post
/// claimed is the par-only shape or a stray release the poster left in
/// the NZB, and deciding which is a policy question the stray-release
/// guard and the residual tier already answer (see `super::residual` and
/// `super::latesets`), on the standing that the set never activated.
/// Activating one here would take that decision away from them without
/// making it.
///
/// So the candidates are PARSED first and activated second. Parsing
/// costs a read of bytes already on disk and decides the question the
/// packets can answer; nothing else changes.
///
/// `activate` MERGES rather than replacing, so every claim a live set
/// already holds survives this and only genuinely new set ids are added.
///
/// # Why `resume_vols` is a second source of paths
///
/// The bytes are reached through `Extractor::slot_path`, which answers
/// from the slot's WRITER - and a RESUME-recognised volume never has
/// one. `get::plan` marks such a slot `par2_sniffed` at build time (its
/// file already carries `PAR2\0PKT` on disk from the killed run), and
/// `get::rig::replay_or_adopt_restored` then skips every `is_par2()`
/// slot on purpose: "its file simply waits on disk for a repair". So
/// without this fallback the set whose parity would heal the member is a
/// file sitting in `out_dir` that nothing ever parses, and a resumed job
/// with two sets still activates only one - which is W4-15 again, with
/// the losing set's bytes arriving from the journal instead of late off
/// the wire. `resume_vols` is keyed by slot and holds exactly the path
/// that resume sniff read the magic from, so it is the authoritative
/// answer where the extractor has none; the extractor still wins where
/// it has one, because it tracks any verified-name publish.
fn activate_deferred_sets(
    verifier: &nzbkit::live::LiveVerifier,
    extractor: &Arc<nzbkit::extract::Extractor>,
    sniff: &Arc<SniffCtl>,
    resume_vols: &HashMap<usize, PathBuf>,
) {
    let live: std::collections::HashSet<[u8; 16]> =
        verifier.sets().iter().map(|s| s.recovery_set_id).collect();
    if live.is_empty() {
        return; // no set live at all: the set-less path owns this job
    }
    // What the live sets name, by the identity a FileDesc carries.
    let mine: std::collections::HashSet<([u8; 16], u64)> = verifier
        .sets()
        .iter()
        .flat_map(|s| s.files.iter())
        .map(|f| (f.md5, f.length))
        .collect();
    let mut fresh: Vec<Vec<u8>> = Vec::new();
    let mut seen: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    // Volumes that ARE a recovery set - their own bytes carry a set id -
    // and whose definition would not parse out of what is on disk. See
    // the report below the loop for why this one skip is spoken and the
    // others are not.
    let mut undefined: Vec<String> = Vec::new();
    for sidx in sniff.deferred_slots() {
        let Some(path) = extractor
            .slot_path(sidx)
            .or_else(|| resume_vols.get(&sidx).cloned())
        else {
            continue;
        };
        let Some(bytes) = read_head(&path, SET_DEF_HEAD) else {
            continue;
        };
        // One volume per set is all `activate` needs for the definition,
        // and offering more would only re-read bytes for packets it
        // already has. A slot whose id will not read is not a set.
        let Some(id) = nzbkit::par2::Par2Set::set_id_of(&bytes) else {
            continue;
        };
        if live.contains(&id) || !seen.insert(id) {
            continue;
        }
        // Parsed, then judged: only a set that names a file a live set
        // names too is this row's - see the header.
        let Ok(parsed) = nzbkit::live::pick_sets(&[bytes.as_slice()]) else {
            undefined.push(
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
            );
            continue;
        };
        if !parsed
            .iter()
            .flat_map(|s| s.files.iter())
            .any(|f| mine.contains(&(f.md5, f.length)))
        {
            continue;
        }
        fresh.push(bytes);
    }
    // SPOKEN, and BEFORE the early return, which is the whole point of
    // it. A volume that announces a recovery set id and then will not
    // yield a definition is the one skip here a reader has to be able to
    // tell from "there was no second set": both look identical from
    // outside, and the difference is whether parity the job is holding
    // went unspent - which is exactly what W4-15 cost. Two shapes reach
    // it, and neither is exotic: a deferral cancels a volume's
    // still-queued articles, so what is on disk can be its offset-0
    // article and a hole, and `SET_DEF_HEAD` caps the read at 16 MiB, so
    // a set whose critical packets run past that is cut mid-definition.
    // Both leave the set unparsed and the behaviour is CORRECT - it is
    // today's, and there is nothing here that could safely guess the
    // rest - so this reports rather than acts.
    //
    // It reports NARROWLY, too. A deferred volume stays on the repair's
    // exact-fit fetch list whatever set it belongs to (`deferred_files`),
    // so one whose definition was missing HERE can still be fetched
    // whole later and reached by the disk-side pass; the line therefore
    // says the set was not activated from disk, and must not be widened
    // into a claim that its parity is gone.
    //
    // Every other `continue` above stays silent on purpose. Already
    // live, and a second volume of a set already taken, are not skips at
    // all. A slot with no path and one whose bytes will not read have
    // nothing to say about a SET - after the `resume_vols` fallback
    // above the first of those should not happen, and if it does the
    // defect is upstream of here rather than in this volume. A volume
    // with no readable set id is not a set, which is what the sniff's
    // magic test can be wrong about. And the OVERLAP narrowing - a set
    // naming nothing this post claimed - is the ordinary case on a
    // par-only post or a stray release the poster left in the NZB,
    // decided deliberately (see the header) and handed on to
    // `super::residual` and `super::latesets`; a line there would fire
    // on healthy jobs and stop being read.
    //
    // Not folded into the activation line below, and that is a
    // correction to what this function's own handoff proposed: that line
    // only prints when something WAS activated, so a set lost this way
    // on a job that activated nothing else would still be silent - which
    // is the case where it matters most.
    if !undefined.is_empty() {
        warn!(
            target: "par2",
            "{} deferred recovery volume(s) name a recovery set whose definition \
             does not fit in what landed, so it could not be activated from the \
             bytes on disk - only a repair that fetches the rest of the volume \
             can reach it: {}",
            undefined.len(),
            undefined.join(", "),
        );
    }
    if fresh.is_empty() {
        return;
    }
    let refs: Vec<&[u8]> = fresh.iter().map(|v| v.as_slice()).collect();
    match verifier.activate(&refs) {
        Ok(sets) => info!(
            target: "par2",
            "{} deferred recovery set(s) name a file a live set names too - \
             activated from the bytes already on disk, {} set(s) live",
            fresh.len(),
            sets.len(),
        ),
        Err(e) => warn!(
            target: "par2",
            "a deferred recovery volume would not parse ({e}) - leaving it to the \
             disk-side pass"
        ),
    }
}

/// Settle every slot in parallel - read-back hashing (MD5) is
/// single-thread ~0.6 GB/s, and a big-block set can push
/// gigabytes through this path.
///
/// Returns the per-slot reports, whether a MAPPED slot reported bad blocks,
/// and the deobfuscated names a CHASED slot could not take while its writer
/// was live - applied after `extractor.finish()`, when nothing holds an fd on
/// the partial file any more; otherwise the slot keeps the posted name for
/// good and an obfuscated `hash.bin` is what the user is left looking at.
///
/// Split out of `settle_with_set` (TODO 106), body verbatim.
#[expect(clippy::type_complexity)]
fn settle_slots(
    slots: &[Arc<FileSlot>],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    out_dir: &Path,
) -> (
    Vec<(usize, nzbkit::live::SlotReport)>,
    bool,
    Vec<(usize, String)>,
    crate::unpack::PublishedNames,
) {
    let mut damage_in_mapped = false;
    let mut deferred_renames: Vec<(usize, String)> = Vec::new();
    let mut published_names = crate::unpack::PublishedNames::for_dir(out_dir);
    let settled: Vec<(usize, Option<nzbkit::live::SlotReport>)> = {
        let verifier = &verifier;
        let extractor = &extractor;
        let slot_list: Vec<usize> = slots
            .iter()
            .enumerate()
            // is_par2() and not just is_par2_main: a sniffed slot
            // (bootstrap or deferred) is recovery data - the set
            // never claims it, and read-back would report every
            // deferred article as a bad block.
            //
            // A skipped sample sits out for the same reason and needs
            // the same exemption. There is no file to read back, so
            // read-back claimed its set entry and then reported EVERY
            // block of it bad - which repair took at face value and
            // rebuilt the whole teaser from parity, spending more
            // recovery traffic than the download it was asked to skip.
            // Left unclaimed instead, it reaches `unclaimed_files`,
            // where it is struck off by name.
            .filter(|(_, s)| !s.is_par2() && !s.sample_skipped)
            .map(|(i, _)| i)
            .collect();
        let next = AtomicUsize::new(0);
        let results: std::sync::Mutex<Vec<(usize, Option<nzbkit::live::SlotReport>)>> =
            std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..nzbkit::mem::cpu_workers().min(12) {
                scope.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= slot_list.len() {
                            break;
                        }
                        let sidx = slot_list[i];
                        // A chased slot has no file either - its bytes
                        // are in the frontier buffer - and read_at
                        // serves it byte-exact, so it takes the same
                        // reader. Sending it down the path branch
                        // would read-back against a file that does not
                        // exist and report every pending block bad.
                        // An overlapping write (a malformed post, two
                        // articles for one range) makes in-stream Ok
                        // verdicts untrustworthy - re-hash (`force_readback`).
                        if extractor.slot_had_rewrite(sidx) {
                            verifier.force_readback(sidx);
                        }
                        let r = if extractor.is_mapped(sidx) || extractor.is_chased(sidx) {
                            let reader =
                                |off: u64, buf: &mut [u8]| extractor.read_at(sidx, off, buf);
                            verifier.finish_slot_from(sidx, nzbkit::live::ReadAt::Reader(&reader))
                        } else {
                            // Fully-resumed slots never created a writer
                            // this run - the run-1 file (yEnc name ==
                            // hint for unobfuscated posts) backs them.
                            let path = extractor.slot_path(sidx).or_else(|| {
                                let p = nzbkit::disk::join_out_name(
                                    out_dir,
                                    &nzbkit::disk::sanitize_out_name(&slots[sidx].hint),
                                );
                                p.exists().then_some(p)
                            });
                            verifier.finish_slot(sidx, path.as_deref())
                        };
                        results.lock_ok().push((sidx, r));
                    }
                });
            }
        });
        let mut v = results.into_inner().unwrap();
        v.sort_by_key(|(s, _)| *s);
        v
    };
    super::publishplan::plan_publish_names(
        slots,
        &settled,
        extractor,
        out_dir,
        &mut published_names,
    );
    let mut reports: Vec<(usize, nzbkit::live::SlotReport)> = Vec::new();
    for (sidx, r) in settled {
        let slot = &slots[sidx];
        let mapped = extractor.is_mapped(sidx);
        if let Some(r) = r {
            if !r.bad_blocks.is_empty() {
                warn!(
                    target: "verify",
                    "✘ {} - {}/{} blocks bad",
                    r.par2_name.as_deref().unwrap_or(&slot.hint),
                    r.bad_blocks.len(),
                    r.total_blocks
                );
                if mapped {
                    damage_in_mapped = true;
                }
            }
            // Matrix F5 (lying-size-truncate): a lying `=ybegin size=`
            // preallocates the slot file at the DECLARED size, and the
            // clean path never held the published length to the
            // FileDesc length the way repair's truncation does - the
            // payload shipped with a zero tail at rc=0. The FileDesc
            // blocks tile exactly [0, length), so with every block
            // verified the first `r.length` bytes are proven and
            // anything past them is the poster's lie. Cut it. No
            // claimed descriptor = no truth to truncate to (behavior
            // kept); a mapped or chased slot has no finished file.
            if !mapped
                && !extractor.is_chased(sidx)
                && r.length > 0
                && r.bad_blocks.is_empty()
                && let Some(path) = extractor.slot_path(sidx).or_else(|| {
                    let p = nzbkit::disk::join_out_name(
                        out_dir,
                        &nzbkit::disk::sanitize_out_name(&slot.hint),
                    );
                    p.exists().then_some(p)
                })
                && let Ok(md) = std::fs::metadata(&path)
                && md.len() > r.length
            {
                let cut = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .and_then(|f| f.set_len(r.length));
                match cut {
                    Ok(()) => info!(
                        target: "verify",
                        "✂ {} - yEnc headers declared {} bytes, PAR2 says {}: \
                         truncated the lied tail",
                        r.par2_name.as_deref().unwrap_or(&slot.hint),
                        md.len(),
                        r.length
                    ),
                    Err(e) => warn!(
                        target: "verify",
                        "could not truncate {} to its PAR2 length {}: {e}",
                        path.display(),
                        r.length
                    ),
                }
            }
            // Deobfuscation: the PAR2 FileDesc name is the real one -
            // unless it is a hash and the subject already named this
            // file, which is GH #63. See `filedesc_name_is_better`.
            // M4-86: taken BEFORE the rename below, because it is the
            // name the rename is about to spend. See
            // [`lossy_name_loses_to`] for why the readable name is
            // brought back afterwards rather than kept now.
            // Claim `filedesc-refusal-under-damage`: GH #63's own
            // refusal is deferred here too, for M4-86's reason and
            // measured on the same shape - see
            // [`set_name_loses_to_held`].
            //
            // Asked through `publishplan::deferred_name` rather than
            // spelled out here, because `plan_publish_names` has to ask
            // the SAME question one pass earlier - a slot that defers is
            // not a stayer, and the plan is built out of that
            // distinction. Claim `publishplan-model-vs-deferred-rename`
            // is what the two answers disagreeing cost.
            let held =
                super::publishplan::deferred_name(slot, r.par2_name.as_deref(), extractor, sidx);
            // The rename to the set's spelling happens whenever the set
            // names this member AND the better name can be given back
            // afterwards. `held.is_some()` is what carries the #63 arm:
            // with no name to lose - nothing on disk AND nothing latched
            // for a materialization to use - or a leaf that is not a
            // name, there is nothing to defer and #63's refusal stands
            // exactly as it shipped.
            //
            // "nothing on disk" stopped being the whole of that on
            // 31 Aug 2026, claim `materialize-gh63-rename`: a mapped or
            // chased slot has no file and DOES have a name, so
            // [`current_leaf`] answers off the pending one and this arm
            // reaches the slots the repair ladder materializes.
            if let Some(pname) = &r.par2_name
                && (filedesc_name_is_better(slot, pname) || held.is_some())
            {
                extractor.rename(sidx, pname);
                // A CHASED slot is excluded from the on-disk half
                // for the same reason a mapped one is: it has no
                // finished file. It can now have a PARTIAL one -
                // drop-behind trimming spills the archive's
                // consumed prefix there - and renaming that moves
                // the path out from under a live writer's open
                // fd, so the rest of the spill lands in a file
                // nothing points at.
                //
                // Deferred, not dropped. The chase may still
                // demote, and then that partial file IS the
                // archive: leaving it under the posted name meant
                // the deobfuscated name was lost for good, since
                // `Extractor::rename` also declines once a writer
                // exists. Queue it for after finish(), when the
                // writer is gone.
                if extractor.is_chased(sidx) {
                    // A chased slot's deferred rename is its ONLY
                    // rename, so M4-86's readable name replaces the
                    // set's spelling in it rather than following it -
                    // two entries for one slot would rename twice to
                    // land in the same place.
                    deferred_renames.push((sidx, held.unwrap_or_else(|| pname.clone())));
                } else if mapped {
                    // A MAPPED slot has no file to publish HERE and one
                    // by the time the deferred pass runs: the repair
                    // ladder materializes it under the name
                    // `Extractor::rename` just retargeted (writerless,
                    // so that call took effect), and `report_extraction`
                    // runs after `finish()`. So the take-back is queued
                    // exactly as the on-disk arm queues it and only the
                    // publish half is skipped - claim
                    // `materialize-gh63-rename`. Before this arm, a
                    // mapped slot fell out of the whole block and the
                    // honest name was lost for good the moment the set's
                    // spelling was taken.
                    //
                    // No `unwrap_or(pname)` fallback, unlike the chase
                    // above: `held` is None exactly when the rename fired
                    // on `filedesc_name_is_better` alone, and there the
                    // set's spelling is the name that WINS - queueing it
                    // back would be a rename to where the file already
                    // is.
                    if let Some(held) = held {
                        deferred_renames.push((sidx, held));
                    }
                } else {
                    if let Some(path) = extractor.slot_path(sidx)
                        && let Some(new) =
                            publish_verified_name(&path, pname, out_dir, sidx, &mut published_names)
                    {
                        extractor.note_slot_renamed(sidx, new);
                    }
                    // M4-86: and back again once nothing keys on the
                    // set's spelling - `report_extraction`, which
                    // runs after `settle_verify_repair` returns.
                    if let Some(held) = held {
                        deferred_renames.push((sidx, held));
                    }
                }
            }
            reports.push((sidx, r));
        }
    }
    (reports, damage_in_mapped, deferred_renames, published_names)
}

// The duplicate-donor pass over every set of the job, and the summary
// line that says what it did - one subject, lifted whole (TODO 106,
// 31 Aug 2026). `note_dupefill` is re-exported because repair.rs's
// SECOND entry point calls it too.
mod dupenote;
use dupenote::{fill_from_duplicates, note_dupefill};

/// One recovery set that took damage, and what repairing it needs.
///
/// TODO 311: a post may ship one set per file, and each set's parity
/// speaks only for its own files. So the fetch arithmetic is per set -
/// `needed` is that set's own damage less its own slices already on
/// disk - and `missing` is the subset of the job's unclaimed FileDesc
/// names that THIS set is the one able to recreate.
struct SetPlan {
    set: Arc<nzbkit::par2::Par2Set>,
    /// Which of the job's adopted sets this is, indexed the way
    /// [`nzbkit::live::LiveVerifier::sets`] is. Carried because
    /// `dupefill::wanted_files` may not be handed a set without also
    /// being told which one it is - see the second entry point in
    /// [`run_set_repair`], and `fill_from_duplicates` for the defect
    /// that rule closes.
    index: usize,
    needed: usize,
    missing: Vec<String>,
    /// The live block grid's damage claim, by FileDesc name - sanitized
    /// and lowercased. `needed` is that claim SUMMED, and a sum cannot
    /// be argued with; `shortfall_is_final`'s fourth arm needs to know
    /// which files it was summed over before it can ask their
    /// descriptors whether it was ever true (M4-69's mirror direction).
    ///
    /// Job-wide rather than per set, and the same list in every plan: a
    /// name that is not this set's own is simply not found among its
    /// files, so intersecting here would buy nothing and would have to
    /// re-derive the twin-tier identity the charge above already
    /// resolved.
    damaged: Vec<String>,
}

/// Recovery slices of `set` in `bytes` that can actually serve one of
/// its blocks - the fetch planner's `on_hand`, and the only reason the
/// planner ever decides it needs another volume.
///
/// The predicate is [`nzbkit::par2repair::slice_fits_block`] and must
/// stay that call. This counter spelled its own `== bs` until 31 Aug
/// 2026 while the two SELECTION sites had already moved to `>= bs`
/// (M4-56), so on a post whose writer padded its recovery packets the
/// planner read every volume on disk as holding zero parity: it refetched
/// volumes it already had, treated every resumed one as partial, and the
/// repair then succeeded off slices the planner had said were not there.
/// Nobody got a wrong answer - the direction is safe, which is exactly
/// why nothing reported it - and the post paid for the volumes over the
/// wire. Pinned by `workers::slice_len_tests`, beside the census half.
///
/// Y4b made the SEED this is added to the same currency (31 Aug 2026).
/// `on_hand` starts at each set's `recovery_blocks_seen`, which counted
/// every recovery exponent MENTIONED with no length test at all, so an
/// over-count and this accurate count were being added together and
/// `needed = damage - on_hand` came out too small - the exact-fit fetch
/// then bought too few volumes and the repair landed off the last-resort
/// escalation instead, buying the whole ladder. That parse now applies
/// the same predicate; the two are pinned against each other in
/// `workers::slice_len_tests`.
///
/// A named function and not the closure it was, so a test can reach it.
pub(super) fn usable_slices_of(bytes: &[u8], set: &nzbkit::par2::Par2Set) -> usize {
    let bs = set.block_size as usize;
    nzbkit::par2repair::recovery_slice_locators(bytes, &set.recovery_set_id)
        .into_iter()
        .filter(|(_, _, len)| nzbkit::par2repair::slice_fits_block(*len, bs))
        .count()
}

/// The in-stream bootstrap volume's slice count, read off the DISK file
/// and REPLACING that set's `recovery_blocks_seen`.
///
/// The sniffed bootstrap's capture can have holes - an article decoded
/// BEFORE the head's sniff was written to disk but never mirrored - so
/// `recovery_blocks_seen` can undercount while the bootstrap's file index
/// goes into `already` and is never refetched. On a sniffed post the
/// bootstrap capture is the only one carrying recovery slices (demoted
/// captures are dropped), so this replaces rather than adds.
///
/// A slice carries its own set id, so these bytes answer every set's
/// question and at most one of them says yes: the count replaces the
/// count of the set the bootstrap's bytes belong to and no other's. On a
/// per-file-set post that one file is one set's bootstrap and says
/// nothing about the other seventeen, so replacing every set's count
/// from it would zero out parity sitting right there (TODO 311).
///
/// Out of line because `settle_with_set` sat at 464 of the size gate's
/// 500-line ceiling when this was lifted out of it (30 Aug 2026).
fn replace_bootstrap_slice_counts(
    sniff_bootstrap: Option<usize>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    sets: &[Arc<nzbkit::par2::Par2Set>],
    on_hand: &mut [usize],
    slices_of: impl Fn(&[u8], &nzbkit::par2::Par2Set) -> usize,
) {
    // ID FIRST, off a bounded head, and the file whole only for the set
    // it actually matched. The order matters on a per-file-set post: the
    // bootstrap belongs to ONE of the sets, so the old spelling slurped a
    // volume, asked whose it was, and on a miss threw every byte away.
    // `slices_of` genuinely needs the whole file - it counts recovery
    // slices across the WHOLE volume - so this bounds the question and
    // not the answer. The whole read goes through `volbytes` for the two
    // things it is still owed: the bytes charged to `Sub::RepairScan`
    // while they are resident, and the engine's own packet-file ceiling,
    // past which a REPLACEMENT of zero is the truth - the repair skips
    // that file too, so any count off it is parity nothing can spend.
    if let Some(path) = sniff_bootstrap.and_then(|s| extractor.slot_path(s))
        && let Some(id) = set_id_at(&path, SET_ID_HEAD)
        && let Some(si) = sets.iter().position(|s| s.recovery_set_id == id)
        && let Some(bytes) = read_volume_for_slices(&path)
    {
        on_hand[si] = slices_of(&bytes, &sets[si]);
    }
}

/// The blocks the read-back found bad, charged to the set that owns each
/// slot AND to any other set describing the same file.
///
/// The owner half is TODO 311's rule: repair is per set, so a block of
/// damage in a file set 3 covers is healed by set 3's parity and by
/// nothing else, and a job-wide total would send the wrong set shopping.
///
/// The twin half is W4-15. A slot has exactly ONE owning descriptor, and
/// which set that is comes down to the in-stream bootstrap race - so
/// where two overlapping sets name one member, the set that lost the
/// race charged zero and never spent the parity it was holding. Measured:
/// the weak set (one recovery block) owning a damaged 200 KB member while
/// the strong one (eight) sat idle, and the job failed with `2 block(s)
/// damaged, only 1 recovery block(s) on disk` over five usable volumes on
/// disk beside it. Which set OWNS the slot is a race; which one can HEAL
/// it is not. Answers empty for the ordinary post, where no second set
/// names the file - see [`nzbkit::live::LiveVerifier::slot_twin_damage`]
/// for the identity test and why the block indices are mapped through
/// byte ranges rather than rescaled.
///
/// Out of line because `settle_with_set` sat at 464 of the size gate's
/// 500-line ceiling when this was lifted out of it (30 Aug 2026).
fn charge_reported_damage(
    verifier: &nzbkit::live::LiveVerifier,
    reports: &[(usize, nzbkit::live::SlotReport)],
    damage_by_set: &mut [usize],
) {
    for (sidx, r) in reports {
        let Some(si) = verifier.slot_set(*sidx) else {
            continue;
        };
        damage_by_set[si] += r.bad_blocks.len();
        for (tsi, blocks) in verifier.slot_twin_damage(*sidx, &r.bad_blocks) {
            damage_by_set[tsi] += blocks;
        }
    }
}

/// The FileDesc names the live grid claims damage against - sanitized
/// and lowercased, the key every coverage test in this file uses.
///
/// The other half of [`charge_reported_damage`]: that one turns the
/// reports into a per-set TOTAL, this one keeps the names that total was
/// made of, because a total is not something a descriptor can
/// contradict. Its consumer is `repair::shortfall_is_final`'s fourth
/// arm, which pays a whole-file MD5 only for the members named here -
/// which is what keeps that read proportional to the damage claim rather
/// than to the download.
///
/// A report exists only for a slot some set CLAIMED, and `par2_name` is
/// the name it claimed IN ITS OWN SET, so a twin charged into a second
/// set contributes the owner's spelling. Stated at the consumer, where
/// the permissive direction is argued.
fn damaged_par2_names(reports: &[(usize, nzbkit::live::SlotReport)]) -> Vec<String> {
    let mut out: Vec<String> = reports
        .iter()
        .filter(|(_, r)| !r.bad_blocks.is_empty())
        .filter_map(|(_, r)| r.par2_name.as_deref())
        .map(|n| nzbkit::disk::sanitize_out_name(n).to_lowercase())
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Every adopted set's FileDesc names, sanitized and lowercased - the
/// key every coverage test in this file uses.
///
/// A UNION, and that is the point: "does the recovery set cover this
/// file" is a question about the post, not about one of its sets, so a
/// per-file-set post must not fail a file as out-of-set because the
/// LARGEST set happens not to name it (TODO 311).
fn union_set_names(sets: &[Arc<nzbkit::par2::Par2Set>]) -> std::collections::HashSet<String> {
    sets.iter()
        .flat_map(|s| s.files.iter())
        .map(|f| nzbkit::disk::sanitize_out_name(&f.name).to_lowercase())
        .collect()
}

/// TODO 311: EVERY recovery set the post carries, not the largest one.
///
/// What is per JOB and what is per SET is the whole shape of this
/// function. Verification, the coverage census, the spare rules and the
/// re-extract are per job and read the UNION of the sets' FileDesc
/// tables. Repair is per set and can only ever be: a recovery slice
/// belongs to its own set's Reed-Solomon geometry, `block_size` and
/// `recovery_set_id` are per set, and `par2repair::recovery_slice_locators`
/// filters slices BY set id. So damage is charged to the set whose parity
/// can heal it, and `run_set_repair` is handed one [`SetPlan`] per set.
/// Which adopted sets a slot of this job actually claimed a file of,
/// indexed the way `verifier.sets()` is.
///
/// A report exists only for a slot some set claimed, so this is exactly
/// "did anything in the post turn out to belong to set N". Its use is
/// the stray-release guard in [`settle_with_set`]; see there for why a
/// SIBLING with claims is the whole discriminator.
fn sets_with_claims(
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    reports: &[(usize, nzbkit::live::SlotReport)],
    n: usize,
) -> Vec<bool> {
    (0..n)
        .map(|si| {
            reports
                .iter()
                .any(|(sidx, _)| verifier.slot_set(*sidx) == Some(si))
        })
        .collect()
}

/// Everything the repair planner is told before it is asked to spend or
/// fetch a single recovery slice: how many usable slices each set
/// already has on hand, which NZB entries therefore leave the fetch
/// candidate list, the deferred volumes subject-line classification
/// cannot see, and one [`SetPlan`] per set that took damage.
///
/// Out of line because `settle_with_set` sat at 492 of the size gate's
/// 500-line function ceiling on 31 Aug 2026 - TODO 106 says split it,
/// do not squeeze it, and this is the one span of that function with a
/// single subject, no `.await` in it and nothing but fresh values
/// coming out. Body lifted whole and verbatim; the only edits are the
/// two borrows the move made needless (`sets` and `reports` arrive here
/// as references) and the tuple this returns.
///
/// It stays in this file rather than going to a `settle/` child the way
/// [`repair`] and [`noset`] did, and that is not for want of room - the
/// file has ~880 lines of margin. `replace_bootstrap_slice_counts` is
/// the bootstrap half of this same arithmetic, was hoisted out of
/// `settle_with_set` for this same reason, and is PINNED to this file by
/// name: `settle::setid::set_id_read_tests` reads settle.rs with
/// `include_str!` and asserts the bounded id read precedes the whole
/// read inside its body. Sending the caller to a child while the callee
/// stayed would split one subject across two files.
#[expect(clippy::too_many_arguments)]
fn plan_damaged_sets(
    sets: &[Arc<nzbkit::par2::Par2Set>],
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    sniff: &Arc<SniffCtl>,
    sniff_bootstrap: Option<usize>,
    bootstrap_vol: Option<usize>,
    resume_vols: &HashMap<usize, PathBuf>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    reports: &[(usize, nzbkit::live::SlotReport)],
    damage_by_set: &[usize],
    missing_files: &[String],
) -> (Vec<SetPlan>, Vec<usize>, Vec<usize>) {
    // Slices already on hand: seen while building the set (the
    // bootstrap volume) + M2c.5 prefetched volumes on disk -
    // counted from the files themselves (exact, so a partial
    // prefetch discounts only what actually landed), and their
    // NZB entries leave the fetch-candidate list.
    // The sniffed bootstrap's capture can have holes: an article
    // decoded BEFORE the head's sniff was written to disk but
    // never mirrored, so recovery_blocks_seen can still undercount -
    // while the bootstrap's file index goes into `already` and is
    // never refetched. Count its slices off the DISK file, which
    // write_verified kept whole. On a sniffed post the bootstrap
    // capture is the only one carrying recovery slices (demoted
    // captures are dropped), so this REPLACES recovery_blocks_seen
    // rather than adding to it.
    //
    // Counted per SET. A slice carries its own set id, so the same bytes
    // answer every set's question and at most one of them says yes - and
    // the bootstrap REPLACEMENT above is applied only to the set the
    // bootstrap file actually belongs to, read off its first packet. On
    // a per-file-set post that one file is one set's bootstrap and says
    // nothing about the other seventeen, so replacing every set's count
    // from it would zero out parity that is sitting right there
    // (TODO 311).
    let mut on_hand: Vec<usize> = sets.iter().map(|s| s.recovery_blocks_seen).collect();
    replace_bootstrap_slice_counts(
        sniff_bootstrap,
        extractor,
        sets,
        &mut on_hand,
        usable_slices_of,
    );
    let mut already: Vec<usize> = bootstrap_vol.into_iter().collect();
    // The sniffed in-stream bootstrap (issue #14) is on hand the
    // same way a static bootstrap volume is: its slices were
    // counted at activation, so its NZB entry leaves the fetch
    // list. The other sniffed slots are the deferred volumes -
    // subject-line classification cannot see them, so the repair
    // planner is told about them explicitly.
    already.extend(sniff_bootstrap.map(|s| slot_file[s]));
    // Resume-recognised volumes are already (at least partly) on
    // disk: count their restored slices into on_hand and strike
    // their NZB entries off the fetch list, exactly like an
    // M2c.5 prefetch. The repair itself reads them off disk by
    // packet magic regardless - this only keeps the fetch
    // arithmetic honest.
    for (&s, pth) in resume_vols.iter() {
        let bytes = read_volume_for_slices(pth).unwrap_or_default();
        let per_set: Vec<usize> = sets
            .iter()
            .map(|set| usable_slices_of(&bytes, set))
            .collect();
        let counted: usize = per_set.iter().sum();
        // A PARTIALLY restored volume must stay on the fetch list:
        // striking its index while crediting only the slices that
        // landed leaves its missing slices unreachable by both the
        // exact-fit fetch and the final escalation - a repairable job
        // then reports a false shortfall. Where the name declares a
        // slice count, use it to tell complete from partial; an
        // obfuscated name declares nothing, so there the proof of
        // completeness is the plan itself - a slot with deferred
        // (unjournaled, unfetched) articles is not provably whole. A
        // partial volume is treated as wholly unfetched (no credit,
        // no exclusion - the refetch simply rewrites it).
        let declared = pth
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(nzbkit::nzb::par2_vol_count);
        let partial = match declared {
            Some(d) => counted < d,
            None => slots[s].deferred.load(Ordering::Relaxed) > 0,
        };
        if partial {
            continue;
        }
        already.push(slot_file[s]);
        for (h, c) in on_hand.iter_mut().zip(per_set) {
            *h += c;
        }
    }
    let sniffed_vols: Vec<usize> = sniff.deferred_files();
    for (fi, paths) in prefetched.lock_ok().iter() {
        already.push(*fi);
        for pth in paths {
            if let Some(bytes) = read_volume_for_slices(pth) {
                for (h, set) in on_hand.iter_mut().zip(sets.iter()) {
                    *h += usable_slices_of(&bytes, set);
                }
            }
        }
    }
    // One plan per set that took damage. A set with none is not
    // repaired and not fetched for - which is the ordinary case on a
    // per-file-set post, where one damaged track leaves seventeen sets
    // with nothing to do.
    let plans: Vec<SetPlan> = sets
        .iter()
        .enumerate()
        .filter(|(si, _)| damage_by_set[*si] > 0)
        .map(|(si, set)| SetPlan {
            set: set.clone(),
            index: si,
            needed: damage_by_set[si].saturating_sub(on_hand[si]),
            damaged: damaged_par2_names(reports),
            missing: missing_files
                .iter()
                .filter(|n| set.files.iter().any(|f| &f.name == *n))
                .cloned()
                .collect(),
        })
        .collect();
    (plans, already, sniffed_vols)
}

#[expect(clippy::too_many_arguments)]
async fn settle_with_set(
    sets: Vec<Arc<nzbkit::par2::Par2Set>>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    journal: &Arc<nzbkit::journal::Journal>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Arc<Nzb>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    sniff: &Arc<SniffCtl>,
    sniff_bootstrap: Option<usize>,
    bootstrap_vol: Option<usize>,
    resume_vols: &HashMap<usize, PathBuf>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    fast_verify: bool,
    password: Option<&str>,
    mut incomplete: usize,
    derrs: u64,
    sparse_slots: &[String],
    note_activity: &(dyn Fn(&'static str) + Sync),
    // §129: the owner's recovery-fetch cancel handle, threaded the
    // same way `note_activity` is and for a sibling reason - the
    // repair paths below reach the network, and the tail they run in
    // now outlives the download slot, so a deleted job must be able
    // to stop them. `crate::repair::SideCancel`; None on the CLI.
    cancel: Option<&crate::repair::SideCancel>,
    // §293: donor directories for the disk repair's adoption scan.
    donor_dirs: &[PathBuf],
    // PLAN M31: duplicate postings whose live articles may fill a bad
    // block before repair is asked to rebuild it (`super::dupefill`).
    donor_nzbs: &[PathBuf],
) -> Result<SettleVerdict> {
    // --- settle verification (in-stream results; read-back only for gaps) ---
    let mut all_good;
    // The bytes on disk are fine but turning them into the output file
    // failed - a distinct failure from an incomplete or unrepaired
    // download. Holds WHICH extraction path gave up: several reach here
    // on jobs that never needed (or ran) a PAR2 repair at all, so the
    // reason travels with the flag rather than being assumed at the end.
    // A String rather than a &'static str: the nested-archive arms below
    // know WHICH archive stopped them, and "the log above names the
    // archive" asked the user to go and find in a log ring what the
    // sentence could simply have said.
    let mut reextract_failed: Option<String> = None;
    // Set when repair died on the recovery set - too little parity
    // declared, or a provider that would not serve the parity that is.
    // The arithmetic belongs in the fail message, not just the console
    // log. See [`crate::repair::RepairShortfall`].
    let mut repair_shortfall: Option<crate::repair::RepairShortfall> = None;
    // TODO 159 item 1 - see `SettleVerdict::unhealed_slots`. Only the
    // repair pass ever gets to claim this: the clean-download arm below
    // fails on `incomplete`/`derrs` alone, which name no slot and prove
    // nothing about the rest of the job.
    let mut unhealed_slots: Option<Vec<usize>> = None;
    // X5-10: proven-spent adoption sources, held - `fetch_and_repair`.
    let mut spent: Vec<PathBuf> = Vec::new();
    let mut rescue_left: Vec<PathBuf> = Vec::new();
    let vt0 = Instant::now();
    let (mut reports, damage_in_mapped, deferred_renames, mut pubnames) =
        settle_slots(slots, verifier, extractor, out_dir);
    // PLAN M31 stage 1 - borrow what a duplicate posting can serve
    // before repair spends a recovery block. It belongs exactly HERE:
    // after the read-back has said which blocks are bad, and before
    // anything below may rebuild one. Out of line in
    // [`fill_from_duplicates`], which carries the whole argument - this
    // function sat at 462 of the size gate's 500-line ceiling when that
    // lift landed (28 Aug 2026).
    incomplete = fill_from_duplicates(
        &sets,
        verifier,
        extractor,
        slots,
        servers,
        out_dir,
        donor_nzbs,
        donor_dirs,
        cancel,
        &mut reports,
        incomplete,
    )
    .await;
    let live: u64 = reports.iter().map(|(_, r)| r.live_blocks).sum();
    let readback: u64 = reports.iter().map(|(_, r)| r.readback_blocks).sum();
    let bad: usize = reports.iter().map(|(_, r)| r.bad_blocks.len()).sum();
    // A file the sample skip declined is DELIBERATELY absent, and the
    // recovery set has no way to know that: it lists the file the poster
    // packed, so an unfetched teaser lands in `unclaimed_files` looking
    // exactly like one the servers lost. Left there it would charge its
    // whole length to `damage`, and repair would then pull recovery
    // volumes off the wire to rebuild the very bytes the setting exists
    // to not download - more traffic than simply fetching it, for a file
    // the user asked not to have. So it is struck off here, once, at the
    // source: everything downstream (`damage`, `needed`, the
    // recreated-set test, the uncovered-hole rescan) reads the filtered
    // list.
    //
    // Matched on the sanitized lowercase name, the same key the
    // coverage tests either side of this use. An obfuscated post whose
    // hint is a hash cannot match - and cannot have been skipped
    // either, since the classifier needs a name to read.
    let mut missing_files: Vec<String> = {
        let skipped: std::collections::HashSet<String> = slots
            .iter()
            .filter(|s| s.sample_skipped)
            .map(|s| nzbkit::disk::sanitize_out_name(&s.hint).to_lowercase())
            .collect();
        missing_file_names(verifier.unclaimed_files(), &skipped)
    };
    // `damage` decides WHETHER repair runs; `needed` (the deficit
    // after slices already on hand) decides how much to FETCH.
    // Conflating them skipped repair entirely whenever on-hand
    // slices covered the damage count - silent corruption with
    // exit 0 (latent for bootstrap sets, wide open once M2c.5
    // prefetched volumes mid-download).
    // Per SET, because repair is per set: a block of damage in a file
    // set 3 covers is healed by set 3's parity and by nothing else, and
    // charging it to a job-wide total would send the wrong set shopping
    // for volumes (TODO 311).
    let mut damage_by_set = vec![0usize; sets.len()];
    charge_reported_damage(verifier, &reports, &mut damage_by_set);
    // A set NO slot claimed a single file of is one of two things, and
    // its own packets cannot tell them apart: the par-only shape (every
    // payload article lost, and parity is exactly what rebuilds it -
    // bench leg a2-par-only, 2 Aug), or a recovery set for a DIFFERENT
    // RELEASE that the poster left in the NZB. A SIBLING set WITH claims
    // settles it: this post is evidently the sibling's, so charging the
    // stray's whole content here sends the repair shopping for parity
    // that was never posted and fails a job whose own payload is
    // perfect.
    //
    // Measured on the tree that landed TODO 311: one clean 400 KB file
    // beside another release's two sets exits 1 with `1954 recovery
    // block(s) needed but the recovery set ... carries only 391`, having just
    // reported `verified 1 file(s) ... 0 bad`. Adopting every set is
    // what makes it deterministic - the single-set rule hit it only when
    // its arbitrary tie-break happened to land on a stray - so the guard
    // belongs with the adoption.
    //
    // Scoped so it CANNOT fire on a post carrying one set: with no
    // sibling there is nothing to contradict the par-only reading, and
    // that reading has always been the right one.
    //
    // ...and a FILE the post itself offers is not a stray's however
    // little of it arrived: an NZB entry for it is the evidence the
    // packets cannot carry, and it is what tells the MIXTURE (a
    // per-file-set post with one file taken down whole) from the stray.
    // Per file and not per set - `names_offered_by_the_post` carries
    // that argument and its stated limits.
    let set_has_claims = sets_with_claims(verifier, &reports, sets.len());
    let offered_names = super::emptydesc::names_offered_by_the_post(slots);
    // A zero-length FileDesc (the VIDEO_TS placeholder shape) can never
    // be claimed by any content tier - there is no head to hash - and it
    // contributes zero damage, so without this it stayed "missing
    // entirely" forever while costing nothing to produce. Renames a
    // proven-empty unclaimed slot file onto it, or materializes the
    // empty file outright; landed names leave the missing list. The full
    // argument lives at [`super::emptydesc`].
    super::emptydesc::land_zero_length_filedescs(
        &mut missing_files,
        &sets,
        &set_has_claims,
        &offered_names,
        slots,
        slot_file,
        nzb,
        &reports,
        extractor,
        out_dir,
        &mut pubnames,
    );
    // Finding F10 (dedupe post) - see [`super::emptydesc`].
    super::emptydesc::land_duplicate_filedescs(
        &mut missing_files,
        &sets,
        &set_has_claims,
        &offered_names,
        &reports,
        extractor,
        out_dir,
    );
    // X5-24 (30 Aug 2026 ruling): the charge, the stray-release guard
    // and the residual-assignment tier that decides when the guard's
    // `continue` would be refusing the job's OWN set. Out of line in
    // [`super::residual`], which carries the whole argument - this
    // function sat at 488 of the size gate's 500-line ceiling when that
    // lift landed (30 Aug 2026).
    let unpriced = super::residual::charge_missing_files(
        &missing_files,
        &sets,
        &set_has_claims,
        &offered_names,
        slots,
        slot_file,
        nzb,
        verifier,
        &mut damage_by_set,
    );
    let damage: usize = damage_by_set.iter().sum();
    // Every report belongs to a slot some set CLAIMED - that is what
    // makes a report exist - so no bad block may fall outside the
    // per-set charge above and go unrepaired.
    debug_assert!(damage >= bad, "every bad block belongs to some set's file");
    // The slice arithmetic and the per-set plans it decides: what is
    // already on hand, what therefore leaves the fetch list, and one
    // [`SetPlan`] per damaged set. Out of line in [`plan_damaged_sets`],
    // which carries the whole argument - this function sat at 492 of the
    // size gate's 500-line ceiling when that lift landed (31 Aug 2026).
    let (plans, already, sniffed_vols) = plan_damaged_sets(
        &sets,
        slots,
        slot_file,
        sniff,
        sniff_bootstrap,
        bootstrap_vol,
        resume_vols,
        prefetched,
        extractor,
        &reports,
        &damage_by_set,
        &missing_files,
    );
    // Slots the recovery set does NOT cover. A PAR2 repair proves the
    // files in its own set and says nothing whatever about the rest,
    // but the repair branches below set `all_good` from the repair
    // alone: a covered RAR with one repairable block plus a `.nfo`
    // (or a second payload file) posted outside the set whose
    // articles all 430'd finished Completed, journal deleted, with
    // that file never having arrived. The clean-PAR2 and no-PAR2
    // branches already apply the equivalent test.
    //
    // Requiring the GLOBAL counters to be zero would be wrong - a
    // covered slot's missing bytes are exactly what the repair just
    // healed - so the test is per slot.
    //
    // "Covered" is the recovery set NAMING the file, not the
    // verifier having reported on it. Report presence alone is too
    // strict: a slot claims its set entry off arriving bytes, so a
    // file whose every article 430'd never claims one and reaches
    // here with no report at all - which is precisely the file the
    // repair below then recreates whole from parity. Calling that
    // "outside the PAR2 set" failed the par-only shape (100%
    // recovery posted, every archive article 430) with its payload
    // already rebuilt and extracted byte-correct: bench leg
    // a2-par-only, 2 Aug. The disk-side fallback arm has always
    // tested coverage by name (`slot_is_uncovered_hole`); this is
    // the same test against the set the NZB gave us.
    //
    // Split rather than merged, because only a repair that verified
    // the whole set OFF DISK proves the files it names - see
    // `set_files_proven` below, and the `unproven_bad` check that
    // fails the job for an in-set file no such re-read vouched for.
    // Slot index carried alongside the hint: the obfuscated-alias
    // reconciliation below needs the slot's declared size, which
    // only the NZB file behind it knows.
    let (in_set_pairs, uncovered_pairs) = partition_short_slots(slots, &sets, &reports);
    let in_set_bad: Vec<&str> = in_set_pairs.iter().map(|(_, h)| *h).collect();
    info!(
        target: "verify",
        "verified {} file(s): {} blocks in-stream, {} by read-back, {} bad - settled in {:.0} ms",
        reports.len(),
        live,
        readback,
        bad,
        vt0.elapsed().as_secs_f64() * 1000.0,
    );
    // Hoisted out of the clean arm below (issue #23's spare rule): the
    // late-set pass at the foot of this function needs it on EVERY path.
    let set_names = union_set_names(&sets);
    let spared = spared_metadata_errors(slots, &set_names);
    if damage > 0 {
        let o = run_set_repair(
            &plans,
            verifier,
            extractor,
            journal,
            slots,
            slot_file,
            servers,
            nzb,
            out_dir,
            buf_pool,
            sniff_bootstrap,
            fast_verify,
            password,
            sparse_slots,
            note_activity,
            cancel,
            damage_in_mapped,
            &already,
            &sniffed_vols,
            &reports,
            in_set_bad,
            uncovered_pairs,
            donor_dirs,
            donor_nzbs,
            &mut spent,
            &mut rescue_left,
        )
        .await?;
        all_good = o.all_good;
        reextract_failed = o.reextract_failed;
        repair_shortfall = crate::repair::scope_to_post(o.repair_shortfall, sets.len());
        unhealed_slots = o.unhealed_slots;
    } else {
        // PAR2 verifying clean is NOT the same as the download being
        // whole: `damage` only ever counts files the recovery set
        // covers (`unclaimed_files` walks `set.files`), and the
        // in-stream verifier hashes bytes as they ARRIVE, not off
        // disk. So a .nfo/sample/.sfv posted outside the par2 set
        // whose articles all 430'd, or a covered file whose write hit
        // ENOSPC after its blocks verified in flight, both land here
        // with damage == 0. Reporting success then deletes the
        // journal - the only record of what is still missing - and
        // hands an *arr an incomplete directory to import. Same test
        // the no-PAR2 branch below already applies - and, since sweep
        // 8's L5, the same spare rule the REPAIRED branch has always
        // applied: furniture the set does not cover is optional on
        // every path, not only on the one that happened to run a
        // repair.
        if spared > 0 {
            warn!(
                target: "verify",
                "{spared} decode/write error(s) on optional file(s) the recovery \
                 set does not cover - dropped, not repaired"
            );
        }
        all_good = incomplete == 0 && derrs.saturating_sub(spared) == 0;
        // A file OUTSIDE every set whose own articles contradict each
        // other: no set vouches for it, so the no-set verdict applies.
        if let Some(why) = conflicting_unvouched(slots, extractor, Some(verifier)) {
            reextract_failed = Some(why);
            all_good = false;
        }
        // The verdict line comes AFTER the verdict. It used to be the
        // first thing this branch printed, so a run that then failed on
        // `derrs` announced "clean download ✔" and went on to quarantine
        // the payload and exit 1 - the contradiction reported off the
        // 22 Aug 2026 class E floor leg. `damage == 0` says the recovery
        // set found nothing wrong with the bytes it was shown; it does
        // not say the download is whole, which is the very distinction
        // the comment above draws and the reason `all_good` is not just
        // `damage == 0`. Say the narrower thing when only the narrower
        // thing is true.
        if all_good {
            info!(target: "verify", "clean download - no repair, no post-verify pass ✔");
        } else {
            warn!(
                target: "verify",
                "the recovery set found no damage, but {} decode/write error(s) and \
                 {incomplete} incomplete file(s) are unaccounted for - the set only \
                 vouches for bytes it was shown, so this is not a clean download",
                derrs.saturating_sub(spared)
            );
        }
    }
    // Finding F12 (par2-of-par2), W4-01 and X5-24 - see [`super::latesets`].
    let declared = latesets::declared_slot_bytes(nzb, slot_file);
    let net = derrs.saturating_sub(spared);
    let left = latesets::Outstanding(all_good, incomplete, net, declared, unhealed_slots.clone());
    let (late_good, late_shortfall) =
        latesets::apply_nonactivated_disk_sets(&sets, out_dir, slots, extractor, left, cancel);
    // A late set can only ever account for a SHORT download. It says
    // nothing about a REFUSAL already recorded in `reextract_failed`
    // (M4-14a's self-contradicting post above, or "PAR2 repair
    // succeeded but re-extraction failed" from the repair ladder), and
    // `Outstanding` deliberately carries no field for one - so the flip
    // must not be allowed to outvote it. Without this, `finish_job`'s
    // `if all_good { .. return Ok(()) }` returns Completed ~80 lines
    // ABOVE the `reextract_failed` arm that would have failed the job,
    // and the refusal is dropped along with the journal.
    //
    // Not a completion regression, and checkable rather than asserted:
    // every site that can set `reextract_failed` on the way in here
    // also sets `all_good = false` (the `conflicting_unvouched` arm
    // above, and `settle::repair`'s two, whose outcome
    // `judge_repaired_job` only ever subtracts from), so on entry
    // `reextract_failed.is_some()` already implies `!all_good`. When it
    // is `None` this is exactly `late_good`.
    all_good = late_good && reextract_failed.is_none();
    // Only when the primary ladder never ran (or ran clean): a vouched
    // late set's own arithmetic OWES the same fail-message clause the
    // primary path's does (`failkind::RECOVERY_SHORTFALL_CLAUSE`), and
    // until this the message came out bare - see
    // `two_sets_naming_each_others_packets_terminate_with_an_honest_verdict`.
    // A primary shortfall already names the failure that matters here;
    // never overwritten by a set found only because it was never active.
    if repair_shortfall.is_none() {
        repair_shortfall = late_shortfall;
    }
    // X5-10, HERE and not one line earlier: a donor two sets both need
    // is not spent until the second one - the late pass - is done.
    crate::repair::sweep_spent_sources(&spent);
    // Finding F6 / W4-05: the weakest naming tier, last, over the files
    // no recovery set claimed. See [`super::sfvname`] for why a usable
    // set no longer suppresses it for the whole job.
    sfvname::land_sfv_names(slots, extractor, out_dir, &mut pubnames, &reports, &sets);
    // M4-70: weaker still, and therefore after it - a yEnc header is the
    // poster's word with no checksum behind it at all. Over the files
    // still sitting under a name only an ARTICLE ever gave them, which
    // on a set-covered post is none of them - and since finding F18
    // (1 Sep 2026) `&reports` is what MAKES that sentence true, rather
    // than the tier's own on-disk test, which reads a FileDesc name that
    // coincides with a declared yEnc name as its own work. See
    // [`super::yencname`].
    super::yencname::land_contested_yenc_names(slots, extractor, out_dir, &mut pubnames, &reports);
    // W4-09 / M4-45: a member priced at zero blocks of damage that the
    // job still has not delivered. Last, so a repair that materialized it
    // on its way past counts; `&=` and not `&&` so the report still names
    // it when the verdict is already lost. See [`super::emptydesc`].
    all_good &= !super::emptydesc::report_unsatisfied_zero_length(&unpriced, &sets, out_dir);
    // The end-of-job sniffed-leftover sweep (below, after
    // extractor.finish()) needs the set's FileDesc names to spare
    // payload that is ITSELF par2 - `set_names` above is that list.
    let sniff_covered = Some(set_names);
    Ok(SettleVerdict {
        all_good,
        reextract_failed,
        repair_shortfall,
        deferred_renames,
        published_names: pubnames,
        sniff_covered,
        unhealed_slots,
        rescue_left,
        // `damage` is what decides whether `run_set_repair` is called at
        // all, so it is exactly the "a repair pass ran" test.
        repaired: damage > 0,
    })
}

/// Decode/write errors charged to OPTIONAL FURNITURE the recovery set
/// does not cover, and which every branch of settle therefore has to
/// spare (sweep 8, L5).
///
/// Issue #23's spare rule is the contract: a `.nfo`, `.sfv` or sample
/// the set does not name cannot be healed by any repair, so an absent
/// one does not fail the job - it is dropped at finish instead. The
/// REPAIRED branch has always applied it (`uncovered_pairs` filters
/// `SpareRule` out before it can fail anything), and the clean
/// and no-set branches did not: they test `derrs == 0` flat, so the
/// same corrupt `.nfo` failed the job when the payload was clean and
/// passed green when an unrelated RAR happened to need PAR2 repair.
/// One file, one fault, and the verdict decided by a branch it has
/// nothing to do with.
///
/// The rule is applied here, before the branch, so all three agree.
/// Spared means spared: absent, corrupt and sparse alike, and dropped
/// rather than shipped.
///
/// `set_names` is the sanitized lowercase file list of the recovery set
/// - empty when the post carries no set at all, which makes every slot
/// out-of-set, exactly as that branch already treats them.
/// The files this settle must treat as MISSING ENTIRELY - the skipped
/// samples struck off, and ONE ENTRY PER NAME.
///
/// # Why the dedupe is not tidiness
///
/// `LiveVerifier::unclaimed_files` returns one entry per unclaimed
/// DESCRIPTOR, and once TODO 311 adopts every recovery set a file two
/// sets both describe has two of them. That helper already withholds a
/// name some OTHER descriptor's slot claimed; what it cannot express is
/// the WHOLLY missing case, where neither is claimed and the name comes
/// back twice. The charge loop then finds the FIRST set naming it both
/// times and charges that one set the file's whole block count TWICE -
/// so the set reads short when its own parity covers the real one-file
/// loss, and its sibling is charged nothing at all. What comes out is
/// either recovery volumes bought for damage that does not exist or a
/// false Unrepairable (29 Aug 2026 sweep, M3).
///
/// THE SIBLING HALF OF THAT SENTENCE IS NO LONGER TRUE, and reading it as
/// still open is the one way to misread this note. The dedupe here closed
/// the DOUBLE charge; `super::residual::charge_twin_sets` (31 Aug 2026)
/// closed the other end, charging every set that describes the same file
/// in its own geometry - which is `charge_reported_damage`'s W4-15 rule
/// reached from the wholly-missing door, after a probe measured a job
/// failing `20 recovery block(s) needed ... carries only 1` with
/// a sibling set's 22 slices already fetched and on disk. Deduping the
/// name and cross-charging the sets are complements, not alternatives:
/// one name is still one FILE, and one file is still healable by every
/// set carrying parity for it.
///
/// One name is one FILE here, which is the same rule the charge loop
/// already states in words ("first set naming it owns it"): two
/// descriptors sharing a name describe one path on disk, so only one of
/// them can ever be the file that is absent. Keyed on the sanitized
/// lowercase spelling, the key `offered_names` and the skip filter
/// either side of this already use.
fn missing_file_names(
    unclaimed: Vec<String>,
    skipped: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    unclaimed
        .into_iter()
        .filter(|n| {
            let keep = !skipped.contains(&nzbkit::disk::sanitize_out_name(n).to_lowercase());
            if !keep {
                info!(target: "verify", "{n} - sample skipped on request, so not repaired either");
            }
            keep
        })
        .filter(|n| seen.insert(nzbkit::disk::sanitize_out_name(n).to_lowercase()))
        .collect()
}

/// The short slots this settle still has to account for, split by
/// whether the recovery set NAMES them - carrying the slot index,
/// because the obfuscated-alias reconciliation downstream needs the
/// slot's declared size and only the NZB file behind it knows that.
///
/// Split rather than merged, because only a repair that verified the
/// whole set OFF DISK proves the files it names - see `set_files_proven`
/// and the `unproven_bad` check that fails the job for an in-set file no
/// such re-read vouched for.
///
/// Issue #23's spare rule is applied BEFORE the split, on the same
/// `SpareRule` the census asks: furniture the set does not cover cannot
/// be healed by any repair, so it does not fail the job - it is dropped
/// at finish instead. Everything reaching here is short, and the
/// uncovered side is by definition the "set does not cover it" half, so
/// the rule's own two arms are the whole question. Without it, a job
/// that took ANY damage failed on a file the census had already spared,
/// while the identical post with damage == 0 completed.
///
/// Lifted out of `settle_with_set` (TODO 106) when the M4-33 spare-rule
/// arm took that function to 502 lines against a 500 ceiling. Body
/// verbatim; the two locals it built are now its own.
fn partition_short_slots<'a>(
    slots: &'a [Arc<FileSlot>],
    sets: &[Arc<nzbkit::par2::Par2Set>],
    reports: &[(usize, nzbkit::live::SlotReport)],
) -> (Vec<(usize, &'a str)>, Vec<(usize, &'a str)>) {
    let covered: std::collections::HashSet<usize> = reports.iter().map(|(s, _)| *s).collect();
    let set_names = union_set_names(sets);
    let spare_rule = crate::get::census::SpareRule::of(slots);
    slots
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            // is_par2(): a sniffed volume (bootstrap or deferred) is
            // recovery data, not a payload file the set failed to cover.
            !s.is_par2()
                && !covered.contains(i)
                && (s.missing.load(Ordering::Relaxed) > 0
                    || s.remaining.load(Ordering::Relaxed) > 0
                    || s.errors.load(Ordering::Relaxed) > 0
                    || s.abandoned.load(Ordering::Relaxed) > 0)
        })
        .map(|(i, s)| (i, s.hint.as_str()))
        .filter(|(_, hint)| !spare_rule.spares(hint))
        .partition(|(_, hint)| {
            set_names.contains(&nzbkit::disk::sanitize_out_name(hint).to_lowercase())
        })
}

fn spared_metadata_errors(
    slots: &[Arc<FileSlot>],
    set_names: &std::collections::HashSet<String>,
) -> u64 {
    let spare_rule = crate::get::census::SpareRule::of(slots);
    slots
        .iter()
        .filter(|s| {
            !s.is_par2()
                && !set_names.contains(&nzbkit::disk::sanitize_out_name(&s.hint).to_lowercase())
                && spare_rule.spares(&s.hint)
        })
        .map(|s| s.errors.load(Ordering::Relaxed) as u64)
        .sum()
}

// The set-repair ladder - the mapped pass, the disk pass for the sets
// it declined, the second-entry duplicate fill off newly materialized
// volumes, and the alias reconciliation the repaired names need - is
// one subject and came out whole (TODO 106, 30 Aug 2026). Only the
// ladder itself is called from here; the four rungs are private to it.
mod repair;
use super::latesets;
use super::sfvname;
use repair::run_set_repair;
// ONE item out of that module and not the module itself, so the note
// above stays true of the four rungs. The yEnc encoded-over-decoded
// size model is derived and pinned in there (`band_tests.rs`), and
// `latesets::fits` asks the same physical question about a late set's
// rebuild - see `repair::alias_size_band`'s own note for what having
// answered it twice cost.
pub(in crate::get) use repair::alias_size_band;

// The no-set path - the disk-side PAR2 fallback, the no-set settle arm
// and the two tail-side reclaim doors - is one subject and came out
// whole (TODO 106, 31 Aug 2026). `conflicting_unvouched` below stayed:
// both arms ask it. The two doors are re-exported at the visibility
// they already had, so no call site in `get::tail` changes.
mod noset;
use noset::settle_without_set;
pub(super) use noset::{fetch_matched_deferred, reclaim_par2_named_payload};

/// The slots whose bytes two articles of the post CONTRADICTED, with no
/// recovery set to adjudicate the disagreement - phrased as the refusal,
/// or `None` when there are none.
///
/// A conflicting rewrite (`Extractor::slot_had_conflicting_rewrite`) means
/// two ARTICLE deliveries claimed one byte range and disagreed about what
/// is in it: overlapping `=ypart` ranges, or a rogue duplicate segment.
/// Where a set covers the file this must NOT fire and does not - settle
/// already forces a read-back for any overlap at all (`slot_had_rewrite`
/// -> `force_readback`) and the set's own hashes then say which copy is
/// right, which is what heals it. Where nothing covers it there is no
/// second opinion to consult, and which copy survives is decided by
/// arrival order: the same post delivers two different files on two runs,
/// both at rc=0.
///
/// So the honest answer is a refusal naming the range - and deliberately
/// not "the payload is incomplete", because every article arrived and
/// decoded. What is wrong is the post, and the reason has to say so.
fn conflicting_unvouched(
    slots: &[Arc<FileSlot>],
    extractor: &nzbkit::extract::Extractor,
    verifier: Option<&nzbkit::live::LiveVerifier>,
) -> Option<String> {
    let mut hits: Vec<String> = Vec::new();
    for (sidx, s) in slots.iter().enumerate() {
        // A recovery slot carries no payload to contradict, and a slot
        // some set claimed is the healed case above.
        if s.is_par2() || verifier.is_some_and(|v| v.slot_set(sidx).is_some()) {
            continue;
        }
        if let Some((off, len)) = extractor.slot_had_conflicting_rewrite(sidx) {
            hits.push(format!(
                "{}: two articles both claim bytes [{off}, {}) and disagree about them",
                s.hint,
                off + len
            ));
        }
    }
    if hits.is_empty() {
        return None;
    }
    let why = format!(
        "the post contradicts itself and carries no recovery set to settle it - {}",
        hits.join("; ")
    );
    // Logged HERE rather than at each caller: one sentence, one place, and
    // `settle_with_set` sat at 500 of the size gate's 500-line ceiling
    // when this landed (30 Aug 2026).
    warn!(target: "verify", "✘ {why}");
    Some(why)
}

#[cfg(test)]
mod spare_contract_tests {
    use super::*;

    /// GH #63: the FileDesc rename is guarded, and guarded only in the
    /// losing direction.
    ///
    /// Both `extractor.rename` sites in this file go through
    /// `filedesc_name_is_better`, so a recovery set generated AFTER the
    /// obfuscating rename - which lists the hashes back, and which
    /// `nzbfast-par2-name-recovery` measured to be the common order -
    /// cannot rename a correctly-named file to a hash. Fixing the write
    /// side alone would not have been enough on #63's post: it ships a
    /// set PER FILE, so every track's own set would have renamed it
    /// straight back.
    #[test]
    fn a_hash_filedesc_does_not_rename_a_named_file_back() {
        // #63: the subject named it, the set does not.
        let named = slot("01-duo_something_bi-noir.mp3", false, 0);
        assert!(!filedesc_name_is_better(
            &named,
            "c238183c9ea852006dbc09ffa6a26e987f76060474363d"
        ));

        // #43/#47: the subject is a hash, the FileDesc is the recovery.
        // This is the whole deobfuscation line and it must keep working.
        let obf = slot("2137d880a074c9f1e0b3a5d6c7e8f901", false, 0);
        assert!(filedesc_name_is_better(&obf, "Some.Film.2026-GRP.mkv"));

        // A real FileDesc over a real subject name still wins: the set
        // is MD5-proven and nothing is being given up.
        assert!(filedesc_name_is_better(&named, "Track 01 - Real Title.mp3"));
    }

    /// Wave-4 row M4-86 (31 Aug 2026): the boundary of
    /// [`lossy_name_loses_to`], driven over the names that can be held.
    ///
    /// The three `e2e_norar::encoding` fixtures drive it through real
    /// posts; what this adds is the boundary itself, including the two
    /// directions no fixture reaches - mojibake in hand as well as in the
    /// set, and a readable set name over mojibake on disk, which is the
    /// ordinary deobfuscation rename and must not be undone.
    #[test]
    fn a_lossy_set_name_gives_way_only_to_a_held_name_that_reads() {
        let lossy = "caf\u{fffd}.mkv";
        // The row: a readable name in hand comes back.
        assert!(lossy_name_loses_to(lossy, "caf\u{e9}.mkv"));
        // And a hash does not - most of a name beats none of one, which
        // is what keeps this from costing anything.
        assert!(!lossy_name_loses_to(lossy, "Kj8sWm3xPd"));
        // Mojibake in hand too: both unreadable, so nothing is bought by
        // swapping one for the other and the set's spelling stands.
        assert!(!lossy_name_loses_to(lossy, lossy));
        // A readable FileDesc name is untouched by any of this - it is
        // the name that lands, exactly as before.
        assert!(!lossy_name_loses_to(
            "Some.Film.2026-GRP.mkv",
            "caf\u{e9}.mkv"
        ));
        // The replacement character has to be in the SET's spelling and
        // not just anywhere: a readable set name over mojibake on disk is
        // the ordinary deobfuscation rename and must not be undone.
        assert!(!lossy_name_loses_to("Real.Name.mkv", lossy));
    }

    /// The boundary of [`set_name_loses_to_held`], in its own file. This
    /// one is near its size-gate ceiling with several lanes appending to
    /// it, and a CHILD of this inline module reaches `slot` and both
    /// predicates through `use super::*` with no visibility change - the
    /// same relationship `nzbkit::par2`'s `par2/tests/name_tests.rs` has
    /// to the module above it.
    mod name_rule_tests;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    /// M3 (29 Aug 2026 sweep): a file two adopted recovery sets both
    /// describe, and that NEITHER claimed, is one absent file - not two.
    ///
    /// Charged twice it made the first set read short of parity it
    /// actually has, and charged its sibling nothing: recovery volumes
    /// bought for damage that does not exist, or a false Unrepairable.
    #[test]
    fn a_wholly_missing_name_two_sets_both_name_is_charged_once() {
        let none: HashSet<String> = HashSet::new();
        assert_eq!(
            missing_file_names(
                vec![
                    "shared.bin".into(),
                    "shared.bin".into(),
                    "only-in-a.bin".into()
                ],
                &none
            ),
            vec!["shared.bin".to_string(), "only-in-a.bin".to_string()],
            "two descriptors of one absent path are one loss"
        );
        // Same key the charge loop and `offered_names` use: case and
        // path separators are not evidence about which file this is.
        assert_eq!(
            missing_file_names(vec!["Shared.BIN".into(), "shared.bin".into()], &none).len(),
            1
        );
        // A skipped sample is struck off before the dedupe and stays off.
        let skipped: HashSet<String> = ["sample.mkv".to_string()].into_iter().collect();
        assert_eq!(
            missing_file_names(
                vec!["sample.mkv".into(), "sample.mkv".into(), "real.mkv".into()],
                &skipped
            ),
            vec!["real.mkv".to_string()]
        );
    }

    /// Claim `materialize-gh63-rename` (read-only sweep finding 2,
    /// 31 Aug 2026): the deferral has to be decidable for a slot with
    /// NO FILE, because those are exactly the slots the repair ladder
    /// materializes and then looks for by the set's spelling.
    ///
    /// Before [`current_leaf`] learned to read a writerless slot's
    /// pending name this returned `None` structurally - no writer, so
    /// `slot_path` is `None` - and `settle_slots`' rename gate fell back
    /// to `filedesc_name_is_better` alone. On the #63 shape below that
    /// says NO, so the volume kept the honest name, materialized under
    /// it, and the disk repair went looking for `abc123hashname.rar` and
    /// reported a member missing that it was sitting on.
    ///
    /// The control is the second half: with nothing latched there is no
    /// name to lose and the answer is still `None`, which is where the
    /// rename proceeds exactly as it did before M4-86.
    #[test]
    fn a_slot_with_no_file_yet_can_still_defer_its_honest_name() {
        let dir = std::env::temp_dir().join(format!("nzbfast-gh63-pending-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let ex = Arc::new(nzbkit::extract::Extractor::new(&dir, 2, false));
        ex.anchor();
        let s = slot("Real.Movie.2026.1080p-GRP.mkv", false, 0);

        // Nothing written and nothing latched: no name to lose.
        assert_eq!(current_leaf(&ex, 0), None);
        assert_eq!(
            crate::get::publishplan::deferred_name(&s, Some("abc123hashname.rar"), &ex, 0),
            None,
            "a slot with no name at all has nothing to defer"
        );

        // The mapped slot's real state: writerless, with the name its
        // materialization will create the file under.
        ex.rename(1, "Real.Movie.2026.1080p-GRP.mkv");
        assert_eq!(
            current_leaf(&ex, 1).as_deref(),
            Some("Real.Movie.2026.1080p-GRP.mkv"),
            "the pending name IS what a rename to the set's spelling would cost"
        );
        assert!(
            !filedesc_name_is_better(&s, "abc123hashname.rar"),
            "#63 refuses the hash on its own - which is why the deferral is the only door"
        );
        assert_eq!(
            crate::get::publishplan::deferred_name(&s, Some("abc123hashname.rar"), &ex, 1)
                .as_deref(),
            Some("Real.Movie.2026.1080p-GRP.mkv"),
            "so settle takes the set's spelling and queues the honest name back"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn slot(hint: &str, par2: bool, errors: usize) -> Arc<FileSlot> {
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
            errors: AtomicUsize::new(errors),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(None),
        })
    }

    /// Sweep 8, L5: one contract for out-of-set furniture, applied
    /// before the branch.
    ///
    /// The repaired branch has always spared it (issue #23: the set
    /// does not cover it, so no repair could heal it, so it is dropped
    /// rather than failing the job). The clean and no-set branches
    /// tested `derrs == 0` flat, so the SAME corrupt `.nfo` failed the
    /// job when the payload was clean and passed green when an
    /// unrelated RAR happened to need repair - the verdict decided by a
    /// branch the file has nothing to do with.
    #[test]
    fn out_of_set_furniture_is_spared_whatever_branch_settles_the_job() {
        let slots = vec![
            slot("movie.part01.rar", false, 0),
            slot("movie.nfo", false, 1),
            slot("movie.par2", true, 3),
        ];
        let covers_rar: HashSet<String> = ["movie.part01.rar".to_string()].into_iter().collect();

        // The `.nfo` the set does not cover: optional, so its error may
        // not decide the job on any branch.
        assert_eq!(spared_metadata_errors(&slots, &covers_rar), 1);
        // No set at all - everything is out-of-set, and the answer is
        // the same one.
        assert_eq!(spared_metadata_errors(&slots, &HashSet::new()), 1);
        // A set that DOES name the `.nfo` covers it: repair speaks for
        // it, so it is not spared and its damage still counts.
        let covers_nfo: HashSet<String> = ["movie.nfo".to_string()].into_iter().collect();
        assert_eq!(spared_metadata_errors(&slots, &covers_nfo), 0);
        // Recovery slots are never furniture - they have their own
        // exclusion (`recovery_errs`) and double-counting them here
        // would spare real parity damage.
        assert_eq!(
            spared_metadata_errors(&[slot("movie.par2", true, 3)], &HashSet::new()),
            0
        );
        // And payload is payload: a damaged RAR outside the set fails
        // the job exactly as before.
        assert_eq!(
            spared_metadata_errors(&[slot("extra.part02.rar", false, 2)], &HashSet::new()),
            0
        );
    }

    /// The MIXTURE discriminator, at the census rather than through a
    /// whole download: which key it matches on, and what it refuses to
    /// answer.
    ///
    /// The e2e leg
    /// `a_set_whose_file_the_post_offered_and_lost_whole_is_still_rebuilt`
    /// pins the BEHAVIOUR; this pins the two decisions inside it that a
    /// tidy-up would quietly undo. The obfuscated case is here so the
    /// stated limit is a test and not only a comment: a hash-subject
    /// post answers `false`, its set stays skipped, and nothing about
    /// this census pretends otherwise.
    #[test]
    fn the_offered_census_reads_names_and_says_nothing_about_hashes() {
        // The mixture and the stray, side by side and told apart: the
        // post offers track03 and has never heard of the other release.
        let post = [slot("track01.bin", false, 0), slot("track03.bin", false, 0)];
        let offered = super::super::emptydesc::names_offered_by_the_post(&post);
        assert!(offered.contains("track03.bin"));
        assert!(!offered.contains("elsewhere-a.bin"));

        // Per FILE, not per set. The census answered per set for a day,
        // and one generic name shared with a stray (`01.rar` twice on
        // one wire) then marked the stray's ENTIRE contents as this
        // post's - its never-posted files were charged to damage, which
        // is the exact failure the guard exists to prevent. A set
        // pairing `never-posted.bin` with `track03.bin` gets the
        // offered answer for track03 alone.
        assert!(!offered.contains("never-posted.bin"));

        // Sanitized and lowercased, the key `union_set_names` and the
        // coverage census either side of the guard already use. A
        // matcher narrowed to a byte compare passes every case above
        // and fails this one.
        let shouty =
            super::super::emptydesc::names_offered_by_the_post(&[slot("TRACK03.BIN", false, 0)]);
        assert!(shouty.contains("track03.bin"));

        // THE STATED LIMIT, as a test. An obfuscated post names nothing
        // the FileDesc can be matched against, so the census declines
        // and the set falls back to being skipped exactly as it was
        // before this existed. Size-banding it against the FileDesc
        // length is what `reconcile_obfuscated_aliases` does for the
        // same question, and is rejected here for the reason at
        // `names_offered_by_the_post`: that pairing only ever SPARES a
        // slot, and this answer CHARGES a file to a set's damage.
        let obf = super::super::emptydesc::names_offered_by_the_post(&[slot(
            "2137d880a074c9f1e0b3a5d6c7e8f901",
            false,
            0,
        )]);
        assert!(!obf.contains("track03.bin"));
    }
}
