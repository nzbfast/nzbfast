//! The native in-process Reed-Solomon repair pass over one recovery set.
//!
//! Its own file for `volbase`'s reason: on 31 Aug 2026 repair.rs was at
//! 2,903 of the size gate's 3,000-line ceiling, so a helper lifted to buy
//! a function's margin had to leave the file to avoid spending the file's
//! own. It left [`super::fetch_and_repair`] that day, where it had been a
//! closure 25 lines under the 500-line FUNCTION ceiling. One caller,
//! which still binds it as a closure so its three call sites are
//! unchanged.

use super::*;

/// Every entry of `per_file` whose landed path is not the one its own
/// declared name predicts, appended to `into` without duplicating an
/// entry already there.
///
/// The comparison is [`nzbkit::disk::out_name_of`] against
/// [`nzbkit::disk::sanitize_out_name`] of the FileDesc name - the same
/// pair `par2repair.rs` composes to plan a target's destination in the
/// first place, so a mismatch here is exactly "this landed somewhere
/// other than that plan said", whatever the reason (a same-set collision,
/// a name contested by another set in this directory, or anything else a
/// future disambiguation adds). `into` is checked for the exact pair
/// before pushing: two passes over one set produce the same census
/// (X-8), so calling this once per pass is safe and the caller renders
/// `into` exactly once regardless of how many passes ran.
fn record_declared_name_mismatches(
    dir: &Path,
    per_file: &[nzbkit::par2repair::FileRepair],
    into: &mut Vec<(String, String)>,
) {
    for f in per_file {
        let landed = nzbkit::disk::out_name_of(dir, &f.path);
        if landed != nzbkit::disk::sanitize_out_name(&f.name) {
            let entry = (f.name.clone(), landed);
            if !into.contains(&entry) {
                into.push(entry);
            }
        }
    }
}

/// The native in-process Reed-Solomon pass. It was a closure inside
/// [`super::fetch_and_repair`] over `out_dir`/`set`/`donor_dirs` until
/// 31 Aug 2026, when that function sat at 475 of the size gate's 500-line
/// ceiling; those are parameters now and nothing else changed. PAST TENSE
/// on purpose - the split is what fixed the margin, so a present-tense
/// "is at the ceiling" here would be false the moment it was written. `probe` is
/// the scan-before-buying caller - see [`super::adoption_narrowed_need`] and
/// [`super::native_shortfall`], which is the only thing that reads it.
///
/// Reed-Solomon repair: native in-process GF(2^16) first - verifies the
/// set from disk, reconstructs missing blocks, and patches files IN
/// PLACE (no volume rewrite). Self-proving: success requires every
/// patched file to match its PAR2 whole-file MD5, so a native bug can
/// never ship bad bytes - it falls through to par2cmdline instead.
///
/// SCOPED TO THIS SET BY ID, and load-bearing: this runs once PER
/// declined set (`disk_repair_declined_sets`) and the directory-scoped
/// entry repaired the first set every time, greening over the others'
/// holes - see [`nzbkit::par2repair::repair_dir_set_with_donors`].
///
/// X5-10 (31 Aug 2026): `spent` is where a proven-spent adoption source
/// is RECORDED instead of being deleted here - see the push site below.
/// A `Mutex` and not a `&mut`, because the caller binds this as a
/// closure it hands on as `&dyn Fn`; the whole argument is at that
/// binding.
pub(super) fn native_repair_pass(
    out_dir: &Path,
    set: &nzbkit::par2::Par2Set,
    donor_dirs: &[PathBuf],
    probe: bool,
    spent: &std::sync::Mutex<&mut Vec<PathBuf>>,
    // Declared FileDesc names this set's census says landed somewhere
    // other than their own sanitized name predicts - the once-per-job
    // half of the account `nzbkit::par2repair::dupclaim` documents.
    // `RepairReport::per_file` is a full census of the set on EVERY
    // pass (X-8), so recording from it here is safe to call twice: the
    // caller dedupes by content before it renders anything, so a job
    // that runs this pass twice over the same set says it once.
    mismatches: &std::sync::Mutex<&mut Vec<(String, String)>>,
    // The owner's recovery-work handle, or None on a CLI run. Both
    // halves of the repair's control come off it: the progress the
    // queue row draws, and the cancel the fold polls - see
    // [`nzbkit::par2repair::control`] and
    // [`crate::repair::SideCancel::repair_control`]. `None` builds
    // an INERT control, which is the call this function made before
    // 12 Sep 2026, branch for branch.
    cancel: Option<&crate::repair::SideCancel>,
) -> NativeVerdict {
    if std::env::var_os("NZBFAST_NO_NATIVE_REPAIR").is_some() {
        return NativeVerdict::Backstop;
    }
    let t0 = Instant::now();
    use nzbkit::par2repair::{
        CallerSite, CallerStage, RepairStatus, RetentionCaller,
        repair_dir_set_with_donors_controlled_as,
    };
    // `probe` is the pre-purchase adoption probe (`adoption_narrowed_need`
    // is its only caller), and it is a PAID attempt whose verdict may be
    // thrown away - so the retention admission census sees it as its own
    // caller and stage rather than as a second sighting of this one.
    let caller = if probe {
        RetentionCaller::new(CallerSite::AdoptionProbe).at_stage(CallerStage::Probe)
    } else {
        RetentionCaller::new(CallerSite::DownloadDiskRepair).at_stage(CallerStage::Final)
    };
    // THE CONTROLLED DOOR, since 12 Sep 2026. Same catalog semantics as
    // the uncontrolled `repair_dir_set_with_donors_as` this replaced -
    // complete build, flat scope, no in-place patching of existing
    // volumes, directory-wide contest reading - plus a channel: the
    // engine's verify/fold/solve/write phases report into the queue
    // row, and their loops poll this job's cancel. It also makes this
    // repair ATTENDED, which lifts the unattended unstructured ceiling
    // `serve/mod.rs` sets - see `RepairControl::is_attended`.
    //
    // `_run` is the reporting WINDOW and its scope is load-bearing: the
    // recovery-volume side-fetches between two passes run under the
    // same `repairing` activity word, and a row that went on showing
    // the last phase through them would be the static-word failure this
    // whole change is about, wearing a percentage.
    let control = cancel.map(|c| c.repair_control()).unwrap_or_default();
    let _run = cancel.map(|c| c.repair_progress().enter());
    match repair_dir_set_with_donors_controlled_as(
        out_dir,
        &set.recovery_set_id,
        donor_dirs,
        caller,
        control,
    ) {
        Ok(RepairStatus::NoDamage) => {
            info!(
                target: "repair",
                "repair complete in {:.2?} ✔ (native - set already verifies on disk)",
                t0.elapsed()
            );
            NativeVerdict::Done
        }
        Ok(RepairStatus::Repaired(r)) => {
            // `r.blocks_rebuilt` is what `repair_dir`'s own verify
            // found bad ON DISK at this instant. That is NOT the
            // damage count settle printed, and on a chased set that
            // declined the mapped route it is reproducibly LOWER -
            // often zero, in which case this arm does not run at all
            // and the `NoDamage` line above prints instead. Nothing
            // is undercounted here: a declined mapped attempt is not
            // rolled back, so the blocks it already landed are good
            // on disk by the time this pass looks.
            //
            // Measured 23 Aug 2026 (M3 Ultra, costB2
            // `loop-comp-silent`, 3 reps of 3 identical; same shape
            // at test scale in
            // `a_declined_mapped_repair_still_lands_every_rebuilt_block`)
            // at "3/35 blocks bad", the verify-gated twin saying
            // "mapped: 3 block(s)" and this line "in place: 2
            // block(s)". That split was a DEFECT, fixed the same
            // day: the mapped attempt's first patched block landed
            // in the chase's frontier buffer, `chase_span` saw it
            // conflict with bytes the decode had already consumed
            // and forfeited INSIDE that write, and
            // `patch_volume_span` then refused the demoted slot -
            // so the next block's write returned "no backing data"
            // and two blocks already solved in memory were thrown
            // away for this pass to solve again. `patch_volume_span`
            // now admits `RarFallback` and those writes go through
            // to the volume the demote just materialized, so the
            // same fixture reaches here with nothing to rebuild.
            //
            // What did NOT change is the decline itself: the decode
            // consumed stale bytes, so the set still materializes
            // and re-extracts. Only the repair work stopped being
            // discarded.
            //
            // The "need N block(s) →" line just above still names
            // the LEDGER's N, so this route still plans for blocks
            // it no longer needs - it reuses the mapped attempt's
            // volumes rather than buying them twice (see `banked`),
            // and the surplus is inside the exact-fit margin.
            info!(
                target: "repair",
                "repair complete in {:.2?} ✔ (native, in place: {} block(s) rebuilt across {} file(s){}{})",
                t0.elapsed(),
                r.blocks_rebuilt,
                r.files_patched.len(),
                if r.files_created.is_empty() {
                    String::new()
                } else {
                    format!(", {} recreated", r.files_created.len())
                },
                nzbkit::par2repair::adopted_from_clause(r.blocks_adopted, &r.adopted_from),
            );
            // Sources the report PROVED spent (byte-identical to a
            // verified target, or its damaged twin - see the
            // spent_donors rules in par2repair.rs) are this job's
            // own obfuscated copies, fully superseded by the file
            // the repair just landed. The disk-fallback path has
            // always swept these; this path left them lingering in
            // finished jobs (finding F9's residue).
            //
            // RECORDED, NOT DELETED, since X5-10 (31 Aug 2026): this
            // runs once PER SET, and the proof is about THIS set's
            // targets only. A donor carrying blocks of two disjoint
            // sets is "majority-fed" by whichever set runs first -
            // `adopt::proven_spent`'s twin arm excuses every slice the
            // repair rebuilt from parity, so the blocks that belong to
            // the OTHER set are never compared against anything - and
            // deleting it here took the second set's target to zero
            // bytes, measured. The sweep happens once every set has had
            // its turn, the late ones in `get::latesets` included;
            // `get::settle::settle_with_set` is where that is.
            spent.lock_ok().extend_from_slice(&r.consumed_sources);
            record_declared_name_mismatches(out_dir, &r.per_file, &mut mismatches.lock_ok());
            NativeVerdict::Done
        }
        Ok(RepairStatus::Unrepairable {
            needed,
            have,
            adopted,
            partial,
        }) => {
            // The set is short and the verdict below says so, unchanged.
            // What is new since 31 Aug 2026 is that the engine no longer
            // returns before writing: a MEMBER whose own blocks were all
            // present or adopted is written under its FileDesc name and
            // whole-file-MD5 verified anyway, so this line is the only
            // place a user is told those files landed. `consumed_sources`
            // is always empty on this verdict, so there is deliberately
            // nothing to add to `spent` - see the field's note on
            // `nzbkit::par2repair::RepairStatus::Unrepairable`.
            if !partial.files_patched.is_empty() {
                info!(
                    target: "repair",
                    "native repair{}",
                    nzbkit::par2repair::published_clause(&partial)
                );
            }
            record_declared_name_mismatches(out_dir, &partial.per_file, &mut mismatches.lock_ok());
            native_shortfall(needed, have, adopted, probe)
        }
        // THE USER'S CANCEL IS NOT A FAILED REPAIR, and telling the two
        // apart is the whole reason this arm is ahead of the one below.
        // Falling through to par2cmdline would re-run the entire repair
        // externally for a job that has just been deleted, and the warn
        // would say the set is broken when nothing about it is - see
        // `NativeVerdict::Cancelled` and the on-disk contract on
        // `RepairError::Cancelled`.
        Err(nzbkit::par2repair::RepairError::Cancelled) => {
            info!(
                target: "repair",
                "repair stopped after {:.2?} - the job was cancelled (nothing was renamed \
                 in, and any block already patched is one that was missing)",
                t0.elapsed()
            );
            NativeVerdict::Cancelled
        }
        Err(e) => {
            warn!(target: "repair", "native repair failed ({e}) - falling back to par2cmdline");
            NativeVerdict::Backstop
        }
    }
}
