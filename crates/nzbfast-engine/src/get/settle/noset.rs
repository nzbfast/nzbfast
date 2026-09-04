//! The no-set path: what settle does when the NZB itself carried no
//! recovery set to verify against. The disk-side PAR2 fallback (a set
//! that arrived as PAYLOAD rather than as a declared recovery file),
//! the no-set settle arm itself, and the two tail-side reclaim doors
//! that ask the same question after the download slot has gone.
//! Lifted out of settle.rs whole and in file order (TODO 106,
//! 31 Aug 2026), bodies verbatim.
//!
//! Three call edges in, and they are why this is the cheapest seam
//! left in the file: [`settle_without_set`] from the parent's
//! `settle_verify_repair`, and [`reclaim_par2_named_payload`] and
//! [`fetch_matched_deferred`] from `get::tail`. `disk_par2_fallback`
//! and `feed_slot_from_disk` are called from nowhere else and stay
//! private here.
//!
//! `conflicting_unvouched` deliberately did NOT come with it: both
//! settle arms ask it, so it stays with the parent and is reached
//! through the glob below. That is the same rule the set-repair
//! ladder next door follows - a helper moves only where it belongs to
//! one path.

use super::*;
// Imported from `crate::get` by their full path rather than through
// `super::`: inside the parent those three names are private `use`
// bindings of settle.rs's own, so a `super::latesets` down here would
// be resolving through a binding the parent keeps for ITSELF and would
// break the day settle.rs stops needing it.
use crate::get::{latesets, sfvname, yencname};

/// The disk-side PAR2 fallback: no set came from the NZB, but the downloaded
/// files include one, so every set whose data files are on disk is repaired in
/// place and the slots it does not cover are collected for the caller's guard.
///
/// A no-op when the output directory holds no PAR2 at all - the guard the
/// caller used to spell out - so the three pieces of state it owns come in and
/// go back out unchanged in that case. Split out of `settle_without_set`
/// (TODO 106), body verbatim.
#[expect(clippy::too_many_arguments)]
async fn disk_par2_fallback(
    out_dir: &Path,
    slots: &[Arc<FileSlot>],
    extractor: &Arc<nzbkit::extract::Extractor>,
    sparse_slots: &[String],
    note_activity: &(dyn Fn(&'static str) + Sync),
    par_cleanup: bool,
    mut all_good: bool,
    mut repaired: bool,
    mut uncovered_after_par2: Vec<String>,
    mut repair_shortfall: Option<crate::repair::RepairShortfall>,
) -> (
    bool,
    bool,
    Vec<String>,
    Option<crate::repair::RepairShortfall>,
) {
    if !dir_has_par2(out_dir).unwrap_or(false) {
        return (all_good, repaired, uncovered_after_par2, repair_shortfall);
    }
    use nzbkit::par2repair::{PacketCatalog, RepairStatus};
    let t0 = Instant::now();
    // Everything below this line may rewrite a data file in
    // place, and none of it goes through the extractor.
    repaired = true;
    note_activity("repairing");
    // §129: same one-repair-at-a-time permit as the set-repair
    // path; released when this directory pass ends. Taken AFTER
    // the deferred-volume fetch above on purpose - everything
    // from here down is CPU and local disk, so this pass needs
    // no `without_permit` seam of its own (§137.2).
    let _cpu = crate::lanegate::HeavyCpu::acquire().await;
    info!(
        target: "par2",
        "no PAR2 set came from the NZB, but the downloaded files \
         include one - repairing from disk…"
    );
    // Every set whose data files are on disk, not just the
    // first in packet-sorted order (`repair_dir`'s rule).
    // A season pack posted with a set per episode had one
    // arbitrary set decide the whole job: that set
    // verifying clean reported success while the damaged
    // episode's set was never looked at.
    // The `or_renamed` entry point: on a wholly renamed
    // post no FileDesc name is on disk, and the plain
    // presence gate would skip a complete recovery set
    // sitting right there. Safe HERE because this arm
    // owns a directory where every downloaded byte has
    // already landed; the nested post-pass keeps the
    // name-only gate for the opposite reason.
    // One validated packet catalog for the whole pass: the
    // repairs, `covered_names` and the sniffed-volume sweep
    // below all consult it instead of rescanning the corpus
    // (B2, 20 Aug perf audit).
    let mut cat = match PacketCatalog::build(out_dir) {
        Ok(c) => Some(c),
        Err(e) => {
            warn!(target: "par2", "repair error - {e}");
            None
        }
    };
    let results = match cat
        .as_mut()
        .map(PacketCatalog::repair_present_or_renamed_sets)
    {
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            warn!(target: "par2", "repair error - {e}");
            Vec::new()
        }
        None => Vec::new(),
    };
    // Vacuous truth is not success: no set qualifying (no
    // packets, or no set whose files are here) means no
    // repair happened at all.
    let (mut every_set_ok, multi) = (!results.is_empty(), results.len() > 1);
    // A set that RAN and said it cannot heal its own files, as distinct
    // from `every_set_ok`'s other meaning - the vacuous-truth guard on
    // the line above, which is false whenever NO set qualified. The two
    // are separated because only one of them may fail a job that is
    // otherwise complete: see the `all_good` write at the end of this
    // function.
    let mut any_set_failed = false;
    // Obfuscated copies the adoption scan read the payload
    // out of, gathered across every set and acted on only
    // once ALL of them have verified: with a set per
    // episode, one repaired set is no licence to delete
    // anything another set may still need.
    let mut consumed: Vec<PathBuf> = Vec::new();
    // Names a set actually VERIFIED. A set with no data
    // file on disk is skipped and reports nothing, so
    // its declared names are not evidence about
    // anything - see the hole scan below.
    let mut healed: Vec<String> = Vec::new();
    for r in results {
        match r.status {
            Ok(RepairStatus::NoDamage) => {
                info!(target: "par2", "no damage, set verifies on disk ✔");
                healed.extend(r.names);
            }
            Ok(RepairStatus::Repaired(rep)) => {
                // THE ADOPTION CLAUSE IS NOT DECORATION, and this line
                // went without one until 31 Aug 2026: the disk fallback
                // runs the adoption scan (`consumed` below is what it
                // read the payload out of), and a report naming only
                // the rebuilt count reads to
                // `adoptguard::refuse_a_solve_that_solved_nothing` as a
                // repair that adopted nothing - the silent shape that
                // guard exists to refuse. Shared spelling, see there.
                info!(
                    target: "par2",
                    "repaired ✔ ({} block(s) rebuilt across {} file(s){})",
                    rep.blocks_rebuilt,
                    rep.files_patched.len(),
                    nzbkit::par2repair::adopted_from_clause(rep.blocks_adopted, &rep.adopted_from),
                );
                consumed.extend(rep.consumed_sources);
                healed.extend(r.names);
            }
            Ok(RepairStatus::Unrepairable {
                needed,
                have,
                adopted,
                partial,
            }) => {
                // The set FAILED and every flag below says so, exactly as
                // before. What changed on 31 Aug 2026 is that the engine
                // no longer returns before writing: a member whose own
                // blocks were all present or adopted is published under
                // its FileDesc name and whole-file-MD5 verified anyway.
                //
                // `healed` deliberately does NOT gain those names. It
                // feeds the hole scan below, whose question is which
                // names a set VERIFIED as a whole, and a set that could
                // not repair itself has not answered it - crediting it
                // with a member would let the rest of the set read as
                // covered. And `consumed` gains nothing because
                // `consumed_sources` is always empty on this verdict:
                // see the field's note on
                // `nzbkit::par2repair::RepairStatus::Unrepairable`.
                warn!(
                    target: "par2",
                    "UNREPAIRABLE - need {needed} recovery block(s), have {have}{}{}",
                    crate::diag::adopted_clause(adopted),
                    nzbkit::par2repair::published_clause(&partial)
                );
                repair_shortfall = crate::repair::blocks_over_set(needed, have, r.set_id, multi);
                every_set_ok = false;
                any_set_failed = true;
            }
            Err(e) => {
                warn!(target: "par2", "repair error - {e}");
                every_set_ok = false;
                any_set_failed = true;
            }
        }
    }
    if every_set_ok {
        // A repair proves the files in its own recovery
        // set and says nothing whatever about the rest -
        // the invariant the in-stream arm above spells out
        // and tests for. NoDamage is the sharper case: it
        // means the fallback healed NOTHING, on a path only
        // reached because something was already bad.
        // Two different questions, two different sets.
        //
        // `named` is every name ANY set in the directory
        // speaks for - the right answer to "is this file
        // somebody's payload", which is what the
        // recovery-volume sweep below asks before it
        // deletes anything.
        //
        // `covered` is only what a set that actually
        // REPORTED verified. A set whose data files are
        // all absent is skipped and never runs, so
        // counting its declared names as healed let a
        // wholly missing file - one file of a season
        // pack taken down, every article 430 - read as
        // covered in the hole scan. The job reached
        // Completed, and deleted the journal that was
        // the only record of what was still missing.
        let named: std::collections::HashSet<String> = cat
            .as_mut()
            .and_then(|c| c.covered_names().ok())
            .unwrap_or_default()
            .iter()
            .map(|n| nzbkit::disk::sanitize_out_name(n).to_lowercase())
            .collect();
        let covered: std::collections::HashSet<String> = healed
            .iter()
            .map(|n| nzbkit::disk::sanitize_out_name(n).to_lowercase())
            .collect();
        // Issue #9, second half. The payload now exists
        // under the name the PAR2 set gives it, so the
        // obfuscated file its bytes were read out of is a
        // byte-for-byte duplicate - 8.2 GB of one on the
        // report that raised this, beside the 8.2 GB that
        // was wanted. The engine will not remove a source
        // (it does not own this directory) and the job
        // tail's sweep goes by extension, which a hash
        // name has none of, so the duplicate outlived
        // every existing cleanup.
        //
        // BEFORE the uncovered-hole scan below, and that
        // ordering is load-bearing in both directions.
        // `covered` is already computed, so the packets
        // have been read. And the scan asks whether each
        // damaged slot's file is a hole: a consumed source
        // still sitting there under a hash name matches no
        // covered name and is not par2 magic, so it reads
        // as an uncovered hole and fails the whole job.
        // Deleted, it takes the `!had_writer` branch -
        // "the extractor opened a file and it is gone,
        // adopted or renamed under its FileDesc name" -
        // which is exactly what happened.
        //
        // Only files that provably served as adoption
        // sources, and only once every set verified. Never
        // a sweep by shape: "extensionless in a finished
        // directory" describes real payload too.
        let mut freed: u64 = 0;
        let mut gone: usize = 0;
        // Trash-aware: a consumed adoption source is the
        // obfuscated post's own downloaded volume - the
        // set a user might want to keep or re-share -
        // and the sniffed recovery files go "under the
        // setting that governs named .par2", which since
        // §64 has meant a recoverable delete. Parked for
        // the deferred worker like every other sweep in
        // a job's tail, and the flag read once here at
        // the sweep's entry (remove_user_file's
        // contract).
        let recoverable = crate::smart::cleanup_recoverable();
        let staging = crate::smart::trash_staging_dir(out_dir);
        let mut remove = |p: &std::path::Path| {
            let len = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            match crate::smart::remove_swept_file(p, recoverable, staging.as_deref()) {
                Ok(_) => {
                    freed += len;
                    gone += 1;
                }
                Err(e) => {
                    // warn!, not println: the log ring is
                    // where "why is this file still
                    // here" gets answered.
                    warn!(
                        target: "cleanup",
                        "could not remove {} - {e}",
                        p.display()
                    )
                }
            }
        };
        consumed.sort();
        consumed.dedup();
        for p in &consumed {
            remove(p);
        }
        // The spent recovery volumes go the same way, under
        // the setting that governs named `.par2` - these are
        // simply the ones no extension rule can match. The
        // sniff is directory-wide and says nothing about
        // which set a volume served, which is the other
        // reason this waits for every set to have verified.
        //
        // A sniffed file that is ITSELF recovery-set payload
        // (a post whose content is par2 files) is excluded
        // by name: `named` is exactly the set of names the
        // packets speak for, skipped sets included - a
        // set that never ran still owns its files.
        if par_cleanup {
            let sniffed = cat
                .as_mut()
                .and_then(|c| c.sniffed_packet_files().ok())
                .unwrap_or_default();
            for p in sniffed {
                let is_payload = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase())
                    .is_some_and(|n| named.contains(&n));
                // Wave-4 row M4-53, the same guard the job tail's copy
                // of this sweep carries and for the same reason: the
                // name test alone let eight sniffed bytes authorise a
                // deletion. A file carrying DELIVERED bytes past its
                // packet chain - where a spent or deferred volume
                // carries a hole - is somebody's payload whatever its
                // head looks like.
                if !is_payload && nzbkit::par2repair::is_recovery_volume_shape(&p) {
                    remove(&p);
                }
            }
        }
        if gone > 0 {
            // "freed" only when the bytes actually left
            // the disk - a recoverable delete parks them
            // in the Trash on the same volume.
            info!(
                target: "cleanup",
                "cleaned up {gone} obfuscated leftover(s), {:.1} MB {}",
                freed as f64 / 1e6,
                if recoverable { "to the Trash" } else { "freed" }
            );
        }
        let spare_rule = crate::get::census::SpareRule::of(slots);
        uncovered_after_par2 = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                // is_par2(): a sniffed volume's deferred
                // (or 430'd) articles are not payload holes.
                !s.is_par2()
                    && (s.missing.load(Ordering::Relaxed) > 0
                        || s.remaining.load(Ordering::Relaxed) > 0
                        || s.errors.load(Ordering::Relaxed) > 0
                        || s.abandoned.load(Ordering::Relaxed) > 0)
            })
            // A mapped or chased slot has no standalone
            // file by design (its bytes went straight
            // into extracted output), so the name test
            // below cannot speak for it either way.
            .filter(|(i, _)| {
                !extractor.is_mapped(*i) && !extractor.is_chased(*i) && !extractor.is_rar_chased(*i)
            })
            .filter(|(i, s)| {
                slot_is_uncovered_hole(out_dir, extractor.slot_path(*i), &s.hint, &covered)
            })
            // Issue #23's spare rule again - `slot_is_uncovered_hole`
            // has already established the set does not cover this
            // file, which is exactly when furniture cannot be
            // healed and must not fail the job.
            .filter(|(_, s)| !spare_rule.spares(&s.hint))
            .map(|(_, s)| s.hint.clone())
            .collect();
        // The census's own out-of-set findings belong
        // here too (Codex sweep 2, 3 Aug M2). A slot
        // whose articles ALL arrived and still does not
        // cover its declared range has every counter at
        // zero, so the scan above cannot see it - and
        // it was exempted from the set by construction,
        // so the repair that just succeeded says
        // nothing about it.
        //
        // No skip here for a slot the verifier has since claimed, which
        // `repair::merge_sparse_slots` does carry: on this arm nothing can
        // have claimed one. The whole-file tier, the twin tier's IFSC
        // evidence and the finish-time name tier all bind out of the
        // ACTIVE set's descriptors, and this path runs only where every
        // adopted set names none - and none of the three even runs here,
        // `finish_slot` having no caller outside `settle_with_set`. The
        // late set this function repairs from is a disk `PacketCatalog`
        // and never touches verifier slot state. Held mechanically by the
        // `debug_assert` in `settle_verify_repair`'s set-less branch,
        // which carries the full argument (sweep item 13b, 30 Aug 2026).
        for hint in sparse_slots {
            if !uncovered_after_par2.contains(hint) {
                uncovered_after_par2.push(hint.clone());
            }
        }
        if uncovered_after_par2.is_empty() {
            info!(target: "repair", "repair complete in {:.2?} ✔", t0.elapsed());
        } else {
            warn!(
                target: "repair",
                "✘ repair succeeded, but {} file(s) outside the PAR2 set \
                 are still incomplete: {}",
                uncovered_after_par2.len(),
                uncovered_after_par2.join(", ")
            );
        }
    }
    all_good = disk_fallback_verdict(
        all_good,
        any_set_failed,
        every_set_ok,
        uncovered_after_par2.is_empty(),
    );
    (all_good, repaired, uncovered_after_par2, repair_shortfall)
}

/// Does the set-less disk PAR2 fallback leave the job green?
///
/// A pure rule rather than four assignments inside
/// [`disk_par2_fallback`], because until 31 Aug 2026 (read-only sweep
/// finding 1) two of its four answers were simply MISSING: the only
/// write of `all_good` in that function was `true`, so a fallback that
/// found holes, or a set that reported it could not repair, left the
/// incoming value standing. That is invisible while the caller only
/// enters on `!all_good` - and it stopped being only that when issue
/// #14's `deferred_recovery` arm started entering with a GREEN
/// download. The caller's entire fail ladder sits inside `if !all_good`,
/// so the job Completed and `tail::finish` deleted the journal that was
/// the only record of what was still missing.
///
/// `entered` is what the caller handed in. The three verdict inputs:
///
///  * `any_set_failed` - a set that RAN and reported Unrepairable, or
///    errored. Deliberately NOT `!every_set_ok`, which is also false
///    when NO set qualified at all (the vacuous-truth guard at the top
///    of the pass): on this path that is the ORDINARY state of a
///    healthy post whose volumes were consumed by in-stream extraction
///    and are not on disk to be repaired, and failing on it would
///    redden every such job. Absence of evidence is not a verdict.
///  * `every_set_ok` - the pass got far enough to run the uncovered
///    hole scan at all. `uncovered_clear` means nothing without it,
///    because the scan does not run otherwise.
///  * `uncovered_clear` - no file this job's own census says is short
///    survived the repair. Its false arm is the exact mirror of the
///    set-path sibling in [`super::repair`], warning sentence included;
///    only this copy failed to clear `all_good` with it.
///
/// A green pass (`every_set_ok && uncovered_clear`) can RAISE a job
/// that came in red: that is the fallback doing its job and is why
/// this returns a verdict rather than only ever subtracting.
fn disk_fallback_verdict(
    entered: bool,
    any_set_failed: bool,
    every_set_ok: bool,
    uncovered_clear: bool,
) -> bool {
    if every_set_ok {
        return uncovered_clear;
    }
    !any_set_failed && entered
}

#[expect(clippy::too_many_arguments)]
pub(super) async fn settle_without_set(
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Arc<Nzb>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    sniff: &Arc<SniffCtl>,
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
) -> Result<SettleVerdict> {
    let mut all_good;
    // The ladder's reason where a rung named one; see the recovery-record
    // rung at the end of this function. `None` on every other path, which
    // is what this arm returned unconditionally before §249 item 1.
    let mut reextract_failed: Option<String> = None;
    let mut repair_shortfall: Option<crate::repair::RepairShortfall> = None;
    // See [`SettleVerdict::repaired`]. Raised at each of this path's two
    // in-place rewriters, rather than set unconditionally: this is the
    // arm a post with NO recovery data at all takes, and on that post
    // nothing here writes a byte, so there is nothing to declare.
    let mut repaired = false;
    // No PAR2 set in the NZB (or activation failed): best-effort
    // post-download verify against whatever par2 files landed.
    // Only a proved-clean pass counts here (TODO 310): `verify_dir` used
    // to answer one bool for "clean" and "there was nothing to verify",
    // and this call site wanted the first meaning while silently taking
    // the second as well. `proved_clean` is the first meaning alone.
    let disk_verified = verify_dir(out_dir)?.proved_clean();
    // Sweep 8, L5: no set means every payload slot is out-of-set, so
    // the spare rule covers all of the optional furniture here. Same
    // contract as the clean and repaired branches.
    let spared = spared_metadata_errors(slots, &std::collections::HashSet::new());
    if spared > 0 {
        warn!(
            target: "verify",
            "{spared} decode/write error(s) on optional file(s) no recovery set \
             covers - dropped, not repaired"
        );
    }
    all_good = incomplete == 0 && derrs.saturating_sub(spared) == 0;
    // Nothing on this path can adjudicate a post whose own articles
    // disagree about a byte range.
    if let Some(why) = conflicting_unvouched(slots, extractor, None) {
        reextract_failed = Some(why);
        all_good = false;
    }
    // Succeeding here with the post's recovery data damaged means
    // shipping output nothing ever checked. The payload is whole -
    // every article arrived and decoded, which is why this is not a
    // failure - but "complete" and "verified" are different claims
    // and only the first one is true. Say which, in as many words:
    // the alternative is a silent success that reads exactly like a
    // verified one. Skipped when `verify_dir` proved the files off
    // disk anyway (an obfuscated post's sniffed volumes land there),
    // and when the post simply carried no recovery data at all -
    // that has always succeeded quietly and is not news.
    if all_good && !disk_verified && recovery_errs + recovery_missing > 0 {
        let mut how = Vec::new();
        if recovery_errs > 0 {
            how.push(format!("{recovery_errs} article(s) arrived corrupt"));
        }
        if recovery_missing > 0 {
            // The noun rides on the first clause only, so both the
            // one-cause and two-cause forms read as English.
            how.push(if how.is_empty() {
                format!("{recovery_missing} article(s) never arrived")
            } else {
                format!("{recovery_missing} never arrived")
            });
        }
        warn!(
            target: "par2",
            "the PAR2 recovery data this post carries did not survive ({})",
            how.join(", ")
        );
        info!(
            target: "par2",
            "the download itself is complete: every payload article arrived and \
             decoded, and the files are in place. There was just no usable recovery \
             set left to check them against, so this download is unverified."
        );
    }
    // Slots still short articles that the disk-side PAR2 fallback
    // below turns out not to cover. Held across the RR fallback
    // too: neither repair can certify a file no recovery set ever
    // named.
    let mut uncovered_after_par2: Vec<String> = Vec::new();
    // Finding F11's second half: "every article arrived" is not "the
    // post is done" when NZB-classified volumes sit unread - they never
    // get a slot at all, are normally fetched on demand by repair
    // (which a clean-looking job never runs), and may carry the post's
    // whole naming story ([`crate::get::latesets::unfetched_recovery_files`]).
    // SNIFF- and resume-DEFERRED slots are deliberately NOT in this
    // gate: deferral of an undamaged obfuscated post's recovery set is
    // a bandwidth choice issue #14 made on purpose, and the kill9
    // resume test pins that a clean resume fetches no volume body. The
    // !all_good arm below handles those exactly as it always has.
    let unfetched_recovery = latesets::unfetched_recovery_files(nzb, slot_file);
    let deferred_recovery = !unfetched_recovery.is_empty();
    if all_good && deferred_recovery {
        info!(
            target: "par2",
            "download is complete but recovery volumes were deferred unread - \
             fetching them for the disk-side naming and verify pass"
        );
    }
    if !all_good || deferred_recovery {
        // Public issue #9. Getting here with a damaged download
        // does NOT mean the post shipped no recovery data - on a
        // fully obfuscated post it usually means we could not SEE
        // it. Classification runs off the NZB's subject lines, and
        // when the index and every recovery volume is a hash with
        // no extension there is nothing in a subject to read, so
        // all of it arrives classified as payload and the whole
        // repair ladder above is unreachable. That is why SABnzbd
        // repaired posts we failed: it identifies par2 from the
        // file contents instead.
        //
        // The bytes are on disk either way, so ask the directory
        // rather than the NZB. `dir_has_par2` sniffs the
        // `PAR2\0PKT` packet magic, and `repair_dir` is already
        // obfuscation-complete underneath it: it magic-sniffs
        // packets and hash-matches obfuscated data files during
        // its adoption scan, restoring them under their true
        // FileDesc names. `extract_local` has always driven it
        // this way; this path simply never asked.
        //
        // Strictly a last resort, and it can only ever ADD an
        // outcome: it runs exclusively where no set was activated,
        // which is exactly the case that had no repair at all.
        //
        // Issue #14: volumes identified in-stream were DEFERRED,
        // and reaching this arm means their set never activated
        // (a damaged bootstrap, or unparseable packets) - so the
        // recovery data the disk repair below needs is not on
        // disk yet. Fetch all of it: without a set there is no
        // block arithmetic to fit exactly, and this is the rare
        // fallback where correctness outranks bandwidth.
        {
            // Only slots that actually HAVE deferred articles: a
            // sniffed volume that nonetheless landed in full (a
            // cancel that caught nothing, or a fully-restored
            // resume volume) is already on disk and refetching it
            // buys nothing.
            let mut deferred_vols: Vec<usize> = sniff
                .deferred_slots()
                .into_iter()
                .filter(|&s| slots[s].deferred.load(Ordering::Relaxed) > 0)
                .map(|s| slot_file[s])
                .collect();
            // F11: no slot means never fetched, and nothing else on
            // this path ever will.
            deferred_vols.extend(unfetched_recovery.iter().copied());
            deferred_vols.sort_unstable();
            deferred_vols.dedup();
            if !deferred_vols.is_empty() {
                info!(
                    target: "repair",
                    "fetching {} deferred recovery volume(s) for disk repair…",
                    deferred_vols.len()
                );
                if let Err(e) =
                    fetch_volumes(servers, nzb, out_dir, buf_pool, &deferred_vols, cancel).await
                {
                    warn!(target: "repair", "deferred volume fetch failed: {e}");
                }
            }
        }
        (all_good, repaired, uncovered_after_par2, repair_shortfall) = disk_par2_fallback(
            out_dir,
            slots,
            extractor,
            sparse_slots,
            note_activity,
            par_cleanup,
            all_good,
            repaired,
            uncovered_after_par2,
            repair_shortfall,
        )
        .await;
    }
    if !all_good {
        // The census's findings have to reach THIS arm too, and
        // by their own route. The merge above sits inside
        // `dir_has_par2` AND `every_set_ok`, so a post carrying
        // no PAR2 at all - a named RAR set with embedded
        // recovery records, plus a sidecar whose `=ybegin size`
        // over-declares - left `uncovered_after_par2` empty, the
        // recovery records healed the RAR, and the guard below
        // had nothing to refuse with. The job went green with a
        // hole in the sidecar and deleted the journal, which is
        // the same class the per-slot census exists to close,
        // one arm further down.
        //
        // And no skip here either for a slot the verifier has since
        // claimed, on the same grounds as the merge in
        // `disk_par2_fallback` above: this arm is reached only where no
        // adopted set names a file, so no tier - the three that only
        // decide inside `finish_slot` included - has a descriptor to bind,
        // and `finish_slot` is never called on this path at all. Held by
        // the `debug_assert` in `settle_verify_repair`'s set-less branch
        // (sweep item 13b, 30 Aug 2026).
        for hint in sparse_slots {
            if !uncovered_after_par2.contains(hint) {
                uncovered_after_par2.push(hint.clone());
            }
        }
        // Missing articles left zero-filled holes and no PAR2
        // filled them - embedded RAR recovery records can.
        repaired = true;
        // And the rung's own reason where it has one. This arm composed
        // its whole failure from a bare bool, so a bomb verdict raised
        // by the post-repair extraction was dropped and the job blamed
        // the archive for a full disk (TODO §249 item 1). Only a NAMED
        // reason is taken: the ordinary failure is worded by the arms
        // below exactly as before.
        all_good = match try_rar_rr_repair_why(out_dir, password) {
            Ok(()) => true,
            Err(why) => {
                if let Some(why) = why {
                    reextract_failed = Some(why);
                }
                false
            }
        };
        // Recovery records heal the RAR set they live in. A file
        // the PAR2 pass already found outside every recovery set
        // is still a hole, whatever the volumes did.
        if all_good && !uncovered_after_par2.is_empty() {
            all_good = false;
            warn!(
                target: "repair",
                "✘ RAR recovery records cannot speak for {} file(s) outside \
                 the PAR2 set: {}",
                uncovered_after_par2.len(),
                uncovered_after_par2.join(", ")
            );
        }
    }
    // Finding F6 (no-RAR matrix case 22): with no recovery set named
    // anywhere, an SFV sidecar may be the post's only name source. The
    // weakest tier runs LAST, over whatever nothing else claimed.
    // SEEDED, and RETURNED, for two independent reasons that landed
    // within the hour of each other and both belong here.
    //
    // W4-03: this path used to hand the tier a FRESH registry, which
    // knows no name, so every target looked free and `fs::rename`
    // replaced whatever was at it - a landed same-job payload included.
    // Seeding it from the live slot paths is what makes "never rename
    // over a file this job already landed" true rather than hoped for.
    //
    // X5-09: the set is RETURNED rather than dropped on the floor, so
    // the tail's one publish-failure fold sees the SFV tier's failures
    // too. Nothing else claims out of it on this path (the deferred
    // renames below are empty here), so carrying it forward costs
    // nothing and closes the "which of the four call sites did anyone
    // remember to account for" question at the seam instead of at each
    // site.
    let mut published_names = sfvname::seeded_names(slots, extractor, out_dir);
    // No sets: this path is reached only where nothing activated, so
    // there is no Main packet to have listed a verify-only member (M4-21).
    sfvname::land_sfv_names(slots, extractor, out_dir, &mut published_names, &[], &[]);
    // M4-70, and this is the path where it does the work: no set
    // activated, so nothing stronger than the articles themselves has
    // named these files. See [`crate::get::yencname`].
    yencname::land_contested_yenc_names(slots, extractor, out_dir, &mut published_names, &[]);
    Ok(SettleVerdict {
        all_good,
        reextract_failed,
        repair_shortfall,
        deferred_renames: Vec::new(),
        published_names,
        sniff_covered: None,
        // No per-file claim from the disk-side fallback. It is reached
        // only where no set activated, and its repair works on volume
        // FILES - so any group that was direct-extracting has already
        // materialized and abandoned its output names, leaving the
        // quarantine nothing to discriminate between. Whole-job stays
        // right here, and it stays honest.
        unhealed_slots: None,
        // The payload-posted-as-a-volume rescue is a SET's last resort
        // and this path has no set, so it never ran and nothing was
        // bought - see `repair/volpayload.rs`.
        rescue_left: Vec::new(),
        repaired,
    })
}

/// M4-28 (30 Aug 2026): a slot the NZB called recovery data BY NAME,
/// whose bytes an active recovery set names as one of its own PAYLOAD
/// files.
///
/// `Nzb::kind` reads the extension and nothing else, so a poster who
/// posts the movie as `set.par2` hands the planner a par2 slot: it is
/// captured for activation, excluded from the payload census, never
/// offered to `settle_slots`, never claimed by the FileDesc that
/// describes it and never published. The file then prices as WHOLLY
/// MISSING and repair is asked to rebuild from parity bytes that
/// arrived intact on the wire - measured on the fixture below at 1974
/// blocks needed against 395 posted, i.e. an unrepairable job over a
/// complete download.
///
/// The SNIFFED half of this has been rescued since issue #14
/// (`fetch_matched_deferred` below, "is payload the recovery set
/// covers"); the NAMED half had nothing, and the two are the same
/// mistake reached by two routes.
///
/// Same evidence as `SniffCtl::matched_deferred`, deliberately: the
/// FileDesc's md5-16k over the first 16 KiB plus an EXACT length match.
/// Nothing here matches by length alone and nothing guesses. That is
/// what keeps the rule conservative in the direction that matters - a
/// `.par2` that is merely damaged, or truncated, or a volume for some
/// other set, matches no FileDesc and stays exactly the par2 slot it
/// was. This can only ever move a file a set has positively identified,
/// which is the "content proof beats a `.par2` filename" the row asks
/// for.
///
/// Sets it `par2_name_demoted` rather than fetching: unlike a deferred
/// volume these bytes are already on disk, because a `Par2Main` slot is
/// queued eagerly so its packets are in hand for activation.
pub(in crate::get) fn reclaim_par2_named_payload(
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    slots: &[Arc<FileSlot>],
    extractor: &Arc<nzbkit::extract::Extractor>,
    out_dir: &Path,
) {
    let sets = verifier.sets();
    if sets.is_empty() {
        return;
    }
    for (sidx, slot) in slots.iter().enumerate() {
        if !slot.is_par2_main || slot.par2_name_demoted.load(Ordering::Relaxed) {
            continue;
        }
        let Some(path) = extractor.slot_path(sidx) else {
            continue;
        };
        let Ok(len) = std::fs::metadata(&path).map(|m| m.len()) else {
            continue;
        };
        // 16384 spelled out, as `promote_pending_head16` does for the
        // sniffed twin: `HASH16K_LEN` is `pub(crate)` to nzbkit.
        let want = len.min(16384) as usize;
        if want == 0 {
            continue;
        }
        let mut head = vec![0u8; want];
        if std::fs::File::open(&path)
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
            .is_err()
        {
            continue;
        }
        let Some(h) = nzbkit::par2::md5_16k_of_head(&head, len) else {
            continue;
        };
        let Some(named) = sets.iter().find_map(|set| {
            set.files
                .iter()
                .find(|f| f.length == len && f.md5_16k == h)
                .map(|f| f.name.clone())
        }) else {
            continue;
        };
        info!(
            target: "par2",
            "{} is named like a recovery file but its bytes are payload the \
             recovery set covers ({named}) - publishing it as payload",
            slot.hint
        );
        slot.par2_name_demoted.store(true, Ordering::Release);
        // Demotion alone only lets the slot into the census; the
        // verifier still has no descriptor bound to it, so `finish_slot`
        // would report nothing and the file would price as wholly
        // missing exactly as before. The head this pass just read is
        // what claims it.
        feed_slot_from_disk(verifier, extractor, out_dir, slot, sidx, len);
    }
}

// Issue #14 drain fallback: a deferred slot the ACTIVE set covers is
// payload the sniff got wrong (a posted par2 file the set includes).
// The live reconcile at activation requeues such slots while the pool
// still runs; on a short post the pool is gone by activation time, so
// whatever is still deferred-and-matched is fetched here on the side
// machinery and fed to the verifier off disk - delivered and
// verified, never recreated from recovery blocks.
#[expect(clippy::too_many_arguments)]
pub(in crate::get) async fn fetch_matched_deferred(
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    sniff: &Arc<SniffCtl>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Arc<Nzb>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    cancel: Option<&crate::repair::SideCancel>,
) {
    // Every adopted set (TODO 311): a deferred slot is payload if ANY
    // of them names it. `matched_deferred` marks what it matched, so a
    // slot cannot be reconciled twice across the loop.
    sniff.promote_pending_head16(extractor);
    for set in verifier.sets() {
        for (sidx, file_size) in sniff.matched_deferred(&set) {
            info!(
                target: "par2",
                "{} is payload the recovery set covers - fetching it now",
                slots[sidx].hint
            );
            let fi = slot_file[sidx];
            if let Err(e) = fetch_volumes(servers, nzb, out_dir, buf_pool, &[fi], cancel).await {
                warn!(target: "par2", "fetching it failed ({e}) - leaving it to the repair pass");
                continue;
            }
            // Deferral ledger: these bytes were downloaded after all.
            let undeferred_bytes = sniff
                .state
                .lock_ok()
                .cancelled_ids
                .get(&sidx)
                .map(|(_, b)| *b)
                .unwrap_or(0);
            sniff.mark_reconciled(sidx);
            // Deliberately NOT undoing the deferral's fetch_done credit
            // the way the pool-side reconcile does: these bytes came in
            // through `fetch_volumes` on the side machinery, so no
            // terminal outcome will ever credit them again and dropping
            // the credit would leave the bar short (Codex sweep 2,
            // 3 Aug ML2).
            slots[sidx].par2_sniffed.store(false, Ordering::Release);
            // The side fetch re-attempted every article of the file, so
            // the sniff-era counters are stale; the verification feed
            // below is the authority on what is actually good.
            let undeferred = slots[sidx].deferred.swap(0, Ordering::Relaxed);
            slots[sidx].missing.store(0, Ordering::Relaxed);
            sniff
                .deferred_articles
                .fetch_sub(undeferred, Ordering::Relaxed);
            sniff
                .deferred_bytes
                .fetch_sub(undeferred_bytes, Ordering::Relaxed);
            feed_slot_from_disk(verifier, extractor, out_dir, &slots[sidx], sidx, file_size);
        }
    }
}

/// Feed a slot's finished bytes back through the live verifier off disk.
///
/// The first chunk carries the 16k head, so the verifier claims the slot
/// by md5-16k, and every block then gets a full-MD5 disk-provenance
/// check before settle reads the result. Without this the slot has no
/// claimed descriptor at all, so `finish_slot` reports nothing and the
/// file it holds prices as wholly missing however sound its bytes are.
///
/// Shared by the two "this was not recovery data after all" rescues -
/// the deferred SNIFF (issue #14) and the NAME-classified slot (M4-28,
/// [`reclaim_par2_named_payload`]) - because both end in the same place:
/// a file an active set covers whose bytes never went past the verifier.
fn feed_slot_from_disk(
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    out_dir: &Path,
    slot: &FileSlot,
    sidx: usize,
    file_size: u64,
) {
    let path = extractor.slot_path(sidx).unwrap_or_else(|| {
        nzbkit::disk::join_out_name(out_dir, &nzbkit::disk::sanitize_out_name(&slot.hint))
    });
    match std::fs::File::open(&path) {
        Ok(mut f) => {
            use std::io::Read;
            let mut off = 0u64;
            let mut buf = vec![0u8; 4 << 20];
            loop {
                match f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        verifier.on_data_from_disk(sidx, "", file_size, off, &buf[..n]);
                        off += n as u64;
                    }
                    Err(e) => {
                        warn!(target: "par2", "reading {} back failed: {e}", path.display());
                        break;
                    }
                }
            }
        }
        Err(e) => warn!(target: "par2", "{} not readable after fetch: {e}", path.display()),
    }
}

#[cfg(test)]
mod verdict_tests {
    use super::disk_fallback_verdict;

    /// The ordinary green pass: every set verified, nothing left short.
    /// It RAISES a job that came in red, which is the whole point of the
    /// fallback.
    #[test]
    fn a_clean_pass_greens_the_job_it_was_called_for() {
        assert!(disk_fallback_verdict(false, false, true, true));
        assert!(disk_fallback_verdict(true, false, true, true));
    }

    /// Read-only sweep finding 1, first half. A repair that succeeded
    /// and left a file outside the set still short must not report the
    /// job green - and this is the arm that only ever WARNED, so it is
    /// pinned from the side that was broken: entering GREEN, which is
    /// what issue #14's `deferred_recovery` arm does.
    #[test]
    fn a_leftover_hole_fails_a_job_that_entered_green() {
        assert!(!disk_fallback_verdict(true, false, true, false));
        assert!(!disk_fallback_verdict(false, false, true, false));
    }

    /// Finding 1, second half. A set that RAN and said it cannot heal
    /// its own files fails the job however it came in. Before issue #14
    /// the same post activated its set and went down the SET path, where
    /// an Unrepairable set fails; a bandwidth optimisation must not turn
    /// a Failed job into a Completed one.
    #[test]
    fn a_set_that_reported_it_cannot_repair_fails_a_green_job() {
        assert!(!disk_fallback_verdict(true, true, false, true));
        assert!(!disk_fallback_verdict(true, true, false, false));
    }

    /// The hold-out, and it is the reason `any_set_failed` exists at all
    /// rather than the pass reading `!every_set_ok`. NO set qualified -
    /// nothing on disk for one to repair - which on the set-less path is
    /// the ordinary state of a healthy post whose volumes were consumed
    /// by in-stream extraction. The verdict is whatever the caller
    /// already knew, never a new failure.
    #[test]
    fn no_set_qualifying_is_not_a_verdict_either_way() {
        assert!(disk_fallback_verdict(true, false, false, true));
        assert!(!disk_fallback_verdict(false, false, false, true));
    }
}
