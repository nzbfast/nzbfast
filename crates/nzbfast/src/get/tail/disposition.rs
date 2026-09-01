//! The two ways `finish_job` changes what is in the output directory:
//! the failing job's quarantine (rename the unverified payload and its
//! downloaded volumes aside) and the spared-metadata delete (issue #23).
//! Lifted out of tail.rs whole and in file order (TODO 106, 31 Aug
//! 2026), bodies verbatim.
//!
//! One subject and two call edges in, both from `super::finish_job`:
//! [`quarantine_failed_payload`] on every failing arm that is not
//! exempt, and [`drop_spared_metadata`] on the good finish that is
//! completing without metadata no server had. The two helpers below
//! the door - `partition_failed_payload` and `held_downloaded_files` -
//! are called from nowhere else and would be private here, except that
//! the parent's test module asserts on them directly; they carry
//! `pub(super)` for that and nothing more.
//!
//! Everything else in the tail that touches the disk stayed with the
//! parent, and that is the seam rather than an omission:
//! `sweep_sniffed_leftovers` is a GOOD job's cleanup and reads as a
//! pair with the adoption-source sweep above it in `report_extraction`.

use super::*;

/// Rename a failed job's direct-extracted payload AND its downloaded
/// files aside, and SAY so.
///
/// The mechanism and the reasoning live in
/// `nzbkit::journal::quarantine_partials`; this is the reporting half.
/// A failed job's one line about it matters more than the success
/// path's: the user is about to look in the output directory for the
/// file the verdict just told them they do not have, and without this
/// they find a plausible-looking one wearing a suffix nobody explained.
///
/// A rename that FAILED is a warning rather than a second failure - the
/// job is already failing and has its own cause to report, and burying
/// that cause under a filesystem complaint helps nobody. It still has
/// to be said: the file it names is the false artifact the rename
/// exists to prevent, and it is still sitting there.
///
/// L1 residue (31 Aug 2026) - `rescue_left` is the THIRD population,
/// and the reason it has to be handed in rather than rediscovered.
/// `repair/volpayload.rs` buys volume-named candidates that may BE a
/// missing payload file, proves them by content, and leaves the ones it
/// cannot prove where the fetch put them - under the yEnc name the
/// POSTER chose. Such a file is in neither arm below: it has no slot
/// (`build_fetch_plan` skips a non-bootstrap `Par2Volume` before a slot
/// exists, which is the whole reason that rescue had to be written) and
/// it was never extracted. Measured at `b30f29813`
/// (`research/MEASUREMENTS-BATCH-2026-08-31.md` section 2): on a failed
/// job the one file that arrived through that side door was the ONLY one
/// left wearing an importable name, which inverts what this function
/// exists to say. Nothing here can find it by SHAPE either - the name is
/// the poster's and a `.par2`-looking one is luck, so the rescue reports
/// the paths and this renames them.
///
/// TODO 159 item 1 - `unhealed_slots` narrows this to the files that
/// actually lost bytes. A post whose PAR2 set covers two of three
/// archives, damaged on one covered volume and on the uncovered one,
/// used to have all three payloads withheld: the two that verified and
/// repaired perfectly went out of reach to keep the third from
/// shipping. Withholding what we HAVE is a real cost - it is the
/// difference between a user getting two of three files (SABnzbd's
/// answer on that post) and none (NZBGet's), and the round-4 evidence
/// says two is the better answer.
pub(super) fn quarantine_failed_payload(
    out_dir: &Path,
    extracted: &[String],
    unhealed_slots: Option<&[usize]>,
    slots: &[Arc<FileSlot>],
    rescue_left: &[PathBuf],
    extractor: &Arc<nzbkit::extract::Extractor>,
) {
    let (hold, spare) = partition_failed_payload(extracted, unhealed_slots, extractor);
    if !spare.is_empty() {
        info!(
            target: "repair",
            "{} extracted file(s) came out of archives the repair proved whole, and \
             are left in place: {}",
            spare.len(),
            spare.join(", ")
        );
    }
    let (mut done, mut failed) = nzbkit::journal::quarantine_partials(out_dir, &hold);
    // TODO 159 item 1c: the downloaded files go the same way. A failed
    // job's volume set used to keep wearing real names in the output
    // directory - the one-pass answer to SABnzbd's incomplete/ and
    // NZBGet's inter/ is a rename, not a move, and the retry's
    // unquarantine puts every name back before the journal opens.
    let (vol_done, vol_failed) =
        nzbkit::journal::quarantine_paths(&held_downloaded_files(slots, unhealed_slots, extractor));
    done.extend(vol_done);
    failed.extend(vol_failed);
    // L1 residue: the payload rescue's unproven candidates, through the
    // SAME door and not a parallel one - so the bytes are kept, the
    // suffix is the one `unquarantine_partials` restores at the head of
    // the next attempt, and W4-03's occupancy question is answered
    // wherever `quarantine_paths` already answers it. A path a later set
    // proved and published is simply gone by now, which that function
    // skips.
    let (res_done, res_failed) = nzbkit::journal::quarantine_paths(rescue_left);
    done.extend(res_done);
    failed.extend(res_failed);
    if !done.is_empty() {
        info!(
            target: "verify",
            "{} unverified file(s) renamed to *{} so nothing imports them: {} \
             (the bytes are kept - a retry resumes from them)",
            done.len(),
            nzbkit::journal::PARTIAL_SUFFIX,
            done.join(", ")
        );
        info!(target: "quarantine", "renamed {} unverified payload file(s) aside", done.len());
    }
    for name in &failed {
        warn!(
            target: "verify",
            "could not rename the unverified {name} aside - it is INCOMPLETE despite \
             its name and size, do not import it"
        );
        warn!(target: "quarantine", "{name}: could not be renamed aside");
    }
}

/// Split the direct-extracted payload into (withhold, leave in place).
///
/// Two independent facts have to line up before a file is spared, and
/// EITHER of them missing puts it back in the withhold pile:
///
/// 1. Settle said which slots are still holed and that everything else
///    is proved (`unhealed_slots`). No claim - the pass could not make
///    one - and every file is withheld, exactly as before.
/// 2. The extractor can say which source volumes fed the file
///    (`payload_sources`). A file it cannot speak for is withheld: the
///    map is a positive claim about the names it lists, and a name it
///    omits is a payload written through a path this reasoning has not
///    modelled (a nested level's own output, a chase's members, an
///    archive that fell back mid-job). Absent means unknown, and
///    unknown means hold.
///
/// The mapping is at GROUP granularity, which is what makes it safe for
/// the shapes the scope caution named: a solid or multi-volume set is
/// one group, so damage to any of its volumes withholds every file the
/// set produced, and a payload spanning two volumes cannot be spared by
/// the healthy one alone.
pub(super) fn partition_failed_payload(
    extracted: &[String],
    unhealed_slots: Option<&[usize]>,
    extractor: &Arc<nzbkit::extract::Extractor>,
) -> (Vec<String>, Vec<String>) {
    let Some(unhealed) = unhealed_slots else {
        return (extracted.to_vec(), Vec::new());
    };
    let Some(sources) = extractor.payload_sources() else {
        return (extracted.to_vec(), Vec::new());
    };
    let mut hold = Vec::new();
    let mut spare = Vec::new();
    for name in extracted {
        let whole = sources
            .get(name)
            .is_some_and(|srcs| !srcs.iter().any(|s| unhealed.contains(s)));
        if whole { &mut spare } else { &mut hold }.push(name.clone());
    }
    (hold, spare)
}

/// The downloaded files a failing finish takes out of circulation next
/// to the extracted payload: every slot file still on disk, EXCEPT a
/// plain file this job can prove whole.
///
/// advG (torture rounds 1-3, TODO 159 item 1c): a failed job's partial
/// download used to keep wearing real volume names in the completed
/// directory, so anything consuming that directory counted four `.rar`
/// volumes as delivered files - where SABnzbd and NZBGet park the same
/// bytes in `incomplete/` and `inter/`. One-pass extracts in place as
/// articles arrive, so "somewhere else to live" has to be a rename
/// rather than a move: the volumes join the payload under
/// `*.nzbfast-partial`, and the next attempt's unquarantine puts every
/// name back before the journal opens (`get/plan.rs`), so a retry
/// still resumes from them.
///
/// The discrimination mirrors [`partition_failed_payload`]:
/// - A volume (a materialized fallback) is ALWAYS held, whole or not.
///   Its deliverable was the extraction, which this failing job did
///   not produce; a complete `.part02.rar` of a failed set is
///   furniture, not a result.
/// - A par2 file is always held: recovery data for a job that just
///   failed to recover is spent evidence, not a deliverable.
/// - A plain file IS its own deliverable, so one that is provably
///   whole stays delivered (SABnzbd's answer on partly recoverable
///   posts, which the round-4 evidence prefers): proved by settle's
///   claim when the repair earned one, otherwise by its own census -
///   every segment arrived, decoded and wrote clean, and the writer's
///   declared range is fully covered. The coverage gate is what keeps
///   a lying `=ybegin size` from sparing a sparse tail.
///
/// The failure arms that reach this hold only damaged or unverifiable
/// sets. A failure a password or a manual unpack actually answers
/// keeps its volumes visible: it routes through the exempt
/// `reextract_failed` arm, or completes with `locked_no_password` -
/// so the daemon's locked-failure folder probe never loses an archive
/// it could unlock.
pub(super) fn held_downloaded_files(
    slots: &[Arc<FileSlot>],
    unhealed_slots: Option<&[usize]>,
    extractor: &Arc<nzbkit::extract::Extractor>,
) -> Vec<PathBuf> {
    (0..slots.len())
        .filter_map(|i| {
            let path = extractor.slot_path(i)?;
            let s = &slots[i];
            // Stably plain is the only shape whose on-disk file is its
            // own deliverable; slot_uncovered answers None for every
            // other mode (materialized volumes, chases).
            let uncovered = extractor.slot_uncovered(i);
            let whole = match unhealed_slots {
                Some(unhealed) => !unhealed.contains(&i),
                None => {
                    uncovered == Some(0)
                        && s.missing.load(Ordering::Relaxed) == 0
                        && s.remaining.load(Ordering::Relaxed) == 0
                        && s.errors.load(Ordering::Relaxed) == 0
                        && s.abandoned.load(Ordering::Relaxed) == 0
                }
            };
            if uncovered.is_some() && whole && !s.is_par2() {
                None
            } else {
                Some(path)
            }
        })
        .collect()
}

/// Issue #23: finish the job WITHOUT the metadata files no server had.
///
/// Removed rather than left behind, and that is what makes sparing the
/// job safe. A slot short an article still has a file on disk with a
/// zero-filled hole where the bytes should be, and
/// `a_disk_repair_does_not_certify_files_outside_its_recovery_set` is
/// right that handing an *arr one of those is worse than failing - a
/// holed .nfo looks exactly like a real .nfo. Deleting it is the answer
/// neither the old behaviour nor a bare spare reached: the job
/// completes, and nothing false is left in the directory.
///
/// Safe to delete precisely because of the rule that selected these:
/// the recovery set does not cover them, so nothing can rebuild them,
/// and they are furniture rather than payload.
/// Returns the names it could NOT remove - the caller must refuse to
/// complete while any remain (a holed file that survived is exactly the
/// false artifact the delete exists to prevent).
pub(super) fn drop_spared_metadata(out_dir: &Path, spared: &[String]) -> Vec<String> {
    if spared.is_empty() {
        return Vec::new();
    }
    let mut gone = Vec::new();
    let mut kept = Vec::new();
    for name in spared {
        let p = nzbkit::disk::join_out_name(out_dir, &nzbkit::disk::sanitize_out_name(name));
        match std::fs::remove_file(&p) {
            // Never written at all is the same outcome we want.
            Ok(()) => gone.push(name.clone()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => gone.push(name.clone()),
            Err(e) => {
                warn!(target: "get", "could not remove the partial {}: {e}", p.display());
                kept.push(name.clone());
            }
        }
    }
    if kept.is_empty() {
        info!(
            target: "get",
            "complete, without {} metadata file(s) no server had: {} \
             (the partial copy was removed - nothing can rebuild it)",
            gone.len(),
            gone.join(", ")
        );
    }
    kept
}
