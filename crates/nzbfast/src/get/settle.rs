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

    match verifier.set() {
        Some(set) => {
            settle_with_set(
                set,
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
            )
            .await
        }
        None => {
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
    // Seeded from the live slot paths BEFORE the first publish: a slot
    // that simply kept its posted name owns that name, so another slot's
    // verified name is pushed off it instead of renaming over it. Both
    // payloads then survive under two names, which is the whole point -
    // one of them wearing a `{slot:03}-` prefix beats one of them gone.
    let mut published_names = crate::unpack::PublishedNames::for_dir(out_dir);
    for sidx in 0..slots.len() {
        if let Some(p) = extractor.slot_path(sidx)
            && let Some(n) = p.file_name().and_then(|n| n.to_str())
        {
            published_names.seed(sidx, n);
        }
    }
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
            for _ in 0..std::thread::available_parallelism()
                .map_or(4, |n| n.get())
                .min(12)
            {
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
                        let r = if extractor.is_mapped(sidx) || extractor.is_chased(sidx) {
                            let reader =
                                |off: u64, buf: &mut [u8]| extractor.read_at(sidx, off, buf);
                            verifier.finish_slot_from(sidx, nzbkit::live::ReadAt::Reader(&reader))
                        } else {
                            // Fully-resumed slots never created a writer
                            // this run - the run-1 file (yEnc name ==
                            // hint for unobfuscated posts) backs them.
                            let path = extractor.slot_path(sidx).or_else(|| {
                                let p = out_dir
                                    .join(nzbkit::disk::sanitize_filename(&slots[sidx].hint));
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
            // Deobfuscation: the PAR2 FileDesc name is the real one.
            if let Some(pname) = &r.par2_name {
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
                if !mapped {
                    if extractor.is_chased(sidx) {
                        deferred_renames.push((sidx, pname.clone()));
                    } else if let Some(path) = extractor.slot_path(sidx)
                        && let Some(new) =
                            publish_verified_name(&path, pname, out_dir, sidx, &mut published_names)
                    {
                        extractor.note_slot_renamed(sidx, new);
                    }
                }
            }
            reports.push((sidx, r));
        }
    }
    (reports, damage_in_mapped, deferred_renames, published_names)
}

#[expect(clippy::too_many_arguments)]
async fn settle_with_set(
    set: Arc<nzbkit::par2::Par2Set>,
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
    incomplete: usize,
    derrs: u64,
    sparse_slots: &[String],
    note_activity: &(dyn Fn(&'static str) + Sync),
    // §129: the owner's recovery-fetch cancel handle, threaded the
    // same way `note_activity` is and for a sibling reason - the
    // repair paths below reach the network, and the tail they run in
    // now outlives the download slot, so a deleted job must be able
    // to stop them. `crate::repair::SideCancel`; None on the CLI.
    cancel: Option<&crate::repair::SideCancel>,
) -> Result<SettleVerdict> {
    // --- settle verification (in-stream results; read-back only for gaps) ---
    let all_good;
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
    let vt0 = Instant::now();
    let (reports, damage_in_mapped, deferred_renames, published_names) =
        settle_slots(slots, verifier, extractor, out_dir);
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
    let missing_files: Vec<String> = {
        let skipped: std::collections::HashSet<String> = slots
            .iter()
            .filter(|s| s.sample_skipped)
            .map(|s| nzbkit::disk::sanitize_filename(&s.hint).to_lowercase())
            .collect();
        verifier
            .unclaimed_files()
            .into_iter()
            .filter(|n| {
                let keep = !skipped.contains(&nzbkit::disk::sanitize_filename(n).to_lowercase());
                if !keep {
                    info!(target: "verify", "{n} - sample skipped on request, so not repaired either");
                }
                keep
            })
            .collect()
    };
    // `damage` decides WHETHER repair runs; `needed` (the deficit
    // after slices already on hand) decides how much to FETCH.
    // Conflating them skipped repair entirely whenever on-hand
    // slices covered the damage count - silent corruption with
    // exit 0 (latent for bootstrap sets, wide open once M2c.5
    // prefetched volumes mid-download).
    let mut damage = bad;
    for name in &missing_files {
        if let Some(f) = set.files.iter().find(|f| f.name == *name) {
            damage += f.length.div_ceil(set.block_size.max(1)) as usize;
            warn!(target: "verify", "✘ {} - file missing entirely", f.name);
        }
    }
    // Slices already on hand: seen while building the set (the
    // bootstrap volume) + M2c.5 prefetched volumes on disk -
    // counted from the files themselves (exact, so a partial
    // prefetch discounts only what actually landed), and their
    // NZB entries leave the fetch-candidate list.
    // The sniffed bootstrap's capture can have holes: an article
    // decoded BEFORE the head's sniff was written to disk but
    // never mirrored, so recovery_blocks_seen can undercount -
    // while the bootstrap's file index goes into `already` and is
    // never refetched. Count its slices off the DISK file, which
    // write_verified kept whole. On a sniffed post the bootstrap
    // capture is the only one carrying recovery slices (demoted
    // captures are dropped), so this REPLACES recovery_blocks_seen
    // rather than adding to it.
    let mut on_hand = match sniff_bootstrap.and_then(|s| extractor.slot_path(s)) {
        Some(p) => std::fs::read(&p)
            .map(|bytes| {
                nzbkit::par2repair::recovery_slice_locators(&bytes, &set.recovery_set_id)
                    .into_iter()
                    .filter(|(_, _, len)| *len == set.block_size as usize)
                    .count()
            })
            .unwrap_or(set.recovery_blocks_seen),
        None => set.recovery_blocks_seen,
    };
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
        let counted = std::fs::read(pth)
            .map(|bytes| {
                nzbkit::par2repair::recovery_slice_locators(&bytes, &set.recovery_set_id)
                    .into_iter()
                    .filter(|(_, _, len)| *len == set.block_size as usize)
                    .count()
            })
            .unwrap_or(0);
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
        on_hand += counted;
    }
    let sniffed_vols: Vec<usize> = sniff.deferred_files();
    for (fi, paths) in prefetched.lock_ok().iter() {
        already.push(*fi);
        for pth in paths {
            if let Ok(bytes) = std::fs::read(pth) {
                on_hand +=
                    nzbkit::par2repair::recovery_slice_locators(&bytes, &set.recovery_set_id)
                        .into_iter()
                        .filter(|(_, _, len)| *len == set.block_size as usize)
                        .count();
            }
        }
    }
    let needed = damage.saturating_sub(on_hand);
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
    let (in_set_pairs, uncovered_pairs): (Vec<(usize, &str)>, Vec<(usize, &str)>) = {
        let covered: std::collections::HashSet<usize> = reports.iter().map(|(s, _)| *s).collect();
        let set_names: std::collections::HashSet<String> = set
            .files
            .iter()
            .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
            .collect();
        slots
            .iter()
            .enumerate()
            .filter(|(i, s)| {
                // is_par2(): a sniffed volume (bootstrap or
                // deferred) is recovery data, not a payload file
                // the set failed to cover.
                !s.is_par2()
                    && !covered.contains(i)
                    && (s.missing.load(Ordering::Relaxed) > 0
                        || s.remaining.load(Ordering::Relaxed) > 0
                        || s.errors.load(Ordering::Relaxed) > 0
                        || s.abandoned.load(Ordering::Relaxed) > 0)
            })
            .map(|(i, s)| (i, s.hint.as_str()))
            // Issue #23's spare rule, the same predicate the census
            // applies: furniture the recovery set does not cover cannot
            // be healed by any repair, so it does not fail the job - it
            // is dropped at finish instead. Everything reaching the
            // partition is short; the uncovered side is by definition
            // the "set does not cover it" half, so the extension test is
            // the whole question here. Without this, a job that took ANY
            // damage failed on a file the census had already spared,
            // while the identical post with damage == 0 completed.
            .filter(|(_, hint)| !crate::get::census::is_spared_metadata(hint))
            .partition(|(_, hint)| {
                set_names.contains(&nzbkit::disk::sanitize_filename(hint).to_lowercase())
            })
    };
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
    if damage > 0 {
        let o = run_set_repair(
            &set,
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
            needed,
            &already,
            &sniffed_vols,
            &reports,
            &missing_files,
            in_set_bad,
            uncovered_pairs,
        )
        .await?;
        all_good = o.all_good;
        reextract_failed = o.reextract_failed;
        repair_shortfall = o.repair_shortfall;
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
        let set_names: std::collections::HashSet<String> = set
            .files
            .iter()
            .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
            .collect();
        let spared = spared_metadata_errors(slots, &set_names);
        if spared > 0 {
            warn!(
                target: "verify",
                "{spared} decode/write error(s) on optional file(s) the recovery \
                 set does not cover - dropped, not repaired"
            );
        }
        all_good = incomplete == 0 && derrs.saturating_sub(spared) == 0;
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
    // The end-of-job sniffed-leftover sweep (below, after
    // extractor.finish()) needs the set's FileDesc names to spare
    // payload that is ITSELF par2 - record them while the set is
    // in scope.
    let sniff_covered = Some(
        set.files
            .iter()
            .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
            .collect(),
    );
    Ok(SettleVerdict {
        all_good,
        reextract_failed,
        repair_shortfall,
        deferred_renames,
        published_names,
        sniff_covered,
        unhealed_slots,
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
/// `is_spared_metadata` out before it can fail anything), and the clean
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
fn spared_metadata_errors(
    slots: &[Arc<FileSlot>],
    set_names: &std::collections::HashSet<String>,
) -> u64 {
    slots
        .iter()
        .filter(|s| {
            !s.is_par2()
                && !set_names.contains(&nzbkit::disk::sanitize_filename(&s.hint).to_lowercase())
                && crate::get::census::is_spared_metadata(&s.hint)
        })
        .map(|s| s.errors.load(Ordering::Relaxed) as u64)
        .sum()
}

#[expect(clippy::too_many_arguments)]
async fn run_set_repair(
    set: &nzbkit::par2::Par2Set,
    extractor: &Arc<nzbkit::extract::Extractor>,
    journal: &Arc<nzbkit::journal::Journal>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Arc<Nzb>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    sniff_bootstrap: Option<usize>,
    fast_verify: bool,
    password: Option<&str>,
    sparse_slots: &[String],
    note_activity: &(dyn Fn(&'static str) + Sync),
    // §129: the owner's recovery-fetch cancel handle, threaded the
    // same way `note_activity` is and for a sibling reason - the
    // repair paths below reach the network, and the tail they run in
    // now outlives the download slot, so a deleted job must be able
    // to stop them. `crate::repair::SideCancel`; None on the CLI.
    cancel: Option<&crate::repair::SideCancel>,
    mut damage_in_mapped: bool,
    needed: usize,
    already: &[usize],
    sniffed_vols: &[usize],
    reports: &[(usize, nzbkit::live::SlotReport)],
    missing_files: &[String],
    in_set_bad: Vec<&str>,
    mut uncovered_pairs: Vec<(usize, &str)>,
) -> Result<RepairOutcome> {
    let mut all_good;
    let mut reextract_failed: Option<String> = None;
    let mut repair_shortfall: Option<crate::repair::RepairShortfall> = None;
    note_activity("repairing");
    // §129: one repair at a time across concurrent tails. The token
    // above already says "repairing", so a queued wait reads truthfully;
    // held for the whole pass (mapped repair, materialize, disk repair)
    // EXCEPT across the recovery fetches, which hand it back for the
    // duration - it gates cores, and an unanswered side-fetch holding it
    // would park every other job's tail (§137.2; see `HeavyCpu`).
    let mut cpu = crate::lanegate::HeavyCpu::acquire().await;
    // M2c.1: first try repairing straight INTO the extracted
    // output through the block→payload mapping - no volume
    // files ever touch disk. Every declined case (gate miss,
    // I/O error, MD5 verify failure) returns false and the
    // materialize path below runs unchanged.
    // Par2 names the mapped repair recreated WHOLE from parity
    // (empty unless it succeeded) - each proved by its
    // whole-file MD5, so they answer the "still short" verdict
    // below.
    let mut recreated_names: Vec<String> = Vec::new();
    // Recovery volumes the mapped attempt pulls off the wire before it
    // can know whether its route survives. A decline hands them to
    // `fetch_and_repair` rather than dropping them on the floor: they
    // are the same blocks for the same damage, already on disk, and
    // re-planning would only buy them again (23 Aug 2026).
    let mut mapped_fetched: Vec<usize> = Vec::new();
    // §282 item 4: what the mapped attempt's own recovery fetch asked
    // this provider for and what came back. A decline hands it to
    // `fetch_and_repair` so the same refusal is not bought twice.
    let mut mapped_yield: Option<crate::repair::VolumeYield> = None;
    let mapped_ok = if std::env::var_os("NZBFAST_NO_NATIVE_REPAIR").is_none() {
        try_mapped_repair(
            servers,
            nzb,
            out_dir,
            set,
            needed,
            already,
            sniffed_vols,
            buf_pool.clone(),
            extractor,
            reports,
            missing_files,
            &mut recreated_names,
            &mut mapped_fetched,
            &mut mapped_yield,
            // Fast verify is the default and CRC32 is what the
            // in-stream path trusts too; an operator who turned
            // it off is asking for MD5 everywhere, including
            // here.
            !fast_verify,
            cancel,
            &mut cpu,
        )
        .await?
    } else {
        false
    };
    // Mapped repair writes corrected plaintext through the
    // crypto shim, which refreshes chain checkpoints and
    // final-block padding. Persist those facts before any
    // crash can leave a truthful D placement paired with
    // stale pre-repair K/T records.
    journal.record_crypto_events(&extractor.drain_crypto_events());
    // Did a repair actually PROVE the files the set names? Only
    // then does "the set names this file" prove the file: native
    // repair_dir (and par2cmdline behind it) require every file
    // in the set to match its FileDesc whole-file MD5 or the
    // repair fails. The RAR recovery-record fallback never looks
    // at the par2 set at all, so it can never speak for one.
    //
    // The mapped repair proves exactly what it REBUILT: parity
    // as a source recreates a wholly-missing file and
    // `repair_mapped` whole-file-MD5s it through the same view
    // before returning - the same standard, so those names count
    // (`recreated_names`). A file it merely left alone still
    // does not.
    let mut set_files_proven: Vec<String> = Vec::new();
    if mapped_ok {
        set_files_proven = std::mem::take(&mut recreated_names);
        // §94 B / row 27: the repair's self-prove (below) vouches for
        // every block of the set, including the ones it just rebuilt,
        // but the verifier's block states were taken before it and
        // never move again. A gated chase parked at a rebuilt block -
        // a routed child decode, gated through the parent's cells - is
        // waiting for exactly this, and without it would sit until
        // `finish()` released it and then run its whole decode in the
        // tail. Release now, so the decode runs behind the repair.
        extractor.release_verify_gate();
        // A mapped repair proves ITSELF: `repair_mapped`
        // re-reads every file of the set back through the same
        // block→payload view it wrote through - whole-file MD5
        // for the files it rebuilt into, per-block CRC32 for
        // the rest - and a mismatch declines the repair instead
        // of returning true. A covered file whose pwrite failed
        // therefore cannot reach here: the bytes that never
        // landed read back wrong. Covered slots are exactly the
        // set's files (the verifier claims each one for at most
        // one slot, and only a claimed slot gets a report), so
        // that re-read leaves none of them untested.
        //
        // A per-slot error counter used to gate this instead,
        // from when the self-prove covered only the rebuilt
        // files. It outlived that fix, and it was never the
        // right test anyway: `slot.errors` counts DECODE errors
        // alongside write errors, and a yEnc CRC failure is
        // precisely the hole the repair just filled. A post
        // with one corrupt article per volume repaired
        // perfectly and then finished Failed, with byte-correct
        // output sitting in the directory.
        //
        // Slots the set does NOT cover are still tested below -
        // there a decode error IS lost bytes, because no
        // recovery block speaks for them.
        all_good = true;
    } else {
        // PAR2 repair operates on volume FILES - materialize every
        // mapped slot of the set (complete ones too: par2 verifies
        // the whole set from disk) under its PAR2 name. A CHASED
        // slot (a posted .7z streaming out of RAM) has no file
        // either and must come down too, or par2 sees it missing
        // and tries to recreate a whole archive we are holding.
        let any_mapped = reports.iter().any(|(s, _)| extractor.is_mapped(*s));
        let any_chased = reports.iter().any(|(s, _)| extractor.is_chased(*s));
        // A RAR chase (depth-0 compressed set) must be claimed for
        // the post-repair re-extract too: its "materialized for
        // repair" demote reason is excluded from the unrar ladder
        // on the promise that this path re-extracts what it
        // materialized, and no other pass owns the set - without
        // the claim the job shipped repaired-but-packed volumes as
        // its output with exit 0. A materialized .7z stays out:
        // the 7z post-pass runs regardless and re-extracting here
        // would only double the work.
        let any_rar_chased = reports.iter().any(|(s, _)| extractor.is_rar_chased(*s));
        if any_mapped || any_chased {
            note_activity("repairing");
            info!(target: "repair", "materializing volumes for repair…");
            damage_in_mapped |= any_mapped || any_rar_chased;
            for (sidx, r) in reports {
                if extractor.is_mapped(*sidx) || extractor.is_chased(*sidx) {
                    if let Some(pname) = &r.par2_name {
                        extractor.rename(*sidx, pname);
                    }
                    if let Err(e) = extractor.materialize(*sidx) {
                        warn!(target: "repair", "materialize slot {sidx}: {e}");
                    }
                }
            }
            // A chase that had been DROPPING its consumed prefix just
            // materialized with holes there; the repair below could
            // never cover them from parity, so they come back off the
            // wire first (see get/dropped.rs).
            super::dropped::refetch_dropped_volumes(
                extractor, slot_file, servers, nzb, out_dir, buf_pool, cancel,
            )
            .await?;
        }
        let main_par2 = {
            let mut p = None;
            for (sidx, slot) in slots.iter().enumerate() {
                if slot.is_par2_main
                    && let Some(path) = extractor.slot_path(sidx)
                {
                    p = Some(path);
                    break;
                }
            }
            // Obfuscated post: the sniffed bootstrap's on-disk
            // file carries the same critical packets a named
            // main would - good enough for the par2cmdline
            // fallback's set argument.
            p.or_else(|| sniff_bootstrap.and_then(|s| extractor.slot_path(s)))
        };
        let repaired = fetch_and_repair(
            servers,
            nzb,
            out_dir,
            set,
            needed,
            main_par2,
            already,
            sniffed_vols,
            &mapped_fetched,
            mapped_yield,
            buf_pool.clone(),
            extractor,
            &mut repair_shortfall,
            cancel,
            &mut cpu,
        )
        .await?;
        // A successful disk repair re-read the WHOLE set off
        // disk, so it speaks for every file the set names.
        if repaired {
            set_files_proven = set.files.iter().map(|f| f.name.clone()).collect();
        }
        // Repaired volume files on disk → re-extract them cleanly.
        // rc=0 requires the END state to be usable output, not
        // just a successful repair.
        //
        // Whole-file recreation: any set file no slot claimed
        // (`missing_files`) was just rebuilt on disk by this
        // repair - `repaired` re-read the whole set, so the file
        // is there and proven. A recreated file sits on disk
        // exactly like a materialized one and needs the same
        // re-extract pass; without it the job exits 0 with the
        // recreated volumes still packed (the nested pass skips
        // them as the downloaded outer set). Covers the par-only
        // post (no data slots at all, `reports` empty) and the
        // MIXED set - a clean .nfo that reports beside a wholly
        // ghosted .rar. The old test was `reports.is_empty() &&
        // ...`, which read the .nfo's report as proof nothing
        // was recreated and greened the mixed job still packed
        // (Codex H2, 2 Aug). A recreated bare payload passes
        // through the re-extract untouched (no volumes → success).
        let recreated_set = !missing_files.is_empty();
        if repaired && (damage_in_mapped || recreated_set) {
            // The ladder's own reason where it has one - a bomb
            // verdict names the DISK, and this sentence names the
            // repair. See [`reextract_dir_why`].
            all_good = match reextract_dir_why(out_dir, password)? {
                Ok(()) => true,
                Err(why) => {
                    reextract_failed = Some(unpack_failure(
                        why,
                        "PAR2 repair succeeded but re-extraction failed",
                    ));
                    false
                }
            };
        } else {
            all_good = repaired;
            if !all_good {
                // PAR2 could not repair - the volumes' own embedded
                // recovery records are the last remaining redundancy.
                //
                // TODO §11 (b): the verifier's block verdicts ride along.
                // A failed repair never rewrote an intact file (native
                // patches damaged blocks in place, par2cmdline rewrites
                // only damaged files), so a slot whose every block
                // verified is still the file the verifier proved - and
                // the RR pass can leave it unopened. Slots the set never
                // claimed are absent from `reports` and get the full
                // pass.
                let hint = crate::rarfix::DamageHint::from_reports(reports, set.block_size);
                // The rung's own reason where it has one, on the same
                // terms as the re-extract arm above: a bomb verdict
                // names the DISK and must be quoted, and an ordinary
                // failure is left to the arms below to word, which is
                // what this site has always done (TODO §249 item 1).
                all_good = match crate::rarfix::try_rar_rr_repair_hinted_why(
                    out_dir,
                    password,
                    Some(&hint),
                ) {
                    Ok(()) => true,
                    Err(why) => {
                        if let Some(why) = why {
                            reextract_failed = Some(why);
                        }
                        false
                    }
                };
            }
        }
    } // mapped_ok else
    // An obfuscated post names its files nothing like the PAR2
    // set does - issue #9's shape is par2 created FIRST and
    // every file renamed after - so a file the set covers and
    // parity just rebuilt still lands in `uncovered_pairs`,
    // purely because its posted subject is a hash. Left alone
    // that fails a job whose output is complete and MD5-proved.
    //
    // Reconcile those against set files that no slot claimed
    // and THIS repair rebuilt whole and proved: one FileDesc
    // per slot, only for a slot that arrived nothing at all,
    // and only when the declared sizes agree. Whatever stays
    // unpaired still fails the job, so a genuine out-of-set
    // loss is untouched.
    if all_good && !uncovered_pairs.is_empty() {
        let mut spare: Vec<_> = set
            .files
            .iter()
            .filter(|f| {
                missing_files.iter().any(|m| m == &f.name)
                    && set_files_proven.iter().any(|p| p == &f.name)
            })
            .collect();
        uncovered_pairs.retain(|(i, _)| {
            // Only a slot that arrived NOTHING can be an alias:
            // one that wrote bytes had a yEnc name to claim its
            // FileDesc with, and did not.
            let s = &slots[*i];
            if s.missing.load(Ordering::Relaxed) != s.total_segments {
                return true;
            }
            let posted = nzb.files[slot_file[*i]].bytes();
            // NZB byte counts are yEnc-ENCODED and explicitly
            // approximate, so this is a sanity band and not an
            // equality - it is here to stop an unrelated extra
            // file pairing off against a set file of a quite
            // different size. A sizeless NZB pairs nothing.
            let Some(k) = spare.iter().position(|f| {
                posted > 0
                    && f.length > 0
                    && posted.saturating_mul(100) >= f.length.saturating_mul(90)
                    && posted.saturating_mul(100) <= f.length.saturating_mul(120)
            }) else {
                return true;
            };
            let f = spare.remove(k);
            info!(
                target: "repair",
                "✔ {} never arrived under its posted name, and the set rebuilt \
                 it as {} ({} bytes, MD5-proved)",
                s.hint, f.name, f.length
            );
            false
        });
    }
    // TODO 159 item 1: WHETHER the repair worked is what licenses a
    // per-file quarantine, so latch it before the three checks below
    // start subtracting from it. True here means the pass proved the
    // recovery set - `repair_mapped` re-reads every covered file back
    // through the view it wrote through, the disk repair re-reads the
    // whole set off disk - so anything still wrong is named by one of
    // those checks and nothing else is.
    let repair_ok = all_good;
    let mut uncovered_bad: Vec<String> =
        uncovered_pairs.iter().map(|(_, h)| h.to_string()).collect();
    // The census's own findings belong here too. A slot whose
    // articles ALL arrived and still does not cover its declared
    // range has missing/remaining/errors every one at zero, so
    // the partition above cannot see it - it selects on exactly
    // those three counters. The no-PAR2-set branch below already
    // merges these, and the clean-set branch catches them through
    // `incomplete`; this branch did neither, so a job that took
    // ANY damage and carried a lying `=ybegin size` on a file
    // outside the set finished GREEN with a hole in it, and
    // deleted the journal that named what was missing.
    //
    // Safe against the false REDs that shaped the census: it is
    // already exempt for anything the set covers (so a file
    // rebuilt from parity, whose interval map is legitimately
    // empty, never reaches here), for a reconciled deferral, and
    // for every mapped or chased shape that holds less than it
    // declares - `slot_uncovered` answers None for those.
    for hint in sparse_slots {
        if !uncovered_bad.contains(hint) {
            uncovered_bad.push(hint.clone());
        }
    }
    // Whatever the repair did, it did it inside the recovery set.
    if all_good && !uncovered_bad.is_empty() {
        all_good = false;
        warn!(
            target: "repair",
            "✘ repair succeeded, but {} file(s) outside the PAR2 set are still \
             incomplete: {}",
            uncovered_bad.len(),
            uncovered_bad.join(", ")
        );
    }
    // Short their articles, named by the set, but on a path that
    // never re-read the whole set off disk: unproven bytes, so
    // they fail the job just the same. Reported separately - they
    // are NOT outside the set, and saying so would send a user
    // hunting for a file that is sitting in the recovery set.
    let unproven_bad: Vec<&str> = if all_good {
        let proven: std::collections::HashSet<String> = set_files_proven
            .iter()
            .map(|n| nzbkit::disk::sanitize_filename(n).to_lowercase())
            .collect();
        in_set_bad
            .iter()
            .copied()
            .filter(|h| !proven.contains(&nzbkit::disk::sanitize_filename(h).to_lowercase()))
            .collect()
    } else {
        Vec::new()
    };
    if all_good && !unproven_bad.is_empty() {
        all_good = false;
        warn!(
            target: "repair",
            "✘ repaired in place, but {} file(s) the PAR2 set covers are still \
             short and were never proved against the set: {}",
            unproven_bad.len(),
            unproven_bad.join(", ")
        );
    }
    // The ⚠ census above is the last thing the log says about
    // these files, and on its own it reads like the loss stood.
    // Repair rebuilt them from parity and proved each against its
    // whole-file MD5, so the census stays and this line settles
    // what became of it.
    if all_good && !in_set_bad.is_empty() {
        info!(
            target: "repair",
            "✔ {} file(s) that never arrived were rebuilt in full from PAR2 \
             recovery data: {}",
            in_set_bad.len(),
            in_set_bad.join(", ")
        );
    }
    // TODO 159 item 1: name the slots the two ✘ checks just failed on,
    // by INDEX, so the failed-job quarantine can withhold their payload
    // alone. Licensed only by `repair_ok`: without a proved repair the
    // rest of the output has no certificate either, and the quarantine
    // must stay whole-job.
    //
    // `uncovered_pairs` carries its own indices; the census's
    // `sparse_slots` and the unproven in-set names arrive as hints and
    // have to be looked back up. A hint that resolves to no slot, or to
    // two, abandons the whole claim rather than dropping one file from
    // it - an unnamed damaged slot would otherwise look like a healthy
    // one and its payload would ship.
    let unhealed_slots = repair_ok
        .then(|| {
            let named: std::collections::HashSet<&str> =
                uncovered_pairs.iter().map(|(_, h)| *h).collect();
            let mut idx: Vec<usize> = uncovered_pairs.iter().map(|(i, _)| *i).collect();
            for hint in uncovered_bad
                .iter()
                .map(|h| h.as_str())
                .filter(|h| !named.contains(h))
                .chain(unproven_bad.iter().copied())
            {
                idx.push(slot_by_hint(slots, hint)?);
            }
            idx.sort_unstable();
            idx.dedup();
            Some(idx)
        })
        .flatten()
        // A job that is still good has nothing to quarantine, and an
        // empty list would read as "withhold nothing" on a path that
        // never reached the question.
        .filter(|_| !all_good);
    Ok(RepairOutcome {
        all_good,
        reextract_failed,
        repair_shortfall,
        unhealed_slots,
    })
}

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
    let mut every_set_ok = !results.is_empty();
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
                info!(
                    target: "par2",
                    "repaired ✔ ({} block(s) rebuilt across {} file(s))",
                    rep.blocks_rebuilt,
                    rep.files_patched.len(),
                );
                consumed.extend(rep.consumed_sources);
                healed.extend(r.names);
            }
            Ok(RepairStatus::Unrepairable { needed, have }) => {
                warn!(
                    target: "par2",
                    "UNREPAIRABLE - need {needed} recovery block(s), have {have}"
                );
                repair_shortfall = Some(crate::repair::RepairShortfall::Blocks { needed, have });
                every_set_ok = false;
            }
            Err(e) => {
                warn!(target: "par2", "repair error - {e}");
                every_set_ok = false;
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
            .map(|n| nzbkit::disk::sanitize_filename(n).to_lowercase())
            .collect();
        let covered: std::collections::HashSet<String> = healed
            .iter()
            .map(|n| nzbkit::disk::sanitize_filename(n).to_lowercase())
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
                if !is_payload {
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
            .filter(|(_, s)| !crate::get::census::is_spared_metadata(&s.hint))
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
        for hint in sparse_slots {
            if !uncovered_after_par2.contains(hint) {
                uncovered_after_par2.push(hint.clone());
            }
        }
        if uncovered_after_par2.is_empty() {
            info!(target: "repair", "repair complete in {:.2?} ✔", t0.elapsed());
            all_good = true;
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
    (all_good, repaired, uncovered_after_par2, repair_shortfall)
}

#[expect(clippy::too_many_arguments)]
async fn settle_without_set(
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
    let disk_verified = verify_dir(out_dir)?;
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
    if !all_good {
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
            let deferred_vols: Vec<usize> = sniff
                .deferred_slots()
                .into_iter()
                .filter(|&s| slots[s].deferred.load(Ordering::Relaxed) > 0)
                .map(|s| slot_file[s])
                .collect();
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
    Ok(SettleVerdict {
        all_good,
        reextract_failed,
        repair_shortfall,
        deferred_renames: Vec::new(),
        published_names: crate::unpack::PublishedNames::for_dir(out_dir),
        sniff_covered: None,
        // No per-file claim from the disk-side fallback. It is reached
        // only where no set activated, and its repair works on volume
        // FILES - so any group that was direct-extracting has already
        // materialized and abandoned its output names, leaving the
        // quarantine nothing to discriminate between. Whole-job stays
        // right here, and it stays honest.
        unhealed_slots: None,
        repaired,
    })
}

// Issue #14 drain fallback: a deferred slot the ACTIVE set covers is
// payload the sniff got wrong (a posted par2 file the set includes).
// The live reconcile at activation requeues such slots while the pool
// still runs; on a short post the pool is gone by activation time, so
// whatever is still deferred-and-matched is fetched here on the side
// machinery and fed to the verifier off disk - delivered and
// verified, never recreated from recovery blocks.
#[expect(clippy::too_many_arguments)]
pub(super) async fn fetch_matched_deferred(
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
    if let Some(set) = verifier.set() {
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
            // Feed the whole file from disk: the first chunk carries the
            // 16k head, so the verifier claims the slot by md5-16k, and
            // every block gets a full-MD5 disk-provenance check before
            // settle reads the result.
            let path = extractor.slot_path(sidx).unwrap_or_else(|| {
                out_dir.join(nzbkit::disk::sanitize_filename(&slots[sidx].hint))
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
    }
}

#[cfg(test)]
mod spare_contract_tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn slot(hint: &str, par2: bool, errors: usize) -> Arc<FileSlot> {
        Arc::new(FileSlot {
            hint: hint.into(),
            is_par2_main: par2,
            sample_skipped: false,
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
}
