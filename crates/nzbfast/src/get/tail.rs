//! The disk-unpack tail (TODO 106 phase 2.1, cut 6): the volume-eating
//! decision and its arm, the resumed-run re-extract, the §94A restored-
//! source cleanup, the unrar ladder over demoted volume groups, and the
//! nested-archive second pass. Body is a verbatim move from the
//! orchestrator.

use crate::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// finish_run's own reach across the pipeline's other halves: the
// post-drain census and the settle/repair ladder both run inside it.
use super::census::{Census, take_census};
use super::settle::{SettleVerdict, settle_verify_repair};
use super::workers::{self, CauseSplit, PendingR};
use tracing::{info, warn};

/// How the unpack tail left the job. The orchestrator destructures the
/// fields back onto the inline names.
pub(super) struct UnpackVerdict {
    pub(super) all_good: bool,
    pub(super) reextract_failed: Option<String>,
}

/// The 🔒 line, in one place: the no-password arm prints it, and since
/// TODO 164 so does a PAR2-vouched encrypted leftover (the ladder
/// unpacked a sibling, the vouched set never had a password to try).
/// One spelling, because the daemon's finalize and the suites read it.
fn warn_locked_no_password() {
    warn!(
        target: "password",
        "🔒 archive is password-protected and no password was found - \
         verified volumes kept in the output directory. Supply one with \
         --password, a <meta type=\"password\"> in the NZB, or a \
         {{{{password}}}} suffix on the NZB filename, then retry."
    );
}

/// The unrar ladder over the DEMOTED volume groups: the three arms
/// (compressed or passworded-with-a-password, unowned, locked without a
/// password) and the bomb floor ahead of them. Carved out of
/// `unpack_tail` when TODO 164 put the leftover judgement on the two
/// ladder arms; body otherwise verbatim.
fn demoted_volume_ladder(
    ex_report: &nzbkit::extract::ExtractReport,
    out_dir: &Path,
    password: Option<&str>,
    par2_covered: Option<&std::collections::HashSet<String>>,
    all_good: &mut bool,
    reextract_failed: &mut Option<String>,
    locked_no_password: &mut bool,
) {
    // The unrar ladder below reasons about RAR VOLUMES, so a top-level 7z
    // chase that demoted is filtered out of it entirely: that demote
    // leaves a materialized .7z, which the post-extraction pass further
    // down owns. Left in, its reason text steers all three arms wrongly -
    // "held-bytes cap" reads as an unowned set and "encrypted" as a
    // locked RAR - and each one ends at try_unrar over a directory with
    // no RAR in it, which answers false and fails a job that is fine.
    let vol_fallbacks: Vec<&(String, String)> = ex_report
        .fallbacks
        .iter()
        .filter(|(_, w)| !sevenz_disk_fallback(w))
        .collect();
    // Compressed (non-encrypted) archives can't stream-extract, but a
    // bundled unrar unpacks the verified volumes. Encrypted sets join in
    // when a password is known; without one they stay on disk.
    let enc_fallback = vol_fallbacks
        .iter()
        .any(|(_, w)| w.contains("encrypted") || w.contains("password"));
    // Every OTHER demote leaves its volumes unowned - see
    // [`fallback_needs_disk_unpack`].
    let unowned_fallback = vol_fallbacks
        .iter()
        .any(|(_, w)| fallback_needs_disk_unpack(w));
    // An SFX demote is the tail's SFX arm's (`sevenz_disk_fallback` is what
    // keeps it out of `vol_fallbacks` and so out of all three arms here) -
    // with one exception. Locked with no password to try, the carve has
    // nothing to do: `extract_sfx` hands the archive to a reader that will
    // refuse it, and the job would fail over a `.exe` that is perfectly
    // fine on disk. The answer a locked RAR set gets - volumes kept, 🔒
    // prompt, and a retry once a password arrives - is the right one here
    // too, so this joins the encrypted arm instead.
    let sfx_locked = password.is_none()
        && ex_report
            .fallbacks
            .iter()
            .any(|(_, w)| sfx_locked_fallback(w));
    // Ahead of all three arms, because it forecloses all three: a demote
    // the bomb guard caused has nothing for a second engine to try. See
    // [`bomb_fallback`].
    if *all_good && let Some(why) = bomb_fallback(vol_fallbacks.iter().map(|(_, w)| w.as_str())) {
        *all_good = false;
        *reextract_failed = Some(why);
    } else if *all_good
        && (vol_fallbacks.iter().any(|(_, w)| w.contains("compressed"))
            || (enc_fallback && password.is_some()))
    {
        // The unrar outcome IS the job outcome here: a corrupt compressed
        // set (or a wrong password) must not exit 0 with loose volumes.
        // On success the volumes are spent (Part B of the 2026-07-29
        // one-pass spec): a demoted 57.8 GB job used to finish holding
        // both the movie AND its full volume set.
        let _cpu = crate::lanegate::heavy_cpu_blocking();
        match try_unrar_outcome(out_dir, password) {
            Ok(outcome) => {
                remove_spent_volumes(&outcome.spent);
                settle_leftovers(&outcome, par2_covered, reextract_failed, locked_no_password);
                *all_good &= reextract_failed.is_none();
            }
            // TODO 211's last rung - see the twin below.
            Err(_) if rescue_split_after_failed_unpack(out_dir, password) => {}
            Err(why) => {
                *all_good = false;
                // A refusal that named its own reason keeps it. Only the
                // bomb rungs do (the native verdict, and the preflight
                // ahead of the unrar spawn) and both are about the DISK,
                // where this sentence blames the archive - the exact
                // wrong blame the 22 Aug 2026 incident was reported as.
                // See [`try_unrar_spent_why`].
                *reextract_failed = Some(unpack_failure(
                    why,
                    "the verified volumes could not be unpacked \
                     (compressed set, or the password is wrong)",
                ));
            }
        }
    } else if *all_good && unowned_fallback && !enc_fallback {
        let _cpu = crate::lanegate::heavy_cpu_blocking();
        match try_unrar_outcome(out_dir, password) {
            Ok(outcome) => {
                remove_spent_volumes(&outcome.spent);
                settle_leftovers(&outcome, par2_covered, reextract_failed, locked_no_password);
                *all_good &= reextract_failed.is_none();
            }
            // TODO 211: what looks like a volume set here may be a byte
            // SPLIT of one archive - `stage.rar.001`..`.062`, where part 1
            // is a RAR head over 1/62nd of a container and every other part
            // is raw continuation bytes. No unpacker can open that, which
            // is why this ladder just failed; rejoining the parts and
            // extracting the result is the rung below the fallback. It
            // refuses everything that is not exactly that shape, and a
            // refusal leaves the volumes untouched for the arms above.
            Err(_) if rescue_split_after_failed_unpack(out_dir, password) => {}
            Err(why) => {
                *all_good = false;
                // Same rule as the twin above.
                *reextract_failed = Some(unpack_failure(
                    why,
                    "the verified volumes could not be unpacked after a fallback",
                ));
            }
        }
    } else if *all_good && (enc_fallback || sfx_locked) {
        *locked_no_password = true;
        warn_locked_no_password();
    }
}

/// TODO 164: what the ladder left packed, judged against the job's own
/// PAR2 set. A successful run (a sibling produced) used to be the job's
/// outcome outright; now a leftover the recovery set vouches for fails
/// the level, and a vouched encrypted set that was never offered a
/// password routes to the existing locked shape. Anything the set does
/// not name keeps the decoy tolerance - see [`crate::rarfix::vouch`].
fn settle_leftovers(
    outcome: &crate::rarfix::UnpackOutcome,
    par2_covered: Option<&std::collections::HashSet<String>>,
    reextract_failed: &mut Option<String>,
    locked_no_password: &mut bool,
) {
    use crate::rarfix::vouch::{VouchVerdict, failure_sentence, judge};
    match judge(&outcome.packed, par2_covered) {
        VouchVerdict::Tolerated => {}
        VouchVerdict::Locked(names) => {
            warn!(
                target: "extract",
                "the PAR2 set vouches for {} encrypted archive set(s) still packed: {}",
                names.len(),
                names.join(", ")
            );
            *locked_no_password = true;
            warn_locked_no_password();
        }
        VouchVerdict::Failed { names, reason } => {
            // The group's own refusal (a bomb verdict) outranks the
            // sentence, for the same reason it does one arm up: it is
            // about the disk, and the sentence blames the archive.
            *reextract_failed = Some(unpack_failure(reason, &failure_sentence(&names)));
        }
    }
}

#[expect(clippy::too_many_arguments)]
pub(super) fn unpack_tail(
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<FileSlot>],
    restored: &nzbkit::journal::Restored,
    ex_report: &nzbkit::extract::ExtractReport,
    final_shape: &Option<nzbkit::extract::ArchiveShape>,
    outer_vol_stems: &std::collections::HashSet<String>,
    out_dir: &Path,
    password: Option<&str>,
    resuming: bool,
    no_extract: bool,
    resume_map: bool,
    eat_consent: bool,
    note_activity: &(dyn Fn(&'static str) + Sync),
    hub: &Option<Arc<StreamHub>>,
    stream_owner: &str,
    mut all_good: bool,
    mut reextract_failed: Option<String>,
    // See [`crate::get::settle::SettleVerdict::repaired`]: a repair may
    // have rewritten the very volume bytes a forfeited chase decoded
    // from, so the resume ledger stands down when it is set.
    repaired: bool,
    // TODO 164: the activated PAR2 set's FileDesc names (sanitized,
    // lowercased - `SettleVerdict::sniff_covered`), `None` when no set
    // activated. A group the unrar ladder leaves packed is the posted
    // release, not a decoy, exactly when one of its volumes is named
    // here - see [`crate::rarfix::vouch`].
    par2_covered: Option<&std::collections::HashSet<String>>,
) -> Result<UnpackVerdict> {
    note_activity("extracting");
    // TODO 205: the volume files this ladder is about to work through.
    // Collected ONCE, up here, because two things want them and both
    // want them before anything runs: the eat forecast below needs their
    // bytes, and the queue row needs their COUNT - issue #47's reporter
    // watched "unpacking" for several minutes on a NAS with no way to
    // tell whether it was one volume or his 130.
    let mut on_disk = collect_rar_volumes(out_dir).unwrap_or_default();
    on_disk.extend(collect_obfuscated_rar_volumes(out_dir).unwrap_or_default());
    let vol_bytes = crate::eatvol::volume_bytes(&on_disk);
    // Armed before the §129 admission wait inside the block below, so a
    // ladder parked behind another tail's disk reservation already says
    // how big a job it is waiting to start. Held to the end of the
    // function - every ladder arm and the nested pass are unpack work -
    // and its Drop takes the hub entry with it, on the failure paths
    // too. See `crate::unpackprog` for why this is not the writer
    // registration the in-stream path publishes.
    let _unpack_prog = crate::unpackprog::arm(hub, stream_owner, on_disk.len() as u64);
    // A chase that forfeited on the held-bytes cap left its in-stream
    // output on disk with a mark saying how far it is good; the ladder
    // below resumes from there rather than re-extracting each member
    // from byte zero (`crate::resumeout`, and the ~0.4x of payload it
    // takes off trim-then-forfeit). Held for the whole function: its
    // Drop removes every partial the ladder did NOT go on to finish,
    // which is the guarantee that replaces the delete the forfeit used
    // to do - so it must outlive every arm below, the failure paths and
    // the early returns included.
    //
    // `repaired` is the disk-side half of the trust test. The extractor
    // catches a repair that comes back THROUGH it and drops the ledger
    // itself; a disk-side repair (`repair_dir` and the recovery-record
    // pass, both of which the settle phase may run over materialized
    // volumes) writes to the files directly and it never sees them. The
    // arm still takes the partials in that case - it just offers none of
    // them - so they are removed rather than left lying under the
    // payload's own name.
    //
    // `chase_dropped_bytes` is the third route, and it exists because of
    // the OTHER change that landed the same day. A dropping trim throws
    // the consumed prefix away instead of spilling it, so a demote
    // leaves holes in the volume files and `get::dropped` RE-FETCHES
    // them - by path, not through the extractor, so neither of the two
    // guards above sees it. The re-fetched bytes are the same posted
    // bytes and pass the same per-article CRC, so a difference needs a
    // body that is wrong AND checksums correctly - the one thing the
    // in-chase conflict guard is written for. But without a resume that
    // case still SELF-HEALS (the disk pass re-extracts everything from
    // the re-fetched volumes), and with one it would not: the prefix
    // would come from the first copy and the CRC-verified tail from the
    // second. Standing down when anything was dropped keeps the
    // self-healing, and costs an optimisation on a job that took the
    // slower road anyway.
    let dropped = extractor.chase_dropped_bytes() > 0;
    let stand_down = repaired || dropped;
    // Said out loud, because until this line the stand-down was
    // INVISIBLE: a job that forfeited on the cap and kept a perfectly
    // good prefix simply did not print the "resuming" line, and no
    // counter anywhere separated "there was nothing to resume" from
    // "there was, and we declined it". That is also what made the
    // interaction of the two 22 Aug follow-ups unreadable from a leg's
    // own log (TODO 214). Only when there was something to decline.
    if stand_down && !ex_report.resume_outputs.is_empty() {
        let bytes: u64 = ex_report.resume_outputs.iter().map(|r| r.len).sum();
        info!(
            target: "extract",
            "not resuming {} member(s) ({:.1} GB will be re-extracted from byte zero): {}",
            ex_report.resume_outputs.len(),
            bytes as f64 / 1e9,
            if repaired {
                "a repair rewrote volume bytes on disk after the chase decoded them"
            } else {
                "the one-pass trim dropped volume bytes that were then re-fetched"
            }
        );
    }
    let _resume = if stand_down {
        crate::resumeout::ResumeArm::stood_down(&ex_report.resume_outputs)
    } else {
        crate::resumeout::ResumeArm::new(&ex_report.resume_outputs)
    };
    // Output bytes the ladder below will NOT have to write, because the
    // chase already did. They come off the §129 lane RESERVATION: the
    // partials are on the filesystem now, so the free-bytes read is
    // lower by exactly this much, and leaving the reservation at its
    // full size would make a job wait behind another tail for room it
    // does not want. Zero on every job that did not forfeit, and zero
    // when the arm stood down (nothing resumes, so everything is
    // written).
    let resumed_on_disk: u64 = if stand_down {
        0
    } else {
        ex_report.resume_outputs.iter().map(|r| r.len).sum()
    };
    // TODO 101: should this job's disk unpack eat its own volumes as it
    // consumes them? Decided ONCE, here, where every input is known and
    // measured - the set is fully on disk by now, so the forecast is
    // arithmetic rather than a projection - and armed for the length of
    // the disk ladder below. `all_good` IS the verified gate: it is false
    // for any set PAR2 could not vouch for, and an unverified set is
    // never eaten whatever the mode says.
    //
    // Deliberately NOT extended over the nested pass further down: those
    // are intermediates the extraction produced, owned by
    // `sweep_spent_entry`, not the downloaded volume set this mode is
    // about.
    // Lives to the end of the function: the §129 outstanding-need
    // registration this unpack holds against its output filesystem.
    let _need_guard: crate::lanegate::NeedGuard;
    let eat_arm = {
        // `tag()`, not `display()`. Every other consumer of this shape
        // reads the raw tokens; `display()` runs each one through
        // `shape_word` and joins with " · " for humans, so the token
        // test worked only by the accident that "encrypted" is spelled
        // the same either way. One rewording or one localization of that
        // single word and the encrypted third copy would silently drop
        // out of the forecast, leaving a `low_disk` job that must eat
        // its volumes reading as "fits" and dying at the decrypt.
        let shape = final_shape.as_ref().map(|s| s.tag()).unwrap_or_default();
        let encrypted = shape.split_whitespace().any(|t| t == "encrypted");
        // §129 lane admission: register what this unpack still needs on
        // the output filesystem so concurrent tails stop double-counting
        // the same free space, and WAIT here (activity already says
        // "extracting") when we would fit alone but not beside them.
        // Held to the end of the function - the ladder AND the nested
        // pass write into the same forecasted room.
        // Only the RESERVATION comes down by what the chase already
        // wrote. `Forecast` is left on the true volume bytes on purpose:
        // its one field does double duty - room still needed AND what
        // eating the volumes would give back - and only the first of
        // those shrinks here. Understating the second would decline to
        // eat on exactly the tight disk the mode exists to rescue, and
        // the two errors are not symmetric: a needlessly armed eat still
        // finishes the job, a wrongly declined one meets ENOSPC.
        let to_write = vol_bytes.saturating_sub(resumed_on_disk);
        let needed = if encrypted {
            to_write.saturating_mul(2)
        } else {
            to_write
        };
        _need_guard = crate::lanegate::admit_unpack(out_dir, needed, crate::eatvol::MARGIN);
        let forecast = crate::eatvol::forecast(out_dir, vol_bytes, encrypted);
        let verdict = crate::eatvol::decide(crate::eatvol::mode(), all_good, eat_consent, forecast);
        if verdict.eats() {
            info!(
                target: "extract",
                "volume-eating unpack armed ({}): {} volume(s) on disk, {:.1} GB free, \
                 the unpack needs {:.1} GB",
                crate::eatvol::mode().as_str(),
                on_disk.len(),
                forecast.free as f64 / 1e9,
                forecast.needed() as f64 / 1e9
            );
        }
        crate::eatvol::EatArm::new(verdict.eats())
    };
    // Set when the set is locked and no password was found: the verified
    // volumes ARE the deliverable until one arrives, so the nested pass must
    // not then try (and fail) to unpack them. A NAMED encrypted set was
    // already safe by accident - its stems are in `outer_vol_stems`, so the
    // pass skipped it - but an obfuscated one has no stem to match (hash
    // names carry no extension), so the pass ran, `extract_obfuscated_rar`
    // failed for want of the password, and the job came out FAILED with no
    // password prompt, where the identical named set finishes Completed and
    // offers the unlock.
    let mut locked_no_password = false;
    //
    // Declared ahead of the resumed-run arm since TODO 164: that arm
    // reaches the same leftover judgement as the fresh-run arms, and a
    // vouched encrypted leftover sets this from there too.
    // Resumed runs skipped in-stream extraction - extract from the (now
    // verified) volume files on disk. Not under §94 A replay: there the
    // extractor mapped in-stream like a fresh run, and whatever demoted
    // takes the same disk ladder a fresh run's demotes take, below.
    if resuming && !no_extract && !resume_map && all_good {
        // §129: the re-extract is the heavy-CPU stage - one at a time
        // across concurrent tails (the permit, not the lane, is the
        // serializer, so the MD5-parallel repair work composes).
        let _cpu = crate::lanegate::heavy_cpu_blocking();
        // The reason the ladder refused with wins over the generic
        // sentence when there is one: a bomb verdict is about the DISK,
        // and "the volumes could not be extracted" reads as a damaged
        // archive. See [`reextract_dir_why`].
        match reextract_dir_outcome(out_dir, password)? {
            // TODO 164: the same leftover judgement the fresh-run arms
            // below make, on the same set.
            Ok(packed) => {
                let outcome = crate::rarfix::UnpackOutcome {
                    spent: Vec::new(),
                    packed,
                };
                settle_leftovers(
                    &outcome,
                    par2_covered,
                    &mut reextract_failed,
                    &mut locked_no_password,
                );
                all_good &= reextract_failed.is_none();
            }
            Err(why) => {
                all_good = false;
                reextract_failed = Some(unpack_failure(
                    why,
                    "resumed job: the verified volumes on disk could not be extracted",
                ));
            }
        }
    }
    if resume_map && all_good {
        drop_replayed_sources(extractor, slots, restored, ex_report, out_dir);
    }
    // The unrar ladder over the demoted volume groups - see
    // [`demoted_volume_ladder`].
    demoted_volume_ladder(
        ex_report,
        out_dir,
        password,
        par2_covered,
        &mut all_good,
        &mut reextract_failed,
        &mut locked_no_password,
    );
    // The downloaded volume set is done with. Everything below works on
    // what extraction PRODUCED, which this mode has no business eating.
    drop(eat_arm);
    if all_good
        && !no_extract
        && !locked_no_password
        && let Some(msg) = sfx_pass(extractor, slots, out_dir, password)
    {
        all_good = false;
        reextract_failed = Some(msg);
    }
    // Post-extraction pass: nested archives (a RAR whose payload is one
    // more RAR), 7z sets, and SFX payloads unpack here - the inner layer
    // only exists once the outer extraction produced it, so this is
    // inherently a second pass over the output dir. Volumes of the
    // DOWNLOADED set deliberately remain in some flows (encrypted-no-
    // password, unrar-fallback leftovers) and must never be re-processed:
    // when nothing else needs the pass they simply skip it, and when the
    // fallback unpack itself produced a nested archive beside them
    // (compressed outer wrapping a RAR/7z) they are parked in a scratch
    // hold for the pass's duration instead, so the payload still denests.
    let outer_vols_on_disk = || -> bool {
        use nzbkit::extract::release_stem;
        match std::fs::read_dir(out_dir) {
            Ok(it) => it.flatten().any(|e| {
                let p = e.path();
                looks_like_named_rar(&p)
                    && p.file_name().is_some_and(|n| {
                        outer_vol_stems.contains(&release_stem(&n.to_string_lossy()))
                    })
            }),
            Err(_) => true, // unreadable output dir: keep the conservative skip
        }
    };
    let nested_hold: Option<Option<OuterHold>> = if !(all_good && !no_extract) {
        None
    } else if locked_no_password {
        // The volumes are the deliverable; nothing here can unpack them.
        None
    } else if !outer_vols_on_disk() {
        Some(None) // run the pass, nothing to park
    } else if nested_archive_beside_leftovers(out_dir, outer_vol_stems) {
        match OuterHold::park(out_dir, outer_vol_stems) {
            Ok(h) => Some(Some(h)),
            Err(e) => {
                // Park failure degrades to the historical skip - never
                // risk the pass seeing the outer set.
                warn!(target: "extract", "could not isolate leftover volumes for the nested pass: {e}");
                None
            }
        }
    } else {
        None
    };
    if let Some(hold) = nested_hold {
        // Same permit as the ladder arms above: the nested pass is a
        // full re-extract of what the outer extraction produced.
        // The pass's own reason where it has one, on the same rule as
        // the three arms above: a bomb refused inside the nested pass is
        // about the DISK, and every sentence this match composes blames
        // the archive. See [`extract_nested_why`].
        let mut nested_why: Option<String> = None;
        let nested_res = {
            let _cpu = crate::lanegate::heavy_cpu_blocking();
            extract_nested_why(out_dir, password, 1, &mut nested_why)
        };
        // Restore parked volumes before judging the result - they must be
        // back in place on every path, including the failure ones.
        drop(hold);
        match nested_res {
            Ok(NestOutcome::Produced) => {}
            Ok(outcome) => {
                // A zip we cannot unpack FAILS the job when it is the
                // payload, and is forgiven when it is a sidecar.
                //
                // This used to warn either way, reasoning that failing
                // would loop *arr retries on a download that arrived
                // fine. But it did not arrive fine: if the payload is a
                // zip we cannot open, the release delivered nothing an
                // *arr can import, and Completed is a conclusion it acts
                // on - it stops looking, and the series sits stuck
                // forever. Failed is the honest answer, and it is the one
                // that makes Sonarr blocklist this release and grab a
                // usable one. The archive itself stays on disk either way.
                //
                // (There is no third status worth having. Sonarr's
                // Warning state is reachable only by claiming a disk-full
                // failure verbatim - SAB fail_message
                // "Unpacking failed, write error or disk is full?", or
                // nzbget UnpackStatus=SPACE - which would put a lie in
                // front of the user to buy a softer badge.)
                //
                // Forgiveness keys off what the PASS stopped at, never off
                // "is there a zip somewhere in the tree": a RAR/7z we could
                // not unpack is a payload we did not deliver even when an
                // unrelated `Subs/subs.zip` sits beside it.
                let zip_gap = outcome == NestOutcome::ZipGap;
                match unsupported_archive_present(out_dir) {
                    Some(u) if zip_gap && !u.blocking => u.log(),
                    Some(u) if zip_gap => {
                        u.log();
                        all_good = false;
                        reextract_failed = Some(unpack_failure(
                            nested_why.take(),
                            &format!(
                                "the payload {} could not be unpacked \
                                 (damaged, encrypted, or an unsupported compression method)",
                                u.display
                            ),
                        ));
                    }
                    // Either a non-zip gap over a named archive, or a pass
                    // that stopped without leaving one we can point at.
                    other => {
                        all_good = false;
                        reextract_failed = Some(unpack_failure(
                            nested_why.take(),
                            &match other {
                                Some(u) => format!(
                                    "{} in the output directory could not be unpacked",
                                    u.display
                                ),
                                None => "an archive in the output directory could not be unpacked"
                                    .into(),
                            },
                        ));
                    }
                }
            }
            Err(e) => {
                warn!(target: "extract", "nested-archive pass failed: {e}");
                all_good = false;
                reextract_failed = Some("the nested-archive pass failed".into());
            }
        }
    }
    Ok(UnpackVerdict {
        all_good,
        reextract_failed,
    })
}

/// §94 A: a replayed volume whose slot MAPPED (or chased) leaves its
/// restored source file behind - the output came through the map, so
/// the source is now redundant. Removed only on a fully-good finish
/// (the crash journal's records keep pointing at these files until
/// then, so a kill mid-run still resumes from them), and only when
/// the slot did not adopt that exact file as its plain writer.
/// Split out of `unpack_tail` (TODO 106), body verbatim.
fn drop_replayed_sources(
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<FileSlot>],
    restored: &nzbkit::journal::Restored,
    ex_report: &nzbkit::extract::ExtractReport,
    out_dir: &Path,
) {
    for seed in &restored.seeds {
        // Recovery volumes were never replayed; their files belong to
        // the ordinary end-of-job PAR2 cleanup, not to this pass.
        if seed.slot >= slots.len() || slots[seed.slot].is_par2() {
            continue;
        }
        // Never delete a path an extraction PRODUCED. The preclaim
        // at replay time already stops an inner member taking a
        // restored source's name, so this is the second lock on the
        // same door (Codex sweep 3 Aug H3): identity by path string
        // alone once deleted the only output of the job while
        // reporting it green.
        if ex_report.extracted.iter().any(|(n, _)| n == &seed.name) {
            continue;
        }
        let p = out_dir.join(&seed.name);
        if extractor.slot_path(seed.slot).as_deref() != Some(p.as_path()) && p.exists() {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// The post IS an SFX: every member is an .exe/.bin/.sfx with a RAR or
/// 7z signature sitting past a launcher stub. This is the entry gate for
/// that shape, and it belongs HERE rather than in the nested pass because
/// only this frame can tell a downloaded file from a produced one.
///
/// Two ways a stub reaches it. Out of the offset-0 sniff's reach (a stub
/// longer than the first article, a zip SFX, a signature with no valid
/// header behind it), the file lands on disk as plain data and nothing
/// above ever looks at it - the nested pass will not either, since an
/// `.exe` is deliberately not an extractable archive to it. Or the sniff
/// DID fire (TODO 94 C) and the mapper it started inside the stub then
/// demoted, in which case the posted `.exe` is materialized whole and the
/// unrar ladder has already been told to leave it alone, by the
/// `SFX_DISK_FALLBACK_PREFIX` on its demote reason. Either way what is on
/// disk here is the posted file, byte for byte.
///
/// That distinction is the whole safety argument. A payload's
/// `setup.exe` is very often a legitimate WinRAR SFX installer and must
/// never be auto-exploded, which is why `extract_one_level`'s step 3
/// is depth-0 only - but by the time we get here, extraction output
/// and downloaded files share one directory, so "top level" no longer
/// means "downloaded". `slot_path` does: it is the live on-disk path of
/// a slot the DOWNLOAD wrote (rename-aware, so a deobfuscated name
/// still matches). Only those paths are eligible; anything extraction
/// produced is invisible to this arm however executable it looks.
///
/// Runs before the nested pass, not instead of it: an SFX wrapping a
/// RAR that wraps another archive still denests, because the pass
/// below sees what this produced.
///
/// `Some(msg)` is the sentence the queue row shows. Split out of
/// `unpack_tail` (TODO 106), body verbatim.
fn sfx_pass(
    extractor: &Arc<nzbkit::extract::Extractor>,
    slots: &[Arc<FileSlot>],
    out_dir: &Path,
    password: Option<&str>,
) -> Option<String> {
    let downloaded: std::collections::HashSet<std::path::PathBuf> = (0..slots.len())
        .filter_map(|i| extractor.slot_path(i))
        .collect();
    let sfx: Vec<std::path::PathBuf> = collect_sfx_archives(out_dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| downloaded.contains(p))
        .collect();
    if !sfx.is_empty() {
        // What the badge says for this route. The shape is normally
        // noted by the EXTRACTOR as it classifies a slot, and on this
        // one it never got the chance: a stub deeper than the offset-0
        // article makes the file a plain download to the in-stream
        // sniff, so the job finished with an EMPTY `archive_shape`
        // while the other two SFX routes filled theirs. Latched BEFORE
        // the attempt, not after it: the bit says these bytes were
        // written to disk to be unpacked afterwards, which is true of a
        // failed unpack too - and a failed job's report is exactly where
        // a reader most needs to know what the payload was.
        for p in &sfx {
            if let Some(what) = sfx_disk_shape(p) {
                extractor.note_disk_archive(what);
            }
        }
        // Same permit as every other arm: carving a stub off and
        // unpacking what is behind it is heavy CPU and heavy disk.
        let _cpu = crate::lanegate::heavy_cpu_blocking();
        if !extract_sfx(out_dir, &sfx, password) {
            return Some(
                "the downloaded self-extracting archive could not be unpacked \
                 (damaged, encrypted, or an unsupported compression method)"
                    .into(),
            );
        }
    }
    None
}

/// The end-of-extraction report: finish() the extractor, apply the
/// deferred deobfuscation renames, collect the outer volume stems the
/// nested pass must park, and print what came out in-stream.
pub(super) fn report_extraction(
    extractor: &Arc<nzbkit::extract::Extractor>,
    ex_report: nzbkit::extract::ExtractReport,
    deferred_renames: &[(usize, String)],
    published_names: &mut crate::unpack::PublishedNames,
    out_dir: &Path,
) -> Result<(
    nzbkit::extract::ExtractReport,
    std::collections::HashSet<String>,
    Option<nzbkit::extract::ArchiveShape>,
)> {
    // Now that no writer holds the partial file, a chased slot that
    // demoted can take the deobfuscated name after all. A slot whose
    // chase SUCCEEDED has no file left to rename (sevenz_finish deletes
    // the partial - the payload came out the other way), so slot_path is
    // None and this skips it.
    for (sidx, pname) in deferred_renames {
        if let Some(path) = extractor.slot_path(*sidx)
            && path.exists()
            && let Some(new) = publish_verified_name(&path, pname, out_dir, *sidx, published_names)
        {
            extractor.note_slot_renamed(*sidx, new);
        }
    }
    // Named-RAR volume files of the DOWNLOADED set sitting in the output
    // dir at end-of-download (fallback groups' materialized volumes,
    // resumed runs' on-disk sets). Direct-extraction payload is subtracted
    // by name: a payload that is itself a named RAR set (RAR-in-RAR
    // release) is not an outer volume, and the nested pass below must
    // denest it rather than skip on its presence.
    let outer_vol_stems: std::collections::HashSet<String> = {
        use nzbkit::extract::release_stem;
        let payload: std::collections::HashSet<&str> = ex_report
            .extracted
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        std::fs::read_dir(out_dir)
            .map(|it| {
                it.flatten()
                    .map(|e| e.path())
                    .filter(|p| looks_like_named_rar(p))
                    .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .filter(|n| !payload.contains(n.as_str()))
                    .map(|n| release_stem(&n))
                    .collect()
            })
            .unwrap_or_default()
    };
    let final_shape = extractor.archive_shape();
    if !ex_report.extracted.is_empty() {
        // Sum the per-file sizes printed right below rather than the
        // extractor's `extracted_bytes` counter: that counter is only
        // incremented on the RAR store mapping path, so every CHASE
        // (7z and zip) reported "(0.0 MB)" under a list of files whose
        // own sizes were right. Found on a live 160 MB zip, 31 Jul.
        let extracted_mb: u64 = ex_report.extracted.iter().map(|(_, s)| *s).sum();
        info!(
            target: "extract",
            "extracted {} file(s) in-stream ({:.1} MB) - volumes never touched disk{}:",
            ex_report.extracted.len(),
            extracted_mb as f64 / 1e6,
            final_shape
                .as_ref()
                .map(|sh| format!(" [{}]", sh.display()))
                .unwrap_or_default()
        );
        for (name, size) in &ex_report.extracted {
            let lock = if ex_report.decrypted.contains(name) {
                " 🔓 decrypted"
            } else {
                ""
            };
            info!(target: "extract", "{name} ({:.1} MB){lock}", *size as f64 / 1e6);
        }
    } else if let Some(sh) = final_shape.as_ref() {
        // Nothing came out in-stream, so the shape has not been printed
        // anywhere yet - and it is exactly what explains why.
        info!(target: "extract", "archive: {}", sh.display());
    }
    // Coalesce fallback reports by reason (an encrypted 180-volume set
    // would otherwise print 180 identical lines).
    let mut by_reason: std::collections::BTreeMap<&str, usize> = Default::default();
    for (_, why) in &ex_report.fallbacks {
        *by_reason.entry(why.as_str()).or_default() += 1;
    }
    for (why, n) in by_reason {
        warn!(
            target: "extract",
            "direct extraction fell back for {n} volume group(s): {why} - volumes on disk"
        );
    }
    Ok((ex_report, outer_vol_stems, final_shape))
}

// Issue #14 tail: a sniffed post's recovery files sit on disk under
// hash names - the bootstrap volume, deferred slots' head-article
// partials, restored resume volumes, and anything a repair fetched.
// No extension rule can ever match them, so sweep by packet magic
// under the same `par_cleanup` setting that governs named `.par2`.
// ONLY on a good job (a failed one keeps its recovery data for the
// retry), and only HERE - after extractor.finish() - so no writer
// still holds a handle on the files (Windows would refuse the
// remove), and nothing that runs later reads them. Payload that is
// ITSELF par2 is spared by FileDesc name: the activated set's if one
// exists, the on-disk packets' otherwise.
pub(super) fn sweep_sniffed_leftovers(
    all_good: bool,
    par_cleanup: bool,
    sniff: &Arc<SniffCtl>,
    sniff_covered: Option<std::collections::HashSet<String>>,
    out_dir: &Path,
) {
    if all_good && par_cleanup && sniff.any_sniffed() {
        let covered: std::collections::HashSet<String> = sniff_covered.unwrap_or_else(|| {
            nzbkit::par2repair::covered_names(out_dir)
                .unwrap_or_default()
                .iter()
                .map(|n| nzbkit::disk::sanitize_filename(n).to_lowercase())
                .collect()
        });
        let mut freed: u64 = 0;
        let mut gone: usize = 0;
        // Same reasoning as the adoption-source sweep above: sniffed
        // recovery files ride the setting that governs named `.par2`,
        // and since §64 that is a recoverable, parked delete. Flag read
        // once at the sweep's entry.
        let recoverable = crate::smart::cleanup_recoverable();
        let staging = crate::smart::trash_staging_dir(out_dir);
        for p in nzbkit::par2repair::sniffed_packet_files(out_dir).unwrap_or_default() {
            let is_payload = p
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .is_some_and(|n| covered.contains(&n));
            if is_payload {
                continue;
            }
            let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            match crate::smart::remove_swept_file(&p, recoverable, staging.as_deref()) {
                Ok(_) => {
                    freed += len;
                    gone += 1;
                }
                Err(e) => warn!(
                    target: "cleanup",
                    "could not remove {} - {e}",
                    p.display()
                ),
            }
        }
        if gone > 0 {
            // "freed" only when the bytes actually left the disk - see
            // the adoption-source sweep above.
            info!(
                target: "cleanup",
                "cleaned up {gone} obfuscated leftover(s), {:.1} MB {}",
                freed as f64 / 1e6,
                if recoverable { "to the Trash" } else { "freed" }
            );
        }
    }
}

/// The job's last word: on a good finish drop the spared metadata,
/// retire the journal and return Ok; otherwise print the diagnostics
/// block the dashboard log ring mirrors and fail with the closest
/// cause. Body is a verbatim move from the orchestrator's tail.
#[expect(clippy::too_many_arguments)]
pub(super) fn finish_job(
    all_good: bool,
    out_dir: &Path,
    incomplete_spared: &[String],
    journal: Arc<nzbkit::journal::Journal>,
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    stats: &[nzbkit::pool::PoolStats],
    reextract_failed: Option<String>,
    incomplete: usize,
    derrs: u64,
    recovery_errs: u64,
    recovery_segments: u64,
    // TODO 282 item 4's seam - see `diag::LossCauses::recovery_unobtainable`.
    // The verdict is the repair ladder's to reach; the ORDERING it lands
    // in is `incomplete_reason`'s, and that half is already built.
    recovery_unobtainable: bool,
    missing_430: &Arc<CauseSplit>,
    takedown_430: &Arc<CauseSplit>,
    retention_skipped: u64,
    retention_skipped_payload: u64,
    transport_failed: &Arc<CauseSplit>,
    transport_sample: &Arc<std::sync::Mutex<Option<String>>>,
    decode_error_sample: &Arc<std::sync::Mutex<Option<String>>>,
    dead_servers: &[String],
    left_servers: &[String],
    slots: &[Arc<FileSlot>],
    stalled: &Arc<std::sync::atomic::AtomicBool>,
    missing_segments: u64,
    total_segments: u64,
    total: u64,
    backbones: &[String],
    post_age_days: u32,
    repair_shortfall: Option<(usize, usize)>,
    extracted: &[String],
    unhealed_slots: Option<&[usize]>,
    extractor: &Arc<nzbkit::extract::Extractor>,
) -> Result<()> {
    // Download complete and verified (or repaired): the journal's job is
    // done. Anything less is a FAILED job - the daemon parks it in history
    // (an *arr must see Failed, never import an incomplete dir) and the
    // journal stays on disk so a retry fetches only what's still missing.
    if all_good {
        // Issue #23: a job that completed WITH something missing has to
        // say so at the end, not only in a per-file line a thousand
        // progress updates ago. These are metadata files no repair could
        // have healed, so the download really is done - but "done" and
        // "everything arrived" are different claims and only one of them
        // is true.
        let kept = drop_spared_metadata(out_dir, incomplete_spared);
        if !kept.is_empty() {
            // The delete IS the safety of the spare (see the fn doc):
            // a holed .nfo looks exactly like a real .nfo, and going
            // green while it sits in the directory hands an *arr the
            // false file the sparing rule exists to withhold. Fail
            // instead, and keep the journal so a retry can finish the
            // cleanup.
            anyhow::bail!(with_build(format!(
                "download complete, but {} partial metadata file(s) could not be \
                 removed: {} - refusing to report success while a holed file that \
                 looks real remains in the output directory (fix permissions and retry)",
                kept.len(),
                kept.join(", ")
            )))
        }
        if let Ok(j) = Arc::try_unwrap(journal) {
            j.remove();
        }
        return Ok(());
    }
    // Failing: print the block a bug report can carry whole. The daemon
    // mirrors stdout into the dashboard log ring, so this is what a user
    // pastes when they say "every file failed".
    print_failure_diagnostics(servers, stats);
    if let Some(why) = reextract_failed {
        anyhow::bail!(with_build(format!(
            "{why} - the verified files are still in the output directory"
        )))
    }
    // Nothing below this point certified the payload, and a one-pass job
    // has already written it: take it out of circulation before the
    // failure returns. See quarantine_partials for why this is a rename
    // and not a delete. Deliberately AFTER the reextract_failed arm,
    // whose files really were verified and whose message says so.
    quarantine_failed_payload(out_dir, extracted, unhealed_slots, slots, extractor);
    // Recovery errors are deliberately NOT an entry condition. M6 added
    // them here so corrupt parity beside a MISSING payload article kept
    // its automatic retry, and the marker that does that lives in the
    // `incomplete > 0` arm - so this clause never needed widening. What
    // widening cost: a failure with every payload article present and
    // only the parity damaged took the `incomplete == 0` opening, which
    // talks about decode/write errors that are zero, does not start
    // "download incomplete" or contain "repair could not complete", and
    // therefore classifies FailKind::Local. Local is not transient, so
    // the one automatic retry - which is exactly what would fetch clean
    // parity - never armed. Left to the repair openings below, which
    // classify Unrepairable and do retry (Codex sweep 6, N3).
    if incomplete > 0 || derrs > 0 {
        let causes = LossCauses {
            // Sweep 8, M7: PAYLOAD-only, every one of them. A cause
            // counter that folds recovery articles in is not a
            // statement about the payload, and every gate below reads
            // these as if it were - see `workers::CauseSplit`.
            missing_430: missing_430.payload(),
            takedown_430: takedown_430.payload(),
            retention_excluded: retention_skipped_payload,
            transport_failed: transport_failed.payload(),
            missing_430_recovery: missing_430.recovery(),
            takedown_430_recovery: takedown_430.recovery(),
            retention_excluded_recovery: retention_skipped - retention_skipped_payload,
            transport_failed_recovery: transport_failed.recovery(),
            recovery_segments,
            recovery_unobtainable,
            transport_sample: transport_sample.lock_ok().clone(),
            decode_sample: decode_error_sample.lock_ok().clone(),
            recovery_errs,
            dead_servers,
            left_servers,
            // Sniffed slots count: "this post carries no PAR2 recovery
            // data" must not be claimed about a post whose recovery set
            // was identified in-stream (issue #14).
            par2_slots: slots.iter().filter(|s| s.is_par2()).count(),
            stalled: stalled.load(Ordering::Relaxed),
            missing_segments,
            total_segments,
            bytes_arrived: total,
            backbones,
            post_age_days,
        };
        anyhow::bail!(with_build(incomplete_reason(incomplete, derrs, &causes)))
    } else if let Some((needed, have)) = repair_shortfall {
        anyhow::bail!(with_build(format!(
            "verification failed and PAR2 repair could not complete: {needed} recovery \
             block(s) needed but the NZB only carries {have}"
        )))
    } else {
        anyhow::bail!(with_build(
            "verification failed and PAR2 repair could not complete".into()
        ))
    }
}

/// Instrument-first: this job's yEnc verified-CRC reuse geometry.
///
/// The decoder verifies a whole-article CRC32 that block verification
/// currently throws away. Reusing it is only sound for an article that is
/// exactly one untrimmed, block-aligned, full PAR2 block from a fresh
/// decode under fast verify, and whether real posts are shaped that way
/// is nobody's guess to make - so every job reports its own geometry and
/// a later decision reads the numbers. Nothing is optimized yet.
///
/// Silent on a job that mapped no spans (no PAR2 set, or no IFSC blocks):
/// there is no ratio to report and a zero line would only be noise.
pub(super) fn print_crc_reuse_geometry(verifier: &Arc<nzbkit::live::LiveVerifier>) {
    let g = verifier.crc_reuse_geometry();
    if g.spans == 0 {
        return;
    }
    let pct = |part: u64, whole: u64| {
        if whole == 0 {
            0.0
        } else {
            part as f64 * 100.0 / whole as f64
        }
    };
    info!(
        target: "crc-geometry",
        "{}/{} articles ({:.1}%) are exactly one PAR2 block; {:.2} GB of {:.2} GB mapped ({:.1}% of bytes)",
        g.qualifying,
        g.spans,
        pct(g.qualifying, g.spans),
        g.qualifying_bytes as f64 / 1e9,
        g.spans_bytes as f64 / 1e9,
        pct(g.qualifying_bytes, g.spans_bytes),
    );
}

/// M15 memory summary - the line benchmarks quote and budgets tune.
/// Lifted out of `get_with_progress` for the size gate.
pub(super) fn print_mem_summary(
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    budget: &nzbkit::mem::MemBudget,
    mem_sampler: &super::workers::MemSampler,
) {
    let (pp_peak, pp_spilled) = verifier.partials_stats();
    info!(
        target: "mem",
        "peak RSS {:.2} GB · holds peak {:.0} MB · verify partials peak {:.0} MB ({pp_spilled} blocks to read-back) · chase trimmed {:.0} MB ({:.0} dropped) · budget {:.2} GB",
        nzbkit::mem::peak_rss().unwrap_or(0) as f64 / 1e9,
        extractor.holds_peak() as f64 / 1e6,
        pp_peak as f64 / 1e6,
        // Direct counter for the chase drop-behind (row 30 of the
        // shape-coverage note): bytes of a chased set spilled back into
        // their own volume files because the set outgrew holds_cap.
        // Nonzero means the set only fit because of the trim.
        extractor.chase_trimmed_bytes() as f64 / 1e6,
        extractor.chase_dropped_bytes() as f64 / 1e6,
        budget.total as f64 / 1e9,
    );
    // Held-bytes backpressure (TODO 94 item E), its own line and only
    // when it engaged, so the `[mem]` summary above keeps its shape for
    // every parser that reads it by name.
    let park_cycles = extractor.holds_park_cycles();
    if park_cycles > 0 {
        info!(
            target: "mem",
            "holds backpressure engaged {park_cycles} time(s): chased articles parked at the pool near the holds cap instead of forfeiting the chase"
        );
    }
    print_mem_floor(&mem_sampler.record);
    // The sampler served this summary; a later job spawns its own, and
    // the token keeps this stop from retiring it if it already has.
    super::workers::stop_mem_sampler(mem_sampler.run);
}

/// Instrument-first: the memory-floor attribution block (memgauge).
///
/// Motivated by the 21 Aug --mem-limit ladder: peak RSS sat near 700 MB
/// with `holds peak` and `partials peak` at 0, insensitive to a 66x
/// budget change and to 100-vs-4 connections - so no tracked tier owned
/// the floor and nobody had ever instrumented it. These lines say where
/// the sampled high-water actually went, with the remainder NAMED as
/// unattributed rather than implied.
///
/// Three deliberate readings:
/// - `retained` = rss minus phys_footprint at the same instant: pages
///   the allocator (mimalloc here) already offered back that ps-style
///   RSS still counts. Allocator policy, not working set.
/// - the attribution sum EXCLUDES `wire est` (an 800 KB-per-pipelined-
///   item estimate that overlaps the raw pool) and `channel` (a subset
///   of raw outstanding) - both print for comparison only.
/// - `unattributed` = footprint minus the summed gauges: binary, thread
///   stacks, rustls, rars working memory, allocator metadata, and
///   anything not yet hooked.
///
/// Reads THIS job's record (F-19): in the daemon the next job's download
/// can already be sampling into its own record while this tail prints.
fn print_mem_floor(record: &nzbkit::memgauge::PeakRecord) {
    use nzbkit::memgauge::Sub;
    let Some(at) = record.peak_attribution() else {
        return; // job shorter than one sampler tick
    };
    let mb = |v: u64| v as f64 / 1e6;
    let g = &at.gauges;
    let attributed: u64 = [
        Sub::RawFree,
        Sub::RawOut,
        Sub::OutFree,
        Sub::OutOut,
        Sub::Par2Capture,
        Sub::JobMeta,
        Sub::VerifierMeta,
        Sub::Holds,
        Sub::RepairScan,
        Sub::RepairWork,
    ]
    .into_iter()
    .map(|s| g.cur_of(s))
    .sum();
    let retained = at.rss.saturating_sub(at.footprint);
    let unattributed = at.footprint.saturating_sub(attributed);
    info!(
        target: "mem-floor",
        "sampled peak rss {:.0} MB · footprint {:.0} MB · allocator retained {:.0} MB",
        mb(at.rss),
        mb(at.footprint),
        mb(retained),
    );
    info!(
        target: "mem-floor",
        "at that sample: raw bodies {:.0} MB ({:.0} out + {:.0} free, {:.0} queued) · decoded {:.0} MB ({:.0} out + {:.0} free) · par2 capture {:.0} MB · job meta {:.0} MB · verifier tables {:.0} MB · holds {:.0} MB · [wire est {:.0} MB] · unattributed {:.0} MB",
        mb(g.cur_of(Sub::RawFree) + g.cur_of(Sub::RawOut)),
        mb(g.cur_of(Sub::RawOut)),
        mb(g.cur_of(Sub::RawFree)),
        mb(g.cur_of(Sub::Channel)),
        mb(g.cur_of(Sub::OutFree) + g.cur_of(Sub::OutOut)),
        mb(g.cur_of(Sub::OutOut)),
        mb(g.cur_of(Sub::OutFree)),
        mb(g.cur_of(Sub::Par2Capture)),
        mb(g.cur_of(Sub::JobMeta)),
        mb(g.cur_of(Sub::VerifierMeta)),
        mb(g.cur_of(Sub::Holds)),
        mb(g.cur_of(Sub::WireEst)),
        mb(unattributed),
    );
    if g.peak_of(Sub::RepairScan) > 0 || g.peak_of(Sub::RepairWork) > 0 {
        info!(
            target: "mem-floor",
            "repair: working set {:.0} MB at the sample / {:.0} MB own peak (syndrome rows + feed batches + rebuilt blocks) · scan reads {:.0} MB at the sample / {:.0} MB own peak (transient whole-volume reads)",
            mb(g.cur_of(Sub::RepairWork)),
            mb(g.peak_of(Sub::RepairWork)),
            mb(g.cur_of(Sub::RepairScan)),
            mb(g.peak_of(Sub::RepairScan)),
        );
    }
    info!(
        target: "mem-floor",
        "own peaks: raw out {:.0} · raw free {:.0} · channel {:.0} · decoded out {:.0} · decoded free {:.0} · capture {:.0} · wire est {:.0} MB",
        mb(g.peak_of(Sub::RawOut)),
        mb(g.peak_of(Sub::RawFree)),
        mb(g.peak_of(Sub::Channel)),
        mb(g.peak_of(Sub::OutOut)),
        mb(g.peak_of(Sub::OutFree)),
        mb(g.peak_of(Sub::Par2Capture)),
        mb(g.peak_of(Sub::WireEst)),
    );
}

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
/// TODO 159 item 1 - `unhealed_slots` narrows this to the files that
/// actually lost bytes. A post whose PAR2 set covers two of three
/// archives, damaged on one covered volume and on the uncovered one,
/// used to have all three payloads withheld: the two that verified and
/// repaired perfectly went out of reach to keep the third from
/// shipping. Withholding what we HAVE is a real cost - it is the
/// difference between a user getting two of three files (SABnzbd's
/// answer on that post) and none (NZBGet's), and the round-4 evidence
/// says two is the better answer.
fn quarantine_failed_payload(
    out_dir: &Path,
    extracted: &[String],
    unhealed_slots: Option<&[usize]>,
    slots: &[Arc<FileSlot>],
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
fn partition_failed_payload(
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
fn held_downloaded_files(
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
fn drop_spared_metadata(out_dir: &Path, spared: &[String]) -> Vec<String> {
    if spared.is_empty() {
        return Vec::new();
    }
    let mut gone = Vec::new();
    let mut kept = Vec::new();
    for name in spared {
        let p = out_dir.join(nzbkit::disk::sanitize_filename(name));
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

/// Everything the run still has to do once the wire has gone quiet:
/// post-drain accounting, the settle/repair ladder, the extraction
/// summary, the disk-unpack tail and the journal's retirement. A
/// verbatim move out of the orchestrator (TODO 106).
///
/// The network drain is `get_with_progress`'s natural seam - nothing
/// above this line has finished, nothing below it is still filling
/// slots from the pool - and this file is named for the half below it.
/// Taken because the three self-contained cuts of 375e381b left the
/// function 27 lines under the 500-line ceiling, and its whole recorded
/// history is regrowth: round 5 trimmed it to 478 and it was back over
/// 500 within two days. The long argument list is the house shape here,
/// not an accident: `finish_job` below takes 26 and
/// `settle_verify_repair` 24, and a bundle struct costs the same lines
/// at the call site plus a definition to keep in step.
#[expect(clippy::too_many_arguments)]
pub(super) async fn finish_run(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    stats: &[nzbkit::pool::PoolStats],
    nzb: &Arc<Nzb>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    sniff: &Arc<SniffCtl>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    journal: Arc<nzbkit::journal::Journal>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    decode_errors: &Arc<AtomicU64>,
    retention_excluded: &Arc<CauseSplit>,
    decoded_bytes: &Arc<AtomicU64>,
    missing_430: &Arc<CauseSplit>,
    takedown_430: &Arc<CauseSplit>,
    transport_failed: &Arc<CauseSplit>,
    transport_sample: &Arc<std::sync::Mutex<Option<String>>>,
    decode_error_sample: &Arc<std::sync::Mutex<Option<String>>>,
    stalled: &Arc<std::sync::atomic::AtomicBool>,
    pending_r: &std::sync::Mutex<PendingR>,
    elapsed: std::time::Duration,
    bootstrap_vol: Option<usize>,
    resume_vols: &HashMap<usize, PathBuf>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    restored: &nzbkit::journal::Restored,
    fast_verify: bool,
    par_cleanup: bool,
    password: Option<String>,
    resuming: bool,
    no_extract: bool,
    resume_map: bool,
    eat_consent: bool,
    note_activity: &(dyn Fn(&'static str) + Sync),
    cancel: Option<&crate::repair::SideCancel>,
    hub: &Option<Arc<StreamHub>>,
    stream_owner: &str,
    budget: &nzbkit::mem::MemBudget,
    mem_sampler: &super::workers::MemSampler,
) -> Result<()> {
    // Post-drain accounting: see take_census. The destructure keeps every
    // downstream read on the same names the inline code used.
    let Census {
        total,
        dead_servers,
        left_servers,
        backbones,
        post_age_days,
        sniff_bootstrap,
        incomplete,
        incomplete_spared,
        missing_segments,
        total_segments,
        sparse_slots,
        recovery_errs,
        derrs,
        retention_skipped,
        retention_skipped_payload,
        recovery_missing,
        recovery_segments,
    } = take_census(
        servers,
        stats,
        nzb,
        slots,
        sniff,
        verifier,
        extractor,
        decode_errors,
        retention_excluded,
        decoded_bytes,
        elapsed,
    );

    // Settle verification and the repair ladder: see get/settle.rs. The
    // destructure keeps every downstream read on the inline names.
    let SettleVerdict {
        all_good,
        reextract_failed,
        repair_shortfall,
        deferred_renames,
        mut published_names,
        sniff_covered,
        unhealed_slots,
        repaired,
    } = settle_verify_repair(
        verifier,
        extractor,
        &journal,
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
        par_cleanup,
        password.as_deref(),
        incomplete,
        derrs,
        &sparse_slots,
        recovery_errs,
        recovery_missing,
        &note_activity,
        cancel,
    )
    .await?;

    // finish() is where a chase that FAILED demotes (chase_finish ->
    // fallback_group). If its trim had been dropping, the materialized
    // volumes have holes: re-fetch them now, before the deferred
    // renames below take the slots' posted names away and before the
    // unpack ladder reads the files (see get/dropped.rs).
    let ex_report = extractor.finish()?;
    super::dropped::refetch_dropped_volumes(
        extractor, slot_file, servers, nzb, out_dir, buf_pool, cancel,
    )
    .await?;
    // Extraction summary: see report_extraction in get/tail.rs.
    let (ex_report, outer_vol_stems, final_shape) = report_extraction(
        extractor,
        ex_report,
        &deferred_renames,
        &mut published_names,
        out_dir,
    )?;

    // finish() is where end-of-download demotes fire (the non-uniform
    // store set, the CRC gate, settle_unclassified), and their hold
    // drains surface late placements for articles still parked from the
    // network phase. Sweep them into the journal now - drain_network's
    // final flush ran BEFORE finish(), so without this pass a retry
    // refetched every held article whose bytes the materialized volumes
    // already hold (measured 13 Aug 2026: 9 of the 10 articles a
    // volumes-on-disk retry still pulled were exactly these).
    workers::flush_pending_r(pending_r, extractor, &journal);
    journal.flush();

    // Second late-attach read (C1): the settle/repair phase between the
    // network drain and this ladder runs for minutes on a big damaged
    // set, and a password typed during it must not miss this job too.
    let password: Option<String> = hub
        .as_ref()
        .and_then(|h| h.late_password_for(stream_owner))
        .or(password);
    // Everything from here to the end of `unpack_tail` is unpack work
    // (the disk-side ladders below, or the nested second pass), and the
    // token says so. It is retired the moment that call returns - see
    // below.
    // The disk-unpack tail (eat-arm, unrar ladder, nested pass): see
    // get/tail.rs. Off the scheduler core (Codex sweep 8 Aug H11): the
    // tail is minutes of synchronous unrar work plus parked waits for
    // the heavy-CPU permit and the §129 disk admission, and all of it
    // used to run directly on this task's runtime worker - freezing
    // sockets, timers and the API for the duration, and deadlocking
    // outright when the permit holder needed the same worker to
    // finish. `off_worker` (block_in_place, not spawn_blocking) keeps
    // the tail on THIS thread, which the eat-arm's and the need
    // ledger's thread-locals both rely on.
    let UnpackVerdict {
        all_good,
        reextract_failed,
    } = crate::lanegate::off_worker(|| {
        unpack_tail(
            extractor,
            slots,
            restored,
            &ex_report,
            &final_shape,
            &outer_vol_stems,
            out_dir,
            password.as_deref(),
            resuming,
            no_extract,
            resume_map,
            eat_consent,
            &note_activity,
            hub,
            stream_owner,
            all_good,
            reextract_failed,
            repaired,
            sniff_covered.as_ref(),
        )
    })?;
    // Unpacking is over. The token used to be left saying "extracting"
    // from here to the end of the JOB - through this run's own sweeps
    // and, in the daemon, through the whole post-processing tail behind
    // it, because only `park` ever clears the entry. A user watching a
    // finished download was told "unpacking" for minutes of work that
    // was nothing of the kind. `finalizing` is the same word the queue
    // payload falls back to when no token is set, so this asserts what
    // was already the intended reading rather than inventing a stage.
    note_activity("finalizing");
    // M15 memory summary - the line benchmarks quote and budgets tune:
    // see print_mem_summary in get/tail.rs.
    print_mem_summary(verifier, extractor, budget, mem_sampler);
    // Instrument-first, no behaviour: see print_crc_reuse_geometry.
    print_crc_reuse_geometry(verifier);

    // Issue #14 tail - the sniffed-leftover sweep: see get/tail.rs.
    sweep_sniffed_leftovers(all_good, par_cleanup, sniff, sniff_covered, out_dir);

    // Retire the journal on a good finish; otherwise print the
    // diagnostics block and fail with the closest cause: see
    // finish_job in get/tail.rs.
    finish_job(
        all_good,
        out_dir,
        &incomplete_spared,
        journal,
        servers,
        stats,
        reextract_failed,
        incomplete,
        derrs,
        recovery_errs,
        recovery_segments,
        // Nothing produces this yet: the download-time counters above are
        // all the evidence this run has, and on the 24 Aug incident they
        // were all zero because the recovery volumes were DEFERRED and
        // the fetch that failed ran in the repair ladder. TODO 282 item
        // 4 owns that fetch and the yield gate that ends it; this is
        // where its verdict arrives.
        false,
        missing_430,
        takedown_430,
        retention_skipped,
        retention_skipped_payload,
        transport_failed,
        transport_sample,
        decode_error_sample,
        &dead_servers,
        &left_servers,
        slots,
        stalled,
        missing_segments,
        total_segments,
        total,
        &backbones,
        post_age_days,
        repair_shortfall,
        &ex_report
            .extracted
            .iter()
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>(),
        unhealed_slots.as_deref(),
        extractor,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn tdir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-get-tail-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn an_empty_spared_list_is_a_no_op() {
        // Never-created directory: an empty list must return before any IO.
        drop_spared_metadata(Path::new("/nonexistent/nzbfast-test"), &[]);
    }

    /// The spared partial is removed; a spared name that was never
    /// written at all (NotFound) is the same wanted outcome.
    #[test]
    fn spared_partials_are_removed_and_notfound_is_success() {
        let d = tdir("spared");
        std::fs::write(d.join("a.nfo"), b"partial").unwrap();
        let kept =
            drop_spared_metadata(&d, &["a.nfo".to_string(), "never-written.nfo".to_string()]);
        assert!(
            !d.join("a.nfo").exists(),
            "the holed partial must be deleted"
        );
        assert!(kept.is_empty(), "both outcomes are success: {kept:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A spared partial that CANNOT be removed must come back in the
    /// kept list - the caller refuses to complete on a non-empty one,
    /// because the surviving file is a zero-holed fake that looks like
    /// a real .nfo to an *arr (the exact artifact the delete exists to
    /// prevent). Going green regardless was the 5 Aug sweep's H3.
    #[test]
    #[cfg(unix)]
    fn an_unremovable_spared_partial_is_reported_not_swallowed() {
        use std::os::unix::fs::PermissionsExt;
        let d = tdir("spared-ro");
        std::fs::write(d.join("a.nfo"), b"partial").unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();
        let kept = drop_spared_metadata(&d, &["a.nfo".to_string()]);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(kept, vec!["a.nfo".to_string()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A traversal name is neutered by sanitize_filename: the file the
    /// raw join would have hit, OUTSIDE the output dir, survives.
    #[test]
    fn a_traversal_name_cannot_reach_outside_the_dir() {
        let parent = tdir("traverse");
        let out = parent.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(parent.join("evil.nfo"), b"keep me").unwrap();
        drop_spared_metadata(&out, &["../evil.nfo".to_string()]);
        assert!(
            parent.join("evil.nfo").exists(),
            "sanitize_filename must keep the delete inside the output dir"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// Drive finish_job with everything healthy except the overrides.
    fn run_finish(
        dir: &Path,
        all_good: bool,
        reextract_failed: Option<String>,
        incomplete: usize,
        derrs: u64,
        repair_shortfall: Option<(usize, usize)>,
    ) -> Result<()> {
        run_finish_ex(
            dir,
            all_good,
            reextract_failed,
            incomplete,
            derrs,
            repair_shortfall,
            &[],
        )
    }

    /// The same, with the direct-extracted payload list the quarantine
    /// pass reads.
    fn run_finish_ex(
        dir: &Path,
        all_good: bool,
        reextract_failed: Option<String>,
        incomplete: usize,
        derrs: u64,
        repair_shortfall: Option<(usize, usize)>,
        extracted: &[String],
    ) -> Result<()> {
        run_finish_full(
            dir,
            all_good,
            reextract_failed,
            incomplete,
            derrs,
            repair_shortfall,
            extracted,
            &[],
            &Arc::new(nzbkit::extract::Extractor::new(dir, 0, true)),
        )
    }

    /// The same, with the recovery-error count the census hands over.
    fn run_finish_recovery(
        dir: &Path,
        incomplete: usize,
        derrs: u64,
        recovery_errs: u64,
    ) -> Result<()> {
        let (j, _) = nzbkit::journal::Journal::open(dir, b"<nzb/>").unwrap();
        finish_job(
            false,
            dir,
            &[],
            Arc::new(j),
            &[],
            &[],
            None,
            incomplete,
            derrs,
            recovery_errs,
            0,
            false,
            &Arc::new(CauseSplit::default()),
            &Arc::new(CauseSplit::default()),
            0,
            0,
            &Arc::new(CauseSplit::default()),
            &Arc::new(std::sync::Mutex::new(None)),
            &Arc::new(std::sync::Mutex::new(None)),
            &[],
            &[],
            &[],
            &Arc::new(std::sync::atomic::AtomicBool::new(false)),
            0,
            0,
            0,
            &[],
            0,
            None,
            &[],
            None,
            &Arc::new(nzbkit::extract::Extractor::new(dir, 0, true)),
        )
    }

    /// The same again, with the slots and extractor the downloaded-file
    /// quarantine reads.
    #[expect(clippy::too_many_arguments)]
    fn run_finish_full(
        dir: &Path,
        all_good: bool,
        reextract_failed: Option<String>,
        incomplete: usize,
        derrs: u64,
        repair_shortfall: Option<(usize, usize)>,
        extracted: &[String],
        slots: &[Arc<FileSlot>],
        extractor: &Arc<nzbkit::extract::Extractor>,
    ) -> Result<()> {
        let (j, _) = nzbkit::journal::Journal::open(dir, b"<nzb/>").unwrap();
        finish_job(
            all_good,
            dir,
            &[],
            Arc::new(j),
            &[],
            &[],
            reextract_failed,
            incomplete,
            derrs,
            0,
            0,
            false,
            &Arc::new(CauseSplit::default()),
            &Arc::new(CauseSplit::default()),
            0,
            0,
            &Arc::new(CauseSplit::default()),
            &Arc::new(std::sync::Mutex::new(None)),
            &Arc::new(std::sync::Mutex::new(None)),
            &[],
            &[],
            slots,
            &Arc::new(std::sync::atomic::AtomicBool::new(false)),
            0,
            0,
            0,
            &[],
            0,
            repair_shortfall,
            extracted,
            // No settle claim: the whole-job quarantine, which is what
            // every case below is about.
            None,
            extractor,
        )
    }

    /// Codex sweep 6, N3: damage confined to the RECOVERY volumes must
    /// keep the retry that fetches clean parity.
    ///
    /// M6 taught the retry-preserving marker about recovery errors,
    /// which was right, and also put them in this clause's entry
    /// condition, which was not: with every payload article present and
    /// decoded (`incomplete == 0`, `derrs == 0`) the message that comes
    /// back talks about decode/write errors that are zero and reads as
    /// a LOCAL fault - not transient, so `auto_retry_eligible` never
    /// arms and the failure goes final. This walks the production
    /// chain, census to verdict, because each link was individually
    /// green while the chain was not.
    #[test]
    fn recovery_only_damage_keeps_its_retry() {
        use crate::failkind::{FailKind, fail_kind};
        let d = tdir("recoveryonly");
        let msg = run_finish_recovery(&d, 0, 0, 4).unwrap_err().to_string();
        assert!(
            !msg.contains("decode/write error"),
            "every payload article arrived; this is not a disk problem: {msg}"
        );
        assert!(
            msg.contains("repair could not complete"),
            "corrupt parity is a repair failure: {msg}"
        );
        assert_eq!(
            fail_kind(&msg),
            FailKind::Unrepairable,
            "which classifies as retryable, so fresh parity can be fetched: {msg}"
        );
        assert!(
            fail_kind(&msg).transient(),
            "and Local would suppress the one automatic retry entirely"
        );

        // The M6 shape itself must be untouched: a MISSING payload
        // article beside corrupt parity still opens "download
        // incomplete" and still carries the retry-preserving marker.
        let both = run_finish_recovery(&d, 1, 0, 4).unwrap_err().to_string();
        assert!(both.starts_with("download incomplete"), "{both}");
        assert!(
            both.contains("damaged articles rather than absent ones"),
            "M6's marker still fires for the shape it was written for: {both}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A good finish retires the journal and returns Ok.
    #[test]
    fn a_good_finish_retires_the_journal() {
        let d = tdir("good");
        assert!(run_finish(&d, true, None, 0, 0, None).is_ok());
        assert!(
            !d.join(".nzbfast.journal").exists(),
            "the journal's job is done on a verified finish"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The four failure arms are ranked: reextract beats incomplete and
    /// derrs, which beat repair_shortfall, which beats the bare verdict.
    #[test]
    fn failure_arms_are_ranked() {
        let d = tdir("ranked");
        let msg = |r: Result<()>| r.unwrap_err().to_string();
        // reextract_failed wins over everything behind it.
        let m = msg(run_finish(
            &d,
            false,
            Some("boom".into()),
            3,
            2,
            Some((9, 1)),
        ));
        assert!(m.contains("boom"), "{m}");
        assert!(m.contains("still in the output directory"), "{m}");
        // incomplete files beat the repair-shortfall arm.
        let m = msg(run_finish(&d, false, None, 1, 0, Some((9, 1))));
        assert!(m.contains("download incomplete"), "{m}");
        assert!(!m.contains("recovery block"), "{m}");
        // derrs alone also beat the shortfall arm.
        let m = msg(run_finish(&d, false, None, 0, 2, Some((9, 1))));
        assert!(m.contains("could not write the download"), "{m}");
        // The shortfall arm names its arithmetic.
        let m = msg(run_finish(&d, false, None, 0, 0, Some((9, 1))));
        assert!(m.contains("9 recovery"), "{m}");
        assert!(m.contains("carries 1"), "{m}");
        // Nothing else to say: the bare verdict.
        let m = msg(run_finish(&d, false, None, 0, 0, None));
        assert!(
            m.contains("verification failed and PAR2 repair could not complete"),
            "{m}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The advG lesson (torture round, 12 Aug): a post carrying an
    /// article nobody has fails correctly and USED TO leave `g.bin` -
    /// exactly the payload's name, exactly its size, a zero-filled hole
    /// in the middle - sitting in the output directory, where an *arr
    /// importing on name and size takes it. SABnzbd and NZBGet leave
    /// nothing. Every failing arm has to move it aside; the bytes stay
    /// (they are the retry's resume state) but the NAME must not.
    #[test]
    fn every_failing_arm_takes_the_unverified_payload_out_of_circulation() {
        let suffix = nzbkit::journal::PARTIAL_SUFFIX;
        // One case per failure arm of finish_job, each with its own
        // directory so the arms cannot cover for each other.
        for (label, incomplete, derrs, shortfall) in [
            ("missing-articles", 1usize, 0u64, None),
            ("decode-errors", 0, 2, None),
            ("repair-shortfall", 0, 0, Some((9usize, 1usize))),
            ("bare-verify", 0, 0, None),
        ] {
            let d = tdir(&format!("quarantine-{label}"));
            std::fs::write(d.join("payload.mkv"), b"holed").unwrap();
            assert!(
                run_finish_ex(
                    &d,
                    false,
                    None,
                    incomplete,
                    derrs,
                    shortfall,
                    &["payload.mkv".to_string()]
                )
                .is_err(),
                "{label} must still fail"
            );
            assert!(
                !d.join("payload.mkv").exists(),
                "{label}: the payload name must not survive a failed job"
            );
            assert!(
                d.join(format!("payload.mkv{suffix}")).exists(),
                "{label}: the bytes must be kept for the retry, not deleted"
            );
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// The one failing arm that must NOT touch anything: its files were
    /// verified, and its own message tells the user they are still in
    /// the output directory. Renaming them aside would make that
    /// sentence a lie and take a good payload away from the user over a
    /// re-extract that failed for a different reason.
    #[test]
    fn a_failed_reextract_keeps_its_verified_files_where_the_message_says() {
        let d = tdir("quarantine-reextract");
        std::fs::write(d.join("payload.mkv"), b"verified").unwrap();
        let m = run_finish_ex(
            &d,
            false,
            Some("boom".into()),
            3,
            2,
            None,
            &["payload.mkv".to_string()],
        )
        .unwrap_err()
        .to_string();
        assert!(m.contains("still in the output directory"), "{m}");
        assert!(
            d.join("payload.mkv").exists(),
            "verified files must stay under their own name"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A job that SUCCEEDS is untouched - the whole point is that the
    /// user gets the file. Belt to the `all_good` early return.
    #[test]
    fn a_good_job_keeps_its_payload_under_its_own_name() {
        let d = tdir("quarantine-good");
        std::fs::write(d.join("payload.mkv"), b"whole").unwrap();
        assert!(run_finish_ex(&d, true, None, 0, 0, None, &["payload.mkv".to_string()]).is_ok());
        assert!(d.join("payload.mkv").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// TODO 159 item 1, the advYB shape as the partition sees it: three
    /// archives, damage that survived repair on the third alone. The two
    /// the repair proved whole go out; the third is withheld.
    #[test]
    fn only_the_unhealed_archives_payload_is_withheld() {
        let d = tdir("quarantine-perfile");
        let ex = Arc::new(nzbkit::extract::Extractor::new(&d, 3, true));
        for (slot, vol, inner) in [(0usize, "c1.rar", "yb1.bin"), (1, "c2.rar", "yb2.bin")] {
            let data = vec![slot as u8 + 1; 40_000];
            let v = nzbkit::rar::fixtures::rar5_volume(&[(inner, 40_000, &data, false, false)]);
            feed_volume(&ex, slot, vol, &v);
        }
        let bare = vec![9u8; 40_000];
        let v = nzbkit::rar::fixtures::rar5_volume(&[("yb3.bin", 40_000, &bare, false, false)]);
        feed_volume(&ex, 2, "bare.rar", &v);
        ex.finish().unwrap();
        let extracted: Vec<String> = ["yb1.bin", "yb2.bin", "yb3.bin"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (hold, spare) = partition_failed_payload(&extracted, Some(&[2]), &ex);
        assert_eq!(spare, vec!["yb1.bin".to_string(), "yb2.bin".to_string()]);
        assert_eq!(hold, vec!["yb3.bin".to_string()]);
        // No claim from settle, or a name the extractor cannot speak
        // for: everything is withheld, which is the pre-159 behaviour
        // and the safe direction.
        let (hold, spare) = partition_failed_payload(&extracted, None, &ex);
        assert_eq!(hold.len(), 3);
        assert!(spare.is_empty());
        let stranger = vec!["from-a-nested-level.mkv".to_string()];
        let (hold, spare) = partition_failed_payload(&stranger, Some(&[2]), &ex);
        assert_eq!(hold, stranger, "an unattributable name is never spared");
        assert!(spare.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Feed one whole volume into a slot, in order.
    fn feed_volume(ex: &nzbkit::extract::Extractor, slot: usize, name: &str, vol: &[u8]) {
        for off in (0..vol.len()).step_by(7000) {
            let end = (off + 7000).min(vol.len());
            ex.write(slot, name, vol.len() as u64, off as u64, &vol[off..end])
                .unwrap();
        }
    }

    /// A FileSlot with the given census; everything else healthy.
    fn census_slot(is_par2: bool, missing: usize) -> Arc<FileSlot> {
        Arc::new(FileSlot {
            hint: String::new(),
            is_par2_main: is_par2,
            sample_skipped: false,
            par2_sniffed: std::sync::atomic::AtomicBool::new(false),
            total_segments: 1,
            remaining: AtomicUsize::new(0),
            missing: AtomicUsize::new(missing),
            errors: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(None),
        })
    }

    /// TODO 159 item 1c, the advG shape: a failing finish must take the
    /// downloaded files out of circulation too, or the completed folder
    /// keeps four real-named volumes of a job whose verdict says Failed
    /// (SABnzbd and NZBGet park the same bytes out of sight). A
    /// materialized volume is held even when its own bytes are whole -
    /// its deliverable was the extraction, which never happened. A
    /// plain file that provably arrived whole is its OWN deliverable
    /// and stays; a holed plain file and a par2 go aside.
    #[test]
    fn a_failing_finish_holds_downloaded_volumes_and_spares_proven_plain_files() {
        let suffix = nzbkit::journal::PARTIAL_SUFFIX;
        let d = tdir("quarantine-volumes");
        let ex = Arc::new(nzbkit::extract::Extractor::new(&d, 4, true));
        // Slot 0: first volume of a split set whose successor never
        // arrives - the mapper demotes it and materializes the volume
        // file on disk, exactly advG's "volumes on disk" fallback.
        let data = vec![7u8; 40_000];
        let vol = nzbkit::rar::fixtures::rar5_volume(&[("g.bin", 80_000, &data, false, true)]);
        feed_volume(&ex, 0, "advG.part1.rar", &vol);
        // Slot 1: a plain file that arrived complete.
        feed_volume(&ex, 1, "whole.bin", &vec![3u8; 10_000]);
        // Slot 2: a plain file with a hole (half its declared range).
        let half = vec![5u8; 10_000];
        ex.write(2, "holed.bin", 20_000, 0, &half).unwrap();
        // Slot 3: a complete par2 - recovery data, never a deliverable.
        feed_volume(&ex, 3, "set.par2", &vec![0x50u8; 4_000]);
        let _ = ex.finish();
        let vol_path = ex.slot_path(0).expect("the demoted volume materializes");
        assert!(vol_path.exists(), "the volume file must be on disk");
        let slots = [
            census_slot(false, 0),
            census_slot(false, 0),
            census_slot(false, 1),
            census_slot(true, 0),
        ];
        assert!(
            run_finish_full(&d, false, None, 1, 0, None, &[], &slots, &ex).is_err(),
            "the job must still fail"
        );
        let renamed = |p: &Path| {
            let mut q = p.as_os_str().to_owned();
            q.push(suffix);
            !p.exists() && PathBuf::from(q).exists()
        };
        assert!(
            renamed(&vol_path),
            "a whole volume of a failed set is furniture and must go aside"
        );
        assert!(
            d.join("whole.bin").exists(),
            "a plain file that provably arrived whole is delivered, not withheld"
        );
        assert!(
            renamed(&d.join("holed.bin")),
            "a holed plain file wearing its real name is the false artifact"
        );
        assert!(
            renamed(&d.join("set.par2")),
            "recovery data for a failed recovery is spent evidence"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// With a settle claim the claim wins the plain-file question in
    /// both directions: a proved plain file is spared without
    /// re-deriving its census, an unhealed one is held despite a clean
    /// census - and a volume is held either way.
    #[test]
    fn the_settle_claim_decides_which_downloaded_files_are_held() {
        let d = tdir("quarantine-vol-claim");
        let ex = Arc::new(nzbkit::extract::Extractor::new(&d, 3, true));
        let data = vec![7u8; 40_000];
        let vol = nzbkit::rar::fixtures::rar5_volume(&[("g.bin", 80_000, &data, false, true)]);
        feed_volume(&ex, 0, "set.part1.rar", &vol);
        feed_volume(&ex, 1, "proved.bin", &vec![1u8; 8_000]);
        feed_volume(&ex, 2, "unhealed.bin", &vec![2u8; 8_000]);
        let _ = ex.finish();
        let slots = [
            census_slot(false, 0),
            census_slot(false, 0),
            census_slot(false, 0),
        ];
        let names = |claim: Option<&[usize]>| -> Vec<String> {
            held_downloaded_files(&slots, claim, &ex)
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect()
        };
        let held = names(Some(&[2]));
        assert!(held.iter().any(|n| n.contains("part1")), "{held:?}");
        assert!(held.contains(&"unhealed.bin".to_string()), "{held:?}");
        assert!(!held.contains(&"proved.bin".to_string()), "{held:?}");
        // No claim: the volume is still held, both whole plain files
        // are spared by their own census.
        let held = names(None);
        assert!(held.iter().any(|n| n.contains("part1")), "{held:?}");
        assert!(!held.contains(&"proved.bin".to_string()), "{held:?}");
        assert!(!held.contains(&"unhealed.bin".to_string()), "{held:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
