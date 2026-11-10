//! Spending a password we hold on a locked archive: the unlock ladder
//! itself - [`unlock`] and the non-RAR shapes underneath it - plus the
//! probes that say whether there is anything locked left to spend one
//! on.
//!
//! A top-level module rather than a child of `smart` since the
//! crate-split prep (step 1 of
//! research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md). Nothing here is
//! about filing: it drives `rarfix`'s three extract arms and
//! `repair::reextract_dir_why`, and its callers are all in the daemon.
//! Sitting inside `smart` is what made the filing code reach up into the
//! extractor and the repair ladder, which is the one edge that made
//! those modules need each other. The operator's passwords FILE is
//! `crate::pwfile`; the try-order heuristic over it stays in
//! `smart::pwassoc`, which is about what we remember, not about what we
//! spend.

use std::path::{Path, PathBuf};
use tracing::info;

// The operator's passwords file moved to `crate::pwfile` in the
// crate-split prep - see the module note there. `smart` re-exports both
// doors, so the daemon's settings path and the CLI spell them as before.

/// First password-protected volume in a completed job's folder (top
/// level), or None. Merely-compressed leftovers don't count - those
/// failed for other reasons (e.g. no unrar) and a password won't help.
///
/// A RAR volume is recognised by NAME or by its `Rar!` magic under a
/// numeric or rollover extension, the same predicate
/// `rarfix::passwords::first_encrypted_rar` uses, because that
/// is the shape the field posts: a split set named `movie.001`,
/// `movie.002`, ... or an obfuscated one. This used to require a final
/// extension of exactly `rar`, so a locked `.001` set was invisible to
/// [`encrypted_archive`] (no `password_required`, no key affordance)
/// and, with a locked zip or 7z beside it, [`unlock`] spent the password
/// on the other container and never tried the RAR at all (Gemini 14 Oct
/// sweep H5).
pub fn encrypted_rar(dir: &Path) -> Option<PathBuf> {
    crate::rarfix::passwords::first_encrypted_rar(dir)
}

/// First password-protected archive of ANY kind we can unlock (RAR
/// volume or 7-Zip container) left in a finished job's folder.
///
/// This is what post-processing must ask, and it used to ask
/// [`encrypted_rar`]: a header-encrypted 7z therefore never set
/// `password_required`, and the job died as a generic local "could not
/// be unpacked" with the real reason (`PasswordRequired`) visible only in
/// the log. RAR keeps first claim so the common case pays no extra
/// probe, and so the name reported to the UI stays the one the existing
/// copy expects.
///
/// # The 7z arm asks the EXTRACTOR what the containers are
///
/// It used to scan the directory itself for files whose final extension
/// was exactly `7z`, and that is not the shape the field posts. A split
/// set is `set.7z.001`, `set.7z.002`, ... - every part's extension is a
/// NUMBER, so the loop examined none of them - and an obfuscated
/// container carries no meaningful extension at all. Both are grouped
/// perfectly well by [`crate::rarfix::collect_sevenz_archives`], which is
/// what `LockedNonRar` below (then `unlock_non_rar`) already spends a password on, so the
/// probe and the spend disagreed about what was even in the folder: the
/// job reported a generic "could not be unpacked", `settle_locked_failure`
/// returned at the `None` here before setting the password state, and the
/// one remedy that would have worked was never offered. (N2,
/// reports/code-audit-2026-09-17.)
///
/// The parts are probed as ONE byte space and not one at a time, because
/// a 7z container's end header - which is what answers the password
/// question - sits at the END of the set, so part one on its own says
/// nothing.
pub fn encrypted_archive(dir: &Path) -> Option<PathBuf> {
    if let Some(rar) = encrypted_rar(dir) {
        return Some(rar);
    }
    encrypted_non_rar(dir)
}

/// [`encrypted_archive`] past its RAR arm: the first locked 7z set or
/// zip, by the same evidence. Its own function so [`locked_left`] can
/// judge the RAR volumes against a snapshot and ask this half as is.
fn encrypted_non_rar(dir: &Path) -> Option<PathBuf> {
    let mut sevenz = crate::rarfix::collect_sevenz_archives(dir).unwrap_or_default();
    // Stable across a directory read that hands its entries back in any
    // order: the NAME a job reports is the one the UI shows.
    sevenz.sort();
    if let Some(z) = sevenz
        .into_iter()
        // A set an earlier unlock already opened is not a lock: see
        // `LockedNonRar`, which skips it on the same evidence.
        .find(|parts| {
            crate::rarfix::sevenz_set_needs_password(parts) && !sevenz_already_unlocked(dir, parts)
        })
        .and_then(|parts| parts.into_iter().next())
    {
        return Some(z);
    }
    // Encrypted zip, last of the three. It was invisible here until the
    // 12 Aug correctness round: a job whose only locked archive was a zip
    // never set `password_required`, so the 🔑 affordance was missing on
    // the one job whose entire remedy is a password. Last because it is
    // the rarest lock on Usenet and the scan reads each container's
    // central directory - RAR and 7z answer from a header.
    //
    // A container whose content already sits beside it is NOT reported:
    // the disk ladder unlocks encrypted zips from the passwords file
    // now, and the spent container survives whenever two sets share a
    // directory (the intermediate sweep refuses to guess which is
    // consumed). Reporting it asked the tail to unlock what it had
    // already delivered, and would have put a 🔑 on a job with nothing
    // left to unlock.
    nzbkit::zip::scan(dir)
        .into_iter()
        .find(|f| {
            nzbkit::zip::needs_password(&f.parts) && !crate::diag::zip_already_delivered(dir, f)
        })
        .and_then(|f| f.parts.into_iter().next())
}

/// The locked NON-RAR containers in `dir`: every 7-Zip set and every zip
/// that ASKS for a password, collected in one place so [`unlock`] can
/// decide what it owes BEFORE any extraction runs, and so the probe and
/// the spend read the same set.
///
/// Only containers that actually ASK for a password are kept. 7-Zip
/// and zip both ignore a password they do not need, so an unrelated
/// plain container in the same folder (a sample, an obfuscated sidecar -
/// `collect_sevenz_archives` picks those up by magic under any name)
/// extracted cleanly and reported the wrong password as the one that
/// worked: prompt cleared, "the password worked" toast, the locked set
/// still packed.
///
/// That holds for a SPLIT set too. A multipart 7z cannot be probed part
/// by part - its end header lives in the last part - so it used to be
/// attempted unconditionally, and a plain split sidecar (`subs.7z.001`,
/// `subs.7z.002`) beside a locked zip extracted under any password and
/// answered `Some(true)`: the wrong password reported as the one that
/// worked, the zip still locked (Gemini 14 Oct sweep H5). The parts are
/// probed as ONE byte space through
/// [`crate::rarfix::sevenz_set_needs_password`], exactly as
/// [`encrypted_archive`] asks it, so the probe and the spend agree.
///
/// A zip whose content already sits beside it is left out, on the same
/// evidence [`encrypted_archive`] uses
/// ([`crate::diag::zip_already_delivered`]): the extractors never delete
/// a container they spent, so without it a job holding two locked
/// containers under DIFFERENT passwords could never finish - the second
/// password would be tried on the first container, fail, and fail the
/// unlock that had just delivered everything.
///
/// A header-encrypted 7z cannot answer that question from its own bytes:
/// its file list is behind the key, so nothing can say what it would
/// have produced without the password that opened it. Without help, a
/// 7z delivered under one typed password was attempted again under the
/// next and failed it, so a 7z and a zip under two DIFFERENT typed
/// passwords left a prompt no answer could ever clear - a stuck job
/// (Codex 22 Oct sweep F5). So the evidence is WRITTEN when the 7z
/// opens: [`record_sevenz_unlocked`] stamps each part's name, length and
/// mtime into [`UNLOCKED_7Z_MARKER`], and a set whose every part still
/// matches is left out here and in [`encrypted_archive`].
struct LockedNonRar {
    sevenz: Vec<Vec<PathBuf>>,
    zips: Vec<nzbkit::zip::Finding>,
}

impl LockedNonRar {
    fn find(dir: &Path) -> Self {
        let sevenz = crate::rarfix::collect_sevenz_archives(dir)
            .unwrap_or_default()
            .into_iter()
            .filter(|parts| {
                crate::rarfix::sevenz_set_needs_password(parts)
                    && !sevenz_already_unlocked(dir, parts)
            })
            .collect();
        let zips = nzbkit::zip::scan(dir)
            .into_iter()
            .filter(|f| {
                nzbkit::zip::needs_password(&f.parts) && !crate::diag::zip_already_delivered(dir, f)
            })
            .collect();
        Self { sevenz, zips }
    }

    /// The containers an unlock in `dir` has EXPOSED that are still to
    /// open: every locked set [`Self::find`] reports, plus each set -
    /// locked or not - none of whose parts was on disk before the unlock
    /// began (`before`) and which is not delivered yet. Spending the
    /// password on a plain container extracts it like any other; the
    /// password is simply not asked for.
    fn exposed(dir: &Path, before: &std::collections::HashSet<PathBuf>) -> Self {
        let new =
            |parts: &[PathBuf]| !parts.is_empty() && parts.iter().all(|p| !before.contains(p));
        let mut out = Self::find(dir);
        for parts in crate::rarfix::collect_sevenz_archives(dir).unwrap_or_default() {
            if new(&parts) && !sevenz_already_unlocked(dir, &parts) && !out.sevenz.contains(&parts)
            {
                out.sevenz.push(parts);
            }
        }
        for f in nzbkit::zip::scan(dir) {
            if new(&f.parts)
                && !crate::diag::zip_already_delivered(dir, &f)
                && !out.zips.iter().any(|z| z.parts == f.parts)
            {
                out.zips.push(f);
            }
        }
        out
    }

    /// Spend `password` on EVERY container found: 7-Zip sets, then zips.
    /// `None` means there was nothing of either shape to try, which is
    /// what lets the caller tell "no attempt" apart from "attempted and
    /// the password was wrong". `Some(true)` only when every attempted
    /// container extracted.
    ///
    /// Both shapes are attempted whatever the first one answered. This
    /// returned at the first 7z success, so an encrypted 7z beside an
    /// encrypted zip unlocked the 7z, reported the password as working,
    /// and the API cleared `password_required` over a zip it never tried
    /// - even when the SAME password would have opened it (Codex 22 Oct
    /// sweep F5). A failure on one shape does not stop the other either:
    /// what a right password delivers stays delivered, and the answer is
    /// still `Some(false)`, so the prompt stays up for the rest.
    fn spend(&self, dir: &Path, password: &str) -> Option<bool> {
        if self.sevenz.is_empty() && self.zips.is_empty() {
            return None;
        }
        let mut all_ok = true;
        // One set at a time, so the sets that DID open are known and can
        // be stamped as delivered - `extract_sevenz` answers for the whole
        // list, and walks it one set at a time itself.
        for parts in &self.sevenz {
            if crate::rarfix::extract_sevenz(dir, std::slice::from_ref(parts), Some(password)) {
                info!(target: "unlock", "{}: 7-Zip container unlocked", dir.display());
                record_sevenz_unlocked(dir, parts);
            } else {
                all_ok = false;
            }
        }
        if !self.zips.is_empty() {
            if crate::rarfix::extract_zip(dir, &self.zips, Some(password)) {
                info!(target: "unlock", "{}: zip container unlocked", dir.display());
            } else {
                all_ok = false;
            }
        }
        Some(all_ok)
    }
}

/// The delivery record for header-encrypted 7z sets an unlock opened,
/// kept in the job's directory while the job is still locked (see
/// [`LockedNonRar`] for why it has to exist at all).
///
/// In the `.nzbfast` namespace on purpose: every directory walker that
/// could otherwise mistake it for payload - the categorical keep-media
/// sweep, the namer, the script's file list, the extract diff walkers,
/// the manifest - already skips that prefix as the daemon's own state.
/// It outlives its containers by nothing: when [`unlock`] answers `Ok`
/// it drops every line whose part is no longer on disk as the file it
/// stamped, and the file itself once no line is left
/// ([`retire_sevenz_marker`]). A line whose spent 7z is still there is
/// KEPT, for the reason [`encrypted_archive`] skips a delivered zip: a
/// later probe of the same folder would otherwise put a key on a job
/// with nothing left to unlock. So the record goes wherever the spent
/// container goes and no further - if the final move or a cleanup takes
/// the container, the line describes nothing and matches nothing.
///
/// One line per part, `<length>\t<mtime ns>\t<file name>`. A set counts
/// as delivered only when EVERY part matches its line exactly, so a
/// container rewritten under the same name (a retry, a re-download) is
/// a fresh lock again.
pub(crate) const UNLOCKED_7Z_MARKER: &str = ".nzbfast.unlocked-7z";

/// The marker line for one part, or None when it cannot be stamped
/// honestly (unreadable metadata, or a name the line format cannot
/// carry). An unstampable part is simply never recorded, which fails
/// toward asking again rather than toward skipping a lock.
fn sevenz_part_stamp(p: &Path) -> Option<String> {
    let name = p.file_name()?.to_str()?;
    if name.contains(['\t', '\n', '\r']) {
        return None;
    }
    let md = std::fs::metadata(p).ok()?;
    let mtime = md
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(format!("{}\t{mtime}\t{name}", md.len()))
}

/// Did an earlier [`unlock`] in this directory open this 7z set, and is
/// every part still the file it opened?
fn sevenz_already_unlocked(dir: &Path, parts: &[PathBuf]) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join(UNLOCKED_7Z_MARKER)) else {
        return false;
    };
    let lines: std::collections::HashSet<&str> = text.lines().collect();
    !parts.is_empty()
        && parts
            .iter()
            .all(|p| sevenz_part_stamp(p).is_some_and(|s| lines.contains(s.as_str())))
}

/// Stamp a 7z set as delivered. Best effort: a failed write costs the
/// stuck prompt this exists to prevent, never a wrong unlock, so it is
/// logged and nothing more.
fn record_sevenz_unlocked(dir: &Path, parts: &[PathBuf]) {
    use std::io::Write as _;
    let Some(stamps) = parts
        .iter()
        .map(|p| sevenz_part_stamp(p))
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let wrote = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(UNLOCKED_7Z_MARKER))
        .and_then(|mut f| f.write_all(format!("{}\n", stamps.join("\n")).as_bytes()));
    if let Err(e) = wrote {
        tracing::warn!(
            target: "unlock",
            "{}: could not record the unlocked 7z set ({e}) - it will be asked for again",
            dir.display()
        );
    }
}

/// Unlock a password-protected set: unrar with the password, and on
/// success delete the volume files (the unpacked content is the
/// deliverable, matching the engine's post-extraction behavior).
///
/// `Err(None)` is the ordinary answer and means what the `bool` this
/// returned until 22 Aug 2026 meant: this password did not open anything
/// here. `Err(Some(why))` is a refusal that is about the DISK - today
/// only a bomb verdict, raised by the two rungs inside
/// `crate::rarfix::try_unrar_spent_why` - and dropping it here was
/// worse than wrong wording, because the callers are SWEEPS. Every
/// candidate in the operator's passwords file is another extraction
/// attempt against the same full disk, so one bomb refused every
/// password in the file in turn and the job was then reported as having
/// none that worked (`job_finalize.rs`, `job.rs`). A named
/// reason therefore STANDS THE SWEEP DOWN at the first candidate as well
/// as being quoted: there is nothing for a second password to do
/// differently.
///
/// It also stops the fall-through to the non-RAR arm below, for the
/// same reason the nested pass stops at its first refusal: that arm
/// extracts a 7z or a zip, on the disk that has just refused to hold an
/// extraction.
///
/// A `Result` rather than a bool with a `_why` twin beside it, which is
/// the shape `crate::rarfix::try_unrar_spent_why` and
/// [`crate::repair::reextract_dir_why`] took: those two kept their plain
/// wrappers for callers that genuinely only ask "did it unpack", and
/// this function has none left. Every caller composes something the user
/// reads. A fresh bool wrapper here would be a third place for the
/// verdict to be dropped, which is the whole defect this closes.
///
/// An `Ok` also prunes `UNLOCKED_7Z_MARKER` down to the spent 7z sets
/// still on disk, and removes it when there are none
/// (`retire_sevenz_marker`).
///
/// An `Ok` also means NOTHING LOCKED IS LEFT. A container this password
/// opened can publish another locked one (an encrypted 7z inside an
/// encrypted 7z), and nothing behind this call looked: the API cleared
/// `password_required` over an inner archive still packed, and the
/// completed tail read `still_locked` as false and ran the ordinary
/// cleanup, which deletes every `.7z` a cleanup list names - the inner
/// archive was the only copy of the payload (Codex sweep F5, 27 Oct
/// 2026). So the non-RAR arm spends the same password on each layer it
/// exposes, and whatever arm answered, a directory [`encrypted_archive`]
/// still finds a lock in answers `Err(None)`: the sweeps go on to their
/// next candidate (the opened layers are stamped or delivered, so only
/// the inner one is tried), and with none left the job parks locked with
/// its archives spared.
pub fn unlock(dir: &Path, password: &str) -> std::result::Result<(), Option<String>> {
    let locked_before = locked_rar_volumes(dir);
    let mut answer = unlock_all(dir, password);
    if answer.is_ok() && locked_left(dir, &locked_before).is_some() {
        answer = Err(None);
    }
    if answer.is_ok() {
        retire_sevenz_marker(dir);
    }
    answer
}

/// Every password-protected RAR volume directly in `dir`, with the
/// length and mtime it had when this was asked: the predicate
/// [`encrypted_rar`] stops at the first match of, applied to them all.
fn locked_rar_volumes(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .collect();
    paths.sort();
    paths
        .into_iter()
        .filter(|p| {
            (crate::archname::looks_like_named_rar(p)
                || (nzbkit::extract::archive_sniff_eligible(p) && crate::archname::rar_magic(p)))
                && nzbkit::rar::needs_password(p)
        })
        .filter_map(|p| sevenz_part_stamp(&p).map(|s| (p, s)))
        .collect()
}

/// The set a RAR volume belongs to, as the re-extract ladder groups
/// them (`release_stem` of the lowercased name).
fn rar_set_of(p: &Path) -> String {
    let name = p
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    nzbkit::extract::release_stem(&name).to_string()
}

/// What an unlock that answered `Ok` has LEFT locked, judged against the
/// locked RAR volumes that were on disk before it ran (`before`, from
/// [`locked_rar_volumes`]).
///
/// It used to ask [`encrypted_archive`] of the whole directory, which
/// counts every encrypted RAR volume still there - including a volume of
/// the very set this unlock just extracted, whose delete failed (an AV
/// scanner holding it on Windows, EACCES on a NAS share) or that the
/// spent-proof declined to remove. A RIGHT password then read as wrong:
/// the candidate walks went on to the next line, the winner was never
/// recorded, the job parked locked with its payload on disk, and a typed
/// password was told it "did not unlock the archive". Each later
/// candidate also re-ran the extraction over that survivor, which on a
/// RAR4 set (no password check) can overwrite the delivered output
/// (pre-release sweep, 9 Nov 2026).
///
/// So a locked volume still here counts as SPENT only on evidence: it
/// was locked before, it is byte-for-byte the file it was (length and
/// mtime), and another volume of its own set that was locked before is
/// gone - which only the extraction of that set removes. Everything
/// else is still a lock: a set nothing was removed from (a second set
/// this password did not open keeps every volume), and any locked volume
/// that was not there before (a layer this unlock exposed).
///
/// THE STATED LIMIT: a SINGLE-volume set whose one volume survives has
/// no sibling to be evidence for it, and still reads as locked, as it
/// did before. Telling it apart from an untouched set needs the archive
/// opened again, which is the very extraction this exists to avoid.
fn locked_left(dir: &Path, before: &[(PathBuf, String)]) -> Option<PathBuf> {
    let spent_sets: std::collections::HashSet<String> = before
        .iter()
        .filter(|(p, _)| !p.exists())
        .map(|(p, _)| rar_set_of(p))
        .collect();
    let survivor = |p: &Path, stamp: &str| {
        before.iter().any(|(b, s)| b == p && s == stamp) && spent_sets.contains(&rar_set_of(p))
    };
    if let Some((p, _)) = locked_rar_volumes(dir)
        .into_iter()
        .find(|(p, s)| !survivor(p, s))
    {
        return Some(p);
    }
    encrypted_non_rar(dir)
}

/// Every file directly in `dir` the nested pass could try to extract, by
/// the same test `dir_has_nested_extractable` uses - so the unlock can
/// tell the archives it EXPOSED from the ones it was handed.
fn archive_files(dir: &Path) -> std::collections::HashSet<PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| {
            crate::archname::looks_like_named_rar(p) || crate::unpack::is_extractable_archive(p)
        })
        .collect()
}

/// The name of an archive the unlock exposed and did not deliver, if any.
/// A 7z set it opened is stamped and a zip it extracted is checked
/// member by member ([`LockedNonRar::exposed`] is the same test), so what
/// is left is the shape the walk does not take: named RAR volumes, a tar,
/// or a 7z or zip it failed on or never reached.
fn undelivered_exposed(dir: &Path, before: &std::collections::HashSet<PathBuf>) -> Option<String> {
    let name = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned());
    let pending = LockedNonRar::exposed(dir, before);
    if let Some(parts) = pending.sevenz.first() {
        return parts.first().and_then(|p| name(p));
    }
    if let Some(f) = pending.zips.first() {
        return Some(f.name.clone());
    }
    let opened: std::collections::HashSet<PathBuf> = crate::rarfix::collect_sevenz_archives(dir)
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .chain(nzbkit::zip::scan(dir).into_iter().flat_map(|f| f.parts))
        .collect();
    let mut left: Vec<PathBuf> = archive_files(dir)
        .into_iter()
        .filter(|p| !before.contains(p) && !opened.contains(p))
        .collect();
    left.sort();
    left.first().and_then(|p| name(p))
}

/// How many layers of locked 7z or zip one password is spent through.
/// Real releases nest one or two deep; the bound is for a crafted set
/// that unpacks into itself.
const NESTED_UNLOCK_DEPTH: usize = 8;

/// Drop every [`UNLOCKED_7Z_MARKER`] line whose part is gone or is no
/// longer the file it stamped, and the marker once nothing is left.
/// Best effort, like the write: a stale line matches nothing.
fn retire_sevenz_marker(dir: &Path) {
    let marker = dir.join(UNLOCKED_7Z_MARKER);
    let Ok(text) = std::fs::read_to_string(&marker) else {
        return;
    };
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| {
            line.rsplit('\t')
                .next()
                .and_then(|name| sevenz_part_stamp(&dir.join(name)))
                .is_some_and(|s| s == *line)
        })
        .collect();
    if kept.is_empty() {
        let _ = std::fs::remove_file(&marker);
    } else if kept.len() != text.lines().count() {
        let _ = std::fs::write(&marker, format!("{}\n", kept.join("\n")));
    }
}

/// The body of [`unlock`], every return of which is its answer.
fn unlock_all(dir: &Path, password: &str) -> std::result::Result<(), Option<String>> {
    // The non-RAR shapes are decided UP FRONT, not as a fall-through
    // behind `reextract_dir_why`.
    //
    // That ordering is not a style choice. `reextract_dir_why` answers
    // Ok(Ok(())) for a directory holding no RAR volumes at all ("no
    // archive volumes on disk - nothing to re-extract"), which is
    // correct for what it does and fatal as a gate: a directory whose
    // only lock is a 7z or a zip has no RAR volumes BY DEFINITION, so
    // the arms below never ran and this function reported the password
    // as working over a set still packed - the exact failure the
    // obfuscated-RAR branch inside `reextract_dir_why` was added to prevent,
    // reproduced one level up. Observed on advP (12 Aug): "unpacked - 0
    // volume file(s) spent", then "unlocked", with both containers
    // untouched.
    //
    // Precedence matches `encrypted_archive`, which is what named the
    // archive the caller is unlocking: RAR first claim, so a directory
    // holding a locked RAR keeps the whole path below. The non-RAR
    // containers are still COLLECTED here, before anything extracts, and
    // spent after the RAR arm whatever it answers: returning at the RAR
    // success left a locked zip or 7z beside it untried and reported the
    // job unlocked (Codex 22 Oct sweep F5). Collected first so a
    // container the RAR extraction itself publishes is the nested pass's
    // business, not a second spend of this password.
    let before = archive_files(dir);
    let others = LockedNonRar::find(dir);
    if encrypted_rar(dir).is_none()
        && let Some(unlocked) = others.spend(dir, password)
    {
        if !unlocked {
            return Err(None);
        }
        // Each layer the spend exposed gets the same password, the way
        // a release locked twice under one password expects - and so
        // does an UNLOCKED layer it exposed. The walk used to follow
        // locked layers only, so an encrypted 7z holding a plain zip
        // opened its outer layer, found nothing locked, and answered
        // Ok over a payload still packed: the API cleared the prompt,
        // and the tail's ordinary cleanup could delete the zip and the
        // 7z both (6 Nov 2026 sweep F2). A layer it does not open stops
        // the walk; `unlock` then reports the lock that is left.
        for _ in 0..NESTED_UNLOCK_DEPTH {
            if encrypted_rar(dir).is_some()
                || LockedNonRar::exposed(dir, &before).spend(dir, password) != Some(true)
            {
                break;
            }
        }
        // Done means DELIVERED, not merely "nothing locked is left". A
        // new archive still undelivered here is one this walk could not
        // take - a plain RAR, a tar, a layer past the depth bound, or
        // one that failed to extract - and calling that unlocked hands
        // the only copy of the payload to a cleanup. A named refusal
        // instead parks the job with its archives spared and says why.
        // A new LOCKED one is not this arm's to name: `unlock` reports
        // it as the lock that is left.
        if encrypted_archive(dir).is_none()
            && let Some(left) = undelivered_exposed(dir, &before)
        {
            return Err(Some(crate::diag::unlock_left_packed(&left)));
        }
        return Ok(());
    }
    // Native path first: encrypted STORE sets (the obfuscated-release
    // norm) re-extract and AES-decrypt without unrar, deleting their
    // volumes on success. Compressed or RAR4-encrypted sets fall through
    // to unrar inside reextract_dir_why; a wrong password fails both.
    // Volume deletion belongs to the extraction, not to this function.
    // `reextract_dir_why` removes exactly what it CONSUMED on every success path
    // (the streaming pass sweeps the set it fed, the native and unrar paths
    // sweep against a proof-of-output snapshot), so a RAR-named file still
    // present afterwards is one of three things, and deleting any of them is
    // wrong:
    //
    //   - a file the extraction just PUBLISHED - an encrypted outer set whose
    //     payload is the release's own inner RAR set unlocks to
    //     `inner.partNN.rar`, and sweeping them left a Completed job with no
    //     payload at all;
    //   - a volume the spent-proof deliberately refused to delete;
    //   - the volumes of ANOTHER top-level set in the same directory that
    //     this password did not unlock. `reextract_dir_why`'s directory-level
    //     answer is existential - one set unpacking makes it true - so with
    //     encrypted sets A and B and a password for A only, the sweep deleted
    //     B's only copy. That is the shape this whole path exists to protect.
    //
    // So: count what the extraction removed, delete nothing.
    let vol_snapshot = |dir: &Path| -> std::collections::HashSet<PathBuf> {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        let name = p
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase();
                        // .rar plus split continuations (.r00, .r01, …).
                        name.ends_with(".rar")
                            || name.rfind('.').is_some_and(|i| {
                                let t = &name[i + 1..];
                                t.len() >= 3
                                    && t.starts_with('r')
                                    && t[1..].bytes().all(|c| c.is_ascii_digit())
                            })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let before = vol_snapshot(dir);
    // `reextract_dir_why`, not the bool wrapper: an io error is still
    // "this password opened nothing" (as `unwrap_or(false)` always read
    // it), but a bomb verdict is not, and dropping it here is what let
    // one full disk be reported as a whole passwords file of wrong
    // guesses.
    match crate::reextract_dir_why(dir, Some(password)) {
        Ok(Ok(())) => {}
        Ok(Err(Some(why))) => return Err(Some(why)),
        // No RAR set took the password. A directory holding a locked RAR
        // *and* a locked container of another shape skipped the arms
        // above (RAR had first claim) - so they get their turn here, and
        // what they deliver stays delivered. But the answer is still
        // "not unlocked": a locked RAR that this password did not open is
        // still locked, and reporting success because a zip beside it
        // opened is the same false clear as the other way round (F5).
        Ok(Err(None)) | Err(_) => {
            let _ = others.spend(dir, password);
            return Err(None);
        }
    }
    let removed = before.difference(&vol_snapshot(dir)).count();
    info!(
        target: "unlock",
        "{} unpacked - {removed} volume file(s) spent",
        dir.display()
    );
    // The RAR arm unpacked; now the containers of other shapes that were
    // locked before it ran. Any of them refusing this password leaves the
    // job locked - with the RAR payload kept, and its spent volumes gone,
    // so the next password goes to what is still packed.
    if others.spend(dir, password) == Some(false) {
        return Err(None);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header-encrypted 7-Zip container, which is the `-mhe` shape
    /// posted for a locked release: the file list AND the payload are
    /// behind the key, so nothing about it can be read without one.
    fn mhe_bytes(key: &str, data: &[u8]) -> Vec<u8> {
        mhe_named(key, "movie.mkv", data)
    }

    /// [`mhe_bytes`] with the member's name chosen, for a folder that
    /// holds more than one locked container.
    fn mhe_named(key: &str, name: &str, data: &[u8]) -> Vec<u8> {
        use sevenz_rust2::{
            ArchiveEntry, ArchiveWriter, Password, encoder_options::AesEncoderOptions,
        };
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_encrypt_header(true);
        w.set_content_methods(vec![AesEncoderOptions::new(Password::from(key)).into()]);
        w.push_archive_entry(ArchiveEntry::new_file(name), Some(data))
            .unwrap();
        w.finish().unwrap().into_inner()
    }

    /// `bytes` cut into `parts` numbered pieces under `stem`, the way
    /// the field posts a split container: `stem.001`, `stem.002`, ...
    fn split_as(dir: &Path, bytes: &[u8], parts: usize, stem: &str) -> Vec<PathBuf> {
        let cut = bytes.len().div_ceil(parts);
        bytes
            .chunks(cut)
            .enumerate()
            .map(|(i, chunk)| {
                let p = dir.join(format!("{stem}.{:03}", i + 1));
                std::fs::write(&p, chunk).unwrap();
                p
            })
            .collect()
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "nzbfast-unlockpw-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// N2 (reports/code-audit-2026-09-17): a SPLIT encrypted 7z set
    /// reaches the password path.
    ///
    /// The probe scanned for files whose final extension was exactly
    /// `7z`, which every part of `set.7z.001`, `set.7z.002`, ... fails -
    /// their extensions are numbers. So it examined none of them and
    /// answered None, `settle_locked_failure` returned at that None
    /// before setting the password state or trying a single candidate,
    /// and the job died as a generic "an archive in the output directory
    /// could not be unpacked" for a release whose entire remedy is a
    /// password. The unlock ladder beside it had no such blindness - it
    /// has always grouped these through `collect_sevenz_archives` - so
    /// the two halves disagreed about what was in the folder.
    ///
    /// The set is cut into FOUR parts and the key is in the LAST one,
    /// which is where a 7z end header lives: a probe that read part one
    /// and stopped would answer no here.
    #[test]
    fn a_split_encrypted_7z_set_is_seen_as_password_protected() {
        let dir = tmp("split7z");
        let data: Vec<u8> = (0..150_000u32).map(|i| (i * 7 + 3) as u8).collect();
        let parts = split_as(&dir, &mhe_bytes("n2-split-key", &data), 4, "set.7z");
        assert_eq!(parts.len(), 4, "the fixture is a four-part set");

        let found = encrypted_archive(&dir).expect("a split encrypted 7z set is locked");
        assert!(
            parts.contains(&found),
            "{} is not one of the set's parts",
            found.display()
        );
        // The NAME a row would show, which is what the caller reports.
        assert_eq!(
            found.file_name().unwrap().to_string_lossy(),
            "set.7z.001",
            "the first part is the name to show"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// N2's other named shape: the same container posted under a stem
    /// that says nothing about 7z at all (`hash.001`, `hash.002`, ...),
    /// which `collect_obfuscated_sevenz_splits` groups by its head
    /// bytes. The old extension scan could not see this one either.
    #[test]
    fn an_obfuscated_split_encrypted_7z_set_is_seen_as_password_protected() {
        let dir = tmp("obf7z");
        let data: Vec<u8> = (0..120_000u32).map(|i| (i * 3 + 9) as u8).collect();
        let parts = split_as(&dir, &mhe_bytes("n2-obf-key", &data), 4, "hash");
        let found = encrypted_archive(&dir).expect("an obfuscated encrypted set is locked");
        assert!(
            parts.contains(&found),
            "{} is not one of the set's parts",
            found.display()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The control arm, and the one that matters most: a PLAIN split
    /// 7-Zip set must NOT raise the key.
    ///
    /// The probe answers "does this refuse to open without a password",
    /// not "is this several files" - a job wearing a password
    /// affordance it cannot use is its own defect, and the cheap fix of
    /// treating every multi-part set as locked would have shipped one.
    #[test]
    fn a_plain_split_7z_set_raises_no_password() {
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
        let dir = tmp("plain7z");
        let data: Vec<u8> = (0..90_000u32).map(|i| (i * 5 + 1) as u8).collect();
        let bytes = {
            let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
            w.push_archive_entry(ArchiveEntry::new_file("movie.mkv"), Some(&data[..]))
                .unwrap();
            w.finish().unwrap().into_inner()
        };
        split_as(&dir, &bytes, 3, "set.7z");
        assert_eq!(
            encrypted_archive(&dir),
            None,
            "a plain split set must not ask for a password"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Gemini 14 Oct sweep H5, bug A: a PLAIN split 7z beside a locked
    /// zip must not make a wrong password report success.
    ///
    /// `unlock_non_rar` (now `LockedNonRar`) attempted every multipart 7z set without asking
    /// whether it was locked, and 7-Zip ignores a password it does not
    /// need - so the plain sidecar extracted, the arm answered
    /// `Some(true)`, and the zip it never reached stayed locked behind a
    /// "the password worked".
    #[test]
    fn a_plain_split_7z_beside_a_locked_zip_does_not_pass_a_wrong_password() {
        use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
        use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
        let dir = tmp("plain7z-lockedzip");
        let subs: Vec<u8> = (0..90_000u32).map(|i| (i * 5 + 1) as u8).collect();
        let bytes = {
            let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
            w.push_archive_entry(ArchiveEntry::new_file("subs.srt"), Some(&subs[..]))
                .unwrap();
            w.finish().unwrap().into_inner()
        };
        split_as(&dir, &bytes, 2, "subs.7z");
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + 3) as u8).collect();
        std::fs::write(
            dir.join("payload.zip"),
            zip_of(&[Spec {
                encrypt: Some(Encrypt::ZipCrypto { password: "pw123" }),
                ..Spec::deflated("movie.mkv", &payload)
            }]),
        )
        .unwrap();

        assert_eq!(
            unlock(&dir, "wrong"),
            Err(None),
            "a wrong password must not pass because a plain sidecar extracted"
        );
        assert!(!dir.join("movie.mkv").exists(), "the zip is still locked");
        assert_eq!(unlock(&dir, "pw123"), Ok(()), "the right one still does");
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Gemini 14 Oct sweep H5, bug B: a locked RAR posted under a
    /// numeric extension (`movie.001`) is still a locked RAR. The probe
    /// required a final extension of exactly `rar` and answered None, so
    /// the job never raised the password affordance.
    #[test]
    fn a_numeric_named_encrypted_rar_is_seen_as_password_protected() {
        let dir = tmp("numrar");
        let path = dir.join("movie.001");
        std::fs::write(&path, nzbkit::rar::fixtures::rar4_encrypted_headers(64)).unwrap();
        assert_eq!(encrypted_rar(&dir), Some(path.clone()));
        assert_eq!(encrypted_archive(&dir), Some(path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A header-encrypted RAR5 store archive holding `name`, extractable
    /// natively with `pw` - the `rar -m0 -hp` shape.
    fn locked_rar(pw: &str, name: &str, data: &[u8]) -> Vec<u8> {
        use nzbkit::rar::fixtures;
        let f = fixtures::encrypt_file(pw, data, 9);
        fixtures::rar5_volume_enc_headers(
            &[(name, &f, 0..f.cipher.len(), false, false)],
            None,
            pw,
            9,
        )
    }

    /// An encrypted (ZipCrypto) zip holding `name`.
    fn locked_zip(pw: &'static str, name: &str, data: &[u8]) -> Vec<u8> {
        use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
        zip_of(&[Spec {
            encrypt: Some(Encrypt::ZipCrypto { password: pw }),
            ..Spec::deflated(name, data)
        }])
    }

    /// Codex 22 Oct sweep F7: a password-requiring `.cbr` is a COMIC,
    /// not a locked archive. Its bytes are a RAR, so the magic-only arm
    /// of the probe counted it, while every extract collector excludes
    /// the name - and the disagreement made `unlock` take the RAR road,
    /// find no set, and report the no-work answer as the password
    /// working. Alone, the comic raises no prompt; beside a locked zip,
    /// the ZIP decides the answer, and the comic is never touched.
    #[test]
    fn an_encrypted_cbr_is_a_deliverable_not_a_locked_archive() {
        let dir = tmp("enccbr");
        let pages: Vec<u8> = (0..30_000u32).map(|i| (i * 11 + 5) as u8).collect();
        let comic = locked_rar("comic-key", "page01.jpg", &pages);
        std::fs::write(dir.join("issue.cbr"), &comic).unwrap();
        assert!(
            nzbkit::rar::needs_password(&dir.join("issue.cbr")),
            "the fixture must be a password-requiring RAR, or this proves nothing"
        );
        assert_eq!(encrypted_rar(&dir), None, "a comic is not a locked RAR");
        assert_eq!(encrypted_archive(&dir), None, "and raises no prompt");

        let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + 3) as u8).collect();
        std::fs::write(
            dir.join("payload.zip"),
            locked_zip("pw123", "movie.mkv", &payload),
        )
        .unwrap();
        assert_eq!(
            encrypted_archive(&dir),
            Some(dir.join("payload.zip")),
            "the zip is the lock"
        );
        assert_eq!(
            unlock(&dir, "wrong"),
            Err(None),
            "a wrong password must fail on the zip, not pass on the comic"
        );
        assert!(!dir.join("movie.mkv").exists());
        assert_eq!(unlock(&dir, "pw123"), Ok(()));
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), payload);
        assert_eq!(
            std::fs::read(dir.join("issue.cbr")).unwrap(),
            comic,
            "the comic is the deliverable and stays untouched"
        );
        assert!(
            !dir.join("page01.jpg").exists(),
            "the comic was not unpacked"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex 22 Oct sweep F5: an encrypted 7z beside an encrypted zip,
    /// both under the SAME password. The non-RAR arm returned at the 7z
    /// success, so the zip was never tried and the job was reported
    /// unlocked with half its payload still packed.
    #[test]
    fn a_shared_password_unlocks_both_a_7z_and_a_zip() {
        let dir = tmp("f5-shared");
        let film: Vec<u8> = (0..60_000u32).map(|i| (i * 13 + 1) as u8).collect();
        let extra: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + 3) as u8).collect();
        std::fs::write(dir.join("film.7z"), mhe_named("shared", "film.mkv", &film)).unwrap();
        std::fs::write(
            dir.join("extra.zip"),
            locked_zip("shared", "extra.mkv", &extra),
        )
        .unwrap();

        assert_eq!(unlock(&dir, "shared"), Ok(()));
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), film);
        assert_eq!(
            std::fs::read(dir.join("extra.mkv")).unwrap(),
            extra,
            "the zip beside the 7z must be unlocked too"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F5, different passwords: the first one delivers what it opens and
    /// still FAILS, so the prompt stays up for the rest; the second one
    /// then finishes the job, because the zip already delivered beside
    /// its container is not asked again (the consumed-but-retained
    /// control - extractors never delete a container they spent).
    ///
    /// The order is zip first. The other order needs the written 7z
    /// delivery record and has its own test below.
    #[test]
    fn different_passwords_keep_the_prompt_until_every_container_opens() {
        let dir = tmp("f5-differ");
        let film: Vec<u8> = (0..60_000u32).map(|i| (i * 13 + 1) as u8).collect();
        let extra: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + 3) as u8).collect();
        std::fs::write(dir.join("film.7z"), mhe_named("seven", "film.mkv", &film)).unwrap();
        std::fs::write(
            dir.join("extra.zip"),
            locked_zip("zippy", "extra.mkv", &extra),
        )
        .unwrap();

        assert_eq!(
            unlock(&dir, "zippy"),
            Err(None),
            "the 7z is still locked, so this is not an unlock"
        );
        assert_eq!(
            std::fs::read(dir.join("extra.mkv")).unwrap(),
            extra,
            "what the password did open stays delivered"
        );
        assert!(!dir.join("film.mkv").exists());
        assert!(
            encrypted_archive(&dir).is_some(),
            "the job still has something to ask a password for"
        );
        assert!(dir.join("extra.zip").exists(), "the spent zip is retained");

        assert_eq!(
            unlock(&dir, "seven"),
            Ok(()),
            "the delivered zip is not asked again"
        );
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), film);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F5, different passwords, 7z FIRST - the order that used to be a
    /// prompt nothing could clear. A header-encrypted 7z cannot show
    /// from its own bytes that it was delivered, so without the record
    /// the zip's password was spent on the already-opened 7z, failed,
    /// and failed the unlock every time. With it the 7z is skipped, the
    /// zip opens, and the record lives exactly as long as the spent 7z.
    #[test]
    fn a_7z_opened_first_is_not_asked_again_under_the_zips_password() {
        let dir = tmp("f5-7zfirst");
        let film: Vec<u8> = (0..60_000u32).map(|i| (i * 13 + 1) as u8).collect();
        let extra: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + 3) as u8).collect();
        std::fs::write(dir.join("film.7z"), mhe_named("seven", "film.mkv", &film)).unwrap();
        std::fs::write(
            dir.join("extra.zip"),
            locked_zip("zippy", "extra.mkv", &extra),
        )
        .unwrap();

        assert_eq!(unlock(&dir, "seven"), Err(None), "the zip is still locked");
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), film);
        assert!(dir.join("film.7z").exists(), "the spent 7z is retained");
        assert!(dir.join(UNLOCKED_7Z_MARKER).exists(), "and recorded");
        assert_eq!(
            encrypted_archive(&dir),
            Some(dir.join("extra.zip")),
            "the prompt is for the zip now, not the opened 7z"
        );

        assert_eq!(unlock(&dir, "zippy"), Ok(()), "the job can finish");
        assert_eq!(std::fs::read(dir.join("extra.mkv")).unwrap(), extra);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), film);
        assert_eq!(
            encrypted_archive(&dir),
            None,
            "a later probe of the finished folder raises no key"
        );
        assert!(
            dir.join(UNLOCKED_7Z_MARKER).exists(),
            "the record stays exactly as long as the spent 7z it vouches for"
        );

        // Once the spent container is gone (a cleanup, the move), the
        // next Ok drops the record with it.
        std::fs::remove_file(dir.join("film.7z")).unwrap();
        assert_eq!(unlock(&dir, "anything"), Ok(()), "nothing is locked");
        assert!(
            !dir.join(UNLOCKED_7Z_MARKER).exists(),
            "a record describing nothing on disk is retired"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The record's control arm: it vouches for the FILE it stamped, not
    /// for a name. A container rewritten under the same name (here a
    /// different, longer archive) is a fresh lock and is asked again.
    #[test]
    fn a_rewritten_7z_under_a_recorded_name_is_a_lock_again() {
        let dir = tmp("f5-7zrewrite");
        let film: Vec<u8> = (0..60_000u32).map(|i| (i * 13 + 1) as u8).collect();
        let extra: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + 3) as u8).collect();
        std::fs::write(dir.join("film.7z"), mhe_named("seven", "film.mkv", &film)).unwrap();
        std::fs::write(
            dir.join("extra.zip"),
            locked_zip("zippy", "extra.mkv", &extra),
        )
        .unwrap();
        assert_eq!(unlock(&dir, "seven"), Err(None));
        assert!(dir.join(UNLOCKED_7Z_MARKER).exists());

        let other: Vec<u8> = (0..90_000u32).map(|i| (i * 5 + 2) as u8).collect();
        std::fs::write(dir.join("film.7z"), mhe_named("eight", "other.mkv", &other)).unwrap();
        assert_eq!(
            encrypted_archive(&dir),
            Some(dir.join("film.7z")),
            "a rewritten container is not covered by the old record"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F5's RAR face: a locked RAR set beside a locked zip. The RAR arm
    /// returned at its own success and never reached the zip; with one
    /// password both open, and with two the RAR's payload is kept while
    /// the job stays locked until the zip's arrives.
    #[test]
    fn a_locked_rar_beside_a_locked_zip_needs_both_opened() {
        let film: Vec<u8> = (0..60_000u32).map(|i| (i * 13 + 1) as u8).collect();
        let extra: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + 3) as u8).collect();

        let dir = tmp("f5-rar-shared");
        std::fs::write(dir.join("x.rar"), locked_rar("shared", "film.mkv", &film)).unwrap();
        std::fs::write(
            dir.join("extra.zip"),
            locked_zip("shared", "extra.mkv", &extra),
        )
        .unwrap();
        assert_eq!(unlock(&dir, "shared"), Ok(()));
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), film);
        assert_eq!(std::fs::read(dir.join("extra.mkv")).unwrap(), extra);
        let _ = std::fs::remove_dir_all(&dir);

        let dir = tmp("f5-rar-differ");
        std::fs::write(dir.join("x.rar"), locked_rar("rarpw", "film.mkv", &film)).unwrap();
        std::fs::write(
            dir.join("extra.zip"),
            locked_zip("zippy", "extra.mkv", &extra),
        )
        .unwrap();
        assert_eq!(unlock(&dir, "rarpw"), Err(None), "the zip is still locked");
        assert_eq!(
            std::fs::read(dir.join("film.mkv")).unwrap(),
            film,
            "the RAR payload is kept"
        );
        assert!(!dir.join("extra.mkv").exists());
        assert_eq!(
            encrypted_archive(&dir),
            Some(dir.join("extra.zip")),
            "the zip is what the prompt is for now"
        );
        assert_eq!(unlock(&dir, "zippy"), Ok(()));
        assert_eq!(std::fs::read(dir.join("extra.mkv")).unwrap(), extra);
        let _ = std::fs::remove_dir_all(&dir);

        // And the other order: the zip's password first. It opens the
        // zip and is still not an unlock, because the RAR is locked.
        let dir = tmp("f5-rar-zipfirst");
        std::fs::write(dir.join("x.rar"), locked_rar("rarpw", "film.mkv", &film)).unwrap();
        std::fs::write(
            dir.join("extra.zip"),
            locked_zip("zippy", "extra.mkv", &extra),
        )
        .unwrap();
        assert_eq!(unlock(&dir, "zippy"), Err(None), "the RAR is still locked");
        assert_eq!(std::fs::read(dir.join("extra.mkv")).unwrap(), extra);
        assert_eq!(unlock(&dir, "rarpw"), Ok(()));
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), film);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And a single named `.7z`, which is the shape that DID work
    /// before: the wider discovery must not have lost it.
    #[test]
    fn a_single_encrypted_7z_is_still_seen() {
        let dir = tmp("single7z");
        let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        let path = dir.join("release.7z");
        std::fs::write(&path, mhe_bytes("n2-single-key", &data)).unwrap();
        assert_eq!(encrypted_archive(&dir), Some(path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pre-release sweep, 9 Nov 2026: a volume of the set this unlock
    /// just EXTRACTED that failed to delete (an AV lock, EACCES on a NAS)
    /// is spent, not locked. `unlock` judged "still locked" by asking
    /// [`encrypted_archive`] of the whole folder, which finds it, so a
    /// right password read as wrong - and the walks went on spending the
    /// rest of the file against the delivered set.
    ///
    /// The extraction cannot be made to fail a delete portably, so this
    /// stages the state it leaves: three locked volumes of one set before,
    /// two removed by the set's own sweep, one left exactly as it was.
    #[test]
    fn a_spent_volume_that_survived_its_delete_is_not_a_lock() {
        let dir = tmp("spent-survivor");
        let vol = nzbkit::rar::fixtures::rar4_encrypted_headers(4096);
        for n in 1..=3 {
            std::fs::write(dir.join(format!("movie.part{n}.rar")), &vol).unwrap();
        }
        let before = locked_rar_volumes(&dir);
        assert_eq!(before.len(), 3, "the fixture is three locked volumes");
        std::fs::remove_file(dir.join("movie.part2.rar")).unwrap();
        std::fs::remove_file(dir.join("movie.part3.rar")).unwrap();
        // What the old check said about this folder.
        assert!(encrypted_archive(&dir).is_some());
        assert_eq!(
            locked_left(&dir, &before),
            None,
            "the survivor belongs to a set this unlock spent"
        );

        // The same unlock with a second set beside the first, which the
        // password did NOT open: it keeps every volume, and is still a
        // lock whatever happened to the first.
        for n in 1..=2 {
            std::fs::write(dir.join(format!("other.part{n}.rar")), &vol).unwrap();
        }
        let mut with_other = before.clone();
        with_other.extend(
            locked_rar_volumes(&dir)
                .into_iter()
                .filter(|(p, _)| p.starts_with(dir.join("other"))),
        );
        assert_eq!(
            locked_left(&dir, &with_other),
            Some(dir.join("other.part1.rar")),
            "an untouched set is still locked"
        );

        // A locked volume that was not there before is a layer the
        // unlock EXPOSED, even under a spent set's own stem.
        for n in 1..=2 {
            std::fs::remove_file(dir.join(format!("other.part{n}.rar"))).unwrap();
        }
        std::fs::write(dir.join("movie.part9.rar"), &vol).unwrap();
        assert_eq!(
            locked_left(&dir, &before),
            Some(dir.join("movie.part9.rar")),
            "a new locked volume is never read as spent"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...and through `unlock` itself, on a real two-volume encrypted
    /// set: the right password is an unlock, and the set is delivered.
    #[test]
    fn a_two_volume_encrypted_set_unlocks() {
        use nzbkit::rar::fixtures;
        let dir = tmp("two-vol");
        let film: Vec<u8> = (0..80_000u32).map(|i| (i * 11 + 5) as u8).collect();
        let f = fixtures::encrypt_file("rightpw", &film, 9);
        let half = f.cipher.len() / 2;
        std::fs::write(
            dir.join("movie.part1.rar"),
            fixtures::rar5_volume_enc_headers(
                &[("movie.mkv", &f, 0..half, false, true)],
                Some(0),
                "rightpw",
                9,
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("movie.part2.rar"),
            fixtures::rar5_volume_enc_headers(
                &[("movie.mkv", &f, half..f.cipher.len(), true, false)],
                Some(1),
                "rightpw",
                9,
            ),
        )
        .unwrap();
        assert_eq!(unlock(&dir, "rightpw"), Ok(()));
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), film);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The non-RAR walk's named refusal, when the password opened a
    /// container and exposed a layer the walk does not take (here a plain
    /// RAR).
    /// It reaches a user verbatim, and it was a string continuation
    /// without the backslash, so the next line's indentation sat in the
    /// middle of the sentence; and `diag::unlock_answers` must recognise
    /// it, or a later unlock that delivers leaves it on a Completed row.
    #[test]
    fn the_left_packed_refusal_reads_cleanly_and_a_later_unlock_answers_it() {
        let dir = tmp("left-packed");
        std::fs::write(
            dir.join("outer.zip"),
            locked_zip(
                "zippy",
                "inner.rar",
                &nzbkit::rar::fixtures::rar5_volume(&[("x.mkv", 3, b"abc", false, false)]),
            ),
        )
        .unwrap();
        let answer = unlock(&dir, "zippy");
        let Err(Some(why)) = answer else {
            panic!("expected the named refusal, got {answer:?}");
        };
        assert!(!why.contains("  "), "a run of spaces in {why:?}");
        assert!(why.contains("inner.rar"), "{why:?}");
        assert!(crate::diag::unlock_answers(&why), "{why:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
