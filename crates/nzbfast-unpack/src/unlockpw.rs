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
pub fn encrypted_rar(dir: &Path) -> Option<PathBuf> {
    let mut rars: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rar")))
        .collect();
    rars.sort();
    rars.into_iter().find(|p| nzbkit::rar::needs_password(p))
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
/// what [`unlock_non_rar`] below already spends a password on, so the
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
    let mut sevenz = crate::rarfix::collect_sevenz_archives(dir).unwrap_or_default();
    // Stable across a directory read that hands its entries back in any
    // order: the NAME a job reports is the one the UI shows.
    sevenz.sort();
    if let Some(z) = sevenz
        .into_iter()
        .find(|parts| crate::rarfix::sevenz_set_needs_password(parts))
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

/// Spend `password` on the locked NON-RAR shapes in `dir`: a 7-Zip
/// container, then a zip. `None` means there was nothing of either shape
/// to try, which is what lets the caller tell "no attempt" apart from
/// "attempted and the password was wrong".
///
/// Only containers that actually ASK for a password are attempted. 7-Zip
/// and zip both ignore a password they do not need, so an unrelated
/// plain container in the same folder (a sample, an obfuscated sidecar -
/// `collect_sevenz_archives` picks those up by magic under any name)
/// extracted cleanly and reported the wrong password as the one that
/// worked: prompt cleared, "the password worked" toast, the locked set
/// still packed. A multipart 7z cannot be probed part by part - its
/// header lives in the last part - so it still gets the attempt.
pub(crate) fn unlock_non_rar(dir: &Path, password: &str) -> Option<bool> {
    let sevenz: Vec<Vec<PathBuf>> = crate::rarfix::collect_sevenz_archives(dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|parts| {
            parts.len() > 1
                || parts
                    .first()
                    .is_some_and(|p| nzbkit::nameprobe::sevenz_needs_password(p))
        })
        .collect();
    if !sevenz.is_empty() {
        if !crate::rarfix::extract_sevenz(dir, &sevenz, Some(password)) {
            return Some(false);
        }
        info!(target: "unlock", "{}: 7-Zip container unlocked", dir.display());
        return Some(true);
    }
    let zips: Vec<nzbkit::zip::Finding> = nzbkit::zip::scan(dir)
        .into_iter()
        .filter(|f| nzbkit::zip::needs_password(&f.parts))
        .collect();
    if zips.is_empty() {
        return None;
    }
    if !crate::rarfix::extract_zip(dir, &zips, Some(password)) {
        return Some(false);
    }
    info!(target: "unlock", "{}: zip container unlocked", dir.display());
    Some(true)
}

/// Unlock a password-protected set: unrar with the password, and on
/// success delete the volume files (the unpacked content is the
/// deliverable, matching the engine's post-extraction behavior).
///
/// `Err(None)` is the ordinary answer and means what the `bool` this
/// returned until 22 Aug 2026 meant: this password did not open anything
/// here. `Err(Some(why))` is a refusal that is about the DISK - today
/// only a bomb verdict, raised by the two rungs inside
/// [`crate::rarfix::try_unrar_spent_why`] - and dropping it here was
/// worse than wrong wording, because the callers are SWEEPS. Every
/// candidate in the operator's passwords file is another extraction
/// attempt against the same full disk, so one bomb refused every
/// password in the file in turn and the job was then reported as having
/// none that worked (`job_finalize.rs`, `job.rs`). A named
/// reason therefore STANDS THE SWEEP DOWN at the first candidate as well
/// as being quoted: there is nothing for a second password to do
/// differently.
///
/// It also stops the fall-through to [`unlock_non_rar`] below, for the
/// same reason the nested pass stops at its first refusal: that arm
/// extracts a 7z or a zip, on the disk that has just refused to hold an
/// extraction.
///
/// A `Result` rather than a bool with a `_why` twin beside it, which is
/// the shape [`crate::rarfix::try_unrar_spent_why`] and
/// [`crate::repair::reextract_dir_why`] took: those two kept their plain
/// wrappers for callers that genuinely only ask "did it unpack", and
/// this function has none left. Every caller composes something the user
/// reads. A fresh bool wrapper here would be a third place for the
/// verdict to be dropped, which is the whole defect this closes.
pub fn unlock(dir: &Path, password: &str) -> std::result::Result<(), Option<String>> {
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
    // holding a locked RAR keeps the whole path below and these arms
    // stay out of it.
    if encrypted_rar(dir).is_none()
        && let Some(unlocked) = unlock_non_rar(dir, password)
    {
        return unlocked.then_some(()).ok_or(None);
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
        // above (RAR had first claim) - so they get their turn here,
        // before the password is called wrong.
        Ok(Err(None)) | Err(_) => {
            return unlock_non_rar(dir, password)
                .unwrap_or(false)
                .then_some(())
                .ok_or(None);
        }
    }
    let removed = before.difference(&vol_snapshot(dir)).count();
    info!(
        target: "unlock",
        "{} unpacked - {removed} volume file(s) spent",
        dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header-encrypted 7-Zip container, which is the `-mhe` shape
    /// posted for a locked release: the file list AND the payload are
    /// behind the key, so nothing about it can be read without one.
    fn mhe_bytes(key: &str, data: &[u8]) -> Vec<u8> {
        use sevenz_rust2::{
            ArchiveEntry, ArchiveWriter, Password, encoder_options::AesEncoderOptions,
        };
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_encrypt_header(true);
        w.set_content_methods(vec![AesEncoderOptions::new(Password::from(key)).into()]);
        w.push_archive_entry(ArchiveEntry::new_file("movie.mkv"), Some(data))
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
}
