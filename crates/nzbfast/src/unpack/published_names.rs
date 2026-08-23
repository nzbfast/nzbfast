//! The PAR2 verified-name publish: taking a slot's file from its posted
//! (often obfuscated) name to the name the recovery set's FileDesc gives
//! it, and the per-job claim that keeps two publishes off one path.
//!
//! Split out of `unpack.rs` (TODO 106 size gate); callers reach both
//! items through the parent's `pub(crate) use`.

use super::*;

/// The output names ONE job's PAR2 verified-name publishes have taken.
///
/// `publish_verified_name` replaces whatever sits at its target, which is
/// right for a PREVIOUS run's copy and wrong for a file this same job put
/// there: the second publish then renames over the first and the job
/// finishes a payload short, with two "renamed" lines in the log and no
/// error anywhere (Codex 3 Aug, "sanitized output-name collisions can
/// still overwrite on disk" - dispositioned 23 Aug 2026).
///
/// Two shapes reach it, and only the first is about the sanitizer:
///
/// - `nzbkit::disk::sanitize_filename` is many-to-one, so two distinct
///   PAR2 FileDesc names (`sub/movie.mkv` and `sub_movie.mkv`) map to one
///   on-disk name. The FileDesc name is poster-typed bytes.
/// - On a case-insensitive volume (macOS, Windows, a CIFS/exFAT share
///   under the Linux build) `README.nfo` and `readme.nfo` name ONE
///   object, and no sanitizer is involved at all. A set built on a
///   case-sensitive box carries both names legitimately.
///
/// So the key folds case exactly as the extractor's own output-name claim
/// does (`name_collision_key`, PROBED from the volume rather than guessed
/// from `cfg!(target_os)`), and the disambiguated form is the extractor's
/// too - `{slot:03}-{name}` - so a user looking at the directory sees one
/// convention whichever path renamed the file.
pub(crate) struct PublishedNames {
    /// Probed once from the output volume, not read off the build target.
    fold: bool,
    /// Collision key → the slot that holds it.
    taken: std::collections::HashMap<String, usize>,
}

impl PublishedNames {
    pub(crate) fn for_dir(out_dir: &std::path::Path) -> PublishedNames {
        PublishedNames {
            fold: nzbkit::disk::case_insensitive_dir(out_dir),
            taken: std::collections::HashMap::new(),
        }
    }

    fn key(&self, name: &str) -> String {
        if self.fold {
            name.to_lowercase()
        } else {
            name.to_string()
        }
    }

    /// Record a name `slot` ALREADY holds on disk, without disambiguating
    /// it. Seeded from the live slot paths before the publish pass, so a
    /// slot that simply kept its posted name cannot be renamed over by
    /// another slot's verified name - the same loss with one of the two
    /// files never deobfuscated. First seeder wins; a name two slots
    /// somehow both claim to hold is already the filesystem's answer, not
    /// ours to re-decide.
    pub(crate) fn seed(&mut self, slot: usize, name: &str) {
        let k = self.key(name);
        self.taken.entry(k).or_insert(slot);
    }

    /// The name `slot` may actually publish under. `name` when it is free
    /// or already this slot's, a `{slot:03}-` form when another slot holds
    /// it.
    fn claim(&mut self, slot: usize, name: &str) -> String {
        let k = self.key(name);
        if *self.taken.entry(k).or_insert(slot) == slot {
            return name.to_string();
        }
        let mut n = 0usize;
        loop {
            let cand = if n == 0 {
                format!("{slot:03}-{name}")
            } else {
                format!("{slot:03}-{n}-{name}")
            };
            let k = self.key(&cand);
            if *self.taken.entry(k).or_insert(slot) == slot {
                return cand;
            }
            n += 1;
        }
    }
}

/// Publish a PAR2-verified slot file under the name the FileDesc gives
/// it, replacing whatever sits there. No-op when it is already correct.
///
/// A previous run's copy may already sit at the real name (re-download
/// into the same folder). The bytes we just PAR2-verified are
/// authoritative - REPLACE, never strand this download under its
/// obfuscated post name.
///
/// What it must NOT replace is a file THIS job put there, which is what
/// `taken` separates: see [`PublishedNames`]. The claim happens even when
/// the name is already correct and even when the rename then fails, so
/// the next slot is pushed off a name this one owns either way.
///
/// Rename straight over it: `fs::rename` replaces atomically on unix AND
/// windows (MOVEFILE_REPLACE_EXISTING), so there is never a moment with
/// neither file. The old code removed the target first and then ignored
/// the rename's result, so a failed rename left the good previous copy
/// deleted and the verified bytes still under the obfuscated name.
pub(crate) fn publish_verified_name(
    path: &std::path::Path,
    pname: &str,
    out_dir: &std::path::Path,
    slot: usize,
    taken: &mut PublishedNames,
) -> Option<std::path::PathBuf> {
    let real = taken.claim(slot, &nzbkit::disk::sanitize_filename(pname));
    if path.file_name().and_then(|n| n.to_str()) == Some(real.as_str()) {
        return None;
    }
    let target = out_dir.join(&real);
    let existed = target.exists();
    match std::fs::rename(path, &target) {
        Ok(()) => {
            info!(
                target: "extract",
                "renamed {} → {real}{}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                if existed {
                    " (replaced the previous copy)"
                } else {
                    ""
                }
            );
            // The caller must tell any live writer (note_slot_renamed):
            // its handle survives the rename, but a by-path reopen
            // (unpark after the external par2) needs this name.
            Some(target)
        }
        Err(e) => {
            warn!(
                target: "extract",
                "could not publish {real}: {e} - the verified file is still at {}",
                path.display()
            );
            None
        }
    }
}

#[cfg(test)]
#[path = "publish_name_tests.rs"]
mod publish_name_tests;
