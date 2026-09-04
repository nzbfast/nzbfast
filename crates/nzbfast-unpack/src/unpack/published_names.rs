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
/// - `nzbkit::disk::sanitize_out_name` is many-to-one, so two distinct
///   PAR2 FileDesc names (`sub//movie.mkv` and `sub__movie.mkv` - a
///   provably safe path keeps its tree now, so the colliding shapes are
///   the ones the flatten fallback still owns) map to one on-disk name.
///   The FileDesc name is poster-typed bytes.
/// - On a case-insensitive volume (macOS, Windows, a CIFS/exFAT share
///   under the Linux build) `README.nfo` and `readme.nfo` name ONE
///   object, and no sanitizer is involved at all. A set built on a
///   case-sensitive box carries both names legitimately.
/// - W4-17 (codex Wave 4, 30 Aug 2026): `node` and `node/child.bin` are
///   two valid FileDesc members that COLLIDE ON DISK while sharing no
///   complete string. One name is a file and the other needs it to be a
///   directory, so the claim map has to carry the prefix TOPOLOGY, not
///   just the leaves - see [`PublishedNames::free_for`]. Measured on the
///   30 Aug baseline in both completion orders: flat-first, the child's
///   `create_out_dirs` met a regular file; child-first, publishing the
///   flat name met a nonempty directory. Either way one verified payload
///   stayed under its hash at rc=0.
///
/// So the key folds case exactly as the extractor's own output-name claim
/// does (`name_collision_key`, PROBED from the volume rather than guessed
/// from `cfg!(target_os)`), and the disambiguated form is the extractor's
/// too - `{slot:03}-{name}` - so a user looking at the directory sees one
/// convention whichever path renamed the file.
pub struct PublishedNames {
    /// Probed once from the output volume, not read off the build target.
    fold: bool,
    /// The output directory every name here is relative to - the one
    /// `for_dir` probed. Kept so the disk belt below can ASK the volume
    /// about a candidate rather than guess from [`PublishedNames::key`].
    dir: std::path::PathBuf,
    /// The FILE OBJECT behind every name this job has put a file at,
    /// mapped to the slot that owns it: everything
    /// [`PublishedNames::seed`] was given plus everything
    /// [`PublishedNames::take`] claimed.
    ///
    /// An identity and not a name, because the question
    /// [`PublishedNames::collides_on_disk`] asks is the filesystem's
    /// ("is this one object?") and no fold of the NAMES can answer it -
    /// that is M4-61 in one line. Recorded from the SOURCE path at claim
    /// time, which is the same inode the rename then moves, so a rename
    /// that fails leaves the entry just as true as one that lands.
    ///
    /// A map rather than a walk, and that was measured rather than
    /// preferred: asking `same_file_object` per landed name made the
    /// publish pass quadratic in syscalls, 124 ms to 1.73 s over a
    /// 1,000-file re-download into a populated folder on the 30 Aug 2026
    /// dev box, growing with the square. One `file_object_id` per
    /// publish and a lookup is flat.
    landed: std::collections::HashMap<(u64, u64, u64), usize>,
    /// Collision key → the slot that holds it, as a LEAF (a file).
    taken: std::collections::HashMap<String, usize>,
    /// Collision keys some claimed leaf needs as a DIRECTORY - every
    /// ancestor prefix of every name in `taken`. Unowned on purpose: a
    /// directory is shared (`node/a.bin` and `node/b.bin` both need
    /// `node`), so what matters is not WHO holds it but that the name is
    /// spoken for as a directory and cannot also be a file. See W4-17 in
    /// the type's own header.
    dirs: std::collections::HashSet<String>,
    /// (slot, the name it was owed) for every publish this job could not
    /// land - X5-09. A later pass that DOES land the slot clears its
    /// entry, so this is "still under its posted name at the end", not
    /// "something once went wrong". Read through
    /// [`PublishedNames::unlanded_why`].
    failed: Vec<(usize, String)>,
}

impl PublishedNames {
    pub fn for_dir(out_dir: &std::path::Path) -> PublishedNames {
        PublishedNames {
            fold: nzbkit::disk::case_insensitive_dir(out_dir),
            dir: out_dir.to_path_buf(),
            landed: std::collections::HashMap::new(),
            taken: std::collections::HashMap::new(),
            dirs: std::collections::HashSet::new(),
            failed: Vec::new(),
        }
    }

    /// This volume's collision key for `name` - what `taken` is indexed
    /// by. Public so the settle pass can ask whether two names collide on
    /// THIS filesystem before it plans its renames, rather than
    /// re-deciding case folding for itself.
    pub fn key_of(&self, name: &str) -> String {
        self.key(name)
    }

    fn key(&self, name: &str) -> String {
        Self::fold_key(self.fold, name)
    }

    /// [`PublishedNames::key`] with the volume's answer PASSED rather
    /// than read off `self`, so the fold itself can be pinned without a
    /// volume that folds. `key` is the only production caller.
    ///
    /// M4-44 (31 Aug 2026): this is the fifth and last filesystem-
    /// identity site to leave `str::to_lowercase`, and it takes the same
    /// fold as the extractor's own output-name claim
    /// (`extract::reasons::name_collision_key`) for the same reason.
    /// `to_lowercase` is weaker than what a case-insensitive volume does
    /// - measured against APFS's own equivalence partition, one file per
    /// BMP codepoint with classes read off the inodes, it under-folds
    /// 1,020 codepoints where `case_fold_key` under-folds 925 and
    /// over-folds NOTHING; and over the 104 characters whose fold
    /// EXPANDS, which a single-codepoint sweep cannot see at all, APFS
    /// files all 104 as one object with their expansion, `to_lowercase`
    /// catches 1 and this catches 104. `Straße.mkv` beside `STRASSE.MKV`
    /// is the shape a real post has.
    ///
    /// The prices are why folding harder is right HERE and wrong in
    /// `nzbfast::rarfix`, which must stay on `to_lowercase`: an
    /// over-fold costs this site a needless `{slot:03}-` prefix - both
    /// files land, and the user sees it - while an under-fold costs a
    /// payload at rc=0. `rarfix` resolves a collision by DROPPING an
    /// entry, so its over-fold costs a file, and NTFS folds simple 1:1
    /// case mappings and nothing else, so every pair this newly catches
    /// is two real files on Windows.
    ///
    /// This does NOT retire M4-61's disk belt beside it
    /// ([`PublishedNames::collides_on_disk`]), and must not be read as
    /// doing so: that belt needs no fold table and is right on volumes
    /// nobody here has measured, but it is the STRONG tier's flag alone
    /// and can only fire once something is ON DISK at the name. The
    /// `taken` / `dirs` sets this key indexes cover the names a job has
    /// claimed and not yet landed, which is where a twin is otherwise
    /// still invisible. Belt and fold, not one or the other.
    fn fold_key(fold: bool, name: &str) -> String {
        if fold {
            nzbkit::disk::case_fold_key(name)
        } else {
            name.to_string()
        }
    }

    /// The out-relative names of every ancestor DIRECTORY `name` needs,
    /// outermost first. Empty for a flat name. Safe by construction on a
    /// `sanitize_out_name` result: no leading, trailing or doubled
    /// separator, so every prefix is a real component path.
    fn ancestors(name: &str) -> impl Iterator<Item = &str> {
        name.match_indices('/').map(|(i, _)| &name[..i])
    }

    /// Whether `slot` could actually land a file at `cand` - the
    /// question the filesystem will be asked, not the string question
    /// `taken` alone answers.
    ///
    /// THREE ways one name blocks another, and only the first is a
    /// string equality:
    ///
    /// - another slot already holds `cand` as a leaf;
    /// - `cand` is spoken for as a DIRECTORY (some other name is
    ///   `cand/...`), so creating a file there meets a nonempty
    ///   directory;
    /// - an ANCESTOR of `cand` is somebody's leaf, so `create_out_dirs`
    ///   meets a regular file where it needs a directory.
    ///
    /// The last two are W4-17: `node` and `node/child.bin` are two valid
    /// FileDesc members that share no complete string, so the equality
    /// test saw no collision and whichever published second could not
    /// land at all.
    ///
    /// An ancestor held by THIS slot counts too. That is the shape where
    /// a slot posted as `node` is renamed by its descriptor to
    /// `node/child.bin`: the file in the way is its own, the rename
    /// still cannot happen, and disambiguating costs a `{slot:03}-`
    /// prefix where guessing costs the payload.
    fn free_for(&self, slot: usize, cand: &str) -> bool {
        let k = self.key(cand);
        if self.taken.get(&k).is_some_and(|s| *s != slot) || self.dirs.contains(&k) {
            return false;
        }
        !Self::ancestors(cand).any(|a| self.taken.contains_key(&self.key(a)))
    }

    /// Record `cand` as `slot`'s leaf and every ancestor of it as a
    /// directory this job needs.
    fn take(&mut self, slot: usize, cand: &str, src: Option<&std::path::Path>) {
        for a in Self::ancestors(cand) {
            let k = self.key(a);
            self.dirs.insert(k);
        }
        let k = self.key(cand);
        self.taken.insert(k, slot);
        // The SOURCE's identity, because `cand` is where the file is
        // about to be and `src` is where it is now - one inode either
        // way, and only one of them exists to be stat'd yet.
        if let Some(id) = src.and_then(nzbkit::disk::file_object_id) {
            self.landed.entry(id).or_insert(slot);
        }
    }

    /// The job-failure sentence for names this job owed a verified file
    /// and never landed, or `None` when there is nothing to charge.
    ///
    /// X5-09: a canonical-name publication failure must reach the
    /// verdict. `publish_verified_name` warns and gives up - which is
    /// right, the bytes are safe where they are - and for as long as
    /// nothing read this, the job finished rc=0 with the payload under a
    /// hash and one warn line in a log ring to show for it.
    ///
    /// `still_stranded(slot)` is the caller's answer to "are that slot's
    /// bytes STILL sitting there under their posted name". It is asked
    /// rather than assumed because the unpack ladder runs after the last
    /// publish: a RAR volume whose canonical name never landed, that was
    /// then extracted and eaten, stranded nothing - its name never had
    /// to exist for the payload to land, and failing that job would be a
    /// false failure on a job that delivered.
    pub fn unlanded_why(&self, still_stranded: impl Fn(usize) -> bool) -> Option<String> {
        let mut names: Vec<&str> = self
            .failed
            .iter()
            .filter(|(s, _)| still_stranded(*s))
            .map(|(_, n)| n.as_str())
            .collect();
        if names.is_empty() {
            return None;
        }
        names.sort_unstable();
        names.dedup();
        Some(format!(
            "{} verified file(s) could not be published under the name(s) the \
             post gives them: {}",
            names.len(),
            names.join(", ")
        ))
    }

    /// Record that `slot` could not be landed under `name`.
    fn note_failure(&mut self, slot: usize, name: &str) {
        self.failed.push((slot, name.to_string()));
    }

    /// `slot`'s bytes ARE under a real name now - drop any earlier
    /// failure charged to it. A weaker naming tier running after a
    /// stronger one failed (`land_sfv_names`, the deferred-rename pass,
    /// a late disk set) is a real recovery, not a job to fail.
    fn note_landed(&mut self, slot: usize) {
        self.failed.retain(|(s, _)| *s != slot);
    }

    /// Record a name `slot` ALREADY holds on disk, without disambiguating
    /// it. Seeded from the live slot paths before the publish pass, so a
    /// slot that simply kept its posted name cannot be renamed over by
    /// another slot's verified name - the same loss with one of the two
    /// files never deobfuscated. First seeder wins; a name two slots
    /// somehow both claim to hold is already the filesystem's answer, not
    /// ours to re-decide.
    pub fn seed(&mut self, slot: usize, name: &str) {
        // The directories are recorded whoever wins the leaf: a slot
        // sitting at `sub/movie.mkv` occupies `sub` on disk however the
        // leaf is attributed.
        for a in Self::ancestors(name) {
            let k = self.key(a);
            self.dirs.insert(k);
        }
        let k = self.key(name);
        self.taken.entry(k).or_insert(slot);
        if let Some(id) =
            nzbkit::disk::file_object_id(&nzbkit::disk::join_out_name(&self.dir, name))
        {
            self.landed.entry(id).or_insert(slot);
        }
    }

    /// Does the VOLUME already hold another slot's file at `cand`, under
    /// whatever spelling it stored?
    ///
    /// M4-61 (wave-4 matrix read, 30 Aug 2026). [`PublishedNames::key`]
    /// folds with `str::to_lowercase`, and that is WEAKER than what a
    /// case-insensitive volume actually does. MEASURED on APFS on the
    /// 30 Aug 2026 dev box: `s.mkv`/`ſ.mkv` (U+017F long s) and
    /// `σ.mkv`/`ς.mkv` (final sigma) are each ONE file object, while
    /// `to_lowercase` leaves each pair as two distinct keys - so the
    /// claim map saw no collision, both publishes reported success, and
    /// the second RENAMED OVER the first. One payload gone, rc=0, two
    /// "renamed" lines in the log. That is the exact loss the type's own
    /// header exists to prevent, arriving through a hole in the fold
    /// rather than through a missing claim.
    ///
    /// The row's own remedy - "one fold function, the volume probe's,
    /// everywhere a name is an identity key" - is NOT what this does, and
    /// deliberately. There is no fold in the standard library that is
    /// right: `to_lowercase` under-folds those two pairs, and
    /// `to_uppercase().to_lowercase()`, which fixes them, then breaks
    /// `ß`/`ẞ` (equal under the plain lowercase, and one object on APFS)
    /// and over-folds `I`/`ı`, which APFS keeps apart. What APFS
    /// implements is full Unicode case folding, and picking or writing
    /// that table is M4-44's platform job across FIVE identity-key sites,
    /// not this row's.
    ///
    /// So the belt asks the FILESYSTEM instead, which needs no table and
    /// is right on every volume including ones nobody here has measured -
    /// a CIFS share, exFAT, HFS+'s own normalization. `Path`'s lookup
    /// already folds, so stat'ing the candidate resolves the twin's
    /// stored entry; `same_file_object` then says whether it IS one of
    /// ours. Nothing to keep in step with a platform.
    ///
    /// Cheap in the case that matters: one `symlink_metadata` when
    /// nothing is at the name, which is nearly every publish, and the
    /// walk over `landed` only when something IS - which is the
    /// interesting case by construction.
    ///
    /// A target that exists and is NOT one of ours is a PREVIOUS run's
    /// copy, and the strong tier replacing that is the whole point of
    /// `publish_verified_name` - so `false` there is the answer, not an
    /// oversight.
    fn collides_on_disk(&self, slot: usize, cand: &str) -> bool {
        let target = nzbkit::disk::join_out_name(&self.dir, cand);
        nzbkit::disk::file_object_id(&target)
            .and_then(|id| self.landed.get(&id))
            .is_some_and(|owner| *owner != slot)
    }

    /// The name `slot` may actually publish under. `name` when it is free
    /// or already this slot's, a `{slot:03}-` form when another slot holds
    /// it.
    ///
    /// `check_disk` adds the M4-61 belt above, and it is the STRONG
    /// tier's flag alone. The weak tier needs none: it declines whenever
    /// anything is at its target, and the `symlink_metadata` it asks that
    /// with already goes through the volume's folding lookup, so a
    /// fold-invisible twin is seen there today (W4-03's decline is
    /// unmoved by this change). That it is `symlink_metadata` rather than
    /// `Path::exists` is a decision and not a spelling, and is argued at
    /// the call itself.
    fn claim(
        &mut self,
        slot: usize,
        name: &str,
        src: &std::path::Path,
        check_disk: bool,
    ) -> String {
        if self.free_for(slot, name) && !(check_disk && self.collides_on_disk(slot, name)) {
            self.take(slot, name, Some(src));
            return name.to_string();
        }
        let mut n = 0usize;
        loop {
            // The prefix lands on the FIRST component, so a tree name
            // disambiguates by moving its whole subtree
            // (`node/child.bin` -> `001-node/child.bin`) rather than by
            // renaming the leaf inside a directory it still could not
            // create. Each `n` is a distinct top-level component, so
            // this terminates.
            //
            // Through `disambiguated_out_name` and not a bare `format!`
            // because `name` is a `sanitize_out_name` result and is
            // routinely AT the 255-byte component cap - capping is what
            // produced it - so a raw `001-` prefix is a 259-byte
            // component `renameat` refuses, and the publish lands in
            // `could_not_publish` with the payload left under its
            // posted name. The cap goes on the COMPOSED name, where the
            // key and the path are one string; see that function.
            let cand = nzbkit::disk::disambiguated_out_name(name, slot, n);
            if self.free_for(slot, &cand) && !(check_disk && self.collides_on_disk(slot, &cand)) {
                self.take(slot, &cand, Some(src));
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
pub fn publish_verified_name(
    path: &std::path::Path,
    pname: &str,
    out_dir: &std::path::Path,
    slot: usize,
    taken: &mut PublishedNames,
) -> Option<std::path::PathBuf> {
    publish(path, pname, out_dir, slot, taken, true)
}

/// Publish under a name a WEAK tier asked for - one that will NOT
/// replace a file already sitting at the target.
///
/// The replace rule above is right for the PAR2 tier, whose claim is an
/// MD5 pair over the whole file: those bytes really are authoritative
/// over a previous run's copy. It is wrong for the SFV tier, whose whole
/// claim is a 32-bit checksum, and the difference is not academic - W4-03
/// (30 Aug 2026) is a post where an SFV entry names another file of the
/// SAME JOB, and `fs::rename` replaced it at rc=0 with `[extract] renamed
/// Uw5rTk88NcV -> final.bin (replaced the previous copy)` as the only
/// trace. `taken` closes that door for anything this job published or
/// was seeded with; this closes it for the rest, which is not a
/// hypothetical set - `land_duplicate_filedescs` copies output files
/// without going through the registry at all, and the late-set disk
/// repair creates them without any slot behind them.
///
/// So the belt is the filesystem's own answer rather than the registry's:
/// if something is there, the weak tier declines and says so. Declining
/// is the outcome the W4-03 row calls acceptable; replacing is the one it
/// calls a defect.
pub fn publish_weak_name(
    path: &std::path::Path,
    pname: &str,
    out_dir: &std::path::Path,
    slot: usize,
    taken: &mut PublishedNames,
) -> Option<std::path::PathBuf> {
    publish(path, pname, out_dir, slot, taken, false)
}

fn publish(
    path: &std::path::Path,
    pname: &str,
    out_dir: &std::path::Path,
    slot: usize,
    taken: &mut PublishedNames,
    replace: bool,
) -> Option<std::path::PathBuf> {
    let real = taken.claim(slot, &nzbkit::disk::sanitize_out_name(pname), path, replace);
    // Compare the out_dir-RELATIVE name, not the bare file name: a
    // tree-preserved FileDesc name carries its directories.
    if nzbkit::disk::out_name_of(out_dir, path) == real {
        // Already where it belongs - and that settles any earlier
        // failure charged to this slot.
        taken.note_landed(slot);
        return None;
    }
    // A tree-preserved name renames INTO a subdirectory that may not
    // exist yet; a refusal (a symlink in the way) falls through to the
    // same could-not-publish arm a failed rename takes.
    let target = match nzbkit::disk::prepare_out_path(out_dir, &real) {
        Ok(t) => t,
        Err(e) => {
            could_not_publish(taken, slot, &real, path, &e);
            return None;
        }
    };
    // X5-20 (codex Extreme Wave 5, 30 Aug 2026): the target may already
    // BE this file under another name. `hash.bin` hardlinked as
    // `Real.Name.mkv` is one inode with two entries, and `fs::rename`
    // between two names for one inode is a POSIX no-op that still
    // returns `Ok(())` - so the arm below logged a successful publish
    // (with "replaced the previous copy", since the target existed) and
    // left the obfuscated alias sitting in the output directory. A
    // rename that changed nothing is not a successful publish, so the
    // identity is bound HERE rather than read off the call's result.
    //
    // Ahead of the weak tier's decline on purpose. That refusal exists so
    // a 32-bit checksum cannot replace somebody else's bytes (W4-03), and
    // there are no other bytes to protect when the file already at the
    // name IS this file: declining would leave the same stale alias the
    // strong tier's no-op did, for a payload that is provably already
    // published.
    if nzbkit::disk::is_redundant_link(path, &target) {
        return publish_redundant(out_dir, &target, path, &real, taken, slot);
    }
    // X5-20 residue 1, decided 31 Aug 2026 under claim
    // `publish-exists-dangling-decision`. ONE `lstat` where this was
    // `target.exists()` - the same syscall count, a different question,
    // and the answer both arms below read.
    //
    // THIS IS NOT X5-07, and reaching for that row here is the reflex
    // the paragraph exists to refuse. The fingerprint is identical
    // (`exists` answers false for a dangling link) and the conclusion is
    // the OPPOSITE, because the operation underneath is a rename.
    // `rename(2)` removes whatever entry sits at the destination and
    // never resolves it, so no tier here can reach an inode outside the
    // output directory however the link points; X5-07's harm was
    // `std::fs::copy`, which opens its destination BY NAME with
    // `O_CREAT` and does follow, and created 180 KB outside the job.
    // There is nothing to CONTAIN on this line. What was wrong is what
    // the two arms were being told.
    //
    // MEASURED on APFS, 31 Aug 2026, rather than reasoned, because both
    // halves of the decision below rest on it. Renaming over a link
    // pointing OUT of the directory leaves the entry a regular file
    // holding the source bytes and the outside inode untouched with its
    // own bytes intact - and over a DANGLING one, nothing is created at
    // the far end at all. So the containment question does not arise,
    // and "(replaced the previous copy)" was already false over a link
    // that resolves: that copy is alive where it always was.
    //
    // TWO SEPARATE THINGS MOVED, and neither argument carries the other.
    //
    // * THE WEAK TIER'S REFUSAL, immediately below. W4-03's rule is "if
    //   something is there, decline", and `exists()` asked instead
    //   whether the name RESOLVES. So a dangling link was published over
    //   and a link to a file on an unmounted volume was declined - which
    //   made a deliberately conservative tier's answer depend on state
    //   outside the job: mount the volume and it declines, unmount it
    //   and it deletes the user's link on the authority of a 32-bit
    //   checksum. The harms are not symmetric, which is what settles it.
    //   Declining costs the payload its real name, the log says so in
    //   its own sentence, and one `mv` undoes it. Publishing destroys a
    //   symlink whose target string was the only record of where it
    //   pointed, and nothing undoes that. The tier that is denied the
    //   strong claim takes the recoverable outcome.
    //
    // * THE LOG SENTENCE, in `displaced_suffix`. "(replaced the previous
    //   copy)" was false in BOTH symlink directions and not only the
    //   dangling one: over a link that resolves, the previous copy is
    //   alive at the far end and only the link went. Folding the
    //   dangling case into that suffix would have made it false a third
    //   way rather than fixed it, so the suffix is three-way now.
    //
    // The case fold is unaffected, which the `claim` doc above leans on:
    // `lstat` goes through the same lookup as `stat` and only the FINAL
    // resolve differs, so a fold-invisible twin is still seen here.
    // MEASURED on APFS, 31 Aug 2026: `lstat("README.nfo")` over a stored
    // `readme.nfo` resolves, and reports it as a regular file.
    //
    // The STRONG tier is unchanged on all three states: PAR2 bytes
    // replace a file, a link, or nothing exactly as before. Only what
    // the line SAYS about it moved.
    //
    // THE WINDOW THAT WAS A STATED LIMIT HERE IS CLOSED, 31 Aug 2026,
    // under claim `exclusive-rename-for-occupancy-refusals`. What stood
    // in this paragraph said the weak tier's refusal is a check before a
    // use, that `exists()` had the identical window, and that closing it
    // wanted a per-platform exclusive rename. The first is true, the
    // second is true, and the third was wrong: the remedy is in this
    // repository already, 250 lines into `smart/filing.rs`, and it is
    // portable.
    //
    // MEASURED before anything was built, because the note asked for a
    // price and not a fix. 20,000 publishes on APFS against a thread
    // that claims the name with `create_new` at a swept offset:
    //
    //   window LOST (its entry renamed over)  14,340
    //   declined (it won the lstat)              476
    //   arrived after the rename               5,184
    //
    // So of every arrival that got the name at all, 96.8% landed inside
    // the unprotected part. That is not a sliver of the operation, it is
    // nearly all of it, and the reason is the shape rather than the box:
    // one `lstat` is 968 ns and everything between it and the rename's
    // commit is the `openat` walk (9.4 us) plus the rename itself
    // (102 us). The guard covers about 1% of its own interval.
    //
    // AND IT IS REACHABLE WITHOUT AN ATTACKER. The sibling door in
    // `smart/filing.rs` records this race as a defect that already
    // happened: "Finalize tails run on independent tasks and can overlap
    // ... so two jobs filing the same episode both saw the slot free,
    // the second silently overwrote the first's bytes". That is
    // in-process concurrency in shipped code, and it is why
    // `tv_organize` claims each name with `create_new` before renaming
    // over the placeholder it then owns.
    //
    // THE CLAIM IS NOT A BELT BESIDE THE GUARD, IT IS THE GUARD.
    // MEASURED on APFS the same day: `open_out_leaf_under(..,
    // CreateNew)` answers `AlreadyExists` for a regular file, a DANGLING
    // link, a link pointing out of the directory and a directory - the
    // same four answers `symlink_metadata` gives, which is the whole of
    // what the census bought by moving off `exists()`, taken atomically
    // instead of in two steps. The same 20,000-trial race against it
    // loses ZERO, at a per-trial cost inside the noise of the original.
    //
    // WHY NOT the per-platform primitive the old note prescribed. It
    // works and it was priced: `renameatx_np(RENAME_EXCL)` on APFS
    // refuses an occupied name AND a dangling link with EEXIST, leaving
    // the link intact, for 51.8 us against the plain `renameat`'s
    // 50.3 us. But `renameat2` answers EINVAL/ENOSYS where a filesystem
    // or kernel does not carry the flag, and that is NOT the same answer
    // as "the destination existed" - so its fallback has to be this
    // claim anyway. Building the portable half first is the right order
    // whichever way that question is later settled, and it is the half
    // that needs no `unsafe` on three platforms two of which nobody here
    // can run.
    //
    // COST, stated rather than hidden: two extra syscalls on the weak
    // path, and a process that dies between the claim and the rename
    // leaves a zero-byte file at the canonical name. That residue is
    // safe in BOTH directions here - `PublishedNames::for_dir` seeds
    // from the directory, so a later run reads it as occupied and
    // declines, which is this tier's own correct answer - and the
    // failed-rename arm removes it. `tv_organize` carries the identical
    // trade and names it at its own site.
    //
    // The STRONG tier is untouched by all of this and must stay so: its
    // contract is that PAR2-verified bytes replace a previous run's
    // copy, so it takes no claim, keeps its `symlink_metadata` - which
    // it needs anyway, for `displaced_suffix` - and renames straight
    // over whatever is there.
    let occupant = if replace {
        std::fs::symlink_metadata(&target).ok()
    } else {
        None
    };
    let mut placeholder = false;
    if !replace {
        match nzbkit::disk::open_out_leaf_under(out_dir, &real, nzbkit::disk::LeafOpen::CreateNew) {
            // The name was free at the instant we took it, and no other
            // claimant can take it now. Dropped immediately: the rename
            // below replaces this inode, and holding the handle across
            // it buys nothing.
            Ok(_) => placeholder = true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Neither `note_failure` nor `note_landed`, and both
                // omissions are decisions rather than oversights. This is
                // not a publish FAILURE - X5-09 fails the job for a
                // canonical name a verified file was owed and never got,
                // and a weak tier declining an occupied name is a correct
                // outcome the job should survive. Nor is it a landing:
                // the slot is still under its posted name, so a stronger
                // tier's earlier failure charged to it stands. The
                // `note_landed` above is the arm that clears such a
                // failure, and it fires only where this slot really did
                // take a better name.
                warn!(
                    target: "extract",
                    "declined to publish {real}: something is already there and this \
                     name comes from a weaker tier than whatever is at it - {} keeps \
                     its posted name",
                    path.display()
                );
                return None;
            }
            // Anything else is the door being unusable rather than
            // taken - a leaf that is a symlink the no-follow open
            // refuses, a directory that went away under us, a read-only
            // volume. That is the same class the `prepare_out_path`
            // refusal above takes, and it takes the same arm, so the
            // slot keeps its posted name and the job is told why.
            Err(e) => {
                could_not_publish(taken, slot, &real, path, &e);
                return None;
            }
        }
    }
    // BOUND on the destination side (`rename_out_under`): the
    // directories `real` needs are walked from `out_dir` with no
    // component below it re-resolved, so a directory swapped for a link
    // after `prepare_out_path` cannot carry this publish out of the job
    // directory. `rename(2)` never followed a link at the FINAL
    // component - it replaces it - which is why the identity checks
    // above are about a second NAME for one inode and not about a link.
    match nzbkit::disk::rename_out_under(out_dir, &real, path) {
        Ok(_) => {
            // The belt on the check above, for the window between the two:
            // if `path` became a second link to `target`'s inode after we
            // looked, this rename was the same silent no-op. A success
            // is not the evidence - one entry naming the inode is.
            if nzbkit::disk::is_redundant_link(path, &target) {
                return publish_redundant(out_dir, &target, path, &real, taken, slot);
            }
            info!(
                target: "extract",
                "renamed {} → {real}{}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                displaced_suffix(occupant.as_ref())
            );
            // The caller must tell any live writer (note_slot_renamed):
            // its handle survives the rename, but a by-path reopen
            // (unpark after the external par2) needs this name.
            //
            // `path` is named as the second directory here even though
            // the rename REMOVED it: a rename touches both directories,
            // and the entry that went is exactly as undurable as the one
            // that arrived - so a cut here can bring the posted name
            // back beside the canonical one, which is the residue X5-22
            // asks not to see.
            landed(out_dir, &target, Some(path), taken, slot)
        }
        Err(e) => {
            // Our own placeholder would otherwise be left behind as a
            // zero-byte file wearing the name this slot failed to take,
            // and `PublishedNames::for_dir` seeds the next run from the
            // directory - so a leaked one turns a recoverable failure
            // into a permanent decline. `tv_organize` in
            // `smart/filing.rs` removes its own for the same reason.
            if placeholder {
                let _ = std::fs::remove_file(&target);
            }
            could_not_publish(taken, slot, &real, path, &e);
            None
        }
    }
}

/// The two identity arms of [`publish`] are ONE answer, so they are one
/// function: the target already IS this file under another name, so the
/// redundant posted-name entry goes and the canonical one is reported as
/// landed.
///
/// Folded together on 31 Aug 2026 with the X5-22 durability funnel, and
/// the reason is falsifiability rather than tidiness. The PRE-rename arm
/// is reachable by a test - plant the hardlink, publish - and the belt
/// after the rename is NOT: it exists for the window between the check
/// and the `renameat`, which only a racing thread can open, so nothing
/// deterministic reaches it. Written out twice, a mutation of the belt's
/// copy survived every test in this file (measured). Written once, the
/// mechanism is pinned by the arm that IS reachable and the belt cannot
/// drift away from it.
///
/// STATED LIMIT: what is still unfalsifiable is the belt's CALL, not what
/// it calls. Nothing here can stop somebody inlining a non-durable copy
/// at that site; what it can do is make the copy an obvious one.
fn publish_redundant(
    out_dir: &std::path::Path,
    target: &std::path::Path,
    path: &std::path::Path,
    real: &str,
    taken: &mut PublishedNames,
    slot: usize,
) -> Option<std::path::PathBuf> {
    drop_redundant_alias(path, real);
    landed(out_dir, target, Some(path), taken, slot)
}

/// The ONE way out of [`publish`] that reports a landed name - and the
/// place the publication is made DURABLE (X5-22, 31 Aug 2026).
///
/// Every writer on this path calls `sync_data`, so the BYTES of a
/// published file survive a power cut. Its NAME did not: `publish` made
/// its directory changes - a `create_dir_all` for a tree-preserved name,
/// a `renameat`, an `unlink` of the redundant posted-name alias - and
/// synced no directory at all, on any exit. `nzbkit::disk::sync_dir`
/// existed for exactly this and had ZERO callers in the workspace. So an
/// externally visible rc=0 could be followed by a cut that leaves the
/// canonical entry gone with the payload still on disk under its hash,
/// or the posted-name alias back beside the canonical name.
///
/// THREE SUCCESS EXITS, NOT ONE, and that is why this is a funnel rather
/// than a line at the rename. `publish` reports a landed `Some(target)`
/// from the pre-rename identity arm, from the post-rename identity belt
/// and from the ordinary rename, and the two identity arms are exactly
/// the ones where the canonical entry was created by somebody ELSE - so
/// its directory entry is the one LEAST likely to have been synced
/// already. A durability fix that synced only the rename arm would leave
/// those two nondurable, and that trap was written down as a follow-up
/// of X5-20 before this landed rather than found afterwards. Routing
/// `note_landed` through here too means a fourth exit that reports a
/// landed NAME cannot be added without passing this.
///
/// THE FOURTH `note_landed` IS DELIBERATELY NOT HERE, and it is the one
/// to check before assuming this is incomplete: the "already where it
/// belongs" arm at the top of [`publish`] changes no directory, so there
/// is nothing this call made that could be lost. Whoever created that
/// entry owns its durability - the extract write path, or an earlier
/// publish that came through here - and reaching for it from this
/// function would put an fsync on every slot posted under its own real
/// name to cover a seam that is not this one's.
///
/// WHAT THIS DOES NOT DO, said rather than left to be found. It is the
/// CODE half of X5-22 and not the test half: the row's oracle is an
/// ext4/XFS image under `dm-log-writes` or a VM block device, replaying
/// only acknowledged writes, and no box on this fleet can run it - so
/// nothing here proves the guarantee, only that the syncs are issued on
/// every exit. `sync_dir` is best-effort by contract (SMB/CIFS and some
/// FUSE mounts refuse to open a directory for fsync, and Windows has no
/// directory handle to sync through at all), so a publish is never
/// FAILED over a volume that cannot do this - a job whose bytes are all
/// on disk must not be failed for a durability barrier the filesystem
/// does not offer.
fn landed(
    out_dir: &std::path::Path,
    target: &std::path::Path,
    alias: Option<&std::path::Path>,
    taken: &mut PublishedNames,
    slot: usize,
) -> Option<std::path::PathBuf> {
    for d in publication_dirs(out_dir, target, alias) {
        #[cfg(test)]
        FLUSHED.with_borrow_mut(|v| v.push(d.clone()));
        nzbkit::disk::sync_dir(&d);
    }
    taken.note_landed(slot);
    Some(target.to_path_buf())
}

#[cfg(test)]
thread_local! {
    /// What [`landed`] flushed, so the FUNNEL is falsifiable and not merely
    /// asserted in a doc comment.
    ///
    /// `sync_dir` is best-effort and returns nothing, and no box on this
    /// fleet can run the crash harness X5-22's oracle asks for - so without
    /// this, an exit put back to a bare `note_landed` + `Some(target)` reads
    /// exactly like a durable one and every test stays green. That is the
    /// shape this whole family keeps refusing (a guard nothing can kill),
    /// and the arm it would hide is the one the row names by hand: the two
    /// identity arms, where the canonical entry was created by somebody else
    /// and is least likely to have been synced already.
    ///
    /// A THREAD-LOCAL and never a `static`: `cargo test` runs these on
    /// several threads of ONE process, so a process-global vector would have
    /// each test reading its neighbours' publishes (the class
    /// `tools/test-global-gate.py` exists for). Per-thread, the recorder
    /// belongs to the test that drove it whichever runner is in use.
    static FLUSHED: std::cell::RefCell<Vec<std::path::PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The directories flushed since the last call, and clear.
#[cfg(test)]
fn take_flushed() -> Vec<std::path::PathBuf> {
    FLUSHED.with_borrow_mut(std::mem::take)
}

/// Which directories a publication changed, in the order they must be
/// flushed. Split out of [`landed`] because it is the half that carries
/// the decisions, and the half a crash harness cannot be stood up to
/// check - so it is pinned directly instead.
///
/// THE ORDER IS THE CANONICAL ENTRY FIRST. A cut between two of these
/// syncs is a real state, and the two orders are not equally good: with
/// the destination flushed first, what survives is the canonical name
/// plus, at worst, the posted-name alias back beside it - a duplicate
/// directory entry, which is the residue `drop_redundant_alias` already
/// treats as "worth a line and not a loss". The other order can leave
/// the alias removed with the canonical name not yet on disk, which is
/// the payload reachable under NO name at all.
///
/// THE ANCESTOR WALK is what covers "after fresh parent creation": a
/// tree-preserved FileDesc name renames into a directory `create_out_dirs`
/// may have just made, and that directory's own entry in ITS parent is a
/// separate metadata change. Journaling filesystems order it for us -
/// an fsync commits the transaction, and the mkdir is earlier in it -
/// but that is a property of ext4/XFS/APFS rather than a POSIX
/// guarantee, so the chain is walked instead of leaned on. It costs
/// nothing to do so: the walk stops at `out_dir`, so it is ONE entry for
/// the flat post that is the overwhelmingly common case, and bounded by
/// the FileDesc name's own depth otherwise.
///
/// It also stops at a `target` that is not under `out_dir`, which cannot
/// happen through `rename_out_under`'s bound walk and is guarded anyway:
/// the alternative to stopping is walking to `/` and fsyncing every
/// directory on the way.
///
/// The alias's own directory goes last and only when it is not already
/// in the list - which for a flat post it always is, since the alias and
/// the canonical name share `out_dir` and one fsync covers both the
/// entry that arrived and the entry that went. "Alias" is the posted
/// name on EVERY exit and not only the identity arms: a rename touches
/// both directories, and the entry that went is exactly as undurable as
/// the one that arrived.
fn publication_dirs(
    out_dir: &std::path::Path,
    target: &std::path::Path,
    alias: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    let mut cur = target.parent();
    // TWO GUARDS THAT ARE NOT HERE, and both were removed after a
    // mutation of each survived every test in the file - which is the
    // tell that nothing can reach them, and an unreachable guard makes
    // the one beside it unfalsifiable too. There is no dedupe inside
    // this loop, because a parent chain is strictly ascending and cannot
    // revisit a directory; and there is no empty-path test, because
    // `Path::new("").parent()` is `None` so the walk terminates on its
    // own, and `sync_dir` on a path that will not open is a no-op by its
    // own contract. The alias below is the only place a repeat is
    // possible, so it is the only place a check lives.
    while let Some(d) = cur {
        dirs.push(d.to_path_buf());
        if d == out_dir || !d.starts_with(out_dir) {
            break;
        }
        cur = d.parent();
    }
    if let Some(a) = alias.and_then(|a| a.parent())
        && !dirs.iter().any(|s| s.as_path() == a)
    {
        dirs.push(a.to_path_buf());
    }
    dirs
}

/// What the "renamed" line says about whatever the rename displaced.
///
/// Three answers and not two. A symlink is neither "nothing was there"
/// nor "the previous copy": `rename(2)` removes the LINK and leaves what
/// it pointed at alone, so calling that a replaced copy is wrong even
/// when the link resolved. Split out of the `info!` so all three can be
/// pinned without standing up a tracing subscriber; the decision behind
/// it, and why it is not X5-07, is at the `symlink_metadata` call in
/// `publish`.
fn displaced_suffix(occupant: Option<&std::fs::Metadata>) -> &'static str {
    match occupant {
        Some(m) if m.file_type().is_symlink() => " (replaced a symlink that was there)",
        Some(_) => " (replaced the previous copy)",
        None => "",
    }
}

/// Unlink the posted-name entry that X5-20 leaves behind: a second name
/// for the inode the canonical name already holds.
///
/// A failure here is NOT `could_not_publish`. That arm charges the job
/// with "the verified file is still under its posted name", and here it
/// is not - the canonical entry names the verified bytes either way, so
/// charging it would fail a job that delivered. What is left is a
/// duplicate directory entry, which is worth a line and is not a loss.
fn drop_redundant_alias(path: &std::path::Path, real: &str) {
    let posted = path.file_name().unwrap_or_default().to_string_lossy();
    match std::fs::remove_file(path) {
        Ok(()) => info!(
            target: "extract",
            "published {real}: it was already the same file as {posted} - \
             removed the redundant posted-name link"
        ),
        Err(e) => warn!(
            target: "extract",
            "published {real}, but could not remove {posted}, the second \
             name for the same file: {e}"
        ),
    }
}

/// The one could-not-publish arm: say so, and CHARGE it, so the verdict
/// can see it.
///
/// X5-09: both failure arms above used to warn and return `None`, and
/// `None` is also what a no-op returns, so no caller could tell "already
/// correct" from "the payload is stranded under a hash". The job then
/// finished rc=0 with one warn line in a log ring nobody reads. Charging
/// it here rather than at the four call sites is deliberate - the fifth
/// call site gets the same accounting without anyone remembering to add
/// it, which is exactly what the previous arrangement did not do.
fn could_not_publish(
    taken: &mut PublishedNames,
    slot: usize,
    real: &str,
    path: &std::path::Path,
    e: &std::io::Error,
) {
    warn!(
        target: "extract",
        "could not publish {real}: {e} - the verified file is still at {}",
        path.display()
    );
    taken.note_failure(slot, real);
}

#[cfg(test)]
#[path = "publish_name_tests.rs"]
mod publish_name_tests;
