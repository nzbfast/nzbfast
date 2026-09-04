//! The post-forfeit resume ledger: the disk unpack picks up where the
//! chase stopped instead of extracting the member from byte zero.
//!
//! # The waste this exists to remove
//!
//! A compressed RAR set larger than the held-bytes slice is chased in
//! RAM while it arrives. Two things can happen when the budget goes
//! over: the drop-behind trim releases a consumed prefix and the chase
//! carries on, or the chase FORFEITS and the whole set materializes for
//! the disk pass. Both are fine on their own. It is the SEQUENCE that
//! is expensive - trim a few times, then forfeit anyway - because the
//! forfeit used to throw away every byte the chase had already decoded
//! correctly and re-extract the member from scratch.
//!
//! Measured 21 Aug 2026 on a fast NVMe workstation - a 1.82:1
//! compressed RAR5 set twice the size of the holds slice, arriving at
//! 250 MB/s: **1.96-1.98x** payload of device I/O, against **1.556x**
//! for the same set forfeiting without ever trimming and **1.478x** for
//! a trim that keeps pace. The worst of the four endings was the one in
//! the middle, and about 3.3 GiB of that was in-stream output written
//! correctly and then deleted.
//!
//! # What resuming does and does not save
//!
//! It saves the WRITE. A compressed member has no seekable entry point,
//! so the disk pass still decodes from byte zero - the LZ window and the
//! CRC both demand it - but the decoded bytes below the mark go to a
//! counter instead of to the device. On the measured shape that is the
//! whole ~3.3 GiB, which is what takes trim-then-forfeit back down to
//! plain-forfeit cost. It saves no CPU.
//!
//! # Why the prefix can be trusted
//!
//! [`nzbkit::extract::ResumeOutput`] carries the rules; the short of it
//! is that the chase writes each member sequentially, the extractor
//! records the CONTIGUOUS prefix rather than the byte count, only a
//! settled plain output qualifies, and only the held-bytes-cap forfeit
//! records anything at all - a forfeit raised because "repair rewrote
//! chased bytes" means the decode may have run over bytes PAR2 has
//! since corrected, which is exactly the prefix nobody may trust. A
//! repair landing AFTER the forfeit drops the ledger from the other
//! side, inside the extractor.
//!
//! # Which disk arms use it
//!
//! All four. The RAR arm (`rarfix::native`) shipped first, on 22 Aug
//! 2026; the 7z and zip arms (`rarfix::extract_one_sevenz` /
//! `extract_one_zip`) followed the same day as TODO 213 item 2, because
//! their forfeit takes a different road out of the extractor
//! (`sevenz_fallback_set`) and their disk pass a different road in - the
//! 7z one reads a split set through one logical byte-space over the
//! ordered parts, the zip one opens its entry writers on a worker pool.
//! Neither changes the seam this module owns, which is the member's own
//! output file. The tar arm (`rarfix::tar`) joined on 23 Aug 2026 with
//! TODO 163 item 6's disk half, through the same forfeit road as those
//! two - a tar chase tears its sinks down in `sevenz_teardown_sinks`
//! like any other container - and it takes the plan only when there is
//! a ledger to plan against, since a tar's member list costs a whole
//! extra read of the container. What they share is
//! [`plan_pass`] and [`ResumeWriter`], and that sharing is the point:
//! the duplicate-name refusal and the clear-before-extract step are
//! guards a per-arm copy would quietly ship without.
//!
//! This module adds the disk-side half of that: an entry is used only
//! when the file is still EXACTLY the length the extractor cut it to
//! (so nothing has touched it in between) and sits at exactly the path
//! the disk pass would itself have published the member to (so no
//! rename, dedup suffix or subdirectory can put the bytes somewhere
//! else). Anything that fails either test is left to extract from byte
//! zero, which is the old behaviour and always correct.
//!
//! # The cleanup contract
//!
//! Keeping a partial on disk is the whole trick, and a partial nobody
//! goes on to finish is the hazard the forfeit's delete used to remove.
//! So the arm owns them: on drop it removes every entry the unpack did
//! not take, and it proves ownership by length first - a file that has
//! GROWN past the mark was finished by somebody (the resume itself, or
//! the unrar subprocess publishing over it) and is never removed.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

/// One kept partial, as the disk pass sees it.
#[derive(Debug, Clone)]
struct Entry {
    /// The archive member name; the key the extraction callback matches.
    member: String,
    /// Where the chase left the bytes.
    path: PathBuf,
    /// How many of them are good - and, until somebody appends, the
    /// file's exact length.
    len: u64,
    /// CRC32 of those bytes as the chase wrote them (TODO 217). The
    /// pass re-decodes the prefix anyway, so it hashes the re-decode on
    /// the way past and compares at the mark - see [`ResumeWriter`].
    crc32: u32,
    /// The unpack has taken responsibility for this file; the arm must
    /// not remove it.
    done: bool,
    /// The unpack COMPLETED this member by appending to it. Distinct
    /// from `done`, which a discard also sets: only this one is proof
    /// that the pass produced something - see [`finished_any`].
    finished: bool,
    /// This entry may actually be resumed from. False on a stood-down
    /// arm, which still owns the files - and still removes them - but
    /// offers none of them to an unpack.
    resumable: bool,
}

thread_local! {
    /// Armed for the duration of ONE job's disk unpack ladder, on that
    /// job's own thread - the same thread-local shape, and for the same
    /// reason, as [`crate::eatvol`]'s eat arm: two jobs' tails overlap,
    /// and a global would offer one job's partials to the other job's
    /// unpack. The tail runs under `lanegate::off_worker`, which is
    /// `block_in_place` precisely so these stay on one thread.
    static ARMED: RefCell<Vec<Entry>> = const { RefCell::new(Vec::new()) };
}

/// RAII arming for one job's unpack ladder.
pub struct ResumeArm(Vec<Entry>);

impl ResumeArm {
    /// Arm the ledger the extractor reported. Restores whatever was
    /// armed before on drop, so a nested pass cannot leave one job's
    /// entries standing for whatever this thread does next.
    pub fn new(outputs: &[nzbkit::extract::ResumeOutput]) -> ResumeArm {
        Self::armed(outputs, true)
    }

    /// Take OWNERSHIP of the partials without offering any of them: the
    /// caller has decided this job's prefixes cannot be trusted (a
    /// disk-side repair rewrote the volumes they were decoded from).
    ///
    /// Not the same as arming nothing, and the difference is the whole
    /// point: an empty arm leaves the files sitting in the output
    /// directory, where a short file under the payload's own name is
    /// exactly what the forfeit's delete used to prevent. This arm
    /// removes them on drop like any untaken entry.
    pub fn stood_down(outputs: &[nzbkit::extract::ResumeOutput]) -> ResumeArm {
        Self::armed(outputs, false)
    }

    fn armed(outputs: &[nzbkit::extract::ResumeOutput], resumable: bool) -> ResumeArm {
        let entries: Vec<Entry> = outputs
            .iter()
            .map(|r| Entry {
                member: r.member.clone(),
                path: r.path.clone(),
                len: r.len,
                crc32: r.crc32,
                done: false,
                finished: false,
                resumable,
            })
            .collect();
        ResumeArm(ARMED.with(|a| a.replace(entries)))
    }
}

impl Drop for ResumeArm {
    fn drop(&mut self) {
        let mine = ARMED.with(|a| a.replace(std::mem::take(&mut self.0)));
        for e in mine {
            if e.done {
                continue;
            }
            // Length is the ownership proof. Still exactly the mark: the
            // ladder walked past this member (no set to unpack, no
            // password, the job failed before the unpack, an unpack that
            // never reached this member) and the partial is ours to
            // remove - leaving it would put a short file with a
            // plausible name in the output directory, which is the whole
            // reason the forfeit used to delete it. Anything longer was
            // finished by somebody else - the unrar subprocess publishes
            // over this very path, and deleting its output would destroy
            // the payload on a job that had just succeeded. The one
            // exception is `clear_unresumed`, which removes a moved
            // partial at a path the native pass is ABOUT to publish to,
            // length or no length: a grown partial there is still the
            // chase's own file, and leaving it would shunt the real
            // member to a disambiguated name (Codex F-10, kept).
            let owned = std::fs::metadata(&e.path).is_ok_and(|m| m.len() == e.len);
            if owned {
                let _ = std::fs::remove_file(&e.path);
            }
        }
    }
}

/// The members this extraction may resume, keyed by member name.
///
/// `dir` is where the unpack will PUBLISH, which is not where it writes
/// (that is a staging directory): the comparison has to be against the
/// published path, because that is what the chase wrote and what the
/// staging copy would later be renamed over.
///
/// Empty for every ordinary unpack, and cheap to ask for. The value is
/// (path, mark, crc32 of the bytes below the mark).
pub(crate) fn plan(dir: &Path) -> std::collections::HashMap<String, (PathBuf, u64, u32)> {
    ARMED.with(|a| {
        a.borrow()
            .iter()
            .filter(|e| e.resumable && !e.done && e.len > 0)
            // The member has to land exactly where the chase put it. A
            // subdirectory member, a name the extractor had to
            // deduplicate, a name the two sanitizers spell differently -
            // each of them fails this and extracts from byte zero, which
            // is merely the old cost.
            .filter(|e| sanitized_entry_path(dir, &e.member).as_ref() == Some(&e.path))
            // Nothing may have touched the file since the extractor cut
            // it to the mark. Cheap, and it closes the window between
            // `finish` and here.
            .filter(|e| std::fs::metadata(&e.path).is_ok_and(|m| m.len() == e.len))
            .map(|e| (e.member.clone(), (e.path.clone(), e.len, e.crc32)))
            .collect()
    })
}

/// The members ONE disk extraction pass may resume, with every guard
/// that pass has to apply before it opens a single file: the plan
/// itself, the duplicate-name refusal, and the removal of the partials
/// it is not taking.
///
/// `members` is every entry name the pass will write, in any order.
/// A name it carries TWICE is dropped from the plan: both entries would
/// otherwise open the same partial at the same mark, and the published
/// file would be the first entry's prefix with the second's tail, with
/// both reporting success (Codex F-02, 22 Aug 2026). Such a name falls
/// into `clear_unresumed`'s set instead and extracts from byte zero,
/// which is merely the old cost.
///
/// Call it on the thread the ladder armed, and before the extraction
/// opens anything: the ledger is a thread-local, and both the RAR
/// engine and the zip pass reach their entry writers from worker
/// threads.
///
/// Shared by all four disk arms - RAR (`rarfix::native`), 7z, zip and
/// tar (`rarfix`) - rather than spelled once per arm, because the
/// duplicate rule and the clear-before-extract rule are exactly the sort
/// of guard a per-arm copy would quietly ship without. The tar arm
/// (TODO 163 item 6, 23 Aug 2026) was the fourth, and it asks for the
/// plan only when the ledger is non-empty: its member list costs a
/// second sequential read of the container, because a tar is skipped by
/// READING and there is no seek on that path.
pub(crate) fn plan_pass(
    dir: &Path,
    members: &[String],
) -> std::collections::HashMap<String, (PathBuf, u64, u32)> {
    let mut resume = plan(dir);
    resume.retain(|name, _| members.iter().filter(|m| *m == name).count() == 1);
    clear_unresumed(dir, members.iter().cloned(), &resume);
    if !resume.is_empty() {
        let bytes: u64 = resume.values().map(|(_, len, _)| *len).sum();
        tracing::info!(
            target: "extract",
            "resuming {} member(s) from what the in-stream decode already wrote ({:.1} GB not re-written)",
            resume.len(),
            bytes as f64 / 1e9
        );
    }
    resume
}

/// Hand the files a pass appended to back to the ledger: kept on
/// success, removed on failure.
///
/// A failed append cannot be left on disk - the arm's own cleanup proves
/// ownership by LENGTH, and a partial somebody has appended to no longer
/// has the length it was cut to, so the arm would read it as a published
/// payload and leave it there.
pub(crate) fn finish(paths: &[PathBuf], ok: bool) {
    if paths.is_empty() {
        return;
    }
    if ok {
        keep(paths);
    } else {
        discard(paths);
    }
}

/// Open a resumed member's file positioned at its mark, for a pass that
/// will append the rest of it.
///
/// Deliberately WITHOUT truncation and in the output directory rather
/// than in staging: the prefix is already published, and there is no way
/// to append to it from a staged copy (a hardlink would share the inode,
/// so the writes would land in the published file anyway - with none of
/// the atomicity a staged copy implies).
pub(crate) fn open_at_mark(path: &Path, len: u64) -> std::io::Result<std::fs::File> {
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(len))?;
    Ok(f)
}

/// Remove every armed partial this extraction is about to publish OVER
/// but is not resuming, and mark it taken.
///
/// The publish step refuses to overwrite: it merges and disambiguates
/// rather than clobber (`lift_scratch_into`), so a leftover partial
/// sitting under a member's own name would push the real payload out to
/// a second name beside it. A partial the pass declined - the mark no
/// longer matches the file, most likely - has no further use anyway, so
/// it goes before extraction starts rather than after.
///
/// Keyed on the published PATH, not on the length: whatever the file is
/// now, this pass is about to write the member there.
pub(crate) fn clear_unresumed<I: Iterator<Item = String>>(
    dir: &Path,
    members: I,
    resuming: &std::collections::HashMap<String, (PathBuf, u64, u32)>,
) {
    let doomed: Vec<PathBuf> = members
        .filter(|m| !resuming.contains_key(m))
        .filter_map(|m| sanitized_entry_path(dir, &m))
        .collect();
    if doomed.is_empty() {
        return;
    }
    let hit: Vec<PathBuf> = ARMED.with(|a| {
        a.borrow()
            .iter()
            .filter(|e| !e.done && doomed.contains(&e.path))
            .map(|e| e.path.clone())
            .collect()
    });
    discard(&hit);
}

/// The unpack finished with these files and owns them now: the arm must
/// leave them alone.
pub(crate) fn keep(paths: &[PathBuf]) {
    ARMED.with(|a| {
        for e in a.borrow_mut().iter_mut() {
            if paths.contains(&e.path) {
                e.done = true;
                e.finished = true;
            }
        }
    });
}

/// Did this job's unpack COMPLETE a member by resuming it?
///
/// One caller, and it is about deleting the volume set. The spent-volume
/// rule wants proof that the unpack published something before it will
/// remove the set it read, and it takes that proof from a before/after
/// diff of the directory - which a resumed member cannot appear in,
/// because its path was already there when the snapshot was taken. Left
/// at that, the very shape this module exists for would finish with the
/// payload complete AND its whole volume set still beside it, which is
/// the 144-volume / 57 GB regression Part B of the one-pass spec closed.
pub(crate) fn finished_any() -> bool {
    ARMED.with(|a| a.borrow().iter().any(|e| e.finished))
}

/// The unpack that was appending to these files FAILED, so what is on
/// disk now is a partial nobody can account for - neither the chase's
/// clean prefix nor a finished member. Remove them here rather than
/// leaving them to the arm's length test, which by now cannot tell them
/// from a published payload.
pub(crate) fn discard(paths: &[PathBuf]) {
    for p in paths {
        let _ = std::fs::remove_file(p);
    }
    keep(paths);
}

/// Stand the whole armed ledger down: remove every partial not yet
/// taken and mark it done, so a following pass has nothing to resume.
///
/// This is [`with_mismatch_retry`]'s rewind - once a resumed prefix has
/// failed its verification, no kept prefix of this job is worth another
/// attempt, and marking them done is also the loop-proof: the retry's
/// own `plan` comes back empty, so no [`ResumeWriter::verified`] is
/// ever built and no second mismatch can fire.
pub(crate) fn stand_down_all() {
    let hit: Vec<PathBuf> = ARMED.with(|a| {
        a.borrow()
            .iter()
            .filter(|e| !e.done)
            .map(|e| e.path.clone())
            .collect()
    });
    discard(&hit);
}

/// Run one disk extraction pass that may resume from the chase's kept
/// prefixes, and run it once more from byte zero if a resumed prefix
/// failed its verification (TODO 217's rewind).
///
/// The mismatch is detected inside the extraction engine's entry
/// callback, mid-write, and erroring is the only way out of there - so
/// the whole pass fails, this catches exactly that failure (the flag
/// distinguishes it from every other error), clears the ledger and
/// retries. It cannot loop: [`stand_down_all`] leaves nothing for the
/// second pass's plan, so the second pass has no verified writer to
/// fail, and structurally there is no third call.
///
/// `retry_ok` gates the rewind for a pass that has already destroyed
/// its own inputs - the volume-eating mode deletes each source as the
/// extractor finishes with it, and a retry over missing volumes would
/// turn a clean fallback into a second, stranger failure.
pub(crate) fn with_mismatch_retry<T>(
    retry_ok: impl FnOnce() -> bool,
    mut pass: impl FnMut(&MismatchFlag) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let flag: MismatchFlag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    match pass(&flag) {
        Err(e) if flag.load(std::sync::atomic::Ordering::Relaxed) && retry_ok() => {
            tracing::info!(
                target: "extract",
                "a resumed prefix did not match the re-decode ({e:#}); \
                 extracting from byte zero"
            );
            stand_down_all();
            let fresh: MismatchFlag =
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            pass(&fresh)
        }
        r => r,
    }
}

/// A writer that swallows the first `skip` bytes and appends the rest to
/// an existing file from offset `skip`.
///
/// The swallowed bytes are the ones already on disk. They are still
/// DECODED - a compressed member cannot be entered part-way - so this
/// saves the write, not the work.
///
/// TODO 217: a [`verified`] writer additionally hashes the swallowed
/// bytes and compares against the checksum the chase recorded, at the
/// mark - the last instant before the first appended byte. A match
/// PROVES the append writes exactly what a from-zero extract would
/// have; a mismatch errors out of the pass and raises its flag, and
/// [`with_mismatch_retry`] turns that into one from-zero retry.
///
/// [`verified`]: ResumeWriter::verified
pub(crate) struct ResumeWriter<W: std::io::Write> {
    /// Bytes still to be swallowed before `inner` sees any.
    skip: u64,
    /// The verification half: hash of the swallowed bytes so far, the
    /// checksum they must equal at the mark, and the flag a mismatch
    /// raises. `None` on an unverified writer.
    verify: Option<(crc32fast::Hasher, u32, MismatchFlag)>,
    inner: W,
}

/// The flag a resumed prefix's failed verification raises, shared by
/// every [`ResumeWriter`] of one pass - the entry writers run on the
/// extraction engine's own threads, so the pass reads it afterwards.
pub(crate) type MismatchFlag = std::sync::Arc<std::sync::atomic::AtomicBool>;

impl<W: std::io::Write> ResumeWriter<W> {
    /// The unverified writer. Test-only since TODO 217: every
    /// production arm records a checksum with the mark and builds
    /// [`ResumeWriter::verified`], so an unverified resume cannot be
    /// spelled outside this module's own unit tests.
    #[cfg(test)]
    pub(crate) fn new(skip: u64, inner: W) -> Self {
        ResumeWriter {
            skip,
            verify: None,
            inner,
        }
    }

    /// A writer that verifies the swallowed prefix against `crc32` at
    /// the mark, raising `flag` on a mismatch. Every production arm
    /// builds this one - the unverified [`ResumeWriter::new`] is the
    /// degenerate shape (`skip == 0`, nothing to verify) and the unit
    /// tests'.
    pub(crate) fn verified(skip: u64, crc32: u32, flag: MismatchFlag, inner: W) -> Self {
        ResumeWriter {
            skip,
            verify: (skip > 0).then(|| (crc32fast::Hasher::new(), crc32, flag)),
            inner,
        }
    }

    /// Compare the hashed re-decode against the recorded checksum. Called
    /// exactly once, when `skip` reaches zero (or at flush for a member
    /// whose whole output was below the mark - the decode then ends
    /// without a byte to append, and an unchecked prefix would publish
    /// unverified).
    fn check_at_mark(&mut self) -> std::io::Result<()> {
        let Some((hasher, want, flag)) = self.verify.take() else {
            return Ok(());
        };
        let got = hasher.finalize();
        if got == want {
            return Ok(());
        }
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
        Err(std::io::Error::other(
            "the resumed prefix does not match the re-decode; extracting from byte zero",
        ))
    }
}

impl<W: std::io::Write> std::io::Write for ResumeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.skip == 0 {
            return self.inner.write(buf);
        }
        let drop = (self.skip.min(buf.len() as u64)) as usize;
        if let Some((hasher, _, _)) = &mut self.verify {
            hasher.update(&buf[..drop]);
        }
        self.skip -= drop as u64;
        if self.skip == 0 {
            // The last instant before the first appended byte: everything
            // below the mark has been re-decoded and hashed, and nothing
            // has been written yet.
            self.check_at_mark()?;
        }
        if drop == buf.len() {
            return Ok(drop);
        }
        // The write that straddles the mark: report the whole buffer
        // consumed, because it was - part to the counter, part to the
        // file. A short count here would have the caller re-offer the
        // swallowed head.
        self.inner.write_all(&buf[drop..])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // A member the chase had finished entirely: the decode ran out
        // exactly at the mark, so no write ever crossed it and the
        // comparison has to happen here instead. A decode that ended
        // SHORT of the mark is a mismatch outright - the file on disk is
        // longer than anything this pass re-decoded, so nothing can
        // vouch for its tail.
        if let Some((_, _, flag)) = &self.verify
            && self.skip > 0
        {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
            self.verify = None;
            return Err(std::io::Error::other(
                "the re-decode ended short of the resumed mark; extracting from byte zero",
            ));
        }
        self.check_at_mark()?;
        self.inner.flush()
    }
}

// Both path joins below were `rarfix`'s until the crate-split prep (step
// 1 of research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md). They are pure
// `nzbkit::disk` sanitization with no extractor state behind them, and
// `plan` below computes the SAME key under the publish root to decide
// whether a forfeited chase already wrote a member - so leaving them in
// the extractor was the one edge that made these two modules need each
// other. `rarfix` re-exports both.

/// Join an archive-entry name onto `dir`, rejecting traversal: absolute
/// paths, drive/UNC prefixes, and `..` components all return None.
///
/// `None` means HOSTILE here and nothing else, which is why the length
/// rules below answer with a name instead: every caller turns `None`
/// into an aborted extraction, so anything this refuses takes the whole
/// archive with it.
pub(crate) fn sanitized_entry_path(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    sanitized_entry_path_for(dir, name, cfg!(windows))
}

/// `sanitized_entry_path` with the host as a parameter, so the Windows-only
/// guarantee is asserted by the suite on the Mac and Linux boxes we develop
/// and run CI on.
pub(crate) fn sanitized_entry_path_for(
    dir: &std::path::Path,
    name: &str,
    windows: bool,
) -> Option<PathBuf> {
    use std::path::Component;
    // RAR4-era archives store Windows-style separators; normalize so the
    // name splits into components on every platform. The ORIGINAL is
    // kept because the flat fallback at the foot of this function has
    // to be byte-identical to the in-stream side's, which is handed the
    // name as posted.
    let original = name;
    let name = name.replace('\\', "/");
    let entry = std::path::Path::new(name.trim_start_matches('/'));
    let mut target = dir.to_path_buf();
    let mut pushed = false;
    for component in entry.components() {
        match component {
            Component::Normal(part) => {
                // `Components` only parses a drive/UNC prefix at byte 0, so a
                // LATER component can still carry one ("sub/C:evil.dll") - and
                // `PathBuf::push` re-parses what it is given and CLEARS the
                // buffer when the pushed piece has a prefix, dropping the
                // staging dir entirely. Sanitize every component (which maps
                // ':' on Windows) so no entry name can escape.
                //
                // CAPPED, and the cap belongs HERE rather than at any of the
                // writers. This function's result is not only the path the
                // entry is written to, it IS the filesystem-identity key the
                // module compares on - `extract_one_zip`'s duplicate-target
                // dedup, and `resumeout::plan`'s "did the chase publish
                // exactly here" test. Capping at a writer would shorten one
                // end of that comparison and not the other, which splits the
                // key: two members that resolve to one path would stop being
                // seen as one and race on the pool, each verifying only its
                // own CRC over interleaved bytes. Both ends are this one
                // value, so they cannot part. Nothing that works today
                // changes either - an entry with a component over 255 bytes
                // is `ENAMETOOLONG` at `create_dir_all` or `File::create`
                // today, so every name this shortens is one the write
                // refused outright. It also spells an overlong FLAT member
                // exactly as `sanitize_out_name` does, so a resume that
                // falls back to byte zero today now matches.
                let part =
                    nzbkit::disk::sanitize_filename_capped_for(&part.to_string_lossy(), windows);
                target.push(part);
                pushed = true;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    // Belt and braces: nothing above may leave `dir`.
    if !(pushed && target.starts_with(dir)) {
        return None;
    }
    // THE WHOLE-NAME BUDGET, and it answers with a NAME rather than
    // with `None`. Capping per component above bounds each piece and
    // says nothing about their sum: an entry carrying MANY legal
    // components joins to a path past the filesystem's own ceiling,
    // and there is no per-component shortening that fixes that. What
    // it cost while this was missing was measured on 31 Aug 2026 - an
    // entry of 8 components of 200 bytes took `extract_one_zip` down
    // with `ENAMETOOLONG` at `create_dir_all`, before a single byte of
    // the archive was written, so an ordinary sibling member in the
    // same zip was not extracted either. One awkward entry, and the
    // user gets nothing.
    //
    // Refusing here would have bought exactly that same outcome by a
    // shorter route (`None` -> the caller bails), so the answer is the
    // FLAT capped form - the identical fallback
    // `nzbkit::disk::sanitize_out_name_for` takes for its own
    // whole-name cap, through the identical function, so the two
    // sanitizers spell an over-budget member the same way and
    // `resumeout::plan` matches instead of falling back to byte zero.
    // The archive still extracts; one member lands beside its tree
    // rather than inside it.
    //
    // ROOT-INDEPENDENT, deliberately, and that is the constraint that
    // rules out the obvious alternative of shortening components until
    // the joined path fits. This value is the filesystem-IDENTITY key
    // the module compares on (see the cap note above), and it is
    // computed under TWO different roots in one job - the staging dir
    // here, the publish dir in `resumeout::plan` - so a budget spent
    // against the root would have the two ends disagree about whether
    // to shorten and split the key. The measurement says a root-aware
    // budget could not be exact anyway: the kernel's ceiling applies
    // to the RESOLVED path, so an ancestor symlink moves it (8 bytes
    // through `/tmp` on this fleet's Macs) and no caller can compute
    // the real number from the string it holds.
    // `starts_with` above already proved the strip cannot fail; a
    // refactor that breaks that is a containment failure, so it takes
    // the hostile answer rather than the over-budget one. Borrowed,
    // not allocated: every component came back from
    // `sanitize_filename_capped_for` as a `String`.
    let rel = target.strip_prefix(dir).ok()?.to_string_lossy();
    if !nzbkit::disk::relpath_within_total(&rel) {
        return Some(dir.join(nzbkit::disk::sanitize_filename_capped_for(
            original, windows,
        )));
    }
    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-resumeout-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn out(member: &str, path: &Path, len: u64) -> nzbkit::extract::ResumeOutput {
        nzbkit::extract::ResumeOutput {
            member: member.to_string(),
            path: path.to_path_buf(),
            len,
            crc32: 0,
        }
    }

    /// The straddling write is the only interesting case: the mark falls
    /// inside a buffer, and both halves have to go to the right place
    /// with the caller told the whole buffer landed.
    #[test]
    fn the_writer_swallows_exactly_the_mark_and_appends_the_rest() {
        let mut sink: Vec<u8> = Vec::new();
        {
            let mut w = ResumeWriter::new(5, &mut sink);
            assert_eq!(w.write(b"abc").unwrap(), 3);
            assert_eq!(w.write(b"defgh").unwrap(), 5);
            assert_eq!(w.write(b"ij").unwrap(), 2);
        }
        assert_eq!(sink, b"fghij");
    }

    fn flag() -> MismatchFlag {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    /// TODO 217's match arm at the seam: a verified writer whose
    /// swallowed bytes hash to the recorded checksum appends exactly
    /// like an unverified one, and raises nothing.
    #[test]
    fn a_verified_writer_that_matches_appends_and_raises_nothing() {
        let f = flag();
        let mut sink: Vec<u8> = Vec::new();
        {
            let mut w = ResumeWriter::verified(5, crc32fast::hash(b"abcde"), f.clone(), &mut sink);
            assert_eq!(w.write(b"abc").unwrap(), 3);
            assert_eq!(w.write(b"defgh").unwrap(), 5);
            w.flush().unwrap();
        }
        assert_eq!(sink, b"fgh");
        assert!(!f.load(std::sync::atomic::Ordering::Relaxed));
    }

    /// The mismatch arm: the re-decode disagrees with the recorded
    /// checksum, the write that crosses the mark errors BEFORE a byte
    /// reaches the file, and the flag is raised for the rewind. RED
    /// against a revert of the verification: an unverified writer
    /// appends the tail regardless.
    #[test]
    fn a_verified_writer_that_mismatches_errors_at_the_mark() {
        let f = flag();
        let mut sink: Vec<u8> = Vec::new();
        {
            let mut w = ResumeWriter::verified(5, crc32fast::hash(b"XXXXX"), f.clone(), &mut sink);
            assert_eq!(w.write(b"abc").unwrap(), 3);
            let err = w.write(b"defgh").unwrap_err();
            assert!(err.to_string().contains("does not match"), "{err}");
        }
        assert!(sink.is_empty(), "no byte may land after a failed check");
        assert!(f.load(std::sync::atomic::Ordering::Relaxed));
    }

    /// A member the chase had finished entirely: the decode ends exactly
    /// at the mark. The check fires the moment `skip` reaches zero -
    /// inside that final write - and both verdicts land there, with
    /// flush having nothing left to judge.
    #[test]
    fn a_whole_member_below_the_mark_is_verified_at_the_final_write() {
        let ok = flag();
        let mut sink: Vec<u8> = Vec::new();
        let mut w = ResumeWriter::verified(5, crc32fast::hash(b"abcde"), ok.clone(), &mut sink);
        w.write_all(b"abcde").unwrap();
        w.flush().unwrap();
        assert!(!ok.load(std::sync::atomic::Ordering::Relaxed));

        let bad = flag();
        let mut sink2: Vec<u8> = Vec::new();
        let mut w = ResumeWriter::verified(5, crc32fast::hash(b"abcdX"), bad.clone(), &mut sink2);
        assert!(w.write_all(b"abcde").is_err(), "the final write checks");
        assert!(bad.load(std::sync::atomic::Ordering::Relaxed));
        assert!(sink2.is_empty());
    }

    /// A decode that ends SHORT of the mark is a mismatch outright: the
    /// file holds bytes nothing re-decoded, so nothing can vouch for
    /// them.
    #[test]
    fn a_decode_that_ends_short_of_the_mark_is_a_mismatch() {
        let f = flag();
        let mut sink: Vec<u8> = Vec::new();
        let mut w = ResumeWriter::verified(10, crc32fast::hash(b"abc"), f.clone(), &mut sink);
        w.write_all(b"abc").unwrap();
        assert!(w.flush().is_err());
        assert!(f.load(std::sync::atomic::Ordering::Relaxed));
    }

    /// The rewind cannot loop: after `stand_down_all` the plan is empty,
    /// so the second pass has nothing to verify - and the helper only
    /// ever runs the pass twice by construction.
    #[test]
    fn the_mismatch_retry_stands_the_ledger_down_and_runs_exactly_twice() {
        let dir = tmpdir("retry");
        let p = dir.join("film.mkv");
        std::fs::write(&p, vec![7u8; 100]).unwrap();
        let _arm = ResumeArm::new(&[out("film.mkv", &p, 100)]);
        let mut runs = 0u32;
        let res: anyhow::Result<u32> = with_mismatch_retry(
            || true,
            |flag| {
                runs += 1;
                if runs == 1 {
                    assert_eq!(plan(&dir).len(), 1, "first pass sees the entry");
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    anyhow::bail!("prefix mismatch");
                }
                assert!(plan(&dir).is_empty(), "the rewind must clear the plan");
                Ok(runs)
            },
        );
        assert_eq!(res.unwrap(), 2);
        assert!(!p.exists(), "the stood-down partial must be removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An error WITHOUT the flag is not a mismatch and must not retry -
    /// and a mismatch the gate refuses (sources already eaten) must
    /// surface the original error.
    #[test]
    fn the_retry_fires_only_on_a_flagged_mismatch_the_gate_allows() {
        let mut runs = 0u32;
        let res: anyhow::Result<()> = with_mismatch_retry(
            || true,
            |_| {
                runs += 1;
                anyhow::bail!("ordinary failure");
            },
        );
        assert!(res.is_err());
        assert_eq!(runs, 1, "an unflagged error must not retry");

        let mut runs = 0u32;
        let res: anyhow::Result<()> = with_mismatch_retry(
            || false,
            |flag| {
                runs += 1;
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
                anyhow::bail!("prefix mismatch");
            },
        );
        assert!(res.is_err());
        assert_eq!(runs, 1, "a refused gate must not retry");
    }

    /// A zero-length skip is an ordinary writer, and a skip longer than
    /// everything offered writes nothing.
    #[test]
    fn the_writer_degenerates_cleanly_at_both_ends() {
        let mut all: Vec<u8> = Vec::new();
        ResumeWriter::new(0, &mut all).write_all(b"abcd").unwrap();
        assert_eq!(all, b"abcd");
        let mut none: Vec<u8> = Vec::new();
        ResumeWriter::new(99, &mut none).write_all(b"abcd").unwrap();
        assert!(none.is_empty());
    }

    /// The plan admits the file the chase actually wrote, and refuses a
    /// file whose length has moved since - the guard that keeps a
    /// resumed member from being resumed twice.
    #[test]
    fn the_plan_admits_an_untouched_partial_and_refuses_a_moved_one() {
        let dir = tmpdir("plan");
        let p = dir.join("film.mkv");
        std::fs::write(&p, vec![7u8; 100]).unwrap();
        let _arm = ResumeArm::new(&[out("film.mkv", &p, 100)]);
        assert_eq!(plan(&dir).get("film.mkv"), Some(&(p.clone(), 100, 0)));
        std::fs::write(&p, vec![7u8; 140]).unwrap();
        assert!(plan(&dir).is_empty());
        keep(std::slice::from_ref(&p));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A member whose on-disk path is not the one the disk pass would
    /// publish it to (here: the extractor had to deduplicate the name)
    /// never resumes - the bytes would go to the wrong file.
    #[test]
    fn the_plan_refuses_a_partial_that_moved_off_its_published_name() {
        let dir = tmpdir("renamed");
        let p = dir.join("film-1.mkv");
        std::fs::write(&p, vec![7u8; 100]).unwrap();
        let _arm = ResumeArm::new(&[out("film.mkv", &p, 100)]);
        assert!(plan(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stood-down arm offers nothing and still cleans up - the shape
    /// a job whose volumes were repaired on disk takes.
    #[test]
    fn a_stood_down_arm_offers_nothing_and_still_removes_the_partial() {
        let dir = tmpdir("standdown");
        let p = dir.join("film.mkv");
        std::fs::write(&p, vec![7u8; 100]).unwrap();
        {
            let _arm = ResumeArm::stood_down(&[out("film.mkv", &p, 100)]);
            assert!(plan(&dir).is_empty(), "a stood-down arm must offer nothing");
        }
        assert!(!p.exists(), "it still owns the partial");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The arm removes the partial nobody took, and leaves the one that
    /// grew - the two halves of the ownership proof.
    #[test]
    fn the_arm_removes_only_what_is_still_exactly_the_mark() {
        let dir = tmpdir("drop");
        let untaken = dir.join("a.mkv");
        let published = dir.join("b.mkv");
        let taken = dir.join("c.mkv");
        std::fs::write(&untaken, vec![1u8; 10]).unwrap();
        std::fs::write(&published, vec![1u8; 40]).unwrap();
        std::fs::write(&taken, vec![1u8; 10]).unwrap();
        {
            let _arm = ResumeArm::new(&[
                out("a.mkv", &untaken, 10),
                out("b.mkv", &published, 10),
                out("c.mkv", &taken, 10),
            ]);
            keep(std::slice::from_ref(&taken));
        }
        assert!(!untaken.exists(), "the untouched partial should be gone");
        assert!(published.exists(), "a file that grew is somebody else's");
        assert!(taken.exists(), "a kept file is the unpack's");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex F-10, the direction that is a DECISION rather than a
    /// defect. `clear_unresumed` unlinks an armed partial sitting at a
    /// path this pass is about to publish to EVEN THOUGH its length has
    /// moved off the mark - which is the very test the arm's own
    /// cleanup uses to conclude a file belongs to somebody else (see
    /// `the_arm_removes_only_what_is_still_exactly_the_mark` above, the
    /// same file length in the opposite direction).
    ///
    /// The exception is deliberate and the publish step is the reason:
    /// it never overwrites, it disambiguates, so a leftover under the
    /// member's own name would shunt the real payload out to
    /// `film-1.mkv` beside it. The audit read the unlink as data loss;
    /// what it removes is the chase's own output, at a name the pass is
    /// about to write from byte zero anyway. Pinned because an
    /// undocumented decision is one refactor from being "fixed".
    #[test]
    fn a_changed_partial_under_a_published_name_is_cleared_before_the_pass() {
        let dir = tmpdir("clear");
        let p = dir.join("film.mkv");
        // 140 bytes against a 100-byte mark: somebody appended to it,
        // so `plan` refuses it and the arm's Drop would spare it.
        std::fs::write(&p, vec![7u8; 140]).unwrap();
        let _arm = ResumeArm::new(&[out("film.mkv", &p, 100)]);
        let resume = plan_pass(&dir, &["film.mkv".to_string()]);
        assert!(
            resume.is_empty(),
            "a partial whose length moved never resumes"
        );
        assert!(
            !p.exists(),
            "the pass publishes here, so the stale partial must be gone before it starts"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F-10's other direction, and the one that keeps the exception
    /// above from becoming a licence: the clear reaches ARMED partials
    /// at names THIS pass will publish, and nothing else.
    ///
    /// Three files, one of each kind. The member being resumed keeps its
    /// prefix (removing it would defeat the whole module); an armed
    /// partial no member of this pass publishes over is not this pass's
    /// business; and a file the ledger never armed is not the arm's to
    /// delete at all, published name or not - that one is a user's own
    /// file or another arm's output, and the disambiguating publish is
    /// exactly the right answer for it.
    #[test]
    fn clearing_reaches_only_armed_partials_this_pass_publishes_over() {
        let dir = tmpdir("clear-scope");
        let resumed = dir.join("keep.mkv");
        let other_pass = dir.join("elsewhere.mkv");
        let not_ours = dir.join("theirs.mkv");
        std::fs::write(&resumed, vec![1u8; 50]).unwrap();
        std::fs::write(&other_pass, vec![1u8; 30]).unwrap();
        std::fs::write(&not_ours, vec![1u8; 999]).unwrap();
        let _arm = ResumeArm::new(&[
            out("keep.mkv", &resumed, 50),
            out("elsewhere.mkv", &other_pass, 30),
        ]);
        // `theirs.mkv` IS a member of this pass - so its published path
        // is doomed - but no ledger entry stands behind it.
        let members = ["keep.mkv".to_string(), "theirs.mkv".to_string()];
        let resume = plan_pass(&dir, &members);
        assert_eq!(
            resume.get("keep.mkv"),
            Some(&(resumed.clone(), 50, 0)),
            "the member this pass is resuming must still be offered"
        );
        assert!(
            resumed.exists(),
            "the prefix being resumed is the point of the module"
        );
        assert!(
            other_pass.exists(),
            "an armed partial this pass never publishes over is not its business"
        );
        assert_eq!(
            std::fs::metadata(&not_ours).unwrap().len(),
            999,
            "a file the ledger never armed is not the arm's to delete"
        );
        keep(std::slice::from_ref(&resumed));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Arming nests: an inner arm restores the outer one, and dropping
    /// the inner arm does not touch the outer arm's files.
    #[test]
    fn a_nested_arm_restores_the_one_it_replaced() {
        let dir = tmpdir("nested");
        let outer = dir.join("outer.mkv");
        std::fs::write(&outer, vec![1u8; 10]).unwrap();
        let a = ResumeArm::new(&[out("outer.mkv", &outer, 10)]);
        {
            let _b = ResumeArm::new(&[]);
            assert!(plan(&dir).is_empty());
        }
        assert_eq!(plan(&dir).len(), 1, "the outer arm must be back");
        drop(a);
        assert!(!outer.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
