//! §296: per-file early publish - a finished, PAR2-vouched plain file
//! reaches the completed folder while the rest of the job is still on
//! the wire.
//!
//! The mover is strictly whole-job (`mover.rs`), so a 40 GB
//! season pack keeps episode 1 hostage until episode 12 verifies. The
//! metric a user feels is time-to-USABLE, not time-to-complete, and
//! nothing in the pipeline moved a single file out early.
//!
//! ## Why this is a COPY and not a move
//!
//! Because PAR2 repair reads every present block of every file in the
//! set, not only the damaged ones. Both engines do it:
//! `par2repair::repair_mapped_inner` builds its syndrome work list over
//! ALL files with no damage filter and then re-reads the whole set a
//! second time as a self-proof, and `repair_dir_set_inner`'s only
//! filter is `t.exists` - a clean, fully-verified file passes it,
//! because `verify_all_targets` marks every slice of a clean file
//! present. Nothing from the download pass is retained as block data;
//! `LiveVerifier::finish_slot_from` drops its partials and reads back
//! from disk. So a verified file that LEAVES `out_dir` takes its
//! siblings' repair with it.
//!
//! The original therefore stays exactly where it was until the job's
//! own finalize. What goes to the destination early is a paced copy,
//! and the whole-job move at the end deletes the original instead of
//! copying it again ([`Daemon::early_reconcile`]). Against the baseline
//! that is the SAME total I/O - a cross-device move is a copy plus a
//! delete either way - moved earlier in time, and paced through the
//! mover's own bucket so it never outbids a live download.
//!
//! ## Why the gate is as narrow as it is
//!
//! An early copy is only safe when the destination path and the file's
//! own name are already final, and the finalize tail is what makes them
//! not be. `finalize_names` can move the whole FOLDER (`tv_organize`,
//! `rename_movie`, `rename_from_nzb`) and rename the FILES inside it
//! (`tv_rename`, `rename_obfuscated_video`), and both sweeps
//! (`keep_media_only`, `sweep_junk`) decide what to delete by asking
//! `largest_video(dir)` - a question whose answer changes if the
//! biggest episode has been published out from under it. Every one of
//! those is a settings-gated pass, so [`Daemon::early_publish_dest`]
//! simply refuses the job when any of them is armed.
//!
//! That is not as narrow as it reads: it is exactly the shape an *arr
//! user runs. Sonarr and Radarr do their own renaming and tell you to
//! turn the download client's off, so "auto-rename off, TV sort off, no
//! sweeps" is the recommended *arr configuration rather than an exotic
//! one. It is also why the setting defaults OFF - a user who has NOT
//! turned those passes off gets nothing from this and should not pay a
//! poll for it.
//!
//! ## What is still reconciled anyway
//!
//! One rename survives the gate: settle publishes a slot's real PAR2
//! name over an obfuscated one (`publish_verified_name`), and repair
//! can rewrite a file whose blocks passed in stream but failed the
//! read-back. Neither is a setting, so neither can be gated out. Both
//! are caught the same way - the record carries (name, len, mtime) as
//! they stood at publish time, and [`Daemon::early_reconcile`] keeps
//! the destination copy only when all three still match. Anything else
//! discards the copy and lets the ordinary whole-job move carry the
//! file, which is the baseline behaviour for that file and nothing
//! worse.

use super::*;

/// One file already put at the destination, as it stood when the copy
/// was taken.
///
/// The triple is the whole invalidation rule, and each third of it
/// catches a different way the tail can move underneath us: the NAME
/// catches settle's PAR2 deobfuscation rename, the LENGTH catches a
/// truncated or re-planned file, and the MTIME catches a repair that
/// rewrote the bytes in place without changing either. Public because
/// `Job` is a public struct and a private field type is what
/// `private_interfaces` refuses.
///
/// One stated edge the mtime third cannot see (sweep S16): a filesystem
/// with coarse mtime ticks (exFAT rounds to 2 s) can stamp a repair's
/// same-length rewrite with the SAME mtime as the publish read, and the
/// stale copy is then kept. Left as a limit rather than closed: it
/// needs `out_dir` - the daemon's own download directory, not the
/// destination - on exFAT, AND the repair rewrite landing inside the
/// same 2 s tick as the moment the publish copy was taken, a window
/// that closing would cost a content hash per published file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarlyFile {
    /// The file's name inside the job's `out_dir` - never a path. Early
    /// publish only ever takes files directly under it.
    pub name: String,
    pub len: u64,
    /// Modification time in nanoseconds since the unix epoch, 0 when
    /// the platform would not say.
    pub mtime_ns: u64,
    /// §274's opaque per-file handle for the row this file came from -
    /// what `mode=get_files` reports as `nzf_id`, and the ONLY sound way
    /// to join a published file back to its listing row.
    ///
    /// Not the name, deliberately, even though the name is right here. A
    /// row's `filename` is the poster's subject hint while this record's
    /// `name` is the ON-DISK one (`sanitize_out_name` of the yEnc name;
    /// always a bare file name here - the candidate walk skips any slot
    /// whose file is not directly under the job dir, so a tree-preserved
    /// member is never published early and rides the whole-job move),
    /// and on an obfuscated post those are different strings - so a name
    /// join would stop marking rows for exactly the posts whose drawer is
    /// most worth reading. The handle is a digest of (index, first
    /// message-id), so it survives a restart and both the live table and
    /// the spooled-NZB path derive it identically.
    ///
    /// Empty on a record written before this field existed, which reads
    /// as "no row to mark" - true of all of them, since nothing was ever
    /// published by a build that could not record it.
    pub nzf_id: String,
    /// The directory the copy was published INTO, as
    /// [`Daemon::early_publish_dest`] derived it at publish time - the
    /// copy is at `dest/name`.
    ///
    /// Recorded rather than re-derived, because re-deriving at spend
    /// time answers a different question (sweep S6): `move_dest_for`
    /// says where the job's files would go NOW, and a `move_completed`
    /// repoint, a recategorize or a per-category override lands between
    /// publish and spend often enough to matter. A spender that
    /// re-derives then looks for the copies where they never were,
    /// finds nothing, and leaves the real ones orphaned at the old
    /// root - full payload at the new destination plus stray episodes
    /// at the old one, with the log claiming everything travelled with
    /// the job.
    ///
    /// `None` on a record written before this field existed. Those
    /// spend by re-deriving, which is exactly what they did before the
    /// field - no old store gets worse.
    pub dest: Option<PathBuf>,
}

/// Files below this are not worth a round of I/O and a destination
/// entry of their own: an `.nfo`, a `.srt`, a thumbnail. The payload
/// this feature exists for is measured in gigabytes.
const EARLY_MIN_BYTES: u64 = 1 << 20;

/// How often the publisher looks at the running job.
///
/// A poll rather than a hook on `slot_drained`, deliberately: that hook
/// is inside `get/workers.rs` on the decoder's own path, with no daemon
/// in scope, and the whole of what this needs (`FileSlot` counters, the
/// extractor, the verify gate) is already reachable from the daemon
/// through `StreamHub::job_files_for`. A second of latency costs
/// nothing against a file that took minutes to arrive.
pub const POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// `(len, mtime_ns)` for a path, or None when it is not a readable
/// regular file. Two thirds of the invalidation triple; the name is the
/// key the caller already holds.
pub fn stamp(p: &Path) -> Option<(u64, u64)> {
    let md = std::fs::metadata(p).ok()?;
    if !md.is_file() {
        return None;
    }
    let ns = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    Some((md.len(), ns))
}

/// Is this file plain payload - something the extractor and repair do
/// not own?
///
/// Three refusals, and the first is the load-bearing one. `.par2` is
/// already excluded upstream by `FileSlot::is_par2` (which the in-stream
/// magic sniff can set after the slot was built), so this covers the
/// rest: an archive by MAGIC, which catches an obfuscated `.rar` with no
/// telling extension, and a split-part or archive-volume NAME, which
/// catches a member whose own head carries no magic at all - part 2 of a
/// byte split is indistinguishable from payload by content.
///
/// Reads `unpack::is_extractable_archive` rather than teaching it
/// anything: that predicate is the disk ladder's, and widening it
/// changes what gets unpacked.
///
/// It DID widen on 31 Aug 2026 (matrix row M4-90's disk half), and the
/// consequence here is deliberate rather than incidental: a file the
/// poster named as content - `Movie.mkv`, `disc.iso` - is now plain
/// payload even when its first bytes read `Rar!`, so it publishes early
/// like any other. That is the right answer at this door for the same
/// reason it is the right answer at that one. Nothing will unpack the
/// file, so the destination gets those bytes whatever this says; the
/// only question left is whether the user waits for the whole job to
/// finish before an *arr can see a file that is already complete.
fn plain_payload(path: &Path) -> bool {
    if crate::unpack::is_extractable_archive(path) {
        return false;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    // A member of a SET, judged by name because content cannot judge it:
    // part 2 of a byte split, or a RAR/zip volume past the first, carries
    // no magic of its own and is indistinguishable from payload.
    // `.001`-style numbering, RAR's old `.r00`, RAR5's `partNN` and
    // zip's `.z01` are the four spellings in the wild.
    let numeric_tail = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if ext.len() >= 2 && numeric_tail(&ext) {
        return false;
    }
    for lead in ["r", "z", "part"] {
        if let Some(rest) = ext.strip_prefix(lead)
            && numeric_tail(rest)
        {
            return false;
        }
    }
    !matches!(
        ext.as_str(),
        "rar" | "zip" | "7z" | "tar" | "gz" | "bz2" | "xz" | "par2"
    )
}

/// The sibling name a copy stages under until its one-shot rename. A
/// sibling of the target, so the publish is a same-directory rename and
/// therefore atomic: an *arr scanning the completed folder must never
/// meet a half-written episode, and a partial file with a plausible
/// name is exactly the thing an import would take and a user would then
/// have to find by watching it.
fn staging_name(to: &Path) -> PathBuf {
    // The leaf is a `sanitize_out_name` result - it is a slot's own file
    // directly under the job folder - so it is routinely AT the 255-byte
    // component cap, capping being what produced it. Decorating it raw
    // gives a staging name no filesystem creates, so `stage_copy` fails
    // ENAMETOOLONG, this file never publishes early, and the poll loop
    // logs the same failure again every `POLL` until the job settles.
    // What §296 buys - a usable episode in 0.88 s instead of 6.81 - is
    // then exactly what the longest-named posts do not get.
    //
    // Held back at the STEM rather than capped on the composed name.
    // This name is nobody's identity key (it is created, renamed away,
    // and removed on every failure arm), so what matters is that it
    // stays RECOGNISABLE as an early-publish temp - and the prefix is
    // what recognises it, so the cap has to fall at the TAIL.
    //
    // ONE closure spells the decoration and the reserve is that same
    // closure over an empty leaf, so the two cannot drift. The pid is
    // inside it, because its width is what the reserve has to cover.
    let decorate = |leaf: &str| format!(".nzbfast-early-{}-{leaf}", std::process::id());
    let leaf = to.file_name().unwrap_or_default().to_string_lossy();
    let leaf = nzbkit::disk::cap_shared_stem(&leaf, [decorate("").as_str()]);
    to.with_file_name(decorate(&leaf))
}

/// Copy `from` to `staging`, paced by `pace`. The caller owns the
/// rename that makes it visible - and owns removing `staging` on any
/// error, this one's included.
///
/// The length is re-read from the SOURCE after the copy and compared to
/// what was written. A slot whose articles have all landed is not
/// supposed to grow, but a short copy that publishes anyway is the one
/// failure this cannot walk back, so it is cheaper to ask. The same
/// re-read is what catches a source the whole-job move carried away
/// mid-copy: the open handle keeps the bytes readable, the metadata
/// call fails, and nothing is published.
///
/// `sync_all` before the caller's rename, for the reason `move_tree`
/// runs `sync_written_file`: a crash inside the writeback window must
/// not leave a torn file wearing the final name - reconcile compares
/// LENGTH, and a torn copy at full length would be kept over the good
/// source it deletes.
fn stage_copy(
    from: &Path,
    staging: &Path,
    pace: &crate::smart::PaceFn<'_>,
) -> std::io::Result<u64> {
    use std::io::{Read, Write};
    if let Some(parent) = staging.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut src = std::fs::File::open(from)?;
    let mut dst = std::fs::File::create(staging)?;
    let mut buf = vec![0u8; 4 << 20];
    let mut wrote = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        wrote += n as u64;
        pace(n as u64);
    }
    dst.flush()?;
    dst.sync_all()?;
    drop(dst);
    let want = std::fs::metadata(from)?.len();
    if wrote != want {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("short copy: wrote {wrote} of {want} bytes"),
        ));
    }
    Ok(wrote)
}

/// What one candidate's attempt means for the rest of the pass.
enum Publish {
    /// Copied, renamed and on the record.
    Landed(u64),
    /// This candidate only; the pass goes on to the next.
    Skipped,
    /// The job is no longer this pass's to publish - settled, deleted,
    /// or its files are in another actor's custody. Nothing after this
    /// candidate can be sound either.
    Stop,
}

/// One publishable file the pass found, resolved off the live table.
pub struct Candidate {
    slot: usize,
    src: PathBuf,
    name: String,
    /// The listing row's opaque handle - see [`EarlyFile::nzf_id`].
    nzf_id: String,
}

/// The publisher lane: one look per [`POLL`] at the job that is
/// downloading, and nothing at all when the setting is off.
pub fn spawn(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL).await;
            if !d.early_file_publish.load(Ordering::Relaxed) {
                continue;
            }
            let job = d
                .queue
                .lock_ok()
                .iter()
                .find(|j| j.lock_ok().state == JobState::Downloading)
                .cloned();
            let Some(job) = job else { continue };
            let d2 = d.clone();
            // The copy is bulk I/O and belongs on the blocking pool for
            // the same reason `mover_process` does.
            let _ = tokio::task::spawn_blocking(move || d2.early_publish_pass(&job)).await;
        }
    });
}

impl Daemon {
    /// Where §296 may publish this job's files, or None when it may not.
    ///
    /// Every refusal below names a pass in `finalize_names` that would
    /// move or rename a file AFTER the copy was taken - see the module
    /// docs for why each one is fatal rather than reconcilable.
    pub(super) fn early_publish_dest(
        &self,
        out_dir: &Path,
        cat: &str,
        tv_sort: bool,
    ) -> Option<PathBuf> {
        if !self.early_file_publish.load(Ordering::Relaxed) {
            return None;
        }
        // Season filing does not name a file, it decides a whole
        // directory SHAPE - the folder this job's files end up in is not
        // the one they are in now.
        if tv_sort {
            return None;
        }
        // The metadata renamer: `tv_rename` renames episodes in place,
        // `rename_movie` and the obfuscated-video pass rename the folder
        // or the feature.
        if self.auto_rename.load(Ordering::Relaxed) {
            return None;
        }
        // TODO 142's naming renames the folder and the biggest file.
        if crate::naming::name_from_nzb(self, cat) {
            return None;
        }
        // Both sweeps pick their victims relative to `largest_video(dir)`,
        // and publishing the largest video changes that answer. NOT gated
        // on `auto_rename` upstream, so they need their own refusal.
        if self.rename.media_only.load(Ordering::Relaxed)
            || self.rename.junk.load(Ordering::Relaxed)
        {
            return None;
        }
        let dest = self.move_dest_for(out_dir, cat)?;
        // Nothing to publish EARLY when the destination is where the job
        // already is: `relocate_completed` calls that "already inside the
        // completed folder" and moves nothing.
        // ...and nothing to publish early when the destination is
        // INSIDE the job, which is the same refusal the whole-job move
        // makes and has to be made here too: this pass stages its own
        // copies rather than going through `move_tree`, so without it
        // files land in a folder the move then refuses to visit - a
        // payload split across two directories with nothing to say so.
        // One predicate, shared, for the reason `move_dest_for` was
        // lifted in the first place.
        let same = crate::smart::dst_is_src_or_inside(out_dir, &dest);
        (!same).then_some(dest)
    }

    /// One publisher pass over `job`. Runs on the blocking pool.
    pub(super) fn early_publish_pass(self: &Arc<Self>, job: &Arc<Mutex<Job>>) {
        let (nzo, out_dir, cat, tv_sort, done) = {
            let g = job.lock_ok();
            if g.state != JobState::Downloading || g.tombstone {
                return;
            }
            // TODO 317: a write-through job's `out_dir` IS the
            // destination, so there is nothing to publish EARLY to -
            // every file lands there the moment it is decoded, which is
            // strictly better than a copy taken part way through.
            //
            // Refused HERE, off the job's own record, rather than left
            // to `early_publish_dest`'s existing same-directory test.
            // That test asks `dst_is_src_or_inside(out_dir, dest)`, and
            // `dest` comes from `move_dest_for`, whose relative path is
            // `strip_prefix(crate::naming::out_dir())` - which a write-through
            // `out_dir` does not match. It falls back to
            // `category/<folder>`, and for a category carrying a
            // `cat_meta.dir` override that fallback computes a
            // DIFFERENT directory beside the real one. This pass would
            // then stage copies into a folder holding nothing else: a
            // payload split across two directories with nothing to say
            // so, which is the exact failure that test exists to
            // prevent.
            if g.write_through {
                return;
            }
            (
                g.nzo_id.clone(),
                g.out_dir.clone(),
                g.category.clone(),
                g.tv_sort,
                g.early_published
                    .iter()
                    .map(|e| e.name.clone())
                    .chain(g.early_refused.iter().cloned())
                    .collect::<std::collections::HashSet<_>>(),
            )
        };
        let Some(dest) = self.early_publish_dest(&out_dir, &cat, tv_sort) else {
            return;
        };
        let Some(cands) = self.early_candidates(&nzo, &out_dir, &done) else {
            return;
        };
        for c in cands {
            let pace = mover::mover_pacer(self);
            match self.early_publish_one(job, &nzo, &dest, &c, &pace) {
                Publish::Landed(n) => {
                    info!(
                        target: "move",
                        "early: {} → {} ({n} bytes, slot {})",
                        c.name,
                        dest.display(),
                        c.slot
                    );
                }
                Publish::Skipped => {}
                Publish::Stop => return,
            }
        }
    }

    /// Copy one candidate to the destination and commit it to the
    /// record, or say why not.
    ///
    /// The paced copy runs with nothing held - it can take minutes at
    /// the mover bucket's floor. Everything that makes the copy REAL
    /// (the rename into the destination and the record push) happens
    /// inside a short hold of the `moving` custody fence, the same one
    /// `mover_process`, the delete refusals and recategorize already
    /// share, so the whole-job move can never interleave with a
    /// half-committed publish: its reconcile either sees this file on
    /// the record or never sees it at the destination at all. Held for
    /// a rename and a lock push, not for the copy - a fence held for
    /// minutes would stall the mover's retry loop and every refusal
    /// that reads the set.
    fn early_publish_one(
        &self,
        job: &Arc<Mutex<Job>>,
        nzo: &str,
        dest: &Path,
        c: &Candidate,
        pace: &crate::smart::PaceFn<'_>,
    ) -> Publish {
        let dst = dest.join(&c.name);
        // Never rename over a file that is already there: rename
        // replaces on both platforms, and an occupied destination is an
        // EARLIER grab's finished file (`move_tree` resolves the same
        // meeting with `reserve_free_name`). Refusing here leaves the
        // collision to the whole-job move, which gives this run's copy
        // a "(2)" name - the baseline behaviour - instead of silently
        // destroying the finished one. Remembered per name so the poll
        // loop does not re-copy gigabytes, or re-log, every second.
        //
        // `symlink_metadata` and not `exists()`: "already there" has to
        // mean an ENTRY, because `rename(2)` at the commit below removes
        // whatever entry sits at the destination and never resolves it,
        // while `Path::exists` FOLLOWS symlinks and answers false on any
        // error. `dest` is the user's completed folder - a link there,
        // into a library or onto a share that is not mounted, is
        // ordinary - so this read as free and the commit deleted it.
        // Argued in full at `tv_rename` in `smart/filing.rs`; the
        // in-tree precedent for the spelling is `publish_over_previous`
        // in `job_publish.rs`, which already asks it this way.
        // Declining is what this guard is for and costs nothing: the
        // whole-job move still carries the file, under a "(2)" name.
        //
        // AND IT STAYS A LOOK, deliberately, where the at-commit guard
        // below took a `create_new` claim on 31 Aug 2026 under
        // `occupancy-claim-the-rest-of-the-class`. This one is an
        // EARLY-OUT and not the decision: what it buys is keeping a
        // 9 MiB copy off the disk when the name is plainly taken, and
        // a claim here would have to be held across that whole copy -
        // so a run that died mid-copy would leave a zero-byte file
        // wearing a release name in the user's completed folder, and
        // the adjacent-name import this module exists to avoid would
        // find it. The name is claimed where the outcome is settled,
        // inside the custody fence, and an arrival that beats THIS test
        // simply makes the door decline early and correctly.
        if std::fs::symlink_metadata(&dst).is_ok() {
            if job.lock_ok().early_refused.insert(c.name.clone()) {
                warn!(
                    target: "move",
                    "early: {} already exists at {} - leaving it; the whole-job \
                     move will give this run's copy a fresh name",
                    c.name,
                    dest.display()
                );
            }
            return Publish::Skipped;
        }
        // Read the stamp beside the copy, not before it: what is
        // recorded has to be what was READ, or the reconcile compares
        // the destination against a moment that never existed.
        let Some((len, mtime_ns)) = stamp(&c.src) else {
            return Publish::Skipped;
        };
        if len < EARLY_MIN_BYTES {
            return Publish::Skipped;
        }
        let staging = staging_name(&dst);
        let wrote = match stage_copy(&c.src, &staging, pace) {
            Ok(n) => n,
            Err(e) => {
                let _ = std::fs::remove_file(&staging);
                warn!(target: "move", "early publish of {} failed: {e}", c.name);
                // No retry ladder and none is owed: the ordinary
                // whole-job move still carries this file, so a failure
                // here costs latency and nothing else.
                return Publish::Skipped;
            }
        };
        // The commit. Custody first: a fence already held means the
        // mover, a delete or a recategorize owns these files right now,
        // and a publish landing under any of them is the "(2)"
        // duplicate or the stale record the fence exists to prevent.
        if !self.moving.lock_ok().insert(nzo.to_string()) {
            let _ = std::fs::remove_file(&staging);
            return Publish::Stop;
        }
        struct Fence<'a>(&'a Daemon, &'a str);
        impl Drop for Fence<'_> {
            fn drop(&mut self) {
                self.0.moving.lock_ok().remove(self.1);
            }
        }
        let _fence = Fence(self, nzo);
        {
            let g = job.lock_ok();
            if g.tombstone || g.state != JobState::Downloading {
                // Settled or deleted while the copy ran. Nothing may
                // reach the destination for a job that is no longer
                // downloading: a FAILED job's take-back already ran and
                // cannot see a file that is not on the record yet.
                drop(g);
                let _ = std::fs::remove_file(&staging);
                return Publish::Stop;
            }
        }
        // THE DECIDING GUARD, and since 31 Aug 2026 a CLAIM rather than
        // a look, under `occupancy-claim-the-rest-of-the-class`. The
        // `lstat` here was a check before a use: MEASURED on the
        // sibling guard in `unpack/published_names.rs`, one `lstat` is
        // 968 ns against ~112 us of rename behind it, so it covered
        // about 1% of its own interval and 96.8% of concurrent arrivals
        // that got the name landed inside the gap. `create_new` answers
        // `AlreadyExists` over a regular file, a dangling link, a link
        // out of the directory and a directory - the same four answers
        // the `lstat` gave - so the claim IS this guard, taken
        // atomically instead of in two steps.
        //
        // AND THE CONCURRENT CREATOR IS NAMED IN THIS FUNCTION'S OWN
        // WORDS - "another job's move landing the same release name" -
        // which is why of the nine doors on that census this is the one
        // whose window was never hypothetical. `dest` is the user's
        // completed folder, so the loser is a finished file.
        //
        // The `symlink_metadata` before the copy STAYS and is not this
        // decision: it is an early-out that keeps a 9 MiB copy off the
        // disk when the name is plainly taken, and a name found free by
        // looking is not a name held. This is where the outcome is
        // settled, inside the custody fence taken just above.
        //
        // Plain `create_new` and not `disk::open_out_leaf_under`, per
        // `tv_rename` in `smart/filing.rs`: the rename below resolves
        // its destination by path, and a completed folder reached
        // through a symlink - a category folder on another volume - is
        // ordinary, so a bound claim would refuse those jobs outright.
        //
        // WHAT THE CLAIM COSTS HERE, AND IT IS A REAL TRADE AGAINST THIS
        // MODULE'S OWN ATOMICITY PROMISE, so it is stated rather than
        // buried. `a_published_file_appears_whole_or_not_at_all` says
        // the destination name must not exist until the copy is whole,
        // because "an *arr scanning the completed folder would import
        // it" - and a placeholder is a zero-byte file wearing exactly
        // that name. The window is ONE `rename(2)`, measured at ~102 us
        // on APFS, against the whole copy the staging file already keeps
        // it out of; the staging name is a dotfile, so nothing scanning
        // ever saw a partial and nothing does now.
        //
        // Taken deliberately, because the harms are not the same size.
        // Without the claim a concurrent arrival DESTROYS a finished
        // file - 96.8% of arrivals that got the name landed inside the
        // old guard's gap - and that is permanent. With it, an external
        // scan has to land inside ~100 us AND import a zero-byte file,
        // which Sonarr and Radarr both refuse on size, and the next scan
        // finds the whole one. The counter-attempt for the next lane
        // that wants this at zero is `hard_link(staging, dst)`: it is
        // exclusive (EEXIST) and lands the FULL bytes atomically, but it
        // needs a fallback on a volume with no link support, and that
        // fallback is untestable on this fleet - APFS has links, so the
        // arm would never run here. Not built for that reason.
        if let Err(e) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
        {
            let _ = std::fs::remove_file(&staging);
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                // The folder is unusable rather than taken - a
                // read-only mount, no write right on the share. That is
                // what the rename below would have reported, so it
                // still is, and it is not remembered in `early_refused`:
                // that set exists to stop a per-second re-copy of a name
                // somebody else owns, and this name is owned by nobody.
                warn!(target: "move", "early publish of {} failed: {e}", c.name);
                return Publish::Skipped;
            }
            // Appeared during the copy - another job's move landing the
            // same release name. Same refusal as above, same reason.
            if job.lock_ok().early_refused.insert(c.name.clone()) {
                warn!(
                    target: "move",
                    "early: {} appeared at {} while the copy ran - leaving it",
                    c.name,
                    dest.display()
                );
            }
            return Publish::Skipped;
        }
        if let Err(e) = std::fs::rename(&staging, &dst) {
            let _ = std::fs::remove_file(&staging);
            // Our own placeholder, and here it would be the worst
            // residue of the nine: a zero-byte file wearing a release
            // name in the user's completed folder, which the whole-job
            // move then steps around with a "(2)" name and every
            // library scan picks up.
            let _ = std::fs::remove_file(&dst);
            warn!(target: "move", "early publish of {} failed: {e}", c.name);
            return Publish::Skipped;
        }
        // The harness's window: the file is at the destination and on
        // no record.
        #[cfg(any(test, feature = "test-support"))]
        super::storecut::early_rename_gap(self);
        let mut g = job.lock_ok();
        if g.tombstone || g.state != JobState::Downloading {
            // The job left Downloading between the check above and the
            // rename landing. A tombstone means the record is gone; a
            // failure means park's take-back already ran, and neither
            // could see a file that was not on the record yet - so
            // pushing it now would land an episode in the completed
            // folder for a job that is already filed in history, the
            // *arr partial-import the module docs forbid. Take the
            // fresh copy back instead, exactly as the delete arm does.
            // (A fail-and-auto-retry that lands entirely inside the
            // copy window reads as Downloading again here, and pushing
            // is sound then: the record rides the same requeued Arc and
            // reconcile still validates it by stamp.)
            drop(g);
            let _ = std::fs::remove_file(&dst);
            return Publish::Stop;
        }
        g.early_published.push(EarlyFile {
            name: c.name.clone(),
            len,
            mtime_ns,
            nzf_id: c.nzf_id.clone(),
            dest: Some(dest.to_path_buf()),
        });
        drop(g);
        if !self.save_queue() {
            // The record did not reach disk. A restart from here would
            // restore a job that has never heard of the destination
            // copy - the whole-job move then collides with it, or a
            // failed job's take-back misses it. Undo both halves while
            // the fence is still held so the file and the record stay
            // one transaction; the whole-job move still carries the
            // file, so the cost is only latency.
            let mut g = job.lock_ok();
            g.early_published.pop();
            drop(g);
            let _ = std::fs::remove_file(&dst);
            warn!(
                target: "move",
                "early: queue store refused after publishing {} - took the \
                 copy back; the whole-job move will carry it",
                c.name
            );
            return Publish::Skipped;
        }
        Publish::Landed(wrote)
    }

    /// The files of the ACTIVE run that are finished, vouched, plain,
    /// and not already published.
    ///
    /// None when there is no live table for `nzo` - a job past its
    /// network phase, or one whose table the next job's start retired.
    /// Nothing to publish in either case: the tail owns the payload from
    /// there on.
    fn early_candidates(
        &self,
        nzo: &str,
        out_dir: &Path,
        done: &std::collections::HashSet<String>,
    ) -> Option<Vec<Candidate>> {
        let t = self.hub.job_files_for(nzo)?;
        let ex = &t.seek.extractor;
        let mut out = Vec::new();
        for row in &t.rows {
            let Some(i) = row.slot else { continue };
            let Some(s) = t.slots.get(i) else { continue };
            let c = crate::streamhub::FileSlotCounts::of(s);
            // Recovery data and a skipped sample are not payload; every
            // other counter must be at its "arrived whole" value. This is
            // the same arithmetic `mode=get_files` calls "complete", and
            // it is deliberately NOT enough on its own - it is an
            // article-arrival word, not a verification one.
            //
            // `deferred` is in the list even though the verify mark below
            // subsumes it - a deferred article's bytes were never fetched,
            // so its blocks cannot be Ok - because a counter that reads
            // "this file is not all here" has no business being the one
            // condition nobody checks.
            if c.is_par2
                || c.sample_skipped
                || c.remaining > 0
                || c.missing > 0
                || c.abandoned > 0
                || c.deferred > 0
                || c.errors > 0
            {
                continue;
            }
            // A mapped or chased slot owns no standalone file: its bytes
            // went straight into extracted output or live in the frontier
            // buffer. The extractor owns those, and §296 does not.
            if ex.is_mapped(i) || ex.is_chased(i) {
                continue;
            }
            // The verification verdict, and the reason this is not just a
            // counter read. `Some(u64::MAX)` is "the verifier ENGAGED this
            // slot and every block of it has been vouched against the PAR2
            // set"; `None` is "nothing vouched for yet", which is what an
            // unclaimed slot reads as and must not be mistaken for a pass.
            //
            // Weaker than the settle verdict and knowingly so: under
            // `fast_verify` (the default) an in-stream claim is CRC32
            // where settle also takes MD5, and the whole-file MD5 is
            // never checked in stream at all. The reconcile is what
            // covers the difference - a file settle finds bad is
            // repaired, its mtime moves, and the destination copy is
            // discarded rather than kept.
            if ex.verify_mark(i) != Some(u64::MAX) {
                continue;
            }
            let Some(src) = ex.slot_path(i) else { continue };
            // Directly under the job's own folder, and nowhere else. The
            // reconcile and the take-back both address a published file
            // as `out_dir/name` and `dest/name`, so a slot whose bytes
            // live somewhere else entirely (extractor scratch, a
            // materialized volume) would be published to a path neither
            // of them could ever find again.
            if src.parent() != Some(out_dir) {
                continue;
            }
            let Some(name) = src.file_name().map(|n| n.to_string_lossy().to_string()) else {
                continue;
            };
            if done.contains(&name) || !plain_payload(&src) {
                continue;
            }
            out.push(Candidate {
                slot: i,
                src,
                name,
                nzf_id: row.id.clone(),
            });
        }
        Some(out)
    }

    /// Settle the early copies against what the tail actually left on
    /// disk. Called from `mover_process` BEFORE the whole-job move.
    ///
    /// Two dispositions per file, plus one deferral. The copy still
    /// matches its original AND still sits where this attempt's move is
    /// going, so the ORIGINAL goes and the whole-job move carries only
    /// what is left; or something moved underneath it - the source
    /// rewritten or renamed, the DESTINATION repointed (sweep S6: a
    /// copy at a root the move no longer visits is a stray, however
    /// intact) - so the COPY goes and the original travels the ordinary
    /// way. Never both, and never neither: leaving both would make
    /// `move_tree`'s merge meet an occupied target and publish the
    /// payload a second time as "Episode (2).mkv", which is the
    /// mangling `relocate_completed`'s own `same_place` guard exists to
    /// prevent one directory over.
    ///
    /// The deferral is sweep S7, and it is the reason the record is no
    /// longer spent wholesale at the top: an entry whose destination
    /// cannot be REACHED (the NAS dropped at the tail - `metadata` and
    /// `remove_file` failing with something other than NotFound) has
    /// not settled either way, so it stays on the record. The move
    /// attempt that follows fails against the same unreachable volume,
    /// `settle_move_attempt` schedules the retry, and the retry's own
    /// `mover_process` runs this again - where spending the record on
    /// the first attempt turned every kept copy into a "(2)" duplicate
    /// the moment the retry's merge met it.
    pub(super) fn early_reconcile(&self, job: &Arc<Mutex<Job>>) {
        let (out_dir, cat, early) = {
            let mut g = job.lock_ok();
            if g.early_published.is_empty() {
                return;
            }
            (
                g.out_dir.clone(),
                g.category.clone(),
                std::mem::take(&mut g.early_published),
            )
        };
        // Where THIS attempt's move is going. An entry that recorded its
        // own destination is judged against it; a pre-dest record has
        // nothing recorded and resolves to it, which is what those
        // records always did.
        let cur = self.move_dest_for(&out_dir, &cat);
        let total = early.len();
        let (mut kept, mut dropped, mut lost) = (0usize, 0usize, 0usize);
        let mut deferred: Vec<EarlyFile> = Vec::new();
        for e in early {
            let Some(dir) = e.dest.clone().or_else(|| cur.clone()) else {
                // A pre-dest record and no current destination: nothing
                // here knows where the copies went, so the entry is
                // dropped and the log line is the only record there can
                // be. The one arm the dest field cannot rescue.
                lost += 1;
                continue;
            };
            let src = out_dir.join(&e.name);
            let dst = dir.join(&e.name);
            // S6: a recorded destination the move no longer goes to.
            // The copy may be byte-perfect, but keeping it splits the
            // payload across two roots - so it takes the drop arm below,
            // at the recorded path, where the pre-dest code looked for
            // it at the NEW root, found nothing, and left it stranded.
            let repointed = match (&e.dest, &cur) {
                (Some(d), Some(c)) => d != c,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if !repointed && stamp(&src) == Some((e.len, e.mtime_ns)) {
                match std::fs::metadata(&dst) {
                    Ok(md) if md.len() == e.len => {
                        // Published and unchanged: the destination copy
                        // IS the final file, so the source is what has
                        // to go.
                        if std::fs::remove_file(&src).is_ok() {
                            kept += 1;
                            continue;
                        }
                        // Could not remove it, so both copies exist.
                        // Take the destination one back instead - a
                        // duplicate at the destination is the outcome
                        // this must never produce.
                    }
                    Ok(_) => {
                        // Wrong length at the destination: not the copy
                        // that was published. Take it back below.
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        // The copy is gone - the user moved or removed
                        // it. Settled: the move re-sends the source.
                        dropped += 1;
                        continue;
                    }
                    Err(_) => {
                        // S7: the destination did not answer, which is
                        // not "not the same file" - it is "no verdict".
                        deferred.push(e);
                        continue;
                    }
                }
            }
            match std::fs::remove_file(&dst) {
                Ok(()) => dropped += 1,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => dropped += 1,
                // S7 again: a take-back the volume refused has not
                // happened, and discarding the record here is what left
                // byte-identical copies for the retry's merge to "(2)".
                Err(_) => deferred.push(e),
            }
        }
        if !deferred.is_empty() {
            // Back on the record for the next attempt. No publisher can
            // have pushed meanwhile: the caller holds the `moving`
            // fence, the same one `early_publish_one`'s commit takes.
            warn!(
                target: "move",
                "early: {} file(s) at an unreachable destination stay on the \
                 record for the move's next attempt",
                deferred.len()
            );
            job.lock_ok().early_published.extend(deferred);
        }
        if lost > 0 {
            warn!(
                target: "move",
                "early: {lost} file(s) were published but this job no longer has \
                 a destination - they are wherever it used to point"
            );
        }
        info!(
            target: "move",
            "early: {kept} of {total} file(s) were already at {} and are kept; \
             {dropped} re-sent with the job",
            cur.as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "the recorded destination".into())
        );
    }

    /// Take this job's early copies OFF the record and hand back where
    /// they are, without touching the disk.
    ///
    /// Split from the unlink half ([`early_unlink`]) on purpose: every
    /// caller holds the job under the queue mutex when it learns the row
    /// is doomed, and a destination that has gone away turns an unlink
    /// into a stalled network call. Path arithmetic under the lock, I/O
    /// after it - the same division `api/queue/payload.rs` already makes
    /// for `remove_job_files`.
    pub fn early_take(&self, g: &mut Job) -> Vec<PathBuf> {
        if g.early_published.is_empty() {
            return Vec::new();
        }
        let early = std::mem::take(&mut g.early_published);
        // Only a pre-dest record needs today's derivation; an entry that
        // recorded its destination is addressed where the copy actually
        // is, however the settings have moved since (sweep S6).
        let derived = self.move_dest_for(&g.out_dir, &g.category);
        let mut out = Vec::new();
        let mut lost = 0usize;
        for e in early {
            match e.dest.or_else(|| derived.clone()) {
                Some(dir) => out.push(dir.join(&e.name)),
                None => lost += 1,
            }
        }
        if lost > 0 {
            // A pre-dest record and no current destination: nothing here
            // knows where the copies went, so the entry is dropped and
            // the log line is the only record there can be.
            warn!(
                target: "move",
                "early: {lost} file(s) of {} were published but the job no longer \
                 has a destination - they are wherever it used to point",
                g.nzo_id
            );
        }
        out
    }
}

/// Take back early copies whose job will never reach the mover: a
/// delete, a cancel, a failure that cleaned up after itself.
///
/// Without this a user who stops a download is left with the episodes
/// it had already finished sitting in the completed folder, which for
/// an *arr on the other side is an import of a job that was cancelled -
/// the one outcome an early publish must not be able to produce.
///
/// Best effort by construction: a copy the user has already moved, or a
/// destination that has gone offline, is not something a delete can be
/// held up for.
pub fn early_unlink(paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    for p in paths {
        let _ = std::fs::remove_file(p);
    }
    // Only if it is now empty, and only ever the job's own folder -
    // `remove_dir` refuses a non-empty directory, which is exactly the
    // guard wanted here. Every distinct parent, not just the first's: a
    // destination repoint mid-download can leave one job's copies under
    // two roots, and each recorded its own (sweep S6).
    let mut dirs: Vec<&Path> = paths.iter().filter_map(|p| p.parent()).collect();
    dirs.sort();
    dirs.dedup();
    for dir in dirs {
        let _ = std::fs::remove_dir(dir);
    }
    info!(target: "move", "early: took back {} file(s)", paths.len());
}

#[cfg(test)]
#[path = "earlyfile_tests.rs"]
mod earlyfile_tests;
