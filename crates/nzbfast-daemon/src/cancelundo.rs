//! GH #86: a cancelled download stays undoable for a grace window.
//!
//! The reporter's objection was to confirm-before-an-action dialogs and
//! their example was cancelling a download. The audit
//! (`research/MODAL-BLOCK-AUDIT-2026-09-17.md`, section 2) found that
//! the confirm in front of the stop button had to STAY, and the reason
//! was not UI taste: **the daemon threw the job's spooled `.nzb` away
//! with the record**, so the page could not offer an undo - it did not
//! hold the bytes. Dropping the dialog without fixing that would have
//! replaced a confirm with an irreversible silent action, which is
//! strictly worse than the dialog and the opposite of what was asked
//! for.
//!
//! So this makes the action reversible instead. A queue delete that
//! does NOT ask for the files half keeps a second link to each removed
//! row's spool copy under `<spool>/undo/`, together with the handful of
//! fields an `enqueue_as` needs to put the row back, and hands the
//! caller a token. Spending the token re-adds every row in the batch
//! under its ORIGINAL nzo id, so an *arr that was handed that id still
//! holds a valid handle.
//!
//! ## Four things it has to get right
//!
//! 1. **The window covers the whole promise, not just the row.** An
//!    undo that gives back a row whose `.nzb` has gone gives back
//!    something that can no longer be run, and it looks identical to a
//!    working undo (audit section 5 records exactly that mistake on the
//!    history side). So what is retained is the BYTES, and the restore
//!    reads them back: a slot whose file has vanished, or been emptied
//!    by `drop_spool`'s last resort, refuses out loud rather than
//!    restoring an unrunnable row.
//! 2. **Only the files-KEPT arm.** With `del_files=1` the removal can be
//!    deferred to `park()` or to the prefetch drain - that is
//!    `FilesVerdict::pending`, and it means the daemon has not settled
//!    the files half yet. An undo offered on top of that is a promise
//!    nobody has kept. It is also unnecessary: the three dialogs this
//!    exists to retire (the row's own stop, Clear queue, the selection
//!    bar's Remove) all post no `del_files`, which
//!    `the_quick_ways_out_of_the_queue_still_keep_the_files` pins.
//! 3. **It costs no new disk in the ordinary case.** The retained copy
//!    is a HARD LINK to the spool file the queue was already holding,
//!    so the ceiling on extra bytes is "one queue's worth of NZBs, for
//!    the window" - bytes the user had already accepted - and the
//!    original delete path is left completely alone: it renames,
//!    unlinks and parks exactly as it did, and the link keeps the inode
//!    alive behind it. `std::fs::copy` is the fallback for a spool on a
//!    filesystem with no links (an exFAT stick, some SMB mounts).
//! 4. **All or nothing per batch.** A partial undo is the same silent
//!    downgrade as a missing `.nzb`: the user sees an Undo, presses it,
//!    and gets some of their queue back. So the token is only handed
//!    out when EVERY row this request removed was retained.
//!
//! ## What it deliberately does not do
//!
//! The window never outlives the process. The index is in memory, and
//! [`Daemon::purge_cancel_undo`] empties the directory at startup, so a
//! restart is a purge rather than a resurrection - a cancelled release
//! that came back at the next start would be the `recover_orphaned_spool`
//! defect this repo has already fixed twice. Nothing is persisted, and
//! that is the feature.
//!
//! Position in the queue is not restored. Priority and the per-job
//! paused flag are, so a restored row sorts where its priority puts it;
//! within one priority it goes to the back. History's `history_restore`
//! puts rows back at exact indices and this deliberately does not
//! imitate it: a queue moves under you (a running job finishes, an *arr
//! pushes) and an index captured seconds ago is not a position, it is a
//! guess.

use super::*;

/// How long a cancelled batch stays undoable.
///
/// Ten minutes, and the reasoning rather than the number is the part
/// worth reading, because this is the one figure here that is a
/// judgement call:
///
/// * It is NOT the toast's lifetime. The toast lives 8 s
///   (`TOAST_ACT_MS`) because that is how long an affordance should sit
///   on screen; the window is how long the user has to change their
///   mind, and those are different quantities. Someone who cancels the
///   wrong row, walks away and comes back is the case this is for.
/// * It costs no new bytes (see the module header), so the usual reason
///   to keep a retention window short does not apply. What it does cost
///   is a cancelled release still sitting in the spool, and ten minutes
///   is short enough that this is never a surprise.
/// * A restart purges it, so the true ceiling is `min(10 min, uptime
///   after the cancel)`.
///
/// Not a setting on purpose: a knob here is a new settings row, a new
/// reflection-test entry and a new thing to get wrong, for a number
/// nobody has yet asked to change. If it should be one, it should be
/// one after somebody wants a different value.
pub const CANCEL_UNDO_SECS: u64 = 600;

/// A ceiling on retained ROWS across all live batches, oldest batch
/// dropped first.
///
/// Not the primary bound - [`CANCEL_UNDO_SECS`] is - and it is set high
/// enough that an ordinary Clear queue never reaches it. It is here for
/// the pathological loop (add a thousand, cancel, repeat) that would
/// otherwise hold a thousand inodes open for ten minutes at a time.
/// When it bites, the batch it evicts stops being undoable and its
/// token then refuses by name, which is the loud failure this file
/// prefers everywhere.
pub const CANCEL_UNDO_MAX_ROWS: usize = 200;

/// One removed row, and everything an `enqueue_as` needs to put it back.
///
/// The NZB itself is not in here - it is the file at `nzb`, which is a
/// second link to the spool copy the queue was holding. Reading it at
/// RESTORE time rather than snapshotting the bytes now is deliberate:
/// a 40 MB NZB held in memory for ten minutes per cancelled row is a
/// real cost, and the file is where the bytes already are.
#[derive(Clone, Debug)]
pub struct UndoRow {
    /// The original id. Restoring under it is what keeps an *arr's
    /// handle valid across the cancel - `recover_orphaned_spool` reuses
    /// an id for the same reason.
    pub nzo_id: String,
    pub name: String,
    pub category: String,
    pub priority: i32,
    /// The per-job paused flag, which priority does not carry. A row
    /// that was paused when it was cancelled comes back paused;
    /// unpausing it here would start a download the user had stopped
    /// twice over.
    pub paused: bool,
    /// An obfuscated set's password lives on the record, not in the
    /// NZB, so a restore without it comes back unable to unpack.
    pub password: Option<String>,
    /// The job this row was a HELD SPARE of, empty when it was an
    /// ordinary download (`held_for`).
    ///
    /// Restoring a spare as an ordinary queued job would be the worst
    /// kind of undo: the user clicks ✕ on a paused "alternative" row,
    /// changes their mind, and gets back a download NOBODY asked for,
    /// running. Priority and `paused` alone bring the row back LOOKING
    /// like a spare (`is_held_alternative` is exactly those two), but
    /// they do not say what it is held against, and `enqueue_as`'s
    /// `hold_for` does - including its refusal when the original has
    /// gone in the meantime, which is the answer a spare whose job no
    /// longer exists should get.
    pub held_for: String,
    /// The directory the cancelled job was downloading into.
    ///
    /// Carried so the restore can go back to it - see
    /// `Daemon::reuse_cancelled_dir`, which is the difference between
    /// an undo that resumes and one that quietly starts again from zero.
    pub out_dir: PathBuf,
    /// The retained link, under `<spool>/undo/`.
    pub nzb: PathBuf,
}

/// One delete request's worth of rows, spent as a unit.
#[derive(Debug)]
pub struct UndoBatch {
    pub token: String,
    /// Unix seconds, for the window.
    pub at: i64,
    pub rows: Vec<UndoRow>,
}

/// What a spent token achieved.
///
/// Both halves, always: a restore that put three of five rows back has
/// not done what the button said, and a caller told only a count cannot
/// tell that from a batch that was three rows to begin with.
#[derive(Default, Debug)]
pub struct UndoOutcome {
    /// Rows back in the queue, by their restored nzo id.
    pub restored: Vec<String>,
    /// Rows that could not come back, one reason each. A vanished or
    /// emptied retained copy lands here rather than producing a row
    /// that cannot run.
    pub failed: Vec<String>,
}

/// The next token. Process-local and never persisted - a token is only
/// meaningful to the run that minted it, which is the same property
/// that makes the restart purge correct.
static UNDO_SEQ: AtomicU64 = AtomicU64::new(1);

impl Daemon {
    /// `<spool>/undo`, created on demand.
    ///
    /// A SUBDIRECTORY of the spool and not a suffix on the copies,
    /// because `recover_orphaned_spool` walks the spool root and adopts
    /// every `SABnzbd_nzo_nzbfast*.nzb` no record names. A retained copy
    /// under that shape in that directory is precisely the "the
    /// cancelled release downloaded again at the next start" defect
    /// `mask_spool_path` exists to prevent. A directory entry matches
    /// neither that scan nor `sweep_spool_sidecars`'s `.nzb.cat` test,
    /// so both walk past it.
    pub fn cancel_undo_dir(&self) -> PathBuf {
        self.spool.join("undo")
    }

    /// Retain one row's spool copy and capture its record, under the
    /// queue lock, before the ordinary delete machinery touches it.
    ///
    /// Returns `None` when this row cannot be retained, and every caller
    /// must treat that as "this BATCH is not undoable" - see the
    /// all-or-nothing rule in the module header.
    ///
    /// The record is NOT modified. `g.nzb_path` still names the spool
    /// copy, so `park_or_drop_spool`, `mask_spool_from_recovery`,
    /// `drop_spool` and park's own unlink all keep naming the file they
    /// always named; this just takes a second link to the same inode
    /// first, and unlinking one link leaves the other. That is the whole
    /// reason this is a link rather than a rename: the delete path is a
    /// pile of hard-won special cases and none of them had to change.
    ///
    /// The one place the two links are not independent is
    /// `drop_spool`'s third resort, which EMPTIES the file when both
    /// the unlink and the rename are refused - that truncation goes
    /// through the inode and so through this copy too. It is a fault
    /// path (a Windows sharing violation, a `uchg` flag, a read-only
    /// spool), and [`Self::spend_cancel_undo`] catches the result the
    /// same way `recover_orphaned_spool` does: an empty copy holds no
    /// articles, so it refuses rather than restoring a row that could
    /// only fail.
    pub fn retain_for_undo(&self, g: &Job) -> Option<UndoRow> {
        let dir = self.cancel_undo_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            warn!(
                target: "queue",
                "{}: no undo window for this cancel - the store could not be made: {e}",
                dir.display()
            );
            return None;
        }
        // Named by the id and not by the release: two rows of one
        // season legitimately share a display name, and a collision
        // here would hand the second row's undo the first row's NZB -
        // the same pairing bug `hold_or_drop_spool`'s FIFO fixed.
        let dest = dir.join(format!("{}.nzb", g.nzo_id));
        // A leftover under this name is from an earlier cancel of the
        // same id whose window has since been swept; `hard_link` fails
        // on an existing destination, so it goes first.
        let _ = std::fs::remove_file(&dest);
        if let Err(link_err) = std::fs::hard_link(&g.nzb_path, &dest) {
            // No links on this filesystem (exFAT, some SMB mounts), or
            // the spool copy is already gone. A copy answers the first
            // and fails the second, which is the answer either way.
            if let Err(copy_err) = std::fs::copy(&g.nzb_path, &dest) {
                warn!(
                    target: "queue",
                    "{}: no undo window for this cancel - the spool copy could not be \
                     held (link: {link_err}; copy: {copy_err})",
                    g.nzb_path.display()
                );
                let _ = std::fs::remove_file(&dest);
                return None;
            }
        }
        Some(UndoRow {
            nzo_id: g.nzo_id.clone(),
            name: g.name.clone(),
            category: g.category.clone(),
            priority: g.priority,
            paused: g.paused,
            password: g.password.clone(),
            held_for: g.held_for.clone(),
            out_dir: g.out_dir.clone(),
            nzb: dest,
        })
    }

    /// File a captured batch and mint its token, or throw the whole
    /// batch away.
    ///
    /// `rows` is what [`Self::retain_for_undo`] captured and `removed`
    /// is how many rows the request actually took out of the queue.
    /// They must be equal or there is no token: a batch that can only
    /// put nine of ten rows back is the partial undo the module header
    /// refuses, and the retained nine are unlinked here rather than
    /// left to the sweep.
    pub fn file_cancel_undo(&self, rows: Vec<UndoRow>, removed: usize) -> Option<(String, usize)> {
        if rows.is_empty() || rows.len() != removed {
            if !rows.is_empty() {
                info!(
                    target: "queue",
                    "no undo window for this cancel: {} of {removed} removed row(s) could \
                     be held, and a partial undo is worse than none",
                    rows.len()
                );
                for r in &rows {
                    let _ = std::fs::remove_file(&r.nzb);
                }
            }
            return None;
        }
        let token = format!(
            "undo{}",
            UNDO_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let n = rows.len();
        let batch = UndoBatch {
            token: token.clone(),
            at: job::unix_now(),
            rows,
        };
        {
            let mut b = self.cancel_undo.lock_ok();
            b.push_back(batch);
            // Expiry first, then the row ceiling - an expired batch
            // evicted here is one the ceiling does not have to spend an
            // eviction on.
            drop(b);
        }
        self.sweep_cancel_undo();
        Some((token, n))
    }

    /// Drop expired batches, and the oldest ones past the row ceiling.
    ///
    /// Called after every filing rather than on a timer: the store is
    /// only ever added to by a delete, so a delete is the only moment it
    /// can need trimming, and a timer for a structure that is usually
    /// empty is a thread doing nothing.
    ///
    /// A restart is the other sweep, and the more thorough one - see
    /// [`Self::purge_cancel_undo`].
    pub fn sweep_cancel_undo(&self) {
        let now = job::unix_now();
        let mut dropped: Vec<PathBuf> = Vec::new();
        {
            let mut b = self.cancel_undo.lock_ok();
            while b
                .front()
                .is_some_and(|x| now.saturating_sub(x.at) >= CANCEL_UNDO_SECS as i64)
            {
                if let Some(x) = b.pop_front() {
                    dropped.extend(x.rows.into_iter().map(|r| r.nzb));
                }
            }
            let mut held: usize = b.iter().map(|x| x.rows.len()).sum();
            // `b.len() > 1` and not `b.len() > 0`: a SINGLE batch over the
            // ceiling stays whole. Evicting it would be correct for the
            // inode count and wrong for everything else, because half a
            // batch is not undoable at all (`file_cancel_undo`), so the
            // eviction would spend the whole window's worth of rows to
            // buy nothing.
            while held > CANCEL_UNDO_MAX_ROWS && b.len() > 1 {
                if let Some(x) = b.pop_front() {
                    held -= x.rows.len();
                    dropped.extend(x.rows.into_iter().map(|r| r.nzb));
                }
            }
        }
        for p in dropped {
            let _ = std::fs::remove_file(p);
        }
    }

    /// Take a batch by token, if it is still inside its window.
    ///
    /// Sweeps first, so a token whose window closed a second ago is
    /// refused rather than honoured - the alternative is an undo that
    /// works or does not depending on whether anything else has been
    /// cancelled since, which is worse than either answer.
    pub fn take_cancel_undo(&self, token: &str) -> Option<UndoBatch> {
        self.sweep_cancel_undo();
        let mut b = self.cancel_undo.lock_ok();
        let i = b.iter().position(|x| x.token == token)?;
        b.remove(i)
    }

    /// Put a taken batch back in the queue.
    ///
    /// Restores under the ORIGINAL id (the *arr handle), with the
    /// category, priority, password and paused flag the record carried,
    /// and `DupeExempt::Anybody` because the user has just said in as
    /// many words that they want this release: holding their own undo
    /// as a duplicate of the release they cancelled ten seconds ago
    /// would be the hold at its least useful. `enqueue_as` writes a
    /// fresh spool copy from these bytes, so the retained link has no
    /// reader left afterwards either way and goes.
    pub fn spend_cancel_undo(self: &Arc<Self>, batch: UndoBatch) -> UndoOutcome {
        let mut out = UndoOutcome::default();
        for row in batch.rows {
            let bytes = match std::fs::read(&row.nzb) {
                Ok(b) if !b.is_empty() => b,
                // Empty is not "no bytes to worry about": it is
                // `drop_spool`'s third resort having emptied the inode
                // both links share. Restoring from it would queue a job
                // with no articles in it, which is the unrunnable row
                // this whole file exists to avoid handing back.
                Ok(_) => {
                    out.failed.push(format!(
                        "{}: the queue's copy of the NZB was emptied while it was held",
                        row.name
                    ));
                    continue;
                }
                Err(e) => {
                    out.failed
                        .push(format!("{}: its copy of the NZB is gone ({e})", row.name));
                    continue;
                }
            };
            match self.enqueue_as(
                Some(&row.nzo_id),
                &bytes,
                &row.name,
                &row.category,
                row.priority,
                None,
                row.password.as_deref(),
                "undo",
                DupeExempt::Anybody,
                // Empty means "not a spare", which is what `None` means
                // here - an empty `hold_for` would be a spare held
                // against a job with no id.
                Some(row.held_for.as_str()).filter(|h| !h.is_empty()),
            ) {
                Ok(e) => {
                    if row.paused {
                        // After the add, not through it: `enqueue_as`
                        // has no paused parameter and inventing one for
                        // this would move sixteen call sites.
                        for j in self.queue.lock_ok().iter() {
                            let mut g = j.lock_ok();
                            if g.nzo_id == e.nzo_id {
                                g.paused = true;
                                break;
                            }
                        }
                    }
                    self.reuse_cancelled_dir(&e.nzo_id, &row.out_dir);
                    info!(target: "queue", "undo: {} ({}) is back in the queue", e.nzo_id, row.name);
                    out.restored.push(e.nzo_id);
                }
                Err(err) => out.failed.push(format!("{}: {err}", row.name)),
            }
            let _ = std::fs::remove_file(&row.nzb);
        }
        if !out.restored.is_empty() {
            self.save_queue();
        }
        out
    }

    /// Point a just-restored row back at the directory it was cancelled
    /// out of, undoing the climb the add could not avoid.
    ///
    /// **This is the second half of the promise, and without it the undo
    /// is a silent downgrade of exactly the kind this file exists to
    /// refuse.** The stop button's own copy says "the partial data stays
    /// on disk", and it does - but `enqueue_as` is a FRESH placement, so
    /// `dir_claim_for_add` looks at a directory holding files that no
    /// record names and correctly answers `Occupied`: somebody else's
    /// ground, climb past it. Correct for an add, wrong for this, because
    /// the record that named that directory is the one we are putting
    /// back. Left alone, the restored job downloads into `<stem>.2` from
    /// byte zero and orphans the partial data beside it - and the page
    /// shows exactly what a working undo shows.
    ///
    /// So this is the same move `daemon_retry` makes for a failed row's
    /// leftovers (it asks the BARE `dir_claim` for that reason), applied
    /// after the fact because the placement has already happened.
    ///
    /// FOUR GUARDS, and each one is a way this could take a directory it
    /// has no business in:
    ///
    /// * the old directory must still be `DirClaim::Free` to the BARE
    ///   claim - nothing live names it, and no COMPLETED record does
    ///   either. `Payload` is the case that matters: a finished result
    ///   sitting there is taken over through `replaces` and a verify, or
    ///   not at all.
    /// * it must still EXIST. With nothing on disk there is nothing to
    ///   resume from and the fresh placement is as good as any.
    /// * the directory the add just chose must be EMPTY. `remove_dir`
    ///   enforces it rather than a test that could race: if anything is
    ///   in there, this leaves the record where the add put it.
    /// * the row must still be `Queued`, checked and rewritten under ONE
    ///   hold of its lock. A job the scheduler has already started owns
    ///   its directory, and moving it out from under a live writer would
    ///   be a far worse bug than the one this fixes.
    fn reuse_cancelled_dir(&self, nzo_id: &str, want: &Path) {
        let cur = {
            let q = self.queue.lock_ok();
            q.iter()
                .map(|j| j.lock_ok())
                .find(|g| g.nzo_id == nzo_id)
                .map(|g| g.out_dir.clone())
        };
        let Some(cur) = cur else { return };
        if cur == *want || !want.exists() {
            return;
        }
        // Outside every job lock: `dir_claim` locks each row in the queue
        // and in history, which is the lock note `daemon_retry` carries
        // at its own call.
        if !matches!(self.dir_claim(want), crate::job::DirClaim::Free) {
            return;
        }
        if std::fs::remove_dir(&cur).is_err() && cur.exists() {
            return;
        }
        let q = self.queue.lock_ok();
        for j in q.iter() {
            let mut g = j.lock_ok();
            if g.nzo_id != nzo_id {
                continue;
            }
            if g.state != JobState::Queued || g.out_dir != cur {
                return;
            }
            info!(
                target: "queue",
                "undo: {nzo_id} goes back to {} rather than starting again in {}",
                want.display(),
                cur.display()
            );
            g.out_dir = want.to_path_buf();
            return;
        }
    }

    /// Empty the undo store at startup.
    ///
    /// The index is in memory, so after a restart nothing names these
    /// files and no token can ever reach them again. Leaving them would
    /// be a leak that grows by one queue per unclean stop - and leaving
    /// them under the ADOPTABLE name in the spool ROOT would be worse
    /// than a leak, which is why the store is its own directory.
    ///
    /// Removes the directory's `.nzb` entries rather than the directory
    /// itself: a `remove_dir_all` on a path built from a config value is
    /// the shape this repo has been bitten by, and there is nothing else
    /// in here to remove.
    ///
    /// EVERY `.nzb` in there, which since the history half landed
    /// (`histundo.rs`) means both stores' copies - they share this
    /// directory, and the argument for purging is the same one twice
    /// over. So this is not a place to start matching on the `hist-`
    /// prefix: a copy neither index names is exactly what a start finds.
    pub fn purge_cancel_undo(&self) {
        let dir = self.cancel_undo_dir();
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return;
        };
        let mut n = 0;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "nzb") && std::fs::remove_file(&p).is_ok() {
                n += 1;
            }
        }
        if n > 0 {
            info!(
                target: "queue",
                "cleared {n} cancelled download(s) whose undo window did not survive the restart"
            );
        }
    }
}
