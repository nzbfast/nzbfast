//! GH #86: removing a history entry stays undoable for a grace window.
//!
//! The sibling of [`crate::cancelundo`], for the other list. Read that
//! module's header first - the four rules are the same four, and this
//! one only records where the history case DIFFERS.
//!
//! The audit
//! (`research/MODAL-BLOCK-AUDIT-2026-09-17.md`, section 5) had left this
//! half alone on purpose, and its reason was that a plain
//! `del_files=0` history delete is not the pure list housekeeping its
//! own dialogs claim. It destroys two things:
//!
//! 1. **the spooled `.nzb`**, because `hold_or_drop_spool` is called
//!    with `false` and *"Everywhere else the spool copy dies with the
//!    record it belonged to"*. That copy is what makes a **Retry**
//!    possible, so a row restored without it comes back unretryable -
//!    which looks exactly like a row restored with it;
//! 2. **the early-published destination copies**, unconditionally:
//!    `early_take` does a `std::mem::take`, so after it the record no
//!    longer names them and nothing can re-derive the list.
//!
//! ## What is retained, and what is refused
//!
//! (1) is retained, the same way and in the same place the queue half
//! retains it: a HARD LINK under `<spool>/undo/`, taken before the
//! delete machinery touches the file, so the delete path is left
//! completely alone and the ordinary case costs no new bytes.
//!
//! (2) is **REFUSED**, and that is the whole judgement in this file. A
//! row carrying early copies gets no token and takes its whole batch
//! with it, because the alternatives are both worse:
//!
//! * *Restore the list without the files.* The record would come back
//!   naming destination copies that are gone - the silent downgrade
//!   this class of feature exists to refuse, wearing the face of a
//!   working undo.
//! * *Hold the files back instead of unlinking them.* A window that
//!   leaves them at the destination re-opens the orphan the delete arm
//!   closes in as many words (*"with the record gone this list is the
//!   ONLY thing that names those files"*): an unclean stop inside the
//!   window would strand them there forever, with the tombstone already
//!   durable. Moving them aside instead needs a rename the destination
//!   is usually on the wrong filesystem for, and a copy fallback over
//!   media files is not a thing a delete may pay for.
//!
//! Refusing costs nothing that today does not already cost: the row is
//! deleted exactly as it was before, and what the user loses is the
//! *offer* of an undo rather than any additional data. And the
//! population is narrow twice over - the early-publish feature is off
//! by default, and a settled move CLEARS the list (`mover.rs`), so a
//! history row carries early copies only when the feature is on AND
//! that job's move never landed.
//!
//! ## Why this restores the RECORD rather than re-adding it
//!
//! The queue half hands its rows to `enqueue_as`, which is a FRESH
//! placement - and `dir_claim_for_add` then reads the removed row's own
//! directory as a stranger's ground and climbs to `<stem>.2`, which is
//! the trap `Daemon::reuse_cancelled_dir` exists to undo after the
//! fact.
//!
//! **This route cannot hit that trap at all**, and that is the reason
//! for taking it: `Daemon::history_restore` puts the ORIGINAL
//! `Arc<Mutex<Job>>` back at its original index, so nothing is placed,
//! nothing is claimed, and `out_dir` is the field it always was. The
//! record's own `out_dir` is also why the collision cannot arrive from
//! the other side either: a plain history delete leaves the payload on
//! disk, so a job added in the window finds that directory OCCUPIED and
//! climbs past it exactly as it should.
//!
//! What this route owes instead is the two stamps the delete made on
//! the way out, and both are undone at spend time: `tombstone` on the
//! record, and the durable `{"deleted": true}` line in the store, which
//! is answered by re-appending the record (replay is last-line-wins,
//! and `tombstones_keep_append_order_and_let_an_id_come_back` pins it).
//! A restored row therefore sits at its old index in memory and at the
//! END of the file, so its position survives the window but not a
//! restart before the next compaction. That is the same
//! best-effort promise `history_restore`'s own doc makes.
//!
//! ## And the delete mark
//!
//! `note_releases_deleted` stamped the user's "I no longer have this"
//! on every name the request removed, and the duplicate check reads it.
//! The queue half spends that mark through `enqueue_as`'s
//! `DupeExempt::Anybody`; there is no `enqueue_as` here, so the spend
//! is explicit - [`Daemon::clear_delete_mark`] per restored row. Left
//! alone it would leave the user holding the release again with a mark
//! still saying they do not, for up to a day.

use super::*;

/// The window, and the ROW ceiling, are the queue half's: one figure
/// for one feature.
///
/// A history sweep is the bigger batch of the two ("Clear completed"
/// over a long list), but the ceiling is not the primary bound and
/// `sweep_hist_undo` keeps a SINGLE batch whole however large it is,
/// for the reason its queue-side twin gives - half a batch is not
/// undoable at all, so evicting one to buy inodes spends the whole
/// window and buys nothing.
///
/// If history ever turns out to want a different window from the queue,
/// that is a second constant with its own reasoning, not a number
/// changed here - and a decision for whoever owns the product, because
/// the argument on [`CANCEL_UNDO_SECS`] is about how long someone has to
/// change their mind rather than about anything this code can measure.
pub use crate::cancelundo::{CANCEL_UNDO_MAX_ROWS, CANCEL_UNDO_SECS};

/// One removed history row, and what putting it back needs.
///
/// The RECORD itself travels, not a copy of its fields: this restores
/// through [`Daemon::history_restore`] rather than through an add, so
/// there is nothing to rebuild it from and nothing to get wrong. See
/// the module header.
// No `Debug`: the record travels as an `Arc<Mutex<Job>>` and `Job` has
// none, deliberately - a job is a hundred fields deep and formatting one
// into a log line is how a mutex gets held across an I/O call.
#[derive(Clone)]
pub struct HistUndoRow {
    /// Where the row sat in history AS THE REMOVAL LEFT IT, which is
    /// the index `history_restore` reverses back into place.
    pub at: usize,
    pub job: Arc<Mutex<Job>>,
    /// Carried rather than read back off the record, because both
    /// readers want it when the record is at its least trustworthy: the
    /// failure sentence a user reads, and the [`Daemon::clear_delete_mark`]
    /// key, which must be the name `note_releases_deleted` stamped.
    pub name: String,
    pub nzo_id: String,
    /// Where the record's spool copy belongs - `g.nzb_path` as the
    /// delete found it.
    pub nzb_path: PathBuf,
    /// The retained link, under `<spool>/undo/`.
    pub held: PathBuf,
}

/// One delete request's worth of rows, spent as a unit.
pub struct HistUndoBatch {
    pub token: String,
    /// Unix seconds, for the window.
    pub at: i64,
    pub rows: Vec<HistUndoRow>,
}

/// What a spent token achieved. Both halves, always - see
/// [`crate::cancelundo::UndoOutcome`], which says why a count alone is
/// not an answer.
#[derive(Default, Debug)]
pub struct HistUndoOutcome {
    /// Rows back in the list, by nzo id.
    pub restored: Vec<String>,
    /// Rows that could not come back, one reason each.
    pub failed: Vec<String>,
}

/// The next token. `hundo` and not `undo`: the two stores are separate
/// and a token spent on the wrong one must MISS rather than half-match,
/// so the prefixes are disjoint by construction.
static HIST_UNDO_SEQ: AtomicU64 = AtomicU64::new(1);

impl Daemon {
    /// Retain one doomed history row, under the job lock the delete
    /// already holds, BEFORE it stamps the record.
    ///
    /// Returns `None` when this row cannot be retained, and every caller
    /// must treat that as "this BATCH is not undoable" - the
    /// all-or-nothing rule the queue half states at length.
    ///
    /// Two ways to answer `None`, and the first is the interesting one:
    ///
    /// * **the row carries early-published copies.** They are about to
    ///   be unlinked and cannot be given back; the module header has the
    ///   argument, and the check has to be HERE because `early_take` two
    ///   statements later is what empties the list.
    /// * the spool copy could not be linked aside, so a restored row
    ///   could not be retried.
    ///
    /// The record is NOT modified, for the reason `retain_for_undo`
    /// gives: `g.nzb_path` still names the spool copy, so
    /// `hold_or_drop_spool` keeps naming the file it always named and
    /// unlinking one link leaves the other.
    pub fn retain_hist_for_undo(
        &self,
        at: usize,
        job: &Arc<Mutex<Job>>,
        g: &Job,
    ) -> Option<HistUndoRow> {
        if !g.early_published.is_empty() {
            info!(
                target: "history",
                "{}: no undo window for this delete - {} early copy(ies) at the \
                 destination are about to be taken back and cannot be given back",
                g.nzo_id,
                g.early_published.len()
            );
            return None;
        }
        let dir = self.cancel_undo_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            warn!(
                target: "history",
                "{}: no undo window for this delete - the store could not be made: {e}",
                dir.display()
            );
            return None;
        }
        // `hist-` because the two stores share one directory (and one
        // startup purge, `purge_cancel_undo`, which takes every `.nzb`
        // in it): a RETRY carries a record from history into the queue
        // under the same nzo_id, so the two halves can legitimately name
        // one id minutes apart and an unprefixed name would hand one
        // half the other's NZB.
        let dest = dir.join(format!("hist-{}.nzb", g.nzo_id));
        // A leftover under this name is from an earlier delete of the
        // same id whose window has since been swept; `hard_link` fails
        // on an existing destination, so it goes first.
        let _ = std::fs::remove_file(&dest);
        if let Err(link_err) = std::fs::hard_link(&g.nzb_path, &dest) {
            // No links on this filesystem (exFAT, some SMB mounts), or
            // the spool copy is already gone. A copy answers the first
            // and fails the second, which is the answer either way.
            if let Err(copy_err) = std::fs::copy(&g.nzb_path, &dest) {
                warn!(
                    target: "history",
                    "{}: no undo window for this delete - the entry's copy of the NZB \
                     could not be held (link: {link_err}; copy: {copy_err})",
                    g.nzb_path.display()
                );
                let _ = std::fs::remove_file(&dest);
                return None;
            }
        }
        Some(HistUndoRow {
            at,
            job: job.clone(),
            name: g.name.clone(),
            nzo_id: g.nzo_id.clone(),
            nzb_path: g.nzb_path.clone(),
            held: dest,
        })
    }

    /// File a captured batch and mint its token, or throw the whole
    /// batch away.
    ///
    /// `removed` is how many rows the request actually took out of the
    /// list. They must be equal or there is no token, and the retained
    /// links are unlinked here rather than left to the sweep - see
    /// `Daemon::file_cancel_undo`, which this mirrors exactly.
    pub fn file_hist_undo(
        &self,
        rows: Vec<HistUndoRow>,
        removed: usize,
    ) -> Option<(String, usize)> {
        if rows.is_empty() || rows.len() != removed {
            if !rows.is_empty() {
                info!(
                    target: "history",
                    "no undo window for this delete: {} of {removed} removed row(s) \
                     could be held, and a partial undo is worse than none",
                    rows.len()
                );
                for r in &rows {
                    let _ = std::fs::remove_file(&r.held);
                }
            }
            return None;
        }
        let token = format!(
            "hundo{}",
            HIST_UNDO_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let n = rows.len();
        self.hist_undo.lock_ok().push_back(HistUndoBatch {
            token: token.clone(),
            at: job::unix_now(),
            rows,
        });
        self.sweep_hist_undo();
        Some((token, n))
    }

    /// Drop expired batches, and the oldest ones past the row ceiling.
    ///
    /// Called after every filing rather than on a timer, and a restart
    /// is the other sweep - both for the reasons `sweep_cancel_undo`
    /// states.
    pub fn sweep_hist_undo(&self) {
        let now = job::unix_now();
        let mut dropped: Vec<PathBuf> = Vec::new();
        {
            let mut b = self.hist_undo.lock_ok();
            while b
                .front()
                .is_some_and(|x| now.saturating_sub(x.at) >= CANCEL_UNDO_SECS as i64)
            {
                if let Some(x) = b.pop_front() {
                    dropped.extend(x.rows.into_iter().map(|r| r.held));
                }
            }
            let mut held: usize = b.iter().map(|x| x.rows.len()).sum();
            // `b.len() > 1`, not `> 0`: a single batch over the ceiling
            // stays whole, because half a batch is not undoable at all.
            while held > CANCEL_UNDO_MAX_ROWS && b.len() > 1 {
                if let Some(x) = b.pop_front() {
                    held -= x.rows.len();
                    dropped.extend(x.rows.into_iter().map(|r| r.held));
                }
            }
        }
        for p in dropped {
            let _ = std::fs::remove_file(p);
        }
    }

    /// Take a batch by token, if it is still inside its window. Sweeps
    /// first, so a token whose window closed is refused rather than
    /// honoured.
    pub fn take_hist_undo(&self, token: &str) -> Option<HistUndoBatch> {
        self.sweep_hist_undo();
        let mut b = self.hist_undo.lock_ok();
        let i = b.iter().position(|x| x.token == token)?;
        b.remove(i)
    }

    /// Put a taken batch back into history.
    ///
    /// Four things happen per row, and the ORDER of the last two is the
    /// part that is not free:
    ///
    /// 1. the row is checked for a live twin. Ten minutes is long enough
    ///    for the same nzo_id to have come back on its own - a retry
    ///    moves a record into the queue under its old id, and
    ///    `recover_orphaned_spool` re-adopts one at a start. Restoring
    ///    on top of that would put two records with one id in front of
    ///    every caller that resolves by id, so it refuses by name;
    /// 2. the spool copy is linked BACK to the path the record still
    ///    names, so the restored row can be retried. A held copy that
    ///    has vanished, or been EMPTIED by `drop_spool`'s third resort
    ///    (which truncates through the inode both links share), refuses
    ///    out loud rather than restoring a row whose retry could only
    ///    fail - exactly as `spend_cancel_undo` does;
    /// 3. the records go back into `self.history` at their old indices,
    ///    IN MEMORY FIRST. That order is what makes step 4 safe: a
    ///    `history_compact` racing this publishes the LIVE records, so a
    ///    record already in memory is carried by the rewrite rather than
    ///    erased by it;
    /// 4. and then the store is told, by appending the record again.
    ///    Replay is last-line-wins, so a record appended after its own
    ///    tombstone is alive again. A refused append falls back to the
    ///    atomic rewrite for the reason `history_publish` gives: the
    ///    append needs the FILE, the rewrite needs only the directory.
    pub fn spend_hist_undo(self: &Arc<Self>, batch: HistUndoBatch) -> HistUndoOutcome {
        let mut out = HistUndoOutcome::default();
        let mut back: Vec<(usize, Arc<Mutex<Job>>)> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        for row in batch.rows {
            if self.id_is_live(&row.nzo_id) {
                out.failed.push(format!(
                    "{}: that download is back in the list or the queue already",
                    row.name
                ));
                let _ = std::fs::remove_file(&row.held);
                continue;
            }
            if let Err(why) = self.relink_held_nzb(&row) {
                out.failed.push(format!("{}: {why}", row.name));
                let _ = std::fs::remove_file(&row.held);
                continue;
            }
            // The one stamp the delete made on the record that a restore
            // has to take off again. `early_published` needs nothing: a
            // row carrying early copies never got a token in the first
            // place (`retain_hist_for_undo`), so `early_take` found
            // nothing to take.
            row.job.lock_ok().tombstone = false;
            let _ = std::fs::remove_file(&row.held);
            names.push(row.name.clone());
            out.restored.push(row.nzo_id.clone());
            back.push((row.at, row.job));
        }
        if back.is_empty() {
            return out;
        }
        let jobs: Vec<Arc<Mutex<Job>>> = back.iter().map(|(_, j)| j.clone()).collect();
        self.history_restore(back);
        if !self.history_upsert(&jobs) && !self.history_compact() {
            // Both refused: a data folder this daemon cannot write at
            // all. The rows ARE back and a live daemon carries on with
            // them - what was lost is their survival across a restart,
            // which is the same sentence `history_publish` writes for
            // the same case, and it is the one thing this undo cannot
            // put right.
            warn!(
                target: "history",
                "{} restored entry(ies) could not be written back to the history \
                 store - they are in the list now but will not survive a restart",
                jobs.len()
            );
        }
        // The user holds these releases again, so the delete mark that
        // said otherwise is spent. Per row, because the mark is keyed on
        // the release name and a batch can hold several.
        for name in names {
            self.clear_delete_mark(&name);
        }
        info!(
            target: "history",
            "undo: {} entry(ies) are back in the list", out.restored.len()
        );
        out
    }

    /// Is this nzo_id already taken by a live record?
    ///
    /// Both lists, because both can hold the id a deleted history row
    /// used to carry: a retry moves the record into the QUEUE keeping
    /// its id, and a park files it back into HISTORY under the same one.
    fn id_is_live(&self, nzo_id: &str) -> bool {
        // ONE LOCK AT A TIME, and the queue's first. Every site that
        // wants both takes them in that order (the history delete arm
        // says so at its own `queue_dirs` snapshot), and a helper that
        // held history while reaching for the queue would be the one
        // edge pointing the other way.
        let queued = self
            .queue
            .lock_ok()
            .iter()
            .any(|j| j.lock_ok().nzo_id == nzo_id);
        queued
            || self
                .history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == nzo_id)
    }

    /// Put the retained NZB back where the record still points, or say
    /// why the row cannot come back.
    ///
    /// The EMPTY test comes first and is not a tidy-up: `drop_spool`'s
    /// third resort truncates the file when it can neither unlink nor
    /// rename it, and that truncation goes through the inode the
    /// retained link shares - so an empty held copy is the one case
    /// where the bytes are gone while the path is still there. A row
    /// restored from it would queue a retry with no articles in it.
    fn relink_held_nzb(&self, row: &HistUndoRow) -> Result<(), String> {
        match std::fs::metadata(&row.held) {
            Ok(m) if m.len() > 0 => {}
            Ok(_) => {
                return Err("the list's copy of the NZB was emptied while it was held".to_string());
            }
            Err(e) => return Err(format!("its copy of the NZB is gone ({e})")),
        }
        // Already there and readable - `drop_spool` was refused outright
        // - so there is nothing to put back.
        if std::fs::metadata(&row.nzb_path).is_ok_and(|m| m.len() > 0) {
            return Ok(());
        }
        let _ = std::fs::remove_file(&row.nzb_path);
        if let Some(parent) = row.nzb_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(link_err) = std::fs::hard_link(&row.held, &row.nzb_path)
            && let Err(copy_err) = std::fs::copy(&row.held, &row.nzb_path)
        {
            return Err(format!(
                "its copy of the NZB could not be put back (link: {link_err}; \
                 copy: {copy_err})"
            ));
        }
        Ok(())
    }
}
