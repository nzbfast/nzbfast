//! The history view: the JSON the dashboard and the SAB-compatible
//! clients read, and the recategorize that relabels a finished job and
//! moves its payload to where the new category would have put it.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// What a Retry of this history row needs FREE on the output volume.
///
/// Almost always the extraction peak alone: a job that reached history
/// has its archive parts on the disk already, so the room owed is the
/// payload they unpack into (see [`unpack_space_needed`], and the
/// failure message this pairs with, which says "nothing is re-downloaded
/// and only the unpack re-runs").
///
/// The one row where that is false is the MID-DOWNLOAD full disk. Its
/// bytes are NOT all down - that is why it stopped - so the retry has to
/// fetch the remainder before it can unpack anything, and passing
/// `to_fetch = 0` named a figure a whole unfetched remainder too small.
/// The drawer gates its Retry button on this number, so under-reporting
/// lights the button up early and the user frees exactly what we asked
/// for and fails a second time - which is the defect the encrypted arm
/// of `unpack_space_needed` was added for, one row over. `postproc`
/// already draws this exact line: it appends the "nothing is
/// re-downloaded" clause to every disk-full message EXCEPT this one.
///
/// The remainder comes from `downloaded_bytes` (this run's fetch, so a
/// resumed job that failed again counts a little high - the safe
/// direction, since the whole point is not to name a figure the user can
/// free and still fail at).
pub(super) fn retry_space_needed(j: &Job) -> u64 {
    let to_fetch = if crate::serve::disk_full_mid_download(&j.fail_message) {
        j.total_bytes.saturating_sub(j.downloaded_bytes)
    } else {
        0
    };
    unpack_space_needed(to_fetch, j.total_bytes, &j.archive_shape)
}

/// Change the category of a job that already finished: relabel the
/// history entry and, when the payload sits in a folder of its own, move
/// that folder to where the new category would have put it - the
/// per-category override first, then the global completed destination,
/// then the download root, mirroring `relocate_completed`'s ladder.
///
/// A Failed job moves too - retry reuses `out_dir` when it is free, so
/// the article journal travels with the partial payload and the rerun
/// both resumes AND completes into the right place - but only under the
/// download root: the completed-move destinations are for finished
/// payloads, not in-progress state. One case relabels WITHOUT moving,
/// said out loud in the reply: a TV-filed job, whose files are
/// interleaved with other jobs' in a shared Show/Season folder, so
/// moving `out_dir` would drag innocent siblings along. The move
/// happens with no locks held - `move_tree` on a NAS is seconds, and
/// the queue must not stall behind it.
pub(super) fn history_change_cat(d: &Daemon, id: &str, cat: &str) -> Value {
    let target = d.history.lock_ok().iter().find_map(|j| {
        let g = j.lock_ok();
        (g.nzo_id == id).then(|| {
            (
                j.clone(),
                g.state,
                g.category.clone(),
                g.out_dir.clone(),
                g.filed,
                g.finalizing,
            )
        })
    });
    let Some((job, state, current, out_dir, filed, finalizing)) = target else {
        return json!({"status": false,
            "error": "no job with that nzo_id (a job still downloading keeps its category until it finishes)"});
    };
    if finalizing {
        return json!({"status": false,
            "error": "post-processing is still running for this job - try again when it settles"});
    }
    if current == cat {
        return json!({"status": true});
    }
    // Claim the job for the duration. `finalizing` above is a snapshot
    // and stops being true the moment it is read; this is a live marker
    // retry and delete both consult, so nothing can pull the record out
    // from under a move that has already started. Dropped on EVERY exit
    // below, including the early error returns.
    struct MoveClaim<'a>(&'a Daemon, String);
    impl Drop for MoveClaim<'_> {
        fn drop(&mut self) {
            self.0.moving.lock_ok().remove(&self.1);
        }
    }
    if !d.moving.lock_ok().insert(id.to_string()) {
        return json!({"status": false,
            "error": "this job's files are already being moved - try again when it settles"});
    }
    let _claim = MoveClaim(d, id.to_string());
    // The snapshot above happened BEFORE the claim went up, so re-verify
    // both of its gates now that it has: a delete that slipped into the
    // window has already removed the record (deleting files this move
    // would race), and a password unlock that slipped in has raised
    // `finalizing` (it checks `moving` only after raising, so exactly
    // one of the two proceeds). Checked before any filesystem work.
    if !d.history.lock_ok().iter().any(|j| Arc::ptr_eq(j, &job)) {
        return json!({"status": false,
            "error": "no job with that nzo_id (it was removed just now)"});
    }
    if job.lock_ok().finalizing {
        return json!({"status": false,
            "error": "post-processing is still running for this job - try again when it settles"});
    }
    let mut split_error: Option<String> = None;
    // Nothing on disk to move: relabel and stop. Otherwise move_tree fails
    // (read_dir on a missing source is ENOENT) and the category could never
    // be corrected at all - for a job whose pre-flight verdict failed it
    // before out_dir was ever created, a folder the user tidied by hand, or
    // a move_completed share that is not mounted right now. Worse, every
    // attempt left a stray empty category directory behind, because
    // move_tree's first act is create_dir_all(dst.parent()). Relabelling is
    // the one part that needs no filesystem work, so do just that.
    let source_missing = !filed && !out_dir.is_dir();
    let moved = if !filed && !source_missing {
        let base = if state == JobState::Completed {
            let cat_root = d
                .move_completed_cats
                .read_ok()
                .iter()
                .find(|(c, _)| *c == cat)
                .map(|(_, p)| p.clone());
            match (cat_root, d.move_completed.read_ok().clone()) {
                // The override IS that category's root - no repeated component.
                (Some(root), _) => root,
                (None, Some(root)) if !cat.is_empty() => root.join(cat),
                (None, Some(root)) => root,
                (None, None) if !cat.is_empty() => d.out_dir().join(cat),
                (None, None) => d.out_dir(),
            }
        } else if let Some(root) = d.write_through_root(cat) {
            // TODO 317: a job that has NOT completed is recategorized
            // by moving it now, so the category it moves INTO decides
            // where it downloads for the rest of its life. Sending it
            // to the download root instead would leave it there with
            // its own `write_through` record still saying it owes no
            // move - a payload that never reaches the destination and
            // nothing to say why.
            root
        } else if cat.is_empty() {
            d.out_dir()
        } else {
            d.out_dir().join(cat)
        };
        // Pick a free name rather than merging blind. The queued-job arm
        // goes through refile_out_dir with dir_claim, and retry does the
        // same, for the reason its comment gives: re-using a claimed
        // directory would put two live jobs in it. Without this, re-adding
        // the same NZB under another category (which claims the folder while
        // held as a duplicate) and then recategorising the finished one
        // merges a whole payload into the claimed directory - and both
        // history records then name it, so plan_history_delete marks each as
        // the other's claimant and "Remove and delete files" silently
        // refuses for both, leaving a folder undeletable from the UI.
        let stem = out_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // Under the same lock the enqueue and retry paths pick THEIR
        // directories with, and reserved before the lock goes: a free
        // name is only free until somebody takes it, and no record will
        // name this one until the move below finishes.
        struct Reservation<'a>(&'a Daemon, PathBuf);
        impl Drop for Reservation<'_> {
            fn drop(&mut self) {
                self.0.reserved.lock_ok().remove(&self.1);
            }
        }
        let dest = {
            let _publish = d.add_lock.lock_ok();
            let dest = choose_out_dir(&base.join(&stem), &stem, &|p| d.dir_claim(p)).0;
            d.reserved.lock_ok().insert(dest.clone());
            dest
        };
        let _reservation = Reservation(d, dest.clone());
        // Same aliasing guard as relocate_completed: a dest that IS the
        // current folder through case or symlinks must not self-merge.
        let same = dest == out_dir
            || matches!((dest.canonicalize(), out_dir.canonicalize()),
                        (Ok(a), Ok(b)) if a == b);
        if same {
            None
        } else {
            // Count first: move_tree's same-filesystem merge moves entry by
            // entry and propagates the first error, so a failure can leave
            // the payload split across both folders. Without this the whole
            // failure is indistinguishable from "nothing happened".
            let before = file_count(&out_dir);
            match crate::smart::move_tree(&out_dir, &dest) {
                Ok(()) => {
                    info!(target: "move", "recategorized → {}", dest.display());
                    Some(dest)
                }
                Err(e) => {
                    // Same split detection relocate_completed does. A
                    // partial move is the ordinary Windows case: the
                    // whole-directory rename is refused while a child is
                    // open, the merge path runs, and it stops at the open
                    // file having already moved the siblings.
                    let moved_some = file_count(&out_dir) < before;
                    error!(
                        target: "move",
                        "{} → {}: {e}\n[move] {}",
                        out_dir.display(),
                        dest.display(),
                        if moved_some {
                            format!(
                                "the payload is now SPLIT - some files moved before this \
                                 failed. Check both {} and {} before deleting either.",
                                out_dir.display(),
                                dest.display()
                            )
                        } else {
                            format!(
                                "nothing moved - the download is still at {}",
                                out_dir.display()
                            )
                        }
                    );
                    if moved_some {
                        // The files that moved exist nowhere else, so the
                        // record has to follow the bytes even though the
                        // call failed - leaving it on the half-emptied
                        // source points the dashboard, a later delete and
                        // the *arr import at a folder they have left.
                        // Reported as a failure below, after the state is
                        // updated, so the user is told rather than shown a
                        // success over a split payload.
                        split_error = Some(format!(
                            "the files are now SPLIT between {} and {} because the move \
                             failed part way ({e}). Check both before deleting either.",
                            out_dir.display(),
                            dest.display()
                        ));
                        Some(dest)
                    } else {
                        // Nothing moved: leave the category alone too. A
                        // label saying "movies" over files still sitting in
                        // tv/ is a lie that outlives the error message.
                        return json!({"status": false,
                            "error": format!("could not move the files: {e}")});
                    }
                }
            }
        }
    } else {
        None
    };
    // Commit under the history lock, against a record that is still the
    // one we snapshotted. The `moving` marker keeps retry and delete
    // off this job, but the check is cheap and it is the last chance to
    // notice that the record went somewhere else - a job the user
    // deleted just before the marker went up, say. Writing `out_dir`
    // into a detached Arc would point nothing at the bytes we just
    // moved, and `save_queue` would not persist it either.
    {
        let h = d.history.lock_ok();
        if !h.iter().any(|j| Arc::ptr_eq(j, &job)) {
            let where_ = moved.clone().unwrap_or_else(|| out_dir.clone());
            return json!({"status": false,
                "error": format!(
                    "the history entry was removed while its files were being moved - \
                     they are now at {}",
                    where_.display()),
                "path": where_.to_string_lossy()});
        }
        let mut g = job.lock_ok();
        g.category = cat.to_string();
        if let Some(p) = &moved {
            g.out_dir = p.clone();
            // TODO 317: `out_dir` and `write_through` are one fact
            // stated twice - where the payload is, and whether the
            // mover still owes it a trip. The bytes have just moved, so
            // the record moves with them. A COMPLETED job is not
            // touched here: its arm above targets the destination
            // directly whatever the write-through setting says, so it
            // has arrived by the same route the mover would have taken
            // and owes nothing either way.
            if g.state != JobState::Completed {
                g.write_through = d.write_through_root(cat).is_some();
            }
        }
        // UX §18: a recategorize that stopped part way leaves the
        // payload in two directories, and `out_dir` has just followed
        // the bytes that made it. The error below tells whoever pressed
        // the button, once - it was the ONLY witness, and it does not
        // survive a page reload. Record the source the way the
        // completion path records it, so the row keeps warning and a
        // later delete has something to reach the other half by.
        //
        // SET, never cleared: a job that was already split by its
        // completion move still is - this relocation only touched
        // `out_dir`, and the source half it knows about is untouched.
        if split_error.is_some() {
            g.move_split = out_dir.to_string_lossy().to_string();
        }
    }
    d.register_cat(cat);
    // The record commit is PART of the move: a recategorize that
    // physically relocated the payload and then could not persist the
    // record restores the OLD one at restart, pointing every later
    // delete/retry/import at the emptied source while the bytes sit
    // unclaimed at the destination (Codex sweep 5 Aug M5). The live
    // record is right either way - what failed is durability, and the
    // caller has to hear it with both paths in hand. §129 1a: the
    // record lives in the history store now, so THAT append is the
    // durability that matters here.
    let durability = (!d.history_upsert(std::slice::from_ref(&job))).then(|| match &moved {
        Some(dest) => format!(
            "the updated record could not be written to the history store - after \
             a restart the history points at {} again while the files are at {}. \
             Check free space and write permission on the data folder, then use \
             Save queue",
            out_dir.display(),
            dest.display()
        ),
        None => format!(
            "the new category could not be written to the history store - it \
             reverts at the next restart. Check free space and write permission \
             on the data folder, then use Save queue ({cat} is live for now)"
        ),
    });
    // Reported only now: the record above had to be updated first so it
    // points at where the bytes actually are, but the caller must still be
    // told this failed rather than shown a success over a split payload.
    if let Some(msg) = split_error {
        return json!({"status": false,
            "error": match &durability {
                Some(dur) => format!("{msg} Also: {dur}."),
                None => msg,
            },
            "path": moved.map(|p| p.to_string_lossy().to_string())});
    }
    if let Some(dur) = durability {
        return json!({"status": false,
            "error": dur,
            "moved": moved.as_ref().map(|p| p.to_string_lossy().to_string()),
            "path": moved.unwrap_or(out_dir).to_string_lossy()});
    }
    let note = if filed {
        "relabeled only: the files were filed into a shared TV folder and stayed there"
    } else {
        ""
    };
    // `path` is what the dashboard's toast names; kept even when nothing
    // moved so the message can still say where the files live.
    let path = moved.clone().unwrap_or(out_dir);
    json!({"status": true,
           "moved": moved.map(|p| p.to_string_lossy().to_string()),
           "path": path.to_string_lossy(),
           "note": note})
}

/// The window and filters one history read answers. §129 1a: parsed
/// once, served by ONE pass over the records - filtering, facet counts
/// and row building all under a single job-lock acquisition per record,
/// with the GLOBAL history lock held only long enough to clone the Arc
/// list (a pointer copy per record). Before this, every read held the
/// global lock across an O(all-time) JSON build, which is what a
/// one-year history turns into a wedge.
pub(super) struct HistQuery {
    pub failed_only: bool,
    /// SAB's own `status=`: `clean_comma_separated_list(kwargs.get
    /// ("status"))`, matched against the same word the row publishes
    /// (`sab_history_status` - Moving/Completed/Failed/Queued, the set
    /// our history already speaks). `None` matches every status, same
    /// as SAB's `if statuses:` guard. `failed_only=1` OVERWRITES this to
    /// `{"Failed"}` in `from_params`, exactly as SAB's own
    /// `_api_history_default` does - "We ignore any other statuses,
    /// having both doesn't make sense" - never additive with an
    /// explicit `status=`.
    pub status: Option<std::collections::HashSet<String>>,
    pub category: Option<String>,
    pub ids: Option<std::collections::HashSet<String>>,
    /// Case-insensitive substring over the names a user knows a
    /// download by: posted name, category, oracle identity, filed-as.
    /// SAB's history API takes `search` too, so the param is
    /// compat-shaped rather than invented.
    pub search: Option<String>,
    /// The dashboard's chip buckets: "done" / "failed" / "locked"
    /// (anything else = all). Narrower than `failed_only` and additive
    /// to it; the facet counts are computed before either applies.
    pub bucket: Option<String>,
    pub start: usize,
    /// The window size. 0 = everything from `start` - the shape the
    /// dashboard poll and the internal callers use deliberately, and
    /// what a `nzo_ids=` selection renders under whatever the window
    /// says. `from_params` never produces it: a request that names no
    /// limit gets `HISTORY_DEFAULT_LIMIT`.
    pub limit: usize,
}

/// What a `mode=history` request that names no window gets.
///
/// The page it bounds renders the FULL facade row per record and does up
/// to two `exists()` stats each (`storage_deleted`), so an unbounded
/// default made every bare request cost the whole store: measured at
/// 112 ms + 30 MB of transient allocation at 22,000 rows and
/// 562 ms + 304 MB at 110,000, against 3.1 ms / 6.6 ms and a flat
/// +64 kB with this cap in place (`measure_history_replay` in
/// histstore.rs prices both shapes in one run). Unlike the dashboard poll -
/// which is revision-gated in api/queue.rs and clamps to 1..=500 - this
/// one is ungated, so the cost scaled with the number of polling clients
/// rather than with the download rate. Any *arr or phone client could
/// stand it up at will.
///
/// **500 is more generous than SABnzbd's own answer and than every real
/// client's ask**, which is what makes it safe to default:
///
/// - SABnzbd 4.5.x `_api_history_default` does `if not limit: limit =
///   cfg.history_limit()`, and `cfg.history_limit` is
///   `OptionNumber("misc", "history_limit", 10)` - real SAB answers a
///   bare `mode=history` with **10 rows**. (`build_history`'s
///   `limit: int = 1000000` signature default is unreachable from the
///   API path.) So nothing written against SAB can depend on getting
///   more than ten.
/// - Sonarr and Radarr both send `start=0&limit=DownloadClientHistoryLimit`,
///   default **60** (`Sabnzbd.cs` -> `SabnzbdProxy.GetHistory`).
/// - nzb360 sends `start=0 limit=20` (sabnzbd/sabnzbd#872's traffic log).
/// - LunaSea sends `limit: 200` (`sabnzbd/core/api/api.dart`
///   `getHistory`), our own dashboard `start=0&limit=200`.
///
/// An explicit `limit` is still honoured as asked, however large: paging
/// is the escape hatch for anyone who genuinely wants the whole store,
/// `noofslots` keeps reporting the full matched count so they know how
/// far to page, and a `nzo_ids=` selection bypasses the window entirely
/// (SAB semantics: a named id is always findable). What is gone is
/// paying for all of it without asking.
pub(super) const HISTORY_DEFAULT_LIMIT: usize = 500;

impl HistQuery {
    pub(super) fn from_params(params: &std::collections::HashMap<String, String>) -> Self {
        let failed_only = params.get("failed_only").map(String::as_str) == Some("1");
        HistQuery {
            failed_only,
            // SAB's `_api_history_default`: `failed_only` overwrites
            // whatever `status=` named, it does not narrow it further.
            status: if failed_only {
                Some(std::iter::once("Failed".to_string()).collect())
            } else {
                comma_separated_set(params, "status")
            },
            // `cat` FIRST, then `category` - SAB's own
            // `kwargs.get("cat") or kwargs.get("category")`, on both
            // this mode and `mode=queue`, in 4.5.0 and 5.1.2 alike.
            // Only `category` was read until 31 Aug 2026, so a client
            // sending SAB's shorter spelling got an UNFILTERED history
            // and no error - which is worse than a refusal, because
            // "show me only this category" silently answered with
            // everything.
            category: params
                .get("cat")
                .or_else(|| params.get("category"))
                .filter(|c| !c.is_empty() && *c != "*")
                .cloned(),
            ids: nzo_ids_param(params),
            search: params
                .get("search")
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty()),
            bucket: params
                .get("bucket")
                .filter(|b| matches!(b.as_str(), "done" | "failed" | "locked"))
                .cloned(),
            start: params
                .get("start")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            // `limit=0` is SAB's own spelling of "no window given" -
            // its `if not limit` treats an explicit zero and an absent
            // param identically - so both land on the default cap here
            // too. Answering a zero with an empty page would be the
            // other reading, and no SAB client expects it.
            limit: params
                .get("limit")
                .and_then(|v| v.parse().ok())
                .filter(|n| *n > 0)
                .unwrap_or(HISTORY_DEFAULT_LIMIT),
        }
    }
}

/// One history read: `(slots, noofslots, counts)`. `summary` picks the
/// compact per-row shape (`mode=dashboard`'s list) over the full SAB
/// facade row; `noofslots` counts everything the filters matched, not
/// the window; `counts` are the bucket facets (all/done/failed/locked)
/// over the search/category/ids-filtered set - the client's chips need
/// them and must not need the whole payload to compute them any more.
pub(super) fn history_page(d: &Daemon, q: &HistQuery, summary: bool) -> (Vec<Value>, usize, Value) {
    // Snapshot the Arcs; drop the global lock before any job lock.
    let arcs: Vec<Arc<Mutex<Job>>> = d.history.lock_ok().clone();
    // §284's spare snapshot, taken ONCE and BEFORE the loop below takes
    // its first job lock. `alt_held_spares` walks the queue and locks
    // every row in it, so calling it from inside `history_row` - where a
    // history record's own mutex is held - is the job-then-queue order
    // this tree deadlocks on. On the SUMMARY path it is not taken at
    // all: the compact rows the dashboard polls carry no offer (see
    // `history_row` for why the drawer's on-demand row is the only one
    // that needs it), so the common every-second render pays nothing.
    let held: Vec<crate::serve::altcand::HeldSpare> = if summary {
        Vec::new()
    } else {
        d.alt_held_spares()
    };
    let (mut all, mut done, mut failed, mut locked) = (0usize, 0usize, 0usize, 0usize);
    // What the header's one-click "Clear completed" would take: Completed
    // and not password-locked (locked rows survive the value=completed
    // sweep - see `plan_history_delete`).
    let mut clearable = 0usize;
    // Same question for "Clear failed": Failed and not password-locked. A
    // Failed row can carry `password_required` too - `settle_locked_failure`
    // sets it when an unpack failed for want of a password nobody has
    // supplied yet - and that row is the only thing offering the 🔑, so
    // `plan_history_delete`'s value=failed sweep spares it exactly as
    // value=completed spares a locked Completed row.
    let mut clearable_failed = 0usize;
    let mut matched = 0usize;
    let mut slots: Vec<Value> = Vec::new();
    for j in arcs.iter().rev() {
        let j = j.lock_ok();
        // §91: selected, counted and rendered under ONE lock on the
        // record. Taking it twice - once to test the filter, again to
        // build the row - let the two see different states: a Failed
        // job whose auto-retry cooldown came due between them is pulled
        // back out of history and reset to Queued, so `failed_only=1`
        // answered with a row saying `"status": "Queued"` and an empty
        // `fail_kind` / `fail_action`. An *arr asking for failures is
        // entitled to get only failures back, and the remedy keys it
        // reads to act on one must be there.
        if !q.category.as_ref().is_none_or(|c| j.category == *c)
            || !q.ids.as_ref().is_none_or(|s| s.contains(j.nzo_id.as_str()))
        {
            continue;
        }
        if let Some(needle) = &q.search {
            let hit = j.name.to_lowercase().contains(needle)
                || j.category.to_lowercase().contains(needle)
                || j.identity_name.to_lowercase().contains(needle)
                || j.filed_base
                    .as_ref()
                    .is_some_and(|b| b.to_lowercase().contains(needle));
            if !hit {
                continue;
            }
        }
        // Facets over the search/category set, BEFORE the failed_only
        // bucket narrows it - they are what the bucket chips display.
        //
        // CLASSIFIED ON THE WORD THE ROW PUBLISHES, never on the raw
        // `JobState` - the same call `status=` was moved onto in
        // `f2761fed8` and every render site already makes. The counters,
        // `failed_only` and the bucket chips were all left on the raw
        // state (read-only sweep finding 13, 31 Aug 2026), so a §96
        // storage-deleted row - Completed on paper, its output folder
        // deleted since, and published as `"Failed"` with the sentence
        // saying why - was counted under `done`, excluded by
        // `failed_only=1` and excluded by `bucket=failed`. The user saw
        // a Failed row that "Show failed" then hid, and a chip count
        // that disagreed with the rows under it.
        let pub_failed = publishes_as_failed(&j);
        all += 1;
        if pub_failed {
            failed += 1;
            if !j.password_required {
                clearable_failed += 1;
            }
        } else {
            done += 1;
        }
        if j.password_required {
            locked += 1;
        }
        // `clearable` is what "Clear completed" would sweep, so it has to
        // agree with `plan_history_delete`'s own `value=completed` rule -
        // and that one no longer takes a row it publishes as Failed.
        if j.state == JobState::Completed && !pub_failed && !j.password_required {
            clearable += 1;
        }
        if q.failed_only && !pub_failed {
            continue;
        }
        match q.bucket.as_deref() {
            Some("done") if j.state != JobState::Completed || pub_failed => continue,
            Some("failed") if !pub_failed => continue,
            Some("locked") if !j.password_required => continue,
            _ => {}
        }
        // SAB's `status=`: a comma list matched against the same word
        // the row publishes - `sab_history_status_published`, not the
        // bare `sab_history_status`, or a `status=Completed` request
        // could return a row whose own `"status"` key says `"Failed"`
        // (§96's storage-deleted flip). `None` (no param, or
        // `failed_only`'s own arm above already narrowed to Failed)
        // matches everything.
        if let Some(want) = &q.status
            && !want.contains(sab_history_status_published(&j).1)
        {
            continue;
        }
        let idx = matched;
        matched += 1;
        // Direct id selection bypasses the window (SAB semantics: a
        // named id is always findable, whatever page is showing).
        if q.ids.is_none()
            && q.limit > 0
            && (idx < q.start || idx >= q.start.saturating_add(q.limit))
        {
            continue;
        }
        if q.ids.is_none() && q.limit == 0 && idx < q.start {
            continue;
        }
        slots.push(if summary {
            history_summary(d, &j)
        } else {
            history_row(d, &j, &held)
        });
    }
    let counts = json!({"all": all, "done": done, "failed": failed, "locked": locked,
                        "clearable": clearable, "clearable_failed": clearable_failed});
    (slots, matched, counts)
}

/// §96 (AltMount audit, item 2): a Completed row whose output directory
/// the user has since deleted presents as Failed - "the files this row
/// promises are not there". Nothing else notices for a job nzbfast
/// grabbed for itself, and Failed is the one status a SAB client's
/// failed-download handling acts on (grab another release), which for a
/// payload deleted before anyone consumed it is the right outcome.
///
/// **Not for *arr-grabbed jobs, and that is the fix, not an oversight.**
/// The five conditions below are also the NORMAL successful end state of
/// every *arr download: Sonarr/Radarr import the payload (hardlink or
/// move) and then remove the leftover download folder, leaving the
/// parent - the completed-downloads root - exactly where it was. So the
/// flip fired on success, and every imported row eventually read
/// "Failed: the downloaded files are no longer on disk". No filesystem
/// evidence separates "imported and cleaned up" from "deleted before
/// import" - both leave an absent directory under a live parent - so the
/// question has to be answered by WHO OWNS THE IMPORT, and for an *arr
/// job that is the *arr. What we give up by standing down: an *arr stuck
/// on a folder deleted before it imported no longer gets auto-failed by
/// us, and instead surfaces in the *arr's own queue as the import
/// warning it already raises. That is the smaller error by a wide
/// margin - the false Failed fired on every successful download, the
/// true one needs a user to delete a completed folder inside the import
/// window.
///
/// Measured blast radius of the false Failed, so the next reader does
/// not have to re-derive it: Sonarr's `FailedDownloadService.Check`
/// early-returns unless the tracked download is `Downloading` or
/// `ImportBlocked`, and `TrackedDownloadService` re-seeds state from its
/// own `DownloadImported` history event after a restart - so an
/// already-imported release was NOT blocklisted or re-grabbed. The harm
/// was a false and alarming display plus the facade `status` field every
/// SAB client reads (and a real blocklist only if the *arr's database is
/// reset while the row is still in our history).
///
/// The parent guard stays and is load-bearing: the flip fires only while
/// the PARENT directory still exists, so this is never "the NAS is
/// unmounted" - a mount that is down would otherwise flip a whole page
/// of healthy history to Failed at once and have every *arr blocklist a
/// healthy release per poll, the §154 harm class. Checked at render time
/// for the rows on the requested page only, never persisted and never
/// swept in the background; the store keeps the truthful Completed, so a
/// restored folder restores the row.
fn storage_deleted(j: &Job) -> bool {
    j.state == JobState::Completed
        // Mid-move the directory is legitimately absent at one end;
        // the mover's own amber furniture reports that state.
        && !j.move_pending
        // The *arr owns this payload's import and its cleanup - see above.
        && !is_arr_origin(&j.origin)
        && j.out_dir.is_absolute()
        && !j.out_dir.exists()
        && j.out_dir.parent().is_some_and(|p| p.exists())
}

/// The English diagnostic a storage-deleted row carries in
/// `fail_message`, same contract as the pipeline's own sentences: the
/// opening clause is the verdict, the dashboard composes the localized
/// guidance from the tokens beside it.
const STORAGE_DELETED_MSG: &str = "the downloaded files are no longer on disk; \
     the output folder was deleted after this download completed";

/// §129 1b: the compact row `mode=dashboard` lists. What the LIST
/// renders and nothing else - the drawer fetches the full row on demand
/// via `mode=history&nzo_ids=`. Keys are a subset of the facade row's,
/// under the same names, so the client renders both with one template.
/// The SAB status word for a history row. `Moving` while the
/// completed-folder move is still owed (issue #59): the mover runs
/// post-park, so a job with an absolute category folder sat in history
/// as `Completed` with `storage` still naming the pre-move path for the
/// whole copy - and Sonarr/Radarr import on `Completed`, so they were
/// handed the wrong final folder whenever they polled inside that
/// window. Real SAB shows its post-processing stages in HISTORY
/// (`Verifying`, `Extracting`, `Moving`, `Running`), which is why every
/// SAB client already parses `Moving` as "busy, keep waiting"; once the
/// attempt settles, `move_pending` drops (success and failure both -
/// the retry ladder runs on `move_failed` + the auto-retry stamp), so
/// this can never park an *arr forever. A FAILED move therefore reads
/// `Completed` again, with `storage` truthfully naming the source the
/// files still sit in.
fn sab_history_status(j: &Job) -> &'static str {
    match j.state {
        JobState::Completed if j.move_pending => "Moving",
        JobState::Completed => "Completed",
        JobState::Failed => "Failed",
        _ => "Queued",
    }
}

/// [`sab_history_status`] with the §96 `storage_deleted` flip folded in:
/// `(deleted, the word this crate actually PUBLISHES for the row)`.
/// Filtering on the bare `sab_history_status` would let a row selected
/// under `status=Completed` come back with its own `"status":
/// "Failed"`, because the filter and the render would have disagreed
/// about which word this row carries - so a `status=` filter matches
/// against the SAME call every render site already makes.
fn sab_history_status_published(j: &Job) -> (bool, &'static str) {
    let deleted = storage_deleted(j);
    (
        deleted,
        if deleted {
            "Failed"
        } else {
            sab_history_status(j)
        },
    )
}

/// Does this row PUBLISH as Failed - the one question every filter, chip
/// count and bulk delete has to ask, rather than reading `state`.
///
/// Read-only sweep finding 13 (31 Aug 2026). `status=` was moved onto
/// [`sab_history_status_published`] in `f2761fed8` and the rest were
/// left behind, so a §96 storage-deleted row rendered `"Failed"` while
/// `failed_only=1` hid it, `bucket=failed` excluded it, `delete&value=
/// failed` left it and `value=completed` removed it. One door now, so
/// the word a user reads and the word a filter acts on cannot part
/// again.
pub(crate) fn publishes_as_failed(j: &Job) -> bool {
    sab_history_status_published(j).1 == "Failed"
}

fn history_summary(d: &Daemon, j: &Job) -> Value {
    let (deleted, status) = sab_history_status_published(j);
    json!({
        "nzo_id": j.nzo_id,
        "name": j.name,
        "category": if j.category.is_empty() { "*" } else { &j.category },
        "status": status,
        "bytes": j.total_bytes,
        "size": sab_units_b(j.total_bytes as f64),
        "completed": j.finished_unix.unwrap_or(0),
        "origin": j.origin,
        // Same rename as the facade row above: the count is `retries`
        // in both, so one template reads either.
        "retries": j.retries,
        "library": j.library,
        // §282 item 14: what this row replaced, why, and what replaced
        // it. Empty on every job that did neither, which is almost all
        // of them - the row renders the clause only when there is one.
        // Both directions ride BOTH row shapes, or the list and its
        // drawer would tell two different stories about one switch.
        "alt_from_name": j.alt_from_name,
        "alt_why": j.alt_why,
        "alt_to_name": j.alt_to_name,
        "fail_message": if deleted { STORAGE_DELETED_MSG } else { j.fail_message.as_str() },
        // A deleted-storage row is a LOCAL fact (the post is fine) and
        // the one thing worth offering is a fresh download - "show the
        // folder", local's usual move, would open a path that is gone.
        "fail_kind": if deleted {
            "local"
        } else if j.state == JobState::Failed {
            fail_kind_token(j.fail_kind())
        } else {
            ""
        },
        "fail_action": if deleted {
            "retry"
        } else if j.state == JobState::Failed {
            fail_action(
                j.fail_kind(),
                fail_hint(&j.fail_message),
                &j.fail_message,
                j.password_required,
            )
        } else {
            ""
        },
        "auto_retry_at": j.auto_retry_at,
        "password_required": j.password_required,
        "has_password": j.password.is_some(),
        // U8: the list row shows the disk-space state for a `space`
        // failure without opening the drawer, so it needs the same two
        // facts the full record carries - the verdict and what the
        // retry actually needs free (see the full-record twins for why
        // space_needed is not the set size).
        "disk_full": j.state == JobState::Failed && disk_full_failure(&j.fail_message),
        "space_needed": retry_space_needed(j),
        "media": j.media,
        "archive_shape": j.archive_shape,
        "identity_name": j.identity_name,
        "downloaded_bytes": j.downloaded_bytes,
        "elapsed_secs": (j.elapsed_secs * 10.0).round() / 10.0,
        // TODO 200: the list row showed download time only, so a job
        // that downloaded in 22 s and then sat 27 minutes in its tail
        // read "22s - 16 MB/s" and the stuck tail left no trace in the
        // UI record. The tail's own figure rides the summary too.
        "postproc_secs": (j.postproc_secs * 100.0).round() / 100.0,
        "bad_blocks": j.bad_blocks,
        "verify_blocks": j.verify_blocks,
        "unpack_blocked_by": j.unpack_blocked_by,
        "move_split": j.move_split,
        "move_failed": j.move_failed,
        "move_attempts": j.move_attempts,
        "move_pending": j.move_pending,
        "moved_to": if j.out_dir.starts_with(d.out_dir()) {
            String::new()
        } else {
            j.out_dir.to_string_lossy().into_owned()
        },
        "storage": j.out_dir.to_string_lossy(),
    })
}

/// Downloaded bytes as `(total, month, week, day)`, off the M18b usage
/// ledger - the four running totals SAB puts at the top of its history
/// body, from the one place here that actually counts wire bytes.
///
/// The ledger is keyed `"YYYY-MM-DD" -> host -> bytes`, plus a
/// `"lifetime"` bucket billed in parallel and a `"reliability"` bucket
/// that holds try counts rather than bytes. Only keys that parse as a
/// date are summed for the three windows; `"lifetime"` answers the
/// total, so a pruned date bucket does not shrink it.
fn usage_sums(d: &Daemon) -> (u64, u64, u64, u64) {
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| (t.as_secs() / 86_400) as i64)
        .unwrap_or(0);
    let (ty, tm, _) = civil_from_days(today);
    let u = d.usage.lock_ok();
    let bytes_in = |v: &Value| -> u64 {
        v.as_object()
            .map(|m| m.values().filter_map(Value::as_u64).sum())
            .unwrap_or(0)
    };
    let (mut month, mut week, mut day) = (0u64, 0u64, 0u64);
    for (k, v) in u.iter() {
        // "YYYY-MM-DD" and nothing else: "lifetime" and "reliability"
        // are not days and must not be billed to one.
        let parts: Vec<&str> = k.split('-').collect();
        let (Some(Ok(y)), Some(Ok(m)), Some(Ok(dd))) = (
            parts.first().map(|s| s.parse::<i64>()),
            parts.get(1).map(|s| s.parse::<u32>()),
            parts.get(2).map(|s| s.parse::<u32>()),
        ) else {
            continue;
        };
        let n = bytes_in(v);
        let days = days_from_civil(y, m, dd);
        if y == ty && m == tm {
            month = month.saturating_add(n);
        }
        // The last seven days INCLUDING today, which is what SAB's
        // week total means - not "since Monday".
        if today - days < 7 && today >= days {
            week = week.saturating_add(n);
        }
        if days == today {
            day = day.saturating_add(n);
        }
    }
    let total = u.get("lifetime").map(bytes_in).unwrap_or(0);
    (total, month, week, day)
}

pub(super) fn history_json(
    d: &Daemon,
    params: &std::collections::HashMap<String, String>,
) -> Value {
    let q = HistQuery::from_params(params);
    let (slots, n, counts) = history_page(d, &q, false);
    let (total, month, week, day) = usage_sums(d);
    json!({"history": {
        "slots": slots, "noofslots": n, "counts": counts,
        // --- SABnzbd history-body parity (issue #34) ----------------
        //
        // The keys real SAB puts beside `slots`, and the reason this
        // whole pass exists: SAB 2.0 trimmed its history body, NZB360
        // stopped showing history, and SAB's fix was to put `version`
        // back (sabnzbd/sabnzbd#872). Ours never had it, and #34 is
        // the same symptom on the same client.
        "version": SAB_VERSION,
        "total_size": sab_units(total as f64),
        "month_size": sab_units(month as f64),
        "week_size": sab_units(week as f64),
        "day_size": sab_units(day as f64),
        // Jobs sitting in a post-processing queue that is not the main
        // queue. One-pass has no such queue - a job post-processes in
        // the pipeline that downloaded it and stays a queue slot until
        // it lands in history - so this is always 0.
        "ppslots": 0,
        // SAB's change token: a client may send it back as
        // `last_history_update` to be told "nothing new". Our history
        // revision counter is exactly that quantity, and it is bumped
        // by every write in histstore.rs.
        "last_history_update": d.history_rev.load(Ordering::Relaxed),
    }})
}

/// The full SAB facade row - the pre-§129 key set, byte-stable for
/// external clients (pinned by tests/integration/dashboard_rev.rs).
/// Built under the caller's job lock.
fn history_row(d: &Daemon, j: &Job, held: &[crate::serve::altcand::HeldSpare]) -> Value {
    {
        // Truth-audit I: what this download is CALLED on disk, when
        // that is not what it was posted as. A de-obfuscation rename
        // left the history row saying "a4f9c2e1" and the folder
        // saying "Example.Movie.2019.1080p-GRP", with nothing
        // anywhere connecting the two - so a user who went looking
        // for their download could not tell which folder was it.
        // Empty when the two agree, so the drawer shows the row only
        // when there is something to reconcile.
        let filed_as = {
            let disk = if j.filed {
                // A TV-filed job's directory is the SHARED season
                // folder, so its name says nothing about this
                // episode. The stem the episode files were written
                // under is the answer.
                j.filed_base.clone().unwrap_or_else(|| j.name.clone())
            } else {
                j.out_dir
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            if disk == j.name { String::new() } else { disk }
        };
        // ...and whether `move_completed` put the payload somewhere
        // the download folder does not contain. The completion toast
        // announced a finished download and said nothing about the
        // files having gone to a NAS. Empty for everything still
        // under the download root.
        let moved_to = if j.out_dir.starts_with(d.out_dir()) {
            String::new()
        } else {
            j.out_dir.to_string_lossy().into_owned()
        };
        // §96 item 2: see `storage_deleted`. The same flip in both row
        // shapes, or the list and its drawer would disagree about one
        // record.
        let (deleted, status) = sab_history_status_published(j);
        json!({
            "nzo_id": j.nzo_id,
            "name": j.name,
            "nzb_name": format!("{}.nzb", j.name),
            "origin": j.origin,
            "nzb_path": j.nzb_path.to_string_lossy(),
            "category": if j.category.is_empty() { "*" } else { &j.category },
            "status": status,
            // §282 item 14: what this row replaced, why, and what replaced
            // it. Empty on every job that did neither, which is almost all
            // of them - the row renders the clause only when there is one.
            // Both directions ride BOTH row shapes, or the list and its
            // drawer would tell two different stories about one switch.
            "alt_from_name": j.alt_from_name,
            "alt_why": j.alt_why,
            "alt_to_name": j.alt_to_name,
            // §284: ...and what could still HAPPEN, which until now
            // stopped existing the moment the job left the queue. Absent
            // unless `altcand::parked_replaceable` says another copy is
            // still the move for this record - which is almost every red
            // row's answer of "no", so almost every row omits it.
            //
            // THE FULL ROW ONLY, and not `history_summary`. The drawer
            // fetches this shape on demand for the one row a person
            // opened (`histFullRow`), which is exactly where the offer is
            // drawn and read; the summary is the compact list row the
            // dashboard re-polls every second for every row on the page,
            // and putting a per-row spare filter and a spool stat there
            // would pay that cost on every tick to render a block the
            // list has no room for. The list already carries the
            // half it can act on, in `fail_action`'s own `find another`.
            "alt_offer": crate::serve::altcand::parked_offer_json(j, held),
            "fail_message": if deleted { STORAGE_DELETED_MSG } else { j.fail_message.as_str() },
            "fail_detail": j.fail_detail,
            // This failure was a full disk, decided by the same
            // matcher the NZBGet SPACE verdict uses. Its own key so
            // the drawer can pair the row with the LIVE free-space
            // number instead of string-matching a sentence: the fix
            // is entirely in the user's hands, and Retry re-runs
            // just the unpack (the article journal re-fetches
            // nothing while the volumes are intact).
            "disk_full": j.state == JobState::Failed && disk_full_failure(&j.fail_message),
            // What the retry actually needs FREE, which is not the
            // set size: the volumes are already on the disk, so the
            // room owed is the extracted payload - and, for an
            // ENCRYPTED set, the finish decrypt's temp copy beside
            // it as well. The drawer used to gate its Retry button
            // on `bytes` alone and would have lit it up one whole
            // payload too early on exactly the shape that hit this
            // (RAR5 encrypted, a tester, 2 Aug).
            "space_needed": retry_space_needed(j),
            // The failure classifier as a token, so the drawer can
            // say what to DO per kind - and suppress Retry for the
            // two kinds the daemon itself knows retrying cannot fix
            // (gone, preflight). Empty on anything not Failed.
            "fail_kind": if deleted {
                // A local fact - the post is fine (see the summary row).
                "local"
            } else if j.state == JobState::Failed {
                fail_kind_token(j.fail_kind())
            } else {
                ""
            },
            // M32: when the daemon has already scheduled its own
            // retry, say so - the user was shown a hard failure and
            // then watched the row silently resurrect. Unix seconds,
            // null when no retry is armed.
            "auto_retry_at": j.auto_retry_at,
            // ...and WHAT it is waiting for ("transport" or
            // "propagation"), which is also why the cooldown is the
            // length it is. Null when no retry is armed.
            "auto_retry_why": j.auto_retry_why,
            // The sub-cause inside the message, for the ONE remedy
            // button the drawer offers beside the reason. Two
            // failures can share a fail_kind and need opposite next
            // moves - see `fail_hint`. Empty on anything not Failed.
            "fail_hint": if deleted {
                // Its own sub-cause token: `local`'s generic guidance
                // points at the folder, and the folder is what is gone.
                "deleted"
            } else if j.state == JobState::Failed {
                fail_hint(&j.fail_message)
            } else {
                ""
            },
            // ...and the single action that answers it. One key so
            // the page never has to re-derive the rule, and so the
            // rule itself is testable.
            "fail_action": if deleted {
                "retry"
            } else if j.state == JobState::Failed {
                fail_action(
                    j.fail_kind(),
                    fail_hint(&j.fail_message),
                    &j.fail_message,
                    j.password_required,
                )
            } else {
                ""
            },
            // SAB's `retry` is a BOOLEAN - "this one can be asked for
            // again" - and ours was the try count under the same name.
            // A client that declares the field as a bool throws on a
            // number and never renders the list, which is the shape
            // #34 reported. The count keeps its meaning under
            // `retries`; the dashboard reads that.
            "retry": deleted
                || (j.state == JobState::Failed
                    && fail_action(
                        j.fail_kind(),
                        fail_hint(&j.fail_message),
                        &j.fail_message,
                        j.password_required,
                    ) == "retry"),
            "retries": j.retries,
            // This job came out of the local index rather than from
            // an NZB the user holds. It matters on a failure: a
            // "gone" verdict here means the post rotted out of the
            // library, nothing was ever written to disk, and the
            // copy must not talk about resuming what downloaded.
            "library": j.library,
            "duplicate_key": j.dupe_key.as_deref().unwrap_or(""),
            "storage": j.out_dir.to_string_lossy(),
            "path": j.out_dir.to_string_lossy(),
            "bytes": j.total_bytes,
            "size": sab_units_b(j.total_bytes as f64),
            // Stats (0 until a download actually ran): bytes ÷ secs
            // is the average network speed for this job.
            "downloaded_bytes": j.downloaded_bytes,
            "elapsed_secs": (j.elapsed_secs * 10.0).round() / 10.0,
            // SAB's native key for "when did this finish", unix
            // seconds. 0 for spool entries that predate
            // `finished_unix` - clients treat that as "unknown",
            // never as 1970.
            "completed": j.finished_unix.unwrap_or(0),
            // NULL when nothing verified this download (no PAR2 in
            // the post, or a resume that mapped no block) - the
            // dashboard says "not verified" for that and keeps it
            // out of the clean count. A number is a real verdict,
            // and `verify_blocks` is how many blocks produced it.
            "bad_blocks": j.bad_blocks,
            "verify_blocks": j.verify_blocks,
            // M24: the value never leaves the daemon - only the facts.
            "password_required": j.password_required,
            "has_password": j.password.is_some(),
            // Completed, but something in it is still packed. SAB has
            // no field for "succeeded with a caveat", so the archive
            // NAME rides in its own key (the dashboard composes the
            // sentence in the user's own language) while an English
            // one goes in the SAB-native `script_line` - the single
            // free-text slot a Completed history item has, and one
            // existing clients already surface beside the status.
            "unpack_blocked_by": j.unpack_blocked_by,
            // UX §18: the move to the completed folder stopped part
            // way and the payload is in TWO directories - this one
            // and `storage`. Its own key beside `unpack_blocked_by`
            // and for the same reason: SAB has no "succeeded with a
            // caveat", so the PATH rides here and the dashboard
            // composes the sentence in the user's own language.
            // Empty on everything that moved whole or never moved.
            "move_split": j.move_split,
            "move_failed": j.move_failed,
            // How many tries the ladder has spent. The drawer says
            // "tried N times" off this, and says the daemon has
            // stopped once it reaches the give-up count.
            "move_attempts": j.move_attempts,
            "move_pending": j.move_pending,
            "archive_shape": j.archive_shape,
            // §76: the same quality chip the queue row carries,
            // latched during the download and kept. Another additive
            // key - a client that does not know it ignores it.
            "media": j.media,
            // What an identity oracle said this release is, beside
            // the name it was posted under. Additive keys: `name`
            // stays exactly what every SAB client already matches
            // on, and a client that does not know these ignores
            // them.
            "identity_name": j.identity_name,
            "identity_imdb": j.identity_imdb,
            "identity_src": j.identity_src,
            "filed_as": filed_as,
            // The Smart Folder rule that chose its category, same
            // reason: "why is this in Films?" is answerable only by
            // the rule that decided it.
            "smart_rule": j.smart_rule,
            "moved_to": moved_to,
            // What the post-processing sweeps removed from this
            // job's directory, and whether the deletes were
            // recoverable when they ran. Additive keys; zero means
            // no drawer line.
            "cleaned_files": j.cleaned_files,
            "cleaned_par2": j.cleaned_par2,
            "cleaned_trash": j.cleaned_trash,
            // ...and when no oracle could name it, what synthesised
            // naming made of the payload: the file's own facts, then
            // the shortlist. English, and deliberately so - film
            // titles are not ours to translate, and the runtimes and
            // codecs in it are not words. See Job::identify.
            "identify": j.identify,
            // --- SABnzbd history-slot parity (issue #34) ------------
            //
            // Real SAB's history row, key for key (sabnzbd/database.py
            // unpack_history_info over the history table). Everything
            // below was missing from ours. Same reasoning as the queue
            // slot: a remote that deserializes the row into a declared
            // type finds a null where it expects a value and stops
            // before it renders the list.
            //
            // Where the concept does not exist in a one-pass
            // downloader, the value is what SAB sends when its own
            // feature is off, and the key says so.
            //
            // SAB's post-processing letter: R repair, U +unpack,
            // D +delete. One-pass does all three unless the add asked
            // for less.
            "pp": match j.sab_pp {
                Some(0) => "",
                Some(1) => "R",
                Some(2) => "U",
                _ => "D",
            },
            // The script this job ran, by basename - the override, else
            // the category's, else the global one (L4, 10 Aug sweep).
            "script": super::sabcompat::sab_script_name(
                &j.script_override,
                &d.cat_meta
                    .lock_ok()
                    .get(&j.category)
                    .map(|m| m.script.clone())
                    .unwrap_or_default(),
                &d.scripts.lock_ok(),
            ),
            // SAB reuses `report` to flag a URL-fetch job ("future")
            // and leaves it empty otherwise; nothing here fetches by
            // URL into history.
            "report": "",
            "url": "",
            "url_info": "",
            // Seconds on the wire, and seconds after it. One-pass has
            // no separate post-processing pass to time - verify,
            // repair and unpack all run inside the download - so the
            // whole elapsed time is download time and SAB's second
            // number is 0.
            "download_time": j.elapsed_secs.round() as u64,
            // SABnzbd sends whole seconds here and clients render it as
            // "post-processing took N". It was a hardcoded 0 - not a
            // rounded-down measurement, a placeholder - which made every
            // slow tail invisible to the one surface built to show it.
            // See `Job::postproc_secs` for what that cost.
            "postproc_time": j.postproc_secs.round() as u64,
            // Ours, not SAB's: the same figure unrounded, so a tail under
            // a second is distinguishable from one that never ran.
            "postproc_secs": (j.postproc_secs * 100.0).round() / 100.0,
            // TODO 207: and the OTHER half of "why did this take so
            // long" - which layer owned the network leg, longest-held,
            // with the seconds that back the claim. Another additive
            // key: null on every record written before the field
            // existed and on every job nothing judged, and the drawer
            // renders no row for a null. It is the same verdict the
            // queue row shows while the job is on the wire, so the page
            // renders it through the same `whyPhrase()`.
            "whyslow": j.whyslow.as_ref().map(super::whyslow::verdict_json),
            // SAB's per-stage action log. Nothing here writes one, and
            // an empty list is what SAB sends for a job that logged no
            // stages.
            "stage_log": Value::Array(Vec::new()),
            "downloaded": j.downloaded_bytes,
            // An unused column in SAB's own schema; it sends 0.
            "completeness": 0,
            "meta": Value::Null,
            "series": "",
            // SAB stores the NZB's md5. We keep a SHA of it instead
            // (`nzb_sha`, in the duplicate ledger), so there is no md5
            // to report and "" is SAB's own value for a row without
            // one.
            "md5sum": "",
            // Always empty, deliberately: M24's contract is that the
            // password itself never leaves the daemon, only the facts
            // about it (`has_password` / `password_required` above).
            "password": "",
            // SAB's second-tier history. There is one history here, so
            // nothing is ever archived out of it.
            "archive": false,
            // The postproc queue's live fields, which only SAB's
            // in-flight rows carry.
            "action_line": "",
            "loaded": false,
            // Unix seconds this job was added. Derived from the
            // record's monotonic `queued_at` where it survived, and
            // from the finish time less the elapsed download
            // otherwise.
            "time_added": j.queued_at
                .map(|t| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|n| n.as_secs())
                        .unwrap_or(0)
                        .saturating_sub(t.elapsed().as_secs())
                })
                // The persisted stamp before the estimate: it is the
                // add time itself, where finish-less-elapsed is only
                // the download's own span (M10).
                .or_else(|| j.queued_unix.map(|t| t.max(0) as u64))
                .unwrap_or_else(|| {
                    j.finished_unix
                        .unwrap_or(0)
                        .saturating_sub(j.elapsed_secs.round() as i64)
                        .max(0) as u64
                }),
            "script_line": if j.unpack_blocked_by.is_empty() {
                String::new()
            } else {
                format!(
                    "{} could not be unpacked: it is damaged, encrypted, or uses \
                     a compression method this build does not carry. The verified \
                     archive is in the output folder.",
                    j.unpack_blocked_by
                )
            },
        })
    }
}
