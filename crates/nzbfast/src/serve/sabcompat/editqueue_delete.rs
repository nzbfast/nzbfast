//! The `GroupDelete` family of `jr_editqueue`: the four NZBGet delete
//! verbs (GroupDelete / GroupDupeDelete / GroupFinalDelete /
//! GroupParkDelete). Hoisted out of `sabcompat.rs` verbatim on 22 Aug 2026
//! because `fn jr_editqueue` sat three lines under the size gate's
//! 500-line function ceiling, so the next line anyone added would have
//! reddened main (TODO 106 pattern, as `check_sweep.rs`,
//! `get/fleet_knobs.rs` and `tasks/index_scan.rs`). Behaviour unchanged:
//! this is `jr_editqueue`'s own child module, glob-imported back, and the
//! arm keeps its ordering, its lock discipline and its comment blocks
//! exactly as they were. The `save_queue` that persists the result is
//! still the single one at the tail of `jr_editqueue`.

use super::*;

/// Rename a deleted LIVE job's spooled `.nzb` out of the shape
/// `recover_orphaned_spool` adopts, and point the record at the new
/// name.
///
/// A history-less delete drops the queue row durably right here, while
/// the spool copy is unlinked much later, in `spend_deferred_delete`,
/// once the fetch has drained. A kill in that window left a spool file
/// no record named - which is exactly what `recover_orphaned_spool`
/// re-adopts, so the release an *arr had just cancelled came back and
/// downloaded again at the next start. The suffix defeats that matcher
/// (it takes only `SABnzbd_nzo_nzbfast*.nzb`), and because the path is
/// written back to the record, park's own unlink and any kept-files
/// notice still name the real file.
///
/// A spool copy under any other name is not adoptable in the first
/// place, so it is left alone rather than renamed for nothing - which is
/// `job::mask_spool_path`'s rule, and the rename itself is now its code.
/// This arm and the REST one carried the whole matcher twice; when the
/// unlink-refused delete needed the same rename from a third place
/// (`drop_spool`), the copy became the shared helper and both facades
/// kept only the "point the record at the new name" half.
fn mask_spool_from_recovery(g: &mut Job) {
    if let Some(masked) = mask_spool_path(&g.nzb_path, ".deleting") {
        g.nzb_path = masked;
    }
}

/// The body of the `"GroupDelete" | "GroupDupeDelete" | "GroupFinalDelete"
/// | "GroupParkDelete"` arm. Returns the arm's `ok`: whether any queue
/// row was removed.
///
/// `rpc_error` because the arm can now REFUSE: a history store that
/// cannot take the row replacing the one being deleted must say so
/// rather than answer a bare `false`, which the caller cannot tell from
/// "no such job" (the reason the catch-all arm at the bottom of
/// `jr_editqueue` sets one too).
pub(super) fn group_delete(
    d: &Arc<Daemon>,
    cmd: &str,
    ids: &[i64],
    rpc_error: &mut Option<String>,
) -> bool {
    // NZBGet addresses jobs by the numeric half of the nzo_id.
    let hit_id = |id: &str| ids.contains(&nzo_int(id));
    // M5 (14 Aug sweep): one arm, four distinct NZBGet
    // contracts. Per nzbget.com/documentation/api/editqueue
    // and the nzbgetcom ChangeLog:
    //   GroupDelete      files gone,  history row DELETED/MANUAL
    //   GroupDupeDelete  files gone,  history row DELETED/DUPE
    //   GroupFinalDelete files gone,  NO history row
    //   GroupParkDelete  files KEPT,  history row DELETED/MANUAL
    // Sonarr and Radarr cancel with GroupFinalDelete, so the
    // files half is what stops a cancelled partial download
    // leaving orphaned payload nothing names.
    let del_files = cmd != "GroupParkDelete";
    let hist_status = match cmd {
        "GroupDupeDelete" => "DUPE",
        "GroupFinalDelete" => "",
        _ => "MANUAL",
    };
    // EVERY ROW THIS VERB TAKES OUT OF THE QUEUE OWES A DURABLE
    // REPLACEMENT, AND IT IS WRITTEN BEFORE ANYTHING IS TOUCHED.
    //
    // `delete_prewrite` overrides the terminal keys in the JSON rather
    // than stamping them on a live Job - precisely so it can be written
    // while the pipeline is still running - so there is nothing stopping
    // it going first, and going first is what makes a refusal cost the
    // user an error instead of a job that has left BOTH stores. Its
    // answer was a `()` until 26 Aug 2026, so a store that refused the
    // append (0444, or owned by a uid this daemon no longer runs as -
    // one `sudo nzbfast` is enough) lost the record while this handler
    // went on to abort the transfer, remove the files and publish the
    // absence, reporting success throughout (P2-1).
    //
    // AHEAD of the aborts below and not merely ahead of the queue
    // retain: a refusal here has cancelled nothing, so the request is
    // exactly as safe to retry as it was to make. The alternative -
    // letting the retain run and unpicking a custody plan, a
    // reservation, an emptied early-publish list and four stamped
    // fields on the way back out - is a rollback nobody would trust
    // after the first change to any of them.
    //
    // GroupFinalDelete owes no history row at all, and `delete_prewrite`
    // answers `true` for it rather than pretending otherwise.
    let owed: Vec<Arc<Mutex<Job>>> = d
        .queue
        .lock_ok()
        .iter()
        .filter(|j| hit_id(&j.lock_ok().nzo_id))
        .cloned()
        .collect();
    if !d.delete_prewrite(&owed, hist_status) {
        *rpc_error = Some(
            "the history store could not be written, so nothing was deleted - \
             check the permissions on the data folder"
                .into(),
        );
        return false;
    }
    // A deleted job's prefetch sidecar must stop writing to
    // its directory - the *arrs delete through here, so this
    // is an ordinary path, not a corner of one.
    d.poke_sidecar(hit_id);
    // ...and a job the sidecar is RUNNING still has live
    // writers, however queued its row looks. Snapshotted
    // here, before the queue lock: reading the sidecar mutex
    // inside `q.retain` would take it under queue+job, a
    // lock edge nothing else in the daemon has.
    let sidecar_owner = d.sidecar_owner();
    // §129, same as the REST arm: a Finishing job's repair
    // must stop pulling recovery volumes. The hub abort at
    // the bottom cannot do it - it is scoped to the hub's
    // owner, and a job in the lane is not that.
    d.cancel_tail_fetches(hit_id);
    let mut stopped_active = false;
    // Which job was on the wire: the stop signal is aimed by
    // nzo_id, same as the REST arm.
    let mut stopped_ids: Vec<String> = Vec::new();
    // The file half is collected under the queue lock and done after it,
    // exactly like the REST delete arm - and through the SAME
    // `CustodyBatch` rather than a hand-copy of its choreography, which
    // is the whole point: the `owns_hub` note at the bottom of this
    // function is about a fix the REST path got and this facade did not,
    // and the §296 take diverged the same way inside a single day. File
    // removal can hold locks for a Trash call's timeout, and the notice
    // lock is a leaf.
    let mut custody = CustodyBatch::default();
    // Jobs owed a history row, filed after the queue lock
    // drops - park() pushes to history without the queue
    // lock held, and this path keeps that order.
    let mut to_history: Vec<Arc<Mutex<Job>>> = Vec::new();
    // The releases this verb removes (the *arr's cancel is
    // the same statement), and the spool copies a refused
    // removal may still owe the notice. Both are settled
    // after the lock - see the REST arm, which carries the
    // rationale for each.
    let mut deleted_names: Vec<String> = Vec::new();
    let mut nzb_by_dir = std::collections::HashMap::new();
    // The M8 hold. It used to be the whole answer: the placeholder was
    // written AFTER the retain, so any other mutation's save - the
    // coalescing saver's own thread included - could land in between
    // and publish a queue.json the record had already left while
    // nothing in history named it yet, and a stop right there lost the
    // record from BOTH stores (read-only sweep 2, M8). The placeholder
    // now goes down before the retain, which closes that window on its
    // own; the hold stays as the belt, because the arm that owes NO
    // history row still moves a spool copy and stamps a record between
    // here and this handler's save. IO then queue, the order
    // `save_queue` takes them in.
    let publish_hold = Daemon::hold_queue_writes();
    let mut q = d.queue.lock_ok();
    let before = q.len();
    q.retain(|j| {
        let mut g = j.lock_ok();
        if ids.contains(&nzo_int(&g.nzo_id)) {
            // ...but not the backup copy: see
            // `is_held_alternative`.
            if !is_held_alternative(&g) {
                deleted_names.push(g.name.clone());
            }
            let active = g.state == JobState::Downloading;
            let lane = g.state == JobState::Finishing;
            // The same custody transaction the REST delete arm takes,
            // out of one place rather than copied: the §296 take (not
            // gated on the files half), then the reservation and the
            // choice between removing now, deferring to `park()` and
            // waiting on the prefetch wind-down. The rules, and the
            // incident behind each, live on `CustodyBatch::plan`.
            //
            // BEFORE this arm rewrites the record into its history
            // shape, and that is load-bearing rather than tidy: the
            // deferral asks whether a pipeline is still writing, the
            // history arm below stamps `state = Failed` over the very
            // field that answers it, and a `Finishing` job would then
            // read as idle and have its directory removed out from under
            // the tail that is unlocking and moving inside it. The old
            // hand-copy survived that only because it had snapshotted
            // `lane` fifteen lines earlier and tested the SNAPSHOT.
            // Custody is decided from the record as the request found
            // it.
            custody.plan(d, &mut g, sidecar_owner.as_ref(), del_files);
            g.delete_status = hist_status.to_string();
            if active {
                // The pipeline is running - abort below,
                // park() finishes the job's cleanup once the
                // fetch drains: it removes the files if
                // del_on_drop asks, and files the record into
                // history when delete_status asks (or drops
                // it, the pre-M5 shape, when it is empty).
                g.tombstone = true;
                stopped_active = true;
                stopped_ids.push(g.nzo_id.clone());
                // ...but park is a long way off - the fetch
                // has to drain and the deferred file removal
                // has to run (unbounded on a hung NAS)
                // before it writes anything durable, while
                // the save_queue at the end of THIS handler
                // publishes a queue.json the row has already
                // left. A kill in between and the record is
                // in neither store: no DELETED row for the
                // dupe check or the retry button, and for
                // GroupParkDelete a kept payload nothing
                // names (M1). The durable placeholder that
                // covers that interval is already on disk -
                // it is what this handler opened with.
                if hist_status.is_empty() {
                    // GroupFinalDelete owes no history row, so nothing
                    // durable will ever name this job again - and the
                    // spool copy outlives the row until park spends the
                    // deferred delete. Set aside now so a kill in that
                    // window cannot have it re-adopted.
                    mask_spool_from_recovery(&mut g);
                }
            } else {
                // Tombstoned even though it is leaving the
                // queue right here: a queued job can still be
                // running in the prefetch sidecar, and an Ok
                // that lands after this would otherwise run
                // the whole completion tail and park the
                // deleted job a second time.
                g.tombstone = true;
                if hist_status.is_empty() {
                    // FinalDelete: no history row, so the
                    // spooled NZB is dead weight - unless a
                    // refused removal needs it back.
                    // ...and unless PARK owns the removal,
                    // in which case park owns the copy too
                    // and this masks it instead. Sweep 9,
                    // finding 2; the helper has the argument.
                    park_or_drop_spool(&mut g, del_files, lane, &mut nzb_by_dir);
                } else {
                    // The record becomes a history row now.
                    // Stamped here, not rendered on the fly:
                    // both facades and the dashboard read
                    // these fields.
                    g.state = JobState::Failed;
                    g.fail_message = if hist_status == "DUPE" {
                        "deleted from the queue as a duplicate".into()
                    } else {
                        "deleted from the queue".into()
                    };
                    g.finished_at = Some(std::time::Instant::now());
                    g.finished_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|t| t.as_secs() as i64);
                    to_history.push(j.clone());
                }
            }
            false
        } else {
            true
        }
    });
    let ok = q.len() < before;
    drop(q);
    // The rows are gone from the live queue. Their durable
    // replacements went down before it, so a save landing
    // right here describes no gap - which is what the
    // regression beside this seam asks a restart to prove.
    #[cfg(test)]
    {
        let spool = d.spool.display().to_string();
        let seam = DELETE_PREWRITE_BARRIER
            .lock_ok()
            .clone()
            .filter(|(k, _, _)| *k == spool);
        if let Some((_, open, release)) = seam {
            open.wait();
            release.wait();
        }
    }
    // History first, so a poll that races the delete sees the
    // row appear rather than the job vanish and return.
    if !to_history.is_empty() {
        d.history.lock_ok().extend(to_history.iter().cloned());
        // The record this writes is already durable, as the
        // placeholder this handler opened with: this line
        // refreshes it to the stamped record and its refusal
        // costs the row's `finished_at` precision and nothing
        // else, which is why it is the one answer here that
        // may be dropped.
        let _ = d.history_upsert(&to_history);
    }
    // A placeholder's in-flight registration ends where its record
    // reaches MEMORY. For the ACTIVE arm that is a park an unbounded
    // wait away and park's own guard takes the id back out, so those
    // are left alone; for every other row this handler prewrote it is
    // the extend above. `owed` minus `stopped_ids` is exactly that
    // remainder - and it also covers a row that left the queue between
    // the prewrite and the retain, which reaches neither and would
    // otherwise sit in the set for the life of the daemon.
    let settled: Vec<String> = owed
        .iter()
        .map(|j| j.lock_ok().nzo_id.clone())
        .filter(|id| !stopped_ids.contains(id))
        .collect();
    d.delete_prewrite_filed(&settled);
    // Every record this handler removed now has a durable
    // row of its own, so saves may resume. Retention runs
    // outside the hold - it prunes, it does not replace.
    drop(publish_hold);
    if !to_history.is_empty() {
        d.history_enforce_retention();
    }
    // The slow half, with no global lock held: the unlinks, the removals,
    // the reservations coming back down, the kept-files notices (a
    // refused removal with the queue row already gone is invisible
    // unless the notice names it) and the handoff to the prefetch drain.
    // The order, and why each step sits where it does, is on
    // `CustodyBatch::settle`.
    custody.settle(d, sidecar_owner.as_ref(), &mut nzb_by_dir);
    // After the batch rather than inside it: this is the *arr's own
    // statement that it no longer has these releases, and it touches
    // nothing the removal touches.
    d.note_releases_deleted(&deleted_names);
    // `owns_hub`, exactly as the REST arm does it, and for
    // the reason spelled out there: `state == Downloading`
    // is NOT the owner test. A job whose network leg has
    // finished still reads Downloading through its
    // verify/repair/unpack tail, by which time the
    // scheduler has handed the hub to the NEXT job -
    // so deleting the finished one aborted a healthy,
    // unrelated download, which then failed permanently
    // (a Local fail_kind is not `transient()`, so nothing
    // retried it) and fired its pp-script, failure
    // notification and failure re-grab.
    //
    // The REST path was fixed for this; the JSON-RPC
    // facade is a hand-copy that never got it, so which
    // client type the user configured in Sonarr decided
    // whether the bug was reachable - the same shape the
    // shared queue primitives were extracted to end.
    //
    // Shared with the REST arm now rather than hand-copied a
    // fourth time, which is also how it inherits the re-fire
    // the single shot needed - see `stop_deleted_transfer`.
    super::api::queue::stop_deleted_transfer(d, stopped_ids);
    // Shared with the REST delete rather than hand-copied a
    // third time - the rationale (and the active-deletion
    // exception) lives on the helper.
    if ok {
        super::api::queue::note_queue_idle_unless_active(d, stopped_active);
    }
    ok
}
