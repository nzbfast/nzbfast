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
pub(super) fn group_delete(d: &Arc<Daemon>, cmd: &str, ids: &[i64]) -> bool {
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
    // Slow work is collected under the queue lock and done
    // after it, exactly like the SAB delete arm and for the
    // reasons written there: file removal can hold locks for
    // a Trash call's timeout, and the notice lock is a leaf.
    let mut kept: Vec<(String, std::path::PathBuf, String)> = Vec::new();
    let mut doomed: Vec<(String, std::path::PathBuf, bool, crate::smart::FiledTail)> = Vec::new();
    // The same, for the one job whose writers are the
    // sidecar's: removed only once that has wound down.
    let mut pending_sidecar: Vec<(String, std::path::PathBuf, bool, crate::smart::FiledTail)> =
        Vec::new();
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
    // Active jobs owed a history row park cannot file until
    // its pipeline drains: they get a durable placeholder
    // row instead, written before the save_queue at the end
    // of this handler publishes their absence (M1).
    let mut prewrite: Vec<Arc<Mutex<Job>>> = Vec::new();
    // ...but "before the save_queue at the end of this
    // handler" was only ever true of THIS handler's save.
    // The row leaves the queue on the next line, the
    // placeholder is a file write and cannot go under the
    // queue mutex, and any other mutation's save - the
    // coalescing saver's own thread included - could land
    // in between and publish a queue.json the record had
    // already left while nothing in history named it yet. A
    // stop right there lost the record from BOTH stores
    // (read-only sweep 2, M8). Held until every replacement
    // row is durable, so no save can describe the gap.
    // IO then queue, the order `save_queue` takes them in.
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
                // names (M1). Collected here, written after
                // the lock drops - a file write has no
                // business under the queue mutex.
                if !hist_status.is_empty() {
                    prewrite.push(j.clone());
                } else {
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
                    hold_or_drop_spool(del_files, &g.out_dir, &g.nzb_path, &mut nzb_by_dir);
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
            if del_files {
                if active || lane || g.finalizing {
                    // Writers are still live; removing now
                    // lets the next positioned write recreate
                    // the files. Defer to park(), reserving
                    // the directory so `dir_claim` cannot
                    // hand it out in the gap - the SAB arm
                    // documents both halves.
                    g.del_on_drop = true;
                    d.reserved.lock_ok().insert(g.out_dir.clone());
                } else if sidecar_owner
                    .as_ref()
                    .is_some_and(|(id, _)| *id == g.nzo_id)
                {
                    // A prefetching job is Queued and not
                    // finalizing, so it fell into the arm
                    // below and had its directory removed
                    // while the sidecar was still writing
                    // into it - and the next file's first
                    // article recreated it (M2). Same
                    // reservation, released by the drain.
                    let tail = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                    d.reserved.lock_ok().insert(g.out_dir.clone());
                    pending_sidecar.push((
                        filed_stem(&g).to_string(),
                        g.out_dir.clone(),
                        g.filed,
                        tail,
                    ));
                } else {
                    let tail = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                    d.reserved.lock_ok().insert(g.out_dir.clone());
                    doomed.push((filed_stem(&g).to_string(), g.out_dir.clone(), g.filed, tail));
                }
            }
            false
        } else {
            true
        }
    });
    let ok = q.len() < before;
    drop(q);
    // The rows are gone from the live queue and every
    // durable replacement is still ahead of us.
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
    // The active job's placeholder goes down first, and in
    // any case before this handler's save_queue publishes
    // the queue without it.
    for j in &prewrite {
        d.delete_prewrite(j, hist_status);
    }
    // History first, so a poll that races the delete sees the
    // row appear rather than the job vanish and return.
    if !to_history.is_empty() {
        d.history.lock_ok().extend(to_history.iter().cloned());
        let _ = d.history_upsert(&to_history);
    }
    // Every record this handler removed now has a durable
    // row of its own, so saves may resume. Retention runs
    // outside the hold - it prunes, it does not replace.
    drop(publish_hold);
    if !to_history.is_empty() {
        d.history_enforce_retention();
    }
    // The slow half, with no global lock held. Reservations
    // release after the WHOLE batch (`reserved` is a set; two
    // entries naming one directory are one member).
    let reserved_dirs: Vec<std::path::PathBuf> =
        doomed.iter().map(|(_, dir, _, _)| dir.clone()).collect();
    for (name, dir, filed, tail) in doomed {
        if let FilesGone::Kept(why) = remove_job_files(&dir, &name, filed, &tail) {
            kept.push((name, dir, why));
        }
    }
    {
        let mut r = d.reserved.lock_ok();
        for dir in &reserved_dirs {
            r.remove(dir);
        }
    }
    // A refused removal with the queue row already gone is
    // invisible unless the notice names it.
    note_kept_files(d, kept, &mut nzb_by_dir);
    d.note_releases_deleted(&deleted_names);
    // The sidecar's job waits for the sidecar. Its own
    // reservation is released by the drain, not by the batch
    // above - the removal is still ahead of it.
    if let Some((_, target)) = sidecar_owner {
        for (name, dir, filed, tail) in pending_sidecar {
            d.remove_after_sidecar_drain(target.clone(), name, dir, filed, tail);
        }
    }
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
