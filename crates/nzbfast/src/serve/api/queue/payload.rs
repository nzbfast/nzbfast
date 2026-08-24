//! The two big read payloads the dashboard polls: the queue and the
//! history.
//!
//! Both are whole-collection walks that answer a GET, and between them
//! they were more than a quarter of `queue.rs`. Split out under the
//! §106 file ceiling - the mode handlers that WRITE (pause, delete,
//! recategorise, add) stay with `dispatch` in the parent.

use super::*;

/// Rename a deleted LIVE job's spooled `.nzb` out of the shape
/// `recover_orphaned_spool` adopts, and point the record at the new
/// name.
///
/// This delete files no history row, so it drops the queue row durably
/// right here while the spool copy is unlinked much later, in
/// `spend_deferred_delete`, once the fetch has drained. A kill in that
/// window left a spool file no record named - which is exactly what
/// `recover_orphaned_spool` re-adopts, so the release an *arr had just
/// cancelled came back and downloaded again at the next start. The
/// suffix defeats that matcher (it takes only
/// `SABnzbd_nzo_nzbfast*.nzb`), and because the path is written back to
/// the record, park's own unlink and any kept-files notice still name
/// the real file.
///
/// A spool copy under any other name is not adoptable in the first
/// place, so it is left alone rather than renamed for nothing - the rule
/// and the rename both live in `job::mask_spool_path`. The JSON-RPC
/// facade's GroupFinalDelete keeps a wrapper of its own in
/// `sabcompat::editqueue_delete` (the two arms share no module), but
/// only the wrapper: since 23 Aug 2026 both go through that one helper.
pub(super) fn mask_spool_from_recovery(g: &mut Job) {
    if let Some(masked) = mask_spool_path(&g.nzb_path, ".deleting") {
        g.nzb_path = masked;
    }
}

pub(super) fn m_queue(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let value = params.get("value").cloned().unwrap_or_default();
        // Trimmed, like the delete path's busy guard: a comma list with
        // spaces in it ("nzo_1, nzo_2") otherwise matched the guard and
        // not the action, and the second id was silently ignored.
        let hit_id = |id: &str| value == "all" || value.split(',').any(|v| v.trim() == id);
        let hit = |j: &Arc<Mutex<Job>>| hit_id(&j.lock_ok().nzo_id);
        match params.get("name").map(String::as_str) {
            Some("delete") => {
                // A deleted job's prefetch sidecar must stop
                // writing to its directory.
                d.poke_sidecar(hit_id);
                // The poke is fire-and-forget, so a job the sidecar is
                // RUNNING still has live writers however queued its row
                // looks - see `remove_after_sidecar_drain`. Snapshotted
                // before the queue lock: the sidecar mutex under
                // queue+job would be a lock edge nothing else takes.
                let sidecar_owner = d.sidecar_owner();
                // §129: and its post-network tail must stop pulling
                // recovery volumes. Not covered by the hub abort below -
                // that one is scoped to the job that OWNS the hub, and a
                // Finishing job by definition does not.
                d.cancel_tail_fetches(hit_id);
                let del_files = params.get("del_files").map(String::as_str) == Some("1");
                let mut stopped_active = false;
                // Which job was on the wire, not just that one was: the
                // stop signal is aimed by nzo_id (see
                // `stop_deleted_transfer`), and a batch delete of a
                // whole category names every row in the queue.
                let mut stopped_ids: Vec<String> = Vec::new();
                // Collected under the queue lock, recorded after it -
                // the notice's own lock is a leaf and must stay one.
                let mut kept: Vec<(String, std::path::PathBuf, String)> = Vec::new();
                // The file removal goes the same way, and for a
                // sharper reason: a Trash call is bounded at 30 s per
                // route and macOS runs TWO of them (Finder, then
                // NSFileManager), so doing this inside `q.retain`
                // held the GLOBAL queue lock for up to a minute on a
                // headless mac or a share with no .Trashes. pick_job,
                // queue_json, save_queue and every *arr status poll
                // stall behind it, and the *arr marks the client
                // unhealthy. Deleting after the lock is dropped costs
                // a reservation instead: `dir_claim` consults
                // `reserved` before anything else, precisely so a
                // directory with no record naming it cannot be
                // handed to a new job - which is exactly the window
                // that opens between the record going and the files.
                let mut doomed: Vec<(String, std::path::PathBuf, bool, crate::smart::FiledTail)> =
                    Vec::new();
                // The same, for the one job whose writers are the
                // sidecar's: removed only once that has wound down.
                let mut pending_sidecar: Vec<(
                    String,
                    std::path::PathBuf,
                    bool,
                    crate::smart::FiledTail,
                )> = Vec::new();
                // The releases this request removes: stamped after the
                // lock as the user's own statement that they no longer
                // have them, so a re-add is not held as a duplicate of
                // something that is not there. It is what the stop
                // button already promises in as many words - "adding the
                // same NZB again picks up from it" - and a hold made
                // that promise false.
                let mut deleted_names: Vec<String> = Vec::new();
                // See the history arm: spool copies whose fate waits on
                // the file removal.
                let mut nzb_by_dir = std::collections::HashMap::new();
                let mut q = d.queue.lock_ok();
                let before = q.len();
                q.retain(|j| {
                    if hit(j) {
                        let mut g = j.lock_ok();
                        // ...but not the backup copy: see
                        // `is_held_alternative`.
                        if !is_held_alternative(&g) {
                            deleted_names.push(g.name.clone());
                        }
                        let active = g.state == JobState::Downloading;
                        // §129: a Finishing job's tail is running in the
                        // lane - its writers are live like `finalizing`,
                        // but the hub abort below belongs to whatever is
                        // DOWNLOADING now, so it takes the non-active
                        // arm and relies on the tombstone making its
                        // tail a no-op at park.
                        let lane = g.state == JobState::Finishing;
                        if active {
                            // The pipeline is running - mark it
                            // for silent drop and abort below.
                            // park() drops the record and removes
                            // its spooled .nzb.
                            g.tombstone = true;
                            stopped_active = true;
                            stopped_ids.push(g.nzo_id.clone());
                            // ...and park is a long way off, while the
                            // row leaves the queue durably here. Set
                            // the spool copy aside so a kill in that
                            // window cannot have it re-adopted.
                            if g.delete_status.is_empty() {
                                mask_spool_from_recovery(&mut g);
                            }
                        } else {
                            // Non-active: the record is gone for
                            // good, so its spooled NZB is dead
                            // weight (retry only applies to
                            // history). Remove it now.
                            //
                            // Tombstoned all the same. A queued
                            // job can still be RUNNING in the
                            // prefetch sidecar, and the poke
                            // above only stops a download that
                            // has not finished: an Ok already on
                            // its way to the tail would otherwise
                            // unlock, rename, file into the TV
                            // library, move to the destination
                            // folder, run the pp-script and park
                            // the deleted job into history. The
                            // flag makes that tail a no-op.
                            g.tombstone = true;
                            // ...and its spool copy with it, unless the
                            // files half is about to be attempted: the
                            // notice's "download it again" needs that
                            // NZB when the removal is refused.
                            hold_or_drop_spool(del_files, &g.out_dir, &g.nzb_path, &mut nzb_by_dir);
                        }
                        if del_files {
                            if active || lane || g.finalizing {
                                // Writers are still live; removing
                                // now just lets the next positioned
                                // write recreate the files and
                                // orphan them. Defer to park(),
                                // which runs after the fetch drains.
                                //
                                // `finalizing` matters for the same
                                // reason and is NOT covered by
                                // `active`: a Completed job whose
                                // post-processing (unlock, rename,
                                // TV filing, NAS move) is still
                                // running has left Downloading, so
                                // this used to take the else arm and
                                // remove_dir_all the very directory
                                // the mover was reading from - half
                                // deleting a tree under it, or
                                // deleting an emptied source while
                                // the payload sat at the destination
                                // with no record left to delete it
                                // by. park() already implements the
                                // deferral and is always reached for
                                // a finalizing job (its tail holds
                                // its own Arc and parks after
                                // finalize_completed), so the files
                                // still go. Deferring on `finalizing`
                                // only, not on every non-active
                                // state: a never-run Queued job has
                                // no tail, so park would never fire
                                // and its files would never be
                                // removed at all.
                                g.del_on_drop = true;
                                // Reserve for the SAME reason the
                                // non-deferred arm below does, and
                                // for longer: the queue row goes
                                // now and the files go in `park()`,
                                // once the fetch has drained. A
                                // tombstoned job is dropped rather
                                // than filed, so in between
                                // `dir_claim` finds the directory in
                                // neither queue nor history and
                                // calls it free - and a re-add of
                                // the same release (a user retry, an
                                // *arr re-grab) can claim it and be
                                // writing there when `park()`
                                // finally removes the whole
                                // directory. `park()` releases it.
                                d.reserved.lock_ok().insert(g.out_dir.clone());
                            } else if sidecar_owner
                                .as_ref()
                                .is_some_and(|(id, _)| *id == g.nzo_id)
                            {
                                // The exception the comment above
                                // names: a never-run Queued job has no
                                // tail, but a PREFETCHING one has a
                                // whole pipeline, and removing here let
                                // the next file's first article
                                // recreate the directory and lay a
                                // fresh payload nothing names (M2).
                                // park is still the wrong destination -
                                // the abort's ordinary outcome is the
                                // sidecar's Err arm, which never parks -
                                // so the removal waits on the wind-down
                                // instead, and releases the reservation
                                // itself.
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
                                doomed.push((
                                    filed_stem(&g).to_string(),
                                    g.out_dir.clone(),
                                    g.filed,
                                    tail,
                                ));
                            }
                        }
                        false
                    } else {
                        true
                    }
                });
                let count = before - q.len(); // counted, as history's arm is
                drop(q);
                // Now that no global lock is held: the slow half.
                //
                // Every reservation is released AFTER the whole batch,
                // never per entry. `reserved` is a set, so two entries
                // naming one directory are one member: releasing after
                // the first would unreserve a directory a later entry
                // has not reached yet, and the gap is a whole Trash
                // call wide (30 s per route, two routes on macOS).
                let reserved_dirs: Vec<std::path::PathBuf> =
                    doomed.iter().map(|(_, dir, _, _)| dir.clone()).collect();
                for (name, dir, filed, tail) in doomed {
                    let outcome = remove_job_files(&dir, &name, filed, &tail);
                    if let FilesGone::Kept(why) = outcome {
                        kept.push((name, dir, why));
                    }
                }
                {
                    let mut r = d.reserved.lock_ok();
                    for dir in &reserved_dirs {
                        r.remove(dir);
                    }
                }
                // The row is gone from the queue either way - that is
                // what was asked for and it worked. What did NOT work
                // was the files half, and with the row went the only
                // place the user could see this download named.
                note_kept_files(d, kept, &mut nzb_by_dir);
                // The sidecar's job waits for the sidecar. Its own
                // reservation is released by the drain, not by the batch
                // above - the removal is still ahead of it.
                if let Some((_, target)) = sidecar_owner {
                    for (name, dir, filed, tail) in pending_sidecar {
                        d.remove_after_sidecar_drain(target.clone(), name, dir, filed, tail);
                    }
                }
                // Only the job that OWNS the hub may fire its
                // abort. `state == Downloading` is NOT that
                // test: job N stays Downloading through its
                // whole post-network tail while job N+1 is
                // already on the wire and owns hub.abort /
                // hub.queue_ctl (they are overwritten per job
                // and carry no owner tag), so deleting N during
                // its tail aborted N+1 - a healthy, unrelated
                // download. N+1 then failed permanently (a
                // Local fail_kind is not `transient()`, so no
                // auto-retry) and fired its pp-script, failure
                // notification and failure re-grab on a good
                // release, while N was never stopped at all
                // (its abort flag was last read long before).
                // `active_stream` is the owner - the watchdog
                // was already fixed to steer by it, for exactly
                // this hazard.
                //
                // Fire-and-keep-firing rather than fire-once: the
                // helper's doc has the window that swallowed the single
                // shot.
                stop_deleted_transfer(d, stopped_ids);
                if count > 0 {
                    d.note_releases_deleted(&deleted_names);
                    d.save_queue();
                    // The rationale lives on the helper, which the
                    // JSON-RPC delete variants share.
                    note_queue_idle_unless_active(d, stopped_active);
                }
                json!({"status": count > 0, "removed": count})
            }
            Some(op @ ("pause" | "resume")) => {
                if op == "pause" {
                    // Pausing a job also stops its prefetch.
                    d.poke_sidecar(hit_id);
                }
                let mut n = 0;
                let mut finishing = 0;
                for j in d.queue.lock_ok().iter().filter(|j| hit(j)) {
                    let mut g = j.lock_ok();
                    if apply_pause(d, &mut g, op == "pause") {
                        n += 1;
                    } else {
                        finishing += 1;
                    }
                }
                // The flag alone only takes effect when a job
                // next enters the queue. Pausing the item that
                // was ACTUALLY downloading left it running at
                // full speed while this answered success and
                // the queue kept showing it as Downloading -
                // so an nzb360 tap to free bandwidth did
                // nothing at all. Wind the transfer down too.
                if op == "pause" && n > 0 {
                    d.suspend_matching(true, |g| hit_id(&g.nzo_id));
                }
                if n > 0 {
                    d.save_queue();
                    // Pausing the last runnable job is the other way the
                    // queue goes idle without a park (M3). Resume takes
                    // the same call deliberately: it never EMITS on its
                    // own (the latch keeps a still-idle queue silent),
                    // and the re-arm the resume owes lives inside
                    // `apply_pause`, under this same queue lock.
                    d.note_queue_idle();
                }
                if n == 0 && finishing > 0 {
                    json!({"status": false, "error": "this job is still finishing"})
                } else {
                    json!({"status": n > 0})
                }
            }
            // SAB parity: mode=queue&name=switch&value=<nzo_id>
            // &value2=<index> moves the item to that queue
            // position (the dashboard's drag-to-reorder). Order
            // only breaks ties within a priority - pick_job
            // still runs Force/High first - and the active
            // download can't be moved.
            Some("switch") => {
                let pos: usize = params
                    .get("value2")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let mut q = d.queue.lock_ok();
                let from = q.iter().position(|j| j.lock_ok().nzo_id == value);
                match from {
                    Some(i) if q[i].lock_ok().state != JobState::Downloading => {
                        let job = q.remove(i).unwrap();
                        // A manual reorder reasserts the
                        // user's order - the watchdog's
                        // deferral no longer applies, and
                        // neither does §77's health sink. The
                        // health VERDICT stays: it is what the
                        // servers said, and the row goes on
                        // saying it.
                        {
                            let mut g = job.lock_ok();
                            g.deferred = false;
                            if let Some(h) = g.health.as_mut() {
                                h.waived = true;
                            }
                        }
                        let to = pos.min(q.len());
                        // §96 (AltMount audit, item 6): a move to the FRONT
                        // means "run this next" - nzb360 sends value2=0
                        // expecting exactly that. Position alone only breaks
                        // ties within a priority, so a Normal job dragged
                        // above a High one would still run second. Adopt the
                        // highest priority present among the other runnable
                        // jobs, capped at High: Force is never minted by a
                        // reorder, because Force also runs through a queue
                        // pause - a side effect no drag asked for.
                        if to == 0 {
                            let top = q
                                .iter()
                                .map(|o| o.lock_ok())
                                .filter(|g| g.state == JobState::Queued && !g.tombstone)
                                .map(|g| g.priority)
                                .max()
                                .unwrap_or(0)
                                .min(1);
                            let mut g = job.lock_ok();
                            if top > g.priority {
                                g.priority = top;
                            }
                        }
                        q.insert(to, job);
                        drop(q);
                        d.save_queue();
                        json!({"status": true, "position": to})
                    }
                    Some(_) => json!({
                        "status": false,
                        "error": "cannot move the active download"
                    }),
                    None => {
                        json!({"status": false, "error": "unknown nzo_id"})
                    }
                }
            }
            // The two remote-app arms live in remote.rs (§18): rename
            // (which is also how SAB spells set-password, value3) and
            // whole-queue sort. LunaSea sends both.
            // TODO 274 (issue #51): "download this file next", best
            // effort. The arm is one line because the whole transaction
            // is a queue reorder in `files::promote_arm` - keeping it
            // there is also what holds `m_queue` under the §106
            // function ceiling.
            Some("promote_file") => super::files::promote_arm(d, params),
            Some("rename") => super::super::remote::rename_arm(d, params),
            Some("sort") => super::super::remote::sort_arm(d, params),
            Some("change_complete_action") => super::super::remote::complete_action_arm(params),
            Some("priority") => {
                // SAB's priority dropdown has a "Default" entry
                // and sends the -100 sentinel for it, so it has
                // to be resolved here too - storing the sentinel
                // would sort the job below Low while every
                // client labelled it Normal. (-2, "add paused",
                // is only meaningful on an ADD and is left
                // exactly as it was.)
                let prio: i32 = match params
                    .get("value2")
                    .and_then(|v| super::super::sabcompat::parse_priority_token(v))
                    .unwrap_or(0)
                {
                    SAB_DEFAULT_PRIORITY => 0,
                    p => p,
                };
                let mut n = 0;
                let mut finishing = 0;
                {
                    let mut q = d.queue.lock_ok();
                    // Two passes under the one lock: write the
                    // priorities, then move each row to where it will
                    // now run (see `reposition_for_priority`) - the
                    // moves reorder the deque, so they cannot share the
                    // iteration that finds the targets.
                    let mut moved: Vec<String> = Vec::new();
                    for j in q.iter().filter(|j| hit(j)) {
                        let mut g = j.lock_ok();
                        if apply_priority(d, &mut g, prio) {
                            n += 1;
                            moved.push(g.nzo_id.clone());
                        } else {
                            finishing += 1;
                        }
                    }
                    for id in &moved {
                        reposition_for_priority(&mut q, id);
                    }
                }
                if n > 0 {
                    d.save_queue();
                }
                if n == 0 && finishing > 0 {
                    json!({"status": false, "error": "this job is still finishing"})
                } else {
                    json!({"status": n > 0, "position": -1})
                }
            }
            _ => queue_json(d, params),
        }
    })
}

pub(super) fn m_history(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some({
        let value = params.get("value").cloned().unwrap_or_default();
        let find = |id: &str| {
            d.history
                .lock_ok()
                .iter()
                .find(|j| j.lock_ok().nzo_id == id)
                .cloned()
        };
        match params.get("name").map(String::as_str) {
            // Open the finished item on the DAEMON's machine
            // (the normal local setup): value2 "folder" reveals
            // the download dir, "file" opens the largest media
            // file in the OS default player.
            Some("open") => {
                let what = params.get("value2").map(String::as_str).unwrap_or("folder");
                match find(&value) {
                    None => json!({"status": false, "error": "unknown nzo_id"}),
                    Some(job) => {
                        let dir = job.lock_ok().out_dir.clone();
                        let target = if what == "file" {
                            largest_media_file(&dir).unwrap_or_else(|| dir.clone())
                        } else {
                            dir.clone()
                        };
                        json!({"status": os_open(&target), "path": target.to_string_lossy()})
                    }
                }
            }
            // Re-categorize: move the files to the new
            // category's folder and update the record.
            Some("set_cat") => {
                let cat = params.get("value2").cloned().unwrap_or_default();
                let cat = cat.trim().trim_matches('*').trim().to_string();
                // Untrusted: keep it a single contained path
                // component so the rename target can't escape
                // out_root (bug sweep - same class as enqueue).
                let cat = if cat.is_empty() {
                    cat
                } else {
                    nzbkit::disk::sanitize_filename(&cat)
                };
                // One implementation with change_cat's history
                // leg. This used to rename under the download
                // root only - ignoring the completed-move
                // destinations, failing across filesystems
                // (fs::rename cannot cross onto a NAS), and
                // never persisting - so a recategorized job
                // forgot its category on restart.
                history_change_cat(d, &value, &cat)
            }
            Some("delete") => {
                let del_files = params.get("del_files").map(String::as_str) == Some("1");
                // Snapshot the queue's directories BEFORE the
                // history lock: they are claimants too, and
                // taking the two locks in this order everywhere
                // is what keeps them from deadlocking.
                let queue_dirs: Vec<PathBuf> = d
                    .queue
                    .lock_ok()
                    .iter()
                    .map(|j| j.lock_ok().out_dir.clone())
                    .collect();
                let mut h = d.history.lock_ok();
                // A recategorize is moving one of these payloads on
                // disk right now. It snapshotted the record before
                // the move and writes `out_dir` back afterwards, so
                // deleting the record (and its files) underneath
                // leaves the moved data orphaned at a destination
                // nothing names, or half-deleted across both
                // folders. Refuse for the whole request rather than
                // silently skipping one id of a batch. Checked
                // UNDER the history lock: a recategorize raises its
                // marker and then re-verifies the record is still
                // present, so a check outside this lock could pass
                // just before the marker went up while the move
                // still proceeded (Codex H7).
                let busy: Vec<String> = {
                    let m = d.moving.lock_ok();
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|s| m.contains(*s))
                        .map(str::to_string)
                        .collect()
                };
                if !busy.is_empty() {
                    return Some(json!({"status": false,
                            "error": format!(
                                "{} is having its files moved right now - try again when it settles",
                                busy.join(", "))}));
                }
                let before = h.len();
                let records: Vec<DeleteRecord> = h
                    .iter()
                    .map(|j| {
                        let g = j.lock_ok();
                        DeleteRecord {
                            nzo_id: g.nzo_id.clone(),
                            state: g.state,
                            out_dir: g.out_dir.clone(),
                            filed: g.filed,
                            locked: g.password_required,
                        }
                    })
                    .collect();
                // Decided in one pass over the WHOLE list, so
                // the "somebody else still lives here" test sees
                // the records that survive rather than the ones
                // about to go (see plan_history_delete).
                let plan = plan_history_delete(&records, &value, &queue_dirs);
                // A doomed record whose unlock task is `finalizing`
                // is mid-extraction/rename/move on disk right now
                // (Codex sweep 3 Aug H1) - same refusal as `moving`
                // above, but checked against the PLAN rather than
                // the value string, so the `all`/`failed`/
                // `completed` sweeps hit it too (and a bulk sweep
                // catching a mid-move id is refused here as well).
                let busy: Vec<String> = {
                    let m = d.moving.lock_ok();
                    h.iter()
                        .zip(&plan)
                        .filter(|(_, p)| p.doomed)
                        .filter_map(|(j, _)| {
                            let g = j.lock_ok();
                            (g.finalizing || m.contains(&g.nzo_id)).then(|| g.nzo_id.clone())
                        })
                        .collect()
                };
                if !busy.is_empty() {
                    return Some(json!({"status": false,
                            "error": format!(
                                "{} is being unlocked or moved right now - \
                                 try again when it settles",
                                busy.join(", "))}));
                }
                // Recorded after the history lock is dropped, below.
                let mut kept: Vec<(String, std::path::PathBuf, String)> = Vec::new();
                // Spooled NZBs whose fate waits on the removal: kept for
                // the notice's "download it again" when the files stay,
                // removed with the record when they go.
                let mut nzb_by_dir = std::collections::HashMap::new();
                // And so is the removal itself - see the queue-delete
                // arm above for why a bounded Trash call must not run
                // under a global lock, and why the directory is
                // reserved across the gap.
                let mut to_remove: Vec<(
                    String,
                    std::path::PathBuf,
                    bool,
                    crate::smart::FiledTail,
                )> = Vec::new();
                for (j, p) in h.iter().zip(&plan) {
                    if !p.doomed {
                        continue;
                    }
                    let g = j.lock_ok();
                    // The record is being deleted for good - its spooled
                    // .nzb (kept until now for retry) is now dead
                    // weight. Unless the files half is about to be
                    // attempted: a REFUSED removal leaves the user
                    // holding a folder and a notice, and that NZB is the
                    // only thing that can offer them the download again
                    // from where they are standing. Held back and
                    // decided after the outcome is known, below.
                    hold_or_drop_spool(
                        del_files && p.may_remove_files,
                        &g.out_dir,
                        &g.nzb_path,
                        &mut nzb_by_dir,
                    );
                    if del_files {
                        if p.may_remove_files {
                            let tail = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                            d.reserved.lock_ok().insert(g.out_dir.clone());
                            to_remove.push((
                                filed_stem(&g).to_string(),
                                g.out_dir.clone(),
                                g.filed,
                                tail,
                            ));
                            // UX §18: a move-completed (or
                            // recategorize) that failed part way
                            // left half the payload at the SOURCE,
                            // and `out_dir` followed the bytes that
                            // did move. Only `move_split` names the
                            // other half - so a delete-with-files
                            // that removes just `out_dir` takes the
                            // record away and orphans those files,
                            // with no row left to reach them by and
                            // no kept-files note either. Both
                            // locations, or neither promise is kept.
                            //
                            // `g.filed` carries over to the source,
                            // and it MUST: for a TV-filed job the
                            // folder `relocate_completed` moves FROM
                            // is the shared season folder (see its
                            // `same_place` comment), so `move_split`
                            // can name a directory full of the
                            // user's other episodes. Hardcoding
                            // `false` here - "the source is always a
                            // job-owned folder" - would have handed
                            // a whole season to `remove_user_dir` on
                            // a single episode's delete. With the
                            // flag it takes the narrow per-episode
                            // path, exactly as the destination side
                            // above already does.
                            let src = std::path::PathBuf::from(&g.move_split);
                            let claimed = || {
                                queue_dirs.contains(&src)
                                    || records
                                        .iter()
                                        .zip(&plan)
                                        .any(|(o, op)| !op.doomed && o.out_dir == src)
                            };
                            if !g.move_split.is_empty() && src != g.out_dir && !claimed() {
                                d.reserved.lock_ok().insert(src.clone());
                                to_remove.push((
                                    filed_stem(&g).to_string(),
                                    src,
                                    g.filed,
                                    delete_tail(&g, || d.job_suffix(filed_stem(&g))),
                                ));
                            }
                        } else {
                            // A verified re-download published
                            // over this record's directory and
                            // lives there now. Removing the
                            // record is right; removing the
                            // files would destroy the newer job.
                            info!(
                                target: "history",
                                "{}: record removed, files kept - {} \
                                         belongs to another job now",
                                g.nzo_id,
                                g.out_dir.display()
                            );
                        }
                    }
                }
                // What the user just told us they no longer have. Taken
                // from the plan rather than from `value`, so the bulk
                // words (`all`, `failed`, `completed`) and an id list
                // stamp exactly the records that are leaving - see
                // `Daemon::note_releases_deleted`.
                let deleted_names: Vec<String> = h
                    .iter()
                    .zip(&plan)
                    .filter(|(_, p)| p.doomed)
                    .map(|(j, _)| j.lock_ok().name.clone())
                    .collect();
                // By id, not by position: nzo_ids are unique,
                // and a positional retain would be one refactor
                // away from deleting the wrong record.
                let doomed: std::collections::HashSet<&str> = records
                    .iter()
                    .zip(&plan)
                    .filter(|(_, p)| p.doomed)
                    .map(|(r, _)| r.nzo_id.as_str())
                    .collect();
                h.retain(|j| !doomed.contains(j.lock_ok().nzo_id.as_str()));
                // §129 1a: the store forgets them too, once the lock is
                // down (below, beside save_queue).
                let doomed_ids: Vec<String> = doomed.iter().map(|s| s.to_string()).collect();
                // A bulk sweep needs to say how much it swept:
                // "Cleared." over a list that still has rows in
                // it is indistinguishable from a no-op. `status`
                // keeps its old meaning for every existing
                // caller (SAB clients included).
                let count = before - h.len();
                drop(h);
                // Now that no global lock is held: the slow half.
                // Released after the whole batch - see the queue arm
                // above. It matters more here: `plan_history_delete`
                // counts only SURVIVORS as a claimant, so two doomed
                // records sharing one out_dir both earn
                // `may_remove_files`, and a set holds that directory
                // once.
                let reserved_dirs: Vec<std::path::PathBuf> =
                    to_remove.iter().map(|(_, dir, _, _)| dir.clone()).collect();
                for (name, dir, filed, tail) in to_remove {
                    let outcome = remove_job_files(&dir, &name, filed, &tail);
                    if let FilesGone::Kept(why) = outcome {
                        kept.push((name, dir, why));
                    }
                }
                {
                    let mut r = d.reserved.lock_ok();
                    for dir in &reserved_dirs {
                        r.remove(dir);
                    }
                }
                // "Delete + files" is two promises, and only the
                // record half is guaranteed. A row the user deleted
                // to reclaim the disk space, whose files are still
                // taking it up, is the case this exists for: the row
                // was their handle on that folder and it has just
                // gone, so the path has to be handed back.
                note_kept_files(d, kept, &mut nzb_by_dir);
                if count > 0 {
                    d.note_releases_deleted(&deleted_names);
                    d.history_tombstone(&doomed_ids);
                    d.save_queue();
                }
                // A class sweep (all/completed/failed) is idempotent:
                // asking for a state the history is already in is
                // success, and LunaSea's clear-history dialog reads
                // false as an error toast (§18). A per-id delete keeps
                // reporting the miss - an unknown id is diagnosable.
                let class_sweep = matches!(value.as_str(), "all" | "completed" | "failed");
                json!({"status": count > 0 || class_sweep, "removed": count})
            }
            _ => history_json(d, params),
        }
    })
}
