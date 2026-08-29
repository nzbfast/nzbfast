//! Watchlist: the pass that decides what a watched show or film still
//! wants, and the two ways of getting it (the local index, and the
//! configured external indexers).
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// M23d: keep TVmaze episode lists (with airdates) cached for watched
/// shows - the "coming up" calendar's data. One kv blob per show
/// (`eplist:<norm title>`), refreshed every 12 h; "show not found" is
/// cached too so unknown titles aren't re-queried every minute. Runs on
/// the watcher's blocking thread, so the network calls are fine here.
#[cfg(feature = "indexer")]
pub(super) fn watch_calendar_refresh(d: &Arc<Daemon>) {
    // §151: a synced show needs its airdates cached like any other,
    // or "coming up" would be blank for everything Plex added.
    let items = d.watch_items();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    for item in items.iter().filter(|i| i.enabled && i.kind == "tv") {
        let key = format!("eplist:{}", crate::wall::norm_title(&item.title));
        let fresh = d
            .with_index(|ix| ix.kv_get(&key))
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v["fetched"].as_i64())
            .is_some_and(|t| now - t < 12 * 3600);
        if fresh {
            continue;
        }
        let show_id = crate::wall::tvmaze_lookup(&item.title).map(|m| m.tmdb_id);
        let eps = show_id
            .map(crate::wall::tvmaze_episodes)
            .unwrap_or_default();
        info!(
            target: "watch",
            "episode list for {}: {} episodes{}",
            item.title,
            eps.len(),
            if show_id.is_none() {
                " (show not found on TVmaze)"
            } else {
                ""
            }
        );
        let blob = json!({"fetched": now, "show_id": show_id, "episodes": eps}).to_string();
        d.with_index(|ix| ix.kv_set(&key, &blob).ok());
    }
}

/// Where a watchlist candidate came from: our own index, or one of the
/// user's third-party indexer accounts (M35 phase 2). Everything
/// between finding it and deciding on it is identical - only the fetch
/// differs, and only an external one costs a metered grab.
pub(super) enum CandSrc {
    #[cfg(feature = "indexer")]
    Local(i64),
    External {
        url: String,
        indexer: String,
        /// `indexer`'s configured URL and the addresses it answered the
        /// search from. `url` is an `<enclosure url>` that indexer's
        /// search response chose, so the grab binds the fetch to this
        /// origin (M12/M9).
        origin: SourceOrigin,
    },
}

/// Default cadence for the watchlist's external leg: how long an item
/// waits between spending one search on the user's indexer accounts.
///
/// The watcher itself runs every 60 s, and a third-party account is
/// metered per DAY (a free tier can be 100 searches), so the watcher's
/// own tempo is not a safe tempo to query at. Twice a day per item
/// keeps a 20-item watchlist at ~40 searches/day even before budgets.
pub(super) const WATCH_EXT_INTERVAL_SECS: i64 = 12 * 60 * 60;

/// §74: default ceiling on instant watchlist passes per hour.
///
/// Sized against what a watchlist actually wants, not against what a
/// group can post: a busy evening on a watched show is a handful of
/// arrivals, and six of them an hour is already generous. Everything
/// over the line waits for the periodic pass a minute later, so the only
/// thing a low ceiling costs is the seconds.
pub(super) const INSTANT_MAX_DEFAULT: u32 = 6;

/// Free space the queue keeps in hand by default: new jobs wait below
/// it, and the header says which floor is holding them.
///
/// It used to be 0, which is to say there was no protection at all
/// unless the operator went looking for the setting. That is how a
/// tester's disk reached 1.8 GB free (3 Aug): the download itself fits,
/// so nothing objects, and the machine is the thing that suffers - a
/// full disk tears settings writes, starves the OS, and fails the
/// unpack that was going to need the room anyway.
///
/// 2 GB, not more: this is a floor against a disk hitting ZERO, not a
/// per-job forecast (the queue row does that, and it counts the
/// extraction). High enough that macOS and Windows keep working, low
/// enough that a NAS deliberately run near full is not held hostage -
/// and it is one field away from 0, which now MEANS off and survives a
/// restart.
pub(super) const MIN_FREE_DEFAULT: u64 = 2_000_000_000;

/// §74: how long a matched-but-incomplete arrival keeps its short
/// re-check before it is handed back to the periodic pass. A post still
/// going up is the normal case at +6 s; one that has not finished ten
/// minutes later is either enormous or in trouble, and either way the
/// periodic pass is the right owner. NEVER read as "the post is dead" -
/// missing articles are not evidence of that.
#[cfg(feature = "indexer")]
pub(super) const INSTANT_PENDING_SECS: i64 = 10 * 60;

/// §74: cadence of that re-check.
#[cfg(feature = "indexer")]
pub(super) const INSTANT_RECHECK_SECS: u64 = 30;

/// Test seam: settlement trips it once it holds the superseded
/// record's custody - the mover claim taken, the sidecar snapshotted -
/// and before it removes any record or any file. First barrier says the
/// window is open, second says the test has run whatever it wanted to
/// race in there and releases it. Same two-stage shape as
/// `sabcompat::DELETE_PREWRITE_BARRIER` and `daemon_park::PARK_GEN_BARRIER`,
/// and keyed the same way - by the owning daemon's spool path - so a
/// watchlist pass belonging to some other test can never wander into a
/// two-party barrier that is not its own. Unkeyed, a stranger is a third
/// waiter and the parallel bin run hangs instead of failing.
#[cfg(test)]
pub(in crate::serve) static SETTLE_CUSTODY_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// The mover's fence, held for the length of one settlement rather than
/// read once at the top of it.
///
/// `d.moving` names the records whose payload is being moved on disk
/// right now, and settlement used to CONSULT it: read it, find the id
/// absent, and go on to remove the files. That is a check-then-act, and
/// `mover_process` fills the gap - it inserts into the same set and runs
/// `relocate_completed` with no lock held, deliberately, because a move
/// on a NAS is seconds and the queue must not stall behind it. Landing
/// in the window deleted the source out from under a move that had just
/// started: a half-published payload with no record naming either side
/// (Codex sweep 24 Aug, F-05).
///
/// `history_change_cat` had already settled the shape - TAKE the fence,
/// then re-verify the snapshot the claim was decided on - and this is
/// that, one caller over. A mover that arrives while it is held gets
/// `false` from its own insert and requeues itself a moment later, which
/// is the behaviour it was written for; a mover already in flight is
/// what makes the insert here fail, and settlement defers exactly as it
/// did before.
struct MoveClaim(Arc<Daemon>, String);

impl Drop for MoveClaim {
    fn drop(&mut self) {
        self.0.moving.lock_ok().remove(&self.1);
    }
}

/// Is the superseded history record's `out_dir` still its own to remove?
///
/// TODO 290 F-05a. Asked through `plan_history_delete` - the SAME plan
/// the REST history delete decides on - rather than a second claimant
/// test grown beside it. This is an ADAPTER, not a rule: it snapshots
/// the two stores into the shape that function reads and hands back the
/// one record's answer.
///
/// The rule itself is A6's, and settlement had never consulted it.
/// `publish_over_previous` hands the CANONICAL directory to a verified
/// re-download and leaves the superseded record pointing at that same
/// path, so TWO history records name it and only one of them put the
/// bytes there. Removing that directory on the older record's behalf
/// destroys the newer job's payload - the record deleted is not the data
/// destroyed. A live queue job's directory counts the same way; the
/// leftover record can always be deleted again, the payload cannot.
///
/// The claimant test runs against SURVIVORS, which is why the record
/// being settled has to still be in history when this is called: it is
/// `plan_history_delete`'s `value`, so it is the one record marked
/// doomed and it cannot claim its own directory.
///
/// TV-filed records are exempt inside that plan, and stay exempt here:
/// their `out_dir` IS the shared season folder, every episode of the
/// season claims it, and `remove_job_files` takes the narrow
/// per-episode path there. That exemption is why this defect has never
/// shown up on the TV path.
///
/// Not folded into [`Daemon::remove_files_in_custody`], which is the
/// custody transaction both halves of settlement take: the claimant test
/// needs the whole DOOMED set to know which records survive, and that
/// function is handed one directory at a time. A batch caller taking it
/// per record would see its own siblings as claimants and refuse
/// everything.
fn settle_may_remove_files(d: &Arc<Daemon>, nzo_id: &str) -> bool {
    // Queue before history, the order the REST delete arm takes them in
    // and the reason it says so: taking the two in one order everywhere
    // is what keeps them from deadlocking.
    let queue_dirs: Vec<PathBuf> = d
        .queue
        .lock_ok()
        .iter()
        .map(|j| j.lock_ok().out_dir.clone())
        .collect();
    let records: Vec<DeleteRecord> = d
        .history
        .lock_ok()
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
    plan_history_delete(&records, nzo_id, &queue_dirs)
        .iter()
        .zip(&records)
        .find(|(_, r)| r.nzo_id == nzo_id)
        .is_some_and(|(plan, _)| plan.may_remove_files)
}

/// The history half of a settled `delete_old` upgrade: take the
/// superseded record out of history, make that removal DURABLE, and
/// only then destroy its spool copy and its payload.
///
/// ONE ORDERED TRANSACTION, and it ran the other way round until the
/// v1.2.4 tranche sweep (F3, 28 Aug 2026): the payload was deleted
/// first, the row was dropped from live memory next, and the tombstone
/// came LAST with its answer only logged. A store that refused that
/// append therefore left the record ABSENT from memory and PRESENT in
/// the durable store with its payload already gone - so the next start
/// replayed a row pointing at content that no longer existed, while the
/// run that did it had already saved its state and emitted a
/// `watchlist.upgraded` success. `history_tombstone`'s own contract says
/// `false` means the row replays after a restart, and `history_restore`
/// exists for exactly this gap; this branch never called it.
///
/// The order below is the one the QUEUED half above already takes (the
/// 27 Aug C09 fix, which makes the queue save durable before it removes
/// anything) and the one `api/queue/payload.rs`'s history delete takes:
/// decide, remove, persist, and destroy nothing until the removal is
/// durable. Reintroducing the defect looks like moving any of
/// `drop_spool`, `remove_files_in_custody` or the event above the
/// tombstone.
///
/// Returns the pending entry when the settlement must be tried again on
/// a later pass, having changed nothing.
fn settle_superseded_record(
    d: &Arc<Daemon>,
    p: crate::watchlist::PendingDelete,
    job: &Arc<Mutex<Job>>,
    sidecar: Option<&(String, Arc<AtomicBool>)>,
) -> Option<crate::watchlist::PendingDelete> {
    let (dir, nzb, name, filed, tail) = {
        let g = job.lock_ok();
        // The tail is the SUPERSEDED release's own, as FILED, so a filed
        // delete cannot reach the upgrade that has just landed in the
        // same season folder under the same episode base. Same rule the
        // queue half applies to its own row.
        let t = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
        (
            g.out_dir.clone(),
            g.nzb_path.clone(),
            filed_stem(&g).to_string(),
            g.filed,
            t,
        )
    };
    // WHOSE DIRECTORY IS IT (TODO 290 F-05a), asked before any of the
    // transaction below. Settlement removed it unconditionally, and a
    // superseded record's `out_dir` is not necessarily its own: an A6
    // publish leaves it pointing at the canonical path a verified
    // re-download now lives in. Read while the record is STILL IN
    // HISTORY, which is what makes it the doomed one and everything else
    // a survivor - so only the ANSWER is bound here, and the removal it
    // authorises happens at the far end, after the tombstone.
    let may_remove = settle_may_remove_files(d, &p.old_nzo);
    if !may_remove {
        // LOGGED, not noticed, which is the REST arm's choice on this
        // branch and is deliberate: the kept-files strip hands the user
        // a folder and invites them to clear it, and this folder is a
        // live record's payload. The row that owns it is in History and
        // can be deleted there with its files, the ordinary way.
        //
        // The record still goes. It names a directory that is not its
        // payload any more, so leaving it strands a row whose
        // delete-with-files the plan would refuse for the same reason,
        // forever.
        info!(
            target: "watch",
            "upgrade landed - dropped the record for {}, \
             files kept: {} belongs to another job now",
            p.prev_stem,
            dir.display()
        );
    }
    // The sidecar question is asked HERE, ahead of the transaction, and
    // it used to be read off `remove_files_in_custody`'s `None`. A
    // history record is not the prefetch sidecar's to hold - it runs
    // QUEUED jobs, and the queue half above has already consumed any row
    // under this id - but if that ever stops being true the drain owns
    // the removal and this pass has removed nothing, so the record
    // settles on a later pass rather than reporting a fate its files have
    // not reached yet. That re-park cannot live where it was any more:
    // below this point the row is gone and tombstoned, and re-parking
    // there would leave a pending delete for a record that no longer
    // exists.
    if may_remove && sidecar.is_some_and(|(id, _)| *id == p.old_nzo) {
        info!(
            target: "watch",
            "upgrade landed, but the prefetch sidecar is still holding {} \
             - deleting it once it settles",
            p.prev_stem
        );
        return Some(p);
    }
    // Reserved BEFORE the row leaves memory, not first inside
    // `remove_files_in_custody`: from the retain below until that call
    // takes over, the directory is named by no queue row, no history
    // row and (without this) no reservation - and the tombstone in
    // between is real IO (an append, or the full history rescue-rewrite
    // on a refused append), so `dir_claim` would answer Free long
    // enough for a re-add of the same release to be handed the doomed
    // directory the destructive half then deletes. `reserved` is a set,
    // so the insert inside `remove_files_in_custody` becomes a no-op
    // and its own remove still releases; the arms that return without
    // reaching it give the reservation back below.
    if may_remove {
        d.reserved.lock_ok().insert(dir.clone());
    }
    // Where the row SAT, so a store that refuses the tombstone can have
    // it back exactly as this pass found it. A bare `retain` cannot be
    // undone, which is why this is spelled the way
    // `api/queue/payload.rs`'s history delete spells it. Out of memory
    // BEFORE the store is asked to forget it, deliberately: an
    // `history_upsert_if_present` landing in the gap finds the record
    // absent and writes nothing, where the other order would let it
    // write back the row the tombstone had just buried (the H6 shape).
    let removed: Vec<(usize, Arc<Mutex<Job>>)> = {
        let mut h = d.history.lock_ok();
        let mut at = 0usize;
        let mut out = Vec::new();
        h.retain(|j| {
            let keep = j.lock_ok().nzo_id != p.old_nzo;
            if keep {
                at += 1;
            } else {
                out.push((at, j.clone()));
            }
            keep
        });
        out
    };
    if !d.history_tombstone(std::slice::from_ref(&p.old_nzo)) {
        // TERMINAL for this item, and nothing has been destroyed: the
        // row goes back where it was, the pending entry goes back so a
        // later pass retries the whole settlement, and NO success event
        // is emitted for a delete that did not happen. The reservation
        // goes back too - the restored row speaks for the directory
        // again, and nothing below will release it on this arm.
        if may_remove {
            d.reserved.lock_ok().remove(&dir);
        }
        d.history_restore(removed);
        error!(
            target: "watch",
            "{}: the upgraded record could not be removed from the history \
             store, so it was left exactly as it was - its files and its \
             spool copy were kept, and the delete will be retried",
            p.old_nzo
        );
        return Some(p);
    }
    // Durable from here, so the destructive half can run. The spool copy
    // goes first and only now (P2-1): a store that refused the tombstone
    // would otherwise have brought the superseded record back at the next
    // start with the `.nzb` its retry needs already unlinked. A refused
    // unlink must not leave the copy adoptable either - which is
    // `drop_spool`'s own job.
    drop_spool(&nzb);
    let outcome = if may_remove {
        // Same custody transaction as the queue half: the directory is
        // reserved for the length of the removal, so `dir_claim` cannot
        // hand it to a new job in the window between the row going and
        // the files - a window a Trash call wide.
        match d.remove_files_in_custody(sidecar, &p.old_nzo, name.clone(), dir.clone(), filed, tail)
        {
            Some(outcome) => {
                // A REFUSED removal is terminal too, and in the other
                // direction: the row is durably gone, so resurrecting it
                // to retry a destructive step is how one delete becomes
                // two. The user is told through the kept-files notice
                // and the event's `fate` instead.
                if let FilesGone::Kept(why) = &outcome {
                    d.note_delete_kept(&name, &dir, why, None);
                }
                outcome
            }
            // Unreachable while the sidecar arm above stands, and kept
            // honest rather than unwrapped: the drain owns the removal
            // and owes the reservation back, so the files are still
            // there AT THIS INSTANT. Reported as kept, which is the only
            // checked claim available, and WITHOUT a kept-files notice -
            // that strip would invite the user to clear a folder the
            // drain is about to take.
            None => FilesGone::Kept("the prefetch drain is removing them".to_string()),
        }
    } else {
        FilesGone::Kept("the folder belongs to another job now".to_string())
    };
    d.save_queue();
    // Asked of the REMOVAL, not of the settings. This read the two
    // globals and inferred a fate from them, which is a promise the
    // globals cannot make: on 4 Aug a 14 GB download was reported "went
    // to the Trash" - the setting was on, nothing had latched
    // unresponsive - while it had been destroyed outright, because the
    // backend returned Ok on a volume whose Trash is not usable.
    // `Removed::Trashed` is now only reported when the file was FOUND in
    // a Trash afterwards, so "trash" here is a checked claim. A refused
    // delete is the third state: the files are still there, so neither
    // "went to the Trash" nor "was deleted" is true of them.
    let fate = match &outcome {
        FilesGone::Kept(_) => "kept",
        FilesGone::Yes(crate::smart::Removed::Trashed) => "trash",
        FilesGone::Yes(crate::smart::Removed::Gone) => "gone",
    };
    info!(
        target: "watch",
        "upgrade landed - superseded {} ({}) - {}",
        p.prev_stem,
        p.old_nzo,
        match fate {
            "trash" => "its files went to the Trash",
            "kept" => "its record went, its files are still on disk",
            _ => "its files were deleted",
        }
    );
    // Narrate it where the user looks: a completed download and its
    // history row just disappeared, and two log lines were the only
    // witnesses.
    //
    // §129 1b(b): on the sequence-cursored lifecycle ring. It used to be
    // a bounded `watch_upgraded` array on the queue payload that the
    // dashboard diffed against a seen-set of its own - and this one was
    // the LATE case, like the give-up trip: the deletes here leave the
    // queue untouched, so on a daemon with nothing downloading the
    // payload carrying the notice was not re-sent until some unrelated
    // mutation moved the queue revision.
    //
    // EMITTED ONLY ON THE DURABLE PATH, which is the F3 half of the
    // ordering above: every early return before the tombstone leaves
    // this unsaid, because a record that is still in history has not
    // been upgraded away from yet.
    //
    // The keys are the page's, unchanged: `old`/`oldq` are the
    // superseded release and its quality, and `fate` is the checked
    // claim about its files - "trash", "gone" or "kept" - so the
    // sentence can never promise a Trash the delete did not use.
    d.life_emit(
        "watchlist.upgraded",
        json!({
            "name": p.new_stem,
            "old": p.prev_stem,
            "oldq": p.prev_quality,
            "fate": fate,
        }),
    );
    None
}

/// Step 1 of a watchlist pass: settle the upgrade-deletes left pending
/// by an earlier pass. The replacement download's fate decides -
/// Completed means the superseded version goes, Failed or user-deleted
/// means we fall back to the version we already have. Returns whether
/// the state was changed and needs persisting.
fn settle_pending_upgrades(d: &Arc<Daemon>, state: &mut crate::watchlist::WatchState) -> bool {
    let mut dirty = false;
    let pending = std::mem::take(&mut state.pending);
    for p in pending {
        let in_queue = d
            .queue
            .lock_ok()
            .iter()
            .any(|j| j.lock_ok().nzo_id == p.new_nzo);
        if in_queue {
            state.pending.push(p);
            continue;
        }
        // A record mid-move between the two stores is in NEITHER, and
        // that window holds real work for exactly this job class -
        // `park` drops the queue row, then runs `giveup_note_outcome`
        // (which for a watchlist Completed job records the success and
        // can synchronously write the give-up file) before pushing to
        // history. This pass takes neither lock, so landing in there
        // read "not queued, not in history" and fell into the `None`
        // arm below - the user-deleted verdict - reverting the slot and
        // blacklisting the replacement stem for a job that had just
        // COMPLETED. `hist_inflight` is registered by park, retry and
        // activate_parked and deregistered by their guards on every
        // exit, so it names precisely the neither-store windows; a
        // genuinely deleted job has no guard and still takes `None`.
        if d.hist_inflight.lock_ok().contains(&p.new_nzo) {
            state.pending.push(p);
            continue;
        }
        let hist = d
            .history
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == p.new_nzo)
            .cloned();
        match hist.map(|j| j.lock_ok().state) {
            Some(JobState::Completed) => {
                // The superseded copy is usually a COMPLETED history
                // entry, but can still be sitting in the queue (paused,
                // or the upgrade overtook it). Never touch one that's
                // actively downloading.
                // Mid-download is not "gone" - it is "not yet". Excluding
                // it here found nothing in history either (the job is
                // still in the queue), and the pending entry was taken at
                // the top of this loop and never pushed back, so the
                // delete_old the user asked for was dropped on the floor:
                // the superseded copy finished later and its files sat on
                // disk forever with nothing reporting it. Keep the entry
                // and settle it on a later pass instead.
                //
                // THE MOVER'S FENCE FIRST, and taken rather than read -
                // `MoveClaim` carries the argument. Nothing below may
                // touch the superseded record's files while a move is in
                // flight over them, and reading `d.moving` once at the
                // top of the history half left `mover_process` a window
                // to start one in.
                if !d.moving.lock_ok().insert(p.old_nzo.clone()) {
                    info!(
                        target: "watch",
                        "upgrade landed, but the superseded {} is being moved - \
                         deleting it once it settles",
                        p.prev_stem
                    );
                    state.pending.push(p);
                    continue;
                }
                let _move_claim = MoveClaim(d.clone(), p.old_nzo.clone());
                // A prefetching predecessor reads Queued and not
                // finalizing, so the busy test below cannot see its live
                // writers: the sidecar holds the job Arc directly, and
                // its ownership check is (retries, move_seq, out_dir,
                // !tombstone) - none of which this delete changes.
                // Removing the row and its directory under it let the
                // sidecar recreate files inside the deleted tree, mark
                // the removed job Completed and park it back into
                // history after the tombstone (Codex sweep 24 Aug,
                // F-05).
                //
                // Poked and then handed to the DRAIN, which is what the
                // two delete arms do with the same shape: the row leaves
                // the queue here under a tombstone, its directory stays
                // reserved, and `remove_after_sidecar_drain` removes it
                // the moment the last writer lets go. It used to be
                // deferred to the next pass instead, which is a minute
                // of a reservation nobody holds - and the deferral only
                // ever moved the removal, so the directory sat unclaimed
                // and unreserved in between.
                //
                // Snapshotted BEFORE the queue lock: the sidecar mutex
                // under queue+job would be a lock edge nothing else in
                // the daemon has.
                let sidecar = d.sidecar_owner();
                let sidecar_old = sidecar.as_ref().is_some_and(|(id, _)| *id == p.old_nzo);
                // `finalizing` is live for the same reason Downloading
                // is, and it is NOT covered by it: a Completed job whose
                // post-processing (unlock, rename, TV filing, NAS move)
                // is still running has already left Downloading, so this
                // took the delete path below and removed the files out
                // from under the mover - half-deleting a tree it was
                // reading, or deleting the emptied source while the
                // payload sat at the destination with no record left to
                // delete it by. The queue-delete path has had this
                // deferral since the 3 Aug sweep; watch settlement
                // walked straight past it. Settle on a later pass, the
                // way a still-downloading predecessor already does.
                let old_busy = d.queue.lock_ok().iter().any(|j| {
                    let g = j.lock_ok();
                    g.nzo_id == p.old_nzo
                        && (matches!(g.state, JobState::Downloading | JobState::Finishing)
                            || g.finalizing)
                });
                if old_busy {
                    info!(
                        target: "watch",
                        "upgrade landed, but the superseded {} is still \
                         downloading or being unpacked - deleting it once it settles",
                        p.prev_stem
                    );
                    state.pending.push(p);
                    continue;
                }
                if sidecar_old {
                    d.poke_sidecar(|id| id == p.old_nzo);
                }
                // §129, as both delete arms do it: a Finishing job's
                // repair must stop pulling recovery volumes, and the
                // hub abort cannot reach it - that one is scoped to the
                // hub's owner and a job in the lane is not that.
                d.cancel_tail_fetches(|id| id == p.old_nzo);
                #[cfg(test)]
                {
                    let spool = d.spool.display().to_string();
                    let seam = SETTLE_CUSTODY_BARRIER
                        .lock_ok()
                        .clone()
                        .filter(|(k, _, _)| *k == spool);
                    if let Some((_, open, release)) = seam {
                        open.wait();
                        release.wait();
                    }
                }
                let queued_old = {
                    let mut q = d.queue.lock_ok();
                    let pos = q.iter().position(|j| {
                        let g = j.lock_ok();
                        g.nzo_id == p.old_nzo
                            && !matches!(g.state, JobState::Downloading | JobState::Finishing)
                            && !g.finalizing
                    });
                    pos.and_then(|i| q.remove(i))
                };
                if let Some(job) = queued_old {
                    // Tombstoned even though it is leaving the queue
                    // right here: the sidecar handoff above closes the
                    // steady state, and this closes the race window
                    // between its snapshot and the remove - an Ok that
                    // lands after this refuses to run the completion
                    // tail (`sidecar_result_is_ours` tests it), same as
                    // the SAB delete arms.
                    job.lock_ok().tombstone = true;
                    let (dir, nzb, name, filed, tail) = {
                        let g = job.lock_ok();
                        // The tail is the SUPERSEDED release's own, as
                        // FILED, so a filed delete cannot reach the upgrade
                        // that has just landed in the same season folder
                        // under the same episode base.
                        let t = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                        (
                            g.out_dir.clone(),
                            g.nzb_path.clone(),
                            filed_stem(&g).to_string(),
                            g.filed,
                            t,
                        )
                    };
                    // The removal is made DURABLE before anything is
                    // destroyed, same order the history half below
                    // enforces: a queue store that refuses the save
                    // brings the superseded row back at the next start,
                    // and destroying custody first would hand that row
                    // back with its files and spool copy already gone -
                    // a resume with nothing to resume from.
                    if d.save_queue() {
                        // Through the delete arms' own custody
                        // transaction rather than a bare remove beside
                        // it: the directory is reserved for the length
                        // of the removal, so `dir_claim` cannot hand it
                        // to a new job in the window between the row
                        // going and the files - a window a Trash call
                        // wide.
                        if let Some(FilesGone::Kept(why)) = d.remove_files_in_custody(
                            sidecar.as_ref(),
                            &p.old_nzo,
                            name.clone(),
                            dir.clone(),
                            filed,
                            tail,
                        ) {
                            d.note_delete_kept(&name, &dir, &why, None);
                        }
                        // Through `drop_spool` rather than a swallowed
                        // `remove_file` (Codex sweep 24 Aug, F-04): the
                        // row is gone for good, so a spool copy whose
                        // unlink is refused would be re-adopted at the
                        // next start and the superseded release
                        // downloads again.
                        drop_spool(&nzb);
                        info!(
                            target: "watch",
                            "upgrade landed - dropped queued {} ({})",
                            p.prev_stem, p.old_nzo
                        );
                    } else {
                        error!(
                            target: "watch",
                            "{}: the superseded queue row could not be saved out \
                             of the queue store, so it comes back at the next \
                             start - its files and spool copy were kept rather \
                             than removed under it",
                            p.old_nzo
                        );
                    }
                }
                let old = d
                    .history
                    .lock_ok()
                    .iter()
                    .find(|j| j.lock_ok().nzo_id == p.old_nzo)
                    .cloned();
                // A history row can be busy too: a password unlock marks
                // the record `finalizing` while it extracts, renames and
                // moves on disk. Same deferral as the queue side above.
                // The mover's own fence is the claim taken at the top of
                // this arm - it is NOT covered by `finalizing`: a
                // completed predecessor whose NAS move is mid-copy is in
                // that set and nothing else, and deleting through it
                // removed the source out from under `relocate_completed`
                // - a half-published move with the record gone too
                // (Codex sweep 24 Aug, F-05). The SAB and JSON-RPC
                // history deletes have refused this shape since the
                // 3 Aug sweep; parity here. Read AFTER the claim went
                // up, which is the re-verify `history_change_cat` makes
                // for the same reason: the value it decides on has to be
                // one nothing can move under it.
                if old.as_ref().is_some_and(|j| j.lock_ok().finalizing) {
                    info!(
                        target: "watch",
                        "upgrade landed, but the superseded {} is being unlocked \
                         - deleting it once it settles",
                        p.prev_stem
                    );
                    state.pending.push(p);
                    continue;
                }
                if let Some(job) = old {
                    // The whole of the record half is ONE ORDERED
                    // TRANSACTION, and it lives in its own function
                    // because the order is the point - see
                    // `settle_superseded_record`. A `Some` back means it
                    // changed nothing and wants a later pass.
                    if let Some(back) = settle_superseded_record(d, p, &job, sidecar.as_ref()) {
                        state.pending.push(back);
                        continue;
                    }
                }
                dirty = true;
            }
            Some(JobState::Failed) | None => {
                // (None = the user deleted the replacement mid-flight.)
                //
                // Revert EVERY slot the upgrade claimed, not only the
                // primary. The Upgrade arm wrote the new job into each
                // slot a multi-episode release covers, while
                // `PendingDelete` carries prev_* for one slot - so after
                // a failed double-episode upgrade the extra slots still
                // named the failed job, and step 1b below then EMPTIED
                // them, even though the superseded release's files still
                // cover that episode. A later standalone candidate scored
                // as a fresh grab and re-downloaded an episode the user
                // already had on disk; the history-adopt net cannot catch
                // it, because the old job's dupe_key names the FIRST
                // episode only.
                let claimed: Vec<String> = state
                    .slots
                    .iter()
                    .filter(|(k, s)| **k == p.slot || s.nzo_id == p.new_nzo)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in &claimed {
                    if let Some(slot) = state.slots.get_mut(k) {
                        slot.rank = p.prev_rank;
                        slot.stem = p.prev_stem.clone();
                        slot.quality = p.prev_quality.clone();
                        slot.nzo_id = p.old_nzo.clone();
                        if !slot.failed.contains(&p.new_stem) {
                            slot.failed.push(p.new_stem.clone());
                        }
                    }
                }
                info!(
                    target: "watch",
                    "upgrade lost - keeping {} across {} slot(s)",
                    p.prev_stem,
                    claimed.len()
                );
                dirty = true;
            }
            Some(_) => state.pending.push(p),
        }
    }
    dirty
}

/// Step 1b of a watchlist pass: reconcile slots against the download's
/// REAL outcome. Slots were recorded at enqueue time and never revisited
/// (the only revert path was the pending-upgrade machinery, gated on
/// delete_old), so a dead post permanently read "have it" - the episode
/// was never re-grabbed while the calendar showed ✓. A Failed grab records
/// its stem in the never-retry list and empties the slot; a user-deleted
/// one just empties it (a deliberate delete is not a dead post).
fn reconcile_slots(d: &Arc<Daemon>, state: &mut crate::watchlist::WatchState) -> bool {
    let mut dirty = false;
    let keys: Vec<String> = state.slots.keys().cloned().collect();
    for key in keys {
        if state.pending.iter().any(|p| p.slot == key) {
            continue; // settle_pending_upgrades owns this slot
        }
        let nzo = state.slots[&key].nzo_id.clone();
        if nzo.is_empty() {
            continue; // already emptied - waiting for a new candidate
        }
        let in_queue = d.queue.lock_ok().iter().any(|j| j.lock_ok().nzo_id == nzo);
        if in_queue {
            continue;
        }
        let hstate = d
            .history
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == nzo)
            .map(|j| j.lock_ok().state);
        let s = state.slots.get_mut(&key).unwrap();
        match hstate {
            Some(JobState::Failed) => {
                // A genuinely failed grab: remember the dead stem so we
                // don't re-pick it, and free the slot for another
                // release.
                let stem = s.stem.clone();
                if !s.failed.contains(&stem) {
                    s.failed.push(stem);
                }
                info!(
                    target: "watch",
                    "grab of {} failed - slot freed for another release",
                    s.stem
                );
                s.nzo_id.clear();
                s.stem.clear();
                s.quality.clear();
                s.rank = 0;
                dirty = true;
            }
            // Vanished from BOTH queue and history with no Failed record.
            // This fires when the user clears/prunes history (or Sonarr-
            // style auto-pruning does), NOT just a mid-flight delete -
            // and the two are indistinguishable here. Emptying the slot
            // made step 2 re-Grab it, re-downloading every long-completed
            // watchlist episode whose history row was pruned. Treat a
            // vanished job as "still had": leave the slot intact so a
            // pruned history never triggers a mass re-download. (A user
            // who truly wants it again can re-add the item.)
            None => continue,
            _ => continue, // Completed (or still post-processing)
        }
    }
    dirty
}

/// One M23 watcher pass: settle pending upgrade-deletes, then match
/// every enabled watch item against the index and grab / upgrade.
pub(super) fn watchlist_pass(d: &Arc<Daemon>) {
    use crate::watchlist as wl;
    // §151: the user's own list PLUS what the external sources synced.
    // This is the one path that grabs anything, so it is the one that
    // makes a synced entry an ordinary watched item.
    let items = d.watch_items();
    // §74: the arrivals that woke this pass, if it was woken by one.
    // Taken, not read: a name only earns the "grabbed as it arrived"
    // record once, and a later periodic pass grabbing the same release
    // (because the instant one declined it, or was rate-limited) is not
    // an instant grab and must not claim to be.
    let arrived: Vec<String> = std::mem::take(&mut *d.instant_hint.lock_ok());
    // 24D: every stem the watcher looks at goes through the SAME
    // classify pass as ingest, so a custom-category item sees the kind
    // and identity key the index stored - and a built-in item never
    // grabs a release a category has claimed.
    let cats = d.custom_categories.read_ok().clone();
    let classify = |stem: &str| nzbkit::categories::classify(stem, &cats);
    // The watcher owns this state: it's only ever mutated here, so
    // working on a clone and writing back at the end is race-free.
    let mut state = d.watch_state.lock_ok().clone();
    // Bundle D: the skip reasons describe THIS pass, so the previous
    // pass's are cleared rather than accumulated - an item that is no
    // longer being declined must stop saying it is.
    state.skips.clear();
    let mut dirty = false;

    // 1. Pending upgrade-deletes, then 1b: reconcile the slots against
    // what actually became of each grab. Both settle state this pass
    // inherited; step 2 below is the one that decides anything new.
    dirty |= settle_pending_upgrades(d, &mut state);
    dirty |= reconcile_slots(d, &mut state);

    // §96.3: snapshot the give-up breaker once per pass. A tripped
    // target's candidates are skipped below - that skip IS the
    // watchlist's "unmonitor", and it keeps the one-grab-path invariant:
    // nothing new decides, the pass just declines dead content.
    let giveup_threshold = d.arr_giveup_threshold.load(Ordering::Relaxed).min(1000) as u32;
    // Expire stale evidence before reading it. This timer pass is the
    // one place that reads the give-up state on a schedule, and a
    // tripped target never calls `record_failure` again - so without
    // this the 45-day window never opened for exactly the targets it
    // was written for (see `GiveupState::prune`).
    let giveup = {
        let mut g = d.giveup.lock_ok();
        let before = g.targets.len();
        g.prune(unix_now());
        let shrank = g.targets.len() != before;
        let snap = g.clone();
        drop(g);
        if shrank {
            d.save_giveup();
        }
        snap
    };

    // 2. Match the index against each enabled item.
    for item in items.iter().filter(|i| i.enabled) {
        let min = wl::threshold_rank(&item.min_quality);
        let target = wl::threshold_rank(&item.target_quality);
        // Best complete candidate per slot (episode / the movie).
        struct Cand {
            rank: u32,
            bytes: u64,
            src: CandSrc,
            stem: String,
            quality: String,
            /// When the post itself went up (unix, 0 = unknown) - only
            /// used to say how far behind the post an instant grab was.
            posted: i64,
        }
        #[cfg(feature = "indexer")]
        let hits = d
            .with_index(|ix| ix.search_complete(&item.title, 1000).ok())
            .unwrap_or_default();
        let mut best: std::collections::HashMap<String, Cand> = std::collections::HashMap::new();
        let now_unix = unix_now();
        #[cfg(feature = "indexer")]
        for r in hits.iter() {
            // Matched on the name the release is KNOWN by: a
            // watchlist entry can never match an obfuscated stem, and
            // the whole point of a pre hit is that we now have the
            // string it would have matched all along.
            let name = r.display_name();
            let p = classify(name);
            if !wl::matches(item, name, &p) {
                continue;
            }
            // M32: per-item age window - skip too-fresh
            // (still propagating) and too-stale (repost) candidates.
            //
            // Deliberately AFTER the match test, which it used to
            // precede: the search is a fuzzy title query, so most hits
            // belong to some other title, and recording an age skip
            // against every one of them would report the window
            // rejecting posts this item never wanted. The cost is
            // classifying the age-rejected minority, which is small
            // beside the hits that reach here anyway.
            if !wl::age_ok(item, r.first_posted, now_unix) {
                wl::note_skip(&mut state.skips, item.id, "age");
                continue;
            }
            // §96.3: the give-up breaker has concluded this target is
            // not obtainable - stop pursuing it (any release of it).
            if giveup.tripped(&p, giveup_threshold) {
                wl::note_skip(&mut state.skips, item.id, "giveup");
                continue;
            }
            let Some(slot) = wl::slot_of(item, &p) else {
                continue;
            };
            // Exclude posts this slot already tried and lost (dead/DMCA'd):
            // a failed top-ranked release would otherwise still win `best`,
            // and the later `failed.contains` check skipped the whole SLOT
            // rather than that one candidate - so the next-best HEALTHY
            // release was never considered and the episode never downloaded.
            // Dropping failed stems here lets the best NON-failed post win.
            let skey = wl::state_key(item.id, &slot);
            if state
                .slots
                .get(&skey)
                .is_some_and(|s| s.failed.iter().any(|f| f == name))
            {
                continue;
            }
            let cand = Cand {
                rank: wl::quality_rank(&p),
                bytes: r.total_bytes,
                src: CandSrc::Local(r.id),
                stem: name.to_string(),
                quality: crate::wall::quality_label(&p),
                posted: r.first_posted,
            };
            match best.entry(slot) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(cand);
                }
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    // Same rank → prefer the bigger post (better bitrate).
                    if (cand.rank, cand.bytes) > (e.get().rank, e.get().bytes) {
                        e.insert(cand);
                    }
                }
            }
        }
        // M35 phase 2: ask the user's indexer accounts for this item, on
        // its own slow cadence, and let anything they offer compete as
        // an ordinary candidate. This is the one path that spends a
        // metered third-party account without a click, so it is fenced
        // by WATCH_EXT_INTERVAL_SECS and the per-indexer daily budgets
        // rather than by being off - a watchlist that cannot see
        // obfuscated posts and will not ask the accounts that CAN sees
        // nothing at all. An explicit off still wins, always.
        // Results run through the SAME classify /
        // matches / slot_of / age_ok pipeline as local rows, so quality
        // ranking, the failed-stem memory and every decide() rule apply
        // unchanged - an external candidate is just a candidate.
        if d.watchlist_external_on() {
            let due = state
                .ext_checked
                .get(&item.id)
                .is_none_or(|last| now_unix - *last >= WATCH_EXT_INTERVAL_SECS);
            if due {
                state.ext_checked.insert(item.id, now_unix);
                dirty = true;
                let (ext, gated) = watchlist_external_candidates(d, item);
                // The budget and backoff gates are the reason a "search
                // my indexer accounts" item can go quiet for a day with
                // nothing anywhere saying so - manual search has always
                // shown these notes, the watchlist swallowed them.
                if let Some(reason) = gated {
                    wl::note_skip(&mut state.skips, item.id, &reason);
                }
                for r in ext {
                    let p = classify(&r.title);
                    if !wl::matches(item, &r.title, &p) {
                        continue;
                    }
                    // §96.3: same give-up skip as the local leg - an
                    // external candidate for a dead target would spend
                    // third-party allowance re-proving it.
                    if giveup.tripped(&p, giveup_threshold) {
                        wl::note_skip(&mut state.skips, item.id, "giveup");
                        continue;
                    }
                    if !wl::age_ok(item, r.posted, now_unix) {
                        wl::note_skip(&mut state.skips, item.id, "age");
                        continue;
                    }
                    let Some(slot) = wl::slot_of(item, &p) else {
                        continue;
                    };
                    let skey = wl::state_key(item.id, &slot);
                    if state
                        .slots
                        .get(&skey)
                        .is_some_and(|s| s.failed.contains(&r.title))
                    {
                        continue;
                    }
                    let cand = Cand {
                        rank: wl::quality_rank(&p),
                        bytes: r.size,
                        src: CandSrc::External {
                            url: r.link,
                            indexer: r.indexer,
                            origin: r.origin,
                        },
                        posted: r.posted,
                        stem: r.title,
                        quality: crate::wall::quality_label(&p),
                    };
                    match best.entry(slot) {
                        std::collections::hash_map::Entry::Vacant(e) => {
                            e.insert(cand);
                        }
                        std::collections::hash_map::Entry::Occupied(mut e) => {
                            // STRICTLY better only: a local copy wins
                            // every tie, because grabbing it costs no
                            // third-party allowance.
                            if (cand.rank, cand.bytes) > (e.get().rank, e.get().bytes) {
                                e.insert(cand);
                            }
                        }
                    }
                }
            }
        }
        // M23e season packs: a bare-season post fills every episode of
        // its season at once, which is the efficient way to get a season
        // and a wasteful way to get the last two episodes of one. Judge
        // each pack candidate against what this item already holds, and
        // drop the ones that lose - see `wl::pack_eligible`.
        let pack_cands: Vec<(String, u32, u32)> = best
            .iter()
            .filter_map(|(k, c)| {
                wl::slot_parts(k).and_then(|(s, e)| e.is_none().then_some((k.clone(), s, c.rank)))
            })
            .collect();
        if !pack_cands.is_empty() {
            let cand_slots: Vec<String> = best.keys().cloned().collect();
            for (key, season, rank) in pack_cands {
                // The index only shows what has been POSTED, so on its
                // own it cannot say how much of a season is missing. The
                // calendar's cached episode list can, when there is one
                // - read here rather than up front because a pack
                // candidate is rare and this is a database round trip.
                let listed = aired_episodes(d, item, season);
                let st = wl::season_state(item, season, &state.slots, &cand_slots, &listed);
                if !wl::pack_eligible(item, season, rank, st) {
                    info!(
                        target: "watch",
                        "{}: season {season} pack skipped ({} of {} in-scope \
                         episode(s) already grabbed) - collecting single episodes instead",
                        item.title, st.have, st.known
                    );
                    best.remove(&key);
                }
            }
        }
        // Packs first, then the rest in a stable order: a season's pack
        // has to be settled BEFORE the single episodes it covers, or
        // whichever the hash map happened to yield first would win and
        // the same index could grab a pack one pass and singles the next.
        let mut ordered: Vec<(String, Cand)> = best.into_iter().collect();
        ordered.sort_by(|a, b| {
            wl::is_pack_slot(&b.0)
                .cmp(&wl::is_pack_slot(&a.0))
                .then_with(|| a.0.cmp(&b.0))
        });
        for (slot, c) in ordered {
            let key = wl::state_key(item.id, &slot);
            // An upgrade is already in flight for this slot - one at a time.
            if state.pending.iter().any(|p| p.slot == key) {
                continue;
            }
            let own = state.slots.get(&key);
            if own.is_some_and(|s| s.stem == c.stem || s.failed.contains(&c.stem)) {
                continue;
            }
            // What this slot effectively HAS: its own grab, or the season
            // pack covering it. An emptied slot (failed/deleted grab)
            // keeps its never-retry list but counts as having nothing.
            let cur = wl::covering(&state.slots, item.id, &slot);
            let cur_rank = cur.map(|s| s.rank);
            let prev_failed = own.map(|s| s.failed.clone()).unwrap_or_default();
            match wl::decide(cur_rank, c.rank, min, target, item.upgrade) {
                wl::Decision::Skip => {}
                wl::Decision::Grab => {
                    // §4b's lost-persist join - see `find_existing_copy`.
                    if let Some((h_where, h_name, h_nzo)) =
                        find_existing_copy(d, item, &key, &c.stem, &cats)
                    {
                        let hp = classify(&h_name);
                        let h_rank = wl::quality_rank(&hp);
                        // completed_in_history joins on the quality-AGNOSTIC
                        // dupe_key, so the history copy can be BELOW the
                        // user's min_quality floor (e.g. an old 480p when the
                        // floor is 720p). Adopting it as the slot would then
                        // Skip forever with upgrade=false - the release the
                        // floor demands never downloads. Only adopt a copy
                        // that meets the floor; otherwise fall through and
                        // grab the candidate (which already passed decide).
                        if h_rank >= min {
                            info!(
                                target: "watch",
                                "{}: already in {h_where} as {} - adopted, not re-grabbed",
                                item.title, h_name
                            );
                            let slot_val = wl::Slot {
                                rank: h_rank,
                                stem: h_name,
                                quality: crate::wall::quality_label(&hp),
                                nzo_id: h_nzo,
                                grabbed_at: unix_now(),
                                failed: prev_failed.clone(),
                            };
                            // A double episode owns every slot it covers.
                            for extra in wl::extra_slots(item, &hp) {
                                claim_extra_slot(
                                    &mut state.slots,
                                    wl::state_key(item.id, &extra),
                                    &slot_val,
                                );
                            }
                            state.slots.insert(key, slot_val);
                            dirty = true;
                            continue;
                        }
                        info!(
                            target: "watch",
                            "{}: the copy in {h_where} ({}) is below min_quality - \
                             grabbing {} instead",
                            item.title, h_name, c.stem
                        );
                    }
                    let origin =
                        crate::serve::origin::watchlist_origin(&slot, &c.quality, &item.title);
                    let g = watchlist_grab(d, &c.src, &c.stem, &item.category, false, &origin);
                    // Only a refusal earns the never-retry bar: `GrabMiss`.
                    let refused = g == Err(GrabMiss::Refused);
                    if let Ok(nzo) = g {
                        info!(target: "watch", "{}: grabbed {} ({})", item.title, c.stem, c.quality);
                        note_instant(&mut state, &arrived, item.id, &c.stem, c.posted, unix_now());
                        let cp = classify(&c.stem);
                        let slot_val = wl::Slot {
                            rank: c.rank,
                            stem: c.stem,
                            quality: c.quality,
                            nzo_id: nzo,
                            grabbed_at: unix_now(),
                            failed: prev_failed,
                        };
                        // A double episode owns every slot it covers, so
                        // a standalone E02 alt is never re-grabbed.
                        for extra in wl::extra_slots(item, &cp) {
                            claim_extra_slot(
                                &mut state.slots,
                                wl::state_key(item.id, &extra),
                                &slot_val,
                            );
                        }
                        state.slots.insert(key, slot_val);
                        dirty = true;
                    } else if refused
                        && remember_refused_grab(&mut state, &key, &c.stem, prev_failed)
                    {
                        dirty = true;
                    }
                }
                wl::Decision::Upgrade => {
                    // `prev` is what this slot HAD, which for an episode
                    // can be the season pack covering it rather than a
                    // grab of its own. Everything below reads the right
                    // thing off it either way: the log line names the
                    // copy being beaten, and the delete is gated on
                    // whether the replacement reaches as far as that
                    // copy did - which a single episode never does
                    // against a pack, so the pack is never deleted for
                    // one better episode.
                    let prev = cur.cloned().unwrap();
                    // The Grab arm's §4b lost-persist join, applied to
                    // the UPGRADE arm - see `adopt_existing_upgrade`.
                    if adopt_existing_upgrade(
                        d,
                        item,
                        &mut state,
                        &key,
                        prev.rank,
                        &prev_failed,
                        &c.stem,
                        &cats,
                    ) {
                        dirty = true;
                        continue;
                    }
                    let origin =
                        crate::serve::origin::watchlist_origin(&slot, &c.quality, &item.title);
                    let g = watchlist_grab(d, &c.src, &c.stem, &item.category, true, &origin);
                    let refused = g == Err(GrabMiss::Refused);
                    if let Ok(nzo) = g {
                        info!(
                            target: "watch",
                            "{}: upgrading {} → {} ({})",
                            item.title, prev.quality, c.quality, c.stem
                        );
                        note_instant(&mut state, &arrived, item.id, &c.stem, c.posted, unix_now());
                        // The upgrade itself always stands; only the
                        // DELETE is held back, and only when this
                        // replacement does not reach as far as the
                        // download it supersedes. Held back, the old
                        // copy simply stays, exactly as it does for a
                        // delete_old=false item.
                        let cp = classify(&c.stem);
                        if item.delete_old
                            && upgrade_supersedes_all(item, &state, &prev, &cp, &cats)
                        {
                            state.pending.push(wl::PendingDelete {
                                slot: key.clone(),
                                new_nzo: nzo.clone(),
                                new_stem: c.stem.clone(),
                                old_nzo: prev.nzo_id.clone(),
                                prev_rank: prev.rank,
                                prev_stem: prev.stem.clone(),
                                prev_quality: prev.quality.clone(),
                            });
                        }
                        let slot_val = wl::Slot {
                            rank: c.rank,
                            stem: c.stem,
                            quality: c.quality,
                            nzo_id: nzo,
                            grabbed_at: unix_now(),
                            // This slot's OWN never-retry list, not
                            // `prev`'s: when prev is the season pack,
                            // its dead stems belong to the pack slot.
                            failed: prev_failed,
                        };
                        // A double-episode upgrade owns every slot it covers,
                        // exactly like the Grab and adopt arms. Without this
                        // the secondary slot (e.g. s01e02 of an S01E01E02
                        // upgrade) stayed empty and a standalone E02 was later
                        // grabbed as a duplicate of content already had.
                        for extra in wl::extra_slots(item, &cp) {
                            claim_extra_slot(
                                &mut state.slots,
                                wl::state_key(item.id, &extra),
                                &slot_val,
                            );
                        }
                        state.slots.insert(key, slot_val);
                        dirty = true;
                    } else if refused
                        && remember_refused_grab(&mut state, &key, &c.stem, prev_failed)
                    {
                        dirty = true;
                    }
                }
            }
        }
    }

    if dirty {
        let path = d.spool.join("watchlist-state.json");
        // SAY SO when it does not land. The in-memory state below still
        // carries the pass's decisions, so nothing re-grabs while this
        // process lives - but across a restart the slots are back to
        // whatever was last written, and the pass that follows grabs
        // everything again. A swallowed error made that indistinguishable
        // from a healthy save; the queue join in the Grab arm is what
        // stops the re-grab, and this is what says the state was lost.
        match serde_json::to_string_pretty(&state) {
            Ok(text) => {
                if let Err(e) = crate::persist::write_atomic(&path, text.as_bytes()) {
                    warn!(
                        target: "watch",
                        "watchlist state could not be written to {} ({e}) - \
                         the slots grabbed this pass are live but not durable",
                        path.display()
                    );
                }
            }
            Err(e) => warn!(target: "watch", "watchlist state could not be encoded ({e})"),
        }
    }
    *d.watch_state.lock_ok() = state;
}

/// §74: record a grab as INSTANT when the release being grabbed is one
/// of the arrivals that woke this pass.
///
/// The test is the name, not the timing: a pass woken by an arrival also
/// grabs whatever else it finds along the way, and calling those instant
/// too would turn the record into "a pass ran recently". Nothing reads
/// this back - it exists so the watchlist can show that the feature did
/// something, and so the tests can tell the two paths apart.
pub(super) fn note_instant(
    state: &mut crate::watchlist::WatchState,
    arrived: &[String],
    item_id: u64,
    stem: &str,
    posted: i64,
    now: i64,
) {
    if !arrived.iter().any(|a| a == stem) {
        return;
    }
    let lag = if posted > 0 { (now - posted).max(0) } else { 0 };
    info!(target: "watch", "grabbed {stem} {lag}s after it was posted");
    state.instant.insert(
        item_id.to_string(),
        crate::watchlist::InstantGrab {
            stem: stem.to_string(),
            at: now,
            lag,
        },
    );
}

/// Episodes of one season that have ALREADY AIRED, from the calendar's
/// cached TVmaze episode list (M23d) - the denominator the season-pack
/// decision needs and the index cannot supply, since the index only
/// knows what somebody posted.
///
/// Unaired episodes are excluded deliberately: counting them would make
/// every part-way season look mostly missing, and a pack posted two
/// episodes in would then always look like the better buy. Empty when
/// there is no cached list (an unwatched title, a show TVmaze does not
/// have, a first pass before the refresh) - `pack_eligible` reads that
/// as "nobody knows", not as "nothing exists".
#[cfg_attr(not(feature = "indexer"), expect(unused_variables))]
pub(super) fn aired_episodes(
    d: &Arc<Daemon>,
    item: &crate::watchlist::WatchItem,
    season: u32,
) -> Vec<u32> {
    if item.kind != "tv" {
        return Vec::new();
    }
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| (t.as_secs() / 86_400) as i64)
        .unwrap_or(0);
    let (y, m, dd) = civil_from_days(days);
    let today = format!("{y:04}-{m:02}-{dd:02}");
    #[cfg(feature = "indexer")]
    let key = format!("eplist:{}", crate::wall::norm_title(&item.title));
    #[cfg(feature = "indexer")]
    let eps: Vec<crate::wall::EpInfo> = d
        .with_index(|ix| ix.kv_get(&key))
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| serde_json::from_value(v["episodes"].clone()).ok())
        .unwrap_or_default();
    // Slim build: no index, so no cached episode list to consult.
    #[cfg(not(feature = "indexer"))]
    let eps: Vec<crate::wall::EpInfo> = Vec::new();
    eps.iter()
        .filter(|e| e.season == season && !e.airdate.is_empty() && e.airdate <= today)
        .map(|e| e.episode)
        .collect()
}

/// Every slot of `item` a release fills: the one it places in, plus the
/// extra episodes of a multi-episode post. This is how far a download
/// reaches, read off the release itself, so it stays true however the
/// slot map has since been rewritten. Empty when the release does not
/// place in this item at all.
pub(super) fn covered_slots(
    item: &crate::watchlist::WatchItem,
    p: &crate::wall::Parsed,
) -> Vec<String> {
    let Some(primary) = crate::watchlist::slot_of(item, p) else {
        return Vec::new();
    };
    std::iter::once(primary)
        .chain(crate::watchlist::extra_slots(item, p))
        .map(|s| crate::watchlist::state_key(item.id, &s))
        .collect()
}

/// May an upgrade delete the download it supersedes? Only when the
/// replacement reaches every slot the old download did.
///
/// A double-episode post is written into every episode slot it fills, so
/// it is the only copy of those episodes too, and deleting it for one
/// slot's upgrade takes the others with it - leaving the watchlist
/// believing it still has an episode whose files are gone. Reach comes
/// off each release's own stem, not off the slot map: the matching loop
/// rewrites that map as it goes, so with both episodes of a double
/// upgrading in one pass a map scan finds the first slot already
/// replaced and reads the second as unshared. The map is still consulted
/// for anything ELSE pointing at the old job - two watchlist items that
/// adopted the same completed download.
///
/// A like-for-like double upgrade (S01E01E02 720p → the same 1080p)
/// reaches both slots and so still deletes: the new job covers
/// everything the old one did.
pub(super) fn upgrade_supersedes_all(
    item: &crate::watchlist::WatchItem,
    state: &crate::watchlist::WatchState,
    prev: &crate::watchlist::Slot,
    new_p: &crate::wall::Parsed,
    cats: &[nzbkit::categories::CustomCategory],
) -> bool {
    let new_reach = covered_slots(item, new_p);
    covered_slots(item, &nzbkit::categories::classify(&prev.stem, cats))
        .iter()
        .all(|k| new_reach.contains(k))
        && state
            .slots
            .iter()
            .all(|(k, s)| s.nzo_id != prev.nzo_id || new_reach.contains(k))
}

/// A Completed history entry with the same series/movie identity as
/// `stem` (dupe-key join): (job name, nzo_id).
/// §4b: the join both decision arms make before grabbing. History
/// first - slot state can lag reality (rebuilt state file, RSS/manual
/// grabs), and relying on the duplicate-hold as the net piled dupe-held
/// junk rows into the queue EVERY pass while the episode sat Completed
/// in history; a Completed copy is the stronger claim on the slot. And
/// against the QUEUE too, which the history-only join could not see: a
/// grab whose slot write was lost (a failed `write_atomic`, a crash
/// between the enqueue and the persist) is sitting in the queue, not in
/// history, so every pass re-grabbed it. Under `dupe_action = "discard"`
/// that is a LOOP with no exit - the daemon refuses the duplicate,
/// nothing is written, the next pass tries again - and on an external
/// candidate each turn spends the indexer's daily grab allowance.
///
/// Only a copy that actually FILLS this slot is answered. The join is
/// on dupe_key, a separate text parser from the classified identity
/// used for slots, and where the two disagree the mismatch is silent
/// and permanent: the slot records a download the user never asked for,
/// `cur_rank` is now set, and every later pass Skips while the event
/// itself never downloads and nothing says so. Reading the reach off
/// the found release's own name is the same check
/// `upgrade_supersedes_all` makes.
fn find_existing_copy(
    d: &Arc<Daemon>,
    item: &crate::watchlist::WatchItem,
    key: &str,
    stem: &str,
    cats: &[nzbkit::categories::CustomCategory],
) -> Option<(&'static str, String, String)> {
    completed_in_history(d, stem)
        .map(|(n, i)| ("history", n, i))
        .or_else(|| queued_dupe(d, stem).map(|(n, i)| ("the queue", n, i)))
        .filter(|(_, h_name, _)| {
            covered_slots(item, &nzbkit::categories::classify(h_name, cats))
                .iter()
                .any(|k| k == key)
        })
}

/// §4b for the UPGRADE arm: a lost UPGRADE persist has the same shape
/// the Grab arm's join covers - the better copy is already queued or
/// Completed - and re-grabbing enqueues a second copy (default
/// dupe_action=pause) or bars the stem via the never-retry list
/// (discard) while the first copy still downloads. Adopt only a copy
/// that actually IS the upgrade (rank above what the slot holds): the
/// join is quality-agnostic, so it also finds the superseded copy the
/// arm exists to replace. No pending delete on adopt - the pass whose
/// persist was lost owns that, and held back the old copy simply stays,
/// exactly as it does for a delete_old=false item.
///
/// True when the found copy was adopted into `key`'s slot (the caller
/// marks the state dirty and moves on); false means grab as usual.
fn adopt_existing_upgrade(
    d: &Arc<Daemon>,
    item: &crate::watchlist::WatchItem,
    state: &mut crate::watchlist::WatchState,
    key: &str,
    prev_rank: u32,
    prev_failed: &[String],
    stem: &str,
    cats: &[nzbkit::categories::CustomCategory],
) -> bool {
    use crate::watchlist as wl;
    let Some((h_where, h_name, h_nzo)) = find_existing_copy(d, item, key, stem, cats) else {
        return false;
    };
    let hp = nzbkit::categories::classify(&h_name, cats);
    let h_rank = wl::quality_rank(&hp);
    if h_rank <= prev_rank {
        return false;
    }
    info!(
        target: "watch",
        "{}: the upgrade is already in {h_where} as {} - adopted, not re-grabbed",
        item.title, h_name
    );
    let slot_val = wl::Slot {
        rank: h_rank,
        stem: h_name,
        quality: crate::wall::quality_label(&hp),
        nzo_id: h_nzo,
        grabbed_at: unix_now(),
        failed: prev_failed.to_vec(),
    };
    // A double episode owns every slot it covers.
    for extra in wl::extra_slots(item, &hp) {
        claim_extra_slot(&mut state.slots, wl::state_key(item.id, &extra), &slot_val);
    }
    state.slots.insert(key.to_string(), slot_val);
    true
}

pub(super) fn completed_in_history(d: &Arc<Daemon>, stem: &str) -> Option<(String, String)> {
    let key = dupe_key(stem)?;
    d.history.lock_ok().iter().find_map(|j| {
        let g = j.lock_ok();
        (g.state == JobState::Completed && g.dupe_key.as_deref() == Some(key.as_str()))
            .then(|| (g.name.clone(), g.nzo_id.clone()))
    })
}

/// [`completed_in_history`] against the QUEUE, on the same `dupe_key`
/// join and with the same answer shape.
///
/// The two together are exactly what the daemon's own duplicate check
/// looks at (`serve::dupe`: any queued job, plus a Completed history
/// row), which is what makes the pair a complete answer to "will this
/// enqueue be refused as a duplicate". History alone was not: a grab
/// whose slot write never landed is in the QUEUE, and re-grabbing it
/// under `dupe_action = "discard"` fails forever with nothing recorded.
///
/// Any queue state counts, paused and dupe-held included - the copy is
/// there and the enqueue will collide with it whatever it is doing.
pub(super) fn queued_dupe(d: &Arc<Daemon>, stem: &str) -> Option<(String, String)> {
    let key = dupe_key(stem)?;
    d.queue.lock_ok().iter().find_map(|j| {
        let g = j.lock_ok();
        (g.dupe_key.as_deref() == Some(key.as_str())).then(|| (g.name.clone(), g.nzo_id.clone()))
    })
}

/// A grab the daemon REFUSED - `watchlist_grab` answered
/// [`GrabMiss::Refused`], so the enqueue itself said no and nothing was
/// enqueued or slotted.
///
/// Without this the pass simply ends and the next one, 60 s later,
/// finds the same candidate and asks again, forever; for an external
/// candidate every one of those turns fetches the enclosure and spends
/// the indexer's server-side grab before the enqueue refuses again.
/// The stem goes on the slot's never-retry list exactly as a genuinely
/// failed grab's does (step 1b), and on an EMPTY slot - no nzo_id - so
/// it claims no coverage: `wl::covering` skips a slot with none, which
/// leaves the item open for a different release.
///
/// THE TRADE, stated rather than left to be found: a refusal that was
/// TRANSIENT (a full disk, a spool write that failed) bars this stem for
/// good too. That is the same bar a genuinely failed download takes, and
/// it is survivable for the same reason - the ranking drops failed stems
/// rather than skipping the whole slot, so the item is still served by
/// the best release that is not on the list. The alternative measured
/// worse: a permanent refusal (which is what a duplicate is, for as long
/// as the duplicate exists) asked again every 60 s, forever, spending an
/// indexer's daily grab allowance each time.
///
/// THE TRADE STOPS AT THE ENQUEUE, and the callers hold it there: a
/// miss from a gate that never asked anyone for anything -
/// [`GrabMiss::Transient`], the daily budget, a disabled indexer, a
/// failed enclosure fetch - is NOT recorded, because recording it
/// cascades. Each pass would bar the item's next-best candidate for
/// nothing, so an afternoon of exhausted budget walked the entire
/// ranking onto this list and the item was silently never grabbed
/// (v1.2.4 tranche sweep, 27 Aug 2026).
///
/// Returns whether anything was recorded (a repeat refusal is not).
fn remember_refused_grab(
    state: &mut crate::watchlist::WatchState,
    key: &str,
    stem: &str,
    prev_failed: Vec<String>,
) -> bool {
    let s = state
        .slots
        .entry(key.to_string())
        .or_insert_with(|| crate::watchlist::Slot {
            rank: 0,
            stem: String::new(),
            quality: String::new(),
            nzo_id: String::new(),
            grabbed_at: unix_now(),
            failed: prev_failed,
        });
    if s.failed.iter().any(|f| f == stem) {
        return false;
    }
    s.failed.push(stem.to_string());
    true
}

/// Why [`watchlist_grab`] came back without a job, split by what asking
/// again would cost - because the two consumers of a miss answer
/// opposite questions. `remember_refused_grab` bars the stem for good,
/// and that bar is only owed to a miss that will answer the same way
/// on every future pass while ALSO spending something real each time
/// it is asked (the duplicate under `dupe_action = "discard"`: the
/// enclosure fetch succeeds, the indexer's server-side grab is spent,
/// and the enqueue then refuses). A miss from a gate that
/// short-circuited BEFORE anything was spent is the opposite shape -
/// self-clearing (a daily budget rolls over, a disabled indexer is
/// re-enabled, a 5xx passes) and free to re-ask - and recording it
/// cascades: each 60 s pass bars the item's next-best candidate for
/// nothing, so a budget exhausted for an afternoon walks the entire
/// ranking onto the never-retry list and the item is silently never
/// grabbed (v1.2.4 tranche sweep, 27 Aug 2026).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GrabMiss {
    /// The enqueue itself refused or failed - a duplicate discard, a
    /// spool write failure. Asking again gets the same answer at the
    /// same price, so the stem goes on the never-retry list.
    Refused,
    /// A gate short-circuited before anything was asked of anyone: the
    /// indexer is disabled or removed, its daily grab budget is
    /// reached, or the enclosure fetch failed. Self-clearing; the next
    /// pass may ask again and nothing is recorded.
    Transient,
}

/// Synthesize the NZB for an indexed release and enqueue it. `promote`
/// lifts the M14f duplicate hold: an intentional upgrade IS a duplicate
/// of the completed original, that's the point.
///
/// `job_origin` is what the job records as its provenance - built by
/// `origin::watchlist_origin` from the item, slot and quality that
/// matched, so the drawer can say which of them did rather than only
/// that the watchlist did. Passed in rather than built here because the
/// decision loop is what holds all three; this function only knows the
/// release. Not `origin`: the external arm destructures a `CandSrc`
/// field of that name, which is the INDEXER's `SourceOrigin`, and the
/// two are one `&str`-vs-`&SourceOrigin` slip apart.
pub(super) fn watchlist_grab(
    d: &Arc<Daemon>,
    src: &CandSrc,
    stem: &str,
    category: &str,
    promote: bool,
    job_origin: &str,
) -> Result<String, GrabMiss> {
    // A local candidate is served out of our own index; an external one
    // is fetched from the indexer that offered it, which is also what
    // spends that account's daily grab allowance. The external path
    // goes through enqueue_fetched so a watchlist grab gets the same
    // X-DNZB failure-link handling a hand-clicked one does.
    //
    // Grab-deferred mode: the match is enqueued PAUSED (-2 is SAB's
    // add-paused flag), which makes it a retention-insurance candidate
    // when `insurance_cap_gb` is on - the payload is banked in the
    // background while the articles are still alive, and the user
    // unpauses when they actually want it. Never for an upgrade
    // (`promote`): those collide with the completed original and ride
    // the duplicate-hold machinery, which must not mix with a deferred
    // add.
    let priority = if !promote && d.watchlist_deferred.load(Ordering::Relaxed) {
        -2
    } else {
        -100
    };
    let nzo = match src {
        #[cfg(feature = "indexer")]
        CandSrc::Local(id) => {
            // A row the index cannot render any more (deleted, or the
            // NZB build failed) costs nothing to ask about again, and
            // the index may heal - Transient, not Refused.
            let Some(xml) = d.with_index(|ix| ix.make_nzb(*id).ok()) else {
                return Err(GrabMiss::Transient);
            };
            d.enqueue(
                xml.as_bytes(),
                stem,
                category,
                priority,
                None,
                None,
                job_origin,
                false,
            )
        }
        CandSrc::External {
            url,
            indexer,
            origin,
        } => {
            {
                let mut rt = d.indexer_rt.lock_ok();
                rt.usage.roll(unix_now());
                let cfg = d
                    .indexers
                    .lock_ok()
                    .iter()
                    .find(|i| &i.name == indexer)
                    .cloned();
                // The search that produced this candidate snapshotted the
                // ENABLED indexers, then awaited the network. By the time we
                // get here the user may have disabled or deleted that
                // account - and the old check was `cfg.is_some_and(...)`, so
                // a MISSING config passed it: the stale response still
                // fetched its enclosure with the (removed) credentials, spent
                // the account's daily grab and enqueued the download (Codex
                // sweep 12 Aug F6c). A revoked indexer is not a budget
                // question, so say which it is.
                let Some(cfg) = cfg.filter(|c| c.enabled) else {
                    warn!(
                        target: "watch",
                        "{indexer} is no longer configured or is disabled - {stem} not grabbed"
                    );
                    return Err(GrabMiss::Transient);
                };
                if !rt.usage.grab_allowed(&cfg) {
                    warn!(target: "watch", "{indexer}: daily grab budget reached - {stem} not grabbed");
                    return Err(GrabMiss::Transient);
                }
            }
            // fetch_url_from: the link is an `<enclosure url>` this
            // indexer's search response chose, so it may not reach a
            // private address the indexer does not own (M12).
            let fetched = match fetch_url_from(url, origin) {
                Ok(f) => f,
                Err(e) => {
                    // redact_url_creds: fetch_url names the URL it failed
                    // on, and here that is the indexer's enclosure link,
                    // which carries the user's account apikey. logtee
                    // mirrors stdout/stderr into the dashboard log, so an
                    // unscrubbed line is not merely "in a file on the NAS".
                    warn!(
                        target: "watch",
                        "fetching {stem} from {indexer}: {}",
                        redact_url_creds(&e.to_string())
                    );
                    return Err(GrabMiss::Transient);
                }
            };
            let r = d.enqueue_fetched(
                &fetched,
                stem,
                category,
                priority,
                None,
                None,
                0,
                job_origin,
                DupeExempt::Nobody,
            );
            if r.is_ok() {
                let mut rt = d.indexer_rt.lock_ok();
                rt.usage.count_grab(indexer);
                drop(rt);
                save_indexer_usage(d);
            }
            r
        }
    };
    match nzo {
        Ok(Enqueued { nzo_id: nzo, .. }) => {
            if promote {
                {
                    let q = d.queue.lock_ok();
                    if let Some(j) = q.iter().find(|j| j.lock_ok().nzo_id == nzo) {
                        let mut g = j.lock_ok();
                        if g.priority == -3 {
                            g.priority = 0;
                            g.paused = false;
                        }
                    }
                }
                d.save_queue();
            }
            Ok(nzo)
        }
        Err(e) => {
            warn!(target: "watch", "enqueue {stem}: {e}");
            // The one arm that is worth remembering: for the external
            // source the enclosure fetch SUCCEEDED, so the indexer's
            // server-side grab is already spent, and the refusal (a
            // duplicate under discard, a spool write failure) answers
            // the same on every future pass.
            Err(GrabMiss::Refused)
        }
    }
}

/// One external search on behalf of a watchlist item, tagged with the
/// indexer each result came from.
pub(super) struct ExtCand {
    title: String,
    link: String,
    size: u64,
    posted: i64,
    indexer: String,
    /// That indexer's configured URL and search-time addresses, carried
    /// beside its name so the grab can bind the enclosure fetch to the
    /// origin that offered it (M12/M9) without a by-name lookup the user
    /// may have renamed away, and without a re-resolution a hostile DNS
    /// would answer differently.
    origin: SourceOrigin,
}

/// Ask every enabled, in-budget indexer about one watchlist item.
///
/// Deliberately free-text on the item's title: a watchlist entry is
/// something the user typed, and carries no imdb/tvdb id to be precise
/// with. A movie item pins its year, which is what disambiguates a
/// remake. Season/episode are NOT sent - one search per item per
/// cadence has to cover every wanted episode, and `slot_of` sorts the
/// results out afterwards anyway.
///
/// Returns the candidates plus, when this leg asked NOBODY, the reason
/// the gates gave - bundle D: those were bare `continue`s, so an item
/// whose indexers were all out of daily allowance looked exactly like
/// one nothing had been posted for.
pub(super) fn watchlist_external_candidates(
    d: &Arc<Daemon>,
    item: &crate::watchlist::WatchItem,
) -> (Vec<ExtCand>, Option<String>) {
    let list: Vec<crate::newznab::IndexerConfig> = d
        .indexers
        .lock_ok()
        .iter()
        .filter(|i| i.enabled)
        .cloned()
        .collect();
    if list.is_empty() {
        return (Vec::new(), None);
    }
    let mut runnable = Vec::new();
    // Per-indexer, and named: "your indexers are out of allowance" is a
    // different sentence from "NZBGeek is", and with three accounts
    // configured only the second one is actionable.
    let (mut spent, mut backed_off) = (Vec::new(), Vec::new());
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(unix_now());
        let now = Instant::now();
        for i in list {
            if rt.penalty_until.get(&i.name).is_some_and(|t| *t > now) {
                backed_off.push(i.name.clone());
                continue;
            }
            if !rt.usage.hit_allowed(&i) {
                spent.push(i.name.clone());
                continue;
            }
            rt.usage.count_hit(&i.name);
            runnable.push(i);
        }
    }
    if runnable.is_empty() {
        // Budget leads: an exhausted daily allowance lasts until
        // midnight and is the one the user can do something about,
        // where a rate-limit backoff clears itself in minutes.
        let gated = if !spent.is_empty() {
            Some(format!("indexer_budget:{}", spent.join(", ")))
        } else if !backed_off.is_empty() {
            Some(format!("indexer_backoff:{}", backed_off.join(", ")))
        } else {
            None
        };
        return (Vec::new(), gated);
    }
    save_indexer_usage(d);
    let q = match (item.kind.as_str(), item.year) {
        ("movie", Some(y)) => format!("{} {y}", item.title),
        _ => item.title.clone(),
    };
    let query = crate::newznab::SearchQuery {
        q,
        cats: cat_for_kind(&item.kind)
            .map(|c| vec![c])
            .unwrap_or_default(),
        limit: 100,
        ..Default::default()
    };
    let mut out = Vec::new();
    // The watcher already runs off the queue's critical path, so a
    // plain scoped fan-out is fine here; each call carries the shared
    // agent's 15 s ceiling.
    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = runnable
            .iter()
            .map(|i| {
                let query = query.clone();
                s.spawn(move || (i.name.clone(), indexer_search_one(i, &query)))
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    let mut asked_ok = 0usize;
    let mut refused: Vec<String> = Vec::new();
    for (name, r) in results {
        match r {
            Ok((items, origin)) => {
                asked_ok += 1;
                for it in items {
                    out.push(ExtCand {
                        title: it.title,
                        link: it.link,
                        size: it.size,
                        posted: it.posted,
                        indexer: name.clone(),
                        origin: origin.clone(),
                    });
                }
            }
            Err(e) => {
                if matches!(e, crate::newznab::NewznabError::Limit(..)) {
                    d.indexer_rt
                        .lock_ok()
                        .penalty_until
                        .insert(name.clone(), Instant::now() + INDEXER_LIMIT_BACKOFF);
                }
                refused.push(name.clone());
                // Never fatal: the item simply has no external candidate
                // this pass, and the local index still decides.
                warn!(target: "watch", "{name}: {e}");
            }
        }
    }
    // Every account we did ask refused us. Same class of silence as the
    // gates above and reported the same way; a leg that partly answered
    // says nothing, because the answer is what the item wanted.
    let gated = (asked_ok == 0 && !refused.is_empty())
        .then(|| format!("indexer_error:{}", refused.join(", ")));
    (out, gated)
}

#[cfg(test)]
mod settle_tests {
    use super::*;
    use crate::serve::testutil::test_daemon;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-settle-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// One Completed history record, with a real payload directory so the
    /// delete has something to remove.
    fn completed(d: &Arc<Daemon>, root: &std::path::Path, id: &str, stem: &str) -> PathBuf {
        let out = root.join(stem);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("payload.mkv"), b"x").unwrap();
        completed_naming(d, root, id, stem, &out);
        out
    }

    /// A Completed history record NAMING `out`, leaving whatever is
    /// already there alone.
    ///
    /// An A6 publish is why this is a shape at all: the re-download takes
    /// the canonical directory over and the superseded record is left
    /// pointing at it, so two records name one path and only one of them
    /// put the bytes there.
    fn completed_naming(
        d: &Arc<Daemon>,
        root: &std::path::Path,
        id: &str,
        stem: &str,
        out: &std::path::Path,
    ) {
        let v = json!({
            "nzo_id": id, "name": stem,
            "out_dir": out.to_string_lossy(),
            "nzb_path": root.join(format!("{id}.nzb")).to_string_lossy(),
            "state": "Completed",
        });
        std::fs::write(root.join(format!("{id}.nzb")), b"<nzb/>").unwrap();
        let job = Arc::new(Mutex::new(job_from_json(&v).expect("job")));
        d.history.lock_ok().push(job);
    }

    /// The pending-delete record a settled upgrade leaves behind, for
    /// the two ids the test cares about.
    fn pending(old: &str, new: &str) -> crate::watchlist::PendingDelete {
        crate::watchlist::PendingDelete {
            slot: "7:s01e01".to_string(),
            new_nzo: new.to_string(),
            new_stem: format!("stem-{new}"),
            old_nzo: old.to_string(),
            prev_rank: 3,
            prev_stem: format!("stem-{old}"),
            prev_quality: "720p".to_string(),
        }
    }

    /// §129 1b(b): a settled delete_old upgrade narrates itself on the
    /// lifecycle ring as `watchlist.upgraded`, not through a bounded
    /// array on the queue payload for the page to diff.
    ///
    /// The moment is worth an event precisely because nothing else marks
    /// it: a COMPLETED download and its history row both disappear, and
    /// before the notice existed two `info!` lines were the only
    /// witnesses. It is also the LATE case the migration fixes - the
    /// deletes here touch neither queue, so nothing bumps the queue
    /// revision that the old transport rode, and on an idle daemon the
    /// toast waited for an unrelated mutation.
    ///
    /// `fate` is asserted as well as the names, because it is a CHECKED
    /// claim about the user's files rather than a reading of the Trash
    /// setting (4 Aug: a 14 GB download reported "went to the Trash"
    /// while it had been destroyed outright). The Trash is off under
    /// `cfg(test)`, so a removal that happened is "gone".
    #[test]
    fn a_settled_upgrade_reaches_the_dashboard_as_a_lifecycle_event() {
        let _steady = crate::smart::trash_globals_steady();
        let dir = tmp("upgraded");
        let d = test_daemon(&dir);
        completed(&d, &dir, "new1", "New.Show.S01E01.1080p.WEB-TEST");
        let old_out = completed(&d, &dir, "old1", "Old.Show.S01E01.720p.WEB-TEST");

        let mut state = crate::watchlist::WatchState::default();
        state.pending.push(crate::watchlist::PendingDelete {
            slot: "7:s01e01".to_string(),
            new_nzo: "new1".to_string(),
            new_stem: "New.Show.S01E01.1080p.WEB-TEST".to_string(),
            old_nzo: "old1".to_string(),
            prev_rank: 3,
            prev_stem: "Old.Show.S01E01.720p.WEB-TEST".to_string(),
            prev_quality: "720p".to_string(),
        });

        assert!(
            settle_pending_upgrades(&d, &mut state),
            "a settled upgrade is a state change"
        );
        assert!(state.pending.is_empty(), "the entry must not be re-parked");
        assert!(!old_out.exists(), "the superseded payload should be gone");

        let (events, reset, _) = d.life_since(0);
        assert!(!reset, "this test's traffic is far inside the ring");
        let e = events
            .iter()
            .find(|e| e["kind"] == "watchlist.upgraded")
            .unwrap_or_else(|| panic!("no watchlist.upgraded on the ring: {events:?}"));
        assert_eq!(e["name"], "New.Show.S01E01.1080p.WEB-TEST");
        assert_eq!(e["old"], "Old.Show.S01E01.720p.WEB-TEST");
        assert_eq!(e["oldq"], "720p");
        assert_eq!(e["fate"], "gone");
        assert_eq!(e["schema_version"], 1);
        assert!(e["seq"].as_u64().unwrap_or(0) > 0);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TODO 290 F-05a: a directory a SURVIVOR still names is not
    /// settlement's to remove, and settlement had never asked.
    ///
    /// The REST history delete has asked since A6: `plan_history_delete`
    /// grants `may_remove_files` only to a doomed record whose `out_dir`
    /// no queue job and no surviving history record also names, precisely
    /// because `publish_over_previous` hands the CANONICAL directory to a
    /// verified re-download and leaves the superseded record pointing at
    /// it. Upgrade settlement removed the directory unconditionally, so
    /// the record it deleted was not the data it destroyed.
    ///
    /// The sharing here is BUILT rather than asserted, through the two
    /// production functions that make it: `dir_claim` says a completed
    /// payload claims its directory, `choose_out_dir` refiles the re-add
    /// beside it and records `replaces`, and `publish_over_previous`
    /// moves the verified re-download onto the canonical path. What is
    /// left is the two-record shape, and the bytes under it belong to the
    /// SURVIVOR.
    ///
    /// The `filed` arm is deliberately not the subject: a TV-filed
    /// record's `out_dir` IS the shared season folder, every episode
    /// claims it, and `remove_job_files` takes the narrow per-episode
    /// path there - which is why `plan_history_delete` exempts it and why
    /// this has never shown up on the TV path.
    #[test]
    fn settlement_keeps_a_directory_a_surviving_record_still_claims() {
        let _steady = crate::smart::trash_globals_steady();
        let dir = tmp("shareddir");
        let d = test_daemon(&dir);
        completed(&d, &dir, "new1", "New.Movie.2024.2160p.WEB-TEST");

        // The superseded release, downloaded once and completed.
        let stem = "Old.Movie.2024.720p.WEB-TEST";
        let canon = completed(&d, &dir, "old1", stem);

        // A re-add of that same release, through the production claim
        // rule: a completed payload claims its directory, so the re-add
        // downloads beside it and records the canonical path.
        let (fresh, replaces) = choose_out_dir(&dir.join(stem), stem, &|p| d.dir_claim(p));
        assert_eq!(
            replaces.as_deref(),
            Some(canon.as_path()),
            "a completed payload claims its directory"
        );
        assert_ne!(fresh, canon, "the re-add downloads beside it");
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(fresh.join("payload.mkv"), b"the re-download").unwrap();
        // ...and takes it over once it verifies, which is the moment two
        // history records start naming one directory.
        assert_eq!(
            publish_over_previous(&fresh, &canon).as_deref(),
            Some(canon.as_path()),
            "the verified re-download publishes over the canonical path"
        );
        completed_naming(&d, &dir, "re1", stem, &canon);
        assert_eq!(
            std::fs::read(canon.join("payload.mkv")).unwrap(),
            b"the re-download",
            "the bytes under the shared path are the survivor's"
        );

        let mut state = crate::watchlist::WatchState::default();
        state.pending.push(pending("old1", "new1"));
        assert!(
            settle_pending_upgrades(&d, &mut state),
            "a settled upgrade is a state change"
        );
        assert!(state.pending.is_empty(), "the entry must not be re-parked");

        // The record goes - it names a directory that is not its payload
        // any more, so leaving it would strand a row nothing can act on.
        assert!(
            !d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "old1"),
            "the superseded record still leaves history"
        );
        // The files do NOT.
        assert_eq!(
            std::fs::read(canon.join("payload.mkv")).ok().as_deref(),
            Some(&b"the re-download"[..]),
            "the surviving record's payload must still be there"
        );

        let (events, _, _) = d.life_since(0);
        let e = events
            .iter()
            .find(|e| e["kind"] == "watchlist.upgraded")
            .unwrap_or_else(|| panic!("no watchlist.upgraded on the ring: {events:?}"));
        assert_eq!(
            e["fate"], "kept",
            "a removal that did not happen must not be reported as one"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One QUEUED record, with a real payload directory - what a
    /// superseded release the prefetch sidecar is still working on
    /// looks like from the queue's side.
    fn queued(d: &Arc<Daemon>, root: &std::path::Path, id: &str, stem: &str) -> PathBuf {
        let out = root.join(stem);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("part01.rar"), b"bytes").unwrap();
        let v = json!({
            "nzo_id": id, "name": stem,
            "out_dir": out.to_string_lossy(),
            "nzb_path": root.join(format!("{id}.nzb")).to_string_lossy(),
            "state": "Queued",
        });
        std::fs::write(root.join(format!("{id}.nzb")), b"<nzb/>").unwrap();
        let job = Arc::new(Mutex::new(job_from_json(&v).expect("job")));
        d.queue.lock_ok().push_back(job);
        out
    }

    /// Codex sweep 24 Aug, F-05, the sidecar half: settlement must take
    /// the delete arms' custody transaction over a superseded release
    /// the prefetch sidecar is still writing into, not remove it beside
    /// them and not simply come back in a minute.
    ///
    /// A prefetching row reads Queued and not `finalizing`, so the busy
    /// test cannot see its writers. The first half of the repair - the
    /// snapshot, the poke, and deferring to a later pass - shipped on
    /// 23 Aug and stopped the sidecar recreating files inside a deleted
    /// tree. What it left is what this asserts: the row stays in the
    /// queue for up to a whole pass, the directory is reserved by
    /// nobody, and the removal happens only when some later pass
    /// happens to find the sidecar gone. The custody route removes the
    /// row now, under its tombstone, and hands the FILES to
    /// `remove_after_sidecar_drain`, which holds the reservation until
    /// the last writer lets go and then removes them itself.
    ///
    /// The sidecar here is blocked exactly where the finding puts it:
    /// holding the slot, immediately before its final Ok.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settlement_hands_a_prefetching_predecessor_to_the_sidecar_drain() {
        let _steady = crate::smart::trash_globals_steady();
        let dir = tmp("sidecar");
        let d = test_daemon(&dir);
        completed(&d, &dir, "new2", "New.Show.S01E02.1080p.WEB-TEST");
        let old_out = queued(&d, &dir, "old2", "Old.Show.S01E02.720p.WEB-TEST");

        // The sidecar is mid-prefetch on the superseded release and
        // will not return until this test lets it.
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *d.sidecar.lock_ok() = Some(crate::serve::sidecar::Sidecar {
            nzo_id: "old2".into(),
            hub: Arc::new(crate::StreamHub::default()),
            progress: Arc::new(AtomicU64::new(0)),
            cancelled: cancelled.clone(),
            task: tokio::spawn(async {}),
            borrowed: false,
        });

        let mut state = crate::watchlist::WatchState::default();
        state.pending.push(pending("old2", "new2"));

        assert!(
            settle_pending_upgrades(&d, &mut state),
            "the settlement happened, so it is a state change"
        );
        assert!(
            state.pending.is_empty(),
            "the superseded row is gone, so there is nothing left to re-park - \
             deferring the whole settlement to a later pass leaves the directory \
             claimed by nobody in the meantime"
        );
        assert!(
            d.queue.lock_ok().is_empty(),
            "the superseded row must leave the queue under this settlement"
        );
        assert!(
            cancelled.load(std::sync::atomic::Ordering::Relaxed),
            "the sidecar must be told to stop before its directory is taken"
        );
        // The FILES are the drain's, and so is the reservation.
        assert!(
            old_out.join("part01.rar").exists(),
            "the files went while the sidecar was still writing into the directory"
        );
        assert!(
            d.reserved.lock_ok().contains(&old_out),
            "nothing reserved the directory, so `dir_claim` can hand it to a new \
             job in the window between the row going and the files"
        );

        // The sidecar winds down and clears its own slot.
        *d.sidecar.lock_ok() = None;
        // Wait on the LAST thing the drain does, exactly as
        // `a_delete_waits_for_the_sidecar_before_removing_its_files`
        // does and for the reason written there: it removes the files
        // and only then gives the reservation back.
        for _ in 0..200 {
            if !d.reserved.lock_ok().contains(&old_out) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(
            !old_out.exists(),
            "the drain never removed the superseded payload once the sidecar let go"
        );
        assert!(
            !d.reserved.lock_ok().contains(&old_out),
            "the drain owes the reservation back"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex sweep 24 Aug, F-05, the mover half: settlement must HOLD
    /// the mover's fence for the length of the removal, not read it
    /// once and act on the answer.
    ///
    /// `d.moving` is consulted by every actor that must stand off a
    /// payload in flight, and `mover_process` joins it by INSERTING and
    /// then running `relocate_completed` with no lock held - deliberately,
    /// because a move on a NAS is seconds and the queue must not stall
    /// behind it. Settlement read the set and went on to remove the
    /// files, so a move that started in between copied out of a
    /// directory that was being deleted: a half-published payload with
    /// no record naming either side.
    ///
    /// The mover is held exactly where the finding puts it - mid-copy,
    /// which here means "admitted and about to walk the source" - by
    /// running it from this thread while settlement sits on the custody
    /// seam. It must be REFUSED (`true` = busy, try again shortly),
    /// which is the answer `mover_process` was written to give and
    /// requeues the move rather than losing it.
    #[test]
    fn settlement_holds_the_movers_fence_while_it_removes() {
        let _steady = crate::smart::trash_globals_steady();
        let dir = tmp("mover");
        let d = test_daemon(&dir);
        completed(&d, &dir, "new3", "New.Show.S01E03.1080p.WEB-TEST");
        let old_out = completed(&d, &dir, "old3", "Old.Show.S01E03.720p.WEB-TEST");
        // A destination to move TO, so an admitted mover really does
        // relocate the payload rather than finding nothing to do.
        let done = dir.join("completed");
        std::fs::create_dir_all(&done).unwrap();
        *d.move_completed.write_ok() = Some(done.clone());
        let old_job = d
            .history
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == "old3")
            .cloned()
            .expect("the superseded record");
        old_job.lock_ok().move_pending = true;

        let open = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        *SETTLE_CUSTODY_BARRIER.lock_ok() =
            Some((d.spool.display().to_string(), open.clone(), release.clone()));

        let d2 = d.clone();
        let settler = std::thread::spawn(move || {
            let mut state = crate::watchlist::WatchState::default();
            state.pending.push(pending("old3", "new3"));
            let dirty = settle_pending_upgrades(&d2, &mut state);
            (dirty, state.pending.len())
        });

        // Settlement holds the superseded record's custody and has not
        // removed anything yet. This is the whole window.
        open.wait();
        let busy = d.mover_process(&old_job);
        assert!(
            busy,
            "the mover was admitted while settlement held the record - it would \
             have copied the payload out of a directory that is being deleted, \
             leaving a half-published move and no record naming either side"
        );
        assert!(
            old_out.join("payload.mkv").exists(),
            "the mover moved the superseded payload out from under the settlement"
        );
        release.wait();

        let (dirty, left) = settler.join().expect("the settlement");
        *SETTLE_CUSTODY_BARRIER.lock_ok() = None;
        assert!(dirty, "the settlement happened, so it is a state change");
        assert_eq!(left, 0, "the entry must not be re-parked");
        assert!(!old_out.exists(), "the superseded payload should be gone");
        assert!(
            !d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "old3"),
            "and its record with it"
        );
        assert!(
            !d.moving.lock_ok().contains("old3"),
            "the fence has to be given back, or every later mover and retry \
             stands off this id forever"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F3 (v1.2.4 tranche sweep, 28 Aug 2026): a history store that
    /// REFUSES the tombstone leaves the superseded record exactly as
    /// this pass found it - in memory, with its payload and its spool
    /// copy - and says nothing on the ring.
    ///
    /// The order used to be: delete the payload, drop the row from live
    /// memory, then attempt the tombstone and merely LOG a refusal.
    /// `Daemon::history_tombstone` is explicit that `false` means the
    /// removal is not durable and `history_replay` brings the row back
    /// at the next start, so the run ended with the record absent from
    /// memory, present on disk, and its content destroyed - and it still
    /// saved the watch state and emitted `watchlist.upgraded` to say the
    /// upgrade had settled. `Daemon::history_restore` exists for exactly
    /// that gap and this branch never called it. The restart then
    /// resurrected a row pointing at content that no longer existed,
    /// with a "download it again" its spool copy could no longer serve.
    ///
    /// The refusal is the real one rather than a hand-written fixture:
    /// `Store::HistoryAppend` and `Store::HistoryRewrite` together are a
    /// `history.jsonl` this daemon cannot write BY EITHER ROUTE, which
    /// is the permission fault P2-1 turns on - the append needs the
    /// FILE, the rescue rewrite needs only the DIRECTORY, so refusing
    /// one alone would heal.
    #[test]
    fn a_refused_tombstone_leaves_the_superseded_record_exactly_as_it_was() {
        use crate::serve::storecut::{Store, arm_store_cut, disarm};
        let _steady = crate::smart::trash_globals_steady();
        let dir = tmp("refusedtomb");
        let d = test_daemon(&dir);
        completed(&d, &dir, "new5", "New.Show.S01E05.1080p.WEB-TEST");
        let old_out = completed(&d, &dir, "old5", "Old.Show.S01E05.720p.WEB-TEST");
        let old_nzb = dir.join("old5.nzb");

        let mut state = crate::watchlist::WatchState::default();
        state.pending.push(pending("old5", "new5"));

        arm_store_cut(&[Store::HistoryAppend, Store::HistoryRewrite]);
        let dirty = settle_pending_upgrades(&d, &mut state);
        disarm();

        assert!(
            !dirty,
            "nothing settled, so there is no watch state to persist"
        );
        assert_eq!(
            state.pending.len(),
            1,
            "the delete has to stay pending, or a store that recovers never \
             gets asked again"
        );
        assert_eq!(state.pending[0].old_nzo, "old5");
        assert!(
            d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "old5"),
            "the row left live memory while the store still holds it - the next \
             start replays it, and everything below was destroyed under it"
        );
        assert!(
            old_out.join("payload.mkv").exists(),
            "the payload was destroyed on the strength of a removal that is not \
             durable, so the resurrected row points at content that is gone"
        );
        assert!(
            old_nzb.exists(),
            "the spool copy went, so the resurrected row has nothing to \
             re-download from"
        );
        let (events, _, _) = d.life_since(0);
        assert!(
            !events.iter().any(|e| e["kind"] == "watchlist.upgraded"),
            "a delete that did not happen must not be announced as one: {events:?}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ...and the far end of the same transaction: a payload the delete
    /// CANNOT remove leaves the record gone for good and reports the
    /// files kept.
    ///
    /// The two refusals are deliberately asymmetric and this is the half
    /// that says why. Before the tombstone nothing has been destroyed,
    /// so a refusal rewinds; after it the removal is DURABLE, so
    /// resurrecting the row to retry a destructive step is how one
    /// delete becomes two - the row would come back, settle again on the
    /// next pass, and delete whatever had taken that directory over in
    /// between. The user is told through the kept-files notice and the
    /// event's checked `fate` instead.
    ///
    /// The refusal is physical: the payload sits in a holder directory
    /// this process can read but not write, so the final `rmdir` inside
    /// `remove_user_dir` fails the way a read-only mount or a directory
    /// owned by another uid fails it.
    #[cfg(unix)]
    #[test]
    fn a_refused_payload_delete_keeps_the_record_gone_and_says_files_kept() {
        use std::os::unix::fs::PermissionsExt;
        let _steady = crate::smart::trash_globals_steady();
        let dir = tmp("refusedfiles");
        let d = test_daemon(&dir);
        completed(&d, &dir, "new6", "New.Show.S01E06.1080p.WEB-TEST");
        let stem = "Old.Show.S01E06.720p.WEB-TEST";
        let holder = dir.join("holder");
        let old_out = holder.join(stem);
        std::fs::create_dir_all(&old_out).unwrap();
        std::fs::write(old_out.join("payload.mkv"), b"x").unwrap();
        completed_naming(&d, &dir, "old6", stem, &old_out);

        let mut state = crate::watchlist::WatchState::default();
        state.pending.push(pending("old6", "new6"));

        std::fs::set_permissions(&holder, std::fs::Permissions::from_mode(0o555)).unwrap();
        let dirty = settle_pending_upgrades(&d, &mut state);
        std::fs::set_permissions(&holder, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(dirty, "the record was removed durably, so the state moved");
        assert!(
            state.pending.is_empty(),
            "a durably-deleted row must not be re-parked to retry a destructive \
             step against a directory that may since have been handed on"
        );
        assert!(
            !d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "old6"),
            "the tombstone was durable, so the row stays gone - bringing it back \
             would disagree with the store"
        );
        assert!(
            old_out.exists(),
            "the fixture never refused the removal, so this test proves nothing"
        );
        let (events, _, _) = d.life_since(0);
        let e = events
            .iter()
            .find(|e| e["kind"] == "watchlist.upgraded")
            .unwrap_or_else(|| panic!("no watchlist.upgraded on the ring: {events:?}"));
        assert_eq!(
            e["fate"], "kept",
            "a removal that was refused must not be reported as one"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod grab_miss_tests {
    use super::*;
    use crate::serve::testutil::test_daemon;

    /// An unknown (or disabled) indexer is a gate that short-circuited
    /// before anything was asked of anyone: `watchlist_grab` must answer
    /// [`GrabMiss::Transient`] so the caller does NOT bar the stem.
    /// Recording an early-gate miss cascades - each 60 s pass bars the
    /// item's next-best candidate for nothing, and an afternoon of
    /// exhausted daily budget (the same early-return shape as this one)
    /// walked the whole ranking onto the never-retry list (v1.2.4
    /// tranche sweep, 27 Aug 2026).
    #[test]
    fn a_missing_indexer_answers_transient_not_refused() {
        let dir = std::env::temp_dir().join(format!("nzbfast-grabmiss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = test_daemon(&dir);
        let src = CandSrc::External {
            url: "https://indexer.example/get?x=1".into(),
            indexer: "nobody-configured-this".into(),
            origin: crate::netfetch::SourceOrigin::unwitnessed("https://indexer.example/"),
        };
        let r = watchlist_grab(&d, &src, "some.release", "tv", false, "test");
        assert_eq!(
            r,
            Err(GrabMiss::Transient),
            "an early gate is not an enqueue refusal"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
