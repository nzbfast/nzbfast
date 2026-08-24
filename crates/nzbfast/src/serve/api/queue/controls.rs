//! The queue controls both API facades share: pause, priority, the
//! delete abort and the idle edge a delete leaves behind.
//!
//! Every function here exists because the SAB/API arm and the NZBGet
//! JSON-RPC arm had drifted apart on the same question, and which
//! client type the user happened to configure decided what their queue
//! did. They are a file rather than a stretch of `queue.rs` for the
//! same reason they are shared at all: the refusals are the contract,
//! and a reader looking for "what may a client do to a running job"
//! should find all of it in one place.
//!
//! Re-exported by the parent, so `crate::serve::api::queue::apply_pause`
//! and its siblings stay the paths every caller already uses.

use super::*;

/// Is this job inside its post-network tail - verifying, repairing or
/// unpacking?
///
/// `state == Downloading` cannot answer it: the record says Downloading
/// from the first article to the last extracted byte, so every queue
/// control that refuses to act on "the active download" was in fact
/// still acting on a job whose download had finished minutes ago. The
/// pipeline's own phase word is the answer, and the queue row is now
/// rendered from the same one, so a control that refuses here is a
/// control the user could already see was not on offer.
fn finishing_tail(d: &Arc<Daemon>, g: &Job) -> bool {
    // §129: the lane gave the tail its own state, so the answer no
    // longer leans on the phase word alone - but the Downloading+phase
    // arm stays for the moment between net-drain and lane submission,
    // which it reaches only because `tail_phase` maps the daemon's own
    // tail tokens too: `finalizing` mapped to nothing, so this said no.
    g.state == JobState::Finishing
        || (g.state == JobState::Downloading && d.tail_phase(&g.nzo_id).is_some())
}

/// Set (or clear) one job's pause flag, with the one refusal that makes
/// the flag mean anything. Returns whether the job took it.
///
/// There is nothing left to pause once the bytes are in: the
/// verify/repair/unpack tail and the move to the destination run to
/// completion whatever this flag says. Setting it anyway labelled a job
/// "paused" in every client while its files went on moving - and left
/// the flag SET, so a later auto-retry put the job back in the queue
/// with `paused` still true and `pick_job` skipped it forever (Codex
/// sweep 2, 3 Aug M4).
///
/// Shared so the SAB/API `mode=queue&name=pause` arm and the NZBGet
/// JSON-RPC `GroupPause` cannot drift: they had drifted, and which
/// client type the user happened to configure in Sonarr decided whether
/// a paused job could ever run again.
pub(in crate::serve) fn apply_pause(d: &Arc<Daemon>, g: &mut Job, pause: bool) -> bool {
    if pause && (g.state == JobState::Completed || finishing_tail(d, g)) {
        return false;
    }
    let was = g.paused;
    g.paused = pause;
    // A resume that puts a Queued row back under the idle predicate's
    // "busy" arm is a real queue transition, and only the add and the
    // runner's pick re-arm the idle latch - neither of which can happen
    // while a global pause or a guard hold keeps `pick_job` away. So
    // pause -> resume -> pause under a global pause announced the first
    // idle edge and swallowed the second, which is the one thing the
    // latch's "once per transition" contract promises not to do (Codex
    // sweep 14 Aug L2). Both callers hold the queue lock across this,
    // which is the same serialization the add's re-arm relies on
    // (daemon_enqueue.rs) and what keeps a concurrent notifier's
    // scan-to-CAS from emitting over a row this call just made runnable.
    //
    // `state == Queued` matches the predicate exactly and is
    // load-bearing: re-arming for a Completed or Finishing row would
    // make the `note_queue_idle()` the same handler calls a moment later
    // emit a second queue.idle over a queue that never left idle.
    if was && !pause && g.state == JobState::Queued {
        d.queue_idle_latch.store(false, Ordering::Relaxed);
    }
    true
}

/// The idle edge after a delete removed rows without a park. Deleting
/// the last queued job empties the queue with no park, so park's
/// queue.idle would never fire (M3, 10 Aug sweep). Not while an active
/// download is draining: it has left the queue but its pipeline has not
/// stopped, and its own park announces the real transition a moment
/// later.
///
/// Shared so the SAB/API delete arm and the NZBGet JSON-RPC delete
/// variants cannot drift (Codex sweep 14 Aug M4): the facade is a
/// hand-copy of the REST path and this is the second REST fix it
/// missed. Call after the rows are gone and no queue lock is held.
pub(in crate::serve) fn note_queue_idle_unless_active(d: &Daemon, stopped_active: bool) {
    if !stopped_active {
        d.note_queue_idle();
    }
}

/// Stop the transfer a delete just took the record away from - and keep
/// asking until the pipeline is actually listening.
///
/// `hub.abort` / `hub.queue_ctl` are published by `install_seek` partway
/// into the fetch, and the QueueControl stays INERT after that until the
/// pool run attaches its shared state to it (`QueueControl::abort`
/// answers false while its weak reference has nothing to upgrade). A
/// single shot aimed at either window is silently swallowed: the record
/// vanishes from the queue and the download it named runs its whole
/// ladder anyway. Measured 16 Aug 2026 on a delete issued the instant the
/// row read Downloading - "active download stopped by user" in the log,
/// then `sharding 200 connections` AFTER it, then a full minute of
/// `connect failed: Connection refused` against a host nothing was
/// waiting for. The pause path has re-fired for this exact reason since
/// M23e; delete never did, and it also DISARMS pause's loop, whose
/// wind-down check ("still in the queue, still suspended") a delete makes
/// false on the next pass.
///
/// So: fire, and if the pool did not take it, keep firing on the same
/// 250 ms cadence `suspend_matching` uses until it does. Bounded at the
/// same 60 s, which is far past any launch: a job that never attaches a
/// pool has already failed on its own by then.
///
/// Only ever aimed at the job named, by owner - never by
/// `state == Downloading` (see `owns_hub`): job N stays Downloading
/// through its whole disk tail while N+1 is on the wire holding these
/// handles, and this loop firing at the wrong one is the "deleted a
/// finished job, killed a healthy unrelated download" bug. While no slot
/// names one of ours the loop only WAITS - it never fires blind - so the
/// launch window (the record is Downloading, the pipeline has not
/// published yet) is covered without ever pointing the abort at a
/// stranger.
///
/// Both live slots count: the active hub AND the job draining behind it
/// since the cross-job hand-over, whose own handles moved into
/// `drain_dl` (see `Daemon::fire_drain`). Gating on `owns_hub` alone
/// left a deleted predecessor's metered traffic running to its own end,
/// with the loop waiting out its full 60 s because `was_ours` could
/// never become true for it.
///
/// Shared so the SAB/API delete arm and the NZBGet JSON-RPC delete
/// variants cannot drift, like the two helpers above it.
pub(in crate::serve) fn stop_deleted_transfer(d: &Arc<Daemon>, stopped: Vec<String>) {
    if stopped.is_empty() {
        return;
    }
    if fire_delete_abort(d, &stopped) {
        return;
    }
    let d = d.clone();
    std::thread::spawn(move || {
        // Whether the hub has ever named one of these jobs. Before it
        // does, another job's name means "ours has not launched yet" and
        // we wait; after it has, another name means the transfer we were
        // aiming at is over and there is nothing left to stop.
        let mut was_ours = false;
        for _ in 0..240 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            if d.owns_wire(|id| stopped.iter().any(|s| s == id)) {
                was_ours = true;
                if fire_delete_abort(&d, &stopped) {
                    return;
                }
            } else if was_ours {
                return;
            }
        }
        warn!(
            target: "queue",
            "{} was deleted mid-download but its pipeline never took the stop \
             signal - it will run to its own end",
            stopped.join(", ")
        );
    });
}

/// One shot of the delete abort, aimed only if the hub is still this
/// job's. Returns whether the POOL took it: the flag half is read after
/// the network phase and stops nothing by itself, so "delivered" can
/// only mean the QueueControl found a live run to abort.
fn fire_delete_abort(d: &Arc<Daemon>, stopped: &[String]) -> bool {
    if !d.owns_hub(|id| stopped.iter().any(|s| s == id)) {
        // Not the active transfer - but a job that handed the hub over
        // and is still draining behind the new one keeps its own stop
        // handles in the drain slot, and they are the only way to stop
        // its metered traffic. Aimed by id, so the successor is never
        // touched.
        return d.fire_drain(true, |id| stopped.iter().any(|s| s == id));
    }
    if let Some(f) = d.hub.abort.lock_ok().as_ref() {
        f.store(true, Ordering::Relaxed);
    }
    let landed = d
        .hub
        .queue_ctl
        .lock_ok()
        .as_ref()
        .is_some_and(|c| c.abort());
    if landed {
        info!(target: "queue", "active download stopped by user");
    }
    landed
}

/// Write one job's priority, releasing the states an explicit priority
/// is an instruction to release. Returns whether the job took it.
///
/// A duplicate hold is a PAUSE at priority -3, and the UI has always
/// told the user to raise the priority to download the copy anyway -
/// which did nothing at all, because `pick_job` skips a paused job
/// whatever its priority. An explicit priority write on a held
/// duplicate is that instruction, so it releases the hold here, exactly
/// as the failed-original promotion arm does (daemon.rs: paused=false,
/// priority=0). Only for -3: an ordinary paused job re-prioritised by a
/// client stays paused, which is what every SAB caller expects.
///
/// Refused on a job whose download is over for the same reason as
/// [`apply_pause`]: priority decides what starts NEXT, and clearing the
/// deferral and health waiver on a finished record is meaningless. A
/// held duplicate has never started, so that guard can never claim one.
/// Move a job whose priority just changed to the position it will
/// actually run in: the end of its new priority group (the first QUEUED
/// row with a lower priority; rows that are not Queued - active,
/// finishing - keep their place).
///
/// `pick_job` has always run Force and High ahead of queue order, but
/// nothing moved the ROW - so the dashboard's ⏫ toasted "Downloads
/// next" while the row sat exactly where it was, and the queue every
/// client renders showed an order the scheduler was not going to
/// follow. SAB moves the row on a priority write; now so do we. Both
/// priority arms (the SAB facade and the JSON-RPC GroupSetPriority)
/// call this after `apply_priority` lands, under the same queue lock.
pub(in crate::serve) fn reposition_for_priority(
    q: &mut std::collections::VecDeque<Arc<Mutex<Job>>>,
    id: &str,
) {
    let Some(from) = q.iter().position(|j| j.lock_ok().nzo_id == id) else {
        return;
    };
    let prio = {
        let g = q[from].lock_ok();
        // Only a queued row moves: the active download's position is
        // where the work is, and the switch arm refuses to move it too.
        if g.state != JobState::Queued {
            return;
        }
        g.priority
    };
    let Some(job) = q.remove(from) else { return };
    let to = q
        .iter()
        .position(|j| {
            let o = j.lock_ok();
            o.state == JobState::Queued && !o.tombstone && o.priority < prio
        })
        .unwrap_or(q.len());
    q.insert(to, job);
}

pub(in crate::serve) fn apply_priority(d: &Arc<Daemon>, g: &mut Job, prio: i32) -> bool {
    if g.state == JobState::Completed || finishing_tail(d, g) {
        return false;
    }
    if g.priority == -3 && g.paused {
        g.paused = false;
        // The re-arm this release owes, for the same reason the resume
        // owes one (see `apply_pause`): the row is runnable again, and
        // only the add and the runner's pick clear the latch - neither
        // of which can happen while a global pause keeps `pick_job`
        // away. `state == Queued` matches the idle predicate exactly, so
        // this can never make a later `note_queue_idle` emit over a
        // queue that never left idle (Fable sweep 15 Aug).
        if g.state == JobState::Queued {
            d.queue_idle_latch.store(false, Ordering::Relaxed);
        }
    }
    g.priority = prio;
    // Explicit priority overrides a watchdog deferral - and §77's
    // health sink, which is an advisory guess and does not get to argue
    // with an order the user has just given.
    g.deferred = false;
    if let Some(h) = g.health.as_mut() {
        h.waived = true;
    }
    true
}
