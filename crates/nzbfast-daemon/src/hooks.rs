//! §129 4a: how events leave the daemon - the post-job hook bundle
//! (script + notifications + failure report, moved verbatim from
//! daemon.rs), the 2e warning-event router, and the lifecycle webhook
//! dispatcher that turns ring events into signed, idempotent,
//! retried HTTP deliveries.
//!
//! The dispatcher's contract (design doc
//! research/DESIGN-2026-08-10-129-4a-hooks.md):
//!
//! - `life_emit` OFFERS every event with a try-send that can neither
//!   block nor fail the emitter. Delivery, signing and retries all
//!   happen off the emitter's thread; a full channel drops the event
//!   for webhooks (the ring itself is unaffected) and says so.
//! - One lane per target: a router thread reads the channel and does
//!   nothing but fan each event out, and a worker per target key owns
//!   that target's queue, its socket and its retry clock. A receiver
//!   that accepts and never answers therefore burns its own ten-second
//!   timeouts and fills its own [`PENDING_CAP`] backlog, and no healthy
//!   target waits behind it (M12, 10 Aug sweep).
//! - **Deliveries to one target keep the order its events happened
//!   in.** A lane is strictly FIFO and a deferred retry goes back on
//!   the head, so a consumer never sees `job.completed` before the
//!   `job.added` that preceded it. What order does NOT promise is
//!   completeness: a delivery dropped for exhausted retries or for a
//!   full backlog leaves a gap, and `seq` (in the body, and in the
//!   `delivery` handle) is how a consumer detects one. Across targets
//!   nothing is ordered - the lanes run concurrently on purpose.
//! - A webhook-kind notify target subscribes by naming lifecycle kinds
//!   in its `events` list - any token containing a dot (`job.added`,
//!   `queue.idle`), or a trailing-`.*` prefix wildcard (`job.*`). The
//!   dotless tokens keep their 2e human-notification meaning; the two
//!   routings coexist on one target.
//! - The POST body is the ring event verbatim plus a `delivery` key,
//!   `<boot>-<seq>` - seq restarts at boot, so that pair is the
//!   idempotency handle a consumer dedupes on. Headers:
//!   `X-NzbFast-Event` (kind), `X-NzbFast-Delivery` (same handle),
//!   and when the target carries a secret `X-NzbFast-Signature:
//!   sha256=<hex HMAC-SHA256 of the exact body bytes>` (GitHub's
//!   shape, so existing verifier snippets port).
//! - 2xx = delivered. Any other HTTP answer is terminal - the server
//!   spoke, redirects are off on purpose, and hammering a 404 or a
//!   signature-rejecting 401 with retries would only hide the
//!   misconfiguration. Transport errors (refused, DNS, timeout) retry
//!   on [`RETRY_AFTER`]'s backoff, then drop with a warning. Every
//!   outcome lands in `notify_health`, so the settings row shows it.

use super::script::Fence;
use super::*;
use std::time::Duration;

/// Has this record been handed to a NEW round since `gen0` was taken?
///
/// The RETRY half of `Daemon::record_generation` only, and this is the
/// one caller that may not ask the whole question. Every other fence
/// runs before `park`; the hook worker is detached and its caller parks
/// the instant it has spawned it - and `park` stamps a queue -> history
/// move of its own (§158 item 1), which bumps `move_seq`. Comparing the
/// pair therefore raced the park and dropped the pp-script and every
/// notification of an ORDINARY completion, at random (the daemon
/// suite's `sonarr_style_cycle` caught it within the hour). Filing a
/// finished job into history is not a change of custody; `retry`
/// bumping `retries` is exactly that, and it is what re-queues the
/// record this worker would otherwise be talking about.
fn retried_since(j: &Job, gen0: Option<(u32, u64)>) -> bool {
    gen0.is_some_and(|(retries, _)| j.retries != retries)
}

/// Test seam: the post-job hook worker trips it as its first act, once
/// it is on the blocking pool and before it has checked anything - the
/// window between the fenced PLAN and the unfenced side effects. First
/// barrier says the worker is in that window; second releases it, and is
/// waited a SECOND time by both sides once the fan-out is over, so a
/// test can assert what did and did not happen without polling.
///
/// Keyed by nzo_id, like `postproc::TAIL_GEN_BARRIER`: every completion
/// in this binary reaches this worker, the bin tests run in parallel,
/// and an unkeyed two-party barrier does not fail such a run, it HANGS
/// it (15 Aug, twice).
#[cfg(test)]
pub(crate) static HOOKS_GEN_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// What a finished job still owes the outside world, decided once and
/// then discharged - the post-processing script, the notification
/// targets, and whether a failure report is due on top.
struct PostJobOwed {
    /// §192: the ordered chain, empty = no script.
    script: Vec<PathBuf>,
    targets: Vec<crate::notify::Target>,
    failing: bool,
    /// Snapshotted beside the plan, never re-read in the worker - see
    /// the note at the snapshot site.
    cx: crate::notify::Ctx,
    /// The round the plan was decided on, so the detached worker can
    /// re-ask custody before each side effect ([`retried_since`]).
    gen0: Option<(u32, u64)>,
}

/// §129 2e: fire the notification targets routed onto a warning
/// event ("disk", "quota"). Cheap no-op unless a target actually
/// asked for the token; the send goes to the blocking pool - the
/// callers sit in the download runner.
pub fn notify_event(d: &Arc<Daemon>, event: &'static str, message: &str) {
    let targets = d.notify_targets.lock_ok().clone();
    if !targets
        .iter()
        .any(|t| t.enabled && t.events.iter().any(|e| e == event))
    {
        return;
    }
    let cx = crate::notify::Ctx::for_event(event, message);
    let d = d.clone();
    tokio::task::spawn_blocking(move || {
        let out = crate::notify::fire(&targets, &cx, unix_now());
        let mut health = d.notify_health.lock_ok();
        for (k, o) in out {
            health.insert(k, o);
        }
    });
}
/// The post-job hook fan-out, fenced to the round of the record's
/// life the caller started on. There is deliberately no unfenced
/// spelling: 5ac9c747b retired it as the footgun H1 was about.
///
/// A job ends in a long-running tail, and a delete verb plus a retry
/// can hand that record to a new generation while the tail is still
/// on its way here. Firing then is not a stale script run against a
/// dead job: it announces a completion (or a failure, and reports it
/// to the indexer, and re-grabs against it) for a release that is at
/// that moment sitting in the queue waiting to download again
/// (read-only sweep 2, H1 and M5). Read under the same hold as the
/// plan, because the plan is what the whole fan-out is decided from.
pub(crate) fn run_post_job_hooks_gen(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    gen0: Option<(u32, u64)>,
) {
    let Some(owed) = post_job_owed(d, job, gen0) else {
        return;
    };
    spawn_post_job(d, owed, job);
}

/// [`Self::run_post_job_hooks_gen`] with the post-processing SCRIPT
/// finished before this returns, for the one caller whose very next
/// statement is `park`.
///
/// `park` is what files the job into history, and history is where
/// a SAB client reads "Completed" - Sonarr imports on that word.
/// The script is the step of post-processing most likely to still
/// be MOVING the payload (a sorter, a renamer, a library filer),
/// which is precisely what the *arr is about to walk. Firing it
/// beside `park` rather than before it made the whole contract a
/// race: measured over 80 runs of `sonarr_style_cycle` at 20-way
/// parallelism the script landed 105-313 ms AFTER the history row,
/// and nothing whatever ordered the two -
/// the hook is dispatched to the blocking pool and `park` runs on
/// regardless, so a loaded box can widen that gap without limit.
/// That race is also the `sonarr_style_cycle` intermittent (a
/// "hook never ran" that goes green on a rerun): the suite asserts
/// the contract, and the product satisfied it by luck.
///
/// Only the script is awaited, and the rest is left exactly as it
/// was: `report_failure` can re-grab a replacement for the title
/// that just failed, and waiting for THAT before `park` would put
/// the replacement in the queue while the row it replaces is still
/// sitting in it - which is the ordering `park_gen`'s
/// promote-the-held-duplicate arm is written against. The
/// notifications ride along with it for the same reason: nothing
/// asked for them to move.
pub(crate) async fn run_post_job_hooks_before_park(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    gen0: Option<(u32, u64)>,
) {
    let Some(mut owed) = post_job_owed(d, job, gen0) else {
        return;
    };
    let chain = std::mem::take(&mut owed.script);
    if !chain.is_empty() {
        // The longest thing a tail can legitimately do - the chain is
        // bounded by `script_timeout_secs`, an hour by default - and
        // the one whose slowness is entirely the user's own to fix.
        // It has to name itself on the row.
        let id = job.lock_ok().nzo_id.clone();
        d.note_tail_stage(&id, "scripting");
        let (d, j) = (d.clone(), job.clone());
        if let Err(e) = tokio::task::spawn_blocking(move || {
            d.run_script_chain(&chain, &j, gen0, Fence::Generation)
        })
        .await
        {
            // A panicking script runner must not take the tail (and
            // with it `park`) down: the job is finished either way,
            // and a record stuck outside both stores is the worse
            // failure. Say so - this is the one place that knows.
            warn!(target: "script", "the post-processing hook did not finish: {e}");
        }
    }
    spawn_post_job(d, owed, job);
}

/// What this finished job still owes, decided on the caller's
/// thread and under one hold of the record.
///
/// `None` is "nothing at all", and it is deliberately noisy about
/// the one case that is not obvious from the outside: a record that
/// left the round the caller started on. A pp-script that never ran
/// is otherwise indistinguishable in a log from one that failed to
/// spawn, and telling those two apart is the whole of the diagnosis
/// when someone reports "my script did not run".
fn post_job_owed(
    d: &Daemon,
    job: &Arc<Mutex<Job>>,
    gen0: Option<(u32, u64)>,
) -> Option<PostJobOwed> {
    let script = d.resolve_scripts(job);
    let targets = d.notify_targets.lock_ok().clone();
    let mode = d.failure_link.lock_ok().clone();
    let secs = d.auto_retry_secs.load(Ordering::Relaxed);
    let g = job.lock_ok();
    if !Daemon::same_generation(&g, gen0) {
        info!(
            target: "script",
            "{}: no post-job hooks - the record left the round this tail started on",
            g.nzo_id
        );
        return None;
    }
    let failing = post_job_plan(&g, &mode, secs)?;
    // The notification context comes off the record HERE, under the
    // same hold as the plan, and rides into the worker as owned
    // data. It used to be read inside the worker, AFTER the
    // pp-script returned - so for a job deleted and retried while
    // that script ran (the documented case: "the script may still be
    // moving or renaming files"), the send described the RETRY
    // instead: an empty error and the retry's output directory,
    // routed to the targets that subscribe to the wrong outcome
    // (sweep 3, H3).
    let cx = notify_ctx_for(&g);
    Some(PostJobOwed {
        script,
        targets,
        failing,
        cx,
        gen0,
    })
}

/// Everything in [`PostJobOwed`] that is left, on the blocking
/// pool. Cheap no-op when nothing is owed.
fn spawn_post_job(d: &Arc<Daemon>, owed: PostJobOwed, job: &Arc<Mutex<Job>>) {
    let PostJobOwed {
        script,
        targets,
        failing,
        cx,
        gen0,
    } = owed;
    if script.is_empty() && targets.is_empty() && !failing {
        return;
    }
    let d = d.clone();
    let job = job.clone();
    tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        let seam = {
            // The id is read BEFORE the seam lock (see
            // `daemon_park`): a job lock taken under the seam guard
            // would order the two the other way round from every
            // other reader of this record.
            let id = job.lock_ok().nzo_id.clone();
            HOOKS_GEN_BARRIER
                .lock_ok()
                .clone()
                .filter(|(k, _, _)| *k == id)
        };
        #[cfg(test)]
        if let Some((_, open, release)) = &seam {
            open.wait();
            release.wait();
        }
        // A closure so the seam's completion rendezvous below is
        // reached on every early return, not just the last one.
        let fan_out = move || {
            // The plan was fenced; the SIDE EFFECTS were not. This
            // worker is detached and the caller parks straight after
            // it, so a delete verb plus a Retry can land between the
            // two - and then the script runs inside a live
            // download's folder, and the targets are told that a
            // release which is at that moment queued has finished.
            // Asked again below, because the script in between can
            // run for minutes.
            if retried_since(&job.lock_ok(), gen0) {
                return;
            }
            if !script.is_empty() {
                // gen0 again, inside: the check above is a statement
                // earlier than the record read it guards.
                // RetriesOnly, NOT the pair: this caller parked the
                // instant it spawned us, and park stamps a move of
                // its own. Asking the pair here is the race
                // `retried_since` above exists to avoid.
                d.run_script_chain(&script, &job, gen0, Fence::RetriesOnly);
            }
            if !targets.is_empty() && !retried_since(&job.lock_ok(), gen0) {
                // §G: keep what each delivery did, so the settings
                // row can say "last send failed: HTTP 401". The map
                // is keyed by kind+url+name and only ever grows to
                // the number of targets the user has configured.
                let out = crate::notify::fire(&targets, &cx, unix_now());
                let mut health = d.notify_health.lock_ok();
                for (k, o) in out {
                    health.insert(k, o);
                }
            }
            // Last: a webhook that reports failures should say so
            // before a replacement for the same title appears in the
            // queue.
            if failing {
                d.report_failure(&job);
            }
        };
        fan_out();
        #[cfg(test)]
        if let Some((_, _, done)) = &seam {
            // Second rendezvous on the SAME barrier: the test has
            // released the worker, and this says the fan-out is
            // over. Both sides wait twice, so the pairing holds.
            done.wait();
        }
    });
}

/// Offer one ring event to the lifecycle dispatcher. Called by
/// `life_emit` once the event is in the ring and with the ring lock
/// released - a dispatcher that is behind must never be able to
/// stall an emitter or a poll; never blocks either way. The
/// cheap pre-filter keeps the channel silent unless some enabled
/// webhook target actually subscribed to lifecycle kinds.
pub(crate) fn hooks_offer(d: &Daemon, event: &Value) {
    let Some(kind) = event["kind"].as_str() else {
        return;
    };
    if !d.notify_targets.lock_ok().iter().any(|t| {
        t.enabled && t.kind == crate::notify::Kind::Webhook && wants_lifecycle(&t.events, kind)
    }) {
        return;
    }
    let tx = d.hooks_tx.lock_ok();
    if let Some(tx) = tx.as_ref()
        && tx.try_send(event.clone()).is_err()
    {
        // Full channel = a receiver that cannot keep up. The ring
        // and the dashboard are unaffected; only webhooks lose this
        // event, and the log says which.
        warn!(
            target: "hooks",
            "webhook queue full - dropping {kind} (seq {})",
            event["seq"].as_u64().unwrap_or(0)
        );
    }
}

/// Re-point a RETRY at its target's current configuration. Returns false
/// when the delivery must be abandoned: the target is gone or has been
/// switched off since the event fired.
///
/// A pending delivery snapshots url, secret and body, and a transient
/// failure can hold it for minutes. Without this, an operator who
/// disabled a webhook, deleted it, or rotated its secret still had the
/// old URL contacted with the old credential afterwards - the one thing
/// rotating a secret is supposed to stop (L1, 10 Aug sweep). The URL is
/// re-read for the same reason; the body is not, because it describes an
/// event that did happen.
fn refresh_target(p: &mut Pending, targets: &[crate::notify::Target]) -> bool {
    let Some(t) = targets
        .iter()
        .find(|t| crate::notify::target_key(t) == p.key)
    else {
        info!(
            target: "hooks",
            "{}: {} delivery dropped - the target is gone", p.name, p.kind
        );
        return false;
    };
    if !t.enabled {
        info!(
            target: "hooks",
            "{}: {} delivery dropped - the target is switched off", p.name, p.kind
        );
        return false;
    }
    p.url = t.url.trim().trim_end_matches('/').to_string();
    p.secret = t.secret.clone();
    true
}

/// Does this target's `events` list subscribe it to lifecycle `kind`?
/// Exact dotted tokens and trailing-`.*` prefix wildcards only - the
/// dotless 2e tokens never match here, and unknown names simply never
/// fire (same forgiving contract as 2e routing).
pub(crate) fn wants_lifecycle(events: &[String], kind: &str) -> bool {
    events.iter().any(|e| {
        let e = e.trim();
        if let Some(prefix) = e.strip_suffix(".*") {
            !prefix.is_empty()
                && kind
                    .strip_prefix(prefix)
                    .is_some_and(|r| r.starts_with('.'))
        } else {
            e.contains('.') && e == kind
        }
    })
}

/// How many deliveries may wait in ONE target's lane before its oldest
/// is dropped. Per target, not shared: a receiver that never answers
/// fills its own lane and costs every other target nothing (M12, 10 Aug
/// sweep). A stuck target therefore holds at most this much memory, and
/// the bill scales with the number of webhook targets a user configured.
const PENDING_CAP: usize = 512;

/// A lane with nothing left to send retires after this long, so a target
/// that was renamed, re-pointed or deleted does not leave a thread
/// parked for the life of the daemon. The next event for that target
/// starts a fresh lane.
const LANE_IDLE_EXIT: Duration = Duration::from_secs(60);

/// Backoff after a failed transport attempt: first retry in 10 s, then
/// 60 s, then 5 min, then the delivery is dropped (with its outcome
/// recorded). Overridable for tests via `Dispatcher::retry_after`.
const RETRY_AFTER: &[Duration] = &[
    Duration::from_secs(10),
    Duration::from_secs(60),
    Duration::from_secs(300),
];

/// One delivery attempt not yet resolved.
pub struct Pending {
    /// `notify::target_key` of the target this goes to, for health.
    key: String,
    /// Target name for logs (never the URL - it is a capability).
    name: String,
    url: String,
    secret: String,
    kind: String,
    delivery: String,
    body: String,
    attempt: usize,
    due: Instant,
}

/// One target's delivery lane: the FIFO of everything owed to it, and
/// the condvar its worker sleeps on between events and retries.
#[derive(Default)]
pub struct Lane {
    q: Mutex<LaneQueue>,
    wake: std::sync::Condvar,
}

#[derive(Default)]
struct LaneQueue {
    pending: VecDeque<Pending>,
    /// The router is going away (the daemon dropped its sender); the
    /// worker stops at its next chance instead of finishing the queue.
    closed: bool,
    /// The worker has left - idle for [`LANE_IDLE_EXIT`], or closed.
    /// Set under the lock, so an offer that reads it false is
    /// guaranteed to be seen by a worker that is still there.
    retired: bool,
}

/// The router. Reads the event channel and fans each event out to the
/// lanes of the targets subscribed to it - and does nothing else, so
/// however wedged a receiver is, the 256-slot channel behind
/// `hooks_offer` drains at memory speed.
pub(crate) struct Dispatcher {
    rx: std::sync::mpsc::Receiver<Value>,
    d: std::sync::Weak<Daemon>,
    boot: u64,
    lanes: std::collections::HashMap<String, Arc<Lane>>,
    retry_after: &'static [Duration],
}

/// Spawn the dispatcher thread and hand its sender to the daemon.
/// Called once at boot (and by the test daemon); the thread exits when
/// the daemon is dropped or the channel closes.
pub fn spawn_dispatcher(d: &Arc<Daemon>) {
    let (tx, rx) = std::sync::mpsc::sync_channel(256);
    *d.hooks_tx.lock_ok() = Some(tx);
    let boot = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let disp = Dispatcher {
        rx,
        d: Arc::downgrade(d),
        boot,
        lanes: std::collections::HashMap::new(),
        retry_after: RETRY_AFTER,
    };
    // Through the census like every other long-lived lane: it already
    // holds the daemon weakly and exits when the channel closes, so it
    // never leaked - but the reclamation test can only prove that if it
    // is counted.
    crate::spawn_aux("hooks", move || disp.run());
}

impl Dispatcher {
    pub fn run(mut self) {
        // No timers here: each lane owns its own retry clock, so the
        // router only ever blocks on the channel.
        while let Ok(ev) = self.rx.recv() {
            self.enqueue(&ev);
        }
        // The daemon dropped its sender. Stop the lanes with it, rather
        // than let one sit in a 10 s POST for a generation that is gone.
        for lane in self.lanes.values() {
            lane.q.lock_ok().closed = true;
            lane.wake.notify_all();
        }
    }

    /// Fan one event out to every subscribed target as a Pending.
    pub fn enqueue(&mut self, ev: &Value) {
        let Some(d) = self.d.upgrade() else { return };
        let Some(kind) = ev["kind"].as_str().map(str::to_string) else {
            return;
        };
        let seq = ev["seq"].as_u64().unwrap_or(0);
        let delivery = format!("{}-{seq}", self.boot);
        let mut body_v = ev.clone();
        if let Some(o) = body_v.as_object_mut() {
            o.insert("delivery".into(), json!(delivery));
        }
        let body = body_v.to_string();
        let targets = d.notify_targets.lock_ok().clone();
        for t in targets.iter().filter(|t| {
            t.enabled
                && t.kind == crate::notify::Kind::Webhook
                && wants_lifecycle(&t.events, &kind)
                && category_ok(t, ev)
        }) {
            self.push(Pending {
                key: crate::notify::target_key(t),
                name: if t.name.is_empty() {
                    "webhook".into()
                } else {
                    t.name.clone()
                },
                url: t.url.trim().trim_end_matches('/').to_string(),
                secret: t.secret.clone(),
                kind: kind.clone(),
                delivery: delivery.clone(),
                body: body.clone(),
                attempt: 0,
                due: Instant::now(),
            });
        }
    }

    /// Hand one delivery to its target's lane, starting the lane if this
    /// is the first event that target has been owed.
    pub fn push(&mut self, p: Pending) {
        let lane = self.lane(&p.key);
        let Some(p) = offer(&lane, p) else { return };
        // The lane retired between two events for the same target (or
        // never started): a fresh one takes the delivery.
        self.lanes.remove(&p.key);
        let lane = self.lane(&p.key);
        if offer(&lane, p).is_some() {
            warn!(target: "hooks", "no webhook lane to deliver on - event dropped");
        }
    }

    /// This target's lane, spawning its worker on first use.
    pub fn lane(&mut self, key: &str) -> Arc<Lane> {
        if let Some(lane) = self.lanes.get(key) {
            return lane.clone();
        }
        let lane = Arc::new(Lane::default());
        let worker = LaneWorker {
            lane: lane.clone(),
            d: self.d.clone(),
            retry_after: self.retry_after,
        };
        // Through the census like the router itself: a lane holds the
        // daemon weakly and stops when the router closes it, and the
        // reclamation proof only covers what it can count.
        crate::spawn_aux("hooks-lane", move || worker.run());
        self.lanes.insert(key.to_string(), lane.clone());
        lane
    }
}

/// Put one delivery on a lane's tail. Returns it back when the lane is
/// no longer live, so the caller can start a replacement; the check and
/// the push are one critical section, so a worker cannot retire in
/// between and strand the event.
pub fn offer(lane: &Lane, p: Pending) -> Option<Pending> {
    let mut q = lane.q.lock_ok();
    if q.retired || q.closed {
        return Some(p);
    }
    if q.pending.len() >= PENDING_CAP {
        // The oldest is the one at the head being retried into a
        // receiver that will not take it, so dropping it is also what
        // lets the rest of this target's backlog move.
        let dropped = q.pending.pop_front();
        warn!(
            target: "hooks",
            "{}: webhook backlog at {PENDING_CAP} - dropping the oldest ({})",
            p.name,
            dropped.as_ref().map(|p| p.kind.as_str()).unwrap_or("?"),
        );
    }
    q.pending.push_back(p);
    lane.wake.notify_all();
    None
}

/// One target's sender: the only thread that ever posts to that target,
/// draining its lane strictly in order.
struct LaneWorker {
    lane: Arc<Lane>,
    d: std::sync::Weak<Daemon>,
    retry_after: &'static [Duration],
}

impl LaneWorker {
    pub fn run(self) {
        while let Some(mut p) = self.next_due() {
            // A generation that is gone has nothing left to deliver for
            // and nowhere to record an outcome.
            let Some(d) = self.d.upgrade() else { return };
            // The current targets, re-read for THIS attempt: a delivery
            // being retried minutes later must answer to the
            // configuration as it is now, not as it was when the event
            // fired. See `refresh_target`.
            if p.attempt > 0 {
                let targets = d.notify_targets.lock_ok().clone();
                if !refresh_target(&mut p, &targets) {
                    continue;
                }
            }
            // Never hold the Arc across the send: ten seconds on a wedged
            // socket must not be ten seconds a stop cannot reclaim in.
            drop(d);
            match post_event(&p) {
                Ok(code) => self.record(&p, code, String::new(), false),
                Err(SendErr::Terminal(code, e)) => self.record(&p, code, e, false),
                Err(SendErr::Transient(e)) => {
                    if p.attempt < self.retry_after.len() {
                        p.due = Instant::now() + self.retry_after[p.attempt];
                        p.attempt += 1;
                        // Back on the HEAD, not the tail: this target's
                        // deliveries keep the order its events happened
                        // in, and the wait is nobody else's.
                        self.lane.q.lock_ok().pending.push_front(p);
                    } else {
                        warn!(
                            target: "hooks",
                            "{}: {} delivery gave up after {} attempts: {e}",
                            p.name,
                            p.kind,
                            p.attempt + 1
                        );
                        self.record(&p, 0, e, true);
                    }
                }
            }
        }
    }

    /// Block until the head of the lane is due, and take it. `None` ends
    /// the worker: the router closed the lane, or nothing has been owed
    /// to this target for [`LANE_IDLE_EXIT`].
    pub fn next_due(&self) -> Option<Pending> {
        let mut q = self.lane.q.lock_ok();
        loop {
            if q.closed {
                q.retired = true;
                return None;
            }
            let head = q.pending.front().map(|p| p.due);
            let wait = match head {
                None => LANE_IDLE_EXIT,
                Some(due) => {
                    let now = Instant::now();
                    if due <= now {
                        return q.pending.pop_front();
                    }
                    due - now
                }
            };
            let idle = head.is_none();
            let (guard, timed) = self
                .lane
                .wake
                .wait_timeout(q, wait)
                .unwrap_or_else(|e| e.into_inner());
            q = guard;
            if idle && timed.timed_out() && q.pending.is_empty() {
                q.retired = true;
                return None;
            }
        }
    }

    /// One outcome into notify_health, so the target's settings row
    /// reports lifecycle deliveries exactly like notification sends.
    pub fn record(&self, p: &Pending, code: u16, error: String, gave_up: bool) {
        let Some(d) = self.d.upgrade() else { return };
        if error.is_empty() {
            info!(target: "hooks", "{}: {} delivered ({code})", p.name, p.kind);
        } else if !gave_up {
            warn!(target: "hooks", "{}: {} failed: {}", p.name, p.kind, error);
        }
        d.notify_health.lock_ok().insert(
            p.key.clone(),
            crate::notify::Outcome {
                at: unix_now(),
                code,
                error,
                test: false,
            },
        );
    }
}

/// The 2e category rule, applied to events that carry a category: a
/// category-filtered target only hears about its own jobs, and never
/// hears the category-less kinds (queue.idle, disk.low...) - exactly
/// how notification routing treats warning events.
fn category_ok(t: &crate::notify::Target, ev: &Value) -> bool {
    if t.category.trim().is_empty() {
        return true;
    }
    ev["category"]
        .as_str()
        .is_some_and(|c| c.eq_ignore_ascii_case(t.category.trim()))
}

enum SendErr {
    /// The server (or the config) spoke: do not retry. Carries the
    /// HTTP status when there was one.
    Terminal(u16, String),
    /// The wire failed: retry on the backoff.
    Transient(String),
}

/// POST one delivery. 2xx = Ok(status); any other HTTP answer is
/// terminal (the server spoke - retrying a 404/401 hides the
/// misconfiguration, and redirects are off on purpose); a transport
/// failure is transient and retried.
fn post_event(p: &Pending) -> Result<u16, SendErr> {
    if !(p.url.starts_with("http://") || p.url.starts_with("https://")) {
        // Same wording as notify's gate, and like it, never the URL.
        return Err(SendErr::Terminal(
            0,
            "url must start with http:// or https://".into(),
        ));
    }
    let a = ssrf_safe_agent(0, 10);
    let req = a
        .post(&p.url)
        .set("Content-Type", "application/json")
        .set("X-NzbFast-Event", &p.kind)
        .set("X-NzbFast-Delivery", &p.delivery);
    let req = if p.secret.is_empty() {
        req
    } else {
        req.set(
            "X-NzbFast-Signature",
            &crate::notify::sign(&p.secret, p.body.as_bytes()),
        )
    };
    match req.send_string(&p.body) {
        Ok(r) => Ok(r.status()),
        Err(ureq::Error::Status(code, _)) => Err(SendErr::Terminal(code, format!("HTTP {code}"))),
        Err(ureq::Error::Transport(t)) => {
            Err(SendErr::Transient(crate::notify::transport_brief(&t)))
        }
    }
}

/// The job's facts, taken from a hold the CALLER already owns.
///
/// It lives HERE and not on `notify::Ctx` (TODO 276 item 3): reading a
/// `Job` was the only thing `crate::notify` needed from `serve`, and it
/// held the whole notification module inside the daemon's dependency
/// cycle for one constructor with one caller. `Ctx`'s fields are all
/// `pub`, so the struct literal reads the same from this side.
///
/// It used to take the Arc and lock for itself, which read the
/// record wherever the caller happened to have got to. The post-job
/// hooks decide their whole fan-out under one hold and then run on
/// the blocking pool, where a pp-script can hold the thread for
/// minutes - so the send described whatever the record had become by
/// then: for a job deleted and retried mid-script, a "Failed" event
/// with an empty error naming the RETRY's directory (Codex sweep 3,
/// H3). One hold, one snapshot, and nothing to drift.
pub(super) fn notify_ctx_for(j: &Job) -> crate::notify::Ctx {
    let ok = j.state == JobState::Completed;
    crate::notify::Ctx {
        name: j.name.clone(),
        status: if ok { "Completed" } else { "Failed" },
        category: j.category.clone(),
        dir: j.out_dir.to_string_lossy().into_owned(),
        bytes: j.total_bytes,
        error: j.fail_message.clone(),
        nzo_id: j.nzo_id.clone(),
        event: if ok { "completed" } else { "failed" }.into(),
        repaired: j.bad_blocks.unwrap_or(0) > 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{Kind, Target};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    fn scratch(name: &str) -> crate::testscratch::ScratchDir {
        let dir = std::env::temp_dir().join(format!("nzbfast-hooks-{name}-{}", std::process::id()));
        crate::testscratch::ScratchDir::attach(&dir)
    }

    fn target(url: &str, events: &[&str], secret: &str) -> Target {
        Target {
            name: "hooktest".into(),
            kind: Kind::Webhook,
            url: url.into(),
            token: String::new(),
            body: String::new(),
            enabled: true,
            on_failure: false,
            category: String::new(),
            events: events.iter().map(|s| s.to_string()).collect(),
            email_to: String::new(),
            email_from: String::new(),
            secret: secret.into(),
        }
    }

    /// The real dispatcher wiring, with a test-tiny retry backoff in
    /// place of [`RETRY_AFTER`]'s minutes.
    fn fast_dispatcher(d: &Arc<Daemon>, retry_after: &'static [Duration]) {
        let (tx, rx) = std::sync::mpsc::sync_channel(16);
        *d.hooks_tx.lock_ok() = Some(tx);
        let disp = Dispatcher {
            rx,
            d: Arc::downgrade(d),
            boot: 1,
            lanes: std::collections::HashMap::new(),
            retry_after,
        };
        std::thread::spawn(move || disp.run());
    }

    /// One accepted request: (headers, body), answered `status`.
    fn accept_one(l: &TcpListener, status: &str) -> (String, String) {
        let (mut s, _) = l.accept().expect("accept");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let (head_end, body_len) = loop {
            let n = s.read(&mut buf).expect("read");
            assert!(n > 0, "peer closed mid-request");
            raw.extend_from_slice(&buf[..n]);
            if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..at]).to_string();
                let len = head
                    .to_ascii_lowercase()
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().to_string())
                    })
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                break (at + 4, len);
            }
        };
        while raw.len() < head_end + body_len {
            let n = s.read(&mut buf).expect("read body");
            assert!(n > 0);
            raw.extend_from_slice(&buf[..n]);
        }
        let _ = s.write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        (
            String::from_utf8_lossy(&raw[..head_end]).to_string(),
            String::from_utf8_lossy(&raw[head_end..head_end + body_len]).to_string(),
        )
    }

    /// A retry answers to the configuration as it is NOW.
    ///
    /// A pending delivery snapshots url, secret and body, and a
    /// transient failure holds it for minutes. It used to be replayed
    /// verbatim, so an operator who switched a webhook off, deleted it,
    /// or rotated its secret still had the old credential sent
    /// afterwards - the one thing rotating a secret is meant to stop
    /// (L1, 10 Aug sweep).
    #[test]
    fn a_retry_re_reads_its_target_before_sending() {
        let live = target("http://127.0.0.1:9/hook", &["job.*"], "old-secret");
        let mut p = Pending {
            key: crate::notify::target_key(&live),
            name: live.name.clone(),
            url: live.url.clone(),
            secret: live.secret.clone(),
            kind: "job.completed".into(),
            delivery: "1-1".into(),
            body: "{}".into(),
            attempt: 1,
            due: Instant::now(),
        };
        // Rotated secret: the delivery goes on, with the new one.
        let mut rotated = live.clone();
        rotated.secret = "new-secret".into();
        assert!(refresh_target(&mut p, std::slice::from_ref(&rotated)));
        assert_eq!(p.secret, "new-secret");
        // Switched off, and then deleted: the delivery is abandoned.
        let mut off = rotated.clone();
        off.enabled = false;
        assert!(!refresh_target(&mut p, std::slice::from_ref(&off)));
        assert!(!refresh_target(&mut p, &[]));
    }

    #[test]
    fn lifecycle_tokens_route_and_legacy_tokens_do_not() {
        let ok = |evs: &[&str], kind: &str| {
            wants_lifecycle(&evs.iter().map(|s| s.to_string()).collect::<Vec<_>>(), kind)
        };
        assert!(ok(&["job.added"], "job.added"));
        assert!(!ok(&["job.added"], "job.started"));
        assert!(ok(&["job.*"], "job.started"));
        assert!(!ok(&["job.*"], "queue.idle"));
        assert!(ok(&["completed", "queue.idle"], "queue.idle"));
        // The dotless 2e tokens never subscribe to ring kinds...
        assert!(!ok(&["completed", "failed"], "job.completed"));
        // ...and a bare star is not a subscription either.
        assert!(!ok(&["*"], "job.added"));
        assert!(!ok(&[".*"], "job.added"));
    }

    /// The full path: life_emit -> offer -> dispatcher -> signed POST.
    /// Asserts headers, the idempotency handle, a verifiable signature,
    /// and the outcome landing in notify_health.
    #[test]
    fn an_event_is_delivered_signed_and_recorded() {
        let dir = scratch("signed");
        let d = testutil::test_daemon(&dir);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        *d.notify_targets.lock_ok() = vec![target(&url, &["job.*"], "s3cret")];
        spawn_dispatcher(&d);

        d.life_emit("job.added", json!({"name": "X", "category": "tv"}));
        let (head, body) = accept_one(&l, "200 OK");
        assert!(head.contains("X-NzbFast-Event: job.added"), "{head}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["kind"], "job.added", "{v}");
        assert_eq!(v["schema_version"], 1, "{v}");
        let delivery = v["delivery"].as_str().expect("delivery id");
        assert!(
            head.contains(&format!("X-NzbFast-Delivery: {delivery}")),
            "{head}"
        );
        let sig = crate::notify::sign("s3cret", body.as_bytes());
        assert!(
            head.contains(&format!("X-NzbFast-Signature: {sig}")),
            "{head}"
        );
        // Recorded as the target's last send.
        let key = crate::notify::target_key(&d.notify_targets.lock_ok()[0]);
        for _ in 0..100 {
            if d.notify_health.lock_ok().contains_key(&key) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let h = d.notify_health.lock_ok();
        let o = h.get(&key).expect("outcome recorded");
        assert_eq!(o.code, 200);
        assert!(o.error.is_empty(), "{}", o.error);
    }

    /// An unsubscribed kind never leaves the daemon: the offer
    /// pre-filter refuses it before the channel.
    #[test]
    fn an_unsubscribed_kind_is_not_delivered() {
        let dir = scratch("filter");
        let d = testutil::test_daemon(&dir);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        *d.notify_targets.lock_ok() = vec![target(&url, &["job.*"], "")];
        spawn_dispatcher(&d);
        d.life_emit("queue.idle", json!({}));
        d.life_emit("job.added", json!({"name": "Y"}));
        // The FIRST request to arrive is already the job.added - the
        // queue.idle was filtered, not queued ahead of it.
        let (_, body) = accept_one(&l, "200 OK");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["kind"], "job.added", "{v}");
    }

    /// A target that accepts the connection and then answers nothing
    /// costs its own lane ten seconds per attempt - and costs a healthy
    /// target sitting beside it nothing at all.
    ///
    /// Serially (one thread, one queue) the healthy target waited out
    /// the black hole's full agent timeout for every event, and a burst
    /// against a wedged receiver could fill the shared backlog and drop
    /// deliveries meant for targets that were answering perfectly
    /// (M12, 10 Aug sweep).
    #[test]
    fn a_black_holing_target_cannot_delay_a_healthy_one() {
        let dir = scratch("isolation");
        let d = testutil::test_daemon(&dir);

        // Accepts, then says nothing ever. The accepted sockets are
        // parked in a Vec so they stay open, and the thread blocks in
        // accept() for the rest of the test.
        let black = TcpListener::bind("127.0.0.1:0").unwrap();
        let black_url = format!("http://{}", black.local_addr().unwrap());
        std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((s, _)) = black.accept() {
                held.push(s);
            }
        });
        let good = TcpListener::bind("127.0.0.1:0").unwrap();
        let good_url = format!("http://{}", good.local_addr().unwrap());

        let mut wedged = target(&black_url, &["job.*"], "");
        wedged.name = "wedged".into();
        let mut healthy = target(&good_url, &["job.*"], "");
        healthy.name = "healthy".into();
        // The wedged one FIRST, which is the order a serial dispatcher
        // would have met them in.
        *d.notify_targets.lock_ok() = vec![wedged, healthy];
        spawn_dispatcher(&d);

        let started = Instant::now();
        d.life_emit("job.added", json!({"name": "A"}));
        d.life_emit("job.completed", json!({"name": "A"}));
        let (_, first) = accept_one(&good, "200 OK");
        let (_, second) = accept_one(&good, "200 OK");
        let waited = started.elapsed();
        let a: Value = serde_json::from_str(&first).unwrap();
        let b: Value = serde_json::from_str(&second).unwrap();
        assert_eq!(a["kind"], "job.added", "{a}");
        assert_eq!(b["kind"], "job.completed", "{b}");
        // One shared queue put a full ten-second timeout in front of
        // each of these; its own lane puts none.
        assert!(
            waited < Duration::from_secs(5),
            "the healthy target waited {waited:?} behind a black hole"
        );
    }

    /// Within one target, a deferred delivery is not overtaken: the
    /// event that failed first still arrives first.
    ///
    /// The old dispatcher kept one due-ordered queue, so a transient
    /// failure on event 1 handed the wire to event 2 and the consumer
    /// saw job.completed before job.added (L3, 10 Aug sweep).
    #[test]
    fn one_target_keeps_its_events_in_order_across_a_retry() {
        let dir = scratch("order");
        let d = testutil::test_daemon(&dir);
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = dead.local_addr().unwrap();
        drop(dead);

        const FAST_RETRY: &[Duration] = &[Duration::from_millis(200)];
        fast_dispatcher(&d, FAST_RETRY);
        *d.notify_targets.lock_ok() = vec![target(&format!("http://{addr}"), &["job.*"], "")];

        // Event one is refused and deferred...
        d.life_emit("job.added", json!({"name": "one"}));
        std::thread::sleep(Duration::from_millis(60));
        // ...and the receiver only comes up now, so event two would be
        // deliverable at once if anything were allowed to overtake.
        let l = TcpListener::bind(addr).expect("rebind the same port");
        d.life_emit("job.completed", json!({"name": "two"}));

        let (_, first) = accept_one(&l, "200 OK");
        let (_, second) = accept_one(&l, "200 OK");
        let a: Value = serde_json::from_str(&first).unwrap();
        let b: Value = serde_json::from_str(&second).unwrap();
        assert_eq!(a["name"], "one", "the deferred event must still land first");
        assert_eq!(b["name"], "two", "{b}");
        assert!(
            a["seq"].as_u64() < b["seq"].as_u64(),
            "{} then {}",
            a["seq"],
            b["seq"]
        );
    }

    /// Transport failure retries on the (test-tiny) backoff and lands;
    /// an HTTP error answer is terminal and never retried.
    #[test]
    fn transport_failures_retry_and_http_answers_do_not() {
        let dir = scratch("retry");
        let d = testutil::test_daemon(&dir);

        // A port with nothing listening: first attempt is refused.
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = dead.local_addr().unwrap();
        drop(dead);

        const FAST_RETRY: &[Duration] = &[Duration::from_millis(80)];
        fast_dispatcher(&d, FAST_RETRY);

        // Refused now; a listener appears before the 80 ms retry.
        *d.notify_targets.lock_ok() = vec![target(&format!("http://{addr}"), &["job.*"], "")];
        d.life_emit("job.added", json!({"name": "R"}));
        std::thread::sleep(Duration::from_millis(30));
        let l = TcpListener::bind(addr).expect("rebind the same port");
        let (head, _) = accept_one(&l, "200 OK");
        assert!(head.contains("X-NzbFast-Event: job.added"), "{head}");

        // Terminal: a 404 answer records and does NOT come back.
        d.life_emit("job.added", json!({"name": "T"}));
        let _ = accept_one(&l, "404 Not Found");
        l.set_nonblocking(true).unwrap();
        std::thread::sleep(Duration::from_millis(250));
        assert!(l.accept().is_err(), "a 4xx answer must not be retried");
        let key = crate::notify::target_key(&d.notify_targets.lock_ok()[0]);
        let h = d.notify_health.lock_ok();
        let o = h.get(&key).expect("outcome recorded");
        assert_eq!(o.code, 404);
        assert!(o.error.contains("HTTP 404"), "{}", o.error);
    }

    /// The DETACHED worker's script must survive its own caller's park.
    ///
    /// 18 Aug sweep. `retried_since` exists because the hook worker is
    /// spawned and then its caller parks immediately, and park stamps a
    /// queue -> history move that bumps `move_seq` - so the worker
    /// cannot ask the whole `(retries, move_seq)` pair without racing
    /// it. The worker's own guard did ask only the retry half, but it
    /// then handed the whole pair to `run_script`, whose fence asked
    /// the pair again: an ordinary un-retried completion silently ran
    /// no post-processing script, at random and biased toward dropping.
    /// That is the documented race, re-introduced for the script half.
    ///
    /// This pins the DECISION rather than the plumbing: same job, same
    /// gen0, move_seq bumped exactly as park bumps it, one fence each
    /// way. `sonarr_style_cycle` covers the awaited caller only and did
    /// not catch this.
    ///
    /// `cfg(unix)` like every other script-executing test here: the body
    /// is a `#!/bin/sh` file and production `run_script` launches the
    /// path directly, so Windows has neither the executable bit nor a
    /// guaranteed shell and the marker would never appear. Same rule,
    /// and the same reason, as the note at tests_api.rs:8 (Codex sweep 5
    /// M11 - the first version of this test was ungated and would have
    /// reddened the Windows lane).
    #[cfg(unix)]
    #[test]
    fn a_parked_move_must_not_cancel_the_detached_workers_script() {
        let dir = scratch("fence");
        let d = testutil::test_daemon(&dir);
        let ran = dir.join("it-ran");
        let script = dir.join("hook.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ntouch {}\n", ran.to_string_lossy()),
        )
        .expect("write script");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let job = Arc::new(Mutex::new(
            job_from_json(&json!({
                "nzo_id": "fenced",
                "name": "fenced",
                "nzb_path": dir.join("f.nzb").to_string_lossy(),
                "out_dir": dir.to_string_lossy(),
                "state": "Completed",
            }))
            .expect("job"),
        ));

        // The round the worker was planned on, then the park that the
        // caller performs the instant the worker is spawned.
        let g0 = Daemon::record_generation(&job.lock_ok());
        let gen0 = Some(g0);
        job.lock_ok().move_seq += 1;
        assert!(
            !Daemon::same_generation(&job.lock_ok(), gen0),
            "precondition: a park makes the PAIR differ"
        );
        assert_eq!(
            job.lock_ok().retries,
            g0.0,
            "precondition: but the retry half is untouched - nobody re-queued this"
        );

        // The pair fence: refuses, which is the bug when the caller is
        // the detached worker.
        d.run_script_chain(std::slice::from_ref(&script), &job, gen0, Fence::Generation);
        assert!(
            !ran.exists(),
            "the pair fence cannot tell a park from a retry, so it declines"
        );

        // The retry-half fence: runs, which is what the user configured
        // the script for.
        d.run_script_chain(
            std::slice::from_ref(&script),
            &job,
            gen0,
            Fence::RetriesOnly,
        );
        assert!(
            ran.exists(),
            "an ordinary completion must still run its post-processing script"
        );
    }

    /// The hook fan-out must belong to the round the caller planned it
    /// from - and must describe THAT round, not whatever the record has
    /// become by the time a slow pp-script returns.
    ///
    /// The generation was checked while the plan was built and then the
    /// worker was detached: the caller parks immediately, so a delete
    /// verb plus a Retry lands between the two and the script then runs
    /// inside a live download's folder while the targets are told a
    /// queued release has finished. And the notify context was read
    /// LIVE, after the script - which for the documented slow script
    /// ("it may still be moving or renaming files") described the record
    /// as it was minutes later: status "Failed", an empty error, and a
    /// directory the plan never saw (Codex sweep 3, H3).
    ///
    /// Both halves in one test on purpose: a fence that declined
    /// everything would pass the first assert and silence every real
    /// completion notification.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_hook_fan_out_is_fenced_and_describes_the_round_it_was_planned_from() {
        let dir = scratch("hookgen");
        let d = testutil::test_daemon(&dir);
        // The stale half's target is a REFUSED port on purpose: a
        // regression there must fail this test in milliseconds, not
        // block the worker on a socket nobody is accepting.
        let refused = target("http://127.0.0.1:1/hook", &["completed"], "");
        let refused_key = crate::notify::target_key(&refused);
        *d.notify_targets.lock_ok() = vec![refused];

        // A two-party seam is only ever entered by the job it names.
        let stage = |id: &str| {
            let open = Arc::new(std::sync::Barrier::new(2));
            let release = Arc::new(std::sync::Barrier::new(2));
            *HOOKS_GEN_BARRIER.lock_ok() = Some((id.into(), open.clone(), release.clone()));
            (open, release)
        };
        let wait = |b: Arc<std::sync::Barrier>| async move {
            tokio::task::spawn_blocking(move || b.wait()).await.unwrap();
        };
        let completed_job = |id: &str, out: &std::path::Path| {
            Arc::new(Mutex::new(
                job_from_json(&json!({
                    "nzo_id": id,
                    "name": id,
                    "nzb_path": dir.join("hooked.nzb").to_string_lossy(),
                    "out_dir": out.to_string_lossy(),
                    "state": "Completed",
                }))
                .expect("job"),
            ))
        };

        // --- the stale direction: deleted and retried mid-fan-out -----
        let out = dir.join("Hooked.Release");
        let job = completed_job("nzo-hookgen-1", &out);
        let gen0 = Daemon::record_generation(&job.lock_ok());
        let (open, release) = stage("nzo-hookgen-1");
        run_post_job_hooks_gen(&d, &job, Some(gen0));
        wait(open).await;
        {
            // What a delete verb plus the Retry it enables leaves: the
            // same Arc, queued to run again, one generation on.
            let mut g = job.lock_ok();
            g.retries += 1;
            g.state = JobState::Queued;
        }
        wait(release.clone()).await;
        wait(release).await;
        assert!(
            !d.notify_health.lock_ok().contains_key(&refused_key),
            "the stale worker announced a completion for a release that is queued to download"
        );

        // --- the content direction: the plan's round, not the live row -
        // A delete that files the row bumps no generation, so the fence
        // waves this one through and the SNAPSHOT is what keeps the send
        // honest.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        *d.notify_targets.lock_ok() = vec![target(&url, &["completed"], "")];
        let key = crate::notify::target_key(&d.notify_targets.lock_ok()[0]);
        let out2 = dir.join("Second.Release");
        let job2 = completed_job("nzo-hookgen-2", &out2);
        let gen2 = Daemon::record_generation(&job2.lock_ok());
        let (open2, release2) = stage("nzo-hookgen-2");
        run_post_job_hooks_gen(&d, &job2, Some(gen2));
        wait(open2).await;
        {
            let mut g = job2.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "deleted from the queue".into();
            g.out_dir = dir.join("Somewhere.Else");
        }
        let addr = l.local_addr().unwrap();
        let accept = std::thread::spawn(move || accept_one(&l, "200 OK"));
        wait(release2.clone()).await;
        wait(release2).await;
        // The fan-out is over. If it delivered nothing, this probe is
        // what the accept above takes instead - it closes at once, so
        // the thread panics and this test FAILS rather than hanging on a
        // socket nobody will ever connect to.
        let _ = std::net::TcpStream::connect(addr);
        let (_head, body) = accept.join().expect(
            "no notification was delivered: the send read the record live, after the script",
        );
        *HOOKS_GEN_BARRIER.lock_ok() = None;
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["status"], "Completed",
            "the send described the record as it was minutes later: {v}"
        );
        assert_eq!(v["dir"], out2.to_string_lossy().to_string(), "{v}");
        assert_eq!(v["error"], "", "{v}");
        assert!(
            d.notify_health.lock_ok().contains_key(&key),
            "and the live half still records its outcome"
        );
    }
}
