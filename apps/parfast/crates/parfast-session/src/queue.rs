//! The session: the job table, the scheduler, and what happens when
//! the last job finishes.
//!
//! # Serial by default, and the reason is not caution
//!
//! Every job here is already parallel inside - the verify hashes
//! members across lanes, the fold is a thread pool, the create writes
//! its volumes in parallel - so two jobs at once do not add throughput,
//! they contend for the same disk and the same
//! [`crate::runner::KnobLock`]. Concurrency above 1 exists because a
//! user with two spindles asked for it, and the Settings pane says what
//! it costs.
//!
//! # The exception: two large single-file creates
//!
//! One create over one large file is NOT parallel inside where it counts:
//! it is bound by a serial whole-file MD5 chain, and the fold beside it
//! is paced down to a few workers. So a second such create is started
//! beside a running one, at any concurrency, when [`crate::pairing`]'s
//! rule says the machine has the cores and the memory for both - and a
//! create that fails the rule stays queued. It makes no job faster; it
//! makes a queue of them finish sooner.
//!
//! # The post-queue action is REPORTED, never performed
//!
//! Sleeping or shutting down a machine is a platform call and a
//! decision a human has to be able to stop. This crate runs in a
//! library with no window and no way to ask; the host has both. So the
//! queue snapshot carries `post_action` and a `post_action_due` flag,
//! and the host is what puts a confirmation on screen and calls the
//! platform.
//!
//! # Persistence
//!
//! The queue is written to a path the HOST names - it knows where an
//! app's data directory is on its own platform and this crate does not.
//! A job that was RUNNING when the file was written comes back
//! `interrupted` rather than `running`: the process that was running it
//! is gone, and re-running is the human's call.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use serde::{Deserialize, Serialize};

use crate::job::{JobKind, JobSnapshot, JobSpec, JobState};
use crate::pairing::{self, PairShape};
use crate::runner::{self, Control, Job, KnobLock, Publisher};
use crate::settings::{PostQueueAction, Settings};

/// One entry of the table.
struct Entry {
    spec: JobSpec,
    control: Arc<Control>,
    publisher: Arc<Publisher>,
    /// Live while a worker holds this job.
    running: bool,
    /// The pairing shape this job was STARTED with, when it could pair
    /// ([`pairing::shape_of`]); such a job holds the knob lock shared, and
    /// a second create is judged against this. `None` while queued and for
    /// every job that cannot pair.
    pair: Option<PairShape>,
    /// Why pairing last left this job queued, as far as its log has been
    /// told ([`PairWait`]). Reset when the job starts.
    pair_wait: PairWait,
    /// Section 5.5's "Run now": take this job before anything else
    /// queued, whatever its id. Cleared when it starts.
    ///
    /// A FLAG AND NOT A REORDERED TABLE. The table is a `BTreeMap` on
    /// the id, so iteration IS submission order and the display and the
    /// scheduler read one ordering rather than two that can disagree.
    /// The Windows lane's workaround for the missing verb - raise the
    /// concurrency, or resume the selected job and let the scheduler
    /// reach it next - starts everything queued ahead of it too, which
    /// is a different thing from running one job now.
    run_next: bool,
}

/// Why a create with a pairing shape was left queued beside a running
/// one, kept on its entry so the log hears each reason ONCE.
///
/// The scheduler comes round at least every 100 ms and asks the rule
/// again each time, so a line per refusal is a log that fills with the
/// same sentence. A line is written when the reason CHANGES: a different
/// running job, or a different clause of [`pairing::Refusal`]. The numbers
/// inside a clause are not part of the comparison, because the pacer's
/// width moves by a worker or two while it settles (20 to 22 on the
/// rotational Synology, research/PARFAST-SINGLE-FILE-MD5-HEADROOM-2026-09-13.md
/// addendum 7), and a line per wobble is the per-tick log again.
///
/// `NotSettled` IS NOT LOGGED WHEN IT IS SEEN. It is the normal state for
/// the first moments of every create - the pacer has not published a
/// width yet - so a line for it would stand on nearly every job that later
/// pairs. It is logged only if it is STILL the reason when the running
/// create finishes: that is the case where it was never transient (a
/// running create that never paces, such as a file under the fused
/// route's size floor, keeps it for its whole run), and without the line
/// that wait would carry no reason at all. And only if nothing else was
/// said beside that job: a paced create drops its published width before
/// its worker returns (the cap is released when the hashing ends, and the
/// volumes are still being written), so an unsettled pacer is the last
/// thing seen before almost every finish, and a line for it after a
/// "needs N cores" line would contradict the true one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PairWait {
    /// The refusal the log was last told, and the running job it named.
    said: Option<(i64, pairing::Refusal)>,
    /// The running job the latest attempt found unsettled, when that was
    /// the latest attempt's reason.
    unsettled_beside: Option<i64>,
}

impl PairWait {
    /// A pair attempt beside `first` was refused: the line to log, when
    /// this is a reason the log has not been told.
    fn refused(&mut self, first: i64, why: pairing::Refusal) -> Option<String> {
        if let pairing::Refusal::NotSettled { .. } = why {
            self.unsettled_beside = Some(first);
            return None;
        }
        self.unsettled_beside = None;
        let same = |(id, said): (i64, pairing::Refusal)| {
            id == first && std::mem::discriminant(&said) == std::mem::discriminant(&why)
        };
        if self.said.is_some_and(same) {
            return None;
        }
        self.said = Some((first, why));
        Some(refusal_line(first, why))
    }

    /// Job `first` finished: the line to log, when the latest attempt beside
    /// it was refused for want of a settled pacer.
    fn beside_finished(&mut self, first: i64) -> Option<String> {
        if self.unsettled_beside != Some(first) {
            return None;
        }
        self.unsettled_beside = None;
        if self.said.is_some_and(|(id, _)| id == first) {
            return None;
        }
        Some(refusal_line(
            first,
            pairing::Refusal::NotSettled { paced_creates: 0 },
        ))
    }
}

/// The log line for one refusal, in the "Started beside" line's voice.
/// Hard-coded English like that line: the log tail is not catalogued.
fn refusal_line(first: i64, why: pairing::Refusal) -> String {
    use pairing::Refusal;
    let reason = match why {
        Refusal::Knobs => "the two jobs set different threads, memory or solver settings, \
                           and the engine has one of each"
            .to_string(),
        Refusal::Floor { cores } => format!(
            "this computer has {cores} cores, too few to give two large single-file creates \
             room each"
        ),
        Refusal::NotSettled { .. } => format!(
            "job {first} finished without settling on how many cores it needed, so there \
             was nothing to judge a second create against"
        ),
        Refusal::Cores { need, have } => {
            format!("two creates at once would need {need} cores and this computer has {have}")
        }
        Refusal::Route => "the memory left beside it is too little for this create to run \
                           the way two at once need"
            .to_string(),
    };
    format!("Not started beside job {first}: {reason}. It runs when a slot is free.")
}

/// What `pf_queue_snapshot` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueSnapshot {
    pub paused: bool,
    pub concurrency: u32,
    pub post_action: String,
    /// The queue has drained and the action above has not been carried
    /// out yet. An ADDITION to section 4.5, because the action is the
    /// HOST's to perform and it needs to be told when.
    pub post_action_due: bool,
    pub jobs: Vec<JobSnapshot>,
}

/// What the persisted file holds. A version field so a later shape can
/// be read or discarded on purpose rather than by a parse error.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Persisted {
    version: u32,
    settings: Settings,
    jobs: Vec<PersistedJob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedJob {
    spec: JobSpec,
    snapshot: JobSnapshot,
}

/// The session a host holds one of.
pub struct Session {
    inner: Arc<Inner>,
}

struct Inner {
    jobs: Mutex<BTreeMap<i64, Entry>>,
    next_id: AtomicI64,
    settings: Mutex<Settings>,
    paused: AtomicBool,
    /// Set when the queue drains with an action pending; cleared when
    /// the host says it has dealt with it, or when a new job arrives.
    post_action_due: AtomicBool,
    /// The LATCH behind that flag. Clearing `post_action_due` says the
    /// host has dealt with this drain; without a second bit the queue
    /// is still drained on the next tick and the action falls due again
    /// immediately, which is a machine that will not stay awake. Only a
    /// new job lowers this.
    post_action_fired: AtomicBool,
    knobs: Arc<KnobLock>,
    wake: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Where the table is written, if the host asked for persistence.
    store: Mutex<Option<PathBuf>>,
    /// The scheduler's own wake, so a submit or a resume does not wait
    /// for a poll interval.
    tick: Condvar,
    tick_lock: Mutex<()>,
    stopping: AtomicBool,
}

impl Session {
    /// A fresh session. `settings` is `None` for the defaults, which is
    /// what `pf_session_new(NULL)` means.
    pub fn new(settings: Option<Settings>) -> Session {
        // The per-block verify verdict, which parfast 1.5.0-beta.3 made
        // its default (d89e1027da): the engine's tier is process-global
        // and OFF until a surface chooses, and until 13 Sep 2026 no
        // surface in this app did, so every check here ran the
        // whole-file MD5 chain on one thread - 11 s against 0.5 s on an
        // 8.86 GB member. The CLI's `--slow` has no counterpart in the
        // app yet; when it gets one it lands as a Settings field and
        // this call reads it.
        nzbkit::par2::set_fast_check(true);
        let inner = Arc::new(Inner {
            jobs: Mutex::new(BTreeMap::new()),
            next_id: AtomicI64::new(1),
            settings: Mutex::new(settings.unwrap_or_default()),
            paused: AtomicBool::new(false),
            post_action_due: AtomicBool::new(false),
            post_action_fired: AtomicBool::new(false),
            knobs: KnobLock::new(),
            wake: Mutex::new(None),
            store: Mutex::new(None),
            tick: Condvar::new(),
            tick_lock: Mutex::new(()),
            stopping: AtomicBool::new(false),
        });
        let scheduler = Arc::clone(&inner);
        // ONE scheduler thread, which starts workers. It is the only
        // thing that decides what runs, so "concurrency" has exactly
        // one reader and a change to it cannot race two starts.
        std::thread::Builder::new()
            .name("parfast-queue".to_string())
            .spawn(move || scheduler_loop(scheduler))
            .expect("the queue scheduler thread");
        Session { inner }
    }

    /// Install the host's wake. It carries no data, may be called from
    /// ANY thread, and fires whenever a snapshot would differ from the
    /// last one handed out.
    pub fn set_wake(&self, f: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.inner.wake.lock().unwrap_or_else(|p| p.into_inner()) = f.clone();
        let jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        for e in jobs.values() {
            e.publisher.set_wake(wake_box(f.clone()));
        }
    }

    /// Queue a job and answer its id.
    pub fn submit(&self, spec: JobSpec) -> i64 {
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let low = matches!(&spec, JobSpec::Create { create } if create.perf.low_priority)
            || self
                .inner
                .settings
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .performance
                .low_priority;
        let snap = JobSnapshot::queued(id, spec.kind(), now_rfc3339(), low);
        let publisher = Publisher::new(snap);
        publisher.set_wake(wake_box(
            self.inner
                .wake
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
        ));
        self.inner
            .jobs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                id,
                Entry {
                    spec,
                    control: Control::new(),
                    publisher,
                    running: false,
                    pair: None,
                    pair_wait: PairWait::default(),
                    run_next: false,
                },
            );
        self.inner.post_action_due.store(false, Ordering::SeqCst);
        self.inner.post_action_fired.store(false, Ordering::SeqCst);
        self.inner.kick();
        self.inner.persist();
        id
    }

    /// One job's snapshot, or `None` for an id nothing answers.
    pub fn job(&self, id: i64) -> Option<JobSnapshot> {
        self.inner
            .jobs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .map(|e| e.publisher.get())
    }

    /// The whole table.
    pub fn snapshot(&self) -> QueueSnapshot {
        let s = self
            .inner
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        QueueSnapshot {
            paused: self.inner.paused.load(Ordering::SeqCst),
            concurrency: s.concurrency,
            post_action: s.post_queue_action.as_str().to_string(),
            post_action_due: self.inner.post_action_due.load(Ordering::SeqCst),
            jobs: jobs.values().map(|e| e.publisher.get()).collect(),
        }
    }

    /// Cancel a job. A queued job is cancelled at once; a running one
    /// at its next honouring point (see [`crate::runner`]).
    pub fn cancel(&self, id: i64) -> bool {
        let jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let Some(e) = jobs.get(&id) else {
            return false;
        };
        e.control.cancel();
        if !e.running {
            e.publisher.update(|s| {
                s.state = JobState::Cancelled;
                s.phase_text = "Cancelled".to_string();
            });
        }
        drop(jobs);
        self.inner.kick();
        true
    }

    pub fn set_job_paused(&self, id: i64, paused: bool) -> bool {
        let jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let Some(e) = jobs.get(&id) else {
            return false;
        };
        if e.publisher.get().state.finished() {
            return false;
        }
        e.control.set_paused(paused);
        e.publisher.update(|s| {
            if paused && s.state == JobState::Running {
                s.state = JobState::Paused;
            } else if !paused && s.state == JobState::Paused {
                s.state = JobState::Running;
            }
        });
        true
    }

    /// Remove a FINISHED job. A running or queued one is refused: a
    /// host that wants it gone cancels it first, and a remove that
    /// silently cancelled would lose work on a misclick.
    pub fn remove(&self, id: i64) -> bool {
        let mut jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let Some(e) = jobs.get(&id) else {
            return false;
        };
        if !e.publisher.get().state.finished() {
            return false;
        }
        jobs.remove(&id);
        drop(jobs);
        self.inner.persist();
        self.inner.ring();
        true
    }

    /// Section 5.5's "Run now": take this job before anything else
    /// queued. Refused for a job that is already running or finished -
    /// there is nothing to bring forward.
    ///
    /// It does NOT interrupt what is running, and it does not raise the
    /// concurrency: on a serial queue the effect is that this job is
    /// the next one started. Marking a second job while the first is
    /// still waiting leaves both marked, and they start in submission
    /// order among themselves.
    pub fn run_next(&self, id: i64) -> bool {
        let mut jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let Some(e) = jobs.get_mut(&id) else {
            return false;
        };
        if e.running || e.publisher.get().state != JobState::Queued {
            return false;
        }
        e.run_next = true;
        drop(jobs);
        self.inner.kick();
        self.inner.ring();
        true
    }

    pub fn set_low_priority(&self, id: i64, on: bool) -> bool {
        let jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let Some(e) = jobs.get(&id) else {
            return false;
        };
        e.publisher.update(|s| s.low_priority = on);
        true
    }

    pub fn set_queue_paused(&self, paused: bool) {
        self.inner.paused.store(paused, Ordering::SeqCst);
        self.inner.kick();
        self.inner.ring();
    }

    pub fn set_concurrency(&self, n: u32) {
        self.inner
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .concurrency = n.max(1);
        self.inner.kick();
        self.inner.ring();
    }

    pub fn set_post_action(&self, action: PostQueueAction) {
        self.inner
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .post_queue_action = action;
        self.inner.ring();
    }

    /// The host has carried out (or declined) the post-queue action.
    pub fn clear_post_action_due(&self) {
        self.inner.post_action_due.store(false, Ordering::SeqCst);
        self.inner.ring();
    }

    pub fn settings(&self) -> Settings {
        self.inner
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn set_settings(&self, s: Settings) {
        *self
            .inner
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = s;
        self.inner.kick();
        self.inner.persist();
        self.inner.ring();
    }

    /// "Clear remembered checksums": delete every record in the per-user
    /// digest store (`nzbkit::digest_cache`) that creates and full checks
    /// consult while `performance.digest_cache` is on, and answer how many
    /// files went. The store the runner opens is the one at the default
    /// location, so that is the one cleared. A platform that names no
    /// per-user cache folder, and a store never created, both answer 0.
    ///
    /// Safe beside a running job, which is why it is not refused while
    /// one runs: a record removed after a lookup read it changes nothing,
    /// one removed before is a miss, and a writer whose temp file went has
    /// its rename fail, which the store counts and the job does not see.
    pub fn clear_digest_cache(&self) -> Result<usize, String> {
        clear_digest_store(nzbkit::digest_cache::DigestCache::at_default_location())
    }

    /// Persist the table to `path` from now on, and load whatever is
    /// already there. A file that cannot be parsed is REPORTED and not
    /// deleted: a host that silently dropped a queue it could not read
    /// would lose a night's work to a one-character bug.
    pub fn open_store(&self, path: &Path) -> Result<usize, String> {
        *self.inner.store.lock().unwrap_or_else(|p| p.into_inner()) = Some(path.to_path_buf());
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            // Nothing there yet is the ordinary first run.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let loaded: Persisted =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let wake = self
            .inner
            .wake
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut max = 0i64;
        for pj in loaded.jobs {
            let mut snap = pj.snapshot;
            // The process that was running this is gone.
            if matches!(snap.state, JobState::Running | JobState::Paused) {
                snap.state = JobState::Interrupted;
                snap.phase_text = "Interrupted".to_string();
            }
            max = max.max(snap.id);
            let publisher = Publisher::new(snap.clone());
            publisher.set_wake(wake_box(wake.clone()));
            jobs.insert(
                snap.id,
                Entry {
                    spec: pj.spec,
                    control: Control::new(),
                    publisher,
                    running: false,
                    pair: None,
                    pair_wait: PairWait::default(),
                    run_next: false,
                },
            );
        }
        let n = jobs.len();
        drop(jobs);
        self.inner.next_id.store(max + 1, Ordering::SeqCst);
        *self
            .inner
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = loaded.settings;
        self.inner.kick();
        Ok(n)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.inner.stopping.store(true, Ordering::SeqCst);
        // Every job is cancelled: the scheduler is about to stop
        // starting work, and a worker still hashing a 200 GiB set would
        // otherwise outlive the session that owns its snapshot.
        let jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        for e in jobs.values() {
            e.control.cancel();
        }
        drop(jobs);
        self.inner.kick();
    }
}

impl Inner {
    fn kick(&self) {
        let _g = self.tick_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.tick.notify_all();
    }

    fn ring(&self) {
        let held = self.wake.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(w) = held.as_ref() {
            w();
        }
    }

    /// Write the table, if a store was opened. Best effort by design:
    /// a queue file that cannot be written must not stop the job that
    /// is running.
    fn persist(&self) {
        let store = self.store.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let Some(path) = store else { return };
        let settings = self
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let out = Persisted {
            version: 1,
            settings,
            jobs: jobs
                .values()
                .map(|e| PersistedJob {
                    spec: e.spec.clone(),
                    snapshot: e.publisher.get(),
                })
                .collect(),
        };
        drop(jobs);
        let Ok(text) = serde_json::to_string_pretty(&out) else {
            return;
        };
        // Written beside and renamed over: a crash mid-write must not
        // leave a half a queue, which parses as an empty one.
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, text.as_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// The scheduler. It starts jobs and never runs one itself, so a job
/// that wedges cannot stop the next cancel from being noticed.
fn scheduler_loop(inner: Arc<Inner>) {
    loop {
        if inner.stopping.load(Ordering::SeqCst) {
            return;
        }
        let started = start_due(&inner);
        if started {
            continue;
        }
        maybe_post_action(&inner);
        let guard = inner.tick_lock.lock().unwrap_or_else(|p| p.into_inner());
        // A timeout as well as the condvar: a worker finishing is the
        // event that frees a slot and it does not take this lock, so
        // the loop must come round on its own too. 100 ms is under the
        // ~20 Hz the wake contract promises and costs nothing measurable.
        let _ = inner
            .tick
            .wait_timeout(guard, std::time::Duration::from_millis(100))
            .unwrap_or_else(|p| p.into_inner());
    }
}

/// Start at most ONE job, and answer whether it started one - so the
/// caller comes straight round and fills the next slot rather than
/// waiting a tick per job.
fn start_due(inner: &Arc<Inner>) -> bool {
    if inner.paused.load(Ordering::SeqCst) || inner.stopping.load(Ordering::SeqCst) {
        return false;
    }
    let settings = inner
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let limit = settings.concurrency.max(1) as usize;
    // The pick's pairing shape reads the filesystem (its one source's
    // length), and a stat on a network volume can take seconds - which,
    // under the table lock, is seconds of a host's polls hanging. So it is
    // read with NO lock held, between two looks at the table, and the
    // second look starts over if the pick moved in between.
    let candidate = {
        let jobs = inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let Some(id) = pick(&jobs) else {
            return false;
        };
        let spec = &jobs.get(&id).expect("the id just picked").spec;
        (settings.performance.pair_large_creates && spec.kind() == JobKind::Create)
            .then(|| (id, spec.clone()))
    };
    let shape = candidate
        .as_ref()
        .and_then(|(_, spec)| pairing::shape_of(spec, &settings));
    let mut jobs = inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
    let Some(id) = pick(&jobs) else {
        return false;
    };
    if candidate
        .as_ref()
        .is_some_and(|(read_for, _)| *read_for != id)
    {
        return true;
    }
    let running: Vec<(i64, Option<&PairShape>)> = jobs
        .iter()
        .filter(|(_, e)| e.running)
        .map(|(k, e)| (*k, e.pair.as_ref()))
        .collect();
    let beside_shared = running.iter().any(|(_, p)| p.is_some());
    // A create that could pair, beside a create that was started able to:
    // the pairing rule decides, and the concurrency does not - a pass
    // starts it however low the limit, a refusal leaves it QUEUED however
    // high (rather than started only to wait on the knob lock). Everything
    // else is the limit, as it always was.
    let paired_with = match (&shape, beside_shared) {
        (Some(next), true) => {
            let [(first_id, Some(first))] = running.as_slice() else {
                return false;
            };
            let paces = nzbkit::par2gen::single_file_create_paces(
                next.length,
                next.block_size,
                next.recovery_blocks,
            );
            match pairing::admit_second(pairing::Machine::now(), first, next, paces) {
                Ok(()) => Ok(Some(*first_id)),
                Err(why) => Err((*first_id, why)),
            }
        }
        _ => {
            if running.len() >= limit {
                return false;
            }
            Ok(None)
        }
    };
    let entry = jobs
        .get_mut(&id)
        .expect("the id just selected is in the table");
    let paired_with = match paired_with {
        Ok(p) => p,
        Err((first, why)) => {
            if let Some(line) = entry.pair_wait.refused(first, why) {
                entry.publisher.update(|s| s.log_tail.push(line));
            }
            return false;
        }
    };
    entry.pair_wait = PairWait::default();
    entry.run_next = false;
    if entry.control.is_cancelled() {
        entry.publisher.update(|s| s.state = JobState::Cancelled);
        return true;
    }
    entry.running = true;
    entry.pair = shape;
    if let Some(first) = paired_with {
        entry.publisher.update(|s| {
            s.log_tail.push(format!(
                "Started beside job {first}: this machine has the cores and memory for two \
                 large single-file creates at once. Neither runs faster than it would alone; \
                 the queue finishes sooner."
            ))
        });
    }
    let job = Job {
        spec: entry.spec.clone(),
        control: Arc::clone(&entry.control),
        publisher: Arc::clone(&entry.publisher),
        knobs: Arc::clone(&inner.knobs),
        settings,
        shared: entry.pair.is_some(),
    };
    drop(jobs);
    let back = Arc::clone(inner);
    std::thread::Builder::new()
        .name(format!("parfast-job-{id}"))
        .spawn(move || {
            runner::run(&job);
            let mut jobs = back.jobs.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(e) = jobs.get_mut(&id) {
                e.running = false;
                e.pair = None;
            }
            for e in jobs.values_mut() {
                if let Some(line) = e.pair_wait.beside_finished(id) {
                    e.publisher.update(|s| s.log_tail.push(line));
                }
            }
            drop(jobs);
            back.persist();
            back.kick();
            back.ring();
        })
        .expect("a job worker thread");
    true
}

/// The job the scheduler would start next: the first queued, in
/// submission order - the table is a BTreeMap on the id, so iteration IS
/// submission order and there is no second ordering rule to keep in step
/// with the display. A job marked `run_next` jumps that order and nothing
/// else does; among several marked ones, submission order again.
fn pick(jobs: &BTreeMap<i64, Entry>) -> Option<i64> {
    let ready = |e: &Entry| !e.running && e.publisher.get().state == JobState::Queued;
    jobs.iter()
        .find(|(_, e)| ready(e) && e.run_next)
        .map(|(k, _)| *k)
        .or_else(|| jobs.iter().find(|(_, e)| ready(e)).map(|(k, _)| *k))
}

/// Has the queue drained with an action waiting? Set the flag ONCE, so
/// a host is asked to sleep the machine once and not every tick.
fn maybe_post_action(inner: &Arc<Inner>) {
    let action = inner
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .post_queue_action;
    if action == PostQueueAction::None || inner.post_action_fired.load(Ordering::SeqCst) {
        return;
    }
    let jobs = inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
    // Nothing to do if there is nothing here at all: an empty queue on
    // a fresh launch has not "finished".
    if jobs.is_empty() || jobs.values().any(|e| !e.publisher.get().state.finished()) {
        return;
    }
    drop(jobs);
    inner.post_action_fired.store(true, Ordering::SeqCst);
    inner.post_action_due.store(true, Ordering::SeqCst);
    inner.ring();
}

fn wake_box(f: Option<Arc<dyn Fn() + Send + Sync>>) -> Option<Box<dyn Fn() + Send + Sync>> {
    f.map(|w| Box::new(move || w()) as Box<dyn Fn() + Send + Sync>)
}

/// The `added_at` stamp, RFC 3339 in UTC, with no dependency on a date
/// crate for a field nothing arithmetics on.
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Howard Hinnant's `civil_from_days`, the standard one, because a
/// timestamp field is not worth a dependency and a hand-rolled leap
/// year rule is worth even less.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

/// A label for the queue table's Kind column, so both apps spell it
/// the same.
pub fn kind_label(kind: JobKind) -> &'static str {
    runner::kind_label(kind)
}

/// [`Session::clear_digest_cache`] with the store handed in, so a test can
/// point it at a scratch folder rather than at the user's real cache.
fn clear_digest_store(store: Option<nzbkit::digest_cache::DigestCache>) -> Result<usize, String> {
    let Some(store) = store else {
        return Ok(0);
    };
    store
        .clear()
        .map_err(|e| format!("{}: {e}", store.dir().display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{ChecksumCreateSpec, ChecksumFormat, ChecksumVerifySpec, Source, VerifySpec};
    use crate::survey::Verdict;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "parfast-session-queue-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("temp dir");
        p
    }

    /// The clear removes records and a crashed writer's temp file, and
    /// nothing else in the folder; a missing store and no store at all
    /// are both a clear store. Never the default location: that is the
    /// user's real cache.
    #[test]
    fn clearing_the_digest_store_removes_records_and_temp_files_only() {
        use nzbkit::digest_cache::DigestCache;
        let dir = tmp("digest-clear");
        let store = dir.join("digests");
        std::fs::create_dir_all(&store).expect("store dir");
        for name in ["a.pfd", "b.pfd", ".a.pfd.1.0.tmp", "keep.txt"] {
            std::fs::write(store.join(name), b"x").expect("fixture");
        }
        assert_eq!(clear_digest_store(Some(DigestCache::new(&store))), Ok(3));
        let left: Vec<_> = std::fs::read_dir(&store)
            .expect("store still there")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("keep.txt")]);
        assert_eq!(clear_digest_store(Some(DigestCache::new(&store))), Ok(0));
        let never = dir.join("never-created");
        assert_eq!(clear_digest_store(Some(DigestCache::new(&never))), Ok(0));
        assert_eq!(clear_digest_store(None), Ok(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Wait for a predicate, or fail saying what it saw. No bare
    /// sleeps: a fixed sleep is either a flake on a loaded box or dead
    /// time on an idle one.
    fn until(s: &Session, what: &str, f: impl Fn(&QueueSnapshot) -> bool) -> QueueSnapshot {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let snap = s.snapshot();
            if f(&snap) {
                return snap;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}: {snap:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn checksum_job(dir: &Path, n: usize) -> JobSpec {
        for i in 0..n {
            std::fs::write(dir.join(format!("f{i}.bin")), vec![(i as u8) + 1; 4096])
                .expect("fixture");
        }
        JobSpec::ChecksumCreate {
            checksum_create: ChecksumCreateSpec {
                sources: (0..n)
                    .map(|i| Source {
                        path: dir.join(format!("f{i}.bin")),
                        recursive: false,
                    })
                    .collect(),
                format: ChecksumFormat::Sha256,
                output: dir.join("out.sha256"),
                relative: false,
            },
        }
    }

    #[test]
    fn a_submitted_job_runs_and_reaches_done() {
        let d = tmp("run");
        let s = Session::new(None);
        let id = s.submit(checksum_job(&d, 3));
        let snap = until(&s, "the job to finish", |q| {
            q.jobs.iter().all(|j| j.state.finished())
        });
        let j = &snap.jobs[0];
        assert_eq!(j.id, id);
        assert_eq!(j.state, JobState::Done, "{j:?}");
        assert_eq!(
            j.result
                .as_ref()
                .and_then(|r| r.checksum.as_ref())
                .map(|c| c.ok),
            Some(3)
        );
        assert!(d.join("out.sha256").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A paused QUEUE starts nothing, and resuming starts it. This is
    /// the one property a Pause queue button is.
    #[test]
    fn a_paused_queue_starts_nothing_until_it_is_resumed() {
        let d = tmp("qpause");
        let s = Session::new(None);
        s.set_queue_paused(true);
        let _id = s.submit(checksum_job(&d, 2));
        for _ in 0..40 {
            assert_eq!(
                s.snapshot().jobs[0].state,
                JobState::Queued,
                "a paused queue must not start a job"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        s.set_queue_paused(false);
        until(&s, "the job after resume", |q| q.jobs[0].state.finished());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Cancelling a QUEUED job takes effect immediately and it never
    /// runs.
    #[test]
    fn cancelling_a_queued_job_stops_it_before_it_starts() {
        let d = tmp("qcancel");
        let s = Session::new(None);
        s.set_queue_paused(true);
        let id = s.submit(checksum_job(&d, 2));
        assert!(s.cancel(id));
        s.set_queue_paused(false);
        let snap = until(&s, "the cancelled job", |q| q.jobs[0].state.finished());
        assert_eq!(snap.jobs[0].state, JobState::Cancelled);
        assert!(
            !d.join("out.sha256").exists(),
            "a cancelled job wrote its output"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Only a finished job can be removed, so a misclick cannot throw
    /// away work that is still running.
    #[test]
    fn only_a_finished_job_can_be_removed() {
        let d = tmp("qremove");
        let s = Session::new(None);
        s.set_queue_paused(true);
        let id = s.submit(checksum_job(&d, 2));
        assert!(!s.remove(id), "a queued job refuses removal");
        s.set_queue_paused(false);
        until(&s, "the job to finish", |q| q.jobs[0].state.finished());
        assert!(s.remove(id));
        assert!(s.snapshot().jobs.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The post-queue action is REPORTED once, not performed and not
    /// repeated.
    #[test]
    fn the_post_queue_action_is_reported_once_when_the_queue_drains() {
        let d = tmp("qpost");
        let s = Session::new(None);
        s.set_post_action(PostQueueAction::Sleep);
        s.submit(checksum_job(&d, 1));
        let snap = until(&s, "the post action to fall due", |q| q.post_action_due);
        assert_eq!(snap.post_action, "sleep");
        s.clear_post_action_due();
        for _ in 0..20 {
            assert!(
                !s.snapshot().post_action_due,
                "the action fell due a second time on an unchanged queue"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The table survives a restart, and a job that was RUNNING comes
    /// back interrupted rather than pretending to still be running.
    #[test]
    fn the_queue_persists_and_a_running_job_comes_back_interrupted() {
        let d = tmp("qstore");
        let store = d.join("queue.json");
        {
            let s = Session::new(None);
            s.open_store(&store).expect("open store");
            s.set_queue_paused(true);
            s.submit(checksum_job(&d, 1));
            // Force the shape a crash leaves: a snapshot that says
            // running, with no process behind it.
            let j = s.snapshot().jobs[0].clone();
            assert_eq!(j.state, JobState::Queued);
        }
        // Rewrite the stored state to `running`, which is what a kill
        // -9 mid-job leaves behind.
        let text = std::fs::read_to_string(&store).expect("stored");
        std::fs::write(&store, text.replace("\"queued\"", "\"running\"")).expect("rewrite");

        let s = Session::new(None);
        s.set_queue_paused(true);
        let n = s.open_store(&store).expect("reopen");
        assert_eq!(n, 1);
        assert_eq!(s.snapshot().jobs[0].state, JobState::Interrupted);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A store that cannot be parsed is reported, never deleted.
    #[test]
    fn an_unreadable_store_is_reported_and_left_alone() {
        let d = tmp("qbad");
        let store = d.join("queue.json");
        std::fs::write(&store, "{ not json").expect("write");
        let s = Session::new(None);
        assert!(s.open_store(&store).is_err());
        assert!(store.exists(), "a queue file must never be deleted");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Section 5.5's "Run now" takes ONE job out of turn.
    ///
    /// DETERMINISTIC, with no timing in it at all - the first spelling
    /// of this test raced and was right to fail: four tiny jobs all
    /// finished inside one poll, so "nothing was left queued" said
    /// nothing about the order they ran in.
    ///
    /// The trick is to make the scheduler's PICK observable instead of
    /// its outcome. Every job is paused individually before the queue
    /// is let go, so the one job the scheduler takes parks at the first
    /// gate in `runner::run` and reports `paused` while every job it
    /// did NOT take stays `queued` indefinitely. Exactly one job can
    /// therefore leave `queued`, and which one it is IS the pick.
    #[test]
    fn run_next_is_the_job_the_scheduler_picks() {
        let d = tmp("qrunnext");
        let s = Session::new(None);
        s.set_queue_paused(true);
        let ids: Vec<i64> = (0..4)
            .map(|i| {
                let sub = d.join(format!("s{i}"));
                std::fs::create_dir_all(&sub).expect("sub");
                s.submit(checksum_job(&sub, 2))
            })
            .collect();
        for &id in &ids {
            assert!(s.set_job_paused(id, true), "job {id} pauses");
        }
        let last = *ids.last().expect("four jobs");
        assert!(
            s.run_next(last),
            "the last queued job can be brought forward"
        );
        s.set_queue_paused(false);

        let q = until(&s, "the scheduler to take one job", |q| {
            q.jobs.iter().any(|j| j.state == JobState::Paused)
        });
        let taken: Vec<i64> = q
            .jobs
            .iter()
            .filter(|j| j.state != JobState::Queued)
            .map(|j| j.id)
            .collect();
        assert_eq!(
            taken,
            vec![last],
            "the scheduler took {taken:?}; `run_next` marked {last}, and at concurrency 1 \
             with every job paused exactly one can leave `queued`"
        );

        // And the mark is CONSUMED: let everything go and the rest run
        // in their own submission order behind it.
        for &id in &ids {
            s.set_job_paused(id, false);
        }
        until(&s, "every job to finish", |q| {
            q.jobs.iter().all(|j| j.state.finished())
        });
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The pick rule itself, with nothing running: a marked job is
    /// chosen over earlier unmarked ones, and the mark is consumed.
    #[test]
    fn the_scheduler_picks_a_marked_job_before_an_earlier_unmarked_one() {
        let d = tmp("qpick");
        let s = Session::new(None);
        s.set_queue_paused(true);
        let mut ids = Vec::new();
        for i in 0..3 {
            let sub = d.join(format!("s{i}"));
            std::fs::create_dir_all(&sub).expect("sub");
            ids.push(s.submit(checksum_job(&sub, 1)));
        }
        assert!(s.run_next(ids[2]));
        // A running or finished job cannot be brought forward - there
        // is nothing to bring.
        s.set_queue_paused(false);
        let q = until(&s, "the marked job to finish", |q| {
            q.jobs
                .iter()
                .find(|j| j.id == ids[2])
                .is_some_and(|j| j.state.finished())
        });
        assert!(!s.run_next(ids[2]), "a finished job is refused");
        assert!(!s.run_next(9_999), "an unknown id is refused");
        let _ = q;
        until(&s, "the rest to finish", |q| {
            q.jobs.iter().all(|j| j.state.finished())
        });
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn ids_are_handed_out_in_submission_order_and_the_table_keeps_it() {
        let d = tmp("qorder");
        let s = Session::new(None);
        s.set_queue_paused(true);
        let ids: Vec<i64> = (0..4).map(|_| s.submit(checksum_job(&d, 1))).collect();
        assert_eq!(ids, vec![1, 2, 3, 4]);
        assert_eq!(
            s.snapshot().jobs.iter().map(|j| j.id).collect::<Vec<_>>(),
            ids
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Concurrency 1 means one at a time, which is what the default
    /// claims - asserted while the jobs are running, not after.
    #[test]
    fn concurrency_one_never_runs_two_at_once() {
        let d = tmp("qconc");
        let s = Session::new(None);
        s.set_queue_paused(true);
        for i in 0..4 {
            let sub = d.join(format!("s{i}"));
            std::fs::create_dir_all(&sub).expect("sub");
            s.submit(checksum_job(&sub, 6));
        }
        s.set_queue_paused(false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let q = s.snapshot();
            let running = q
                .jobs
                .iter()
                .filter(|j| matches!(j.state, JobState::Running | JobState::Paused))
                .count();
            assert!(running <= 1, "two jobs ran at concurrency 1: {q:?}");
            if q.jobs.iter().all(|j| j.state.finished()) {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "timed out: {q:?}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A verify spec that names nothing fails rather than hanging, and
    /// says which code it failed with.
    #[test]
    fn a_checksum_verify_of_a_missing_file_fails_with_a_code() {
        let d = tmp("qmissing");
        let s = Session::new(None);
        s.submit(JobSpec::ChecksumVerify {
            checksum_verify: ChecksumVerifySpec {
                file: d.join("nothing.sfv"),
            },
        });
        let q = until(&s, "the failure", |q| q.jobs[0].state.finished());
        assert_eq!(q.jobs[0].state, JobState::Failed);
        assert_eq!(
            q.jobs[0].error.as_ref().map(|e| e.code.as_str()),
            Some("io"),
            "{:?}",
            q.jobs[0]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Section 5.4's Verify table is *Name | Expected | Status* per
    /// file, and the three counts cannot draw it. The Windows lane read
    /// the missing rows as "empty until it exists" on 12 Sep 2026; they
    /// exist now, in the file's own order, with the mismatched row
    /// carrying what the file actually came to.
    #[test]
    fn a_checksum_verify_publishes_a_row_per_entry_and_not_only_counts() {
        let d = tmp("qrows");
        std::fs::write(d.join("a.bin"), b"the quick brown fox").expect("a");
        std::fs::write(d.join("b.bin"), b"second").expect("b");
        let sfv = d.join("set.sfv");
        std::fs::write(
            &sfv,
            crate::checksum::write_text(
                &[
                    ("a.bin".to_string(), d.join("a.bin")),
                    ("b.bin".to_string(), d.join("b.bin")),
                ],
                ChecksumFormat::Sfv,
            )
            .expect("write"),
        )
        .expect("sfv");
        // Damage one of the two, so the table has to carry both verdicts.
        std::fs::write(d.join("b.bin"), b"SECOND").expect("damage");

        let s = Session::new(None);
        s.submit(JobSpec::ChecksumVerify {
            checksum_verify: ChecksumVerifySpec { file: sfv },
        });
        let q = until(&s, "the verify to finish", |q| q.jobs[0].state.finished());
        let ck = q.jobs[0]
            .result
            .as_ref()
            .and_then(|r| r.checksum.as_ref())
            .expect("a checksum result");
        assert_eq!((ck.ok, ck.mismatch, ck.missing), (1, 1, 0));
        assert_eq!(
            ck.entries
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a.bin", "b.bin"],
            "rows come back in the file's own order"
        );
        assert_eq!(ck.entries[0].status, crate::checksum::RowStatus::Ok);
        assert_eq!(ck.entries[1].status, crate::checksum::RowStatus::Mismatch);
        assert!(
            !ck.entries[1].actual.is_empty() && ck.entries[1].actual != ck.entries[1].expected,
            "a mismatched row carries what the file actually came to: {:?}",
            ck.entries[1]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Build a real PAR2 set over three members through the session
    /// itself, damage it however `wreck` says, verify, and hand back
    /// the snapshot. Everything real: the engine creates, the engine
    /// verifies, and the numbers are the CLI's.
    fn verify_after(tag: &str, wreck: impl FnOnce(&Path)) -> JobSnapshot {
        use crate::job::{
            BlockSpec, CreateSpec, PathMode, RecoverySpec, UnicodePolicy, VolumeSpec,
        };

        let d = tmp(tag);
        for (name, len, seed) in [
            ("alpha.bin", 30_001usize, 2u8),
            ("bravo.bin", 41_000, 8),
            ("charlie.bin", 22_003, 19),
        ] {
            let bytes: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(31).wrapping_add(seed as usize * 7)) as u8)
                .collect();
            std::fs::write(d.join(name), bytes).expect("member");
        }
        let s = Session::new(None);
        s.submit(JobSpec::Create {
            create: CreateSpec {
                sources: ["alpha.bin", "bravo.bin", "charlie.bin"]
                    .iter()
                    .map(|n| Source {
                        path: d.join(n),
                        recursive: false,
                    })
                    .collect(),
                path_mode: PathMode::Basename,
                base_path: None,
                block: Some(BlockSpec::Size { size: 2_048 }),
                recovery: Some(RecoverySpec::Percent { percent: 40.0 }),
                output: d.join("set.par2"),
                volumes: VolumeSpec::Pow2,
                first_recovery_block: 0,
                comment: String::new(),
                overwrite: false,
                std_naming: false,
                unicode: UnicodePolicy::Auto,
                perf: Default::default(),
            },
        });
        let q = until(&s, "the create", |q| {
            q.jobs.iter().all(|j| j.state.finished())
        });
        assert_eq!(q.jobs[0].state, JobState::Done, "create: {:?}", q.jobs[0]);

        wreck(&d);

        let id = s.submit(JobSpec::Verify {
            verify: VerifySpec {
                par2: d.join("set.par2"),
                extra_dirs: Vec::new(),
                options: Default::default(),
            },
        });
        until(&s, "the verify", |q| {
            q.jobs
                .iter()
                .find(|j| j.id == id)
                .is_some_and(|j| j.state.finished())
        });
        let snap = s.job(id).expect("the verify snapshot");
        let _ = std::fs::remove_dir_all(&d);
        snap
    }

    /// THE INVARIANT BOTH CREATE-SIDE CAPABILITIES REST ON: the pane
    /// shows what the create writes. Not "the same numbers" - the same
    /// FILES, by name and by size, off one real create.
    ///
    /// It is one test because the two switches are one shape. Each
    /// reaches `parfast::create` through the command line the preview
    /// itself spells (`runner::run_create` re-parses it and runs off
    /// the result), so a switch that got as far as the preview and no
    /// further would show up here as a pane describing a set that is
    /// not on disk - which is exactly what an explicit ceiling did for
    /// an afternoon before it was withdrawn.
    ///
    /// Both arms are CHECKED TO BITE rather than assumed to: the
    /// ceiling is below the exponential plan's largest volume, so the
    /// layout has to change, and the naming arm is compared against the
    /// same set written the reference's way.
    #[test]
    fn a_create_writes_exactly_the_files_its_preview_drew() {
        use crate::job::{
            BlockSpec, CreateSpec, PathMode, Pow2Limit, RecoverySpec, UnicodePolicy, VolumeSpec,
        };
        let d = tmp("createcaps");
        std::fs::write(d.join("a.bin"), vec![7u8; 200_000]).expect("member");
        let base = CreateSpec {
            sources: vec![Source {
                path: d.join("a.bin"),
                recursive: false,
            }],
            path_mode: PathMode::Basename,
            base_path: None,
            block: Some(BlockSpec::Size { size: 2_048 }),
            recovery: Some(RecoverySpec::Count { count: 20 }),
            output: d.join("plain.par2"),
            volumes: VolumeSpec::Pow2,
            first_recovery_block: 0,
            comment: String::new(),
            overwrite: false,
            std_naming: false,
            unicode: UnicodePolicy::Auto,
            perf: Default::default(),
        };

        // Run a spec and hand back the preview beside what landed on
        // disk, so every assertion below compares the two.
        let run = |spec: &CreateSpec| {
            let preview = crate::planner::preview(spec).expect("preview");
            let s = Session::new(None);
            let id = s.submit(JobSpec::Create {
                create: spec.clone(),
            });
            let q = until(&s, "the create", |q| {
                q.jobs.iter().any(|j| j.id == id && j.state.finished())
            });
            let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
            assert_eq!(job.state, JobState::Done, "create: {job:?}");
            let written = job
                .result
                .as_ref()
                .expect("a result")
                .written
                .iter()
                .map(|w| (w.name.clone(), w.size))
                .collect::<Vec<_>>();
            let mut drawn = preview
                .files
                .iter()
                .map(|f| (f.name.clone(), f.size))
                .collect::<Vec<_>>();
            drawn.sort();
            (drawn, written, preview)
        };

        // The control: par2cmdline's spelling, the exponential split,
        // no ceiling. 1 + 2 + 4 + 8 + 5 over twenty blocks.
        let (drawn, written, preview) = run(&base);
        assert_eq!(drawn, written, "the plain create must match its preview");
        assert_eq!(written.len(), 6, "index + five volumes: {written:?}");
        assert!(
            written.iter().any(|(n, _)| n.contains("+8")),
            "the exponential plan reaches an eight-block volume: {written:?}"
        );
        assert!(
            preview.warnings.is_empty(),
            "nothing to warn about here: {:?}",
            preview.warnings
        );

        // The spec's own volume spelling.
        let mut spec = base.clone();
        spec.std_naming = true;
        spec.output = d.join("spec.par2");
        let (drawn, written, _) = run(&spec);
        assert_eq!(drawn, written, "std_naming: the preview must name it too");
        let vols: Vec<&String> = written
            .iter()
            .map(|(n, _)| n)
            .filter(|n| n.contains(".vol"))
            .collect();
        assert_eq!(vols.len(), 5, "{written:?}");
        for name in &vols {
            let (first, last) = spec_volume(name);
            assert!(last >= first, "{name} runs backwards");
        }
        // First and LAST exponent: the five volumes tile 0..=19 with no
        // gap and no overlap, which the count form cannot be mistaken
        // for - `vol01+2` and `vol01-02` describe different sets of
        // exponents and only one of them is what was written.
        let mut spans: Vec<(u64, u64)> = vols.iter().map(|n| spec_volume(n)).collect();
        spans.sort();
        assert_eq!(spans[0].0, 0, "{spans:?}");
        assert_eq!(spans.last().expect("a volume").1, 19, "{spans:?}");
        for w in spans.windows(2) {
            assert_eq!(w[1].0, w[0].1 + 1, "a gap or an overlap in {spans:?}");
        }

        // The UNIFORM scheme, which is the reference's own `-n` and has
        // been shipped since the crate landed. It is here because the
        // ceiling arm below found that NO volume scheme was reaching
        // the create - see the test's own comment - so the arm that
        // proves the fix has to cover the reference's schemes too, not
        // only the new switch.
        let mut spec = base.clone();
        spec.output = d.join("even.par2");
        spec.volumes = VolumeSpec::Uniform {
            files: Some(4),
            blocks_per_file: None,
            file_size: None,
        };
        let (drawn, written, _) = run(&spec);
        assert_eq!(drawn, written, "uniform: the preview must match too");
        assert_eq!(written.len(), 5, "four equal volumes + index: {written:?}");

        // An explicit ceiling, which the reference's dialect cannot
        // spell at all. Three is under the eight-block volume the plain
        // arm above proved is there, so the layout MUST move.
        let mut spec = base.clone();
        spec.std_naming = true;
        spec.output = d.join("capped.par2");
        spec.volumes = VolumeSpec::Pow2Limit {
            limit: Pow2Limit::Blocks { blocks: 3 },
        };
        let (drawn, written, _) = run(&spec);
        assert_eq!(drawn, written, "capped: the preview must match too");
        let vols: Vec<&String> = written
            .iter()
            .map(|(n, _)| n)
            .filter(|n| n.contains(".vol"))
            .collect();
        assert!(
            vols.len() > 5,
            "the ceiling must split further: {written:?}"
        );
        for name in &vols {
            let (first, last) = spec_volume(name);
            let blocks = last - first + 1;
            assert!(
                blocks <= 3,
                "{name} carries {blocks} blocks, more than the three asked for"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `<base>.vol<first>-<last>.par2` back into its two exponents, read
    /// off the name on DISK - the only place the spec form can be
    /// checked without trusting the code that wrote it.
    fn spec_volume(name: &str) -> (u64, u64) {
        let rest = name
            .rsplit_once(".vol")
            .expect("a volume name")
            .1
            .strip_suffix(".par2")
            .expect("a .par2 suffix");
        let (first, last) = rest.split_once('-').unwrap_or_else(|| {
            panic!("{name} is not the spec's first-and-last form");
        });
        (
            first.parse().expect("first exponent"),
            last.parse().expect("last exponent"),
        )
    }

    /// THE INVARIANT THE MAC LANE FOUND BROKEN, 12 Sep 2026.
    ///
    /// `survey.verdict` and `result.exit_code` come from the same two
    /// predicates and must never argue inside one snapshot: exit 0 is
    /// `complete`, exit 1 is `repairable`, exit 2 is `unrepairable`.
    /// API.md promises exactly this, and on the corpus's `misnamed`
    /// scenario the model was answering `complete` over a set the CLI
    /// exits 1 on - so the app showed "Complete, no repair needed" in
    /// green with Repair disabled, over a set that needed repairing.
    #[test]
    fn the_verdict_and_the_exit_code_never_argue() {
        // Clean.
        let clean = verify_after("vclean", |_| {});
        // A member renamed IN PLACE: its bytes are still in the folder,
        // so a repair costs no parity - and the set is still not whole
        // until something acts.
        let misnamed = verify_after("vmisnamed", |d| {
            std::fs::rename(d.join("charlie.bin"), d.join("IMG_4417.dat")).expect("rename");
        });
        // A member damaged in place.
        let damaged = verify_after("vdamaged", |d| {
            let mut b = std::fs::read(d.join("bravo.bin")).expect("read");
            for x in b.iter_mut().skip(4_096).take(4_096) {
                *x = 0x5a;
            }
            std::fs::write(d.join("bravo.bin"), b).expect("damage");
        });

        for (label, snap) in [
            ("clean", &clean),
            ("misnamed", &misnamed),
            ("damaged", &damaged),
        ] {
            let survey = snap
                .survey
                .as_ref()
                .unwrap_or_else(|| panic!("{label}: a survey"));
            let code = snap
                .result
                .as_ref()
                .and_then(|r| r.exit_code)
                .unwrap_or_else(|| panic!("{label}: an exit code"));
            let want = match code {
                0 => Verdict::Complete,
                1 => Verdict::Repairable,
                2 => Verdict::Unrepairable,
                other => panic!("{label}: a verify cannot exit {other}"),
            };
            assert_eq!(
                survey.verdict, want,
                "{label}: exit {code} and verdict {:?} disagree inside one snapshot",
                survey.verdict
            );
            // And the owed count is the CLI's, not a second reading:
            // zero exactly when the set is whole.
            assert_eq!(
                survey.recovery_needed == 0,
                code == 0,
                "{label}: recovery_needed {} against exit {code}",
                survey.recovery_needed
            );
        }

        assert_eq!(clean.result.as_ref().and_then(|r| r.exit_code), Some(0));
        assert_eq!(misnamed.result.as_ref().and_then(|r| r.exit_code), Some(1));

        // The misnamed row is still MISNAMED and still names where the
        // bytes went - that distinction is the whole reason the state
        // exists, and the fix above must not have cost it.
        let m = misnamed.survey.as_ref().expect("survey");
        let row = m
            .files
            .iter()
            .find(|f| f.name == "charlie.bin")
            .expect("the renamed member");
        assert_eq!(row.status, crate::survey::FileStatus::Misnamed, "{row:?}");
        assert!(
            row.found_as
                .as_deref()
                .is_some_and(|p| p.ends_with("IMG_4417.dat")),
            "the row must say where the bytes went: {row:?}"
        );
        assert_eq!(m.verdict, Verdict::Repairable);
        assert!(m.recovery_needed > 0, "a misnamed member still owes blocks");
        // Drawn as MISNAMED on the strip, not as missing: a rename
        // fixes it and no parity is spent.
        assert!(
            m.block_runs
                .iter()
                .any(|r| r[0] == u64::from(crate::survey::block_state::MISNAMED)),
            "the strip lost the misnamed run: {:?}",
            m.block_runs
        );
    }

    fn one_file_create(dir: &Path, stem: &str) -> JobSpec {
        use crate::job::{
            BlockSpec, CreateSpec, PathMode, RecoverySpec, UnicodePolicy, VolumeSpec,
        };
        let src = dir.join(format!("{stem}.bin"));
        std::fs::write(&src, vec![9u8; 50_000]).expect("member");
        JobSpec::Create {
            create: CreateSpec {
                sources: vec![Source {
                    path: src,
                    recursive: false,
                }],
                path_mode: PathMode::Basename,
                base_path: None,
                block: Some(BlockSpec::Size { size: 4_096 }),
                recovery: Some(RecoverySpec::Percent { percent: 10.0 }),
                output: dir.join(format!("{stem}.par2")),
                volumes: VolumeSpec::Pow2,
                first_recovery_block: 0,
                comment: String::new(),
                overwrite: false,
                std_naming: false,
                unicode: UnicodePolicy::Auto,
                perf: Default::default(),
            },
        }
    }

    /// A second one-file create beside a running one waits for
    /// `pairing`'s rule, and it waits at a concurrency that would otherwise
    /// start it at once.
    ///
    /// Deterministic the way `run_next_is_the_job_the_scheduler_picks` is:
    /// the first create is paused before the queue is let go, so it is
    /// RUNNING (a worker holds it, parked at its first gate) and has
    /// published no paced fold width - a refusal by name, whatever this
    /// machine's cores - for as long as the test looks. The control arm
    /// turns pairing off, and the same second job then starts under the
    /// concurrency of 2, which proves the wait was the rule's and not the
    /// limit's.
    #[test]
    fn a_second_single_file_create_waits_for_the_pairing_rule_not_the_limit() {
        for pairing_on in [true, false] {
            let d = tmp(if pairing_on { "qpair-on" } else { "qpair-off" });
            let settings = Settings {
                concurrency: 2,
                performance: crate::settings::Performance {
                    pair_large_creates: pairing_on,
                    ..Default::default()
                },
                ..Default::default()
            };
            let s = Session::new(Some(settings));
            s.set_queue_paused(true);
            let first = s.submit(one_file_create(&d, "a"));
            let second = s.submit(one_file_create(&d, "b"));
            assert!(s.set_job_paused(first, true));
            assert!(s.set_job_paused(second, true));
            s.set_queue_paused(false);
            until(&s, "the first create to start", |q| {
                q.jobs[0].state == JobState::Paused
            });
            if pairing_on {
                // More than one scheduler tick (100 ms) of refusals, so a
                // line per tick would show below.
                for _ in 0..60 {
                    assert_eq!(
                        s.job(second).expect("the second job").state,
                        JobState::Queued,
                        "a second create started beside one with no settled pacer"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            } else {
                until(&s, "the second create to start under the limit", |q| {
                    q.jobs[1].state == JobState::Paused
                });
            }
            assert!(s.set_job_paused(first, false));
            assert!(s.set_job_paused(second, false));
            let q = until(&s, "both creates to finish", |q| {
                q.jobs.iter().all(|j| j.state.finished())
            });
            for j in &q.jobs {
                assert_eq!(j.state, JobState::Done, "pairing {pairing_on}: {j:?}");
            }
            // The wait said why, once, however many ticks it lasted. The
            // first create never paces, so alone it is the unsettled line,
            // logged when the first finished; the pacer counter is
            // process-global, though, and another test's create can make it
            // a cores line instead - never both. With pairing off nothing
            // waited.
            let said: Vec<&String> = q.jobs[1]
                .log_tail
                .iter()
                .filter(|l| l.starts_with("Not started beside"))
                .collect();
            assert_eq!(said.len(), usize::from(pairing_on), "{said:?}");
            if pairing_on {
                assert!(
                    said[0].starts_with(&format!("Not started beside job {first}: ")),
                    "{said:?}"
                );
            }
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// The log hears each reason for a wait once, however many ticks ask
    /// the rule again, and again only when the reason changes.
    #[test]
    fn a_pairing_refusal_is_logged_once_per_change_of_reason() {
        use pairing::Refusal;
        let mut w = PairWait::default();
        let cores = |need| Refusal::Cores { need, have: 12 };
        let first = w.refused(3, cores(20)).expect("the first refusal is said");
        assert_eq!(
            first,
            "Not started beside job 3: two creates at once would need 20 cores and this \
             computer has 12. It runs when a slot is free."
        );
        // Every tick after, and the pacer's width wobbling inside the clause.
        for need in [20, 22, 21, 20, 22] {
            assert_eq!(w.refused(3, cores(need)), None, "need {need}");
        }
        // A different clause is a new reason.
        let route = w.refused(3, Refusal::Route).expect("a changed reason");
        assert!(route.contains("memory left"), "{route}");
        assert_eq!(w.refused(3, Refusal::Route), None);
        // So is the same clause beside a different running job.
        assert!(w.refused(4, Refusal::Route).is_some());
        assert_eq!(w.refused(4, Refusal::Route), None);

        // An unsettled pacer is silent while it is seen...
        let mut w = PairWait::default();
        for _ in 0..5 {
            assert_eq!(w.refused(7, Refusal::NotSettled { paced_creates: 0 }), None);
        }
        // ...not said when another job finishes...
        assert_eq!(w.beside_finished(6), None);
        // ...and said once when the job it waited on finishes with it still
        // the reason.
        let line = w.beside_finished(7).expect("still unsettled at the end");
        assert!(
            line.starts_with("Not started beside job 7: job 7 finished"),
            "{line}"
        );
        assert_eq!(w.beside_finished(7), None);

        // The usual case: unsettled for a moment, then a real reason. The
        // finish then says nothing more, because the unsettled moment was
        // transient and the real reason is already in the log.
        let mut w = PairWait::default();
        assert_eq!(w.refused(7, Refusal::NotSettled { paced_creates: 0 }), None);
        assert!(w.refused(7, cores(20)).is_some());
        assert_eq!(w.beside_finished(7), None);

        // The END of a paced create: its width is released before its
        // worker returns, so the last ticks see an unsettled pacer after a
        // real reason was said. The finish must not contradict that line.
        let mut w = PairWait::default();
        assert!(w.refused(7, cores(20)).is_some());
        assert_eq!(w.refused(7, Refusal::NotSettled { paced_creates: 0 }), None);
        assert_eq!(w.beside_finished(7), None);
    }

    /// Every refusal's line obeys the copy rules the log tail is shown
    /// under in both apps.
    #[test]
    fn every_refusal_line_keeps_the_copy_rules() {
        use pairing::Refusal;
        for why in [
            Refusal::Knobs,
            Refusal::Floor { cores: 4 },
            Refusal::NotSettled { paced_creates: 0 },
            Refusal::Cores { need: 22, have: 12 },
            Refusal::Route,
        ] {
            let line = refusal_line(2, why);
            assert!(line.starts_with("Not started beside job 2: "), "{line}");
            assert!(
                !line.contains('\u{2014}') && !line.contains('\u{2013}'),
                "{line}"
            );
            assert!(!line.to_lowercase().contains("streaming"), "{line}");
            assert!(!line.to_lowercase().contains("faster"), "{line}");
        }
    }

    #[test]
    fn the_timestamp_is_rfc_3339_in_utc() {
        let t = now_rfc3339();
        assert_eq!(t.len(), 20, "{t}");
        assert!(t.ends_with('Z'), "{t}");
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
        // The civil calendar, at three dates a leap rule gets wrong.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(59), (1970, 3, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }
}
