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

/// The [`Persisted::version`] this build writes, and the newest it reads.
const PERSISTED_VERSION: u32 = 1;

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
    /// Held across a whole `persist` - the snapshot AND its publication.
    /// See [`Inner::persist`].
    persist_lock: Mutex<()>,
    /// The scheduler's own wake, so a submit or a resume does not wait
    /// for a poll interval.
    tick: Condvar,
    tick_lock: Mutex<()>,
    stopping: AtomicBool,
    /// Test-only: hold `maybe_post_action` off, so a test can stand in
    /// the gap between the last job finishing and the scheduler's next
    /// pass, which is otherwise at most 100 ms wide and not raceable.
    #[cfg(test)]
    post_action_held: AtomicBool,
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
            persist_lock: Mutex::new(()),
            tick: Condvar::new(),
            tick_lock: Mutex::new(()),
            stopping: AtomicBool::new(false),
            #[cfg(test)]
            post_action_held: AtomicBool::new(false),
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
            || matches!(&spec, JobSpec::PostingSet { posting_set } if posting_set.perf.low_priority)
            || self
                .inner
                .settings
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .performance
                .low_priority;
        let mut snap = JobSnapshot::queued(id, spec.kind(), now_rfc3339(), low);
        snap.title = spec.subject();
        let publisher = Publisher::new(snap);
        publisher.set_wake(wake_box(
            self.inner
                .wake
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
        ));
        let mut jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        jobs.insert(
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
        // Lowered UNDER the table lock, which `maybe_post_action` also
        // holds from its "is the queue drained?" read through its raising
        // of these two flags. With either half outside the lock, a drain
        // judged an instant before this insert raised `post_action_due`
        // an instant after this lowered it: the host was told to sleep
        // the machine with a job sitting queued, and the latch then
        // stayed up through the whole of the new batch.
        self.inner.post_action_due.store(false, Ordering::SeqCst);
        self.inner.post_action_fired.store(false, Ordering::SeqCst);
        drop(jobs);
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
    ///
    /// A QUEUED job's cancellation is PERSISTED here and not left to the
    /// worker that would otherwise have saved it. There is no such
    /// worker: the scheduler never selects a cancelled entry, so on a
    /// paused queue - or on any queue the process leaves before the
    /// entry would have been reached - nothing ever wrote the terminal
    /// state down, and the job came back `Queued` after a relaunch and
    /// ran. Terminal states are the queue's own to record.
    ///
    /// A FINISHED job is refused, as `set_job_paused` and `remove`
    /// refuse one. `settled` below is "no worker holds it", which is
    /// true of a finished job too, so a Cancel pressed on a Done repair
    /// (or one that landed between the worker publishing Done and
    /// letting go of `running`) rewrote it to Cancelled with its result
    /// still attached - a finished job reporting that it never finished.
    pub fn cancel(&self, id: i64) -> bool {
        let jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let Some(e) = jobs.get(&id) else {
            return false;
        };
        if e.publisher.get().state.finished() {
            return false;
        }
        e.control.cancel();
        let settled = !e.running;
        if settled {
            // `update_quiet`, because this lock is still held: see
            // [`crate::runner::Publisher::update_quiet`].
            e.publisher.update_quiet(|s| {
                s.state = JobState::Cancelled;
                s.phase_text = "Cancelled".to_string();
            });
        }
        drop(jobs);
        if settled {
            self.inner.persist();
        }
        self.inner.kick();
        self.inner.ring();
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
        e.publisher.update_quiet(|s| {
            if paused && s.state == JobState::Running {
                s.state = JobState::Paused;
            } else if !paused && s.state == JobState::Paused {
                s.state = JobState::Running;
            }
        });
        drop(jobs);
        self.inner.ring();
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
        e.publisher.update_quiet(|s| s.low_priority = on);
        drop(jobs);
        self.inner.ring();
        true
    }

    pub fn set_queue_paused(&self, paused: bool) {
        self.inner.paused.store(paused, Ordering::SeqCst);
        self.inner.kick();
        self.inner.ring();
    }

    /// Both of these are `Settings` fields, and `Settings` is what the
    /// store carries - so both are PERSISTED, as `set_settings` is. They
    /// were not: a concurrency or a power action chosen through these
    /// two doors reached the file only if some later submit, cancel or
    /// worker happened to write it, and was otherwise gone at relaunch.
    pub fn set_concurrency(&self, n: u32) {
        self.inner
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .concurrency = n.max(1);
        self.inner.kick();
        self.inner.persist();
        self.inner.ring();
    }

    pub fn set_post_action(&self, action: PostQueueAction) {
        self.inner.write_settings(|s| s.post_queue_action = action);
        self.inner.persist();
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
        // The whole struct carries `post_queue_action`, so this is a
        // door to choosing the action as much as `set_post_action` is.
        self.inner.write_settings(|held| *held = s);
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
    /// already there. A file that cannot be read is REPORTED and never
    /// deleted: a host that silently dropped a queue it could not read
    /// would lose a night's work to a one-character bug.
    ///
    /// # What happens to a store this build cannot use
    ///
    /// It used to stay where it was with the path ARMED, so the very next
    /// submit, cancel or settings write renamed a fresh table over the
    /// file the paragraph above promises to keep - and both hosts drop the
    /// error. Two cases now, decided by reading `version` ALONE first:
    ///
    /// * **Written by a NEWER build** (`version` above this build's): the
    ///   file is left exactly where it is and the store is NOT armed, so
    ///   this session persists nothing and the newer build finds its queue
    ///   intact on its next launch. The error says so.
    /// * **Unreadable for any other reason** - zero length, torn by a
    ///   crash, hand-edited, a shape this build does not know: the file is
    ///   moved aside to `<name>.unreadable-<seconds>-<pid>` (never deleted),
    ///   the path IS armed, and the error names where the file went. Not
    ///   arming here made a single torn write permanent and invisible:
    ///   nothing was persisted ever again until someone found the file
    ///   and deleted it by hand. If the move itself fails, nothing is
    ///   armed, for the newer-build reason.
    ///
    /// # Ids already handed out are kept
    ///
    /// A host that submits before it opens its store already holds ids
    /// for those jobs. The counter only moves FORWARD here, and a
    /// restored job whose id is already in the table takes a fresh one
    /// rather than replacing the live entry under it.
    pub fn open_store(&self, path: &Path) -> Result<usize, String> {
        let text = match std::fs::read(path) {
            Ok(t) => t,
            // Nothing there yet is the ordinary first run.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                *self.inner.store.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some(path.to_path_buf());
                return Ok(0);
            }
            Err(e) => return self.set_aside(path, &e.to_string()),
        };
        // `version` exists so a later shape is "read or discarded on
        // purpose rather than by a parse error" - and it is read on its
        // OWN, so a newer shape this build cannot parse is still known to
        // be newer, and left for the build that can.
        #[derive(Deserialize)]
        struct VersionOnly {
            version: u32,
        }
        if let Ok(v) = serde_json::from_slice::<VersionOnly>(&text)
            && v.version > PERSISTED_VERSION
        {
            return Err(format!(
                "{}: written by a newer parfast (queue format {}, this build reads {}); \
                 left untouched, and this session's queue is not saved",
                path.display(),
                v.version,
                PERSISTED_VERSION
            ));
        }
        let loaded: Persisted = match serde_json::from_slice(&text) {
            Ok(l) => l,
            Err(e) => return self.set_aside(path, &e.to_string()),
        };
        *self.inner.store.lock().unwrap_or_else(|p| p.into_inner()) = Some(path.to_path_buf());
        let mut jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let wake = self
            .inner
            .wake
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        // Past every restored id FIRST, so an id taken for a collision
        // below cannot land on a restored job further down the file.
        let restored_max = loaded.jobs.iter().map(|j| j.snapshot.id).max().unwrap_or(0);
        self.inner
            .next_id
            .fetch_max(restored_max + 1, Ordering::SeqCst);
        let mut max = 0i64;
        for pj in loaded.jobs {
            let mut snap = pj.snapshot;
            // The process that was running this is gone.
            if matches!(snap.state, JobState::Running | JobState::Paused) {
                snap.state = JobState::Interrupted;
                snap.phase_text = "Interrupted".to_string();
            }
            // From the spec, not the file: a store older than the field
            // has none, and the spec is what the name is OF.
            snap.title = pj.spec.subject();
            // An id this session already handed out (see the doc above).
            if jobs.contains_key(&snap.id) {
                snap.id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
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
        // A RESTORED batch has already had whatever post-queue action it
        // was going to have. The action is armed by the queue DRAINING,
        // and the drain happened in the session that ran these jobs -
        // but `post_action_fired` was never persisted, so a fresh
        // session that restored a finished table plus a saved "Sleep"
        // found a drained queue on its first scheduler tick and armed it
        // again. The host reads the flag and sleeps the machine, on a
        // launch during which nothing ran. So the latch is raised HERE,
        // over the restored jobs, and lowered again by the next `submit`
        // exactly as it always was: a new batch legitimately re-arms the
        // action, a relaunch never does.
        //
        // The flag is raised only when there is something finished to
        // have finished: an empty store leaves a fresh session alone,
        // and so does one holding work still to do - that queue has not
        // drained yet and its drain is the host's to act on.
        if n > 0 && jobs.values().all(|e| e.publisher.get().state.finished()) {
            self.inner.post_action_fired.store(true, Ordering::SeqCst);
        }
        drop(jobs);
        self.inner.next_id.fetch_max(max + 1, Ordering::SeqCst);
        *self
            .inner
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = loaded.settings;
        self.inner.kick();
        Ok(n)
    }
}

impl Session {
    /// [`Session::open_store`]'s answer to a store it cannot read: move it
    /// aside, arm the path, and say both. See there.
    fn set_aside(&self, path: &Path, why: &str) -> Result<usize, String> {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut aside = path.as_os_str().to_owned();
        aside.push(format!(".unreadable-{secs}-{}", std::process::id()));
        let aside = PathBuf::from(aside);
        if let Err(e) = std::fs::rename(path, &aside) {
            return Err(format!(
                "{}: {why}; it could not be moved aside ({e}), so it is left as it is and \
                 this session's queue is not saved",
                path.display()
            ));
        }
        *self.inner.store.lock().unwrap_or_else(|p| p.into_inner()) = Some(path.to_path_buf());
        Err(format!(
            "{}: {why}; the file was kept as {} and a new queue is saved in its place",
            path.display(),
            aside.display()
        ))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.inner.stopping.store(true, Ordering::SeqCst);
        // Every job is cancelled: the scheduler is about to stop
        // starting work, and a worker still hashing a 200 GiB set would
        // otherwise outlive the session that owns its snapshot.
        //
        // AND THE WAKE GOES WITH THEM. A worker holds an `Arc` of its
        // publisher, so it outlives this `Session` and keeps publishing
        // until it reaches its next honouring point - and the wake it
        // rings is the host's function pointer over the host's own
        // context. `pf_session_free` does not wait for workers (it says
        // so), so a direct C caller that frees that context as soon as
        // free returns was being called back through it. Dropping the
        // wakes here closes all of it but the callback that is already
        // running, which no amount of locking can close and which
        // `parfast-ffi/API.md` now states as the host's obligation.
        //
        // AND THE STORE IS WRITTEN ONCE MORE AND THEN DISARMED, before
        // a single cancel goes out. The cancels below are the SESSION
        // ending, not a user's choice, but each worker they reach
        // finishes Cancelled and persisted that on its way out - so a
        // job that was running when the app quit came back `cancelled`,
        // and not `interrupted` as the module doc promises, whenever the
        // process outlived its session by long enough for the worker to
        // unwind. Written here it is saved as running (which a reload
        // reads as interrupted); disarmed, nothing a winding-down worker
        // does can write over that.
        self.inner.persist();
        *self.inner.store.lock().unwrap_or_else(|p| p.into_inner()) = None;
        let jobs = self.inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
        for e in jobs.values() {
            e.control.cancel();
            e.publisher.set_wake(None);
        }
        drop(jobs);
        *self.inner.wake.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.inner.kick();
    }
}

impl Inner {
    /// Change the settings, and raise the post-action latch when this
    /// change CHOSE an action - from None to anything else - over a queue
    /// that has ALREADY drained: what finished before the action existed
    /// has had its drain (see [`maybe_post_action`]).
    ///
    /// Only that change. An action that was already chosen when the queue
    /// drained is ARMED for that drain, and must stay armed however often
    /// it is written back - the Windows host writes the whole settings
    /// struct on every toggle, and the mac host re-sends it when Settings
    /// opens, so a latch raised on any write over a drained queue
    /// swallowed a "Shut down when done" chosen before the batch whenever
    /// a save landed between the last job finishing and the scheduler's
    /// next pass. Switching one action for another keeps it armed too.
    ///
    /// The write and the latch decision are made under ONE hold of the
    /// settings lock, and the latch under the table lock, where
    /// `maybe_post_action` reads it. With the action written first and the
    /// latch raised after, a scheduler pass in between saw the new action
    /// on a drained, unlatched queue and fired it.
    fn write_settings(&self, write: impl FnOnce(&mut Settings)) {
        let mut held = self.settings.lock().unwrap_or_else(|p| p.into_inner());
        let before = held.post_queue_action;
        write(&mut held);
        if before == PostQueueAction::None && held.post_queue_action != PostQueueAction::None {
            let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
            if drained(&jobs) {
                self.post_action_fired.store(true, Ordering::SeqCst);
            }
        }
    }

    fn kick(&self) {
        let _g = self.tick_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.tick.notify_all();
    }

    /// Ring the host's wake, holding NOTHING while it runs.
    ///
    /// The handle is cloned out and the mutex released first: API.md
    /// promises a wake handler may call straight back in, and
    /// `Session::set_wake` is one of the doors it may use.
    fn ring(&self) {
        let held = self
            .wake
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(Arc::clone);
        if let Some(w) = held {
            w();
        }
    }

    /// Write the table, if a store was opened. Best effort by design:
    /// a queue file that cannot be written must not stop the job that
    /// is running.
    ///
    /// # Why the whole transaction is under one lock
    ///
    /// Every mutating door calls this - submit, cancel, remove,
    /// set_settings, and a worker finishing - and the GUI's thread and
    /// the job threads reach them at once. This used to take its
    /// snapshot, drop every lock, and then write ONE fixed
    /// `<store>.json.tmp`, with no ordering anywhere: an older snapshot
    /// that got delayed between those two steps replaced a newer one, two
    /// writers truncated and wrote the SAME temporary inode, and one
    /// could rename that half-written inode into place while the other
    /// was still writing it - which is precisely the atomic replacement
    /// the temporary file exists to provide. The guard below spans
    /// snapshot generation through publication, so the writer that
    /// publishes last is the one that read the table last; the unique
    /// temporary name is the second belt, for a second PROCESS pointed at
    /// the same store, which no lock in here can reach.
    fn persist(&self) {
        let _txn = self.persist_lock.lock().unwrap_or_else(|p| p.into_inner());
        let store = self.store.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let Some(path) = store else { return };
        let settings = self
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let out = Persisted {
            version: PERSISTED_VERSION,
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
        // The seam the transaction is PROVED through - see
        // [`persist_seam`]. It is the gap between "this writer has read
        // the table" and "this writer has published it", which is
        // exactly the gap the lock above exists to make uncrossable, and
        // there is no way to observe that from outside. Compiled out of
        // every non-test build.
        #[cfg(test)]
        persist_seam(&path);
        // Written beside and renamed over: a crash mid-write must not
        // leave a half a queue, which parses as an empty one. And SYNCED
        // before the rename, or the rename can reach the disk ahead of
        // the bytes it names: a power cut then leaves a zero-length or
        // torn store at the real path, which `open_store` refuses - the
        // very outcome the rename exists to rule out. A failed rename is
        // still dropped, deliberately: see "Best effort" above.
        let tmp = persist_tmp_path(&path);
        if write_synced(&tmp, text.as_bytes()).is_ok() {
            if std::fs::rename(&tmp, &path).is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// `std::fs::write` plus `sync_all`, for [`Inner::persist`].
///
/// One full sync per persist, on whichever thread called the door - the
/// host's UI thread for a submit. Left that way deliberately (9 Nov 2026
/// review): a host adds a batch as SEQUENTIAL submits, so there is no
/// burst inside one persist to coalesce, and moving the write to a
/// background thread would make every door return before its change is
/// on disk, which the store's readers (and this crate's tests) rely on.
/// Not measured on a batch add; if it shows up, a coalescing writer
/// thread with a synchronous flush in `Drop` is the shape to build.
fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Distinguishes one `persist` temp file from the next. See there.
static PERSIST_SEQ: AtomicI64 = AtomicI64::new(0);

/// What a test installs to stand INSIDE one `persist` transaction, in
/// the window between reading the table and publishing it.
///
/// The ordering half of the persist defect cannot be seen from outside
/// the function: two writers racing is a property of a window no caller
/// can reach, and a test that merely runs a lot of writers at once and
/// hopes measures the scheduler rather than the code. So the window is
/// given a name, `#[cfg(test)]` only, and
/// `no_two_persists_are_ever_inside_the_transaction_at_once` uses it to
/// assert mutual exclusion directly.
/// It is handed the STORE being written, and a hook that does not
/// recognise it must return at once. The static is process-global while
/// the tests around it are not: `cargo test` runs this crate's whole lib
/// in ONE process, several of these tests own a Session with a store of
/// its own, and every one of them persists - so an unfiltered hook fires
/// for other tests' writes and the mutual-exclusion count reads 2 for a
/// reason that has nothing to do with the lock. Measured, on the first
/// spelling of this seam.
#[cfg(test)]
static PERSIST_SEAM: Mutex<Option<Arc<dyn Fn(&Path) + Send + Sync>>> = Mutex::new(None);

#[cfg(test)]
fn persist_seam(store: &Path) {
    // Cloned out and the lock released before the call, for the reason
    // `Inner::ring` gives: the hook may do anything, including reach
    // back into the session.
    let f = PERSIST_SEAM
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(Arc::clone);
    if let Some(f) = f {
        f(store);
    }
}

#[cfg(test)]
fn set_persist_seam(f: Option<Arc<dyn Fn(&Path) + Send + Sync>>) {
    *PERSIST_SEAM.lock().unwrap_or_else(|p| p.into_inner()) = f;
}

/// The scratch file ONE `persist` writes before renaming it over the
/// store. Never the same path twice: two writers that share a temporary
/// file truncate and write the same inode, and either may rename that
/// half-written inode into place while the other is still filling it -
/// which is the one thing the write-then-rename shape exists to prevent.
/// Pid as well as sequence, because a second process pointed at the same
/// store is outside every lock this file holds.
fn persist_tmp_path(store: &Path) -> PathBuf {
    store.with_extension(format!(
        "json.{}.{}.tmp",
        std::process::id(),
        PERSIST_SEQ.fetch_add(1, Ordering::SeqCst)
    ))
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
            let rang = entry.pair_wait.refused(first, why).inspect(|line| {
                entry
                    .publisher
                    .update_quiet(|s| s.log_tail.push(line.clone()));
            });
            drop(jobs);
            if rang.is_some() {
                inner.ring();
            }
            return false;
        }
    };
    entry.pair_wait = PairWait::default();
    entry.run_next = false;
    if entry.control.is_cancelled() {
        entry
            .publisher
            .update_quiet(|s| s.state = JobState::Cancelled);
        drop(jobs);
        // The scheduler thread rings too, and it holds the table while
        // it decides - so the wake goes out from here, with the lock
        // gone, for the reason `Publisher::update_quiet` gives.
        inner.persist();
        inner.ring();
        return true;
    }
    entry.running = true;
    entry.pair = shape;
    if let Some(first) = paired_with {
        entry.publisher.update_quiet(|s| {
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
    // The pairing note and the Running transition, rung now the table is
    // free: the two `update_quiet` calls above are silent by
    // construction, and the worker's first publish is a tick away.
    inner.ring();
    let back = Arc::clone(inner);
    std::thread::Builder::new()
        .name(format!("parfast-job-{id}"))
        .spawn(move || {
            // A PANIC IS CONTAINED HERE and turned into a failed job.
            // Uncaught, it unwound this thread past the bookkeeping below,
            // so `running` stayed true forever: at concurrency 1 nothing
            // ever started again until the app was relaunched, and the job
            // itself sat at `running` with a bar that never moved. The
            // knob lock it may have held is a `RwLock` every taker reads
            // through `into_inner`, so its poisoning stops nobody.
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runner::run(&job)))
            {
                job.publisher.update(|s| {
                    s.state = JobState::Failed;
                    s.eta_ms = None;
                    s.phase_text = "Failed".to_string();
                    s.error = Some(crate::job::JobError::new(
                        "internal",
                        format!(
                            "this job stopped on an internal error: {}",
                            panic_text(payload.as_ref())
                        ),
                    ));
                });
            }
            let mut jobs = back.jobs.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(e) = jobs.get_mut(&id) {
                e.running = false;
                e.pair = None;
            }
            for e in jobs.values_mut() {
                if let Some(line) = e.pair_wait.beside_finished(id) {
                    e.publisher.update_quiet(|s| s.log_tail.push(line));
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

/// Has the queue drained? Set the flag ONCE, so a host is asked to
/// sleep the machine once and not every tick.
///
/// # A drain under "None" is still a drain
///
/// The latch is raised for EVERY drain, and `post_action_due` only when
/// there was an action to fall due. It used to return early under None
/// without latching, so a queue that had drained with no action chosen
/// stayed unlatched - and picking "Shut down when done" afterwards, to
/// cover the batch the user was about to add, shut the machine down on
/// the next tick, over work that had finished before the action was
/// chosen. The same latch is raised from the doors that CHOOSE an action
/// ([`Inner::write_settings`], and only for a change from None), so the
/// tick between the drain and the next pass of this loop is not a window
/// either.
///
/// The drained read and both stores are under the table lock, which
/// `Session::submit` takes to insert AND to lower the flags: see there.
fn maybe_post_action(inner: &Arc<Inner>) {
    #[cfg(test)]
    if inner.post_action_held.load(Ordering::SeqCst) {
        return;
    }
    if inner.post_action_fired.load(Ordering::SeqCst) {
        return;
    }
    let action = inner
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .post_queue_action;
    let jobs = inner.jobs.lock().unwrap_or_else(|p| p.into_inner());
    // Read AGAIN under the table lock: `Inner::write_settings` may have
    // latched between the read above and this one, for an action that
    // the read of `action` already saw.
    if inner.post_action_fired.load(Ordering::SeqCst) || !drained(&jobs) {
        return;
    }
    inner.post_action_fired.store(true, Ordering::SeqCst);
    let due = action != PostQueueAction::None;
    if due {
        inner.post_action_due.store(true, Ordering::SeqCst);
    }
    drop(jobs);
    if due {
        inner.ring();
    }
}

/// Is there something here, all of it finished? An empty queue on a
/// fresh launch has not "finished".
fn drained(jobs: &BTreeMap<i64, Entry>) -> bool {
    !jobs.is_empty() && jobs.values().all(|e| e.publisher.get().state.finished())
}

/// What a caught panic said, for the failed job's error.
pub(crate) fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no message".to_string())
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

    /// P2: `overwrite = false` protects the WHOLE set, not just the index.
    ///
    /// The guard asked one question - does `spec.output` exist - so a
    /// set whose index was gone (deleted, or written under a different
    /// `-f`) left its recovery volumes unprotected: the engine's
    /// `File::create` truncated them, the CLI's rename walked over the
    /// survivors, and the job reported Done. The pane's own protection,
    /// on the only files it protects.
    ///
    /// Both arms, because only the pair pins the rule: an existing
    /// volume with the index ABSENT must refuse, and a clean directory
    /// must still create.
    #[test]
    fn a_no_overwrite_create_refuses_an_existing_recovery_volume() {
        use crate::job::{
            BlockSpec, CreateSpec, PathMode, RecoverySpec, UnicodePolicy, VolumeSpec,
        };
        let d = tmp("nooverwrite-vol");
        std::fs::write(d.join("a.bin"), vec![3u8; 64_000]).expect("member");
        let spec = CreateSpec {
            sources: vec![Source {
                path: d.join("a.bin"),
                recursive: false,
            }],
            path_mode: PathMode::Basename,
            base_path: None,
            block: Some(BlockSpec::Size { size: 8_192 }),
            recovery: Some(RecoverySpec::Count { count: 1 }),
            output: d.join("set.par2"),
            volumes: VolumeSpec::Pow2,
            first_recovery_block: 0,
            comment: String::new(),
            overwrite: false,
            std_naming: false,
            unicode: UnicodePolicy::Auto,
            perf: Default::default(),
        };
        // A volume of some earlier run, and NO index beside it.
        const SENTINEL: &[u8] = b"an earlier run's recovery volume";
        std::fs::write(d.join("set.vol0+1.par2"), SENTINEL).expect("sentinel");
        assert!(!spec.output.exists(), "the index is deliberately absent");

        let s = Session::new(None);
        let id = s.submit(JobSpec::Create {
            create: spec.clone(),
        });
        let q = until(&s, "the create", |q| {
            q.jobs.iter().any(|j| j.id == id && j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
        assert_eq!(job.state, JobState::Failed, "{job:?}");
        assert_eq!(
            job.error.as_ref().map(|e| e.code.as_str()),
            Some("exists"),
            "{job:?}"
        );
        assert_eq!(
            std::fs::read(d.join("set.vol0+1.par2")).expect("the volume"),
            SENTINEL,
            "a no-overwrite create replaced an existing recovery volume"
        );

        // The other arm: nothing there, and the same spec creates.
        std::fs::remove_file(d.join("set.vol0+1.par2")).expect("clear");
        let id = s.submit(JobSpec::Create { create: spec });
        let q = until(&s, "the second create", |q| {
            q.jobs.iter().any(|j| j.id == id && j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
        assert_eq!(job.state, JobState::Done, "{job:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// THE CONTROL ARM for the guard above, and for the engine door it
    /// now hands down: `overwrite = true` still replaces the set that is
    /// there.
    ///
    /// `run_create` publishes the pane's decision to the engine as
    /// `parfast --no-clobber`, which opens every file of the set with
    /// `O_EXCL` - the half the preflight above cannot do, because a set
    /// that appears after the check walks straight through it. That
    /// makes the polarity of one line load-bearing in a way it was not
    /// before: with it inverted, the Overwrite tick would start REFUSING
    /// every re-run, and the preflight - which the tick switches off -
    /// would say nothing about it. Both files of the existing set are
    /// laid down, index and volume, because they are refused by
    /// different doors (the engine's open, and the rename that
    /// publishes the final name).
    #[test]
    fn an_overwrite_create_still_replaces_the_set_that_is_there() {
        use crate::job::{
            BlockSpec, CreateSpec, PathMode, RecoverySpec, UnicodePolicy, VolumeSpec,
        };
        let d = tmp("overwrite-yes");
        std::fs::write(d.join("a.bin"), vec![5u8; 64_000]).expect("member");
        std::fs::write(d.join("set.par2"), b"an earlier index").expect("old index");
        std::fs::write(d.join("set.vol0+1.par2"), b"an earlier volume").expect("old volume");

        let s = Session::new(None);
        let id = s.submit(JobSpec::Create {
            create: CreateSpec {
                sources: vec![Source {
                    path: d.join("a.bin"),
                    recursive: false,
                }],
                path_mode: PathMode::Basename,
                base_path: None,
                block: Some(BlockSpec::Size { size: 8_192 }),
                recovery: Some(RecoverySpec::Count { count: 1 }),
                output: d.join("set.par2"),
                volumes: VolumeSpec::Pow2,
                first_recovery_block: 0,
                comment: String::new(),
                overwrite: true,
                std_naming: false,
                unicode: UnicodePolicy::Auto,
                perf: Default::default(),
            },
        });
        let q = until(&s, "the overwriting create", |q| {
            q.jobs.iter().any(|j| j.id == id && j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
        assert_eq!(job.state, JobState::Done, "{job:?}");
        for name in ["set.par2", "set.vol0+1.par2"] {
            let len = std::fs::metadata(d.join(name)).expect(name).len();
            assert!(len > 64, "{name} is still the old file at {len} bytes");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P1: a checksum create never writes over one of its own inputs.
    ///
    /// The write was an unconditional `fs::write` with no identity check
    /// at all, so `payload.bin` checksummed INTO `payload.bin` replaced
    /// the file being protected with a one-line manifest of what it used
    /// to be - and reported Done. The data is gone; the manifest that
    /// replaced it describes a file that no longer exists.
    #[test]
    fn a_checksum_create_refuses_to_write_over_its_own_source() {
        let d = tmp("cksum-self");
        let payload = d.join("payload.bin");
        const ORIGINAL: &[u8] = b"ORIGINAL DATA";
        std::fs::write(&payload, ORIGINAL).expect("payload");
        let s = Session::new(None);
        let id = s.submit(JobSpec::ChecksumCreate {
            checksum_create: ChecksumCreateSpec {
                sources: vec![Source {
                    path: payload.clone(),
                    recursive: false,
                }],
                format: ChecksumFormat::Sha256,
                output: payload.clone(),
                relative: false,
            },
        });
        let q = until(&s, "the checksum create", |q| {
            q.jobs.iter().any(|j| j.id == id && j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
        assert_eq!(job.state, JobState::Failed, "{job:?}");
        assert_eq!(
            std::fs::read(&payload).expect("the payload"),
            ORIGINAL,
            "the checksum create overwrote the file it was protecting"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P1's other half: a RECURSIVE source over the manifest's own
    /// folder does not hash the manifest.
    ///
    /// The second run over a folder picked up the checksum file written
    /// by the first, so the manifest recorded its own previous contents
    /// and mismatched itself the instant it was rewritten. Dropped
    /// rather than refused - a whole folder is the ordinary way to ask
    /// for this - so the run still succeeds and covers the real files.
    #[test]
    fn a_checksum_create_over_its_own_folder_is_stable_across_runs() {
        let d = tmp("cksum-folder");
        std::fs::write(d.join("a.bin"), vec![1u8; 512]).expect("a");
        std::fs::write(d.join("b.bin"), vec![2u8; 512]).expect("b");
        let out = d.join("sums.sha256");
        let spec = ChecksumCreateSpec {
            sources: vec![Source {
                path: d.clone(),
                recursive: true,
            }],
            format: ChecksumFormat::Sha256,
            output: out.clone(),
            relative: true,
        };
        let s = Session::new(None);
        let run = |s: &Session, spec: &ChecksumCreateSpec| {
            let id = s.submit(JobSpec::ChecksumCreate {
                checksum_create: spec.clone(),
            });
            let q = until(s, "the checksum create", |q| {
                q.jobs.iter().any(|j| j.id == id && j.state.finished())
            });
            q.jobs.iter().find(|j| j.id == id).expect("the job").clone()
        };
        let first = run(&s, &spec);
        assert_eq!(first.state, JobState::Done, "{first:?}");
        let text1 = std::fs::read_to_string(&out).expect("manifest");
        let second = run(&s, &spec);
        assert_eq!(second.state, JobState::Done, "{second:?}");
        let text2 = std::fs::read_to_string(&out).expect("manifest");
        assert_eq!(
            text1, text2,
            "the second run hashed the first run's manifest"
        );
        assert!(
            !text1.contains("sums.sha256"),
            "the manifest lists itself: {text1}"
        );

        // ...and it verifies clean, in place.
        let id = s.submit(JobSpec::ChecksumVerify {
            checksum_verify: ChecksumVerifySpec { file: out },
        });
        let q = until(&s, "the verify", |q| {
            q.jobs.iter().any(|j| j.id == id && j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
        assert_eq!(job.state, JobState::Done, "{job:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P7: never write a manifest this same code cannot read back.
    ///
    /// A source that does not sit under the manifest's own directory has
    /// no name the format can carry, and `expand_sources` fell back to
    /// the source's own absolute path. The checker resolves names under
    /// the manifest folder, so the file the user had just hashed came
    /// back Missing while sitting untouched where it always was.
    #[test]
    fn a_checksum_create_refuses_a_source_outside_the_manifest_folder() {
        let d = tmp("cksum-outside");
        let out_dir = d.join("output");
        std::fs::create_dir_all(&out_dir).expect("output dir");
        let payload = d.join("payload.bin");
        std::fs::write(&payload, vec![9u8; 1024]).expect("payload");
        let s = Session::new(None);
        let id = s.submit(JobSpec::ChecksumCreate {
            checksum_create: ChecksumCreateSpec {
                sources: vec![Source {
                    path: payload,
                    recursive: false,
                }],
                format: ChecksumFormat::Sha256,
                output: out_dir.join("sums.sha256"),
                relative: true,
            },
        });
        let q = until(&s, "the checksum create", |q| {
            q.jobs.iter().any(|j| j.id == id && j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
        assert_eq!(job.state, JobState::Failed, "{job:?}");
        assert_eq!(
            job.error.as_ref().map(|e| e.code.as_str()),
            Some("outside_checksum_folder"),
            "{job:?}"
        );
        assert!(
            !out_dir.join("sums.sha256").exists(),
            "a manifest this reader cannot resolve was written anyway"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P8: a manifest written here checks clean here, for names the
    /// download path's sanitizer would have rewritten.
    ///
    /// The checker resolved through `disk::sanitize_out_name`, which is
    /// the function that decides what to CREATE for a name a stranger
    /// declared - it trims leading whitespace, folds trailing dots and
    /// spaces, and maps a leading dot to `_`. Applied to a name being
    /// LOOKED UP, every one of those rewrites names a different file:
    /// `" name.bin"` was hashed, written and then reported Missing by
    /// the same process, seconds apart.
    #[test]
    fn checksum_names_round_trip_for_names_the_download_sanitizer_rewrites() {
        let d = tmp("cksum-names");
        // Each of these survives on APFS and on ext4 and is rewritten by
        // the download sanitizer: a leading space is trimmed, a trailing
        // dot is folded the way Windows folds it, and the non-ASCII name
        // is the control that must go through untouched either way.
        //
        // NOT a leading-dot name, though the sanitizer maps those to `_`
        // as well: `planner::skipped` drops dot-files before any of this,
        // which is par2cmdline's source rule and a separate question from
        // the one under test here.
        let awkward = [" leading space.bin", "trailing dot.", "ünïcøde.bin"];
        for (i, name) in awkward.iter().enumerate() {
            std::fs::write(d.join(name), vec![i as u8 + 1; 256]).expect("fixture");
        }
        let out = d.join("sums.sha256");
        let s = Session::new(None);
        let id = s.submit(JobSpec::ChecksumCreate {
            checksum_create: ChecksumCreateSpec {
                sources: awkward
                    .iter()
                    .map(|n| Source {
                        path: d.join(n),
                        recursive: false,
                    })
                    .collect(),
                format: ChecksumFormat::Sha256,
                output: out.clone(),
                relative: true,
            },
        });
        let q = until(&s, "the checksum create", |q| {
            q.jobs.iter().any(|j| j.id == id && j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
        assert_eq!(job.state, JobState::Done, "{job:?}");

        let id = s.submit(JobSpec::ChecksumVerify {
            checksum_verify: ChecksumVerifySpec { file: out },
        });
        let q = until(&s, "the verify", |q| {
            q.jobs.iter().any(|j| j.id == id && j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
        let tally = job
            .result
            .as_ref()
            .and_then(|r| r.checksum.as_ref())
            .expect("a checksum result");
        assert_eq!(
            (tally.ok, tally.missing, tally.mismatch),
            (awkward.len(), 0, 0),
            "files this very run hashed came back unresolved: {:?}",
            tally.entries
        );
        assert_eq!(job.state, JobState::Done, "{job:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The LINE must read back as the name too, not just the name
    /// through the resolver: the reader trims each line, so a trailing
    /// space (any format) or a leading one (SFV, where the name leads)
    /// was written and then verified as Missing by the same process
    /// (Gemini sweep M1). Refused up front, and nothing is written.
    #[test]
    fn a_checksum_create_refuses_a_name_its_own_line_cannot_carry() {
        for (tag, name, format, ext) in [
            ("trail", "trailing.bin ", ChecksumFormat::Sha256, "sha256"),
            ("lead-sfv", " leading.bin", ChecksumFormat::Sfv, "sfv"),
        ] {
            let d = tmp(&format!("cksum-line-{tag}"));
            std::fs::write(d.join(name), vec![5u8; 256]).expect("fixture");
            let out = d.join(format!("sums.{ext}"));
            let s = Session::new(None);
            let id = s.submit(JobSpec::ChecksumCreate {
                checksum_create: ChecksumCreateSpec {
                    sources: vec![Source {
                        path: d.join(name),
                        recursive: false,
                    }],
                    format,
                    output: out.clone(),
                    relative: true,
                },
            });
            let q = until(&s, "the checksum create", |q| {
                q.jobs.iter().any(|j| j.id == id && j.state.finished())
            });
            let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
            assert_eq!(job.state, JobState::Failed, "{tag}: {job:?}");
            assert_eq!(
                job.error.as_ref().map(|e| e.code.as_str()),
                Some("unrepresentable_name"),
                "{tag}: {job:?}"
            );
            assert!(
                !out.exists(),
                "{tag}: a manifest that reads back wrong was written"
            );
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// A checksum create hashes what it was POINTED AT.
    ///
    /// `expand_sources` applied par2cmdline's source rules to every
    /// caller, and the checksum pane is not par2cmdline: a folder
    /// holding a PAR2 set produced a manifest with every `.par2`
    /// missing from it, and a dot-file named EXPLICITLY as a source was
    /// dropped with nothing said. Both then verified CLEAN, because what
    /// is not in the manifest is not checked - which is the worst shape
    /// a "verified" answer can have. Found while testing P8 of the
    /// 17 Sep sweep; `planner::SourceRules` is the fix.
    ///
    /// The PAR2 side keeps its rule, and the control arm below is what
    /// says so - a create over the same folder still protects only
    /// `movie.mkv`.
    #[test]
    fn a_checksum_create_covers_par2_files_and_dot_files() {
        use crate::job::{
            BlockSpec, CreateSpec, PathMode, RecoverySpec, UnicodePolicy, VolumeSpec,
        };
        let d = tmp("cksum-rules");
        for name in ["movie.mkv", "movie.par2", ".hidden.bin"] {
            std::fs::write(d.join(name), vec![6u8; 512]).expect("fixture");
        }
        let out = d.join("sums.sha256");
        let s = Session::new(None);
        let id = s.submit(JobSpec::ChecksumCreate {
            checksum_create: ChecksumCreateSpec {
                sources: vec![Source {
                    path: d.clone(),
                    recursive: true,
                }],
                format: ChecksumFormat::Sha256,
                output: out.clone(),
                relative: true,
            },
        });
        let q = until(&s, "the checksum create", |q| {
            q.jobs.iter().any(|j| j.id == id && j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
        assert_eq!(job.state, JobState::Done, "{job:?}");
        let text = std::fs::read_to_string(&out).expect("manifest");
        for want in ["movie.mkv", "movie.par2", ".hidden.bin"] {
            assert!(text.contains(want), "{want} is not in the manifest: {text}");
        }
        assert!(
            !text.contains("sums.sha256"),
            "the manifest lists itself: {text}"
        );

        // The PAR2 side is UNCHANGED: par2cmdline does not protect a
        // dot-file or another set's recovery files, and neither do we.
        // Its own folder, because the manifest written above would
        // otherwise be a member of it and the count would say nothing.
        let p2 = d.join("par2side");
        std::fs::create_dir_all(&p2).expect("dir");
        for name in ["movie.mkv", "movie.par2", ".hidden.bin"] {
            std::fs::write(p2.join(name), vec![6u8; 512]).expect("fixture");
        }
        let preview = crate::planner::preview(&CreateSpec {
            sources: vec![Source {
                path: p2.clone(),
                recursive: true,
            }],
            path_mode: PathMode::Basename,
            base_path: None,
            block: Some(BlockSpec::Size { size: 512 }),
            recovery: Some(RecoverySpec::Count { count: 1 }),
            output: p2.join("set.par2"),
            volumes: VolumeSpec::Pow2,
            first_recovery_block: 0,
            comment: String::new(),
            overwrite: true,
            std_naming: false,
            unicode: UnicodePolicy::Auto,
            perf: Default::default(),
        })
        .expect("preview");
        assert_eq!(
            preview.source_files, 1,
            "a PAR2 create must still skip the dot-file and the .par2"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P10: nothing checked is not a clean check.
    ///
    /// An extension hint rescued a file with zero entries, so
    /// `empty.sha256` holding one comment verified zero of zero and came
    /// back Done with a green tick - while the identical text named
    /// `empty.txt` was refused. Which answer a user got turned on the
    /// spelling of the file name.
    #[test]
    fn a_checksum_file_with_no_entries_is_not_a_successful_check() {
        let d = tmp("cksum-empty");
        let s = Session::new(None);
        for name in ["empty.sha256", "empty.txt"] {
            let f = d.join(name);
            std::fs::write(&f, "; nothing here\n\n").expect("fixture");
            let id = s.submit(JobSpec::ChecksumVerify {
                checksum_verify: ChecksumVerifySpec { file: f },
            });
            let q = until(&s, "the verify", |q| {
                q.jobs.iter().any(|j| j.id == id && j.state.finished())
            });
            let job = q.jobs.iter().find(|j| j.id == id).expect("the job");
            assert_eq!(
                job.state,
                JobState::Failed,
                "{name} verified nothing and called it a pass: {job:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P3: a RELAUNCH is not a drain.
    ///
    /// The action is armed by the queue finishing work. Restoring a
    /// table whose jobs were all finished in some earlier session is not
    /// that, and until 17 Sep 2026 it read as exactly that: the fired
    /// latch lived only in memory, so the first scheduler tick of the
    /// new process found a drained queue with "Sleep" saved beside it
    /// and armed the action. The host reads that flag and puts the
    /// machine to sleep - on a launch during which nothing ran, every
    /// launch, until the user changed the setting.
    #[test]
    fn a_restored_finished_queue_does_not_re_arm_the_post_action() {
        let d = tmp("qpost-restore");
        let store = d.join("queue.json");
        {
            let s = Session::new(None);
            s.open_store(&store).expect("open store");
            s.set_post_action(PostQueueAction::Sleep);
            s.submit(checksum_job(&d, 1));
            until(&s, "the post action to fall due", |q| q.post_action_due);
            // The host has dealt with it - which is the state a machine
            // that actually slept and woke comes back in.
            s.clear_post_action_due();
            assert!(!s.snapshot().post_action_due);
        }
        let s = Session::new(None);
        let n = s.open_store(&store).expect("reopen");
        assert_eq!(n, 1, "the finished job is restored");
        assert_eq!(s.snapshot().post_action, "sleep", "and so is the action");
        for _ in 0..30 {
            assert!(
                !s.snapshot().post_action_due,
                "a relaunch armed the saved power action with no work behind it"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // ...and a NEW batch still re-arms it, which is the half a
        // blanket disarm would have broken.
        s.submit(checksum_job(&d, 2));
        until(&s, "a new batch to re-arm the action", |q| {
            q.post_action_due
        });
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P4: cancelling a QUEUED job is written down.
    ///
    /// A cancel changed the published state and woke the scheduler, and
    /// nothing else - the save was left to the worker completion that
    /// would follow. For a job that never runs there is no such worker:
    /// the scheduler skips a cancelled entry forever, so on a paused
    /// queue (or any queue the process leaves first) the cancellation
    /// existed only in memory and the job came back Queued and RAN.
    #[test]
    fn a_cancelled_queued_job_stays_cancelled_across_a_restart() {
        let d = tmp("qcancel-store");
        let store = d.join("queue.json");
        let id = {
            let s = Session::new(None);
            s.set_queue_paused(true);
            s.open_store(&store).expect("open store");
            let id = s.submit(checksum_job(&d, 1));
            assert!(s.cancel(id));
            assert_eq!(s.job(id).expect("the job").state, JobState::Cancelled);
            id
        };
        let s = Session::new(None);
        s.set_queue_paused(true);
        s.open_store(&store).expect("reopen");
        assert_eq!(
            s.job(id).expect("the job came back").state,
            JobState::Cancelled,
            "a cancelled job came back runnable"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P5: a wake handler may call straight back in, which is what
    /// API.md promises and what a host that polls from its wake does.
    ///
    /// `cancel` held the jobs table while it published the new state,
    /// and publishing rings the wake ON THE CALLING THREAD - so the
    /// handler's `snapshot()` re-entered a `std` mutex the same thread
    /// already held, and the call never returned. The test would HANG
    /// rather than fail if this regressed, so the poll runs on a second
    /// thread with a deadline in front of it.
    #[test]
    fn a_wake_handler_that_polls_does_not_wedge_a_cancel() {
        use std::sync::mpsc;
        let d = tmp("qwake");
        let s = Arc::new(Session::new(None));
        s.set_queue_paused(true);
        let weak = Arc::downgrade(&s);
        let rang = Arc::new(AtomicI64::new(0));
        let counter = Arc::clone(&rang);
        s.set_wake(Some(Arc::new(move || {
            if let Some(live) = weak.upgrade() {
                // The re-entrant poll itself. Every door a host reaches
                // for from a wake, on the ringing thread.
                let _ = live.snapshot();
                let _ = live.settings();
                counter.fetch_add(1, Ordering::SeqCst);
            }
        })));
        let id = s.submit(checksum_job(&d, 1));
        let (tx, rx) = mpsc::channel();
        let worker = Arc::clone(&s);
        let t = std::thread::spawn(move || {
            let ok = worker.cancel(id);
            let _ = tx.send(ok);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(ok) => assert!(ok, "the cancel refused a queued job"),
            Err(e) => panic!("cancel never returned ({e}) - a lock is held across the wake"),
        }
        t.join().expect("the cancelling thread");
        assert!(
            rang.load(Ordering::SeqCst) > 0,
            "the wake never fired, so nothing was proved"
        );
        assert_eq!(s.job(id).expect("the job").state, JobState::Cancelled);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P6, the half that is DETERMINISTIC: no two persists share a
    /// scratch file.
    ///
    /// The write used one fixed `<store>.json.tmp` for every caller, so
    /// two concurrent writers truncated and filled the same inode and
    /// either could rename it into place while the other was still
    /// writing it - publishing a torn table through the very mechanism
    /// that exists to make the replacement atomic. The ordering half of
    /// the same defect is answered by the transaction lock in
    /// [`Inner::persist`] and exercised by the soak below; this is the
    /// part a test can pin outright.
    #[test]
    fn no_two_persists_write_the_same_scratch_file() {
        let store = Path::new("/tmp/parfast-queue-store/queue.json");
        let a = persist_tmp_path(store);
        let b = persist_tmp_path(store);
        assert_ne!(a, b, "two persists would share a temp inode");
        for p in [&a, &b] {
            assert_eq!(
                p.parent(),
                store.parent(),
                "the scratch file must sit beside the store, or the rename is cross-device"
            );
            assert!(
                p.to_string_lossy().ends_with(".tmp"),
                "{}: the store's own reader skips `.tmp` by suffix",
                p.display()
            );
        }
    }

    /// P6's ordering half, DETERMINISTICALLY: two persists are never
    /// inside the transaction at once.
    ///
    /// The soak below cannot prove this and says so - two writers racing
    /// is a property of a window no caller can reach from outside, and
    /// running eight of them and hoping measures the scheduler. So the
    /// window has a name (`PERSIST_SEAM`, `#[cfg(test)]` only) and this
    /// stands in it: every writer records that it is inside, waits long
    /// enough that any other writer would have joined it if it could,
    /// and records the high-water mark. Under the transaction lock that
    /// mark is 1, always. Without it, eight writers each holding the
    /// window open reach 8 - it is the SLEEP that makes the failure
    /// certain rather than likely, which is the opposite of a timing
    /// test: the test passes on a property and fails on a fact.
    #[test]
    fn no_two_persists_are_ever_inside_the_transaction_at_once() {
        let d = tmp("qpersist-excl");
        let store = d.join("queue.json");
        let s = Arc::new(Session::new(None));
        s.set_queue_paused(true);
        s.open_store(&store).expect("open store");
        s.submit(checksum_job(&d, 1));

        let inside = Arc::new(AtomicI64::new(0));
        let peak = Arc::new(AtomicI64::new(0));
        {
            let (inside, peak) = (Arc::clone(&inside), Arc::clone(&peak));
            let mine = store.clone();
            set_persist_seam(Some(Arc::new(move |written: &Path| {
                // ONLY this test's store: the seam is process-global and
                // the other tests in this binary are persisting too.
                if written != mine {
                    return;
                }
                let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                // Wide enough that a second writer WOULD be seen if one
                // could get in, and short enough to cost nothing.
                std::thread::sleep(std::time::Duration::from_millis(10));
                inside.fetch_sub(1, Ordering::SeqCst);
            })));
        }
        let gate = Arc::new(std::sync::Barrier::new(8));
        let mut hands = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&s);
            let gate = Arc::clone(&gate);
            hands.push(std::thread::spawn(move || {
                gate.wait();
                let mut set = s.settings();
                set.concurrency = 2;
                s.set_settings(set);
            }));
        }
        for h in hands {
            h.join().expect("a writer thread");
        }
        set_persist_seam(None);
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "two writers were inside one persist transaction at once"
        );
        // And what landed is still a whole table.
        let text = std::fs::read_to_string(&store).expect("the store is there");
        serde_json::from_str::<Persisted>(&text).expect("the store parses");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P6's ordering half, as a SOAK and labelled one: every mutating
    /// door on the store at once, and what lands must be a whole table.
    ///
    /// It did NOT reproduce the race against the unfixed code on this
    /// box (17 Sep 2026) and is not claimed to - the interleaving needs
    /// a writer descheduled between its snapshot and its publication,
    /// which nothing here can force without a hook in `persist`. The
    /// finding is source-traced and the fix is the transaction lock; this
    /// keeps the concurrent path exercised and would catch a future
    /// change that published a partial table under load.
    #[test]
    fn concurrent_persists_never_publish_a_torn_store() {
        let d = tmp("qpersist-race");
        let store = d.join("queue.json");
        let s = Arc::new(Session::new(None));
        s.set_queue_paused(true);
        s.open_store(&store).expect("open store");
        // Enough jobs that one table is several KiB, so a torn write has
        // room to be visibly torn.
        let ids: Vec<i64> = (0..24).map(|_| s.submit(checksum_job(&d, 1))).collect();
        let gate = Arc::new(std::sync::Barrier::new(9));
        let mut hands = Vec::new();
        for k in 0..8 {
            let s = Arc::clone(&s);
            let gate = Arc::clone(&gate);
            let ids = ids.clone();
            hands.push(std::thread::spawn(move || {
                gate.wait();
                for _ in 0..12 {
                    if k % 2 == 0 {
                        let mut set = s.settings();
                        set.concurrency = (k as u32 % 3) + 1;
                        s.set_settings(set);
                    } else {
                        s.cancel(ids[k as usize % ids.len()]);
                    }
                }
            }));
        }
        gate.wait();
        for h in hands {
            h.join().expect("a writer thread");
        }
        let text = std::fs::read_to_string(&store).expect("the store is there");
        let back: Persisted = serde_json::from_str(&text).expect("the store parses");
        assert_eq!(
            back.jobs.len(),
            ids.len(),
            "a published table lost jobs, so a stale or torn snapshot won"
        );
        // And no temp file is left lying beside it.
        let strays: Vec<_> = std::fs::read_dir(&d)
            .expect("read dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(strays.is_empty(), "temp files left behind: {strays:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A store that cannot be parsed is reported, never deleted: it is
    /// kept beside, under a name the error gives.
    #[test]
    fn an_unreadable_store_is_reported_and_kept() {
        let d = tmp("qbad");
        let store = d.join("queue.json");
        std::fs::write(&store, "{ not json").expect("write");
        let s = Session::new(None);
        let e = s.open_store(&store).expect_err("refused");
        let kept = set_aside_files(&d);
        assert_eq!(
            kept.len(),
            1,
            "a queue file must never be deleted: {kept:?}"
        );
        assert!(e.contains(&kept[0]), "the error names where it went: {e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The `<name>.unreadable-...` files beside a store.
    fn set_aside_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".unreadable-"))
            .collect()
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
        let (d, s) = built_set(tag);

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

    /// The three-member set [`verify_after`] works on, created through a
    /// session, with that session handed back for the next job.
    fn built_set(tag: &str) -> (PathBuf, Session) {
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
        (d, s)
    }

    /// "Keep damaged copies" and "Delete the recovery files" are TWO
    /// decisions, and a repair honours each on its own: the `<name>.1`
    /// copy survives exactly when it was asked to, and the recovery
    /// files go exactly when they were asked to. Until 14 Oct 2026
    /// `keep_damaged` was read by nothing, so purge took the copy the
    /// user had ticked to keep and an unticked box kept it anyway
    /// (Gemini sweep H7). All four corners, each off a real repair.
    #[test]
    fn a_repair_keeps_the_damaged_copy_exactly_when_asked() {
        for (purge, keep_damaged) in [(false, true), (false, false), (true, true), (true, false)] {
            let tag = format!("keepdamaged-{purge}-{keep_damaged}");
            let (d, s) = built_set(&tag);
            // Same length, different bytes: a damaged member, not a
            // missing one, so the engine backs it aside before writing.
            let mut alpha = std::fs::read(d.join("alpha.bin")).expect("member");
            for b in &mut alpha[1_000..1_400] {
                *b ^= 0x5a;
            }
            std::fs::write(d.join("alpha.bin"), &alpha).expect("damage");
            let id = s.submit(JobSpec::Repair {
                repair: crate::job::RepairSpec {
                    par2: d.join("set.par2"),
                    extra_dirs: Vec::new(),
                    options: Default::default(),
                    purge,
                    keep_damaged,
                },
            });
            let q = until(&s, "the repair", |q| {
                q.jobs
                    .iter()
                    .find(|j| j.id == id)
                    .is_some_and(|j| j.state.finished())
            });
            let job = q.jobs.iter().find(|j| j.id == id).expect("the repair");
            assert_eq!(job.state, JobState::Done, "{tag}: {job:?}");
            assert_eq!(
                d.join("alpha.bin.1").exists(),
                keep_damaged,
                "{tag}: the damaged copy"
            );
            assert_eq!(
                d.join("set.par2").exists(),
                !purge,
                "{tag}: the recovery set's index"
            );
            assert!(d.join("alpha.bin").exists(), "{tag}: the repaired member");
            // And the snapshot names the equivalent command (M18.5).
            assert!(
                job.command.starts_with("parfast r ") && job.command.contains("set.par2"),
                "{tag}: {:?}",
                job.command
            );
            assert_eq!(
                job.command.contains(" -p "),
                purge,
                "{tag}: {:?}",
                job.command
            );
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// A finished repair's survey describes the set: its name and folder,
    /// its block size, every member's size and block count. The repair
    /// path builds its survey from the engine's per-member COUNTS, which
    /// carry none of these, so the window drew a completed repair with a
    /// blank title, "0 bytes" for the block size and "0 bytes" beside
    /// every file - found driving the mac app against the real engine,
    /// 9 Nov 2026. With purge on, because that deletes the index the
    /// description is read from: it must be read before the repair.
    #[test]
    fn a_finished_repair_describes_the_set() {
        for purge in [false, true] {
            let tag = format!("repair-describes-{purge}");
            let (d, s) = built_set(&tag);
            let mut alpha = std::fs::read(d.join("alpha.bin")).expect("member");
            for b in &mut alpha[1_000..1_400] {
                *b ^= 0x5a;
            }
            std::fs::write(d.join("alpha.bin"), &alpha).expect("damage");
            let id = s.submit(JobSpec::Repair {
                repair: crate::job::RepairSpec {
                    par2: d.join("set.par2"),
                    extra_dirs: Vec::new(),
                    options: Default::default(),
                    purge,
                    keep_damaged: false,
                },
            });
            let q = until(&s, "the repair", |q| {
                q.jobs
                    .iter()
                    .find(|j| j.id == id)
                    .is_some_and(|j| j.state.finished())
            });
            let job = q.jobs.iter().find(|j| j.id == id).expect("the repair");
            assert_eq!(job.state, JobState::Done, "{tag}: {job:?}");
            let survey = job.survey.as_ref().expect("a repair carries a survey");
            assert_eq!(survey.set_name, "set.par2", "{tag}");
            assert_eq!(survey.folder, d.to_string_lossy(), "{tag}");
            assert_eq!(survey.block_size, 2_048, "{tag}");
            let want = [
                ("alpha.bin", 30_001u64),
                ("bravo.bin", 41_000),
                ("charlie.bin", 22_003),
            ];
            assert_eq!(survey.files.len(), want.len(), "{tag}");
            for (name, len) in want {
                let row = survey
                    .files
                    .iter()
                    .find(|f| f.name == name)
                    .unwrap_or_else(|| panic!("{tag}: no row for {name}"));
                assert_eq!(row.size, len, "{tag}: {name} size");
                let blocks = len.div_ceil(2_048) as usize;
                assert_eq!(row.blocks_total, blocks, "{tag}: {name} blocks");
                assert_eq!(row.blocks_ok, blocks, "{tag}: {name} blocks ok");
            }
            let _ = std::fs::remove_dir_all(&d);
        }
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

    /// A3: a store that cannot be read is never written over - the
    /// path used to be armed before the parse, so the next submit renamed
    /// a fresh table over it - and it does not stop persistence for good
    /// either: a zero-length or torn file is kept aside, byte for byte,
    /// and the queue is saved afresh at the real path.
    #[test]
    fn a_torn_store_is_kept_aside_and_the_queue_is_saved_afresh() {
        for torn in ["{ not json", ""] {
            let d = tmp("qbad-armed");
            let store = d.join("queue.json");
            std::fs::write(&store, torn).expect("write");
            let s = Session::new(None);
            s.set_queue_paused(true);
            assert!(s.open_store(&store).is_err());
            s.submit(checksum_job(&d, 1));
            let kept = set_aside_files(&d);
            assert_eq!(kept.len(), 1, "{torn:?}: {kept:?}");
            assert_eq!(
                std::fs::read_to_string(d.join(&kept[0])).expect("kept"),
                torn,
                "the unreadable file was not kept as it was"
            );
            let saved: Persisted =
                serde_json::from_str(&std::fs::read_to_string(&store).expect("saved afresh"))
                    .expect("a whole table");
            assert_eq!(saved.jobs.len(), 1, "{torn:?}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// A3's second shape: a queue written by a NEWER build is refused by
    /// its version even when this build could parse it, and left alone.
    #[test]
    fn a_store_from_a_newer_build_is_refused_by_its_version() {
        let d = tmp("qnewer");
        let store = d.join("queue.json");
        let newer = format!(
            r#"{{"version":{},"settings":{{}},"jobs":[]}}"#,
            PERSISTED_VERSION + 1
        );
        std::fs::write(&store, &newer).expect("write");
        let s = Session::new(None);
        s.set_queue_paused(true);
        let e = s.open_store(&store).expect_err("a newer format is refused");
        assert!(e.contains("newer"), "{e}");
        s.submit(checksum_job(&d, 1));
        assert_eq!(std::fs::read_to_string(&store).expect("there"), newer);
        assert!(set_aside_files(&d).is_empty(), "a newer store was moved");
        // ...and a newer store THIS build cannot even parse is still known
        // to be newer by its version alone.
        let newer_shape = format!(
            r#"{{"version":{},"jobs":"a shape from the future"}}"#,
            PERSISTED_VERSION + 1
        );
        std::fs::write(&store, &newer_shape).expect("write");
        let s = Session::new(None);
        s.set_queue_paused(true);
        assert!(s.open_store(&store).expect_err("refused").contains("newer"));
        s.submit(checksum_job(&d, 1));
        assert_eq!(std::fs::read_to_string(&store).expect("there"), newer_shape);
        assert!(set_aside_files(&d).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A store opened AFTER a submit keeps the live job: a restored id
    /// that collides takes a fresh one, and the counter never rewinds.
    #[test]
    fn opening_a_store_after_a_submit_keeps_the_live_job() {
        let d = tmp("qrewind");
        let store = d.join("queue.json");
        {
            let s = Session::new(None);
            s.set_queue_paused(true);
            s.open_store(&store).expect("open");
            s.submit(checksum_job(&d, 1));
            s.submit(checksum_job(&d, 1));
        }
        let s = Session::new(None);
        s.set_queue_paused(true);
        let live = s.submit(checksum_job(&d, 2));
        assert_eq!(s.open_store(&store).expect("reopen"), 3);
        let snap = s.snapshot();
        let mut ids: Vec<i64> = snap.jobs.iter().map(|j| j.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 3, "an id was reused: {:?}", snap.jobs);
        assert!(s.job(live).is_some(), "the live job was replaced");
        let next = s.submit(checksum_job(&d, 1));
        assert!(
            ids.iter().all(|&i| next > i),
            "the counter rewound: {next} vs {ids:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A10: Cancel on a FINISHED job is refused, and the job keeps its
    /// state and its result.
    #[test]
    fn cancelling_a_finished_job_is_refused_and_keeps_its_result() {
        let d = tmp("qcancel-done");
        let s = Session::new(None);
        let id = s.submit(checksum_job(&d, 1));
        until(&s, "the job to finish", |q| q.jobs[0].state.finished());
        assert!(!s.cancel(id), "a finished job accepted a cancel");
        let j = s.job(id).expect("the job");
        assert_eq!(j.state, JobState::Done, "{j:?}");
        assert!(j.result.is_some(), "the result went");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A20: a job that panics FAILS, and the queue goes on to the next
    /// one - at concurrency 1, where a stuck `running` stopped
    /// everything.
    #[test]
    fn a_panicking_job_fails_and_the_queue_moves_on() {
        let d = tmp("qpanic");
        let boom = d.join("boom.sha256");
        let _seam = {
            let boom = boom.clone();
            runner::RUN_SEAM.add(Arc::new(move |job: &Job| {
                if let JobSpec::ChecksumCreate { checksum_create } = &job.spec
                    && checksum_create.output == boom
                {
                    panic!("a deliberate test panic");
                }
            }))
        };
        let s = Session::new(None);
        s.set_queue_paused(true);
        let mut first = checksum_job(&d, 1);
        if let JobSpec::ChecksumCreate { checksum_create } = &mut first {
            checksum_create.output = boom.clone();
        }
        let bad = s.submit(first);
        let good = s.submit(checksum_job(&d, 2));
        s.set_queue_paused(false);
        let snap = until(&s, "both jobs to finish", |q| {
            q.jobs.iter().all(|j| j.state.finished())
        });
        let b = snap.jobs.iter().find(|j| j.id == bad).expect("bad");
        assert_eq!(b.state, JobState::Failed, "{b:?}");
        assert_eq!(b.error.as_ref().map(|e| e.code.as_str()), Some("internal"));
        let g = snap.jobs.iter().find(|j| j.id == good).expect("good");
        assert_eq!(g.state, JobState::Done, "{g:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A21: an action chosen AFTER the queue drained does not fire over
    /// work that had already finished - and a new batch still arms it.
    #[test]
    fn an_action_chosen_after_the_drain_waits_for_the_next_batch() {
        let d = tmp("qpost-late");
        let s = Session::new(None);
        s.submit(checksum_job(&d, 1));
        until(&s, "the batch to finish", |q| q.jobs[0].state.finished());
        s.set_post_action(PostQueueAction::Shutdown);
        for _ in 0..40 {
            assert!(
                !s.snapshot().post_action_due,
                "an action chosen after the drain fired over finished work"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        s.submit(checksum_job(&d, 2));
        until(&s, "the next batch to arm the action", |q| {
            q.post_action_due
        });
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The other half of A21: an action chosen BEFORE the batch stays
    /// armed through a settings write that lands after the last job
    /// finished and before the scheduler noticed the drain - the Windows
    /// host writes the whole struct on every toggle, the mac host on
    /// opening Settings. The scheduler's pass is held off so the test
    /// stands in that gap instead of racing it.
    #[test]
    fn an_action_chosen_before_the_drain_survives_a_settings_save() {
        let d = tmp("qpost-armed");
        let s = Session::new(None);
        s.inner.post_action_held.store(true, Ordering::SeqCst);
        s.set_post_action(PostQueueAction::Shutdown);
        s.submit(checksum_job(&d, 1));
        until(&s, "the batch to finish", |q| q.jobs[0].state.finished());
        // The gap: drained, and the scheduler has not looked yet.
        s.set_settings(s.settings());
        s.set_post_action(PostQueueAction::Shutdown);
        s.set_post_action(PostQueueAction::Sleep);
        s.inner.post_action_held.store(false, Ordering::SeqCst);
        let q = until(&s, "the armed action to fall due", |q| q.post_action_due);
        assert_eq!(q.post_action, "sleep");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Session B4: a job RUNNING when the session ends comes back
    /// interrupted, never cancelled. The session's own shutdown cancels
    /// every worker, and each one used to persist that on its way out.
    #[test]
    fn a_job_running_when_the_session_ends_comes_back_interrupted() {
        let d = tmp("qquit");
        let store = d.join("queue.json");
        let id = {
            let s = Session::new(None);
            s.set_queue_paused(true);
            s.open_store(&store).expect("open");
            let id = s.submit(checksum_job(&d, 1));
            // Paused before it starts, so the worker parks at its first
            // gate and STAYS running until the session ends.
            assert!(s.set_job_paused(id, true));
            s.set_queue_paused(false);
            until(&s, "the job to park", |q| {
                q.jobs[0].state == JobState::Paused
            });
            id
        };
        // The cancel releases the parked worker at once; give it every
        // chance to write what it used to write.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(750);
        while std::time::Instant::now() < deadline {
            let text = std::fs::read_to_string(&store).expect("the store");
            assert!(
                !text.contains("\"cancelled\""),
                "a winding-down worker wrote Cancelled over the store"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let s = Session::new(None);
        s.set_queue_paused(true);
        s.open_store(&store).expect("reopen");
        assert_eq!(s.job(id).expect("the job").state, JobState::Interrupted);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Session B5: a concurrency or a power action set through its own
    /// door reaches the store, with nothing else written after it.
    #[test]
    fn concurrency_and_the_post_action_are_persisted_on_their_own() {
        let d = tmp("qpersist-knobs");
        let store = d.join("queue.json");
        // Read off the FILE while the session is still alive: the session
        // writes once more when it ends, which would carry either value
        // and hide a door that never wrote (a killed app gets no such
        // last write). Each door alone, so neither carries the other.
        let stored = || -> Persisted {
            serde_json::from_str(&std::fs::read_to_string(&store).expect("the store"))
                .expect("parses")
        };
        let s = Session::new(None);
        s.open_store(&store).expect("open");
        s.set_concurrency(3);
        assert_eq!(stored().settings.concurrency, 3);
        s.set_post_action(PostQueueAction::Notify);
        assert_eq!(stored().settings.post_queue_action, PostQueueAction::Notify);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A9's GUI twin: a Cancel that lands AFTER the repair completed -
    /// in the window between the engine returning and the runner reading
    /// the flag - reports Done with its result, not Cancelled with none.
    /// The window is sub-millisecond, so the test stands in it through
    /// `runner::REPAIR_RETURNED_SEAM` rather than racing it.
    #[test]
    fn a_cancel_after_the_repair_completed_reports_done() {
        let (d, s) = built_set("late-cancel-repair");
        let mut alpha = std::fs::read(d.join("alpha.bin")).expect("member");
        for b in &mut alpha[1_000..1_400] {
            *b ^= 0x5a;
        }
        std::fs::write(d.join("alpha.bin"), &alpha).expect("damage");
        let par2 = d.join("set.par2");
        let _seam = {
            let par2 = par2.clone();
            runner::REPAIR_RETURNED_SEAM.add(Arc::new(move |job: &Job| {
                if let JobSpec::Repair { repair } = &job.spec
                    && repair.par2 == par2
                {
                    job.control.cancel();
                }
            }))
        };
        let id = s.submit(JobSpec::Repair {
            repair: crate::job::RepairSpec {
                par2: par2.clone(),
                extra_dirs: Vec::new(),
                options: Default::default(),
                purge: false,
                keep_damaged: true,
            },
        });
        let q = until(&s, "the repair", |q| {
            q.jobs
                .iter()
                .find(|j| j.id == id)
                .is_some_and(|j| j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the repair");
        assert_eq!(job.state, JobState::Done, "{job:?}");
        let r = job
            .result
            .as_ref()
            .expect("a completed repair names its result");
        assert_eq!(r.repaired_files, 1, "{r:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The other half of that rule: a repair that did NOT complete still
    /// reports a late Cancel, so the change above is not "ignore every
    /// late cancel". Same seam, same moment, over a set too damaged to
    /// repair.
    #[test]
    fn a_late_cancel_on_a_repair_that_did_not_complete_still_reports_cancelled() {
        let (d, s) = built_set("late-cancel-unrepairable");
        for n in ["alpha.bin", "bravo.bin", "charlie.bin"] {
            std::fs::remove_file(d.join(n)).expect("remove");
        }
        let par2 = d.join("set.par2");
        let _seam = {
            let par2 = par2.clone();
            runner::REPAIR_RETURNED_SEAM.add(Arc::new(move |job: &Job| {
                if let JobSpec::Repair { repair } = &job.spec
                    && repair.par2 == par2
                {
                    job.control.cancel();
                }
            }))
        };
        let id = s.submit(JobSpec::Repair {
            repair: crate::job::RepairSpec {
                par2: par2.clone(),
                extra_dirs: Vec::new(),
                options: Default::default(),
                purge: false,
                keep_damaged: true,
            },
        });
        let q = until(&s, "the repair", |q| {
            q.jobs
                .iter()
                .find(|j| j.id == id)
                .is_some_and(|j| j.state.finished())
        });
        let job = q.jobs.iter().find(|j| j.id == id).expect("the repair");
        assert_eq!(job.state, JobState::Cancelled, "{job:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A create from the Create pane's defaults, for the end-to-end
    /// tests below.
    fn create_over(sources: Vec<PathBuf>, output: PathBuf) -> crate::job::CreateSpec {
        use crate::job::{BlockSpec, PathMode, RecoverySpec, UnicodePolicy, VolumeSpec};
        crate::job::CreateSpec {
            sources: sources
                .into_iter()
                .map(|path| Source {
                    path,
                    recursive: false,
                })
                .collect(),
            path_mode: PathMode::Basename,
            base_path: None,
            block: Some(BlockSpec::Size { size: 4_096 }),
            recovery: Some(RecoverySpec::Count { count: 4 }),
            output,
            volumes: VolumeSpec::Pow2,
            first_recovery_block: 0,
            comment: String::new(),
            overwrite: false,
            std_naming: false,
            unicode: UnicodePolicy::Auto,
            perf: Default::default(),
        }
    }

    fn run_one(spec: JobSpec) -> JobSnapshot {
        let s = Session::new(None);
        let id = s.submit(spec);
        let q = until(&s, "the job", |q| q.jobs.iter().all(|j| j.state.finished()));
        q.jobs.into_iter().find(|j| j.id == id).expect("the job")
    }

    /// A6, end to end: a Basename create written into a DIFFERENT folder
    /// stores each member by its bare name - not under the raw absolute
    /// path the create fell back to with no `-B`.
    #[test]
    fn a_set_written_elsewhere_stores_bare_member_names() {
        let d = tmp("elsewhere-names");
        let (src, out) = (d.join("src"), d.join("out"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(src.join("a.bin"), vec![9u8; 50_000]).unwrap();
        let j = run_one(JobSpec::Create {
            create: create_over(vec![src.join("a.bin")], out.join("set.par2")),
        });
        assert_eq!(j.state, JobState::Done, "{j:?}");
        let index = std::fs::read(out.join("set.par2")).expect("the index");
        let has = |needle: &str| index.windows(needle.len()).any(|w| w == needle.as_bytes());
        assert!(has("a.bin"), "the member is named");
        assert!(
            !has(&src.to_string_lossy()),
            "the member was stored under its source folder's path"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A6 across SEVERAL folders, with the set written outside all of
    /// them: the run succeeds (the create now IGNORES a source outside its
    /// base rather than storing a raw path), every member is stored by its
    /// path below the sources' common folder, and the pane's file sizes -
    /// built on the member names - are the sizes on disk, which they are
    /// only if the pane named the members as the run stored them.
    #[test]
    fn a_set_over_several_folders_written_elsewhere_matches_its_preview() {
        let d = tmp("elsewhere-folders");
        let (src, out) = (d.join("src"), d.join("out"));
        std::fs::create_dir_all(src.join("deeper")).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(src.join("a.bin"), vec![9u8; 50_000]).unwrap();
        std::fs::write(src.join("deeper/c.bin"), vec![5u8; 30_000]).unwrap();
        let spec = create_over(
            vec![src.join("a.bin"), src.join("deeper/c.bin")],
            out.join("set.par2"),
        );
        let preview = crate::planner::preview(&spec).expect("preview");
        assert!(
            preview
                .warnings
                .iter()
                .any(|w| w.contains("more than one folder")),
            "{:?}",
            preview.warnings
        );
        let j = run_one(JobSpec::Create { create: spec });
        assert_eq!(j.state, JobState::Done, "{j:?}");
        let index = std::fs::read(out.join("set.par2")).expect("the index");
        let has = |needle: &str| index.windows(needle.len()).any(|w| w == needle.as_bytes());
        assert!(
            has("deeper/c.bin") && has("a.bin"),
            "both members are named"
        );
        assert!(
            !has(&src.to_string_lossy()),
            "a member kept its source path"
        );
        let on_disk: Vec<(String, u64)> = j
            .result
            .as_ref()
            .expect("result")
            .written
            .iter()
            .map(|w| (w.name.clone(), w.size))
            .collect();
        let drawn: Vec<(String, u64)> = preview
            .files
            .iter()
            .map(|f| (f.name.clone(), f.size))
            .collect();
        assert_eq!(
            on_disk, drawn,
            "the pane drew a different set from the one written"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The verify-lane's A1, as the GUI draws it: a member the Main
    /// packet declares with NO FileDesc makes the set Unrepairable - never
    /// Complete beside the CLI's exit 6, which is what the survey said
    /// when it judged the described members alone.
    #[test]
    fn a_member_with_no_filedesc_is_never_drawn_complete() {
        let (d, s) = built_set("undescribed");
        // Drop bravo's FileDesc from every file of the set; a dropped
        // packet needs no reseal. A dumb packet walk, as the CLI lane's
        // own test is, so the engine's parser cannot agree with itself.
        const MAGIC: &[u8; 8] = b"PAR2\0PKT";
        const FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
        for e in std::fs::read_dir(&d).expect("dir").flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("par2") {
                continue;
            }
            let bytes = std::fs::read(&path).expect("read");
            let mut out = Vec::with_capacity(bytes.len());
            let mut i = 0usize;
            while i < bytes.len() {
                let framed = i + 64 <= bytes.len() && &bytes[i..i + 8] == MAGIC;
                let len = if framed {
                    u64::from_le_bytes(bytes[i + 8..i + 16].try_into().expect("8")) as usize
                } else {
                    0
                };
                if !framed || len < 64 || i + len > bytes.len() {
                    out.push(bytes[i]);
                    i += 1;
                    continue;
                }
                let pkt = &bytes[i..i + len];
                i += len;
                let named_bravo = &pkt[48..64] == FILEDESC
                    && String::from_utf8_lossy(&pkt[64 + 56..])
                        .trim_end_matches('\0')
                        .starts_with("bravo.bin");
                if !named_bravo {
                    out.extend_from_slice(pkt);
                }
            }
            std::fs::write(&path, out).expect("write");
        }
        let id = s.submit(JobSpec::Verify {
            verify: VerifySpec {
                par2: d.join("set.par2"),
                extra_dirs: Vec::new(),
                options: Default::default(),
            },
        });
        let q = until(&s, "the verify", |q| {
            q.jobs
                .iter()
                .find(|j| j.id == id)
                .is_some_and(|j| j.state.finished())
        });
        let j = q.jobs.iter().find(|j| j.id == id).expect("verify");
        assert_eq!(
            j.result.as_ref().and_then(|r| r.exit_code),
            Some(6),
            "{j:?}"
        );
        let m = j.survey.as_ref().expect("a survey");
        assert_eq!(m.verdict, Verdict::Unrepairable, "{m:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `title` (the mac lane's ask): every snapshot names its job from its
    /// spec, and a job restored from a store written before the field
    /// existed still gets one.
    #[test]
    fn every_snapshot_carries_a_title_and_a_restored_one_too() {
        let d = tmp("qtitle");
        let store = d.join("queue.json");
        {
            let s = Session::new(None);
            s.set_queue_paused(true);
            s.open_store(&store).expect("open");
            let id = s.submit(checksum_job(&d, 1));
            assert_eq!(s.job(id).expect("job").title, "out.sha256");
        }
        // A store from before the field: every `title` taken out.
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&store).expect("store")).expect("json");
        for j in v["jobs"].as_array_mut().expect("jobs") {
            j["snapshot"]
                .as_object_mut()
                .expect("snapshot")
                .remove("title");
        }
        std::fs::write(&store, v.to_string()).expect("rewrite");
        let s = Session::new(None);
        s.set_queue_paused(true);
        s.open_store(&store).expect("reopen");
        assert_eq!(s.snapshot().jobs[0].title, "out.sha256");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Review item 3, end to end: a set at `/out/set.par2` over sources in
    /// `/out/sub` verifies COMPLETE from its own folder - the member names
    /// keep `sub/`, so the verify finds every one where it is.
    #[test]
    fn a_set_over_a_subfolder_verifies_complete_from_its_own_folder() {
        let d = tmp("subfolder-verify");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub/a.bin"), vec![3u8; 40_000]).unwrap();
        let j = run_one(JobSpec::Create {
            create: create_over(vec![d.join("sub/a.bin")], d.join("set.par2")),
        });
        assert_eq!(j.state, JobState::Done, "{j:?}");
        let v = run_one(JobSpec::Verify {
            verify: VerifySpec {
                par2: d.join("set.par2"),
                extra_dirs: Vec::new(),
                options: Default::default(),
            },
        });
        assert_eq!(
            v.result.as_ref().and_then(|r| r.exit_code),
            Some(0),
            "{v:?}"
        );
        assert_eq!(
            v.survey.as_ref().map(|m| m.verdict),
            Some(Verdict::Complete)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A38, end to end: the two volume asks the pane accepted and the
    /// create used to refuse now RUN.
    #[test]
    fn volume_counts_the_pane_accepts_are_counts_the_create_runs() {
        use crate::job::{RecoverySpec, VolumeSpec};
        let d = tmp("volcount-run");
        std::fs::write(d.join("a.bin"), vec![4u8; 64_000]).unwrap();
        let mut none = create_over(vec![d.join("a.bin")], d.join("none.par2"));
        none.recovery = Some(RecoverySpec::Count { count: 0 });
        none.volumes = VolumeSpec::None;
        let j = run_one(JobSpec::Create { create: none });
        assert_eq!(j.state, JobState::Done, "no recovery, no split: {j:?}");
        let mut many = create_over(vec![d.join("a.bin")], d.join("many.par2"));
        many.volumes = VolumeSpec::Uniform {
            files: Some(30),
            blocks_per_file: None,
            file_size: None,
        };
        let j = run_one(JobSpec::Create { create: many });
        assert_eq!(j.state, JobState::Done, "30 files over 4 blocks: {j:?}");
        let vols = j
            .result
            .as_ref()
            .expect("result")
            .written
            .iter()
            .filter(|w| w.name.contains(".vol"))
            .count();
        assert_eq!(vols, 4, "{:?}", j.result);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Runner B7: a checksum verify's per-row log lines are held to the
    /// log length setting like every other line; the rows themselves are
    /// all in the result.
    #[test]
    fn a_checksum_verify_keeps_its_log_to_the_setting() {
        let d = tmp("verify-logcap");
        let s = Session::new(Some(Settings {
            log_tail_lines: 2,
            ..Settings::default()
        }));
        s.submit(checksum_job(&d, 5));
        until(&s, "the manifest", |q| q.jobs[0].state.finished());
        let id = s.submit(JobSpec::ChecksumVerify {
            checksum_verify: ChecksumVerifySpec {
                file: d.join("out.sha256"),
            },
        });
        let q = until(&s, "the verify", |q| {
            q.jobs.iter().all(|j| j.state.finished())
        });
        let j = q.jobs.iter().find(|j| j.id == id).expect("verify");
        assert_eq!(j.state, JobState::Done, "{j:?}");
        assert!(j.log_tail.len() <= 2, "{:?}", j.log_tail);
        let rows = j
            .result
            .as_ref()
            .and_then(|r| r.checksum.as_ref())
            .expect("rows");
        assert_eq!(rows.entries.len(), 5);
        let _ = std::fs::remove_dir_all(&d);
    }
}
