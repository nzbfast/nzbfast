//! What happens when the queue runs dry: nothing (the default), a
//! script, sleep, or shut the machine down. SABnzbd's "on queue finish"
//! action, which we had no answer to at all.
//!
//! Three things make this different from every other setting here, and
//! all three are about the same worry: two of the four choices turn the
//! machine off, so the one failure that matters is firing when the user
//! did not mean it.
//!
//!  1. **The trigger is an EDGE, never a state.** `note_queue_idle`
//!     already owns "the queue just ran dry" - it is latched, it is on
//!     every path that can empty a queue (park, delete, pause the last
//!     runnable job), and it emits `queue.idle` exactly once until an
//!     add or a pick re-arms it. This hangs off that same CAS rather
//!     than sampling the queue on a timer, so "once per drain" is a
//!     property of the substrate and not of anything written here. A
//!     poller would have re-fired on every tick of a quiet queue.
//!  2. **A drain is not enough.** `queue.idle` deliberately treats a
//!     paused job as not keeping the queue busy - a held duplicate is
//!     paused by design, and the subscribers that spin a disk down do
//!     not care. Shutting the machine down over a job the user paused
//!     five minutes ago and means to resume is a different matter, so
//!     [`drain_blocker`] re-checks the queue and refuses on anything the
//!     user could still resume. Held alternatives (priority -3, paused
//!     by design, invisible until their primary fails) are the one
//!     exception, or an install that keeps duplicates around would never
//!     fire at all.
//!  3. **Sleep and shutdown count down first, in public, with a cancel
//!     button.** The countdown rides the queue payload the dashboard
//!     already polls every second. It is abandoned if new work arrives
//!     while it runs, and firing DISARMS the setting (SAB's semantics):
//!     a machine that wakes to a still-empty queue must not go back to
//!     sleep, and a shutdown that the user cancelled must not lie in
//!     wait for the next drain.
//!
//! The script action is sticky, because a notifier or a library refresh
//! is meant to run every time and turns nothing off.

use super::*;

/// What to do when the queue finishes.
///
/// The persisted key is the lowercase name (`queue_finished_action`);
/// anything else is refused by the settings arm rather than silently
/// read as `None`, so a typo cannot look like "off" when the user
/// believes they armed a script.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FinishAction {
    #[default]
    None,
    Script,
    Sleep,
    Shutdown,
}

impl FinishAction {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim() {
            "" | "none" | "off" => Self::None,
            "script" => Self::Script,
            "sleep" | "standby" | "suspend" => Self::Sleep,
            "shutdown" | "poweroff" => Self::Shutdown,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Script => "script",
            Self::Sleep => "sleep",
            Self::Shutdown => "shutdown",
        }
    }

    /// Does firing it turn it back off?
    ///
    /// Yes for the two that end the session, and the asymmetry is the
    /// point: a script is a notifier and wants to run every time, while
    /// a sleep that re-armed itself would put a woken machine straight
    /// back to sleep over the same empty queue it slept on. This is
    /// SABnzbd's rule too.
    pub fn one_shot(self) -> bool {
        matches!(self, Self::Sleep | Self::Shutdown)
    }

    /// Does it need the countdown and the cancel button before it runs?
    pub fn counts_down(self) -> bool {
        self.one_shot()
    }
}

/// A sleep or shutdown that has been announced and not yet run.
#[derive(Clone, Copy)]
pub struct Pending {
    pub action: FinishAction,
    pub at: Instant,
}

/// Everything this feature keeps on the daemon, as ONE field: the
/// `Daemon` struct is declared in `crates/nzbfast-daemon/src/daemon.rs`, which sat at its
/// size-gate ceiling when this was written (the 31 Aug 2026
/// recalibration moved it), and four loose fields would not fit.
/// Grouping is also honest: these five only ever move together.
pub struct FinishState {
    pub action: Mutex<FinishAction>,
    pub script: Mutex<Option<PathBuf>>,
    pub delay_secs: AtomicU64,
    /// The drain edge, set by `note_queue_idle`'s latch CAS and TAKEN
    /// (swapped false) by the lane. A bool rather than a channel so the
    /// emitter - which runs under the queue lock - does nothing but
    /// store a byte.
    pub drained: AtomicBool,
    /// The refusal reason last logged, so a drain edge that is HELD
    /// across many ticks says why once rather than every two seconds.
    pub last_refusal: Mutex<Option<&'static str>>,
    pub pending: Mutex<Option<Pending>>,
}

impl Default for FinishState {
    fn default() -> Self {
        FinishState {
            action: Mutex::new(FinishAction::None),
            script: Mutex::new(None),
            delay_secs: AtomicU64::new(DEFAULT_DELAY_SECS),
            drained: AtomicBool::new(false),
            last_refusal: Mutex::new(None),
            pending: Mutex::new(None),
        }
    }
}

/// How long the countdown runs before a sleep or shutdown, when the user
/// has not said otherwise. Long enough to walk back to the machine and
/// cancel, short enough that "shut down when it finishes" still means
/// tonight rather than in an hour.
pub(crate) const DEFAULT_DELAY_SECS: u64 = 60;

/// Ceiling on the countdown. An hour is already far past any use for it,
/// and an unbounded value is a countdown that never ends - which reads
/// to the user as the feature being broken rather than as their typo.
const MAX_DELAY_SECS: u64 = 3600;

/// How long the lane sleeps between passes with nothing pending. It only
/// has to notice a drain edge that has already happened, so seconds are
/// fine and one wakeup every two seconds is cheaper than the stall
/// watchdog beside it.
const IDLE_TICK: std::time::Duration = std::time::Duration::from_secs(2);

/// ...and while a countdown runs, when the banner's remaining seconds
/// and the cancel-on-new-work check both want to be fresh.
const COUNTDOWN_TICK: std::time::Duration = std::time::Duration::from_millis(500);

/// How long a queue-finished script may run before it is killed. Shared
/// with the post-processing script's own setting deliberately: it is the
/// same question about the same kind of program, and a second timeout
/// field would be one more thing to get wrong.
fn script_budget(d: &Daemon) -> u64 {
    d.script_timeout.load(Ordering::Relaxed)
}

impl FinishState {
    pub(crate) fn action(&self) -> FinishAction {
        *self.action.lock_ok()
    }

    pub(crate) fn set_action(&self, a: FinishAction) {
        *self.action.lock_ok() = a;
        // Changing the choice abandons any countdown already running.
        // Switching from shutdown to none while the banner is up is the
        // clearest possible statement that the user does not want it.
        *self.pending.lock_ok() = None;
    }

    pub(crate) fn set_script(&self, p: Option<PathBuf>) {
        *self.script.lock_ok() = p;
    }

    pub(crate) fn script(&self) -> Option<PathBuf> {
        self.script.lock_ok().clone()
    }

    pub(crate) fn set_delay_secs(&self, n: u64) -> u64 {
        let n = n.min(MAX_DELAY_SECS);
        self.delay_secs.store(n, Ordering::Relaxed);
        n
    }

    pub(crate) fn delay_secs(&self) -> u64 {
        self.delay_secs.load(Ordering::Relaxed)
    }

    /// The queue just ran dry. Called from `note_queue_idle`'s latch CAS
    /// - i.e. exactly once per drain - and from nowhere else.
    ///
    /// Runs under the queue lock, so it stores and returns. Everything
    /// that could block, read the queue again or spawn a process happens
    /// on the lane.
    pub(crate) fn note_drained(&self) {
        self.drained.store(true, Ordering::Relaxed);
    }

    fn take_drain_edge(&self) -> bool {
        self.drained.swap(false, Ordering::Relaxed)
    }

    fn pending(&self) -> Option<Pending> {
        *self.pending.lock_ok()
    }

    fn clear_pending(&self) -> Option<Pending> {
        self.pending.lock_ok().take()
    }
}

/// Why this drain must NOT fire the action, or `None` if it may.
///
/// `queue.idle` has already said the queue ran dry; this is the stricter
/// second question that only the destructive actions need asked. A job
/// the user paused is work they intend to come back to, and a machine
/// that shut down over it did the one thing they were not expecting.
///
/// Held alternatives are exempt. They are paused by construction - the
/// dupe ladder parks them at [`DUPE_PRIORITY`] and promotes one only when
/// the primary fails - so the user never asked for them and usually does
/// not know they are there. Counting them would mean an install with
/// duplicate handling on never fires this at all.
pub(crate) fn drain_blocker(d: &Daemon) -> Option<&'static str> {
    // The latch is the edge's own evidence, and it is cleared by the
    // next add or pick. Re-reading it here is what makes "a job arrived
    // during the countdown" cancel rather than shut the machine down on
    // top of a fresh download.
    if !d.queue_idle_latch.load(Ordering::Relaxed) {
        return Some("new work arrived");
    }
    if d.exiting.load(Ordering::Relaxed) {
        return Some("nzbfast is shutting down");
    }
    // A payload the mover is still relocating has LEFT the queue - park
    // files the record before handing the move over, precisely so the
    // runner does not wait on a NAS copy - so the walk below cannot see
    // it. Sleeping or powering off in the middle of a bulk copy to a
    // network volume is the one outcome a queue-finished action must
    // never produce, and it is likeliest exactly here: the copy is the
    // slowest thing that happens after the queue looks empty.
    // `mover_inflight` and not just the two structures: a job is in
    // NEITHER `mover_q` nor `moving` while the dispatcher resolves its
    // lane (a config read plus an fs metadata walk - seconds on a hung
    // network mount) and for a lane's whole 2 s busy-requeue sleep. The
    // counter covers the hand-off from enqueue to the lane's last word.
    if d.mover_inflight.load(Ordering::Relaxed) > 0
        || !d.moving.lock_ok().is_empty()
        || !d.mover_q.lock_ok().is_empty()
    {
        return Some("a finished download is still being moved");
    }
    let q = d.queue.lock_ok();
    for j in q.iter() {
        let g = j.lock_ok();
        // `finalizing` catches a Completed row whose post-processing
        // tail (unlock/unpack, rename, the pp-script) is still running:
        // it stays in the queue until park, but matches neither state
        // arm below, and powering off mid-unpack is exactly what this
        // walk exists to refuse.
        if g.finalizing || matches!(g.state, JobState::Downloading | JobState::Finishing) {
            return Some("a download is still finishing");
        }
        if g.state == JobState::Queued {
            // Held alternative: paused by design, not by the user.
            if g.paused && g.priority == DUPE_PRIORITY {
                continue;
            }
            return Some(if g.paused {
                "a paused download is still in the queue"
            } else {
                "a download is still waiting to start"
            });
        }
    }
    None
}

/// The lane. One thread, mostly asleep, that turns the drain edge into
/// an action - and owns the countdown while one runs.
///
/// A thread rather than a tokio task for the same reason `auto-conn` is
/// one: it blocks on a child process (`run_capped`), and a weak daemon
/// reference plus `RunStop` is the established shape for a lane that
/// must not keep a stopped engine's daemon alive.
pub fn spawn_finish_watcher(daemon: &Arc<Daemon>) {
    let dw = Arc::downgrade(daemon);
    let stop = crate::RunStop::current();
    crate::spawn_aux("queue-finish", move || {
        let mut nap = IDLE_TICK;
        loop {
            if !stop.sleep(nap) {
                return;
            }
            let Some(d) = dw.upgrade() else { return };
            nap = tick(&d);
        }
    });
}

/// One pass. Returns how long to sleep before the next one.
pub fn tick(d: &Arc<Daemon>) -> std::time::Duration {
    // A countdown in flight outranks a fresh edge: it IS the previous
    // edge, still being served, and a second one cannot arrive without
    // work having arrived first - which cancels this one below.
    if let Some(p) = d.finish.pending() {
        if let Some(why) = drain_blocker(d) {
            if d.finish.clear_pending().is_some() {
                announce(d, p.action, "cancelled", why);
                // Give the edge back, exactly as the refusal path
                // below does. The latch still being set means this
                // idle period will never issue another edge, so a
                // countdown cancelled by a transient blocker (a move
                // auto-retry mid-drain) that merely SPENDS the edge
                // has silently disarmed the action until unrelated
                // new work drains again.
                if d.queue_idle_latch.load(Ordering::Relaxed) {
                    d.finish.note_drained();
                }
            }
            return IDLE_TICK;
        }
        if Instant::now() < p.at {
            return COUNTDOWN_TICK;
        }
        // Take it before firing: a cancel landing in this instant loses
        // the race, and the alternative (fire, then clear) would let a
        // second pass fire the same countdown twice.
        if d.finish.clear_pending().is_some() {
            fire(d, p.action);
        }
        return IDLE_TICK;
    }
    if !d.finish.take_drain_edge() {
        return IDLE_TICK;
    }
    let action = d.finish.action();
    if action == FinishAction::None {
        return IDLE_TICK;
    }
    if let Some(why) = drain_blocker(d) {
        // Hold the edge rather than spend it. `note_queue_idle`
        // short-circuits on the set latch, so it can never issue a
        // SECOND edge for an idle period that is already announced -
        // and a refusal that consumed this one therefore disarmed the
        // action for good: emptying the queue by deleting the job that
        // blocked it would then sit there and never fire. Re-armed only
        // while the queue is still idle; if new work arrived the latch
        // is already clear and the next drain issues its own edge.
        if d.queue_idle_latch.load(Ordering::Relaxed) {
            d.finish.note_drained();
        }
        // Once per distinct reason: the edge above is now held across
        // every tick until the blocker clears, and this runs every two
        // seconds.
        let mut last = d.finish.last_refusal.lock_ok();
        if *last != Some(why) {
            *last = Some(why);
            info!(
                target: "finish",
                "queue-finished action ({}) not run: {why}",
                action.as_str()
            );
        }
        return IDLE_TICK;
    }
    *d.finish.last_refusal.lock_ok() = None;
    if !action.counts_down() {
        fire(d, action);
        return IDLE_TICK;
    }
    let secs = d.finish.delay_secs();
    *d.finish.pending.lock_ok() = Some(Pending {
        action,
        at: Instant::now() + std::time::Duration::from_secs(secs),
    });
    announce(d, action, "armed", &format!("in {secs}s"));
    // The banner rides the revisioned queue payload, so the poll has to
    // be told there is something new to send.
    d.queue_rev.fetch_add(1, Ordering::Relaxed);
    COUNTDOWN_TICK
}

/// Do it.
fn fire(d: &Arc<Daemon>, action: FinishAction) {
    // Disarm BEFORE running anything, and persist it. A shutdown that
    // reaches the OS never comes back here to tidy up, and a sleep comes
    // back to the same empty queue it slept on - either way the stored
    // value has to already say "none" or the next start re-arms itself.
    if action.one_shot() {
        disarm(d);
    }
    match action {
        FinishAction::None => {}
        FinishAction::Script => run_finish_script(d),
        FinishAction::Sleep | FinishAction::Shutdown => run_power_action(d, action),
    }
}

/// Put the setting back to `none`, live and on disk.
pub fn disarm(d: &Arc<Daemon>) {
    d.finish.set_action(FinishAction::None);
    if !save_settings(
        &d.settings_path,
        &[("queue_finished_action", json!("none"))],
    ) {
        // Not fatal and deliberately not an error: the live value is
        // already off, which is what stops a second firing THIS run. Say
        // it anyway, because a restart would bring the arm back.
        warn!(
            target: "finish",
            "could not write the disarmed queue-finished action to {} - \
             it comes back armed on the next start",
            d.settings_path.display()
        );
    }
    d.queue_rev.fetch_add(1, Ordering::Relaxed);
}

/// Cancel a countdown from the dashboard's button.
///
/// Also disarms, and that is a decision rather than an oversight: the
/// user is looking at "shutting down in 43 seconds" and pressing stop.
/// Reading that as "not this time, but do it after the next batch"
/// leaves a machine armed to power off by someone who just said no. Two
/// clicks to arm it again is the right price.
pub fn cancel(d: &Arc<Daemon>) -> Value {
    let had = d.finish.clear_pending();
    let armed = d.finish.action();
    let disarmed = armed.one_shot();
    if disarmed {
        disarm(d);
    }
    if let Some(p) = had {
        announce(d, p.action, "cancelled", "cancelled from the dashboard");
    }
    // Two separate facts, because the two callers press this from
    // different states: the banner stops a countdown that is running, and
    // the header chip switches off an arm that has not fired yet. One
    // boolean would have told the chip's user their countdown had already
    // ended, over a click that did exactly what they asked.
    json!({"cancelled": had.is_some(), "disarmed": disarmed})
}

/// One line in the log, one marker on the throughput chart, one
/// lifecycle event for anything subscribed to the webhook stream.
fn announce(d: &Arc<Daemon>, action: FinishAction, what: &str, detail: &str) {
    let sentence = format!("queue-finished action {} {what}: {detail}", action.as_str());
    info!(target: "finish", "{sentence}");
    d.note_event("finish", sentence);
    // event-arm-gate: a STATE, not a moment - the countdown banner and
    // the header's finChip both draw it from the queue payload's
    // `finish_action`, live and with a button that stops it. §129 1b
    // finding (b) is the rule.
    d.life_emit(
        "queue.finished_action",
        json!({"action": action.as_str(), "phase": what, "detail": detail}),
    );
}

/// Run the user's queue-finished script.
///
/// No positional arguments: this is not a job, so SABnzbd's eight
/// per-job slots have nothing to put in them and passing empty strings
/// would only invite a script to read them as real values. What it gets
/// instead is an environment naming the event, which is what a notifier
/// or a library refresh actually needs.
fn run_finish_script(d: &Arc<Daemon>) {
    let Some(script) = d.finish.script() else {
        warn!(
            target: "finish",
            "queue-finished action is \"run a script\" but no script is set - nothing run"
        );
        return;
    };
    // TODO 314 stage 1. No job, so nothing to add to the daemon's own
    // directories: a queue-finished script is a notifier or a library
    // refresh, and both of those are covered by them.
    let mut cmd = crate::script::confined_command(d, &script, &[]);
    cmd.env("NZBFAST_EVENT", "queue_finished")
        .env("SAB_VERSION", SAB_VERSION);
    let secs = script_budget(d);
    announce(
        d,
        FinishAction::Script,
        "running",
        &script.display().to_string(),
    );
    // `_capture`, and the captured stdout is dropped on the floor.
    // §189 replaced the plain drop-everything runner with two stdout
    // modes, and neither is quite this caller: the NZBGet command
    // channel (`_sieve`) is per-DOWNLOAD, and a queue-finished script
    // has no download to command. Head-capture is the harmless one -
    // bounded at SCRIPT_OUT_HEAD, everything past it still drained and
    // dropped - so a chatty script cannot spend memory here either.
    match crate::script::run_capped_capture(cmd, secs) {
        Ok((Some(st), _, _)) if st.success() => {
            info!(target: "finish", "{} ok", script.display());
        }
        Ok((Some(st), _, stderr)) => warn!(
            target: "finish",
            "{} exited {st}: {}",
            script.display(),
            stderr.trim()
        ),
        Ok((None, _, _)) => warn!(
            target: "finish",
            "{} still running after {secs}s - killed. Raise or clear \
             script_timeout_secs if it needs longer.",
            script.display()
        ),
        Err(e) => warn!(target: "finish", "{} failed to launch: {e}", script.display()),
    }
}

/// The commands that put THIS machine to sleep or turn it off, in the
/// order they are tried.
///
/// A list rather than a single command, and the list is walked exactly
/// once: the first one that exits 0 wins, and if none does the action is
/// reported failed and abandoned. That is not a retry loop - a daemon
/// without the privilege for this will never gain it by asking again,
/// and a loop would spend the user's log on the same refusal forever.
/// The alternatives exist because the split is real: on macOS
/// `System Events` is the graceful shutdown a logged-in session gets,
/// while a launchd daemon with no session has to use `shutdown(8)`, and
/// on Linux the same daemon may or may not be able to reach logind.
fn power_commands(action: FinishAction) -> &'static [(&'static str, &'static [&'static str])] {
    #[cfg(target_os = "macos")]
    {
        match action {
            FinishAction::Sleep => &[("pmset", &["sleepnow"])],
            _ => &[
                (
                    "osascript",
                    &["-e", "tell application \"System Events\" to shut down"],
                ),
                ("shutdown", &["-h", "now"]),
            ],
        }
    }
    #[cfg(target_os = "windows")]
    {
        match action {
            // SetSuspendState's first argument is "hibernate": 0 asks
            // for sleep, but Windows still hibernates instead when
            // hibernation is enabled and sleep is not available. There
            // is no supported way to force one from a command line, so
            // the setting's help text says so rather than pretending.
            FinishAction::Sleep => &[("rundll32.exe", &["powrprof.dll,SetSuspendState", "0,1,0"])],
            _ => &[("shutdown.exe", &["/s", "/t", "0"])],
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        match action {
            FinishAction::Sleep => &[("systemctl", &["suspend"]), ("loginctl", &["suspend"])],
            _ => &[("systemctl", &["poweroff"]), ("shutdown", &["-h", "now"])],
        }
    }
}

/// Set to `1` to make sleep and shutdown announce themselves and stop
/// there. The daemon suite arms a real shutdown to prove the trigger
/// only fires when it should; without this that proof would turn off
/// whichever machine the tests are running on.
fn dry_run() -> bool {
    std::env::var("NZBFAST_FINISH_DRY_RUN").is_ok_and(|v| v == "1")
}

fn run_power_action(d: &Arc<Daemon>, action: FinishAction) {
    if dry_run() {
        announce(
            d,
            action,
            "fired",
            "NZBFAST_FINISH_DRY_RUN=1, command not run",
        );
        return;
    }
    let mut refusals: Vec<String> = Vec::new();
    for (prog, args) in power_commands(action) {
        announce(d, action, "fired", &format!("running {prog}"));
        // sandbox-seam-gate: `power_commands` answers &'static str programs
        // with &'static str arguments - pmset, osascript, shutdown, systemctl,
        // rundll32 - selected by a FinishAction enum and by nothing else.
        // Confining a shutdown is absurd on its own terms, and `Policy::tool`
        // would additionally tie the child's life to a daemon that is about to
        // be stopped by the very command it is running.
        let mut cmd = std::process::Command::new(prog);
        cmd.args(*args);
        // 60 s is generous for a command whose whole job is to hand the
        // request to the OS; anything slower has already failed in a way
        // waiting will not fix.
        match crate::script::run_capped_capture(cmd, 60) {
            Ok((Some(st), _, _)) if st.success() => return,
            Ok((Some(st), _, stderr)) => {
                refusals.push(format!("{prog} exited {st} ({})", stderr.trim()))
            }
            Ok((None, _, _)) => refusals.push(format!("{prog} did not return within 60s")),
            Err(e) => refusals.push(format!("{prog} would not launch: {e}")),
        }
    }
    // Fail soft, loudly, once. A daemon usually lacks the privilege for
    // this - that is the ordinary case, not a defect - so the message
    // has to say what was tried and what to grant, and then stop.
    let tried = refusals.join("; ");
    warn!(
        target: "finish",
        "could not {} this machine: {tried}. nzbfast runs without the \
         privilege for it on most installs - grant it to the account the \
         daemon runs as, or use the script action instead.",
        action.as_str()
    );
    announce(d, action, "failed", &tried);
}

/// The countdown and the current arm, for the queue payload the
/// dashboard polls every second. Never null: the header control shows
/// the arm whether or not anything is counting down.
pub fn payload(d: &Daemon) -> Value {
    let left = d.finish.pending().map(|p| {
        p.at.saturating_duration_since(Instant::now())
            .as_secs()
            // Round up, so a banner never reads "0 seconds" for the half
            // second before it happens.
            .max(1)
    });
    json!({
        "armed": d.finish.action().as_str(),
        "in_secs": left,
        "delay_secs": d.finish.delay_secs(),
    })
}

#[cfg(test)]
#[path = "finish_action_tests.rs"]
mod finish_action_tests;
