//! How the daemon stops, and the pause timer that stops it temporarily
//! (TODO 106 code motion out of daemon.rs).
//!
//! Two halves of one subject: stopping. `wind_down` is the graceful
//! exit - park the transfer, persist the queue, QUIT every open NNTP
//! session - shared by `mode=shutdown` and by SIGTERM/SIGINT, with
//! `wind_down_and_exit` and the signal handlers on top of it. The pause
//! timer is the same thing bounded in time: `timed_pause` stops the
//! queue for N minutes, `arm_pause_timer` is the one-shot that lifts it,
//! and `persist_pause`/`restore_pause` carry the state across a restart
//! so a timed pause survives being stopped mid-pause.
//!
//! A child module of `daemon` on the daemon_idle shape, so `Daemon`'s
//! private fields and daemon.rs's private imports (`info!`, `Value`)
//! stay in scope exactly as they were inline. `pub(super)` became
//! `pub(in crate::serve)` for exactly that reason: `super` is `daemon`
//! here, and every call site - startup, sabcompat, api/system,
//! api/queue, api/config - is one level up, reached through
//! serve/mod.rs's `use daemon::*`.

use super::*;

/// How long the wind-down below is allowed to take before it exits
/// anyway.
///
/// Sized against `docker stop`, which sends SIGTERM and then SIGKILLs 10
/// seconds later. Being killed halfway through the wind-down is the
/// ungraceful exit we are fixing, so the whole sequence has to finish
/// well inside that with room for a loaded host - and every step it
/// waits on is separately bounded (`Connection::quit` at 500 ms, the
/// pool's own EXIT_GRACE at 5 s).
pub(in crate::serve) const WIND_DOWN_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(4);

/// How long going offline waits for the wound-down fleet to park before
/// it clears the warm pool regardless.
///
/// Longer than [`WIND_DOWN_BUDGET`] because nothing is about to SIGKILL
/// us: this one is racing the operator's patience, not a container
/// runtime. A graceful pause escalates to a hard abort at ~10 s
/// (`suspend_matching`), and the abort's own QUITs are bounded, so the
/// gauge reaches zero well inside this on any provider that answers at
/// all. It exists for the one that does not.
pub(in crate::serve) const OFFLINE_PARK_BUDGET: std::time::Duration =
    std::time::Duration::from_secs(60);

/// How long the exit waits to get the index's write connection to
/// itself before it gives up on closing the database.
///
/// Short on purpose. The index loops hold that mutex through whole
/// synchronous SQLite passes - a catch-up ingest held it 62 s straight
/// on 28 Jul - and the wind-down has four seconds for everything. A
/// stop that arrives mid-ingest leaves the log for the next start,
/// which is what every stop has always done; a stop that arrives at
/// idle (the overwhelming majority: `docker stop`, the tray's Quit, a
/// deploy) takes the mutex on the first try.
#[cfg(feature = "indexer")]
const INDEX_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// How long the truncating checkpoint waits for readers before it
/// reports itself busy and leaves the log alone.
///
/// Same trade as above, one level down: TRUNCATE blocks until every
/// reader has caught up to the latest snapshot, and a query handler
/// that borrowed a read connection a moment before the signal is
/// exactly such a reader. Whatever the checkpoint copied before giving
/// up is copied - a busy answer costs the next start a shorter recovery,
/// not a failed one.
#[cfg(feature = "indexer")]
const INDEX_CHECKPOINT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// Stop cleanly and exit: park the transfer, persist the queue, and
/// hand every open NNTP session back to the provider with a QUIT.
///
/// Shared by `mode=shutdown` and by SIGTERM/SIGINT (issue #13). A
/// container stop has exactly the same work to do as the tray's Quit
/// item, and used to do none of it - nothing was wired to signals, so
/// `docker restart` killed the process outright and left the provider
/// counting ~100 orphaned sessions until its own idle timeout. The
/// restart then asked for a full pool the account could not give it and
/// sat at 0 MB/s.
///
/// Bounded by [`WIND_DOWN_BUDGET`] as a whole: if a step overruns we
/// carry on regardless, because a slow clean exit that gets SIGKILLed is
/// worth no more than the abrupt one.
pub(in crate::serve) fn wind_down(d: &Arc<Daemon>, rt: &tokio::runtime::Handle, reason: &str) {
    let started = Instant::now();
    info!(target: "shutdown", "{reason} - persisting queue and closing connections");
    // Said first, because `index_db_wanted` reads it: from here on
    // nothing lazily reopens the index database behind the close
    // started below. Never cleared - every caller of this either exits
    // or execs (`restart_in_place` exits if its exec fails).
    // BEFORE that store, because `index_db_wanted` reads it and the
    // ledger's last unwritten record is worth one bounded attempt while
    // the database is still open. Best-effort and never blocking - see
    // `flush_index_ledger_for_exit`.
    #[cfg(feature = "indexer")]
    d.flush_index_ledger_for_exit();
    d.exiting.store(true, Ordering::Relaxed);
    // Order matters. Pause first so nothing new is admitted while we are
    // tearing down, THEN wind the transfer down GRACEFULLY.
    //
    // Graceful, not the immediate abort, and the difference is the whole
    // point of this function: the hard abort drops the pool future, and
    // a dropped worker never reaches the `conn.quit()` its exit path is
    // built around. Measured against a mock provider that logs commands
    // - eight busy connections, SIGTERM, eight sockets closed and not one
    // QUIT logged. The graceful path admits no new articles, lets the
    // in-flight window land, and lets each worker say goodbye, which is
    // what actually returns the session slot to the account. It also
    // costs less on resume: what landed is journalled instead of being
    // re-fetched.
    // Through the timer-aware setter, not a bare store: a timed pause
    // armed a thread that clears `paused` when its generation is still
    // current, and a bare store leaves that generation alone - so a
    // stale timer could fire mid-shutdown and admit a job to the very
    // queue this is tearing down. Not persisted (see `persist_pause`):
    // a clean quit must not come back paused.
    set_paused_cancel_timer(d, true);
    d.suspend_active(true);
    // The prefetch sidecar is its own hub and its own fleet, so the
    // wind-down above does not reach it - `suspend_active`, the pause
    // and the gauge below all read `d.hub` alone. Its sessions are on
    // the same account and count against the same cap, so a stop that
    // ignored them closed those sockets without a QUIT and left the
    // provider counting them until its own idle timeout, which is
    // exactly the connection-cap refusal the restart then met (read-
    // only sweep 2, M9). The offline path has poked the sidecar
    // explicitly for this reason since it was written; this one had
    // the same gap and not the same line.
    //
    // Sync context (a signal thread with no reactor of its own), so
    // this is `poke_sidecar` rather than the async `stop_sidecar` -
    // same signal, and the gauge below is what actually waits.
    //
    // The hub is RETAINED before the signal, not re-read from the slot
    // afterwards. The signalled task clears `d.sidecar` on its way out,
    // so every later read - the connection gauge below, and the
    // warm-pool sweep after it - found None and lost the route to the
    // very hub this signal was aimed at: the gauge then stopped
    // counting sessions that were still saying goodbye, and the sweep
    // had nothing to clear (Codex sweep 3, M13). `stop_sidecar` takes
    // the hub out of the slot for exactly this reason.
    let sidecar_hub = d.sidecar.lock_ok().as_ref().map(|s| s.hub.clone());
    d.poke_sidecar(|_| true);
    d.save_queue();
    // Off to its own thread NOW, to run alongside the connection drain
    // below rather than after it: both are waits, and they share one
    // budget. Nothing downstream depends on the index, and the index
    // work touches nothing the fleet teardown touches.
    let index_closed = close_index_in_background(d);
    // Now wait for the sessions themselves to go, because THAT is what
    // the provider is counting - not the job's state.
    //
    // Aborted workers QUIT on their way out, but only at their next
    // response boundary: the abort flag is checked at the top of the
    // worker loop, not inside the read it is parked on. So the job
    // leaves `Downloading` well before the fleet has said goodbye, and
    // waiting on the job (which is what this loop did first) exited
    // after 0.3 s with eight connections still open and not one QUIT
    // sent - measured against a mock provider that logs its commands.
    // The live gauge is the honest signal.
    //
    // BOTH hubs. The provider counts sessions, not jobs, and the
    // sidecar's fleet is not on `d.hub` - so a wind-down that watched
    // the main gauge alone reached zero while the prefetch was still
    // connected, and the process exited before those workers had said
    // goodbye (read-only sweep 2, M9).
    let hub_connected = |h: &crate::StreamHub| -> usize {
        h.pool_live
            .lock_ok()
            .as_ref()
            .map(|l| {
                l.servers
                    .iter()
                    .map(|s| s.connected.load(Ordering::Relaxed))
                    .sum()
            })
            .unwrap_or(0)
    };
    let connected = || -> usize {
        hub_connected(&d.hub) + sidecar_hub.as_deref().map(hub_connected).unwrap_or(0)
    };
    let open_at_signal = connected();
    while started.elapsed() < WIND_DOWN_BUDGET && connected() > 0 {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    if open_at_signal > 0 {
        let left = connected();
        info!(
            target: "shutdown",
            "{} of {open_at_signal} provider connection(s) closed{}",
            open_at_signal - left,
            if left > 0 {
                format!(" - {left} still busy, dropping them")
            } else {
                String::new()
            }
        );
    }
    // The connections nobody is using are the ones a restart trips over:
    // an idle daemon holds no pool at all, but it does hold parked warm
    // sessions, and those are pure occupancy on the account's cap.
    // `clear()` QUITs each one.
    //
    // `.get()`, NOT `hub.warm()`: the accessor CONSTRUCTS the pool on
    // first call, and construction spawns a keepalive tick, which needs
    // a reactor this thread does not have. On a daemon that had never
    // pooled anything, asking for the pool in order to empty it panicked
    // the wind-down thread - and with SIGTERM's default disposition
    // already replaced, that left a process no `docker stop` could end.
    //
    // The sidecar's hub parks its own, and on the same account: same
    // accessor rule, same reason.
    let warms: Vec<_> = d
        .hub
        .warm
        .get()
        .into_iter()
        .cloned()
        .chain(sidecar_hub.as_ref().and_then(|h| h.warm.get().cloned()))
        .collect();
    for warm in warms {
        let left = WIND_DOWN_BUDGET.saturating_sub(started.elapsed());
        let _ = rt.block_on(async {
            tokio::time::timeout(
                left.max(std::time::Duration::from_millis(200)),
                warm.clear(),
            )
            .await
        });
    }
    // Whatever is left of the budget, and never nothing: an idle
    // daemon - the ordinary stop - reaches here with the drain already
    // finished and the checkpoint already done or nearly so.
    if let Some(done) = index_closed {
        let left = WIND_DOWN_BUDGET.saturating_sub(started.elapsed());
        if done
            .recv_timeout(left.max(std::time::Duration::from_millis(250)))
            .is_err()
        {
            info!(
                target: "shutdown",
                "the index did not close in time - its write-ahead log stays \
                 for the next start to recover"
            );
        }
    }
    info!(
        target: "shutdown",
        "wound down in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    // Flush the log tee's buffer along with stdout before the exit.
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Start closing the index database on a thread of its own, and hand
/// back the channel that says it finished.
///
/// A thread rather than a step in the wind-down because the close is
/// the one part of the exit that can block for an unbounded time: a
/// truncating checkpoint copies whatever the log holds, and while the
/// log is bounded now (`nzbkit::index::WAL_SIZE_LIMIT`), it was 28.1
/// GiB on the live index a day before this was written. The caller
/// waits for the budget it has and no longer; a checkpoint still
/// running when the process goes is safe to lose - checkpointing is
/// idempotent, and the frames stay in the log until they are durably in
/// the database file, which is the same guarantee that makes a power
/// cut survivable.
///
/// `None` in a build without the indexer: there is no database.
#[cfg(feature = "indexer")]
fn close_index_in_background(d: &Arc<Daemon>) -> Option<std::sync::mpsc::Receiver<()>> {
    let (tx, rx) = std::sync::mpsc::channel();
    let d = d.clone();
    let spawned = std::thread::Builder::new()
        .name("index-close".into())
        .spawn(move || {
            close_index_for_exit(&d);
            let _ = tx.send(());
        })
        .is_ok();
    // A daemon that cannot spawn a thread still has to stop. The
    // receiver would simply time out; say so once instead.
    if !spawned {
        info!(target: "shutdown", "cannot spawn the index-close thread - its write-ahead log stays");
        return None;
    }
    Some(rx)
}

#[cfg(not(feature = "indexer"))]
fn close_index_in_background(_d: &Arc<Daemon>) -> Option<std::sync::mpsc::Receiver<()>> {
    None
}

/// Hand the index's write-ahead log back and close every connection to
/// it that this daemon holds.
///
/// SQLite deletes the -wal and the -shm when the last connection to a
/// WAL database closes, checkpointing on the way. The daemon never got
/// that far: it exits through `std::process::exit` (SIGTERM, SIGINT,
/// `mode=shutdown`) or through `exec` (`mode=restart`), and neither
/// runs a destructor - so the connections were still open at exit,
/// every time. Measured 14 Aug 2026 on the live daemon: SIGTERM, the
/// process gone and the port free, and a 28.1 GiB `index.db-wal` and
/// 6.9 MiB `index.db-shm` still on disk. The next start then paid a
/// recovery pass over the whole log instead of opening a database that
/// was already whole.
///
/// Every wait here is bounded and every failure is a shrug, because the
/// thing being protected is the exit: leaving the log behind is the
/// behaviour we have shipped since the beginning, and the next start
/// recovers from it correctly. What must not happen is a stop that
/// overruns - `docker stop` SIGKILLs at 10 s, and a `mode=restart`
/// blocked here would never re-exec at all.
#[cfg(feature = "indexer")]
fn close_index_for_exit(d: &Arc<Daemon>) {
    let started = Instant::now();
    // The read-only pool first, and for two reasons: its idle
    // connections close here, and a reader is exactly what makes a
    // TRUNCATE checkpoint report busy. One lent out to a query running
    // right now is retired by the generation stamp instead - this never
    // waits on somebody's query.
    d.drop_index_read();
    // try_lock on a timer, never a blocking lock. See INDEX_LOCK_WAIT:
    // this mutex is held for whole ingest passes, and the exit cannot
    // afford to queue behind one. A POISONED mutex lands in the same
    // place - try_lock reports it as an error, we run out the deadline
    // and leave the database alone, which is the right answer for a
    // connection whose last holder panicked mid-statement.
    let deadline = Instant::now() + INDEX_LOCK_WAIT;
    let taken = loop {
        if let Ok(mut guard) = d.index.try_lock() {
            // Out of the mutex, not merely borrowed: the connection is
            // ours to close. Safe because every lazy open asks
            // `index_db_wanted` again UNDER this mutex (`open_locked`),
            // not only at its entry gate - the bare `exiting` store was
            // not enough on its own, because a caller admitted a moment
            // before it and parked here would wake onto the empty mutex
            // we are about to leave behind and reopen the database.
            break guard.take();
        }
        if Instant::now() >= deadline {
            info!(
                target: "shutdown",
                "the index is busy - leaving its write-ahead log for the next start"
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    // Never opened in this process (or already closed by a switch going
    // off): there is nothing of ours to checkpoint.
    let Some(ix) = taken else { return };
    match ix.checkpoint_truncate(INDEX_CHECKPOINT_WAIT) {
        Ok(true) => {}
        Ok(false) => info!(
            target: "shutdown",
            "a reader still held the index - part of its write-ahead log stays"
        ),
        Err(e) => info!(target: "shutdown", "index checkpoint failed ({e}) - its log stays"),
    }
    // The close itself. With the pool retired above and no scan pass
    // holding its own scratch connection, this is the LAST connection,
    // and SQLite removes the -wal and the -shm as it goes.
    drop(ix);
    info!(
        target: "shutdown",
        "index closed in {:.1}s",
        started.elapsed().as_secs_f64()
    );
}

/// [`wind_down`], then go - and go whatever happens.
///
/// Installing a signal handler replaces SIGTERM's default disposition,
/// so from here on NOTHING else will end this process for us: a panic or
/// a wedge inside the wind-down does not degrade to the old abrupt exit,
/// it degrades to a daemon that ignores `docker stop` entirely and waits
/// out the 10 s until SIGKILL. Both are covered - the wind-down cannot
/// unwind past `catch_unwind`, and the watchdog exits on time even if it
/// blocks forever.
pub(in crate::serve) fn wind_down_and_exit(
    d: &Arc<Daemon>,
    rt: &tokio::runtime::Handle,
    reason: &str,
) -> ! {
    {
        let reason = reason.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(WIND_DOWN_BUDGET + std::time::Duration::from_secs(2));
            info!(target: "shutdown", "{reason}: wind-down overran its budget - exiting now");
            std::process::exit(0);
        });
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wind_down(d, rt, reason)));
    if r.is_err() {
        info!(target: "shutdown", "wind-down failed - exiting anyway");
    }
    std::process::exit(0);
}

/// Wire SIGTERM/SIGINT to [`wind_down_and_exit`].
///
/// Unix only for the terminate signal; Ctrl-C is handled on every
/// platform. A second signal while the first wind-down is still running
/// is ignored on purpose - the budget already bounds it, and re-entering
/// the sequence would abort the QUITs it exists to send.
///
/// The wait runs on a DEDICATED thread with its own single-thread
/// runtime, never as a task on the shared runtime. A spawned signal
/// task is only as responsive as the runtime's free workers, and the
/// index loops park workers in synchronous SQLite work behind one
/// mutex: with every worker blocked that way, a spawned handler is not
/// polled AT ALL - measured on a saturated 4-worker runtime, SIGTERM
/// went unhandled for five minutes, and the live daemon sat ~30 s on
/// SIGTERM mid-deepening (2 Aug, TODO §98.2). On its own thread the
/// same handler answered in under a millisecond under the same
/// saturation. `docker stop` SIGKILLs at 10 s, so those 30 s are the
/// difference between a graceful exit and an abrupt one.
pub(in crate::serve) fn install_shutdown_signals(daemon: &Arc<Daemon>) {
    // Not when a host app owns the process. Two reasons, either alone
    // sufficient: this path ends in `std::process::exit(0)`, which from
    // an iOS staticlib kills the HOST, not a daemon; and the thread
    // parks forever by design, so installing it once per start/stop
    // cycle leaked a thread plus a whole `Arc<Daemon>` graph per
    // generation. An embedded host's stop is `nzbfast_stop`, which the
    // serve loop already answers.
    if super::is_embedded() {
        return;
    }
    let rt = tokio::runtime::Handle::current();
    let d = daemon.clone();
    let spawned = std::thread::Builder::new()
        .name("signal-wait".into())
        .spawn(move || {
            let srt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    info!(target: "shutdown", "cannot build the signal runtime ({e}) - stop will be abrupt");
                    return;
                }
            };
            let reason = srt.block_on(wait_for_shutdown_signal());
            // Off this thread too: the wind-down blocks on locks and on
            // `Handle::block_on`, and this thread must stay free to keep
            // ignoring further signals (see above).
            std::thread::spawn(move || wind_down_and_exit(&d, &rt, reason));
            // Park forever rather than return: dropping the runtime
            // would unregister the signal handlers and restore the
            // default disposition, so a second SIGTERM mid-wind-down
            // would kill the process abruptly - the exact exit the
            // wind-down exists to avoid.
            loop {
                std::thread::park();
            }
        })
        .is_ok();
    if !spawned {
        info!(target: "shutdown", "cannot spawn the signal thread - stop will be abrupt");
    }
}

/// Resolve to the name of whichever shutdown signal arrives first.
pub(in crate::serve) async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // A failure to register is not fatal: it costs the graceful exit,
        // not the daemon. Say so rather than dying at startup.
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                info!(target: "shutdown", "cannot listen for SIGTERM ({e}) - stop will be abrupt");
                let _ = tokio::signal::ctrl_c().await;
                return "SIGINT";
            }
        };
        tokio::select! {
            _ = term.recv() => "SIGTERM",
            _ = tokio::signal::ctrl_c() => "SIGINT",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "Ctrl-C"
    }
}

/// Pause now; with `mins > 0` also arm an auto-resume ("pause for N
/// minutes", SAB's set_pause). The timer only fires if no manual
/// pause/resume happened in between (generation check).
pub(in crate::serve) fn timed_pause(d: &Arc<Daemon>, mins: u64, graceful: bool) {
    // Raise the flag and invalidate any pending auto-resume in one step
    // (see `set_paused_cancel_timer`); `arm_pause_timer` below re-arms
    // its own deadline under the same lock for the mins > 0 case.
    let was_paused = set_paused_cancel_timer(d, true);
    // Every caller of this is a person or a client acting for one - the
    // scheduler pauses through `apply_action`, which claims the pause
    // for itself.
    *d.pause_source.lock_ok() = "user";
    // M23e: also stop the transfer that's in flight, not just new jobs.
    d.suspend_active(graceful);
    // Marker on the transition only; a re-sent pause of a paused queue
    // is not a new moment.
    if !was_paused {
        d.note_event(
            "pause",
            if mins == 0 {
                "downloads paused".to_string()
            } else {
                format!("downloads paused for {mins} minutes")
            },
        );
    }
    if mins > 0 {
        // Saturating: `mins` arrives from the API as a caller-chosen
        // u64, and the product need not fit. The clamp inside
        // `arm_pause_timer` takes it from there.
        arm_pause_timer(d, std::time::Duration::from_secs(mins.saturating_mul(60)));
    }
    persist_pause(d);
}

/// Arm the auto-resume timer for a pause that is ALREADY in effect.
///
/// Split out of `timed_pause` so a pause restored at startup can run out
/// the time it has left rather than a fresh full interval, and so it can
/// take a Duration - a pause with 90 seconds to go does not round to a
/// whole number of minutes.
pub(in crate::serve) fn arm_pause_timer(d: &Arc<Daemon>, dur: std::time::Duration) {
    // Clamp at the choke point. `Instant::now() + dur` PANICS on
    // overflow, and the remote-app arms (`scheduleresume` takes a bare
    // u64 of seconds off the wire) reach here with anything a caller
    // cares to send - which killed an HTTP worker thread for the life
    // of the process, since that pool has no catch_unwind. A pause
    // longer than a year is indistinguishable from a pause with no
    // timer, so capping it loses nothing a user can observe.
    let dur = dur.min(std::time::Duration::from_secs(365 * 24 * 3600));
    let spawn = {
        let mut until = d.pause_until.lock_ok();
        *until = Some(Instant::now() + dur);
        // Under the SAME lock the worker clears it under on its way out,
        // so exactly one of "reprogram the worker that is already there"
        // and "there is no worker, start one" happens. Read it outside
        // and two arms landing together spawn two workers, or an arm
        // racing a retirement notifies a thread that has already gone
        // and the pause never lifts.
        !d.pause_timer_live.swap(true, Ordering::Relaxed)
    };
    // Outside the lock: the woken worker's first act is to take it.
    d.pause_wake.notify_all();
    if spawn {
        let weak = Arc::downgrade(d);
        let stop = crate::serve::RunStop::current();
        // Weak, and through the aux census like every other long-lived
        // lane. Weak because a worker asleep on a deadline must not be
        // what keeps a whole daemon generation alive; censused because
        // that is what makes "at most one of these exists" provable
        // rather than asserted - this lane replaced a raw
        // `std::thread::spawn` per arm, which the census never saw.
        if !crate::serve::spawn_aux("pause-timer", move || pause_timer(&weak, stop)) {
            // Nothing is running to clear the flag, so clear it here or
            // no later arm would ever start a worker again.
            d.pause_timer_live.store(false, Ordering::Relaxed);
        }
    }
}

/// How long the auto-resume worker sleeps at a stretch before it looks
/// at the run's stop token again.
///
/// The deadline itself is exact - the last wait is the whole of what is
/// left - so this costs precision nothing and buys the one thing a
/// condvar inside the daemon cannot deliver: an embedded `nzbfast_stop`
/// notifies the process-wide stop gate, not this lane's condvar, and a
/// pause with six hours to run must not hold its daemon generation open
/// for six hours. One wake a second, only while a timed pause is
/// actually pending, and none at all otherwise.
const PAUSE_STOP_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// The one auto-resume worker: sleep until `pause_until` comes due, lift
/// the pause, retire.
///
/// One reprogrammable timer, not a thread per arm. Every arm used to
/// spawn a raw sleeper that slept the WHOLE duration and was invalidated
/// - never woken, never joined - by a generation counter, so N
/// `set_pause` calls left N OS threads and N `Arc<Daemon>` clones asleep
/// for up to the clamp of a year. Re-arming now replaces the deadline in
/// place and wakes this loop; cancelling clears it and this loop retires.
///
/// The deadline read under the lock is the WHOLE decision, which is what
/// retires the generation counter that used to make it: a cancel is
/// `None` and a re-arm is a later `Some`, both written under this mutex,
/// so there is no window in which a stale wake can lift a pause somebody
/// else has just re-taken (the 14 Aug sweep's check-then-act hole,
/// closed by construction rather than by a matching number).
fn pause_timer(weak: &std::sync::Weak<Daemon>, stop: crate::serve::RunStop) {
    // The `Weak` is upgraded once and held only for as long as this
    // worker is actually timing something: it retires the moment the
    // deadline is gone, so an idle daemon carries no strong reference
    // from here at all, and a pending one carries it for at most
    // [`PAUSE_STOP_POLL`] past a stop.
    let Some(d) = weak.upgrade() else { return };
    let mut until = d.pause_until.lock_ok();
    loop {
        let Some(deadline) = *until else {
            // Cancelled by a resume, a manual pause, or going offline.
            // Retire under the lock, so an arm either sees the flag
            // still set and reprograms a worker that is still here, or
            // sees it clear and starts a new one.
            d.pause_timer_live.store(false, Ordering::Relaxed);
            return;
        };
        if stop.stopping() {
            d.pause_timer_live.store(false, Ordering::Relaxed);
            return;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let (next, _) = d
            .pause_wake
            .wait_timeout(until, left.min(PAUSE_STOP_POLL))
            .unwrap_or_else(|p| p.into_inner());
        until = next;
    }
    // Due. Fire and clear under the same lock every pause/resume writer
    // takes, then retire: a pause that wants a timer arms one.
    d.paused.store(false, Ordering::Relaxed);
    *until = None;
    d.pause_timer_live.store(false, Ordering::Relaxed);
    drop(until);
    persist_pause(&d);
    info!(target: "pause", "timed pause over - resumed");
    d.note_event("resume", "timed pause over - downloads resumed");
    // Writes the flag directly (it has to - the deadline check and the
    // store are one step under the lock), so it owes the announce by
    // hand. Nobody is at the keyboard when a timed pause expires, which
    // is precisely the resume worth saying.
    announce_pause(&d);
}

/// Set or clear the pause flag and cancel any pending auto-resume
/// deadline - as ONE step with respect to the timer worker, which reads
/// that deadline and stores the resumed flag under this same
/// `pause_until` lock. Writers that wrote the two as bare atomics raced
/// the worker's check-then-act window. Returns the previous flag value.
/// Callers do their own `persist_pause` / events / wind-down outside the
/// lock.
///
/// It also ANNOUNCES the edge, which is what makes six of the flag's
/// nine writers free: `mode=pause`, `mode=resume` on both facades, the
/// shutdown wind-down, the storage pause and the schedule all reach the
/// atomic through here, so none of them has to remember. The announce
/// is deliberately OUTSIDE the `pause_until` hold - `life_emit` takes
/// the ring lock and then offers the event to the webhook dispatcher,
/// and no other lock may be held across either.
pub(in crate::serve) fn set_paused_cancel_timer(d: &Daemon, paused: bool) -> bool {
    let was = {
        let mut until = d.pause_until.lock_ok();
        let was = d.paused.swap(paused, Ordering::Relaxed);
        *until = None;
        was
    };
    // Outside the lock: the worker wakes, reads no deadline, and retires
    // rather than sleeping out the rest of a pause that is over.
    d.pause_wake.notify_all();
    announce_pause(d);
    was
}

/// Who paused, in the words the queue payload uses. One derivation, two
/// readers - the payload's `pause_source` field and the `queue.paused`
/// event - because a second copy could only ever disagree with the
/// first about which of the two mechanisms stopped the queue.
pub(in crate::serve) fn pause_source_now(d: &Daemon) -> &'static str {
    if d.paused_by_offline.load(Ordering::Relaxed) {
        "offline"
    } else {
        *d.pause_source.lock_ok()
    }
}

/// §129 1b(b): say `queue.paused` / `queue.resumed` if the flag has
/// moved since the last time this said anything.
///
/// `Daemon::pause_announced` is the memory, and it is separate from
/// `paused` because the two answer different questions and only one of
/// them is allowed to be stale: `paused` is what `pick_job` gates on
/// and must be exact, `pause_announced` is what has been SAID, and the
/// gap between them is the edge. Seeded false to match a fresh
/// daemon's unpaused flag, so the first pause is an edge; the restore
/// path announces the pause it restores rather than writing the flag
/// behind this one's back, which would leave the pair disagreeing and
/// swallow the following resume.
///
/// THE EDGE IS COMPUTED HERE AND NOT BY THE CALLER, which is the whole
/// design. The dashboard used to recover this cue by diffing
/// `q.paused` against the previous poll's value, and that diff is
/// exactly what §129 1b(b) is retiring - but a per-door emit would put
/// the same fragile judgement in nine places instead of one, and the
/// day somebody adds a tenth door the chime is lost with nothing to say
/// so. Reading the flag and swapping against what was last announced
/// makes this IDEMPOTENT: call it from anywhere, as often as you like,
/// and it emits once per real transition. That is what lets the queue
/// poll call it as a belt (`sabcompat::queue_payload`), so a future
/// writer that forgets costs one poll of lateness rather than the cue.
///
/// Call with no locks held.
pub(in crate::serve) fn announce_pause(d: &Daemon) {
    let now = d.paused.load(Ordering::Relaxed);
    if d.pause_announced.swap(now, Ordering::Relaxed) == now {
        return;
    }
    // `source` only on the pause, for the same reason the payload nulls
    // it on a running queue: "who paused" is not a fact about a queue
    // that is not paused, and the resume that follows may be a
    // different mechanism's entirely.
    if now {
        d.life_emit("queue.paused", json!({"source": pause_source_now(d)}));
    } else {
        d.life_emit("queue.resumed", json!({}));
    }
}

/// Record the queue's pause state so it survives a restart.
///
/// A pause is a deliberate act - a metered week, a call in progress, a
/// benchmark running - and an update or a crash-restart used to undo it
/// silently, with the queue back at full speed and nothing on screen
/// saying the user's choice had been dropped.
///
/// A timed pause is stored as an ABSOLUTE deadline, not "N minutes left".
/// "Pause for 30 minutes" is a statement about when downloading may start
/// again, so a daemon that is down for an hour must come back running,
/// not sit out another half hour. `restore_pause` handles the deadline
/// that passed while we were gone.
///
/// Called only from the paths that carry the user's intent. Notably NOT
/// from `shutdown`/`restart_daemon`, which pause the queue as part of
/// winding down - persisting that would mean every clean quit came back
/// paused.
pub(in crate::serve) fn persist_pause(d: &Daemon) {
    // The dashboard's change handle, bumped WITH the write, exactly as
    // `save_queue` does for the job rows - because paused / offline /
    // pause_source / resume_at ride the same revisioned queue payload.
    // Without this the §129 1b poll answers `"queue": null` for an idle
    // daemon whose only change was this one, the page keeps the queue
    // object it last applied, and the second after the header flips to
    // "Offline" the poll repaints "Online" over a daemon that really is
    // offline. Pause hid the same staleness because it is normally
    // pressed mid-download, where `any_active` makes the queue ride
    // regardless.
    d.queue_rev.fetch_add(1, Ordering::Relaxed);
    let paused = d.paused.load(Ordering::Relaxed);
    let until = d.pause_until.lock_ok().map(|deadline| {
        // Instant is monotonic and process-local, so convert through the
        // time REMAINING to get a wall-clock deadline we can write down.
        unix_now() + deadline.saturating_duration_since(Instant::now()).as_secs() as i64
    });
    // Null removes the key: a running queue leaves nothing behind, so
    // settings.json keeps holding only what the user actually changed.
    save_settings(
        &d.settings_path,
        &[
            ("paused", if paused { json!(true) } else { Value::Null }),
            (
                "pause_until_unix",
                match until.filter(|_| paused) {
                    Some(u) => json!(u),
                    None => Value::Null,
                },
            ),
            // Offline must survive a restart, or a daemon that was
            // deliberately kept off the account would silently reconnect
            // the moment it came back - reoccupying the address slot the
            // operator went offline to free, with nothing on screen
            // saying so.
            (
                "offline",
                match d.offline.load(Ordering::Relaxed) {
                    true => json!(true),
                    false => Value::Null,
                },
            ),
            (
                "paused_by_offline",
                match d.paused_by_offline.load(Ordering::Relaxed) {
                    true => json!(true),
                    false => Value::Null,
                },
            ),
        ],
    );
}

/// Put back the pause the last run was in, at startup.
///
/// Runs BEFORE the scheduler's own startup evaluation, which is allowed
/// to overrule it: a schedule is a standing rule about what should be
/// true at this hour, and it already re-evaluates the whole week on boot
/// for exactly that reason.
pub(in crate::serve) fn restore_pause(d: &Arc<Daemon>, saved: &serde_json::Map<String, Value>) {
    // Offline first, and independently of the pause below: it is the
    // stronger state and the one with a promise attached (this machine
    // is not on the account). Restored by setting the flags directly
    // rather than through `set_offline`, because the queue pause it
    // would apply is already recorded alongside it - re-deriving it here
    // would forget whether the operator had ALSO paused by hand.
    if saved.get("offline").and_then(Value::as_bool) == Some(true) {
        d.offline.store(true, Ordering::Relaxed);
        d.paused_by_offline.store(
            saved.get("paused_by_offline").and_then(Value::as_bool) == Some(true),
            Ordering::Relaxed,
        );
        info!(target: "offline", "restored: offline, touching no provider");
    }
    if saved.get("paused").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let Some(deadline) = saved.get("pause_until_unix").and_then(Value::as_i64) else {
        d.paused.store(true, Ordering::Relaxed);
        // Announced even though nothing can be listening yet: the point
        // is to leave `pause_announced` AGREEING with the flag, or the
        // resume that follows computes "false -> false" and says
        // nothing. A page that opens later adopts the ring's head
        // (`life_cursor`), so this is never replayed as news.
        announce_pause(d);
        info!(target: "pause", "restored: queue paused");
        return;
    };
    let left = deadline - unix_now();
    if left <= 0 {
        // The auto-resume fell due while the daemon was down. Honour it:
        // start running, and clear the keys so we don't re-read them.
        info!(target: "pause", "timed pause expired while stopped - resumed");
        persist_pause(d);
        return;
    }
    d.paused.store(true, Ordering::Relaxed);
    announce_pause(d);
    arm_pause_timer(d, std::time::Duration::from_secs(left as u64));
    info!(target: "pause", "restored: paused, {} min left", (left + 59) / 60);
}

#[cfg(test)]
mod shutdown_sidecar_tests {
    use super::*;
    use crate::serve::sidecar::Sidecar;

    fn live_one(host: &str) -> Arc<nzbkit::pool::LiveStats> {
        nzbkit::pool::LiveStats::for_servers(&[(
            nzbkit::config::ServerConfig {
                host: host.into(),
                port: 563,
                tls: false,
                username: None,
                password: None,
                connections: 4,
                pin_connections: false,
                rcvbuf: None,
                level: 0,
                group: None,
                retention_days: 0,
                block_bytes: None,
                block_account: false,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
                idle_release_secs: None,
                idle_keep: None,
                max_source_ips: None,
                address_family: Default::default(),
                tls_hostname: None,
            },
            nzbkit::pool::PoolConfig::default(),
        )])
    }

    /// A clean stop hands every open NNTP session back with a QUIT, and
    /// the prefetch sidecar's sessions are on the same account and the
    /// same cap - but the pause, the gauge and the warm-pool clear all
    /// read `d.hub` alone, and the sidecar owns a hub of its own. So a
    /// SIGTERM with a prefetch running signalled nothing at it and
    /// watched a gauge it was not in: the main count reached zero, the
    /// process exited, and the provider went on counting those sockets
    /// until its own idle timeout - which is the connection-cap refusal
    /// the restart then met. The offline path has poked the sidecar
    /// explicitly since it was written; this one had the same gap and
    /// not the same line (read-only sweep 2, M9).
    #[test]
    fn the_wind_down_signals_and_waits_for_the_sidecar_hub_too() {
        let dir = std::env::temp_dir().join(format!("nzbfast-winddown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);
        let rt = tokio::runtime::Runtime::new().expect("runtime");

        // A prefetch with one open session on its OWN hub, and none on
        // the daemon's: exactly the shape the main gauge cannot see.
        let hub = Arc::new(crate::StreamHub::default());
        let live = live_one("news.example");
        live.servers[0].connected.store(1, Ordering::Relaxed);
        *hub.pool_live.lock_ok() = Some(live.clone());
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *d.sidecar.lock_ok() = Some(Sidecar {
            nzo_id: "nzo-winddown-1".into(),
            hub: hub.clone(),
            progress: Arc::new(AtomicU64::new(0)),
            rate_win: Mutex::new(VecDeque::new()),
            cancelled: cancelled.clone(),
            task: rt.spawn(async {}),
            borrowed: false,
        });

        // That session says goodbye a while after the signal, as a real
        // one does - the abort is read at the worker's next response
        // boundary, not inside the read it is parked on.
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r2 = released.clone();
        let quitter = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1_200));
            live.servers[0].connected.store(0, Ordering::Relaxed);
            r2.store(true, Ordering::Relaxed);
        });

        let t0 = Instant::now();
        wind_down(&d, rt.handle(), "test stop");
        let waited = t0.elapsed();
        // Read BEFORE the join, or the join itself makes it true and
        // the assertion says nothing at all.
        let left_before_the_quit = !released.load(Ordering::Relaxed);
        quitter.join().expect("quitter");

        assert!(
            cancelled.load(Ordering::Relaxed),
            "the stop never reached the prefetch - its sockets close with no QUIT"
        );
        assert!(
            !left_before_the_quit,
            "the stop exited with the prefetch still connected, so the provider \
             goes on counting those sessions"
        );
        // ...and it must stop waiting when the sessions are gone, not
        // burn the whole budget: a wind-down that always waits is the
        // abrupt exit it replaced, one timeout further on.
        assert!(
            waited < WIND_DOWN_BUDGET,
            "the wind-down spent its entire budget instead of leaving when the \
             connections had gone ({waited:?})"
        );

        *d.sidecar.lock_ok() = None;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...and it keeps watching that hub after the sidecar task has
    /// CLEARED THE SLOT, which is what the signal makes it do.
    ///
    /// The gauge and the warm-pool sweep both re-read `d.sidecar` after
    /// the poke, and the signalled task empties that slot on its way
    /// out - so the route to the hub the signal was aimed at was
    /// normally gone by the time either looked. The wind-down then saw
    /// zero connections and left while the prefetch's sessions were
    /// still saying goodbye, which is the same provider-occupancy
    /// symptom the sidecar leg above exists to prevent (Codex sweep 3,
    /// M13). Retaining the hub before signalling is what `stop_sidecar`
    /// already does.
    #[test]
    fn the_wind_down_keeps_watching_a_sidecar_that_clears_its_own_slot() {
        let dir = std::env::temp_dir().join(format!("nzbfast-winddown2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);
        let rt = tokio::runtime::Runtime::new().expect("runtime");

        let hub = Arc::new(crate::StreamHub::default());
        let live = live_one("news.example");
        live.servers[0].connected.store(1, Ordering::Relaxed);
        *hub.pool_live.lock_ok() = Some(live.clone());
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // The real task's exit path: it takes the abort, then empties
        // the slot - well before its sessions have finished quitting.
        let d2 = d.clone();
        let c2 = cancelled.clone();
        let task = rt.spawn(async move {
            while !c2.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            *d2.sidecar.lock_ok() = None;
        });
        *d.sidecar.lock_ok() = Some(Sidecar {
            nzo_id: "nzo-winddown-2".into(),
            hub: hub.clone(),
            progress: Arc::new(AtomicU64::new(0)),
            rate_win: Mutex::new(VecDeque::new()),
            cancelled: cancelled.clone(),
            task,
            borrowed: false,
        });

        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r2 = released.clone();
        let quitter = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(1_200));
            live.servers[0].connected.store(0, Ordering::Relaxed);
            r2.store(true, Ordering::Relaxed);
        });

        wind_down(&d, rt.handle(), "test stop");
        let left_before_the_quit = !released.load(Ordering::Relaxed);
        quitter.join().expect("quitter");

        assert!(
            !left_before_the_quit,
            "the wind-down lost the route to the sidecar's hub when the task \
             cleared the slot, and exited with those sessions still open"
        );

        *d.sidecar.lock_ok() = None;
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod pause_timer_tests {
    use super::*;

    /// The aux-thread census is process-global, and these tests both
    /// spawn into it and count what is in it, so they run one at a time.
    /// Taken as the FIRST statement of each, so it drops last.
    fn one_pause_timer_test_at_a_time() -> std::sync::MutexGuard<'static, ()> {
        static GATE: Mutex<()> = Mutex::new(());
        GATE.lock_ok()
    }

    /// Auto-resume workers alive right now. Nothing else in this process
    /// arms a pause, so under the guard above this is exactly what the
    /// test under it started.
    fn live_pause_timers() -> usize {
        crate::serve::live_aux_threads()
            .into_iter()
            .find(|(name, _)| name == "pause-timer")
            .map_or(0, |(_, n)| n)
    }

    /// Wait for the census to settle at `want` workers. Zero is the half
    /// a leak test cannot skip - "stopped growing" is what a leak that
    /// saturates looks like - and one is the same assertion for a cancel
    /// that is immediately re-armed: the retiring worker and its
    /// replacement can both be counted for the instant the first takes
    /// to return, so the claim is where it settles, not where it is
    /// caught mid-handover.
    fn wait_for_workers(want: usize, what: &str) {
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while live_pause_timers() != want {
            assert!(
                Instant::now() < deadline,
                "expected {want} auto-resume worker(s) after {what}, found {}",
                live_pause_timers()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nzbfast-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// `scheduleresume` takes its seconds as a bare u64 straight off the
    /// wire, and `Instant::now() + dur` panics on overflow - so a
    /// remote app (or anything pointed at the API) could kill an HTTP
    /// worker thread outright, permanently, since that pool runs with
    /// no catch_unwind. The clamp lives in `arm_pause_timer` so every
    /// caller inherits it; the pause must still be ARMED, not dropped.
    ///
    /// It also puts the timer back, which is why the cancel at the end
    /// is part of the test rather than tidying: this case used to end
    /// with TWO year-long sleeper threads still asleep, each holding an
    /// `Arc<Daemon>` for the life of the test binary - the very leak
    /// `re_arming_reprograms_the_one_worker` is about, shipped inside
    /// the test that was meant to prove the clamp.
    #[test]
    fn an_absurd_pause_length_clamps_instead_of_panicking() {
        let _serial = one_pause_timer_test_at_a_time();
        let dir = scratch("pauseclamp");
        let d = crate::serve::testutil::test_daemon(&dir);

        arm_pause_timer(&d, std::time::Duration::from_secs(u64::MAX));
        assert!(
            d.pause_until.lock_ok().is_some(),
            "a clamped pause is still a pause"
        );

        // The minutes path multiplies before it gets here, so it has to
        // saturate too or it panics one step earlier in debug builds.
        timed_pause(&d, u64::MAX, false);
        assert!(d.paused.load(Ordering::Relaxed), "still paused");
        assert!(d.pause_until.lock_ok().is_some(), "timer armed");
        wait_for_workers(1, "two absurd pauses - the second reprograms the first");

        set_paused_cancel_timer(&d, false);
        wait_for_workers(0, "a resume cancelled the clamped pause");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Codex sweep 24 Aug 2026, F-07: every arm used to spawn a raw `std::thread`
    /// that slept the WHOLE duration holding an `Arc<Daemon>`, with a
    /// generation counter that invalidated the old sleeper without ever
    /// waking it. So N authenticated `set_pause`/`scheduleresume` calls
    /// left N OS threads and N daemon clones asleep for up to the clamp
    /// of a year - unbounded accumulation from an ordinary API call.
    ///
    /// The fix is one reprogrammable worker: re-arming replaces the
    /// deadline in place and wakes it. Both halves are asserted, because
    /// "one thread" is worth nothing if it is timing the wrong deadline
    /// - the last arm here is SHORTER than the first, so a worker still
    /// running the original deadline would be timing an hour.
    #[test]
    fn re_arming_reprograms_the_one_worker() {
        let _serial = one_pause_timer_test_at_a_time();
        let dir = scratch("pausearm");
        let d = crate::serve::testutil::test_daemon(&dir);

        for _ in 0..25 {
            arm_pause_timer(&d, std::time::Duration::from_secs(3600));
            assert_eq!(
                live_pause_timers(),
                1,
                "one worker however many times the pause is re-armed"
            );
        }

        // Shorter than everything before it: the deadline moved, in
        // place, rather than a 26th sleeper queueing up behind an hour.
        arm_pause_timer(&d, std::time::Duration::from_secs(30));
        let left = d
            .pause_until
            .lock_ok()
            .expect("re-armed pause is armed")
            .saturating_duration_since(Instant::now());
        assert!(
            left <= std::time::Duration::from_secs(30),
            "the deadline is the LAST arm's, not the first's: {left:?} left"
        );
        assert_eq!(live_pause_timers(), 1, "still one worker");

        // And a resume takes it away, rather than leaving it to sleep
        // out the half hour nobody is waiting for any more.
        set_paused_cancel_timer(&d, false);
        wait_for_workers(0, "a resume cancelled the pause");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The behaviour all of the above exists to preserve: the pause
    /// actually lifts, once, at its deadline - and the worker retires
    /// behind it rather than sitting on the daemon waiting for a
    /// deadline that has already passed.
    #[test]
    fn the_timer_lifts_the_pause_when_it_comes_due() {
        let _serial = one_pause_timer_test_at_a_time();
        let dir = scratch("pausefire");
        let d = crate::serve::testutil::test_daemon(&dir);

        set_paused_cancel_timer(&d, true);
        arm_pause_timer(&d, std::time::Duration::from_millis(50));
        wait_for_workers(0, "the pause came due");

        assert!(
            !d.paused.load(Ordering::Relaxed),
            "a timed pause that has run out is not a pause"
        );
        assert!(
            d.pause_until.lock_ok().is_none(),
            "and it leaves no deadline behind for `pause_int` to report"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod pause_edge_tests {
    use super::*;

    fn kinds(d: &Arc<Daemon>) -> Vec<String> {
        d.life_since(0)
            .0
            .iter()
            .filter_map(|e| e["kind"].as_str())
            .filter(|k| k.starts_with("queue.pause") || k.starts_with("queue.resum"))
            .map(str::to_string)
            .collect()
    }

    /// §129 1b(b): pause and resume are EDGES on the lifecycle ring, and
    /// the dashboard no longer diffs `q.paused` against the previous
    /// poll to find them.
    ///
    /// The repeats are the substance. `announce_pause` is called on
    /// every queue poll as a belt (see `sabcompat::queue_payload`), and
    /// a pause door may reach it more than once on one transition - the
    /// offline arm does - so an implementation that emitted per CALL
    /// rather than per EDGE would put a chime on every second of a
    /// paused queue. Pausing an already-paused queue is not a
    /// transition either: an *arr sends `mode=pause` routinely.
    #[test]
    fn pause_and_resume_are_edges_and_repeats_say_nothing() {
        let dir = std::env::temp_dir().join(format!("nzbfast-pauseedge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);

        assert!(kinds(&d).is_empty(), "a fresh daemon has said nothing");
        // The belt, on a queue nobody has touched: still nothing.
        announce_pause(&d);
        announce_pause(&d);
        assert!(kinds(&d).is_empty(), "polling is not a transition");

        set_paused_cancel_timer(&d, true);
        assert_eq!(kinds(&d), ["queue.paused"]);
        // A second pause of a paused queue, and the belt behind it.
        set_paused_cancel_timer(&d, true);
        announce_pause(&d);
        assert_eq!(kinds(&d), ["queue.paused"], "pausing twice is one pause");

        set_paused_cancel_timer(&d, false);
        announce_pause(&d);
        assert_eq!(kinds(&d), ["queue.paused", "queue.resumed"]);

        let e = d
            .life_since(0)
            .0
            .into_iter()
            .find(|e| e["kind"] == "queue.paused")
            .expect("the pause is on the ring");
        assert_eq!(e["source"], "user");
        assert_eq!(e["schema_version"], 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The belt is what makes the ninth pause door - and the tenth
    /// nobody has written yet - safe. A writer that sets the flag and
    /// forgets to announce loses ONE POLL, not the cue: the next call
    /// from the queue payload finds flag and announcement disagreeing
    /// and says so.
    ///
    /// This is the failure mode §129 1b(b) is about. A cue recovered by
    /// diffing a payload cannot be lost by a new writer, because the
    /// diff sees the state and not the write; an event can, and the
    /// belt is the price of moving it.
    #[test]
    fn a_writer_that_forgets_to_announce_costs_one_poll_not_the_cue() {
        let dir = std::env::temp_dir().join(format!("nzbfast-pausebelt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);

        // A hypothetical tenth door: writes the atomic, says nothing.
        d.paused.store(true, Ordering::Relaxed);
        assert!(kinds(&d).is_empty(), "nothing has announced it yet");
        announce_pause(&d);
        assert_eq!(kinds(&d), ["queue.paused"], "the belt caught it");

        // And the same in reverse, so a forgotten RESUME cannot leave
        // the pair stuck agreeing on "paused" forever.
        d.paused.store(false, Ordering::Relaxed);
        announce_pause(&d);
        assert_eq!(kinds(&d), ["queue.paused", "queue.resumed"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restored pause leaves the pair AGREEING, which is the whole
    /// reason `restore_pause` announces into an empty room.
    ///
    /// Get this wrong and the bug is silent and durable: the flag says
    /// paused, the announcement still says running, and the user's
    /// first resume of the session computes "false -> false" and chimes
    /// nothing. Nothing else in the daemon would ever notice.
    #[test]
    fn a_restored_pause_still_lets_the_next_resume_be_heard() {
        let dir = std::env::temp_dir().join(format!("nzbfast-pauserestore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);

        let mut saved = serde_json::Map::new();
        saved.insert("paused".into(), json!(true));
        restore_pause(&d, &saved);
        assert!(d.paused.load(Ordering::Relaxed), "the pause was restored");

        set_paused_cancel_timer(&d, false);
        assert!(
            kinds(&d).contains(&"queue.resumed".to_string()),
            "the first resume after a restored pause must be heard: {:?}",
            kinds(&d)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
