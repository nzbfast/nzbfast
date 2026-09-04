//! §129 perf lane: the process-global gates the engine's post-network
//! tail consults when more than one job's tail can run at once.
//!
//! Two resources live here, both deliberately global for the same reason
//! `eatvol`'s mode is - the repair pass and the disk-unpack ladder run
//! several layers below anything that holds a `Daemon`:
//!
//! 1. **The heavy-CPU permit.** One permit, taken by the repair pass and
//!    the disk re-extract ladder. Two concurrent single-core repairs are
//!    tolerable today, but the sibling §129 MD5-parallelization bullet
//!    makes each repair want every core, and two of those fight. Verify
//!    read-backs, unlock probes, renames and sweeps never take it. A
//!    tail waiting for the permit sits with its activity token unchanged
//!    (it is genuinely "repairing", just queued for the cores).
//!
//!    It gates CORES, so it is never held across a network wait - see
//!    [`HeavyCpu::without_permit`], the seam the repair pass's recovery
//!    fetches go through.
//!
//! 2. **The per-filesystem outstanding-need ledger.** Concurrent on-disk
//!    unpacks multiply peak usage, and the §101 forecast reads FREE
//!    bytes - two concurrent forecasts would both count the same free
//!    space and both conclude they fit. Each disk unpack registers what
//!    it still needs against its output volume; `eatvol::forecast` and
//!    the admission check both subtract OTHER jobs' registered need
//!    from free. Admission WAITS (never fails) when the unpack would fit
//!    alone but not beside the registered need - the §123 ENOSPC verdict
//!    stays the backstop, we just do not engineer avoidable failures.
//!
//! A job's own registration is excluded from what it reads via a
//! thread-local, the same shape as `eatvol`'s ARMED cell and safe for
//! the same reason: the forecast and the ladder run on the tail's own
//! driving thread.

use std::cell::Cell;
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};

use crate::tools::MutexExt;

// ---------------------------------------------------------------------
// The heavy-CPU permit
// ---------------------------------------------------------------------

fn cpu_sem() -> &'static Arc<tokio::sync::Semaphore> {
    static SEM: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
}

/// Take the heavy-CPU permit from async code (the settle/repair path).
/// Held for the scope of the returned permit; FIFO-fair across waiters.
async fn heavy_cpu() -> tokio::sync::OwnedSemaphorePermit {
    cpu_sem()
        .clone()
        .acquire_owned()
        .await
        .expect("the heavy-CPU semaphore is never closed")
}

/// The heavy-CPU permit held by an async pass, with an explicit seam for
/// the waits that pass makes on something OTHER than cores.
///
/// The repair pass holds this for its whole length on purpose (mapped
/// repair, materialize, disk repair - see `run_set_repair`), and inside
/// that length it fetches recovery volumes off the network. Holding one
/// process-global permit across a network wait gates permit turnover on
/// the provider rather than on CPU work, and the exposure is not the
/// round trip: a side-fetch has no overall deadline (`fetch_volumes` →
/// `fetch_all_multi_ctl`, bounded only by the pool's own retry ladder
/// and stall watchdog, and cancellable only by deleting the job), so a
/// provider that stops answering parks every OTHER job's repair and
/// disk-unpack tail behind it. That is not hypothetical: the 7 Aug 2026
/// wedge parked a side-fetch forever through the consumer-ack seam
/// (sidefetch.rs `fetch_volume_articles`, fixed there), and this permit
/// would have spread one job's version of it across the whole daemon.
///
/// So: every await under the permit that is not CPU work goes through
/// [`HeavyCpu::without_permit`] (Codex sweep 10 Aug H3, TODO §137.2).
pub struct HeavyCpu(Option<tokio::sync::OwnedSemaphorePermit>);

impl HeavyCpu {
    /// Wait for the permit and hold it until this handle drops.
    pub async fn acquire() -> Self {
        Self(Some(heavy_cpu().await))
    }

    /// A handle holding nothing, for a call path reached without the
    /// permit: `without_permit` on it just awaits. The direct-drive
    /// repair unit tests use this rather than contending on the
    /// process-global semaphore the suite runs in parallel with.
    #[cfg(any(test, feature = "test-support"))]
    pub fn unheld() -> Self {
        Self(None)
    }

    /// Give the permit up, await `fut`, then queue for it again.
    ///
    /// Re-acquisition is FIFO like any other waiter, so a pass that
    /// releases can find a sibling's repair ahead of it and finish
    /// later than it would have. That is the trade being made: one
    /// pass's wall clock for cores that are not idle behind a network
    /// wait, and for a stuck provider that can no longer stall every
    /// other tail in the process.
    ///
    /// Cancel-safe in both directions. The permit is dropped before
    /// `fut` is ever polled, so dropping this future mid-`fut` leaks
    /// nothing; dropping it during the re-acquire means the caller
    /// never resumes, so it cannot proceed unpermitted.
    pub async fn without_permit<F: Future>(&mut self, fut: F) -> F::Output {
        match self.0.take() {
            // Released FIRST: the whole point is that `fut` is not
            // polled while this permit is held.
            Some(permit) => {
                drop(permit);
                let out = fut.await;
                self.0 = Some(heavy_cpu().await);
                out
            }
            None => fut.await,
        }
    }
}

/// Take the heavy-CPU permit from sync code (the disk-unpack ladder,
/// which runs blocking-style on its task's thread).
///
/// A parked FIFO wait on the same semaphore the async path uses, moved
/// off the scheduler with [`off_worker`] first. This used to be a
/// 200 ms try/sleep poll loop on whatever thread called it (Codex
/// sweep 8 Aug H11): from ordinary async task execution that thread is
/// a runtime worker, and a worker that sleeps instead of yielding
/// starves every task queued behind it - on a one-worker runtime the
/// permit HOLDER could never be polled again, which is a deadlock, and
/// the poll loop also jumped the semaphore's fair queue and woke up to
/// 200 ms late.
pub fn heavy_cpu_blocking() -> tokio::sync::OwnedSemaphorePermit {
    off_worker(|| block_on_parked(cpu_sem().clone().acquire_owned()))
        .expect("the heavy-CPU semaphore is never closed")
}

/// Run blocking-style work without starving the async runtime.
///
/// On a multi-thread runtime worker this is `block_in_place`: the
/// worker hands its scheduler core to a fresh thread BEFORE the
/// closure runs, so even a one-worker runtime keeps polling everyone
/// else (the H11 shape). Everywhere else - a plain thread, a
/// blocking-pool thread, a multi-thread `block_on` caller, a nested
/// call - `block_in_place` already degrades to running the closure in
/// place, and the one context where it would panic instead
/// (current_thread runtimes) is excluded by the flavor guard; no
/// production runtime is current_thread (the daemon and the CLI both
/// run `#[tokio::main]`).
pub fn off_worker<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// Drive one future to completion by parking THIS thread between
/// polls - the minimal executor `heavy_cpu_blocking` needs. Tokio's
/// semaphore acquire is executor-agnostic and queue-fair, so parking
/// on its future keeps FIFO order with the async waiters and wakes the
/// moment the permit drops.
fn block_on_parked<F: Future>(fut: F) -> F::Output {
    struct Unparker(std::thread::Thread);
    impl std::task::Wake for Unparker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unparker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            // Spurious unparks just re-poll; Pending without a wake
            // cannot be missed because the waker unparks this thread.
            Poll::Pending => std::thread::park(),
        }
    }
}

// ---------------------------------------------------------------------
// The per-filesystem outstanding-need ledger
// ---------------------------------------------------------------------

struct Need {
    id: u64,
    vol: u64,
    bytes: u64,
}

fn ledger() -> &'static Mutex<Vec<Need>> {
    static LEDGER: OnceLock<Mutex<Vec<Need>>> = OnceLock::new();
    LEDGER.get_or_init(|| Mutex::new(Vec::new()))
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// The registration owned by the tail driving THIS thread (0 =
    /// none), so its own need is never subtracted from its own view.
    static MINE: Cell<u64> = const { Cell::new(0) };
}

/// One key per filesystem: the device id where the platform gives one,
/// a hash of the path's root component otherwise. Two directories on
/// the same volume must collide here - that is the point.
pub(crate) fn vol_key(dir: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::metadata(dir) {
            return m.dev();
        }
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    // Windows: the drive letter / UNC prefix is the volume identity.
    dir.components().next().hash(&mut h);
    h.finish()
}

/// Bytes OTHER tails have registered against `dir`'s filesystem.
pub(crate) fn other_need(dir: &Path) -> u64 {
    let vol = vol_key(dir);
    let mine = MINE.with(|m| m.get());
    ledger()
        .lock_ok()
        .iter()
        .filter(|n| n.vol == vol && n.id != mine)
        .map(|n| n.bytes)
        .fold(0u64, u64::saturating_add)
}

/// RAII registration of one unpack's outstanding need. Dropped at the
/// end of the disk stage; restores the thread's previous registration
/// so a nested pass cannot orphan the outer one.
pub struct NeedGuard {
    id: u64,
    prev: u64,
}

impl Drop for NeedGuard {
    fn drop(&mut self) {
        if self.id == 0 {
            return;
        }
        ledger().lock_ok().retain(|n| n.id != self.id);
        MINE.with(|m| m.set(self.prev));
    }
}

/// Append one registration to an ALREADY-HELD ledger and adopt it as
/// this thread's own. Split out so `try_admit` can register under the
/// same lock hold its admission check took.
fn register_entry(led: &mut Vec<Need>, vol: u64, bytes: u64) -> NeedGuard {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    led.push(Need { id, vol, bytes });
    let prev = MINE.with(|m| m.replace(id));
    NeedGuard { id, prev }
}

/// Test seam: register against `dir`'s volume in one call. Production
/// registration goes through `try_admit`, which needs the lock held
/// across the admission check too.
#[cfg(test)]
fn register_locked(dir: &Path, bytes: u64) -> NeedGuard {
    register_entry(&mut ledger().lock_ok(), vol_key(dir), bytes)
}

/// One admission attempt against `vol`, ATOMIC under a single ledger
/// lock hold: the read of the other tails' registered need and this
/// unpack's own registration cannot be separated (Codex sweep 8 Aug
/// M9 - check under one hold, register under a second let two
/// same-volume tails both read zero in the window between them and
/// both pass, engineering the exact concurrent-unpack ENOSPC the gate
/// exists to avoid; Gary's disk-full evening, TODO §100/§101, is the
/// reported shape of that class). The free-space figure stays a
/// parameter probed OUTSIDE the lock: statfs on a network volume can
/// hang without bound, and `admit_unpack`'s loop re-probes it each
/// pass anyway.
fn try_admit(vol: u64, needed: u64, margin: u64, free: u64) -> Option<NeedGuard> {
    let want = needed.saturating_add(margin);
    let mine = MINE.with(|m| m.get());
    let mut led = ledger().lock_ok();
    let others = led
        .iter()
        .filter(|n| n.vol == vol && n.id != mine)
        .map(|n| n.bytes)
        .fold(0u64, u64::saturating_add);
    if free >= want.saturating_add(others) || free < want {
        Some(register_entry(&mut led, vol, needed))
    } else {
        None
    }
}

/// Admit one disk unpack needing `needed` bytes on `dir`'s filesystem.
///
/// Three outcomes, decided against live figures each pass:
/// - fits beside the other tails' registered need: register and go;
/// - does not fit even ALONE: register and go anyway - waiting cannot
///   help, and the §101 eat decision / §123 ENOSPC verdict own that
///   case exactly as they do today;
/// - fits alone but not beside the others: WAIT here (the caller's
///   activity token already says what stage this is), re-checking as
///   the other tails release their registrations.
///
/// A waiter holds no registration while it waits, so two admissions can
/// never deadlock on each other.
pub fn admit_unpack(dir: &Path, needed: u64, margin: u64) -> NeedGuard {
    if needed == 0 {
        return NeedGuard { id: 0, prev: 0 };
    }
    let vol = vol_key(dir);
    let mut said = false;
    loop {
        let free = crate::diskfree::free_bytes(dir).unwrap_or(u64::MAX);
        if let Some(guard) = try_admit(vol, needed, margin, free) {
            return guard;
        }
        if !said {
            said = true;
            tracing::info!(
                target: "extract",
                "unpack needs {:.1} GB but {:.1} GB is already promised to other \
                 finishing jobs on this disk - waiting for them to release it",
                needed as f64 / 1e9,
                other_need(dir) as f64 / 1e9
            );
        }
        // The caller runs off the scheduler (`off_worker` around the
        // whole unpack tail), so this parks a thread the runtime can
        // afford to lose, never an async worker.
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CPU semaphore is process-global and the unit suite runs its
    /// tests in parallel, so the two tests that take it run one at a
    /// time. Without this they interleave: each expects to be the only
    /// claimant, and a permit taken by the other test satisfies neither
    /// test's assertion while still perturbing both.
    fn cpu_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock_ok()
    }

    // One test on purpose: the ledger is process-global and the unit
    // suite runs in parallel, so sequenced assertions about "nobody
    // else has registered" only hold inside a single test body.
    #[test]
    fn ledger_excludes_self_sums_others_and_restores_on_drop() {
        let dir = std::env::temp_dir();
        let a = register_locked(&dir, 5_000_000_000);
        // On this thread `a` is MINE - invisible to our own read.
        assert_eq!(other_need(&dir), 0);
        // A second thread sees a's need but not its own.
        let d2 = dir.clone();
        std::thread::spawn(move || {
            let _b = register_locked(&d2, 3_000_000_000);
            assert_eq!(other_need(&d2), 5_000_000_000);
        })
        .join()
        .unwrap();
        // Nested registration restores the outer one on drop.
        let outer_id = MINE.with(|m| m.get());
        {
            let _inner = register_locked(&dir, 2);
            assert_ne!(MINE.with(|m| m.get()), outer_id);
        }
        assert_eq!(MINE.with(|m| m.get()), outer_id);
        drop(a);
        assert_eq!(MINE.with(|m| m.get()), 0);
        assert_eq!(other_need(&dir), 0);
        // Zero need admits without registering anything.
        let g = admit_unpack(&dir, 0, 0);
        assert_eq!(g.id, 0);
    }

    /// H11 (Codex sweep 8 Aug): a tail blocked on the heavy-CPU permit
    /// must not park a scheduler worker. One worker on purpose - before
    /// the fix the waiter's 200 ms try/sleep loop occupied the only
    /// worker, the permit holder (parked across an await, exactly the
    /// repair pass's shape) could never be polled again, and the whole
    /// runtime deadlocked, timers included. The runtime therefore lives
    /// on its own thread here, watched over a plain mpsc timeout: with
    /// the old code even the failure path's timer would never fire.
    #[test]
    fn permit_wait_does_not_starve_a_one_worker_runtime() {
        let _serial = cpu_test_lock();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("build the one-worker runtime");
            rt.block_on(async {
                let permit = heavy_cpu().await;
                let (tx, rx) = tokio::sync::oneshot::channel::<()>();
                let holder = tokio::spawn(async move {
                    let _p = permit;
                    let _ = rx.await;
                });
                let waiter = tokio::spawn(async {
                    let _p = heavy_cpu_blocking();
                });
                // Progress on the one worker while the waiter blocks is
                // the assertion: this timer only fires, and the holder
                // is only polled to completion, if the waiter handed
                // its core off instead of sleeping on it.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let _ = tx.send(());
                holder.await.expect("the permit holder ran to completion");
                waiter.await.expect("the blocked waiter got the permit");
            });
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("deadlock: the blocking permit waiter starved the one-worker runtime (H11)");
    }

    /// H3 (Codex sweep 10 Aug, TODO §137.2): the repair pass holds the
    /// heavy-CPU permit across its recovery-volume fetches, so the
    /// permit must be HANDED BACK for the duration of each one. The
    /// property, and the whole point of `without_permit`: while the
    /// wrapped future is pending, another tail can hold the permit.
    ///
    /// Sequenced on channels, not on sleeps - the assertion is ordering
    /// ("the sibling got in while the fetch was outstanding"), and a
    /// timing margin would make it a load-sensitive flake on the shared
    /// checkout ([[nzbfast-daemon-test-flake]]). The outer timeout is
    /// the only clock, and it is the FAILURE path: a `without_permit`
    /// that stops releasing leaves the sibling unable to acquire and
    /// this hangs rather than mis-asserting.
    ///
    /// Own runtime on its own thread, like the H11 test above, so the
    /// hang is caught by that timeout instead of parking the suite.
    #[test]
    fn the_permit_is_handed_back_across_a_network_wait() {
        let _serial = cpu_test_lock();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build the runtime");
            let held_by_sibling = rt.block_on(async {
                let mut cpu = HeavyCpu::acquire().await;
                // Stands in for `fetch_volumes`: pending until the
                // sibling has actually taken the permit.
                let (fetch_tx, fetch_rx) = tokio::sync::oneshot::channel::<()>();
                let (got_tx, got_rx) = tokio::sync::oneshot::channel::<()>();
                let sibling = tokio::spawn(async move {
                    let _p = heavy_cpu().await;
                    // Prove it, THEN release: the permit is held at the
                    // moment the fetch is still outstanding.
                    let _ = got_tx.send(());
                    let _ = fetch_tx.send(());
                });
                let held_by_sibling = cpu
                    .without_permit(async move {
                        let _ = fetch_rx.await;
                        got_rx.await.is_ok()
                    })
                    .await;
                sibling.await.expect("the sibling task ran");
                // Re-acquired: `without_permit` returns holding it again.
                assert!(cpu.0.is_some(), "the permit was not re-acquired");
                held_by_sibling
            });
            // An unheld handle is a no-op wrapper, and it must not
            // acquire what it never had.
            rt.block_on(async {
                let mut unheld = HeavyCpu::unheld();
                assert_eq!(unheld.without_permit(async { 7u8 }).await, 7);
                assert!(
                    unheld.0.is_none(),
                    "an unheld handle acquired the permit behind the caller's back"
                );
            });
            let _ = done_tx.send(held_by_sibling);
        });
        let held_by_sibling = done_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the heavy-CPU permit was held across the network wait (H3)");
        assert!(
            held_by_sibling,
            "the sibling never held the permit while the fetch was outstanding"
        );
    }

    /// M9 (Codex sweep 8 Aug): the admission check and the registration
    /// are one atomic ledger transaction. Eight same-volume tails race
    /// for room that fits exactly one; exactly one may admit. Before
    /// the fix the read and the write took the lock separately, so any
    /// two callers interleaved between them both saw zero registered
    /// need and both passed - the avoidable-ENOSPC pair.
    #[test]
    fn admission_check_and_register_are_atomic() {
        // A synthetic volume key nothing else registers against - the
        // ledger is process-global and the suite runs in parallel, so
        // the assertions filter to this key alone.
        const VOL: u64 = 0x4d39_7261_6365; // "M9race"
        const NEED: u64 = 10_000_000_000;
        const FREE_FOR_ONE: u64 = 15_000_000_000;
        let start = Arc::new(std::sync::Barrier::new(8));
        let hold = Arc::new(std::sync::Barrier::new(8));
        let admitted: usize = (0..8)
            .map(|_| {
                let start = start.clone();
                let hold = hold.clone();
                std::thread::spawn(move || {
                    start.wait();
                    let guard = try_admit(VOL, NEED, 0, FREE_FOR_ONE);
                    let got = guard.is_some();
                    // Keep the registration alive until every thread
                    // has made its attempt - dropping early would hand
                    // the freed room to a later caller legitimately.
                    hold.wait();
                    got
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum();
        assert_eq!(
            admitted, 1,
            "room for one admitted {admitted} same-volume unpacks"
        );
        // Every guard dropped on its own thread: the ledger is clean.
        assert!(ledger().lock_ok().iter().all(|n| n.vol != VOL));

        // Room for both: both admit, neither waits. The second attempt
        // runs (and drops its guard) on its own thread - a guard must
        // die where it was born to restore that thread's own MINE, and
        // a same-thread second registration would be `mine`-excluded
        // anyway.
        let a = try_admit(VOL, NEED, 0, 30_000_000_000).expect("fits beside the other");
        let b_admitted = std::thread::spawn(|| try_admit(VOL, NEED, 0, 30_000_000_000).is_some())
            .join()
            .unwrap();
        assert!(b_admitted, "fits beside the other");
        // Does not fit even alone: register and go anyway - waiting
        // cannot help, the §123 ENOSPC verdict owns that case.
        let c = try_admit(VOL, NEED, 0, 5_000_000_000).expect("hopeless case never waits");
        drop(c);
        drop(a);
        assert!(ledger().lock_ok().iter().all(|n| n.vol != VOL));
    }
}
