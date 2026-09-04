//! The whole-file MD5 prefix the mapped repair's self-prove resumes
//! from - hashed OFF DISK while the download is still running.
//!
//! WHY THIS EXISTS. `par2repair::repair_mapped_inner` ends by rereading
//! every rebuilt file and hashing it end to end against its FileDesc
//! MD5. MD5 is a serial chain at ~0.74 GB/s on one core (measured, M3
//! Ultra, 2 Sep 2026), so that is ~31 s on a 23 GB member and it IS the
//! daemon's `postproc_secs` for the case a user notices: a big member
//! with a few bad articles. The chain cannot be parallelised and the
//! bytes at or above the first rebuilt block cannot be hashed before
//! the solve produces them - so the only work that can be moved is the
//! prefix BELOW the first hole, and the only window big enough to move
//! it into is the rest of the download. The two alternatives (hash the
//! wire bytes on every download; overlap the prefix with the syndrome
//! feed) were priced and rejected in
//! `research/DESIGN-2026-09-02-mapped-selfprove-prefix.md` - the second
//! one measured a 2.7% ceiling.
//!
//! WHAT IT COSTS A CLEAN JOB: nothing. Not "a little" - nothing. No
//! slot is armed until the job has actually lost or failed a block, so
//! a healthy download never starts the thread, never opens the file and
//! never hashes a byte.
//!
//! WHAT IT COSTS A DAMAGED JOB: at most ONE core, and only until the
//! slot settles. There is a single worker thread for the whole
//! verifier, round-robining every armed slot, and MD5 is one chain per
//! file anyway.
//!
//! WHAT IT IS ALLOWED TO HASH: only bytes the PAR2 set has already
//! vouched for, contiguous from offset 0 - the same watermark
//! `LiveVerifier::gate_publish` maintains for the chase gate
//! (`SlotState::ok_prefix`). It reads them back through the extractor,
//! i.e. from the same disk the self-prove rereads, which is what lets
//! the self-prove treat the state as a resume point rather than as
//! hearsay about bytes that only ever existed on the wire.
//!
//! WHEN IT IS VOID: any event that can put different bytes under an
//! already-hashed offset drops the digest and restarts it from zero -
//! `SlotState::unbind` (the slot now holds a different descriptor) and
//! the forced read-back reset (a range was written twice, so only disk
//! can say which copy landed last). The worker hashes outside the lock,
//! so it carries an epoch taken with the bytes and installs its result
//! only if the epoch still stands; a void bumps the epoch, and the
//! worker's finished chunk is dropped rather than resurrecting a
//! digest over bytes that are gone.

use crate::md5fast::{Digest, Md5};
use crate::par2repair::Md5Resume;
use crate::sync::MutexExt;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// Reads `buf.len()` bytes of one slot at an offset, or fails. Same
/// contract as [`super::ReadAt::Reader`]: a range the source cannot
/// FULLY serve must come back as `Err` - never a short read, never zero
/// padding. In production this is `Extractor::read_at`.
pub type PrefixReader = Arc<dyn Fn(usize, u64, &mut [u8]) -> io::Result<()> + Send + Sync>;

/// How much the worker hashes between two looks at the stop flag and
/// the slot lock. 16 MiB is ~22 ms of MD5, which bounds both the
/// shutdown latency and how long a void can go unnoticed.
const CHUNK: u64 = 16 << 20;

/// Kill switch. Default ON; `NZBFAST_SELFPROVE_PREFIX=0` takes the
/// whole feature out of the run - no arming, no thread, and the
/// self-prove falls back to the full reread it did before this existed.
fn enabled() -> bool {
    enabled_for(std::env::var("NZBFAST_SELFPROVE_PREFIX").ok().as_deref())
}

/// [`enabled`]'s rule, as a function of the VALUE rather than of the
/// process. Split out so `live/prefix_tests.rs` can pin it without
/// setting an environment variable: `cargo test --lib` puts this whole
/// crate in ONE process, so a row that mutates the environment decides
/// what its siblings see - which is exactly how the first cut of that
/// file failed two rows that had nothing to do with the switch.
pub(super) fn enabled_for(v: Option<&str>) -> bool {
    !matches!(v, Some("0") | Some("off") | Some("false"))
}

#[derive(Default)]
struct PrefixSlot {
    /// Damage has been seen on this slot - see the module header for
    /// the two arming sites.
    armed: bool,
    /// Bytes the PAR2 set has vouched for, contiguous from 0. Published
    /// by `gate_publish`, which is the one place `ok_prefix` moves.
    proven: u64,
    /// Bytes hashed into `state` so far. Always `<= proven`.
    offset: u64,
    state: Md5,
    /// Bumped by every void. The worker installs a finished chunk only
    /// against the epoch it took the bytes under.
    epoch: u64,
    /// Settled (or abandoned): the worker leaves it alone.
    done: bool,
    /// Consecutive failed reads. A slot can be armed before a byte of
    /// it exists on disk (the engine arms on the first LOST article,
    /// which a slot with nothing landed can reach), and a chased
    /// volume's cold bytes can be paged out from under the reader - so
    /// a failure is retried rather than taken as final, up to
    /// [`FAIL_BUDGET`], after which the slot is abandoned and the
    /// self-prove simply rereads the whole member as it always did.
    fails: u32,
}

/// Failed reads a slot may take before its digest is abandoned. The
/// worker polls at 50 ms when idle, so this is ~3 s of patience.
const FAIL_BUDGET: u32 = 64;

/// One verifier's prefix digests plus the single thread that fills
/// them. Held in an `Arc` so the worker needs no back-reference to the
/// `LiveVerifier` (and so cannot keep one alive).
pub(super) struct PrefixTable {
    slots: Vec<Mutex<PrefixSlot>>,
    reader: Mutex<Option<PrefixReader>>,
    /// Woken when a slot is armed or its watermark moves.
    cv: Condvar,
    /// Guards the condvar only - the real state is per slot.
    tick: Mutex<u64>,
    stop: AtomicBool,
    /// Whether the worker has been spawned. Handle kept for the join in
    /// [`PrefixTable::shutdown`].
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl PrefixTable {
    pub(super) fn new(n_slots: usize) -> Arc<PrefixTable> {
        Arc::new(PrefixTable {
            slots: (0..n_slots)
                .map(|_| Mutex::new(PrefixSlot::default()))
                .collect(),
            reader: Mutex::new(None),
            cv: Condvar::new(),
            tick: Mutex::new(0),
            stop: AtomicBool::new(false),
            worker: Mutex::new(None),
        })
    }

    /// Install the byte source. Until this is called nothing is armed,
    /// which is what keeps every rig that never wires one inert.
    pub(super) fn set_reader(&self, r: PrefixReader) {
        *self.reader.lock_ok() = Some(r);
    }

    /// Damage seen on `slot`: start hashing its proven prefix.
    /// Idempotent, and cheap enough to call per article - the two
    /// production sites already gate themselves to once per slot.
    pub(super) fn arm(self: &Arc<Self>, slot: usize) {
        if !enabled() || self.reader.lock_ok().is_none() {
            return;
        }
        let Some(cell) = self.slots.get(slot) else {
            return;
        };
        {
            let mut s = cell.lock_ok();
            if s.armed || s.done {
                return;
            }
            s.armed = true;
        }
        self.ensure_worker();
        self.wake();
    }

    /// `gate_publish`'s watermark, in bytes, for a slot that has a file
    /// bound. Called under the slot lock, so it must not block on
    /// anything that could be waiting for that lock - it takes only its
    /// own cell and the tick.
    pub(super) fn publish(&self, slot: usize, proven: u64) {
        let Some(cell) = self.slots.get(slot) else {
            return;
        };
        let armed = {
            let mut s = cell.lock_ok();
            if s.proven >= proven {
                return;
            }
            s.proven = proven;
            s.armed && !s.done
        };
        if armed {
            self.wake();
        }
    }

    /// Bytes under an already-hashed offset may have changed: drop the
    /// digest and start again from zero. See the module header.
    pub(super) fn void(&self, slot: usize) {
        let Some(cell) = self.slots.get(slot) else {
            return;
        };
        let mut s = cell.lock_ok();
        s.offset = 0;
        s.proven = 0;
        s.state = Md5::new();
        s.epoch = s.epoch.wrapping_add(1);
    }

    /// Settle: stop hashing this slot and hand over whatever it reached.
    /// `None` unless a whole non-empty prefix was hashed.
    pub(super) fn take(&self, slot: usize) -> Option<Md5Resume> {
        let cell = self.slots.get(slot)?;
        let mut s = cell.lock_ok();
        s.done = true;
        (s.offset > 0).then(|| Md5Resume::from_prefix(s.offset, s.state.clone()))
    }

    /// Stop the worker and join it. Called from `LiveVerifier`'s `Drop`.
    pub(super) fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        self.wake();
        let handle = self.worker.lock_ok().take();
        if let Some(h) = handle {
            let _ = h.join();
        }
    }

    /// How far the digest has reached, for `live/prefix_tests.rs` -
    /// the one thing about a background hasher a test can assert
    /// without sleeping and hoping.
    #[cfg(test)]
    pub(super) fn offset(&self, slot: usize) -> u64 {
        self.slots.get(slot).map_or(0, |c| c.lock_ok().offset)
    }

    fn wake(&self) {
        *self.tick.lock_ok() += 1;
        self.cv.notify_all();
    }

    fn ensure_worker(self: &Arc<Self>) {
        let mut w = self.worker.lock_ok();
        if w.is_some() || self.stop.load(Ordering::Acquire) {
            return;
        }
        let me = Arc::clone(self);
        *w = std::thread::Builder::new()
            .name("par2-prefix".into())
            .spawn(move || me.run())
            .ok();
    }

    /// One bounded step for `slot`: hash at most [`CHUNK`] bytes of its
    /// proven-but-unhashed span. Returns whether it did anything, so
    /// the loop can tell work from an idle pass.
    fn step(&self, slot: usize, reader: &PrefixReader, buf: &mut [u8]) -> bool {
        let (from, to, mut state, epoch) = {
            let s = self.slots[slot].lock_ok();
            if !s.armed || s.done || s.proven <= s.offset {
                return false;
            }
            let to = s.proven.min(s.offset + CHUNK);
            (s.offset, to, s.state.clone(), s.epoch)
        };
        let mut off = from;
        while off < to {
            let take = (to - off).min(buf.len() as u64) as usize;
            if reader(slot, off, &mut buf[..take]).is_err() {
                let mut s = self.slots[slot].lock_ok();
                s.fails += 1;
                s.done |= s.fails >= FAIL_BUDGET;
                return false;
            }
            state.update(&buf[..take]);
            off += take as u64;
        }
        let mut s = self.slots[slot].lock_ok();
        // Voided (or re-armed) while we hashed: those bytes describe a
        // file this slot no longer holds. Drop them.
        if s.epoch == epoch && s.offset == from {
            s.offset = to;
            s.state = state;
            s.fails = 0;
        }
        true
    }

    fn run(self: Arc<Self>) {
        let Some(reader) = self.reader.lock_ok().clone() else {
            return;
        };
        let mut buf = vec![0u8; 1 << 20];
        while !self.stop.load(Ordering::Acquire) {
            let mut did = false;
            for slot in 0..self.slots.len() {
                if self.stop.load(Ordering::Acquire) {
                    return;
                }
                did |= self.step(slot, &reader, &mut buf);
            }
            if did {
                continue;
            }
            // Nothing to hash: park until a watermark moves. The wait is
            // BOUNDED rather than paired exactly with `wake`, for the
            // reason `VerifyGate::wait_past` gives - a missed
            // notification must cost a poll, never a hang.
            let tick = self.tick.lock_ok();
            let _ = self
                .cv
                .wait_timeout(tick, std::time::Duration::from_millis(50));
        }
    }
}
