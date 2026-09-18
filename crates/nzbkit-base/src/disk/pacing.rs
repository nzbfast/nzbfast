//! Write-back PACING and the page-cache policy: how much dirty data the
//! writer lets accumulate before it asks the kernel to start writing it
//! out, which flush primitive each platform uses, and whether pages are
//! dropped behind the writer once they are clean.
//!
//! One subject even though it arrives in two stretches - the latched
//! knobs and `apply_cache_policy` up front, the flush primitive and the
//! watermark step after `FileWriter` - and every measurement behind
//! those choices moved with the code that reads it.
//!
//! Cut out of `disk.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,683 of the size gate's 4,000-line file ceiling. Verbatim move.

use super::*;

/// Process default for [`FileWriter`] cache dropping (see
/// `maybe_drop_cache`). Set BEFORE the first write of the run - the
/// per-process decision is latched on first use.
pub(super) static DROP_CACHE_DEFAULT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_drop_cache_default(on: bool) {
    DROP_CACHE_DEFAULT.store(on, Ordering::Relaxed);
}

/// C1: whether drop-behind should default ON for a reader-less run (the
/// CLI `get` path) given this machine's memory - the RAM-aware policy
/// replacing the old always-on CLI default. The mechanics are
/// `maybe_drop_cache` below; `NZBFAST_DROP_CACHE=1/0` still force-
/// overrides whatever this decides (see `drop_cache_enabled`).
///
/// Why memory-aware: the 1 GB-cgroup evidence said always-on (M32,
/// ~17% of a core saved in memcg reclaim) and a 31 GB 8-core host
/// said always-off (~30% wall cost, Aug 2026) - both measured right,
/// both wrong as a global default. A 20 Aug 2026 six-tier cgroup-v2
/// SSD ladder (512M-16G limits, 24 GB job each) located the
/// crossover: at <= 1 GiB drop-behind zeroes reclaim scanning (5-6M
/// pages per job -> ~0) at no wall cost and holds the job's physical
/// footprint to ~0.25-0.6 GB, at 2 GiB it is a wash, and at 4 GiB+ it
/// costs 25-40% wall (40-70% unconstrained) paying sync_file_range +
/// DONTNEED per stride for evictions the kernel handles for free when
/// it has room. The threshold encloses the wash cell on the protective
/// side. HDD leg unmeasured (no reachable box) - if spinning rust
/// later shows a different crossover, this constant is the one dial.
pub fn drop_cache_auto() -> bool {
    drop_cache_auto_for(crate::mem::physical_ram(), crate::mem::cgroup_mem_limit())
}

/// Enable at 2 GiB effective memory and below; the tighter of host RAM
/// and the cgroup limit decides, same sources as `MemBudget::auto`.
/// Unknown memory reads as "not small" (a failed probe is not a small
/// box - the `concurrency_caps_for` convention), so probes failing on
/// an exotic platform keep today's big-box behaviour, not the slow arm.
pub(super) fn drop_cache_auto_for(ram: Option<u64>, cgroup_limit: Option<u64>) -> bool {
    const THRESHOLD: u64 = 2 << 30;
    let eff = match (ram, cgroup_limit) {
        (Some(r), Some(l)) => r.min(l),
        (Some(r), None) => r,
        (None, Some(l)) => l,
        (None, None) => return false,
    };
    eff <= THRESHOLD
}

/// Default stride for write pacing (macOS, and the Linux daemon
/// path) - see [`FileWriter`]'s
/// `maybe_pace_writeback`. 32 MB: small enough that the per-flush pause
/// hides inside the fetch->decode channel, large enough that a 10 Gbps
/// decoded stream (~1.2 GB/s) syncs ~40 times a second, not thousands.
/// The m1 stride sweep read the same within noise from 16 to 64 MB
/// (2/68, 3/68, 4/68 samples below 80% of peak), so the choice is not
/// delicate.
// Not #[expect]: live on macOS, which takes the arm below. Linux uses
// the 0 arm and Windows has no arm at all, so it is dead on both.
#[allow(dead_code)]
pub(super) const WRITE_PACE_STRIDE_DEFAULT: u64 = 32 << 20;

/// The pacing stride in force, in bytes; 0 = pacing off. Latched on
/// first use; `NZBFAST_WRITE_PACE_MB` overrides in either direction
/// (0 = off).
///
/// macOS: ON by default - the 6 Aug A/B on m1 (87 GB, 10 Gbps) took
/// the job from 25/87 seconds below 80% of peak to 3/68 and sustained
/// 7.2 -> 9.0 Gbps, with the per-server write-side blocking erased.
///
/// Linux: OFF by default. The 7 Aug daemon A/B on the Linux rig
/// (8-core/31 GB ext4 box, 60 GB loopback mock, 8 legs) found no arm
/// that beat
/// no-pacing: fsync per stride read the same or worse (ext4 journal
/// commit + device flush), sync_file_range arms read within noise, and
/// drop-behind was clearly worse. Linux's balance_dirty_pages already
/// bounds the dirty set gradually - the macOS save-up-then-dump
/// pathology was never observed. The machinery stays compiled and
/// env-selectable so a real-NAS leg (Synology, TODO 126.1) can test
/// the shipped binary with NZBFAST_WRITE_PACE_MB=32 alone.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn write_pace_stride() -> u64 {
    #[cfg(target_os = "macos")]
    const DEFAULT: u64 = WRITE_PACE_STRIDE_DEFAULT;
    #[cfg(target_os = "linux")]
    const DEFAULT: u64 = 0;
    // env-default-gate: `DEFAULT` above is cfg-split - `WRITE_PACE_STRIDE_DEFAULT`
    // on macOS, 0 on Linux - so there is no one value to pair with, which is
    // also why the doc row reads "32 (macOS)". Check that row against the two
    // consts, not against one of them.
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        parse_pace_mb(std::env::var("NZBFAST_WRITE_PACE_MB").ok().as_deref()).unwrap_or(DEFAULT)
    })
}

/// The `NZBFAST_WRITE_PACE_MB` mapping, split out so it is testable
/// without mutating process env (same seam as [`storage_override`]).
/// None = unset/unparsable, defer to the process default.
// Not #[expect]: live on macOS and Linux via write_pace_stride, which
// is cfg'd out on Windows - dead there, so the waiver is Windows's.
#[allow(dead_code)]
pub(super) fn parse_pace_mb(raw: Option<&str>) -> Option<u64> {
    raw?.trim()
        .parse::<u64>()
        .ok()
        .map(|mb| mb.saturating_mul(1 << 20))
}

/// `NZBFAST_NOCACHE=1`: set F_NOCACHE on every [`FileWriter`] handle
/// (macOS), so the large sequential output streams to the device at a
/// steady rate instead of accumulating dirty pages for the kernel to
/// dump in one burst - fix direction 2 of the line-rate campaign.
/// Reads through the same handle (mapped repair, settle read-back)
/// bypass the cache too, which is why this is bench-gated rather than
/// a default: measure before paying that on real jobs.
#[cfg(target_os = "macos")]
pub(super) fn nocache_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_NOCACHE").is_ok_and(|v| v == "1"))
}

/// Which flush primitive the Linux pacer uses per stride (see
/// `FileWriter::maybe_pace_writeback`). Default `Sfr` (async
/// writeback start, the lightest); `NZBFAST_PACE_MODE=fsync|sfrwait`
/// select the heavier arms for benching, same policy as
/// `NZBFAST_NOCACHE`. On the 7 Aug VPS rig all three read within
/// noise or worse than no pacing - kept for the real-NAS leg.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(super) enum PaceMode {
    Sfr,
    SfrWait,
    Fsync,
}

#[cfg(target_os = "linux")]
pub(super) fn pace_mode() -> PaceMode {
    static V: std::sync::OnceLock<PaceMode> = std::sync::OnceLock::new();
    *V.get_or_init(|| match std::env::var("NZBFAST_PACE_MODE").as_deref() {
        Ok("fsync") => PaceMode::Fsync,
        Ok("sfrwait") => PaceMode::SfrWait,
        _ => PaceMode::Sfr,
    })
}

/// The per-process drop-behind decision, latched on first use (see
/// `FileWriter::maybe_drop_cache`): `NZBFAST_DROP_CACHE=1/0` overrides,
/// else the process default (CLI `get` turns it on, the daemon never
/// does). Shared with `maybe_pace_writeback`, which stands down while
/// drop-behind is active - the two hooks would otherwise race one
/// `drop_next` watermark and double-flush every stride.
#[cfg(target_os = "linux")]
pub(super) fn drop_cache_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| match std::env::var("NZBFAST_DROP_CACHE").as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        _ => DROP_CACHE_DEFAULT.load(Ordering::Relaxed),
    })
}

/// Apply the bench-gated F_NOCACHE policy to a fresh writer handle.
/// Best-effort: a filesystem that refuses the fcntl just keeps the
/// default caching behaviour.
pub(super) fn apply_cache_policy(file: &File) {
    #[cfg(target_os = "macos")]
    if nocache_enabled() {
        use std::os::unix::io::AsRawFd;
        // SAFETY: fcntl takes only the raw fd plus integer arguments;
        // the borrow of `file` keeps the fd open across the call.
        unsafe {
            libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = file;
    }
}

/// The pacer's watermark step ([`FileWriter::maybe_pace_writeback`]),
/// pure so the completion rule below is testable: given the file's
/// `written` counter, the current `drop_next` watermark, the declared
/// size and the stride, decide whether to flush now and what to store
/// as the next watermark.
///
/// The stride alone has a blind spot the 6 Aug measurements never
/// exercised: the watermark is PER FILE, so a file smaller than the
/// initial 16 MB watermark never flushes at all, and one just over it
/// keeps its tail dirty forever. A corpus of many small files (CD-era
/// 15 MB rar parts, image sets) therefore accumulates dirty pages at
/// line rate with the pacer nominally ON - the exact unbounded backlog
/// the stride exists to prevent, rebuilt out of tails. The fix is a
/// once-only flush when the file completes (`written` reaches the
/// declared size): small files get their single flush there, large
/// files get their sub-stride tail cleaned, and the dirty set is
/// bounded by the files actually in flight instead of the whole job.
///
/// `u64::MAX` is the parked sentinel: the completion flush stores it so
/// neither rule can fire again. `written` counts duplicate/repair spans
/// too (see `note_written`), so completion can trip a little early on a
/// duplicate-heavy file - harmless, it is still one flush of whatever
/// is dirty. `size` 0 means unknown: no completion rule, stride only.
/// The pacer's one flush primitive, shared by the inline stride path
/// and the completion flusher. macOS: plain `libc::fsync` (NOT
/// sync_data - std promotes that to a device-barrier fcntl on Apple
/// platforms, a durability tax this path does not need). Linux: NOT
/// fsync by default - measured 7 Aug on ext4 and btrfs daemon rigs, a
/// per-stride fsync forces a journal/tree commit plus a device cache
/// flush and read the same or WORSE than no pacing (btrfs worst case
/// 1230-1317 s blocked). sync_file_range starts writeback with no
/// metadata commit, no device flush and no eviction;
/// NZBFAST_PACE_MODE=fsync|sfrwait are the bench arms.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn pace_flush(fd: std::os::unix::io::RawFd) {
    // SAFETY: both calls take only the raw fd plus integer arguments;
    // every caller keeps the backing File open across the call.
    #[cfg(target_os = "macos")]
    unsafe {
        libc::fsync(fd);
    }
    // SAFETY: as above. Spelled out a second time rather than left to the
    // block comment above: the two arms are cfg-exclusive, so on Linux the
    // macos block and its comment are BOTH gone and this block is the first
    // thing `undocumented_unsafe_blocks` sees. That is a Linux-only clippy
    // error no run on a mac can reach, and it held `check` red on main.
    #[cfg(target_os = "linux")]
    unsafe {
        match pace_mode() {
            PaceMode::Sfr => {
                libc::sync_file_range(fd, 0, 0, libc::SYNC_FILE_RANGE_WRITE);
            }
            PaceMode::SfrWait => {
                libc::sync_file_range(
                    fd,
                    0,
                    0,
                    libc::SYNC_FILE_RANGE_WAIT_BEFORE
                        | libc::SYNC_FILE_RANGE_WRITE
                        | libc::SYNC_FILE_RANGE_WAIT_AFTER,
                );
            }
            PaceMode::Fsync => {
                libc::fsync(fd);
            }
        }
    }
}

/// Whether stride flushes ride the background flusher thread
/// ([`pace_flush_bg`]) rather than running inline on the decode worker
/// that crossed the watermark. `NZBFAST_PACE_BG=0` forces inline (the
/// bench control arm); anything else, including unset, is the default
/// below. Latched on first use like the stride itself.
///
/// Measured 2 Sep 2026 on the dev Mac (32-core M3 Ultra, 512 GB, APFS
/// SSD; loopback `nzbfast mockserve`, 24 x 2 GB stored set, 16 conns,
/// `get --no-extract`, arms alternated, sync + 10 s settle between
/// legs). Inline (`NZBFAST_PACE_BG=0`), 8 legs: wall 16.0-18.4 s,
/// median 16.6; sustained samples 2.9-3.1 GB/s; ~200 s summed
/// write-side blocking. Background, 11 legs: wall 12.3-13.5 s, median
/// 12.5 (-25%); sustained 3.7-4.2 GB/s; ~100 s blocking; user CPU the
/// same (15.6 vs 15.8 s), sys 6% lower, peak RSS identical (287 MB).
/// The pacing effect is kept, by the control: pacing OFF
/// (`NZBFAST_WRITE_PACE_MB=0`) finished the WIRE in the same 12.5-13.3 s
/// but the process took 16.5-22.9 s, the difference being finish()'s
/// sync pass paying the saved-up dirty set - the 6 Aug dump, moved to
/// the tail - with 4-5 of 6 rate samples below 80% of peak and +15-25%
/// CPU; the background arm shows none of that (0 samples below 80%,
/// no tail: raw-in and wall agree to 0.1 s). Queue depth is not the
/// lever here: `NZBFAST_PACE_BG_QUEUE=8` read the same as 64 (12.4,
/// 12.5 s). One background leg of twelve ran disk-bound at ~230 MB/s
/// from its FIRST second for 60 s and then at full rate (75 s wall) -
/// not a mid-run dump, and it preceded the settle change; it did not
/// recur in the eleven legs after. Linux is unaffected in practice
/// (its pacer defaults OFF); a `NZBFAST_WRITE_PACE_MB` leg there gets
/// the same routing, unmeasured.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn pace_bg_enabled() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| !matches!(std::env::var("NZBFAST_PACE_BG").as_deref(), Ok("0")))
}

/// Hand a flush to the background flusher thread - every completion
/// flush, and every stride flush while [`pace_bg_enabled`] (see the
/// notes in [`FileWriter::maybe_pace_writeback`]).
///
/// The channel is bounded and the send never blocks: a full queue means
/// the flusher is at device pace already - exactly the backpressure
/// regime where one more inline fsync on a decode worker is the honest
/// price, so the caller pays it there and then. That fallback is what
/// keeps the stride's pacing effect: the dirty set the flusher has not
/// reached is bounded by the queue, and past it the decoders block as
/// they did inline. The thread is detached on purpose: it owns nothing
/// but cloned handles, and losing queued flushes at process exit loses
/// nothing `finish()`'s own sync pass would not redo.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn pace_flush_bg(file: File) {
    use std::sync::OnceLock;
    use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
    // Option: the thread is an OPTIMISATION, and spawn can genuinely
    // fail (RLIMIT_NPROC/pids.max exhausted after the decoders start).
    // Panicking here would kill a decode worker - and with one decoder,
    // wedge the bounded outcome channel behind a reader that no longer
    // exists. No thread = every flush runs inline instead.
    static TX: OnceLock<Option<SyncSender<File>>> = OnceLock::new();
    let tx = TX.get_or_init(|| {
        let (tx, rx) = sync_channel::<File>(pace_flush_queue());
        std::thread::Builder::new()
            .name("pace-flush".into())
            .spawn(move || {
                use std::os::unix::io::AsRawFd;
                for f in rx {
                    pace_flush(f.as_raw_fd());
                }
            })
            .ok()
            .map(|_| tx)
    });
    let file = match tx {
        Some(tx) => match tx.try_send(file) {
            Ok(()) => return,
            // Full = the flusher is at device pace (backpressure) and
            // Disconnected = the thread died; either way the flush
            // still happens, here - for a completion it is this file's
            // only one, for a stride it is the pacing pause itself.
            Err(TrySendError::Full(f) | TrySendError::Disconnected(f)) => f,
        },
        None => file,
    };
    use std::os::unix::io::AsRawFd;
    pace_flush(file.as_raw_fd());
}

/// Depth of the flusher's queue: how many flushes (each a cloned
/// handle, each fsyncing EVERYTHING dirty on its file when it runs) may
/// wait before a decoder pays its stride inline. `NZBFAST_PACE_BG_QUEUE`
/// overrides for benching; the default is the completion flusher's
/// original 64.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) const PACE_FLUSH_QUEUE_DEFAULT: usize = 64;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn pace_flush_queue() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_PACE_BG_QUEUE")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(PACE_FLUSH_QUEUE_DEFAULT)
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn pace_step(
    written: u64,
    covered: u64,
    due: u64,
    size: u64,
    stride: u64,
) -> Option<u64> {
    const PARKED: u64 = u64::MAX;
    if due == PARKED {
        return None;
    }
    // Completion keys off UNIQUE coverage, never `written`: duplicate
    // spans and repair rewrites push `written` past `size` while real
    // gaps remain, and parking on aggregate traffic would leave the
    // genuine tail unpaced.
    let complete = size > 0 && covered >= size;
    if written >= due {
        // A stride crossing that is also the completion parks the
        // watermark, so the completion rule cannot double-flush.
        // Saturating: parse_pace_mb deliberately saturates an absurd
        // NZBFAST_WRITE_PACE_MB to u64::MAX, and a plain add would
        // panic (debug) or wrap to a tiny watermark that fsyncs every
        // write (release). Saturating to PARKED just stops pacing the
        // file - the right meaning for a stride that large.
        return Some(if complete {
            PARKED
        } else {
            written.saturating_add(stride)
        });
    }
    if complete {
        return Some(PARKED);
    }
    None
}
