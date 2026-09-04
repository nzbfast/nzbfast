//! Preallocated offset writer (PLAN M1 / 1d).
//!
//! One output file per NZB file, preallocated to its yEnc-declared size
//! (real extents on Linux, sparse elsewhere - see `preallocate_capped`);
//! every decoded article `pwrite`s at its final offset. No temp
//! files, no assembly pass: a direct-write design with no reassembly
//! step. `write_at` takes `&self` - decoded articles from
//! multiple consumer tasks write concurrently.

use crate::sync::{MutexExt, RwLockExt};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Raise the open-file soft limit toward the hard limit, returning the
/// effective value.
///
/// The engine holds one writer per output file for the life of a job. That
/// is a handful when direct extraction keeps volumes in RAM, but a low
/// memory budget spills them to disk instead - one writer per RAR volume,
/// 431 of them on the 190 GB set. macOS ships a 256 soft limit against a
/// 245k kernel cap, so exactly the low-memory devices that force the spill
/// path also ran out of descriptors and failed every write with EMFILE.
///
/// macOS rejects RLIM_INFINITY here, so step down through candidate targets
/// rather than asking for the hard limit directly.
///
/// Returns the soft limit now in force, or 0 where there is no such limit to
/// raise - which is every non-unix target. On Windows a `File` is a Win32
/// HANDLE bounded by kernel memory rather than by a per-process soft cap, so
/// 0 means "unlimited as far as this matters", NOT "no descriptors": callers
/// must not size the spill path off this number.
// The two `as u64` at the returns are no-ops where rlim_t IS u64 (Linux,
// macOS - the only two platforms clippy ever runs on here) and are the
// conversion that makes this compile at all where it is i64 (the BSDs).
// Without this the lint is a build error on the platforms we gate on and
// removing the cast is a build error on the platform we ship to.
// Not #[expect]: the casts live inside cfg(unix), so on Windows there
// is nothing to fire on and the expectation goes unfulfilled.
#[allow(clippy::unnecessary_cast)]
pub fn raise_fd_limit() -> u64 {
    #[cfg(unix)]
    // SAFETY: libc::rlimit is a plain all-integer C struct, so the zeroed
    // value is valid; getrlimit and setrlimit only read/write through the
    // pointers to the live stack locals (`lim`, `next`) passed here.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return 0;
        }
        // Everything below is in `libc::rlim_t`, never a hardcoded u64:
        // rlim_t is u64 on Linux and macOS but i64 on the BSDs, so the
        // literals have to be converted to the target's own type and the
        // result converted back at the return. Writing `u64` here builds
        // on the two platforms we test on and fails to compile on FreeBSD.
        let start = lim.rlim_cur;
        let hard = lim.rlim_max;
        let cap = |v: libc::rlim_t| {
            if hard == libc::RLIM_INFINITY {
                v
            } else {
                v.min(hard)
            }
        };
        for target in [65536, 16384, 4096, 1024] {
            let want = cap(target as libc::rlim_t);
            if want <= lim.rlim_cur {
                continue;
            }
            let mut next = lim;
            next.rlim_cur = want;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &next) == 0 {
                return want as u64;
            }
        }
        start as u64
    }
    #[cfg(not(unix))]
    0
}

/// How much of a `remaining`-byte span to take into a `cap`-byte buffer:
/// the span, CLAMPED IN u64, and only then narrowed.
///
/// THE ORDER IS THE WHOLE POINT, and getting it backwards is a class of
/// bug this tree carried at nineteen sites. `(remaining as usize).min(cap)`
/// narrows FIRST, and `usize` is 32 bits on the shipped
/// `armv7-unknown-linux-musleabihf` target - so a remaining span of
/// exactly 4 GiB narrows to ZERO and the caller takes nothing. In a
/// decrementing loop that is no progress at all, forever; in a reader it
/// is `Ok(0)`, which every consumer in this tree - and the vendored rars
/// engine, whose `BlockingRangeSource` contract says `Ok(0)` means the
/// source ends here - reads as a clean end of file.
///
/// AND IT IS NOT AN ALIGNMENT COINCIDENCE. The near-miss case funnels
/// into the zero case: with a cap of B the last short read takes
/// `remaining % 2^32` bytes, which lands `remaining` exactly on a
/// multiple of 2^32, and the next call returns zero. So the trigger is
/// "any span of 4 GiB or more", deterministically - an ordinary large
/// video, a zip64 member, a PAR2 target file.
///
/// On a 64-bit host this is bit-identical to the narrow-first spelling
/// (`u64::MAX as usize == usize::MAX`), which is why the class was
/// invisible to every suite this fleet runs.
///
/// Returns 0 ONLY for an empty span or an empty buffer - the debug
/// assertion pins that, and it is the assertion that would have caught
/// all nineteen, since every one of those call sites had already proved
/// its span non-empty before it narrowed.
#[inline]
pub fn chunk_len(remaining: u64, cap: usize) -> usize {
    let n = remaining.min(cap as u64) as usize;
    debug_assert!(
        n > 0 || remaining == 0 || cap == 0,
        "chunk_len({remaining}, {cap}) took nothing from a non-empty span"
    );
    n
}

/// Positioned read: unix pread never touches the file cursor; Windows
/// `seek_read` does move it, so every access to engine-written files must
/// go through these helpers (nothing reads via the cursor today).
pub fn read_exact_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.read_exact_at(buf, off)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut buf, mut off) = (buf, off);
        while !buf.is_empty() {
            match f.seek_read(buf, off) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    ));
                }
                Ok(n) => {
                    let rest = buf;
                    buf = &mut rest[n..];
                    off += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Process-wide bytes written through the positioned-write path - the
/// dashboard's disk-write rate. Counted here rather than from OS
/// counters: buffered writeback is charged to the kernel, not to us
/// (macOS ri_diskio_byteswritten stays near zero during a download).
static BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);

pub fn bytes_written() -> u64 {
    BYTES_WRITTEN.load(Ordering::Relaxed)
}

/// Process-wide POSITIONED-WRITE CALLS, the quantity round 23 named as
/// the small-article cost: a `pwrite` costs about the same for 50 KB as
/// for 700 KB, so the bytes counter above says nothing about what the
/// kernel is charged and this one says everything. It is what makes the
/// coalescing window ([`stage`]) measurable from inside the binary
/// rather than only under a profiler - an A/B arm reads it at the end of
/// a leg and the ratio IS the change.
static WRITES_ISSUED: AtomicU64 = AtomicU64::new(0);

pub fn writes_issued() -> u64 {
    WRITES_ISSUED.load(Ordering::Relaxed)
}

/// Positioned write, same cross-platform contract as [`read_exact_at`].
///
/// The telemetry counter is charged on SUCCESS, not on entry: charging
/// the requested length up front showed phantom disk throughput during
/// exactly the ENOSPC/EIO episodes where writes were failing and the
/// retry ladder was re-attempting them. On unix a partial write that
/// precedes an error goes uncounted - the conservative direction for a
/// rate readout.
pub fn write_all_at(f: &File, buf: &[u8], off: u64) -> io::Result<()> {
    WRITES_ISSUED.fetch_add(1, Ordering::Relaxed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.write_all_at(buf, off).inspect(|()| {
            BYTES_WRITTEN.fetch_add(buf.len() as u64, Ordering::Relaxed);
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut buf, mut off) = (buf, off);
        while !buf.is_empty() {
            match f.seek_write(buf, off) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ));
                }
                Ok(n) => {
                    BYTES_WRITTEN.fetch_add(n as u64, Ordering::Relaxed);
                    buf = &buf[n..];
                    off += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Is this write-path error the storage itself running out from under
/// us - a condition no amount of refetching fixes? True for a full
/// volume (`StorageFull`), an exhausted quota (`QuotaExceeded`), a
/// filesystem that went read-only mid-run (`ReadOnlyFilesystem` - USB
/// disks and network shares do this when they hit trouble), and the
/// `WriteZero` a positioned write reports when the kernel accepts zero
/// bytes forever (the Windows path above manufactures exactly that on a
/// full disk).
///
/// The raw-code fallback is gated to the platform whose number it is:
/// 112 is ERROR_DISK_FULL on Windows but EHOSTDOWN on Unix, and an
/// unguarded match would call a dead host a full disk (the same trap
/// `disk_full_failure` documents on the message side). Raw codes matter
/// at all because errors built via `Error::from_raw_os_error` carry the
/// code without the kind mapping std's syscall wrappers apply.
pub fn storage_exhausted(e: &io::Error) -> bool {
    match e.kind() {
        io::ErrorKind::StorageFull
        | io::ErrorKind::QuotaExceeded
        | io::ErrorKind::ReadOnlyFilesystem
        | io::ErrorKind::WriteZero => true,
        _ => match e.raw_os_error() {
            // ENOSPC, EROFS / ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL,
            // ERROR_WRITE_PROTECT.
            Some(code) if cfg!(windows) => matches!(code, 112 | 39 | 19),
            Some(code) => matches!(code, 28 | 30),
            None => false,
        },
    }
}

/// Process default for [`FileWriter`] cache dropping (see
/// `maybe_drop_cache`). Set BEFORE the first write of the run - the
/// per-process decision is latched on first use.
static DROP_CACHE_DEFAULT: std::sync::atomic::AtomicBool =
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
fn drop_cache_auto_for(ram: Option<u64>, cgroup_limit: Option<u64>) -> bool {
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
const WRITE_PACE_STRIDE_DEFAULT: u64 = 32 << 20;

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
fn write_pace_stride() -> u64 {
    #[cfg(target_os = "macos")]
    const DEFAULT: u64 = WRITE_PACE_STRIDE_DEFAULT;
    #[cfg(target_os = "linux")]
    const DEFAULT: u64 = 0;
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
fn parse_pace_mb(raw: Option<&str>) -> Option<u64> {
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
fn nocache_enabled() -> bool {
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
enum PaceMode {
    Sfr,
    SfrWait,
    Fsync,
}

#[cfg(target_os = "linux")]
fn pace_mode() -> PaceMode {
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
fn drop_cache_enabled() -> bool {
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
fn apply_cache_policy(file: &File) {
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

/// Windows write-path fixes (6 Aug line-rate campaign), both latched on
/// first use like the macOS pacing stride.
///
/// `NZBFAST_WIN_SPARSE=0` disables the sparse-output fix (see
/// [`preallocate_capped`]); anything else, including unset, leaves it on.
#[cfg(windows)]
fn win_sparse_enabled() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| !matches!(std::env::var("NZBFAST_WIN_SPARSE").as_deref(), Ok("0")))
}

/// How many write lanes (OS handles) a [`FileWriter`] spreads positioned
/// writes across on Windows - see the `aux` field for why. 1 = the old
/// single-handle behaviour; `NZBFAST_WIN_WRITERS` overrides.
#[cfg(windows)]
fn win_writer_lanes() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_WIN_WRITERS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(WIN_WRITER_LANES_DEFAULT)
            .clamp(1, 16)
    })
}

/// Default lane count: 1, i.e. the lane spread stays DARK. Measured on
/// a native-Windows loopback A/B (7 Aug, 80 GB mock, 2 reps): 4 lanes
/// alone moved nothing (135.7/165.6 s wall against a 132.3/173.2 s
/// baseline, write-side blocking identical), and on top of the sparse
/// fix they consistently cost ~10% (89.3/90.0 s against 79.3/86.4 s
/// sparse-alone). File-object lock serialization was not the disease -
/// VDL zero-fill was.
///
/// RE-TESTED AT A HIGHER WRITE RATE AND STILL NULL (3 Sep 2026, audit
/// round 22), which is what TODO 126.5 asked for: the same box, an
/// end-to-end `mockserve` download of 24 GB at 1.38-1.78 GB/s of
/// payload, NINE interleaved pairs across both its drives. C: (970 EVO
/// Plus, six pairs on a quiet box) base 20.82/20.77/21.38/22.07/21.45/
/// 20.86 s against lanes 20.76/21.21/21.39/20.85/21.21/21.39 - three
/// pairs each way, medians 21.12 and 21.21. D: (MP400, inside its SLC
/// cache, three pairs) 19.75/20.25/20.94 against 19.32/18.52/20.72 -
/// lanes ahead in all three, by 2%, 8.5% and 1%, which is INSIDE the
/// 6.3% spread the identical C: arm shows across its own six reps. So
/// the 10% cost is not reproduced either: at this rate the spread is
/// simply not separable from the box, and the default stays 1 on a
/// wider basis than it had. The cell TODO 126.5 actually names - a
/// device sustaining 3+ GB/s - is still unmeasured; no box on this
/// fleet has one.
#[cfg(windows)]
const WIN_WRITER_LANES_DEFAULT: usize = 1;

/// Flag `file` as sparse (FSCTL_SET_SPARSE). Best-effort: a filesystem
/// that refuses the ioctl (FAT32, some network shares) just keeps
/// zero-fill semantics, which is always correct.
#[cfg(windows)]
fn mark_sparse(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    let mut bytes = 0u32;
    // SAFETY: DeviceIoControl with a null input buffer is the documented
    // "SetSparse = TRUE" form; the borrow of `file` keeps the handle
    // open across the call, and `bytes` outlives it on the stack.
    unsafe {
        DeviceIoControl(
            file.as_raw_handle() as _,
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut bytes,
            std::ptr::null_mut(),
        );
    }
}

/// Open `lanes - 1` extra read+write handles on the SAME FILE OBJECT as
/// `primary` for the Windows write-lane spread. Best-effort: stop at the
/// first failure and run with what opened (possibly none) - fewer lanes
/// is always correct.
///
/// FROM THE HANDLE, NEVER FROM THE NAME (X5-06/08/19 OWED item 5,
/// 31 Aug 2026). This is called from inside both constructors' struct
/// literals and from [`FileWriter::unpark`], which is to say AFTER the
/// primary's own no-follow bound open has already settled which inode
/// this writer owns. Reopening `path` here asked the filesystem the
/// question a second time, so anything that changed what the name
/// referred to in between handed the lanes a DIFFERENT INODE from the
/// primary - and every lane writes payload bytes at absolute offsets,
/// so the two would have interleaved one file's contents across two.
/// `ReOpenFile` takes the existing handle and hands back a new one to
/// the same file object with its own file pointer, which is what the
/// lane spread wanted in the first place: there is no name in it to
/// race.
///
/// Windows-only, and EXECUTED for the first time on 3 Sep 2026 (audit
/// round 22: a 6-core x86 Windows box, `NZBFAST_WIN_WRITERS=4` over
/// twelve 24 GB download legs across a TLC and a QLC NVMe drive) -
/// this comment said "COMPILE-VERIFIED
/// ONLY - no box on this fleet can execute it" until then, which had
/// stopped being true when that box gained its MSVC toolchain. The
/// spread is still dark by default
/// ([`WIN_WRITER_LANES_DEFAULT`] is 1, so the loop below does not run
/// unless `NZBFAST_WIN_WRITERS` turns it on - the variable this module
/// actually reads, and NOT `NZBFAST_WIN_WRITE_LANES`, which this comment
/// named until 3 Sep 2026 and which nothing has ever read: a reader
/// following it would have set a variable with no effect, measured one
/// lane, and concluded the spread does nothing). A `ReOpenFile` that
/// refuses is not an error: the writer runs on the primary alone,
/// which is the shipped configuration.
#[cfg(windows)]
fn open_aux_handles(primary: &File) -> Vec<File> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
    };
    let lanes = win_writer_lanes();
    let mut v = Vec::new();
    for _ in 1..lanes {
        // Same sharing std itself opens with, so the lanes can coexist
        // with each other and with whatever else holds the file; 0
        // flags, because `ReOpenFile` takes FILE_FLAG_* values there
        // and this wants none of them.
        // SAFETY: `primary` is borrowed across the call so its handle
        // stays live; ReOpenFile reads it and returns a fresh handle or
        // INVALID_HANDLE_VALUE, and writes nothing back through a
        // pointer.
        let h = unsafe {
            ReOpenFile(
                primary.as_raw_handle() as _,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            break;
        }
        // SAFETY: `h` is a fresh, valid, owned handle from the call
        // above (checked against both failure spellings), and nothing
        // else holds or closes it - so `File` takes sole ownership of
        // it exactly once.
        v.push(unsafe { File::from_raw_handle(h as _) });
    }
    v
}

/// Reopen a read handle on the same Windows file object with an independent
/// cursor. Positioned-read compatibility uses the handle cursor on Windows,
/// so parallel readers cannot safely share one `File`; reopening by pathname,
/// however, can switch to a replacement between verification passes.
#[cfg(windows)]
pub(crate) fn reopen_read_handle(primary: &File) -> io::Result<File> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, ReOpenFile,
    };

    // Same sharing mode as Rust's File::open. ReOpenFile resolves from the
    // live handle rather than from a name and returns a fresh file pointer.
    // SAFETY: `primary` keeps its valid handle alive for the call; a successful
    // result is a fresh owned handle transferred exactly once into `File`.
    let h = unsafe {
        ReOpenFile(
            primary.as_raw_handle() as _,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: failure handles were rejected above and no other owner closes
    // this fresh handle.
    Ok(unsafe { File::from_raw_handle(h as _) })
}

/// What a path is sitting on.
///
/// `Unknown` is a first-class answer and must never be treated as
/// `Rotational`: device mapper, RAID, overlayfs in a container and
/// every non-Linux local disk land here, and guessing "spinning" for
/// them would clamp hardware that has no seek problem.
///
/// `Network` was added 3 Sep 2026 by the read-side cache policy
/// (`readpolicy`), which needs to know what a RE-READ costs and not
/// only what a seek costs - a payload dropped from the page cache on
/// an SMB share is fetched again over the wire. It is a separate
/// variant rather than a second enum because there is one storage
/// question in this tree and it gets one answer; `decoders_for_storage`
/// treats it exactly as it treated the `Unknown` these mounts used to
/// report, so the download path's behaviour is unchanged by the split.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Storage {
    Rotational,
    Solid,
    /// SMB/CIFS, NFS, AFP, WebDAV, 9P or a FUSE client. Local seek cost
    /// unknown; a re-read crosses a wire.
    Network,
    Unknown,
}

/// A storage class and HOW it was reached.
///
/// Two fields because two different questions are asked of this probe
/// and only one of them is answered by the class alone. The read-side
/// cache policy wants to know what a RE-READ costs, which is a property
/// of the device; the decode-worker clamp and the spill governor's
/// stand-down want to know whether OUR WRITE ORDER is the order the
/// platter sees, which is a property of the filesystem on top of it.
/// [`StorageProbe::direct_dev`] is what separates them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StorageProbe {
    /// What the storage is.
    pub class: Storage,
    /// `true` when `class` was read off the block device that the
    /// filesystem's OWN `st_dev` names, or asserted by the operator
    /// through `NZBFAST_STORAGE`.
    ///
    /// `false` means `st_dev` was ANONYMOUS and the device had to be
    /// found through the mount table (`disk::mounttab`). That is not
    /// merely a weaker probe. The filesystems with an anonymous device
    /// are exactly the ones that put a layer between a `pwrite` offset
    /// and a platter address - btrfs and ZFS copy on write, overlayfs
    /// writes into a different filesystem entirely - so a rule that
    /// exists because "N decode workers become N seek lanes" does not
    /// follow there even when the class is right.
    ///
    /// `Unknown` and `Network` carry `true` because there is no indirect
    /// answer for the flag to qualify - including the case where the
    /// fallback ran and stood down, which is what overlayfs inside a
    /// container does (measured: its mountinfo source is the word
    /// `overlay`, and its `upperdir=` names a path in the HOST).
    pub direct_dev: bool,
}

/// What is under `path`, with `NZBFAST_STORAGE=rotational|ssd|auto` as the
/// operator override (`auto`, or anything unset, probes).
///
/// The probe matters because decoded articles `pwrite` at their final
/// offsets: with several decode workers the network's article lanes become
/// the output file's seek lanes, which a spinning disk pays for and an SSD
/// does not.
///
/// The thin reading of [`probe_storage`], for the callers that only want
/// the class. `decoders_for_storage` is the one that wants the rest.
pub fn detect_storage(path: &Path) -> Storage {
    probe_storage(path).class
}

/// [`detect_storage`], plus how the answer was reached.
///
/// ONE probe, one answer, richer answer - the storage question is not
/// duplicated anywhere else in this tree and must not be. The two arms
/// are tried in order: the filesystem's own device id first, and the
/// mount table only when that names nothing.
pub fn probe_storage(path: &Path) -> StorageProbe {
    let direct = |class| StorageProbe {
        class,
        direct_dev: true,
    };
    if let Some(forced) = storage_override(std::env::var("NZBFAST_STORAGE").ok().as_deref()) {
        // The operator asserting a class asserts it for every reader:
        // `NZBFAST_STORAGE=rotational` has clamped decoders since the
        // clamp existed and must keep doing so.
        return direct(forced);
    }
    // Asked BEFORE the rotational flag because a network mount has no
    // block device to read one from: on Linux it would fall through to
    // `Unknown`, and on macOS `rotational` answers `None` for
    // everything. The operator override still wins over both.
    if readpolicy::is_network_fs(path) {
        return direct(Storage::Network);
    }
    if let Some(spinning) = rotational(path) {
        return direct(class_of(spinning));
    }
    match rotational_via_mount_table(path) {
        Some(spinning) => StorageProbe {
            class: class_of(spinning),
            direct_dev: false,
        },
        None => direct(Storage::Unknown),
    }
}

/// The rotational flag as a class. One place, so the two arms of
/// [`probe_storage`] cannot come to disagree about which way round it is.
fn class_of(spinning: bool) -> Storage {
    if spinning {
        Storage::Rotational
    } else {
        Storage::Solid
    }
}

/// The `NZBFAST_STORAGE` override, parsed. Split out so the mapping is
/// testable without mutating the environment: tests share one process, so
/// a `set_var` here would race every other test that probes storage.
fn storage_override(raw: Option<&str>) -> Option<Storage> {
    match raw {
        Some("rotational") | Some("hdd") => Some(Storage::Rotational),
        Some("ssd") | Some("solid") => Some(Storage::Solid),
        _ => None,
    }
}

/// Read the backing block device's `queue/rotational` flag, using the
/// filesystem's OWN device id and nothing else.
///
/// The device id of the file's filesystem indexes `/sys/dev/block`, which
/// for a partition resolves to the partition's directory - `queue/` lives
/// on the parent disk, hence the walk up one level.
///
/// **A whole family of filesystems has no device id to index with, and
/// this answers `None` for every one of them.** btrfs, ZFS and overlayfs
/// allocate an ANONYMOUS block device (`major 0`), so `st_dev` names
/// nothing under `/sys/dev/block` and the canonicalize below fails.
/// Measured on the fleet's rotational NAS on 3 Sep 2026 with the
/// `readpolicy_probe` example, on the box: its btrfs data volume (twelve
/// spinning disks, every one of them reporting `queue/rotational 1`)
/// answered `class=Unknown`, while `/` on ext4 over the same disks
/// answered `class=Rotational`.
///
/// **That hole is no longer the end of the probe** (TODO 325, 4 Sep
/// 2026): [`probe_storage`] falls through to `mounttab`, which finds the
/// device the mount was made from instead, and the NAS volume above now
/// answers `Rotational`. This function is deliberately left as the
/// narrow question it always was - it is the arm whose answer carries
/// `direct_dev`, i.e. the one a caller may read as a statement about
/// write ORDER and not only about the device. The round that found the
/// hole is in `research/PAR2-TWO-LANES-COMPARED-2026-09-03.md`; the one
/// that closed it, including the three shapes that broke the obvious
/// designs, is `research/STORAGE-PROBE-ANON-DEV-2026-09-04.md`.
#[cfg(target_os = "linux")]
fn rotational(path: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    // Probe the directory itself, not a file inside it: the caller may not
    // have created anything yet.
    let dev = std::fs::metadata(path).ok()?.dev();
    // libc::major/minor are safe fns on Linux (they only bit-shift the
    // integer dev value) - an `unsafe` block here trips `-D unused-unsafe`
    // on the CI runner, the one platform that compiles this cfg.
    let (major, minor) = (libc::major(dev), libc::minor(dev));
    sysfs_rotational(format!("/sys/dev/block/{major}:{minor}"))
}

/// `queue/rotational` under a sysfs block-device directory, with the
/// parent walk a partition needs.
///
/// Shared with `mounttab`, which reaches the same file by a different
/// route: one reader for one file, so the two arms of the probe cannot
/// come to disagree about what `1` means or where `queue/` lives.
#[cfg(target_os = "linux")]
fn sysfs_rotational(dir: impl AsRef<Path>) -> Option<bool> {
    let sys = std::fs::canonicalize(dir).ok()?;
    let read = |dir: &Path| -> Option<bool> {
        let raw = std::fs::read_to_string(dir.join("queue/rotational")).ok()?;
        match raw.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    };
    read(&sys).or_else(|| read(sys.parent()?))
}

#[cfg(not(target_os = "linux"))]
fn rotational(_path: &Path) -> Option<bool> {
    None
}

/// Core count at or below which a box is treated as NAS-class for the
/// rotational clamp.
const NAS_CORES: usize = 4;

/// How many decode workers to run, given what the output sits on.
///
/// Decoded articles `pwrite` at their final offsets, so N decode workers
/// scatter N interleaved write streams across the output file: the
/// network's article lanes become the platter's seek lanes. One worker
/// keeps them in order.
///
/// Gated on THREE signals, because the clamp is only free on one side of
/// each. On a NAS-class box it costs nothing - measured flat from 1 to 4
/// decoders on Gracemont E-cores (the N100-class proxy), since this path
/// does not scale with decode workers there. On a big box it is NOT free
/// (1075 -> 3226 MB/s going 1 to 4 decoders on an M3 Ultra), and a
/// rotational device there is usually a wide array that can absorb the
/// parallel writes. `Unknown` never clamps, and neither does `Network`:
/// those mounts reported `Unknown` here until the variant was split out
/// on 3 Sep 2026 and this rule must not change under them.
///
/// **The third signal is [`StorageProbe::direct_dev`], and it is what
/// keeps this rule where its evidence is** (TODO 325, 4 Sep 2026).
/// Closing the anonymous-device hole in the probe made `Rotational`
/// newly VISIBLE on btrfs and ZFS, which would have handed this clamp
/// to every small btrfs NAS in one commit - a throughput change on a
/// population nobody has measured, and the fleet has no box with both a
/// rotational volume and few enough cores to measure it on (the one
/// spinning Linux box has twelve). The stand-down is not merely "not
/// measured", though: the sentence this clamp rests on is about WRITE
/// ORDER reaching the platter, and on the filesystems the fallback
/// reaches it does not - btrfs and ZFS copy on write, so the allocator
/// and not our `pwrite` offset decides where a block lands. So the
/// clamp asks for a class read off the filesystem's own device. An
/// operator who wants it anyway still has `NZBFAST_STORAGE=rotational`,
/// which asserts `direct_dev`.
pub fn decoders_for_storage(storage: StorageProbe, cores: usize, decoders: usize) -> usize {
    if decoders > 1
        && cores <= NAS_CORES
        && storage.class == Storage::Rotational
        && storage.direct_dev
    {
        1
    } else {
        decoders
    }
}

/// The verdict BOTH bomb guards raise - [`WriteBudget::charge`] on the
/// in-stream path and nzbfast's `BombGuardWriter` on the disk one.
///
/// One constant because the text is a CONTRACT, not a message: the
/// extraction ladder reads it back off a demote reason (an in-stream
/// group fallback carries "chase failed: {e}") and off an anyhow error
/// string, and stops there rather than handing the same archive to the
/// next rung. Two hand-copied literals would have drifted the first time
/// either was reworded, and the failure mode is silent - the ladder
/// simply runs on.
pub const BOMB_VERDICT: &str =
    "extraction exceeded available disk space (possible decompression bomb)";

/// Does this failure text carry [`BOMB_VERDICT`]?
///
/// Matched on the distinctive tail rather than the whole sentence: both
/// call sites wrap it (`chase failed: …`, `parsing volumes: …`,
/// anyhow's `{e}` chains), and no other diagnostic in the tree says
/// "decompression bomb".
///
/// The answer is load-bearing on the KEEP side. A set refused here must
/// not be retried by an unpacker that carries no budget of its own: the
/// external `unrar` subprocess has none, so on 22 Aug 2026 a 2 GB
/// zeros RAR5 refused twice - once in-stream, once by the disk guard -
/// still filled a 730 MB volume on the third rung, and the job then
/// blamed the archive ("encrypted or damaged?").
pub fn bomb_verdict(text: &str) -> bool {
    text.contains("decompression bomb")
}

/// A job-wide cap on the DISTINCT extracted bytes an extraction chain may
/// write, shared by every [`FileWriter`] that carries it.
///
/// The disk/post-pass extraction sinks have had a decompression-bomb
/// budget since M3 (`BombGuardWriter`), but the in-stream one-pass
/// extractor - the default path for every download - wrote through
/// `FileWriter` with no budget at all, so the guard covered the fallback
/// and not the common case. Attaching the budget here puts the accounting
/// on the one write chokepoint the in-stream path shares.
///
/// Charged with the NEWLY-COVERED byte count from [`FileWriter::note_written`],
/// never the raw write length: a repair span rewrites a range that already
/// paid for itself, and charging it twice would trip the guard on a job
/// that is merely healing.
#[derive(Debug)]
pub struct WriteBudget {
    limit: AtomicU64,
    written: AtomicU64,
}

impl WriteBudget {
    pub fn new(limit: u64) -> WriteBudget {
        WriteBudget {
            limit: AtomicU64::new(limit),
            written: AtomicU64::new(0),
        }
    }

    /// No cap - the default everywhere a budget has not been wired.
    pub fn unlimited() -> WriteBudget {
        WriteBudget::new(u64::MAX)
    }

    pub fn set_limit(&self, limit: u64) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    pub fn limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    pub fn used(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// Charge `n` newly-covered bytes; Err once the running total crosses
    /// the limit. Saturating so a pathological total can't wrap back under
    /// the cap.
    ///
    /// An UNLIMITED budget is accumulated too, rather than short-circuited:
    /// [`FileWriter`] tallies what it handed over so [`Self::release`] can
    /// hand it back, and a fast path here would make that tally disagree
    /// with `written` on any chain whose limit is set after the first
    /// write. `used()` is then honest on an unlimited budget as well,
    /// which is what `extract_budget_used` reports.
    fn charge(&self, n: u64) -> io::Result<()> {
        if n == 0 {
            return Ok(());
        }
        let limit = self.limit.load(Ordering::Relaxed);
        let total = self
            .written
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
                Some(w.saturating_add(n))
            })
            .unwrap_or(0)
            .saturating_add(n);
        if limit != u64::MAX && total > limit {
            // StorageFull, not `other`: the budget IS a space budget, and
            // the consumer's halt (`note_storage_exhausted_halt`) is
            // keyed on `storage_exhausted`. As a plain `other` this error
            // classified as an ordinary per-article decode/write failure,
            // so the fetch kept running at line rate and every remaining
            // article was downloaded, written, and counted as an error -
            // 134 of them on the 22 Aug 2026 class E floor leg, i.e. the
            // guard let through exactly the gigabytes it exists to stop,
            // then failed the job on a counter instead of a cause.
            // Classified, it aborts the pool on the first trip and
            // `drain_network` reports one out-of-space verdict with this
            // message appended, keeping the journal for the resume.
            //
            // The disk-path twin of this guard (`BombGuardWriter` in
            // nzbfast's rarfix.rs) raises the same message as a plain
            // `other` on purpose: it runs after the download, so it has no
            // fetch to halt and its error aborts the extraction directly.
            return Err(io::Error::new(io::ErrorKind::StorageFull, BOMB_VERDICT));
        }
        Ok(())
    }

    /// Give `n` charged bytes back: the file that paid for them has been
    /// UNLINKED, so they are not on the volume any more and must not go
    /// on counting against a budget that stands for free space.
    ///
    /// The one caller is [`FileWriter::abandon`], which every path that
    /// disowns-and-deletes an output goes through (`drop_slot_file`,
    /// `abandon_slot`, `delete_group_out_files`). It exists for the
    /// drop-behind trim (TODO 37 med1): at depth > 0 a chased archive's
    /// spilled prefix is charged like any other extraction output -
    /// correctly, since it really does occupy the volume beside the
    /// payload - but a chase that SUCCEEDS then deletes that prefix, and
    /// with no credit the next container in the same job started against
    /// a budget already spent on bytes nothing holds. Several nested
    /// archives in one job could refuse a legitimate extract as a bomb.
    ///
    /// Saturating, and deliberately never touches `limit`: the budget is
    /// a high-water allowance, not a reservation, and clamping at zero
    /// means an over-refund (a writer whose charge landed on an unlimited
    /// budget) can only ever be conservative.
    pub fn release(&self, n: u64) {
        if n == 0 {
            return;
        }
        let _ = self
            .written
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
                Some(w.saturating_sub(n))
            });
    }
}

/// Custody of a live output file while an external tool owns it
/// (sweep 8, M4).
///
/// `park` closes the writer's OWN handles, which is all par2cmdline
/// needed until /stream existed. A live range response owns a SEPARATE
/// `std::fs::File` on the same inode for its whole lifetime, and
/// par2cmdline 0.8.1 opens its targets with share mode 0: on Windows one
/// reading player therefore makes the external repair's open fail and it
/// reports a repairable file as missing ("Repair is not possible").
///
/// The VERSION qualifier is load-bearing and is measured, on x86-64
/// Windows 11 with a reader handle held across `par2 repair`: 0.8.1
/// fails the repair outright ("Repair Failed.", exit 5), 1.2.0 and 1.3.0
/// both repair fine. So this custody exists for the par2 a Windows user
/// may well have installed, not for the one they probably do - which is
/// the right way round, but it also means a test run against a current
/// par2 passes whether or not any of this works. The full matrix and
/// that warning live in `nzbfast`'s
/// `tests/integration/stream_repair.rs` header.
///
/// So reader admission and repair share one gate. Entering repair marks
/// the file `repairing`, which
///
/// - refuses (after a bounded wait) every NEW by-path reader open on
///   every platform - a fresh handle landing while the child rewrites
///   the bytes is nobody's idea of a good read, and
/// - on Windows ONLY, revokes the leases already outstanding and waits
///   for their handles to close. Unix does not enforce sharing, so
///   there an existing response survives the repair and goes on to
///   serve the repaired bytes (which is exactly what M5's coverage
///   publication licenses). Killing those responses on Unix would be a
///   regression traded for nothing.
///
/// The response survives; its FD does not. Leaving repair moves the
/// custody generation on, and that is what tells a surviving reader to
/// reopen: par2cmdline renames the damaged target aside and writes its
/// repaired output to a NEW inode, so the fd the response opened with is
/// a file nothing will ever write to again - see
/// [`ReadLease::needs_reopen`] (sweep 8, M5b).
pub struct ReadCustody {
    st: std::sync::Mutex<CustodyState>,
    cv: std::sync::Condvar,
}

#[derive(Default)]
struct CustodyState {
    /// An external tool owns this file right now.
    repairing: bool,
    /// Outstanding [`ReadLease`]s - by-path reader handles on the inode.
    readers: usize,
    /// How many external repairs have COMPLETED on this file. A reader
    /// handle belongs to the generation it was opened in and stops
    /// being the file the moment that number moves - see
    /// [`ReadLease::needs_reopen`].
    generation: u64,
    /// The file as the external repair left it, captured by [`unpark`]
    /// in the same breath as the generation bump. Readers that survived
    /// the repair clone THIS rather than re-opening by name.
    ///
    /// Because by name loses a race it cannot win: postproc renames the
    /// job's whole FOLDER a moment after the repair, `current_path`
    /// tracks only the file's own publish rename, and a reader whose
    /// next read landed after that rename got ENOENT (measured 22 Aug
    /// 2026 - the reopen failed and the response was left on the
    /// damaged inode, which is the whole bug). `unpark` opens the path
    /// at the one instant it is certainly right, so the handle it got
    /// is the answer for every reader after it.
    ///
    /// Cleared by [`claim_for_repair`], because the NEXT repair's
    /// target is a different file and, on Windows, a handle we still
    /// hold is exactly what parking exists to release. Deliberately
    /// survives a plain [`park`]: that one is the end-of-job handle
    /// release, and an in-flight response still owed its rebind must
    /// not be handed a stale path because postproc got there first.
    ///
    /// `None` on Windows, always: every surviving reader is revoked
    /// there, so this would never be read and would only be one more
    /// handle in an external tool's way.
    ///
    /// [`unpark`]: FileWriter::unpark
    /// [`park`]: FileWriter::park
    /// [`claim_for_repair`]: FileWriter::claim_for_repair
    repaired: Option<File>,
    /// Test seam (F-21): parks ONE admitted reader at the door it opens
    /// through - under the custody lock, exactly where the descriptor's
    /// ordering against a later `repairing = true` is decided. Consumed
    /// by its single trip. Two-stage shape as `drain_send_barrier`.
    #[cfg(test)]
    open_barrier: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
}

/// A live reader's claim on an output file's inode. Held for the whole
/// life of the `std::fs::File` it was issued with; dropping it is what
/// tells a waiting [`FileWriter::park`] the handle is gone.
pub struct ReadLease {
    custody: Arc<ReadCustody>,
    /// The custody generation this handle's inode belongs to. Compared
    /// against [`CustodyState::generation`] by [`needs_reopen`]; moved
    /// forward by [`FileWriter::reopen_read`] and by nothing else.
    ///
    /// [`needs_reopen`]: ReadLease::needs_reopen
    seen: AtomicU64,
}

impl ReadLease {
    /// The file has been handed to an external repair and this reader's
    /// handle is in its way. Windows only - see [`ReadCustody`]. Callers
    /// poll it wherever they would otherwise block, and end the response
    /// rather than hold the inode.
    pub fn revoked(&self) -> bool {
        cfg!(windows) && self.custody.st.lock_ok().repairing
    }

    /// An external repair has finished and this handle is on the wrong
    /// inode (sweep 8, M5b). Poll it exactly where [`revoked`] is
    /// polled, and reopen through [`FileWriter::reopen_read`].
    ///
    /// par2cmdline does NOT repair a damaged target in place: it renames
    /// it to `<name>.1` and writes the repaired data to a NEW inode. The
    /// writer survives that because [`unpark`] reopens by
    /// [`current_path`], but a live reader holds its own `File` for the
    /// whole response and that `File` is still the damaged one. M5 then
    /// publishes the repaired coverage, so the reader stops waiting and
    /// serves the stale bytes - the exact hole the repair filled, read
    /// off the orphaned inode (measured 22 Aug 2026 on macOS with a
    /// 16 MB `.mkv` in its own par2 set: two distinct inodes, and the
    /// player was served the zero-filled hole over the repaired span).
    /// Windows never showed it because the lease is revoked there and
    /// the response ends.
    ///
    /// False while a repair is IN PROGRESS - reopening then would just
    /// pick up whichever inode par2 happens to have in place - so a
    /// caller polling this can only ever land on the settled file.
    ///
    /// [`revoked`]: ReadLease::revoked
    /// [`unpark`]: FileWriter::unpark
    /// [`current_path`]: FileWriter::current_path
    pub fn needs_reopen(&self) -> bool {
        let g = self.custody.st.lock_ok();
        !g.repairing && g.generation != self.seen.load(Ordering::Relaxed)
    }
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        let mut g = self.custody.st.lock_ok();
        g.readers = g.readers.saturating_sub(1);
        drop(g);
        self.custody.cv.notify_all();
    }
}

/// How long a fresh reader open waits for an external repair to finish
/// before giving up. Long enough for the ordinary case (par2cmdline on
/// a repairable set is seconds), short enough that a player is told
/// something rather than hanging.
const REPAIR_ADMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long `park` waits for revoked Windows readers to close. Bounded:
/// a reader wedged in the kernel must not turn a repair into a hang,
/// and proceeding anyway is exactly the pre-lease behaviour.
#[cfg(windows)]
const REPAIR_DRAIN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The article-write gate per [`FileWriter`]: the byte spans whose
/// delivery is between its coverage peek and its pwrite. See
/// [`FileWriter::write_article_at`]. Until 2 Sep 2026 this was sixteen
/// mutexes sharded by 1 MiB of file offset, each HELD ACROSS the pwrite -
/// so two neighbouring articles of one file, which usually share a
/// grain, serialised behind each other's disk write: 13% of every decode
/// thread's time on a 16-connection loopback download sat in that wait
/// (research/RAR-PERF-AUDIT-2026-09-02.md, round 5). Now the lock covers
/// only the bookkeeping, and only a span that OVERLAPS one in flight
/// waits, on `article_cv`.
struct ArticleGate {
    inflight: Vec<(u64, u64)>,
}

pub struct FileWriter {
    /// `None` while PARKED - the handle is closed but the writer (and every
    /// `Arc` clone of it) stays alive and reopens on [`FileWriter::unpark`].
    /// See [`FileWriter::park`] for why the handle has to be droppable at
    /// all; ordinary writers are `Some` for their whole life.
    ///
    /// `RwLock` rather than a bare `File` costs one uncontended read
    /// acquisition per `write_at`, which handles a whole article/span - tens
    /// of nanoseconds against a pwrite of tens to hundreds of KB.
    file: std::sync::RwLock<Option<File>>,
    pub path: PathBuf,
    /// Set when the on-disk file is RENAMED under a live writer (PAR2
    /// deobfuscation publishes the verified real name while the handle
    /// is open). The open handle does not care - renames are inode-level
    /// - but [`FileWriter::unpark`] reopens BY PATH, and the creation
    /// path is ENOENT the moment the publish lands. Every by-path reopen
    /// must go through [`FileWriter::current_path`].
    renamed_to: std::sync::Mutex<Option<PathBuf>>,
    pub size: u64,
    written: AtomicU64,
    /// UNIQUE bytes covered (the sum of `note_written`'s fresh counts),
    /// distinct from `written`, which counts every physical write.
    /// The pacer's once-only completion flush keys off THIS: duplicate
    /// article spans and repair rewrites inflate `written` past `size`
    /// while real gaps remain, and parking the watermark on aggregate
    /// traffic would leave the genuine tail unpaced - the exact burst
    /// the pacer exists to prevent.
    covered: AtomicU64,
    /// Job-wide extracted-byte budget (see [`WriteBudget`]); None = the
    /// writer is not an extraction output and is not charged.
    budget: Option<std::sync::Arc<WriteBudget>>,
    /// What this writer has charged to `budget` so far, so
    /// [`FileWriter::abandon`] can release exactly that much when the
    /// file is unlinked. Distinct from `covered`, which counts spans
    /// published without a charge too (`note_repaired`).
    charged: AtomicU64,
    /// A range was written TWICE with DIFFERENT bytes by two article
    /// deliveries (see [`FileWriter::write_article_at`]). Distinct from
    /// [`FileWriter::had_rewrite`], which counts any overlap at all: a
    /// same-article hedge or tail duplicate rewrites a range with the
    /// bytes already there and is harmless, so it leaves this false.
    /// Only a post that CONTRADICTS ITSELF sets it. Holds the FIRST such
    /// range as `(offset, len)`, so the refusal can name the bytes rather
    /// than just assert that some disagreed.
    conflict: std::sync::Mutex<Option<(u64, u64)>>,
    /// Makes an article write's coverage peek atomic with its own pwrite -
    /// see [`FileWriter::write_article_at`]. Without it two decode threads
    /// delivering the two halves of an overlapping pair both peek an empty
    /// map (coverage is published by `note_written` AFTER the pwrite) and
    /// neither sees the other: measured 30 Aug 2026 as a 5-in-12 flake on
    /// the M4-14a fixture before this existed.
    ///
    /// SHARDED by file offset rather than one gate per file, so ordinary
    /// out-of-order arrival keeps its parallelism - the Windows write-lane
    /// pool exists precisely to write one file from several threads, and a
    /// whole-file mutex would undo it. Two spans that OVERLAP share at
    /// least one byte and therefore at least one grain, which is all the
    /// exclusion this needs; aliasing distinct grains onto one mutex only
    /// ever over-serializes, never under. The `intervals` mutex cannot
    /// play this role: `covered`/`contiguous_from_start` take it to answer
    /// the streaming server, and holding it across a pwrite would stall
    /// /stream on every write.
    article_gate: std::sync::Mutex<ArticleGate>,
    article_cv: std::sync::Condvar,
    /// Written spans, sorted + merged - lets the streaming server ask
    /// "are bytes [off, off+len) really on disk yet?". Out-of-order
    /// arrival keeps this list tiny (≈ number of gaps, not writes).
    intervals: std::sync::Mutex<Vec<(u64, u64)>>,
    /// Next `written` watermark at which the per-stride write hook
    /// fires. macOS: maybe_pace_writeback. Linux: maybe_drop_cache
    /// when drop-behind is on (CLI get), else maybe_pace_writeback
    /// (the daemon) - the pacer stands down while drop-behind is
    /// active precisely so this one watermark has one consumer.
    /// Dead on Windows.
    // Not #[expect]: read on macOS and Linux, so the expectation would be
    // unfulfilled on both; the waiver is Windows's alone.
    #[allow(dead_code)]
    drop_next: AtomicU64,
    /// Windows write lanes (line-rate campaign): std's `seek_write`
    /// issues a synchronous WriteFile, and the kernel serializes
    /// synchronous I/O per FILE OBJECT - so N decode workers writing
    /// through one handle queue on its lock. Extra handles on the same
    /// path are distinct file objects with distinct locks; `write_at`
    /// spreads across them round-robin. The system cache is per FILE,
    /// not per handle, so reads through the primary handle and `park`'s
    /// sync still see and cover every lane's bytes. Emptied on park,
    /// refilled on unpark. NOTE: measured a non-fix on Windows (see
    /// `WIN_WRITER_LANES_DEFAULT`) - the pool is empty by default and
    /// only `NZBFAST_WIN_WRITERS` fills it.
    #[cfg(windows)]
    aux: std::sync::RwLock<Vec<File>>,
    /// Round-robin cursor over `aux` + the primary handle.
    #[cfg(windows)]
    next_lane: AtomicU64,
    /// Live-reader / external-repair custody of this file's inode - see
    /// [`ReadCustody`].
    custody: Arc<ReadCustody>,
    /// The extractor has DISOWNED this output - see [`abandon`].
    ///
    /// [`abandon`]: FileWriter::abandon
    abandoned: AtomicBool,
    /// Rolling checksum of the file's contiguous prefix - `None` unless
    /// armed with [`FileWriter::with_prefix_hash`]. See [`PrefixHash`].
    prefix: Option<std::sync::Mutex<PrefixHash>>,
    /// The open write-coalescing run - see [`stage`] for what a staged
    /// byte is and is not. `None` when coalescing is off for this writer,
    /// which is the whole of the old behaviour: every article takes its
    /// own `pwrite` and nothing below this field runs.
    ///
    /// It coexists with [`PrefixHash`], which was not obvious and is
    /// worth stating. That hash advances only on a write landing exactly
    /// at its hashed end, FREEZES on one landing ahead and is POISONED
    /// by one landing below, so it depends on the ORDER writes are
    /// observed in - and two threads can flush two disjoint runs of one
    /// file in either order. Neither outcome is a correctness loss: a
    /// freeze records a SHORTER checksummed prefix and a poison records
    /// nothing, and both are what the resume ledger already does with an
    /// out-of-order arrival. Nor is either newly reachable - a run is
    /// exactly the union of the article spans staged into it, so a run
    /// lands below the hashed end only where one of those articles
    /// would have. The writers that actually advance the hash are the
    /// chase's member sinks, which decode SEQUENTIALLY on one thread, so
    /// their runs go out in the order that thread made them.
    stage: Option<std::sync::Mutex<stage::WriteStage>>,
    /// Serializes this file's RUN WRITES, and nothing else.
    ///
    /// The staging mutex above is held for a memcpy and released before
    /// the `pwrite`, so two decoders can take two disjoint runs out and
    /// race to write them. That is fine for the bytes - the runs are
    /// disjoint by construction - but it leaves an interval in which a
    /// taken run is on neither side, and an observer must be able to
    /// WAIT for it rather than merely notice it. Taking this lock is
    /// that wait.
    ///
    /// Lock order is `stage` then `flush`, never both held at once on
    /// the staging path: `write_article_at` releases the staging mutex
    /// BEFORE it calls `flush_runs`. The flush path takes `flush` and
    /// then `stage`, which is the only place the two are held together
    /// and is therefore not a cycle.
    flush_lock: std::sync::Mutex<()>,
    /// Bytes in the open run, so every "is anything staged?" test on a
    /// path that is not staging is a relaxed load rather than a mutex.
    staged: AtomicU64,
    /// Articles currently INSIDE [`FileWriter::write_article_at`] for
    /// this file, and the reason the window does not weaken anything's
    /// postcondition.
    ///
    /// `Extractor::write` is a synchronous door: its callers read the
    /// output BY PATH straight afterwards and expect the bytes (three
    /// tests under `extract/` do exactly that, and they are right to).
    /// Holding bytes past the last article in flight would break that,
    /// so the window holds them only while the file is BUSY - when this
    /// counter falls back to zero the run goes out at once. A download
    /// keeps sixteen articles in flight per file and hits zero only in a
    /// lull; a caller delivering one article and reading it back hits
    /// zero immediately and sees its bytes, exactly as before.
    ///
    /// It also bounds how long a byte can be invisible without any timer:
    /// a file that stops receiving articles has already been flushed,
    /// which is what keeps a live reader's frontier and the journal's
    /// placement records honest.
    articles_in_flight: AtomicU64,
    /// THE FEEDING SIGNAL (round 44): the job-level fact that this file
    /// is being fed by a download whose end is a POINT SOMEBODY KNOWS,
    /// rather than something this writer has to infer.
    ///
    /// `articles_in_flight` above is an inference, and round 41 measured
    /// exactly what it costs: a fast decoder drives that counter to zero
    /// BETWEEN arrivals, so a busy file looks idle several times a
    /// millisecond and the run goes out for nothing. On round 23's
    /// ladder that inference is the whole gap between -75/-81% of
    /// positioned writes and -13/-39%.
    ///
    /// This flag is the fact instead. It is raised by the engine, which
    /// is the one thing in the system that knows both halves of the
    /// promise: that articles are still coming, and that NOTHING will
    /// open an output by name until it says so - it calls
    /// [`FileWriter::flush_staged`] over every writer the moment the
    /// decode threads join, ahead of settle's read-back, the native
    /// repair's PAR2 scan, the unpack step and the journal's last batch.
    /// A caller that has NOT raised it (every test, every library user,
    /// the three `extract/` tests that write one article and
    /// `std::fs::read` the output by path) keeps the old rule unchanged:
    /// the article that leaves an idle file behind it writes the run.
    ///
    /// Shared, not copied: one `Arc` per job, cloned into every writer
    /// the extractor makes, so a writer created for a member discovered
    /// half way through the download inherits the signal without anyone
    /// walking the writer table to tell it.
    ///
    /// It does NOT let a byte sit in RAM indefinitely. Three separate
    /// rules bound that independently of it: the run cap, the completion
    /// rule below (`covered + staged >= size` writes the tail of a file
    /// whose last article has arrived), and `stage::max_age`, which is
    /// the journal's own `BATCH_AGE`.
    feeding: Arc<AtomicBool>,
    /// This writer's window bounds, resolved once - see [`stage::Caps`].
    caps: stage::Caps,
    /// Positioned writes issued through THIS writer.
    ///
    /// [`writes_issued`] is the process-wide figure and is the one a
    /// benchmark reads; this one exists because a test cannot. Every
    /// `cargo test --lib` target runs its whole crate in ONE process
    /// (CLAUDE.md's one-process oracle), so a test asserting on a
    /// process-global counter is measuring every other test's writes
    /// too - which is exactly how these two failed there while passing
    /// under nextest, where each test owns a process.
    writes: AtomicU64,
}

/// Rolling CRC32 of a writer's contiguous prefix, the quantity TODO 217
/// records beside the resume ledger's mark so a disk pass can PROVE the
/// kept bytes match what a from-zero extract would have written.
///
/// It advances only on a write landing exactly at the current hashed
/// end, which for the chase's member sinks is every write (the sink
/// decodes sequentially). Anything else degrades it, in one of two
/// distinct ways:
///
/// - a write LANDING AHEAD of the hashed end freezes it: the bytes in
///   the gap were never seen in order, so the hash stops and the
///   recorded mark is the CHECKSUMMED length - which can be shorter
///   than `contiguous_from_start`, and shipping the larger of the two
///   is precisely the bug §217's hard-parts list warns about;
/// - a write LANDING BELOW the hashed end poisons it outright: bytes
///   already folded into the hash were rewritten, so the value
///   describes nothing on disk any more and no mark may be recorded.
struct PrefixHash {
    hasher: crc32fast::Hasher,
    /// Bytes hashed so far - the checksummed contiguous prefix.
    len: u64,
    /// A write landed past the hashed end; the hash can never advance
    /// again but still describes `[0, len)`.
    frozen: bool,
    /// A write landed inside the hashed prefix (or an external tool took
    /// the file): the hash describes nothing. Terminal.
    poisoned: bool,
}

impl PrefixHash {
    fn new() -> PrefixHash {
        PrefixHash {
            hasher: crc32fast::Hasher::new(),
            len: 0,
            frozen: false,
            poisoned: false,
        }
    }

    /// Stop advancing, keeping what is already hashed. The window calls
    /// this before writing a run that was JOINED across a hole - see
    /// [`stage::StagedRun::merged`].
    fn freeze(&mut self) {
        self.frozen = true;
    }

    fn observe(&mut self, offset: u64, data: &[u8]) {
        if self.poisoned || data.is_empty() {
            return;
        }
        if offset < self.len {
            self.poisoned = true;
            return;
        }
        if self.frozen {
            return;
        }
        if offset == self.len {
            self.hasher.update(data);
            self.len += data.len() as u64;
        } else {
            self.frozen = true;
        }
    }
}

/// Reserve `size` bytes for `file`, really allocating blocks where the
/// platform lets us.
///
/// `set_len` alone punches a hole - a sparse file whose blocks are
/// allocated lazily at write time. On a near-full or rotational ext4/XFS
/// volume that lazy allocation interleaves blocks from the many files a
/// job writes concurrently, fragmenting all of them. Linux therefore also
/// calls the raw `fallocate(2)` syscall to reserve contiguous extents up
/// front. Raw fallocate, NOT `posix_fallocate`: glibc emulates the latter
/// on EOPNOTSUPP filesystems (FUSE/mergerfs, exFAT, NFS < 4.2) by writing
/// one byte per block over the whole range - a synchronous full-file
/// write pass for a multi-GB output, and it destroys sparseness. Raw
/// fallocate returns EOPNOTSUPP honestly and we ignore it - preallocation
/// is an optimisation, never a correctness requirement.
///
/// `set_len` runs first and unconditionally: it is what truncates a stale
/// longer file at the same path down to exactly `size` (fallocate never
/// shrinks), so create_resume keeps identical semantics on every platform
/// and filesystem. macOS keeps plain `set_len` on purpose: APFS is
/// copy-on-write and SSD-only in practice, so extent contiguity buys
/// nothing and F_PREALLOCATE is not worth the fcntl dance. Windows
/// likewise unchanged.
/// `cap` bounds how much is actually RESERVED (u64::MAX = no ceiling).
///
/// The declared `size` of an extracted inner file comes from a RAR header
/// vint the poster controls. `set_len` plus a real Linux `fallocate` means
/// a few-hundred-KB post declaring `unpacked_size` = 8 TB genuinely
/// reserves the victim's free space for the life of the job - the
/// finish-time header/CRC gates demote such a set, but only long after the
/// blocks are gone. `cap` is the defensible bound (the NZB's own posted
/// byte count at level 0), applied to the RESERVATION only.
///
/// `size` itself is deliberately NOT clamped by the caller: `FileWriter.size`
/// feeds `create_resume`'s stale-file truncation and the reported extracted
/// size, and clamping it corrupts both. Capping the reservation is safe
/// because preallocation is an optimisation, never a correctness
/// requirement (see above) - `write_at` past the preallocated length
/// extends the file normally, exactly as it already does on macOS and
/// Windows where nothing is reserved at all.
///
/// The target is `min(size, max(cap, current_len))`, which
///   * caps a fresh (truncated) file at `cap`,
///   * still trims a stale LONGER file down to `size` (that shrinks, so it
///     reserves nothing), and
///   * never shrinks a resumed file below the bytes it already holds.
fn preallocate_capped(file: &File, size: u64, cap: u64) -> io::Result<()> {
    // Windows line-rate campaign (6 Aug 2026): NTFS tracks a
    // valid-data-length (VDL) per file, and every positioned write past
    // VDL makes the filesystem physically zero-fill [VDL, offset) first.
    // Out-of-order article writes into a set_len file therefore write
    // large zero runs nobody asked for - measured ~1.6x write
    // amplification (disk ~455 MB/s against ~283 MB/s of payload) with
    // the job pinned at a flat 2.1 Gbps plateau. Marking the file SPARSE
    // turns that zero-fill into a hole: unwritten ranges still read as
    // zeros (exactly what `covered_intervals` already promises), but the
    // device only ever sees the bytes we wrote. Measured on the same box
    // (7 Aug loopback A/B, 80 GB mock, 2 reps): amplification 1.53-1.60
    // -> 1.00-1.08, wall 132/173 s -> 79/86 s, per-server write-side
    // blocking 784/1102 s -> 218/289 s.
    //
    // REPRODUCED 3 Sep 2026 on BOTH of that box's drives, by a different
    // rig on a different corpus (audit round 22: 12 x 2 GB stored with a
    // PAR2 index, arms interleaved within each rep off one mock server).
    // With the flag ON the device writes 1.001-1.005x the payload, which
    // is the floor; with `NZBFAST_WIN_SPARSE=0` it writes 1.556-1.571x,
    // and wall goes 19.8-32.0 -> 42.4-48.2 s on C: and 19.8-20.9 ->
    // 30.1-38.6 s on D:. The extra device bytes and the extra KERNEL
    // time are one fact seen twice: ~13.5 GB of zero-fill nobody asked
    // for, and the client's system time 25-29 s -> 57-60 s to write it.
    // The pool's side agrees - write-side blocking 11-45 s summed over
    // 16 connections against 348-1,120 s. Nothing in the shipped
    // configuration is left to win here. The alternative,
    // SetFileValidData, is rejected: it needs SE_MANAGE_VOLUME_NAME
    // (Administrators only - a normal user install cannot hold it), it
    // is documented not to work on sparse files, and it exposes whatever
    // stale disk contents sit under the file until we overwrite them.
    // Must run BEFORE set_len so the preallocation itself never zeroes.
    #[cfg(windows)]
    if win_sparse_enabled() {
        mark_sparse(file);
    }
    let target = if cap == u64::MAX {
        size
    } else {
        let cur = file.metadata().map(|m| m.len()).unwrap_or(0);
        size.min(cap.max(cur))
    };
    file.set_len(target)?;
    #[cfg(target_os = "linux")]
    if target > 0 {
        use std::os::unix::io::AsRawFd;
        // Best-effort: mode 0 allocates real blocks for [0, target). Any
        // failure (EOPNOTSUPP, EINVAL, ENOSPC racing) leaves the sparse
        // file from set_len above, which is always correct.
        // SAFETY: fallocate takes only integer arguments; the raw fd comes
        // from `file`, whose borrow keeps it open across the call.
        unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, target as libc::off_t) };
    }
    Ok(())
}

/// Preallocate an EXTRACTED output before its sequential writes: the
/// same per-platform reservation the article writer uses (raw fallocate
/// on Linux, set_len elsewhere, the NTFS valid-data-length trick on
/// Windows), with `cap` bounding what is actually reserved - the size
/// comes from an archive header the poster controls, so callers pass
/// the free space they are prepared to commit. A Copy-method 7z member
/// on ext4 spent 2.0-2.6 s of system time per GiB growing the file one
/// write at a time (7-Zip 1.0 s for the same bytes) before this
/// (research/RAR-PERF-AUDIT-2026-09-02.md, round 9).
pub fn preallocate_output(file: &File, size: u64, cap: u64) -> io::Result<()> {
    preallocate_capped(file, size, cap)
}

impl FileWriter {
    /// Create (truncating any existing file) and preallocate to `size` -
    /// really allocated on Linux, sparse elsewhere (see `preallocate_capped`).
    pub fn create(path: &Path, size: u64) -> io::Result<FileWriter> {
        Self::create_capped(path, size, u64::MAX)
    }

    /// [`FileWriter::create`] with a ceiling on the RESERVATION only (see
    /// [`preallocate_capped`]). `size` is stored unchanged.
    pub fn create_capped(path: &Path, size: u64, prealloc_cap: u64) -> io::Result<FileWriter> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // The no-follow, descriptor-bound open (see
        // `relpath::open_out_leaf`): the parent this write lands in is
        // the one that was checked, and neither it nor the leaf may be
        // an alias. A plain `OpenOptions::open` here followed a symlink
        // planted at the payload's own name and truncated an outside
        // inode (X5-06, 30 Aug 2026).
        let file = relpath::open_out_leaf(path, relpath::LeafOpen::Truncate)?;
        Self::around(file, path.to_path_buf(), size, prealloc_cap)
    }

    /// Open WITHOUT truncating (crash-resume: earlier runs' bytes are
    /// already at their final offsets) and ensure the file spans `size`.
    pub fn create_resume(path: &Path, size: u64) -> io::Result<FileWriter> {
        Self::create_resume_capped(path, size, u64::MAX)
    }

    /// [`FileWriter::create_resume`] with a ceiling on the RESERVATION
    /// only. The cap never shrinks a resumed file below the bytes it
    /// already holds - see [`preallocate_capped`].
    pub fn create_resume_capped(
        path: &Path,
        size: u64,
        prealloc_cap: u64,
    ) -> io::Result<FileWriter> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // `LeafOpen::Keep` never truncates: this is the RESUME open,
        // and the bytes already on disk are the point - a truncate here
        // silently restarts the download it was called to continue.
        // Same no-follow, descriptor-bound rule as the fresh open above;
        // the resume arm followed a planted leaf alias too, and resized
        // an outside inode through `preallocate_capped` (X5-06).
        let file = relpath::open_out_leaf(path, relpath::LeafOpen::Keep)?;
        Self::around(file, path.to_path_buf(), size, prealloc_cap)
    }

    /// [`FileWriter::create_capped`] ANCHORED ON THE JOB'S OUTPUT ROOT:
    /// the directories `out_name` needs are made and the payload is
    /// opened inside the last of them, with no component below `root`
    /// ever re-resolved between the check and the write.
    ///
    /// This is the shape every write site under a known root should
    /// take. The path-taking constructors above can bind no more than
    /// the leaf and its immediate parent, so `out/a/b/leaf.bin` with
    /// `a` swapped for a symlink after the directories were made is
    /// still followed by them - the residue X5-06/08/19 left open, and
    /// exactly the shape of a BDMV tree (`BDMV/STREAM/00001.m2ts`). See
    /// `relpath::open_out_leaf_under`.
    pub fn create_under(
        root: &Path,
        out_name: &str,
        size: u64,
        prealloc_cap: u64,
    ) -> io::Result<FileWriter> {
        let file = relpath::open_out_leaf_under(root, out_name, relpath::LeafOpen::Truncate)?;
        Self::around(
            file,
            relpath::join_out_name(root, out_name),
            size,
            prealloc_cap,
        )
    }

    /// [`FileWriter::create_resume_capped`] anchored on the output root,
    /// the same way [`FileWriter::create_under`] is - and never
    /// truncating, for the reason that constructor gives.
    pub fn create_resume_under(
        root: &Path,
        out_name: &str,
        size: u64,
        prealloc_cap: u64,
    ) -> io::Result<FileWriter> {
        let file = relpath::open_out_leaf_under(root, out_name, relpath::LeafOpen::Keep)?;
        Self::around(
            file,
            relpath::join_out_name(root, out_name),
            size,
            prealloc_cap,
        )
    }

    /// Everything the four constructors above do once the payload is
    /// OPEN: the cache policy, the reservation, and the writer around
    /// them. Spelled once so a field added to `FileWriter` cannot be
    /// added to three of four openings - the state this replaced, where
    /// two copies of a 24-line literal sat one screen apart.
    fn around(file: File, path: PathBuf, size: u64, prealloc_cap: u64) -> io::Result<FileWriter> {
        apply_cache_policy(&file);
        preallocate_capped(&file, size, prealloc_cap)?;
        // From the handle the open above bound, and BEFORE the struct
        // literal takes ownership of it - see `open_aux_handles`.
        #[cfg(windows)]
        let aux = std::sync::RwLock::new(open_aux_handles(&file));
        Ok(FileWriter {
            file: std::sync::RwLock::new(Some(file)),
            path,
            renamed_to: std::sync::Mutex::new(None),
            size,
            written: AtomicU64::new(0),
            covered: AtomicU64::new(0),
            budget: None,
            charged: AtomicU64::new(0),
            conflict: std::sync::Mutex::new(None),
            article_gate: std::sync::Mutex::new(ArticleGate {
                inflight: Vec::new(),
            }),
            article_cv: std::sync::Condvar::new(),
            intervals: std::sync::Mutex::new(Vec::new()),
            drop_next: AtomicU64::new(16 << 20),
            #[cfg(windows)]
            aux,
            #[cfg(windows)]
            next_lane: AtomicU64::new(0),
            custody: Arc::new(ReadCustody {
                st: std::sync::Mutex::new(CustodyState::default()),
                cv: std::sync::Condvar::new(),
            }),
            abandoned: AtomicBool::new(false),
            prefix: None,
            stage: stage::Caps::from_env()
                .on()
                .then(|| std::sync::Mutex::new(stage::WriteStage::default())),
            caps: stage::Caps::for_file(size),
            writes: AtomicU64::new(0),
            flush_lock: std::sync::Mutex::new(()),
            articles_in_flight: AtomicU64::new(0),
            feeding: Arc::new(AtomicBool::new(false)),
            staged: AtomicU64::new(0),
        })
    }

    /// Attach the job-wide extracted-byte budget (see [`WriteBudget`]).
    /// Builder-style so the extraction paths can opt in at construction;
    /// writers without one are never charged.
    pub fn with_budget(mut self, budget: std::sync::Arc<WriteBudget>) -> FileWriter {
        self.budget = Some(budget);
        self
    }

    /// Attach the job's FEEDING SIGNAL - see the `feeding` field, which
    /// carries the whole of why this exists. Builder-style like
    /// [`FileWriter::with_budget`], and the caller keeps the `Arc`: it
    /// lowers the flag once, for every writer of the job at once, at the
    /// single point where "the download is over" is a fact.
    ///
    /// A writer without one is a writer nobody promised anything about,
    /// and it behaves exactly as it did before round 44.
    pub fn with_feeding(mut self, feeding: Arc<AtomicBool>) -> FileWriter {
        self.feeding = feeding;
        self
    }

    /// Is the job that owns this writer still delivering articles to it?
    fn is_feeding(&self) -> bool {
        self.feeding.load(Ordering::Relaxed)
    }

    /// Arm the rolling prefix checksum (see [`PrefixHash`]). Builder-style
    /// like [`FileWriter::with_budget`], and armed on the same writers:
    /// the extraction outputs a chase forfeit may hand to the resume
    /// ledger. Never armed on level-0 downloads - the per-byte download
    /// path pays nothing for a ledger it can never appear in.
    pub fn with_prefix_hash(mut self) -> FileWriter {
        self.prefix = Some(std::sync::Mutex::new(PrefixHash::new()));
        self
    }

    /// Positioned writes issued through this writer - see the `writes`
    /// field for why a test may not read the process-wide counter.
    #[cfg(test)]
    pub(crate) fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    /// Bytes this writer's window is holding right now.
    #[cfg(test)]
    pub(crate) fn staged_bytes(&self) -> u64 {
        self.staged.load(Ordering::Relaxed)
    }

    /// Pin one virtual article in flight, so the window behaves as it
    /// does on a BUSY file - see `articles_in_flight`, which is what
    /// makes a single-article delivery flush at once. A test that means
    /// to exercise the window has to say that the file is busy, because
    /// on a quiet one there is deliberately nothing to exercise.
    #[cfg(test)]
    pub(crate) fn hold_busy(&self) -> BusyGuard<'_> {
        self.articles_in_flight.fetch_add(1, Ordering::AcqRel);
        BusyGuard(self)
    }

    /// Turn the coalescing window on or off for this writer whatever the
    /// process default is - the two arms of every staging test, so a
    /// test can assert on both behaviours in one process without
    /// depending on a latched environment variable.
    ///
    /// The window ships ON, at [`stage::COALESCE_CAP_DEFAULT`]. It
    /// shipped OFF until round 44 replaced the quiescence INFERENCE with
    /// the engine's own `feeding` signal; these two comments still said
    /// "ships OFF at 0" afterwards, and on 4 Sep 2026 a review read them
    /// and reported the shipped default as 0 in a section headed clean.
    /// A test still says which arm it means, because the shipped window
    /// arms itself only on a file proved to be fed fast enough and no
    /// test's handful of small articles is.
    #[cfg(test)]
    pub(crate) fn coalescing(mut self, on: bool) -> FileWriter {
        // The same 4 MiB the process default uses - see
        // `stage::COALESCE_CAP_DEFAULT`; zero is this crate's spelling
        // of "no window".
        self.caps = stage::Caps::sized(if on { 4 << 20 } else { 0 });
        self.stage = on.then(|| {
            // ARMED, because that is what "coalescing on" MEANS to a
            // test - see `stage::WriteStage::arm_for_test`. The shipped
            // window arms itself only once a file has proved it is fed
            // fast enough for a run to fill, which no test's handful of
            // small articles ever is.
            let mut st = stage::WriteStage::default();
            st.arm_for_test();
            std::sync::Mutex::new(st)
        });
        self
    }

    /// Shorten this writer's run-age bound - see
    /// [`stage::STAGE_MAX_AGE_DEFAULT`]. The shipped bound is the
    /// journal's `BATCH_AGE`, and a test that means to observe it
    /// expiring cannot wait 100 ms per assertion in a suite this size.
    #[cfg(test)]
    pub(crate) fn staging_age(mut self, age: std::time::Duration) -> FileWriter {
        self.caps.age = age;
        self
    }

    /// Attach a fresh feeding signal already RAISED - the two-line form
    /// of what the engine does across a whole job, for a test that means
    /// to exercise the window as a download drives it. The returned
    /// handle is how the test lowers it again.
    #[cfg(test)]
    pub(crate) fn fed(mut self) -> (FileWriter, Arc<AtomicBool>) {
        let sig = Arc::new(AtomicBool::new(true));
        self.feeding = sig.clone();
        (self, sig)
    }

    /// The checksummed contiguous prefix: its length and its CRC32.
    ///
    /// `None` when the hash was never armed or has been poisoned - a
    /// caller about to record a resume mark must then record nothing,
    /// because nothing about the file can be proven later. The length is
    /// at most [`FileWriter::contiguous_from_start`], and the resume
    /// ledger records THIS length, never the larger one: bytes past the
    /// hashed end may be contiguous on disk, but no later pass could
    /// tell them from a stale copy.
    pub fn prefix_hash(&self) -> Option<(u64, u32)> {
        self.prefix.as_ref()?;
        // A DOOR, like every other door on this writer (round 44). This
        // one does not read the file's BYTES, it reads a property OF
        // them - "the first N bytes on disk are provably what a
        // from-zero extract would have written" - and a byte still in a
        // coalescing run is not on disk, so a mark taken over an open
        // window describes a shorter file than the one the caller is
        // about to keep. `flush_stage` writes the open runs in
        // ASCENDING OFFSET order (see `stage::WriteStage::take_all`),
        // which is exactly the order `PrefixHash::observe` can advance
        // over, so the mark this returns covers everything the window
        // was holding rather than stopping at the first hole it left.
        //
        // Round 41 built the window without this and could not see it:
        // with the default at 0 there was never a run to flush. Turning
        // the window on took
        // `e2e_chaseresume::a_forfeited_7z_chase_resumes_its_member_on_disk`
        // red with "the 7z arm wrote no ledger".
        let _ = self.flush_stage();
        let g = self.prefix.as_ref()?.lock_ok();
        if g.poisoned {
            return None;
        }
        Some((g.len, g.hasher.clone().finalize()))
    }

    /// The positioned write every non-article caller takes - the
    /// in-place crypto transform, the repair patch, the chase's member
    /// sink. It is ordered against the coalescing window
    /// ([`stage`]): a direct write that overlaps bytes still staged
    /// would land UNDER them and be overwritten when the run went out,
    /// so the run goes out first.
    pub fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if self.stage_overlaps(offset, offset + data.len() as u64) {
            self.flush_stage()?;
        }
        self.write_at_raw(offset, data)
    }

    /// [`FileWriter::write_at`] with the staging check already made -
    /// the door the window's own flush goes through, so writing a run
    /// out cannot re-enter the flush that produced it.
    fn write_at_raw(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.write_lane(data, offset)?;
        // After the pwrite, so a hashed byte is always a byte on disk;
        // concurrent in-order writers still observe in a disk-consistent
        // order because each span is durable before it is folded in.
        if let Some(ph) = &self.prefix {
            ph.lock_ok().observe(offset, data);
        }
        let fresh = self.note_written(offset, data.len() as u64);
        self.maybe_drop_cache();
        self.maybe_pace_writeback();
        // Decompression-bomb budget (extraction outputs only). The bytes
        // are already on disk when this trips, exactly like the disk-path
        // `BombGuardWriter` - the point is to stop the NEXT gigabyte, and
        // the error aborts the job the same way a genuine ENOSPC does.
        if let Some(b) = &self.budget {
            // Tallied BEFORE the verdict: a write that trips the guard is
            // on disk and charged like any other, so a demote that then
            // unlinks this file must get those bytes back too.
            self.charged.fetch_add(fresh, Ordering::Relaxed);
            b.charge(fresh)?;
        }
        Ok(())
    }

    /// [`FileWriter::write_at`] for bytes delivered by ONE ARTICLE of the
    /// post, which is the only caller that can tell a duplicate from a
    /// contradiction.
    ///
    /// In a well-formed post every article owns a disjoint byte range, so
    /// this peeks the coverage map and, in the overwhelming majority of
    /// writes, finds nothing and falls straight through to `write_at`
    /// unchanged - one uncontended shard lock, which the grain being
    /// wider than an article keeps cheap.
    ///
    /// The peek MUST be ordered against any OVERLAPPING span's pwrite,
    /// which is what `article_gate` buys: coverage is published by
    /// `note_written` AFTER the pwrite, so two threads delivering the two
    /// halves of an overlapping pair would otherwise both peek an empty
    /// map and neither would see the other. A span is registered in
    /// flight under the gate before its peek and struck after its pwrite
    /// has published; a later span that overlaps one in flight waits for
    /// it to finish. Spans that do not overlap - every ordinary pair of
    /// neighbours - peek, write and publish fully in parallel, with no
    /// lock held across the pwrite.
    ///
    /// When the range HAS been written before, the sub-ranges that
    /// overlap are read back and compared against the matching slices of
    /// `data`:
    ///
    /// * equal - a same-article hedge or tail duplicate re-delivering
    ///   bytes already on disk. Silent, and the write still happens, so
    ///   nothing about the existing behaviour moves.
    /// * different - two articles of one file claim the same range and
    ///   DISAGREE (overlapping `=ypart` ranges, or a rogue duplicate
    ///   segment). [`FileWriter::had_conflicting_rewrite`] latches, and
    ///   the write still happens: settle is what decides the job's fate,
    ///   and refusing the pwrite here would only make WHICH bytes land
    ///   depend on arrival order all over again.
    ///
    /// NOT a check that belongs inside `write_at` itself. Two of that
    /// method's callers legitimately rewrite a range with different
    /// bytes - `extract::crypto` writes plaintext over the ciphertext it
    /// just decrypted (an in-place transform), and the repair path
    /// patches rebuilt blocks over the damaged ones - so a check there
    /// would fire on every encrypted or repaired download. The
    /// distinction is the CALLER's to make, which is why this is a
    /// second door rather than a flag.
    ///
    /// A read-back failure is not the caller's error to report: it means
    /// the compare could not be made, so the conflict is latched (the
    /// honest answer - "this range may disagree") and the write proceeds.
    /// COALESCING (round 41). With the window on, this article's bytes
    /// may be COPIED into the file's open run instead of taking a
    /// `pwrite` of their own, and the run is written as one call when it
    /// can no longer be extended - see [`stage`] for the bound and for
    /// the rule that a staged byte is never published as covered.
    ///
    /// The gate is what makes that safe rather than merely faster. An
    /// article whose bytes are staged KEEPS its in-flight entry until
    /// the run is written, so a later article overlapping it still
    /// collides with something; the collision is resolved by writing the
    /// run out and looking again, which restores exactly the state the
    /// peek assumed before any of this existed.
    pub fn write_article_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let Some(stage) = &self.stage else {
            return self.write_article_direct(offset, data);
        };
        if data.is_empty() {
            return Ok(());
        }
        let end = offset + data.len() as u64;
        let age_bound = self.caps.age;
        self.articles_in_flight.fetch_add(1, Ordering::AcqRel);
        let prior = self.gate_enter(offset, end);
        if !prior.is_empty() {
            self.compare_prior(offset, data, &prior);
        }
        let (run, held) = {
            let mut st = stage.lock_ok();
            // AGE FIRST, so an expired run cannot be extended by the
            // very article that noticed it was expired. See
            // `stage::STAGE_MAX_AGE_DEFAULT`: this is the bound that
            // keeps the journal's "a kill loses at most BATCH_AGE of
            // placements, never corrupting anything" true with the
            // window on, and it is checked here - on arrival at this
            // file - rather than by a timer thread, because a file that
            // stops receiving articles is already covered by the
            // completion rule, by every door, by `flush_staged` and by
            // `Drop`.
            let mut out = if age_bound.is_zero() {
                Vec::new()
            } else {
                st.take_expired(age_bound)
            };
            let (more, held) = st.offer(offset, data, self.caps);
            out.extend(more);
            self.staged.store(st.held(), Ordering::Relaxed);
            (out, held)
        };
        let mut flushed = self.flush_runs(run);
        // COMPLETION. A file whose last article has just arrived is
        // about to be read by name - by settle's read-back, by the
        // native repair's PAR2 scan, by the unpack step - and none of
        // those goes through this writer. `covered` counts only bytes
        // whose `pwrite` has returned, so `covered + staged` reaching
        // the declared size is exactly "this run is the rest of the
        // file". The same rule the pacer's watermark uses
        // (`pace_step`), for the same reason: a per-file window with no
        // completion rule leaves every file's tail behind.
        if self.size > 0
            && self.covered.load(Ordering::Relaxed) + self.staged.load(Ordering::Relaxed)
                >= self.size
        {
            flushed = flushed.and(self.flush_stage());
        }
        if !held {
            // No room in the window: this article takes its own write,
            // exactly as it did before the window existed.
            flushed = flushed.and(self.write_at_raw(offset, data));
            self.gate_leave(offset, end);
        }
        // LAST ONE OUT WRITES - UNLESS THE JOB SAID IT IS STILL FEEDING
        // THIS FILE.
        //
        // Without the signal this is the whole postcondition: the window
        // may hold bytes only while the file is BUSY, so the article
        // that leaves an idle file behind it puts the run on disk and a
        // caller that delivers one article and reads the output by path
        // sees its bytes. That is the rule round 41 shipped, and it is
        // still the rule for every caller that has not raised
        // `feeding` - which is every test, every library user and the
        // three `extract/` tests that hold `Extractor::write` to exactly
        // this.
        //
        // It is also, measured, the reason the window was not worth
        // turning on: a fast decoder empties this counter between
        // arrivals, so "idle" fires several times a millisecond on a
        // file that is anything but. The signal replaces that inference
        // with the engine's own promise - articles are still coming, and
        // nothing opens this file by name until `flush_staged` - and
        // when it is raised the run survives the gap. What still bounds
        // the byte's time in RAM is not this counter: it is the run cap,
        // the completion rule above, `stage::max_age`, and the engine's
        // flush at the join.
        if self.articles_in_flight.fetch_sub(1, Ordering::AcqRel) == 1 && !self.is_feeding() {
            flushed = flushed.and(self.flush_stage());
        }
        flushed
    }

    /// [`FileWriter::write_article_at`] with no coalescing: register,
    /// peek, compare, write, strike. This is the whole of the behaviour
    /// before round 41, and it is still what a writer with the window
    /// off (or with the prefix hash armed) does.
    fn write_article_direct(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let end = offset + data.len() as u64;
        let prior = self.gate_enter(offset, end);
        if !prior.is_empty() {
            self.compare_prior(offset, data, &prior);
        }
        let result = self.write_at_raw(offset, data);
        self.gate_leave(offset, end);
        result
    }

    /// Register `[offset, end)` in flight and peek the coverage it
    /// overlaps, under one hold of the gate - the ordering property
    /// round 5 bought and this method must not lose.
    ///
    /// One thing is new: an overlap may now be a span that is merely
    /// STAGED, whose write will not be issued until something else
    /// happens. Waiting on that is a deadlock dressed as a 30-second
    /// timeout, so the first overlap writes the open run out (which
    /// strikes its entries) and looks again; only a genuinely in-flight
    /// `pwrite` is waited for.
    fn gate_enter(&self, offset: u64, end: u64) -> Vec<(u64, u64)> {
        let mut may_flush = self.stage.is_some();
        let mut gate = self.article_gate.lock_ok();
        // Bounded, like every wait in this workspace: a writer that
        // died with its thread has struck its span on the way out,
        // and a wedged pwrite must never wedge every neighbour
        // behind it - past the deadline the span goes ahead and the
        // coverage peek is what it always was before the gate.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while gate.inflight.iter().any(|&(s, e)| s < end && offset < e) {
            if may_flush {
                may_flush = false;
                drop(gate);
                let _ = self.flush_stage();
                gate = self.article_gate.lock_ok();
                continue;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }
            let (g, _) = self
                .article_cv
                .wait_timeout(gate, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            gate = g;
        }
        gate.inflight.push((offset, end));
        self.covered_intervals_raw(offset, end - offset)
    }

    /// Strike one article's own in-flight entry.
    fn gate_leave(&self, offset: u64, end: u64) {
        {
            let mut gate = self.article_gate.lock_ok();
            if let Some(i) = gate
                .inflight
                .iter()
                .position(|&(s, e)| s == offset && e == end)
            {
                gate.inflight.swap_remove(i);
            }
        }
        self.article_cv.notify_all();
    }

    /// Strike every entry a written RUN covers. A run is the union of
    /// the contiguous article spans that were staged into it, so an
    /// entry lying wholly inside it is one of them by construction.
    fn gate_leave_range(&self, start: u64, end: u64) {
        {
            let mut gate = self.article_gate.lock_ok();
            gate.inflight.retain(|&(s, e)| !(start <= s && e <= end));
        }
        self.article_cv.notify_all();
    }

    /// Does the open run share a byte with `[offset, end)`? A relaxed
    /// load first, so every path that is not staging (the fallback
    /// path's per-article `covered` question, the repair patch, the
    /// crypto transform) pays a load rather than a mutex.
    fn stage_overlaps(&self, offset: u64, end: u64) -> bool {
        let Some(stage) = &self.stage else {
            return false;
        };
        if self.staged.load(Ordering::Relaxed) == 0 {
            return false;
        }
        stage.lock_ok().overlaps(offset, end)
    }

    /// Write the open run out, if there is one. Every door that reads
    /// bytes back or promises durability calls this; it is a relaxed
    /// load when there is nothing staged, which is the whole of the
    /// no-coalescing case.
    pub(crate) fn flush_stage(&self) -> io::Result<()> {
        let Some(stage) = &self.stage else {
            return Ok(());
        };
        if self.staged.load(Ordering::Relaxed) == 0 {
            return Ok(());
        }
        // Held across the take AND the write: an observer that called
        // this because a run overlapped its range must not return while
        // a run taken by somebody else is still on its way to disk.
        let _g = self.flush_lock.lock_ok();
        let runs = {
            let mut st = stage.lock_ok();
            let runs = st.take_all();
            self.staged.store(st.held(), Ordering::Relaxed);
            runs
        };
        let mut r = Ok(());
        for run in runs {
            r = r.and(self.flush_run_locked(run));
        }
        r
    }

    /// Put this writer's open run on disk NOW.
    ///
    /// The window's invariant is that a byte becomes VISIBLE when its
    /// run is written, and every reader inside this module keeps it.
    /// What this door exists for is the readers that are OUTSIDE it -
    /// the settle read-back, the native repair's PAR2 scan and the
    /// unpack step all open the output BY PATH and read the inode, so
    /// nothing downstream of them could flush on their behalf. The
    /// engine calls this over `Extractor::writers_snapshot()` the moment
    /// the decode threads join, which is the one point where "the
    /// download is over" is a fact rather than a guess, and everything
    /// that reads a finished file by name happens after it.
    pub fn flush_staged(&self) -> io::Result<()> {
        self.flush_stage()
    }

    /// Drop the open run WITHOUT writing it - the file is being unlinked
    /// and these bytes have nowhere to go. Only `abandon_close` may do
    /// this; every other close writes the run out.
    fn discard_stage(&self) {
        let Some(stage) = &self.stage else {
            return;
        };
        // Behind the flush lock, so a run another thread took is on disk
        // (harmlessly, into a file about to be unlinked) rather than
        // landing after the descriptor closes.
        let _g = self.flush_lock.lock_ok();
        let mut st = stage.lock_ok();
        for run in st.take_all() {
            let (s, e) = (run.start, run.end());
            drop(run);
            st.landed(s, e);
        }
        self.staged.store(st.held(), Ordering::Relaxed);
    }

    /// One run, one `pwrite`. The gate entries the run carries are
    /// struck whatever the write did: a neighbour must never wait out
    /// the 30-second deadline behind a write that has already failed.
    /// Write out runs the staging path displaced, in the order it
    /// displaced them.
    fn flush_runs(&self, runs: Vec<stage::StagedRun>) -> io::Result<()> {
        if runs.is_empty() {
            return Ok(());
        }
        let _g = self.flush_lock.lock_ok();
        let mut r = Ok(());
        for run in runs {
            r = r.and(self.flush_run_locked(run));
        }
        r
    }

    /// [`FileWriter::flush_runs`] for one run, with the flush lock
    /// already held.
    fn flush_run_locked(&self, run: stage::StagedRun) -> io::Result<()> {
        let (start, end) = (run.start, run.end());
        // A run joined across a hole is contiguous on disk but did not
        // ARRIVE in order, so it must not extend the resume mark - see
        // [`stage::StagedRun::merged`].
        if run.merged
            && let Some(ph) = &self.prefix
        {
            ph.lock_ok().freeze();
        }
        let r = self.write_at_raw(start, &run.buf);
        // Retired whatever the write did - a failed run's bytes are not
        // coming, and leaving the span in flight would make every later
        // observer of that range wait for a write nobody will issue.
        if let Some(stage) = &self.stage {
            let mut st = stage.lock_ok();
            st.landed(start, end);
            self.staged.store(st.held(), Ordering::Relaxed);
        }
        self.gate_leave_range(start, end);
        r
    }

    /// Read back the already-written sub-ranges of an article write and
    /// latch [`FileWriter::conflict`] if any of them disagrees with the
    /// bytes about to be written over them. Split out of
    /// [`FileWriter::write_article_at`] so the common no-overlap path is
    /// one `covered_intervals` call and a branch.
    fn compare_prior(&self, offset: u64, data: &[u8], prior: &[(u64, u64)]) {
        let mut buf = Vec::new();
        for &(s, e) in prior {
            let n = (e - s) as usize;
            buf.clear();
            buf.resize(n, 0);
            let at = (s - offset) as usize;
            match self.read_at(&mut buf, s) {
                Ok(()) if buf[..] == data[at..at + n] => {}
                _ => {
                    // First writer wins the record; a second thread
                    // finding its own conflict does not overwrite the
                    // range already named.
                    self.conflict.lock_ok().get_or_insert((s, e - s));
                    return;
                }
            }
        }
    }

    /// True when two ARTICLE deliveries wrote the same range with
    /// DIFFERENT bytes - see [`FileWriter::write_article_at`]. A post
    /// that contradicts itself and has no recovery set to adjudicate it
    /// cannot be delivered honestly: whichever copy survives is decided
    /// by arrival order, so settle fails the job rather than shipping one
    /// of two different files at rc=0.
    pub fn had_conflicting_rewrite(&self) -> bool {
        self.conflict.lock_ok().is_some()
    }

    /// The first range two disagreeing article deliveries both claimed,
    /// as `(offset, len)` - see [`FileWriter::had_conflicting_rewrite`].
    pub fn conflicting_rewrite_span(&self) -> Option<(u64, u64)> {
        *self.conflict.lock_ok()
    }

    /// The positioned write behind [`FileWriter::write_at`], routed
    /// through one of the Windows write lanes when the pool has any
    /// (see the `aux` field). Everywhere else it is exactly the old
    /// single-handle write.
    #[cfg(windows)]
    fn write_lane(&self, data: &[u8], offset: u64) -> io::Result<()> {
        {
            let aux = self.aux.read_ok();
            if !aux.is_empty() {
                // Lanes are aux[0..n] plus the primary handle as lane n,
                // so the primary keeps carrying its share of the load.
                let lane =
                    (self.next_lane.fetch_add(1, Ordering::Relaxed) as usize) % (aux.len() + 1);
                if lane < aux.len() {
                    return write_all_at(&aux[lane], data, offset);
                }
            }
        }
        // Parked writers have an empty pool, so the parked error still
        // comes from handle() exactly as before.
        write_all_at(self.handle()?.as_ref().unwrap(), data, offset)
    }

    #[cfg(not(windows))]
    fn write_lane(&self, data: &[u8], offset: u64) -> io::Result<()> {
        write_all_at(self.handle()?.as_ref().unwrap(), data, offset)
    }

    /// M32 perf (loopback-rig measured): under a small memory cgroup
    /// (1 GB NAS/docker), streaming writes cost ~17% of a core in
    /// page-cache reclaim (evict_folios/memcg walks). When enabled,
    /// every ~16 MB written per file we kick off async writeback and
    /// drop the file's clean pages, so eviction is a driveby instead
    /// of reclaim-scan work. Linux-only. Enablement: the CLI `get`
    /// path turns it on (no /stream readers can exist there; verify
    /// settle read-back of the few Pending blocks comes from disk -
    /// measured negligible, revisit on spinning rust); the daemon
    /// leaves it off (a stream reader can attach mid-job).
    /// NZBFAST_DROP_CACHE=1/0 force-overrides for benching.
    #[cfg(target_os = "linux")]
    fn maybe_drop_cache(&self) {
        if !drop_cache_enabled() {
            return;
        }
        const STRIDE: u64 = 16 << 20;
        // Same state machine as the pacer, including the once-only
        // completion action: without it a file smaller than the first
        // 16 MB watermark never got a single writeback+evict, and every
        // file kept a sub-stride tail - on the 1 GB-cgroup boxes this
        // hook exists for, a many-small-file job left its whole page
        // cache turnover to memcg reclaim, the exact cost drop-behind
        // was measured to remove (M32).
        let w = self.written.load(Ordering::Relaxed);
        let c = self.covered.load(Ordering::Relaxed);
        let due = self.drop_next.load(Ordering::Relaxed);
        let Some(next) = pace_step(w, c, due, self.size, STRIDE) else {
            return;
        };
        if self
            .drop_next
            .compare_exchange(due, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        use std::os::unix::io::AsRawFd;
        // Parked: the handle is gone and its pages were synced on the way
        // down, so there is nothing to write back or evict.
        let g = self.file.read_ok();
        let Some(fd) = g.as_ref().map(|f| f.as_raw_fd()) else {
            return;
        };
        // SAFETY: both calls take only the raw fd plus integer arguments;
        // the read guard `g` keeps the File open across them, so `fd`
        // stays valid.
        unsafe {
            // Start writeback for everything dirty, then drop what's
            // clean. Repeated calls sweep up what writeback finished.
            libc::sync_file_range(fd, 0, 0, libc::SYNC_FILE_RANGE_WRITE);
            libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED);
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn maybe_drop_cache(&self) {}

    /// Line-rate campaign (6 Aug 2026): the sawtooth that keeps a
    /// download from HOLDING line rate is write-side burstiness. At
    /// 10 Gbps the decoded stream dirties page cache faster than macOS
    /// writes it back; every ~8 GB the kernel dumps the backlog in one
    /// multi-GB/s burst (2941-5890 MB/s measured while the wire
    /// stalled), our writers block behind it, the fetch->decode channel
    /// fills, and the pool parks for seconds. Pacing the writeback
    /// ourselves - an fsync every stride of NEW bytes per file - keeps
    /// the dirty set bounded at about one stride, so the flush the OS
    /// would have saved up happens as frequent small pauses the channel
    /// absorbs instead of one rare dump the wire cannot hide.
    ///
    /// Plain `libc::fsync`, deliberately NOT `File::sync_data`: on
    /// Apple platforms std promotes sync_data to a device-barrier
    /// fcntl, and a barrier per stride would tax the drive for a
    /// durability promise this path does not need (fsync moves the
    /// dirty pages to the device, which is the whole point here).
    ///
    /// `NZBFAST_WRITE_PACE_MB` sets the stride in MB; 0 disables; unset
    /// = the measured 32 MB default (see `write_pace_stride`).
    ///
    /// Linux compiles the same hook but defaults OFF (see
    /// `write_pace_stride` for the 7 Aug measurement): the daemon has
    /// no drop-behind (a /stream reader can attach and DONTNEED would
    /// evict pages it wants), yet balance_dirty_pages already throttles
    /// writers gradually and no pacing arm beat no-pacing on the rig.
    /// The hook exists so a real-NAS leg can flip it on the shipped
    /// binary: NZBFAST_WRITE_PACE_MB sets the stride, NZBFAST_PACE_MODE
    /// picks the flush primitive. It is stream-safe by construction
    /// (nothing here evicts). While drop-behind IS active the pacer
    /// stands down - that path already writes back each stride, and
    /// both hooks share the one `drop_next` watermark. Windows has not
    /// shown the sawtooth (a different, continuous write-path disease -
    /// TODO 126.2).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn maybe_pace_writeback(&self) {
        #[cfg(target_os = "linux")]
        if drop_cache_enabled() {
            return;
        }
        let stride = write_pace_stride();
        if stride == 0 {
            return;
        }
        let w = self.written.load(Ordering::Relaxed);
        let c = self.covered.load(Ordering::Relaxed);
        let due = self.drop_next.load(Ordering::Relaxed);
        let Some(next) = pace_step(w, c, due, self.size, stride) else {
            return;
        };
        if self
            .drop_next
            .compare_exchange(due, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        use std::os::unix::io::AsRawFd;
        // Parked: the handle is gone and park() synced on the way down.
        let g = self.file.read_ok();
        let Some(fd) = g.as_ref().map(|f| f.as_raw_fd()) else {
            return;
        };
        // The COMPLETION flush leaves the hot path: inline it cost a
        // measured ~7% of the m1 loopback ceiling on a big-file corpus
        // (28 -> 30 s per 80 GB leg, both reps) - forty tail fsyncs
        // riding decode workers while the disk was the bottleneck.
        // A background flusher fsyncs a clone of the handle instead;
        // the clone keeps the fd alive on its own, so a concurrent
        // park() stays correct (park's own sync_data covers the same
        // bytes anyway).
        //
        // STRIDE flushes take the same thread when `pace_bg_enabled`
        // says so (the default - see it for the measurement). The
        // pacing effect is not the decoder's pause as such, it is the
        // dirty set staying bounded: the flusher's queue is bounded and
        // a full queue puts the flush back inline on this decoder, so
        // while the device keeps up the decoders never block, and once
        // it does not the old behaviour returns exactly (the pause is
        // then the device's, which it always was). `NZBFAST_PACE_BG=0`
        // is the inline arm, kept as a bench control.
        if (next == u64::MAX || pace_bg_enabled())
            && let Ok(clone) = g.as_ref().unwrap().try_clone()
        {
            pace_flush_bg(clone);
            return;
        }
        // (try_clone can only really fail on fd exhaustion - flush
        // inline below rather than skip: for the completion the parked
        // watermark means this was the file's one chance.)
        // SAFETY: both calls take only the raw fd plus integer
        // arguments; the read guard `g` keeps the File open across the
        // call. Concurrent pwrites from the other decode workers
        // proceed under their own read guards - only park() (write
        // lock) waits, and it wants the sync anyway.
        pace_flush(fd);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn maybe_pace_writeback(&self) {}
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
fn pace_flush(fd: std::os::unix::io::RawFd) {
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
fn pace_bg_enabled() -> bool {
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
fn pace_flush_bg(file: File) {
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
const PACE_FLUSH_QUEUE_DEFAULT: usize = 64;

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn pace_flush_queue() -> usize {
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
fn pace_step(written: u64, covered: u64, due: u64, size: u64, stride: u64) -> Option<u64> {
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

/// The error [`FileWriter::read_covered_at`] answers with. Same kind as
/// the extractor's `nofile()`, which is what its callers already branch
/// on.
fn uncovered(path: &std::path::Path, off: u64, len: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{}: [{off}, {}) is not written - refusing to serve a hole",
            path.display(),
            off + len
        ),
    )
}

impl FileWriter {
    /// pread through the writer's own handle - spares callers a fresh
    /// open() per read (the mapped-repair path reads thousands of
    /// blocks back through the volume view).
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        // A staged byte is not on disk, so a read that would land on one
        // writes the run out first (see [`stage`]).
        if self.stage_overlaps(offset, offset + buf.len() as u64) {
            self.flush_stage()?;
        }
        read_exact_at(self.handle()?.as_ref().unwrap(), buf, offset)
    }

    /// [`FileWriter::read_at`], refusing a range this writer cannot
    /// vouch for instead of preading a sparse hole and handing the
    /// zeros back as data.
    ///
    /// A plain pread cannot tell a hole from a run of written zeros, so
    /// the coverage question has to be asked - and asked HERE, on the
    /// writer's own interval lock, immediately around the read. A
    /// caller that asks somewhere else asks across a window: the mapped
    /// container path resolved a destination under the extractor's
    /// routing lock and preaded 0.3-1.3 ms after releasing it, and a
    /// promote landing inside that gap served an entire zip member as
    /// zeros (research/MEASURED-2026-09-03-zip-mapped-damaged-container-races.md,
    /// "Race 2").
    ///
    /// Asked on BOTH sides of the read, because the hazard is coverage
    /// going away rather than arriving: a range that was covered before
    /// the pread and is still covered after it was covered during it,
    /// short of a shrink and a restore inside one read - which no path
    /// here performs. `NotFound` is deliberate: every caller of the
    /// extractor read path already treats it as "cannot serve this
    /// range yet" and retries or prices it as damage.
    pub fn read_covered_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let len = buf.len() as u64;
        if !self.covered(offset, len) {
            return Err(uncovered(&self.path, offset, len));
        }
        self.read_at(buf, offset)?;
        if !self.covered(offset, len) {
            return Err(uncovered(&self.path, offset, len));
        }
        Ok(())
    }

    /// The live handle, or `NotConnected` when the writer is parked.
    ///
    /// Parked is never a state a caller should paper over: it means someone
    /// deliberately handed this file to an external process, so a write that
    /// lands now would be silently overwritten (or would corrupt what that
    /// process is rebuilding). Failing is the honest answer.
    fn handle(&self) -> io::Result<std::sync::RwLockReadGuard<'_, Option<File>>> {
        let g = self.file.read_ok();
        if g.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("{} is parked for an external tool", self.path.display()),
            ));
        }
        Ok(g)
    }

    /// Close this file's OS handle, keeping the writer itself alive.
    ///
    /// Windows opens are share-negotiated: par2cmdline opens its targets with
    /// share mode 0, so ANY handle we still hold makes its open fail and it
    /// concludes the file is missing ("Repair is not possible"). Unix does not
    /// care, but parking there too keeps one code path and makes the external
    /// tool the sole writer on every platform - which it must be, since it
    /// rewrites these bytes underneath us.
    ///
    /// Syncs first: buffered pwrites that never reached disk would otherwise
    /// hand par2 a stale file and it would "repair" bytes we were about to
    /// write. A sync failure is returned, not swallowed - same contract as
    /// [`Extractor::finish`](crate::extract::Extractor::finish).
    ///
    /// Parking works through the writer's own shared state, NOT by dropping an
    /// `Arc`: releasing one reference cannot close anything while the daemon's
    /// stream picker or a settle reader still holds a clone.
    pub fn park(&self) -> io::Result<()> {
        // BEFORE the write lock, not after: the flush writes through
        // `handle()`, which takes the same lock for reading.
        self.flush_stage()?;
        let mut g = self.file.write_ok();
        // Write lanes go first: the system cache is per file, so the
        // primary handle's sync below flushes their bytes too - they
        // only need to be CLOSED for par2's share-mode-0 open to pass.
        #[cfg(windows)]
        self.aux.write_ok().clear();
        if let Some(f) = g.as_ref() {
            f.sync_data()?;
        }
        *g = None;
        Ok(())
    }

    /// [`park`] plus exclusive custody for the external tool that is
    /// about to own the file (sweep 8, M4). Paired with [`unpark`],
    /// which hands the file back.
    ///
    /// The plain [`park`] is the end-of-job handle release
    /// (`postproc`'s cleanup), which never unparks and must therefore
    /// never claim custody: doing so would lock every later reader out
    /// of a finished job's outputs for good.
    ///
    /// [`park`]: FileWriter::park
    /// [`unpark`]: FileWriter::unpark
    pub fn park_for_repair(&self) -> io::Result<()> {
        // An external tool is about to own the bytes, and whatever it
        // writes never comes through `write_at` - so the prefix hash can
        // no longer claim to describe the file. Belt: the resume
        // ledger's own repair guards stand it down on this path anyway.
        if let Some(ph) = &self.prefix {
            ph.lock_ok().poisoned = true;
        }
        self.claim_for_repair();
        self.park()
    }

    /// Where the file lives RIGHT NOW: the publish target once
    /// [`note_renamed`] has been called, the creation path before that.
    ///
    /// [`note_renamed`]: FileWriter::note_renamed
    pub fn current_path(&self) -> PathBuf {
        self.renamed_to
            .lock_ok()
            .clone()
            .unwrap_or_else(|| self.path.clone())
    }

    /// Record that the on-disk file moved to `new` (the verified-name
    /// publish renames it while this writer's handle is open). The live
    /// handle is untouched - it follows the inode - but a later by-path
    /// reopen must use the new name: before this existed, `unpark` after
    /// the external par2 hit ENOENT on the old name and failed the whole
    /// job on exactly the obfuscated posts that repair exists for
    /// (soak 11 Aug, sab3287-stall).
    pub fn note_renamed(&self, new: PathBuf) {
        *self.renamed_to.lock_ok() = Some(new);
    }

    /// Reopen a parked writer at its current path, without truncating and
    /// without preallocating: the bytes on disk now are the external tool's
    /// repaired output and must survive verbatim. Idempotent - unparking a
    /// live writer is a no-op, so a caller may pair it with [`park`] on a path
    /// that bailed out early.
    ///
    /// `written`/`intervals` are deliberately untouched: they describe which
    /// spans of the file are populated, which is exactly as true after a
    /// repair as before it (repair fills bytes in, it never unwrites them).
    ///
    /// [`park`]: FileWriter::park
    pub fn unpark(&self) -> io::Result<()> {
        // Before the reopen, not after: readers admitted from here on
        // are reading the repaired file, and one that has to wait for
        // our own handle is waiting on nothing.
        let after_repair = self.release_after_repair();
        let mut g = self.file.write_ok();
        if g.is_some() {
            return Ok(());
        }
        let path = self.current_path();
        // The same no-follow, descriptor-bound open the constructors
        // take, in the one mode that must NEVER create: this is a
        // REOPEN of bytes the external par2 just rewrote, and a
        // `LeafOpen::Keep` here would answer a file that has gone by
        // making an empty one and handing it back as the repaired
        // payload (X5-06/08/19 OWED item 6, 31 Aug 2026).
        //
        // Why a by-name reopen at all, rather than keeping the handle:
        // `park_for_repair` CLOSES it on purpose, because par2 opens
        // the file with share-mode 0 on Windows and is the sole writer
        // on every platform. So the name is all there is at this point,
        // and what this fixes is what the name is allowed to resolve
        // to - a regular file inside a directory that is not itself an
        // alias, never a symlink that appeared while par2 was renaming
        // inodes around.
        let file = relpath::open_out_leaf(&path, relpath::LeafOpen::Existing)?;
        apply_cache_policy(&file);
        // The readers that kept their handles through the repair are
        // holding an inode par2 renamed aside; this is where they are
        // told, and handed the one we just proved openable.
        if after_repair {
            self.publish_repaired_handle(&file);
        }
        #[cfg(windows)]
        {
            *self.aux.write_ok() = open_aux_handles(&file);
        }
        *g = Some(file);
        Ok(())
    }

    /// Record `[offset, offset+len)` as on-disk without writing - crash
    /// resume seeds the coverage map with spans a previous run persisted.
    ///
    /// `intervals` is kept sorted by start and disjoint (touching runs
    /// merged), so this is a binary-search insert-and-merge: no per-write
    /// allocation and no full re-sort. The old rebuild-and-sort was
    /// O(n log n) + a heap alloc on EVERY span; under heavy out-of-order
    /// arrival (one disjoint region per in-flight connection) every
    /// decoder thread paid that while serialized on this mutex.
    /// Record [offset, offset+len) as written, returning the number of
    /// bytes that were NOT already covered. A rewrite (repair span, or a
    /// duplicate article) returns 0, which is what makes the extraction
    /// budget in `write_at` immune to double-charging a healing file.
    pub fn note_written(&self, offset: u64, len: u64) -> u64 {
        if len == 0 {
            return 0;
        }
        self.written.fetch_add(len, Ordering::Relaxed);
        let fresh = self.merge_span(offset, len);
        self.covered.fetch_add(fresh, Ordering::Relaxed);
        fresh
    }

    /// Merge `[offset, offset+len)` into the coverage map, returning the
    /// bytes that were not already in it. Split out of `note_written` so
    /// [`note_repaired`](FileWriter::note_repaired) can publish spans an
    /// external tool wrote without charging them to `written`.
    fn merge_span(&self, offset: u64, len: u64) -> u64 {
        if len == 0 {
            return 0;
        }
        let (s, e) = (offset, offset + len);
        let mut iv = self.intervals.lock_ok();
        // First interval that could touch/overlap on the left (its end
        // reaches `s`), and first that starts beyond `e` (can't touch).
        let lo = iv.partition_point(|&(_, fe)| fe < s);
        let hi = iv.partition_point(|&(fs, _)| fs <= e);
        if lo < hi {
            // Merge the overlapping/adjacent run [lo, hi) into one span.
            // The run's spans are disjoint, so the newly-covered count is
            // the merged length minus what the run already held.
            let held: u64 = iv[lo..hi].iter().map(|&(fs, fe)| fe - fs).sum();
            let ns = s.min(iv[lo].0);
            let ne = e.max(iv[hi - 1].1);
            iv[lo] = (ns, ne);
            iv.drain(lo + 1..hi);
            (ne - ns) - held
        } else {
            iv.insert(lo, (s, e));
            len
        }
    }

    /// True when every byte of [off, off+len) has been written.
    pub fn covered(&self, off: u64, len: u64) -> bool {
        // Coverage is published after the `pwrite`, so a staged span
        // reads as a hole. That is the SAFE direction for every consumer
        // (nobody is told a byte is there when it is not), but a caller
        // waiting for its own bytes would wait for a write nothing has
        // asked for yet - so an overlapping run goes out here.
        //
        // The cost is bounded and it is the same write either way: the
        // relaxed load above answers no for every writer that is not
        // staging, which on the direct-map one-pass path is every volume
        // writer `materialized_span_on_disk` asks about.
        if self.stage_overlaps(off, off + len) {
            let _ = self.flush_stage();
        }
        let iv = self.intervals.lock_ok();
        iv.iter().any(|&(s, e)| s <= off && off + len <= e)
    }

    /// True when some byte range was written MORE THAN ONCE - the total
    /// bytes written exceed the distinct bytes covered. In a well-formed
    /// download every article owns a disjoint byte range, so this stays
    /// false; it turns true only when two writes land on the same range:
    /// a same-article hedge/tail duplicate (identical bytes, harmless) or
    /// - the reason this exists - a MALFORMED post carrying two different
    /// articles for one file range. The second is silent corruption: the
    /// later write overwrites the first on disk, but a block the in-stream
    /// verifier already marked Ok from the first copy is never re-hashed,
    /// so garbage ships as a "clean download". Settle consults this to
    /// force a read-back of such a slot (see `LiveVerifier::force_readback`).
    pub fn had_rewrite(&self) -> bool {
        // Both counters advance when a coalescing run is WRITTEN, so a
        // duplicate still sitting in the open run would read as no
        // rewrite at all - and settle would skip exactly the read-back
        // this answer exists to force. Cold path (settle), so the run
        // goes out first and the comparison is over the whole file.
        let _ = self.flush_stage();
        self.written.load(Ordering::Relaxed) > self.covered.load(Ordering::Relaxed)
    }

    /// The written sub-ranges of [off, off+len), clipped, in file offsets.
    /// Anything not returned is a sparse hole that would pread as zeros -
    /// the extractor's fallback read-back must never copy those.
    pub fn covered_intervals(&self, off: u64, len: u64) -> Vec<(u64, u64)> {
        if self.stage_overlaps(off, off + len) {
            let _ = self.flush_stage();
        }
        self.covered_intervals_raw(off, len)
    }

    /// [`FileWriter::covered_intervals`] with no staging flush - the
    /// door [`FileWriter::gate_enter`] takes, because it is already
    /// inside the gate and the overlap it would flush is the one the
    /// gate has just excluded.
    fn covered_intervals_raw(&self, off: u64, len: u64) -> Vec<(u64, u64)> {
        let end = off + len;
        let iv = self.intervals.lock_ok();
        iv.iter()
            .filter_map(|&(s, e)| {
                let cs = s.max(off);
                let ce = e.min(end);
                (cs < ce).then_some((cs, ce))
            })
            .collect()
    }

    /// End of the contiguous prefix starting at 0 (the streaming frontier).
    pub fn contiguous_from_start(&self) -> u64 {
        // The streaming frontier, polled by live readers: a run held
        // behind it would stall a player on bytes we already have.
        let _ = self.flush_stage();
        let iv = self.intervals.lock_ok();
        match iv.first() {
            Some(&(0, e)) => e,
            _ => 0,
        }
    }

    /// Bytes written so far (not necessarily contiguous).
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// Count `n` bytes a PRIOR run left in this file as written, without
    /// claiming coverage of any range. A crash-resume opens an output
    /// that already holds bytes, and the extractor's in-stream decrypt
    /// gate reads this counter as "this output holds ciphertext" (rule 2
    /// of `instream_decrypt_allowed`): a resumed writer that started at
    /// zero let the gate latch plaintext-once over them (TODO 158 item
    /// 2). Coverage stays empty on purpose - the resume replays or
    /// refetches every one of those bytes, and `covered` must keep
    /// answering for THIS run's writes alone.
    pub fn seed_written(&self, n: u64) {
        self.written.fetch_add(n, Ordering::Relaxed);
    }

    /// Open this file for READING at its current path, taking a custody
    /// lease for the handle's whole life (sweep 8, M4).
    ///
    /// Every by-path live reader goes through here: the lease is what
    /// makes an external repair able to see, and on Windows revoke, the
    /// handles standing in its way. Waits out an in-progress repair
    /// (bounded by [`REPAIR_ADMIT_WAIT`]) rather than failing
    /// immediately - par2cmdline on a repairable set is seconds, and a
    /// player that seeks into one should get its bytes, not a 410.
    ///
    /// The extractor has DISOWNED this output: the file has been
    /// unlinked and no byte will ever be written through this writer
    /// again. Sticky, and set by every path that takes a writer out of
    /// the extractor and removes its file - `abandon_slot`,
    /// `delete_group_out_files`, `drop_slot_file`.
    ///
    /// This is NOT custody and it is not a repair signal. Custody says
    /// "an external tool wants this inode for a moment"; this says the
    /// file is gone. The distinction matters because the two arrive by
    /// completely different routes, and the shape that motivated this
    /// gets only the second one (sweep 8 M4, defect 3, measured 22 Aug
    /// 2026): a damaged MULTI-VOLUME set demotes to "materializing
    /// volumes for repair" BEFORE the repair runs, and that demote
    /// abandons the extracted media file - `fallback_group` drains the
    /// group's routed members and `abandon_slot` takes the child slot's
    /// writer and unlinks it. By the time
    /// [`Extractor::park_outputs_for_repair`] walks the tree, the media
    /// writer is no longer in any slot, so it is claimed by nothing;
    /// par2's targets are the VOLUMES and the file the player is
    /// holding is not even on disk. Nothing revokes, nothing bumps a
    /// generation, and a live `/stream` response parked on that
    /// writer's frontier waits for a frontier that will never move
    /// again - five minutes, on a job that repaired fine.
    ///
    /// So the live readers poll this exactly where they poll
    /// [`ReadLease::revoked`], and on EVERY platform: sharing has
    /// nothing to do with it. A reader that keeps going here would be
    /// serving an unlinked inode the job has already disowned, over a
    /// name the post-repair re-extract is about to rewrite - the same
    /// class of stale-bytes answer [`ReadLease::needs_reopen`] exists to
    /// prevent, and with no repaired handle to rebind onto.
    ///
    /// Releasing the extraction budget is part of the same statement:
    /// the bytes this writer charged are gone from the volume with the
    /// file (see [`WriteBudget::release`]). The swap makes the refund
    /// once-only, so the sticky flag stays idempotent. A write racing
    /// this refund re-charges bytes that no longer exist, which is the
    /// conservative direction and cannot outlive the job.
    ///
    /// [`Extractor::park_outputs_for_repair`]: crate::extract::Extractor::park_outputs_for_repair
    pub fn abandon(&self) {
        self.abandoned.store(true, Ordering::Release);
        if let Some(b) = &self.budget {
            b.release(self.charged.swap(0, Ordering::Relaxed));
        }
    }

    /// Has [`abandon`] been called? Cheap enough for a per-read poll.
    ///
    /// [`abandon`]: FileWriter::abandon
    pub fn is_abandoned(&self) -> bool {
        self.abandoned.load(Ordering::Acquire)
    }

    /// [`abandon`] plus closing the shared OS handle, returning the
    /// path an unlink must target. The delete sites' primitive: every
    /// site that unlinks an abandoned writer's file must go through
    /// this, never through `abandon()` alone.
    ///
    /// Why the close is not optional there: the handle lives in shared
    /// state behind the `Arc`, and clones of that `Arc` legitimately
    /// outlive the slot - the stream picker's snapshot, a group's
    /// `routed_plain` cache, a pending spill, the resume ledger. On
    /// unix an unlinked file with ANY live descriptor keeps its blocks,
    /// so `abandon()` + `remove_file` with a surviving clone pinned the
    /// whole file until process exit. Measured 30 Aug 2026 on the live
    /// daemon: a 51.2 GB preallocated .mkv, demoted mid-chase
    /// ("materialized for repair"), sat unlinked-but-open for over four
    /// hours because the writer's handle was still in the shared slot.
    /// Closing through the shared state ends it for every clone at
    /// once - the same argument [`park`] makes for its own close. On
    /// Windows the close is also what lets the unlink itself succeed.
    ///
    /// No sync, deliberately, where [`park`] syncs first: park hands
    /// the bytes to an external tool, so they must be durable; this
    /// hands them to `remove_file`, so flushing dirty pages into blocks
    /// the kernel is about to free would be pure wasted I/O on a file
    /// this size.
    ///
    /// Returns [`current_path`], not `path`: a verified-name publish
    /// renames the file under the live writer, and unlinking the
    /// creation name is then ENOENT while the real file survives as
    /// exactly the false artifact the delete existed to prevent.
    ///
    /// [`abandon`]: FileWriter::abandon
    /// [`park`]: FileWriter::park
    /// [`current_path`]: FileWriter::current_path
    pub fn abandon_close(&self) -> PathBuf {
        self.abandon();
        // The file is about to be unlinked, so the open run is the one
        // thing in this module that is thrown away rather than written.
        self.discard_stage();
        let mut g = self.file.write_ok();
        #[cfg(windows)]
        self.aux.write_ok().clear();
        *g = None;
        drop(g);
        self.current_path()
    }

    /// Opens [`current_path`], never `path`: a verified-name publish
    /// renames the file under the live writer, and the creation name is
    /// ENOENT from that moment (sweep 8, M6).
    ///
    /// [`current_path`]: FileWriter::current_path
    /// [`park`]: FileWriter::park
    pub fn open_read(&self) -> io::Result<(File, ReadLease)> {
        self.open_read_admit(REPAIR_ADMIT_WAIT)
    }

    /// [`open_read`] that does NOT wait out a repair: refuses at once
    /// with `ResourceBusy` while an external tool owns the file.
    ///
    /// The 30 s admit wait is sized for a `/stream` range request, where
    /// a player that seeks into a repairable set should get its bytes.
    /// The probe paths (`/preview/probe`, the SAB playback listing, the
    /// background prober) answered instantly before they were routed
    /// through the custody gate, and every one of them has a "not yet"
    /// answer to give - so they take this one and keep their callers'
    /// threads (bug sweep 22 Aug 2026).
    ///
    /// [`open_read`]: FileWriter::open_read
    pub fn try_open_read(&self) -> io::Result<(File, ReadLease)> {
        self.open_read_admit(std::time::Duration::ZERO)
    }

    fn open_read_admit(&self, admit: std::time::Duration) -> io::Result<(File, ReadLease)> {
        // The caller gets a raw descriptor and reads the INODE, not this
        // writer, so nothing downstream can flush for it.
        self.flush_stage()?;
        {
            let mut g = self.custody.st.lock_ok();
            let deadline = std::time::Instant::now() + admit;
            while g.repairing {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::ResourceBusy,
                        format!(
                            "{} is being repaired by an external tool",
                            self.current_path().display()
                        ),
                    ));
                }
                g = self
                    .custody
                    .cv
                    .wait_timeout(g, left)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
            // Opened UNDER the gate, so the descriptor is ordered before
            // any later `repairing = true`. Unix repair does not drain
            // readers, so an open after the unlock could land on the
            // inode a child was mid-rewrite of (Codex F-21, 22 Aug 2026).
            // A failed open leaves `readers` untouched - no lease exists
            // to undo it.
            #[cfg(test)]
            if let Some((entered, released)) = g.open_barrier.take() {
                entered.wait();
                released.wait();
            }
            let f = File::open(self.current_path())?;
            g.readers += 1;
            let generation = g.generation;
            drop(g);
            Ok((
                f,
                ReadLease {
                    seen: AtomicU64::new(generation),
                    custody: self.custody.clone(),
                },
            ))
        }
    }

    /// Re-open a live reader's handle at the file's CURRENT path, on the
    /// lease it already holds (sweep 8, M5b).
    ///
    /// The companion to [`ReadLease::needs_reopen`], which says when this
    /// is needed and why: an external repair that rewrites the target
    /// onto a new inode leaves every live reader's `File` pointing at
    /// the damaged one. This is a re-open, not a second admission - the
    /// lease and its slot in `readers` are the ones already granted, so
    /// there is no waiting on custody and nothing for a concurrent
    /// [`park_for_repair`] to drain twice.
    ///
    /// Clones the handle [`unpark`] captured rather than opening
    /// `current_path` again - see `CustodyState::repaired` for the race
    /// that costs. The by-path open is the fallback for the one
    /// case that has no captured handle: a Windows reader, which is
    /// revoked long before it could get here.
    ///
    /// The generation is adopted whatever happens, including a failed
    /// open: a caller that could not be given the repaired file has
    /// nothing to gain from being asked again every read, and the
    /// failure is the same stale handle it already had.
    ///
    /// [`unpark`]: FileWriter::unpark
    /// [`park_for_repair`]: FileWriter::park_for_repair
    pub fn reopen_read(&self, lease: &ReadLease) -> io::Result<File> {
        debug_assert!(
            Arc::ptr_eq(&lease.custody, &self.custody),
            "a lease may only be reopened against the writer that issued it"
        );
        let (generation, repaired) = {
            let g = self.custody.st.lock_ok();
            (g.generation, g.repaired.as_ref().map(File::try_clone))
        };
        lease.seen.store(generation, Ordering::Relaxed);
        match repaired {
            Some(f) => f,
            None => File::open(self.current_path()),
        }
    }

    /// Take exclusive custody for an external tool - see [`ReadCustody`].
    fn claim_for_repair(&self) {
        let mut g = self.custody.st.lock_ok();
        g.repairing = true;
        // The last repair's handle is not this file any more, and it is
        // one of the handles `park` is about to be asked to have let go.
        g.repaired = None;
        drop(g);
        // Wakes readers blocked in `open_read` (they will now bail) and,
        // on Windows, arms `ReadLease::revoked` for the live ones.
        self.custody.cv.notify_all();
        #[cfg(windows)]
        {
            let deadline = std::time::Instant::now() + REPAIR_DRAIN_WAIT;
            let mut g = self.custody.st.lock_ok();
            while g.readers > 0 {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                g = self
                    .custody
                    .cv
                    .wait_timeout(g, left)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        }
    }

    /// Hand the file back to live readers after an external tool.
    /// Reports whether there was really a repair to hand back - `unpark`
    /// is also called on paths that never claimed custody, and the
    /// reader rebind below must not fire for those.
    fn release_after_repair(&self) -> bool {
        let mut g = self.custody.st.lock_ok();
        let was_repairing = std::mem::take(&mut g.repairing);
        drop(g);
        self.custody.cv.notify_all();
        was_repairing
    }

    /// Publish the file an external repair left behind, and with it the
    /// generation bump that tells every reader still holding a handle
    /// from before to come and get it (see [`ReadLease::needs_reopen`]).
    ///
    /// Called from [`unpark`] with the handle it has just opened, which
    /// is the last moment anything in this process can be sure which
    /// inode the repaired bytes are on.
    ///
    /// [`unpark`]: FileWriter::unpark
    fn publish_repaired_handle(&self, repaired: &File) {
        // Windows readers were revoked and their responses ended before
        // the child ever ran - nothing there to hand anything to, and a
        // spare handle on a finished job's output is a liability.
        let keep = (!cfg!(windows))
            .then(|| repaired.try_clone().ok())
            .flatten();
        let mut g = self.custody.st.lock_ok();
        g.repaired = keep;
        g.generation += 1;
        drop(g);
        self.custody.cv.notify_all();
    }

    /// True while an external tool owns this file. Test/diagnostic
    /// window onto [`ReadCustody`].
    pub fn under_repair(&self) -> bool {
        self.custody.st.lock_ok().repairing
    }

    /// Publish coverage for bytes an EXTERNAL tool wrote (sweep 8, M5).
    ///
    /// `unpark` deliberately preserves the interval map, on the reading
    /// that repair fills bytes in and never unwrites them. True for the
    /// bytes we wrote - and silent about the ones we did NOT: external
    /// par2 fills the sparse ranges that were missing, outside the
    /// writer, so a live reader whose coverage map still calls them
    /// holes goes on waiting for them or zero-filling over correct data
    /// that is already on disk. Callers publish here only against the
    /// same verification that licenses the repair as successful.
    ///
    /// Charges `covered` but NOT `written`: `written` counts physical
    /// writes through this handle, and inflating it with an external
    /// tool's output would misreport the job's disk rate.
    pub fn note_repaired(&self, offset: u64, len: u64) {
        // An external tool's bytes are already on disk; a staged run
        // over the same range would land on top of them.
        if self.stage_overlaps(offset, offset + len) {
            let _ = self.flush_stage();
        }
        let fresh = self.merge_span(offset, len);
        self.covered.fetch_add(fresh, Ordering::Relaxed);
    }

    /// §94 A in-place replay: publish `[offset, offset+len)` as covered
    /// WITHOUT writing it, because the bytes are already there - the
    /// caller has checked that this run's derived placement is the very
    /// (file, offset) the resume journal recorded the bytes at, so a
    /// pwrite here would copy the range onto itself. Everything a write
    /// would have done to the bookkeeping still happens: the coverage
    /// map (a live reader must not call the range a hole), and the
    /// extraction bomb budget, charged exactly as the write would have
    /// charged it (fresh bytes only) so a resumed job cannot extract
    /// past the ceiling a cold one is held to. `written` is left alone
    /// for the same reason as [`note_repaired`](FileWriter::note_repaired):
    /// it counts physical writes through this handle.
    pub fn note_covered(&self, offset: u64, len: u64) -> io::Result<()> {
        // §94 A says these bytes are ALREADY at this offset from a prior
        // run; a staged run over them would rewrite the range with the
        // same bytes, which is harmless, but publishing coverage for a
        // range whose staged copy has not landed is not.
        if self.stage_overlaps(offset, offset + len) {
            self.flush_stage()?;
        }
        let fresh = self.merge_span(offset, len);
        self.covered.fetch_add(fresh, Ordering::Relaxed);
        if let Some(b) = &self.budget {
            // Tallied here exactly as `write_at` tallies it, and BEFORE
            // the verdict: a replayed range that is charged but not
            // recorded in `charged` is a charge `abandon` can never
            // refund, so the next container in the job is refused with
            // BOMB_VERDICT over bytes that are no longer on the volume.
            self.charged.fetch_add(fresh, Ordering::Relaxed);
            b.charge(fresh)?;
        }
        Ok(())
    }

    /// A PARKED writer syncs nothing and reports success: [`park`] synced it
    /// on the way down and closed the handle, so there is no buffered state
    /// left to lose. Erroring here instead would fail a job whose bytes are
    /// all safely on disk.
    ///
    /// [`park`]: FileWriter::park
    pub fn sync(&self) -> io::Result<()> {
        self.flush_stage()?;
        match self.file.read_ok().as_ref() {
            Some(f) => f.sync_data(),
            None => Ok(()),
        }
    }

    /// [`Self::sync`] WITHOUT the whole-device barrier.
    ///
    /// Plain `libc::fsync` on Apple platforms, exactly as the writeback
    /// pacer uses (see `pace_flush`): std's `sync_data` is
    /// `fcntl(F_FULLFSYNC)` there, which flushes the DRIVE's volatile
    /// cache and not just this file's dirty pages. A caller syncing many
    /// files wants N of these and then ONE [`Self::sync_barrier`], which
    /// is the same durability promise for a fraction of the device work
    /// - a per-file barrier is cheap on an internal SSD (17 us measured
    /// on APFS, round 26 of research/RAR-PERF-AUDIT-2026-09-02.md) and a
    /// different order of cost on a NAS or a spinning disk. On every
    /// other platform `sync_data` already IS the plain flush, so the two
    /// methods are the same call and the extra barrier is a second sync
    /// of clean data.
    ///
    /// A PARKED writer syncs nothing and answers `false`, for the reason
    /// [`Self::sync`] gives - and the boolean is load-bearing, not a
    /// convenience: it is how a caller picks a handle to issue the
    /// closing [`Self::sync_barrier`] through. A parked writer's `sync`
    /// is a silent no-op, so choosing one for the barrier would issue
    /// NO barrier at all. (Nothing is lost by skipping a parked writer:
    /// `park` synced it on the way down, with the full barrier.)
    pub fn sync_plain(&self) -> io::Result<bool> {
        let g = self.file.read_ok();
        let Some(f) = g.as_ref() else {
            return Ok(false);
        };
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: takes only the raw fd; `f` (and so the fd) is alive
            // for the whole call, pinned by the guard above.
            if unsafe { libc::fsync(f.as_raw_fd()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(not(target_os = "macos"))]
        f.sync_data()?;
        Ok(true)
    }

    /// One whole-device barrier, issued through THIS file's handle - the
    /// closing half of a run of [`Self::sync_plain`] calls. The barrier
    /// is a property of the device, not of the file, so one call covers
    /// every file already flushed to the same device (which is every
    /// output of a job: they share one output directory).
    pub fn sync_barrier(&self) -> io::Result<()> {
        self.sync()
    }
}

/// One pinned article in flight - see [`FileWriter::hold_busy`].
#[cfg(test)]
pub(crate) struct BusyGuard<'a>(&'a FileWriter);

#[cfg(test)]
impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.articles_in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The belt behind every close door.
///
/// `sync`, `park` and `Extractor::finish`'s per-writer sync all write the
/// open run out and RETURN the error if that fails, which is how a
/// staging failure reaches the job. This exists for the writer that is
/// simply dropped - a slot torn down on an error path, a `routed_plain`
/// cache entry released - where there is no caller left to tell.
///
/// `abandon_close` has already discarded the run (the file is unlinked),
/// so the common teardown reaches here with nothing to do and pays one
/// relaxed load.
impl Drop for FileWriter {
    fn drop(&mut self) {
        if self.staged.load(Ordering::Relaxed) == 0 || self.is_abandoned() {
            return;
        }
        let _ = self.flush_stage();
    }
}

/// Flush a directory's own entries, so a rename that published a file
/// survives a power cut. Best-effort on purpose: no caller may depend on
/// it for correctness (SMB/CIFS and some FUSE mounts - the NAS setups we
/// actually ship to - refuse to open a directory for fsync, and failing a
/// good job over that would be pure harm), and Windows has no directory
/// handle to sync through at all.
pub fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(f) = File::open(dir) {
            let _ = f.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

#[cfg(test)]
mod tests;

pub mod stage;

mod sanitize;
pub(crate) use sanitize::trimmed_extension;
pub use sanitize::{sanitize_filename, sanitize_filename_for};

// The one fold every identity-key site in the tree shares (M4-44). Gate
// it on `case_insensitive_dir`, never on the build target.
mod casefold;
pub use casefold::case_fold_key;

// Whether two paths reach ONE file object: the volume's own case
// behaviour (`case_insensitive_dir`) and the inode identity behind a
// pair of names (`file_object_id` and the two doors over it). Split out
// under the size gate on 31 Aug 2026; the module's own header says what
// the subject is and why the halves belong together.
mod identity;
pub use identity::{case_insensitive_dir, file_object_id, is_redundant_link, same_file_object};

mod cowcopy;
pub use cowcopy::copy_file_cow;

// The SECOND route from a path to its block device, for the filesystems
// that have no `st_dev` to index `/sys/dev/block` with - see
// `rotational` above, and the module's own header for the three
// measured facts that shape it.
#[cfg(unix)]
mod mounttab;
#[cfg(unix)]
use mounttab::rotational_via_mount_table;

/// Windows has no mount table of this shape and no `queue/rotational`
/// to reach through it, so the fallback is absent rather than empty.
#[cfg(not(unix))]
fn rotational_via_mount_table(_path: &Path) -> Option<bool> {
    None
}

// The READ side's cache policy, the mirror of `maybe_drop_cache` and
// `maybe_pace_writeback` above: what to tell the kernel about a payload
// we read once (a PAR2 verify, a create scan) so it does not evict
// everything else the box was holding. Keyed on a probed device class
// and the member's size, never on a pathname - see the module header.
mod readpolicy;
pub use readpolicy::{
    ReadHints, ScanCache, ScanReader, device_class, hints_for_path, open_for_scan,
};

mod relpath;
/// Not in the `pub use` below because it is `pub(crate)`: it is a policy
/// budget two sites inside this crate must agree on, not a name nzbkit
/// publishes. `journal::restore::unquarantine_partials` bounds its
/// directory walk by it - see the constant's own doc.
pub use relpath::MAX_DEPTH;
pub use relpath::{
    LeafOpen, cap_shared_stem, create_out_dirs, disambiguated_out_name, join_out_name,
    name_within_limits, open_out_leaf, open_out_leaf_under, out_name_of, prepare_out_path,
    relpath_within_total, rename_out_under, resolve_out_root, sanitize_filename_capped,
    sanitize_filename_capped_for, sanitize_out_name, sanitize_out_name_for, sanitize_relpath_for,
};

/// Mark one of our own bookkeeping files or dirs as hidden.
///
/// We name everything internal with a leading dot - `.nzbfast.journal`,
/// `.spool`, the `.nzbfast-hold` markers - which hides it on macOS and
/// Linux and hides NOTHING on Windows, where the convention does not
/// exist. So a Windows user opening a failed download's folder finds one
/// mysterious file sitting in it, reads it as leftover junk, and is
/// right to: it looks like junk even though it is the resume state that
/// lets a retry fetch only what is still missing.
///
/// Best-effort by design. A filesystem that cannot store the attribute
/// (a network share, a FAT volume mounted oddly) is not a reason to fail
/// the download the file belongs to.
pub fn hide_from_user(path: &Path) {
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
        // SAFETY: the declarations must match the real kernel32 exports;
        // these mirror the documented Win32 signatures (GetFileAttributesW:
        // LPCWSTR -> DWORD; SetFileAttributesW: LPCWSTR, DWORD -> BOOL).
        unsafe extern "system" {
            fn GetFileAttributesW(name: *const u16) -> u32;
            fn SetFileAttributesW(name: *const u16, attrs: u32) -> i32;
        }
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is NUL-terminated (the chained 0 above) and stays
        // alive across both calls, so each receives a valid wide C string;
        // the attribute word is a plain integer.
        unsafe {
            // OR into whatever is already set: replacing the attribute
            // word outright would clear ARCHIVE/READONLY and anything
            // else the volume put there.
            let cur = GetFileAttributesW(wide.as_ptr());
            let base = if cur == INVALID_FILE_ATTRIBUTES {
                0
            } else {
                cur
            };
            SetFileAttributesW(wide.as_ptr(), base | FILE_ATTRIBUTE_HIDDEN);
        }
    }
    #[cfg(not(windows))]
    {
        // The leading dot already does this everywhere else.
        let _ = path;
    }
}
