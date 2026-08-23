//! Preallocated offset writer (PLAN M1 / 1d).
//!
//! One output file per NZB file, preallocated to its yEnc-declared size
//! (real extents on Linux, sparse elsewhere - see `preallocate_capped`);
//! every decoded article `pwrite`s at its final offset. No temp
//! files, no assembly pass: a direct-write design with no reassembly
//! step. `write_at` takes `&self` - decoded articles from
//! multiple consumer tasks write concurrently.

use crate::sync::{MutexExt, RwLockExt};
use std::fs::{File, OpenOptions};
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

/// Positioned write, same cross-platform contract as [`read_exact_at`].
///
/// The telemetry counter is charged on SUCCESS, not on entry: charging
/// the requested length up front showed phantom disk throughput during
/// exactly the ENOSPC/EIO episodes where writes were failing and the
/// retry ladder was re-attempting them. On unix a partial write that
/// precedes an error goes uncounted - the conservative direction for a
/// rate readout.
pub fn write_all_at(f: &File, buf: &[u8], off: u64) -> io::Result<()> {
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
/// VDL zero-fill was. Kept env-gated for hardware this box cannot
/// represent.
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

/// Open `lanes - 1` extra read+write handles on `path` for the Windows
/// write-lane spread. Best-effort: stop at the first failure and run
/// with what opened (possibly none) - fewer lanes is always correct.
#[cfg(windows)]
fn open_aux_handles(path: &Path) -> Vec<File> {
    let lanes = win_writer_lanes();
    let mut v = Vec::new();
    for _ in 1..lanes {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
        {
            Ok(f) => v.push(f),
            Err(_) => break,
        }
    }
    v
}

/// What the output directory is sitting on.
///
/// `Unknown` is a first-class answer and must never be treated as
/// `Rotational`: device mapper, RAID, network mounts (SMB/NFS on a NAS),
/// overlayfs in a container and every non-Linux host all land here, and
/// guessing "spinning" for them would clamp hardware that has no seek
/// problem.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Storage {
    Rotational,
    Solid,
    Unknown,
}

/// What is under `path`, with `NZBFAST_STORAGE=rotational|ssd|auto` as the
/// operator override (`auto`, or anything unset, probes).
///
/// The probe matters because decoded articles `pwrite` at their final
/// offsets: with several decode workers the network's article lanes become
/// the output file's seek lanes, which a spinning disk pays for and an SSD
/// does not.
pub fn detect_storage(path: &Path) -> Storage {
    if let Some(forced) = storage_override(std::env::var("NZBFAST_STORAGE").ok().as_deref()) {
        return forced;
    }
    match rotational(path) {
        Some(true) => Storage::Rotational,
        Some(false) => Storage::Solid,
        None => Storage::Unknown,
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

/// Read the backing block device's `queue/rotational` flag.
///
/// The device id of the file's filesystem indexes `/sys/dev/block`, which
/// for a partition resolves to the partition's directory - `queue/` lives
/// on the parent disk, hence the walk up one level.
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
    let sys = std::fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")).ok()?;
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
/// Gated on BOTH signals, because the clamp is only free on one side of
/// them. On a NAS-class box it costs nothing - measured flat from 1 to 4
/// decoders on Gracemont E-cores (the N100-class proxy), since this path
/// does not scale with decode workers there. On a big box it is NOT free
/// (1075 -> 3226 MB/s going 1 to 4 decoders on an M3 Ultra), and a
/// rotational device there is usually a wide array that can absorb the
/// parallel writes. `Unknown` never clamps.
pub fn decoders_for_storage(storage: Storage, cores: usize, decoders: usize) -> usize {
    if decoders > 1 && cores <= NAS_CORES && storage == Storage::Rotational {
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
    // blocking 784/1102 s -> 218/289 s. The alternative,
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
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        apply_cache_policy(&file);
        preallocate_capped(&file, size, prealloc_cap)?;
        Ok(FileWriter {
            file: std::sync::RwLock::new(Some(file)),
            path: path.to_path_buf(),
            renamed_to: std::sync::Mutex::new(None),
            size,
            written: AtomicU64::new(0),
            covered: AtomicU64::new(0),
            budget: None,
            charged: AtomicU64::new(0),
            intervals: std::sync::Mutex::new(Vec::new()),
            drop_next: AtomicU64::new(16 << 20),
            #[cfg(windows)]
            aux: std::sync::RwLock::new(open_aux_handles(path)),
            #[cfg(windows)]
            next_lane: AtomicU64::new(0),
            custody: Arc::new(ReadCustody {
                st: std::sync::Mutex::new(CustodyState::default()),
                cv: std::sync::Condvar::new(),
            }),
            abandoned: AtomicBool::new(false),
            prefix: None,
        })
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
        let file = OpenOptions::new()
            .create(true)
            // Never truncate: this is the RESUME open. The bytes already on
            // disk are the point - a truncate here silently restarts the
            // download it was called to continue.
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        apply_cache_policy(&file);
        preallocate_capped(&file, size, prealloc_cap)?;
        Ok(FileWriter {
            file: std::sync::RwLock::new(Some(file)),
            path: path.to_path_buf(),
            renamed_to: std::sync::Mutex::new(None),
            size,
            written: AtomicU64::new(0),
            covered: AtomicU64::new(0),
            budget: None,
            charged: AtomicU64::new(0),
            intervals: std::sync::Mutex::new(Vec::new()),
            drop_next: AtomicU64::new(16 << 20),
            #[cfg(windows)]
            aux: std::sync::RwLock::new(open_aux_handles(path)),
            #[cfg(windows)]
            next_lane: AtomicU64::new(0),
            custody: Arc::new(ReadCustody {
                st: std::sync::Mutex::new(CustodyState::default()),
                cv: std::sync::Condvar::new(),
            }),
            abandoned: AtomicBool::new(false),
            prefix: None,
        })
    }

    /// Attach the job-wide extracted-byte budget (see [`WriteBudget`]).
    /// Builder-style so the extraction paths can opt in at construction;
    /// writers without one are never charged.
    pub fn with_budget(mut self, budget: std::sync::Arc<WriteBudget>) -> FileWriter {
        self.budget = Some(budget);
        self
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
        let g = self.prefix.as_ref()?.lock_ok();
        if g.poisoned {
            return None;
        }
        Some((g.len, g.hasher.clone().finalize()))
    }

    pub fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
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
        // bytes anyway). Stride flushes stay inline on purpose: their
        // brief writer pause is the measured 6 Aug behaviour, and it is
        // what keeps the dirty set from outrunning the flusher.
        if next == u64::MAX
            && let Ok(clone) = g.as_ref().unwrap().try_clone()
        {
            completion_flush_bg(clone);
            return;
        }
        // (try_clone can only really fail on fd exhaustion - flush
        // inline below rather than skip: the parked watermark means
        // this was the file's one chance.)
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

/// Hand a completed file's flush to the background flusher thread
/// (see the completion note in [`FileWriter::maybe_pace_writeback`]).
///
/// The channel is bounded and the send never blocks: a full queue means
/// the flusher is at device pace already - exactly the backpressure
/// regime where one more inline fsync on a decode worker is the honest
/// price, so the caller pays it there and then. The thread is detached
/// on purpose: it owns nothing but cloned handles, and losing queued
/// flushes at process exit loses nothing `finish()`'s own sync pass
/// would not redo.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn completion_flush_bg(file: File) {
    use std::sync::OnceLock;
    use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
    // Option: the thread is an OPTIMISATION, and spawn can genuinely
    // fail (RLIMIT_NPROC/pids.max exhausted after the decoders start).
    // Panicking here would kill a decode worker - and with one decoder,
    // wedge the bounded outcome channel behind a reader that no longer
    // exists. No thread = every completion flush runs inline instead.
    static TX: OnceLock<Option<SyncSender<File>>> = OnceLock::new();
    let tx = TX.get_or_init(|| {
        let (tx, rx) = sync_channel::<File>(64);
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
            // Disconnected = the thread died; either way the completion
            // flush must still happen - it is this file's only one.
            Err(TrySendError::Full(f) | TrySendError::Disconnected(f)) => f,
        },
        None => file,
    };
    use std::os::unix::io::AsRawFd;
    pace_flush(file.as_raw_fd());
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

impl FileWriter {
    /// pread through the writer's own handle - spares callers a fresh
    /// open() per read (the mapped-repair path reads thousands of
    /// blocks back through the volume view).
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        read_exact_at(self.handle()?.as_ref().unwrap(), buf, offset)
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
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        apply_cache_policy(&file);
        // The readers that kept their handles through the repair are
        // holding an inode par2 renamed aside; this is where they are
        // told, and handed the one we just proved openable.
        if after_repair {
            self.publish_repaired_handle(&file);
        }
        *g = Some(file);
        #[cfg(windows)]
        {
            *self.aux.write_ok() = open_aux_handles(&path);
        }
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
        let iv = self.intervals.lock_ok();
        iv.iter().any(|&(s, e)| s <= off && off + len <= e)
    }

    /// The written sub-ranges of [off, off+len), clipped, in file offsets.
    /// Anything not returned is a sparse hole that would pread as zeros -
    /// the extractor's fallback read-back must never copy those.
    pub fn covered_intervals(&self, off: u64, len: u64) -> Vec<(u64, u64)> {
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
        match self.file.read_ok().as_ref() {
            Some(f) => f.sync_data(),
            None => Ok(()),
        }
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

/// Does this directory live on a case-insensitive filesystem?
///
/// Decided by PROBING, not by the build target. Case sensitivity is a
/// property of the destination VOLUME, and `cfg!(target_os)` gets both
/// interesting cases wrong: the Linux container/NAS build writing to a
/// CIFS/SMB share or an exFAT disk is case-INsensitive, and a macOS build
/// writing to a case-sensitive APFS volume is not. Guessing from the build
/// target means `README` and `readme` are treated as two output files on a
/// volume where they name one - and the second write truncates the first.
///
/// Probes the nearest EXISTING ancestor, so it still answers correctly when
/// the output directory has not been created yet (sensitivity is a mount
/// property, and an ancestor is on the same mount). Falls back to the
/// platform default if no probe can be written.
pub fn case_insensitive_dir(dir: &Path) -> bool {
    let default = cfg!(any(target_os = "macos", target_os = "windows"));
    let mut at = Some(dir);
    while let Some(d) = at {
        if d.is_dir() {
            return probe_case_insensitive(d).unwrap_or(default);
        }
        at = d.parent();
    }
    default
}

/// One probe: write a mixed-case name, then ask for it in lower case. The
/// pid + a counter keep concurrent jobs (and concurrent probes of one dir)
/// from deleting each other's probe file.
fn probe_case_insensitive(dir: &Path) -> Option<bool> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tag = format!(
        ".nzbfast-CaseProbe-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let mixed = dir.join(&tag);
    std::fs::File::create(&mixed).ok()?;
    // `tag` is deliberately mixed-case, so this differs ONLY in case.
    let lowered = dir.join(tag.to_lowercase());
    let insensitive = std::fs::metadata(&lowered).is_ok();
    let _ = std::fs::remove_file(&mixed);
    Some(insensitive)
}

/// Make a filename safe as a single path component. Neutralises path
/// separators and NUL, ASCII control characters (which have no place in a
/// filename and can confuse terminals/loggers), and - so a crafted archive
/// entry or NZB name is portable and can't open a device on Windows - the
/// reserved DOS device names (CON, NUL, COM1..9, LPT1..9, AUX, PRN) and
/// trailing dots/spaces that Windows silently strips.
pub fn sanitize_filename(name: &str) -> String {
    sanitize_filename_for(name, cfg!(windows))
}

/// `sanitize_filename` with the platform as a parameter, so the Windows-only
/// guarantee is asserted by the suite on every host. A `cfg!`-only guard would
/// leave that test vacuous on the Mac and Linux boxes we actually develop and
/// run CI on - the trap an earlier filesystem-behaviour test fell into.
pub fn sanitize_filename_for(name: &str, windows: bool) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            // Windows only: ':' carries path meaning even with no separator.
            // "C:evil.dll" is a DRIVE-RELATIVE path, and `Path::join` DISCARDS
            // the base when the joined name has a prefix - so an archive entry
            // named that way escapes the download directory entirely (it lands
            // in the process's cwd on C:, which for the installed app is the
            // directory holding nzbfast.exe = first in the DLL search order).
            // "payload.mkv:hidden" is the other half: an NTFS alternate data
            // stream, where the payload writes into the stream and the visible
            // file is left 0 bytes. Neither is a legal Windows filename, so
            // mapping it costs nothing there; on Unix ':' is legal and common
            // in release names ("Movie: The Sequel.mkv"), so leave it alone.
            ':' if windows => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    // Windows strips trailing dots and spaces, so "evil. " -> "evil"; strip
    // them ourselves for a stable, portable name (leading dots too: hidden).
    let trimmed = cleaned.trim().trim_matches('.').trim().to_string();
    // The trim chain above is NOT a fixed point: `trim_matches('.')` peels the
    // outer dots, the following `.trim()` then exposes INTERIOR dots as the
    // new ends, and ". .. ." comes out as ".." (". . ." as "."). Both are
    // non-empty, so they used to be returned verbatim - a single path
    // component that escapes its parent. Every caller joins this straight
    // onto a root (`out_dir/<category>/<stem>`) and nothing re-checks
    // containment, so a category or NZB name of ". .. ." put the payload
    // outside the download root, and "Remove + delete files" then ran
    // `remove_dir_all` on that parent. A name that is nothing but dots has no
    // meaning worth preserving.
    if trimmed.is_empty() || trimmed.chars().all(|c| c == '.') {
        return "unnamed".to_string();
    }
    // Reserved DOS device names match case-insensitively on the stem before
    // the first dot (CON, con.txt, and "CON " all open the console device).
    // Normalise for the match: uppercase, map the Unicode superscript digits
    // Windows folds to 1/2/3 (COM\u{B9} opens COM1), and drop a trailing '$'
    // (CLOCK$/CONIN$/CONOUT$ handles).
    let raw_stem = trimmed.split('.').next().unwrap_or(&trimmed).trim();
    let stem: String = raw_stem
        .trim_end_matches('$')
        .chars()
        .map(|c| match c {
            '\u{B9}' => '1', // superscript one
            '\u{B2}' => '2', // superscript two
            '\u{B3}' => '3', // superscript three
            c => c.to_ascii_uppercase(),
        })
        .collect();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK" | "CONIN" | "CONOUT"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && stem.as_bytes()[3].is_ascii_digit()
        && stem.as_bytes()[3] != b'0');
    if reserved {
        format!("_{trimmed}")
    } else {
        trimmed
    }
}

#[cfg(test)]
mod case_probe_tests {
    use super::*;

    /// The probe must agree with what the filesystem ACTUALLY does, on
    /// whatever volume the suite happens to run on. That is the whole point
    /// of probing instead of reading `cfg!(target_os)`: this assertion is
    /// meaningful on case-sensitive Linux CI, on a case-insensitive macOS
    /// dev box, and on a Linux runner whose tmp is a case-insensitive mount -
    /// where the old build-target guess was simply wrong.
    #[test]
    fn case_probe_agrees_with_the_real_filesystem() {
        let dir = std::env::temp_dir().join(format!("nzbfast-case-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Ground truth: write one spelling, ask for the other.
        std::fs::write(dir.join("Ground.txt"), b"x").unwrap();
        let truth = std::fs::metadata(dir.join("ground.txt")).is_ok();

        assert_eq!(
            case_insensitive_dir(&dir),
            truth,
            "probe disagrees with the filesystem at {}",
            dir.display()
        );

        // A not-yet-created output dir must still answer correctly: the
        // probe walks up to the nearest existing ancestor, since case
        // sensitivity is a property of the mount.
        let unborn = dir.join("does").join("not").join("exist");
        assert_eq!(case_insensitive_dir(&unborn), truth);

        // The probe must not leave its scratch file behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("CaseProbe") || n.contains("caseprobe"))
            .collect();
        assert!(leftovers.is_empty(), "probe left {leftovers:?} behind");

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod tests;

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
