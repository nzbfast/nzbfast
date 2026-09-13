//! The positioned-IO primitives every writer in this file is built out
//! of, and the process counters that watch them: the descriptor-limit
//! raise, the chunking rule, `pread`/`pwrite` retry loops, and the
//! "is this failure out-of-space" test the budget path branches on.
//!
//! Cut out of `disk.rs` on 7 Sep 2026 (claim `debt-split-hot-files-7sep`)
//! at 3,683 of the size gate's 4,000-line file ceiling - 92% used and,
//! excluding the two PAR2 files a live lane holds, the narrowest row in
//! the tree. Verbatim move; the public items are re-exported beside the
//! `mod` line so every caller keeps its `disk::` path.

use super::*;

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
pub(super) static BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);

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
pub(super) static WRITES_ISSUED: AtomicU64 = AtomicU64::new(0);

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
