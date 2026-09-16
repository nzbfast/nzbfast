//! Where a slabbed PAR2 solve keeps its rebuilt blocks between the last
//! slab and the patch phase.
//!
//! Cut out of `par2repair.rs` when slabbing landed (9 Sep 2026): the
//! staging choice is self-contained - it touches the rebuilt output and
//! nothing else in the driver - and the driver was at its size ceiling.

use super::reconstruct;
use crate::par2repair::RepairError;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Where a slabbed solve keeps its rebuilt blocks until the patch phase
/// writes them into the members, and the whole memory trade in one type.
///
/// The disk driver's patch phase consumes the WHOLE rebuilt output - it
/// decides in-place versus temp file, copies present blocks over,
/// interleaves adopted ones and renames - so unlike the mapped driver it
/// cannot write each slab straight out as it is solved. The output has
/// to live somewhere between the last slab and the patch, and the three
/// arms are the three answers in order of preference. The plan picks the
/// first that fits; all three answer `write_block_to` identically, so
/// the patch phase cannot tell them apart.
pub(super) enum RebuiltStore {
    /// ONE slab, and the solve's own buffers are the output. Nothing is
    /// copied and nothing is allocated twice - this is the pre-slab
    /// driver exactly, and it is what an ordinary repair takes.
    Whole(Vec<reconstruct::RebuiltBlock>),
    /// Slabbed, with the assembled output resident. Costs `m x bs` of
    /// memory beside the solve's window and no I/O at all, so it is
    /// preferred over spilling whenever the budget has room for it.
    Assembled(Vec<Vec<u8>>),
    /// Slabbed, with the output staged on disk. The last resort, taken
    /// only when `m x bs` will not fit beside the window: it costs one
    /// write and one read of the whole rebuilt payload against the
    /// repair directory, which is far cheaper than not repairing.
    Spill {
        file: File,
        path: PathBuf,
        bs: u64,
        n: usize,
    },
}

impl RebuiltStore {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Whole(v) => v.len(),
            Self::Assembled(v) => v.len(),
            Self::Spill { n, .. } => *n,
        }
    }

    /// The scratch file for a spilled solve, in the repair directory:
    /// the one place already known writable and sized for this payload,
    /// and where these bytes are going anyway. `create_new` for the same
    /// reason the repair temps use it - the name must not be able to
    /// land on an existing file or follow a symlink out of the
    /// directory.
    ///
    /// A predecessor that was SIGKILLed here (an OOM kill is the usual
    /// one) never ran `Drop`, so its file is swept first - see
    /// [`sweep_stale_spills`] for why here and not at repair start.
    ///
    /// A name that is still taken after the sweep never fails the repair
    /// while a free one is left: the next of [`SPILL_TRIES`] names is
    /// tried (`<pid>`, then `<pid>-1`, `<pid>-2`, ...). Two things leave
    /// one taken - a concurrent spill in this process into the same
    /// directory (the daemon runs several jobs), and a stale file the
    /// sweep had to keep because its filesystem has no locks. Only when
    /// every name is taken does the `AlreadyExists` reach the caller.
    pub(super) fn spill(dir: &Path, n: usize, bs: u64) -> Result<Self, RepairError> {
        let own = std::process::id();
        // Sweep, create and lock as ONE step against every other spill in
        // this process. The sweep now considers our own pid's names and
        // tells a live one by its lock, so a concurrent spill must never be
        // seen between its `create_new` and its `try_lock`: unlocked there,
        // it would read as a dead predecessor's file. Spills are rare and
        // the sweep is one `read_dir`, so the wait costs nothing measurable.
        let serial = SPILL_OPEN.lock().unwrap_or_else(|e| e.into_inner());
        sweep_stale_spills(dir, own);
        let mut attempt = 0;
        let (file, path) = loop {
            let path = dir.join(spill_name(own, attempt));
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => break (file, path),
                Err(e)
                    if e.kind() == std::io::ErrorKind::AlreadyExists
                        && attempt + 1 < SPILL_TRIES =>
                {
                    attempt += 1;
                }
                Err(e) => return Err(e.into()),
            }
        };
        if attempt > 0 {
            tracing::info!(
                target: "repair-timing",
                "spill: {attempt} name(s) taken in {}, using {}",
                dir.display(),
                path.display()
            );
        }
        // Held for the file's life and dropped by the kernel however this
        // process dies. It is the sweep's second witness that we are alive:
        // the pid alone cannot see a repair in another pid namespace or on
        // another host sharing this directory, and it is the ONLY witness
        // that tells this process's live spills from a dead predecessor that
        // had our pid. Best effort - a filesystem without locks leaves the
        // pid as the only witness, and the sweep keeps whatever it cannot
        // lock, so this can only make it keep more.
        let _ = file.try_lock();
        drop(serial);
        // Sized up front so a short disk is reported HERE, by name and
        // before any solving, rather than as a truncated write in the
        // middle of the last slab.
        file.set_len(n as u64 * bs)?;
        Ok(Self::Spill { file, path, bs, n })
    }

    /// Park slab `[c0, c0 + w)` of every rebuilt block. Never called on
    /// [`Whole`](Self::Whole), which took the output by move.
    pub(super) fn put_slab(
        &mut self,
        blocks: &[reconstruct::RebuiltBlock],
        c0: usize,
        w: usize,
    ) -> Result<(), RepairError> {
        match self {
            Self::Whole(_) => Ok(()),
            Self::Assembled(v) => {
                for (mi, b) in blocks.iter().enumerate() {
                    v[mi][c0..c0 + w].copy_from_slice(&b[..w]);
                }
                Ok(())
            }
            Self::Spill { file, bs, .. } => {
                for (mi, b) in blocks.iter().enumerate() {
                    crate::disk::write_all_at(file, &b[..w], mi as u64 * *bs + c0 as u64)?;
                }
                if flush_spill_per_slab() {
                    let t = std::time::Instant::now();
                    flush_slab(file);
                    tracing::info!(
                        target: "repair-timing",
                        "spill flush ({} B): {:.2?}",
                        blocks.len() * w,
                        t.elapsed()
                    );
                }
                Ok(())
            }
        }
    }

    /// Write `take` bytes of rebuilt block `mi` into `dst` at `off` -
    /// the one thing the patch phase asks of this type.
    pub(super) fn write_block_to(
        &self,
        mi: usize,
        take: usize,
        dst: &File,
        off: u64,
    ) -> Result<(), RepairError> {
        match self {
            Self::Whole(v) => crate::disk::write_all_at(dst, &v[mi][..take], off)?,
            Self::Assembled(v) => crate::disk::write_all_at(dst, &v[mi][..take], off)?,
            Self::Spill { file, bs, .. } => {
                let mut buf = vec![0u8; take];
                crate::disk::read_exact_at(file, &mut buf, mi as u64 * *bs)?;
                crate::disk::write_all_at(dst, &buf, off)?;
            }
        }
        Ok(())
    }
}

impl Drop for RebuiltStore {
    fn drop(&mut self) {
        if let Self::Spill { path, .. } = self {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Whether each slab's spill write is flushed to disk before the next
/// slab's feed allocates. Latched on first use.
///
/// WHY: `put_slab` runs while the slab's solve buffer is still live, so the
/// pages it dirties are charged beside the bytes they copy. Inside a memory
/// cgroup those dirty pages count against the limit and reclaim cannot free
/// them without I/O; a `-m192` repair was OOM-killed inside 512 MiB with
/// ~453 MiB anonymous and 49 MiB of spill pages dirty
/// (research/PARFAST-512MB-M192-KILL-ATTRIBUTION-2026-09-15.md section 7).
fn flush_spill_per_slab() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        spill_flush_wanted(
            std::env::var("NZBFAST_SPILL_FLUSH").ok().as_deref(),
            crate::mem::cgroup_mem_limit,
        )
    })
}

/// The rule behind [`flush_spill_per_slab`], split out so it is testable
/// without mutating process env. `NZBFAST_SPILL_FLUSH` `1` / `0` force it
/// either way (the bench arms); otherwise the cgroup limit decides, and is
/// only read then.
pub(super) fn spill_flush_wanted(
    env: Option<&str>,
    cgroup_limit: impl FnOnce() -> Option<u64>,
) -> bool {
    match env {
        Some("1") => true,
        Some("0") => false,
        _ => cgroup_limit().is_some(),
    }
}

/// Write the spill's dirty pages out and wait for them: WAIT_BEFORE picks up
/// writeback an earlier slab left in flight, WAIT_AFTER returns only once the
/// pages are clean. No metadata commit and no device flush, which is all a
/// memory bound needs (the cost of those two is measured in
/// `disk/pacing.rs`'s `pace_flush`). Best effort: a failure leaves today's
/// asynchronous write, and a real I/O error surfaces at the read-back.
#[cfg(target_os = "linux")]
fn flush_slab(file: &File) {
    use std::os::unix::io::AsRawFd;
    // SAFETY: takes only the raw fd plus integer arguments; `file` is
    // borrowed across the call, so the fd stays open.
    let rc = unsafe {
        libc::sync_file_range(
            file.as_raw_fd(),
            0,
            0,
            libc::SYNC_FILE_RANGE_WAIT_BEFORE
                | libc::SYNC_FILE_RANGE_WRITE
                | libc::SYNC_FILE_RANGE_WAIT_AFTER,
        )
    };
    if rc != 0 {
        tracing::warn!(
            target: "repair-timing",
            "spill flush: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// No `sync_file_range` off Linux, and no memory cgroup to charge the
/// pages to either.
#[cfg(not(target_os = "linux"))]
fn flush_slab(_file: &File) {}

/// The spill file's name is exactly `SPILL_PREFIX` + decimal pid +
/// `SPILL_SUFFIX`, or on a retry `SPILL_PREFIX` + pid + `-` + attempt +
/// `SPILL_SUFFIX` (attempt 1 and up, no leading zero), and the sweep matches
/// nothing else.
const SPILL_PREFIX: &str = ".nzbfast-repair-slab.";
const SPILL_SUFFIX: &str = ".tmp";

/// How many names one spill tries before the `AlreadyExists` fails the
/// repair. Past the sweep a name is only taken by a concurrent spill in this
/// process or by a stale file on a filesystem without locks, so this is far
/// more than either needs; it exists so a directory that somehow holds every
/// name reports the error rather than looping.
pub(super) const SPILL_TRIES: u32 = 16;

/// Serialises [`RebuiltStore::spill`]'s sweep, create and lock within this
/// process - see there.
static SPILL_OPEN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The spill name for `pid` on retry `attempt` (0 is the first try).
pub(super) fn spill_name(pid: u32, attempt: u32) -> String {
    if attempt == 0 {
        format!("{SPILL_PREFIX}{pid}{SPILL_SUFFIX}")
    } else {
        format!("{SPILL_PREFIX}{pid}-{attempt}{SPILL_SUFFIX}")
    }
}

/// What one sweep removed, and how many stale files it could not.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Swept {
    pub files: usize,
    pub bytes: u64,
    pub failed: usize,
}

/// The pid a spill file name was created for, or `None` when the name is
/// not exactly one of [`spill_name`]'s shapes. Digits only: `u32::from_str`
/// would also take a leading `+`, which no name of ours carries.
fn spill_pid(name: &std::ffi::OsStr) -> Option<u32> {
    let stem = name
        .to_str()?
        .strip_prefix(SPILL_PREFIX)?
        .strip_suffix(SPILL_SUFFIX)?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let pid = match stem.split_once('-') {
        None => stem,
        // A retry's attempt is 1 and up with no leading zero, which also
        // refuses a second `-` and an attempt past `u32`.
        Some((pid, attempt)) => {
            if !digits(attempt) || attempt.starts_with('0') || attempt.parse::<u32>().is_err() {
                return None;
            }
            pid
        }
    };
    if !digits(pid) {
        return None;
    }
    pid.parse().ok()
}

/// Remove the spill files SIGKILLed repairs left in `dir` (measured: 67 to
/// 448 MiB each, research/PARFAST-512MB-CGROUP-REPAIR-2026-09-15.md section
/// 7), and never one that might still be in use.
///
/// WHY AT THE SPILL AND NOT AT REPAIR START: only a spilled solve makes
/// these files, so a directory that has one is a directory whose repair
/// spills, and the retry after an OOM kill is exactly the run that is about
/// to `set_len` another `m x bs` beside it. Sweeping here costs one
/// `read_dir` on a path that is already about to write the whole rebuilt
/// payload to disk; at repair start it would cost that on every repair,
/// the in-memory ones included, to find nothing. The cost is that a stale
/// file waits for the next repair in that directory that spills.
///
/// A file is removed only when BOTH witnesses say its owner is gone:
///  - its pid is dead on this host. Every doubt reads as alive - a pid we
///    may not signal, an error we do not recognise, a pid that does not fit
///    the platform's type - so a pid reused by an unrelated live process
///    keeps the file, never the other way round;
///  - its advisory lock is free. The owner holds one for the file's life
///    (`spill`), which the kernel drops on any death, so this catches the
///    owner the pid cannot see: another pid namespace (a container sharing
///    a bind-mounted download directory) or another host on a network
///    share. A file we cannot open or lock is kept.
///
/// NO AGE FLOOR on mtime. It would guard the same two cases the witnesses
/// already cover, and it would refuse the one case this exists for: a
/// retry that follows its killed predecessor within minutes.
///
/// OUR OWN PID'S NAMES ARE SWEPT TOO, on the lock alone (changed 15 Sep
/// 2026, claim `parfast-spill-name-collision-15sep`; until then they were
/// never touched). The pid cannot help there - it is alive, it is us - but
/// it is exactly the case that matters: a container restarts its daemon on
/// the same small pid every time, so the retry of an OOM-killed repair
/// finds its dead predecessor's file under its OWN pid, and a spill that
/// kept it failed on `create_new`. The lock separates the two owners: a
/// concurrent spill in this process holds its lock through its own open
/// file (flock is per open file description on unix, LockFileEx per handle
/// on Windows, so our fresh open sees `WouldBlock`), and a dead
/// predecessor's lock went with it. [`RebuiltStore::spill`] serialises
/// create-and-lock against this sweep so a live spill is never caught
/// between the two. Where locks do not work at all the file is kept, and
/// the spill takes the next name instead.
///
/// Only regular files directly in `dir` are considered - no recursion, and
/// neither the directory entry nor the open follows a symlink.
///
/// Never fails the repair: every error is logged on `repair-timing` and
/// the sweep moves on.
pub(super) fn sweep_stale_spills(dir: &Path, own: u32) -> Swept {
    let mut out = Swept::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(target: "repair-timing", "spill sweep: cannot list {}: {e}", dir.display());
            return out;
        }
    };
    for entry in entries.flatten() {
        let Some(pid) = spill_pid(&entry.file_name()) else {
            continue;
        };
        // `DirEntry::file_type` does not follow a symlink. Our own pid is
        // always alive, so its names go straight to the lock.
        if (pid != own && pid_alive(pid)) || !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        match remove_if_unlocked(&path) {
            Ok(Some(bytes)) => {
                out.files += 1;
                out.bytes += bytes;
            }
            Ok(None) => {}
            Err(e) => {
                out.failed += 1;
                tracing::warn!(target: "repair-timing", "spill sweep: kept {}: {e}", path.display());
            }
        }
    }
    if out.files > 0 || out.failed > 0 {
        tracing::info!(
            target: "repair-timing",
            "spill sweep: removed {} stale slab file(s), {} bytes, in {} ({} failed)",
            out.files,
            out.bytes,
            dir.display(),
            out.failed
        );
    }
    out
}

/// Remove `path` if it is a regular file whose lock nobody holds, returning
/// its size; `Ok(None)` when somebody holds the lock.
fn remove_if_unlocked(path: &Path) -> std::io::Result<Option<u64>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    // Refuse a symlink swapped in since `read_dir`, and never block opening
    // a FIFO swapped in the same way.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(
        &mut opts,
        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
    );
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Ok(None);
    }
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(std::fs::TryLockError::Error(e)) => return Err(e),
    }
    // Released before the unlink so Windows removes the name at once rather
    // than leaving it delete-pending behind our handle. Nothing can take the
    // lock back in between: the owner is dead, a new process that got its
    // pid cannot `create_new` over a name that still exists, and a spill in
    // this process cannot lock until the sweep that called us returns.
    drop(file);
    std::fs::remove_file(path)?;
    Ok(Some(meta.len()))
}

/// Whether `pid` may be a live process on this host. Errs toward `true`.
#[cfg(unix)]
pub(super) fn pid_alive(pid: u32) -> bool {
    // 0 and anything past `pid_t` are not a process: kill(0, ..) and
    // negative pids address process GROUPS.
    let Ok(p) = libc::pid_t::try_from(pid) else {
        return true;
    };
    if p <= 0 {
        return true;
    }
    // SAFETY: signal 0 delivers nothing; the kernel only checks that the
    // pid exists and that we may signal it.
    if unsafe { libc::kill(p, 0) } == 0 {
        return true;
    }
    // EPERM is a live process we may not signal.
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Whether `pid` may be a live process on this host. Errs toward `true`.
#[cfg(windows)]
pub(super) fn pid_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    // 0 is the System Idle Process, which OpenProcess refuses with the same
    // error as a pid that does not exist.
    if pid == 0 {
        return true;
    }
    // SAFETY: plain FFI; a failed open returns null and sets the last error.
    let h = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if h.is_null() {
        // SAFETY: reads the calling thread's last-error value.
        // ERROR_INVALID_PARAMETER is "no such process"; access denied and
        // anything else is a process that exists or a doubt.
        return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
    }
    // SAFETY: `h` is a process handle we just opened with SYNCHRONIZE; a
    // zero timeout only polls. A process object outlives its process while
    // any handle to it is open, so a signalled handle is an exited process.
    let exited = unsafe { WaitForSingleObject(h, 0) } == WAIT_OBJECT_0;
    // SAFETY: closing a handle we opened.
    unsafe { CloseHandle(h) };
    !exited
}

/// No liveness probe on this platform, so every pid reads as alive and the
/// sweep removes nothing.
#[cfg(not(any(unix, windows)))]
pub(super) fn pid_alive(_pid: u32) -> bool {
    true
}
