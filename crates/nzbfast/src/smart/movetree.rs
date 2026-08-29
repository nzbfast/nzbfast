//! Putting a finished job where it belongs: the move, the copy it falls
//! back to when the destination is a different filesystem, and the
//! durability calls under both.
//!
//! One subject end to end - `move_tree` renames where it can, stages and
//! publishes where it cannot, and `copy_tree` is the same machinery with
//! the source left alone. Everything else here exists for one of those
//! two: the background-I/O demotion a NAS copy runs under, the two error
//! wrappers that name the failing syscall and its operand, the collision
//! reservation, and the fsync ladder.
//!
//! Split out of smart.rs for the size gate (TODO 106); `smart::move_tree`
//! and the other four public doors are re-exported, so no caller spells a
//! new path.

use std::path::{Path, PathBuf};

use tracing::warn;

use super::{is_real_dir, is_real_file};

/// Distinguishes the staging directories of concurrent moves that share a
/// destination. See [`move_tree`].
static MOVE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Dark knob: run the copy half of a move at background disk-I/O
/// priority. `NZBFAST_MOVE_IOPOL=throttle|utility|off` - unset means off
/// until the default is priced (see research/MOVE-INTERFERENCE-2026-08-05.md).
///
/// Only the COPY side is ever demoted. Renames are metadata and never
/// contend with a download's writes; the clone that `std::fs::copy` makes
/// on same-volume APFS is one too (measured: 4 GiB in 0.05 s with zero
/// foreground impact).
fn move_iopol() -> Option<&'static str> {
    match std::env::var("NZBFAST_MOVE_IOPOL").ok()?.as_str() {
        "throttle" => Some("throttle"),
        "utility" => Some("utility"),
        _ => None,
    }
}

/// Lower the calling thread's disk-I/O priority while a bulk copy runs,
/// and RESTORE it on drop: moves run on tokio's blocking pool, whose
/// threads are reused, so a policy left set would demote whatever
/// unrelated work lands on this thread next (a spool write, a directory
/// sweep, another job's unlock).
///
/// macOS: `setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD, ..)` -
/// the mechanism Time Machine and Spotlight use, enforced in the kernel's
/// I/O scheduler. Linux: `ioprio_set` to the idle class, best effort (it
/// only shapes traffic under the CFQ/BFQ/mq-deadline schedulers; on none
/// it is a no-op, which is fine for an opt-in knob). Windows: not
/// implemented - `THREAD_MODE_BACKGROUND_BEGIN` also drops memory and
/// scheduling priority, which is a bigger hammer than this knob promises,
/// so it stays out until someone measures it.
pub(super) struct BackgroundIo {
    #[cfg(target_os = "macos")]
    pub(super) prev: i32,
    // `libc::syscall` is variadic and takes/returns `c_long`, which is
    // 32-bit on 32-bit Linux (armv7). Typing this i64 built fine on
    // x86_64/aarch64 and pushed 8-byte variadic args at a kernel wrapper
    // expecting longs on armv7 - where ARM EABI also 8-byte-aligns them,
    // so the restore would have addressed the wrong argument slots.
    #[cfg(target_os = "linux")]
    prev: libc::c_long,
}

#[cfg(target_os = "macos")]
pub(super) mod iopol {
    pub const IOPOL_TYPE_DISK: i32 = 0;
    pub const IOPOL_SCOPE_THREAD: i32 = 1;
    pub const IOPOL_THROTTLE: i32 = 3;
    pub const IOPOL_UTILITY: i32 = 4;
    unsafe extern "C" {
        pub fn getiopolicy_np(iotype: i32, scope: i32) -> i32;
        pub fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
    }
}

impl BackgroundIo {
    /// Demote this thread per the knob; `None` when the knob is off (or
    /// the platform has nothing to set), which callers hold just the same.
    fn engage() -> Option<Self> {
        let which = move_iopol()?;
        #[cfg(target_os = "macos")]
        {
            let policy = if which == "throttle" {
                iopol::IOPOL_THROTTLE
            } else {
                iopol::IOPOL_UTILITY
            };
            // SAFETY: both calls take three ints and touch no memory of
            // ours. They act on the CALLING thread's own I/O policy,
            // which is what makes the paired restore in `Drop` correct -
            // see this type's doc comment.
            unsafe {
                let prev = iopol::getiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD);
                if iopol::setiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD, policy)
                    != 0
                {
                    return None;
                }
                Some(Self { prev })
            }
        }
        #[cfg(target_os = "linux")]
        {
            // Both spellings demote to the idle class: Linux has no
            // in-between the knob's two names map onto cleanly, and
            // "utility" meaning "idle" beats the surprise of a knob that
            // works on one platform and silently not the other.
            let _ = which;
            const IOPRIO_WHO_PROCESS: libc::c_long = 1;
            const IOPRIO_CLASS_IDLE: libc::c_long = 3;
            // SAFETY: `syscall` is variadic, so the argument types have
            // to match the kernel's ABI by hand: both ioprio calls take
            // `long` arguments and return an int, which is what is
            // passed. Neither reads or writes user memory, and `who = 0`
            // means the calling thread, so this changes nothing outside
            // this process.
            unsafe {
                let prev =
                    libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0 as libc::c_long);
                if libc::syscall(
                    libc::SYS_ioprio_set,
                    IOPRIO_WHO_PROCESS,
                    0 as libc::c_long,
                    IOPRIO_CLASS_IDLE << 13,
                ) != 0
                {
                    return None;
                }
                Some(Self { prev })
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = which;
            None
        }
    }
}

impl Drop for BackgroundIo {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        // SAFETY: three ints, no memory touched, and it acts on the
        // calling thread - the same thread `engage` demoted, since this
        // guard is neither Send nor Sync by construction (it is held
        // across no await and moved to no other thread).
        unsafe {
            let _ =
                iopol::setiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD, self.prev);
        }
        #[cfg(target_os = "linux")]
        // SAFETY: as the macos arm above - a raw syscall taking only
        // integer arguments, touching no memory, and acting on the
        // calling thread, which is the same thread `engage` demoted
        // because this guard is neither Send nor Sync by construction.
        unsafe {
            const IOPRIO_WHO_PROCESS: libc::c_long = 1;
            let _ = libc::syscall(
                libc::SYS_ioprio_set,
                IOPRIO_WHO_PROCESS,
                0 as libc::c_long,
                self.prev,
            );
        }
    }
}

/// A pacing hook for the copy half of a move: called once per copied
/// chunk with its size, and free to sleep. See `Daemon::mover_pacer` -
/// the mover uses it so a NAS copy never slows a live download.
pub type PaceFn<'a> = dyn Fn(u64) + Send + Sync + 'a;

/// Name the failing step and its operand on an io::Error. A move is a
/// dozen different syscalls over two trees, and the bare "Permission
/// denied (os error 13)" one of them bubbled up on 7 Aug 2026 said
/// nothing about WHICH call on WHICH path refused - that cost hours
/// against a guest SMB mount. The original error rides along whole, so
/// the "(os error N)" substring `disk_full_failure` matches stays
/// present, and the kind is preserved for callers that match on it.
fn err_at(op: &str, path: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("{op} {}: {e}", path.display()))
}

/// [`err_at`] for the two-operand steps (copy, rename).
fn err_between(op: &str, from: &Path, to: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        e.kind(),
        format!("{op} {} -> {}: {e}", from.display(), to.display()),
    )
}

/// Move a finished job's tree into `dst`, merging with whatever is
/// already there (a Season folder on a NAS accumulates episodes across
/// jobs). Same-filesystem with no pre-existing destination = one rename;
/// a same-filesystem merge goes entry by entry, which is again nothing
/// but renames. Different filesystems - a NAS share is the whole point
/// of this helper - means the bytes have to be copied, so the tree is
/// staged beside the destination and published only once it is whole:
/// see [`staged_move`]. A name collision keeps the existing destination
/// file and lands ours beside it with a " (n)" suffix - completed
/// downloads are never overwritten. Empty source dirs are removed as
/// they drain.
pub fn move_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    move_tree_paced(src, dst, None)
}

pub fn move_tree_paced(src: &Path, dst: &Path, pace: Option<&PaceFn<'_>>) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| err_at("create dir", parent, e))?;
    }
    if !dst.exists() {
        // Fast path: same filesystem, nothing to merge.
        if std::fs::rename(src, dst).is_ok() {
            return Ok(());
        }
    }
    // Staging is a sibling of the destination, so it shares the
    // destination's filesystem and everything published out of it is a
    // plain rename.
    //
    // The name identifies this MOVE, not the destination. Two jobs can
    // share a `dst` - with TV filing, every episode of a season lands in
    // the same `Season NN` folder - and their post-processing tails run
    // concurrently. A name derived from `dst` alone gave both of them one
    // staging directory, and each cleared it before staging its own tree:
    // one payload was published into the other's place, the loser's source
    // was then drained, and both jobs reported success. A hard kill now
    // leaves its staging directory behind rather than having the next move
    // to the same folder clear it, which costs disk space until it is
    // deleted and never costs a payload.
    let mut staging_name = std::ffi::OsString::from(".");
    staging_name.push(
        dst.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("job")),
    );
    staging_name.push(format!(
        ".moving.{}.{}",
        std::process::id(),
        MOVE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let staging = dst.with_file_name(staging_name);
    if !rename_reaches(src, &staging) {
        return staged_move(src, dst, &staging, pace);
    }
    std::fs::create_dir_all(dst).map_err(|e| err_at("create dir", dst, e))?;
    for entry in std::fs::read_dir(src).map_err(|e| err_at("read dir", src, e))? {
        let entry = entry.map_err(|e| err_at("read dir", src, e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        // `is_real_dir`, not `is_dir`: the latter follows symlinks, so a
        // job containing `extras -> /external` used to make this function
        // read_dir THROUGH the link and move the target's children into the
        // completed destination, deleting them from where they actually
        // lived. A link is moved as the link object it is, never walked.
        if is_real_dir(&from) {
            move_tree_paced(&from, &to, pace)?;
        } else {
            let target = reserve_free_name(&to)?;
            if std::fs::rename(&from, &target).is_err() {
                if is_symlink(&from) {
                    // Cross-device and a symlink: `copy` would follow it and
                    // write the TARGET's bytes here, so leave the link where
                    // it is rather than silently turning it into a fat copy
                    // of something outside the job.
                    let _ = std::fs::remove_file(&target); // our placeholder
                    warn!(
                        target: "move",
                        "left symlink in place (cross-device): {}",
                        from.display()
                    );
                    continue;
                }
                // One filesystem and the rename STILL failed, so fall back
                // to a copy for this file alone; make it durable before the
                // source goes. A failure in either half leaves `target`
                // holding zero, partial or unflushed bytes under the
                // payload's own file name, and an importer scanning the
                // destination would take that as the episode. The source
                // has not been touched yet at this point, so dropping our
                // half-written copy can never cost the only copy - the file
                // simply has not moved.
                let _bg = BackgroundIo::engage();
                let copied = copy_verified_paced(&from, &target, pace)
                    .and_then(|()| sync_written_file(&target));
                if let Err(e) = copied {
                    if let Err(rm) = std::fs::remove_file(&target) {
                        // Whatever broke the copy can break the unlink too
                        // (a share that dropped answers both with EIO), so
                        // say the fragment may still be sitting there.
                        warn!(
                            target: "move",
                            "could not remove the partial copy {}: {rm}",
                            target.display()
                        );
                    }
                    return Err(e);
                }
                std::fs::remove_file(&from)
                    .map_err(|e| err_at("remove copied source", &from, e))?;
            }
        }
    }
    let _ = std::fs::remove_dir(src); // only removes if now empty
    Ok(())
}

/// Can a rename move things out of `src` and into `probe_dst`'s directory,
/// or do the two sit on different filesystems?
///
/// Asked with an EMPTY directory of our own, never with payload: the probe
/// is created inside `src` and renamed to where the staging directory would
/// go. It decides only which of two correct routes [`move_tree`] takes, so
/// a wrong answer costs speed, not data - which is why this asks the
/// filesystem the exact question rather than approximating it from device
/// numbers that Windows does not expose.
fn rename_reaches(src: &Path, probe_dst: &Path) -> bool {
    let probe = src.join(".nzbfast-moving-probe");
    let _ = std::fs::remove_dir(&probe); // abandoned by an earlier crash
    if std::fs::create_dir(&probe).is_err() {
        return false;
    }
    let same = std::fs::rename(&probe, probe_dst).is_ok();
    let _ = std::fs::remove_dir(if same { probe_dst } else { &probe });
    same
}

/// The cross-device half of [`move_tree`]: copy the whole tree into
/// `staging`, publish it, and only then delete the source.
///
/// Copying file by file straight into `dst` is what used to SPLIT a payload
/// across two filesystems. Each source file was deleted the moment its copy
/// landed, so a failure partway (ENOSPC, EIO, a share that dropped) left
/// some episodes on the NAS and the rest in the download folder, while the
/// caller reported one directory as the job's home - an importer then took
/// whichever fragment it was pointed at as the whole release. Staging keeps
/// the source whole until the destination is, so a failure costs the move
/// and never the payload. It is the shape the spool migration already uses.
pub(super) fn staged_move(
    src: &Path,
    dst: &Path,
    staging: &Path,
    pace: Option<&PaceFn<'_>>,
) -> std::io::Result<()> {
    // Held for the whole copy: this is the multi-GB bulk transfer that
    // competes with a live download's write side. Dropped before the
    // publish renames and the source drain - they are metadata and the
    // download should not have to wait behind an idle-class unlink queue.
    let bg = BackgroundIo::engage();
    let mut copied = std::collections::HashSet::new();
    if let Err(e) = copy_tree_into_paced(src, staging, &mut copied, pace).and_then(|()| {
        drop(bg);
        publish_staged(staging, dst)
    }) {
        // Nothing in `src` has been deleted, so the payload is still whole
        // where it was and the caller is right to report the move as not
        // taken. Drop what is still staged; note this cannot un-publish a
        // merge that failed part way, so `dst` may keep the entries that
        // were already renamed into it, under the payload's own names.
        // They are copies - the originals are all still in `src`.
        let _ = std::fs::remove_dir_all(staging);
        return Err(e);
    }
    drain_copied(src, &copied);
    Ok(())
}

/// Publish a staged tree into its final home. `staging` is a sibling of
/// `dst`, so every step is a same-filesystem rename: ONE for the whole
/// directory when nothing is there yet, and otherwise entry by entry so a
/// Season folder already holding episodes keeps them.
pub(super) fn publish_staged(staging: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() && std::fs::rename(staging, dst).is_ok() {
        // Persist the name before the caller deletes the source.
        return sync_dir(dst.parent().unwrap_or(dst));
    }
    std::fs::create_dir_all(dst).map_err(|e| err_at("create dir", dst, e))?;
    for entry in std::fs::read_dir(staging).map_err(|e| err_at("read dir", staging, e))? {
        let entry = entry.map_err(|e| err_at("read dir", staging, e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if is_real_dir(&from) {
            publish_staged(&from, &to)?;
        } else {
            let target = reserve_free_name(&to)?;
            if let Err(e) = std::fs::rename(&from, &target) {
                let _ = std::fs::remove_file(&target); // our placeholder
                return Err(err_between("publish rename", &from, &target, e));
            }
        }
    }
    let _ = std::fs::remove_dir(staging); // only removes if now empty
    sync_dir(dst)
}

/// Delete what [`copy_tree`] reproduced at the destination and leave what
/// it skipped. Symlinks are the reason it is not a `remove_dir_all`:
/// `copy_tree` does not follow them, so the link object here is still the
/// only one and stays put, exactly as a cross-device move has always left
/// it.
///
/// `copied` is the manifest [`copy_tree_into_paced`] filled in, and ONLY
/// those files are deleted. Re-walking the source instead deleted whatever
/// the walk found, including files that appeared AFTER the copy pass - a
/// post-processing script's output, a user's drop-in - which were therefore
/// deleted having never been copied anywhere, so they existed nowhere
/// afterwards. Anything not in the manifest stays where it is.
///
/// Best effort by design. The payload is already whole and durable at the
/// destination by the time this runs, so a source file that will not go is
/// clutter to report - failing the move over it would tell the caller
/// nothing had moved when everything had.
pub(super) fn drain_copied(src: &Path, copied: &std::collections::HashSet<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(src) else {
        return;
    };
    for entry in rd.flatten() {
        let from = entry.path();
        if is_real_dir(&from) {
            drain_copied(&from, copied);
        } else if is_real_file(&from) {
            if !copied.contains(&from) {
                warn!(
                    target: "move",
                    "appeared after the copy, so it stays where it is: {}",
                    from.display()
                );
                continue;
            }
            if let Err(e) = std::fs::remove_file(&from) {
                warn!(
                    target: "move",
                    "copied, but the source stays: {} ({e})",
                    from.display()
                );
            }
        } else {
            warn!(
                target: "move",
                "left symlink in place (cross-device): {}",
                from.display()
            );
        }
    }
    let _ = std::fs::remove_dir(src); // only removes if now empty
}

/// Recursively COPY `src` into `dst`, fsyncing every file as it lands.
///
/// The copying twin of [`move_tree`], and the engine of its cross-device
/// path: for anything that must be able to fail without having touched the
/// source. Deleting each source file as soon as its copy is durable is what
/// leaves half the state at the destination and half at the source with no
/// single complete copy, so callers copy first and publish second.
/// Symlinks are skipped rather than followed, for the reason in
/// [`is_real_dir`].
pub fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    copy_tree_into_paced(src, dst, &mut std::collections::HashSet::new(), None)
}

/// [`copy_tree`], recording every SOURCE file it actually reproduced in
/// `copied`. The record is what lets [`drain_copied`] delete exactly what
/// was copied and nothing that arrived later.
pub(super) fn copy_tree_into_paced(
    src: &Path,
    dst: &Path,
    copied: &mut std::collections::HashSet<PathBuf>,
    pace: Option<&PaceFn<'_>>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dst).map_err(|e| err_at("create dir", dst, e))?;
    for entry in std::fs::read_dir(src).map_err(|e| err_at("read dir", src, e))? {
        let entry = entry.map_err(|e| err_at("read dir", src, e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if is_real_dir(&from) {
            copy_tree_into_paced(&from, &to, copied, pace)?;
        } else if is_real_file(&from) {
            copy_verified_paced(&from, &to, pace)?;
            sync_written_file(&to)?;
            copied.insert(from);
        }
    }
    sync_dir(dst)
}

/// `std::fs::copy`, refusing to call a short copy done. The source is
/// only ever deleted against what this wrote, so the check runs before
/// anything downstream can trust the destination: a filesystem that
/// silently truncated (an SMB share at quota, a FUSE layer that dropped
/// a write) must fail the move while the source is still whole, not be
/// discovered by the player. Sizes, not hashes - the byte-for-byte cost
/// belongs to the transports that are known to lie, and none of the
/// failures seen in the field so far kept the length intact.
/// [`copy_verified`], chunked and paced when a hook is supplied. The
/// manual 4 MiB loop exists for the pacing case only: fs::copy is one
/// opaque syscall-driven burst, and a cap that cannot breathe between
/// chunks is not a cap. No pace = the fast path, unchanged.
pub(super) fn copy_verified_paced(
    from: &Path,
    to: &Path,
    pace: Option<&PaceFn<'_>>,
) -> std::io::Result<()> {
    let Some(pace) = pace else {
        return copy_verified(from, to);
    };
    use std::io::{Read, Write};
    let mut src = std::fs::File::open(from).map_err(|e| err_at("open source", from, e))?;
    let mut dst = std::fs::File::create(to).map_err(|e| err_at("create", to, e))?;
    let mut buf = vec![0u8; 4 << 20];
    let mut wrote: u64 = 0;
    loop {
        let n = src.read(&mut buf).map_err(|e| err_at("read", from, e))?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])
            .map_err(|e| err_at("write", to, e))?;
        wrote += n as u64;
        pace(n as u64);
    }
    dst.flush().map_err(|e| err_at("write", to, e))?;
    drop(dst);
    let want = std::fs::metadata(from)
        .map_err(|e| err_at("stat source", from, e))?
        .len();
    if wrote != want {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "short copy {} -> {}: wrote {wrote} of {want} bytes",
                from.display(),
                to.display()
            ),
        ));
    }
    Ok(())
}

pub(super) fn copy_verified(from: &Path, to: &Path) -> std::io::Result<()> {
    let wrote = std::fs::copy(from, to).map_err(|e| err_between("copy", from, to, e))?;
    let want = std::fs::metadata(from)
        .map_err(|e| err_at("stat source", from, e))?
        .len();
    if wrote != want {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "short copy {} -> {}: wrote {wrote} of {want} bytes",
                from.display(),
                to.display()
            ),
        ));
    }
    Ok(())
}

/// fsync a directory, so the names created in it survive power loss.
///
/// Syncing a file persists its CONTENTS; the directory entry pointing at it
/// is separate metadata and needs its own flush. Without this a rename can be
/// reported successful and still be absent after a crash. Unix only - Windows
/// has no directory handle to flush this way, and `File::open` on a directory
/// fails there, so it is a deliberate no-op.
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(|e| err_at("fsync dir", dir, e))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// fsync a file we have just written, addressed by its path.
///
/// The handle has to be WRITABLE. Unix flushes a read-only descriptor quite
/// happily, so `File::open(p)?.sync_all()` looked correct here for as long
/// as this code existed - but Windows answers `FlushFileBuffers` on a
/// read-only handle with ERROR_ACCESS_DENIED, and that one difference broke
/// every cross-device move and the spool migration on Windows. `copy_tree`
/// failed on the FIRST file it copied, so `staged_move` returned "Access is
/// denied." having moved nothing, and `spool_dir` logged that it could not
/// move the daemon state out of the download folder and carried on using
/// the old location. Neither ever lost a byte - both are written to fail
/// with the source still whole - but on Windows neither could ever succeed,
/// and a download folder and a library on two different drives is the
/// ordinary Windows setup.
///
/// Measured directly on x86-64 Windows (rustc 1.97.1): a read-only handle
/// gives os error 5, a writable one gives Ok(()).
fn sync_written_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // Deliberately unchanged: a read-only descriptor is a valid fsync
        // target here, and it flushes a mode-444 file, which opening for
        // write would not even be allowed to touch.
        std::fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| err_at("fsync", path, e))
    }
    #[cfg(not(unix))]
    {
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(f) => return f.sync_all().map_err(|e| err_at("fsync", path, e)),
            // `fs::copy` reproduces the source's read-only ATTRIBUTE, and
            // such a file cannot be flushed through ANY handle on Windows.
            // Clear the bit, flush, put it back: we own this copy, and
            // skipping the flush instead would hand the caller an
            // undurable destination to delete the source against, which is
            // the one failure staging exists to prevent.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(e) => return Err(e),
        }
        let md = std::fs::metadata(path).map_err(|e| err_at("stat", path, e))?;
        let mut relaxed = md.permissions();
        // clippy::permissions_set_readonly_false objects that this leaves a
        // file world-writable, which is a statement about Unix modes, and
        // this arm is `cfg(not(unix))`. On Windows it clears the read-only
        // ATTRIBUTE - the entire point of the block - and the original
        // permissions go back on after the flush. std exposes no other
        // stable way to touch that attribute.
        #[expect(clippy::permissions_set_readonly_false)]
        relaxed.set_readonly(false);
        std::fs::set_permissions(path, relaxed).map_err(|e| err_at("set permissions", path, e))?;
        let flushed = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| err_at("fsync", path, e));
        std::fs::set_permissions(path, md.permissions())
            .map_err(|e| err_at("set permissions", path, e))?;
        flushed
    }
}

/// Is this path a symlink (rather than what it points at)?
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// CLAIM the first free variant of `path`: itself, else "stem (2).ext",
/// "stem (3).ext", … The returned path exists as an empty file that this
/// call created and therefore owns.
///
/// Reserving matters because `exists()` is not an ownership primitive. The
/// old version only *looked* for a free name, so two movers racing the same
/// destination both saw "free" and both picked it: on unix the second
/// `rename` silently replaced the first's bytes, and both sources were then
/// deleted, so one payload was gone with both movers reporting success.
/// `create_new` is atomic, so exactly one caller can win each name.
pub(super) fn reserve_free_name(path: &Path) -> std::io::Result<PathBuf> {
    use std::io::ErrorKind;
    let mut candidate = path.to_path_buf();
    let stem = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let parent = path.parent().unwrap_or(Path::new(""));
    for n in 2.. {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(_) => return Ok(candidate),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                candidate = parent.join(format!("{stem} ({n}){ext}"));
            }
            Err(e) => return Err(err_at("reserve name", &candidate, e)),
        }
    }
    unreachable!()
}
