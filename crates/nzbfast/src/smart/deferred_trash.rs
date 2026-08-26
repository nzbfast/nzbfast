//! One background worker owns every conversation with the Trash, so no
//! job's finalize ever waits on Finder.
//!
//! A file is handed over by RENAME into a staging folder first - that is
//! the synchronous part, and the reason a directory move immediately
//! after a sweep cannot race the delete: by the time the sweep returns,
//! the file is already out of the tree. The worker then does the real
//! recoverable delete at its leisure, inheriting the bounded call and the
//! unresponsive latch from `remove_user_file`.
//!
//! Lifted out of `smart.rs` under the §91 rule (the size gate forces new
//! code into helpers); the body is verbatim.

use crate::MutexExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use tracing::warn;

static SENDER: OnceLock<mpsc::Sender<PathBuf>> = OnceLock::new();
/// Staging roots this process has already drained of leftovers.
static SEEN: OnceLock<Mutex<std::collections::HashSet<PathBuf>>> = OnceLock::new();
/// Disambiguates same-named files from different jobs (every job has
/// a `.par2`, most have an `.nfo`).
static SEQ: AtomicU64 = AtomicU64::new(0);

fn sender() -> &'static mpsc::Sender<PathBuf> {
    SENDER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<PathBuf>();
        std::thread::Builder::new()
            .name("trash-worker".into())
            .spawn(move || {
                for p in rx {
                    // The setting is re-read at disposal time, not
                    // frozen at park time: the file already left the
                    // user's tree when the sweep decided to delete it,
                    // so only its disposition (Trash vs gone) is at
                    // stake here - and under cfg(test) the default-off
                    // global keeps the suite out of the developer's
                    // real Trash, exactly like every sweep. Read
                    // through cleanup_recoverable: everything staged
                    // here came from a GARBAGE sweep, so its
                    // disposition follows the garbage setting, not
                    // the download-delete one.
                    // NotFound is Ok here (a double-enqueue after a
                    // leftover drain, or Finder finishing behind us).
                    //
                    // A REFUSED delete leaves the file staged, which is
                    // the one place this differs from an inline sweep:
                    // the file has already left the user's tree, so the
                    // log has to name where it is now or it is simply
                    // missing. Staged is still recoverable - a visible
                    // file on the same volume - and the next drain of
                    // this root retries it.
                    //
                    // Which is what `forget` is for. `SEEN` latches a
                    // root at its FIRST stage and every later stage
                    // into it sends only its own file, so "the next
                    // drain of this root" meant the next PROCESS: a
                    // backend that refuses without timing out (the
                    // latch in `remove_swept_file` only covers a
                    // timeout) had every refused file pile up in
                    // `.nzbfast-trash` beside the user's downloads,
                    // with nothing but a warn line to say so - the
                    // Unraid `.Trash-<uid>` complaint in our own
                    // handwriting, which is exactly what this staging
                    // folder was built not to become. Dropping the
                    // root re-arms the drain, so the next stage into it
                    // re-lists the folder and asks again for
                    // everything still sitting there.
                    if let Err(e) = super::remove_user_file(&p, super::cleanup_recoverable()) {
                        warn!(target: "cleanup", "deferred trash {}: {e}", p.display());
                        if let Some(root) = p.parent() {
                            forget(root);
                        }
                    }
                    // Leave nothing behind when the queue drains: an
                    // empty staging folder is clutter beside the
                    // user's downloads. Non-empty simply refuses.
                    if let Some(root) = p.parent() {
                        let _ = std::fs::remove_dir(root);
                    }
                }
            })
            .expect("spawn trash worker");
        tx
    })
}

/// Re-arm the leftover drain for `root`: the next [`stage`] into it
/// re-lists the folder instead of sending only its own file. Called
/// when a disposal was REFUSED, so what it left behind gets asked
/// about again inside this process rather than at the next restart.
fn forget(root: &Path) {
    if let Some(seen) = SEEN.get() {
        seen.lock_ok().remove(root);
    }
}

/// Move `path` into `root` and queue it for the worker. The caller
/// treats any Err as "park unavailable" and deletes inline instead.
pub(super) fn stage(path: &Path, root: &Path) -> std::io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("no file name"))?;
    open_staging_root(root)?;
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut staged_name = std::ffi::OsString::from(format!("{}-{n}-", std::process::id()));
    staged_name.push(name);
    let dest = root.join(staged_name);
    std::fs::rename(path, &dest)?;
    // First touch of a root this process: sweep up leftovers a
    // crashed predecessor parked and never got to. The listing
    // includes `dest`, so nothing extra to send; later touches send
    // just their own file. A racing second stager double-sends at
    // worst, and the worker tolerates NotFound.
    let fresh = SEEN
        .get_or_init(|| Mutex::new(std::collections::HashSet::new()))
        .lock_ok()
        .insert(root.to_path_buf());
    let tx = sender();
    if fresh {
        if let Ok(rd) = std::fs::read_dir(root) {
            for e in rd.flatten() {
                // ONLY WHAT THIS MODULE WRITES. The drain used to send
                // `e.path()` for every entry, of any name and any type,
                // straight to `remove_user_file` - so anything already
                // sitting in `.nzbfast-trash` was adopted as our garbage
                // and moved to the user's Trash, or hard-unlinked when
                // the cleanup setting said Delete (the worker re-reads
                // that flag per file, at disposal time, not at stage
                // time). That folder is a fixed name in the user's own
                // downloads directory, which a NAS share, a sync client,
                // a container bind-mount or a second app can all write
                // to. A directory entry was worse still: `trash_attempt`
                // takes a whole tree in one call.
                if is_staged_entry(&e) {
                    let _ = tx.send(e.path());
                }
            }
        }
    } else {
        let _ = tx.send(dest);
    }
    Ok(())
}

/// Open the staging root, REFUSING one this module does not own.
///
/// `create_dir_all` answers Ok for any existing `is_dir()` path, and
/// `is_dir()` follows symlinks - so a symlink (or a Windows junction) at
/// `.nzbfast-trash` was followed all the way through the rename and the
/// drain below, and the contents of whatever it pointed at were
/// enumerated and disposed of. Measured on this box: create_dir_all,
/// rename and read_dir all succeeded through a symlink and the drain saw
/// the target directory's files.
///
/// `symlink_metadata` is the whole fix: it describes the LINK rather
/// than its target. An Err here is not fatal to the caller - `stage`'s
/// contract is that any Err means "park unavailable", and
/// `remove_swept_file` then deletes inline exactly as it did before this
/// module existed.
fn open_staging_root(root: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(root) {
        Ok(md) if md.file_type().is_dir() => Ok(()),
        Ok(_) => Err(std::io::Error::other(format!(
            "{} is not a directory we own",
            root.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir_all(root),
        Err(e) => Err(e),
    }
}

/// Is this an entry THIS module staged? The name shape `stage` writes -
/// `<pid>-<seq>-<original name>`.
///
/// `git log -S` on the staged-name format shows that prefix is the only
/// shape ever written (it arrived with the feature in `3ef414aaf`), so
/// nothing a real predecessor parked is stranded by this filter.
///
/// DELIBERATELY THE NAME AND NOT THE FILE TYPE, which is the narrower
/// test of the two and is enough: a directory in the root is only
/// drained if it carries this prefix, so an adopted root's own
/// subdirectories are as safe as its files. Adding a
/// regular-file-only test on top would break the one thing the drain
/// still has to do with a non-file - `a_refused_disposal_is_retried_by_
/// the_next_stage` forces its refusal with a staged-shape directory,
/// because that is the only refusal a test can produce without a broken
/// Trash backend, and a refusal is what re-arms this drain.
fn is_staged_entry(e: &std::fs::DirEntry) -> bool {
    let name = e.file_name();
    let Some(name) = name.to_str() else {
        return false;
    };
    let mut parts = name.splitn(3, '-');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(pid), Some(seq), Some(_))
            if !pid.is_empty()
                && pid.bytes().all(|c| c.is_ascii_digit())
                && !seq.is_empty()
                && seq.bytes().all(|c| c.is_ascii_digit())
    )
}
