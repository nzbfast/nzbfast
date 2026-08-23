//! Housekeeping the daemon does to itself: sweeping spool NZBs no job
//! refers to any more, and restarting in place.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Delete spool NZBs that no job refers to any more.
///
/// The spool copy is written BEFORE `save_queue()` records the job, so a
/// crash between the two orphans the file permanently and nothing ever
/// looked for it. Metadata-only "library" jobs keep theirs by design and
/// are indistinguishable from an orphan by name alone, which is exactly
/// why this works from the live set of referenced paths rather than from
/// any naming rule.
///
/// Only files whose name looks like ours are considered, and only ones
/// older than a grace period, so a job being enqueued right now (spool
/// written, not yet in the queue) cannot be swept out from under itself.
#[cfg(feature = "indexer")]
pub(super) fn sweep_orphan_spool_nzbs(d: &Arc<Daemon>) -> usize {
    const GRACE_SECS: u64 = 3600;
    let referenced: std::collections::HashSet<PathBuf> = d
        .queue
        .lock_ok()
        .iter()
        .chain(d.history.lock_ok().iter())
        .map(|j| j.lock_ok().nzb_path.clone())
        .collect();
    let Ok(rd) = std::fs::read_dir(&d.spool) else {
        return 0;
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0;
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("nzb") {
            continue;
        }
        let Some(stem) = path.file_name().and_then(|x| x.to_str()) else {
            continue;
        };
        if !stem.starts_with("SABnzbd_nzo_nzbfast") {
            continue; // not one of ours: leave it entirely alone
        }
        if referenced.contains(&path) {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age.as_secs() > GRACE_SECS);
        if old && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        info!(target: "spool", "removed {removed} orphaned NZB(s) no job referred to");
    }
    removed
}

/// Replace this process with a fresh copy of the same command line.
///
/// `exec` does not return on success: the kernel swaps the image and the
/// new binary starts from main with our pid. That is what makes this safe
/// for a network daemon - there is no window in which two processes both
/// want the port. The listening socket is closed for us because Rust
/// opens sockets CLOEXEC.
///
/// What that does NOT buy is a port that is free the moment the new image
/// asks for it: the kernel reclaims the closed listener asynchronously,
/// and the replacement gets there first often enough to matter. That race
/// is absorbed at the other end, in `take_listener`'s
/// `bind_past_a_closing_predecessor` - read its note before concluding
/// that a restart can just bind.
///
/// Note it picks up a REPLACED binary on disk, so this doubles as
/// "restart onto the version I just installed".
///
/// If exec fails there is nothing sensible left to do: the queue is
/// already persisted and the daemon is paused, so exiting is closer to
/// the user's intent (they asked for a restart) than carrying on in a
/// half-stopped state. Whatever supervises us - Docker, systemd, the
/// tray - brings it back.
#[cfg(unix)]
pub(super) fn restart_in_place(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
    cwd: Option<&std::path::Path>,
) {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    // exec replaces the image without running any exit handler, so the
    // log tee has to be drained here or the last lines before a restart
    // die in its pipe - and then UNINSTALLED, or the replacement image
    // inherits the dead pipe as its stdout and a launcher-attached
    // daemon.log never sees another line (restore_for_exec drains
    // first).
    nzbkit::logtee::restore_for_exec();
    let err = cmd.exec(); // only returns on failure
    error!(
        target: "restart",
        "could not re-exec {}: {err} - exiting instead",
        exe.display()
    );
    std::process::exit(1);
}

#[cfg(not(unix))]
pub(super) fn restart_in_place(
    _exe: &std::path::Path,
    _args: &[std::ffi::OsString],
    _cwd: Option<&std::path::Path>,
) {
    // Unreachable: the handler refuses restart off Unix before spawning.
    warn!(target: "restart", "not supported on this platform");
}

/// Collect abandoned poster-upload staging files out of the art cache.
///
/// `m_wall_art` writes an upload to [`api::wall::art_staging_name`]'s
/// dotted name and publishes it by rename only once the index row that
/// names it has landed (Codex F-07, 8453aaf0a); every path that gives up
/// on the upload removes its own staging file. What no such path can
/// reach is one left by a process that DIED between the write and the
/// rename, and nothing else ever looked for it: the name is unservable
/// by construction (`art_name_ok` refuses the `-`), no index row names
/// it, and `db_bytes` / `live_bytes` measure the SQLite file rather than
/// this directory - so up to 8 MB per crashed upload accumulates where
/// neither the user nor the index-size cap can see it. `wall_refresh`
/// with `value=all` needs nothing from this: it already
/// `remove_dir_all`s the whole art directory.
///
/// Age, never the pid in the name. The pid is a liveness hint and no
/// more - pids wrap, so a file a crashed daemon left behind can name a
/// live process, and on this side of it a live upload's own staging file
/// carries OUR pid either way. An hour is the sibling spool sweep's
/// grace period and is far past any legitimate window: the only wait
/// between the write and the rename is `index_write_checked`, bounded at
/// `Daemon::HTTP_INDEX_WAIT` (5 s).
#[cfg(feature = "indexer")]
pub(super) fn sweep_abandoned_art_staging(d: &Arc<Daemon>) -> usize {
    const GRACE: std::time::Duration = std::time::Duration::from_secs(3600);
    sweep_art_staging_in(&d.spool.join("art"), GRACE)
}

/// The directory walk behind [`sweep_abandoned_art_staging`], split off
/// the daemon so a test can plant files and name its own threshold.
#[cfg(feature = "indexer")]
fn sweep_art_staging_in(art: &std::path::Path, grace: std::time::Duration) -> usize {
    let Ok(rd) = std::fs::read_dir(art) else {
        return 0; // no art directory yet: nothing to collect
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0;
    for e in rd.flatten() {
        let name = e.file_name();
        if !name.to_str().is_some_and(api::wall::is_art_staging_name) {
            continue;
        }
        // An unreadable mtime and a mtime in the FUTURE both mean leave
        // it: `duration_since` fails on the second rather than
        // saturating, and a clock that stepped backwards is no reason to
        // delete an upload somebody may still be publishing.
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age >= grace);
        if old && std::fs::remove_file(e.path()).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        info!(target: "wall", "removed {removed} abandoned poster upload(s) from the art cache");
    }
    removed
}

#[cfg(all(test, feature = "indexer"))]
mod tests {
    use super::*;

    fn age_to(p: &std::path::Path, secs: u64) {
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
        std::fs::OpenOptions::new()
            .write(true)
            .open(p)
            .expect("open for mtime")
            .set_modified(when)
            .expect("set mtime");
    }

    /// The gap Codex F-07's fixer named and left open: a process that
    /// dies between the staged write and the publishing rename leaves a
    /// file no later request can reach, and until this sweep existed
    /// nothing collected it.
    ///
    /// The pair is the whole test. Collecting the OLD file is only half
    /// of it - a sweep that also took the fresh one would delete the
    /// bytes of an upload currently parked on `index_write_checked`, and
    /// the user would be told their poster was saved over a file that no
    /// longer exists. Everything else in the directory (the live poster,
    /// its thumbnail, a dotted file that is not ours) has to survive
    /// being older than the threshold.
    #[test]
    fn a_stale_art_staging_file_is_collected_and_a_fresh_one_is_not() {
        let dir = std::env::temp_dir().join(format!("nzbfast-artstage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        let live = crate::wall::art_name("m:the matrix:1999", false);
        let stale = dir.join(format!(".{live}.new-1234-56789"));
        let fresh = dir.join(format!(".{live}.new-4321-98765"));
        let poster = dir.join(&live);
        let thumb = dir.join(format!("thumb_{live}"));
        // Dotted, old, and NOT one of ours - the sweep's name filter is
        // what keeps it, not its age.
        let alien = dir.join(".DS_Store");
        for p in [&stale, &fresh, &poster, &thumb, &alien] {
            std::fs::write(p, b"bytes").expect("plant");
        }
        for p in [&stale, &poster, &thumb, &alien] {
            age_to(p, 7200);
        }

        let removed = sweep_art_staging_in(&dir, std::time::Duration::from_secs(3600));

        assert_eq!(removed, 1, "exactly the abandoned staging file");
        assert!(!stale.exists(), "the abandoned staging file survived");
        assert!(fresh.exists(), "an in-flight upload was deleted");
        assert!(poster.exists() && thumb.exists() && alien.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The recogniser and the producer are in `api/wall.rs` together;
    /// this is the round trip that pins them to each other, from the
    /// side that DELETES. A change to the staging format that this stops
    /// matching is a change that starts orphaning files again.
    #[test]
    fn the_sweep_recognises_what_the_uploader_writes() {
        for key in ["m:the matrix:1999", "t:severance", ""] {
            for backdrop in [false, true] {
                let live = crate::wall::art_name(key, backdrop);
                let staged = api::wall::art_staging_name(&live);
                assert!(api::wall::is_art_staging_name(&staged), "{staged}");
                assert!(!api::wall::is_art_staging_name(&live), "{live}");
            }
        }
        for n in [
            "",
            ".",
            ".new-1-2",
            "m_x_jpg.new-1-2",
            ".m_x.jpg.new-1",
            ".m_x.jpg.new-a-2",
            ".m_x.jpg.new-1-",
            ".notes.new-draft",
            ".notes.new-draft-2",
        ] {
            assert!(!api::wall::is_art_staging_name(n), "{n}");
        }
    }
}
