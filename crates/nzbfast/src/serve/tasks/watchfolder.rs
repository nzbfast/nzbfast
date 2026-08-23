//! The watch folder: the scan that turns dropped .nzb files into jobs,
//! the six states a file can end up in when it does NOT become one, and
//! the quarantine directory unusable files are moved into.
//!
//! Four of the six [`watchfail`] states are SUCCESSES - the release is
//! queued or was downloaded weeks ago and only the file on disk is
//! unresolved - which is why the strings and the classifier that reads
//! them back live in one place here.
//!
//! Split out of `serve/tasks.rs` whole (TODO 106) - the code is verbatim,
//! only visibility changed, plus one doc comment reunited with the
//! function it describes (`watch_fail_kind`'s summary had been stranded
//! above `watch_fail_id` by an earlier move).

use super::*;

/// The reasons a watch-folder file ends up listed rather than ingested.
///
/// Written as constants, and read back by [`watch_fail_kind`], because
/// four of the six are SUCCESSES: the release is queued (or was
/// downloaded weeks ago) and only the file on disk is unresolved. One
/// sentence for all six told a user their download "couldn't be read"
/// when it had in fact already finished, and offered a Delete that is
/// harmless for some of them and destroys the only copy for others.
/// Keeping the strings and the classifier in one place is what stops the
/// two drifting: an edit to a message that forgets the mapping would
/// silently demote that state back to the generic sentence.
pub(in crate::serve) mod watchfail {
    /// No closing `</nzb>`, and the file has stopped growing. NOT
    /// ingested - the only state where the user must act on the file.
    pub(crate) const TRUNCATED: &str = "truncated: no closing </nzb>";
    /// The identical NZB is already sitting in the queue.
    pub(crate) const ALREADY_QUEUED: &str = "already queued";
    /// ...and this one already finished downloading.
    pub(crate) const ALREADY_DONE: &str = "already downloaded";
    /// Queued, but the queue record could not be persisted, so the file
    /// is deliberately KEPT as the recovery copy.
    pub(crate) const UNSAVED: &str = "queued, but queue.json could not be written";
    /// Queued and durable, but the source file could not be removed.
    /// Prefix: the OS error is appended.
    pub(crate) const KEPT: &str = "queued, but the file could not be removed";
}

/// Opaque, stable identity for one tracked watch-folder rejection
/// (Codex sweep 2, 3 Aug L1).
///
/// The queue payload names these rows by basename, which is not an
/// identity: change the watch directory and a rejected `same.nzb` can
/// be tracked in both the old and the new one, leaving the user two
/// identical-looking rows and the delete handler picking whichever
/// HashMap iteration reached first. A digest of the FULL path names the
/// row exactly. Truncated to 16 hex chars - this is a handle for a set
/// with a handful of members, not a credential - and deliberately not
/// the path itself, which the browser has no business holding.
pub(crate) fn watch_fail_id(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(path.as_os_str().as_encoded_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

/// Which of the six [`watchfail`] states a listed file is in, as a token
/// the dashboard switches on. `"rejected"` is the sixth: an `enqueue`
/// error, i.e. the only case besides `truncated` where the file really
/// could not be used.
pub(crate) fn watch_fail_kind(msg: &str) -> &'static str {
    if msg == watchfail::TRUNCATED {
        "truncated"
    } else if msg == watchfail::ALREADY_QUEUED {
        "queued"
    } else if msg == watchfail::ALREADY_DONE {
        "done"
    } else if msg == watchfail::UNSAVED {
        "unsaved"
    } else if msg.starts_with(watchfail::KEPT) {
        "kept"
    } else {
        "rejected"
    }
}

/// Is this listed file's release actually in hand? True for the four
/// states where the queue (or history) owns it and only the file on disk
/// is unfinished business - which is exactly the set where deleting the
/// file is safe and "couldn't be read" is a lie.
pub(crate) fn watch_fail_ingested(kind: &str) -> bool {
    matches!(kind, "queued" | "done" | "unsaved" | "kept")
}

/// The quarantine folder [`quarantine_rejected`] moves unusable files
/// into, directly under the watch root. Never scanned, even with
/// recursion on - a moved file must not come straight back as a job in
/// a "rejected" category.
const WATCH_REJECT_DIR: &str = "rejected";

/// Every .nzb under `root`, paired with the category its location
/// implies: with `recursive` on, the FIRST subfolder's name
/// (watch/tv/x.nzb -> "tv", however deep the file sits); "" for a file
/// at the root, and always "" when recursion is off (the old
/// single-directory read). The first-level [`WATCH_REJECT_DIR`] is
/// skipped, symlinked directories are not followed (cycle safety), and
/// the walk stops 6 levels down so a runaway tree costs stats, not the
/// pass.
fn watch_scan(root: &std::path::Path, recursive: bool) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if !recursive || depth >= 6 {
                    continue;
                }
                if depth == 0
                    && p.file_name()
                        .is_some_and(|n| n.eq_ignore_ascii_case(WATCH_REJECT_DIR))
                {
                    continue;
                }
                stack.push((p, depth + 1));
                continue;
            }
            if !p.extension().is_some_and(|x| x.eq_ignore_ascii_case("nzb")) {
                continue;
            }
            let category = if depth == 0 {
                String::new()
            } else {
                p.strip_prefix(root)
                    .ok()
                    .and_then(|r| r.components().next())
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .unwrap_or_default()
            };
            out.push((p, category));
        }
    }
    out
}

/// Move a rejected .nzb into `<root>/rejected/`, with a `.why.txt`
/// beside it explaining the failure, and return the new path. The
/// rename stays on one filesystem (the quarantine lives inside the
/// watch root), and a name collision gets " (2)" rather than an
/// overwrite - the colliding file is a DIFFERENT bad file the user has
/// not looked at yet.
fn quarantine_rejected(
    root: &std::path::Path,
    p: &std::path::Path,
    reason: &str,
) -> std::io::Result<PathBuf> {
    let qdir = root.join(WATCH_REJECT_DIR);
    std::fs::create_dir_all(&qdir)?;
    let name = p
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let mut dest = qdir.join(&name);
    let mut n = 1u32;
    while dest.exists() && n < 1000 {
        n += 1;
        dest = qdir.join(format!("{} ({n}).nzb", name.trim_end_matches(".nzb")));
    }
    if dest.exists() {
        // The counter ran out with every candidate taken. Falling
        // through renamed ONTO " (1000)" - POSIX replaces that
        // incumbent (a different bad file the user has not seen),
        // Windows errors and leaves this one re-scanned forever.
        // Uniquify by clock instead; nanoseconds cannot collide with
        // the counter names or realistically with each other.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        dest = qdir.join(format!("{} ({nanos}).nzb", name.trim_end_matches(".nzb")));
    }
    std::fs::rename(p, &dest)?;
    // Best-effort: the move is the point; the note is a courtesy for
    // whoever opens the folder without the dashboard.
    let _ = std::fs::write(
        dest.with_extension("nzb.why.txt"),
        format!(
            "nzbfast could not use this file: {reason}\n\
             It was moved here from {}.\n\
             Save a corrected copy into the watch folder to try again.\n",
            p.display()
        ),
    );
    Ok(dest)
}

/// The queue owns this release now, so the user's source file goes.
///
/// To the Trash, not gone: this is the user's own .nzb, and "I dropped it
/// in and now I cannot find it again" is a real complaint. If it cannot be
/// removed at all (read-only bind mount, no unlink right on the share) it
/// has to be remembered exactly like a failure is - otherwise every pass
/// re-reads the same bytes and the release is queued, and fetched from the
/// provider, all over again, once every 5 s, forever.
///
/// Returns whether the pass should forget `p`'s signature. A re-drop of the
/// same .nzb at the same path would otherwise match the record just
/// ingested (mtime-preserving copies reproduce it exactly) and count as
/// settled on sight - the very thing the pass memory exists to stop.
fn consume_source_file(d: &Arc<Daemon>, p: &std::path::Path, sig: (u64, u64), name: &str) -> bool {
    // One more identity check first. The signature was last confirmed
    // before the parse, the enqueue and a durable queue write, and what
    // gets deleted here is a PATHNAME - so a producer that atomically
    // renamed a DIFFERENT x.nzb over the path in that window had its
    // replacement trashed, unread, while the old bytes went to the queue.
    // The replacement is left exactly where it is and the next pass picks
    // it up (Codex sweep 12 Aug F7).
    if watch_sig(p) != Some(sig) {
        info!(
            target: "watch",
            "{} was replaced after {name} was queued - leaving the new file for \
             the next pass",
            p.display()
        );
        d.watch_failed_remove(p);
        return true;
    }
    match crate::smart::remove_user_file(p, crate::smart::delete_to_trash()) {
        Ok(_) => {
            d.watch_failed_remove(p);
            true
        }
        Err(err) => {
            warn!(
                target: "watch",
                "{name} queued, but {} could not be removed - {err}; delete it \
                 yourself or it stays listed",
                p.display()
            );
            d.watch_failed_insert(
                p.to_path_buf(),
                (
                    sig.0,
                    sig.1,
                    format!("{}: {err}", watchfail::KEPT),
                    String::new(),
                ),
            );
            false
        }
    }
}

/// Watch-folder poller. Always running; the folder itself is a live
/// setting (None = idle), so the dashboard can point it elsewhere or
/// turn it off without a restart.
pub(in crate::serve) fn spawn_watch_folder(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        // (mtime, len) of every .nzb this folder held on the previous
        // pass. A file copied in over SMB/NFS is visible from its first
        // byte, and a half-written NZB still parses - the XML reader
        // simply stops at the last whole <file> - so reading on sight
        // queued a fraction of the release and then deleted the user's
        // original. A file is ingested once it is provably whole (its
        // closing </nzb> is on disk) or, failing that, once its size and
        // mtime have held still for a full pass. The
        // in-progress suffixes (.part/.tmp/.crdownload/.filepart) need
        // no list of their own - they aren't .nzb, so the extension
        // gate drops them until the writer renames.
        let mut prev_pass: std::collections::HashMap<PathBuf, (u64, u64)> =
            std::collections::HashMap::new();
        // Keep-mode processed marker: path -> (mtime, len, nzb_sha) of
        // every file ingested while "keep the .nzb" was on. Deleting
        // the file WAS the durable consumed-marker; when the file
        // stays, this set is what stops the next pass - and the next
        // daemon START, hence persisted beside the spool - from
        // re-downloading the whole folder. A re-save changes the
        // signature and falls out of the set, so "re-save it to retry"
        // stays true in keep mode too. The sha is recorded for
        // debugging only; skipping compares (mtime, len) alone, so a
        // settled file costs a stat per pass, never a read.
        let seen_path = d.spool.join("watch_seen.json");
        let mut watch_seen: std::collections::HashMap<PathBuf, (u64, u64, String)> =
            std::fs::read(&seen_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
        fn save_watch_seen(
            path: &std::path::Path,
            seen: &std::collections::HashMap<PathBuf, (u64, u64, String)>,
        ) {
            // Best-effort like save_queue: a failed write costs one
            // re-dedupe against the queue/history shas after a restart,
            // never a wrong download.
            if let Ok(b) = serde_json::to_vec(seen) {
                let _ = std::fs::write(path, b);
            }
        }
        // Filesystem notifications, so a drop is picked up in the time
        // it takes to write the file rather than on the next poll.
        //
        // Kept deliberately dumb: every event just pokes the same loop,
        // which then does the identical pass it would have done on its
        // timer. Nothing about correctness depends on the watcher - it
        // only decides WHEN a pass happens - so a platform where it
        // silently delivers nothing degrades to exactly the old
        // behaviour rather than to a folder that is never read.
        //
        // Re-armed whenever the folder changes (it is a live setting,
        // and it starts out unset on a fresh install), and dropped with
        // the old path so a stale watch cannot keep firing.
        let mut _fs_watch: Option<notify::RecommendedWatcher> = None;
        // The path AND the recursion mode it was armed with: flipping
        // watch_recursive re-arms just like pointing at a new folder,
        // or a subfolder drop would sit until the polling backstop.
        let mut watched: Option<(PathBuf, bool)> = None;
        loop {
            let dir = d.watch_dir.lock_ok().clone();
            let recursive = d.watch_recursive.load(Ordering::Relaxed);
            let want = dir.clone().map(|p| (p, recursive));
            // (Re)arm the filesystem watch when the configured folder
            // changes. Failure is not fatal and not even noteworthy on
            // a share: the poll below still runs.
            // Re-arm when the folder changes, AND retry while unarmed:
            // a failed attach used to latch forever (the arm only ran on
            // a config change), which left the watcher dead and the
            // folder on pure 5 s polling for the daemon's whole life -
            // exactly the "drops feel slow" a user reports. The warning
            // still prints once per configured path, not once per retry.
            if watched != want || (_fs_watch.is_none() && dir.is_some()) {
                let fresh = watched != want;
                _fs_watch = None;
                watched = want.clone();
                if let Some(ref path) = dir {
                    // FSEvents (and inotify by-path lookups) want an
                    // absolute path: the daemon is launched with
                    // `--watch watch`, and the bare relative form failed
                    // with "No path was found" while the poll fallback
                    // masked it. Canonicalize, falling back to cwd-join
                    // for a folder that does not exist yet.
                    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| {
                        std::env::current_dir()
                            .map(|c| c.join(path))
                            .unwrap_or_else(|_| path.clone())
                    });
                    let d2 = d.clone();
                    match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                        if res.is_ok() {
                            d2.watch_scan_now.notify_one();
                        }
                    }) {
                        Ok(mut w) => {
                            use notify::Watcher;
                            let mode = if recursive {
                                notify::RecursiveMode::Recursive
                            } else {
                                notify::RecursiveMode::NonRecursive
                            };
                            match w.watch(&abs, mode) {
                                Ok(()) => {
                                    _fs_watch = Some(w);
                                    info!(
                                        target: "watch",
                                        "watching {} - drops are picked up on the event, \
                                         with a {}s polling backstop",
                                        abs.display(),
                                        d.watch_interval_secs.load(Ordering::Relaxed)
                                    );
                                }
                                Err(e) if fresh => warn!(
                                    target: "watch",
                                    "{} is polled every {}s - the filesystem \
                                     watcher could not attach ({e}); this is normal on a \
                                     network share (still retrying quietly)",
                                    abs.display(),
                                    d.watch_interval_secs.load(Ordering::Relaxed)
                                ),
                                Err(_) => {}
                            }
                        }
                        Err(e) => {
                            if fresh {
                                warn!(target: "watch", "no filesystem watcher ({e}); polling");
                            }
                        }
                    }
                }
            }
            if let Some(dir) = dir {
                // The pass is all stats and whole-file reads - and the
                // watched folder is often an SMB/NFS share, where any of
                // them can stall. It runs on a tokio worker, so demote
                // the thread for the pass (there is no await anywhere
                // inside it).
                crate::persist::blocking_db(|| {
                    {
                        let mut this_pass = std::collections::HashMap::new();
                        for (p, category) in watch_scan(&dir, recursive) {
                            // A file that already failed is skipped until
                            // its mtime or size changes (re-saving it is
                            // the user's retry).
                            let Some(sig) = watch_sig(&p) else { continue };
                            let settled = prev_pass.get(&p) == Some(&sig);
                            this_pass.insert(p.clone(), sig);
                            // Ingested earlier with keep-mode on and unchanged
                            // since: already downloaded from here. Checked
                            // before anything reads the file, so a kept
                            // folder full of settled .nzbs costs stats, not
                            // reads - and never lands in watch_failed as an
                            // "already queued" warning it does not deserve.
                            if watch_seen.get(&p).is_some_and(|(t, l, _)| (*t, *l) == sig) {
                                continue;
                            }
                            // Completeness is now the gate, and stillness
                            // only decides when to give up waiting for it.
                            //
                            // Stillness ALONE used to be the gate, and it is
                            // not sound: a copy that stalls for two passes
                            // looks identical to a finished one, and a clean
                            // cut between </file> and </nzb> parses happily
                            // as a SHORTER release. Measured on a stalled
                            // 2-file nzb truncated after the first </file>:
                            // queued as a 1-file release, and the user's
                            // original deleted behind it - unrecoverable,
                            // and silent. That predates the watcher; it is
                            // just reachable in 5 s rather than never.
                            //
                            // So an incomplete file is never ingested. If it
                            // also stops changing, say so and stop retrying
                            // it - a visible complaint with the file still on
                            // disk beats a fragment queued in its place.
                            let complete = std::fs::read(&p)
                                .ok()
                                .is_some_and(|b| nzb_looks_complete(&b));
                            if !complete {
                                if settled
                                    && d.watch_failed_insert(
                                        p.clone(),
                                        (sig.0, sig.1, watchfail::TRUNCATED.into(), String::new()),
                                    )
                                {
                                    info!(
                                        target: "watch",
                                        "{} looks truncated - no closing </nzb> tag, \
                                         and it has stopped changing. Left alone; re-save it \
                                         to retry.",
                                        p.display()
                                    );
                                }
                                continue;
                            }
                            if d.watch_failed
                                .lock_ok()
                                .get(&p)
                                .is_some_and(|(t, l, _, _)| (*t, *l) == sig)
                            {
                                continue;
                            }
                            if let Ok(bytes) = std::fs::read(&p) {
                                // Re-check the signature AFTER the read.
                                // The settle test compared two passes and
                                // then read seconds later, so a re-save
                                // landing in that window was read as a
                                // torn prefix - which still parses, since
                                // the XML reader simply stops at the last
                                // whole <file> - queued as if it were the
                                // whole release, and then the user's
                                // freshly written file was DELETED below.
                                // That is the exact outcome the two-pass
                                // settle exists to prevent, surviving in
                                // the gap between the stat and the read.
                                if watch_sig(&p) != Some(sig) {
                                    info!(
                                        target: "watch",
                                        "{} changed while being read - leaving it \
                                         for the next pass",
                                        p.display()
                                    );
                                    continue;
                                }
                                // Is this exact NZB already waiting in the
                                // queue? Deleting the file was the only
                                // durable "consumed" marker, and the
                                // in-memory skip list does not survive a
                                // restart - so a share that refuses the
                                // unlink, a crash between the queue write
                                // and the delete, or a deliberately-kept
                                // file after ENOSPC all meant the next
                                // start downloaded the whole release
                                // again. A name without an SxxEyy or year
                                // has no dupe_key to catch it either.
                                // The queue IS persisted, so ask it.
                                let sha = nzb_sha(&bytes);
                                // The id, not just the fact: the strip's whole
                                // job here is to point at the record that made
                                // this file redundant, and a name lookup in the
                                // page picks the wrong row for a re-post.
                                let queued_id = d.queue.lock_ok().iter().find_map(|j| {
                                    let g = j.lock_ok();
                                    (g.nzb_sha == sha).then(|| g.nzo_id.clone())
                                });
                                if let Some(queued_id) = queued_id {
                                    info!(
                                        target: "watch",
                                        "{} is already queued - leaving the file \
                                         alone rather than downloading it twice",
                                        p.display()
                                    );
                                    d.watch_failed_insert(
                                        p.clone(),
                                        (sig.0, sig.1, watchfail::ALREADY_QUEUED.into(), queued_id),
                                    );
                                    continue;
                                }
                                // ...and once it finishes, it is not in the
                                // queue any more - it is in HISTORY, which is
                                // persisted through the same file and carries
                                // the same nzb_sha. Asking only the queue meant
                                // a source file that cannot be deleted (a
                                // read-only share, a NAS that refuses the
                                // unlink) was re-ingested on every single
                                // daemon start, re-downloading the whole
                                // release each time; the in-memory skip list
                                // covers the running process and nothing more.
                                //
                                // Completed rows only. A FAILED job's source
                                // file is exactly the one a user wants
                                // retried - a takedown that later refills, a
                                // provider outage - so a failure must not
                                // become a permanent refusal to look at it.
                                let done = d.history.lock_ok().iter().find_map(|j| {
                                    let j = j.lock_ok();
                                    (j.nzb_sha == sha && j.state == JobState::Completed)
                                        .then(|| j.nzo_id.clone())
                                });
                                if let Some(done_id) = done {
                                    info!(
                                        target: "watch",
                                        "{} has already been downloaded - leaving the \
                                         file alone rather than downloading it twice. To \
                                         download it again, delete its History entry first, \
                                         or add the NZB from the dashboard",
                                        p.display()
                                    );
                                    d.watch_failed_insert(
                                        p.clone(),
                                        (sig.0, sig.1, watchfail::ALREADY_DONE.into(), done_id),
                                    );
                                    continue;
                                }
                                let name = p
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();
                                // The success path is the one moment nothing
                                // explained: the file simply vanishes from
                                // the folder (a browser's download list says
                                // "Removed", and Gary read that as nzbfast
                                // deleting his download). Say it in the log,
                                // and remember it so an open dashboard can
                                // toast it - named by the folder it came
                                // from, which is what the user recognises.
                                let mut folder = dir
                                    .file_name()
                                    .map(|f| f.to_string_lossy().to_string())
                                    .unwrap_or_else(|| dir.display().to_string());
                                // A subfolder pickup names the folder the
                                // user actually dropped into - which is
                                // also the category the job just got.
                                if !category.is_empty() {
                                    folder = format!("{folder}/{category}");
                                }
                                // §129 1b(b): the pickup goes on the
                                // lifecycle ring, which is
                                // sequence-cursored - it used to ride a
                                // bounded `watch_picked` array on the
                                // queue payload that the page diffed
                                // against a seen-set of its own, and
                                // that payload is only re-sent when the
                                // queue revision moves.
                                //
                                // A pickup DOES move it (enqueue is
                                // what raised this), so unlike the
                                // give-up trip the old transport was
                                // not late - it was just a second
                                // mechanism for a moment the ring
                                // already knew how to carry.
                                let note_pickup = || {
                                    info!(
                                        target: "watch",
                                        "picked up {name} from {folder} - queued"
                                    );
                                    d.life_emit(
                                        "watch.picked",
                                        serde_json::json!({"name": name, "folder": folder}),
                                    );
                                };
                                match d.enqueue(
                                    &bytes, &name, &category, -100, None, None, "watch", false,
                                ) {
                                    // Delete the user's file only once the
                                    // queue record is DURABLE.
                                    //
                                    // `enqueue` used to persist best-effort
                                    // and return Ok either way, and this
                                    // deleted on Ok - so ENOSPC or EIO on
                                    // queue.json plus a later crash lost both
                                    // the record and the source, with nothing
                                    // left to recover from. It now says
                                    // whether its own save landed (A12), so
                                    // the second `save_queue` that used to
                                    // sit in this guard is gone. The job is
                                    // live in memory regardless, so on a
                                    // failed commit we keep their .nzb and
                                    // record the failure: that stops the next
                                    // scan re-enqueueing a duplicate, and
                                    // leaves the file for the restart - where
                                    // `recover_orphaned_spool` re-adopts the
                                    // spool copy first and this poller then
                                    // finds the file ALREADY_QUEUED by sha.
                                    Ok(Enqueued { durable: true, .. }) => {
                                        note_pickup();
                                        // Keep-mode: the user wants the file
                                        // (collectors, sharing it for a bug
                                        // report), so the durable marker is
                                        // the seen-set instead of the
                                        // deletion. Read live, per pickup.
                                        if d.watch_keep_nzb.load(Ordering::Relaxed) {
                                            watch_seen
                                                .insert(p.clone(), (sig.0, sig.1, sha.clone()));
                                            save_watch_seen(&seen_path, &watch_seen);
                                            d.watch_failed_remove(&p);
                                            continue;
                                        }
                                        if consume_source_file(&d, &p, sig, &name) {
                                            this_pass.remove(&p);
                                        }
                                    }
                                    Ok(_) => {
                                        // Queued in memory even though the
                                        // save failed, so the pickup is
                                        // still worth announcing.
                                        note_pickup();
                                        warn!(
                                            target: "watch",
                                            "{name} queued but the queue could not be \
                                             saved - keeping your file at {}",
                                            p.display()
                                        );
                                        d.watch_failed_insert(
                                            p,
                                            (
                                                sig.0,
                                                sig.1,
                                                watchfail::UNSAVED.to_string(),
                                                String::new(),
                                            ),
                                        );
                                    }
                                    Err(err) => {
                                        info!(target: "watch", "{name} rejected: {err}");
                                        // Complete but unusable. With the
                                        // quarantine on, the file moves to
                                        // <watch>/rejected/ with a note
                                        // saying why; the strip entry
                                        // follows it to the new path so
                                        // the dashboard still explains it.
                                        // A failed move falls back to
                                        // leave-in-place, which is also
                                        // the off behaviour.
                                        let mut fp = p.clone();
                                        if d.watch_move_rejected.load(Ordering::Relaxed) {
                                            match quarantine_rejected(&dir, &p, &err.to_string()) {
                                                Ok(newp) => {
                                                    info!(
                                                        target: "watch",
                                                        "{name} moved to {} with a note \
                                                         explaining the problem",
                                                        newp.display()
                                                    );
                                                    this_pass.remove(&p);
                                                    fp = newp;
                                                }
                                                Err(e) => warn!(
                                                    target: "watch",
                                                    "{name} could not be moved to the \
                                                     rejected folder ({e}); leaving it in place"
                                                ),
                                            }
                                        }
                                        d.watch_failed_insert(
                                            fp,
                                            (sig.0, sig.1, err.to_string(), String::new()),
                                        );
                                    }
                                }
                            }
                        }
                        // Only names this pass actually saw carry over, so
                        // an ingested or deleted file leaves nothing behind.
                        prev_pass = this_pass;
                    }
                    // Files the user deleted or moved drop off the list.
                    // Through the bumping helper: this retain is exactly
                    // where a ghost row was born - the entry left the map
                    // here while every idle dashboard kept rendering it,
                    // and its delete button answered "no such rejected
                    // file" from then on.
                    d.watch_failed_prune_missing();
                    // ...and off the keep-mode seen-set, so it never grows
                    // past what the folder actually holds. Persisted only
                    // when something actually left.
                    let before = watch_seen.len();
                    watch_seen.retain(|p, _| p.exists());
                    if watch_seen.len() != before {
                        save_watch_seen(&seen_path, &watch_seen);
                    }
                });
            }
            // Wake on whichever comes first: the backstop interval, or
            // the filesystem watcher saying the folder changed. The poll
            // cannot be dropped - a write made on another host to an
            // SMB/NFS mount produces no local event at all - but on a
            // real local folder the notify arm is what makes a drop feel
            // instant instead of costing up to two five-second passes.
            let every = d.watch_interval_secs.load(Ordering::Relaxed).clamp(1, 3600);
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(every)) => {}
                _ = d.watch_scan_now.notified() => {
                    // Let the writer finish the burst it is in the middle
                    // of rather than reading on the first CREATE event.
                    // A whole file then passes nzb_looks_complete on this
                    // very pass; a partial one waits for the next.
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{WATCH_REJECT_DIR, quarantine_rejected};

    /// L4 sweep 10 Aug (Codex L3): with "bad.nzb" through "bad
    /// (1000).nzb" all taken, the collision loop used to exit while the
    /// chosen destination still existed - POSIX rename then REPLACED
    /// that incumbent (a different rejected file the user had not
    /// looked at), Windows errored and left the new file re-scanned
    /// forever. Past the counter the name must still be unique.
    #[test]
    fn the_thousandth_collision_never_overwrites_an_incumbent() {
        let root = std::env::temp_dir().join(format!("nzbfast-quar-{}", std::process::id()));
        let qdir = root.join(WATCH_REJECT_DIR);
        std::fs::create_dir_all(&qdir).unwrap();
        std::fs::write(qdir.join("bad.nzb"), b"incumbent 1").unwrap();
        for n in 2..=1000u32 {
            std::fs::write(qdir.join(format!("bad ({n}).nzb")), b"incumbent").unwrap();
        }
        let src = root.join("bad.nzb");
        std::fs::write(&src, b"the new reject").unwrap();
        let dest = quarantine_rejected(&root, &src, "test").expect("quarantine");
        assert!(!src.exists(), "source must have moved");
        assert_eq!(std::fs::read(&dest).unwrap(), b"the new reject");
        // Every incumbent survives untouched.
        assert_eq!(std::fs::read(qdir.join("bad.nzb")).unwrap(), b"incumbent 1");
        assert_eq!(
            std::fs::read(qdir.join("bad (1000).nzb")).unwrap(),
            b"incumbent"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
