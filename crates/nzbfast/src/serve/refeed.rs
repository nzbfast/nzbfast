//! TODO 280 / GitHub #54: the container post - a small NZB whose payload
//! is another `.nzb` - and the switch that hands that inner NZB back to
//! the queue instead of leaving it on disk for a drag-and-drop.
//!
//! This is a wiring job, not a new subsystem: `tasks/watchfolder.rs`
//! already turns an NZB file into a job, and all this module does is
//! recognise that a COMPLETED job's own output holds one and walk it
//! down the same road. What it does NOT do is reuse the watch folder
//! literally. The reporter asked for the file to be MOVED there, and
//! that shape was measured against the code and rejected for two
//! reasons, both of which make it do less than this does:
//!
//!  * the watch folder is unset on a fresh install and on most Docker
//!    images, so a literal move has nowhere to go - the feature would
//!    silently do nothing for the majority of the people asking for it;
//!  * the watch scan enqueues at the default priority and NOT paused, so
//!    a file moved there would start downloading immediately, which is
//!    the opposite of the waiting state the same request asked for.
//!    Teaching the scan to pause would change what a hand-dropped file
//!    does for everybody.
//!
//! So the enqueue is direct and the WAITING state is the observable
//! behaviour that was asked for: the child lands in the queue paused
//! (SAB priority -2, the shipped add-paused path), the user reads its
//! size and presses start. That manual gate is also the cascade control
//! - a chain cannot advance without a human click - and the depth cap
//! below is the belt to its braces.
//!
//! One thing it CANNOT tell apart, said out loud rather than discovered:
//! a release that simply ships its own `.nzb` beside the payload, which
//! some posters do. That file is not a container post and refeeding it
//! re-queues the release you just finished. Three things keep it cheap:
//! the setting is off by default, the child is PAUSED so nothing is
//! fetched until someone looks, and `enqueue`'s own duplicate hold
//! catches it outright whenever the stem carries an SxxEyy or a year.
//! Deleting the paused row is the whole remedy. Nothing on disk can
//! distinguish the two cases - both are a well-formed NZB in a finished
//! download's folder - so this is a limit of the feature, not a bug in
//! it, and it is why the feature asks first.
//!
//! Everything a refeed reads is UNTRUSTED. The bytes came off Usenet,
//! and this is a new path that turns them into parser input, so the
//! candidate is held to three refusals before `Nzb::parse` ever sees it
//! (size, closing tag, extension) and to two after (parse error, no
//! files at all). Every refusal is a skip with a log line, never a
//! fallback that guesses.

use super::*;

/// How many refeed generations deep a chain may go.
///
/// One: a job the user added can produce children, and those children
/// produce nothing. A container post is one indirection by construction,
/// and every level past the first is a level whose only author is the
/// poster. The paused landing already means no chain advances without a
/// click, so this is the backstop for a future where that changes rather
/// than today's only defence.
pub(super) const REFEED_MAX_DEPTH: u8 = 1;

/// The largest candidate that is worth reading, in bytes.
///
/// An NZB is XML at roughly 120 bytes per segment, so even a 100 GB
/// release lands well inside this; 32 MB is chosen to be generous about
/// real NZBs and mean about a payload that merely ENDS in `.nzb`. The
/// point is that a 4 GB file named `movie.nzb` is never read into memory
/// and never handed to a parser.
pub(super) const REFEED_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// How many children one finished download may contribute.
///
/// A container post carries one inner NZB, occasionally a handful. A
/// payload holding hundreds is either junk or hostile, and either way
/// the answer is the same: take the first few, say in the log that the
/// rest were left, and let the user look. Deliberately a constant - it
/// is a sanity bound, not a preference anyone can tune better than this
/// file can.
const REFEED_MAX_PER_JOB: usize = 20;

/// How deep into the finished folder to look for candidates. Deep enough
/// for an unpacked set that nests a few levels, shallow enough that a
/// pathological tree costs stats and not the pass.
const REFEED_WALK_DEPTH: usize = 6;

/// Every `.nzb` under `root`, breadth-bounded and symlink-safe.
///
/// No symlink of any kind is taken - not followed, not listed. A
/// symlinked DIRECTORY turns a bounded walk into an unbounded one and
/// was always refused; a symlinked FILE walked straight through the old
/// is_dir test to the extension check, so `outside.nzb -> /elsewhere`
/// planted in an extracted payload made a file OUTSIDE the completed
/// job look like its output and queued it (Codex sweep 24 Aug, F-13).
/// `DirEntry::file_type` is lstat-shaped, which is what makes the test
/// honest: a link reports is_symlink, never what it points at.
fn scan_nzbs(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(t) = e.file_type() else {
                continue;
            };
            if t.is_symlink() {
                continue;
            }
            if t.is_dir() {
                if depth < REFEED_WALK_DEPTH {
                    stack.push((p, depth + 1));
                }
                continue;
            }
            if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("nzb")) {
                out.push(p);
            }
        }
    }
    // Stable order, so a payload holding more than REFEED_MAX_PER_JOB
    // candidates takes the same ones on every machine and the log line
    // naming what was left means the same thing twice.
    out.sort();
    out
}

/// Why a candidate was not queued, as one sentence for the log. `None`
/// means it passed every refusal and `bytes` may be enqueued.
///
/// Split out so the refusals can be tested without a daemon, a disk or a
/// queue: this is the whole of the untrusted-input judgement, and it is
/// the part of the feature that has to stay right.
pub(super) fn refeed_refusal(len: u64, bytes: &[u8]) -> Option<String> {
    if len > REFEED_MAX_BYTES {
        return Some(format!(
            "it is {:.1} MB, past the {} MB limit for a file this is willing to read",
            len as f64 / 1e6,
            REFEED_MAX_BYTES / (1024 * 1024)
        ));
    }
    if !nzb_looks_complete(bytes) {
        return Some("it has no closing </nzb> tag".to_string());
    }
    match nzbkit::nzb::Nzb::parse(bytes) {
        Err(e) => Some(format!("it is not a readable NZB ({e})")),
        // Belt to the parser's braces. `Nzb::parse` refuses an empty
        // document itself today ("NZB contains no files"), so this arm
        // is not what catches it - it is what keeps the refusal here if
        // that ever relaxes, since a zero-file job is a queue row that
        // can only ever finish green having fetched nothing.
        Ok(nzb) if nzb.files.is_empty() => Some("it names no files".to_string()),
        Ok(_) => None,
    }
}

impl Daemon {
    /// Hand every NZB in a finished job's output back to the queue,
    /// paused. Called from `finalize_completed_gen` on the success path
    /// only, and only with the setting on.
    ///
    /// Blocking: it walks a folder, reads whole files and calls
    /// `enqueue`, which itself stats the output volume. The caller runs
    /// it on the blocking pool.
    ///
    /// Takes no job lock across `enqueue`, which locks every job in the
    /// queue and in history through `dir_claim` - holding the parent's
    /// lock here is a deadlock, not a slow path.
    pub(super) fn refeed_completed(
        self: &Arc<Self>,
        job: &Arc<Mutex<Job>>,
        gen0: Option<(u32, u64)>,
    ) {
        let (parent_id, parent_name, out_dir, category, depth) = {
            let g = job.lock_ok();
            // A record that left the round this tail started on belongs
            // to a live download now; queueing children off its old
            // output would be describing the wrong job.
            if !Daemon::same_generation(&g, gen0) {
                return;
            }
            (
                g.nzo_id.clone(),
                g.name.clone(),
                g.out_dir.clone(),
                g.category.clone(),
                g.refeed_depth,
            )
        };
        if depth >= REFEED_MAX_DEPTH {
            // Said out loud rather than skipped in silence: a user who
            // turned this on and sees a chain stop wants to know it was
            // the cap and not a parse failure.
            info!(
                target: "refeed",
                "{parent_name}: not looking for NZB files - this download was itself \
                 queued from one, and the chain goes {REFEED_MAX_DEPTH} level deep"
            );
            return;
        }
        let found = scan_nzbs(&out_dir);
        if found.is_empty() {
            return;
        }
        let over = found.len().saturating_sub(REFEED_MAX_PER_JOB);
        if over > 0 {
            warn!(
                target: "refeed",
                "{parent_name} holds {} NZB files - queueing the first {REFEED_MAX_PER_JOB} \
                 and leaving {over} on disk; they are in {}",
                found.len(),
                out_dir.display()
            );
        }
        for p in found.into_iter().take(REFEED_MAX_PER_JOB) {
            self.refeed_one(&p, &parent_id, &parent_name, &category, depth);
        }
    }

    /// One candidate: refuse it, or queue it paused and stamp its depth.
    fn refeed_one(
        self: &Arc<Self>,
        p: &std::path::Path,
        parent_id: &str,
        parent_name: &str,
        category: &str,
        depth: u8,
    ) {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // lstat, never stat: the walk refused symlinks by entry type,
        // and this closes the enumerate-then-open gap the same way - a
        // link that appeared since is refused rather than followed to a
        // file outside the completed job (Codex sweep 24 Aug, F-13).
        let Ok(meta) = std::fs::symlink_metadata(p) else {
            return;
        };
        if !meta.is_file() {
            return;
        }
        let len = meta.len();
        // Read only what the size gate admits. A file past the cap is
        // never read at all, which is the point of asking the metadata
        // first rather than reading and then measuring.
        if len > REFEED_MAX_BYTES {
            info!(
                target: "refeed",
                "{name} left alone: {}",
                refeed_refusal(len, b"").unwrap_or_default()
            );
            return;
        }
        // A capped read, judged by the bytes that actually arrived: the
        // file can grow between the lstat above and this read, so the
        // stale length is advisory and the byte count is the gate - the
        // reader never takes more than one byte past the cap, whatever
        // the file has become (F-13's other half).
        let mut bytes = Vec::new();
        {
            use std::io::Read;
            let ok = std::fs::File::open(p)
                .and_then(|f| f.take(REFEED_MAX_BYTES + 1).read_to_end(&mut bytes));
            if ok.is_err() {
                return;
            }
        }
        if let Some(why) = refeed_refusal(bytes.len() as u64, &bytes) {
            info!(target: "refeed", "{name} left alone: {why}");
            return;
        }
        // Already in hand? Exactly the watch folder's two questions, and
        // for the same reason: this is what makes a refeed idempotent
        // across an unlock re-run of the parent's tail, across a restart,
        // and across a user who queued the inner NZB by hand first.
        let sha = nzb_sha(&bytes);
        if self
            .queue
            .lock_ok()
            .iter()
            .any(|j| j.lock_ok().nzb_sha == sha)
        {
            info!(target: "refeed", "{name} is already in the queue - leaving it alone");
            return;
        }
        if self.history.lock_ok().iter().any(|j| {
            let j = j.lock_ok();
            j.nzb_sha == sha && j.state == JobState::Completed
        }) {
            info!(
                target: "refeed",
                "{name} has already been downloaded - leaving it alone. To download it \
                 again, delete its History entry first, or add the NZB by hand"
            );
            return;
        }
        // -2 is SAB's add-paused priority, and it is the whole point:
        // the child WAITS. The user reads its size and presses start.
        match self.enqueue(&bytes, &name, category, -2, None, None, "refeed", false) {
            Ok(e) => {
                // The stamp answers WHERE the add landed, and the two
                // announcements below hang on it. `enqueue` returns Ok
                // for an add a pre-queue verdict filed straight to
                // history as Failed, and this arm used to log "paused,
                // waiting for you to start it" and emit `nzb.refeed`
                // about a row that was never in the queue (Codex sweep
                // 24 Aug, F-12).
                if self.stamp_refeed_depth(&e.nzo_id, depth + 1) {
                    info!(
                        target: "refeed",
                        "queued {name} from {parent_name} - paused, waiting for you to start it"
                    );
                    self.life_emit(
                        "nzb.refeed",
                        json!({
                            "name": name,
                            "parent": parent_name,
                            "parent_id": parent_id,
                            "nzo_id": e.nzo_id,
                        }),
                    );
                } else {
                    info!(
                        target: "refeed",
                        "{name} from {parent_name} was filed straight to history by a \
                         pre-queue verdict - it is not waiting in the queue"
                    );
                }
            }
            Err(err) => info!(target: "refeed", "{name} was refused: {err}"),
        }
    }

    /// Record how deep a freshly queued child is, and make it durable.
    /// Returns whether the child is LIVE ON THE QUEUE - the caller's
    /// placement oracle for what to announce.
    ///
    /// Same shape and same reason as `enqueue_fetched`'s failure-link
    /// stamp: `enqueue` saved the queue BEFORE this field existed on the
    /// record, so without a second save a restart in the window puts the
    /// child back at depth 0 and its own output becomes eligible again.
    ///
    /// The HISTORY arm is not optional. A pre-queue verdict files the
    /// child there as Failed, and "depth 0 on a record that is not
    /// going to run costs nothing" - this function's old excuse for
    /// stamping only the queue - fails exactly at `retry`, which
    /// re-publishes THAT record's Arc into the queue without re-running
    /// the hook or touching the depth. A retried child then completed
    /// at depth 0, below REFEED_MAX_DEPTH, and its output was scanned
    /// for grandchildren past the declared one-level cap (Codex sweep
    /// 24 Aug, F-12). Stamped wherever the record landed, and persisted
    /// there, so the cap survives the retry.
    fn stamp_refeed_depth(&self, nzo_id: &str, depth: u8) -> bool {
        let stamped = {
            let q = self.queue.lock_ok();
            match q.iter().find(|j| j.lock_ok().nzo_id == nzo_id) {
                Some(job) => {
                    job.lock_ok().refeed_depth = depth;
                    true
                }
                None => false,
            }
        };
        if stamped {
            self.save_queue();
            return true;
        }
        let filed = {
            let h = self.history.lock_ok();
            let found = h.iter().find(|j| j.lock_ok().nzo_id == nzo_id).cloned();
            if let Some(j) = &found {
                j.lock_ok().refeed_depth = depth;
            }
            found
        };
        // Outside the history lock: the upsert takes it itself.
        if let Some(job) = filed {
            let _ = self.history_upsert_if_present(&job);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The size cap is measured in BYTES OF FILE, not bytes read: a
    /// candidate past it must be refused without the read. The refusal
    /// helper is therefore asked with an empty body on purpose, which is
    /// how `refeed_one` calls it.
    #[test]
    fn an_oversized_candidate_is_refused_before_it_is_read() {
        let why = refeed_refusal(REFEED_MAX_BYTES + 1, b"").expect("refused");
        assert!(why.contains("32 MB limit"), "{why}");
        // ...and the cap is inclusive at the boundary, so a file exactly
        // at the limit is judged on its contents like any other.
        let why = refeed_refusal(REFEED_MAX_BYTES, b"not xml").expect("refused");
        assert!(why.contains("closing"), "{why}");
    }

    /// Fail CLOSED on anything that is not a well-formed NZB. Each of
    /// these is a real shape a `.nzb` file on disk turns out to be: a
    /// login page saved under the name, a torn copy, and a valid NZB
    /// document that names nothing to fetch.
    #[test]
    fn a_candidate_that_is_not_an_nzb_is_refused_rather_than_guessed_at() {
        assert!(refeed_refusal(64, b"<html><body>Sign in</body></html>").is_some());
        assert!(refeed_refusal(64, b"<nzb><file subject=\"x\">").is_some());
        // A well-formed NZB document that names nothing to fetch. The
        // parser refuses this one itself, so the sentence names the
        // parser - the `files.is_empty()` arm is the belt behind it, not
        // the thing under test here.
        let empty =
            br#"<?xml version="1.0"?><nzb xmlns="http://www.newzbin.com/DTD/2003/nzb"></nzb>"#;
        let why = refeed_refusal(empty.len() as u64, empty).expect("refused");
        assert!(why.contains("not a readable NZB"), "{why}");
    }

    /// The happy shape: a one-file NZB passes every refusal.
    #[test]
    fn a_well_formed_nzb_passes() {
        let good = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="p" date="1" subject="inner.rar (1/1)">
<groups><group>alt.binaries.test</group></groups>
<segments><segment bytes="100" number="1">abc@example</segment></segments>
</file>
</nzb>"#;
        assert!(refeed_refusal(good.len() as u64, good).is_none());
    }

    /// One well-formed NZB, one release under it. Small enough to keep
    /// the tests readable and complete enough for `Nzb::parse`.
    fn inner_nzb(subject: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="p" date="1" subject="{subject} (1/1)">
<groups><group>alt.binaries.test</group></groups>
<segments><segment bytes="100" number="1">{subject}@example</segment></segments>
</file>
</nzb>"#
        )
        .into_bytes()
    }

    /// A finished job with `out_dir` under the daemon's download folder,
    /// at the refeed depth asked for.
    fn parent(d: &Arc<Daemon>, id: &str, depth: u8) -> Arc<Mutex<Job>> {
        let out = d.out_dir().join(format!("Container.{id}"));
        std::fs::create_dir_all(&out).expect("mkdir");
        let j = job_from_json(&json!({
            "nzo_id": id,
            "name": format!("Container.{id}"),
            "out_dir": out.to_string_lossy(),
            "nzb_path": d.spool.join(format!("{id}.nzb")).to_string_lossy(),
            "state": "Completed",
            "refeed_depth": depth,
        }))
        .expect("job");
        Arc::new(Mutex::new(j))
    }

    fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-refeed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);
        f(&d);
        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole feature in one test: a finished download holding an
    /// `.nzb` produces a SECOND queue row, and that row is PAUSED.
    ///
    /// Paused is the load-bearing half. GitHub #54's reporter asked for
    /// the inner NZB to land in a waiting state so he can read its size
    /// and start it himself, and that manual gate is what stops a
    /// container post cascading. A child that arrived unpaused would
    /// still close the issue's headline complaint and would be the
    /// wrong feature.
    #[test]
    fn a_finished_download_holding_an_nzb_queues_it_paused_at_depth_one() {
        with_daemon("queues", |d| {
            let job = parent(d, "SABnzbd_nzo_c1", 0);
            let out = job.lock_ok().out_dir.clone();
            std::fs::write(out.join("Inner.Release.nzb"), inner_nzb("inner")).unwrap();

            d.refeed_completed(&job, None);

            let q = d.queue.lock_ok();
            assert_eq!(q.len(), 1, "exactly one child, and the parent is not in it");
            let g = q[0].lock_ok();
            // The add strips the extension, exactly as it does for a
            // file picked out of the watch folder.
            assert_eq!(g.name, "Inner.Release");
            assert!(g.paused, "the child waits for the user to start it");
            assert_eq!(g.refeed_depth, 1, "the child is one generation deep");
            assert_eq!(g.origin, "refeed");
        });
    }

    /// The depth cap. A job that was ITSELF queued by a refeed produces
    /// nothing, so a chain is one indirection and not a walk.
    #[test]
    fn a_child_of_a_refeed_never_produces_a_grandchild() {
        with_daemon("depth", |d| {
            let job = parent(d, "SABnzbd_nzo_c2", REFEED_MAX_DEPTH);
            let out = job.lock_ok().out_dir.clone();
            std::fs::write(out.join("Deeper.nzb"), inner_nzb("deeper")).unwrap();

            d.refeed_completed(&job, None);

            assert!(
                d.queue.lock_ok().is_empty(),
                "the cap holds the chain at one level"
            );
        });
    }

    /// Idempotent. The parent's tail runs again after an unlock, and a
    /// restart re-reads the same folder - neither may queue the inner
    /// NZB a second time. The dedupe is by content sha, exactly as the
    /// watch folder's is, so it also covers a user who added the same
    /// file by hand first.
    #[test]
    fn a_second_pass_over_the_same_output_queues_nothing_new() {
        with_daemon("idem", |d| {
            let job = parent(d, "SABnzbd_nzo_c3", 0);
            let out = job.lock_ok().out_dir.clone();
            std::fs::write(out.join("Inner.nzb"), inner_nzb("inner")).unwrap();

            d.refeed_completed(&job, None);
            assert_eq!(d.queue.lock_ok().len(), 1);
            d.refeed_completed(&job, None);
            assert_eq!(d.queue.lock_ok().len(), 1, "the sha dedupe held");

            // ...and a DIFFERENT NZB beside it is still picked up, so
            // the dedupe is about identity and not about "this job has
            // been refed already".
            std::fs::write(out.join("Other.nzb"), inner_nzb("other")).unwrap();
            d.refeed_completed(&job, None);
            assert_eq!(d.queue.lock_ok().len(), 2);
        });
    }

    /// Nothing that is not a well-formed NZB reaches the queue. Each of
    /// these files is a shape that really does turn up under an `.nzb`
    /// name in a download folder.
    #[test]
    fn unusable_candidates_are_left_on_disk_rather_than_queued() {
        with_daemon("refuse", |d| {
            let job = parent(d, "SABnzbd_nzo_c4", 0);
            let out = job.lock_ok().out_dir.clone();
            std::fs::write(out.join("login.nzb"), b"<html>Sign in</html>").unwrap();
            std::fs::write(out.join("torn.nzb"), b"<nzb><file subject=\"x\">").unwrap();
            std::fs::write(out.join("payload.mkv"), inner_nzb("mkv")).unwrap();

            d.refeed_completed(&job, None);

            assert!(d.queue.lock_ok().is_empty());
            assert!(
                out.join("login.nzb").exists(),
                "a refusal never deletes the file"
            );
        });
    }

    /// The call site's real SHAPE, not just its result.
    ///
    /// `finalize_completed_gen` hands this to `spawn_blocking`, and
    /// `enqueue` reaches `persist::blocking_db`, which calls
    /// `block_in_place` whenever a multi-threaded runtime is current -
    /// an arm that panics on the wrong kind of thread and that a plain
    /// `#[test]` never touches, because there is no runtime at all. So
    /// this one drives the production shape: multi-threaded runtime,
    /// blocking pool, awaited, panic surfaced as a JoinError.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_blocking_pool_call_site_the_tail_uses_does_not_panic() {
        let dir = std::env::temp_dir().join(format!("nzbfast-refeed-pool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);
        let job = parent(&d, "SABnzbd_nzo_c5", 0);
        let out = job.lock_ok().out_dir.clone();
        std::fs::write(out.join("Pooled.nzb"), inner_nzb("pooled")).unwrap();

        let (d5, j5) = (d.clone(), job.clone());
        tokio::task::spawn_blocking(move || d5.refeed_completed(&j5, None))
            .await
            .expect("the tail's blocking call must not panic");

        assert_eq!(d.queue.lock_ok().len(), 1);
        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The walk finds nested candidates, ignores everything that is not
    /// an `.nzb`, and hands them back in a stable order - the order the
    /// per-job cap slices.
    #[test]
    fn the_walk_finds_nested_nzbs_and_nothing_else() {
        let root = std::env::temp_dir().join(format!("nzbfast-refeed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub/deeper")).expect("mkdir");
        std::fs::write(root.join("b.nzb"), b"x").unwrap();
        std::fs::write(root.join("a.NZB"), b"x").unwrap();
        std::fs::write(root.join("movie.mkv"), b"x").unwrap();
        std::fs::write(root.join("sub/deeper/c.nzb"), b"x").unwrap();
        let found = scan_nzbs(&root);
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["a.NZB", "b.nzb", "c.nzb"], "{found:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A symlink named like a candidate is refused, file and directory
    /// alike. The old walk only refused the directory shape (and that
    /// by accident of is_dir being false for links), so `outside.nzb ->
    /// /elsewhere/real.nzb` planted in an extracted payload queued a
    /// file from OUTSIDE the completed job - the exact thing the
    /// "symlink-safe" doc promised could not happen (Codex sweep
    /// 24 Aug, F-13).
    #[cfg(unix)]
    #[test]
    fn a_symlinked_nzb_is_not_a_candidate() {
        let base = std::env::temp_dir().join(format!("nzbfast-refeedln-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("job");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("real.nzb"), b"x").unwrap();
        std::fs::write(root.join("honest.nzb"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.join("real.nzb"), root.join("planted.nzb")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("door")).unwrap();
        let names: Vec<String> = scan_nzbs(&root)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["honest.nzb"], "a symlink walked through");
        let _ = std::fs::remove_dir_all(&base);
    }
}
