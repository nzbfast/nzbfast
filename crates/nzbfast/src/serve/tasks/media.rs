//! TODO §76: the queue-row media prober - what the file actually IS,
//! read out of the file's own header while it is still downloading.
//!
//! Both passes and everything that supports them: the live pass over the
//! running job's writer, the final on-disk pass once the job leaves the
//! queue, the latch that never downgrades an answer it already has, and
//! the claim name a mismatch is judged against. The probe itself is
//! [`nzbkit::mediaprobe`], which §73 phase 1 built for the preview panel
//! - this task exists because that panel's answer is per-request, and a
//! queue row needs one that is already computed, already durable, and
//! shared by every client polling the queue.
//!
//! Split out of `serve/tasks.rs` whole under the size gate (TODO 106);
//! the code is verbatim, only visibility and two paths changed. `super`
//! is `tasks` from here, so the two calls into `serve`'s own `stream`
//! module are spelled `crate::serve::stream::` rather than `super::`.
//! `probe_disk_facts_checked` is `pub(in crate::serve)` because
//! `histmigrate`'s re-derivation pass calls it.

use super::*;

/// How often the prober looks at the running job. Env-tunable so the
/// daemon suite can compress the timeline, like the defer watchdog's.
fn media_tick() -> std::time::Duration {
    std::time::Duration::from_millis(
        std::env::var("NZBFAST_MEDIA_TICK_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5_000)
            .max(50),
    )
}
/// Attempts at the fast cadence before backing off. A container header
/// is usually readable within one or two ticks; past a minute of trying,
/// the missing region is a trailing index that arrives with the download
/// and there is nothing to gain from asking twice a minute.
const MEDIA_FAST_TRIES: u32 = 12;
const MEDIA_SLOW: std::time::Duration = std::time::Duration::from_secs(30);
/// How long a finished job stays on the final-pass list. Post-processing
/// on a large release is minutes (unpack, repair, rename, a move to a
/// NAS); half an hour covers that and stops a job that never reaches
/// history from being retried forever.
const MEDIA_FINAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(1800);
/// How many times an I/O fault on the final pass is worth retrying. A
/// sleeping NAS wakes within a tick or two; a volume that is simply gone
/// answers the same way every time, and the log line below has already
/// said so once.
const MEDIA_IO_RETRIES: u32 = 3;

/// What the final pass read, in one line for the log. The same fields
/// the chip shows, in the same order, so the log and the row agree.
///
/// Never empty: an `any()`-false answer is the interesting case here
/// (the file parsed, no track came out of it) and must not print as a
/// bare nzo_id with a colon after it.
pub(super) fn media_line(f: &nzbkit::mediaprobe::MediaFacts) -> String {
    let parts: Vec<&str> = [
        f.res.as_deref(),
        f.vcodec.as_deref(),
        f.audio.as_deref(),
        f.hdr.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    if parts.is_empty() {
        match f.container.as_deref() {
            Some(c) => format!("{c}, but no track could be read from it"),
            None => "nothing could be read from the file".to_string(),
        }
    } else {
        parts.join(" · ")
    }
}

/// A job owed the final on-disk pass, with what it has cost so far.
struct FinalPass {
    id: String,
    /// When it was admitted - `MEDIA_FINAL_WINDOW` runs from here, so an
    /// I/O retry cannot extend its own deadline.
    at: std::time::Instant,
    io_faults: u32,
}

/// The name a mismatch is judged against: what an identity oracle
/// concluded, when one answered, and the posted name otherwise.
///
/// This matters most on exactly the posts the feature is for. An
/// obfuscated stem claims nothing - `parse_release` finds no resolution
/// and no codec in "a4f9c2e1", so nothing can contradict it - while the
/// canonical name srrdb or xREL handed back claims everything. Judging
/// the bytes against that is free here and impossible anywhere else.
pub(super) fn media_claim_name(j: &Job) -> String {
    if j.identity_name.is_empty() {
        j.name.clone()
    } else {
        j.identity_name.clone()
    }
}

/// Has this job's chip stopped changing? A partial answer is worth
/// showing - the resolution lands before the audio - but it is not worth
/// keeping. A chip owed a re-judge (the identity oracle answered after
/// pass 1 settled) is not settled either: the facts are complete but the
/// NAME they were judged against has changed.
pub(super) fn media_settled(j: &Job) -> bool {
    !j.media_rejudge && j.media.as_ref().is_some_and(|m| m.complete && m.any())
}

/// Latch a probe result, never downgrading. Same rule as
/// [`Job::archive_shape`] and for the same reason: a later pass that
/// could read less (a renamed file the on-disk walk no longer finds, a
/// resumed job whose writer maps nothing) must not replace an answer
/// that was right.
pub(super) fn latch_media(job: &Arc<Mutex<Job>>, facts: nzbkit::mediaprobe::MediaFacts) -> bool {
    let mut j = job.lock_ok();
    if !facts.any() && j.media.is_some() {
        return false;
    }
    if j.media.as_ref() == Some(&facts) {
        return false;
    }
    if !facts.mismatch.is_empty() {
        let list: Vec<String> = facts
            .mismatch
            .iter()
            .map(|m| format!("{} claimed, {} found", m.claimed, m.actual))
            .collect();
        info!(
            target: "media",
            "{}: the file contradicts its name - {}",
            j.nzo_id,
            list.join("; ")
        );
    }
    j.media = Some(facts);
    true
}

/// Pass 2's miss, which is two different things, and only one of them
/// is the end of it.
///
/// A settled miss - the output holds no media file of ours, or its
/// bytes are not a container we read - answers the same way forever, so
/// the row keeps no chip and the entry is dropped. A miss taken while
/// the payload is IN FLIGHT is neither of those: `mover_process` calls
/// `relocate_completed` first and rewrites `Job::out_dir` only when the
/// copy returns, so for the whole duration of a move the record names
/// the folder the bytes are leaving and the walk under that name finds
/// nothing. The disk was read fine and the payload is whole; it is just
/// not under the name the record carries. Returns whether the entry is
/// owed another look.
///
/// It matters here more than the log line suggests, because pass 2 is
/// the ONLY source of a chip for the shapes that unpack after the
/// download - and those are exactly the jobs that then take a move.
/// Nothing re-derives what this arm drops: `finals.remove` has already
/// taken the entry, the mover owes no `media_final_owed` when it lands,
/// and §188's re-derivation pass skips a row with no label outright
/// ("there is no view here to correct"), so a miss recorded here is a
/// chipless row for the life of the record, not a cached one.
///
/// Asked AFTER the walk and never before it, for the reason
/// [`crate::serve::stream::payload_in_flight`] documents: the
/// cross-device route stages its copy and leaves the source whole until
/// it publishes, so most of a long NAS move still reads its chip out of
/// the old folder and settles here for good. Refusing on the marker
/// alone would defer every one of those to a retry it may not get.
///
/// The wait is bounded by `MEDIA_FINAL_WINDOW` from admission, which
/// the re-push deliberately does not reset. A move still running half
/// an hour after the job parked loses the chip - the same bound the
/// I/O retries accept, and the alternative is an entry that a wedged
/// move keeps alive forever.
///
/// `pub(in crate::serve)` for its test, which lives with the rest of
/// the move window in `stream::stream_move_window_tests` - the window
/// is rigged there against the real markers and a real emptied folder,
/// and a seeded spool cannot produce it.
pub(in crate::serve) fn miss_is_in_flight(d: &Daemon, job: &Arc<Mutex<Job>>, id: &str) -> bool {
    if crate::serve::stream::payload_in_flight(d, job) {
        info!(
            target: "media",
            "{id}: the payload is in flight to its final folder - \
             the chip's disk pass waits for it to land"
        );
        true
    } else {
        info!(
            target: "media",
            "{id}: no media file to read in the output - the row keeps no chip"
        );
        false
    }
}

/// §76: read the main video's own header while it downloads, so the
/// queue row can say what the file actually IS - "2160p HEVC · DDP 5.1"
/// - and say so when that contradicts the name the post carries.
///
/// The probe itself is [`nzbkit::mediaprobe`], which §73 phase 1 built
/// for the preview panel: this task exists because the panel's answer is
/// per-open-drawer and per-request, and a queue row needs one that is
/// already computed, already durable, and shared by every client polling
/// the queue. It reads container headers only (a few hundred KB, skipping
/// every payload region by arithmetic) off an ordinary blocking thread.
///
/// Two passes, deliberately:
///
/// 1. While a job runs, over the live writer. Bytes that have not landed
///    read as a gap, never as a wait, and this pass NEVER promotes
///    articles - the preview endpoint may reorder a download because a
///    user is watching that file, but a background badge has no business
///    perturbing fetch order for every job on the queue.
/// 2. Once, on disk, after the job leaves the queue. Archive shapes that
///    unpack after the download write no media file until post-processing
///    finishes, so pass 1 sees nothing at all for them; and a shape that
///    does write one may still have been reading a trailing index that
///    only completes at the end.
pub(in crate::serve) fn spawn_media_prober(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        // The job pass 1 is watching, its attempt count, and when it is
        // next due. All task-local: nothing else needs to know, and a
        // restart correctly starts over.
        let mut watching: Option<String> = None;
        let mut tries: u32 = 0;
        let mut due = std::time::Instant::now();
        // Jobs that left the queue owing a final on-disk pass.
        let mut finals: Vec<FinalPass> = Vec::new();
        let tick = media_tick();
        loop {
            tokio::time::sleep(tick).await;
            // The job actually on the wire. `active_stream` alone will
            // not do: it is deliberately left pointing at the last job
            // that ran so post-completion streaming keeps working, so
            // the queue is what says whether that job is still fetching.
            //
            // Two statements ON PURPOSE (issue #38): chained as
            // `.lock_ok().clone().filter(..)` the guard is a statement
            // temporary that stays held while the closure takes the
            // queue lock - the exact reverse of queue_json's
            // queue -> active_stream order. With a huge queue the
            // completion path holds the queue lock for seconds, this
            // task parked inside that convoy still holding
            // active_stream, a mode=queue poll won the queue mutex and
            // then blocked on active_stream: both sides frozen forever,
            // and with them every HTTP worker and the runner. The clone
            // must be bound (and the guard dropped) before any other
            // lock is touched.
            let cur = d.active_stream.lock_ok().clone();
            let live = cur.filter(|id| {
                d.queue_job(id)
                    .is_some_and(|job| job.lock_ok().state == JobState::Downloading)
            });
            // A different job (or none) is fetching: whatever we were
            // watching is owed its final pass.
            if watching != live
                && let Some(prev) = watching.take()
                && !finals.iter().any(|f| f.id == prev)
            {
                finals.push(FinalPass {
                    id: prev,
                    at: std::time::Instant::now(),
                    io_faults: 0,
                });
            }
            if let Some(id) = &live {
                if watching.is_none() {
                    watching = Some(id.clone());
                    tries = 0;
                    due = std::time::Instant::now();
                }
                let job = d.queue_job(id);
                let ask = job.as_ref().is_some_and(|job| {
                    let j = job.lock_ok();
                    !media_settled(&j)
                });
                if ask && std::time::Instant::now() >= due {
                    tries += 1;
                    due = std::time::Instant::now()
                        + if tries < MEDIA_FAST_TRIES {
                            tick
                        } else {
                            MEDIA_SLOW
                        };
                    let (d2, id2) = (d.clone(), id.clone());
                    // Blocking file reads, off the runtime's worker
                    // threads - the same rule the endpoint follows.
                    if let Ok(Some(facts)) =
                        tokio::task::spawn_blocking(move || probe_live_facts(&d2, &id2)).await
                        && let Some(job) = job
                        && latch_media(&job, facts)
                    {
                        // A DOWNLOADING job: `Absent` is the normal
                        // answer and `save_queue` below is what makes
                        // the chip durable. The call is here for the
                        // job that parked between the probe and this
                        // line, and only THAT one can be refused - so
                        // the reporting hangs off the outcome rather
                        // than off "nothing was written".
                        d.history_publish_change(&job, "the media chip");
                        d.save_queue();
                    }
                }
            }
            // The two events that owe a final pass: a record reaching
            // history, and an identity oracle answering after the chip
            // had already settled (a settled job has left `finals`, so
            // it has to be re-admitted here). Neither is something this
            // task can see for itself - see `Daemon::media_final_owed`.
            for id in d.media_final_owed.lock_ok().drain(..) {
                if !finals.iter().any(|f| f.id == id) {
                    finals.push(FinalPass {
                        id,
                        at: std::time::Instant::now(),
                        io_faults: 0,
                    });
                }
            }
            // Pass 2. One job per tick, and only once post-processing
            // has published the payload: `finalizing` is set for the
            // whole of unpack/rename/move, during which out_dir names a
            // directory whose contents are still arriving.
            finals.retain(|f| f.at.elapsed() < MEDIA_FINAL_WINDOW);
            let ready = finals.iter().position(|f| {
                d.history_job(&f.id).is_some_and(|job| {
                    let j = job.lock_ok();
                    // A failed job has no settled payload to read. The
                    // retain arm below already treats it that way; this
                    // stops it costing a directory walk and a "no media
                    // file" line first.
                    !j.finalizing && !media_settled(&j) && j.state != JobState::Failed
                })
            });
            match ready {
                Some(i) => {
                    let entry = finals.remove(i);
                    let Some(job) = d.history_job(&entry.id) else {
                        continue;
                    };
                    // This attempt IS the re-judge, whatever it reads:
                    // cleared before the probe so a failed read leaves
                    // the chip settled-as-judged, not owed forever.
                    job.lock_ok().media_rejudge = false;
                    let (d2, job2) = (d.clone(), job.clone());
                    // `_checked`, not the lossy wrapper: the three
                    // outcomes are three different things to say, and a
                    // row with no chip used to look exactly like a row
                    // nobody had probed. Every arm leaves a line.
                    let read =
                        tokio::task::spawn_blocking(move || probe_disk_facts_checked(&d2, &job2))
                            .await;
                    match read {
                        Ok(Ok(Some(facts))) => {
                            let shown = media_line(&facts);
                            if latch_media(&job, facts) {
                                info!(target: "media", "{}: {shown}", entry.id);
                                // Cosmetic, and self-healing on a build
                                // bump: the §188 re-derivation pass walks
                                // every row and writes the facts again.
                                d.history_publish_change(&job, "the media chip");
                                d.save_queue();
                            }
                        }
                        // A miss, which is two different things - see
                        // `miss_is_in_flight`. Re-admitted with its OWN
                        // `at` and `io_faults`: waiting for a move is
                        // not an I/O fault and must not extend the
                        // window it waits inside.
                        Ok(Ok(None)) => {
                            if miss_is_in_flight(&d, &job, &entry.id) {
                                finals.push(entry);
                            }
                        }
                        // A failure to LOOK: an absent volume, a sleeping
                        // mount, a folder the OS declined. Worth another
                        // try, and worth saying once.
                        Ok(Err(e)) => {
                            if entry.io_faults == 0 {
                                warn!(
                                    target: "media",
                                    "{}: could not read the payload for the media chip - {e}",
                                    entry.id
                                );
                            }
                            if entry.io_faults + 1 < MEDIA_IO_RETRIES {
                                finals.push(FinalPass {
                                    io_faults: entry.io_faults + 1,
                                    ..entry
                                });
                            }
                        }
                        // The blocking thread itself died. Nothing was
                        // read and nothing can be said about the file.
                        Err(e) => warn!(
                            target: "media",
                            "{}: the media probe did not finish - {e}",
                            entry.id
                        ),
                    }
                }
                // Nothing ready, but drop any entry that has already
                // settled (pass 1 finished the job off) or that failed
                // outright and has no payload to read.
                None => finals.retain(|f| {
                    d.history_job(&f.id).is_none_or(|job| {
                        let j = job.lock_ok();
                        !media_settled(&j) && j.state != JobState::Failed
                    })
                }),
            }
        }
    });
}

/// Pass 1: the running job's main video, from the bytes on disk so far.
fn probe_live_facts(d: &Daemon, id: &str) -> Option<nzbkit::mediaprobe::MediaFacts> {
    let name = media_claim_name(&d.queue_job(id)?.lock_ok());
    let (file, w, mut r, _lease) = crate::serve::stream::open_live_probe(d, id)?;
    let info = nzbkit::mediaprobe::probe(
        &mut r,
        nzbkit::mediaprobe::ProbeHint {
            filename: Some(file),
            known_size: Some(w.size),
        },
    )
    .ok()?;
    Some(nzbkit::mediaprobe::facts::check(&info, &name))
}

/// Pass 2: the finished payload, whatever post-processing left behind,
/// keeping the difference between "there is nothing to read" and "I
/// could not read it".
///
/// `Ok(None)` is a settled answer: no media file of ours in the output
/// directory, or a file whose bytes are not a container we understand.
/// `Err` is a failure to look, and only ever an I/O one - the volume,
/// the permission, the network mount. Every caller needs that
/// distinction (Codex sweep 7, M6): the re-derivation pass must not
/// record "no payload" for a disk it never managed to read, and the
/// prober says a different thing in the log for each - a lossy wrapper
/// that erased both into `None` is what made a chipless row and an
/// unprobed row look identical.
pub(in crate::serve) fn probe_disk_facts_checked(
    d: &Daemon,
    job: &Arc<Mutex<Job>>,
) -> std::io::Result<Option<nzbkit::mediaprobe::MediaFacts>> {
    let Some(path) = crate::serve::stream::finished_media_path_checked(d, job)? else {
        return Ok(None);
    };
    let name = media_claim_name(&job.lock_ok());
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        // The walk named it a moment ago, so a NotFound here is a file
        // that has just been moved or deleted - an answer, not a fault.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let info = match nzbkit::mediaprobe::probe(
        &mut f,
        nzbkit::mediaprobe::ProbeHint {
            filename: path.file_name().map(|n| n.to_string_lossy().to_string()),
            known_size: Some(size),
        },
    ) {
        Ok(i) => i,
        // A container we cannot parse is a property of the FILE and will
        // read the same way forever; only the I/O arm is worth retrying.
        Err(nzbkit::mediaprobe::ProbeError::Io(e)) => return Err(e),
        Err(_) => return Ok(None),
    };
    Ok(Some(nzbkit::mediaprobe::facts::check(&info, &name)))
}
