use super::*;

/// The library pointer a media server indexes: a one-line .strm whose URL
/// plays (and on first play, downloads) the job.
///
/// Neither half of that URL is a placeholder any more. `scheme` is what
/// this run's listener actually bound ([`Daemon::scheme`]) - there is no
/// request here to read a forwarded scheme off, the file is written at
/// finalize and read back possibly months later, so a hardcoded `http`
/// on a TLS daemon wrote a pointer that could never play. `authority`
/// is the same argument one field over, and [`pointer_authority`] is
/// where it is derived.
///
/// **Plex will never describe what this points at, and no change here can
/// fix it.** Measured 25 Aug 2026 in
/// `research/PLEX-STRM-ANALYZE-2026-08-25.md`: Plex's scanner treats the
/// .strm FILE as the media, recording a part whose size and path are the
/// pointer's own, and resolves the URL at one moment only - playback, as a
/// 301 the client follows. Four pointer shapes in one library, including a
/// bare path ending in `.mp4` and a trailing filename after the id, all
/// report no duration and no container, and the origin logged ZERO requests
/// across the library scan AND an explicit analyze of every item. So do not
/// reshape this URL to carry an extension (that would want the id taken as
/// the FIRST path segment in `serve/http.rs`, which is the change to not
/// make), and do not reach for a response header such as
/// `Content-Disposition`: there is no request to answer. The only thing that
/// gives Plex metadata is real bytes on disk, which is what library mode
/// exists to avoid. Jellyfin and Emby fetch server-side and are unaffected.
pub(super) fn write_strm(
    out_dir: &std::path::Path,
    name: &str,
    scheme: &str,
    authority: &str,
    nzo_id: &str,
    token: &str,
) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    let path = out_dir.join(nzbkit::disk::sanitize_filename(&format!("{name}.strm")));
    std::fs::write(
        &path,
        format!("{scheme}://{authority}/stream/{nzo_id}?t={token}\n"),
    )?;
    info!(target: "library", "wrote {}", path.display());
    Ok(())
}

/// The authority a library pointer has to name, derived from what this
/// run's listener actually bound.
///
/// It was a hardcoded `127.0.0.1` until 25 Aug 2026, flagged in this
/// module's own comment as a placeholder because the daemon knows its
/// port and not its public host. That is still true, and loopback is
/// still the wrong answer for every consumer that is not on this
/// machine. Measured that day (`research/MOUNT-MEASUREMENT-2026-08-25.md`,
/// Finding 5): Plex DOES read a .strm, contrary to the usual claim, and
/// serves it as an HTTP 301 to the URL inside - so the CLIENT is what
/// follows it, and a phone or a TV resolves loopback to ITSELF and gets
/// nothing. Jellyfin and Emby fetch the URL server-side, which is why the
/// placeholder survived: they are unaffected while the server shares this
/// host, and they break the same way the moment it does not (another box,
/// or a bridged container, where loopback is the container's own).
///
/// This is the BIND and not [`public_base`], and the difference is not a
/// preference: `public_base` does the right header arithmetic but takes a
/// `&tiny_http::Request`, and there is no request in scope at finalize -
/// the file is written when the job settles and read back months later.
/// So the listener is the only witness available, exactly as it is for
/// the scheme above:
///
/// * a specific address is what the operator asked to be reachable on,
///   so it IS the answer, and no guess is involved;
/// * loopback stays loopback, because nothing else on this box is
///   listening - a LAN address there would point at a closed port, which
///   is a REGRESSION on the one deployment the placeholder served;
/// * a wildcard (`0.0.0.0`, the shipped default for `serve`, so this is
///   the row nearly every install takes) has no single answer, so the
///   address on the default route is taken - the one a machine on the
///   LAN would reach this one at - and loopback is the fallback when
///   there is none.
///
/// The route is read through [`crate::serve::lanaddr::route_src`], at
/// the same destination the "connect your phone" panel uses, which is
/// load-bearing twice over: it sends no packet, and it is CACHED, so a
/// queue of library jobs settling one after another costs one wildcard
/// UDP bind per minute rather than one per job. That bind is a macOS
/// firewall dialog (TODO 33), which is why `lanaddr` owns the only one
/// in the daemon and a test refuses a second.
///
/// What this cannot name is a reverse proxy, a container's published
/// port or an external hostname. That needs a setting nobody has decided
/// on; TODO 298 is where the decision lives, and this deliberately does
/// not pre-empt it.
pub(super) fn pointer_authority(bind: &str, port: u16) -> String {
    pointer_authority_from(bind, port, || {
        crate::serve::lanaddr::route_src("8.8.8.8:53")
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
    })
}

/// The arithmetic behind [`pointer_authority`], split off the route
/// lookup so it is testable without one - the answer would otherwise
/// depend on which network the box running the test happens to be on.
///
/// The lookup is a closure and not a value because a bind that already
/// names an address must not pay for one: on every path but the wildcard
/// this opens no socket at all.
fn pointer_authority_from(
    bind: &str,
    port: u16,
    lan: impl FnOnce() -> Option<std::net::IpAddr>,
) -> String {
    use std::net::{IpAddr, Ipv4Addr};
    let Ok(ip) = bind.parse::<IpAddr>() else {
        // `--bind` takes a NAME too, and a name the operator typed is
        // one they believe resolves. Passed through rather than
        // resolved: a DNS answer that moves next month should not be
        // frozen into a file read next month.
        return format!("{bind}:{port}");
    };
    let host = if ip.is_loopback() {
        ip
    } else if ip.is_unspecified() {
        lan().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    } else {
        ip
    };
    match host {
        // A v6 literal is bracketed or the port reads as one more group.
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        IpAddr::V4(v4) => format!("{v4}:{port}"),
    }
}

/// Largest media-extension writer in the extractor owned by `want` (the
/// M11 active stream when `want` is None), if any. Resolving ownership and
/// reading the writers off the same cloned extractor keeps the pick tied to
/// the job the caller verified.
/// What counts as the thing a player wants. One list, so the live pick
/// and the finished-download pick cannot disagree about which file the
/// ▶ button means.
pub(super) const MEDIA_EXTS: [&str; 6] = [".mkv", ".mp4", ".avi", ".m4v", ".ts", ".wmv"];

pub(super) fn is_media_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    MEDIA_EXTS.iter().any(|x| l.ends_with(x))
}

pub(super) fn pick_media(
    d: &Daemon,
    want: Option<&str>,
) -> Option<(String, Arc<nzbkit::disk::FileWriter>)> {
    let ex = d.hub.extractor_for(want)?;
    let mut ws = ex.writers_snapshot();
    ws.retain(|(n, _)| is_media_name(n));
    ws.sort_by_key(|(_, w)| std::cmp::Reverse(w.size));
    ws.into_iter().next()
}

/// The biggest media file inside a finished job's output folder - the
/// feature, not the sample or the extra. Season packs unpack into
/// subfolders, so the walk descends, but only a little: a bounded walk
/// cannot be talked into scanning a whole disk by a deep archive.
///
/// Symlinks are never followed and never served. A RAR can carry one,
/// and "biggest .mkv in the folder" would otherwise happily resolve a
/// planted link to any file the daemon can read.
pub(super) fn find_completed_media(dir: &std::path::Path) -> Option<PathBuf> {
    const MAX_DEPTH: u32 = 4;
    const MAX_ENTRIES: usize = 5_000;
    let mut best: Option<(u64, PathBuf)> = None;
    let mut seen = 0usize;
    let mut stack = vec![(dir.to_path_buf(), 0u32)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            if seen >= MAX_ENTRIES {
                break;
            }
            seen += 1;
            let p = e.path();
            // symlink_metadata: a link is judged as a link, not as
            // whatever it points at.
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if md.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((p, depth + 1));
                }
            } else if md.is_file()
                && is_media_name(&e.file_name().to_string_lossy())
                && best.as_ref().is_none_or(|(sz, _)| md.len() > *sz)
            {
                best = Some((md.len(), p));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Serve a file from disk with Range support, for players. The live
/// [`serve_range`] cannot do this job: it reads through a
/// `FileWriter` and blocks waiting for a write frontier that, for a
/// finished download, will never move again.
pub(super) fn serve_file_range(req: tiny_http::Request, path: &std::path::Path) {
    let Ok(mut f) = std::fs::File::open(path) else {
        let _ = req.respond(tiny_http::Response::from_string("gone").with_status_code(410));
        return;
    };
    let total = f.metadata().map(|m| m.len()).unwrap_or(0);
    let range = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Range"))
        .map_or(RangeVerdict::Ignore, |h| {
            byte_range(h.value.as_str(), total)
        });
    let (start, end, status) = match range {
        RangeVerdict::Span(s, e) => (s, e, 206),
        RangeVerdict::Ignore => (0, total, 200),
        RangeVerdict::Unsatisfiable => return respond_unsatisfiable(req, total),
    };
    use std::io::{Read, Seek};
    if f.seek(std::io::SeekFrom::Start(start)).is_err() {
        let _ = req.respond(tiny_http::Response::from_string("unreadable").with_status_code(500));
        return;
    }
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ctype: &[u8] = if name.to_ascii_lowercase().ends_with(".mp4") {
        b"video/mp4"
    } else {
        b"video/x-matroska"
    };
    // THE READER'S LIMIT IS THE FULL u64 SPAN. Clamping it to
    // `usize::MAX` first - which this line used to do, to keep one value
    // behind the header, the reader and data_length - fixed the header
    // disagreement by TRUNCATING THE BODY instead: on the armv7 beta a
    // 5 GB completed file ended after ~4 GiB, and a 206 shipped fewer
    // bytes than its own Content-Range claimed. `Take` is u64, so the
    // reader was the one thing that never needed narrowing.
    //
    // What cannot carry a >4 GiB span on a 32-bit target is tiny_http's
    // `data_length`, which is `Option<usize>`. So the two cases split:
    // a span that FITS keeps the identity framing players want (exact
    // Content-Length, no chunking - `with_chunked_threshold(usize::MAX)`
    // below), and a span that does not is served CHUNKED with no
    // Content-Length at all, which is the honest answer and is what
    // tiny_http already does for `None` (see `choose_transfer_encoding`).
    // Content-Range still names the true span either way; a chunked 206
    // with a correct Content-Range is well-formed, a short one is not.
    // Both arms are a no-op on 64-bit, where the span always fits.
    let len = end - start;
    let fits = usize::try_from(len).ok();
    let mut headers = vec![
        tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype).unwrap(),
        tiny_http::Header::from_bytes(&b"Accept-Ranges"[..], &b"bytes"[..]).unwrap(),
    ];
    if fits.is_some() {
        headers.push(
            tiny_http::Header::from_bytes(&b"Content-Length"[..], len.to_string().into_bytes())
                .unwrap(),
        );
    }
    let mut resp = tiny_http::Response::new(
        tiny_http::StatusCode(status),
        headers,
        f.take(len),
        fits,
        None,
    )
    // Identity encoding with an exact length, as the live path does:
    // players seek against Content-Length and dislike chunked video.
    .with_chunked_threshold(usize::MAX);
    if status == 206 {
        resp.add_header(
            tiny_http::Header::from_bytes(
                &b"Content-Range"[..],
                format!("bytes {start}-{}/{total}", end - 1).into_bytes(),
            )
            .unwrap(),
        );
    }
    let _ = req.respond(resp);
}

// TODO 16m's question - "may this request answer its 404 now?" - and
// the store reading that supports it. A child module: see
// stream/admit.rs.
mod admit;
use admit::{
    ADMIT_WAIT_SECS, Custody, custody, hub_run_still_queued, no_writers_and_no_prospect,
    refuse_finished,
};

/// Is this finished job's payload IN FLIGHT to its final folder right
/// now - moving, or owed a move that has not run yet?
///
/// `mover_process` copies first and rewrites `Job::out_dir` only when
/// the copy is done, so for the whole duration of a move the history
/// record still names the folder the bytes are leaving. Anything that
/// resolves a file through that name - `/stream`'s finished-job branch
/// is the one this was written for - can therefore find nothing, and
/// "nothing is there" is NOT "the file is gone": the payload is whole,
/// it is simply somewhere neither name reaches yet.
///
/// Both halves are needed and neither implies the other.
/// `Job::move_pending` is the OWED marker: raised at park, cleared by
/// `mover_process` under the same hold that rewrites `out_dir` - so for
/// the completion move it covers the whole window on its own, from the
/// wait in the mover queue through the copy, with no seam at the end.
/// `Daemon::moving` is the live fence, and it is the ONLY marker over
/// the relocations that owe no `move_pending` at all: a recategorize
/// (`history_change_cat`) and a retry redrive both `move_tree` a
/// finished payload with the record still naming the source, which is
/// the same bulk copy to the same NAS and reads identically from here.
///
/// Read one lock at a time: the job's is taken and RELEASED before
/// `moving` is, so this adds no edge to the lock graph.
pub(super) fn payload_in_flight(d: &Daemon, job: &Arc<Mutex<Job>>) -> bool {
    let (owed, id) = {
        let j = job.lock_ok();
        (j.move_pending, j.nzo_id.clone())
    };
    owed || d.moving.lock_ok().contains(&id)
}

/// The finished-download branch: a job whose bytes are on disk, not in
/// the pipeline. Answers the request, or hands it back UNANSWERED
/// (`Some`) when this job is not one - the caller carries on with the
/// live path. Not a `Result`: a `tiny_http::Request` is 176 bytes and
/// clippy's `result_large_err` is right that it does not belong in one.
///
/// Without it the live path waits 30 s for media that is never coming
/// and then 404s. That gap was visible in the UI - "play the copy you
/// have" could only open the file in the daemon's own player, which does
/// nothing a remote viewer can see.
///
/// Byte-serving the LIVE pipeline is deliberately open (players cannot
/// send API keys, and it only ever carries the download in front of
/// you). A finished job is different: nzo_ids are enumerable, so this
/// would hand any LAN host the user's library a guess at a time. It
/// takes the same key-or-token gate as the library trigger, and the
/// /m3u handoff already embeds the token. That gate is also why the
/// admit wait re-asks this question AHEAD of its own `pick_media` and
/// not after: a job that finishes mid-request has its writers published
/// away, and a straggling one answered first would serve a finished job
/// in front of the gate.
///
/// Ahead of, and not INSTEAD of. This function judges the record, and
/// only one shape of it (`Completed && fetched && !tombstone`), while
/// the hub goes on holding a spent run's writers until the next job
/// claims it - so a `Failed` row, a tombstoned one, and the bare
/// `/stream` route with no record to read at all each reached the open
/// live path past this gate. [`hub_run_still_queued`] is the other half
/// and carries the measurement.
///
/// `filed` decides which file: a filed job's out_dir is the shared
/// `Show/Season NN` folder, where "the biggest media file in there" is a
/// sibling episode as often as not, so only the episode this job filed -
/// its stem, under the tail it was FILED with - may be served out of one.
fn serve_finished_from_disk(
    d: &Daemon,
    req: tiny_http::Request,
    job: &Arc<Mutex<Job>>,
    authed: bool,
) -> Option<tiny_http::Request> {
    let (done, dir, filed, stem, tail) = {
        let j = job.lock_ok();
        let sfx = delete_tail(&j, || d.job_suffix(filed_stem(&j)));
        (
            j.state == JobState::Completed && j.fetched && !j.tombstone,
            j.out_dir.clone(),
            j.filed,
            filed_stem(&j).to_string(),
            sfx,
        )
    };
    if !done {
        return Some(req);
    }
    if !authed {
        refuse_finished(d, req, "stream completed");
        return None;
    }
    // A private out_dir is all this job's, so the biggest media file in
    // it is the feature. A shared season folder is not.
    let found = if filed {
        crate::smart::find_filed_episode_media(&dir, &stem, &tail)
    } else {
        find_completed_media(&dir)
    };
    match found {
        Some(p) => serve_file_range(req, &p),
        // Nothing under the name the record carries - but the mover
        // rewrites that name LAST, so ask whether the payload is simply
        // in flight before calling it gone. Asked in this order, not
        // before the pick: the cross-device route stages its copy and
        // leaves the source whole until it publishes, so most of a long
        // NAS move still plays out of the old folder, and refusing on
        // the marker alone would take that away.
        //
        // NOT served from the destination. It is derivable
        // (`move_dest_root`), and what sits there mid-move is a
        // half-copied file under the payload's own name: a player handed
        // one plays the head and then hits a wall it cannot tell from a
        // corrupt release. A refusal that says "later" costs one retry;
        // a torn file costs the user's trust in the file itself.
        None if payload_in_flight(d, job) => {
            let _ = req.respond(
                tiny_http::Response::from_string(
                    "this download's files are being moved right now - \
                     try again when it settles",
                )
                .with_status_code(503)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Retry-After"[..], &b"5"[..])
                        .expect("static header"),
                ),
            );
        }
        // Moved away by hand, deleted, or a download with no video in
        // it. Say which, rather than the live path's "no active media".
        None => {
            let _ = req.respond(
                tiny_http::Response::from_string(
                    "this download has no playable file on disk any more",
                )
                .with_status_code(404),
            );
        }
    }
    None
}

/// One /stream request. `want = None` keeps the M11 contract (active
/// download, single attempt). `want = Some(id)` is M14i on-demand playback:
/// a parked library job is force-enqueued and we wait (≤30 s) for its
/// writers to appear before giving up. `authed` (API key or per-job token,
/// always true on keyless installs) gates that force-enqueue - it mutates
/// queue state, and nzo_ids are enumerable, so without the gate any LAN
/// host or CSRF page could start downloads past a user pause.
pub(super) fn stream_request(
    d: Arc<Daemon>,
    mut req: tiny_http::Request,
    want: Option<String>,
    authed: bool,
) {
    let mut deadline = Instant::now();
    // The record this request is about, held across the wait below.
    // Kept rather than re-found each pass because `activate_parked` and
    // `park` move the SAME `Arc` between the two stores - a handle taken
    // from either one stays the live record whichever store it is in.
    let mut tracked: Option<Arc<Mutex<Job>>> = None;
    // The instant the admit wait runs out, in unix seconds. An armed
    // auto-retry is a prospect only if it lands before this.
    let mut wait_ends = 0u64;
    if let Some(id) = &want {
        let parked = d
            .history
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == *id)
            .cloned();
        let running = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == *id)
            .cloned();
        let queued = running.is_some();
        if parked.is_none() && !queued {
            let _ = req
                .respond(tiny_http::Response::from_string("unknown nzo_id").with_status_code(404));
            return;
        }
        tracked = parked.clone().or(running);
        wait_ends = unix_now() as u64 + ADMIT_WAIT_SECS;
        // Did this request just PUT the job on the wire? The §16m
        // early-out below must not fire on a job it force-enqueued one
        // statement ago, whose writers are on their way.
        let mut triggered = false;
        if let Some(job) = &parked {
            // Never-fetched library entry: this play IS the download
            // trigger. Front of the queue, force → starts even if paused.
            let trigger = {
                let mut j = job.lock_ok();
                if j.library && !j.fetched && j.state == JobState::Completed {
                    if !authed {
                        drop(j);
                        let blocked = d.note_auth_failure(peer_ip(&req), "stream start");
                        let _ = req.respond(if blocked {
                            tiny_http::Response::from_string("too many bad keys")
                                .with_status_code(429)
                        } else {
                            tiny_http::Response::from_string(
                                "starting this download needs an apikey or stream token (?t=)",
                            )
                            .with_status_code(401)
                        });
                        return;
                    }
                    j.state = JobState::Queued;
                    // Force priority: pick_job starts it even while the
                    // queue is paused (the M14a semantics).
                    j.priority = 2;
                    j.paused = false;
                    true
                } else {
                    false
                }
            };
            if trigger {
                // The history -> queue move itself: stamped, queue first,
                // tombstone second, and never the tombstone alone. Shared
                // with `Daemon::retry` (see `moveseq::activate_parked`) so
                // the two paths cannot drift apart on the ordering their
                // durability depends on.
                d.activate_parked(job);
                triggered = true;
                info!(target: "library", "/stream/{id} → fetching now");
            } else {
                // Bytes already on disk: answer from there rather than
                // waiting out an admit deadline for writers that were
                // published away when the job finished.
                let Some(back) = serve_finished_from_disk(&d, req, job, authed) else {
                    return;
                };
                req = back;
            }
        }
        // TODO 16m: everything from here down is the wait for writers to
        // appear. When there are none and none can ever appear, the 404
        // is knowable NOW, and sitting out the 30 s only makes a player
        // (and the dashboard's ▶) look hung on an answer we already have.
        // Not `custody` here: both stores were just read by name, and a
        // record in neither of them has already been answered with
        // `unknown nzo_id` above - so there is no third case to find,
        // and asking again would only re-read what this scope knows.
        let held = if queued {
            Custody::Queued
        } else {
            Custody::Parked
        };
        if !triggered && no_writers_and_no_prospect(&d, id, parked.as_ref(), held, wait_ends) {
            let _ = req
                .respond(tiny_http::Response::from_string("no active media").with_status_code(404));
            return;
        }
        deadline = Instant::now() + std::time::Duration::from_secs(ADMIT_WAIT_SECS);
    }
    // ...and the SECOND half of 16m: that question is asked again on the
    // way round, because a job can run out of prospect DURING the wait.
    // A job that was Downloading when the request arrived, and completes
    // before the deadline, has its writers published away and - asked
    // only once, before the loop - then sat out the rest of the 30 s for
    // a 404, with its bytes finished on disk the whole time. Re-asking
    // converges the wait on whatever the entry path would say to a
    // request arriving right now, which for that job is "served from the
    // file".
    //
    // Once a second, not once a pass: this re-reads the queue, and the
    // defect being fixed is measured in tens of seconds, so 1 Hz answers
    // it inside a second while leaving the 10 Hz writer poll's cost
    // exactly where it was.
    let mut next_poll = Instant::now() + std::time::Duration::from_secs(1);
    loop {
        // Ahead of the live pick below, deliberately: see the gate note
        // on `serve_finished_from_disk`.
        if let Some(id) = &want
            && Instant::now() >= next_poll
        {
            next_poll = Instant::now() + std::time::Duration::from_secs(1);
            // The record's OWN custody, by identity - which is the half
            // that reads a delete. `tracked` is always `Some` while
            // `want` is (the entry path 404s before the loop when it is
            // not), so the fallback is unreachable rather than a
            // meaningful state; it is spelled as the waiting answer so
            // that if it ever became reachable it would cost a wait and
            // not a wrong 404.
            let held = tracked
                .as_ref()
                .map_or(Custody::Queued, |job| custody(&d, job));
            if no_writers_and_no_prospect(&d, id, tracked.as_ref(), held, wait_ends) {
                // Still asked of a deleted record, deliberately: a
                // history delete that KEPT the files leaves them
                // playable, and this branch is what served them before
                // the third case existed. `serve_finished_from_disk`
                // refuses a tombstoned row on its own, which is every
                // record the queue-delete arm produces.
                if let Some(job) = &tracked {
                    let Some(back) = serve_finished_from_disk(&d, req, job, authed) else {
                        return;
                    };
                    req = back;
                }
                let _ = req.respond(
                    tiny_http::Response::from_string("no active media").with_status_code(404),
                );
                return;
            }
        }
        // Only serve hub bytes that belong to the requested job.
        let owner_ok = match &want {
            None => true,
            Some(id) => d.active_stream.lock_ok().as_deref() == Some(id.as_str()),
        };
        if owner_ok && let Some((name, w)) = pick_media(&d, want.as_deref()) {
            // ...and only while the run that made them is still on the
            // queue. Past that they are a FINISHED download's residue,
            // and this route is open on the premise that it is not -
            // see [`hub_run_still_queued`].
            if !authed && !hub_run_still_queued(&d, want.as_deref()) {
                refuse_finished(&d, req, "stream spent");
                return;
            }
            // No pre-opened fd and no decryptor: an encrypted store
            // output holds PLAINTEXT while it downloads, so it serves
            // exactly like any other file. Until TODO 27 phase 3 it was
            // ciphertext until the finish decrypt, and `open_stream`
            // handed back a lock-consistent fd plus a `StreamCrypt` to
            // decrypt through on the fly.
            let seek = d.hub.seek.lock_ok().clone();
            serve_range(
                req,
                &name,
                w,
                None,
                seek,
                d.hub.stream_readers.clone(),
                d.hub.stream_gen.clone(),
                d.hub.stream_alive.clone(),
                d.hub.stream_stats.clone(),
            );
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = req.respond(tiny_http::Response::from_string("no active media").with_status_code(404));
}

// ---------------------------------------------------------------------------
// §73 phase 1: the preview-and-verify probe
// ---------------------------------------------------------------------------

/// The three states of the `preview` setting, in the order the settings
/// dropdown offers them.
///
/// `off` refuses `/preview/probe` outright: no half-downloaded file is
/// read for anyone, and the dashboard drops the panel. `metadata-only`
/// reads the container and says what the file is, with the handoff to
/// the user's own player that has always been there. `full` adds a
/// player in the page for the files this browser can actually open -
/// which is a question only the browser can answer, so the daemon says
/// what the file IS and the page decides what it can do with it.
pub(super) const PREVIEW_MODES: [&str; 3] = ["off", "metadata-only", "full"];

/// Default: what the file is, without a player. The verification value
/// is the part everyone wants; a video element in the page is a taste.
pub(super) const PREVIEW_DEFAULT: &str = "metadata-only";

/// The current mode, normalised - anything unrecognised reads as the
/// default rather than as "off", so a hand-edited settings.json cannot
/// silently disable a feature the user never turned off.
pub(super) fn preview_mode(d: &Daemon) -> String {
    let m = d.preview.lock_ok().clone();
    if PREVIEW_MODES.contains(&m.as_str()) {
        m
    } else {
        PREVIEW_DEFAULT.to_string()
    }
}

/// The still-downloading main video of `id`, as something the probe can
/// read: its output name, its writer, and a reader that answers
/// `WouldBlock` for bytes that have not landed.
///
/// `None` means there is nothing to read yet - `id` is not the job the
/// pipeline is running, it has written no media file (an archive shape
/// that only produces one at unpack time), or the writer's backing file
/// has already been published away because the job finished. That last
/// case is NOT an error: the answer moved to disk, and both callers fall
/// through to the on-disk path.
pub(super) fn open_live_probe(
    d: &Daemon,
    id: &str,
) -> Option<(
    String,
    Arc<nzbkit::disk::FileWriter>,
    nzbkit::mediaprobe::LiveProbeReader,
    // Held for the reader's life - see [`open_live_media`].
    Option<nzbkit::disk::ReadLease>,
)> {
    // A probe never waits out an external repair: it has a "not yet"
    // answer, and the 30 s admit wait belongs to the range path only.
    let (name, w, f, lease) = open_live_media_admit(d, id, false)?;
    let r = nzbkit::mediaprobe::LiveProbeReader {
        w: w.clone(),
        f,
        pos: 0,
    };
    Some((name, w, r, lease))
}

/// The same resolution, one step earlier: the open file, before either
/// reader wraps it.
///
/// [`open_live_probe`] hands back the non-blocking reader a poll wants;
/// the remux path needs the same file under a reader that WAITS, so the
/// step both share lives here rather than being written twice.
pub(super) fn open_live_media(
    d: &Daemon,
    id: &str,
) -> Option<(
    String,
    Arc<nzbkit::disk::FileWriter>,
    std::fs::File,
    Option<nzbkit::disk::ReadLease>,
)> {
    open_live_media_admit(d, id, true)
}

/// [`open_live_media`] with the custody wait chosen by the caller:
/// `wait` = sit out an in-progress external repair (bounded, for a
/// player that wants its bytes); `!wait` = answer `None` at once, for
/// the probe paths that have a "not yet" to give instead.
fn open_live_media_admit(
    d: &Daemon,
    id: &str,
    wait: bool,
) -> Option<(
    String,
    Arc<nzbkit::disk::FileWriter>,
    std::fs::File,
    Option<nzbkit::disk::ReadLease>,
)> {
    let live = d.active_stream.lock_ok().as_deref() == Some(id);
    if !live {
        return None;
    }
    let (name, w) = pick_media(d, Some(id))?;
    // Every output - encrypted store included, since TODO 27 phase 3
    // put plaintext on disk from the first article - opens through the
    // writer's custody gate (sweep 8, M4/M6): the lease is what an
    // external repair can see and, on Windows, revoke, and the open
    // follows `current_path`, so a verified-name publish under the live
    // writer does not send this at a path that no longer exists.
    let (f, lease) = if wait {
        w.open_read().ok()?
    } else {
        w.try_open_read().ok()?
    };
    Some((name, w, f, Some(lease)))
}

/// The finished main video of `job` on disk. A private `out_dir` is all
/// this job's, so the biggest media file in it is the feature; a shared
/// season folder is not, and only the episode this job filed may be read
/// out of it.
pub(super) fn finished_media_path(d: &Daemon, job: &Arc<Mutex<Job>>) -> Option<PathBuf> {
    finished_media_path_checked(d, job).ok().flatten()
}

/// The same lookup, with the reason a miss was a miss still attached.
///
/// `Ok(None)` means the output directory resolved and simply holds no
/// media file of ours - a deleted payload, a season pack that never
/// filed, a failed download. `Err` means we could not look: the volume
/// is not mounted under a parent that IS, the OS declined the folder
/// (a launchd-started daemon reaching a TCC-gated Downloads folder), a
/// network mount has not woken, a handle went stale. Everything below
/// erased both into `None`, and the history re-derivation then recorded
/// "no payload" for a disk it had never managed to read (Codex sweep 7,
/// M6).
///
/// The check is at the ROOT of the walk on purpose. That is where a
/// volume that is absent, asleep or forbidden announces itself, and it
/// costs one `opendir` that the walk is about to do anyway. An I/O
/// error partway down a subdirectory still reads as "not found", which
/// is the same answer as before and no worse.
pub(super) fn finished_media_path_checked(
    d: &Daemon,
    job: &Arc<Mutex<Job>>,
) -> std::io::Result<Option<PathBuf>> {
    let (dir, filed, stem, tail) = {
        let j = job.lock_ok();
        let sfx = delete_tail(&j, || d.job_suffix(filed_stem(&j)));
        (j.out_dir.clone(), j.filed, filed_stem(&j).to_string(), sfx)
    };
    match std::fs::read_dir(&dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    Ok(if filed {
        crate::smart::find_filed_episode_media(&dir, &stem, &tail)
    } else {
        find_completed_media(&dir)
    })
}

/// One `GET /preview/probe/{nzo_id}` - what the file IS, from whatever
/// bytes have landed.
///
/// Deliberately cheap and deliberately non-blocking: the probe reads
/// container headers only (a few hundred KB at most, and never the
/// payload), and reports a region that has not downloaded yet as
/// "pending" rather than waiting for it. The client polls; nothing here
/// holds a worker thread the way [`stream_request`] can.
///
/// The one thing it DOES ask the download for is a promotion: a file
/// whose index sits at the end (a moov-at-end MP4, Matroska's
/// SeekHead-indexed Chapters) cannot be read until that tail arrives, so
/// the probe pulls the same tail window the playhead promotion keeps hot
/// and answers "pending" this time round. The next poll usually has it.
pub(super) fn preview_probe_request(d: Arc<Daemon>, req: tiny_http::Request, id: String) {
    let mut body = serde_json::json!({
        "nzo_id": id,
        "file": serde_json::Value::Null,
        "size": 0,
        "coverage": serde_json::Value::Null,
        "source": "none",
        "pending": false,
        "media": serde_json::Value::Null,
    });

    if let Some((name, w, mut r, _lease)) = open_live_probe(&d, &id) {
        let need_tail = fill_live_probe(&mut body, &name, &w, || {
            nzbkit::mediaprobe::probe(
                &mut r,
                nzbkit::mediaprobe::ProbeHint {
                    filename: Some(name.clone()),
                    known_size: Some(w.size),
                },
            )
        });
        if need_tail && let Some(sc) = d.hub.seek.lock_ok().clone() {
            // The index is in the part that has not arrived. Ask for it
            // the same way a seek does; the poll after next reads it.
            let (n, _) = promote_playhead(&sc, &name, &w, 0);
            if n > 0 {
                info!(target: "preview", "{id}: promoted {n} article(s) for the file index");
            }
        }
        let _ = req.respond(json_resp(body));
        return;
    }

    // Not the live job: a finished download's bytes are on disk.
    let Some(job) = d.history_job(&id) else {
        let _ = req.respond(
            json_resp(serde_json::json!({"error": "unknown or not yet downloading"}))
                .with_status_code(404),
        );
        return;
    };
    let Some(path) = finished_media_path(&d, &job) else {
        // Nothing under the name the record carries. Ask - after the
        // pick and never before it, for the reason `payload_in_flight`
        // gives - whether the payload is simply in flight to its final
        // folder, because the mover rewrites that name LAST. `/stream`
        // one door down answers this state 503; so does this, with its
        // own `error` string: a client that reads "no playable file on
        // disk" gives up on a file that is whole and about to be
        // readable again.
        let _ = if payload_in_flight(&d, &job) {
            req.respond(
                json_resp(serde_json::json!({
                    "error": "the files are being moved right now - \
                              try again when it settles",
                    "moving": true,
                }))
                .with_status_code(503)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Retry-After"[..], &b"5"[..])
                        .expect("static header"),
                ),
            )
        } else {
            req.respond(
                json_resp(serde_json::json!({"error": "no playable file on disk"}))
                    .with_status_code(404),
            )
        };
        return;
    };
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    body["file"] = name.clone().into();
    body["size"] = size.into();
    body["source"] = "disk".into();
    body["coverage"] = serde_json::json!({"head_bytes": size, "pct": 100.0, "tail_ok": true});
    match std::fs::File::open(&path) {
        Ok(mut f) => {
            match nzbkit::mediaprobe::probe(
                &mut f,
                nzbkit::mediaprobe::ProbeHint {
                    filename: Some(name),
                    known_size: Some(size),
                },
            ) {
                Ok(info) => {
                    body["media"] = serde_json::to_value(&info).unwrap_or(serde_json::Value::Null)
                }
                Err(e) => body["error"] = e.to_string().into(),
            }
            let _ = req.respond(json_resp(body));
        }
        Err(_) => {
            let _ = req.respond(json_resp(body).with_status_code(410));
        }
    }
}

/// The live half of a probe answer: what the walk read, and the
/// coverage it ran under. Returns true when the file's index sits in
/// bytes that have not arrived, so the caller should promote the tail.
///
/// **The order is the contract: walk first, sample coverage after.**
/// Coverage only ever grows, and the walk cannot read a byte that is
/// not covered, so a snapshot taken first can describe less of the file
/// than the parse went on to read - and `head_bytes: 0` beside a fully
/// parsed container is not a state the download was ever in, it is two
/// instants in one answer. Sampling last cannot under-report what the
/// parse used, which makes the whole class structurally impossible
/// rather than merely unlikely. The reverse staleness is harmless: a
/// region that lands mid-walk shows up as coverage the parse did not
/// use yet, and the next poll reads it.
fn fill_live_probe(
    body: &mut serde_json::Value,
    name: &str,
    w: &Arc<nzbkit::disk::FileWriter>,
    probe: impl FnOnce() -> Result<nzbkit::mediaprobe::MediaInfo, nzbkit::mediaprobe::ProbeError>,
) -> bool {
    let info = probe();
    let covered = w.contiguous_from_start();
    let tail_from = w.size.saturating_sub(TAIL_KEEP);
    let tail_ok = w.covered(tail_from, w.size - tail_from);
    body["file"] = name.into();
    body["size"] = w.size.into();
    body["source"] = "live".into();
    body["coverage"] = serde_json::json!({
        "head_bytes": covered,
        "pct": if w.size > 0 { (covered as f64 * 100.0 / w.size as f64 * 10.0).round() / 10.0 } else { 0.0 },
        "tail_ok": tail_ok,
    });
    match info {
        Ok(info) => {
            let need_tail = !info.complete && !tail_ok;
            body["pending"] = (!info.complete).into();
            body["media"] = serde_json::to_value(&info).unwrap_or(serde_json::Value::Null);
            need_tail
        }
        // Not enough bytes to even identify the container: a poll, not
        // an error - this is a download that just started.
        Err(nzbkit::mediaprobe::ProbeError::NotYet) => {
            body["pending"] = true.into();
            false
        }
        Err(e) => {
            body["error"] = e.to_string().into();
            false
        }
    }
}

// ---------------------------------------------------------------------------
// A2 (playback contract v1): readiness as API truth
// ---------------------------------------------------------------------------

/// How long a finished job's disk answer is reused before the walk runs
/// again. The answer only changes when someone moves or deletes the
/// files, and the compact mobile poll asks for a page of history every
/// few seconds on a phone that is also playing video.
const DISK_READINESS_TTL_SECS: u64 = 30;

/// The file `/stream/{id}` would serve if a player asked right now, and
/// whether it can be played yet.
///
/// This is the A2 contract's "readiness as API truth": the same question
/// `/preview/probe` answers per job, in a form a job list can carry, and
/// decided by the same two functions the byte-serving path picks its
/// file with ([`open_live_probe`] live, [`finished_media_path`] on
/// disk) - so a client that is told "ready" is told it about the file it
/// will actually receive.
///
/// Deliberately read-only: unlike the probe it never promotes articles
/// for a file index. A list poll must not steer the download queue, and
/// a client that wants the index pulled has `/preview/probe/{id}`.
///
/// `reason` is a closed token set, so a client can branch without
/// parsing prose: `live` (playable, still downloading), `disk`
/// (playable, finished), `pending` (downloading, not enough of the
/// container yet), `not_fetched` (a library entry - playing it IS the
/// download trigger), `not_started` (queued or paused), `moving`
/// (finished, and the payload is in flight to its final folder - not
/// playable this second, playable again when the move lands),
/// `no_media` (finished with no playable file on disk any more),
/// `failed`, `unknown`.
///
/// `moving` is its own token rather than a shade of `no_media` for the
/// reason [`payload_in_flight`] exists at all: those two want opposite
/// things from a client. `no_media` is final - stop asking, drop the
/// Play affordance, the file is gone. `moving` is a wait, and a client
/// that reads it as `no_media` writes the payload off mid-relocation.
/// Both keep `ready: false`, so an existing client that branches on
/// that (both native shells do) is right about the new token without
/// knowing it: no Play button, because `/stream` would answer 503.
pub(super) fn playback_readiness(d: &Daemon, id: &str) -> serde_json::Value {
    let mut o = serde_json::json!({
        "ready": false,
        "reason": "unknown",
        "file": serde_json::Value::Null,
        "size": 0,
        "source": "none",
        "coverage": serde_json::Value::Null,
        "seekable": false,
    });
    if let Some((name, w, mut r, _lease)) = open_live_probe(d, id) {
        let mut body = serde_json::json!({});
        fill_live_probe(&mut body, &name, &w, || {
            nzbkit::mediaprobe::probe(
                &mut r,
                nzbkit::mediaprobe::ProbeHint {
                    filename: Some(name.clone()),
                    known_size: Some(w.size),
                },
            )
        });
        // Same predicate the dashboard's Play affordance uses: a parsed
        // container means a player can start on what has landed.
        let ready = !body["media"].is_null();
        let tail_ok = body["coverage"]["tail_ok"] == serde_json::Value::Bool(true);
        o["ready"] = ready.into();
        o["reason"] = if ready { "live" } else { "pending" }.into();
        o["file"] = body["file"].clone();
        o["size"] = body["size"].clone();
        o["source"] = "live".into();
        o["coverage"] = body["coverage"].clone();
        // The strongest "scrubbing will work" predicate there is: the
        // index at the end of the file has arrived.
        o["seekable"] = (ready && tail_ok).into();
        return o;
    }
    let Some(job) = d.history_job(id) else {
        // Still in the queue. A job whose bytes are moving but whose
        // media file cannot be read yet is PENDING, not "not started" -
        // the download begins with the archive volumes, and the media
        // writer only appears once the first of them unpacks. Anything
        // parked (queued, paused, held) has not begun.
        let running = {
            // §91: the id test and the state read are one lock on the
            // record, so no job can answer for the state it was in
            // before the walk found it.
            let q = d.queue.lock_ok();
            q.iter().find_map(|j| {
                let j = j.lock_ok();
                (j.nzo_id == *id).then(|| {
                    matches!(j.state, JobState::Downloading | JobState::Finishing)
                        && !j.suspended
                        && !j.paused
                })
            })
        };
        o["reason"] = match running {
            Some(true) => "pending",
            Some(false) => "not_started",
            None => "unknown",
        }
        .into();
        return o;
    };
    let (state, fetched, library, tombstone) = {
        let j = job.lock_ok();
        (j.state, j.fetched, j.library, j.tombstone)
    };
    match state {
        JobState::Failed => {
            o["reason"] = "failed".into();
            return o;
        }
        // A library entry nobody has fetched: /stream/{id} starts the
        // download (with a key or the job's stream token). Not ready,
        // but startable - a different sentence from "no media".
        JobState::Completed if library && !fetched => {
            o["reason"] = "not_fetched".into();
            return o;
        }
        JobState::Completed if fetched && !tombstone => {}
        _ => {
            o["reason"] = "not_started".into();
            return o;
        }
    }
    let found = disk_media_memo(d, id, &job);
    match found {
        Some((name, size)) => {
            o["ready"] = true.into();
            o["reason"] = "disk".into();
            o["file"] = name.into();
            o["size"] = size.into();
            o["source"] = "disk".into();
            o["coverage"] = serde_json::json!({
                "head_bytes": size, "pct": 100.0, "tail_ok": true,
            });
            o["seekable"] = true.into();
        }
        // Asked in this order - after the pick, exactly as the
        // byte-serving path asks it. The cross-device move stages its
        // copy and leaves the source whole until it publishes, so most
        // of a long move still resolves out of the old folder and is
        // honestly `disk`; refusing on the marker alone would take that
        // away from every job with a move owed.
        None if payload_in_flight(d, &job) => o["reason"] = "moving".into(),
        None => o["reason"] = "no_media".into(),
    }
    o
}

/// [`finished_media_path`] behind a short-TTL memo - see
/// [`DISK_READINESS_TTL_SECS`] for why. Returns the file's name and its
/// size on disk.
fn disk_media_memo(d: &Daemon, id: &str, job: &Arc<Mutex<Job>>) -> Option<(String, u64)> {
    let now = unix_now().max(0) as u64;
    {
        let memo = d.playback_disk.lock_ok();
        if let Some((at, v)) = memo.get(id)
            && now.saturating_sub(*at) < DISK_READINESS_TTL_SECS
        {
            return v.clone();
        }
    }
    let v = finished_media_path(d, job).map(|p| {
        let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        (
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            size,
        )
    });
    // A miss taken while the payload is in flight is not a fact about
    // the disk, it is a fact about the instant: the mover rewrites
    // `out_dir` last, so the walk read a folder the bytes have left.
    // Memoizing it would outlive the move by up to the TTL and answer
    // `no_media` - the one sentence the `moving` token exists to keep
    // off a payload that is whole - about a file that has already
    // landed. Left uncached instead, so the first poll after the move
    // publishes walks again and reads `disk`. The opposite staleness is
    // left alone: a hit cached BEFORE the move began still reads `disk`
    // for the rest of its TTL, which is the ordinary TTL bargain and
    // errs towards "try it", where `/stream` answers 503 and the client
    // retries.
    if v.is_none() && payload_in_flight(d, job) {
        return None;
    }
    let mut memo = d.playback_disk.lock_ok();
    // Drop what has aged out rather than letting a long-lived daemon's
    // whole history sit in here.
    memo.retain(|_, (at, _)| now.saturating_sub(*at) < DISK_READINESS_TTL_SECS);
    memo.insert(id.to_string(), (now, v.clone()));
    v
}

// ---------------------------------------------------------------------------
// M11: HTTP range streaming over a still-downloading file
// ---------------------------------------------------------------------------

/// Reader that refuses to run ahead of the writer: each chunk waits until
/// its bytes are really on disk (bounded poll), so a media player can sit
/// on a socket while the download races ahead of the playhead.
pub(super) struct LiveRangeReader {
    w: Arc<nzbkit::disk::FileWriter>,
    f: std::fs::File,
    pos: u64,
    end: u64,
    /// M11 seek promotion: handle + our output name. `promoted_to` is the
    /// end of the last promoted window - the reader keeps it rolling
    /// AHEAD of the playhead so the next span is fetching before the
    /// player ever blocks on it (reactive-only promotion guaranteed a
    /// visible stall at every window boundary).
    seek: Option<Arc<crate::SeekCtl>>,
    name: String,
    promoted_to: u64,
    /// Attached-reader gauge (drives the pool's hot lane); decremented on
    /// drop so an abandoned player connection frees the lane.
    readers: Arc<std::sync::atomic::AtomicUsize>,
    /// This reader's generation vs the set of ALIVE readers: only the
    /// newest living /stream request may promote (players open a fresh
    /// request per seek; a superseded reader steering the queue causes
    /// ping-pong, and a dead probe must hand rights back).
    my_gen: u64,
    alive: Arc<std::sync::Mutex<std::collections::BTreeSet<u64>>>,
    /// End of a span already judged terminally undeliverable: reads
    /// inside [pos, dead_until) zero-fill immediately. The verdict is
    /// taken ONCE for the whole hole (up to the next covered byte) -
    /// tiny_http reads in 8 KB chunks, and re-litigating per read call
    /// turned one dead article into minutes of grace waits. Coverage
    /// is still re-checked every read, so bytes that DO land inside a
    /// condemned span (a retry, a repair) serve as real data.
    dead_until: u64,
    /// A2: what this reader has had to do, for the clients' health
    /// overlay. Shared with every other reader on the hub.
    stats: Arc<crate::StreamStats>,
    /// Custody of the backing file (sweep 8, M4). When it is revoked -
    /// Windows only - this response ends rather than hold the inode
    /// against par2cmdline's share-mode-0 open.
    lease: Option<nzbkit::disk::ReadLease>,
}

impl LiveRangeReader {
    fn newest_alive(&self) -> bool {
        self.alive.lock_ok().iter().next_back() == Some(&self.my_gen)
    }

    /// The external repair wants this file's inode and our handle is in
    /// its way (sweep 8, M4). Ending the response drops the handle; the
    /// player reopens against the repaired file. Always `None` off
    /// Windows, where sharing is not enforced and a live reader costs
    /// the repair nothing.
    fn revoked(&self) -> Option<std::io::Error> {
        self.lease.as_ref().filter(|l| l.revoked()).map(|_| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the file is being repaired - reopen the stream",
            )
        })
    }

    /// The extractor has disowned the file under this response (sweep 8,
    /// M4, defect 3). Unlike [`revoked`] this fires on EVERY platform:
    /// the file is unlinked and no byte will ever be written through
    /// this writer again, so a read that waits here waits for ever.
    ///
    /// The shape is a damaged MULTI-VOLUME set. It demotes to
    /// "materializing volumes for repair" BEFORE par2 runs, and that
    /// demote abandons the extracted media file - which is the very file
    /// a player is holding. Nothing revoked it (par2's targets are the
    /// volumes, and this output is not even on disk by then), so the
    /// response used to sit on a frontier that would never move again
    /// and die of the five-minute span timeout below: a player hung for
    /// five minutes on a job that repaired fine. Measured on macOS
    /// arm64 and on an x86-64 Windows 11 laptop, 22 Aug 2026.
    ///
    /// Ending the response is the whole answer, and there is nothing to
    /// rebind onto: the bytes under this handle belong to an unlinked
    /// inode the job has disowned, and the post-repair re-extract
    /// rewrites the same NAME from the repaired volumes. See
    /// [`FileWriter::abandon`] for why this is not custody.
    ///
    /// [`revoked`]: LiveRangeReader::revoked
    /// [`FileWriter::abandon`]: nzbkit::disk::FileWriter::abandon
    ///
    /// Logged, not silent, and at most once per response: the first hit
    /// returns an error out of `read`, tiny_http ends the response and
    /// nothing reads again. It is also the only trace this leaves - the
    /// regression test reads for it rather than for a response that
    /// merely happened to end (`stream_repair.rs` leg 2).
    fn abandoned(&self) -> Option<std::io::Error> {
        self.w.is_abandoned().then(|| {
            info!(
                target: "stream",
                "{}: ending the response at {} - the extractor abandoned this output",
                self.name, self.pos
            );
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the file was rebuilt for repair - reopen the stream",
            )
        })
    }

    /// Follow an external repair onto its new inode (sweep 8, M5b).
    ///
    /// par2cmdline does not repair in place - it renames the damaged
    /// target to `<name>.1` and writes the repaired data fresh - so the
    /// handle this response opened is the DAMAGED file from the moment
    /// the repair completes. M5's coverage publication then tells us
    /// those bytes are good and we serve the hole. Reopening at
    /// `current_path` is the whole fix: same offset, same response, the
    /// file the repair actually wrote. Windows never gets here (the
    /// lease is revoked and the response ends before par2 runs).
    ///
    /// Called only right before the read that uses the handle: every
    /// other decision in `read` is taken from the writer's coverage map,
    /// which survives the repair regardless of which inode holds the
    /// bytes.
    ///
    /// A reopen that FAILS keeps the old handle and plays on. It is the
    /// wrong file, but it is the file this response was serving a
    /// moment ago either way, and there is nothing to be gained by
    /// turning a repair the player never asked for into a dead socket.
    fn rebind(&mut self) {
        if !self.lease.as_ref().is_some_and(|l| l.needs_reopen()) {
            return;
        }
        let lease = self.lease.as_ref().expect("checked immediately above");
        match self.w.reopen_read(lease) {
            Ok(f) => {
                self.f = f;
                info!(
                    target: "stream",
                    "{}: reopened at {} - an external repair rewrote the file",
                    self.name, self.pos
                );
            }
            Err(e) => warn!(
                target: "stream",
                "{}: still on the pre-repair file - could not reopen: {e}",
                self.name
            ),
        }
    }

    /// Is plaintext `[pos, pos+len)` serveable now?
    ///
    /// One line since TODO 27 phase 3: an encrypted store output holds
    /// plaintext while it downloads, so there is no ciphertext-block
    /// widening (`StreamCrypt::covered_bounds`) left to do.
    fn covered(&self, pos: u64, len: u64) -> bool {
        self.w.covered(pos, len)
    }

    /// Length of the covered prefix at the cursor, up to `n`: 0 when
    /// the cursor byte itself has not landed. Binary search over
    /// `covered`. Only called at coverage boundaries (a window that is neither
    /// fully covered nor fully hole), so the ~17 interval probes are
    /// nowhere near any hot path.
    fn covered_prefix(&self, n: u64) -> u64 {
        if n == 0 || !self.covered(self.pos, 1) {
            return 0;
        }
        let (mut lo, mut hi) = (1u64, n);
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            if self.covered(self.pos, mid) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo
    }

    /// The whole uncovered hole under the cursor, bounded to `scan`
    /// bytes: the span a dead-span verdict should be taken over, ending
    /// at the next covered byte so real data resumes right behind it.
    /// The cursor byte itself must be uncovered (both callers serve a
    /// covered head as a short read first) - a covered interval AT the
    /// cursor would be clipped to start exactly at `pos` and the
    /// `> pos` filter below would skip it, mistaking real bytes for
    /// hole.
    fn uncovered_hole_len(&self, scan: u64) -> u64 {
        let next_covered = self
            .w
            .covered_intervals(self.pos, scan)
            .into_iter()
            .map(|(s, _)| s)
            .filter(|s| *s > self.pos)
            .min();
        match next_covered {
            Some(s) => s - self.pos,
            None => scan,
        }
    }
}

impl Drop for LiveRangeReader {
    fn drop(&mut self) {
        self.readers.fetch_sub(1, Ordering::Relaxed);
        self.alive.lock_ok().remove(&self.my_gen);
    }
}

/// Bytes promoted ahead of the playhead (~85 ms of line time at 3 Gbps -
/// a promoted window lands before the player drains its own buffer).
pub(super) const SEEK_READAHEAD: u64 = 32_000_000;
/// Re-promote when the playhead gets this close to the promoted edge -
/// the next window is fetching while the current one still has runway.
pub(super) const ROLL_MARGIN: u64 = 12_000_000;

/// Runway: after a blocked read (a stall - the span wasn't there), hold
/// the response until this much contiguous data PAST the position has
/// landed, so the player buffers once and then streams smoothly instead
/// of stuttering span by span. Env NZBFAST_STREAM_RUNWAY_MB overrides
/// (0 = first covered chunk streams immediately, the old behavior).
pub(super) fn stream_runway() -> u64 {
    static RUNWAY: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *RUNWAY.get_or_init(|| {
        std::env::var("NZBFAST_STREAM_RUNWAY_MB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|mb| mb * 1_000_000)
            .unwrap_or(16_000_000)
    })
}

/// Cap on how long a blocked read holds out for the FULL runway once
/// the bytes under the cursor have landed. The runway is a batching
/// hint, not a debt: on a fast line it fills inside this cap and
/// nothing changes, but on a line slower than the runway/cap ratio
/// (~5 MB/s) an uncapped wait turned into a stare - measured on the
/// chaos rig, play start took 31 s at 0.6 MB/s and every seek 12 s at
/// 1.3 MB/s, all of it spent waiting for 16 MB that the line could not
/// possibly deliver sooner. Past the cap the reader serves what it has
/// and lets the player's own buffering take over.
/// Env NZBFAST_STREAM_RUNWAY_WAIT_MS overrides for A/B tuning.
pub(super) fn stream_runway_wait_ms() -> u64 {
    static CAP: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("NZBFAST_STREAM_RUNWAY_WAIT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3_000)
    })
}

/// Grace before a blocked read even starts asking whether its span is
/// terminally undeliverable, and the spacing of the consecutive
/// verdicts it requires. The check itself is authoritative (pool item
/// state), so the grace only has to outlive the blind windows
/// `QueueControl::any_live` documents - not any network timeout.
///
/// Round 3 of the stream hardening rig
/// (research/STREAM-HARDENING-2026-08.md) A/B'd a tightened window
/// (2000/500, earliest verdict 6.0 s -> 2.5 s of blocked wait - safe
/// in principle since `arrival_ack` closed the channel/consumer blind
/// window) and measured the true hole's rebuffer dominated by the
/// retry ladder keeping the missing articles LIVE, not by this window:
/// the tightening bought ~0.3-0.6 s inside a ~4 s bimodal noise band.
/// Kept at 5000/1000/2 - the margin costs almost nothing and the
/// verdict must never condemn bytes the pool still means to retry.
/// Env overrides exist so the next round's A/B needs no rebuild.
fn dead_span_grace_ms() -> u64 {
    static G: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *G.get_or_init(|| {
        std::env::var("NZBFAST_STREAM_DEAD_SPAN_GRACE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5_000)
    })
}
fn dead_span_vote_ms() -> u64 {
    static V: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("NZBFAST_STREAM_DEAD_SPAN_VOTE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(1_000)
    })
}
/// Consecutive "nothing live can deliver this" verdicts required
/// before the reader zero-fills; see `QueueControl::any_live` for the
/// race this papers over. Two votes spaced `dead_span_vote_ms` apart
/// means a false verdict needs the span invisible at two instants that
/// far apart - the ms-scale blind windows cannot span both.
fn dead_span_votes() -> u32 {
    static N: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("NZBFAST_STREAM_DEAD_SPAN_VOTES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(2)
    })
}

/// How long a blocked read waits once NO fetch run is attached (the
/// run drained or the job parked) before it concludes the hole under
/// the cursor is never coming. This window is what settle-side repair
/// gets: a repair that covers the span inside it un-blocks the read
/// with REAL bytes, so it must be long enough for a plausible repair
/// pass, short enough that a failed job's preview does not sit frozen
/// for the full 5-minute timeout. Env NZBFAST_STREAM_DEAD_GRACE_MS
/// overrides (the regression tests shrink it).
fn stream_dead_grace_ms() -> u64 {
    static G: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *G.get_or_init(|| {
        std::env::var("NZBFAST_STREAM_DEAD_GRACE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(15_000)
    })
}

/// Kill switch for the degraded-playback path: NZBFAST_STREAM_ZEROFILL=0
/// restores the old wait-out-the-timeout behavior.
fn stream_zerofill() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| !std::env::var("NZBFAST_STREAM_ZEROFILL").is_ok_and(|v| v == "0"))
}

/// Bytes of file tail kept hot alongside the playhead window (matches the
/// queue-build tail burst; MKV Cues / MP4 moov live there).
pub(super) const TAIL_KEEP: u64 = 8_000_000;
/// Bytes promoted BEHIND the position: after a seek, players commonly
/// read slightly before the byte target too (preceding keyframe cluster,
/// audio preroll) - without this each such read is its own serial
/// blocked round-trip.
pub(super) const PRE_ROLL: u64 = 4_000_000;

/// One promotion covering the playhead window AND - while it's still
/// uncovered - the file tail. A single call because each promote rewrites
/// the queue's promoted set: promoting only [pos, pos+window] would
/// displace the tail-burst articles, and a player asks for the tail
/// (seek index) at any moment.
pub(super) fn promote_playhead(
    sc: &crate::SeekCtl,
    name: &str,
    w: &nzbkit::disk::FileWriter,
    pos: u64,
) -> (usize, u64) {
    let end = (pos + SEEK_READAHEAD).min(w.size);
    let tail = w.size.saturating_sub(TAIL_KEEP);
    let mut spans = vec![(pos.saturating_sub(PRE_ROLL), end)];
    if !w.covered(tail, w.size - tail) {
        spans.push((tail, w.size));
    }
    (sc.promote_output_spans(name, w.size, &spans, true), end)
}

impl std::io::Read for LiveRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.end {
            return Ok(0);
        }
        if let Some(e) = self.revoked().or_else(|| self.abandoned()) {
            return Err(e);
        }
        // Keep the pool's stream mode fresh for as long as the player
        // actually reads - pipelines stay shallow, promotions stay fast.
        if let Some(sc) = &self.seek {
            sc.note_stream();
        }
        let n = (buf.len() as u64).min(self.end - self.pos).min(256 * 1024) as usize;
        // Rolling readahead: keep [pos, pos+SEEK_READAHEAD] promoted as
        // the playhead advances. A no-op when the span is already fetched
        // (nothing pending to move), so linear playback behind the
        // frontier costs one compare per read.
        let current = self.newest_alive();
        if let Some(sc) = &self.seek {
            // promoted_to == size means the window already reaches EOF -
            // without that check the margin test fires on every read for
            // the file's last few MB (promote spam).
            if current
                && self.promoted_to < self.w.size
                && self.pos + ROLL_MARGIN > self.promoted_to
            {
                let (moved, end) = promote_playhead(sc, &self.name, &self.w, self.pos);
                self.promoted_to = end;
                if moved > 0 {
                    info!(
                        target: "stream",
                        "readahead@{} → promoted {moved} article(s)",
                        self.pos
                    );
                }
            }
        }
        // Bytes under the cursor that HAVE landed are never waited on
        // and never zero-filled: a window straddling the frontier (or
        // the edge of a condemned hole) shrinks to its covered head and
        // serves that as a short read - the hole then starts exactly at
        // the next read's cursor. Without this, the dead-span paths
        // below judged a straddling window by its hole and zero-filled
        // from `pos`, replacing up to a read's worth of real, landed
        // bytes with zeros.
        let n = match self.covered(self.pos, n as u64) {
            true => n,
            false => match self.covered_prefix(n as u64) {
                0 => n,
                head => head as usize,
            },
        };
        // Fast path through a condemned hole: the dead-span verdict was
        // already taken for [pos, dead_until) - zero-fill chunk by
        // chunk without re-waiting. Bytes that landed since (retry,
        // repair) win: the covered check runs first, every read.
        if self.pos < self.dead_until && !self.covered(self.pos, n as u64) {
            let hole = self
                .uncovered_hole_len(self.dead_until - self.pos)
                .min(self.dead_until - self.pos);
            let gap = nzbkit::disk::chunk_len(hole, n);
            if gap > 0 {
                buf[..gap].fill(0);
                self.stats
                    .zero_filled_bytes
                    .fetch_add(gap as u64, Ordering::Relaxed);
                self.pos += gap as u64;
                return Ok(gap);
            }
        }
        // Wait (up to 5 min) for the span to land - a stalled provider
        // should buffer the player, not corrupt the stream. If we block
        // at all, prefer to come back with RUNWAY bytes, not just this
        // chunk (one buffering pause instead of a stutter per span) -
        // but the runway is capped in TIME, not owed in bytes: once the
        // cursor bytes are here, a slow line stops the batching wait at
        // stream_runway_wait_ms and serves what it has. Only the bytes
        // under the cursor may hold the read - a hole further along the
        // runway is the next read's problem, not this one's (waiting on
        // it here turned one missing article up to 16 MB ahead into a
        // full stall of perfectly playable video).
        if !self.covered(self.pos, n as u64) {
            // A2 telemetry: this read is about to wait for its span -
            // server-side, that IS the viewer's buffering event.
            self.stats.blocked_reads.fetch_add(1, Ordering::Relaxed);
            let runway = (n as u64).max((self.end - self.pos).min(stream_runway()));
            let mut waited = 0u64;
            let mut dead_votes = 0u32;
            loop {
                if self.covered(self.pos, runway) {
                    break;
                }
                if self.covered(self.pos, n as u64) && waited >= stream_runway_wait_ms() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                waited += 50;
                // A repair that started while this read was parked
                // needs the inode NOW, not in five minutes (sweep 8,
                // M4). Windows only - see `disk::ReadCustody`. The
                // second half is every platform: a demote that abandoned
                // this output froze the frontier this loop is waiting
                // on, so waiting out the five minutes below is the one
                // thing that cannot help.
                if let Some(e) = self.revoked().or_else(|| self.abandoned()) {
                    return Err(e);
                }
                // Re-issue the promotion occasionally while blocked: the
                // initial one is best-effort (bounded try_lock) and a new
                // fetch run may have started since (queue re-attach).
                if waited.is_multiple_of(2_000)
                    && let Some(sc) = &self.seek
                    && self.newest_alive()
                {
                    promote_playhead(sc, &self.name, &self.w, self.pos);
                }
                // Degraded playback beats a stall: when the bytes under
                // the cursor went terminally missing (430 everywhere /
                // out of retries - nothing pending or in flight carries
                // them), serve zeros for the hole instead of blocking a
                // preview on the 5-minute timeout. The file on disk is
                // never touched: settle-side repair still gets its gap,
                // and a later Range request re-reads whatever repair
                // wrote. With NO pool attached (run drained, job parked)
                // the verdict cannot be asked, so repair gets a bounded
                // window instead - a repair landing inside it un-blocks
                // this read with real bytes. Consecutive votes per
                // any_live's blind spot.
                if stream_zerofill()
                    && waited >= dead_span_grace_ms()
                    && waited.is_multiple_of(dead_span_vote_ms())
                    && !self.covered(self.pos, n as u64)
                    && let Some(sc) = &self.seek
                {
                    // The verdict spans the WHOLE hole (cursor to the
                    // next covered byte, runway-bounded) so one grace
                    // period condemns it once; the fast path above then
                    // fills it chunk by chunk.
                    let hole = self.uncovered_hole_len(runway);
                    let dead = match sc.span_deliverable(&self.name, self.w.size, self.pos, hole) {
                        Some(live) => !live,
                        None => waited >= stream_dead_grace_ms(),
                    };
                    dead_votes = if dead { dead_votes + 1 } else { 0 };
                    if dead_votes >= dead_span_votes() && !self.covered(self.pos, n as u64) {
                        let gap = nzbkit::disk::chunk_len(self.uncovered_hole_len(runway), n);
                        self.dead_until = self.pos + hole;
                        buf[..gap].fill(0);
                        self.stats
                            .zero_filled_bytes
                            .fetch_add(gap as u64, Ordering::Relaxed);
                        info!(
                            target: "stream",
                            "{}: zero-filling {hole} B at {} - the articles under it are \
                             terminally missing and nothing in flight carries them",
                            self.name, self.pos
                        );
                        self.pos += gap as u64;
                        return Ok(gap);
                    }
                }
                if waited > 300_000 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "span never arrived",
                    ));
                }
            }
        }
        // Last thing before the handle is used: a repair may have
        // finished under us while this read waited, and if it did our
        // fd is on the orphaned inode.
        self.rebind();
        nzbkit::disk::read_exact_at(&self.f, &mut buf[..n], self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// The half-open byte span a `Range:` header asks for, clamped to a file
/// of `total` bytes. None means "no usable range" - serve the whole file.
///
/// Players send two forms and both have to work. `bytes=a-b` (and its
/// open-ended `bytes=a-`) is the seek. `bytes=-n` is the SUFFIX form: the
/// LAST n bytes, which is how a player finds a trailing MP4 moov box or
/// an MKV Cues element before it can play anything. Reading the suffix
/// form as a start offset fails, and the whole-file fallback then answers
/// a tail request with the HEAD of the file - the player waits out the
/// download for bytes it will never use.
pub(super) fn byte_range(v: &str, total: u64) -> RangeVerdict {
    let Some(v) = v.strip_prefix("bytes=") else {
        // RFC 9110 §14.2: an origin server MUST IGNORE a range unit it
        // does not understand. This arm is not a judgement call.
        return RangeVerdict::Ignore;
    };
    let Some((a, b)) = v.split_once('-') else {
        return RangeVerdict::Ignore; // malformed, no byte-range-spec
    };
    if a.is_empty() {
        // Suffix. A tail longer than the file is the whole file, never an
        // underflowed start.
        let Ok(n) = b.parse::<u64>() else {
            return RangeVerdict::Ignore; // malformed
        };
        let start = total.saturating_sub(n);
        // `bytes=-0` is well formed and asks for nothing; an empty
        // resource satisfies no suffix at all. Both are 416, not 200.
        return if n > 0 && start < total {
            RangeVerdict::Span(start, total)
        } else {
            RangeVerdict::Unsatisfiable
        };
    }
    let Ok(start) = a.parse::<u64>() else {
        return RangeVerdict::Ignore; // malformed
    };
    let last: Option<u64> = if b.is_empty() {
        None
    } else {
        match b.parse::<u64>() {
            Ok(e) => Some(e),
            Err(_) => return RangeVerdict::Ignore, // malformed
        }
    };
    if last.is_some_and(|e| e < start) {
        // §14.1.1: a last-byte-pos below the first-byte-pos makes the
        // spec INVALID, and §14.2 says a header whose every range is
        // invalid SHOULD be ignored - not answered 416.
        return RangeVerdict::Ignore;
    }
    if start >= total {
        // §14.1.2: a first-byte-pos at or past the representation's
        // length is UNSATISFIABLE. This is the seek-to-EOF probe, and
        // answering it with the whole file is how one stale seek pulls a
        // multi-gigabyte transfer (measured on the sibling
        // /preview/media endpoint: 99 probes, 123.7 GB in six minutes,
        // before that one learned to say 416).
        return RangeVerdict::Unsatisfiable;
    }
    let end = last.map_or(total, |e| e.saturating_add(1).min(total));
    RangeVerdict::Span(start, end)
}

/// What a `Range:` header amounts to, which is THREE answers and not
/// two.
///
/// `Option<(u64, u64)>` collapsed the last two, and both call sites then
/// read `None` as "no range" and served the entire resource under a 200.
/// That is right for [`Ignore`](Self::Ignore) and wrong for
/// [`Unsatisfiable`](Self::Unsatisfiable): a player seeking to or past
/// EOF, or probing with `bytes=-0`, asked for nothing and was handed a
/// multi-gigabyte file - repeatedly, since the probe repeats.
///
/// The split follows RFC 9110 rather than taste. An unrecognised range
/// UNIT must be ignored (§14.2), a malformed header may be, an INVALID
/// spec (last-byte-pos below first) should be, and a well-formed spec
/// this resource cannot satisfy gets 416 with `Content-Range: bytes
/// */<total>` (§14.4 / §15.5.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RangeVerdict {
    /// Serve the whole resource under 200, exactly as before.
    Ignore,
    /// A satisfiable half-open span, `start < end <= total`.
    Span(u64, u64),
    /// Well formed, and this resource cannot satisfy it.
    Unsatisfiable,
}

/// Answer a `Range:` this resource cannot satisfy: 416 with the
/// `Content-Range: bytes */<total>` the spec requires, so the client
/// learns the length instead of guessing again.
pub(super) fn respond_unsatisfiable(req: tiny_http::Request, total: u64) {
    let mut resp = tiny_http::Response::from_string("range not satisfiable").with_status_code(416);
    if let Ok(h) = tiny_http::Header::from_bytes(
        &b"Content-Range"[..],
        format!("bytes */{total}").into_bytes(),
    ) {
        resp.add_header(h);
    }
    if let Ok(h) = tiny_http::Header::from_bytes(&b"Accept-Ranges"[..], &b"bytes"[..]) {
        resp.add_header(h);
    }
    let _ = req.respond(resp);
}

#[expect(clippy::too_many_arguments)]
pub(super) fn serve_range(
    req: tiny_http::Request,
    name: &str,
    w: Arc<nzbkit::disk::FileWriter>,
    pre_opened: Option<std::fs::File>,
    seek: Option<Arc<crate::SeekCtl>>,
    readers: Arc<std::sync::atomic::AtomicUsize>,
    latest_gen: Arc<std::sync::atomic::AtomicU64>,
    alive: Arc<std::sync::Mutex<std::collections::BTreeSet<u64>>>,
    stats: Arc<crate::StreamStats>,
) {
    let total = w.size;
    let range = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Range"))
        .map_or(RangeVerdict::Ignore, |h| {
            byte_range(h.value.as_str(), total)
        });
    let (start, end, status) = match range {
        RangeVerdict::Span(s, e) => (s, e, 206),
        RangeVerdict::Ignore => (0, total, 200),
        // The LIVE half is the worse of the two: `total` here is the
        // full expected size, so a `bytes=<size>-` probe at EOF used to
        // restart a live reader at byte 0 and then block on the write
        // frontier from the beginning of the file.
        RangeVerdict::Unsatisfiable => return respond_unsatisfiable(req, total),
    };
    // A caller that already holds the fd passes it in; otherwise open
    // through the writer's custody gate (sweep 8, M4/M6) - which also
    // means `current_path`, so a verified-name publish under the live
    // writer no longer sends a fresh range request at a removed path
    // and answers 410.
    let (f, lease) = match pre_opened {
        Some(f) => (f, None),
        None => match w.open_read() {
            Ok((f, lease)) => (f, Some(lease)),
            Err(_) => {
                let _ = req.respond(tiny_http::Response::from_string("gone").with_status_code(410));
                return;
            }
        },
    };
    // M11: a Range start past the write frontier IS a seek (players open
    // a fresh request per seek) - pull the articles under it to the queue
    // front before we start blocking on them. Becoming the newest
    // generation FIRST silences any superseded reader's re-promotes.
    let my_gen = latest_gen.fetch_add(1, Ordering::Relaxed) + 1;
    alive.lock_ok().insert(my_gen);
    let mut promoted_to = 0u64;
    if let Some(sc) = &seek {
        // Engage pool stream mode on every request, covered or not - the
        // player is here, and the next promote must find shallow windows.
        sc.note_stream();
        if !w.covered(start, (end - start).clamp(1, 1_000_000)) {
            let (n, to) = promote_playhead(sc, name, &w, start);
            promoted_to = to;
            if n > 0 {
                info!(target: "stream", "seek@{start} → promoted {n} article(s)");
            }
        }
    }
    let ctype: &[u8] = if name.to_ascii_lowercase().ends_with(".mp4") {
        b"video/mp4"
    } else {
        b"video/x-matroska"
    };
    readers.fetch_add(1, Ordering::Relaxed);
    let reader = LiveRangeReader {
        w,
        f,
        pos: start,
        end,
        seek,
        name: name.to_string(),
        promoted_to,
        readers,
        my_gen,
        alive,
        dead_until: 0,
        stats,
        lease,
    };
    // tiny_http chunks any body over ~1 MB even with a known length -
    // players want identity + exact Content-Length for seeking.
    //
    // Clamped once, for the header and data_length together: see the
    // note in `serve_file_range`. A no-op on 64-bit.
    let span_len = (end - start).min(usize::MAX as u64);
    let mut resp = tiny_http::Response::new(
        tiny_http::StatusCode(status),
        vec![
            tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype).unwrap(),
            tiny_http::Header::from_bytes(&b"Accept-Ranges"[..], &b"bytes"[..]).unwrap(),
            tiny_http::Header::from_bytes(
                &b"Content-Length"[..],
                span_len.to_string().into_bytes(),
            )
            .unwrap(),
        ],
        reader,
        Some(span_len as usize),
        None,
    )
    .with_chunked_threshold(usize::MAX);
    if status == 206 {
        resp.add_header(
            tiny_http::Header::from_bytes(
                &b"Content-Range"[..],
                format!("bytes {start}-{}/{total}", end - 1).into_bytes(),
            )
            .unwrap(),
        );
    }
    let _ = req.respond(resp);
}

#[cfg(test)]
mod preview_probe_tests {
    use super::*;

    /// A probe answer must never claim less of the file than the parse
    /// it ships with demonstrably read.
    ///
    /// Coverage only ever grows, and the walk cannot read a byte that
    /// is not covered, so `head_bytes: 0` beside a parsed container is
    /// not a state the download was ever in - it is two different
    /// instants in one answer. This lands the head article DURING the
    /// walk, which is the interleaving a loaded box produces: seen as
    /// `{"coverage":{"head_bytes":0,"pct":0.0,"tail_ok":false},...
    /// "source":"live"}` with a fully parsed mkv beside it, twice in
    /// fourteen daemon-suite runs at load ~175.
    #[test]
    fn coverage_never_undercuts_the_parse_it_ships_with() {
        let dir = std::env::temp_dir().join(format!("nzbfast-probe-cov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("movie.mkv");
        let data = nzbkit::mediaprobe::testmux::mkv_padded(2_000_000);
        let w = Arc::new(nzbkit::disk::FileWriter::create(&path, data.len() as u64).unwrap());
        let mut body = serde_json::json!({});

        let need_tail = fill_live_probe(&mut body, "movie.mkv", &w, || {
            // The article carrying the head lands while the walk runs.
            w.write_at(0, &data[..300_000]).unwrap();
            let mut r = nzbkit::mediaprobe::LiveProbeReader {
                w: w.clone(),
                f: std::fs::File::open(&path).unwrap(),
                pos: 0,
            };
            nzbkit::mediaprobe::probe(
                &mut r,
                nzbkit::mediaprobe::ProbeHint {
                    filename: Some("movie.mkv".into()),
                    known_size: Some(data.len() as u64),
                },
            )
        });

        // The walk read the container out of those 300 KB, so the
        // answer must say so.
        assert_eq!(body["media"]["container"], "mkv", "{body}");
        assert_eq!(body["pending"], false, "{body}");
        assert_eq!(body["coverage"]["head_bytes"], 300_000, "{body}");
        // Still mid-download: the tail has not arrived, and a complete
        // parse means there is no index to promote for.
        assert_eq!(body["coverage"]["tail_ok"], false, "{body}");
        assert!(!need_tail, "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod dead_span_tests {
    use super::*;
    use std::io::Read;

    /// A read window straddling the edge of a condemned hole serves its
    /// covered head as REAL bytes (a short read), and only the hole
    /// itself zero-fills. Before the covered-prefix guard, the fast
    /// path judged the straddling window by its hole: covered_intervals
    /// clips the interval at the cursor to start exactly at `pos`, the
    /// `> pos` filter skipped it, and the whole window - real landed
    /// tail of the last good article included - went out as zeros.
    #[test]
    fn a_condemned_hole_never_swallows_the_covered_head() {
        let dir = std::env::temp_dir().join(format!("nzbfast-deadspan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("movie.mkv");
        const SIZE: u64 = 300_000;
        const HOLE_START: u64 = 100_000; // covered: [0, 100k)
        const HOLE_END: u64 = 200_000; // covered: [200k, 300k); hole between
        let w = Arc::new(nzbkit::disk::FileWriter::create(&path, SIZE).unwrap());
        w.write_at(0, &vec![0xAB; HOLE_START as usize]).unwrap();
        w.write_at(HOLE_END, &vec![0xCD; (SIZE - HOLE_END) as usize])
            .unwrap();
        let alive = Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::from([0])));
        let mut r = LiveRangeReader {
            w: w.clone(),
            f: std::fs::File::open(&path).unwrap(),
            pos: HOLE_START - 4_096,
            end: SIZE,
            seek: None,
            name: "movie.mkv".into(),
            promoted_to: 0,
            readers: Arc::new(std::sync::atomic::AtomicUsize::new(1)),
            my_gen: 0,
            alive,
            // The hole was already condemned (dead-span verdict taken).
            dead_until: HOLE_END,
            stats: Arc::new(Default::default()),
            lease: None,
        };
        // Straddling read: 4 KB of real bytes remain before the hole.
        // They must come back as data, as a short read - not zeros.
        let mut buf = vec![0u8; 8_192];
        let got = r.read(&mut buf).unwrap();
        assert_eq!(got, 4_096, "covered head must be a short REAL read");
        assert!(
            buf[..got].iter().all(|&b| b == 0xAB),
            "head bytes must be the landed data, not zero-fill"
        );
        assert_eq!(r.pos, HOLE_START);
        // The next read starts exactly at the hole: condemned span, so
        // it zero-fills immediately (no wait) up to the hole's end.
        let got = r.read(&mut buf).unwrap();
        assert_eq!(got, 8_192, "condemned hole still zero-fills");
        assert!(buf[..got].iter().all(|&b| b == 0), "hole bytes are zeros");
        assert_eq!(r.pos, HOLE_START + 8_192);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod range_header_tests {
    use super::{RangeVerdict, byte_range};

    const FILE: u64 = 100_000_000;

    /// A player that asks for the LAST bytes of the file gets the last
    /// bytes of the file. This is the first request an MP4 with a
    /// trailing moov (or an MKV reading its Cues) makes, and answering it
    /// with the head instead means the player sits through the whole
    /// download before it can start.
    #[test]
    fn a_tail_request_serves_the_tail() {
        assert_eq!(
            byte_range("bytes=-65536", FILE),
            RangeVerdict::Span(FILE - 65_536, FILE)
        );
        assert_eq!(
            byte_range("bytes=-1", FILE),
            RangeVerdict::Span(FILE - 1, FILE)
        );
    }

    /// Asking for more tail than there is file is the whole file, not a
    /// wrapped-around start offset near u64::MAX.
    #[test]
    fn a_tail_longer_than_the_file_is_the_whole_file() {
        assert_eq!(
            byte_range("bytes=-4096", 1_000),
            RangeVerdict::Span(0, 1_000)
        );
        assert_eq!(
            byte_range(&format!("bytes=-{}", u64::MAX), 1_000),
            RangeVerdict::Span(0, 1_000)
        );
    }

    /// The seek forms every player already used must be unchanged.
    #[test]
    fn seek_ranges_still_work() {
        assert_eq!(
            byte_range("bytes=0-99999", FILE),
            RangeVerdict::Span(0, 100_000)
        );
        assert_eq!(
            byte_range("bytes=20000000-20050000", FILE),
            RangeVerdict::Span(20_000_000, 20_050_001)
        );
        assert_eq!(
            byte_range("bytes=500-", 1_000),
            RangeVerdict::Span(500, 1_000)
        );
        // An end past the file clamps to the file.
        assert_eq!(
            byte_range("bytes=990-99999", 1_000),
            RangeVerdict::Span(990, 1_000)
        );
    }

    /// A header we cannot READ is "no range" - serve the whole file
    /// under a 200, never an empty or inverted span, because
    /// Content-Length is end - start and the reader is built from both.
    ///
    /// This is the half RFC 9110 keeps on 200: an unrecognised range
    /// UNIT must be ignored (§14.2), a malformed header may be, and a
    /// spec whose last-byte-pos is below its first is INVALID rather
    /// than unsatisfiable (§14.1.1), so it is ignored too. The
    /// well-formed-but-unsatisfiable half is the test below, and the two
    /// used to be one answer.
    #[test]
    fn unreadable_ranges_are_no_range_at_all() {
        for v in [
            "bytes=-",       // no number either side
            "bytes=-abc",    // unparseable tail
            "bytes=abc-1",   // unparseable start
            "bytes=0-abc",   // unparseable end
            "megabytes=0-1", // not a byte range
            "0-99",          // no unit
            "bytes=100-50",  // inverted: invalid, so ignored
        ] {
            assert_eq!(byte_range(v, 1_000), RangeVerdict::Ignore, "{v}");
        }
    }

    /// A range this resource cannot satisfy is 416, not the whole file.
    ///
    /// Both of these used to collapse onto `None` and answer 200 with
    /// the entire resource. A player seeking to EOF - which is one
    /// ordinary stale seek - therefore pulled a multi-gigabyte file for
    /// a request that asked for nothing, and asked again. The sibling
    /// /preview/media endpoint learned this on 11 Aug 2026 (99 probes,
    /// 123.7 GB in six minutes, from Safari); /stream never did.
    #[test]
    fn a_well_formed_range_the_file_cannot_satisfy_is_416() {
        for v in [
            "bytes=-0",        // zero-length tail
            "bytes=1000-",     // starts at EOF
            "bytes=1000-2000", // starts past EOF
            "bytes=5000-",     // far past EOF
        ] {
            assert_eq!(byte_range(v, 1_000), RangeVerdict::Unsatisfiable, "{v}");
        }
        // A zero-length resource can satisfy nothing, tail or otherwise.
        assert_eq!(byte_range("bytes=-10", 0), RangeVerdict::Unsatisfiable);
        assert_eq!(byte_range("bytes=0-9", 0), RangeVerdict::Unsatisfiable);
        assert_eq!(byte_range("bytes=0-", 0), RangeVerdict::Unsatisfiable);
    }

    /// Whatever comes back, the invariant the response headers rely on
    /// holds: a non-empty span inside the file.
    #[test]
    fn every_accepted_range_fits_the_file() {
        for v in [
            "bytes=-65536",
            "bytes=-99999999999",
            "bytes=0-",
            "bytes=0-0",
            "bytes=999-1000000",
            "bytes=1-2",
        ] {
            if let RangeVerdict::Span(start, end) = byte_range(v, 1_000) {
                assert!(start < end && end <= 1_000, "{v} -> {start}..{end}");
            }
        }
    }
}

#[cfg(test)]
mod strm_tests {
    use super::{pointer_authority, pointer_authority_from, write_strm};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    /// M2: the library pointer a media server plays months later. There
    /// is no request to read a forwarded scheme off, so a hardcoded
    /// `http` on a TLS daemon wrote a .strm that could never play - the
    /// daemon's own bound scheme is the only answer available, and it
    /// has to reach the file.
    #[test]
    fn the_pointer_carries_the_daemons_own_scheme() {
        let dir = std::env::temp_dir().join(format!("nzbfast-strm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        write_strm(
            &dir,
            "Cat.Show.S01E01",
            "https",
            "127.0.0.1:6789",
            "nzo_1",
            "tok",
        )
        .unwrap();
        let body = std::fs::read_to_string(dir.join("Cat.Show.S01E01.strm")).unwrap();
        assert_eq!(body, "https://127.0.0.1:6789/stream/nzo_1?t=tok\n");

        write_strm(
            &dir,
            "Cat.Show.S01E02",
            "http",
            "127.0.0.1:6789",
            "nzo_2",
            "tok",
        )
        .unwrap();
        let body = std::fs::read_to_string(dir.join("Cat.Show.S01E02.strm")).unwrap();
        assert_eq!(body, "http://127.0.0.1:6789/stream/nzo_2?t=tok\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The 25 Aug 2026 defect: the authority was a hardcoded loopback,
    /// which is unreachable for every consumer that is not on this
    /// machine - always for a Plex CLIENT, which follows the 301 itself,
    /// and for Jellyfin/Emby the moment the server is on another box or
    /// in a bridged container.
    ///
    /// The shipped default for `serve` is `--bind 0.0.0.0`, so the
    /// wildcard row is the one nearly every install takes.
    #[test]
    fn a_wildcard_bind_names_the_lan_address_and_not_loopback() {
        assert_eq!(
            pointer_authority_from("0.0.0.0", 6789, || v4(192, 168, 1, 20)),
            "192.168.1.20:6789"
        );
        assert_eq!(
            pointer_authority_from("::", 6789, || v4(192, 168, 1, 20)),
            "192.168.1.20:6789"
        );

        // No route to anywhere is the one case with no better answer
        // than the placeholder this replaced.
        assert_eq!(
            pointer_authority_from("0.0.0.0", 6789, || None),
            "127.0.0.1:6789"
        );
    }

    /// A specific bind IS the answer - the operator named the address
    /// they want to be reachable on - and the route is never consulted
    /// to find that out. The count is the point: a wildcard UDP bind is
    /// a macOS firewall dialog (TODO 33), so a path that does not need
    /// the route must not pay for it.
    #[test]
    fn a_bind_that_already_names_an_address_never_asks_for_a_route() {
        let asked = AtomicUsize::new(0);
        let route = || {
            asked.fetch_add(1, Ordering::Relaxed);
            v4(192, 168, 1, 20)
        };
        assert_eq!(
            pointer_authority_from("10.0.0.4", 6789, route),
            "10.0.0.4:6789"
        );
        assert_eq!(asked.load(Ordering::Relaxed), 0, "no route lookup");

        // A name is passed through rather than resolved: a DNS answer
        // that moves next month must not be frozen into this file.
        assert_eq!(
            pointer_authority_from("nas.local", 6789, || v4(192, 168, 1, 20)),
            "nas.local:6789"
        );
    }

    /// Loopback STAYS loopback, and asks for no route either. A LAN
    /// address on a loopback-bound daemon points at a closed port, which
    /// would be a regression on the one deployment the old placeholder
    /// actually served.
    #[test]
    fn a_loopback_bind_keeps_loopback_even_when_a_lan_address_exists() {
        let asked = AtomicUsize::new(0);
        let route = || {
            asked.fetch_add(1, Ordering::Relaxed);
            v4(192, 168, 1, 20)
        };
        assert_eq!(
            pointer_authority_from("127.0.0.1", 6789, route),
            "127.0.0.1:6789"
        );
        assert_eq!(asked.load(Ordering::Relaxed), 0, "no route lookup");
        assert_eq!(
            pointer_authority_from("::1", 6789, || v4(192, 168, 1, 20)),
            "[::1]:6789"
        );
    }

    /// A v6 literal is bracketed, or the port reads as one more group -
    /// and the pointer is a URL, so this is the difference between a
    /// playable file and an unparseable one.
    #[test]
    fn a_v6_authority_is_bracketed_all_the_way_into_the_file() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 7));
        let auth = pointer_authority_from("::", 6789, || Some(v6));
        assert_eq!(auth, "[fd00::7]:6789");

        let dir = std::env::temp_dir().join(format!("nzbfast-strm6-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_strm(&dir, "V6.Show.S01E01", "http", &auth, "nzo_6", "tok").unwrap();
        let body = std::fs::read_to_string(dir.join("V6.Show.S01E01.strm")).unwrap();
        assert_eq!(body, "http://[fd00::7]:6789/stream/nzo_6?t=tok\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The live path, wired to the real route lookup. Pins that the two
    /// halves are joined - a `pointer_authority` that stopped consulting
    /// the route would still pass every table-driven case above - and
    /// that a box WITH a default route is not handed loopback, which is
    /// the whole defect.
    ///
    /// Gated like every other wildcard-bind site in this crate: on macOS
    /// the one bind behind `route_src` is a firewall dialog, and
    /// `.github/workflows/pr-check.yml` sets the variable because a
    /// Linux runner has no firewall to prompt. The loopback assertion is
    /// ungated because that path opens no socket at all.
    #[test]
    fn the_live_lookup_yields_a_usable_authority() {
        assert_eq!(pointer_authority("127.0.0.1", 6789), "127.0.0.1:6789");

        if std::env::var("NZBFAST_LAN_TESTS").as_deref() != Ok("1") {
            eprintln!("skipped the wildcard leg: set NZBFAST_LAN_TESTS=1 (binds a UDP socket)");
            return;
        }
        let auth = pointer_authority("0.0.0.0", 6789);
        assert!(auth.ends_with(":6789"), "{auth}");
        match crate::serve::lanaddr::route_src("8.8.8.8:53") {
            Some(IpAddr::V4(ip)) if !ip.is_loopback() && !ip.is_unspecified() => {
                assert_eq!(
                    auth,
                    format!("{ip}:6789"),
                    "a routed box must not get loopback"
                )
            }
            Some(IpAddr::V6(ip)) if !ip.is_loopback() && !ip.is_unspecified() => {
                assert_eq!(auth, format!("[{ip}]:6789"))
            }
            _ => assert_eq!(auth, "127.0.0.1:6789"),
        }
    }
}

#[cfg(test)]
mod stream_move_window_tests {
    use super::*;

    /// A history record, from the same wire shape the stores replay.
    fn rec(id: &str, extra: serde_json::Value) -> Arc<Mutex<Job>> {
        let mut v = serde_json::json!({
            "nzo_id": id, "name": id, "nzb_path": "/tmp/x.nzb",
            "out_dir": format!("/tmp/out/{id}"), "state": "Completed",
            "fetched": true,
        });
        if let Some(m) = extra.as_object() {
            for (k, val) in m {
                v[k] = val.clone();
            }
        }
        Arc::new(Mutex::new(job_from_json(&v).expect("job_from_json")))
    }

    /// The two markers of a payload in flight, and why BOTH are read.
    ///
    /// `mover_process` sets `out_dir` to the destination LAST, so a
    /// finished job whose bytes are being relocated has a record naming
    /// a folder they have left. The window that produced this test was
    /// `/stream` answering "this download has no playable file on disk
    /// any more" for a file that was whole and in flight.
    ///
    /// The completion move raises both markers, so either would answer
    /// it. The fence is not redundant: a recategorize and a retry
    /// redrive relocate the same finished payload with no
    /// `move_pending` anywhere, holding only the fence, and from this
    /// branch they are the same missing file for the same reason.
    #[test]
    fn a_payload_in_flight_is_told_from_a_payload_that_is_gone() {
        let dir = std::env::temp_dir().join(format!("nzbfast-move-win-{}", std::process::id()));
        let d = crate::serve::testutil::test_daemon(&dir);

        // Settled: whatever the file pick found (or did not), nothing
        // is moving, so a miss really is "not there any more".
        let settled = rec("m1", serde_json::json!({}));
        assert!(!payload_in_flight(&d, &settled));

        // Owed but not started: parked with a destination configured
        // and still sitting in the mover queue.
        let owed = rec("m2", serde_json::json!({"move_pending": true}));
        assert!(payload_in_flight(&d, &owed));

        // Mid-recategorize: a finished payload being relocated by
        // `history_change_cat`, which owes no move and raises no
        // marker but the fence.
        let recat = rec("m3", serde_json::json!({}));
        d.moving.lock_ok().insert("m3".to_string());
        assert!(
            payload_in_flight(&d, &recat),
            "the fence is the only marker a recategorize's relocation raises"
        );
        d.moving.lock_ok().remove("m3");
        assert!(!payload_in_flight(&d, &recat));

        // And the fence is read per id: somebody else's move is not
        // this job's excuse for a missing file.
        d.moving.lock_ok().insert("someone-else".to_string());
        assert!(!payload_in_flight(&d, &settled));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The window against the REAL mover, with a real destination.
    ///
    /// Three moments in one pass, so the claim is the code's rather
    /// than the test's: owed while the job sits in the mover queue, in
    /// flight with the source folder emptied under the fence, and
    /// settled afterwards - `out_dir` naming the destination the file
    /// actually reached, and the pick resolving there again. The middle
    /// one is a marker state the completion move does not produce
    /// (`mover_process` clears `move_pending` and rewrites `out_dir`
    /// under one hold) but a recategorize holds for its whole copy, and
    /// it is what a fence-blind fix would answer "gone" to.
    ///
    /// The real move here is a same-volume rename, so it is not the
    /// long window this bug lives in - the last leg pins the far side
    /// of it: after a genuine relocation the record and the file agree
    /// again, and nothing is left in flight.
    #[test]
    fn a_real_move_reads_owed_then_in_flight_then_settled() {
        let dir = std::env::temp_dir().join(format!("nzbfast-move-real-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = crate::serve::testutil::test_daemon(&dir);
        let dest = dir.join("done");
        *d.move_completed.write_ok() = Some(dest.clone());

        let job_dir = d.out_dir().join("Some.Show.S01E01");
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::write(job_dir.join("ep.mkv"), vec![b'x'; 4096]).unwrap();
        let job = rec(
            "SABnzbd_nzo_realmove",
            serde_json::json!({
                "out_dir": job_dir.to_string_lossy(),
                "move_pending": true,
            }),
        );
        d.history.lock_ok().push(job.clone());

        // Before: the file is findable where the record says, so the
        // handler serves it and never asks. The marker is up all the
        // same - this is the mover queue's own backlog.
        assert!(find_completed_media(&job_dir).is_some());
        assert!(payload_in_flight(&d, &job));

        // During: the state the handler actually meets at the seam,
        // built from the fence the mover holds and a source folder its
        // copy has emptied.
        d.moving
            .lock_ok()
            .insert("SABnzbd_nzo_realmove".to_string());
        std::fs::rename(job_dir.join("ep.mkv"), dir.join("ep.mkv")).unwrap();
        job.lock_ok().move_pending = false;
        assert!(find_completed_media(&job_dir).is_none());
        assert!(
            payload_in_flight(&d, &job),
            "an emptied source folder under the fence is in flight, not gone"
        );
        std::fs::rename(dir.join("ep.mkv"), job_dir.join("ep.mkv")).unwrap();
        d.moving.lock_ok().remove("SABnzbd_nzo_realmove");
        job.lock_ok().move_pending = true;

        // After: the mover's own run, end to end. It publishes the
        // payload and rewrites the record, so the handler resolves the
        // file again - and nothing is left in flight.
        assert!(!d.mover_process(&job));
        let moved = job.lock_ok().out_dir.clone();
        assert!(moved.starts_with(&dest), "out_dir still names {moved:?}");
        assert!(find_completed_media(&moved).is_some());
        assert!(!payload_in_flight(&d, &job));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pass 2 of the media chip over that same window: a miss taken
    /// mid-move is not the settled "no media file" it looks like.
    ///
    /// The claim is that the PROBER cannot tell the two apart -
    /// `probe_disk_facts_checked` answers `Ok(None)` to both, and by
    /// its own contract that is "a settled answer: no media file of
    /// ours in the output directory". Under the fence it is nothing of
    /// the kind: the disk read fine and the payload is whole, it is
    /// simply not under the name the record still carries. So the
    /// distinction has to be the caller's, which is what
    /// `miss_is_in_flight` is.
    ///
    /// Worth a test because the arm it guards has no second chance.
    /// Pass 2 is the ONLY source of a chip for a shape that unpacks
    /// after the download - pass 1 sees no media file at all for one -
    /// and those are exactly the jobs that then take a move. Nothing
    /// re-derives what it drops: the mover owes no final pass when it
    /// lands, and §188's re-derivation skips a row with no label
    /// outright, so this arm getting it wrong is a chipless row for the
    /// life of the record.
    ///
    /// Here rather than beside the prober for the reason the sibling
    /// tests above are: the window wants the real markers and a real
    /// emptied source folder, and a seeded spool cannot rig it.
    #[test]
    fn a_disk_pass_miss_mid_move_is_not_a_row_with_no_chip() {
        let dir = std::env::temp_dir().join(format!("nzbfast-move-media-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = crate::serve::testutil::test_daemon(&dir);
        let id = "SABnzbd_nzo_mediamove";
        let job_dir = d.out_dir().join("Some.Show.S01E02");
        std::fs::create_dir_all(&job_dir).unwrap();
        let job = rec(
            id,
            serde_json::json!({ "out_dir": job_dir.to_string_lossy() }),
        );

        // In flight: the mover holds the fence over a source folder its
        // copy has emptied, and `out_dir` still names it.
        d.moving.lock_ok().insert(id.to_string());
        assert!(
            matches!(
                crate::serve::tasks::probe_disk_facts_checked(&d, &job),
                Ok(None)
            ),
            "the prober reads the emptied folder as a settled miss"
        );
        assert!(
            crate::serve::tasks::miss_is_in_flight(&d, &job, id),
            "a miss under the fence is owed another look, not a chipless row"
        );

        // Settled: the same empty folder and the same `Ok(None)`, with
        // no marker over it. This one really is the end of it.
        d.moving.lock_ok().remove(id);
        assert!(matches!(
            crate::serve::tasks::probe_disk_facts_checked(&d, &job),
            Ok(None)
        ));
        assert!(!crate::serve::tasks::miss_is_in_flight(&d, &job, id));

        // And the owed marker answers it on its own, with no fence: a
        // job still sitting in the mover queue has not been read yet.
        job.lock_ok().move_pending = true;
        assert!(crate::serve::tasks::miss_is_in_flight(&d, &job, id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The readiness token over that same window: `moving`, and never
    /// `no_media`.
    ///
    /// Those two tokens ask a client for opposite things - `no_media`
    /// is "stop asking, the file is gone", `moving` is "wait" - so
    /// answering the move with `no_media` is what writes off a payload
    /// that is whole and lands seconds later. Four instants in one
    /// pass, because the interesting claims are about the transitions:
    /// on disk, in flight, landed, and finally gone for real, which is
    /// the one case `no_media` is honest about.
    ///
    /// `/preview/probe`'s 404-vs-503 arm sits on exactly the same
    /// predicate one door up; the readiness token is the half a job
    /// list carries, so it is the half pinned here.
    #[test]
    fn readiness_says_moving_rather_than_no_media_while_the_payload_is_in_flight() {
        const ID: &str = "SABnzbd_nzo_readymove";
        let dir = std::env::temp_dir().join(format!("nzbfast-move-ready-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = crate::serve::testutil::test_daemon(&dir);

        let job_dir = d.out_dir().join("Some.Show.S01E02");
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::write(job_dir.join("ep.mkv"), vec![b'x'; 4096]).unwrap();
        let job = rec(
            ID,
            serde_json::json!({"out_dir": job_dir.to_string_lossy()}),
        );
        d.history.lock_ok().push(job.clone());

        // Settled and on disk: the answer a player acts on.
        let r = playback_readiness(&d, ID);
        assert_eq!(r["reason"], "disk", "{r}");
        assert_eq!(r["ready"], true, "{r}");

        // In flight: the bytes have left the folder the record names,
        // and the fence is up. Not ready - `/stream` answers 503 in
        // this same window - but not gone either.
        std::fs::rename(job_dir.join("ep.mkv"), dir.join("ep.mkv")).unwrap();
        d.moving.lock_ok().insert(ID.to_string());
        // The disk answer is memoized for DISK_READINESS_TTL_SECS and
        // these four instants are one second apart, so the memo is
        // dropped between them rather than waited out. What it must NOT
        // hold is asserted below.
        d.playback_disk.lock_ok().clear();
        let r = playback_readiness(&d, ID);
        assert_eq!(r["reason"], "moving", "{r}");
        assert_eq!(r["ready"], false, "{r}");
        assert!(
            !d.playback_disk.lock_ok().contains_key(ID),
            "a miss taken mid-move must not be memoized - it would outlive \
             the move and answer no_media about a payload that has landed"
        );

        // Landed: the record and the file agree again, and the very
        // next poll reads it. No TTL to wait out, because the miss
        // above was never cached.
        std::fs::rename(dir.join("ep.mkv"), job_dir.join("ep.mkv")).unwrap();
        d.moving.lock_ok().remove(ID);
        let r = playback_readiness(&d, ID);
        assert_eq!(r["reason"], "disk", "{r}");

        // Gone for real: nothing moving, and nothing under the name the
        // record carries. The token that means stop asking - a fix that
        // called every miss a move would say "wait" forever.
        std::fs::remove_file(job_dir.join("ep.mkv")).unwrap();
        d.playback_disk.lock_ok().clear();
        let r = playback_readiness(&d, ID);
        assert_eq!(r["reason"], "no_media", "{r}");
        assert_eq!(r["ready"], false, "{r}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
