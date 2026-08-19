use super::*;

/// The library pointer Jellyfin/Emby index: a one-line .strm whose URL
/// plays (and on first play, downloads) the job. 127.0.0.1 is a
/// placeholder - the daemon only knows its own port, not its public host.
///
/// `scheme` is not a placeholder, though: it is what this run's listener
/// actually bound ([`Daemon::scheme`]). There is no request here to read
/// a forwarded scheme off - the file is written at finalize and read back
/// by Jellyfin possibly months later - so a hardcoded `http` on a TLS
/// daemon wrote a pointer that could never play.
pub(super) fn write_strm(
    out_dir: &std::path::Path,
    name: &str,
    scheme: &str,
    port: u16,
    nzo_id: &str,
    token: &str,
) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    let path = out_dir.join(nzbkit::disk::sanitize_filename(&format!("{name}.strm")));
    std::fs::write(
        &path,
        format!("{scheme}://127.0.0.1:{port}/stream/{nzo_id}?t={token}\n"),
    )?;
    info!(target: "library", "wrote {}", path.display());
    Ok(())
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
        .and_then(|h| byte_range(h.value.as_str(), total));
    let (start, end, status) = match range {
        Some((s, e)) => (s, e, 206),
        None => (0, total, 200),
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
    // ONE clamped value behind the header, the reader and data_length,
    // so a 32-bit target cannot disagree with itself. `Some(len as usize)`
    // truncates on armv7, and tiny_http then DROPS the textual
    // Content-Length (its add_header parses it into usize and gives up on
    // Err) while `io::copy` ships the full body - a 5 GB file behind a
    // 705 MB header. A no-op on 64-bit.
    let len = (end - start).min(usize::MAX as u64);
    let mut resp = tiny_http::Response::new(
        tiny_http::StatusCode(status),
        vec![
            tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype).unwrap(),
            tiny_http::Header::from_bytes(&b"Accept-Ranges"[..], &b"bytes"[..]).unwrap(),
            tiny_http::Header::from_bytes(&b"Content-Length"[..], len.to_string().into_bytes())
                .unwrap(),
        ],
        f.take(len),
        Some(len as usize),
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

/// One /stream request. `want = None` keeps the M11 contract (active
/// download, single attempt). `want = Some(id)` is M14i on-demand playback:
/// a parked library job is force-enqueued and we wait (≤30 s) for its
/// writers to appear before giving up. `authed` (API key or per-job token,
/// always true on keyless installs) gates that force-enqueue - it mutates
/// queue state, and nzo_ids are enumerable, so without the gate any LAN
/// host or CSRF page could start downloads past a user pause.
pub(super) fn stream_request(
    d: Arc<Daemon>,
    req: tiny_http::Request,
    want: Option<String>,
    authed: bool,
) {
    let mut deadline = Instant::now();
    if let Some(id) = &want {
        let parked = d
            .history
            .lock()
            .unwrap()
            .iter()
            .find(|j| j.lock_ok().nzo_id == *id)
            .cloned();
        let queued = d
            .queue
            .lock()
            .unwrap()
            .iter()
            .any(|j| j.lock_ok().nzo_id == *id);
        if parked.is_none() && !queued {
            let _ = req
                .respond(tiny_http::Response::from_string("unknown nzo_id").with_status_code(404));
            return;
        }
        if let Some(job) = parked {
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
                d.activate_parked(&job);
                info!(target: "library", "/stream/{id} → fetching now");
            } else {
                // A download that already FINISHED: its bytes are on
                // disk, not in the pipeline, so the live path below would
                // wait 30 s for media that is never coming and then 404.
                // That gap was visible in the UI - "play the copy you
                // have" could only open the file in the daemon's own
                // player, which does nothing a remote viewer can see.
                //
                // Byte-serving the LIVE pipeline is deliberately open
                // (players cannot send API keys, and it only ever carries
                // the download in front of you). A finished job is
                // different: nzo_ids are enumerable, so this would hand
                // any LAN host the user's library a guess at a time. It
                // takes the same key-or-token gate as the library
                // trigger, and the /m3u handoff already embeds the token.
                // `filed` + the stem + the tail it was FILED with come
                // along because a filed job's out_dir is the shared
                // `Show/Season NN` folder: "the biggest media file in
                // there" is a sibling episode as often as not.
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
                if done {
                    if !authed {
                        let blocked = d.note_auth_failure(peer_ip(&req), "stream completed");
                        let _ = req.respond(if blocked {
                            tiny_http::Response::from_string("too many bad keys")
                                .with_status_code(429)
                        } else {
                            tiny_http::Response::from_string(
                                "playing a finished download needs an apikey or stream token (?t=)",
                            )
                            .with_status_code(401)
                        });
                        return;
                    }
                    // A private out_dir is all this job's, so the biggest
                    // media file in it is the feature. A shared season
                    // folder is not, and only the episode this job filed
                    // may be served out of it.
                    let found = if filed {
                        crate::smart::find_filed_episode_media(&dir, &stem, &tail)
                    } else {
                        find_completed_media(&dir)
                    };
                    match found {
                        Some(p) => serve_file_range(req, &p),
                        // Moved away by hand, deleted, or a download with
                        // no video in it. Say which, rather than the live
                        // path's "no active media".
                        None => {
                            let _ = req.respond(
                                tiny_http::Response::from_string(
                                    "this download has no playable file on disk any more",
                                )
                                .with_status_code(404),
                            );
                        }
                    }
                    return;
                }
            }
        }
        deadline = Instant::now() + std::time::Duration::from_secs(30);
    }
    loop {
        // Only serve hub bytes that belong to the requested job.
        let owner_ok = match &want {
            None => true,
            Some(id) => d.active_stream.lock_ok().as_deref() == Some(id.as_str()),
        };
        if owner_ok && let Some((name, w)) = pick_media(&d, want.as_deref()) {
            // Encrypted store outputs are ciphertext on disk until the
            // finish decrypt - open_stream hands back a decryptor so
            // they stream mid-download, and the fd it returns stays
            // valid straight through the decrypt (that pass publishes
            // by rename and never mutates the inode we hold), so there
            // is nothing to wait for. Cloning through extractor_for
            // ties the open to the SAME job that owns `name`, so a job
            // transition mid-request cannot serve another job's bytes.
            let opened = d
                .hub
                .extractor_for(want.as_deref())
                .map(|ex| ex.open_stream(&name));
            let (pre_opened, crypt) = match opened {
                Some(nzbkit::extract::StreamOpen::Encrypted(f, c)) => (Some(f), Some(c)),
                _ => (None, None),
            };
            let seek = d.hub.seek.lock_ok().clone();
            serve_range(
                req,
                &name,
                w,
                pre_opened,
                crypt,
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
///
/// Encrypted-store outputs are ciphertext on disk until the finish
/// decrypt, so this hands back the same decryptor the byte-serving path
/// uses.
pub(super) fn open_live_probe(
    d: &Daemon,
    id: &str,
) -> Option<(
    String,
    Arc<nzbkit::disk::FileWriter>,
    nzbkit::mediaprobe::LiveProbeReader,
)> {
    let (name, w, f, crypt) = open_live_media(d, id)?;
    let r = nzbkit::mediaprobe::LiveProbeReader {
        w: w.clone(),
        f,
        crypt,
        pos: 0,
    };
    Some((name, w, r))
}

/// The same resolution, one step earlier: the open file and its
/// decryptor, before either reader wraps them.
///
/// [`open_live_probe`] hands back the non-blocking reader a poll wants;
/// the remux path needs the same file under a reader that WAITS, so the
/// step both share lives here rather than being written twice with one
/// of the two copies eventually forgetting the encrypted-store case.
pub(super) fn open_live_media(
    d: &Daemon,
    id: &str,
) -> Option<(
    String,
    Arc<nzbkit::disk::FileWriter>,
    std::fs::File,
    Option<nzbkit::extract::StreamCrypt>,
)> {
    let live = d.active_stream.lock_ok().as_deref() == Some(id);
    if !live {
        return None;
    }
    let (name, w) = pick_media(d, Some(id))?;
    let (f, crypt) = match d
        .hub
        .extractor_for(Some(id))
        .map(|ex| ex.open_stream(&name))
    {
        Some(nzbkit::extract::StreamOpen::Encrypted(f, c)) => (f, Some(c)),
        _ => (std::fs::File::open(&w.path).ok()?, None),
    };
    Some((name, w, f, crypt))
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

    if let Some((name, w, mut r)) = open_live_probe(&d, &id) {
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
        let _ = req.respond(
            json_resp(serde_json::json!({"error": "no playable file on disk"}))
                .with_status_code(404),
        );
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
/// download trigger), `not_started` (queued or paused), `no_media`
/// (finished with no playable file on disk any more), `failed`,
/// `unknown`.
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
    if let Some((name, w, mut r)) = open_live_probe(d, id) {
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
    /// Present iff the backing file is encrypted-store ciphertext:
    /// reads are CBC-decrypted on the fly (holds a live-reader lease so
    /// finish() temp+renames rather than mutating this file's inode).
    crypt: Option<nzbkit::extract::StreamCrypt>,
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
}

impl LiveRangeReader {
    fn newest_alive(&self) -> bool {
        self.alive.lock_ok().iter().next_back() == Some(&self.my_gen)
    }

    /// Is plaintext `[pos, pos+len)` serveable now? For an encrypted
    /// stream this widens to the ciphertext blocks (plus the CBC IV
    /// block) that decrypting the range requires.
    fn covered(&self, pos: u64, len: u64) -> bool {
        match &self.crypt {
            Some(c) => {
                let (lo, clen) = c.covered_bounds(pos, len);
                self.w.covered(lo, clen)
            }
            None => self.w.covered(pos, len),
        }
    }

    /// Length of the covered prefix at the cursor, up to `n`: 0 when
    /// the cursor byte itself has not landed. Binary search over
    /// `covered` so the encrypted-store block mapping is honored too.
    /// Only called at coverage boundaries (a window that is neither
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
    /// hole. Encrypted streams judge one read's worth at a time
    /// instead - the ciphertext-block mapping makes the next-covered
    /// computation fiddly, and the case is rare enough to take the
    /// slow path.
    fn uncovered_hole_len(&self, scan: u64, n: u64) -> u64 {
        if self.crypt.is_some() {
            return n;
        }
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
                .uncovered_hole_len(self.dead_until - self.pos, n as u64)
                .min(self.dead_until - self.pos);
            let gap = (hole as usize).min(n);
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
                    let hole = self.uncovered_hole_len(runway, n as u64);
                    let dead = match sc.span_deliverable(&self.name, self.w.size, self.pos, hole) {
                        Some(live) => !live,
                        None => waited >= stream_dead_grace_ms(),
                    };
                    dead_votes = if dead { dead_votes + 1 } else { 0 };
                    if dead_votes >= dead_span_votes() && !self.covered(self.pos, n as u64) {
                        let gap = (self.uncovered_hole_len(runway, n as u64) as usize).min(n);
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
        match &self.crypt {
            Some(c) => c.decrypt_range(&self.f, self.pos, &mut buf[..n])?,
            None => nzbkit::disk::read_exact_at(&self.f, &mut buf[..n], self.pos)?,
        }
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
pub(super) fn byte_range(v: &str, total: u64) -> Option<(u64, u64)> {
    let v = v.strip_prefix("bytes=")?;
    let (a, b) = v.split_once('-')?;
    if a.is_empty() {
        // Suffix. A tail longer than the file is the whole file, never an
        // underflowed start.
        let n: u64 = b.parse().ok()?;
        let start = total.saturating_sub(n);
        return (n > 0 && start < total).then_some((start, total));
    }
    let start: u64 = a.parse().ok()?;
    let end: u64 = if b.is_empty() {
        total
    } else {
        b.parse::<u64>().ok()?.saturating_add(1).min(total)
    };
    (start < end).then_some((start, end))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn serve_range(
    req: tiny_http::Request,
    name: &str,
    w: Arc<nzbkit::disk::FileWriter>,
    pre_opened: Option<std::fs::File>,
    crypt: Option<nzbkit::extract::StreamCrypt>,
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
        .and_then(|h| byte_range(h.value.as_str(), total));
    let (start, end, status) = match range {
        Some((s, e)) => (s, e, 206),
        None => (0, total, 200),
    };
    // Encrypted streams pass their ciphertext fd in (opened under the
    // extractor lock so it can't race the finish rename); plain files
    // open here as before.
    let f = match pre_opened {
        Some(f) => f,
        None => match std::fs::File::open(&w.path) {
            Ok(f) => f,
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
        crypt,
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
    };
    // tiny_http chunks any body over ~1 MB even with a known length -
    // players want identity + exact Content-Length for seeking.
    //
    // Clamped once, for the header and data_length together: see the
    // note in `serve_file`. A no-op on 64-bit.
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
                crypt: None,
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
            crypt: None,
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
    use super::byte_range;

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
            Some((FILE - 65_536, FILE))
        );
        assert_eq!(byte_range("bytes=-1", FILE), Some((FILE - 1, FILE)));
    }

    /// Asking for more tail than there is file is the whole file, not a
    /// wrapped-around start offset near u64::MAX.
    #[test]
    fn a_tail_longer_than_the_file_is_the_whole_file() {
        assert_eq!(byte_range("bytes=-4096", 1_000), Some((0, 1_000)));
        assert_eq!(
            byte_range(&format!("bytes=-{}", u64::MAX), 1_000),
            Some((0, 1_000))
        );
    }

    /// The seek forms every player already used must be unchanged.
    #[test]
    fn seek_ranges_still_work() {
        assert_eq!(byte_range("bytes=0-99999", FILE), Some((0, 100_000)));
        assert_eq!(
            byte_range("bytes=20000000-20050000", FILE),
            Some((20_000_000, 20_050_001))
        );
        assert_eq!(byte_range("bytes=500-", 1_000), Some((500, 1_000)));
        // An end past the file clamps to the file.
        assert_eq!(byte_range("bytes=990-99999", 1_000), Some((990, 1_000)));
    }

    /// Anything we cannot honour is "no range", which serves the whole
    /// file under a 200 - never an empty or inverted span, because
    /// Content-Length is end - start and the reader is built from both.
    #[test]
    fn unusable_ranges_are_no_range_at_all() {
        for v in [
            "bytes=-0",        // zero-length tail
            "bytes=-",         // no number either side
            "bytes=-abc",      // unparseable tail
            "bytes=1000-",     // starts at EOF
            "bytes=1000-2000", // starts past EOF
            "bytes=abc-1",     // unparseable start
            "megabytes=0-1",   // not a byte range
            "0-99",            // no unit
        ] {
            assert_eq!(byte_range(v, 1_000), None, "{v}");
        }
        // A zero-length file has no span to hand out, tail or otherwise.
        assert_eq!(byte_range("bytes=-10", 0), None);
        assert_eq!(byte_range("bytes=0-9", 0), None);
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
            if let Some((start, end)) = byte_range(v, 1_000) {
                assert!(start < end && end <= 1_000, "{v} -> {start}..{end}");
            }
        }
    }
}

#[cfg(test)]
mod strm_tests {
    use super::write_strm;

    /// M2: the library pointer Jellyfin plays months later. There is no
    /// request to read a forwarded scheme off, so a hardcoded `http` on
    /// a TLS daemon wrote a .strm that could never play - the daemon's
    /// own bound scheme is the only answer available, and it has to
    /// reach the file.
    #[test]
    fn the_pointer_carries_the_daemons_own_scheme() {
        let dir = std::env::temp_dir().join(format!("nzbfast-strm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        write_strm(&dir, "Cat.Show.S01E01", "https", 6789, "nzo_1", "tok").unwrap();
        let body = std::fs::read_to_string(dir.join("Cat.Show.S01E01.strm")).unwrap();
        assert_eq!(body, "https://127.0.0.1:6789/stream/nzo_1?t=tok\n");

        write_strm(&dir, "Cat.Show.S01E02", "http", 6789, "nzo_2", "tok").unwrap();
        let body = std::fs::read_to_string(dir.join("Cat.Show.S01E02.strm")).unwrap();
        assert_eq!(body, "http://127.0.0.1:6789/stream/nzo_2?t=tok\n");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
