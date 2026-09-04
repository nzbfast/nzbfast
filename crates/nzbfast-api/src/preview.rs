//! `GET /preview/media/{nzo_id}` - the remuxed half of the preview
//! player (TODO §73 phase 3).
//!
//! Phase 2 shipped a player that asks the BROWSER what it can open, and
//! then tells the truth when the answer is no. For most scene releases
//! the answer is "the codecs are fine, the container is not": Chrome
//! decodes the H.264 inside a Matroska file it will not open, and
//! Firefox says the same about the MP4 codecs in an MKV. This endpoint
//! is what turns that sentence into playback - the same elementary
//! streams, rewrapped into fragmented MP4 as they are read, with nothing
//! decoded and nothing written to disk.
//!
//! ## Why this is not `/stream` with a filter
//!
//! `/stream` serves bytes at offsets: it honours `Range`, it knows its
//! own length, and a player seeks by asking for a different span. None
//! of that survives a remux, because the output bytes do not exist until
//! they are produced and their length is not knowable in advance. So
//! this is a different contract on purpose - one chunked response, no
//! ranges, and a seek is a NEW request with `start_ms`. The two paths
//! share the byte machinery underneath ([`LiveSource`] promotes exactly
//! the way `LiveRangeReader` does) and nothing above it.
//!
//! Three things it deliberately does NOT inherit from `/stream`:
//!
//! - **No force-start.** `/stream` against a never-fetched library entry
//!   starts the download; that is a queue mutation past a user pause and
//!   it belongs to the play button, not to a preview.
//! - **No keyless access.** `/stream` is open because media players
//!   cannot send API keys. The dashboard always can, so every response
//!   here needs the key or the per-job token.
//! - **No open door at `metadata-only`.** The `preview` setting gates
//!   this endpoint at BOTH `off` and `metadata-only`: a user who asked
//!   for information without a player gets information without a player.

use super::*;
use nzbkit::mediaprobe::samples::RemuxError;
use nzbkit::mediaprobe::session::{Emit, RemuxSession};
use nzbkit::mediaprobe::source::Source;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// How long one `pull` waits for a payload span before it reports back.
/// Not a give-up: the body loop keeps asking, and this only decides how
/// often it comes up for air. Env `NZBFAST_PREVIEW_WAIT_MS` overrides.
fn preview_wait() -> Duration {
    static W: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    Duration::from_millis(*W.get_or_init(|| {
        std::env::var("NZBFAST_PREVIEW_WAIT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(15_000)
    }))
}

/// The ceiling a body waits before it gives up and closes the response.
/// The same five minutes `/stream` allows, for the same reason: a
/// stalled provider should buffer the player, not corrupt the stream.
const BODY_CEILING: Duration = Duration::from_secs(300);

/// How long a SEEK waits for its target span before answering 425.
/// Short on purpose - the client asked for interactivity, and "fetching
/// that part" on screen beats a socket that sits there.
const SEEK_WAIT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// The sources
// ---------------------------------------------------------------------------

/// The remuxer's view of a download in progress.
///
/// Mirrors `LiveRangeReader`'s promotion discipline exactly - claim a
/// generation, promote only while it is the newest live one, re-promote
/// every couple of seconds while blocked, and hand the rights back on
/// drop. The difference is the shape of the answer: this returns
/// `WouldBlock` at the deadline instead of holding out, because the
/// caller above it has a fragment half-built and a client to inform.
pub(super) struct LiveSource {
    w: Arc<nzbkit::disk::FileWriter>,
    /// Behind a lock because it is REPLACED mid-response: an external
    /// par2 repair rewrites its target onto a new inode, so the handle
    /// has to follow it (sweep 8, M5b - see `lease` below). Uncontended
    /// on the read path, which is one reader at a time by construction.
    f: std::sync::RwLock<std::fs::File>,
    /// Custody of the backing file for this source's whole life (sweep
    /// 8, M4). It does the half a lease is for on every platform, which is letting an external
    /// repair SEE the handle and drain it, and `read_at_wait` polls
    /// `revoked` before each read and inside its wait loop so the body
    /// ends and the handle drops within one poll - without that the
    /// source sat on the inode for up to the body ceiling and par2cmdline
    /// 0.8.1 reported its target missing (Codex F-08, 22 Aug 2026). It
    /// also polls `needs_reopen`: par2cmdline does not repair in place, and a
    /// source that kept reading through the old handle would remux the
    /// damaged bytes over a span the repair had already fixed.
    lease: Option<nzbkit::disk::ReadLease>,
    seek: Option<Arc<crate::SeekCtl>>,
    name: String,
    readers: Arc<AtomicUsize>,
    my_gen: u64,
    alive: Arc<std::sync::Mutex<std::collections::BTreeSet<u64>>>,
}

impl LiveSource {
    /// The external repair wants this file's inode and our handle is in
    /// its way (sweep 8, M4): end the response so the handle drops, the
    /// player reopens against the repaired file. Always `None` off
    /// Windows, the mirror of `LiveRangeReader::revoked`.
    fn revoked(&self) -> Option<std::io::Error> {
        self.lease.as_ref().filter(|l| l.revoked()).map(|_| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the file is being repaired - reopen the preview",
            )
        })
    }

    fn newest_alive(&self) -> bool {
        self.alive.lock_ok().iter().next_back() == Some(&self.my_gen)
    }

    /// The extractor has disowned the file under this source - the
    /// remux half of `LiveRangeReader::abandoned`, and the same
    /// mechanism: a demoted volume set abandons the extracted media
    /// file, the coverage frontier freezes, and nothing revokes or
    /// re-binds because par2 never wanted this inode. See
    /// [`FileWriter::abandon`].
    ///
    /// [`FileWriter::abandon`]: nzbkit::disk::FileWriter::abandon
    fn abandoned(&self) -> Option<std::io::Error> {
        self.w.is_abandoned().then(|| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "the file was rebuilt for repair - reopen the stream",
            )
        })
    }

    /// Ask the download for `off` and, while it is cold, the file tail
    /// as well. A remuxer alternates between a cluster walk and an index
    /// lookup at the end of the file, which is precisely the pair
    /// `promote_playhead` already covers in one call.
    fn promote(&self, off: u64) {
        if let Some(sc) = &self.seek
            && self.newest_alive()
        {
            sc.note_stream();
            promote_playhead(sc, &self.name, &self.w, off);
        }
    }
}

impl Source for LiveSource {
    fn covered(&self, off: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        // No ciphertext-block widening since TODO 27 phase 3: an
        // encrypted store output holds plaintext while it downloads, so
        // a range needs only its own span to have landed.
        self.w.covered(off, len)
    }

    fn size(&self) -> u64 {
        self.w.size
    }

    fn prefetch(&self, off: u64, _len: u64) {
        self.promote(off);
    }

    fn read_at_wait(&self, off: u64, buf: &mut [u8], wait: Duration) -> std::io::Result<()> {
        let len = buf.len() as u64;
        if len == 0 {
            return Ok(());
        }
        // Past the end of the file is not something waiting can fix.
        if off.saturating_add(len) > self.w.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "past end of file",
            ));
        }
        // Two distinct ways this handle stops being worth waiting on,
        // landed in parallel and both live: par2 wants the inode back
        // (`revoked`), and the extractor disowned the output
        // (`abandoned` - sweep 8 M4, defect 3, see `FileWriter::abandon`).
        // For the second, `WouldBlock` would be a lie: the frontier is
        // frozen, so `PreviewBody` would spin its 3 s pulls until the
        // 300 s body ceiling on a file that is already unlinked. A hard
        // error stops the remux at once, which is the same answer
        // `LiveRangeReader` gives the range path.
        if let Some(e) = self.revoked().or_else(|| self.abandoned()) {
            return Err(e);
        }
        if !self.covered(off, len) {
            self.promote(off);
            let deadline = Instant::now() + wait;
            let mut waited = 0u64;
            while !self.covered(off, len) {
                if Instant::now() >= deadline {
                    return Err(nzbkit::mediaprobe::source::would_block());
                }
                std::thread::sleep(Duration::from_millis(50));
                waited += 50;
                if let Some(e) = self.revoked().or_else(|| self.abandoned()) {
                    return Err(e);
                }
                // The first promotion is best-effort (a bounded
                // try_lock) and a fetch run may have re-attached since.
                if waited.is_multiple_of(2_000) {
                    self.promote(off);
                }
            }
        }
        // An external repair that finished while this source was open
        // left our handle on the orphaned inode - follow it before the
        // read, exactly as `LiveRangeReader::rebind` does.
        if let Some(l) = &self.lease
            && l.needs_reopen()
        {
            match self.w.reopen_read(l) {
                Ok(f) => {
                    *self.f.write_ok() = f;
                    info!(
                        target: "preview",
                        "{}: reopened at {off} - an external repair rewrote the file",
                        self.name
                    );
                }
                // The same call as `LiveRangeReader::rebind`: a remux
                // half-way through a fragment is no better off dead.
                Err(e) => warn!(
                    target: "preview",
                    "{}: still on the pre-repair file - could not reopen: {e}",
                    self.name
                ),
            }
        }
        let f = self.f.read_ok();
        nzbkit::disk::read_exact_at(&f, buf, off)
    }
}

impl Drop for LiveSource {
    fn drop(&mut self) {
        self.readers.fetch_sub(1, Ordering::Relaxed);
        self.alive.lock_ok().remove(&self.my_gen);
    }
}

/// A finished download: every byte is there, so nothing ever waits.
///
/// The remux still earns its keep here. A finished Matroska file is
/// exactly as unopenable in Firefox as a half-downloaded one, and the
/// browser's verdict - which is what routes a request to this endpoint -
/// does not change when the last article lands.
struct DiskSource {
    f: std::fs::File,
    size: u64,
}

impl Source for DiskSource {
    fn covered(&self, _off: u64, _len: u64) -> bool {
        true
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at_wait(&self, off: u64, buf: &mut [u8], _wait: Duration) -> std::io::Result<()> {
        if off.saturating_add(buf.len() as u64) > self.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "past end of file",
            ));
        }
        nzbkit::disk::read_exact_at(&self.f, buf, off)
    }
}

// ---------------------------------------------------------------------------
// The body
// ---------------------------------------------------------------------------

/// The chunked response body: init segment, then fragments as the
/// session produces them.
///
/// `Read` is the wrong shape for a producer that emits whole blobs, so
/// this holds one blob and drains it. The interesting part is what
/// happens when the next fragment is not ready: the read does NOT return
/// zero, because zero means end of stream and MediaSource would treat
/// the file as finished. It waits instead, which is the same thing the
/// player would do with its own buffer, and only gives up at the
/// ceiling.
struct PreviewBody {
    session: RemuxSession,
    src: Box<dyn Source>,
    buf: Vec<u8>,
    at: usize,
    done: bool,
    started: Instant,
    name: String,
}

impl Read for PreviewBody {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.at < self.buf.len() {
                let n = (self.buf.len() - self.at).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            match self.session.pull(self.src.as_ref(), preview_wait()) {
                Ok(Emit::Init(b)) | Ok(Emit::Fragment(b)) => {
                    self.buf = b;
                    self.at = 0;
                }
                Ok(Emit::NotYet { need_off }) => {
                    if self.started.elapsed() >= BODY_CEILING {
                        // Closing the stream is honest: MediaSource sees
                        // the network end, and the page reopens with a
                        // start time rather than staring at a still
                        // frame forever.
                        info!(
                            target: "preview",
                            "{}: giving up at byte {need_off} - it never arrived",
                            self.name
                        );
                        self.done = true;
                        return Ok(0);
                    }
                    // `pull` already spent its wait inside the source;
                    // coming straight back keeps the promotion fresh.
                    continue;
                }
                Ok(Emit::Eos) => {
                    self.done = true;
                    return Ok(0);
                }
                Err(e) => {
                    warn!(target: "preview", "{}: remux stopped: {e}", self.name);
                    self.done = true;
                    return Ok(0);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

/// `425 Too Early` plus what the client needs to decide when to ask
/// again. Never a long server-side hold: these are dashboard requests,
/// and a held socket is a worker that cannot answer the next one.
fn pending_resp(need_off: u64, covered_pct: f64) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    json_resp(serde_json::json!({
        "status": "pending",
        "need_off": need_off,
        "covered_pct": (covered_pct * 10.0).round() / 10.0,
    }))
    .with_status_code(425)
    .with_header(tiny_http::Header::from_bytes(&b"Retry-After"[..], &b"2"[..]).unwrap())
}

fn err_resp(code: u16, error: &str, hint: &str) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let mut body = serde_json::json!({ "error": error });
    if !hint.is_empty() {
        body["hint"] = hint.into();
    }
    json_resp(body).with_status_code(code)
}

/// One `GET /preview/media/{nzo_id}`.
///
/// Runs on its own thread: unlike the probe next door, this one holds a
/// socket for as long as the viewer watches.
pub fn preview_media_request(d: Arc<Daemon>, req: tiny_http::Request, id: String, q: String) {
    let sp = parse_query(&q);
    let start_ms: u64 = sp.get("start_ms").and_then(|v| v.parse().ok()).unwrap_or(0);
    let want_audio: Option<usize> = sp.get("a").and_then(|v| v.parse().ok());
    let init_only = sp.get("init_only").is_some_and(|v| v == "1");

    // The live job first. A job that FINISHES between this check and the
    // open is not an error: its writer's backing file has been published
    // away and the answer moved to disk, so the on-disk path below is
    // the right one - returning 410 there was the phase-1 bug that the
    // daemon suite caught on its first run.
    if let Some((name, w, f, lease)) = open_live_media(&d, &id) {
        let covered = w.contiguous_from_start();
        let pct = if w.size > 0 {
            covered as f64 * 100.0 / w.size as f64
        } else {
            0.0
        };
        // Claim a promotion generation before reading anything, so a
        // superseded preview stops steering the queue the moment this
        // one starts.
        let my_gen = d.hub.stream_gen.fetch_add(1, Ordering::Relaxed) + 1;
        d.hub.stream_alive.lock_ok().insert(my_gen);
        d.hub.stream_readers.fetch_add(1, Ordering::Relaxed);
        let src = LiveSource {
            w: w.clone(),
            f: std::sync::RwLock::new(f),
            lease,
            seek: d.hub.seek.lock_ok().clone(),
            name: name.clone(),
            readers: d.hub.stream_readers.clone(),
            my_gen,
            alive: d.hub.stream_alive.clone(),
        };
        // The file's index may be in bytes that have not arrived. Ask
        // for the tail the same way a seek does before concluding
        // anything - the next request usually has it.
        src.prefetch(0, 0);
        serve_remux(
            req,
            Box::new(src),
            &name,
            start_ms,
            want_audio,
            init_only,
            pct,
        );
        return;
    }

    // Not the live job: a finished download's bytes are on disk.
    let Some(job) = d.history_job(&id) else {
        let _ = req.respond(err_resp(404, "unknown or not yet downloading", ""));
        return;
    };
    let Some(path) = finished_media_path(&d, &job) else {
        // Nothing under the name the record carries. Ask - after the
        // pick and never before it, for the reason `payload_in_flight`
        // gives - whether the payload is simply in flight to its final
        // folder, because the mover rewrites that name LAST. `/stream`
        // and `/preview/probe` answer this state 503; so does this, the
        // third door onto the same record. The destination is derivable
        // and deliberately NOT served: what sits there mid-move is a
        // half-copied file under the payload's own name, and a player
        // handed one plays the head and then hits a wall it cannot tell
        // from a corrupt release. The 404 wording stays for a file that
        // really has gone.
        let _ = if payload_in_flight(&d, &job) {
            req.respond(
                err_resp(
                    503,
                    "the files are being moved right now - try again when it settles",
                    "",
                )
                .with_header(
                    tiny_http::Header::from_bytes(&b"Retry-After"[..], &b"5"[..])
                        .expect("static header"),
                ),
            )
        } else {
            req.respond(err_resp(404, "no playable file on disk", ""))
        };
        return;
    };
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let (Ok(f), Ok(meta)) = (std::fs::File::open(&path), std::fs::metadata(&path)) else {
        let _ = req.respond(err_resp(410, "the file is no longer readable", ""));
        return;
    };
    let src = DiskSource {
        f,
        size: meta.len(),
    };
    serve_remux(
        req,
        Box::new(src),
        &name,
        start_ms,
        want_audio,
        init_only,
        100.0,
    );
}

/// Open a session over `src` and answer with it.
///
/// Everything that can refuse does so BEFORE a body byte is written -
/// once a chunked response has started there is no status code left to
/// send, and a player that has already been handed a `200` reads a
/// truncated body as a broken file rather than as "come back later".
fn serve_remux(
    req: tiny_http::Request,
    src: Box<dyn Source>,
    name: &str,
    start_ms: u64,
    want_audio: Option<usize>,
    init_only: bool,
    covered_pct: f64,
) {
    let mut session = match RemuxSession::new(src.as_ref(), want_audio, preview_wait()) {
        Ok(s) => s,
        // The container header has not landed. A poll, not a failure.
        Err(e) if e.is_pending() => {
            let _ = req.respond(pending_resp(0, covered_pct));
            return;
        }
        Err(RemuxError::NoUsableTrack) | Err(RemuxError::Unsupported(_, _)) => {
            // This is where the transcode seam goes when there is one:
            // the codecs themselves are the problem, and no amount of
            // rewrapping fixes that.
            let _ = req.respond(err_resp(
                501,
                "transcode_unavailable",
                "this file's codecs cannot be rewrapped for a browser",
            ));
            return;
        }
        Err(e) => {
            let _ = req.respond(err_resp(422, "unreadable_container", &e.to_string()));
            return;
        }
    };

    // A seek is answered before the response opens, so a target that is
    // not down yet can still be a status code.
    let mut actual_ms = 0u64;
    if start_ms > 0 {
        match session.seek(src.as_ref(), start_ms, SEEK_WAIT) {
            Ok(ms) => actual_ms = ms,
            Err(RemuxError::NoIndex) => {
                let _ = req.respond(err_resp(
                    501,
                    "no_seek_index",
                    "this file carries no keyframe index, so it can only play from the start",
                ));
                return;
            }
            // Not 416: the range exists, it is just late.
            Err(e) if e.is_pending() => {
                src.prefetch(0, 0);
                let _ = req.respond(pending_resp(0, covered_pct));
                return;
            }
            Err(e) => {
                let _ = req.respond(err_resp(422, "seek_failed", &e.to_string()));
                return;
            }
        }
    }

    if init_only {
        // A client priming a SourceBuffer wants the init and nothing
        // else, and it is small and complete, so it gets a real length.
        let bytes = session.init_bytes().to_vec();
        let n = bytes.len();
        let _ = req.respond(
            tiny_http::Response::new(
                tiny_http::StatusCode(200),
                media_headers(actual_ms, true),
                std::io::Cursor::new(bytes),
                Some(n),
                None,
            )
            .with_chunked_threshold(usize::MAX),
        );
        return;
    }

    let body = PreviewBody {
        session,
        src,
        buf: Vec::new(),
        at: 0,
        done: false,
        started: Instant::now(),
        name: name.to_string(),
    };
    // No Content-Length: the output does not exist yet and its size is
    // not knowable, so tiny_http emits it chunked. That is also what
    // tells the client this response cannot be range-requested.
    let _ = req.respond(tiny_http::Response::new(
        tiny_http::StatusCode(200),
        media_headers(actual_ms, false),
        body,
        None,
        None,
    ));
}

/// Headers common to both remux answers.
///
/// `X-Nzbfast-Start-Ms` is the KEYFRAME-SNAPPED time, not the one that
/// was asked for: MediaSource needs it to place the buffer, and a player
/// told 1200 ms that receives content starting at 960 ms shows the seek
/// as having failed.
fn media_headers(start_ms: u64, known_length: bool) -> Vec<tiny_http::Header> {
    let mut h = vec![
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"video/mp4"[..]).unwrap(),
        tiny_http::Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap(),
        tiny_http::Header::from_bytes(&b"X-Nzbfast-Path"[..], &b"remux"[..]).unwrap(),
        tiny_http::Header::from_bytes(
            &b"X-Nzbfast-Start-Ms"[..],
            start_ms.to_string().into_bytes(),
        )
        .unwrap(),
    ];
    if !known_length {
        // Ranges are meaningless over a stream that is produced as it is
        // read; saying so stops a player from trying.
        h.push(tiny_http::Header::from_bytes(&b"Accept-Ranges"[..], &b"none"[..]).unwrap());
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use nzbkit::mediaprobe::testmux;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-preview-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A finished file on disk never waits and never reports a gap: the
    /// degenerate case of the live source.
    #[test]
    fn a_disk_source_is_always_covered() {
        let dir = scratch("disk");
        let p = dir.join("f.mkv");
        let bytes = testmux::mkv_remux_fixture();
        std::fs::write(&p, &bytes).unwrap();
        let src = DiskSource {
            f: std::fs::File::open(&p).unwrap(),
            size: bytes.len() as u64,
        };
        assert!(src.covered(0, src.size()));
        let mut buf = [0u8; 4];
        src.read_at_wait(0, &mut buf, Duration::ZERO).unwrap();
        assert_eq!(&buf, &[0x1A, 0x45, 0xDF, 0xA3], "EBML magic");
        // Past the end is an error the caller must not retry.
        assert_eq!(
            src.read_at_wait(src.size() - 2, &mut buf, Duration::ZERO)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn live_source(w: &Arc<nzbkit::disk::FileWriter>) -> LiveSource {
        LiveSource {
            w: w.clone(),
            f: std::sync::RwLock::new(std::fs::File::open(&w.path).unwrap()),
            lease: None,
            seek: None,
            name: "movie.mkv".into(),
            readers: Arc::new(AtomicUsize::new(1)),
            my_gen: 1,
            alive: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::from([
                1u64,
            ]))),
        }
    }

    /// The other thing nothing else drives: `LiveSource::abandoned`
    /// (sweep 8 M4, defect 3). A demoted volume set UNLINKS the
    /// extracted output before par2 runs, so the coverage frontier the
    /// remux is waiting on freezes for ever - and no lease is revoked
    /// and no generation moves, because par2 never wanted this inode.
    ///
    /// `WouldBlock` would be a lie in that state: it is the answer that
    /// sends `PreviewBody` straight back for another 3 s pull, so the
    /// remux would grind to the 300 s body ceiling on a file that is
    /// already gone. This asserts the difference between the two
    /// answers, which is the whole point of the check.
    ///
    /// The `/stream` half is covered on a real daemon and a real par2
    /// by `tests/integration/stream_repair.rs` leg 2; nothing there
    /// touches the remux path, hence this.
    #[test]
    fn a_live_source_gives_up_on_an_output_the_extractor_abandoned() {
        let dir = scratch("liveabandon");
        let path = dir.join("movie.mkv");
        let bytes = testmux::mkv_remux_fixture();
        // Declared longer than what lands, so the tail is a genuine
        // uncovered span the source has to wait on.
        let w = Arc::new(nzbkit::disk::FileWriter::create(&path, bytes.len() as u64 + 64).unwrap());
        w.write_at(0, &bytes).unwrap();
        let src = live_source(&w);
        let tail = bytes.len() as u64;
        let mut buf = [0u8; 4];

        // Before: an uncovered span times out as WouldBlock, and
        // `PreviewBody` reads that as "come back in a moment".
        assert_eq!(
            src.read_at_wait(tail, &mut buf, Duration::from_millis(60))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );

        // The demote: writer disowned, file unlinked.
        w.abandon();
        std::fs::remove_file(&path).unwrap();

        // After: a hard error, and it must not spend the wait first -
        // waiting is the one thing that cannot help now.
        let t0 = Instant::now();
        assert_eq!(
            src.read_at_wait(tail, &mut buf, Duration::from_secs(30))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "the source sat out its wait on an abandoned output: {:?}",
            t0.elapsed()
        );

        // And a COVERED read is refused too. The interval map still
        // says those bytes are good, and on Unix the fd would even
        // serve them off the unlinked inode - but they belong to a file
        // the job has disowned, over a name the post-repair re-extract
        // is about to rewrite.
        assert!(src.covered(0, 4), "the head really is still covered");
        assert_eq!(
            src.read_at_wait(0, &mut buf, Duration::ZERO)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::ConnectionAborted
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The remuxer's source has the same duty as
    /// `LiveRangeReader::rebind`, and nothing else drives it: after an
    /// EXTERNAL par2 repair the handle it opened with is the file par2
    /// renamed ASIDE, so a source that read on through it would remux
    /// the damaged bytes over a span the repair had already fixed
    /// (sweep 8, M5b).
    ///
    /// The `/stream` legs in `tests/integration/stream_repair.rs` prove
    /// the reader half on a real daemon and a real par2; they never touch
    /// the remux path, which is why this one is written out here instead.
    /// The folder move is not decoration: `current_path` tracks only
    /// the FILE's publish rename, so postproc renaming the job folder
    /// is what makes a by-name reopen hopeless and a captured handle
    /// the only answer (see `disk::ReadCustody`). Windows has no
    /// captured handle - its readers are revoked before the child runs
    /// - so it keeps the by-name path and skips the move.
    #[test]
    fn a_live_source_follows_an_external_repair_onto_its_new_inode() {
        let dir = scratch("liverepair");
        let job = dir.join("Some.Release.2026");
        std::fs::create_dir_all(&job).unwrap();
        let path = job.join("movie.mkv");
        let damaged = testmux::mkv_remux_fixture();
        let w = Arc::new(nzbkit::disk::FileWriter::create(&path, damaged.len() as u64).unwrap());
        w.write_at(0, &damaged).unwrap();

        // The remux session, holding its lease for the whole response.
        let (f, lease) = w.open_read().unwrap();
        let src = LiveSource {
            w: w.clone(),
            f: std::sync::RwLock::new(f),
            lease: Some(lease),
            seek: None,
            name: "movie.mkv".into(),
            readers: Arc::new(AtomicUsize::new(1)),
            my_gen: 1,
            alive: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::from([
                1u64,
            ]))),
        };
        let mut buf = [0u8; 4];
        src.read_at_wait(8, &mut buf, Duration::ZERO).unwrap();
        assert_eq!(&buf, &damaged[8..12]);

        // par2cmdline, to the letter: the damaged target renamed aside,
        // the repaired data written to a NEW inode.
        let mut repaired = damaged.clone();
        repaired[8..12].copy_from_slice(b"OKAY");
        w.park_for_repair().unwrap();
        std::fs::rename(&path, job.join("movie.mkv.1")).unwrap();
        std::fs::write(&path, &repaired).unwrap();
        w.unpark().unwrap();
        #[cfg(not(windows))]
        std::fs::rename(&job, dir.join("Some Release 2026")).unwrap();

        src.read_at_wait(8, &mut buf, Duration::ZERO).unwrap();
        assert_eq!(
            &buf, b"OKAY",
            "the source is still reading the inode par2 renamed away"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The half of the same check that
    /// `a_live_source_gives_up_on_an_output_the_extractor_abandoned`
    /// cannot reach: a source ALREADY PARKED on a hole when the demote
    /// lands. That test sets the flag between reads, so the poll at the
    /// top of `read_at_wait` answers it and the one inside the wait
    /// loop never runs - back the loop poll out and it still passes.
    ///
    /// The parked case is the live one. `PreviewBody` pulls with a 15 s
    /// budget, so the demote almost always arrives while a read is
    /// sitting in that loop; with no poll there the read spends its
    /// whole budget and hands back `WouldBlock`, which sends the body
    /// round again until the 300 s ceiling. That is the measured
    /// symptom of defect 3 on the `/stream` twin - a player hung five
    /// minutes on a job that repaired fine.
    #[test]
    fn a_live_source_parked_on_a_hole_ends_when_the_output_is_abandoned() {
        let dir = scratch("liveabandonparked");
        let path = dir.join("movie.mkv");
        let data = testmux::mkv_remux_fixture();
        let w = Arc::new(nzbkit::disk::FileWriter::create(&path, data.len() as u64).unwrap());
        w.write_at(0, &data[..4_096]).unwrap();
        let src = live_source(&w);

        // The demote lands while the read below is already waiting.
        // Nothing else can end it: the frontier never moves again.
        let abandoner = {
            let w = w.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                w.abandon();
            })
        };
        let t0 = Instant::now();
        let mut cold = [0u8; 16];
        let e = src
            .read_at_wait(20_000, &mut cold, Duration::from_secs(10))
            .unwrap_err();
        abandoner.join().unwrap();
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::ConnectionAborted,
            "a parked read never noticed the abandon: {e}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "the read sat on the frozen frontier for {:?}",
            t0.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The revoke twin of the abandon pair above, and Windows-only by
    /// construction: `ReadLease::revoked` is `cfg!(windows) &&
    /// repairing`, so a Unix run of this could only ever assert the
    /// false branch (Codex F-08, TODO 246). An external par2 wants the
    /// inode and our handle is in its way; without the `revoked` polls
    /// the source sat on it for up to the body ceiling and par2cmdline
    /// 0.8.1 reported its target missing.
    ///
    /// Both poll sites in `read_at_wait` are exercised, in the order
    /// that separates them: the revoke lands while a read is PARKED on
    /// a hole, so only the poll inside the wait loop can end it (the
    /// top-of-read one already ran); then a COVERED read is refused by
    /// the top-of-read poll alone, since a covered read never enters
    /// the loop. `park_for_repair`'s Windows drain blocks its thread
    /// until our lease drops, which is why it runs on a helper and the
    /// join sits after `drop(src)`.
    #[cfg(windows)]
    #[test]
    fn a_live_source_parked_on_a_hole_ends_when_par2_revokes_the_lease() {
        let dir = scratch("liverevoked");
        let path = dir.join("movie.mkv");
        let data = testmux::mkv_remux_fixture();
        let w = Arc::new(nzbkit::disk::FileWriter::create(&path, data.len() as u64).unwrap());
        w.write_at(0, &data[..4_096]).unwrap();

        // The remux session, holding its lease as the live path does.
        let (f, lease) = w.open_read().unwrap();
        let src = LiveSource {
            w: w.clone(),
            f: std::sync::RwLock::new(f),
            lease: Some(lease),
            seek: None,
            name: "movie.mkv".into(),
            readers: Arc::new(AtomicUsize::new(1)),
            my_gen: 1,
            alive: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::from([
                1u64,
            ]))),
        };

        // par2 claims the file while the read below is parked on the
        // hole. On Windows this arms `revoked` at once and then waits
        // for the reader handle to close, so it cannot run inline.
        let repairer = {
            let w = w.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                w.park_for_repair().unwrap();
            })
        };
        let t0 = Instant::now();
        let mut cold = [0u8; 16];
        let e = src
            .read_at_wait(20_000, &mut cold, Duration::from_secs(10))
            .unwrap_err();
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::ConnectionAborted,
            "a parked read never noticed the revoke: {e}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "the source held the inode against a repair for {:?}",
            t0.elapsed()
        );

        // And a COVERED read is refused too, by the poll at the top of
        // `read_at_wait`: the bytes are on disk and the handle could
        // serve them, but every read the source answers is time spent
        // holding the inode the repair is waiting to own.
        assert!(src.covered(0, 4), "the head really is still covered");
        let mut buf = [0u8; 4];
        assert_eq!(
            src.read_at_wait(0, &mut buf, Duration::ZERO)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::ConnectionAborted
        );

        // Dropping the source is what lets the repair in: the lease and
        // the handle go together, and the drain in `park_for_repair`
        // returns.
        drop(src);
        repairer.join().unwrap();
        w.unpark().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The live source waits for a hole and then gives up; it does not
    /// spin, and it does not sleep over bytes that are already here.
    ///
    /// Both halves matter. A source that returned `WouldBlock`
    /// immediately would make the session busy-loop through the body,
    /// and one that slept on covered bytes would cost a fixed pause per
    /// sample on a file that is entirely downloaded.
    #[test]
    fn live_source_does_not_spin() {
        let dir = scratch("live");
        let path = dir.join("movie.mkv");
        let data = testmux::mkv_remux_fixture();
        let w = Arc::new(nzbkit::disk::FileWriter::create(&path, data.len() as u64).unwrap());
        w.write_at(0, &data[..4_096]).unwrap();
        let src = live_source(&w);

        // Covered: answered from disk with no wait at all.
        let t = Instant::now();
        let mut head = [0u8; 4];
        src.read_at_wait(0, &mut head, Duration::from_secs(5))
            .unwrap();
        assert_eq!(&head, &[0x1A, 0x45, 0xDF, 0xA3]);
        assert!(
            t.elapsed() < Duration::from_millis(200),
            "a covered read waited {:?}",
            t.elapsed()
        );

        // Uncovered: waits out the budget, then reports a retryable
        // miss rather than a failure.
        let t = Instant::now();
        let mut cold = [0u8; 16];
        let e = src
            .read_at_wait(20_000, &mut cold, Duration::from_millis(300))
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
        assert!(
            t.elapsed() >= Duration::from_millis(250),
            "an uncovered read returned in {:?} - that is a spin",
            t.elapsed()
        );
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "an uncovered read overran its budget by {:?}",
            t.elapsed()
        );

        // Past the end of the FILE is not a hole, and no budget makes
        // it one.
        let t = Instant::now();
        let e = src
            .read_at_wait(w.size - 2, &mut cold, Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(t.elapsed() < Duration::from_millis(200), "EOF waited");

        // Dropping hands the promotion rights and the reader gauge back,
        // so an abandoned preview does not hold the pool's hot lane.
        let (readers, alive) = (src.readers.clone(), src.alive.clone());
        drop(src);
        assert_eq!(readers.load(Ordering::Relaxed), 0);
        assert!(alive.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A live source over a half-written file remuxes what it has and
    /// then reports a gap - the shape the endpoint turns into a body
    /// that keeps the socket open.
    #[test]
    fn a_partial_download_remuxes_what_has_landed() {
        let dir = scratch("partial");
        let path = dir.join("movie.mkv");
        let data = testmux::mkv_remux_fixture();
        let w = Arc::new(nzbkit::disk::FileWriter::create(&path, data.len() as u64).unwrap());
        // The head, plus the tail the Cues live in.
        let half = data.len() / 2;
        w.write_at(0, &data[..half]).unwrap();
        let tail = data.len() - 8_192;
        w.write_at(tail as u64, &data[tail..]).unwrap();
        let src = live_source(&w);

        let mut s = RemuxSession::new(&src, None, Duration::ZERO).unwrap();
        let mut emitted = 0usize;
        let mut blocked = false;
        for _ in 0..10_000 {
            match s.pull(&src, Duration::ZERO).unwrap() {
                Emit::Init(b) | Emit::Fragment(b) => emitted += b.len(),
                Emit::NotYet { .. } => {
                    blocked = true;
                    break;
                }
                Emit::Eos => break,
            }
        }
        assert!(blocked, "half a file never reported a gap");
        assert!(emitted > 1024, "nothing was remuxed from the half we had");

        // The rest lands and the same session carries on.
        w.write_at(half as u64, &data[half..]).unwrap();
        let mut more = 0usize;
        for _ in 0..10_000 {
            match s.pull(&src, Duration::ZERO).unwrap() {
                Emit::Init(b) | Emit::Fragment(b) => more += b.len(),
                Emit::NotYet { need_off } => panic!("still blocked at {need_off}"),
                Emit::Eos => break,
            }
        }
        assert!(more > 0, "the session did not resume once the rest landed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The body drains a session into a `Read`, and reaches the end
    /// exactly once.
    #[test]
    fn the_body_yields_the_whole_remux_then_stops() {
        let dir = scratch("body");
        let p = dir.join("f.mkv");
        let bytes = testmux::mkv_remux_fixture();
        std::fs::write(&p, &bytes).unwrap();
        let src = DiskSource {
            f: std::fs::File::open(&p).unwrap(),
            size: bytes.len() as u64,
        };
        let session = RemuxSession::new(&src, None, Duration::ZERO).unwrap();
        let mut body = PreviewBody {
            session,
            src: Box::new(src),
            buf: Vec::new(),
            at: 0,
            done: false,
            started: Instant::now(),
            name: "f.mkv".into(),
        };
        let mut out = Vec::new();
        body.read_to_end(&mut out).unwrap();
        assert!(out.len() > 1024, "the body produced almost nothing");
        assert_eq!(&out[4..8], b"ftyp", "the body does not open with an init");
        assert!(
            out.windows(4).any(|w| w == b"moof"),
            "the body carries no fragments"
        );
        // A second read past the end stays at the end.
        let mut more = [0u8; 16];
        assert_eq!(body.read(&mut more).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
