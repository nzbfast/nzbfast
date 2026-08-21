//! Posting: yEnc-encode local files, split them into articles, upload via
//! NNTP POST (IHAVE fallback), and emit the matching NZB.
//!
//! This backs the `nzbfast post` ops tool (benchmark-corpus uploads). It is
//! deliberately conservative about headers: an article carries From,
//! Newsgroups, Subject, Message-ID and Date - nothing else. No User-Agent,
//! no X-Newsreader, and Message-IDs are built from random material plus a
//! caller-chosen domain, so nothing about the posting host leaks into the
//! group (the header-plane twin of the remap-path-prefix binary scrub).

use crate::sync::MutexExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::config::ServerConfig;
use crate::nntp::{Connection, NntpError};

#[derive(Debug, thiserror::Error)]
pub enum PostError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("NNTP: {0}")]
    Nntp(#[from] NntpError),
    /// A "not now" from the server: RFC 3977's 400/502/503 on the POST
    /// command line, 436 on IHAVE. The article was NOT taken, but the
    /// condition is transient by definition, so the worker spends another
    /// attempt from its existing (bounded) budget instead of killing an
    /// upload that would have gone through.
    #[error("{0}")]
    Retryable(String),
    /// A resend was rejected as a duplicate, but the provider's read farm
    /// has not made the article visible to STAT yet. The Message-ID may
    /// already be public and must ride in abort/rescue output even though it
    /// is not safe to call the upload successful.
    #[error("{0}")]
    Unconfirmed(String),
    /// The upload stopped partway with articles already on the server.
    /// `posted` carries every Message-ID the server accepted before the
    /// abort - those articles are public, under random ids that exist
    /// nowhere else, so the caller MUST surface or persist them. Losing
    /// them means the operator can neither fetch nor cancel what they
    /// just published.
    #[error("{message}")]
    Aborted {
        message: String,
        posted: Box<PostedSet>,
    },
    #[error("{0}")]
    Other(String),
}

/// Posting parameters. All header material is caller-controlled; the
/// defaults live at the CLI layer so the library stays explicit.
#[derive(Debug, Clone)]
pub struct PostOpts {
    /// Newsgroup to post into.
    pub group: String,
    /// From header value.
    pub from: String,
    /// Right-hand side of generated Message-IDs.
    pub msgid_domain: String,
    /// Decoded payload bytes per article.
    pub article_size: usize,
    /// Optional release title: subjects become
    /// `title [i/n] - "file" yEnc (p/t)` instead of `"file" yEnc (p/t)`.
    pub title: Option<String>,
    /// Concurrent posting connections.
    pub connections: usize,
}

/// One posted article, as the NZB will describe it.
#[derive(Debug, Clone)]
pub struct PostedSegment {
    /// 1-based part number within the file.
    pub(crate) number: u32,
    /// Message-ID without angle brackets.
    pub(crate) message_id: String,
    /// Encoded (yEnc body) size in bytes.
    pub bytes: u64,
}

/// One posted file with its article set.
#[derive(Debug, Clone)]
pub struct PostedFile {
    pub(crate) name: String,
    pub(crate) subject: String,
    /// Unix time stamped into the articles' Date headers.
    pub(crate) date: i64,
    /// Decoded file size.
    pub size: u64,
    pub segments: Vec<PostedSegment>,
}

/// A completed post: everything the NZB needs.
#[derive(Debug, Clone)]
pub struct PostedSet {
    pub(crate) group: String,
    pub from: String,
    pub files: Vec<PostedFile>,
}

/// The upload plan for one file, before any bytes move.
#[derive(Debug, Clone)]
pub struct PlanFile {
    pub path: PathBuf,
    /// Name as posted (file name only - local directory layout never
    /// reaches the wire).
    pub name: String,
    pub size: u64,
    pub parts: u32,
}

/// Expand `paths` (files and/or directories, directories walked
/// recursively) into a deterministic posting plan. Hidden files (dot
/// prefix) are skipped; empty files and duplicate posted names are
/// errors - both would produce NZBs that cannot round-trip.
pub fn plan(paths: &[PathBuf], article_size: usize) -> Result<Vec<PlanFile>, PostError> {
    if article_size == 0 || article_size > ARTICLE_SIZE_CAP {
        return Err(PostError::Other(format!(
            "article size must be between 1 and {ARTICLE_SIZE_CAP} bytes"
        )));
    }
    let mut files: Vec<PathBuf> = Vec::new();
    for p in paths {
        collect(p, &mut files)?;
    }
    files.sort();
    if files.is_empty() {
        return Err(PostError::Other("nothing to post".into()));
    }
    let mut seen = std::collections::HashSet::new();
    let mut plan = Vec::new();
    for path in files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.is_empty() || !seen.insert(name.clone()) {
            return Err(PostError::Other(format!(
                "duplicate or unusable posted name {name:?} ({})",
                path.display()
            )));
        }
        // The name is reproduced verbatim on the yEnc `name=` line and
        // quoted into subjects (`"name" yEnc (n/m)`). A control character -
        // an embedded CRLF especially - would terminate the line early and
        // desync the article; a double quote closes the subject's quoted
        // filename early, so our own subject parser reads a truncated name
        // and verification/PAR2 classification mis-fires. Refuse rather than
        // rename: the corpus is the operator's, and a silent rename breaks
        // their round-trip.
        if name.chars().any(|c| c.is_control() || c == '"') {
            return Err(PostError::Other(format!(
                "posted name {name:?} contains a control or double-quote character ({})",
                path.display()
            )));
        }
        let size = std::fs::metadata(&path)?.len();
        if size == 0 {
            return Err(PostError::Other(format!(
                "{} is empty - refusing to post a zero-byte file",
                path.display()
            )));
        }
        // Keep the part count wide and reject anything the u32 posting loop
        // and NZB segment index cannot represent. Casting `as u32` here would
        // wrap a >4G-article file to a tiny (or zero) count and silently
        // upload only a fraction of it. `--article-size 1` on a huge/sparse
        // file is the reachable trigger.
        let parts = size.div_ceil(article_size as u64).max(1);
        if parts > u32::MAX as u64 {
            return Err(PostError::Other(format!(
                "{} needs {parts} articles at {article_size}-byte parts, over the {} limit - raise --article-size",
                path.display(),
                u32::MAX
            )));
        }
        plan.push(PlanFile {
            parts: parts as u32,
            path,
            name,
            size,
        });
    }
    Ok(plan)
}

fn collect(p: &Path, out: &mut Vec<PathBuf>) -> Result<(), PostError> {
    // symlink_metadata + explicit skip: following links would post bytes
    // from outside the corpus, and a cyclic link tree would recurse
    // forever. A skipped-everything plan fails loudly in `plan`.
    let meta = std::fs::symlink_metadata(p)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(p)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            collect(&entry.path(), out)?;
        }
    } else if meta.is_file() {
        out.push(p.to_path_buf());
    }
    Ok(())
}

/// Header values ride one CRLF-terminated line each; strip anything that
/// could split or smuggle a header (CR, LF, other control bytes).
fn sanitize_header(v: &str) -> String {
    v.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Largest accepted `--article-size`. Real-world articles run 100 KB to
/// ~1 MB; the encoder holds `connections * article_size` in memory, so an
/// unbounded value is an OOM lever, not a tuning knob.
pub const ARTICLE_SIZE_CAP: usize = 16 << 20;

/// A fresh Message-ID `<local@domain>` whose local part is random hex -
/// no hostname, no username, no timestamp structure worth fingerprinting.
/// Uniqueness material: OS entropy would be overkill; nanosecond clock +
/// pid + a process counter through SHA-256 cannot collide in practice.
/// The domain rides inside `<local@domain>` on the Message-ID header AND
/// the `IHAVE` command line, so it is restricted to hostname characters
/// here - one place, both consumers stay consistent.
pub fn message_id(domain: &str) -> String {
    use sha2::{Digest, Sha256};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(nanos.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let digest = h.finalize();
    let mut local = String::with_capacity(40);
    for b in &digest[..16] {
        local.push_str(&format!("{b:02x}"));
    }
    let safe: String = domain
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        .collect();
    let domain = if safe.is_empty() {
        "nzbfast.invalid"
    } else {
        safe.as_str()
    };
    format!("{local}@{domain}")
}

/// Subject for part `n` of `total` of file `fi` (1-based) of `files`.
/// The quoted-filename yEnc convention every downloader parses:
/// `"file.bin" yEnc (3/10)`, with an optional `title [fi/files] - `
/// prefix for multi-file sets.
pub fn subject_for(
    title: Option<&str>,
    name: &str,
    file_index: u32,
    files_total: u32,
    part: u32,
    parts_total: u32,
) -> String {
    let tail = format!("\"{name}\" yEnc ({part}/{parts_total})");
    match title {
        Some(t) => format!("{t} [{file_index}/{files_total}] - {tail}"),
        None => tail,
    }
}

/// RFC 5322 Date header value, always +0000 (no local-timezone leak).
/// Inverse of `nntp::parse_nntp_date`'s civil-days math.
pub fn rfc5322_date(unix: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    let weekday = (days + 4).rem_euclid(7) as usize; // 1970-01-01 was a Thursday
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[weekday],
        d,
        MONTHS[(m - 1) as usize],
        y,
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Assemble the full wire article: minimal headers, blank line, the
/// dot-stuffed yEnc body, and the terminating lone-dot line. Ready to
/// send verbatim after a 340/335 continue.
pub fn build_wire_article(
    from: &str,
    group: &str,
    subject: &str,
    message_id: &str,
    date_unix: i64,
    yenc_body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(yenc_body.len() + yenc_body.len() / 128 + 512);
    for (k, v) in [
        ("From", from),
        ("Newsgroups", group),
        ("Subject", subject),
        ("Message-ID", &format!("<{message_id}>")),
        ("Date", &rfc5322_date(date_unix)),
    ] {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(sanitize_header(v).as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    // Dot-stuff the body (headers can't start with '.').
    for line in yenc_body.split_inclusive(|&b| b == b'\n') {
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
    }
    if out.last() != Some(&b'\n') {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// Does the server actually hold `<message_id>`? The only evidence that
/// counts on this path: a 223 to a STAT. `Ok(false)` is a MISS
/// (423/430/451) - which is not the same as "the article is not there",
/// so what a miss means is the caller's decision, and the two callers
/// decide differently. An answer we cannot read at all is neither, and is
/// reported as retryable so the article gets another attempt rather than
/// being recorded as posted on a guess.
async fn stat_exists(conn: &mut Connection, message_id: &str) -> Result<bool, PostError> {
    conn.send(&format!("STAT <{message_id}>")).await?;
    conn.read_stat().await.map_err(|e| {
        PostError::Retryable(format!(
            "cannot confirm whether <{message_id}> reached the server: {e}"
        ))
    })
}

/// A POST 441 is free-form, so only the conventional leading secondary
/// status (`441 435 Duplicate...`) is a claim that this exact Message-ID
/// already exists. A later mention of "435" or "duplicate" can describe an
/// unrelated policy/count and must remain a hard rejection.
fn post_response_claims_duplicate(line: &str) -> bool {
    let mut words = line.split_whitespace();
    if words.next() != Some("441") || words.next() != Some("435") {
        return false;
    }
    words.next().is_some_and(|word| {
        word.trim_matches(|c: char| !c.is_ascii_alphabetic())
            .eq_ignore_ascii_case("duplicate")
    })
}

/// Upload one wire article. Tries POST first; a server that refuses
/// posting outright (440) is retried via IHAVE when `allow_ihave` still
/// holds true. Returns whether IHAVE was used (callers latch it so later
/// articles skip the doomed POST round-trip).
pub async fn post_article(
    conn: &mut Connection,
    wire: &[u8],
    message_id: &str,
    use_ihave: bool,
    resent: bool,
) -> Result<bool, PostError> {
    if !use_ihave {
        let st = conn.exec("POST").await?;
        match st.code {
            340 => {
                conn.send_raw(wire).await?;
                let st = conn.read_status().await?;
                if st.code != 240 {
                    // A 441 on a RE-send can mean the first attempt was
                    // accepted after all and we simply never saw the
                    // acknowledgement (the acceptance read is bounded by
                    // COMMAND_TIMEOUT, and the session can die outright).
                    // The article would then be on the server under this
                    // exact Message-ID, and failing here would abort an
                    // upload that landed.
                    //
                    // Proof, not prose: ask whether the article is there.
                    // The 441 text is free-form and is not evidence - it can
                    // mention a duplicate of something else, or carry "435"
                    // as part of a byte count - and a segment recorded on
                    // that guess puts a Message-ID in the NZB that no server
                    // will ever answer.
                    //
                    // Only a 223 records the segment. A STAT that says NO is
                    // NOT the mirror image of that: `441 ... duplicate` is
                    // the posting server's own first-hand statement that it
                    // already holds this Message-ID, whereas the STAT may be
                    // answered by a read farm the article has not propagated
                    // to yet (routine on a big provider) or by a
                    // posting-only account that cannot STAT at all. Absence
                    // of evidence is not evidence of absence, so a miss is
                    // INCONCLUSIVE: spend another attempt instead of
                    // hard-failing an upload that most likely landed. If the
                    // budget runs out the post still fails - loudly, and
                    // with the Message-ID in the error text.
                    if resent && st.code == 441 {
                        // A STAT that cannot be ANSWERED must not erase what
                        // the server just told us. `?` here discarded the 441
                        // duplicate claim and failed with the transport error
                        // instead - worst on exactly the accounts that
                        // provoke it, since a posting-only account cannot
                        // STAT at all and would hard-fail every resend of an
                        // article the server said it already holds. An
                        // unanswerable STAT is the same "cannot confirm" the
                        // miss below reports, so it takes the same branch.
                        let exists = match stat_exists(conn, message_id).await {
                            Ok(v) => v,
                            Err(e) if post_response_claims_duplicate(st.line()) => {
                                return Err(PostError::Unconfirmed(format!(
                                    "article <{message_id}>: resend rejected as a duplicate and \
                                     the server could not be asked whether it holds it ({e}): {}",
                                    st.line()
                                )));
                            }
                            Err(e) => return Err(e),
                        };
                        return if exists {
                            Ok(false)
                        } else if post_response_claims_duplicate(st.line()) {
                            Err(PostError::Unconfirmed(format!(
                                "resend rejected as a duplicate and the article is not (yet) \
                                 confirmed on the server: {}",
                                st.line()
                            )))
                        } else {
                            // A 441 whose wording we do not recognise, with
                            // STAT not (yet) seeing the article. 441 is
                            // free-form, so this is genuinely ambiguous: a
                            // server that spells its duplicate rejection any
                            // other way looks identical here to one that
                            // really refused. Retryable, not terminal, so the
                            // remaining attempts re-STAT and a merely-lagging
                            // read farm still gets to confirm it. Making this
                            // Other spent the whole budget on one look at a
                            // race that is defined by propagation delay.
                            // If the attempts run out it still fails, loudly,
                            // with the Message-ID in the text.
                            Err(PostError::Retryable(format!(
                                "article {message_id}: server rejected the resend and does not \
                                 (yet) have it: {}",
                                st.line()
                            )))
                        };
                    }
                    return Err(PostError::Other(format!(
                        "server rejected article after POST: {}",
                        st.line()
                    )));
                }
                return Ok(false);
            }
            440 => {} // posting not permitted - fall through to IHAVE
            // RFC 3977's try-again-later family. "Not now" is not "never":
            // bucketing these with hard rejections throws away an upload
            // over a momentary server condition.
            400 | 502 | 503 => {
                return Err(PostError::Retryable(format!(
                    "server cannot take a POST right now: {}",
                    st.line()
                )));
            }
            _ => {
                return Err(PostError::Other(format!(
                    "unexpected response to POST: {}",
                    st.line()
                )));
            }
        }
    }
    let st = conn.exec(&format!("IHAVE <{message_id}>")).await?;
    match st.code {
        335 => {
            conn.send_raw(wire).await?;
            let st = conn.read_status().await?;
            match st.code {
                235 => Ok(true),
                // "transfer failed; try again later" - nothing was filed,
                // and the server is asking for a retry (437 in contrast is
                // "rejected, do not retry" and stays fatal below).
                436 => Err(PostError::Retryable(format!(
                    "article <{message_id}>: server could not take it: {}",
                    st.line()
                ))),
                _ => Err(PostError::Other(format!(
                    "article <{message_id}>: server rejected it after IHAVE: {}",
                    st.line()
                ))),
            }
        }
        // 435 = "not wanted". That is the answer both for an article the
        // server already holds (our own resend landing twice) and for one
        // it declines to file at all - the status line cannot tell them
        // apart, and only the first may be written into the NZB.
        //
        // A STAT miss IS decisive here, unlike on the POST path above:
        // 435 is not a claim of possession, so "we won't take it" plus
        // "it isn't here" is a coherent, final answer rather than a
        // propagation race. Failing now says so clearly instead of
        // re-offering an article the server has already declined.
        435 => {
            if stat_exists(conn, message_id).await? {
                Ok(true)
            } else {
                Err(PostError::Other(format!(
                    "article <{message_id}>: server will not take it and does not have it: {}",
                    st.line()
                )))
            }
        }
        400 | 436 | 502 | 503 => Err(PostError::Retryable(format!(
            "article <{message_id}>: server cannot take an IHAVE right now: {}",
            st.line()
        ))),
        _ => Err(PostError::Other(format!(
            "article <{message_id}>: server refused both POST and IHAVE: {}",
            st.line()
        ))),
    }
}

/// Progress callback data: (articles done, articles total, raw bytes sent).
pub type Progress = Arc<dyn Fn(u64, u64, u64) + Send + Sync>;

/// Post every planned file through `server` and return the NZB material.
/// Articles are encoded lazily (positioned reads) so memory stays at
/// `connections * article_size`, and `connections` NNTP sessions drain a
/// shared queue. Any article that keeps failing aborts the whole post -
/// a partially posted corpus is worse than a loud failure - but the abort
/// is never silent about what already landed: it comes back as
/// [`PostError::Aborted`] carrying every accepted Message-ID, and the
/// caller is expected to persist or print them.
pub async fn post_files(
    server: &ServerConfig,
    plan: &[PlanFile],
    opts: &PostOpts,
    progress: Option<Progress>,
) -> Result<PostedSet, PostError> {
    // The title rides the subject prefix (`title [i/n] - "file" yEnc ...`).
    // A double quote there injects a spurious quote our own subject parser
    // latches onto; a control char splits the Subject header line. Reject
    // both up front rather than emit a subject we cannot round-trip.
    if let Some(t) = opts.title.as_deref()
        && t.chars().any(|c| c.is_control() || c == '"')
    {
        return Err(PostError::Other(format!(
            "post title {t:?} contains a control or double-quote character"
        )));
    }
    let date = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Pre-assign every article its subject and message-id so results can
    // land out of order and the NZB still comes out deterministic.
    struct Task {
        file: usize,
        part: u32,
        offset: u64,
        len: usize,
        subject: String,
        message_id: String,
    }
    let mut tasks: Vec<Task> = Vec::new();
    let mut files_out: Vec<PostedFile> = Vec::new();
    for (fi, f) in plan.iter().enumerate() {
        let subject = subject_for(
            opts.title.as_deref(),
            &f.name,
            fi as u32 + 1,
            plan.len() as u32,
            1,
            f.parts,
        );
        files_out.push(PostedFile {
            name: f.name.clone(),
            // The NZB subject is the file's part-1 subject (the standard
            // indexer convention).
            subject,
            date,
            size: f.size,
            segments: Vec::new(),
        });
        for part in 1..=f.parts {
            let offset = (part as u64 - 1) * opts.article_size as u64;
            let len = (f.size - offset).min(opts.article_size as u64) as usize;
            tasks.push(Task {
                file: fi,
                part,
                offset,
                len,
                subject: subject_for(
                    opts.title.as_deref(),
                    &f.name,
                    fi as u32 + 1,
                    plan.len() as u32,
                    part,
                    f.parts,
                ),
                message_id: message_id(&opts.msgid_domain),
            });
        }
    }
    let total_articles = tasks.len() as u64;

    // Results: per-file slot per part, filled as workers finish.
    let results: Arc<Vec<std::sync::Mutex<Vec<Option<PostedSegment>>>>> = Arc::new(
        plan.iter()
            .map(|f| std::sync::Mutex::new(vec![None; f.parts as usize]))
            .collect(),
    );
    let tasks = Arc::new(tasks);
    let next = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));
    let ihave_latch = Arc::new(AtomicBool::new(false));
    let failed: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));

    let workers = opts.connections.clamp(1, 32).min(tasks.len().max(1));
    let mut handles = Vec::new();
    for _ in 0..workers {
        let server = server.clone();
        let opts = opts.clone();
        let plan: Vec<PlanFile> = plan.to_vec();
        let tasks = tasks.clone();
        let next = next.clone();
        let done = done.clone();
        let sent = sent.clone();
        let results = results.clone();
        let ihave_latch = ihave_latch.clone();
        let failed = failed.clone();
        let progress = progress.clone();
        handles.push(tokio::spawn(async move {
            let mut conn: Option<Connection> = None;
            loop {
                if failed.lock_ok().is_some() {
                    break;
                }
                let ti = next.fetch_add(1, Ordering::Relaxed);
                let Some(task) = tasks.get(ti) else { break };
                let f = &plan[task.file];

                // Read + encode this part (blocking file I/O is fine at
                // this call rate - one pread per ~700 KB posted).
                let chunk = match read_chunk(&f.path, task.offset, task.len) {
                    Ok(c) => c,
                    Err(e) => {
                        fail(&failed, format!("reading {}: {e}", f.path.display()));
                        break;
                    }
                };
                let body = crate::yenc::encode(
                    &f.name,
                    f.size,
                    Some((task.part, f.parts)),
                    task.offset + 1,
                    &chunk,
                );
                let wire = build_wire_article(
                    &opts.from,
                    &opts.group,
                    &task.subject,
                    &task.message_id,
                    date,
                    &body,
                );

                // Up to 3 attempts, reconnecting between failures.
                let mut attempt = 0u32;
                loop {
                    attempt += 1;
                    if conn.is_none() {
                        match Connection::connect(&server).await {
                            Ok((c, _)) => conn = Some(c),
                            Err(e) if attempt < 3 => {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                let _ = e;
                                continue;
                            }
                            Err(e) => {
                                fail(&failed, format!("connect: {e}"));
                                break;
                            }
                        }
                    }
                    let c = conn.as_mut().expect("connected above");
                    match post_article(
                        c,
                        &wire,
                        &task.message_id,
                        ihave_latch.load(Ordering::Relaxed),
                        attempt > 1,
                    )
                    .await
                    {
                        Ok(used_ihave) => {
                            if used_ihave {
                                ihave_latch.store(true, Ordering::Relaxed);
                            }
                            results[task.file].lock_ok()[task.part as usize - 1] =
                                Some(PostedSegment {
                                    number: task.part,
                                    message_id: task.message_id.clone(),
                                    bytes: body.len() as u64,
                                });
                            let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                            let s = sent.fetch_add(wire.len() as u64, Ordering::Relaxed)
                                + wire.len() as u64;
                            if let Some(p) = &progress {
                                p(d, total_articles, s);
                            }
                            break;
                        }
                        // A definitive server rejection (240/235 refused)
                        // will repeat on retry - abort loudly. The
                        // try-again-later codes are NOT in here: they come
                        // back as PostError::Retryable and fall into the
                        // bounded retry arm below.
                        Err(PostError::Other(m)) => {
                            fail(&failed, m);
                            break;
                        }
                        Err(e) if attempt < 3 => {
                            conn = None; // reconnect and retry the article
                            // A server that said "not now" means it: give it
                            // a moment rather than hammering the same
                            // condition twice in a row. Still bounded by the
                            // same 3-attempt budget as every other failure.
                            if matches!(e, PostError::Retryable(_) | PostError::Unconfirmed(_)) {
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            }
                        }
                        Err(PostError::Unconfirmed(m)) => {
                            // A provider-reported duplicate is not enough
                            // to declare SUCCESS while STAT still misses,
                            // but it is enough to make losing this random
                            // Message-ID unsafe. Preserve it in the rescue
                            // set before another worker's error wins the
                            // shared failure slot.
                            results[task.file].lock_ok()[task.part as usize - 1] =
                                Some(PostedSegment {
                                    number: task.part,
                                    message_id: task.message_id.clone(),
                                    bytes: body.len() as u64,
                                });
                            fail(
                                &failed,
                                format!(
                                    "article {} may already be accepted but is not yet \
                                     STAT-confirmed: {m}",
                                    task.message_id
                                ),
                            );
                            break;
                        }
                        Err(e) => {
                            fail(&failed, format!("article {}: {e}", task.message_id));
                            break;
                        }
                    }
                }
                if failed.lock_ok().is_some() {
                    break;
                }
            }
            if let Some(c) = conn.take() {
                c.quit().await;
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    // Harvest what the server actually took - holes and all, on EVERY exit
    // path. On an abort these Message-IDs are the only record of articles
    // that are already public (random ids, indexed nowhere else), so they
    // ride out with the error instead of being dropped alongside it.
    let mut missing: Option<String> = None;
    for (fi, slots) in results.iter().enumerate() {
        let slots = slots.lock_ok();
        for (pi, s) in slots.iter().enumerate() {
            match s {
                Some(seg) => files_out[fi].segments.push(seg.clone()),
                None => {
                    missing.get_or_insert_with(|| {
                        format!(
                            "article {}/{} of {} never completed",
                            pi + 1,
                            slots.len(),
                            files_out[fi].name
                        )
                    });
                }
            }
        }
    }
    let aborted = { failed.lock_ok().take() }.or(missing);
    if let Some(message) = aborted {
        // Files with nothing on the server are noise in a rescue index.
        files_out.retain(|f| !f.segments.is_empty());
        if files_out.is_empty() {
            return Err(PostError::Other(message));
        }
        return Err(PostError::Aborted {
            message,
            posted: Box::new(PostedSet {
                group: opts.group.clone(),
                from: opts.from.clone(),
                files: files_out,
            }),
        });
    }

    Ok(PostedSet {
        group: opts.group.clone(),
        from: opts.from.clone(),
        files: files_out,
    })
}

fn fail(slot: &std::sync::Mutex<Option<String>>, msg: String) {
    slot.lock_ok().get_or_insert(msg);
}

fn read_chunk(path: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let f = std::fs::File::open(path)?;
    crate::disk::read_exact_at(&f, &mut buf, offset)?;
    Ok(buf)
}

/// SHA-256 of a file, streamed - the round-trip verify comparator.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(hex)
}

/// Serialize a posted set as NZB XML - the exact shape `Nzb::parse`
/// consumes (files, groups, segments with encoded sizes and bracketless
/// message-ids).
pub fn emit_nzb(set: &PostedSet) -> String {
    fn esc(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
    let mut out = String::with_capacity(1024);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE nzb PUBLIC \"-//newzBin//DTD NZB 1.1//EN\" \"http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd\">\n",
    );
    out.push_str("<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n");
    for f in &set.files {
        out.push_str(&format!(
            "  <file poster=\"{}\" date=\"{}\" subject=\"{}\">\n",
            esc(&set.from),
            f.date,
            esc(&f.subject)
        ));
        out.push_str("    <groups>\n");
        out.push_str(&format!("      <group>{}</group>\n", esc(&set.group)));
        out.push_str("    </groups>\n");
        out.push_str("    <segments>\n");
        for s in &f.segments {
            out.push_str(&format!(
                "      <segment bytes=\"{}\" number=\"{}\">{}</segment>\n",
                s.bytes,
                s.number,
                esc(&s.message_id)
            ));
        }
        out.push_str("    </segments>\n");
        out.push_str("  </file>\n");
    }
    out.push_str("</nzb>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nzb::Nzb;

    fn test_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 13 + i / 251) as u8).collect()
    }

    #[test]
    fn rfc5322_dates_round_trip_through_our_parser() {
        for unix in [
            0i64,
            880_127_706,
            1_714_653_296,
            1_767_225_600,
            1_753_358_400, // 2026-07-24
            86_399,
            86_400,
        ] {
            let s = rfc5322_date(unix);
            assert_eq!(
                crate::nntp::parse_nntp_date(&s),
                Some(unix),
                "date {unix} formatted as {s:?} must parse back"
            );
        }
        // Known fixed point: RFC 2822's example date.
        assert_eq!(rfc5322_date(880_127_706), "Fri, 21 Nov 1997 15:55:06 +0000");
    }

    #[test]
    fn message_ids_are_neutral_and_unique() {
        let a = message_id("corpus.example");
        let b = message_id("corpus.example");
        assert_ne!(a, b);
        assert!(a.ends_with("@corpus.example"));
        // Local part is pure hex - no hostname, username or structure.
        let local = a.split('@').next().unwrap();
        assert!(local.len() >= 32);
        assert!(local.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn subjects_follow_the_yenc_convention() {
        assert_eq!(
            subject_for(None, "a.bin", 1, 1, 3, 10),
            "\"a.bin\" yEnc (3/10)"
        );
        assert_eq!(
            subject_for(Some("corpus v1"), "a.bin", 2, 5, 1, 4),
            "corpus v1 [2/5] - \"a.bin\" yEnc (1/4)"
        );
        // The quoted-filename extractor the whole pipeline uses must see
        // the posted name.
        assert_eq!(
            crate::nzb::quoted_filename(&subject_for(Some("t"), "x.part01.rar", 1, 2, 2, 9)),
            Some("x.part01.rar")
        );
    }

    #[test]
    fn wire_article_has_only_the_five_headers() {
        let body = crate::yenc::encode("h.bin", 4, None, 1, b"test");
        let wire = build_wire_article(
            "c@d.e",
            "alt.binaries.test",
            "\"h.bin\" yEnc (1/1)",
            "x@y",
            0,
            &body,
        );
        let text = String::from_utf8_lossy(&wire);
        let headers: Vec<&str> = text.split("\r\n\r\n").next().unwrap().lines().collect();
        assert_eq!(headers.len(), 5, "exactly five headers: {headers:?}");
        for h in &headers {
            let k = h.split(':').next().unwrap();
            assert!(
                ["From", "Newsgroups", "Subject", "Message-ID", "Date"].contains(&k),
                "unexpected header {k:?}"
            );
        }
        assert!(!text.contains("User-Agent"));
        assert!(!text.contains("X-Newsreader"));
        assert!(text.ends_with("\r\n.\r\n"));
        // Header-splitting attempt in a value is neutralized: the CRLF
        // collapses to spaces, so no LINE ever starts with the smuggled
        // header (the text may survive inline in the Subject, harmless).
        let evil = build_wire_article("a@b", "g", "s\r\nX-Injected: yes", "m@d", 0, &body);
        let etext = String::from_utf8_lossy(&evil).into_owned();
        assert!(etext.lines().all(|l| !l.starts_with("X-Injected:")));
        assert!(
            etext
                .lines()
                .any(|l| l.starts_with("Subject: s  X-Injected: yes"))
        );
    }

    #[test]
    fn wire_article_dot_stuffs_and_decodes_back() {
        // Data crafted so encoded lines start with '.' somewhere: encode
        // enough byte-soup that '.'-leading lines occur (0xE4 + 42 = '.').
        let mut data = test_data(50_000);
        for i in (0..data.len()).step_by(97) {
            data[i] = 0xE4;
        }
        let body = crate::yenc::encode("d.bin", data.len() as u64, None, 1, &data);
        let wire = build_wire_article("a@b", "g", "s", "m@d", 0, &body);
        // Peel headers, terminator; un-dot-stuff like a server would store it.
        let sep = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let stored = &wire[sep + 4..wire.len() - 3]; // strip trailing ".\r\n"
        // The decoder itself tolerates dot-stuffed input.
        let dec = crate::yenc::decode(stored).unwrap();
        assert_eq!(dec.data, data);
    }

    #[test]
    fn plan_splits_at_exact_boundaries() {
        let dir = std::env::temp_dir().join(format!("nzbfast-post-plan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let art = 1000usize;
        for (name, size, want_parts) in [
            ("exact.bin", 1000u64, 1u32),
            ("plus1.bin", 1001, 2),
            ("minus1.bin", 999, 1),
            ("triple.bin", 3000, 3),
            ("tiny.bin", 1, 1),
            ("spill.bin", 2001, 3),
        ] {
            std::fs::write(dir.join(name), test_data(size as usize)).unwrap();
            let p = plan(&[dir.join(name)], art).unwrap();
            assert_eq!(p[0].parts, want_parts, "{name}");
            assert_eq!(p[0].size, size);
        }
        // Empty file refused.
        std::fs::write(dir.join("empty.bin"), b"").unwrap();
        assert!(plan(&[dir.join("empty.bin")], art).is_err());
        // Directory walk is deterministic (sorted) and skips dotfiles.
        std::fs::write(dir.join(".hidden"), b"x").unwrap();
        std::fs::remove_file(dir.join("empty.bin")).unwrap();
        let all = plan(std::slice::from_ref(&dir), art).unwrap();
        let names: Vec<&str> = all.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "exact.bin",
                "minus1.bin",
                "plus1.bin",
                "spill.bin",
                "tiny.bin",
                "triple.bin"
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A posted name is reproduced verbatim on the yEnc `name=` line, so
    /// a control character (an embedded CRLF above all) must refuse the
    /// plan instead of desyncing every article of the file.
    #[cfg(unix)]
    #[test]
    fn plan_rejects_control_character_names() {
        let dir = std::env::temp_dir().join(format!("nzbfast-post-ctl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("evil\r\n.bin");
        std::fs::write(&bad, b"payload").unwrap();
        let err = plan(&[bad], 1000).unwrap_err();
        assert!(format!("{err}").contains("control"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The walk must not follow symlinks - a link would post its target's
    /// bytes (possibly from outside the corpus) or loop forever.
    #[cfg(unix)]
    #[test]
    fn plan_skips_symlinks() {
        let dir = std::env::temp_dir().join(format!("nzbfast-post-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("real.bin"), b"payload").unwrap();
        std::os::unix::fs::symlink(dir.join("real.bin"), dir.join("alias.bin")).unwrap();
        std::os::unix::fs::symlink(&dir, dir.join("loop")).unwrap();
        let p = plan(std::slice::from_ref(&dir), 1000).unwrap();
        let names: Vec<&str> = p.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["real.bin"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plan_caps_article_size() {
        let dir = std::env::temp_dir().join(format!("nzbfast-post-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.bin"), b"payload").unwrap();
        assert!(plan(&[dir.join("a.bin")], ARTICLE_SIZE_CAP + 1).is_err());
        assert!(plan(&[dir.join("a.bin")], ARTICLE_SIZE_CAP).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The msgid domain rides on the Message-ID header AND the IHAVE
    /// command line - hostile flag values must not smuggle CRLF (or
    /// anything else) into either.
    #[test]
    fn message_id_domain_is_sanitized() {
        let id = message_id("evil.com\r\nX-Inject: 1");
        assert!(!id.contains('\r') && !id.contains('\n') && !id.contains(' '));
        assert!(id.contains("@evil.com"));
        assert!(message_id("<>@ ").ends_with("@nzbfast.invalid"));
    }

    /// Full loop against the mock server: plan → post (POST path) → emit
    /// NZB → parse it back → BODY-fetch every segment → decode →
    /// reassemble → byte-compare with the source files.
    async fn round_trip(chaos: crate::mock::Chaos, expect_ihave: bool) {
        use std::collections::HashMap;
        let srv = crate::mock::MockServer::start(HashMap::new(), chaos).await;
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-post-e2e-{}-{expect_ihave}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let multi = test_data(2500); // 3 parts at 1000 bytes
        let single = test_data(700);
        std::fs::write(dir.join("multi.bin"), &multi).unwrap();
        std::fs::write(dir.join("single.bin"), &single).unwrap();

        let plan_files = plan(std::slice::from_ref(&dir), 1000).unwrap();
        let opts = PostOpts {
            group: "alt.binaries.test".into(),
            from: "corpus@nzbfast.com".into(),
            msgid_domain: "corpus.example".into(),
            article_size: 1000,
            title: Some("e2e set".into()),
            connections: 3,
        };
        let set = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect("post");

        let nzb = Nzb::parse(emit_nzb(&set).as_bytes()).expect("emitted NZB parses");
        assert_eq!(nzb.files.len(), 2);
        let (mut conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        for f in &nzb.files {
            let name = f.filename_hint().expect("subject carries the filename");
            let source = std::fs::read(dir.join(name)).unwrap();
            let mut got = vec![0u8; source.len()];
            assert!(!f.segments.is_empty());
            for seg in &f.segments {
                let raw = conn
                    .body(&format!("<{}>", seg.message_id))
                    .await
                    .expect("BODY")
                    .expect("posted article must exist");
                let dec = crate::yenc::decode(&raw).expect("decode + CRC");
                assert_eq!(dec.name, name);
                assert_eq!(dec.file_size, source.len() as u64);
                let off = dec.offset() as usize;
                got[off..off + dec.data.len()].copy_from_slice(&dec.data);
            }
            assert_eq!(got, source, "{name} must survive the round trip");
        }
        conn.quit().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn e2e_post_round_trips_through_the_mock() {
        round_trip(crate::mock::Chaos::default(), false).await;
    }

    #[tokio::test]
    async fn e2e_ihave_fallback_when_posting_rejected() {
        round_trip(
            crate::mock::Chaos {
                post_rejected: true,
                ..Default::default()
            },
            true,
        )
        .await;
    }

    /// A one-file corpus of `parts` articles in its own temp directory,
    /// posted through a SINGLE connection so the mock's global failure
    /// counters land on known articles.
    fn corpus(tag: &str, parts: usize, art: usize) -> (PathBuf, Vec<PlanFile>, PostOpts) {
        let dir = std::env::temp_dir().join(format!("nzbfast-post-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("corpus.bin"), test_data(parts * art)).unwrap();
        let plan_files = plan(std::slice::from_ref(&dir), art).unwrap();
        let opts = PostOpts {
            group: "alt.binaries.test".into(),
            from: "corpus@nzbfast.com".into(),
            msgid_domain: "corpus.example".into(),
            article_size: art,
            title: None,
            connections: 1,
        };
        (dir, plan_files, opts)
    }

    /// Every Message-ID the set claims must be answerable by the server.
    async fn assert_all_present(srv: &crate::mock::MockServer, set: &PostedSet) {
        let (mut conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        for f in &set.files {
            for seg in &f.segments {
                assert!(
                    conn.body(&format!("<{}>", seg.message_id))
                        .await
                        .expect("BODY")
                        .is_some(),
                    "{} segment {} was recorded as posted but is not on the server",
                    f.name,
                    seg.number
                );
            }
        }
        conn.quit().await;
    }

    /// The case the 441 escape hatch exists for: the first attempt WAS
    /// accepted and the acknowledgement never arrived. The resend meets a
    /// duplicate rejection, STAT proves the article is there, and the
    /// segment is recorded.
    #[tokio::test]
    async fn a_lost_acknowledgement_is_resolved_by_stat() {
        let srv = crate::mock::MockServer::start(
            std::collections::HashMap::new(),
            crate::mock::Chaos {
                post: crate::mock::PostChaos {
                    ack_lost: 1,
                    ack_lost_keeps: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let (dir, plan_files, opts) = corpus("acklost", 2, 1000);
        let set = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect("the article landed on the first attempt - the resend must recognise it");
        assert_eq!(set.files[0].segments.len(), 2);
        assert_all_present(&srv, &set).await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two posting frontends can both accept before their acknowledgements
    /// vanish while the provider's separate read farm still answers 430.
    /// Neither is safe to call successful, but both random Message-IDs must
    /// survive in the rescue NZB.
    #[tokio::test]
    async fn concurrent_unconfirmed_duplicates_all_reach_the_rescue_index() {
        let srv = crate::mock::MockServer::start(
            std::collections::HashMap::new(),
            crate::mock::Chaos {
                post: crate::mock::PostChaos {
                    ack_lost: 2,
                    ack_lost_keeps: true,
                    // Attempts 2 and 3 STAT once per article.
                    stat_miss: 4,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let (dir, plan_files, mut opts) = corpus("acklag", 2, 1000);
        opts.connections = 2;
        let err = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect_err("read-farm lag must keep the upload from claiming success");
        let PostError::Aborted { posted, .. } = err else {
            panic!("possibly accepted ids need rescue output, got {err:?}");
        };
        assert_eq!(posted.files.len(), 1);
        assert_eq!(posted.files[0].segments.len(), 2);
        let nzb = Nzb::parse(emit_nzb(&posted).as_bytes()).expect("rescue NZB parses");
        assert_eq!(nzb.files[0].segments.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A 441 is free-form, so a duplicate rejection we do not recognise
    /// must not be read as "the server does not have it". Here the
    /// article DID land (the acknowledgement was lost), the server says
    /// so in its own words, and the read farm is one STAT behind. Making
    /// that terminal spent the whole attempt budget on a single look at a
    /// race defined by propagation delay; the remaining attempts re-STAT
    /// and the article is confirmed.
    #[tokio::test]
    async fn an_unfamiliar_duplicate_wording_still_gets_its_retries() {
        let srv = crate::mock::MockServer::start(
            std::collections::HashMap::new(),
            crate::mock::Chaos {
                post: crate::mock::PostChaos {
                    ack_lost: 1,
                    ack_lost_keeps: true,
                    // Neither the "435" secondary status nor the word
                    // "duplicate" in the blessed position.
                    duplicate_text: Some("441 Posting failed: dupe message-id".into()),
                    // The first STAT is behind; a later one sees it.
                    stat_miss: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let (dir, plan_files, opts) = corpus("oddDupe", 2, 1000);
        let set = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect("a lagging read farm must not turn an unfamiliar 441 into a hard failure");
        assert_eq!(set.files[0].segments.len(), 2);
        assert_all_present(&srv, &set).await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A STAT that cannot be ANSWERED must not erase the 441 duplicate
    /// claim the server just made. The posting-only account is the case
    /// that matters: it has no read access, so every STAT dies, and
    /// letting the transport error win hard-failed the resend of an
    /// article the server had already said it holds. "Cannot confirm" is
    /// the honest verdict, and it is Unconfirmed - the same branch a STAT
    /// miss takes - so the Message-ID still reaches the rescue NZB.
    #[tokio::test]
    async fn an_unanswerable_stat_does_not_erase_the_servers_duplicate_claim() {
        let srv = crate::mock::MockServer::start(
            std::collections::HashMap::new(),
            crate::mock::Chaos {
                post: crate::mock::PostChaos {
                    ack_lost: 1,
                    ack_lost_keeps: true,
                    stat_dies: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let (dir, plan_files, opts) = corpus("statdies", 2, 1000);
        let err = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect_err("an unconfirmable article must not be claimed as posted");
        let PostError::Aborted { posted, .. } = err else {
            panic!("a duplicate claim we could not verify needs rescue output, got {err:?}");
        };
        let nzb = Nzb::parse(emit_nzb(&posted).as_bytes()).expect("rescue NZB parses");
        assert!(
            !nzb.files.is_empty(),
            "the id the server claimed to hold must survive into the rescue NZB"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Same shape over IHAVE: the resend is answered "435 not wanted"
    /// because the server already holds it, and STAT (not the wording)
    /// is what makes that safe to record.
    #[tokio::test]
    async fn an_ihave_resend_the_server_already_holds_is_confirmed_by_stat() {
        let srv = crate::mock::MockServer::start(
            std::collections::HashMap::new(),
            crate::mock::Chaos {
                post_rejected: true, // forces the IHAVE path
                post: crate::mock::PostChaos {
                    ack_lost: 1,
                    ack_lost_keeps: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let (dir, plan_files, opts) = corpus("ihavedup", 2, 1000);
        let set = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect("a 435 for an article the server really has is not a failure");
        assert_eq!(set.files[0].segments.len(), 2);
        assert_all_present(&srv, &set).await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A 441 whose free-form text merely MENTIONS a duplicate (or happens
    /// to carry "435") is a rejection, not an acceptance. Recording it
    /// would put a Message-ID in the NZB that no server can answer. The
    /// article is never confirmed by STAT here, so the attempts run out
    /// and the post fails with nothing recorded - and the failure names
    /// the Message-ID that was sent, plus the server's own words.
    #[tokio::test]
    async fn a_441_that_only_mentions_duplicates_is_still_a_failure() {
        for text in [
            "posting failed - 435 duplicate submissions were rejected today",
            "posting failed",
        ] {
            let srv = crate::mock::MockServer::start(
                std::collections::HashMap::new(),
                crate::mock::Chaos {
                    post: crate::mock::PostChaos {
                        ack_lost: 1,           // force a resend...
                        ack_lost_keeps: false, // ...of an article that never landed
                        reject_441: Some(text.into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let (dir, plan_files, opts) = corpus("bogus441", 1, 1000);
            let err = post_files(&srv.server_config(), &plan_files, &opts, None)
                .await
                .expect_err("a rejection must never be recorded as a posted segment");
            let msg = format!("{err}");
            // The operator is told which article was sent and what the
            // server actually said about it.
            assert!(msg.contains("@corpus.example"), "{msg}");
            assert!(msg.contains(text), "{msg}");
            // Nothing was confirmed, so there is nothing to rescue either.
            assert!(matches!(err, PostError::Other(_)), "{err:?}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// An abort partway through must hand back the Message-IDs of
    /// everything the server already accepted: those articles are public
    /// and this is their only index.
    #[tokio::test]
    async fn an_abort_surfaces_every_article_that_already_landed() {
        let srv = crate::mock::MockServer::start(
            std::collections::HashMap::new(),
            crate::mock::Chaos {
                post: crate::mock::PostChaos {
                    reject_441: Some("posting failed".into()),
                    reject_after: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let (dir, plan_files, opts) = corpus("abort", 5, 1000);
        let err = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect_err("the third article is rejected");
        let PostError::Aborted { posted, .. } = &err else {
            panic!("an abort with articles on the server must be Aborted, got {err:?}");
        };
        assert_eq!(posted.files.len(), 1);
        assert_eq!(
            posted.files[0].segments.len(),
            2,
            "both accepted articles belong in the rescue index"
        );
        // The rescue index is a real NZB and every id in it resolves.
        let nzb = Nzb::parse(emit_nzb(posted).as_bytes()).expect("rescue index parses");
        assert_eq!(nzb.files[0].segments.len(), 2);
        assert_all_present(&srv, posted).await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// RFC 3977's try-again-later on the POST command line is a pause, not
    /// a refusal: the upload must ride it out inside the retry budget.
    #[tokio::test]
    async fn a_503_on_post_is_retried_not_fatal() {
        let srv = crate::mock::MockServer::start(
            std::collections::HashMap::new(),
            crate::mock::Chaos {
                post: crate::mock::PostChaos {
                    try_later: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let (dir, plan_files, opts) = corpus("try503", 3, 1000);
        let set = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect("503 means ask again, not give up");
        assert_eq!(set.files[0].segments.len(), 3);
        assert_all_present(&srv, &set).await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ...and the same on IHAVE's 436.
    #[tokio::test]
    async fn a_436_on_ihave_is_retried_not_fatal() {
        let srv = crate::mock::MockServer::start(
            std::collections::HashMap::new(),
            crate::mock::Chaos {
                post_rejected: true,
                post: crate::mock::PostChaos {
                    try_later: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let (dir, plan_files, opts) = corpus("try436", 2, 1000);
        let set = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect("436 means ask again, not give up");
        assert_eq!(set.files[0].segments.len(), 2);
        assert_all_present(&srv, &set).await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The retry is bounded: a server that never stops saying "later"
    /// fails the post rather than looping forever.
    #[tokio::test]
    async fn an_endless_try_again_later_still_fails() {
        let srv = crate::mock::MockServer::start(
            std::collections::HashMap::new(),
            crate::mock::Chaos {
                post: crate::mock::PostChaos {
                    try_later: u64::MAX,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
        let (dir, plan_files, opts) = corpus("tryforever", 1, 1000);
        let err = post_files(&srv.server_config(), &plan_files, &opts, None)
            .await
            .expect_err("the retry budget is finite");
        assert!(format!("{err}").contains("503"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn emitted_nzb_parses_back_with_escaping() {
        let set = PostedSet {
            group: "alt.binaries.test".into(),
            from: "corpus@nzbfast.com".into(),
            files: vec![PostedFile {
                name: "a&b <c>.bin".into(),
                subject: "\"a&b <c>.bin\" yEnc (1/2)".into(),
                date: 1_753_358_400,
                size: 1400,
                segments: vec![
                    PostedSegment {
                        number: 1,
                        message_id: "one@corpus.example".into(),
                        bytes: 730,
                    },
                    PostedSegment {
                        number: 2,
                        message_id: "two@corpus.example".into(),
                        bytes: 731,
                    },
                ],
            }],
        };
        let xml = emit_nzb(&set);
        let nzb = Nzb::parse(xml.as_bytes()).unwrap();
        assert_eq!(nzb.files.len(), 1);
        let f = &nzb.files[0];
        assert_eq!(f.subject, "\"a&b <c>.bin\" yEnc (1/2)");
        assert_eq!(f.poster, "corpus@nzbfast.com");
        assert_eq!(f.date, 1_753_358_400);
        assert_eq!(f.groups, vec!["alt.binaries.test"]);
        assert_eq!(f.segments.len(), 2);
        assert_eq!(f.segments[0].message_id, "one@corpus.example");
        assert_eq!(f.segments[1].bytes, 731);
        assert_eq!(f.filename_hint(), Some("a&b <c>.bin"));
    }
}
