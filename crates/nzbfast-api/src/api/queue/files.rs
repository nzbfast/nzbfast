//! TODO 274 (issue #51): the per-file half of the SAB-shaped surface -
//! `mode=get_files` lists one job's files with an opaque handle each,
//! and `mode=queue&name=promote_file` moves one file's still-pending
//! articles to the front of the queue.
//!
//! Reporting and one queue reorder. Nothing here teaches the ENGINE a
//! new state: the listing reads counters `FileSlot` already keeps, and
//! the promote rides the same `QueueControl::promote_opts` the
//! extractor's offset-0 probe and the player's span promotes ride.
//!
//! One word in the listing is not a counter, and it is the exception
//! that proves the rest: §296's "published", which says this file is
//! already AT the destination and usable while the job downloads. It
//! comes off the job RECORD (`Job::early_published`) rather than off a
//! slot, because no counter can know it - the copy is a daemon action,
//! not something the engine did. It is joined by §274's opaque handle
//! and never by the filename; see `earlyfile::EarlyFile::nzf_id` for
//! why a name join silently fails on exactly the obfuscated posts whose
//! drawer is worth reading.
//! Exclusion - declining a file's remaining articles - is deliberately
//! NOT here: absent articles are damage to the census, settle and
//! repair passes, so a naive skip sends repair off to rebuild the very
//! bytes that were declined. That is TODO 274 (c)/(d) and an accounting
//! project rather than an endpoint.
//!
//! One shape the daemon imposes: it downloads one job at a time, so
//! live per-file progress and promotion mean something only for the
//! ACTIVE job. A queued job is answered from its own spooled `.nzb`,
//! which carries names, sizes and segment counts but no state - and the
//! handles match, because both sides derive them the same way
//! (`streamhub::job_file_id`).

use super::*;

/// The handles of the files §296 has already put at the destination for
/// `nzo_id`, and the job's spool path if it has a queue row.
///
/// One walk of the queue for both answers, because the alternative is
/// two locks of it per poll of a drawer that is open on one job. The
/// published set is normally EMPTY - the feature is off by default, and
/// even on it is empty outside the window between a job's first early
/// copy and its move - so the common cost is a comparison against
/// nothing.
fn queue_facts(
    d: &Arc<Daemon>,
    nzo_id: &str,
) -> (std::collections::HashSet<String>, Option<PathBuf>) {
    d.queue
        .lock_ok()
        .iter()
        .find_map(|j| {
            let g = j.lock_ok();
            (g.nzo_id == nzo_id).then(|| {
                (
                    g.early_published
                        .iter()
                        .filter(|e| !e.nzf_id.is_empty())
                        .map(|e| e.nzf_id.clone())
                        .collect(),
                    Some(g.nzb_path.clone()),
                )
            })
        })
        .unwrap_or_default()
}

/// Where one file's facts came from, handed to a row renderer beside
/// the NZB half ([`crate::streamhub::JobFileRow`]).
///
/// The renderer is a parameter because two dialects list the same
/// files: SAB's `mode=get_files` below and NZBGet's `listfiles`
/// (`sabcompat::nzbget_lists`). The SOURCE choice - the active table,
/// a retired tail, or the spooled `.nzb` - and its gates are the part
/// that has been wrong before (see TODO 274 (e) below), so it is
/// walked once, here, and each dialect only says how a row looks.
pub(crate) enum FileSrc<'a> {
    /// A job with no plan yet, answered from its spooled `.nzb`.
    /// `recovery` is the NZB's own classification, which is not `Data`
    /// for the index `.par2` as well as the volumes; `volume` is the
    /// narrower "a `.volNN+MM.par2` fetched only for repair".
    Queued { recovery: bool, volume: bool },
    /// A job WITH a plan, live or retired. `counts` is None for an
    /// NZB-classified recovery volume the plan never gave a slot.
    /// `published` is §296's set of handles already AT the destination.
    Planned {
        counts: Option<&'a crate::streamhub::FileSlotCounts>,
        published: &'a std::collections::HashSet<String>,
    },
}

/// The listing rows for `nzo_id`, or None when no queue row has that id.
fn listing(d: &Arc<Daemon>, nzo_id: &str) -> Option<Vec<Value>> {
    listing_with(d, nzo_id, |r, src| match src {
        FileSrc::Queued { recovery, .. } => queued_row(r, recovery),
        FileSrc::Planned { counts, published } => live_row(r, counts, published),
    })
}

/// Every file of queue row `nzo_id`, rendered by `render`, or None when
/// no queue row has that id. See [`FileSrc`].
pub(crate) fn listing_with<T>(
    d: &Arc<Daemon>,
    nzo_id: &str,
    render: impl FnMut(&crate::streamhub::JobFileRow, FileSrc<'_>) -> T,
) -> Option<Vec<T>> {
    let (published, path) = queue_facts(d, nzo_id);
    listing_from(d, nzo_id, &published, path, render)
}

/// [`listing_with`] for a caller that already holds the job's spool
/// path and published set, so a walk over the whole queue (NZBGet's
/// `listgroups`) need not re-find each row under the queue lock - which
/// is O(queue) per job, and a DEADLOCK if the caller still holds that
/// lock. The source choice is the same code either way.
pub(crate) fn listing_from<T>(
    d: &Arc<Daemon>,
    nzo_id: &str,
    published: &std::collections::HashSet<String>,
    path: Option<PathBuf>,
    mut render: impl FnMut(&crate::streamhub::JobFileRow, FileSrc<'_>) -> T,
) -> Option<Vec<T>> {
    let mut planned = |r: &crate::streamhub::JobFileRow,
                       c: Option<&crate::streamhub::FileSlotCounts>| {
        render(
            r,
            FileSrc::Planned {
                counts: c,
                published,
            },
        )
    };
    // The ACTIVE job first: its table is already built, so nothing is
    // parsed on a poll. The owner tag inside `job_files_for` is what
    // makes this safe to consult before the record lookup - a stale
    // table belongs to a different id and simply does not match.
    if let Some(t) = d.hub.job_files_for(nzo_id) {
        let counts = |r: &crate::streamhub::JobFileRow| {
            r.slot
                .and_then(|i| t.slots.get(i))
                .map(|s| crate::streamhub::FileSlotCounts::of(s))
        };
        return Some(
            t.rows
                .iter()
                .map(|r| planned(r, counts(r).as_ref()))
                .collect(),
        );
    }
    let path = path?;
    // TODO 274 (e): a job PAST its network phase, whose table the next
    // job's start retired into `hub.tail_files`. Its rows are the run's
    // own counters, so the tail says which files arrived whole, which
    // lost articles and which were declined - the question a user
    // watching Repairing is actually asking, and the one the parse
    // below cannot answer at all.
    //
    // Gated on the tail phase and not merely on the entry existing. A
    // retired entry outlives its job by design (it is bounded by a cap,
    // not by a park hook), and a RETRY re-queues the same nzo_id: a
    // listing keyed on the id alone would report the previous run's
    // damage against a job that has not started. `tail_phase` is the
    // same test the queue payload's status word comes from, so the
    // listing and the row it appears under can never disagree.
    if let Some(t) = d
        .tail_phase(nzo_id)
        .and_then(|_| d.hub.tail_files_for(nzo_id))
    {
        return Some(
            t.rows
                .iter()
                .zip(t.counts.iter())
                .map(|(r, c)| planned(r, c.as_ref()))
                .collect(),
        );
    }
    // A queued job answers from the file it was spooled from. Read on
    // the request thread like `/jobnzb` does, and unreadable or
    // unparseable is an empty listing rather than a 500 - the record
    // exists, we just cannot describe it.
    let rows = queued_rows(&path);
    Some(
        rows.iter()
            .map(|q| {
                let src = FileSrc::Queued {
                    recovery: q.recovery,
                    volume: q.volume,
                };
                render(&q.row, src)
            })
            .collect(),
    )
}

/// One file of a queued job's spooled NZB, with the NZB's own
/// classification - the same one the plan will apply the moment the
/// job starts (`get/plan.rs` reads `kind()` too). Without it a queued
/// listing calls the recovery set payload, and a reader counting "what
/// did I queue" counts a par2 set that may be a third of the rows.
/// `recovery` is not `Data` (the index `.par2` as well as the volumes);
/// `volume` is the narrower "a `.volNN+MM.par2` fetched only for repair".
pub(crate) struct QueuedFile {
    pub(crate) row: crate::streamhub::JobFileRow,
    pub(crate) recovery: bool,
    pub(crate) volume: bool,
}

/// What one cache entry was parsed from: the spool's (mtime, length).
/// A rewritten spool changes one or both, and a stale entry is simply
/// re-parsed; a spool whose metadata cannot be read is never cached.
type SpoolStamp = (std::time::SystemTime, u64);

/// How many spools the parse cache holds before it starts over. A
/// queued job's rows are its NZB's names and sizes, so an entry is a
/// few KB per hundred files; the cap bounds a pathological queue, and
/// clearing (rather than LRU) is enough because every entry is cheap to
/// rebuild and a queue walk refills it in one pass.
const QUEUED_ROWS_CAP: usize = 512;

type QueuedRowsCache = std::collections::HashMap<PathBuf, (SpoolStamp, Arc<Vec<QueuedFile>>)>;

/// Parsed queued spools, keyed by path and stamped by [`SpoolStamp`].
///
/// TODO 358 sweep E1/E3: NZBGet clients poll `listgroups` - which now
/// carries each group's real file count - every second or two, and an
/// unfiltered `listfiles` lists every queued job. Both would answer a
/// queued job by parsing its whole NZB per call, which for a deep queue
/// is the request thread re-reading megabytes of XML that has not
/// changed since it was spooled. The spool is written once at add, so
/// the parse is memoized; a spool that is rewritten moves its stamp
/// and is parsed again.
static QUEUED_ROWS: std::sync::LazyLock<Mutex<QueuedRowsCache>> =
    std::sync::LazyLock::new(Default::default);

fn spool_stamp(path: &std::path::Path) -> Option<SpoolStamp> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}

/// A queued job's files off its spooled `.nzb`, parsed at most once per
/// spool revision. Empty when the spool is unreadable or unparseable.
pub(crate) fn queued_rows(path: &std::path::Path) -> Arc<Vec<QueuedFile>> {
    let stamp = spool_stamp(path);
    if let Some(stamp) = stamp
        && let Some((s, rows)) = QUEUED_ROWS.lock_ok().get(path)
        && *s == stamp
    {
        return Arc::clone(rows);
    }
    // Parsed with the cache lock RELEASED: a large NZB takes a while,
    // and the cache is shared by every request thread.
    let rows: Arc<Vec<QueuedFile>> = Arc::new(
        std::fs::read(path)
            .ok()
            .and_then(|b| nzbkit::nzb::Nzb::parse(&b).ok())
            .map(|nzb| {
                nzb.files
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        let kind = f.kind();
                        QueuedFile {
                            row: crate::streamhub::job_file_row(i, f),
                            recovery: !matches!(kind, nzbkit::nzb::FileKind::Data),
                            volume: matches!(kind, nzbkit::nzb::FileKind::Par2Volume),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
    );
    // Cached under the stamp read BEFORE the parse: a write landing
    // mid-parse moves the stamp, so the next call misses and parses the
    // new bytes rather than trusting these.
    if let Some(stamp) = stamp {
        let mut cache = QUEUED_ROWS.lock_ok();
        if cache.len() >= QUEUED_ROWS_CAP {
            cache.clear();
        }
        cache.insert(path.to_path_buf(), (stamp, Arc::clone(&rows)));
    }
    rows
}

/// Whether `path` has a cached parse - for tests that prove a call
/// did NOT parse a spool.
#[cfg(test)]
pub(crate) fn queued_rows_cached(path: &std::path::Path) -> bool {
    QUEUED_ROWS.lock_ok().contains_key(path)
}

/// SAB's own `mb`/`mbleft` formatting, so a client that parses one of
/// our queue slots parses these with the same code.
fn mb(bytes: u64) -> String {
    format!("{:.2}", bytes as f64 / API_MB)
}

/// The keys every row carries whatever its source, so a client's
/// deserializer sees one shape for a queued job and a running one.
///
/// `nzf_id` and `id` are the same value under both of SAB's spellings.
fn base_row(r: &crate::streamhub::JobFileRow) -> serde_json::Map<String, Value> {
    let mut o = serde_json::Map::new();
    o.insert("nzf_id".into(), json!(r.id));
    o.insert("id".into(), json!(r.id));
    o.insert("filename".into(), json!(r.name));
    // A STRING, because that is what SAB puts under this name:
    // `build_file_list` writes `"bytes": "%.2f" % nzf.bytes`, identical
    // in 4.5.0, 5.1.2 and develop (read 30 Aug 2026). It emitted a JSON
    // number here until 31 Aug 2026, which is GH #69's defect one mode
    // over - a statically-typed client deserializing `String` (or
    // Dart's `tryParse`, which takes one) throws at parse time, and the
    // `fullstatus` arm in `api/system.rs` already carries the
    // note about LunaSea doing exactly that. The numeric reading keeps
    // a key of its own beside it, the same way `bytes_left` sits beside
    // SAB's `mbleft`: SAB spellings carry SAB's types, ours carry ours.
    o.insert("bytes".into(), json!(format!("{:.2}", r.bytes as f64)));
    o.insert("bytes_total".into(), json!(r.bytes));
    o.insert("mb".into(), json!(mb(r.bytes)));
    // SAB emits `age` on every file row and we emitted none, which is
    // the other half of the same class - an absent key a client with a
    // non-nullable field dies on. The NZB carries the date; nothing
    // read it.
    o.insert("age".into(), json!(crate::sabcompat::sab_age(r.date)));
    o.insert("segments".into(), json!(r.segments));
    o
}

/// A file of a QUEUED job: the NZB's own facts, and no state claim.
///
/// `status` is SAB's word for "nothing of this has moved yet", which is
/// exactly true of every file of a job that has not started; `state` is
/// ours and says the same thing without borrowing SAB's vocabulary.
///
/// `recovery` is the ONE judgement this side does make, and it is the
/// NZB's rather than ours: a `.par2` that wears a volume suffix is data
/// the job fetches only if repair asks for it, whichever job it is. The
/// row carries it on both sides so a client need not learn two shapes -
/// `state` stays "queued" rather than borrowing the live side's
/// "recovery" word, because nothing about this job has been decided yet
/// and a volume of a job that never starts was never declined.
fn queued_row(r: &crate::streamhub::JobFileRow, recovery: bool) -> Value {
    let mut o = base_row(r);
    o.insert("mbleft".into(), json!(mb(r.bytes)));
    o.insert("bytes_left".into(), json!(r.bytes));
    o.insert("status".into(), json!("queued"));
    o.insert("state".into(), json!("queued"));
    o.insert("recovery".into(), json!(recovery));
    Value::Object(o)
}

/// What is left of one planned file, in the NZB's own byte unit.
///
/// Bytes are the NZB's declaration, so what is left is the same
/// declaration scaled by the segments still owed. Approximate by
/// construction - articles of one file are not exactly equal - and
/// quoted in the same unit as the queue's own denominator. Both
/// dialects' renderers read it here, so they cannot disagree about one
/// file.
pub(crate) fn bytes_left(
    r: &crate::streamhub::JobFileRow,
    s: &crate::streamhub::FileSlotCounts,
) -> u64 {
    if s.total_segments == 0 {
        0
    } else {
        (r.bytes as u128 * s.remaining as u128 / s.total_segments as u128) as u64
    }
}

/// A file of a job that HAS a plan, with the slot counters overlaid.
///
/// A row with no slot is an NZB-classified recovery volume: the plan
/// never queued its articles, and repair fetches them only if it needs
/// them. Reported rather than hidden - a listing that silently omits
/// the recovery set does not describe the post.
///
/// One builder for both the active run and a retired one (TODO 274 e),
/// which is why the counters arrive as a value rather than being read
/// off a slot here: a second renderer for the tail would be a second
/// place for the state words to drift, and the tail's whole point is
/// that they are the SAME words the download reported.
fn live_row(
    r: &crate::streamhub::JobFileRow,
    c: Option<&crate::streamhub::FileSlotCounts>,
    published: &std::collections::HashSet<String>,
) -> Value {
    let mut o = base_row(r);
    let Some(s) = c else {
        o.insert("mbleft".into(), json!(mb(r.bytes)));
        o.insert("bytes_left".into(), json!(r.bytes));
        o.insert("status".into(), json!("queued"));
        o.insert("state".into(), json!("recovery"));
        o.insert("recovery".into(), json!(true));
        return Value::Object(o);
    };
    let (total, remaining, missing) = (s.total_segments, s.remaining, s.missing);
    let (deferred, abandoned, errors) = (s.deferred, s.abandoned, s.errors);
    // Everything accounted for that is neither still owed nor a
    // non-arrival. Saturating rather than trusted: these are five
    // independent atomics and a reader can land between two of them.
    let arrived = total
        .saturating_sub(remaining)
        .saturating_sub(missing)
        .saturating_sub(deferred)
        .saturating_sub(abandoned);
    let left = bytes_left(r, s);
    o.insert("mbleft".into(), json!(mb(left)));
    o.insert("bytes_left".into(), json!(left));
    // SAB's three words, and only those: a client that switches on
    // `status` must never meet a token SAB cannot produce.
    o.insert(
        "status".into(),
        json!(match (remaining, arrived) {
            (0, _) => "finished",
            (_, 0) => "queued",
            _ => "active",
        }),
    );
    // Ours, and the precise one. `deferred` is the word the engine uses
    // for a choice that is not damage - a skipped sample, a volume
    // identified as recovery data in-stream - and it is the distinction
    // SAB has no room for, so it gets its own token here rather than
    // being flattened into "finished".
    let state = if remaining > 0 && arrived > 0 {
        "active"
    } else if remaining > 0 {
        "queued"
    } else if arrived == 0 && deferred > 0 && abandoned == 0 {
        "deferred"
    } else if missing > 0 || abandoned > 0 {
        "damaged"
    } else {
        "complete"
    };
    // §296: this file is not merely finished, it is already AT the
    // destination and usable while the rest of the job downloads - which
    // is the question a user watching a slow pack actually has, and
    // nothing else in this payload could answer it.
    //
    // It only ever refines "complete", never any other word. A published
    // file was PAR2-vouched before the copy was taken so it cannot
    // honestly read as damaged - but the RECORD outlives the verdict:
    // settle can find at read-back what the in-stream check did not, and
    // between that moment and the reconcile the row is both published and
    // damaged. Damage is the sharper fact and keeps the row.
    o.insert(
        "state".into(),
        json!(if state == "complete" && published.contains(&r.id) {
            "published"
        } else {
            state
        }),
    );
    o.insert("segments_remaining".into(), json!(remaining));
    o.insert("segments_missing".into(), json!(missing));
    o.insert("segments_deferred".into(), json!(deferred));
    o.insert("segments_abandoned".into(), json!(abandoned));
    o.insert("decode_errors".into(), json!(errors));
    o.insert("recovery".into(), json!(s.is_par2));
    o.insert("sample_skipped".into(), json!(s.sample_skipped));
    Value::Object(o)
}

/// `mode=get_files&value=<nzo_id>` - SAB's per-file listing.
///
/// Answers `{"files": [...]}` like SAB does, so a client that already
/// parses SAB's reply needs no new code for the fields it knows.
/// History is deliberately out of scope: a finished job has no files
/// left to describe in these terms, and answering from its NZB would
/// hand back progress words for something that is not downloading.
pub(super) fn m_get_files(
    d: &Arc<Daemon>,
    _req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    _ctx: &ApiCtx<'_>,
    _api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    let id = params.get("value").cloned().unwrap_or_default();
    Some(match listing(d, &id) {
        Some(files) => json!({"files": files}),
        // `files` is present and empty either way, so a client that
        // reads only that key never has to special-case the error - and
        // `status: false` beside it is SAB's own error shape
        // (`report(_MSG_NO_VALUE)`), so a client that switches on that
        // key instead is not left reading a null.
        None => json!({"status": false, "files": [], "error": "unknown nzo_id"}),
    })
}

/// `mode=queue&name=promote_file&value=<nzo_id>&value2=<nzf_id>` -
/// "download this file next", to the extent the queue can honour it.
///
/// BEST EFFORT, and the response says so rather than leaving the caller
/// to infer it: `moved` is how many of the file's articles were actually
/// reordered, which is 0 for a file whose articles have all been issued
/// already, and 0 again if the queue mutex was busy for the bounded wait
/// the reorder is willing to take. Nothing in flight is cancelled, and
/// no other file is demoted below where the queue would have reached it.
///
/// Only the ACTIVE job: the daemon downloads one at a time, so there is
/// no pending queue to reorder for anything else. Refused in words
/// instead of silently doing nothing, because "the file did not move" and
/// "there was nothing to move it in" are different answers to the user.
pub(super) fn promote_arm(
    d: &Arc<Daemon>,
    params: &std::collections::HashMap<String, String>,
) -> Value {
    let nzo = params.get("value").cloned().unwrap_or_default();
    let file = params.get("value2").cloned().unwrap_or_default();
    let Some(t) = d.hub.job_files_for(&nzo) else {
        return json!({"status": false, "error": "not the active job"});
    };
    let Some(row) = t.rows.iter().find(|r| r.id == file) else {
        return json!({"status": false, "error": "unknown file id"});
    };
    match t.promote_row(row) {
        // No slot: an NZB-classified recovery volume, whose articles the
        // plan never queued. Repair fetches those if it needs them, and
        // it is the one part of the plan a user asking for payload
        // sooner does not want moved.
        None => json!({"status": false, "error": "file has no queued articles"}),
        Some(moved) => json!({"status": true, "moved": moved, "nzf_id": row.id}),
    }
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod files_tests;
