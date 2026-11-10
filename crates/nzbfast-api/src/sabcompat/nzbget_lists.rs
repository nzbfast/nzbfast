//! TODO 358 item 4: NZBGet's `listfiles`, `postqueue` and
//! `servervolumes`, which this facade answered with `[]` until 9 Nov
//! 2026. Mobile clients (NZB360, LunaSea, NZBClient) call all three,
//! and issue #118 already showed what a strict decoder does with a
//! reply that is short of NZBGet's keys.
//!
//! THE FIELD SETS ARE NZBGET'S OWN, RECORDED, not read off a document:
//! `nzbget_recorded.json` beside this file is the three replies a
//! scratch NZBGet 26.3 gave on 9 Nov 2026 (a local NNTP stub serving
//! real yEnc, one part held open so a file sat half done), and
//! `nzbget_lists_tests.rs` holds every key and every JSON type of ours
//! to it. Two facts came out of that recording that no field list
//! says: `listfiles`' `Progress` is PER-MILLE (500 at one of two
//! articles), and `servervolumes`' element 0 is the ALL-SERVERS total,
//! with the configured servers at 1..N - NZBGet's webui indexes it by
//! `server.id` directly.
//!
//! WHAT IS ZERO, AND WHY. Every number below is one the daemon keeps,
//! or it is zero; none is estimated:
//!
//! - `listfiles`: `ActiveDownloads` is 0 on every row, because the
//!   pool does not count connections per FILE; `FilenameConfirmed` is
//!   false, because the name is the NZB's hint and this layer does not
//!   see the yEnc header that NZBGet confirms it against.
//! - `postqueue`: `FileProgress`, `StageProgress`, `StageTimeSec` and
//!   `TotalTimeSec` are 0, because the tail keeps a phase WORD
//!   (`Daemon::tail_phase`) and no clock or fraction beside it.
//!   `ProgressLabel` is that word.
//! - `servervolumes`: the per-second, per-minute and per-hour arrays
//!   are all zero, at NZBGet's lengths (60/60/24), because the provider
//!   ledger is billed per UTC DAY when a download finishes - so bytes
//!   of the job on the wire right now are in no counter yet either. The
//!   day series is real, from the oldest day the ledger still holds
//!   (it keeps ~60). `CustomSize*` is the lifetime figure and
//!   `CustomTime`/`CountersResetTime` are 0: `resetservervolume` is a
//!   no-op here, so the custom counter has never been reset and we
//!   hold no date it started. NZBGet's slots are local time; these are
//!   UTC, the ledger's own day boundary.

use super::*;

/// The integer file-id namespace: file `i` (0-based, NZB order) of job
/// `NZBID` is `NZBID * FILE_ID_STRIDE + i + 1`.
///
/// This arm used to stay `[]` rather than mint these, on the ground that
/// NZBGet's `editqueue` File* commands take them and this facade
/// implements none (research/PER-FILE-EXCLUSION-DESIGN-2026-09-20.md
/// section 2.4). That still holds and is still the answer to a File*
/// command - `jr_editqueue` refuses it with a JSON-RPC error rather
/// than a silent `false`. What changed is that the listing is wanted
/// for READING (a client's per-file drawer), and that needs no stable
/// queue-wide counter: deriving the id from two things that already
/// are stable - the NZBID and the file's NZB position, which is also
/// what `streamhub::job_file_id` hashes - gives the same id for the
/// same file on every poll and across a restart, with nothing stored.
///
/// The price, stated: a post of more than 9,999 files has ids that run
/// into the next NZBID's range, and the product stays inside a signed
/// 32-bit integer (what a Kotlin or Java client deserializes) only
/// while NZBIDs are below 214,748.
const FILE_ID_STRIDE: i64 = 10_000;

/// The queue facts one `listfiles` row repeats, copied out under the
/// queue lock so the file walk (which takes that lock itself, in
/// `queue_facts`) runs with it released.
struct Group {
    nzo_id: String,
    nzbid: i64,
    name: String,
    nzb_file: String,
    dest: String,
    category: String,
    priority: i32,
    paused: bool,
}

/// `listfiles(IDFrom, IDTo, NZBID)`. NZBGet's own filter: a positive
/// NZBID lists that group alone; otherwise both bounds 0 lists every
/// file and anything else lists the ids in `IDFrom..=IDTo`.
///
/// NZBGet removes a file from its group once it is complete, so a file
/// with nothing left to fetch is not listed - which during a job's tail
/// leaves exactly the recovery volumes repair never asked for, held
/// Paused, as NZBGet holds its own.
///
/// COST: a queued job is answered from its spooled `.nzb`
/// (`files::queued_rows`, parsed once per spool revision and cached),
/// so only the first unfiltered call after a job is added pays its
/// parse. An id range names its groups - the id is `NZBID * 10,000 +
/// position` - so it walks only those (TODO 358 sweep E3); it used to
/// parse every queued job because the range was tested per row. The
/// one id a range cannot place is a file past position 9,999, which
/// [`FILE_ID_STRIDE`] already says runs into the next group's ids.
pub(super) fn jr_listfiles(d: &Arc<Daemon>, params: &[Value]) -> Value {
    let arg = |i: usize| params.get(i).and_then(Value::as_i64).unwrap_or(0);
    let (id_from, id_to, want_nzb) = (arg(0), arg(1), arg(2));
    // The NZBIDs an id range can reach; every group when unfiltered.
    let ranged = want_nzb <= 0 && !(id_from == 0 && id_to == 0);
    let group_of = |id: i64| id.saturating_sub(1).div_euclid(FILE_ID_STRIDE);
    let (lo, hi) = (group_of(id_from), group_of(id_to));
    let groups: Vec<Group> = d
        .queue
        .lock_ok()
        .iter()
        .filter_map(|j| {
            let g = j.lock_ok();
            let nzbid = nzo_int(&g.nzo_id);
            let wanted = if want_nzb > 0 {
                nzbid == want_nzb
            } else {
                !ranged || (lo <= nzbid && nzbid <= hi)
            };
            wanted.then(|| Group {
                nzo_id: g.nzo_id.clone(),
                nzbid,
                name: g.name.clone(),
                nzb_file: g
                    .nzb_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                dest: g.out_dir.to_string_lossy().into_owned(),
                category: g.category.clone(),
                priority: g.priority,
                paused: g.paused,
            })
        })
        .collect();
    let in_range =
        |id: i64| want_nzb > 0 || (id_from == 0 && id_to == 0) || (id_from <= id && id <= id_to);
    let mut out = Vec::new();
    for grp in &groups {
        let mut idx = 0i64;
        let rows = crate::api::queue::files::listing_with(d, &grp.nzo_id, |r, src| {
            idx += 1;
            let id = grp.nzbid * FILE_ID_STRIDE + idx;
            let (left, done, held, owed) = file_state(r, src);
            (owed && in_range(id)).then(|| file_row(grp, r, id, left, done, held))
        });
        out.extend(rows.into_iter().flatten().flatten());
    }
    json!(out)
}

/// One file's (bytes left, bytes in, held paused, still owed anything),
/// the reading both `listfiles` and `listgroups`' counts take, so the
/// group's `RemainingFileCount` is exactly the rows `listfiles` lists.
fn file_state(
    r: &crate::streamhub::JobFileRow,
    src: crate::api::queue::files::FileSrc<'_>,
) -> (u64, u64, bool, bool) {
    use crate::api::queue::files::FileSrc;
    match src {
        FileSrc::Queued { volume, .. } => (r.bytes, 0, volume, true),
        // No slot: a recovery volume the plan never queued.
        FileSrc::Planned { counts: None, .. } => (r.bytes, 0, true, true),
        FileSrc::Planned {
            counts: Some(c), ..
        } => {
            let left = crate::api::queue::files::bytes_left(r, c);
            (left, r.bytes.saturating_sub(left), false, c.remaining > 0)
        }
    }
}

/// `listgroups`' file half for one group: `(FirstID, LastID, FileCount,
/// RemainingFileCount)` in `listfiles`' own id namespace (TODO 358
/// sweep E1). They were `NZBID, NZBID, 0, 0` - so a client paging a
/// group with `listfiles(FirstID, LastID, 0)` got nothing, and a group
/// with two listed files claimed none.
///
/// FirstID..=LastID spans every NZB position, the complete ones too:
/// `listfiles` skips those itself, and the ids are positions, so the
/// span is the same on every poll. An empty or unreadable group is all
/// zeros, NZBGet's own answer for a group with no files.
///
/// COST, per `listgroups` poll: the active job's table is already
/// built and a tail's is frozen, so neither parses; a queued job reads
/// `files::queued_rows`, which parses a spool once per revision. So a
/// steady poll costs a stat per queued job, not a parse.
pub(super) fn group_file_ids(
    d: &Arc<Daemon>,
    nzo_id: &str,
    nzb_path: PathBuf,
) -> (i64, i64, i64, i64) {
    let none = std::collections::HashSet::new();
    let owed = crate::api::queue::files::listing_from(d, nzo_id, &none, Some(nzb_path), |r, s| {
        file_state(r, s).3
    })
    .unwrap_or_default();
    let n = owed.len() as i64;
    if n == 0 {
        return (0, 0, 0, 0);
    }
    let base = nzo_int(nzo_id) * FILE_ID_STRIDE;
    let remaining = owed.iter().filter(|o| **o).count() as i64;
    (base + 1, base + n, n, remaining)
}

/// One `listfiles` row, in NZBGet 26.3's field set.
fn file_row(
    grp: &Group,
    r: &crate::streamhub::JobFileRow,
    id: i64,
    left: u64,
    done: u64,
    held: bool,
) -> Value {
    let (flo, fhi) = lohi(r.bytes);
    let (rlo, rhi) = lohi(left);
    // Per-mille, as NZBGet's own reply measured it (500 with one of two
    // articles in). Widened: `bytes` is an NZB attribute and can be
    // anything a hostile file declares.
    let progress = (u128::from(done.min(r.bytes)) * 1000)
        .checked_div(u128::from(r.bytes))
        .unwrap_or(0) as u64;
    json!({
        "ID": id,
        "FileSizeLo": flo,
        "FileSizeHi": fhi,
        "RemainingSizeLo": rlo,
        "RemainingSizeHi": rhi,
        "PostTime": r.date,
        "FilenameConfirmed": false,
        "Paused": grp.paused || held,
        "NZBID": grp.nzbid,
        "NZBName": grp.name,
        "NZBNicename": grp.name,
        "NZBFilename": grp.nzb_file,
        // `JobFileRow` keeps the poster's filename hint and falls back
        // to the subject only when there is none, so the subject proper
        // is not carried this far. The same label goes in both rather
        // than an empty Subject, which a client would show as a blank.
        "Subject": r.name,
        "Filename": r.name,
        "DestDir": grp.dest,
        "Category": grp.category,
        "Priority": grp.priority * 50,
        "ActiveDownloads": 0,
        "Progress": progress,
    })
}

/// The group `Status` words that mean "in post-processing", which is
/// what puts a row in `postqueue`.
const POST_STATUSES: &[&str] = &["VERIFYING_SOURCES", "REPAIRING", "UNPACKING", "MOVING"];

/// `postqueue(NumberOfLogEntries)`: the queue rows past their network
/// phase, in NZBGet 26.3's field set (its `PostQueueXmlCommand`, which
/// carries the whole per-NZB block `listgroups` does).
///
/// Membership is `nzbget_group_status` and nothing else, so a job is in
/// this list exactly when `listgroups` calls it VERIFYING_SOURCES,
/// REPAIRING, UNPACKING or MOVING - the two replies cannot disagree.
pub(super) fn jr_postqueue(d: &Arc<Daemon>, params: &[Value]) -> Value {
    let want_log = params.first().and_then(Value::as_u64).unwrap_or(0) as usize;
    let mut rows: Vec<(serde_json::Map<String, Value>, u64, u64)> = Vec::new();
    for j in d.queue.lock_ok().iter() {
        let g = j.lock_ok();
        // The same phase test `jr_listgroups` makes, for the same reason.
        let phase = (matches!(g.state, JobState::Downloading | JobState::Finishing)
            && !g.suspended)
            .then(|| d.tail_phase(&g.nzo_id))
            .flatten();
        let stage = nzbget_group_status(phase, false, g.state, g.paused);
        if !POST_STATUSES.contains(&stage) {
            continue;
        }
        let id = nzo_int(&g.nzo_id);
        let mut o = serde_json::Map::new();
        o.extend([
            ("ID".to_string(), json!(id)),
            ("InfoName".to_string(), json!(g.name)),
            ("ParFilename".to_string(), json!("")),
            ("Stage".to_string(), json!(stage)),
            ("FileProgress".to_string(), json!(0)),
            (
                "ProgressLabel".to_string(),
                json!(phase.unwrap_or("Moving")),
            ),
            ("StageProgress".to_string(), json!(0)),
            ("StageTimeSec".to_string(), json!(0)),
            ("TotalTimeSec".to_string(), json!(0)),
        ]);
        for (k, v) in size_fields("File", g.total_bytes) {
            o.insert(k, v);
        }
        nzbinfo_gaps(&mut o, &g);
        rows.push((o, g.log_mark, g.log_end));
    }
    // The log is sliced with every lock released: the ring has a mutex
    // of its own, taken by every line the daemon prints.
    let out: Vec<Value> = rows
        .into_iter()
        .map(|(mut o, mark, end)| {
            o.insert("Log".into(), json!(job_log(d, mark, end, want_log)));
            Value::Object(o)
        })
        .collect();
    json!(out)
}

/// The last `n` captured lines of one job's span, as NZBGet log
/// entries. The span is the job's own `log_mark..log_end` (the slice
/// `mode=report` uses, with its "0 = nothing to slice" sentinel), and
/// it goes out SCRUBBED for the reason the `log` arm gives: this is a
/// door remote apps call over the network.
///
/// `Time` is when the reply was built - the ring keeps text, not a
/// clock - which is what the `log` arm has always sent too.
fn job_log(d: &Arc<Daemon>, mark: u64, end: u64, n: usize) -> Vec<Value> {
    if n == 0 || mark == 0 {
        return Vec::new();
    }
    let to = if end > mark {
        end
    } else {
        nzbkit::logtee::mark()
    };
    let lines =
        crate::logscrub::LogScrub::new(d).tail(nzbkit::logtee::between(mark, to, n.min(1000)));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs())
        .unwrap_or(0);
    log_entries(&lines, now)
}

/// Captured lines as NZBGet log entries. Split out because the ring is
/// process-global and only `logtee::install` fills it, which a unit
/// test must not call - so the shape is tested here, on its own.
pub(super) fn log_entries(lines: &[String], now: u64) -> Vec<Value> {
    lines
        .iter()
        .enumerate()
        .map(|(i, l)| json!({"ID": i as u64 + 1, "Kind": "INFO", "Time": now, "Text": l}))
        .collect()
}

/// A ledger day key `YYYY-MM-DD` as a day number since the epoch, or
/// None for every other bucket name (`lifetime`, `reliability`, ...).
///
/// A year before 2000 is None too (TODO 358 sweep E2): no download was
/// billed then, so such a key is a clock that was wrong when it was
/// written - a board with no RTC boots at 1970 until NTP answers, and
/// `add_usage` billed the epoch's own day when the clock read before
/// it. One such key used to set `FirstDay` and stretch every element
/// of every reply to ~20,000 day cells.
fn ledger_day(key: &str) -> Option<i64> {
    let mut it = key.splitn(3, '-');
    let (y, m, dd) = (it.next()?, it.next()?, it.next()?);
    if y.len() != 4 || m.len() != 2 || dd.len() != 2 {
        return None;
    }
    let (y, m, dd) = (y.parse().ok()?, m.parse().ok()?, dd.parse().ok()?);
    (y >= 2000 && (1..=12).contains(&m) && (1..=31).contains(&dd))
        .then(|| crate::days_from_civil(y, m, dd))
}

/// The longest day series `servervolumes` draws, today included.
///
/// The ledger keeps ~60 day buckets (`add_usage` prunes past that), so
/// a year covers it on any install that downloads at least once a
/// week. A sparser ledger - or a key billed while the clock was set
/// years back - loses its oldest days from THIS reply only, rather than
/// costing every poll a cell per day back to them; the dashboard's
/// usage table still reads the whole ledger.
pub(super) const SERVERVOLUME_DAYS: i64 = 366;

/// One NZBGet size cell, `{SizeLo, SizeHi, SizeMB}`.
fn size_cell(bytes: u64) -> Value {
    Value::Object(size_fields("", bytes))
}

/// `servervolumes()`: element 0 the all-servers total, then one element
/// per configured server in config order (`ServerID` 1..N, NZBGet's
/// `Server<N>` numbering), off the provider ledger. See the module
/// header for which halves are zero.
///
/// The ledger bills per HOST (`Daemon::add_usage` says why), so two
/// configured accounts on one host each report that host's figures,
/// and element 0 - summed over the ledger's hosts, not over this list -
/// counts them once.
pub(super) fn jr_servervolumes(d: &Arc<Daemon>) -> Value {
    let hosts: Vec<String> = crate::current_servers(&d.cfg_path)
        .iter()
        .map(|s| {
            s.get("host")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        })
        .collect();
    // Cloned and released at once: every finishing download takes it.
    let u = d.usage.lock_ok().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    servervolumes_json(&u, &hosts, now)
}

/// The pure half of [`jr_servervolumes`]: the ledger, the configured
/// hosts and the clock in, the reply out.
pub(super) fn servervolumes_json(
    u: &serde_json::Map<String, Value>,
    hosts: &[String],
    now: i64,
) -> Value {
    let today = now.div_euclid(86_400);
    // Per host, per day number: bytes, and (failed, success) articles.
    let mut bytes: std::collections::BTreeMap<(String, i64), u64> = Default::default();
    let mut arts: std::collections::BTreeMap<(String, i64), (u64, u64)> = Default::default();
    let mut first = today;
    for (key, per_host) in u {
        let (Some(day), Some(per_host)) = (ledger_day(key), per_host.as_object()) else {
            continue;
        };
        for (host, b) in per_host {
            *bytes.entry((host.clone(), day)).or_default() += b.as_u64().unwrap_or(0);
            first = first.min(day);
        }
    }
    if let Some(by_host) = u.get("article_days").and_then(Value::as_object) {
        for (host, days) in by_host {
            for (key, c) in days.as_object().into_iter().flatten() {
                let Some(day) = ledger_day(key) else {
                    continue;
                };
                let g = |k| c.get(k).and_then(Value::as_u64).unwrap_or(0);
                let (tried, missing) = (g("tried"), g("missing"));
                let e = arts.entry((host.clone(), day)).or_default();
                e.0 += missing;
                e.1 += tried.saturating_sub(missing);
                first = first.min(day);
            }
        }
    }
    // Bounded at read, whatever the ledger holds: see SERVERVOLUME_DAYS.
    let first = first.max(today - (SERVERVOLUME_DAYS - 1));
    let lifetime = |host: Option<&str>| -> u64 {
        let Some(m) = u.get("lifetime").and_then(Value::as_object) else {
            return 0;
        };
        match host {
            Some(h) => m.get(h).and_then(Value::as_u64).unwrap_or(0),
            None => m.values().filter_map(Value::as_u64).sum(),
        }
    };
    let secs = now.rem_euclid(86_400);
    let entry = |server_id: usize, host: Option<&str>| -> Value {
        let mine = |h: &str| host.is_none_or(|want| want == h);
        let per_day: Vec<Value> = (first..=today)
            .map(|day| {
                size_cell(
                    bytes
                        .iter()
                        .filter(|((h, dd), _)| *dd == day && mine(h))
                        .map(|(_, b)| *b)
                        .sum(),
                )
            })
            .collect();
        let per_day_arts: Vec<Value> = (first..=today)
            .map(|day| {
                let (f, s) = arts
                    .iter()
                    .filter(|((h, dd), _)| *dd == day && mine(h))
                    .fold((0, 0), |a, (_, c)| (a.0 + c.0, a.1 + c.1));
                json!({"Failed": f, "Success": s})
            })
            .collect();
        let total = lifetime(host);
        let mut o = serde_json::Map::new();
        o.insert("ServerID".into(), json!(server_id));
        o.insert("DataTime".into(), json!(now));
        o.insert("FirstDay".into(), json!(first));
        o.extend(size_fields("Total", total));
        o.extend(size_fields("Custom", total));
        o.insert("CustomTime".into(), json!(0));
        o.insert("CountersResetTime".into(), json!(0));
        o.insert("SecSlot".into(), json!(secs % 60));
        o.insert("MinSlot".into(), json!(secs / 60 % 60));
        o.insert("HourSlot".into(), json!(secs / 3600));
        o.insert("DaySlot".into(), json!(today - first));
        o.insert("BytesPerSeconds".into(), json!(vec![size_cell(0); 60]));
        o.insert("BytesPerMinutes".into(), json!(vec![size_cell(0); 60]));
        o.insert("BytesPerHours".into(), json!(vec![size_cell(0); 24]));
        o.insert("BytesPerDays".into(), json!(per_day));
        o.insert("ArticlesPerDays".into(), json!(per_day_arts));
        Value::Object(o)
    };
    let mut out = vec![entry(0, None)];
    out.extend(hosts.iter().enumerate().map(|(i, h)| entry(i + 1, Some(h))));
    json!(out)
}
