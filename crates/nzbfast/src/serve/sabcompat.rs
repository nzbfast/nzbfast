use super::*;

/// Test seam: the JSON-RPC delete arm trips it once its rows have left
/// the queue and before their durable replacements are written - the
/// window a save landing in the middle publishes absence from. First
/// barrier says the window is open, second says the test has staged its
/// save and releases it. Same two-stage shape as
/// `daemon_park::PARK_GEN_BARRIER`, and keyed the same way - by the
/// owning daemon's spool path - so a delete verb belonging to some
/// other test can never wander into a two-party barrier that is not its
/// own. Unkeyed, a stranger is a third waiter and the parallel bin run
/// hangs instead of failing.
#[cfg(test)]
pub(in crate::serve) static DELETE_PREWRITE_BARRIER: Mutex<
    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = Mutex::new(None);

/// Version we report to API clients. The *arrs feature-gate on the SAB
/// version string, so claim parity with the release whose API we match.
pub(super) const SAB_VERSION: &str = "4.5.0";

/// Minutes until a timed pause auto-resumes (SAB's `pause_int`).
pub(super) fn pause_int(d: &Daemon) -> String {
    d.pause_until
        .lock_ok()
        .map(|t| {
            t.saturating_duration_since(Instant::now())
                .as_secs()
                .div_ceil(60)
        })
        .unwrap_or(0)
        .to_string()
}

/// The conditions worth interrupting someone about, in SAB's warning
/// shape (a client renders these verbatim).
///
/// `mode=warnings` was a permanent empty list, so the states a user most
/// needs to see were invisible in every remote app: nothing downloads
/// and nothing says why. Each entry here is a condition that is
/// currently true and currently stopping or degrading work - not a log
/// tail, and not history. Nothing that resolves itself is listed, or the
/// pane becomes noise nobody reads.
/// `hide_job_names`: the caller holds the ADD-ONLY key. The tier is
/// documented as giving "paused/warning/disk numbers" while queue
/// contents stay full-key, and the password-waiting warnings name up
/// to five queued releases - so they are counted but not named.
///
/// `free`: bytes free on the output disk, passed in rather than read
/// here. §91 - `mode=status` reports that number as `diskspace1` in the
/// same body as these warnings, and a second statvfs of its own could
/// put "Queue held: 1.2 GB free is below the 5.0 GB minimum" beside a
/// `diskspace1` saying there is plenty. One reading, one answer.
pub(super) fn sab_warnings(
    d: &Daemon,
    cfg_path: &std::path::Path,
    hide_job_names: bool,
    free: Option<u64>,
) -> Vec<Value> {
    let mut out: Vec<String> = Vec::new();

    // Nothing can download at all. This is the first-run state, and the
    // one most likely to be met by someone who has just wired up Sonarr.
    // An unreadable config counts the same as an empty one here: either
    // way there is nothing to download from.
    let servers = nzbkit::config::Config::load(cfg_path)
        .map(|c| c.servers.len())
        .unwrap_or(0);
    if servers == 0 {
        out.push("No Usenet server is configured - add one in Settings before downloading".into());
    }

    // The queue is held by the low-disk guard: it re-checks every five
    // seconds and will not start anything until there is room.
    let min = d.min_free.load(Ordering::Relaxed);
    if min > 0
        && let Some(free) = free
        && free < min
    {
        out.push(format!(
            "Queue held: {:.1} GB free is below the {:.1} GB minimum",
            free as f64 / 1e9,
            min as f64 / 1e9
        ));
    }

    // Jobs that have stopped and will not move without the user. A
    // password prompt is invisible to an *arr, which just sees a job
    // that never finishes.
    let waiting: Vec<String> = d
        .queue
        .lock_ok()
        .iter()
        .filter_map(|j| {
            let g = j.lock_ok();
            g.password_required.then(|| g.name.clone())
        })
        .collect();
    if hide_job_names {
        if !waiting.is_empty() {
            out.push(format!(
                "{} download(s) need a password to unpack",
                waiting.len()
            ));
        }
    } else {
        for name in waiting.iter().take(5) {
            out.push(format!("{name} needs a password to unpack"));
        }
    }
    if !hide_job_names && waiting.len() > 5 {
        out.push(format!(
            "...and {} more waiting for a password",
            waiting.len() - 5
        ));
    }

    out.into_iter()
        .map(|text| json!({"type": "WARNING", "text": text, "time": epoch_secs()}))
        .collect()
}

/// Escape for XML - and DROP what XML 1.0 cannot carry at all.
///
/// A C0 control byte reaching an attribute or element makes the whole
/// document not well-formed, so one hostile or merely malformed article
/// poisons every search that pages over its row: the `poster` field is
/// the raw OVER `From:` header, kept verbatim, and the API facades are
/// uncurated by design so no junk filter drops it. Escaping is not an
/// option - `&#1;` is equally illegal and expat/libxml2 reject it - and
/// emitting one would break nzbfast's own quick-xml reader, which
/// hard-errors on InvalidCharRef. Dropping is the only representable
/// answer. `char` already excludes surrogates, so the XML 1.0 `Char`
/// production reduces to: keep tab/LF/CR, drop the rest below U+0020,
/// drop the two permanently-unassigned noncharacters.
#[cfg(feature = "indexer")]
pub(super) fn esc_xml(s: &str) -> String {
    let clean: String = s.chars().filter(|&c| xml_char_ok(c)).collect();
    clean
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Is `c` representable in an XML 1.0 document at all? See [`esc_xml`].
#[cfg(feature = "indexer")]
pub(super) fn xml_char_ok(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{FFFE}' && c != '\u{FFFF}')
}

/// The four index kinds as newznab top-level category ids. The standard
/// tree is 1000 Console, 2000 Movies, 3000 Audio, 4000 PC, 5000 TV,
/// 6000 XXX, 7000 Books, 8000 Other - so software belongs under PC, and
/// Other is 8000, never 7000 (Prowlarr remaps/misfiles anything declared
/// under Books). A custom category has no id of its own and rides Other,
/// as `docs/DESIGN-user-categories.md` decided.
pub(super) fn cat_for_kind(kind: &str) -> Option<u32> {
    match kind {
        "movie" => Some(2000),
        "tv" => Some(5000),
        "software" => Some(4000),
        "other" => Some(8000),
        _ => None,
    }
}

/// Newznab top-level id → index kind, the inverse of [`cat_for_kind`].
/// Subcategories share their parent's thousand (5030 TV/SD → tv, 4050
/// PC/Games → software). The ids we carry no kind for (console, audio,
/// xxx, books) return None rather than being remapped to `other`: a
/// remap answered an audio search with obfuscated junk.
#[cfg(feature = "indexer")]
pub(super) fn kind_for_cat(cat: u32) -> Option<&'static str> {
    match cat / 1000 {
        2 => Some("movie"),
        4 => Some("software"),
        5 => Some("tv"),
        8 => Some("other"),
        _ => None,
    }
}

/// Newznab category for a result row. The stored classification decides
/// (so the id we report is the same one `cat=` filtered on); rows the
/// backfill has not reached carry no kind, and fall back to the stem:
/// episode marker → TV, year marker → Movies, else Other. Reuses the
/// M14f parser.
#[cfg(feature = "indexer")]
pub(super) fn newznab_category(kind: &str, stem: &str) -> u32 {
    if let Some(cat) = cat_for_kind(kind) {
        return cat;
    }
    // A custom category: labelled Other, though `cat=8000` (which
    // filters on kind='other' in SQL) will not select it.
    if !kind.is_empty() {
        return 8000;
    }
    match dupe_key(stem) {
        Some(k) if k.rsplit('/').next().is_some_and(|m| m.starts_with('s')) => 5000,
        Some(_) => 2000,
        None => 8000,
    }
}

/// Scheme + authority to build client-facing links from.
///
/// Behind a reverse proxy the `Host` header names the proxy and the TLS
/// was terminated there, so a plain `http://{Host}` link is mixed
/// content that Prowlarr and Sonarr refuse to fetch - the one thing an
/// HTTPS deployment cannot work around from its side. `X-Forwarded-Host`
/// wins over `Host`, `X-Forwarded-Proto` picks the scheme, and each is
/// a comma list when the request crossed more than one hop, of which the
/// first entry is the client-facing one. An unrecognised scheme falls
/// back rather than being echoed into a URL.
///
/// Not indexer-gated: playback/stream capability URLs (mobile contract,
/// m3u handoffs) need the same client-facing authority in every build,
/// or a TLS reverse proxy gets loopback links and permanent tokens ride
/// cleartext http.
///
/// Without `X-Forwarded-Proto` the fallback is what THIS listener bound
/// with ([`Daemon::scheme`]), not a hardcoded `http`. A direct native-TLS
/// request has no proxy to correct the scheme for it, so the old default
/// handed Prowlarr, Sonarr and every player an `http://` link to a socket
/// that only speaks TLS.
pub(super) fn public_base(req: &tiny_http::Request, d: &Daemon) -> String {
    let hdr = |name: &'static str| {
        req.headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().to_string())
    };
    public_base_from(
        hdr("X-Forwarded-Host"),
        hdr("Host"),
        hdr("X-Forwarded-Proto"),
        d.scheme(),
        d.port,
    )
}

/// The header arithmetic behind [`public_base`], split off the request so
/// it is testable without a socket - a native-TLS listener is otherwise
/// only reachable through a whole daemon with a certificate on disk.
fn public_base_from(
    xf_host: Option<String>,
    host: Option<String>,
    xf_proto: Option<String>,
    own_scheme: &str,
    port: u16,
) -> String {
    let first = |v: String| v.split(',').next().unwrap_or("").trim().to_string();
    let host = xf_host
        .map(first)
        .filter(|h| !h.is_empty())
        .or(host)
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| format!("127.0.0.1:{port}"));
    let scheme = xf_proto
        .map(first)
        .filter(|s| s == "http" || s == "https")
        .unwrap_or_else(|| own_scheme.to_string());
    format!("{scheme}://{host}")
}

#[cfg(test)]
#[path = "sabcompat_public_base_tests.rs"]
mod public_base_tests;

#[cfg(feature = "indexer")]
mod newznab;
#[cfg(feature = "indexer")]
pub(super) use newznab::newznab_xml;

/// A newznab error body. The spec puts these on HTTP 200 with the code
/// in the payload, which is what every client parses.
#[cfg(feature = "indexer")]
pub(super) fn newznab_error(code: u32, desc: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<error code=\"{code}\" description=\"{}\"/>",
        esc_xml(desc)
    )
}

/// RFC 2822-ish date from a unix timestamp (what RSS pubDate wants).
#[cfg(feature = "indexer")]
pub(super) fn httpdate(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, day) = civil_from_days(days);
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        WD[days.rem_euclid(7) as usize],
        day,
        MO[(m - 1) as usize],
        y,
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// SAB accepts the priority as a number OR a word - the *arrs send
/// numbers, but nzb360-class clients send the token. An unknown string
/// used to fall through to the -100 "not given" sentinel and silently
/// become Normal.
pub(super) fn parse_priority_token(v: &str) -> Option<i32> {
    if let Ok(n) = v.parse() {
        return Some(n);
    }
    match v.to_ascii_lowercase().as_str() {
        "force" => Some(2),
        "high" => Some(1),
        "normal" => Some(0),
        "low" => Some(-1),
        "paused" => Some(-2),
        _ => None,
    }
}

pub(super) fn param_priority(params: &std::collections::HashMap<String, String>) -> i32 {
    params
        .get("priority")
        .and_then(|v| parse_priority_token(v))
        .unwrap_or(-100)
}

/// SABnzbd's `timeleft`, in the shape its own API emits.
///
/// Sonarr deserialises this field straight into a .NET `TimeSpan`, whose
/// `hh:mm:ss` form rejects an hours component above 23. We used to emit
/// `s / 3600` unbounded, so a slow enough job produced "27:46:12" and
/// Sonarr failed to parse the WHOLE `mode=queue` response - reporting
/// "Unable to retrieve queue and history items from SABnzbd" and losing
/// track of every download, not just the slow one, for as long as the
/// ETA stayed over a day. Past 24h SAB switches to a leading days field,
/// which `TimeSpan` reads as `d:hh:mm:ss`.
pub(super) fn sab_timeleft(secs: f64) -> String {
    let s = if secs.is_finite() && secs > 0.0 {
        secs as u64
    } else {
        0
    };
    let (d, h, m, sec) = (s / 86_400, s / 3600 % 24, s / 60 % 60, s % 60);
    if d > 0 {
        format!("{d}:{h:02}:{m:02}:{sec:02}")
    } else {
        format!("{h}:{m:02}:{sec:02}")
    }
}

/// SAB's `to_units`: binary steps with a one-letter unit ("998 ",
/// "417 K", "1.2 M"). NZB Unity parses `queue.speed` with
/// `/([\d.]+)\s+(\w+)/` and multiplies by the unit letter, so the
/// bare-KB-with-a-trailing-space format this used to send always read
/// as 0 B/s there.
pub(super) fn sab_units(n: f64) -> String {
    const K: f64 = 1024.0;
    if n < K {
        format!("{n:.0} ")
    } else if n < K * K {
        format!("{:.0} K", n / K)
    } else if n < K * K * K {
        format!("{:.1} M", n / (K * K))
    } else {
        format!("{:.1} G", n / (K * K * K))
    }
}

/// SAB's `script` field: the script that will ACTUALLY run for this job,
/// by basename, or `"None"`.
///
/// The facade used to report `script_override` alone, so a job running
/// its category's script - or the global one - was published to every
/// SAB client as having no script at all, and a client's "which jobs run
/// my script" view answered wrongly for the whole ordinary case (L4,
/// 10 Aug sweep). The ladder is `resolve_scripts`'s: an explicit "none"
/// suppresses everything, an override wins, then the category, then the
/// global script. Basename because that is SAB's vocabulary - the same
/// name `mode=get_scripts` lists and an add's `script=` sends back - and
/// `script_override` may hold the resolved absolute path.
pub(super) fn sab_script_name(
    over: &str,
    cat_script: &str,
    global: &[std::path::PathBuf],
) -> String {
    let base = |s: &str| -> String {
        std::path::Path::new(s)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| s.to_string())
    };
    if over.eq_ignore_ascii_case("none") {
        return "None".into();
    }
    // §192: every rung may be a CHAIN, and the name a client shows for
    // the job has to be the whole of what will run - a client that
    // renders only the first link tells the user the wrong thing about
    // the other two.
    let chain = |s: &str| -> String {
        super::nzbget_script::script_chain(s)
            .iter()
            .map(|p| base(&p.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(",")
    };
    if !over.is_empty() {
        return chain(over);
    }
    if !cat_script.is_empty() {
        return chain(cat_script);
    }
    if global.is_empty() {
        return "None".into();
    }
    global
        .iter()
        .map(|p| base(&p.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(",")
}

/// The active download's counters as `(decoded, declared total, left)`,
/// taken under the ONE lock their writer sets all of them in (tasks.rs,
/// "Claim the shared progress counters for THIS job").
///
/// §91: bare loads straddle that lock section, so a reader can pair the
/// finishing job's `progress` with the next job's freshly stored
/// `active_total`. That is the pipeline card's download lane reading
/// "40.0 / 2.0 GB" - the bar clamps at 100%, which is exactly why the
/// wrong pair went unnoticed, but the note beside it does not - and an
/// NZBGet `Remaining` that saturates to zero next to a `Downloaded` for
/// a job that had only just started.
///
/// `left` prefers the published fetch plan (UX §15): declared bytes
/// against declared bytes, so the fraction reaches exactly 100% at
/// net-drain. The subtraction is the fallback. Unlike `queue_json`'s
/// `active_left` this asks no question about ownership - the callers
/// here report the daemon's active download as a whole, not one row.
pub(super) fn active_counters(d: &Daemon) -> (u64, u64, u64) {
    let _owner = d.active_dl.lock_ok();
    let done = d.progress.load(Ordering::Relaxed);
    let total = d.active_total.load(Ordering::Relaxed);
    let left = d
        .hub
        .fetch_left()
        .map(|(_, _, left)| left)
        .unwrap_or_else(|| total.saturating_sub(done));
    (done, total, left)
}

/// What one queue row reports as `(percentage, bytes left)`.
///
/// Pulled out of the queue walk because it is the rule the whole bundle
/// turns on, and because getting it wrong is invisible until two jobs
/// are live at once. The daemon has ONE pair of network progress
/// counters, but up to two jobs are `Downloading` at any moment - the
/// scheduler deliberately starts the next download while the previous
/// job's disk tail runs, and the record has no state for that tail. So
/// this decides, per row, which of four different things "progress"
/// means:
///
/// - `live` is Some only for the slot that OWNS the counters (see
///   `Daemon::active_dl`), and only that slot may read them. Every
///   `Downloading` slot used to, so a finishing job drew the NEW
///   download's bar: it fell from ~98% to 0 and climbed again.
/// - `tail` (the pipeline is verifying / repairing / unpacking) wins
///   even over ownership: a job holds the counters for the moment
///   between draining the line and the scheduler picking the next job,
///   and its verify pass must not report "97%, 40 MB left" at 0 MB/s.
/// - a `Downloading` slot that is neither has flipped state but not yet
///   claimed the counters (the index-pause gate can hold that gap open
///   for a while). It has fetched nothing, and that is what it says.
/// - anything else reports from the record: for a paused or re-queued
///   job that is what the journal is holding, and 0-with-everything-left
///   is what has users deleting a job that would resume in seconds.
fn slot_progress(
    state: JobState,
    live: Option<(u64, u64)>,
    tail: bool,
    total_bytes: u64,
    downloaded_bytes: u64,
) -> (u64, u64) {
    // Widened, because neither operand is trustworthy: `total_bytes` is
    // summed from an NZB attribute (the parser saturates it rather than
    // wrapping, so a hostile file really can present u64::MAX) and
    // `downloaded_bytes` is whatever a previous run recorded. `x * 100`
    // in u64 overflows well before that. An empty NZB divides by zero.
    let pct_of = |done: u64, total: u64| {
        (u128::from(done.min(total)) * 100)
            .checked_div(u128::from(total))
            .unwrap_or(0)
            .min(100) as u64
    };
    match live.filter(|_| !tail) {
        Some((done, total)) => (pct_of(done, total), total.saturating_sub(done)),
        // The bytes are all in; what is left is the local tail (verify,
        // repair, unpack, unlock, rename, and the move to the
        // destination). Reporting 0% with everything still to fetch made
        // a finished download look like it had gone backwards.
        // `Finishing` (§129) is that tail as a state of its own.
        None if tail || matches!(state, JobState::Completed | JobState::Finishing) => (100, 0),
        None if state == JobState::Downloading => (0, total_bytes),
        // Decoded bytes against an encoded total, so this reads a few
        // percent shy of the truth (audit #15). A floor, never an
        // overstatement.
        None => (
            pct_of(downloaded_bytes, total_bytes),
            total_bytes.saturating_sub(downloaded_bytes.min(total_bytes)),
        ),
    }
}

/// The scheduler-hold banner facts. `a`/`b` shipped first and stay,
/// because the dashboard reads them - but a caller cannot tell which is
/// which, and the pair means different things per reason: name them.
/// Both numbers are gigabytes, except the §129 postproc backpressure
/// pair, which is a count and its bound.
fn hold_json(k: &str, a: f64, b: f64) -> Value {
    let mut o = serde_json::Map::new();
    o.insert("kind".into(), json!(k));
    o.insert("reason".into(), json!(k));
    o.insert("a".into(), json!(a));
    o.insert("b".into(), json!(b));
    match k {
        "disk" => {
            o.insert("free_gb".into(), json!(a));
            o.insert("min_free_gb".into(), json!(b));
        }
        "postproc" => {
            o.insert("finishing".into(), json!(a));
            o.insert("bound".into(), json!(b));
        }
        // TODO §154: the only hold with no numbers behind it - there is
        // no threshold to report, just the absence of a server. `a`/`b`
        // stay in the object (both zero) because the shape is the
        // contract; nothing else is added, and in particular NOT the
        // quota pair the fallthrough arm below would have named them.
        "noservers" => {}
        _ => {
            o.insert("spent_gb".into(), json!(a));
            o.insert("cap_gb".into(), json!(b));
        }
    }
    Value::Object(o)
}

/// Unix seconds when downloading is expected to resume by itself.
/// Null unless something has actually promised a time: a timed pause
/// (its own deadline, to the second - `pause_int` rounds up to whole
/// minutes and would say "1m left" for four seconds) or a schedule
/// with a Resume entry ahead of it.
fn resume_at(d: &Daemon, paused_now: bool, pause_source: &str) -> Option<i64> {
    if !paused_now {
        None
    } else if let Some(left) = d
        .pause_until
        .lock_ok()
        .map(|t| t.saturating_duration_since(Instant::now()).as_secs().max(1))
    {
        Some(job::unix_now() + left as i64)
    } else if pause_source == "schedule" {
        let entries = d.schedule.lock_ok().clone();
        next_resume_in(&entries, local_minute_of_week())
            .map(|mins| job::unix_now() + i64::from(mins) * 60)
    } else {
        None
    }
}

/// Watch-folder rejects: shown in the Queue card with a Delete button
/// (mode=watch_failed_delete). Sorted for a stable render. Built
/// outside json! - the macro can't parse a typed let binding.
fn watch_failed_json(d: &Daemon) -> Vec<Value> {
    let wf = d.watch_failed.lock_ok();
    let mut v: Vec<_> = wf
        .iter()
        .map(|(p, (_, _, err, id))| {
            (
                p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                err.clone(),
                id.clone(),
                // What Delete addresses. Two watch folders can hold
                // rejected files of the same NAME, and the basename
                // then names neither of them (Codex sweep 2,
                // 3 Aug L1).
                crate::serve::tasks::watch_fail_id(p),
            )
        })
        .collect();
    v.sort();
    v.into_iter()
        .map(|(name, error, nzo_id, wf_id)| {
            // The strip used to render one sentence for all six of
            // these, four of which are successes with an unfinished
            // file beside them. `kind` is the token it switches on
            // and `ingested` is the half that decides whether Delete
            // is safe here - both derived by the classifier that
            // lives beside the strings that produced them.
            let kind = crate::serve::tasks::watch_fail_kind(&error);
            json!({"name": name, "error": error, "kind": kind,
                   "ingested": crate::serve::tasks::watch_fail_ingested(kind),
                   // The queue or history record that made this file
                   // redundant, for the states that have one.
                   "nzo_id": nzo_id,
                   // The handle Delete sends back.
                   "id": wf_id})
        })
        .collect()
}

/// The queue payload's notice rings, built outside the `json!` literal.
///
/// Two lists that share one job - telling the user about something that
/// happened while nobody was looking - and one shape: a ring the dashboard
/// drains. Split out of `queue_json` for the size gate (TODO 106); they
/// touch nothing else in that function, which is why they are the cut.
///
/// Not one of them is toast-once any more. Each describes a STATE the
/// user can still act on, so the page keeps it on screen until they do:
/// files still sitting in the watch folder, a deleted record's folder
/// still on disk, history rows that kept their original labels.
///
/// §129 1b(b) emptied this struct of the other sort: a moment that is
/// OVER belongs on the sequence-cursored event ring (`life_emit`), not in
/// a bounded array the client has to diff against a seen-set of its own.
/// `giveup_tripped` went first, then `watch_picked`, `auto_retried` and
/// `watch_upgraded`.
struct QueueNotices {
    watch_failed: Vec<Value>,
    delete_kept: Vec<Value>,
    hist_upgraded: Value,
}

fn queue_notices(d: &Daemon) -> QueueNotices {
    let watch_failed = watch_failed_json(d);
    // Deletes that removed the record but not the files. NOT a
    // toast-once ring like the four above: those narrate a moment that
    // is over, this one describes a folder that is still there, so the
    // page keeps it until the user dismisses it
    // (mode=delete_kept_dismiss).
    let delete_kept: Vec<Value> = d
        .delete_kept
        .lock_ok()
        .iter()
        .map(|n| {
            // `retry` rather than the path itself: what the page needs
            // to know is whether the button can be offered at all, and
            // a spool path is not a thing to put in front of a person.
            json!({"name": n.name, "path": n.path, "why": n.why, "at": n.at,
                   "retry": !n.nzb.is_empty()})
        })
        .collect();
    // §188: the one-time strip after a history re-derivation. Same
    // "kept until dismissed" contract as delete_kept above and for a
    // related reason - it reports a state the user can still act on
    // (rows that kept their original labels), not a moment that passed.
    // Null when there is nothing owed, which is every run but the first
    // after an upgrade that changed something.
    let hist_upgraded = d
        .hist_notice()
        .map(|n| json!({"corrected": n.corrected, "kept": n.kept, "at": n.at}))
        .unwrap_or(Value::Null);
    QueueNotices {
        watch_failed,
        delete_kept,
        hist_upgraded,
    }
}

/// The once-per-payload snapshot every queue row is built against.
///
/// A struct rather than a dozen arguments, and read ONCE for the whole
/// body rather than per row: that is the §91 contract these fields carry.
/// Pairing one row with a fresh read of any of them is the bug that shipped
/// the finishing job's ~98% bar onto the next job's row. Handing every row
/// the same values makes "one instant" true by construction, because
/// nothing downstream is able to re-read.
struct SlotCtx {
    /// The running job's live archive shape (owner, tag), straight off its
    /// extractor; the latched `archive_shape` answers for every other row.
    live_shape: Option<(String, String)>,
    /// The owner tag of a download blocked on a password right now.
    pw_wanted: Option<String>,
    /// §77: whether the health sink is switched on at all.
    health_defer: bool,
    /// Free bytes on the output disk, for the per-row unpack-space check.
    free_now: Option<u64>,
    /// Wall-clock seconds, for deriving each row's absolute `time_added`
    /// from its monotonic `queued_at` (issue #34).
    now_unix: u64,
    /// Live speed over the ~5 s rolling window, for `timeleft`.
    speed_bps: f64,
    /// Prefetch sidecar state (owner, bytes), matched per row.
    sc: Option<(String, u64)>,
    /// The pipeline's own activity token per job, plus the three reads the
    /// fetching refinement needs: the hub owner, an open stall episode, and
    /// the per-server pool view.
    activity_map: std::collections::HashMap<String, &'static str>,
    /// TODO 205: the disk-unpack ladder's live counters per job, so a
    /// row that says "unpacking" can say how much of it is left.
    unpack_map: std::collections::HashMap<String, Arc<crate::unpackprog::UnpackProgress>>,
    active_id: Option<String>,
    stall: Option<(String, Instant)>,
    pool_view: Vec<(String, usize, u64)>,
    /// Servers granting no sessions right now, longest outage first.
    /// Read here so a stalled row can say WHICH provider it is waiting
    /// on instead of only how long it has been waiting.
    outages: Vec<ServerOutage>,
    /// The post-processing script ladder as `(category -> script,
    /// global script)`, snapshotted here for the same reason everything
    /// else is: the row reports which script it will run (L4) and must
    /// not reach back into the daemon under the queue lock to find out.
    cat_scripts: std::collections::HashMap<String, String>,
    global_script: Vec<PathBuf>,
}

/// One SABnzbd queue slot, built from the row's own state and the payload
/// snapshot beside it.
///
/// Split out of `queue_json` for the size gate (TODO 106): the row is a
/// self-contained subject - it reads no daemon state of its own, only the
/// `SlotCtx` its caller took once before the queue lock and the numbers
/// that caller already derived under this slot's lock. Everything that has
/// to be one instant stays one instant, because nothing here can re-read.
fn slot_json(
    ctx: &SlotCtx,
    i: usize,
    j: &Job,
    phase: Option<&'static str>,
    live: bool,
    pct: u64,
    left: u64,
) -> Value {
    let SlotCtx {
        live_shape,
        pw_wanted,
        health_defer,
        free_now,
        now_unix,
        speed_bps,
        sc,
        activity_map,
        unpack_map,
        active_id,
        stall,
        pool_view,
        outages,
        cat_scripts,
        global_script,
    } = ctx;
    let mbleft = left as f64 / API_MB;
    // Only a job actually on the wire has a rate to divide by.
    let timeleft = if live && phase.is_none() && *speed_bps > 1.0 {
        sab_timeleft(left as f64 / *speed_bps)
    } else {
        "0:00:00".to_string()
    };
    // Live shape for the job that is actually downloading; the
    // latched one otherwise (a queued job that already ran once,
    // or a paused one).
    let shape = live_shape
        .as_ref()
        .filter(|(owner, _)| *owner == j.nzo_id)
        .map(|(_, tag)| tag.clone())
        .unwrap_or_else(|| j.archive_shape.clone());
    // "What is happening right now" for this row: a token the
    // dashboard maps to an i18n phrase, an optional server-name
    // detail (language-neutral by construction), and for an open
    // stall episode the seconds since bytes last moved.
    let (activity, activity_detail, activity_secs) = match j.state {
        // The whole post-network tail: repair hand-off, unlock,
        // rename, the move to the destination.
        JobState::Completed => ("finalizing", String::new(), None),
        // §129: the activity map still carries the REAL stage.
        JobState::Finishing => (
            activity_map.get(&j.nzo_id).copied().unwrap_or("finalizing"),
            String::new(),
            None,
        ),
        JobState::Downloading if !j.suspended => {
            let tok = activity_map.get(&j.nzo_id).copied().unwrap_or("fetching");
            if tok == "fetching" && active_id.as_deref() == Some(j.nzo_id.as_str()) {
                let connected: usize = pool_view.iter().map(|(_, c, _)| *c).sum();
                let bytes: u64 = pool_view.iter().map(|(_, _, b)| *b).sum();
                let joined = |v: &[&str]| match v.len() {
                    0 => String::new(),
                    1 => v[0].to_string(),
                    n => format!("{} +{}", v[0], n - 1),
                };
                // A provider that has been granting NO sessions for the
                // whole window outranks "no data for Ns": both describe
                // the same flatline, but only this one says whose it is
                // and what to do about it. Gated on the stall episode
                // deliberately - a dead BACKUP while the job downloads
                // fine at full speed is a fact for the Providers card,
                // not an alarm on a row that is working. (Soak, 12 Aug
                // 2026: two jobs sat 25 minutes at zero bytes behind a
                // capped Giganews account and the row said nothing but
                // "no data for Ns" the whole time.)
                let stalled = stall.as_ref().filter(|(sid, _)| *sid == j.nzo_id);
                if let Some((tok, o)) = row_outage(stalled.is_some(), outages) {
                    (tok, o.host.clone(), Some(o.secs))
                } else if let Some((_, since)) = stalled {
                    ("waiting", String::new(), Some(since.elapsed().as_secs()))
                } else if !pool_view.is_empty() && connected == 0 {
                    let all: Vec<&str> = pool_view.iter().map(|(h, _, _)| h.as_str()).collect();
                    // Bytes already moved means the connections
                    // dropped mid-run; none yet means first dial.
                    let tok = if bytes > 0 {
                        "reconnecting"
                    } else {
                        "connecting"
                    };
                    (tok, joined(&all), None)
                } else {
                    let up: Vec<&str> = pool_view
                        .iter()
                        .filter(|(_, c, _)| *c > 0)
                        .map(|(h, _, _)| h.as_str())
                        .collect();
                    ("fetching", joined(&up), None)
                }
            } else {
                (tok, String::new(), None)
            }
        }
        _ => ("", String::new(), None),
    };
    // Unpack-space preflight: a shape whose volumes land on disk
    // and unpack after the download needs room for the archive
    // parts PLUS the extracted payload - roughly twice the set -
    // and a disk that fits only the volumes fails at the very
    // end, after every byte was spent. Warn the moment the shape
    // is known instead. Bytes still short, not a boolean, so the
    // row can say how much to free. `mixed-pass` overshoots (only
    // part of it materializes) - an amber warning that is
    // sometimes cautious beats a failure at 96%.
    let space_short = free_now
        .filter(|_| shape_unpacks_on_disk(&shape) && j.state != JobState::Completed)
        .and_then(|free| {
            // Volumes already fetched sit on the disk and are
            // subtracted from `free` by their existence, so what
            // is still owed is the unfetched remainder plus the
            // whole extracted payload (approximated by the set
            // size - archives on Usenet are near-incompressible
            // media).
            // The same remainder the row reports - a job whose
            // volumes are already down and unpacking still needs
            // room for the payload, but not for bytes it has.
            // An encrypted set is counted a copy higher still:
            // see `unpack_space_needed`.
            let needed = unpack_space_needed(left, j.total_bytes, &shape);
            needed.checked_sub(free).filter(|s| *s > 0)
        })
        .unwrap_or(0);
    json!({
        "nzo_id": j.nzo_id,
        "filename": j.name,
        // Ours, not SAB's: the *arrs ignore unknown keys, and
        // "why is this here / where is its NZB" was unanswerable
        // from the UI.
        "origin": j.origin,
        "nzb_path": j.nzb_path.to_string_lossy(),
        "cat": if j.category.is_empty() { "*" } else { &j.category },
        "status": match j.state {
            // A pause-suspended job reads Paused the moment the
            // user hits pause - not Downloading until the
            // pipeline finishes unwinding and parks it.
            JobState::Downloading if j.suspended => "Paused",
            // The post-network tail, by the phase the pipeline
            // says it is in. Same reasoning as `Moving` below:
            // the record has no state for any of this (it says
            // Downloading from the first article to the last
            // extracted byte), and calling a verify pass a
            // download meant a row that sat at "100%, 0 MB/s"
            // for minutes with nothing to distinguish it from a
            // pool that had died. These are SABnzbd's own state
            // words, so the *arrs already read them as "busy,
            // keep waiting".
            JobState::Downloading if phase.is_some() => phase.unwrap_or("Downloading"),
            JobState::Downloading => "Downloading",
            // §129: SAB's own stage words; "Moving" for the
            // finalize window - no new compat vocabulary.
            JobState::Finishing => phase.unwrap_or("Moving"),
            _ if j.paused => "Paused",
            // `Completed` is set when the NETWORK leg ends, well
            // before repair hand-off, unlock, rename and the move
            // to the destination. Reporting that tail as "Queued"
            // at 0% made a job that had just shown 100% appear to
            // regress and sit stuck - a 90 GB move to a NAS reads
            // as ten minutes of "Queued 0%", and users delete it
            // mid-move. SAB reports the tail as its own states,
            // which the *arrs know to keep waiting through.
            JobState::Completed => "Moving",
            _ => "Queued",
        },
        // Ours, not SAB's (additive): the dashboard's state
        // word; `status` keeps SAB vocabulary for the *arrs.
        "finishing": j.state == JobState::Finishing,
        "index": i,
        "percentage": format!("{pct}"),
        "mb": format!("{:.2}", j.total_bytes as f64 / API_MB),
        "mbleft": format!("{mbleft:.2}"),
        "timeleft": timeleft,
        // --- SABnzbd `build_queue` slot parity (issue #34) ---
        // Every key below is in real SAB's queue slot and was
        // missing from ours. A remote that deserializes the
        // slot into a declared type gets a null where it
        // expects a value and stops before it renders
        // anything - which is the shape #34 reported, with
        // mode=addfile (no slot parsing) working throughout.
        // Names and formats mirror sabnzbd/api.py build_queue.
        "size": format!("{}B", sab_units(j.total_bytes as f64)),
        "sizeleft": format!("{}B", sab_units(left as f64)),
        // SAB's post-processing level for the job as a
        // string; `sab_pp` is what the add asked for, and 3
        // (repair + unpack + delete) is what one-pass does
        // when nothing named a level.
        "unpackopts": j.sab_pp.unwrap_or(3).to_string(),
        // The script this job will actually run, by basename - the
        // override, else the category's, else the global one. See
        // `sab_script_name`; the raw override alone told every client
        // "None" for the ordinary category/global case.
        "script": sab_script_name(
            &j.script_override,
            cat_scripts.get(&j.category).map(String::as_str).unwrap_or(""),
            global_script,
        ),
        // Always empty, deliberately: M24's contract is that
        // the password itself never leaves the daemon, only
        // the facts about it (`has_password` above). SAB puts
        // the value here; we put what SAB puts when there is
        // none, and a client reads "no password" rather than
        // failing to find the key at all.
        "password": "",
        // SAB's per-job label list (DUPLICATE, ALTERNATIVE,
        // ...). Nothing here produces them yet, and an empty
        // list is what SAB sends for a job with none.
        "labels": Value::Array(Vec::new()),
        // Average article age. We do not carry the post dates
        // on the queue record, and "-" is SAB's own value for
        // a job whose age it does not know.
        "avg_age": "-",
        // Unix seconds this job was added. Derived from the
        // record's monotonic `queued_at` against the one
        // `now_unix` read at the top of this payload, and from
        // the persisted `queued_unix` when that Instant is gone
        // - it is process-local AND consumed at pick, so this
        // answered null both for every job that had started and
        // for the whole queue after a restart, and SAB's own
        // field is always a number (M10, 10 Aug sweep).
        "time_added": j.queued_at
            .map(|t| now_unix.saturating_sub(t.elapsed().as_secs()))
            .or_else(|| j.queued_unix.map(|t| t.max(0) as u64))
            .unwrap_or(0),
        // Bytes the post is short. One-pass decides that at
        // verify time, not while the queue row is live, so
        // this is SAB's healthy-job value until it does.
        "mbmissing": "0.00",
        // SAB's direct-unpack progress line. One-pass unpacks
        // in stream rather than as a separate direct-unpack
        // pass, so there is no such line: null, which is what
        // SAB sends with the feature off.
        "direct_unpack": Value::Null,
        // Ours, not SAB's, like `origin`: the active row's
        // "what is happening right now" sub-line. Empty when
        // there is nothing to say (queued, paused).
        "activity": activity,
        "activity_detail": activity_detail,
        "activity_secs": activity_secs,
        // TODO 205: and, while the DISK unpack ladder runs, how far
        // through it this row is. Absent on every other row and on
        // every other stage - the page falls back to the bare
        // "unpacking" phrase it has always shown. `volumes` is the
        // count that landed on disk (issue #47 asked for it by name);
        // `total` is 0 until the first volume set has been parsed, so
        // the page has a shape for "the count is known, the bytes are
        // not" as well as one for both.
        "unpack": unpack_map.get(&j.nzo_id).map(|p| json!({
            "volumes": p.volumes(),
            "done": p.done(),
            "total": p.total(),
        })).unwrap_or(Value::Null),
        "priority": priority_name(j.priority),
        // Truth-audit I: the canonical name an oracle gave this
        // release, on the QUEUE row and not just in history. A
        // retried obfuscated job already knew its own name - it
        // survives the retry on the record - and still went back
        // to showing a hash for the whole of its second
        // download. Additive keys the *arrs ignore; the
        // dashboard runs them through the same identName() the
        // history row uses.
        "identity_name": j.identity_name,
        "identity_src": j.identity_src,
        // ...and which Smart Folder rule chose this job's
        // category, so a download that landed somewhere
        // unexpected can say who sent it there. Empty when no
        // rule matched.
        "smart_rule": j.smart_rule,
        "duplicate_key": j.dupe_key.as_deref().unwrap_or(""),
        // §129 2b: the SAB pp level the add requested (null =
        // none named) and the job's script= override - the
        // drawer shows the one-pass mapping instead of the
        // params silently vanishing.
        "sab_pp": j.sab_pp,
        "script_override": j.script_override,
        // M24, ours like `origin`: the queue drawer's password
        // control shows whether one is already attached. The
        // value itself never leaves the daemon - history's
        // has_password contract.
        "has_password": j.password.is_some(),
        // ...and whether the RUNNING download is blocked on one
        // right now (the "ask at once" prompt trigger, and a 🔑
        // badge in every mode).
        "password_needed": pw_wanted.as_deref() == Some(j.nzo_id.as_str()),
        "deferred": j.deferred,
        "defer_reason": j.defer_reason,
        // TODO §77 pre-flight verdict, ours like `origin` and
        // `deferred` beside it - SAB has no such field and the
        // *arrs ignore what they don't know. Null until the
        // prober has sampled the job (and forever if the
        // operator turned it off), which renders no badge.
        //
        // `sunk` is the verdict's only scheduling consequence,
        // resolved here rather than in the client: whether the
        // optional auto-defer is actually holding THIS job
        // behind healthier ones depends on the live setting and
        // on the job's own priority, and a queue row that has
        // to explain why it is not starting must not have to
        // guess at either.
        "health": j.health.as_ref().map(|h| {
            let mut v = crate::health::health_json(h);
            if let Some(o) = v.as_object_mut() {
                o.insert(
                    "sunk".into(),
                    json!(*health_defer && j.priority < 2 && h.sinks()),
                );
            }
            v
        }),
        "zip_packed": j.zip_packed,
        "archive_shape": shape,
        // Ours, like the keys around it: bytes the output disk
        // is short of what this set's download + unpack will
        // take. 0 = fine (or the shape one-passes and needs no
        // headroom). Advisory - nothing is held back by it.
        "space_short": space_short,
        // §76. Ours, not SAB's, like the keys above it: what the
        // main video's own header says it is, and anything the
        // name claims that those bytes deny. Null until the
        // prober has an answer.
        "media": j.media,
        "prefetching": sc.as_ref().is_some_and(|(id, _)| *id == j.nzo_id),
        "prefetched_mb": sc
            .as_ref()
            .filter(|(id, _)| *id == j.nzo_id)
            .map(|(_, b)| format!("{:.2}", *b as f64 / API_MB))
            .unwrap_or_default(),
    })
}

// The pre-queue-lock reads, a child module: see sabcompat/prelock.rs.
mod prelock;
use prelock::{PreLock, prelock_reads};

// The queue walk itself, a child module: see sabcompat/walk.rs.
mod walk;
use walk::{QueueView, QueueWalk, queue_walk};

// The GroupDelete arm of `jr_editqueue`, a child module: see
// sabcompat/editqueue_delete.rs.
mod editqueue_delete;
use editqueue_delete::group_delete;

pub(super) fn queue_json(d: &Daemon, params: &std::collections::HashMap<String, String>) -> Value {
    // Everything read BEFORE the queue lock: see prelock_reads. The
    // destructure keeps every downstream read on the inline names. This
    // call must stay ABOVE `let q` - that ordering is the issue #38
    // deadlock, not a style note.
    let PreLock {
        live_shape,
        pw_wanted,
        health_defer,
        disk_now,
        free_now,
        now_unix,
        hold,
        hold_quota_spent,
        sc,
        activity_map,
        unpack_map,
        active_id,
        stall,
        pool_view,
        outages,
    } = prelock_reads(d);
    let q = d.queue.lock_ok();
    // Live speed over a ~5 s rolling window (see current_speed_bps): a
    // whole-job average hid stalls; idle or a fresh window reports 0,
    // never `bytes / ~zero elapsed`.
    let speed_bps = d.current_speed_bps();
    let (peak_bps, peak_src, line_hint) = d.link_peak.chart(d.line_speed.load(Ordering::Relaxed));
    // SAB's queue call takes the same category filter as history (the
    // *arrs pass category=<their cat> when one is configured).
    let cat_filter = params
        .get("category")
        .filter(|c| !c.is_empty() && *c != "*");
    let ids = nzo_ids_param(params);
    // Whole-queue bytes still to fetch, for the top-level sizeleft /
    // timeleft SAB carries. Accumulated INSIDE the slot walk below, from
    // the very number each row reports, so the header and its rows are
    // the same arithmetic on the same instant by construction.
    //
    // §91: it used to be its own walk over the same queue, ahead of the
    // rows. That took a second lock on every job and re-read the live
    // counters, so the header summed one instant and the rows rendered
    // another - "a total against its parts", and the comment right here
    // already declared the two must agree. It also applied a subtly
    // different rule: the header called a SUSPENDED job in its tail
    // finished (0 left) while its row, which excludes suspended jobs
    // from the tail, reported the whole set still to fetch. One walk
    // ends both. That walk is `queue_walk` below, a child module since
    // since the B5 queue-window work - it returns the page and every
    // total in one `QueueWalk`.
    //
    // B5 (20 Aug perf audit): the window the caller asked for, taken
    // here and PASSED
    // INTO the walk. It used to be applied after the fact, by trimming a
    // vector every row of which had already been built - so a dashboard
    // poll on a 15k queue rendered 15k slot bodies to throw all but its
    // page away, with the queue lock held for the whole of it, once a
    // second. Echoed back in the header below the way SAB does.
    let window = window_of(params);
    let (win_start, win_limit) = window;
    // Ours, not SAB's, and off unless a client asks for it by name: a
    // row whose job is in a live pipeline state rides the page wherever
    // it sits in the queue. `pick_job` runs Force and High ahead of
    // queue order, and skips paused, held and deferred rows wherever
    // they sit (a priority WRITE moves its row now - see
    // `reposition_for_priority` - but a pick does not), so
    // what is on the wire can be row 9000 of 15000 - and a client that
    // pages from the top would then draw "what is running" off a page
    // with nothing running in it. The dashboard sends this; no SAB
    // client does, so no SAB client's paging changes shape.
    let pin_live = params.get("pin_live").is_some_and(|v| v == "1");
    // The snapshot every row below is built against - see `SlotCtx`. Each
    // field is moved from the read above it, in the order it was taken, so
    // building it changes nothing about WHEN anything was sampled;
    // `free_now` and `speed_bps` are Copy and the header still reads them.
    let ctx = SlotCtx {
        live_shape,
        pw_wanted,
        health_defer,
        free_now,
        now_unix,
        speed_bps,
        sc,
        activity_map,
        unpack_map,
        active_id,
        stall,
        pool_view,
        outages,
        cat_scripts: d
            .cat_meta
            .lock_ok()
            .iter()
            .filter(|(_, m)| !m.script.is_empty())
            .map(|(name, m)| (name.clone(), m.script.clone()))
            .collect(),
        global_script: d.scripts.lock_ok().clone(),
    };
    let walk = queue_walk(
        d,
        &q,
        &ctx,
        &QueueView {
            cat_filter,
            ids: ids.as_ref(),
            window,
            pin_live,
        },
    );
    let QueueWalk {
        slots,
        matched: n,
        remaining_bytes,
        total_bytes_all,
        runnable_bytes,
        need_bytes,
    } = walk;
    // Everything in the queue, before the caller's category / nzo_ids
    // filter - SAB's `noofslots_total` beside the filtered `noofslots`.
    let total_slots = q.len();
    // SAB's percentage-of-line-speed cap, as a string beside the
    // absolute one. "0" when nothing is capped, or when the line speed
    // is unknown and a percentage of it would mean nothing.
    let speedlimit_pct = {
        let line = d.line_speed.load(Ordering::Relaxed);
        let abs = d.hub.rate.get();
        if line > 0 && abs > 0 {
            format!("{}", (abs as f64 * 100.0 / line as f64).round() as u64)
        } else {
            "0".to_string()
        }
    };
    // What is left of the quota, in SAB's units: the cap less what the
    // period has actually cost. `quota_spent` is the download runner's
    // republished ledger total, so this falls as the bytes arrive; the
    // queue hold (GB, and set only once the quota already holds the
    // queue) is the fallback for the tick before the runner has
    // published anything (L5, 10 Aug sweep).
    let left_quota = {
        let cap = d.quota.load(Ordering::Relaxed) as f64;
        let spent = (d.quota_spent.load(Ordering::Relaxed) as f64)
            .max(hold_quota_spent.unwrap_or(0.0) * 1e9);
        format!("{}B", sab_units((cap - spent).max(0.0)))
    };
    // Minutes until a timed pause auto-resumes (SAB's pause_int).
    let pause_int = d
        .pause_until
        .lock_ok()
        .map(|t| {
            t.saturating_duration_since(Instant::now())
                .as_secs()
                .div_ceil(60)
        })
        .unwrap_or(0);
    // Who paused, and when the queue comes back.
    //
    // The offline mechanism's own pause is named here rather than
    // stored: `paused_by_offline` is already the state that decides
    // whether coming back online may resume, and a second copy of it
    // could only ever disagree with it.
    let paused_now = d.paused.load(Ordering::Relaxed);
    let pause_source = if d.paused_by_offline.load(Ordering::Relaxed) {
        "offline"
    } else {
        *d.pause_source.lock_ok()
    };
    let resume_at = resume_at(d, paused_now, pause_source);
    // Who chose the speed cap now in force. The auto governor moves the
    // number every second, so it names itself here rather than writing
    // "auto" over the operator's stored source on every step.
    let limit_source = if d.auto_speed.load(Ordering::Relaxed) {
        "auto"
    } else {
        *d.limit_source.lock_ok()
    };
    let notices = queue_notices(d);
    json!({"queue": {
        // §91: `paused_now` above, not a fresh load - this flag, the
        // `pause_source` / `resume_at` pair derived from it and the
        // `status` word at the bottom of this body are one answer to one
        // question, and three separate loads of the atomic could ship
        // `"paused": false` beside `"status": "Paused"` and a null
        // source. The dashboard draws the button off one and the state
        // line off the other.
        "paused": paused_now,
        // Deliberately NOT folded into "paused": the dashboard polls this
        // and has to show which of the two states it is in. They look the
        // same from the queue's point of view and mean different things -
        // paused keeps indexing and keeps the account occupied, offline
        // does neither - so a single flag would leave the user unable to
        // tell why nothing is downloading.
        "offline": d.offline.load(Ordering::Relaxed),
        "pause_int": format!("{pause_int}"),
        // Ours: who paused ("user"|"schedule"|"offline"), when it comes
        // back on its own (unix seconds, null when nothing promised a
        // time), and who set the speed cap ("user"|"schedule"|"api"|
        // "auto"). All three are presentation - the *arrs ignore them.
        "pause_source": if paused_now { json!(pause_source) } else { Value::Null },
        "resume_at": resume_at,
        "limit_source": limit_source,
        // What is armed to happen when the queue runs dry, and the
        // seconds left if a sleep or shutdown has already been
        // announced. Here rather than in get_config for the same reason
        // as `password_prompt` above it: the countdown banner and its
        // cancel button are drawn off the queue poll, and get_config is
        // only fetched when the settings view is open.
        "finish_action": crate::serve::finish_action::payload(d),
        // Update banner state: the dashboard already polls the queue
        // every second, so the chip appears without a dedicated poll.
        "update_version": d
            .update_manifest
            .lock_ok()
            .as_ref()
            .and_then(|m| m.get("version").cloned())
            .unwrap_or(Value::Null),
        // Notify-only since 1.0.5: the update chip always links to the
        // download page; no install offered anywhere.
        "bundled": bundled_install(),
        // In a container the download page is the wrong advice - the
        // image is the update channel. The dashboard shows the container
        // recipe instead when this is set.
        "container": container_install(),
        // Same reason, different recipe: a Flatpak owns the files it
        // installed and `flatpak update` is its channel, so the download
        // page is a dead end here too. Kept as its own flag rather than
        // folded into `container` - the container recipe is all compose
        // files and Watchtower, which is wrong advice inside a Flatpak.
        "flatpak": flatpak_install(),
        // The launcher owns the port: the settings field is disabled and
        // says where to change it instead (see `port_locked`).
        "port_locked": d.port_locked,
        // Keyless state, for the dashboard's open-API notice. Telling an
        // unauthenticated caller "there is no key here" leaks nothing:
        // when it is true every endpoint is already answering them, and
        // when it is false this response needed a key to reach.
        //
        // The opt-in half matters as much as the flag. An operator who
        // set NZBFAST_OPEN=1 chose this, usually behind another auth
        // layer, and nagging them forever would teach everyone to ignore
        // the notice - including the people who did not choose it.
        // What the dashboard should do when an archive wants a password
        // (now|done|never). Rides the queue payload the page already
        // polls every second - the prompt decision is made there, and
        // get_config is only fetched when the settings view opens.
        "password_prompt": d.password_prompt.lock_ok().clone(),
        // §73 phase 2, and here for the same reason as the two around
        // it: the row drawers decide whether to offer the verify panel
        // and the in-page player, and they are drawn off the queue poll
        // rather than off get_config (only fetched with the settings
        // view). off | metadata-only | full.
        "preview": preview_mode(d),
        // TODO 101, and here for the same reason: the disk-full drawer
        // has to decide whether to offer "extract in place", and it is
        // drawn off the queue poll rather than off get_config (which is
        // only fetched when the settings view opens).
        "unpack_eat_volumes": d.unpack_eat_volumes.lock_ok().clone(),
        "open_api": d.apikey.lock_ok().is_none(),
        "open_optin": std::env::var("NZBFAST_OPEN").is_ok_and(|v| v == "1"),
        // §91: `free_now` from the top of this function, not a second
        // statvfs. The per-slot `space_short` warnings are computed
        // against that reading, so a fresh one here could put "this job
        // is 5 GB short" in the same body as a headline free-space
        // figure that says there is room - the row and the header
        // disagreeing about the one disk they both describe.
        "diskspace1": format!("{:.2}", free_now.unwrap_or(0) as f64 / 1e9),
        // Ours: {kind:"disk"|"quota", a, b} while the scheduler holds
        // the queue (a/b are free/floor or spent/cap, in GB). Null when
        // downloads can start. The *arrs ignore unknown keys.
        "hold": hold, "storage_pause": crate::serve::slowstore::payload(d),
        // A STRING, as SAB sends it and as our own mode=status already
        // did - the two disagreed on type for the same field name.
        "speedlimit_abs": d.hub.rate.get().to_string(),
        // The configured line speed, bytes/sec, 0 when unset. Ours: the
        // header's limit menu offers percentage presets only once this
        // is known, because `apply_setting("speedlimit")` REFUSES a bare
        // percentage without it - a menu entry that can only error is
        // worse than no menu entry.
        "line_speed": d.line_speed.load(Ordering::Relaxed),
        // §125: the graph's 100% anchor - learned peak bytes/sec (0 =
        // unknown); source "measured" or "line" (see serve/linkpeak.rs).
        "link_peak": peak_bps, "link_peak_src": peak_src,
        "link_line_hint": line_hint,
        // §129 4b: the layer that owns the current shortfall, with the
        // numbers that convicted it - or null when no job is on the
        // wire. Tokens only; the dashboard owns the words.
        "whyslow": d.whyslow.payload(d),
        "auto_speed": d.auto_speed.load(Ordering::Relaxed),
        "watch_failed": notices.watch_failed,
        "delete_kept": notices.delete_kept,
        "hist_upgraded": notices.hist_upgraded,
        // Already exactly the window the caller asked for - applied
        // inside the walk above, where the rows outside it are never
        // built. Direct id selection bypasses the window entirely (SAB
        // semantics; see nzo_ids_param), which the walk honours too.
        "slots": slots,
        "speed": sab_units(speed_bps),
        "kbpersec": format!("{:.0}", speed_bps / 1e3),
        // SAB's own suffix convention: to_units(bytes) + "B".
        "sizeleft": format!("{}B", sab_units(remaining_bytes as f64)),
        // ETA from the RUNNABLE remainder, not the total: `sizeleft`
        // keeps promising the whole backlog, but a paused or
        // duplicate-held job contributes size and no time (walk.rs
        // computes `runnable_bytes` for exactly this), and dividing
        // the total by the line speed put a header ETA on the queue
        // that never converged while the active job downloaded.
        "timeleft": if speed_bps > 1.0 && runnable_bytes > 0 {
            sab_timeleft(runnable_bytes as f64 / speed_bps)
        } else {
            "0:00:00".to_string()
        },
        "noofslots": n,
        "status": if paused_now {
            "Paused"
        } else if n == 0 {
            "Idle"
        } else {
            "Downloading"
        },
        // --- SABnzbd `build_header` parity (issue #34) ---------------
        //
        // Real SAB starts its queue body with build_header(), and every
        // key below is in it and was missing from ours. It matters
        // because a phone remote reads the header out of the queue and
        // history bodies rather than calling mode=version for it: SAB
        // 2.0 trimmed these same fields, NZB360's history stopped
        // working, and SAB's own fix was to put `version` back
        // (sabnzbd/sabnzbd#872). #34 is that shape again - queue and
        // history both stuck at "Connecting" on a daemon where
        // mode=addfile, which reads no header, worked fine.
        //
        // Mirrors sabnzbd/api.py build_header() key for key. Where a
        // number is genuinely ours we send ours; where the concept does
        // not exist in a one-pass downloader we send what SAB sends
        // when the feature is off, and say so at the key.
        "version": SAB_VERSION,
        "paused_all": paused_now,
        // We download and complete under one tree, so both of SAB's
        // disks are the same filesystem, measured once above.
        "diskspace2": format!("{:.2}", free_now.unwrap_or(0) as f64 / 1e9),
        "diskspace1_norm": sab_units(free_now.unwrap_or(0) as f64),
        "diskspace2_norm": sab_units(free_now.unwrap_or(0) as f64),
        "diskspacetotal1": format!("{:.2}", disk_now.map(|(_, t)| t).unwrap_or(0) as f64 / 1e9),
        "diskspacetotal2": format!("{:.2}", disk_now.map(|(_, t)| t).unwrap_or(0) as f64 / 1e9),
        // SAB's percentage-of-line-speed cap, as a string beside the
        // absolute one. 0 when nothing is capped, or when the line
        // speed is unknown and a percentage has no meaning.
        "speedlimit": speedlimit_pct,
        // Count of warnings in SAB's GUI log. nzbfast keeps no such
        // log: `mode=warnings` derives its list from conditions that
        // are true right now, and deriving them here would put a
        // config-file read on a once-a-second poll. "0" is what SAB
        // sends when nothing has been logged; clients that want the
        // list already call mode=warnings or mode=status for it.
        "have_warnings": "0",
        // No queue-complete action exists here, which is what null
        // means in SAB too.
        "finishaction": Value::Null,
        // The download quota, in SAB's units. `left_quota` is the
        // remainder the scheduler's own hold knows about: the hold
        // carries (spent, cap) in GB while a spent quota is holding
        // the queue, and nothing is spent from this facade's point of
        // view until it does.
        "quota": format!("{}B", sab_units(d.quota.load(Ordering::Relaxed) as f64)),
        "have_quota": d.quota.load(Ordering::Relaxed) > 0,
        "left_quota": left_quota,
        // One-pass decodes straight into the output file and holds no
        // article cache, so SAB's cache pair is zero by construction.
        "cache_art": "0",
        "cache_size": "0 B",
        // The queue totals SAB puts beside `sizeleft` / `timeleft`,
        // from the one walk above.
        "mb": format!("{:.2}", total_bytes_all as f64 / API_MB),
        "mbleft": format!("{:.2}", remaining_bytes as f64 / API_MB),
        // Ours, not SAB's (additive, B5). Both are whole-queue facts
        // that a paged client cannot recover from the rows it was sent:
        // `mbleft_runnable` is the part of `mbleft` the line will
        // actually work through (Downloading + Queued rows only), which
        // is the header ETA's numerator, and `space_need_bytes` is what
        // the whole queue will ask of the download disk before it is
        // done, summed from each row's own unpack forecast.
        "mbleft_runnable": format!("{:.2}", runnable_bytes as f64 / API_MB),
        "space_need_bytes": need_bytes,
        "size": format!("{}B", sab_units(total_bytes_all as f64)),
        "noofslots_total": total_slots,
        // The window this body answered for, echoed back as SAB does.
        "start": win_start,
        "limit": win_limit,
        "finish": win_start.saturating_add(win_limit),
    }})
}

// ---------------------------------------------------------------------------
// M21: NZBGet JSON-RPC facade (remote-app compatibility)
// ---------------------------------------------------------------------------

/// Minimal standard-alphabet base64 decode (NZBGet `append` payloads).
pub(super) fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// "SABnzbd_nzo_nzbfast42" → 42 (NZBGet uses integer NZBIDs).
pub(super) fn nzo_int(nzo: &str) -> i64 {
    nzo.chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

pub(super) fn lohi(bytes: u64) -> (u32, u32) {
    ((bytes & 0xFFFF_FFFF) as u32, (bytes >> 32) as u32)
}

pub(super) fn size_fields(prefix: &str, bytes: u64) -> serde_json::Map<String, Value> {
    let (lo, hi) = lohi(bytes);
    let mut m = serde_json::Map::new();
    m.insert(format!("{prefix}SizeLo"), json!(lo));
    m.insert(format!("{prefix}SizeHi"), json!(hi));
    m.insert(format!("{prefix}SizeMB"), json!(bytes / API_MB_U));
    m
}

/// NZBGet-shaped post-processing parameter list for a job
/// ([{Name, Value}] - the *arrs match their downloads by the `drone`
/// entry they appended with).
pub(super) fn pp_params_json(g: &Job) -> Value {
    Value::Array(
        g.pp_params
            .iter()
            .map(|(n, v)| json!({"Name": n, "Value": v}))
            .collect(),
    )
}

fn jr_status(d: &Arc<Daemon>) -> Value {
    let unix_now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    };
    {
        let rate = d.current_speed_bps() as u64;
        let (disk_free, _) = disk_stat_walk(&d.out_dir()).unwrap_or((0, 0));
        let paused = d.paused.load(Ordering::Relaxed);
        // §91: progress is sampled AFTER the disk walk above (which
        // can take milliseconds) and right beside the queue scan, so
        // "Downloaded"/"Remaining" describe the same instant as the
        // rest of the answer - not a snapshot from before the walk.
        // ...and each job is tested and read under ONE lock. Taking it
        // twice let a slot that flipped Queued -> Downloading in between
        // contribute its WHOLE size here and its remainder again through
        // `active_remaining` below - the same job counted twice in one
        // total.
        let queued_remaining: u64 = d
            .queue
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                (g.state == JobState::Queued).then_some(g.total_bytes)
            })
            .sum();
        // `Downloaded` stays the decoded volume this session moved,
        // which is what it has always meant; the two were never required
        // to sum. See `active_counters` for the pairing.
        let (done, _, active_remaining) = active_counters(d);
        let remaining = active_remaining + queued_remaining;
        let mut o = serde_json::Map::new();
        for (k, v) in size_fields("Remaining", remaining) {
            o.insert(k, v);
        }
        for (k, v) in size_fields("Downloaded", done) {
            o.insert(k, v);
        }
        // NZBGet's disk fields do NOT carry "Size" in the name.
        let (dlo, dhi) = lohi(disk_free);
        o.insert("FreeDiskSpaceLo".into(), json!(dlo));
        o.insert("FreeDiskSpaceHi".into(), json!(dhi));
        o.insert("FreeDiskSpaceMB".into(), json!(disk_free / API_MB_U));
        o.extend([
            ("DownloadRate".to_string(), json!(rate)),
            ("AverageDownloadRate".to_string(), json!(rate)),
            (
                "DownloadLimit".to_string(),
                json!(d.speed_ceiling.load(Ordering::Relaxed)),
            ),
            ("DownloadPaused".to_string(), json!(paused)),
            ("Download2Paused".to_string(), json!(paused)),
            ("PostPaused".to_string(), json!(false)),
            ("ScanPaused".to_string(), json!(false)),
            ("ServerStandBy".to_string(), json!(rate == 0)),
            ("ServerTime".to_string(), json!(unix_now())),
            ("UpTimeSec".to_string(), json!(0)),
            ("DownloadTimeSec".to_string(), json!(0)),
            (
                "ThreadCount".to_string(),
                json!(d.connections.load(Ordering::Relaxed)),
            ),
            ("ParJobCount".to_string(), json!(0)),
            ("PostJobCount".to_string(), json!(0)),
            ("UrlCount".to_string(), json!(0)),
            ("FeedActive".to_string(), json!(false)),
            ("QueueScriptCount".to_string(), json!(0)),
            ("NewsServers".to_string(), json!([])),
        ]);
        Value::Object(o)
    }
}

fn jr_listgroups(d: &Arc<Daemon>) -> Value {
    {
        let groups: Vec<Value> = d
            .queue
            .lock_ok()
            .iter()
            .map(|j| {
                let g = j.lock_ok();
                // The same pairing the SAB queue does, and for the
                // same reasons - this facade had the identical
                // defect. Every `Downloading` group read the shared
                // counters, so while job N finished its disk tail
                // (still Downloading, by state) an NZBGet client saw
                // N's group reporting job N+1's bytes.
                //
                // §91: sampled under this group's lock, after its
                // state was read, so (Status, Downloaded) is one
                // instant - a snapshot from before the queue walk
                // could pair the previous job's progress with a
                // group that started downloading mid-walk.
                let phase = (matches!(g.state, JobState::Downloading | JobState::Finishing)
                    && !g.suspended)
                    .then(|| d.tail_phase(&g.nzo_id))
                    .flatten();
                let tail = phase.is_some();
                // The same pairing the SAB queue's active_left takes -
                // the two compat surfaces must not disagree about the
                // same job's percentage.
                let live = (g.state == JobState::Downloading)
                    .then(|| {
                        d.wire_counters(&g.nzo_id)
                            .map(|(done, total, _)| (done, total))
                    })
                    .flatten();
                // On the wire right now, as opposed to merely still
                // holding a queue slot: NZBGet has no state for the
                // tail either, and `ActiveDownloads` below claiming
                // this job's connections while another download
                // actually holds them is the same untruth.
                let downloading = live.is_some() && !tail;
                let (_, rem) =
                    slot_progress(g.state, live, tail, g.total_bytes, g.downloaded_bytes);
                let dl = g.total_bytes.saturating_sub(rem);
                let mut o = serde_json::Map::new();
                for (k, v) in size_fields("File", g.total_bytes) {
                    o.insert(k, v);
                }
                for (k, v) in size_fields("Remaining", rem) {
                    o.insert(k, v);
                }
                for (k, v) in size_fields("Downloaded", dl) {
                    o.insert(k, v);
                }
                for (k, v) in size_fields("Paused", 0) {
                    o.insert(k, v);
                }
                o.extend([
                    ("NZBID".to_string(), json!(nzo_int(&g.nzo_id))),
                    ("NZBName".to_string(), json!(g.name)),
                    ("NZBNicename".to_string(), json!(g.name)),
                    ("Kind".to_string(), json!("NZB")),
                    (
                        "Status".to_string(),
                        // NZBGet's own post-processing states for the
                        // tail, the counterpart of the SAB queue's
                        // Verifying/Repairing/Extracting - a client
                        // that knows this protocol knows to keep
                        // waiting through them. Without them a
                        // finishing job fell back to QUEUED, which
                        // reads as "not started" for work that is
                        // nearly done.
                        json!(match phase {
                            Some("Verifying") => "VERIFYING_SOURCES",
                            Some("Repairing") => "REPAIRING",
                            Some("Extracting") => "UNPACKING",
                            Some(_) => "MOVING",
                            None if downloading => "DOWNLOADING",
                            // §129 Finishing with no phase word left is
                            // the finalize/move window - same NZBGet
                            // vocabulary as the Completed mover arm.
                            None if matches!(
                                g.state,
                                JobState::Completed | JobState::Finishing
                            ) =>
                                "MOVING",
                            None if g.paused => "PAUSED",
                            None => "QUEUED",
                        }),
                    ),
                    ("Category".to_string(), json!(g.category)),
                    ("Priority".to_string(), json!(g.priority * 50)),
                    ("MaxPriority".to_string(), json!(g.priority * 50)),
                    ("MinPostTime".to_string(), json!(0)),
                    ("MaxPostTime".to_string(), json!(0)),
                    (
                        "ActiveDownloads".to_string(),
                        json!(if downloading {
                            d.connections.load(Ordering::Relaxed)
                        } else {
                            0
                        }),
                    ),
                    ("Health".to_string(), json!(1000)),
                    ("CriticalHealth".to_string(), json!(900)),
                    ("DupeMode".to_string(), json!("SCORE")),
                    ("DupeScore".to_string(), json!(0)),
                    (
                        "DupeKey".to_string(),
                        json!(g.dupe_key.clone().unwrap_or_default()),
                    ),
                    ("MessageCount".to_string(), json!(0)),
                    ("RemainingFileCount".to_string(), json!(0)),
                    ("RemainingParCount".to_string(), json!(0)),
                    ("Parameters".to_string(), pp_params_json(&g)),
                    ("PostInfoText".to_string(), json!("")),
                    ("PostStageProgress".to_string(), json!(0)),
                ]);
                Value::Object(o)
            })
            .collect();
        json!(groups)
    }
}

fn jr_history(d: &Arc<Daemon>) -> Value {
    let unix_now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    };
    {
        let entries: Vec<Value> = d
            .history
            .lock_ok()
            .iter()
            .rev()
            .map(|j| {
                let g = j.lock_ok();
                // M5: a row a delete verb filed here is not a download
                // verdict - NZBGet spells it DELETED/<why>, and the
                // *arrs read that as "removed", not "failed".
                let (status, par_status, unpack_status) = if g.delete_status.is_empty() {
                    let (s, p, u) = nzbget_status(&g);
                    (s.to_string(), p, u)
                } else {
                    (format!("DELETED/{}", g.delete_status), "NONE", "NONE")
                };
                // Prefer the wall clock: `finished_at` is monotonic
                // and process-local, so after a restart it was None
                // and every row reported an age of zero - a week of
                // history all "finished seconds ago", re-sorted
                // wrongly and re-notified as new on every restart.
                let ago = g
                    .finished_unix
                    .map(|t| (unix_now() - t).max(0))
                    .or_else(|| g.finished_at.map(|t| t.elapsed().as_secs() as i64))
                    .unwrap_or(0);
                let mut o = serde_json::Map::new();
                for (k, v) in size_fields("File", g.total_bytes) {
                    o.insert(k, v);
                }
                o.extend([
                    ("NZBID".to_string(), json!(nzo_int(&g.nzo_id))),
                    ("Name".to_string(), json!(g.name)),
                    ("NZBName".to_string(), json!(g.name)),
                    ("NZBNicename".to_string(), json!(g.name)),
                    ("Kind".to_string(), json!("NZB")),
                    ("Status".to_string(), json!(status)),
                    ("ParStatus".to_string(), json!(par_status)),
                    ("UnpackStatus".to_string(), json!(unpack_status)),
                    ("ScriptStatus".to_string(), json!("NONE")),
                    // Absent = deserialized as "" by the *arrs, which is
                    // outside their {SUCCESS, NONE} success set → every
                    // finished item shows Warning. NONE = "no move ran".
                    ("MoveStatus".to_string(), json!("NONE")),
                    (
                        "DeleteStatus".to_string(),
                        json!(if g.delete_status.is_empty() {
                            "NONE"
                        } else {
                            g.delete_status.as_str()
                        }),
                    ),
                    ("MarkStatus".to_string(), json!("NONE")),
                    ("UrlStatus".to_string(), json!("NONE")),
                    ("Category".to_string(), json!(g.category)),
                    ("HistoryTime".to_string(), json!(unix_now() - ago)),
                    ("DestDir".to_string(), json!(g.out_dir.to_string_lossy())),
                    ("FinalDir".to_string(), json!(g.out_dir.to_string_lossy())),
                    (
                        "DownloadedSizeMB".to_string(),
                        json!(g.downloaded_bytes / API_MB_U),
                    ),
                    ("DownloadTimeSec".to_string(), json!(g.elapsed_secs as u64)),
                    ("PostTotalTimeSec".to_string(), json!(0)),
                    ("ParTimeSec".to_string(), json!(0)),
                    ("RepairTimeSec".to_string(), json!(0)),
                    ("UnpackTimeSec".to_string(), json!(0)),
                    ("MessageCount".to_string(), json!(0)),
                    ("Health".to_string(), json!(1000)),
                    ("CriticalHealth".to_string(), json!(900)),
                    ("Parameters".to_string(), pp_params_json(&g)),
                ]);
                Value::Object(o)
            })
            .collect();
        json!(entries)
    }
}

fn jr_append(d: &Arc<Daemon>, params: &[Value], ua_hdr: &str) -> Value {
    {
        // v13+ order: [NZBFilename, Content(b64), Category, Priority,
        // AddToTop, AddPaused, DupeKey, DupeScore, DupeMode].
        // Legacy:   [NZBFilename, Category, Priority, AddToTop, Content].
        let strs: Vec<&str> = params.iter().filter_map(Value::as_str).collect();
        let name = strs.first().copied().unwrap_or("remote.nzb");
        let content = strs
            .iter()
            .skip(1)
            .max_by_key(|s| s.len())
            .copied()
            .unwrap_or_default();
        let category = strs
            .iter()
            .skip(1)
            .find(|s| s.len() < 64 && !s.contains('='))
            .copied()
            .unwrap_or("");
        let prio_ng = params.iter().filter_map(Value::as_i64).next().unwrap_or(0);
        let mut priority = if prio_ng >= 900 {
            2
        } else if prio_ng > 0 {
            1
        } else if prio_ng < 0 {
            -1
        } else {
            0
        };
        // AddPaused was accepted and thrown away: Radarr on the nzbget
        // client type with "Add Paused" enabled got an immediate full
        // download, which is the opposite of what the user asked for
        // and can matter on a metered line.
        //
        // The v13+ order carries two booleans, AddToTop then
        // AddPaused; the legacy shape has only AddToTop. So a lone
        // boolean is never a pause, and the second one is. -2 is
        // already the internal "add paused" priority (see the
        // `paused:` field in enqueue), which is also how the SAB
        // facade spells it, so both front doors agree.
        let bools: Vec<bool> = params.iter().filter_map(Value::as_bool).collect();
        let add_to_top = bools.first().copied().unwrap_or(false);
        if bools.len() >= 2 && bools[1] {
            priority = -2;
        }
        // v13+ trailing PPParameters. Two wire shapes exist:
        // [{Name, Value}, …] (nzbget docs) and a flat alternating
        // ["name", "value", …] (what Sonarr/Radarr actually send).
        // The *arrs tag every add with a `drone` GUID here and match
        // queue/history items ONLY by it, so both must parse.
        let pp: Vec<(String, String)> = params
            .iter()
            .rev()
            .find_map(Value::as_array)
            .map(|a| {
                if a.iter().all(Value::is_string) {
                    a.chunks(2)
                        .filter_map(|c| {
                            Some((
                                c.first()?.as_str()?.to_string(),
                                c.get(1)?.as_str()?.to_string(),
                            ))
                        })
                        .collect()
                } else {
                    a.iter()
                        .filter_map(|p| {
                            let name = p.get("Name")?.as_str()?.to_string();
                            let value = match p.get("Value")? {
                                Value::String(s) => s.clone(),
                                other => other.to_string(),
                            };
                            Some((name, value))
                        })
                        .collect()
                }
            })
            .unwrap_or_default();
        // NZBGet also accepts a URL as the Content and fetches it
        // itself; LunaSea's add-by-URL sends exactly that, with an
        // empty NZBFileName, so the base64-only reading below answered
        // 0 - "failed" - for every URL add (§18). The category
        // heuristic above is tuned for base64 bodies (a short URL
        // would itself pass the length test and be taken for a
        // category), so this arm reads the v13+ positional Category
        // instead of `category`.
        let trimmed = content.trim();
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            let cat = params.get(2).and_then(Value::as_str).unwrap_or("");
            return match fetch_url(trimmed) {
                Ok(f) => {
                    // An explicit NZBFilename wins; otherwise name from
                    // the fetch (Content-Disposition first), the same
                    // ladder mode=addurl walks - naming from the URL
                    // alone titles indexer grabs with an id hash.
                    let jobname = Some(name)
                        .filter(|n| !n.trim().is_empty())
                        .map(str::to_string)
                        .or_else(|| name_from_fetch(&f, trimmed))
                        .unwrap_or_else(|| "download.nzb".to_string());
                    match d.enqueue_fetched(
                        &f,
                        &jobname,
                        cat,
                        priority,
                        None,
                        None,
                        0,
                        &api_origin(ua_hdr, "arr"),
                        false,
                    ) {
                        Ok(Enqueued { nzo_id: nzo, .. }) => json!(nzo_int(&nzo)),
                        Err(e) => {
                            // `fetch_url`'s errors are formatted "{url}:
                            // ..." and an NZB link routinely carries the
                            // indexer's apikey in its query string. The
                            // log ring is not private - logtee mirrors it
                            // into mode=log, the JSON-RPC log methods and
                            // `docker logs` - so it goes through the same
                            // redaction every sibling path uses.
                            warn!(
                                target: "jsonrpc",
                                "append url: {}",
                                super::indexers::redact_url_creds(&e.to_string())
                            );
                            json!(0)
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        target: "jsonrpc",
                        "append url: {}",
                        super::indexers::redact_url_creds(&e.to_string())
                    );
                    json!(0)
                }
            };
        }
        match b64_decode(content).filter(|b| !b.is_empty()) {
            None => json!(0),
            Some(bytes) => match d.enqueue(
                &bytes,
                name,
                category,
                priority,
                None,
                None,
                &api_origin(ua_hdr, "arr"),
                false,
            ) {
                Ok(Enqueued { nzo_id: nzo, .. }) => {
                    if !pp.is_empty() {
                        for j in d.queue.lock_ok().iter() {
                            let mut g = j.lock_ok();
                            if g.nzo_id == nzo {
                                g.pp_params = pp.clone();
                            }
                        }
                    }
                    // AddToTop was parsed and discarded alongside
                    // AddPaused. Moving the job to the head of the
                    // queue is what the flag means; priority ordering
                    // still applies on top of it, as it does for any
                    // other job.
                    if add_to_top {
                        let mut q = d.queue.lock_ok();
                        if let Some(i) = q.iter().position(|j| j.lock_ok().nzo_id == nzo)
                            && let Some(j) = q.remove(i)
                        {
                            q.push_front(j);
                        }
                    }
                    if !pp.is_empty() || add_to_top {
                        d.save_queue();
                    }
                    json!(nzo_int(&nzo))
                }
                Err(e) => {
                    warn!(target: "jsonrpc", "append: {e}");
                    json!(0)
                }
            },
        }
    }
}

fn jr_editqueue(d: &Arc<Daemon>, params: &[Value], rpc_error: &mut Option<String>) -> Value {
    {
        // [Command, Param, IDs] (v13+) or [Command, Offset, Text, IDs].
        let cmd = params.first().and_then(Value::as_str).unwrap_or("");
        let ids: Vec<i64> = params
            .iter()
            .rev()
            .find_map(|p| p.as_array())
            .map(|a| a.iter().filter_map(Value::as_i64).collect())
            .unwrap_or_default();
        let param_str = params
            .iter()
            .skip(1)
            .find_map(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut ok = false;
        match cmd {
            // Body in api/remote.rs, with the tail-guard, suspend and
            // idle-announce rationale on it (Codex sweeps 3 + 14 Aug).
            "GroupPause" | "GroupResume" => {
                ok = super::api::remote::pause_by_ids(d, &ids, cmd == "GroupPause");
            }
            "GroupDelete" | "GroupDupeDelete" | "GroupFinalDelete" | "GroupParkDelete" => {
                ok = group_delete(d, cmd, &ids);
            }
            "GroupMoveTop" | "GroupMoveBottom" => {
                let mut q = d.queue.lock_ok();
                let (mut hit, rest): (VecDeque<_>, VecDeque<_>) = q
                    .drain(..)
                    .partition(|j| ids.contains(&nzo_int(&j.lock_ok().nzo_id)));
                ok = !hit.is_empty();
                if cmd == "GroupMoveTop" {
                    hit.extend(rest);
                    *q = hit;
                } else {
                    let mut rest = rest;
                    rest.extend(hit.drain(..));
                    *q = rest;
                }
            }
            // The four editqueue subcommands LunaSea sends that the
            // *arrs never do; their bodies live in api/remote.rs (§18).
            "GroupMoveOffset" => {
                ok = super::api::remote::move_by_offset(
                    d,
                    &ids,
                    param_str.trim().parse::<i64>().unwrap_or(0),
                );
            }
            "GroupSetName" => {
                ok = super::api::remote::rename_by_ids(d, &ids, param_str.trim());
            }
            "GroupSetParameter" => {
                ok = super::api::remote::set_parameter(d, &ids, &param_str);
            }
            // NZBGet spells the sort "<key>+"/"<key>-"; the shared
            // helper also serves SAB's queue&name=sort.
            "GroupSort" => {
                let t = param_str.trim();
                let (key, asc) = match t.strip_suffix(['+', '-']) {
                    Some(k) => (k, t.ends_with('+')),
                    None => (t, true),
                };
                ok = super::api::remote::sort_queue(d, key, asc);
            }
            "GroupSetCategory" | "GroupApplyCategory" => {
                // Untrusted category must never escape out_root at
                // completion (tv_organize joins it onto the root). Force
                // a single contained path component, like enqueue and
                // history set_cat - this was the one write path skipping
                // sanitize, allowing "../../.." traversal via editqueue.
                let cat = if param_str.trim().is_empty() {
                    String::new()
                } else {
                    nzbkit::disk::sanitize_filename(param_str.trim())
                };
                // Through the same queued-recategorize transaction as
                // the SAB change_cat arm (Codex sweep 3 Aug M9):
                // category controls filesystem routing, so writing the
                // label without re-deriving out_dir under add_lock left
                // the record saying movies while the job downloaded
                // into the old tv directory - and relabelled active
                // jobs the SAB side refuses.
                let targets: Vec<(Arc<Mutex<Job>>, String, String)> = d
                    .queue
                    .lock_ok()
                    .iter()
                    .filter_map(|j| {
                        let g = j.lock_ok();
                        (ids.contains(&nzo_int(&g.nzo_id)) && g.state == JobState::Queued)
                            .then(|| (j.clone(), g.name.clone(), g.category.clone()))
                    })
                    .collect();
                for (job, name, current) in targets {
                    if current == cat {
                        ok = true; // already there: don't re-derive
                        continue;
                    }
                    // register_cat happens inside, and only for a cat
                    // that actually landed - matching the SAB
                    // precedent (unregistered ids must not grow the
                    // persisted category list).
                    ok |= super::api::queue::requeue_category(d, &job, &name, &cat).is_ok();
                }
            }
            "GroupSetPriority" => {
                // The SAB facade has had this since M26 and this side
                // never did, so which of the two client types the user
                // picked in Sonarr decided whether priority worked at
                // all - and an unknown command answered `false`, which
                // is also what "no such job" answers.
                let prio = nzbget_priority(param_str.trim().parse::<i64>().unwrap_or(0));
                // Through the shared transition, not a bare write
                // (Codex sweep 2, 3 Aug M4). This copy cleared the
                // watchdog deferral but not the duplicate hold, so
                // raising a held duplicate to Normal or Force
                // answered success while `pick_job` - which skips a
                // paused job whatever its priority - went on
                // skipping it forever. That hold is precisely what
                // the UI tells the user to raise the priority to
                // release.
                let mut q = d.queue.lock_ok();
                // Same two passes as the SAB facade's priority arm: the
                // repositioning reorders the deque, so it runs after
                // the pass that finds and writes the targets.
                let mut moved: Vec<String> = Vec::new();
                for j in q.iter() {
                    let mut g = j.lock_ok();
                    if ids.contains(&nzo_int(&g.nzo_id))
                        && super::api::queue::apply_priority(d, &mut g, prio)
                    {
                        ok = true;
                        moved.push(g.nzo_id.clone());
                    }
                }
                for id in &moved {
                    super::api::queue::reposition_for_priority(&mut q, id);
                }
            }
            "HistoryDelete" | "HistoryFinalDelete" => {
                let mut h = d.history.lock_ok();
                // Parity with the SAB/API delete (Codex sweep 3 Aug
                // M10): a record whose files are mid-move
                // (recategorize) or mid-unlock (password finalizing)
                // is being worked on disk right now, and removing it
                // leaves the payload at a destination no surviving
                // record names. Refuse the whole request, checked
                // under the history lock like the SAB side.
                let busy = {
                    let m = d.moving.lock_ok();
                    h.iter().any(|j| {
                        let g = j.lock_ok();
                        ids.contains(&nzo_int(&g.nzo_id)) && (m.contains(&g.nzo_id) || g.finalizing)
                    })
                };
                if busy {
                    *rpc_error = Some(
                        "files are being moved or unlocked right now - \
                             try again when it settles"
                            .into(),
                    );
                } else {
                    let before = h.len();
                    let mut gone: Vec<String> = Vec::new();
                    h.retain(|j| {
                        let g = j.lock_ok();
                        let hit = ids.contains(&nzo_int(&g.nzo_id));
                        if hit {
                            // Record deleted for good - drop its spooled
                            // .nzb. Through `drop_spool` rather than a
                            // swallowed `remove_file` (Codex sweep F-05):
                            // the row is gone durably by the time this
                            // returns, so a copy whose unlink is REFUSED
                            // is a file under the adoptable name that no
                            // record names, and `recover_orphaned_spool`
                            // downloads the deleted release again at the
                            // next start. The REST history delete has gone
                            // through `hold_or_drop_spool` since that fix;
                            // this facade is the hand-copy that did not.
                            drop_spool(&g.nzb_path);
                            gone.push(g.nzo_id.clone());
                        }
                        !hit
                    });
                    ok = h.len() < before;
                    drop(h);
                    d.history_tombstone(&gone);
                }
            }
            "HistoryRedownload" | "HistoryReturn" | "HistoryRetry" => {
                let jobs: Vec<String> = d
                    .history
                    .lock_ok()
                    .iter()
                    .filter(|j| ids.contains(&nzo_int(&j.lock_ok().nzo_id)))
                    .map(|j| j.lock_ok().nzo_id.clone())
                    .collect();
                for nzo in jobs {
                    ok |= d.retry(&nzo);
                }
            }
            other => {
                // `false` was also the answer for "no such job", so a
                // client could not tell a command we do not implement
                // from one that simply matched nothing.
                *rpc_error = Some(format!("unsupported editqueue command {other:?}"));
            }
        }
        // Load-bearing, and for more than the queue order: this is the
        // ONLY store behind `GroupSetName` and `GroupApplyCategory`,
        // whose shared `requeue_category` re-points `out_dir` and can
        // already have MOVED the partial download to the new folder. A
        // restructure that gives an arm its own early return takes the
        // rename with it, and the record comes back after a restart
        // naming a directory the bytes have left. One save, not one per
        // arm, so renaming N jobs is one rewrite of a queue.json that
        // reaches 14,500 rows. Pinned by `remote_compat.rs`.
        if rpc_error.is_none() {
            d.save_queue();
        }
        json!(ok)
    }
}

fn jr_config(d: &Arc<Daemon>, _rpc_error: &mut Option<String>) -> Value {
    {
        // The *arrs' Test() validates their configured category against
        // CategoryN.Name entries and sanity-checks KeepHistory, so the
        // config dump must carry both or the nzbget client type fails
        // with "Category does not exist".
        //
        // KeepHistory is DELIBERATELY a non-zero literal, and must
        // stay one. We keep history indefinitely, which NZBGet spells
        // `0` - but Sonarr and Radarr reject a client reporting 0
        // ("KeepHistory should be greater than 0", their guard against
        // a downloader that forgets a job before they can import it),
        // and again above 25000. So the honest number is the one value
        // they refuse. 7 says "history sticks around for a while",
        // which is true, and the SAB facade's own
        // `history_retention_option: "all"` is the accurate answer for
        // the clients that ask in that dialect.
        let mut cfg = vec![
            json!({"Name": "ControlPort", "Value": d.port.to_string()}),
            json!({"Name": "DestDir", "Value": d.out_dir().to_string_lossy()}),
            json!({"Name": "AppVersion", "Value": "21.0"}),
            json!({"Name": "KeepHistory", "Value": "7"}),
        ];
        for (i, c) in d.cats.lock_ok().iter().filter(|c| *c != "*").enumerate() {
            let n = i + 1;
            cfg.push(json!({"Name": format!("Category{n}.Name"), "Value": c}));
            cfg.push(json!({
                "Name": format!("Category{n}.DestDir"),
                "Value": d.out_dir().join(c).to_string_lossy(),
            }));
        }
        json!(cfg)
    }
}

pub(super) fn handle_jsonrpc(
    d: &Arc<Daemon>,
    mut req: tiny_http::Request,
    apikey: Option<&str>,
    nzbkey: Option<&str>,
    // NZBGet's `/<user>:<pass>/jsonrpc` URL credential, already
    // percent-decoded by the router. LunaSea sends ONLY this form -
    // no Authorization header - so it stands in for the Basic
    // password everywhere below (§18).
    path_pw: Option<&str>,
) {
    // Basic auth: the password must match a configured key. Gate on ANY
    // configured key - the old code only checked `apikey`, so an install
    // with only the add-only nzbkey set (apikey None) skipped auth entirely
    // and ran full-control editqueue/append unauthenticated. Accept either
    // key here (like /stream); the surface is only fully open when NEITHER
    // is set.
    let keys: Vec<&str> = [apikey, nzbkey].into_iter().flatten().collect();
    // Which remote-control app is talking to us, for an appended job's
    // origin. Read before the body is, since that consumes the reader.
    let ua_hdr = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("User-Agent"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default();
    // Tier tracking: the facade is FULL only for the primary apikey (or a
    // keyless/open install). A caller presenting the add-only nzbkey gets
    // the same restricted surface as the /api add-only tier - otherwise
    // /jsonrpc is a side door around it, escalating an add-only key to
    // editqueue/pause/rate/config (GroupFinalDelete wipes the queue).
    // The tier itself is decided ONLY by the post-body snapshot below;
    // this pre-body pass exists to reject an unauthenticated caller
    // before we read a 256 MiB body for them.
    let full_auth;
    if !keys.is_empty() {
        // auth_credentials, not strip_prefix("Basic "): the scheme token
        // is case-insensitive per RFC 7235 (Codex sweep 12 Aug F18).
        let cred_pw = auth_credentials(&req, "basic")
            .and_then(|b| b64_decode(&b))
            .and_then(|raw| String::from_utf8(raw).ok())
            .and_then(|cred| cred.split_once(':').map(|(_, p)| p.to_string()))
            .or_else(|| path_pw.map(str::to_string));
        // ct_eq, matching every other auth comparison in this file (/api,
        // /stream, /getnzb, /newznab). This facade was the one that stayed on
        // `==`, which short-circuits on the first differing byte.
        let matched = cred_pw
            .as_deref()
            .is_some_and(|p| keys.iter().any(|k| ct_eq(p, k)));
        if !matched {
            if d.note_auth_failure(peer_ip(&req), "basic auth") {
                let _ = req.respond(
                    tiny_http::Response::from_string("too many bad keys").with_status_code(429),
                );
                return;
            }
            let _ = req.respond(
                tiny_http::Response::from_string("Unauthorized")
                    .with_status_code(401)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"WWW-Authenticate"[..],
                            &b"Basic realm=\"nzbfast\""[..],
                        )
                        .unwrap(),
                    ),
            );
            return;
        }
    }
    // NZBGet's append carries the whole NZB base64-encoded in the params,
    // so this one needs a big-file cap, not a JSON-sized one.
    // The hold keeps the budget reservation alive through the parse and
    // dispatch below, not just the read - see [`BodyHold`].
    let (raw, _body_hold) = read_body_capped_hold(req.as_reader(), 256 << 20);
    // Re-decide against the key as of NOW, not as of the request line.
    // That body is client-paced: a caller authenticated with key A can
    // stream whitespace, wait out a rotation to key B, and only then
    // finish a destructive editqueue - executing on a credential the
    // owner has already revoked. `/api` re-reads after its body for
    // exactly this reason, and the manual promises rotation takes
    // effect immediately. The tier is re-derived too, so a key demoted
    // from full to add-only mid-body cannot keep its old reach.
    //
    // UNCONDITIONAL, including the empty-to-non-empty transition (Codex
    // sweep 3 Aug H4): this used to run only when the request-START key
    // list was non-empty, so an install that was open when the request
    // line arrived kept full_auth=true even if the owner set the very
    // first key while the body was stalled - the anonymous request then
    // completed as full admin against a now-keyed daemon.
    {
        let now_apikey = d.apikey.lock_ok().clone();
        let now_nzbkey = d.nzbkey.lock_ok().clone();
        let now_keys: Vec<&str> = [now_apikey.as_deref(), now_nzbkey.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        // auth_credentials, not strip_prefix("Basic "): the scheme token
        // is case-insensitive per RFC 7235 (Codex sweep 12 Aug F18).
        let cred_pw = auth_credentials(&req, "basic")
            .and_then(|b| b64_decode(&b))
            .and_then(|raw| String::from_utf8(raw).ok())
            .and_then(|cred| cred.split_once(':').map(|(_, p)| p.to_string()))
            .or_else(|| path_pw.map(str::to_string));
        // Still open right now: no key exists, so the surface stays
        // open exactly as it was at the request line.
        if now_keys.is_empty() {
            full_auth = true;
        } else {
            let still_ok = cred_pw
                .as_deref()
                .is_some_and(|p| now_keys.iter().any(|k| ct_eq(p, k)));
            if !still_ok {
                let _ = req.respond(
                    tiny_http::Response::from_string("Unauthorized")
                        .with_status_code(401)
                        .with_header(
                            tiny_http::Header::from_bytes(
                                &b"WWW-Authenticate"[..],
                                &b"Basic realm=\"nzbfast\""[..],
                            )
                            .unwrap(),
                        ),
                );
                return;
            }
            full_auth = now_apikey
                .as_deref()
                .is_some_and(|ak| cred_pw.as_deref().is_some_and(|p| ct_eq(p, ak)));
        }
    }
    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    // Method from the body, or from a GET /jsonrpc/<method> path. The
    // path may carry a leading `/<user>:<pass>` credential segment, so
    // the method is whatever FOLLOWS the "jsonrpc" segment rather than
    // a fixed position from the front.
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            let mut seg = req.url().split('/').skip_while(|s| *s != "jsonrpc");
            seg.next(); // the "jsonrpc" segment itself
            seg.next()
                .map(|m| m.split('?').next().unwrap_or(m).to_string())
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    let params = body
        .get("params")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let id = body.get("id").cloned().unwrap_or(json!(1));

    // Add-only tier (nzbkey): mirror the /api add_only allowlist. Only
    // adding a job and the harmless read methods a client polls after an
    // append are permitted; anything that mutates the queue/config/rate is
    // full-key only. Keep this list tight - it is the security boundary.
    const ADD_ONLY_JSONRPC: &[&str] = &["append", "version", "status"];
    if !full_auth && !ADD_ONLY_JSONRPC.contains(&method.as_str()) {
        let _ = req.respond(
            tiny_http::Response::from_string(
                "Forbidden: this method requires the full API key, not the add-only key",
            )
            .with_status_code(403),
        );
        return;
    }

    let unix_now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    };
    // Set by any arm that cannot honour the call; turns the reply into a
    // JSON-RPC error instead of a result.
    let mut rpc_error: Option<String> = None;
    let result: Value = match method.as_str() {
        "version" => json!("21.0"),
        "status" => jr_status(d),
        "listgroups" => jr_listgroups(d),
        "history" => jr_history(d),
        "pausedownload" | "pausedownload2" => {
            timed_pause(d, 0, true); // remote-app pause winds down gracefully
            json!(true)
        }
        "resumedownload" | "resumedownload2" => {
            set_paused_cancel_timer(d, false);
            persist_pause(d);
            json!(true)
        }
        // NZBGet's "resume in N seconds". LunaSea's pause-for dialog is
        // pausedownload followed by this, so without it the app pauses
        // the queue and then reports the whole operation as failed -
        // leaving the user paused with no timer they asked for (§18).
        // The timer only fires if no manual pause/resume lands in
        // between, same as SAB's set_pause.
        "scheduleresume" => {
            let secs = params.first().and_then(Value::as_u64).unwrap_or(0);
            arm_pause_timer(d, std::time::Duration::from_secs(secs));
            json!(true)
        }
        "rate" => {
            // NZBGet rate is KB/s; 0 = unlimited.
            let kb = params.first().and_then(Value::as_u64).unwrap_or(0);
            d.set_speed_ceiling_from(kb.saturating_mul(1024), "api");
            json!(true)
        }
        "append" => jr_append(d, &params, &ua_hdr),
        "editqueue" => jr_editqueue(d, &params, &mut rpc_error),
        // TODO 274 built the per-file listing the SAB side now serves
        // as `mode=get_files`, and this arm STAYS an empty list rather
        // than being filled from it. NZBGet's file handle is an integer
        // in a queue-wide namespace, and the same integer is what its
        // `editqueue` File* commands take - none of which this facade
        // implements. Minting integers for a listing whose ids no
        // command here accepts hands a client rows it cannot act on and
        // a namespace we would then have to keep stable across
        // restarts; the empty list is at least an honest answer to
        // "what can I do per file over JSON-RPC", which is nothing.
        "listfiles" => json!([]),
        "postqueue" => json!([]),
        // We have one pause, covering the whole pipeline - there is no
        // separate post-processing or scan queue to hold. Answering true
        // is honest for a caller asking us to stop doing that work.
        "pausepost" | "resumepost" | "pausescan" | "resumescan" => json!(true),
        "servervolumes" => json!([]),
        "log" | "loadlog" => {
            let n = params.get(1).and_then(Value::as_u64).unwrap_or(100) as usize;
            // §163 item 5: scrubbed on the way out. This tail used to go
            // into the response verbatim, which made it the one door
            // every credential that reached the ring by some path we did
            // not guard could leave by - and it is a door remote apps
            // call over the network.
            let lines = super::logscrub::LogScrub::new(d).tail(nzbkit::logtee::tail(n.min(1000)));
            let now = unix_now();
            let entries: Vec<Value> = lines
                .iter()
                .enumerate()
                .map(|(i, l)| json!({"ID": i as u64 + 1, "Kind": "INFO", "Time": now, "Text": l}))
                .collect();
            json!(entries)
        }
        "writelog" | "scanupdate" | "resetservervolume" => json!(true),
        "config" | "loadconfig" => jr_config(d, &mut rpc_error),
        other => {
            // A null result is indistinguishable from "succeeded, nothing
            // to report", so an unimplemented method looked like a
            // working one that had no answer. JSON-RPC has a code for
            // this and NZBGet itself uses it.
            rpc_error = Some(format!("no such method {other:?}"));
            Value::Null
        }
    };
    let resp = match rpc_error {
        Some(message) => json!({
            "version": "1.1",
            "result": Value::Null,
            "error": {"name": "JSONRPCError", "code": -32601, "message": message},
            "id": id,
        }),
        None => json!({"version": "1.1", "result": result, "error": Value::Null, "id": id}),
    };
    let _ = req.respond(json_resp(resp));
}

#[cfg(test)]
mod tail_truth_tests;

#[cfg(test)]
mod delete_durability_tests;

// Unix-gated at the declaration: its one test forces the unlink
// refusal with a read-only directory, which Windows mode bits do not
// express - on Windows the file's import and fixture are dead code and
// windows-clippy's -D warnings reds on them.
#[cfg(all(test, unix))]
mod history_custody_tests;
