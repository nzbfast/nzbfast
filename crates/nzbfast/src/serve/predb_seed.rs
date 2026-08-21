//! Historical pre seed: fill the predb table with pres from BEFORE the
//! live feed was switched on, so the correlation backlog can name posts
//! that are already indexed.
//!
//! Source: api.predb.net (probed live 1 Aug 2026 - clean JSON, unix
//! `pretime`, `section`, `size` in MB, `files`; the design's primary
//! candidate pre.corrupt-net.org answered 502 on every probe). The API
//! pages newest-first, 100 rows a page, and caps the UNFILTERED walk at
//! roughly a week of history - but a `section=` filter gets its own
//! page budget, which for the video sections stretches the reachable
//! window past the 180-day seed target. Hence the two phases below:
//! one shallow unfiltered walk (recent everything + section discovery),
//! then a deep walk per video section.
//!
//! Manners are constants, not settings, because the correct value is
//! "polite": one request per 2 s, an honest UA, and any 429/403 ends
//! the run on the spot with a 6 h cooling stamp. Never triggered in the
//! background - a Settings action or the API starts it, once.

use crate::MutexExt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tracing::{info, warn};

use super::daemon::Daemon;

const BASE: &str = "https://api.predb.net/";
const UA: &str = concat!("nzbfast-predb-seed/", env!("CARGO_PKG_VERSION"));
/// One request per this many milliseconds, everywhere, no exceptions.
const PACE_MS: u64 = 2_000;
/// Pages per walk. The API's own depth limit is 100 pages - past it
/// the server answers HTTP 400 (measured on the first live run; the
/// probe session had seen empty 200s, so both shapes must read as
/// "walked off the end", never as an error).
const MAX_PAGES: u32 = 100;
/// The feed table's cap when nothing says otherwise - the `predb_max_rows`
/// setting owns it at runtime, and the prune and this importer read the
/// same number on purpose: a cap the importer does not know about is a
/// cap that imports rows the next prune silently eats.
pub(super) const PREDB_MAX_ROWS_DEFAULT: u64 = 250_000;
/// Bounds on that setting. The floor keeps a feed table big enough to be
/// worth having; the ceiling is the point past which a "pre database" is
/// a research project, not a naming aid.
pub(super) const PREDB_MAX_ROWS_MIN: u64 = 10_000;
pub(super) const PREDB_MAX_ROWS_MAX: u64 = 5_000_000;
/// Default history window for a seed import that does not name one.
pub(super) const PREDB_SEED_DAYS_DEFAULT: u64 = 180;
/// Headroom the live feed keeps growing into, as a fraction of the cap.
/// A fraction rather than a constant so raising the cap raises the room
/// with it - at the 250k default this is the 50k it has always been.
fn headroom(cap: u64) -> u64 {
    cap / 5
}
/// A 429/403 marks the source cooling for this long.
const COOL_SECS: i64 = 6 * 3_600;
/// predb.net sizes are MB. Scene tooling means binary MB.
const MB: f64 = 1024.0 * 1024.0;

/// Sections the deep walk always tries even if the shallow walk did
/// not happen to see them this week. Quiet sections cost one request to
/// discover as empty.
const VIDEO_SECTIONS: &[&str] = &[
    "X264",
    "X264-HD",
    "X264-SD",
    "X265",
    "X265-HD",
    "TV-X264",
    "TV-WEB-X264",
    "TV-WEB-HD-X264",
    "TV-WEB-HD-X265",
    "BLURAY",
    "SPORTS",
    "DVDR",
    "XVID",
];

/// One row as the API sends it, already reduced to what we store.
struct SeedRow {
    line: nzbkit::predb::PreLine,
    pretime: i64,
}

/// Everything the seed walk needs from the world around it.
///
/// The daemon supplies one of these. So does the `predb-seed` CLI
/// subcommand, which has an `Index` and no daemon at all - and that is
/// the point: the alternative to this trait was a second importer that
/// drifted from this one the first time either changed.
pub(crate) trait SeedSink {
    fn kv_get(&self, k: &str) -> Option<String>;
    fn kv_set(&self, k: &str, v: &str);
    /// Rows actually stored, or `None` when the index was unavailable
    /// (switched off, or locked) - which is a stop, not a zero.
    fn store(&self, lines: &[nzbkit::predb::PreLine], now: i64) -> Option<usize>;
    /// Pre rows currently held, for the cap check.
    fn rows(&self) -> u64;
    /// The `predb_max_rows` cap this run must respect.
    fn cap(&self) -> u64;
    /// Progress, for whoever is watching (a settings card, a terminal).
    fn say(&self, what: &str);
}

/// The daemon's sink: the index behind its lock, and the status string
/// the settings card reads.
struct DaemonSink(Arc<Daemon>);

impl SeedSink for DaemonSink {
    fn kv_get(&self, k: &str) -> Option<String> {
        self.0.with_index(|ix| ix.kv_get(k))
    }
    fn kv_set(&self, k: &str, v: &str) {
        self.0.with_index_mut(|ix| ix.kv_set(k, v).ok());
    }
    fn store(&self, lines: &[nzbkit::predb::PreLine], now: i64) -> Option<usize> {
        // retiring_ddl: a first seed import builds the named-count
        // index - same schema event as the live feed's first batch.
        self.0.with_index_mut_retiring_ddl(|ix| {
            ix.predb_seed_store(lines, "seed:predb.net", now).ok()
        })
    }
    fn rows(&self) -> u64 {
        self.0
            .with_index(|ix| ix.predb_stats().ok())
            .map(|(rows, _)| rows)
            .unwrap_or(0)
    }
    fn cap(&self) -> u64 {
        self.0.predb_max_rows.load(Ordering::Relaxed)
    }
    fn say(&self, what: &str) {
        *self.0.predb_seed_status.lock_ok() = what.to_string();
    }
}

/// Start an import on its own thread. `false` = one is already running
/// or the source is cooling; the status string says which.
pub(super) fn spawn_seed_import(daemon: Arc<Daemon>, days: u32) -> bool {
    let sink = DaemonSink(daemon.clone());
    if std::env::var_os("NZBFAST_NO_ENRICH").is_some() {
        sink.say("disabled by NZBFAST_NO_ENRICH");
        return false;
    }
    let now = unix_now();
    if let Some(until) = cooling_until(&sink)
        && now < until
    {
        sink.say(&format!(
            "source asked us to back off - try again in {} min",
            (until - now) / 60
        ));
        return false;
    }
    if daemon.predb_seed_running.swap(true, Ordering::SeqCst) {
        return false;
    }
    std::thread::Builder::new()
        .name("predb-seed".into())
        .spawn(move || {
            let sink = DaemonSink(daemon.clone());
            let _busy = daemon.busy.hold("predb");
            match run(&sink, days) {
                Ok(msg) => {
                    info!(target: "predb", "seed import done: {msg}");
                    sink.say(&msg);
                }
                Err(e) => {
                    warn!(target: "predb", "seed import stopped: {e}");
                    sink.say(&format!("stopped: {e}"));
                }
            }
            daemon.predb_seed_running.store(false, Ordering::SeqCst);
        })
        .expect("spawn predb-seed thread");
    true
}

/// When the source last told us to go away, if it did.
fn cooling_until(sink: &dyn SeedSink) -> Option<i64> {
    sink.kv_get("predb_seed_cooling")
        .and_then(|v| v.parse::<i64>().ok())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0)
}

fn run(sink: &dyn SeedSink, days: u32) -> Result<String, String> {
    let agent = crate::serve::ssrf_safe_agent(0, 30);
    let now = unix_now();
    // Fetch down past the oldest post the correlation window can use:
    // a post at the window edge still wants pres up to 14 d older.
    let floor = now - i64::from(days.max(1)) * 86_400 - nzbkit::predb_corr::DELTA_MAX;
    let mut requests = 0u32;
    let mut stored = 0usize;
    let mut oldest_seen = now;

    // Phase A: the unfiltered walk. Covers every section for the week
    // or so the API reaches without a filter, and discovers the section
    // names for phase B.
    let mut sections: Vec<String> = VIDEO_SECTIONS.iter().map(|s| s.to_string()).collect();
    let mut batch: Vec<nzbkit::predb::PreLine> = Vec::new();
    walk(
        sink,
        &agent,
        None,
        floor,
        &mut requests,
        &mut oldest_seen,
        |row| {
            let sec = row.line.category.clone();
            if !sec.is_empty() && !sections.iter().any(|s| s.eq_ignore_ascii_case(&sec)) {
                // Discovered section: phase B walks it iff it is video.
                if nzbkit::predb_corr::section_class(&sec) == nzbkit::predb_corr::GroupKind::Video {
                    sections.push(sec);
                }
            }
            batch.push(row.line);
        },
    )?;
    stored += flush(sink, &mut batch, "recent")?;

    // Phase B: one deep walk per video section, oldest useful time as
    // the floor. Sections the API does not know just come back empty.
    for sec in &sections {
        cap_check(sink, stored)?;
        sink.say(&format!(
            "importing {sec} ({stored} pres so far, {requests} requests)"
        ));
        walk(
            sink,
            &agent,
            Some(sec),
            floor,
            &mut requests,
            &mut oldest_seen,
            |row| {
                batch.push(row.line);
            },
        )?;
        stored += flush(sink, &mut batch, sec)?;
    }

    // The generation bump is what re-opens the correlation backlog
    // cursor - the one event that makes re-walking the index worth it.
    let g: u64 = sink
        .kv_get("predb_seed_gen")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    sink.kv_set("predb_seed_gen", &(g + 1).to_string());
    let days_reached = (now - oldest_seen) / 86_400;
    Ok(format!(
        "{stored} pres imported ({requests} requests, back {days_reached} day(s)); correlation backlog re-opened"
    ))
}

/// Page one walk (unfiltered or one section) down to `floor`, feeding
/// kept rows to `keep`. Stops on empty page, floor reached, page cap,
/// or a source refusal (which also stamps the cooling window).
fn walk(
    sink: &dyn SeedSink,
    agent: &ureq::Agent,
    section: Option<&str>,
    floor: i64,
    requests: &mut u32,
    oldest_seen: &mut i64,
    mut keep: impl FnMut(SeedRow),
) -> Result<(), String> {
    for page in 1..=MAX_PAGES {
        std::thread::sleep(Duration::from_millis(PACE_MS));
        let mut url = format!("{BASE}?limit=100&page={page}");
        if let Some(s) = section {
            url.push_str("&section=");
            url.push_str(&urlencode(s));
        }
        *requests += 1;
        let rows = match fetch_page(agent, &url) {
            Ok(rows) => rows,
            Err(FetchErr::End) => return Ok(()),
            Err(FetchErr::Refused(code)) => {
                let until = unix_now() + COOL_SECS;
                sink.kv_set("predb_seed_cooling", &until.to_string());
                return Err(format!("the source answered {code} - cooling off for 6 h"));
            }
            Err(FetchErr::Transient(e)) => {
                // One retry, gently, then give up on the run. The
                // resumable part is the idempotent upsert: a re-run
                // re-covers cheaply.
                std::thread::sleep(Duration::from_secs(10));
                *requests += 1;
                match fetch_page(agent, &url) {
                    Ok(rows) => rows,
                    Err(_) => return Err(format!("{e} (and the retry failed)")),
                }
            }
        };
        if rows.is_empty() {
            return Ok(());
        }
        let mut done = false;
        for row in rows {
            *oldest_seen = (*oldest_seen).min(row.pretime);
            if row.pretime < floor {
                done = true;
                continue;
            }
            keep(row);
        }
        if done {
            return Ok(());
        }
    }
    Ok(())
}

fn flush(
    sink: &dyn SeedSink,
    batch: &mut Vec<nzbkit::predb::PreLine>,
    what: &str,
) -> Result<usize, String> {
    if batch.is_empty() {
        return Ok(0);
    }
    let lines = std::mem::take(batch);
    let n = lines.len();
    let now = unix_now();
    sink.store(&lines, now)
        .ok_or_else(|| format!("index unavailable while storing {n} rows ({what})"))
}

fn cap_check(sink: &dyn SeedSink, _stored: usize) -> Result<(), String> {
    let rows = sink.rows();
    let cap = sink.cap();
    // The lookahead scales with the cap the same way `headroom` does
    // (cap/25 is the 10k it has always been at the 250k default). A
    // fixed 10_000 exceeded the entire usable budget at small caps -
    // at the documented PREDB_MAX_ROWS_MIN floor of 10k the budget is
    // 8k, so every import refused with an EMPTY table.
    if rows + cap / 25 > cap.saturating_sub(headroom(cap)) {
        return Err(format!(
            "the feed table holds {rows} rows - stopping short of the {cap} cap \
             rather than importing rows the prune would silently eat"
        ));
    }
    Ok(())
}

enum FetchErr {
    /// 429/403: told to go away. Ends the run and stamps the cooldown.
    Refused(u16),
    /// The far edge of the source's paging depth: end this walk,
    /// nothing wrong.
    End,
    /// Everything else worth one retry.
    Transient(String),
}

fn fetch_page(agent: &ureq::Agent, url: &str) -> Result<Vec<SeedRow>, FetchErr> {
    let resp = agent
        .get(url)
        .set("User-Agent", UA)
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code @ (403 | 429), _) => FetchErr::Refused(code),
            // Past the API's paging depth. Not an error: it is the
            // far edge of the walk, same as an empty page.
            ureq::Error::Status(400, _) => FetchErr::End,
            ureq::Error::Status(code, _) => FetchErr::Transient(format!("HTTP {code}")),
            ureq::Error::Transport(t) => FetchErr::Transient(t.to_string()),
        })?;
    let text = resp
        .into_string()
        .map_err(|e| FetchErr::Transient(format!("read body: {e}")))?;
    let body: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| FetchErr::Transient(format!("bad JSON: {e}")))?;
    let Some(data) = body.get("data").and_then(|d| d.as_array()) else {
        // A well-formed "no results" answer; deep pages do this.
        return Ok(Vec::new());
    };
    Ok(data.iter().filter_map(row_from_json).collect())
}

/// One API record -> the PreLine the seed store expects. Every field is
/// optional except the release name and the timestamp - a pre with no
/// time cannot feed a time-correlation leg, and the seed store would
/// refuse it anyway; skipping here keeps the batch counts honest.
fn row_from_json(v: &serde_json::Value) -> Option<SeedRow> {
    let title = v.get("release")?.as_str()?.trim();
    let pretime = v.get("pretime")?.as_i64().unwrap_or(0);
    if title.is_empty() || pretime <= 0 {
        return None;
    }
    // Placeholder-in-words guard, same predicate as the wire parser:
    // aggregator HTML says "N/A" in words too, and a stored placeholder
    // is permanent under non-empty-wins merge rules.
    let clean = |s: &str| {
        let t = s.trim();
        if nzbkit::predb::is_absent_marker(t) {
            ""
        } else {
            t
        }
        .to_string()
    };
    let size_mb = v.get("size").and_then(|s| s.as_f64()).unwrap_or(0.0);
    let reason = v
        .get("reason")
        .and_then(|r| r.as_str())
        .map(clean)
        .unwrap_or_default();
    let nuked = v.get("status").and_then(|s| s.as_i64()).unwrap_or(0) != 0 || !reason.is_empty();
    Some(SeedRow {
        pretime,
        line: nzbkit::predb::PreLine {
            kind: if nuked {
                nzbkit::predb::PreKind::Nuk
            } else {
                nzbkit::predb::PreKind::New
            },
            title: title.to_string(),
            category: v
                .get("section")
                .and_then(|s| s.as_str())
                .map(clean)
                .unwrap_or_default(),
            size: if size_mb > 0.0 {
                (size_mb * MB) as u64
            } else {
                0
            },
            files: v
                .get("files")
                .and_then(|f| f.as_i64())
                .unwrap_or(0)
                .clamp(0, u32::MAX as i64) as u32,
            date: pretime,
            nuke_reason: reason,
            ..Default::default()
        },
    })
}

/// Query-string escaping for the section parameter, which in practice
/// is ASCII letters, digits and dashes - but "in practice" is not a
/// contract.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The `predb-seed` subcommand's sink: one index opened directly, and
/// progress on stderr so a redirected stdout stays clean.
///
/// `RefCell` rather than a lock because there is exactly one thread
/// here - the daemon's sink is the one that needs the index's own
/// locking, and it has it.
struct CliSink {
    ix: std::cell::RefCell<nzbkit::index::Index>,
    cap: u64,
}

impl SeedSink for CliSink {
    fn kv_get(&self, k: &str) -> Option<String> {
        self.ix.borrow().kv_get(k)
    }
    fn kv_set(&self, k: &str, v: &str) {
        let _ = self.ix.borrow_mut().kv_set(k, v);
    }
    fn store(&self, lines: &[nzbkit::predb::PreLine], now: i64) -> Option<usize> {
        self.ix
            .borrow_mut()
            .predb_seed_store(lines, "seed:predb.net", now)
            .ok()
    }
    fn rows(&self) -> u64 {
        self.ix.borrow().predb_stats().map(|(r, _)| r).unwrap_or(0)
    }
    fn cap(&self) -> u64 {
        self.cap
    }
    fn say(&self, what: &str) {
        eprintln!("[predb-seed] {what}");
    }
}

/// One seed import against an index file, with no daemon in the way.
///
/// Same walk, same pacing, same refusals as the daemon's button: the
/// point of the sink trait is that this cannot drift into a second
/// importer. It bumps `predb_seed_gen` on success exactly as the daemon
/// does, so a daemon later opened on this file re-walks its correlation
/// backlog over the newly seeded pres.
pub(crate) fn run_cli(db: &std::path::Path, days: u32, cap: u64) -> Result<String, String> {
    // CLAUDE.md invariant 5, and the same answer the daemon's button
    // gives: the variable that fences every other outbound call fences
    // this one too, so a test or a sandboxed run cannot put requests on
    // the wire by reaching for the CLI instead.
    if std::env::var_os("NZBFAST_NO_ENRICH").is_some() {
        return Err("disabled by NZBFAST_NO_ENRICH".into());
    }
    let ix = nzbkit::index::Index::open(db).map_err(|e| format!("open {}: {e}", db.display()))?;
    let sink = CliSink {
        ix: std::cell::RefCell::new(ix),
        cap: cap.clamp(PREDB_MAX_ROWS_MIN, PREDB_MAX_ROWS_MAX),
    };
    let now = unix_now();
    if let Some(until) = cooling_until(&sink)
        && now < until
    {
        return Err(format!(
            "the source asked us to back off - try again in {} min",
            (until - now) / 60
        ));
    }
    run(&sink, days)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubSink {
        rows: u64,
        cap: u64,
    }
    impl SeedSink for StubSink {
        fn kv_get(&self, _k: &str) -> Option<String> {
            None
        }
        fn kv_set(&self, _k: &str, _v: &str) {}
        fn store(&self, lines: &[nzbkit::predb::PreLine], _now: i64) -> Option<usize> {
            Some(lines.len())
        }
        fn rows(&self) -> u64 {
            self.rows
        }
        fn cap(&self) -> u64 {
            self.cap
        }
        fn say(&self, _what: &str) {}
    }

    /// The fixed 10k lookahead exceeded the whole usable budget at small
    /// caps: at the documented PREDB_MAX_ROWS_MIN floor (10k) the budget
    /// is 8k, so every import refused with an EMPTY table. Proportional
    /// now - and unchanged at the 250k default (refuses past 190k).
    #[test]
    fn the_cap_check_admits_imports_at_the_floor() {
        let at_floor = StubSink {
            rows: 0,
            cap: PREDB_MAX_ROWS_MIN,
        };
        assert!(cap_check(&at_floor, 0).is_ok());
        // Near the floor cap's own budget it still refuses.
        let full_floor = StubSink {
            rows: 7_800,
            cap: PREDB_MAX_ROWS_MIN,
        };
        assert!(cap_check(&full_floor, 0).is_err());
        // The 250k default keeps its historical refusal point.
        let default_ok = StubSink {
            rows: 189_000,
            cap: PREDB_MAX_ROWS_DEFAULT,
        };
        assert!(cap_check(&default_ok, 0).is_ok());
        let default_full = StubSink {
            rows: 191_000,
            cap: PREDB_MAX_ROWS_DEFAULT,
        };
        assert!(cap_check(&default_full, 0).is_err());
    }
}
