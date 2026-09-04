//! Historical pre seed: fill the predb table with pres from BEFORE the
//! live feed was switched on, so the correlation backlog can name posts
//! that are already indexed.
//!
//! Source: api.predb.net (probed live 1 Aug 2026 - clean JSON, unix
//! `pretime`, `section`, `size` in MB, `files`; the design's primary
//! candidate pre.corrupt-net.org answered 502 on every probe). The API
//! pages newest-first, 100 rows a page, and caps the UNFILTERED walk at
//! roughly a week of history - but a `section=` filter gets its own
//! page budget, so the quieter video sections reach much further back
//! per page. Hence the two phases below: one unfiltered walk (recent
//! everything + section discovery), then one walk per video section.
//! Both are two pages deep now, so this is a top-up of what is newest,
//! not the 180-day sweep it once was - see `PAGES_PER_WALK`.
//!
//! Manners are constants, not settings, because the correct value is
//! "polite" and politeness is not a user preference: one request per
//! 6 s, a two-page budget per walk, an honest UA, `tag=-foreign` so a
//! fixed budget spends itself on rows this index can use, and any
//! 429/403 ends the run on the spot with a cooling stamp that honours
//! `Retry-After` and is never shorter than 6 h. Never triggered in the
//! background - a Settings action or the API starts it, once.
//!
//! Re-paced 2 Sep 2026. Until then this walked 100 pages per section
//! over ~12 sections at one request per 2 s, which is 30 requests per
//! 60 s - the API's published ceiling, exactly - and one measured run
//! (E1, 9 Aug 2026) put 905 requests on the wire. The operator's
//! documentation asks for neither of those things; the quotation is on
//! `PACE_MS` below, and `research/PRE-FEED-SURVEY-2026-09-02.md` has
//! the reading. The open question this code does NOT settle is whether
//! a desktop application polling at all is inside their "don't create
//! your own DB" line; until somebody asks them, this is the smallest
//! shape that still does something.

use crate::tools::MutexExt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tracing::{info, warn};

use super::daemon::Daemon;

pub const BASE: &str = "https://api.predb.net/";
const UA: &str = concat!("nzbfast-predb-seed/", env!("CARGO_PKG_VERSION"));
/// The API's documented `tag` filter, asking it to leave out releases
/// tagged as non-English. Measured on one page of TV-HD-X264 (2 Sep
/// 2026) before being relied on: 0 of 100 rows carried a
/// foreign-language tag against 20 of 100 without it, same newest row,
/// 80 rows in common. So it does what the docs say, and under a fixed
/// page budget it spends the budget on rows this index can actually
/// match rather than on a European scene feed. Plain ASCII, so it goes
/// into the query string as it stands.
const TAG_ENGLISH_ONLY: &str = "-foreign";
/// One request per this many milliseconds, everywhere, no exceptions.
///
/// predb.net's API documentation (<https://predb.net/api-documentation/>,
/// page dated 08.08.2025) publishes a ceiling and, in the same breath,
/// asks that nobody run up against it:
///
/// > Treat this API respectfully, it runs on a simple server with
/// > limited ressources. Your IP will be blocked if you overload the
/// > API. And yes, I check the logs!
/// > Don't use the API to create your own DB. It makes more sense to
/// > import another dump.
/// > Rate limit: 30/60s
/// > The results are hard limited to 100 pages. This won't be modified.
///
/// 6 s is at most 10 requests a minute: a third of the published
/// 30/60s. The old 2 s was 30/60s to the millisecond, i.e. the number
/// the operator describes as the point at which they block you. There
/// is deliberately no setting that raises this back - a knob whose
/// only use is to be less polite to somebody else's server is not a
/// preference worth offering.
pub const PACE_MS: u64 = 6_000;
/// Pages per walk, per run. The API's own depth limit is 100 pages -
/// past it the server answers HTTP 400 (measured on the first live
/// run; the probe session had seen empty 200s, so both shapes must
/// read as "walked off the end", never as an error, and that handling
/// stays even though this budget no longer reaches the edge).
///
/// Two pages is ~200 rows per section, which caps a whole run at
/// `1 + VIDEO_SECTIONS.len()` walks x 2 requests. Asking for all 100
/// pages of every section, as this did until 2 Sep 2026, is up to
/// 1,300 requests for one button press against a source whose operator
/// asks people not to build a database out of it.
///
/// The consequence, stated plainly because it is a real loss: a run can
/// no longer reach the 180-day window `predb_seed_days` names. That
/// setting still bounds the walk from the older end; the page budget is
/// simply what stops it first now, and the Settings copy says so.
/// Deepening the reach again would mean a resume cursor that walks
/// further on every run, which IS assembling a local copy of their
/// database - the exact thing the quoted terms ask us not to do. Do not
/// add one without an answer from the operator.
const PAGES_PER_WALK: u32 = 2;
/// The feed table's cap when nothing says otherwise - the `predb_max_rows`
/// setting owns it at runtime, and the prune and this importer read the
/// same number on purpose: a cap the importer does not know about is a
/// cap that imports rows the next prune silently eats.
pub const PREDB_MAX_ROWS_DEFAULT: u64 = 250_000;
/// Bounds on that setting. The floor keeps a feed table big enough to be
/// worth having; the ceiling is the point past which a "pre database" is
/// a research project, not a naming aid.
pub(super) const PREDB_MAX_ROWS_MIN: u64 = 10_000;
pub(super) const PREDB_MAX_ROWS_MAX: u64 = 5_000_000;
/// Default history window for a seed import that does not name one.
pub const PREDB_SEED_DAYS_DEFAULT: u64 = 180;
/// Headroom the live feed keeps growing into, as a fraction of the cap.
/// A fraction rather than a constant so raising the cap raises the room
/// with it - at the 250k default this is the 50k it has always been.
fn headroom(cap: u64) -> u64 {
    cap / 5
}
/// A 429/403 marks the source cooling for at least this long.
pub const COOL_SECS: i64 = 6 * 3_600;
/// The longest `Retry-After` honoured verbatim. Past a day the header
/// is likelier a mistake than an instruction, and the run has ended
/// either way - the stamp only decides when the next one may start.
const RETRY_AFTER_MAX_SECS: i64 = 24 * 3_600;
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
    // Added 2 Sep 2026: the pre-feed survey measured them and this
    // list did not have them. TV-HD-X264 is the cleanest English-TV
    // section on this API - a probe page read 43/100 sized and 20/100
    // foreign-tagged over 27.7 h, where the TV-X264 already above is
    // 5/100 sized and 68/100 foreign. TV-HD-X265 is quiet (20/100
    // sized, a 79-day page span) but answers with rows, so it stays.
    // Both were verified with one paced request each before landing;
    // a section that comes back EMPTY costs one request every run and
    // belongs off this list, never left in to be rediscovered.
    "TV-HD-X264",
    "TV-HD-X265",
    "TV-WEB-X264",
    "TV-WEB-HD-X264",
    "TV-WEB-HD-X265",
    "BLURAY",
    "SPORTS",
    "DVDR",
    "XVID",
];

/// One row as the API sends it, already reduced to what we store.
pub struct SeedRow {
    line: nzbkit::predb::PreLine,
    pretime: i64,
}

/// Everything the seed walk needs from the world around it.
///
/// The daemon supplies one of these. So does the `predb-seed` CLI
/// subcommand, which has an `Index` and no daemon at all - and that is
/// the point: the alternative to this trait was a second importer that
/// drifted from this one the first time either changed.
pub trait SeedSink {
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
        self.0.predb.max_rows.load(Ordering::Relaxed)
    }
    fn say(&self, what: &str) {
        *self.0.predb.seed_status.lock_ok() = what.to_string();
    }
}

/// Start an import on its own thread. `false` = one is already running
/// or the source is cooling; the status string says which.
pub fn spawn_seed_import(daemon: Arc<Daemon>, days: u32) -> bool {
    let sink = DaemonSink(daemon.clone());
    if !crate::identity::may_call_out() {
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
    if daemon.predb.seed_running.swap(true, Ordering::SeqCst) {
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
            daemon.predb.seed_running.store(false, Ordering::SeqCst);
        })
        .expect("spawn predb-seed thread");
    true
}

/// When the source last told us to go away, if it did.
fn cooling_until(sink: &dyn SeedSink) -> Option<i64> {
    sink.kv_get("predb_seed_cooling")
        .and_then(|v| v.parse::<i64>().ok())
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0)
}

pub fn run(sink: &dyn SeedSink, days: u32) -> Result<String, String> {
    let agent = crate::ssrf_safe_agent(0, 30);
    let now = unix_now();
    // Fetch down past the oldest post the correlation window can use:
    // a post at the window edge still wants pres up to 14 d older.
    let floor = now - i64::from(days.max(1)) * 86_400 - nzbkit::predb_corr::DELTA_MAX;
    let mut requests = 0u32;
    let mut stored = 0usize;
    let mut oldest_seen = now;

    // Phase A: the unfiltered walk. The newest rows across every
    // section, and where phase B's section list picks up names this
    // file does not hard-code.
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

    // Phase B: one walk per video section, oldest useful time as the
    // floor - though at two pages a walk the page budget is usually
    // what stops it. Sections the API does not know come back empty.
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
pub fn walk(
    sink: &dyn SeedSink,
    agent: &ureq::Agent,
    section: Option<&str>,
    floor: i64,
    requests: &mut u32,
    oldest_seen: &mut i64,
    mut keep: impl FnMut(SeedRow),
) -> Result<(), String> {
    for page in 1..=PAGES_PER_WALK {
        std::thread::sleep(Duration::from_millis(PACE_MS));
        let mut url = format!("{BASE}?limit=100&page={page}&tag={TAG_ENGLISH_ONLY}");
        if let Some(s) = section {
            url.push_str("&section=");
            url.push_str(&urlencode(s));
        }
        *requests += 1;
        let rows = match fetch_page(agent, &url) {
            Ok(rows) => rows,
            Err(FetchErr::End) => return Ok(()),
            Err(FetchErr::Refused { code, retry_after }) => {
                // Honour Retry-After, but never let it SHORTEN the
                // back-off: 6 h is our own manners floor and the header
                // is the source asking for MORE than that, not less.
                let cool = cool_secs(retry_after);
                sink.kv_set("predb_seed_cooling", &(unix_now() + cool).to_string());
                return Err(format!(
                    "the source answered {code} - cooling off for {} min",
                    cool / 60
                ));
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

pub fn flush(
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
    /// 429/403: told to go away. Ends the run and stamps the cooldown,
    /// for `retry_after` seconds when the source named a number.
    Refused { code: u16, retry_after: Option<i64> },
    /// The far edge of the source's paging depth: end this walk,
    /// nothing wrong.
    End,
    /// Everything else worth one retry.
    Transient(String),
}

/// `Retry-After` read as delta-seconds, when the refusal carried one.
///
/// The HTTP-date form is legal and ignored on purpose: the fallback is
/// already 6 h, longer than any date form a rate limiter realistically
/// sends, and a clock-skewed date parse that SHORTENS the wait is worse
/// than no parse at all.
fn retry_after_secs(resp: &ureq::Response) -> Option<i64> {
    parse_retry_after(resp.header("Retry-After")?)
}

/// The header's delta-seconds form, clamped. Split out from the
/// response so it can be tested without one.
fn parse_retry_after(raw: &str) -> Option<i64> {
    let secs: i64 = raw.trim().parse().ok()?;
    (secs > 0).then_some(secs.min(RETRY_AFTER_MAX_SECS))
}

/// How long a refusal parks the source for: what it asked for, floored
/// at our own manners minimum. A header may lengthen the wait, never
/// shorten it.
fn cool_secs(retry_after: Option<i64>) -> i64 {
    retry_after.unwrap_or(0).max(COOL_SECS)
}

fn fetch_page(agent: &ureq::Agent, url: &str) -> Result<Vec<SeedRow>, FetchErr> {
    let resp = agent
        .get(url)
        .set("User-Agent", UA)
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code @ (403 | 429), resp) => FetchErr::Refused {
                code,
                retry_after: retry_after_secs(&resp),
            },
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
pub fn urlencode(s: &str) -> String {
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
pub fn run_cli(db: &std::path::Path, days: u32, cap: u64) -> Result<String, String> {
    // CLAUDE.md invariant 5, and the same answer the daemon's button
    // gives: the gate that fences every other outbound call fences this
    // one too, so a test or a sandboxed run cannot put requests on the
    // wire by reaching for the CLI instead.
    if !crate::identity::may_call_out() {
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

    /// The manners this importer owes api.predb.net, pinned so raising
    /// one is a deliberate act with a test to answer to rather than a
    /// one-character edit. The operator's own words are quoted on
    /// `PACE_MS`; the numbers below are the shape those words describe.
    #[test]
    fn the_walk_stays_well_under_the_published_rate_limit() {
        // Published ceiling: 30 requests per 60 s. Ours, in the same
        // unit, must leave real room under it - not sit on it, which is
        // what one request per 2 s did until 2 Sep 2026.
        let per_min = 60_000 / PACE_MS;
        assert!(
            per_min <= 10,
            "pace of {PACE_MS} ms is {per_min}/min against a published 30/60s ceiling"
        );
        // And the whole run is bounded: phase A plus one walk per
        // section, PAGES_PER_WALK each. The measured old run was 905
        // requests; this holds the new shape near two orders below it.
        let walks = 1 + VIDEO_SECTIONS.len() as u32;
        let max_requests = walks * PAGES_PER_WALK;
        assert!(
            max_requests <= 64,
            "a run can make {max_requests} requests ({walks} walks x {PAGES_PER_WALK} pages)"
        );
        // Sections are asked for by name, so a duplicate is a wasted
        // request every single run.
        let mut seen = VIDEO_SECTIONS.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), VIDEO_SECTIONS.len(), "duplicate video section");
    }

    /// A 429 may ask for LONGER than our own cooling window; it may
    /// never talk us into a shorter one, and a header we cannot read is
    /// the full 6 h rather than no wait at all.
    #[test]
    fn retry_after_lengthens_the_cooling_window_but_never_shortens_it() {
        assert_eq!(parse_retry_after("120"), Some(120));
        assert_eq!(parse_retry_after("  120  "), Some(120));
        assert_eq!(parse_retry_after("0"), None);
        assert_eq!(parse_retry_after("-5"), None);
        // The HTTP-date form is legal and deliberately unparsed.
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        // Clamped, so a nonsense header cannot park the source forever.
        assert_eq!(
            parse_retry_after("99999999"),
            Some(RETRY_AFTER_MAX_SECS),
            "an absurd Retry-After must clamp"
        );
        assert_eq!(cool_secs(None), COOL_SECS);
        assert_eq!(
            cool_secs(Some(60)),
            COOL_SECS,
            "a short header must not win"
        );
        assert_eq!(cool_secs(Some(COOL_SECS + 60)), COOL_SECS + 60);
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
