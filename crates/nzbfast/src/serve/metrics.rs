//! `GET /metrics`: the daemon's state in Prometheus text exposition
//! format 0.0.4, hand-rendered.
//!
//! Hand-rendered, and no crate for it, deliberately. The format is
//! `# HELP`, `# TYPE` and one `name{labels} value` line per sample -
//! about a hundred lines of `write!` - against a dependency that would
//! have to clear `cargo deny` and would then own the registry every
//! call site in this daemon writes into. Every number below already
//! exists as a gauge somebody else maintains; this module reads them and
//! spells them out.
//!
//! ## What it may not do
//!
//! TODO 166: an HTTP worker must never park on the index write mutex,
//! because the realtime tip watcher holds it for a whole header-ingest
//! transaction (~80 s, measured 14 Aug 2026) and four workers queued
//! behind a 62 s hold is how one dashboard tab wedged the entire daemon
//! on 28 Jul. A scrape runs on a poll loop, so it is the WORST possible
//! caller to put behind that mutex: Prometheus would keep asking every
//! fifteen seconds forever. So nothing here touches the index at all -
//! not through a bounded door either. Index-derived figures are simply
//! not in the metric set, and `tools/index-lock-gate.py` refuses the
//! first one that tries.
//!
//! ## Units
//!
//! Base units only - bytes and seconds, never MB and never minutes -
//! which is both the Prometheus convention and the house one. A
//! dashboard converts; an exporter that pre-formats has thrown the
//! precision away before anyone can.
//!
//! ## Counter resets
//!
//! The per-server counters below belong to the RUN, not to the daemon:
//! `LiveStats` is replaced when a job hands over, so they go back to
//! zero. That is ordinary counter behaviour to Prometheus, which
//! assumes any drop is a restart and corrects for it in `rate()` - the
//! same thing it does when a process restarts. Their HELP text says so.
//! The gauges beside them (`connected`, `budget`, `down`) are levels and
//! are simply absent while nothing is downloading, because the live
//! gauges do not exist then.

use super::*;

/// `Content-Type` for text exposition format 0.0.4. The version
/// parameter is not decoration: a scraper reads it to decide which
/// parser to use, and Prometheus's own `text/plain` fallback assumes
/// 0.0.4 anyway - saying it explicitly is what makes the guess
/// unnecessary.
pub(super) const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The prefix every metric name in this file carries. One place, so a
/// family cannot be added under a different one by accident.
const NS: &str = "nzbfast";

/// A body under construction, with the one rule the format has that is
/// easy to break by hand: a metric NAME may be declared once. Prometheus
/// answers a repeated `# TYPE` with a parse error and drops the whole
/// scrape, so the second family silently costs you the first as well.
///
/// `family()` therefore records what it has declared and `sample()`
/// refuses a name that was never declared. Both are `debug_assert` plus
/// a skip: a metrics endpoint that panics takes the daemon's HTTP worker
/// with it, and no monitoring number is worth that.
struct Exposition {
    out: String,
    declared: Vec<String>,
}

impl Exposition {
    fn new() -> Self {
        Exposition {
            out: String::with_capacity(4096),
            declared: Vec::new(),
        }
    }

    /// Open a metric family: its `# HELP` and `# TYPE` lines. `name` is
    /// spelled WITHOUT the namespace, which is added here.
    ///
    /// A repeat is SKIPPED rather than asserted on. The two candidates
    /// were both worse: a panic here kills the HTTP worker that is
    /// serving the scrape, and no monitoring number is worth that, while
    /// emitting the second `# TYPE` is precisely the parse error this
    /// guard exists to prevent - Prometheus drops the WHOLE scrape on
    /// one, so the second family would cost you every family before it
    /// too. What holds the guard honest is the test side: the daemon
    /// suite parses a real body and refuses a repeated name, so a
    /// silently skipped family shows up as a missing series in a test
    /// rather than in production.
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let full = format!("{NS}_{name}");
        if self.declared.contains(&full) {
            return;
        }
        use std::fmt::Write as _;
        let _ = write!(
            self.out,
            "# HELP {full} {}\n# TYPE {full} {kind}\n",
            esc_help(help)
        );
        self.declared.push(full);
    }

    /// One sample of an already-declared family.
    ///
    /// A sample whose family was never opened is dropped, for the same
    /// reason: a bare `name value` line with no preceding `# TYPE` is
    /// legal to a parser but silently untyped, so it would arrive in
    /// Prometheus as an untyped series that nothing can `rate()`. Better
    /// absent, and pinned by the same test.
    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: &str) {
        let full = format!("{NS}_{name}");
        if !self.declared.contains(&full) {
            return;
        }
        use std::fmt::Write as _;
        let _ = write!(self.out, "{full}");
        if !labels.is_empty() {
            self.out.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.out.push(',');
                }
                let _ = write!(self.out, "{k}=\"{}\"", esc_label(v));
            }
            self.out.push('}');
        }
        let _ = writeln!(self.out, " {value}");
    }

    /// A family with exactly one unlabelled sample, which is most of
    /// them. Saves spelling the name twice and cannot get the two out of
    /// step.
    fn single(&mut self, name: &str, kind: &str, help: &str, value: &str) {
        self.family(name, kind, help);
        self.sample(name, &[], value);
    }
}

/// Escape a label VALUE per the exposition format: backslash, double
/// quote and newline. A provider hostname holds none of these today,
/// which is exactly why this has to be written now rather than the first
/// time one does.
fn esc_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape HELP text: backslash and newline only - a quote is ordinary
/// text on a HELP line, and escaping it would put a stray backslash in
/// front of every apostrophe-free quotation somebody writes later.
fn esc_help(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// A float as the exposition format wants it. Whole numbers print
/// without a fraction (so a count reads as a count), and the three
/// non-finite values have their own spellings - `format!("{}", f64::NAN)`
/// gives `NaN`, which is right by luck, and `inf`, which is not.
fn num(v: f64) -> String {
    if v.is_nan() {
        return "NaN".to_string();
    }
    if v.is_infinite() {
        return if v > 0.0 { "+Inf" } else { "-Inf" }.to_string();
    }
    if v == v.trunc() && v.abs() < 9e15 {
        return format!("{}", v as i64);
    }
    format!("{v:.6}")
}

/// A bool as the 1/0 Prometheus uses for a state gauge.
fn flag(b: bool) -> &'static str {
    if b { "1" } else { "0" }
}

/// Render the whole scrape.
///
/// Every read here is a lock this daemon takes on its ordinary polling
/// paths already (the dashboard reads all of them once a second), so a
/// scrape costs a scrape's worth of contention and no more. The two
/// collection loops each COPY out of their mutex and then let it go
/// before doing anything with the copy, so a slow render can never be
/// what a queue mutation is waiting behind.
pub(super) fn render(d: &Daemon) -> String {
    let mut e = Exposition::new();

    // --- Identity -----------------------------------------------
    e.family(
        "build_info",
        "gauge",
        "Build information; the value is always 1 and the labels carry the facts.",
    );
    e.sample(
        "build_info",
        &[
            ("version", env!("CARGO_PKG_VERSION")),
            ("os", std::env::consts::OS),
            ("arch", std::env::consts::ARCH),
        ],
        "1",
    );
    e.single(
        "uptime_seconds",
        "gauge",
        "Seconds since this daemon process started serving.",
        &num(d.boot_at.elapsed().as_secs_f64()),
    );

    // --- Line state ---------------------------------------------
    // `current_speed_bps` is the dashboard's own figure and it MUTATES:
    // it pushes a sample into the shared 5 s window and prunes the
    // window's tail. Sharing it is still right - a second rate estimator
    // beside it is exactly the drift `tools/rate-format-gate.py` exists
    // to refuse, one layer down - and the perturbation is nil, because
    // the answer is (last - first) / (last_t - first_t) over a window
    // keyed on wall time and CUMULATIVE bytes: extra samples inside it
    // move neither end. The one prune that could bite, the leading
    // no-progress trim, only fires while nothing is moving, and the
    // answer is 0 then whoever asks.
    e.single(
        "download_rate_bytes_per_second",
        "gauge",
        "Decoded bytes per second over the last ~5 seconds; 0 when nothing is on the wire.",
        &num(d.current_speed_bps()),
    );
    e.single(
        "speed_limit_bytes_per_second",
        "gauge",
        "The configured download cap in bytes per second; 0 means uncapped.",
        &d.hub.rate.get().to_string(),
    );
    e.single(
        "line_speed_bytes_per_second",
        "gauge",
        "The line speed this install was told it has, in bytes per second; 0 means unknown.",
        &d.line_speed.load(Ordering::Relaxed).to_string(),
    );
    e.single(
        "paused",
        "gauge",
        "1 while the queue is paused, so no new job starts.",
        flag(d.paused.load(Ordering::Relaxed)),
    );
    e.single(
        "offline",
        "gauge",
        "1 while the daemon is in offline mode: no downloading and no indexing.",
        flag(d.offline.load(Ordering::Relaxed)),
    );

    queue_metrics(d, &mut e);
    history_metrics(d, &mut e);
    server_metrics(d, &mut e);
    memory_metrics(&mut e);

    e.out
}

/// Queue counts and bytes.
///
/// The job handles are CLONED out of the queue mutex and the mutex is
/// then dropped, so the per-job locks below are taken without it held.
/// `queue_walk` does hold both, and is right to - it is building the
/// rows a caller asked for. A scrape is not, and holding the queue lock
/// across N job locks on a fifteen-second poll is the kind of thing that
/// only ever shows up under load.
fn queue_metrics(d: &Daemon, e: &mut Exposition) {
    let jobs: Vec<Arc<Mutex<Job>>> = d.queue.lock_ok().iter().cloned().collect();

    let mut queued = 0u64;
    let mut downloading = 0u64;
    let mut finishing = 0u64;
    let mut other = 0u64;
    let mut paused = 0u64;
    let mut total_bytes = 0u64;
    let mut remaining_bytes = 0u64;
    for j in &jobs {
        let j = j.lock_ok();
        match j.state {
            JobState::Queued => queued += 1,
            JobState::Downloading => downloading += 1,
            JobState::Finishing => finishing += 1,
            // A Completed or Failed record still in the queue is a
            // job mid-handover. Counted rather than dropped: a
            // total that does not add up is worse than a bucket
            // nobody expected.
            _ => other += 1,
        }
        if j.paused {
            paused += 1;
        }
        total_bytes = total_bytes.saturating_add(j.total_bytes);
        // The row's own remainder, from the record rather than from
        // the live counters: `downloaded_bytes` is what the job has
        // banked, and the active job's in-flight window is reported
        // by the rate gauge above rather than deducted here. That
        // makes this figure fall in steps rather than continuously,
        // which for a queue-depth series is the right shape.
        remaining_bytes =
            remaining_bytes.saturating_add(j.total_bytes.saturating_sub(j.downloaded_bytes));
    }

    e.family(
        "queue_jobs",
        "gauge",
        "Jobs in the queue by pipeline state.",
    );
    e.sample("queue_jobs", &[("state", "queued")], &queued.to_string());
    e.sample(
        "queue_jobs",
        &[("state", "downloading")],
        &downloading.to_string(),
    );
    e.sample(
        "queue_jobs",
        &[("state", "finishing")],
        &finishing.to_string(),
    );
    e.sample("queue_jobs", &[("state", "other")], &other.to_string());
    e.single(
        "queue_jobs_paused",
        "gauge",
        "Jobs in the queue that are individually paused; a subset of the states above.",
        &paused.to_string(),
    );
    e.single(
        "queue_bytes_total",
        "gauge",
        "Declared size of everything in the queue, in bytes.",
        &total_bytes.to_string(),
    );
    e.single(
        "queue_bytes_remaining",
        "gauge",
        "Bytes still to fetch for everything in the queue.",
        &remaining_bytes.to_string(),
    );
}

/// What history holds right now.
///
/// A GAUGE and not a counter, which is the one thing about this family
/// worth reading twice: history is TRIMMED on its own schedule
/// (`history_keep_count` / `history_keep_secs`), so these numbers go
/// DOWN without anything having been undone. Calling them counters would
/// teach `rate()` to read a retention sweep as a burst of completions.
fn history_metrics(d: &Daemon, e: &mut Exposition) {
    let jobs: Vec<Arc<Mutex<Job>>> = d.history.lock_ok().iter().cloned().collect();
    let mut completed = 0u64;
    let mut failed = 0u64;
    let mut completed_bytes = 0u64;
    for j in &jobs {
        let j = j.lock_ok();
        match j.state {
            JobState::Failed => failed += 1,
            _ => {
                completed += 1;
                completed_bytes = completed_bytes.saturating_add(j.total_bytes);
            }
        }
    }
    e.family(
        "history_jobs",
        "gauge",
        "Jobs currently held in history by outcome; falls when history is trimmed.",
    );
    e.sample(
        "history_jobs",
        &[("outcome", "completed")],
        &completed.to_string(),
    );
    e.sample(
        "history_jobs",
        &[("outcome", "failed")],
        &failed.to_string(),
    );
    e.single(
        "history_completed_bytes",
        "gauge",
        "Declared size of the completed jobs currently held in history, in bytes.",
        &completed_bytes.to_string(),
    );
}

/// Per-provider gauges and counters, from the live pool.
///
/// ABSENT while nothing is downloading, and that is correct rather than
/// a gap: `pool_live` is the running job's own fleet, so between jobs
/// there is no such thing as "connections to this server" to report. A
/// series that vanishes is what Prometheus expects from a target whose
/// subject went away; a series pinned at zero would be a claim that the
/// provider is idle, which is a different statement.
///
/// ## Why every family below carries TWO labels
///
/// `server=<host>` alone is not an identity. `LiveStats::for_servers`
/// emits one row per configured ACCOUNT and two accounts on ONE hostname
/// are supported and tested (`block_threshold_tests.rs::
/// duplicate_host_entries_edge_trigger_independently`) - a big flat-rate
/// account plus a small block fill at the same provider is the ordinary
/// shape. With one label the two rows rendered the SAME metric name with
/// the SAME complete label set, which is an invalid sample identity:
/// Prometheus keeps the first and rejects the second with
/// `ErrDuplicateSampleForTimestamp`, so the second account's bytes,
/// connections and outages were simply not exported and nothing here or
/// there said so. `index` is the second label, and the shape that
/// reintroduces the bug is dropping it back to one - or making it
/// conditional on the host being duplicated, which is worse: the first
/// account's series identity would then change silently on the day a
/// second account is added, which is the harder failure to debug.
///
/// It is the row's position in THIS run's fleet, counted from 0 in
/// configuration order (`LiveStats::for_servers` builds its rows in that
/// order). Not the on-disk config index, because the fleet build has
/// already dropped switched-off servers and hosts excluded for this job
/// (`get/plan.rs`) by the time the pool exists - so a disabled server
/// shifts the numbers of the rows after it. That is a re-identification
/// on a settings change, which Prometheus handles the way it handles any
/// series that ends. It is not a credential: `username` was rejected
/// outright, since /metrics can be served unauthenticated when
/// `metrics_open` is on. host+port was rejected too - two accounts at
/// one provider routinely share 563.
///
/// `server` stays FIRST so existing selectors keep matching and so the
/// daemon suite's substring assertions
/// (`crates/nzbfast/tests/daemon_metrics/mod.rs`) keep reading. /metrics
/// is not in v1.2.4, so no user dashboard breaks on the changed
/// identity - this is the cheapest moment the label will ever cost.
fn server_metrics(d: &Daemon, e: &mut Exposition) {
    // Copy every figure out under the lock, then render. The pool's own
    // workers write these gauges on the fetch path, so the shorter this
    // is held the better.
    struct Row {
        host: String,
        /// The `index` label's value: this row's position in the live
        /// fleet. See the function's own doc for why a hostname alone
        /// is not an identity here.
        idx: usize,
        connected: u64,
        budget: u64,
        bytes: u64,
        tried: u64,
        missing: u64,
        reconnects: u64,
        blocked_ms: u64,
        art_ms: u64,
        down_secs: Option<u64>,
        granted_hi: u64,
    }
    let rows: Vec<Row> = {
        let live = d.hub.pool_live.lock_ok();
        let Some(l) = live.as_ref() else {
            return;
        };
        l.servers
            .iter()
            .enumerate()
            .map(|(idx, s)| Row {
                host: s.host.clone(),
                idx,
                connected: s.connected.load(Ordering::Relaxed) as u64,
                budget: s.budget.load(Ordering::Relaxed) as u64,
                bytes: s.bytes.load(Ordering::Relaxed),
                tried: s.articles_tried.load(Ordering::Relaxed),
                missing: s.articles_missing.load(Ordering::Relaxed),
                reconnects: s.reconnects.load(Ordering::Relaxed),
                blocked_ms: s.blocked_ms.load(Ordering::Relaxed),
                art_ms: s.srv_art_ms.load(Ordering::Relaxed),
                down_secs: s.down_secs(),
                granted_hi: s.granted_hi.load(Ordering::Relaxed) as u64,
            })
            .collect()
    };
    if rows.is_empty() {
        return;
    }

    // Each family is opened once and then filled, because the format
    // groups by family and not by label set: interleaving them would put
    // a second `# TYPE` for the first name after the second server's
    // first sample.
    e.family(
        "server_connections",
        "gauge",
        "Open NNTP sessions to this provider right now.",
    );
    for r in &rows {
        e.sample(
            "server_connections",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &r.connected.to_string(),
        );
    }
    e.family(
        "server_connection_budget",
        "gauge",
        "Sessions this run intends to hold on this provider; the live tuner moves it.",
    );
    for r in &rows {
        e.sample(
            "server_connection_budget",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &r.budget.to_string(),
        );
    }
    e.family(
        "server_connections_granted_max",
        "gauge",
        "The most sessions this provider was serving when it last refused another; 0 means it has never refused us.",
    );
    for r in &rows {
        e.sample(
            "server_connections_granted_max",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &r.granted_hi.to_string(),
        );
    }
    e.family(
        "server_down",
        "gauge",
        "1 while this provider is granting no sessions at all.",
    );
    for r in &rows {
        e.sample(
            "server_down",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            flag(r.down_secs.is_some()),
        );
    }
    e.family(
        "server_down_seconds",
        "gauge",
        "Seconds since this provider stopped granting sessions; 0 while it is granting them.",
    );
    for r in &rows {
        e.sample(
            "server_down_seconds",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &r.down_secs.unwrap_or(0).to_string(),
        );
    }
    e.family(
        "server_article_latency_seconds",
        "gauge",
        "Dispatch-to-done moving average for one article on this provider, in seconds.",
    );
    for r in &rows {
        e.sample(
            "server_article_latency_seconds",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &num(r.art_ms as f64 / 1000.0),
        );
    }

    e.family(
        "server_bytes_total",
        "counter",
        "Raw bytes fetched from this provider this run; resets to 0 when a new run takes the pool.",
    );
    for r in &rows {
        e.sample(
            "server_bytes_total",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &r.bytes.to_string(),
        );
    }
    e.family(
        "server_articles_tried_total",
        "counter",
        "Article dispatches sent to this provider this run, duplicates and retries included; resets with the run.",
    );
    for r in &rows {
        e.sample(
            "server_articles_tried_total",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &r.tried.to_string(),
        );
    }
    e.family(
        "server_articles_missing_total",
        "counter",
        "430/423 no-such-article answers from this provider this run; resets with the run.",
    );
    for r in &rows {
        e.sample(
            "server_articles_missing_total",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &r.missing.to_string(),
        );
    }
    e.family(
        "server_reconnects_total",
        "counter",
        "Sessions this provider dropped and we redialled mid-run; the first connect is not one. Resets with the run.",
    );
    for r in &rows {
        e.sample(
            "server_reconnects_total",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &r.reconnects.to_string(),
        );
    }
    e.family(
        "server_blocked_seconds_total",
        "counter",
        "Seconds this provider's workers spent parked because everything downstream of the network was full. Resets with the run.",
    );
    for r in &rows {
        e.sample(
            "server_blocked_seconds_total",
            &[("server", &r.host), ("index", &r.idx.to_string())],
            &num(r.blocked_ms as f64 / 1000.0),
        );
    }
}

/// Process and subsystem memory.
///
/// The per-subsystem gauge is the interesting half: an RSS figure says a
/// number is high and nothing about which part of the pipeline is
/// holding it, and this daemon already attributes every charge (see
/// `nzbkit::memgauge`). Exporting the attribution is what makes a memory
/// alert actionable rather than merely loud.
fn memory_metrics(e: &mut Exposition) {
    use nzbkit::memgauge::Sub;
    e.single(
        "memory_budget_bytes",
        "gauge",
        "The memory budget this process is working to, in bytes.",
        &nzbkit::mem::process_budget().total.to_string(),
    );
    if let Some(rss) = nzbkit::mem::dashboard_rss() {
        e.single(
            "memory_rss_bytes",
            "gauge",
            "The kernel's memory charge for this process, in bytes.",
            &rss.to_string(),
        );
    }
    if let Some(peak) = nzbkit::mem::peak_rss() {
        e.single(
            "memory_rss_peak_bytes",
            "gauge",
            "The high-water memory charge for this process since it started, in bytes.",
            &peak.to_string(),
        );
    }
    if let Some(cpu) = nzbkit::mem::cpu_time_secs() {
        e.single(
            "process_cpu_seconds_total",
            "counter",
            "CPU seconds this process has used, user and system together.",
            &num(cpu),
        );
    }

    // The full roster, spelled out rather than derived, for the reason
    // `mem_floor_json` in serve/api/system.rs spells its own out: `Sub`
    // has no iterator, and a hand list is what makes a thirteenth
    // subsystem a compile-time question at exactly one site instead of a
    // silently missing series.
    let subs = [
        Sub::RawFree,
        Sub::RawOut,
        Sub::OutFree,
        Sub::OutOut,
        Sub::Channel,
        Sub::WireEst,
        Sub::Par2Capture,
        Sub::JobMeta,
        Sub::VerifierMeta,
        Sub::Holds,
        Sub::RepairScan,
        Sub::RepairWork,
    ];
    let snap = nzbkit::memgauge::snapshot();
    e.family(
        "memory_subsystem_bytes",
        "gauge",
        "Bytes charged to each pipeline subsystem right now.",
    );
    for s in subs {
        e.sample(
            "memory_subsystem_bytes",
            &[("subsystem", s.name())],
            &snap.cur_of(s).to_string(),
        );
    }
    e.family(
        "memory_subsystem_peak_bytes",
        "gauge",
        "High-water bytes charged to each pipeline subsystem since this process started.",
    );
    for s in subs {
        e.sample(
            "memory_subsystem_peak_bytes",
            &[("subsystem", s.name())],
            &snap.peak_of(s).to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of `Exposition`: a family name may be declared
    /// once. A second `# TYPE` for the same name is a parse error that
    /// costs the reader the ENTIRE scrape, not just the repeat, which is
    /// why the guard skips rather than emits.
    #[test]
    fn a_repeated_family_is_declared_once() {
        let mut e = Exposition::new();
        e.family("thing", "gauge", "first");
        e.family("thing", "counter", "second");
        e.sample("thing", &[], "1");
        assert_eq!(
            e.out.matches("# TYPE nzbfast_thing").count(),
            1,
            "{}",
            e.out
        );
        assert!(
            !e.out.contains("counter"),
            "the repeat wrote nothing: {}",
            e.out
        );
        assert!(e.out.ends_with("nzbfast_thing 1\n"), "{}", e.out);
    }

    /// A sample with no family before it would land as an untyped
    /// series that nothing can `rate()`, so it is dropped instead.
    #[test]
    fn a_sample_without_a_family_is_dropped() {
        let mut e = Exposition::new();
        e.sample("orphan", &[], "1");
        assert_eq!(e.out, "", "{}", e.out);
    }

    /// Label values carry a provider hostname today and could carry
    /// anything tomorrow. The three characters the format reserves are
    /// escaped; everything else, a dot and a dash included, is not.
    #[test]
    fn label_values_escape_exactly_the_three_reserved_characters() {
        assert_eq!(esc_label("news.example.com"), "news.example.com");
        assert_eq!(esc_label("a\\b"), "a\\\\b");
        assert_eq!(esc_label("a\"b"), "a\\\"b");
        assert_eq!(esc_label("a\nb"), "a\\nb");
        // A quote is ordinary text on a HELP line and must NOT be
        // escaped there - only the backslash and the newline are, since
        // the newline is what ends the line.
        assert_eq!(esc_help("say \"hi\""), "say \"hi\"");
        assert_eq!(esc_help("a\nb"), "a\\nb");
        assert_eq!(esc_help("a\\b"), "a\\\\b");
    }

    /// Whole numbers print as whole numbers - a count rendered `3.000000`
    /// is legal and reads as a mistake - and the three non-finite values
    /// get the spellings the format defines. `format!` gives `inf`, which
    /// is not one of them.
    #[test]
    fn numbers_render_the_way_the_format_defines() {
        assert_eq!(num(0.0), "0");
        assert_eq!(num(3.0), "3");
        assert_eq!(num(-2.0), "-2");
        assert_eq!(num(1.5), "1.500000");
        assert_eq!(num(f64::INFINITY), "+Inf");
        assert_eq!(num(f64::NEG_INFINITY), "-Inf");
        assert_eq!(num(f64::NAN), "NaN");
        // Past 2^53 an f64 is not an integer any more in the sense this
        // shortcut assumes, so it falls back rather than printing a lie.
        assert!(num(1e300).contains('.') || num(1e300).contains('e'));
    }

    /// Every sample line this module can emit must be `name` optionally
    /// followed by `{labels}`, then ONE space, then the value. A stray
    /// space in a label value is what breaks that, which is what
    /// `esc_label` does not cover - so the invariant is checked here on
    /// a value that holds one.
    #[test]
    fn a_labelled_sample_has_one_space_before_its_value() {
        let mut e = Exposition::new();
        e.family("thing", "gauge", "help");
        e.sample("thing", &[("a", "one two"), ("b", "x")], "7");
        let line = e.out.lines().last().unwrap();
        assert_eq!(line, "nzbfast_thing{a=\"one two\",b=\"x\"} 7", "{}", e.out);
        // The value is the last space-separated token, which is what a
        // parser takes - a space inside a QUOTED label value is fine.
        assert_eq!(line.rsplit(' ').next().unwrap(), "7");
    }
}
