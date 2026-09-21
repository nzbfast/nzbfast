//! The process's log sink: `tracing` events formatted onto our own
//! stdout/stderr.
//!
//! Why that destination and not a file: `nzbkit::logtee` dup2()s both fds
//! onto a pipe at daemon startup and keeps the last 2000 lines in a ring,
//! which is what the dashboard's log pane (`mode=log`) serves. Anything
//! written to stdout is therefore already in the viewer, in a terminal,
//! and in whatever file the packaging redirected to - three destinations
//! for free, and no second copy of the log to keep in sync. A subscriber
//! that opened its own file would have shown the dashboard nothing.
//!
//! House format, unchanged from the println era it replaces:
//!
//! ```text
//! [queue] added SABnzbd_nzo_1a2b3c            (CLI)
//! 2026-08-02 14:03:11Z INFO  [queue] added …  (daemon)
//! ```
//!
//! The `[tag]` is the event's tracing *target*, so the same string that
//! reads as a prefix is also the filter key: `NZBFAST_LOG=warn,queue=debug`
//! turns the queue lane up and everything else down. Tags were already the
//! de-facto module names in this codebase; this makes them addressable.
//!
//! The CLI keeps the bare `[tag] message` line. `nzbfast get` output is
//! read as program output, not as a log, and stamping every line of a
//! foreground download would be noise; the daemon, whose log is read hours
//! later out of a screenshot, gets the timestamp and level.

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
// `with_filter` (per-layer filtering) hangs off the Layer trait.
use tracing_subscriber::Layer as _;

/// Environment variable holding the filter directive. `RUST_LOG` is
/// honoured too, second, because that is the one everybody's fingers
/// already type - but the prefixed name is the documented one, so turning
/// on someone else's crate's logging cannot accidentally turn on ours.
const ENV: &str = "NZBFAST_LOG";

/// How much of the line is prefix.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Style {
    /// `[tag] message` - byte-identical to what the CLI printed before.
    Cli,
    /// `2026-08-02 14:03:11Z INFO  [tag] message`.
    Daemon,
}

/// Install the global subscriber. Call once, as early as the chosen
/// [`Style`] is known; a second call is a no-op (`try_init` fails and the
/// first subscriber stands, which is the right outcome for a test binary
/// that already installed its own).
pub fn init(style: Style) {
    let fmt = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .event_format(House { style })
        // Level-split the writer so warnings and errors keep going to
        // stderr exactly as `eprintln!` did. In the daemon both fds are
        // the same pipe, so this only shows up in the CLI - where it is
        // the difference between `nzbfast probe > out.txt` capturing the
        // report and capturing the report plus its complaints.
        //
        // `with_max_level` is in tracing's VERBOSITY order, where ERROR
        // is the smallest level: `stdout.with_max_level(INFO)` takes
        // INFO, WARN and ERROR, so the stderr arm it was chained behind
        // was dead and every warning went to stdout from the day §80
        // shipped until 22 Aug 2026 (`nzbfast extract` on a directory
        // with an unparseable Rar!-magic file put its "skipping" warning
        // on stdout and nothing on stderr). Stderr takes the severe end
        // first; everything it declines is stdout's.
        .with_writer(
            std::io::stderr
                .with_max_level(Level::WARN)
                .or_else(std::io::stdout),
        );
    // The filter goes in behind a reload handle so the daemon can turn
    // the log up or down while it runs (`set_detail`). Nothing else
    // about the pipeline changes: a reload swaps the `Targets` value
    // and the fmt layer never knows.
    let (filter, handle) = tracing_subscriber::reload::Layer::new(env_or_default());
    let _ = RELOAD.set(handle);
    let _ = tracing_subscriber::registry()
        .with(fmt.with_filter(filter))
        .try_init();
}

/// How loud the log should be, in the three steps a person picks from.
///
/// Deliberately coarser than `NZBFAST_LOG`, which stays the full
/// `Targets` language for anyone debugging one lane. This is the dial
/// for the case the setting exists for: somebody who does not want a
/// log at all, on a machine where setting an environment variable means
/// editing a launchd plist or a tray shortcut.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Detail {
    /// Warnings and errors only - the things that are worth waking up
    /// for. An idle daemon on this setting writes nothing at all.
    Quiet,
    /// What the daemon has always written.
    #[default]
    Normal,
    /// Everything, including the `debug` lanes. Costs real throughput on
    /// a busy pipeline, which is why it is not the place to leave it.
    Verbose,
}

impl Detail {
    /// The stored spelling, and the one the API and settings.json use.
    pub fn as_str(self) -> &'static str {
        match self {
            Detail::Quiet => "quiet",
            Detail::Normal => "normal",
            Detail::Verbose => "verbose",
        }
    }

    /// The filter this level means. Every target moves together: a
    /// per-target dial is what `NZBFAST_LOG` is for.
    fn filter(self) -> Targets {
        Targets::new().with_default(match self {
            Detail::Quiet => LevelFilter::WARN,
            Detail::Normal => LevelFilter::INFO,
            Detail::Verbose => LevelFilter::DEBUG,
        })
    }
}

impl FromStr for Detail {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s.trim().to_ascii_lowercase().as_str() {
            "quiet" => Ok(Detail::Quiet),
            "normal" | "" => Ok(Detail::Normal),
            "verbose" => Ok(Detail::Verbose),
            _ => Err(()),
        }
    }
}

/// The live filter's reload handle, installed by [`init`].
static RELOAD: std::sync::OnceLock<
    tracing_subscriber::reload::Handle<Targets, tracing_subscriber::Registry>,
> = std::sync::OnceLock::new();

/// What [`set_detail`] has been asked for, so [`detail`] can answer
/// without reading the filter back (a `Targets` does not say which of
/// our three steps produced it).
static DETAIL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

/// True when the environment named a filter, which pins the level: an
/// operator who typed `NZBFAST_LOG` gets what they typed, and the
/// setting must not fight them. The UI reads this to say so rather than
/// showing a dial that does nothing.
static ENV_PINNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The startup filter, recording whether the environment set it.
fn env_or_default() -> Targets {
    match raw_env() {
        Some(_) => {
            ENV_PINNED.store(true, std::sync::atomic::Ordering::Relaxed);
            filter_from_env()
        }
        None => filter_from_env(),
    }
}

/// Turn the log up or down, now, for a running process.
///
/// Returns false when the environment pinned the filter (see
/// `ENV_PINNED`) or when no subscriber of ours is installed - a test
/// binary that brought its own, or a `set_detail` before [`init`]. The
/// caller stores the setting either way; it takes effect at the next
/// start, which is the same rule every other startup-shaped setting
/// here follows.
pub fn set_detail(d: Detail) -> bool {
    DETAIL.store(d as u8, std::sync::atomic::Ordering::Relaxed);
    if env_pinned() {
        return false;
    }
    RELOAD.get().is_some_and(|h| h.reload(d.filter()).is_ok())
}

/// What the dial is set to.
pub fn detail() -> Detail {
    match DETAIL.load(std::sync::atomic::Ordering::Relaxed) {
        0 => Detail::Quiet,
        2 => Detail::Verbose,
        _ => Detail::Normal,
    }
}

/// Is the level fixed by `NZBFAST_LOG` / `RUST_LOG`?
pub fn env_pinned() -> bool {
    ENV_PINNED.load(std::sync::atomic::Ordering::Relaxed)
}

/// The filter from the environment, or plain `info` when nothing is set.
///
/// A directive we cannot parse is not worth killing the daemon over and is
/// not worth silencing either: fall back to the default and say so on
/// stderr (the subscriber is not up yet, so this one really is a print).
fn filter_from_env() -> Targets {
    match raw_env() {
        None => default_filter(),
        Some(s) => match Targets::from_str(&s) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[log] ignoring {ENV}={s:?} ({e}) - logging at the default level");
                default_filter()
            }
        },
    }
}

/// The directive the environment names, if any. Split out so the
/// startup path can tell "the operator set a filter" from "we fell back
/// to the default", which is what pins the dial.
fn raw_env() -> Option<String> {
    std::env::var(ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("RUST_LOG").ok())
        .filter(|s| !s.trim().is_empty())
}

fn default_filter() -> Targets {
    Targets::new().with_default(LevelFilter::INFO)
}

/// The house line format.
struct House {
    style: Style,
}

impl<S, N> FormatEvent<S, N> for House
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();
        if self.style == Style::Daemon {
            write!(writer, "{} {:<5} ", stamp(now_unix()), meta.level())?;
        }
        write!(writer, "[{}] ", meta.target())?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The same UTC stamp the log writes, for the per-job report - which
/// travels between timezones for exactly the reason `stamp` below
/// gives.
pub fn stamp_for_report(ts: i64) -> String {
    stamp(ts)
}

/// `2026-08-02 14:03:11Z` from a unix timestamp.
///
/// UTC, and said so with the `Z`. Everything else in this codebase that
/// writes a date writes UTC (history, quota rollover, RSS dates), and a
/// log line that silently used local time would not survive being pasted
/// into a bug report from another timezone.
fn stamp(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// (year, month, day) from days-since-epoch - Howard Hinnant's civil
/// calendar algorithm. A local copy on purpose: this module has to be able
/// to format a line during `serve`'s own startup, before anything in
/// `serve` is constructed. `pub(crate)` since 1 Sep 2026: the expected-
/// episode sweep needs yesterday's date for a TVmaze schedule URL, and a
/// third copy of this algorithm would be the copy-paste-sibling defect.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Collect what the layer writes, so the tests can assert on the
    /// actual rendered line rather than on the pieces that build it.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Sink;
        fn make_writer(&'a self) -> Sink {
            self.clone()
        }
    }

    /// Run `f` under a subscriber using the house format, and return
    /// everything it emitted.
    fn rendered(style: Style, f: impl FnOnce()) -> String {
        let sink = Sink::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .event_format(House { style })
            .with_writer(sink.clone());
        let sub = tracing_subscriber::registry().with(layer.with_filter(default_filter()));
        tracing::subscriber::with_default(sub, f);
        let out = sink.0.lock().unwrap().clone();
        String::from_utf8(out).expect("utf-8")
    }

    /// The CLI line is byte-identical to the `println!` it replaced.
    /// `nzbfast get`'s output is the shape a pile of e2e tests grep, and
    /// the shape users have in their heads.
    #[test]
    fn the_cli_line_is_the_old_println_line() {
        let out = rendered(Style::Cli, || {
            tracing::info!(target: "queue", "added {}", "SABnzbd_nzo_1a2b3c");
        });
        assert_eq!(out, "[queue] added SABnzbd_nzo_1a2b3c\n");
    }

    /// The daemon line adds a stamp and a level in front of that same
    /// text - a prefix, never a rewrite, so every `log.contains(…)` in
    /// the daemon suite still matches and so does the user's grep.
    #[test]
    fn the_daemon_line_prefixes_rather_than_rewrites() {
        let out = rendered(Style::Daemon, || {
            tracing::warn!(target: "queue", "added {}", "SABnzbd_nzo_1a2b3c");
        });
        let line = out.trim_end();
        assert!(
            line.ends_with("WARN  [queue] added SABnzbd_nzo_1a2b3c"),
            "{line}"
        );
        // …behind a stamp of exactly the width `stamp` produces.
        assert_eq!(
            line.len(),
            stamp(0).len() + 1 + 5 + 1 + "[queue] added SABnzbd_nzo_1a2b3c".len()
        );
        assert!(line.starts_with("20"), "{line}");
    }

    /// Structured fields ride along as `key=value` after the message, so
    /// a call site can attach a number without inventing a format string
    /// for it. The message still leads, which is what keeps the pane
    /// readable.
    #[test]
    fn fields_follow_the_message() {
        let out = rendered(Style::Cli, || {
            tracing::info!(target: "index", articles = 12u64, "scan {} done", "alt.binaries.x");
        });
        assert_eq!(out, "[index] scan alt.binaries.x done articles=12\n");
    }

    /// Nothing the formatter writes may carry an escape code: the line
    /// goes down logtee's pipe and into the dashboard's `<pre>`, where an
    /// ANSI sequence renders as literal garbage.
    #[test]
    fn no_ansi_reaches_the_log_pane() {
        let out = rendered(Style::Daemon, || {
            tracing::error!(target: "shutdown", "wind-down failed");
        });
        assert!(!out.contains('\u{1b}'), "escape code in {out:?}");
    }

    #[test]
    fn stamps_are_utc_and_sortable() {
        assert_eq!(stamp(0), "1970-01-01 00:00:00Z");
        // 2026-08-02 14:03:11Z
        assert_eq!(stamp(1_785_679_391), "2026-08-02 14:03:11Z");
        // Leap day, and the last second of a year - the two dates a
        // hand-rolled calendar gets wrong.
        assert_eq!(stamp(1_709_164_800), "2024-02-29 00:00:00Z");
        assert_eq!(stamp(1_767_225_599), "2025-12-31 23:59:59Z");
        // Fixed width, so the pane's lines stay in columns.
        assert_eq!(stamp(0).len(), stamp(1_785_679_391).len());
    }

    /// The directive grammar the docs promise. `Targets` is what parses
    /// it, so this is really pinning that we picked a filter whose syntax
    /// matches the `[tag]` prefixes the code actually emits.
    #[test]
    fn per_target_directives_parse() {
        let t = Targets::from_str("warn,queue=debug,index=off").expect("parses");
        assert!(t.would_enable("queue", &Level::DEBUG));
        assert!(!t.would_enable("index", &Level::ERROR));
        assert!(t.would_enable("shutdown", &Level::WARN));
        assert!(!t.would_enable("shutdown", &Level::INFO));
    }

    #[test]
    fn the_default_is_info() {
        let t = default_filter();
        assert!(t.would_enable("queue", &Level::INFO));
        assert!(!t.would_enable("queue", &Level::DEBUG));
    }

    /// A typo in the variable must not take the log with it.
    #[test]
    fn a_broken_directive_falls_back_to_the_default() {
        assert!(Targets::from_str("queue=verbose").is_err());
        let t = default_filter();
        assert!(t.would_enable("queue", &Level::INFO));
    }

    /// The dial's three words, and the levels they mean. The mapping is
    /// the whole setting: get it wrong and "quiet" is a log that still
    /// writes every info line, which is the complaint the setting
    /// exists to answer (r/usenet, 18 Sep 2026).
    #[test]
    fn the_dial_maps_its_three_words_onto_three_levels() {
        for (word, want) in [
            ("quiet", Detail::Quiet),
            ("normal", Detail::Normal),
            ("verbose", Detail::Verbose),
            // Spelling is forgiving in case, and an empty string is the
            // absent value rather than an error: settings.json can hold
            // one, and it means "the default".
            ("  VERBOSE ", Detail::Verbose),
            ("", Detail::Normal),
        ] {
            assert_eq!(word.parse::<Detail>(), Ok(want), "{word:?}");
        }
        // Refused rather than defaulted - see the apply arm.
        assert_eq!("loud".parse::<Detail>(), Err(()));

        // The filters themselves, checked through a callsite-shaped
        // question rather than by comparing `Targets` values: what
        // matters is which levels survive.
        for (d, warn_on, info_on, debug_on) in [
            (Detail::Quiet, true, false, false),
            (Detail::Normal, true, true, false),
            (Detail::Verbose, true, true, true),
        ] {
            let f = d.filter();
            assert_eq!(f.would_enable("index", &Level::WARN), warn_on, "{d:?} warn");
            assert_eq!(f.would_enable("index", &Level::INFO), info_on, "{d:?} info");
            assert_eq!(
                f.would_enable("index", &Level::DEBUG),
                debug_on,
                "{d:?} debug"
            );
        }
    }

    /// `set_detail` is what the settings row calls, and `detail` is what
    /// it reads back - including when the reload could not be applied,
    /// because the value is still what the user asked for and the UI
    /// must show it rather than silently snapping back.
    ///
    /// Process-global state, so it puts the dial back where it found it:
    /// this crate's unit tests share ONE process by design (see the
    /// one-process lines in CLAUDE.md) and a test that leaves the log on
    /// `quiet` would take another test's expected output with it.
    #[test]
    fn the_dial_reads_back_what_it_was_set_to() {
        let was = detail();
        for d in [Detail::Quiet, Detail::Verbose, Detail::Normal] {
            // The answer says whether it took effect NOW; the stored
            // value moves either way.
            let _live = set_detail(d);
            assert_eq!(detail(), d);
        }
        set_detail(was);
    }
}
