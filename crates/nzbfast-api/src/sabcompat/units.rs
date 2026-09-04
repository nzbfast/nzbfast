//! The SAB facade's VALUE formats: the handful of pure functions that
//! decide what a number or a state word LOOKS like on the wire.
//!
//! A child module under the §106 file ceiling, and the split fell here
//! rather than anywhere else in `sabcompat.rs` because these five
//! answer one question - "what would SABnzbd have printed?" - and
//! nothing else in the parent does. Each is a port of a named function
//! in SAB's own source, cited at the item, and each carries the
//! incident that made somebody go and read that source.
//!
//! WHY THEY ARE WORTH TESTING SEPARATELY, which is the other half of
//! why they are together. `crates/nzbfast/tests/daemon_facade` pins the
//! two big payloads key by key WITH THE TYPE each key carries, and that
//! census is complete: measured 31 Aug 2026 against SAB 5.1.2, the
//! queue body, the queue slot, the history body and the history slot
//! have between them ZERO keys SAB sends and we do not. What a census
//! of names and types cannot see is a VALUE - a wrong string is still a
//! string - and every defect the 31 Aug audit found was one:
//! `"2089.6 G"` for a 2 TB disk where SAB says `"2.0 T"`, `"5"` for a
//! five-minute pause where SAB says `"5:00"`, `Duplicate` in a field
//! whose vocabulary has five words in it and that is not one of them.
//! So the tests beside these functions are exact-value tests, driven
//! off SAB's own algorithm rather than off what we happen to emit.

use super::*;

/// SAB's `calc_age` vocabulary over an ELAPSED count of seconds: whole
/// days, else whole hours, else whole minutes (`sabnzbd/misc.py`,
/// unchanged across 4.5.0, 5.1.2 and develop, read 30 Aug 2026).
pub(crate) fn sab_elapsed(secs: i64) -> String {
    match secs.max(0) {
        s if s >= 86_400 => format!("{}d", s / 86_400),
        s if s >= 3_600 => format!("{}h", s / 3_600),
        s => format!("{}m", s / 60),
    }
}

/// SAB's `age` field: [`sab_elapsed`] of now minus a post's date, and
/// `"-"` for a date SAB's own `except` arm would have caught - absent
/// (our NZB parser stores 0) or in the future, which is a negative
/// `timedelta` there and formats as nonsense. `"-"` is the same token
/// the queue payload's `avg_age` already sends for an unknown age.
pub(crate) fn sab_age(date: i64) -> String {
    let now = epoch_secs() as i64;
    if date <= 0 || date > now {
        return "-".into();
    }
    sab_elapsed(now - date)
}

/// How long a timed pause has left, in SAB's `pause_int` shape.
///
/// `"M:SS"` - `sabnzbd/scheduler.py::pause_int`, whose own docstring is
/// "Return minutes:seconds until pause ends" - or `"0"` when nothing is
/// scheduled. This published bare whole minutes until 31 Aug 2026, so a
/// five-minute pause read `"5"` where SAB says `"5:00"`: same TYPE, so
/// the facade's key-and-type census could not see it, and a client
/// rendering a countdown off `split(":")` got one field where it
/// expected two. The minutes still parse out in front for anything
/// reading it loosely (our own dashboard takes `parseInt`).
///
/// SAB carries a sign because its deadline can go negative between the
/// pause expiring and `pause_check` clearing it; ours cannot, because
/// `saturating_duration_since` floors at zero. The sign is spelled out
/// anyway rather than dropped, so the shape is SAB's whatever a future
/// caller hands it.
pub(crate) fn pause_int(d: &Daemon) -> String {
    let secs = d
        .pause_until
        .lock_ok()
        .map(|t| t.saturating_duration_since(Instant::now()).as_secs());
    match secs {
        None => "0".to_string(),
        Some(v) => format!("{}:{:02}", v / 60, v % 60),
    }
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
pub(crate) fn sab_timeleft(secs: f64) -> String {
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

/// The queue slot's `priority`, in SAB's `INTERFACE_PRIORITIES`
/// vocabulary: Force, Repair, High, Normal, Low.
///
/// `priority_name` is the DASHBOARD's version and keeps `Duplicate`,
/// because the page has a sentence to write about a held row and that
/// sentence is the whole reason the sentinel exists. This one is the
/// WIRE version, and the two part company on exactly one value - see
/// the note at the `priority` key in `slot_json` for why SAB can never
/// send a sixth word, and `labels` for where the hold goes instead.
///
/// A held row reports `Normal`, which is what SAB's own
/// `set_stateless_priority` settles on when the job's category names no
/// priority of its own. We do not keep what the row's priority was
/// before the hold took it (`dupe.rs` and `insurance.rs` both assign
/// `DUPE_PRIORITY` over it), so `Normal` is the honest answer rather
/// than a lossy guess - and a client that promotes the row gets the
/// priority it asked for on the very next poll.
pub(super) fn sab_priority_name(j: &Job) -> &'static str {
    if j.priority == crate::job::DUPE_PRIORITY {
        "Normal"
    } else {
        priority_name(j.priority)
    }
}

#[cfg(test)]
#[path = "units_tests.rs"]
mod units_tests;

// `sab_units`, `sab_units_b` and their one implementation moved DOWN
// into `nzbfast_daemon::sabvocab` when the daemon layer became its own
// crate: `history` reads them for the SAB history payload's size
// fields and is a layer BELOW this one, so leaving them here made a
// daemon module depend on the api layer for a number formatter.
//
// NOT re-exported from here, deliberately: every call site in this
// module and in `sabcompat` reaches them as bare names through serve's
// root `use sabvocab::*;`, which is the same door the daemon layer
// uses. A re-export would put the NAME on this unit too, and
// `modgraph.py --serve`'s glob table would then attribute it to
// `sabcompat` - reporting the api layer as the owner of a symbol the
// daemon layer defines, and printing a cross-layer edge that does not
// exist.
