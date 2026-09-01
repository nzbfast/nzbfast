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
pub(in crate::serve) fn sab_elapsed(secs: i64) -> String {
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
pub(in crate::serve) fn sab_age(date: i64) -> String {
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
pub(in crate::serve) fn pause_int(d: &Daemon) -> String {
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
pub(in crate::serve) fn sab_timeleft(secs: f64) -> String {
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

/// SAB's `to_units`, ported step for step from `sabnzbd/misc.py`:
/// binary tiers with a one-letter tag and an optional postfix
/// ("417 K", "1.2 M", "40.2 TB").
///
/// NZB Unity parses `queue.speed` with `/([\d.]+)\s+(\w+)/` and
/// multiplies by the unit letter, so the bare-KB-with-no-letter format
/// this once sent always read as 0 B/s there.
///
/// THREE THINGS THIS GOT WRONG until 31 Aug 2026, all of them invisible
/// to `tests/daemon_facade`'s key-and-type census (which pins `Ty::Str`
/// and so cannot see a wrong string), and all three live-confirmed
/// against a running daemon on the day:
///
///   * IT STOPPED AT `G`. SAB's `TAB_UNITS` is `("", K, M, G, T, P)`,
///     so a 2 TB output disk published `diskspace1_norm` as
///     `"2089.6 G"` where SAB says `"2.0 T"`, a 1 TiB job's `size` read
///     `"1024.0 GB"` against `"1.0 TB"`, and `history.total_size` - a
///     lifetime figure that is in TB on any real install - was wrong on
///     every install that has one. That last one is the header of the
///     very view GH #69 was reported against.
///   * IT DID NOT CARRY THE ROUNDING UP A TIER. SAB rounds to the
///     precision it is about to print and then re-checks, with its own
///     comment saying why: 1048575 must read `"1.0 M"`, not `"1024 K"`.
///     Ours printed `"1024 K"`, and `"1024.0 M"` for 1073741823.
///   * THE BARE FORM CARRIED A TRAILING SPACE. SAB emits the tag only
///     when there is one to emit or a postfix to carry it -
///     `if n == 0 and postfix == ""` gives no unit at all - so
///     `to_units(0)` is `"0"` and ours was `"0 "`. That is the shape
///     `queue.speed` and the four `*_size` totals in the history body
///     take, and a client that hands one to a strict numeric parse
///     (Kotlin's `String.toInt()` refuses trailing whitespace) sees the
///     difference. `to_units(0, "B")` is `"0 B"` in both, because the
///     postfix brings the space with it.
///
/// Measured over 17 boundary values before and after: 12 of 17
/// disagreed with SAB on the bare form and 7 of 17 with the `"B"` one;
/// all 17 agree now. `sab_units_b` is the `"B"` form and exists so the
/// postfix goes through the ONE implementation - the hand-appended
/// suffix idiom it replaces at ten call sites is what let the bare form
/// and the suffixed one drift apart in the first place.
pub(in crate::serve) fn sab_units(n: f64) -> String {
    sab_to_units(n, "")
}

/// `to_units(x, "B")` - the byte form, for every SAB field that carries
/// the suffix (`size`, `sizeleft`, `quota`, `left_quota`, `cache_size`).
pub(in crate::serve) fn sab_units_b(n: f64) -> String {
    sab_to_units(n, "B")
}

/// The one implementation. `TAB_UNITS` and the tier arithmetic are
/// SAB's; see `sab_units` for what each step is defending against.
fn sab_to_units(val: f64, postfix: &str) -> String {
    const TAB_UNITS: [&str; 6] = ["", "K", "M", "G", "T", "P"];
    // NaN is not a size. SAB's own guard is `isinstance(val, (int,
    // float))` and Python has no way in from JSON to reach a NaN here;
    // ours is an f64 cast from a counter, so the honest answer for one
    // is the zero the counter would have read.
    let val = if val.is_nan() { 0.0 } else { val };
    let (sign, mut val) = if val < 0.0 { ("-", -val) } else { ("", val) };
    // `min(5, trunc(log2(val)/10))`, SAB's spelling. Below 1024 the
    // logarithm is not consulted at all - log2(0) is -inf.
    let mut n: usize = if val < 1024.0 {
        0
    } else {
        ((val.log2() / 10.0) as usize).min(5)
    };
    let mut decimals = if n > 1 { 1 } else { 0 };
    let round_to = |v: f64, d: usize| {
        let f = 10f64.powi(d as i32);
        (v * f).round() / f
    };
    val = round_to(val / 2f64.powi(10 * n as i32), decimals);
    // SAB's carry: rounding to the printed precision can push the value
    // up into the next tier (1048575 rounds to 1024 K, which must read
    // 1.0 M). Not applied at the top tier, which has nowhere to go.
    if n < 5 && val >= 1024.0 {
        n += 1;
        if n > 1 {
            decimals = 1;
        }
        val = round_to(val / 1024.0, decimals);
    }
    // The tag, and SAB's rule for when there is none: a sub-1024 value
    // with no postfix carries no unit and therefore no space either.
    let units = if n == 0 && postfix.is_empty() {
        String::new()
    } else {
        format!(" {}{}", TAB_UNITS[n], postfix)
    };
    format!("{sign}{val:.decimals$}{units}")
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
    if j.priority == crate::serve::job::DUPE_PRIORITY {
        "Normal"
    } else {
        priority_name(j.priority)
    }
}

#[cfg(test)]
#[path = "units_tests.rs"]
mod units_tests;
