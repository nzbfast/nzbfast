//! The SAB-compatibility vocabulary the daemon layer shares with the API
//! layer: the version string we advertise, the newznab category mapping,
//! and the `search=` predicate.
//!
//! Every item here is pure - no `Daemon`, no request, no I/O - and
//! together they are the whole of what serve's DAEMON-layer modules used
//! to reach UP into `sabcompat` and `api::queue` for. `finish_action`, `script` and
//! `prequeue` put `SAB_VERSION` in a user script's environment,
//! `history` and `sabcompat` both put it in a JSON payload, `watchlist`
//! and `api::index::pull` both classify a row with `cat_for_kind`, and
//! `job`'s history sweep narrows on the same `sab_search_matches` the
//! queue and history write arms do, and `history` names the script a job
//! will run with the same `sab_script_name` the facade does. Leaving them
//! where they were made
//! seven daemon-layer modules depend on the API layer for a constant and
//! two predicates, which is the wrong direction and is what
//! `tools/modgraph.py --serve --check` refuses.
//!
//! Nothing here may grow a `Daemon` argument: the point of the module is
//! that it is the layer BELOW everything that has one.

use crate::job::JobState;

/// Version we report to API clients. The *arrs feature-gate on the SAB
/// version string, so claim parity with the release whose API we match.
pub const SAB_VERSION: &str = "4.5.0";

/// The four index kinds as newznab top-level category ids. The standard
/// tree is 1000 Console, 2000 Movies, 3000 Audio, 4000 PC, 5000 TV,
/// 6000 XXX, 7000 Books, 8000 Other - so software belongs under PC, and
/// Other is 8000, never 7000 (Prowlarr remaps/misfiles anything declared
/// under Books). A custom category has no id of its own and rides Other,
/// as `docs/DESIGN-user-categories.md` decided.
pub fn cat_for_kind(kind: &str) -> Option<u32> {
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
pub fn kind_for_cat(cat: u32) -> Option<&'static str> {
    match cat / 1000 {
        2 => Some("movie"),
        4 => Some("software"),
        5 => Some("tv"),
        8 => Some("other"),
        _ => None,
    }
}

/// `mode=queue&name=purge&search=X` and
/// `mode=history&name=delete&value=all|failed|completed&search=X` all
/// narrow the sweep to jobs whose name matches. Neither arm read the
/// parameter until 31 Aug 2026, and an unread filter on a DELETE does
/// not fail - it deletes everything. Live-confirmed on both: a four-row
/// history answered `value=all&search=Alpha` by removing all four, and a
/// three-row queue answered `value=all&search=Alpha` by removing all
/// three, where SAB removes the one that matched.
///
/// A case-insensitive substring of the job's name, which is
/// `NzbQueue.remove_all`'s rule exactly (`search in
/// nzo.final_name.lower()`). SAB's HISTORY half goes through
/// `database.convert_search`, which additionally reads `*` as a
/// wildcard and `^` / `$` as anchors; those are treated literally here,
/// and that is the safe direction on purpose - a pattern we do not
/// understand matches FEWER rows and deletes less, never more. It is
/// also deliberately narrower than `HistQuery`'s read-side search, which
/// also matches the category, the identity name and the filed base: a
/// filter that is wider than SAB's on a read shows extra rows, and on a
/// delete destroys extra jobs.
///
/// An absent or blank `search` is no filter at all, as in SAB.
pub fn sab_search_matches(name: &str, search: Option<&str>) -> bool {
    match search.map(str::trim).filter(|s| !s.is_empty()) {
        None => true,
        Some(needle) => name.to_lowercase().contains(&needle.to_lowercase()),
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
pub fn sab_script_name(over: &str, cat_script: &str, global: &[std::path::PathBuf]) -> String {
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
        crate::nzbget_script::script_chain(s)
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
pub fn sab_units(n: f64) -> String {
    sab_to_units(n, "")
}

/// `to_units(x, "B")` - the byte form, for every SAB field that carries
/// the suffix (`size`, `sizeleft`, `quota`, `left_quota`, `cache_size`).
pub fn sab_units_b(n: f64) -> String {
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
pub fn slot_progress(
    state: JobState,
    live: Option<(u64, u64)>,
    tail: bool,
    total_bytes: u64,
    downloaded_bytes: u64,
    prefetched: u64,
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
        // `prefetched` is what the idle-server early start has banked
        // into this job's out_dir and journal RIGHT NOW, and it counts
        // exactly as a previous run's bytes do: the next run resumes
        // from both, so both are bytes this queue no longer has to
        // fetch. Zero on every row but the one the sidecar holds.
        //
        // The max, not the sum - they are the same bytes counted twice.
        // The sidecar resumes from the journal, so its counter already
        // includes whatever an earlier run left, and adding them put a
        // resumed early start past 100% of its own job.
        //
        // Until this arm read it, the feature's best night looked like a
        // stuck queue: 29.5 GB banked in 9.4 minutes and the row said
        // `Queued, 0%, mbleft unchanged` for the whole of it (live
        // daemon, 29 Aug 2026). Nothing here mutates the record - the
        // bytes are reported where they are read, and `downloaded_bytes`
        // stays what an actual RUN recorded, because spend accounting
        // (insurance, altspend) reads it.
        None => {
            let banked = downloaded_bytes.max(prefetched);
            (
                pct_of(banked, total_bytes),
                total_bytes.saturating_sub(banked.min(total_bytes)),
            )
        }
    }
}
