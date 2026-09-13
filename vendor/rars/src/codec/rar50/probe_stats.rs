//! Where the ring probe's per-candidate work goes (nzbfast-local change,
//! 8 Sep 2026; see VENDORING.md).
//!
//! `ratio-lab` only, and it is NOT free: every counter is a relaxed atomic
//! add on a shared line, so an instrumented run is several times slower
//! than a production one. It answers a question timing cannot - how many
//! candidates reach each stage of [`super::best_match_probe`], which exit
//! ends each walk, and how many bytes the length loop compares - and every
//! number it reports is deterministic for a given input, so a loaded box
//! does not change it.
//!
//! The 8 Sep 2026 profile put 86% of non-idle samples in the match search
//! at the shipped 2 MiB dictionary and could not say which stage of it.
//! This says. Set `RARS_PROBE_STATS=1` and `rar5cli` prints the table.

use std::sync::atomic::{AtomicU64, Ordering};

/// One counter per stage. Kept as an array with a name table so adding a
/// stage is one enum arm and one string.
#[derive(Copy, Clone)]
#[repr(usize)]
pub enum Stat {
    /// Probes that got past the cheap early return.
    Probes,
    /// Repeat-distance slots examined, and those whose four bytes matched.
    RepChecked,
    RepPrefixHit,
    /// Ring candidates that spent a slot of the candidate budget.
    RingChecked,
    /// ... rejected by the tag, with no history load at all.
    RingTagReject,
    /// ... rejected by the one byte at `best.length - 1`.
    RingByteReject,
    /// ... whose tag passed but whose four-byte prefix did not (a tag
    /// collision: the load happened and bought nothing).
    RingPrefixReject,
    /// ... that reached the length loop.
    RingPrefixHit,
    /// How each walk ended.
    ExitDistance,
    ExitNice,
    ExitCap,
    ExitExhausted,
    /// The long table and the tree finder.
    LongProbe,
    LongPrefixHit,
    TreeProbe,
    TreePrefixHit,
    /// Bytes the length loop reported matching, summed over every call
    /// (the loop compares at least this many and stops on the first
    /// mismatch, so it is a floor on its work, not a total).
    MatchLengthBytes,
    /// Calls into the length loop, from every site.
    MatchLengthCalls,
    /// Ring candidates walked per probe, bucketed 0/1-2/3-4/5-8/9-16/
    /// 17-32/33-64/65+.
    Walk0,
    Walk2,
    Walk4,
    Walk8,
    Walk16,
    Walk32,
    Walk64,
    WalkMore,
    /// The OPTIMAL parse's own ring walk (`match_candidates_at`), which the
    /// 8 Sep census did not instrument: it is a second walk over the same
    /// index with its own stop rules, and the `smallest` profile spends its
    /// candidates here rather than in `best_match_probe`.
    OptProbes,
    OptRingChecked,
    OptRingTagReject,
    OptRingByteReject,
    OptRingPrefixHit,
    OptExitDistance,
    OptExitNice,
    OptExitCap,
    OptExitExhausted,
    OptTreeProbe,
    Count,
}

static COUNTERS: [AtomicU64; Stat::Count as usize] =
    [const { AtomicU64::new(0) }; Stat::Count as usize];

const NAMES: [&str; Stat::Count as usize] = [
    "probes",
    "rep_checked",
    "rep_prefix_hit",
    "ring_checked",
    "ring_tag_reject",
    "ring_byte_reject",
    "ring_prefix_reject",
    "ring_prefix_hit",
    "exit_distance",
    "exit_nice",
    "exit_cap",
    "exit_exhausted",
    "long_probe",
    "long_prefix_hit",
    "tree_probe",
    "tree_prefix_hit",
    "match_length_bytes",
    "match_length_calls",
    "walk_0",
    "walk_1_2",
    "walk_3_4",
    "walk_5_8",
    "walk_9_16",
    "walk_17_32",
    "walk_33_64",
    "walk_65_plus",
    "opt_probes",
    "opt_ring_checked",
    "opt_ring_tag_reject",
    "opt_ring_byte_reject",
    "opt_ring_prefix_hit",
    "opt_exit_distance",
    "opt_exit_nice",
    "opt_exit_cap",
    "opt_exit_exhausted",
    "opt_tree_probe",
];

#[inline]
pub(crate) fn bump(stat: Stat, by: u64) {
    COUNTERS[stat as usize].fetch_add(by, Ordering::Relaxed);
}

/// The bucket a walk of `checked` candidates belongs to.
#[inline]
pub(crate) fn walk_bucket(checked: usize) -> Stat {
    match checked {
        0 => Stat::Walk0,
        1..=2 => Stat::Walk2,
        3..=4 => Stat::Walk4,
        5..=8 => Stat::Walk8,
        9..=16 => Stat::Walk16,
        17..=32 => Stat::Walk32,
        33..=64 => Stat::Walk64,
        _ => Stat::WalkMore,
    }
}

/// Every counter, as `name value` lines with a few derived ratios.
pub fn report() -> String {
    let value = |stat: Stat| COUNTERS[stat as usize].load(Ordering::Relaxed);
    let mut out = String::new();
    for (index, name) in NAMES.iter().enumerate() {
        out.push_str(&format!(
            "{name} {}\n",
            COUNTERS[index].load(Ordering::Relaxed)
        ));
    }
    let probes = value(Stat::Probes).max(1);
    let checked = value(Stat::RingChecked).max(1);
    out.push_str(&format!(
        "derived ring_candidates_per_probe {:.3}\n",
        value(Stat::RingChecked) as f64 / probes as f64
    ));
    out.push_str(&format!(
        "derived tag_reject_share {:.4}\n",
        value(Stat::RingTagReject) as f64 / checked as f64
    ));
    out.push_str(&format!(
        "derived byte_reject_share {:.4}\n",
        value(Stat::RingByteReject) as f64 / checked as f64
    ));
    out.push_str(&format!(
        "derived prefix_reject_share {:.4}\n",
        value(Stat::RingPrefixReject) as f64 / checked as f64
    ));
    out.push_str(&format!(
        "derived prefix_hit_share {:.4}\n",
        value(Stat::RingPrefixHit) as f64 / checked as f64
    ));
    out.push_str(&format!(
        "derived bytes_per_length_call {:.3}\n",
        value(Stat::MatchLengthBytes) as f64 / value(Stat::MatchLengthCalls).max(1) as f64
    ));
    let opt_probes = value(Stat::OptProbes).max(1);
    let opt_checked = value(Stat::OptRingChecked).max(1);
    out.push_str(&format!(
        "derived opt_candidates_per_probe {:.3}\n",
        value(Stat::OptRingChecked) as f64 / opt_probes as f64
    ));
    out.push_str(&format!(
        "derived opt_tag_reject_share {:.4}\n",
        value(Stat::OptRingTagReject) as f64 / opt_checked as f64
    ));
    out.push_str(&format!(
        "derived opt_prefix_hit_share {:.4}\n",
        value(Stat::OptRingPrefixHit) as f64 / opt_checked as f64
    ));
    out
}

/// Zero every counter, so a caller can measure one member at a time.
pub fn reset() {
    for counter in COUNTERS.iter() {
        counter.store(0, Ordering::Relaxed);
    }
}
