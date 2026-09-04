//! Real-content article supply for connection ladders (design doc 12.1).
//!
//! The synthetic probe group measured the wrong backend per provider:
//! xsnews read 0.20 Gbps on the probe group and 3.52 Gbps on real
//! articles in the same minute on the same box (BENCHMARKS 8 Aug) - a
//! deterministic 17x false low that none of the knee guards (suspect,
//! corroboration, jagged) can catch, because a re-probe of the same
//! wrong population reproduces it exactly and calls that corroboration.
//! So every ladder now measures articles from the install's OWN
//! downloads: the spooled NZBs of history jobs, newest first. That is
//! the population the knee is supposed to describe, and it is the only
//! one that cannot be structurally unrepresentative of it.
//!
//! Retention differs per provider - an article a fast primary holds may
//! not exist on a low-retention fill, and a ladder over 430s measures
//! nothing (conntune::MIN_LADDER_GBPS) - so the supply is STAT-checked
//! against the TARGET provider before any rung runs, at ~50 bytes per
//! sampled id. Jobs whose sample misses are dropped whole rather than
//! diluting the supply.
//!
//! When nothing usable exists (fresh install, empty history, every job
//! aged off this provider) the answer is NONE, and the caller must
//! leave the provider untuned: a wrong ladder is strictly worse than no
//! ladder, and the live tuner learns from the first real download
//! anyway. There is no probe-group fallback, silent or otherwise.

use nzbkit::config::ServerConfig;
use std::collections::HashSet;

/// Ladder supply target - matches what discover_ids used to fetch, and
/// outlasts a multi-gig line's 5 s rungs.
const TARGET_IDS: usize = 8_000;

/// Below this the rungs of a fast line drain the supply in well under a
/// second each and every reading is ramp-biased. Prefer no ladder.
const MIN_IDS: usize = 1_000;

/// Most spooled NZBs to parse per sourcing pass. History is newest
/// first here, so this is "the user's last 40 downloads".
const MAX_NZBS: usize = 40;

/// Stop parsing once this many ids are collected: 3x the target, so the
/// STAT gate can drop jobs and still leave a full supply.
const ENOUGH_IDS: usize = 3 * TARGET_IDS;

/// STAT sample size per contributing job...
const STATS_PER_JOB: usize = 8;

/// ...and how many of those may miss before the whole job is dropped.
/// One: a single takedown in an otherwise-present release is ordinary,
/// two of eight is a job this provider does not really hold.
const JOB_MISS_BUDGET: usize = 1;

/// Segment ids worth laddering with, from one NZB's XML. Same size band
/// discover_ids used: whole articles in the 300 KB - 1.2 MB range, the
/// shape the supply-sizing model assumes.
fn ids_from_nzb(xml: &[u8]) -> Vec<String> {
    let Ok(nzb) = nzbkit::nzb::Nzb::parse(xml) else {
        return Vec::new();
    };
    nzb.files
        .iter()
        .flat_map(|f| f.segments.iter())
        .filter(|s| (300_000..=1_200_000).contains(&s.bytes) && !s.message_id.is_empty())
        .map(|s| nzbkit::sysbench::bracket_id(&s.message_id))
        .collect()
}

/// Evenly spread sample indices over a job's ids, so the STAT verdict
/// covers the whole release rather than its first file.
fn sample_indices(len: usize, n: usize) -> Vec<usize> {
    let n = n.min(len);
    (0..n).map(|i| i * len / n).collect()
}

/// Interleave jobs' ids round-robin so no rung's slice is one release
/// on one group, capped at `target`. Order inside each job preserved.
fn interleave(jobs: &[Vec<String>], target: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(target.min(jobs.iter().map(|j| j.len()).sum()));
    let mut i = 0;
    loop {
        let mut any = false;
        for j in jobs {
            if let Some(id) = j.get(i) {
                any = true;
                if out.len() < target {
                    out.push(id.clone());
                }
            }
        }
        if !any || out.len() >= target {
            return out;
        }
        i += 1;
    }
}

/// The spooled NZB paths worth sourcing from, newest finished first.
/// Snapshot under the lock, parse outside it.
fn candidate_paths(d: &super::daemon::Daemon) -> Vec<std::path::PathBuf> {
    use crate::tools::MutexExt;
    let mut jobs: Vec<(i64, std::path::PathBuf)> = d
        .history
        .lock_ok()
        .iter()
        .filter_map(|j| {
            let g = j.lock_ok();
            // A real download completed: its articles existed recently.
            // Library (metadata-only) entries never fetched a byte but
            // their NZBs were availability-checked at add time - still a
            // fine id source; the STAT gate is the arbiter either way.
            (!g.nzb_path.as_os_str().is_empty())
                .then(|| (g.finished_unix.unwrap_or(0), g.nzb_path.clone()))
        })
        .collect();
    // Newest first; history is stored oldest-first, so equal stamps
    // (and the unstamped 0s) fall back to reverse insertion order.
    jobs.reverse();
    jobs.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    jobs.into_iter().map(|(_, p)| p).collect()
}

/// Build a STAT-verified real-article supply for one provider, or None
/// when the install has nothing safe to measure with.
pub async fn real_ladder_ids(d: &super::daemon::Daemon, srv: &ServerConfig) -> Option<Vec<String>> {
    // Collect per-job id lists from the newest spooled NZBs.
    let mut seen: HashSet<String> = HashSet::new();
    let mut jobs: Vec<Vec<String>> = Vec::new();
    let mut total = 0usize;
    for path in candidate_paths(d).into_iter().take(MAX_NZBS) {
        let Ok(xml) = std::fs::read(&path) else {
            continue; // spool file gone (tombstoned, migrated) - skip
        };
        let mut ids = ids_from_nzb(&xml);
        ids.retain(|id| seen.insert(id.clone()));
        if ids.len() < STATS_PER_JOB * 2 {
            continue; // too small to be worth a sample verdict
        }
        total += ids.len();
        jobs.push(ids);
        if total >= ENOUGH_IDS {
            break;
        }
    }
    if total < MIN_IDS {
        return None;
    }
    // STAT gate against THIS provider: one pipelined connection, a
    // spread sample per job, drop jobs that miss.
    let mut sample: Vec<String> = Vec::new();
    let mut owner: Vec<usize> = Vec::new();
    for (ji, ids) in jobs.iter().enumerate() {
        for i in sample_indices(ids.len(), STATS_PER_JOB) {
            sample.push(ids[i].clone());
            owner.push(ji);
        }
    }
    // A provider that cannot answer STATs cannot be laddered either.
    let present = nzbkit::sysbench::stat_presence(srv, &sample).await.ok()?;
    let mut misses = vec![0usize; jobs.len()];
    for (o, ok) in owner.iter().zip(&present) {
        if !ok {
            misses[*o] += 1;
        }
    }
    let survivors: Vec<Vec<String>> = jobs
        .into_iter()
        .zip(&misses)
        .filter_map(|(ids, &m)| (m <= JOB_MISS_BUDGET).then_some(ids))
        .collect();
    let out = interleave(&survivors, TARGET_IDS);
    (out.len() >= MIN_IDS).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nzb_with(sizes: &[u64]) -> Vec<u8> {
        let segs: String = sizes
            .iter()
            .enumerate()
            .map(|(i, b)| {
                format!(
                    r#"<segment bytes="{b}" number="{n}">seg{i}@test</segment>"#,
                    n = i + 1
                )
            })
            .collect();
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file poster="p" date="1" subject="a.rar (1/{n})">
  <groups><group>alt.binaries.test</group></groups>
  <segments>{segs}</segments>
 </file>
</nzb>"#,
            n = sizes.len()
        )
        .into_bytes()
    }

    /// Only whole articles in the ladder's size band count, and NZB ids
    /// (bare, per spec) come back bracketed for STAT/BODY.
    #[test]
    fn nzb_ids_are_band_filtered_and_bracketed() {
        let ids = ids_from_nzb(&nzb_with(&[700_000, 5_000, 2_000_000, 400_000]));
        assert_eq!(ids.len(), 2);
        assert!(ids.iter().all(|i| i.starts_with('<') && i.ends_with('>')));
        assert_eq!(ids[0], "<seg0@test>");
        assert_eq!(ids[1], "<seg3@test>");
        // Garbage XML is an empty list, not a panic.
        assert!(ids_from_nzb(b"not an nzb").is_empty());
    }

    /// The sample must span the release: a job whose tail was taken
    /// down would pass a head-only sample.
    #[test]
    fn sample_indices_span_the_job() {
        let idx = sample_indices(1000, 8);
        assert_eq!(idx.len(), 8);
        assert_eq!(idx[0], 0);
        assert!(*idx.last().unwrap() >= 875, "tail uncovered: {idx:?}");
        // Small jobs sample everything once, no repeats.
        assert_eq!(sample_indices(3, 8), vec![0, 1, 2]);
        assert!(sample_indices(0, 8).is_empty());
    }

    /// No rung's slice may be one release on one group: consecutive ids
    /// alternate across source jobs while both still have some.
    #[test]
    fn interleave_alternates_jobs_and_caps() {
        let a: Vec<String> = (0..4).map(|i| format!("<a{i}>")).collect();
        let b: Vec<String> = (0..2).map(|i| format!("<b{i}>")).collect();
        let out = interleave(&[a, b], 100);
        assert_eq!(out, vec!["<a0>", "<b0>", "<a1>", "<b1>", "<a2>", "<a3>"]);
        // The cap is respected mid-round.
        let a: Vec<String> = (0..4).map(|i| format!("<a{i}>")).collect();
        assert_eq!(interleave(&[a], 2).len(), 2);
        assert!(interleave(&[], 10).is_empty());
    }
}
