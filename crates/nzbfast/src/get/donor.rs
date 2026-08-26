//! §293 plan-side adoption: strike a member file out of the fetch plan
//! when a failed predecessor already has it, whole and byte-exact.
//!
//! # What §293 shipped, and what it did not
//!
//! §293 threaded `donor_dirs` from the daemon's history through
//! `get::settle` / `get::tail` / `repair` to the disk repair's adoption
//! scan, and that arm is real: a repair that would otherwise report
//! Unrepairable completes, which is what its own A/B measures. But the
//! scan runs AFTER the fetch, so it can never pre-empt a download - and
//! §293's plan had asked for the other thing, in its own words:
//! "Baseline: successor fetches 100% of the post. Treatment: successor
//! fetches only the unadopted remainder."
//!
//! TODO 305 item 2 measured the gap off the mock's own body ledger: a
//! promoted spare whose predecessor left 39 of 40 payload blocks
//! verified on disk fetched **41 bodies for a 40-article payload** - the
//! whole payload plus the PAR2 main index. This module is that item.
//!
//! # Why it needs the successor's own PAR2 set, and fetches it
//!
//! Skipping a file has to be PROVED, because there is no way back: the
//! payload would never be fetched, and a repair cannot rebuild what was
//! never asked for. A repack - same names, same lengths, different bytes
//! - is exactly the shape that would poison it, and the only evidence
//! that separates a repack from the real thing is a digest the
//! SUCCESSOR's set states. An NZB carries none: a filename hint and
//! encoded segment sizes, nothing content-derived.
//!
//! So the pre-pass fetches the successor's PAR2 main index on its own,
//! ahead of the plan, and reads the FileDesc packets out of it. That
//! costs one small article set - the same index the plan fetches again a
//! moment later, because activation needs its packets in memory - and it
//! is the whole extra cost of this arm. It is paid only on a job that
//! HAS donors, which is a spare promotion, a hunt enqueue or a §284
//! parked switch; `donor_dirs` is documented empty on the CLI, the
//! sidecar and every ordinary job, and this returns without touching the
//! disk or the network for those.
//!
//! # Every failure is "no donation", never a failed job
//!
//! No par2 main in the NZB, a probe that answers nothing, a donor
//! directory that cannot be read, a copy that runs out of space, a file
//! whose name the NZB and the set spell differently: each of those
//! leaves the fetch plan exactly as it would have been. The property
//! `a_donor_with_wrong_bytes_donates_nothing_and_changes_nothing` pinned
//! for the repair-time arm is the rule here too, and the bar is one rung
//! stricter - that arm may adopt a BLOCK on a CRC hit confirmed by block
//! MD5, this one places a file only on its whole-file MD5.

use crate::*;
use nzbkit::nzb::FileKind;
use std::path::{Path, PathBuf};
use tracing::info;

/// What the pre-pass hands the plan.
#[derive(Default)]
pub(super) struct Donated {
    /// Indexed by NZB FILE index: this file's bytes are already in
    /// `out_dir`, so none of its articles may be queued.
    pub(super) by_file: Vec<bool>,
    /// `(nzb file index, on-disk name, length)` for the extractor and
    /// verifier seeds - the same three facts a crash resume's `SlotSeed`
    /// carries, and they take the same adopt path.
    pub(super) placed: Vec<(usize, String, u64)>,
    /// Declared bytes of the articles this saves, for the banner.
    pub(super) bytes: u64,
}

impl Donated {
    pub(super) fn any(&self) -> bool {
        !self.placed.is_empty()
    }
}

/// Ceiling on the whole pre-pass, which sits between the job starting
/// and its first payload byte. `probe_par2_set` already caps itself per
/// server; this caps the sum, so the worst case is a bounded delay
/// rather than three thirty-second timeouts in a row.
const PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

/// The set name an NZB file would be posted under, folded the way
/// `census.rs` folds it: the PAR2 FileDesc and the NZB subject are two
/// records of one filename written by different tools.
fn fold(name: &str) -> String {
    nzbkit::disk::sanitize_filename(name).to_lowercase()
}

pub(super) async fn adopt_from_donors(
    servers: &[nzbkit::config::ServerConfig],
    nzb: &Nzb,
    out_dir: &Path,
    donors: &[PathBuf],
) -> Donated {
    let mut out = Donated {
        by_file: vec![false; nzb.files.len()],
        ..Default::default()
    };
    if donors.is_empty() || servers.is_empty() {
        return out;
    }
    // The index, not a recovery volume: only the main index is
    // guaranteed to carry the FileDesc packets for every member, and a
    // volume's recovery slices would be megabytes of nothing this pass
    // reads.
    let Some(main) = nzb.files.iter().find(|f| f.kind() == FileKind::Par2Main) else {
        return out;
    };
    let ids: Vec<String> = main
        .segments
        .iter()
        .map(|s| format!("<{}>", s.message_id))
        .collect();
    if ids.is_empty() {
        return out;
    }
    // Ask the cheap question first. Fetching the index is this pass's
    // entire cost, and a donor directory that offers no file at all -
    // already swept, or unreadable - can never repay it.
    if nzbkit::par2repair::donor_candidates(donors, out_dir) == 0 {
        return out;
    }
    // Which member names this NZB actually posts, so a member the plan
    // could not strike out is never copied: bytes in `out_dir` under a
    // name no slot writes are bytes the fetch would then write a second
    // copy of beside. An obfuscated post - whose subjects are hashes and
    // whose real names live only in the FileDesc packets - maps nothing
    // here and donates nothing, which is a stated limit of this arm
    // rather than a bug: the pre-fetch has no yEnc `name=` to read.
    let mut want: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (fi, f) in nzb.files.iter().enumerate() {
        if f.kind() != FileKind::Data || f.segments.is_empty() {
            continue;
        }
        if let Some(hint) = f.filename_hint_lenient() {
            // A repeated name identifies no single file, so NEITHER
            // claim is trusted - the same rule `probe_recovery_set`
            // applies to a FileDesc length two members disagree about.
            // Donating to the first would put the bytes at a name the
            // second file's writer then has to be disambiguated away
            // from, which is worse than fetching both.
            match want.entry(fold(hint)) {
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    o.insert(usize::MAX);
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(fi);
                }
            }
        }
    }
    want.retain(|_, fi| *fi != usize::MAX);
    if want.is_empty() {
        return out;
    }
    // The probe bounds itself per server (three servers, thirty seconds
    // each), and this bounds the sum: a switch job whose index is
    // unfetchable everywhere must not hold its own download at the
    // starting line for a minute and a half to learn that. It will fetch
    // the index again in the plan and fail there on its own terms.
    let t0 = std::time::Instant::now();
    let probe = nzbkit::preflight::probe_par2_set(servers, &ids);
    let Ok(Some(mut set)) = tokio::time::timeout(PROBE_BUDGET, probe).await else {
        info!(
            target: "repair",
            "donor adoption: the recovery set's index did not come back in {:.2?} - \
             fetching the post in full",
            t0.elapsed()
        );
        return out;
    };
    set.files.retain(|f| want.contains_key(&fold(&f.name)));
    if set.files.is_empty() {
        return out;
    }
    let placed = nzbkit::par2repair::donate_whole_files(&set, donors, out_dir);
    for d in placed {
        let Some(&fi) = want.get(&fold(&d.name)) else {
            continue;
        };
        if out.by_file[fi] {
            continue;
        }
        out.by_file[fi] = true;
        out.bytes = out
            .bytes
            .saturating_add(nzb.files[fi].segments.iter().map(|s| s.bytes).sum::<u64>());
        out.placed.push((fi, d.name, d.length));
    }
    if out.any() {
        info!(
            target: "repair",
            "donor adoption: {} whole file(s) taken off the predecessor's disk in {:.2?} - \
             {:.1} MB of this post will not be fetched",
            out.placed.len(),
            t0.elapsed(),
            out.bytes as f64 / 1e6,
        );
    }
    out
}
