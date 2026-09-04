//! The bounded PAR2 packet-byte scan of a directory.
//!
//! One `read_dir`, the packet magic or a `.par2` name, and a memory cap -
//! nothing about extraction, and nothing about filing. It is here rather
//! than in `unpack` because both askers sit on opposite sides of that
//! module: `unpack::verify_dir` runs the diagnostic verify pass, and
//! `smart::setclaim` reads the same bytes to learn what a set DECLARES
//! before the junk sweep classifies by name alone. Leaving it in `unpack`
//! made the filing code reach up into the extraction module for a
//! directory read (step 1 of
//! research/PLAN-NZBFAST-CRATE-SPLIT-2026-09-01.md); `unpack` re-exports
//! both doors, so its own callers are unchanged.

use crate::archname::file_starts_with_par2_magic;
use anyhow::Result;
use std::path::PathBuf;

/// How many PAR2 bytes the diagnostic verify pass may hold at once.
///
/// A slice of the process budget, because nothing else on this path
/// consults it and the pass is nearly pure printing: `verify_dir`'s
/// verdict decides only `nzbfast verify`'s exit code and one settle
/// warning, so trading a complete recovery-block count for a bounded
/// footprint costs nothing else a caller can observe. A capped-out scan
/// reports `NothingToVerify` rather than a verdict, which is why the cap
/// cannot turn into a false conviction.
pub fn par2_scan_cap() -> u64 {
    (nzbkit::mem::process_budget().total / 8).clamp(64 << 20, 512 << 20)
}

/// Collect the PAR2 packet bytes in `dir` for the diagnostic verify pass,
/// bounded so an obfuscated recovery set cannot be resident all at once.
///
/// The magic sniff matches recovery VOLUMES, not just the index: on a
/// fully obfuscated post every one of them lands here under an
/// extensionless hash name, and a 10% recovery set on a 50 GB release is
/// several GB of them. Reading the lot into one live `Vec<Vec<u8>>` would
/// blow a container's memory clamp at settle, after the whole download.
/// Returns the bytes plus the number of candidates a cap kept out.
pub fn collect_par2_bytes(dir: &std::path::Path, total_cap: u64) -> Result<(Vec<Vec<u8>>, usize)> {
    /// Ceiling on one packet file, matching the sibling sniffer in
    /// `nzbkit::par2repair::collect_packet_files` so the two agree on what
    /// is too big to slurp. Generous on purpose: a legitimate `.par2` this
    /// large is rare, and the aggregate cap does the real work.
    const MAX_PACKET_FILE_BYTES: u64 = 1 << 30;

    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        // By name OR by the `PAR2\0PKT` packet magic. An obfuscated post
        // ships its index and recovery volumes as extensionless hashes,
        // and taking only the name meant this reported "no .par2 files"
        // over a directory holding a complete recovery set (issue #9).
        // Same rule `dir_has_par2` and `smart::par2_magic` use. The
        // eligibility test stays exactly that wide - it is the BYTES that
        // are capped below, never the sniff, because narrowing the sniff
        // is what issue #9 was.
        let by_name = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("par2"));
        if !by_name && !file_starts_with_par2_magic(&path) {
            continue;
        }
        paths.push(path);
    }
    // Sorted, like `collect_packet_files`: `name.par2` sorts ahead of
    // `name.vol*.par2`, so the index - which carries the complete critical
    // packet set - is in hand before a cap starts dropping recovery slices.
    // `read_dir` order is arbitrary and would drop them at random.
    paths.sort();

    let mut par2_bytes: Vec<Vec<u8>> = Vec::new();
    let mut held: u64 = 0;
    let mut skipped = 0usize;
    for path in paths {
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len > MAX_PACKET_FILE_BYTES || held.saturating_add(len) > total_cap {
            skipped += 1;
            continue;
        }
        let data = std::fs::read(&path)?;
        held += data.len() as u64;
        par2_bytes.push(data);
    }
    Ok((par2_bytes, skipped))
}
