//! The bounded reader for an ID-ONLY set read: which recovery set do
//! these bytes belong to, asked without holding the file.
//!
//! Two callers want this and nothing else from the file, so neither has
//! any reason to hold it whole - see [`set_id_at`]. The two RESUME sites
//! in the parent are deliberately not among them: `usable_slices_of`
//! counts recovery slices across the WHOLE volume, so a bounded read
//! there UNDERCOUNTS parity, and that error is the invisible one - the
//! planner refetches volumes it already has and the repair still
//! succeeds off slices it said were not there.

use super::*;

/// The head an ID-ONLY read takes, and it is NOT `SET_DEF_HEAD`'s
/// constraint wearing the same number.
///
/// `SET_DEF_HEAD` is sized for `pick_sets`, which needs the CRITICAL
/// packet set, so its comment reasons about the IFSC packet - 20 bytes
/// per slice, 16 MiB at 800k blocks. An id needs one COMPLETE packet of
/// any kind, which sounds far cheaper and is not, because of where
/// par2cmdline puts them. Measured 31 Aug 2026 against par2cmdline
/// 1.2.0: a recovery VOLUME opens with a full recovery slice packet and
/// the critical packets are INTERLEAVED after it, so the first complete
/// packet is `block_size + 68` bytes and the Main packet sits past it.
/// At `-s716800` (issue #63's block size) that is 716,868 bytes with
/// Main at 716,868; at `-s8388608` it is 8,388,676 with Main at
/// 8,388,676. So the floor here is the BLOCK SIZE, and a head chosen off
/// the "one packet header" intuition - 64 KiB, say - would find zero
/// complete packets on any ordinary volume and read no id at all.
///
/// 16 MiB is therefore ~23x the repo's own reference block size rather
/// than a copy of the constant above, and the two move independently.
pub(super) const SET_ID_HEAD: usize = 16 << 20;

/// The recovery set id `path`'s bytes claim, off a read bounded to `cap`.
///
/// Two callers ask "which set do these bytes belong to" and want NOTHING
/// else from the file, so neither has any reason to hold it whole:
/// `settle::repair`'s `main_par2_for` returns a `PathBuf`, and
/// `replace_bootstrap_slice_counts` reads the file whole only AFTER this
/// has told it which set it matched. Both were `std::fs::read` on a file
/// that is routinely hundreds of MB - `is_par2_main` comes from the
/// magic sniff, which `unpack::collect_par2_bytes`'s header says
/// "matches recovery VOLUMES, not just the index", and the in-stream
/// election can leave a large volume elected as bootstrap.
///
/// THE WHOLE-FILE FALLBACK IS NOT BELT AND BRACES, it is what makes this
/// an optimisation rather than a bet. A head that lands inside the first
/// packet yields no COMPLETE packet, `set_id_of` answers `None`, and at
/// `main_par2_for` that reads as "this index is not this set's" - a
/// SILENT wrong answer on a post whose block size runs past `cap`. So a
/// head that came back FULL and yielded nothing falls back to today's
/// behaviour exactly; a SHORT head is the whole file already and cannot
/// be hiding anything, so it returns straight away.
///
/// The stated limit: for a file carrying TWO sets' packets, `set_id_of`
/// tallies bytes across the whole buffer, so a bounded read and an
/// unbounded one can disagree - the head's answer stands. A real par2
/// file is one set's, so this is reachable only by construction, and it
/// is what `set_id_read_tests` drives to prove the bound is real.
pub(super) fn set_id_at(path: &Path, cap: usize) -> Option<[u8; 16]> {
    let head = read_head(path, cap)?;
    if let Some(id) = nzbkit::par2::Par2Set::set_id_of(&head) {
        return Some(id);
    }
    if head.len() < cap {
        return None;
    }
    // Through `volbytes` so the fallback's bytes are charged to
    // `Sub::RepairScan` while they are resident - the uncapped door,
    // because a ceiling here would restore the very silence this
    // fallback exists to end, one file size along.
    nzbkit::par2::Par2Set::set_id_of(&read_whole_charged(path)?)
}

// The bound, the fallback, the constant, and - because no test in this
// module can see a CALLER that stopped using them - a source scan over
// the two call sites.
#[cfg(test)]
mod set_id_read_tests;
