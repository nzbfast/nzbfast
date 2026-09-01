//! The whole-volume read the settle path's slice arithmetic needs, with
//! the two things it had neither of: a `memgauge` charge, and the same
//! size ceiling the repair engine holds a packet file to.
//!
//! Three sites in the parent read a PAR2 recovery volume WHOLE, because
//! `usable_slices_of` counts recovery slices across the whole buffer and
//! a bounded read there UNDERCOUNTS parity - the one error in this area
//! that is invisible, since the planner refetches volumes it already has
//! and the repair still succeeds off slices it said were not there. So
//! the read cannot go, and [`settle::setid`] is deliberately NOT the
//! answer here. What can be fixed is what the read was not saying.
//!
//! MEASURED 31 Aug 2026 (`research/SET-ID-READ-BOUNDS-MEASURED-2026-08-31.md`,
//! residue item 1): `grep memgauge crates/nzbfast/src/get/settle.rs` and
//! its child modules returned NOTHING. Every one of these reads was
//! invisible to `memgauge` and so to the `[mem-floor]` line, while
//! `Sub::RepairScan`'s own doc comment describes exactly this shape -
//! "Repair-path transient whole-file reads ... one recovery volume at a
//! time, up to MAX_PACKET_FILE_BYTES" - and calls itself "the suspected
//! owner of the damaged-fixture ladder floor". These reads happen on a
//! RESUMED damaged job, which is that ladder's own scenario, so the
//! hypothesis the gauge exists to test was being tested with a hole in
//! it exactly where it mattered.
//!
//! THE CEILING IS A CONSISTENCY REQUIREMENT AND NOT ONLY A MEMORY BOUND,
//! which is the half that makes it a correctness fix rather than
//! hygiene. Both repair-side readers refuse a packet file over
//! [`nzbkit::par2repair::MAX_PACKET_FILE_BYTES`] - `collect_packet_files`
//! skips it by name and by sniff alike, and `PacketCatalog::build_lazy`
//! bounds its relist on the same constant - so a volume past it
//! contributes ZERO slices to the repair that actually runs. Settle
//! counting its slices into `on_hand` is therefore an OVERCOUNT of
//! parity nothing can ever spend: `needed` comes out too small, too few
//! volumes are fetched, and the repair fails with a shortfall no line of
//! the plan explains. Past the ceiling this answers `Some(empty)` - "we
//! looked, and the repair will see nothing here" - which is what the
//! engine will in fact see, and which the parent's own `partial` test
//! then handles without a special case.
//!
//! Its own file rather than inline, the same relationship `setid.rs` and
//! `dupenote.rs` already have to the parent. PAST TENSE on purpose:
//! `settle_with_set` sat at 492 of the size gate's 500-line function
//! ceiling when this landed on 31 Aug 2026, so both of its call sites
//! had to come out line-neutral, and they do - the function is 492
//! before and after. A present-tense claim here would be false the day
//! that function is split, which is the one event guaranteed to follow.

use super::*;

/// A recovery volume held whole, with its bytes charged to
/// [`nzbkit::memgauge::Sub::RepairScan`] for exactly as long as they are
/// resident.
///
/// A wrapper rather than a bare `Vec<u8>` because the charge has to
/// outlive the call and die with the buffer, and both of the parent's
/// call sites bind their bytes INSIDE a loop body - so the peak is one
/// volume at a time and the release has to happen at the end of each
/// iteration, not at the end of the loop. `Deref<Target = [u8]>` is what
/// keeps those sites line-neutral: `usable_slices_of(&bytes, set)` reads
/// exactly as it did.
///
/// `bytes` is declared FIRST so it drops first: the buffer leaves RSS
/// and only then is the gauge told. Nothing can observe the window
/// between (same thread, no yield), so this is honesty rather than a
/// load-bearing ordering.
pub(super) struct VolumeBytes {
    bytes: Vec<u8>,
    _charge: nzbkit::memgauge::Charge,
}

impl VolumeBytes {
    fn new(bytes: Vec<u8>) -> VolumeBytes {
        let charge =
            nzbkit::memgauge::Charge::new(nzbkit::memgauge::Sub::RepairScan, bytes.len() as u64);
        VolumeBytes {
            bytes,
            _charge: charge,
        }
    }
}

impl Default for VolumeBytes {
    /// No bytes and no charge. `memgauge::add`/`sub` both return early on
    /// zero, so an empty charge costs nothing and cannot drift the gauge.
    fn default() -> VolumeBytes {
        VolumeBytes::new(Vec::new())
    }
}

impl std::ops::Deref for VolumeBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

/// `path` read whole and charged, with NO ceiling.
///
/// The one caller is [`super::setid::set_id_at`]'s whole-file fallback,
/// which exists precisely because a volume whose first complete packet
/// runs past the id head would otherwise answer `None` - a silent wrong
/// answer at `main_par2_for`. Capping it would restore that silence for
/// the same file at a different size, so this door deliberately has no
/// ceiling and only ever adds the charge that read was missing.
pub(super) fn read_whole_charged(path: &Path) -> Option<VolumeBytes> {
    Some(VolumeBytes::new(std::fs::read(path).ok()?))
}

/// `path` read whole for slice counting, charged, and refused past the
/// packet-file ceiling the repair engine itself enforces.
///
/// `None` means the file could not be read AT ALL, which leaves each
/// caller's existing failure path exactly as it was. Past the ceiling is
/// `Some(empty)`, which is a different statement - we looked, and the
/// repair will find no usable slice here either.
pub(super) fn read_volume_for_slices(path: &Path) -> Option<VolumeBytes> {
    read_volume_bounded(path, nzbkit::par2repair::MAX_PACKET_FILE_BYTES)
}

/// [`read_volume_for_slices`] with the ceiling spelled out, so a test can
/// exercise the bound without writing a gigabyte - the same arrangement
/// `par2repair::collect_packet_files_bounded` makes, and for the same
/// reason.
///
/// The ceiling is checked against `metadata`, so a file that GROWS past
/// it between the check and the read is still slurped. That is the house
/// shape rather than an oversight: `collect_packet_files` measures the
/// same way through its directory walk and reads later, and these files
/// were written by this job's own settle path minutes earlier. A second
/// belt over the read would be a guard no test could falsify separately
/// from this one.
pub(super) fn read_volume_bounded(path: &Path, max_bytes: u64) -> Option<VolumeBytes> {
    let len = std::fs::metadata(path).ok()?.len();
    if len > max_bytes {
        warn!(
            file = %path.display(),
            bytes = len,
            ceiling = max_bytes,
            "recovery volume past the packet-file ceiling - counting zero slices, \
             which is what the repair will see: it skips the file too"
        );
        return Some(VolumeBytes::default());
    }
    Some(VolumeBytes::new(std::fs::read(path).ok()?))
}

// The charge, the ceiling, and - because no test in this module can see
// a CALLER that stopped using either - a source scan over the settle
// subtree's whole-file reads.
#[cfg(test)]
mod volbytes_tests;
