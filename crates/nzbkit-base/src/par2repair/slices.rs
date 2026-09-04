//! Finding recovery slices in a buffer of PAR2 packets, one set at a
//! time or all of them at once.
//!
//! Out of `par2repair.rs` for the size gate (TODO 106), the same way
//! `catalog` and `reconstruct` are. The two finders are one subject and
//! came out together: they answer opposite sides of the same question
//! and their doc comments only make sense beside each other.
//!
//! Both report the length a packet ACTUALLY carries and judge nothing.
//! [`slice_fits_block`] is that judgement. It moved in here from
//! `catalog` on 31 Aug 2026 so the finders and the rule their callers
//! must apply to the answers sit in one file, and it moved on DOWN into
//! `par2` the same day (Y4b) once the parse turned out to need it too -
//! see its own comment there for what each split cost. It is re-exported
//! here, so this is still where a repair-side reader meets it.

use crate::par2;
use std::collections::HashMap;

/// Locate every valid recovery slice for `set_id` in a buffer of PAR2
/// packets: (exponent, offset of slice data, data length). Packets
/// failing their MD5 are already dropped by the scanner; duplicates are
/// NOT deduped here - callers dedupe by exponent across files.
///
/// The length reported is the packet's OWN, not the set's block size,
/// and that is deliberate: this function has no `Par2Set` and so cannot
/// know a block size (a buffer routinely holds several sets, each with
/// its own). Judging it is the caller's, with [`slice_fits_block`] and
/// nothing else - a caller that re-spells the comparison is the M4-56
/// defect, and the counting half of it went unnoticed for a day because
/// its direction is silent.
pub fn recovery_slice_locators(bytes: &[u8], set_id: &[u8; 16]) -> Vec<(u32, usize, usize)> {
    let mut out = Vec::new();
    par2::scan_packets(bytes, |pkt| {
        if &pkt.ptype == par2::TYPE_RECVSLIC && &pkt.set_id == set_id && pkt.body.len() >= 4 {
            let e = u32::from_le_bytes(pkt.body[0..4].try_into().unwrap());
            out.push((e, pkt.body_offset + 4, pkt.body.len() - 4));
        }
    });
    out
}

/// Every recovery slice in a buffer of PAR2 packets, GROUPED by the set
/// it belongs to: `(set id, slice data length, how many)`.
///
/// [`recovery_slice_locators`] answers about ONE set, which is what a
/// repair wants - it knows which set it is rebuilding. A CENSUS asks the
/// opposite question: it holds a file and a LIST of adopted sets, and a
/// volume can only ever belong to one of them. Calling the singular once
/// per set therefore reads the same bytes N times to answer 0 for N-1 of
/// them, and on a post carrying one recovery set per file (GH #63's
/// eighteen) that is an N-squared read of every volume on disk. One pass
/// answers all of them.
///
/// Same scanner and the same MD5 drop as the singular, and duplicates
/// are NOT deduped here either - a census counts what a file HOLDS, and
/// the caller dedupes across files if it needs to.
///
/// Length is a GROUPING KEY here, not a filter, for the reason the
/// singular gives: one buffer, several sets, several block sizes, and
/// this function is handed none of them. So the caller reads the groups
/// back through [`slice_fits_block`] - `>= bs`, never `== bs`, or a
/// padded volume reports as holding nothing.
pub fn recovery_slice_census(bytes: &[u8]) -> Vec<([u8; 16], usize, usize)> {
    let mut out: Vec<([u8; 16], usize, usize)> = Vec::new();
    // Key -> index into `out`, so a packet costs one hash rather than a
    // scan of every key already seen (X5-17). The scan was quadratic in
    // DISTINCT keys, which the doc comment above is precisely about: the
    // census exists because calling the singular once per set is an
    // N-squared READ, and it was paying an N-squared COMPARE to avoid it.
    // A buffer whose packets each carry their own set id is what a
    // malformed post looks like, and 16,000 of them cost 14x what 4,000
    // did. The map is the index only - `out` keeps first-appearance
    // order, which is what every caller reads.
    //
    // std's `RandomState` on purpose, NOT a faster non-cryptographic
    // hasher: the key is a set id straight off the wire, so the whole
    // point of this row is that somebody chooses it. A per-process
    // random seed is what stops a collision-tuned buffer putting the
    // quadratic scan back inside one bucket.
    let mut at: HashMap<([u8; 16], usize), usize> = HashMap::new();
    par2::scan_packets(bytes, |pkt| {
        if &pkt.ptype == par2::TYPE_RECVSLIC && pkt.body.len() >= 4 {
            let len = pkt.body.len() - 4;
            match at.entry((pkt.set_id, len)) {
                std::collections::hash_map::Entry::Occupied(e) => out[*e.get()].2 += 1,
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(out.len());
                    out.push((pkt.set_id, len, 1));
                }
            }
        }
    });
    out
}

/// The one spelling of the slice-length rule, re-exported here so it
/// still sits beside the two finders whose output it judges - and so
/// `par2repair::slice_fits_block`, which four call sites and their
/// tests name, keeps working.
///
/// It is DEFINED in [`crate::par2`], where its own doc comment lives,
/// and moved down there on 31 Aug 2026 (Y4b) because the PARSE has to
/// ask it too: `Par2Set::recovery_blocks_seen` is the fetch planner's seed
/// and had no length test at all, and `par2repair` depends on `par2`,
/// so a rule kept up here could not have one spelling. That it is a
/// statement about a PAR2 packet - the spec's layout, nothing about
/// repair - is why moving it DOWN was the right direction rather than
/// giving the parse a second comparison.
pub use crate::par2::slice_fits_block;
