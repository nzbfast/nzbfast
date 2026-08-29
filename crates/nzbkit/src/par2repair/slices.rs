//! Finding recovery slices in a buffer of PAR2 packets, one set at a
//! time or all of them at once.
//!
//! Out of `par2repair.rs` for the size gate (TODO 106), the same way
//! `catalog` and `reconstruct` are. The two functions are one subject
//! and came out together: they answer opposite sides of the same
//! question and their doc comments only make sense beside each other.

use crate::par2;

/// Locate every valid recovery slice for `set_id` in a buffer of PAR2
/// packets: (exponent, offset of slice data, data length). Packets
/// failing their MD5 are already dropped by the scanner; duplicates are
/// NOT deduped here - callers dedupe by exponent across files.
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
pub fn recovery_slice_census(bytes: &[u8]) -> Vec<([u8; 16], usize, usize)> {
    let mut out: Vec<([u8; 16], usize, usize)> = Vec::new();
    par2::scan_packets(bytes, |pkt| {
        if &pkt.ptype == par2::TYPE_RECVSLIC && pkt.body.len() >= 4 {
            let len = pkt.body.len() - 4;
            match out
                .iter_mut()
                .find(|(id, l, _)| *id == pkt.set_id && *l == len)
            {
                Some((_, _, n)) => *n += 1,
                None => out.push((pkt.set_id, len, 1)),
            }
        }
    });
    out
}
