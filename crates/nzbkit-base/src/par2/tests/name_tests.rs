//! Wave-4 row M4-86 (31 Aug 2026): what `parse_filedesc` does with a
//! FileDesc name that is not valid UTF-8.
//!
//! A child of `par2`'s own `mod tests` rather than another case inside
//! it, because par2.rs was AT its 3,000-line size-gate ceiling when this
//! landed - it had ONE line of headroom, the declaration next door spent
//! it, and the blank line above that block's `use super::*` went with it.
//! par2.rs was split on 31 Aug 2026 (TODO 106: the framing walk and the
//! parsers to `par2/packet.rs`, the block-check grid and the verifiers to
//! `par2/verify.rs`), which took it to ~2,280 lines and handed that blank
//! line back, so `mod tests` will take a case again. This file stays
//! where it is: the subject is one subject, and the size gate is a
//! ceiling to keep clear rather than a budget to spend back down to.
//!
//! Being a child of that block rather than of `par2` is what makes the
//! packet builders reachable through `use super::*` with no visibility
//! change and no second `pkt` in this crate - two spellings of one
//! packet header is how the drift starts.

use super::*;

/// Wave-4 row M4-86 (31 Aug 2026): a FileDesc name that is not valid
/// UTF-8 at all.
///
/// The spec says the field is ASCII/UTF-8 and a poster who writes
/// CP1252 breaks that; `from_utf8_lossy` does not fail on it, it
/// SUBSTITUTES, so `caf\xE9.mkv` comes back `caf\u{FFFD}.mkv` and
/// nothing downstream can tell that spelling from one the poster
/// really chose. This pins the substitution rather than the repair:
/// re-reading those bytes as CP1252 would give `caf\u{e9}.mkv` and is
/// very likely what was meant, and it is an ENCODING GUESS, which
/// [`parse_unifilen`] refuses for this family in as many words - the
/// spec's channel for a non-ASCII name is the Unicode Filename
/// packet, which that function reads.
///
/// So this is the fact the fix leans on, held at the seam that
/// produces it: `get::settle::lossy_name_loses_to` recognises such a
/// name and brings the post's own readable spelling back after the
/// repair, and it can do that only while THIS function is what puts
/// the replacement character there. A lane that ever teaches this to
/// decode a legacy encoding should read that guard in the same pass -
/// it would then be dead code rather than wrong, and nothing else
/// would say so.
#[test]
fn a_filedesc_name_that_is_not_utf8_comes_back_lossily_decoded() {
    let set_id = [21u8; 16];
    let f = [7u8; 16];
    let mut body = f.to_vec();
    body.extend_from_slice(&[1u8; 16]);
    body.extend_from_slice(&[1u8; 16]);
    body.extend_from_slice(&1u64.to_le_bytes());
    body.extend_from_slice(b"caf\xE9.mkv");
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let mut buf = pkt(set_id, TYPE_MAIN, &main_ids(4, &[f]));
    buf.extend(pkt(set_id, TYPE_FILEDESC, &body));
    let set = Par2Set::parse(&[&buf]).unwrap();
    assert_eq!(
        set.files[0].name, "caf\u{fffd}.mkv",
        "the byte 0xE9 is not UTF-8 and is replaced, not decoded"
    );
    // And it survives to disk unchanged, which is what makes it a
    // user-visible defect rather than an internal spelling: the
    // sanitizer has no opinion about the replacement character.
    assert_eq!(
        crate::disk::sanitize_out_name(&set.files[0].name),
        "caf\u{fffd}.mkv"
    );
}
