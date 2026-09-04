//! The head-digest ARBITER: what a slot's complete 16 KiB head says
//! about one descriptor, and which of a name's candidates that settles.
//!
//! Three callers, which is why it lives here rather than inline in any
//! one of them: the parent's in-stream name tier and `rejudge_binding`,
//! `nametier`'s finish-time `head_is_shared`, and `matchref`'s
//! reference drain.
//!
//! Split out of `live.rs` (TODO 106 size gate), bodies verbatim; a
//! child module, so `SlotState`'s private fields stay private to this
//! file's parent and its descendants.

use super::*;

/// What a slot's complete-head digest says about one name candidate.
///
/// `Unknown` is NOT a soft no: the descriptor's `md5_16k` covers
/// `min(16 KiB, its own length)` bytes and the slot's head covers
/// `min(16 KiB, the yEnc-declared size)`, so when those spans differ the
/// two digests can never be equal however right the name is. Comparing
/// them anyway would read "the poster's size header disagrees with the
/// FileDesc" as "this file is an impostor".
#[derive(PartialEq)]
pub(super) enum HeadSays {
    Confirm,
    Deny,
    Unknown,
}

pub(super) fn head_says(f: &crate::par2::Par2File, want: usize, key: [u8; 16]) -> HeadSays {
    if f.length.min(HEAD_LEN as u64) != want as u64 {
        HeadSays::Unknown
    } else if f.md5_16k == key {
        HeadSays::Confirm
    } else {
        HeadSays::Deny
    }
}

/// Arbitrate name candidates by the slot's head digest - the shared rule
/// behind both matchers' name tiers, so the indexed and linear drains
/// cannot drift on it. `Some((fi, true))` is a CLAIM, `Some((fi, false))`
/// a tentative binding, and `None` a DECLINE - never "unmatchable":
/// every path to it is resolvable later, by a twin's claim, by the
/// whole-file tier, or by [`SlotState::try_match_named`] at finish.
///
/// `key` is `None` while the head is still filling. The name tier then
/// claims NOTHING - a name is a nomination and the evidence that
/// finalizes it has not arrived. See [`SlotState::try_match`] for the
/// three measured crossings that rule exists for.
///
/// SEVERAL candidates confirming is the duplicate POSTING: one file in
/// two recovery sets, which is what a poster running par2create twice
/// over a directory emits, and the everyday per-file-set shape. Their
/// heads agree because their bytes do, so the first is taken - but
/// TENTATIVELY, because a shared 16 KiB head is not a shared file and
/// the blocks are what tell two of them apart. The first Ok block
/// promotes it in the same call for the duplicate-posting case, and a
/// pairing the blocks refuse is dropped at finish for the whole-file
/// tier to settle (matrix finding F1's rule, reached through a name).
pub(super) fn arbitrate_by_head(
    cands: &[usize],
    active: &Active,
    want: usize,
    key: Option<[u8; 16]>,
) -> Option<(usize, bool)> {
    let key = key?;
    let mut confirm: Option<usize> = None;
    let mut unknown: Option<usize> = None;
    let (mut n_confirm, mut n_unknown) = (0usize, 0usize);
    for &fi in cands {
        match head_says(active.file(fi), want, key) {
            HeadSays::Confirm => {
                n_confirm += 1;
                confirm.get_or_insert(fi);
            }
            HeadSays::Unknown => {
                n_unknown += 1;
                unknown.get_or_insert(fi);
            }
            HeadSays::Deny => {}
        }
    }
    if n_confirm > 0 {
        return confirm.map(|fi| (fi, n_confirm == 1));
    }
    // A SOLE INCOMPARABLE CANDIDATE, AND ONLY WHERE THE HEAD REALLY
    // CANNOT SPEAK (F12, 1 Sep 2026). `Unknown` covers two opposite
    // shapes and this arm used to claim on both, which left the
    // pre-W4-02 answer - a poster-controlled name finalizing a
    // descriptor on zero content evidence - alive for every file where
    // either side is under 16 KiB.
    //
    // The two shapes are told apart by DIRECTION. `want` bytes at
    // offset 0 are in hand and complete, so:
    //
    //   * `want` SHORTER than the descriptor's own 16k span - the slot
    //     has not reached the bytes the digest covers, the two spans
    //     can never be compared, and the head is silent. Claim, as
    //     before: this is the under-declared `size=` of W4-11, where
    //     declining would cost an intact member its in-stream
    //     verification.
    //   * `want` LONGER - the head covers the descriptor whole, and a
    //     complete head proves this slot's file has MORE bytes than the
    //     descriptor says its file has in total. That is a different
    //     file, and the head is not silent about it at all. Decline,
    //     and let the name stand as the nomination it is: the sole
    //     candidate is still bound TENTATIVELY by the caller, still
    //     verifies every block in-stream, and is settled at finish by
    //     `try_match_named`, which reads the descriptor's OWN 16k span
    //     and asks for per-block IFSC evidence (the W4-18 rule).
    if n_unknown == 1
        && let Some(fi) = unknown
        && (want as u64) < active.file(fi).length.min(HEAD_LEN as u64)
    {
        return Some((fi, true));
    }
    None
}
