//! The create request's SHAPE: what the caller asked for, validated, and
//! the set geometry that follows from it.
//!
//! Everything here runs before `CreateAdmission::acquire()` and that is
//! the seam, not a tidy-up: a request refused for its shape must never
//! charge the create gauge, so the whole of this has to finish - and be
//! able to return an error - before the budget is claimed. It is also
//! the ONE prepass over the members (the metadata loop, the head loop
//! and the scan's own stat used to be three), so nothing below it needs
//! to stat a member again.
//!
//! Split out of `par2gen.rs` on 17 Sep 2026 for the 500-line function
//! ceiling on [`super::create_body`] (claim
//! `create-body-prologue-split-17sep`). It went to its own FILE rather
//! than to a sibling function because `par2gen.rs` is the file this
//! module keeps running out of: a function extracted into the same file
//! buys function headroom by spending file headroom, which is what the
//! 15 Sep split of this same function did (`dc01f9057`, +38 file lines)
//! and what memory topic `nzbfast-size-gate-split-traps` records.
//!
//! A move and not a rewrite: every check, comment and error string below
//! is the one that was in the parent.

use super::{
    CreateControl, MAX_BLOCK_SIZE, MAX_INPUT_SLICES, Member, Par2GenError, Par2Spec,
    default_block_size, scan_heads, scan_lengths,
};

/// The validated request and the geometry it implies - what
/// [`super::create_body`] works from once [`resolve`] has returned.
pub(super) struct CreateShape {
    /// The 16 KiB head scan, `None` for an index-only create, which has
    /// no fold to overlap and defers the digest to its one full scan.
    /// `create_body` takes it, so it is owned rather than borrowed.
    pub(super) heads: Option<Vec<(usize, u64, [u8; 16], [u8; 16])>>,
    pub(super) lengths: Vec<u64>,
    pub(super) total: u64,
    pub(super) block_size: u64,
    pub(super) n_slices: usize,
    pub(super) n_recovery: usize,
}

/// Scan the members once, settle the block size, and count the input and
/// recovery slices - refusing any request whose shape cannot be built.
pub(super) fn resolve(
    members: &[Member],
    spec: &Par2Spec,
    exact_recovery: Option<usize>,
    control: &CreateControl,
) -> Result<CreateShape, Par2GenError> {
    // Recovery needs the head digest early to put input slices in file-id
    // order while the full hashes run beside the fold. Index-only creation has
    // no fold to overlap and can defer that digest to the one full scan, so it
    // reads lengths alone. Either way this is the ONE prepass: the metadata
    // loop, the head loop and the scan's own stat used to be three.
    let wants_recovery = exact_recovery.map_or(spec.redundancy_pct != 0, |n| n != 0);
    let heads = if !wants_recovery {
        None
    } else {
        Some(scan_heads(members, control)?)
    };
    let lengths: Vec<u64> = match &heads {
        Some(heads) => heads.iter().map(|&(_, length, _, _)| length).collect(),
        None => scan_lengths(members)?,
    };
    let Some(total) = lengths
        .iter()
        .try_fold(0u64, |total, &length| total.checked_add(length))
    else {
        return Err(Par2GenError::Other(
            "the total PAR2 member length overflowed u64".into(),
        ));
    };
    let block_size = match spec.block_size {
        Some(bs) => {
            if bs == 0 || !bs.is_multiple_of(4) || bs > MAX_BLOCK_SIZE {
                return Err(Par2GenError::Other(format!(
                    "PAR2 block size {bs} must be a positive multiple of 4 no larger than \
                     {MAX_BLOCK_SIZE}"
                )));
            }
            bs
        }
        None => default_block_size(total),
    };

    // Count in the on-disk width and validate BEFORE narrowing. On 32-bit, a
    // 16 GiB file at the four-byte minimum has 2^32 slices, and casting each
    // quotient to usize first wrapped that impossible request to zero.
    let Some(n_slices_u64) = lengths.iter().try_fold(0u64, |total, &length| {
        total.checked_add(length.div_ceil(block_size))
    }) else {
        return Err(Par2GenError::Other(
            "the PAR2 input-slice count overflowed u64".into(),
        ));
    };
    if n_slices_u64 > MAX_INPUT_SLICES as u64 {
        return Err(Par2GenError::Other(format!(
            "{n_slices_u64} input slices at a {block_size}-byte block exceeds the PAR2 \
             limit of {MAX_INPUT_SLICES} - raise the block size"
        )));
    }
    let n_slices = n_slices_u64 as usize;

    let n_recovery_u64 = match exact_recovery {
        Some(n) => n as u64,
        None if spec.redundancy_pct == 0 => 0,
        None => n_slices_u64
            .saturating_mul(spec.redundancy_pct as u64)
            .div_ceil(100)
            .max(1),
    };
    // Every recovery slice needs its own exponent against the same
    // coprime sequence the input slices walk, so the input limit is the
    // practical ceiling here too.
    if n_recovery_u64 > MAX_INPUT_SLICES as u64 {
        return Err(Par2GenError::Other(format!(
            "{n_recovery_u64} recovery slices exceeds the PAR2 limit of {MAX_INPUT_SLICES} \
             - lower the redundancy or raise the block size"
        )));
    }
    let n_recovery = n_recovery_u64 as usize;
    if n_recovery > 0 && n_slices == 0 {
        return Err(Par2GenError::Other(
            "a set of only 0-byte members has no slices to build parity over - post it \
             at zero redundancy"
                .into(),
        ));
    }

    Ok(CreateShape {
        heads,
        lengths,
        total,
        block_size,
        n_slices,
        n_recovery,
    })
}
