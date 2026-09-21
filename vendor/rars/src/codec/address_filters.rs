//! Address-conversion filters for executable code.
//!
//! Three transforms, each implemented exactly once and parameterised by
//! direction, so the archive reader and the archive writer run the same code:
//!
//! - x86 call/jump: RAR 5 filter types 1 (calls) and 2 (calls and jumps), and
//!   the RAR 3 standard programs of the same two kinds. The formats differ in
//!   one place only: RAR 5 reduces an operand's position into the 16 MiB
//!   window, RAR 3 keeps all 32 bits.
//! - ARM branch-with-link: RAR 5 filter type 3.
//! - IA-64 branch: the RAR 3 standard IA-64 program.
//!
//! "Decode" is the reader's direction (filtered bytes back to the original),
//! "encode" the writer's. Every entry point works in place on exactly one
//! filter block and receives `file_offset`, the member-relative offset of
//! `data[0]` truncated to 32 bits. It handles every length (0 included) and
//! every offset, runs in linear time, never allocates, never panics, and
//! reads and writes nothing outside `data`.
//!
//! Written from nzbfast's `research/cleanroom/SPEC-C-address-filters.md`.

#![deny(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Filtered bytes back to the original bytes (the archive reader).
    Decode,
    /// Original bytes to filtered bytes (the archive writer).
    Encode,
}

/// Which x86 opcodes introduce a 32-bit displacement to convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum X86Opcodes {
    /// Near calls only (`0xE8`).
    Call,
    /// Near calls and near jumps (`0xE8` and `0xE9`).
    CallAndJump,
}

/// Which archive format's rule for an operand's position applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum X86Format {
    /// RAR 5: the position is reduced modulo 16 MiB.
    Rar5,
    /// RAR 3: the position is used as a full 32-bit value.
    Rar3,
}

/// The x86 call/jump transform.
pub(crate) fn x86(
    data: &mut [u8],
    file_offset: u32,
    direction: Direction,
    opcodes: X86Opcodes,
    format: X86Format,
) {
    use Direction::{Decode, Encode};
    use X86Format::{Rar3, Rar5};
    use X86Opcodes::{Call, CallAndJump};
    // The block census, for the lane picking `X86_PROBE_BYTES`. Off unless a
    // bench-internals build turned it on, and absent from every other build.
    #[cfg(feature = "bench-internals")]
    if direction == Direction::Decode && census::enabled() {
        let rar5 = format == X86Format::Rar5;
        match opcodes {
            X86Opcodes::CallAndJump => census::record::<true>(data, rar5),
            X86Opcodes::Call => census::record::<false>(data, rar5),
        }
    }
    // Eight monomorphic passes of the one implementation below, so the hot
    // loop carries no per-byte test of any of the three parameters.
    match (direction, opcodes, format) {
        (Decode, Call, Rar5) => x86_pass::<false, false, true>(data, file_offset),
        (Decode, CallAndJump, Rar5) => x86_pass::<false, true, true>(data, file_offset),
        (Decode, Call, Rar3) => x86_pass::<false, false, false>(data, file_offset),
        (Decode, CallAndJump, Rar3) => x86_pass::<false, true, false>(data, file_offset),
        (Encode, Call, Rar5) => x86_pass::<true, false, true>(data, file_offset),
        (Encode, CallAndJump, Rar5) => x86_pass::<true, true, true>(data, file_offset),
        (Encode, Call, Rar3) => x86_pass::<true, false, false>(data, file_offset),
        (Encode, CallAndJump, Rar3) => x86_pass::<true, true, false>(data, file_offset),
    }
}

/// The ARM branch-with-link transform.
pub(crate) fn arm(data: &mut [u8], file_offset: u32, direction: Direction) {
    match direction {
        Direction::Decode => arm_pass::<false>(data, file_offset),
        Direction::Encode => arm_pass::<true>(data, file_offset),
    }
}

/// The IA-64 branch transform.
pub(crate) fn ia64(data: &mut [u8], file_offset: u32, direction: Direction) {
    match direction {
        Direction::Decode => ia64_pass::<false>(data, file_offset),
        Direction::Encode => ia64_pass::<true>(data, file_offset),
    }
}

// ---------------------------------------------------------------------------
// x86
// ---------------------------------------------------------------------------

/// The absolute-target window: 16 MiB.
const WINDOW: u32 = 1 << 24;

/// Operands are displacements of near calls and jumps. The encoder turns a
/// displacement whose target lands inside the window into that absolute
/// target, which repeats across a binary and compresses better; the decoder
/// turns it back. Seen as signed values, both directions work cyclically on
/// the interval `[-offset, WINDOW)`: decode subtracts `offset`, encode adds
/// it, and anything outside the interval is left alone.
#[inline(never)]
fn x86_pass<const ENCODE: bool, const JUMP: bool, const RAR5: bool>(
    data: &mut [u8],
    file_offset: u32,
) {
    visit_x86_operands::<JUMP>(data, |position, operand| {
        // The operand's own position, one byte past its opcode. Truncating
        // `position` is exact: only its value modulo 2^32 can matter.
        let mut offset = file_offset.wrapping_add(position as u32).wrapping_add(1);
        if RAR5 {
            offset &= WINDOW - 1;
        }
        let value = u32::from_le_bytes(*operand);
        let mapped = if ENCODE {
            x86_encode_operand(value, offset)
        } else {
            x86_decode_operand(value, offset)
        };
        *operand = mapped.to_le_bytes();
    });
}

#[inline(always)]
fn x86_decode_operand(value: u32, offset: u32) -> u32 {
    if value < WINDOW {
        // An absolute target inside the window (top byte zero).
        value.wrapping_sub(offset)
    } else if reaches_back(value, offset) {
        // A target below the start of the member, stored shifted up by one
        // window so it does not collide with the absolute targets.
        value.wrapping_add(WINDOW)
    } else {
        value
    }
}

#[inline(always)]
fn x86_encode_operand(value: u32, offset: u32) -> u32 {
    let absolute = value.wrapping_add(offset);
    let lowered = value.wrapping_sub(WINDOW);
    if absolute < WINDOW {
        absolute
    } else if reaches_back(lowered, offset) {
        lowered
    } else {
        value
    }
}

/// Whether `value` read as a signed displacement lies in `[-offset, 0)`.
///
/// That signed range is the rule while `offset <= 2^31`, which always holds
/// for RAR 5 (whose offset is reduced into the 16 MiB window). A RAR 3
/// operand past 2 GiB into its member has a larger offset, and there the
/// rule is stated on bit 31 instead: the value is negative and adding the
/// offset makes it non-negative.
///
/// The bit-31 statement covers BOTH cases, so this is one expression and not
/// a choice between two. For `value >= 2^31` and `offset <= 2^31` the sum
/// lies in `[2^31, 2^32 + 2^31)`, and it clears bit 31 exactly when it
/// wraps, which is exactly `value >= 2^32 - offset`, which is the signed
/// range. Writing it this way SPARES the RAR 3 arm a test of `offset` per
/// operand that it used to pay and that could never fail in practice: the
/// whole predicate is now three instructions with no branch in it.
#[inline(always)]
fn reaches_back(value: u32, offset: u32) -> bool {
    (value & !value.wrapping_add(offset)) >> 31 == 1
}

/// Calls `visit(position, operand)` for each trigger opcode, left to right,
/// where `operand` is the four bytes after the opcode byte at `position`.
///
/// After a trigger the scan resumes five bytes on, so operand bytes are never
/// tested, and a trigger without four whole bytes after it is ignored. Only
/// opcode bytes are tested and they are never written, so a buffer and its
/// transformed image visit the same positions in either direction.
#[inline(always)]
fn visit_x86_operands<const JUMP: bool>(
    data: &mut [u8],
    mut visit: impl FnMut(usize, &mut [u8; 4]),
) {
    let mut start = 0;
    while let Some(position) = next_x86_trigger::<JUMP>(data, start) {
        if let Some(operand) = data
            .get_mut(position + 1..)
            .and_then(|rest| rest.first_chunk_mut::<4>())
        {
            visit(position, operand);
        }
        start = position + 5;
    }
}

/// How far the word-at-a-time probe runs before the vector search takes
/// over, in bytes.
///
/// Measured on the `C1-tiled` bench corpus (a real executable), 16 Sep 2026:
/// scanning for calls alone, the gap from one trigger to the next is a
/// median of 17 bytes and NEVER under 8, while scanning for calls and jumps
/// half the gaps are under 8. So a probe one word wide resolved every
/// call-and-jump second gap and no call-only gap at all, and in the
/// call-only modes every trigger on that corpus paid a `memchr` call over a
/// ten-byte haystack - a non-inlined call with a vector prologue to cover a
/// distance a word probe crosses in two instructions. That is the whole of
/// the 0.76-0.86x x86-64 regression the 16 Sep round found, and the reason
/// it showed up in the call-only modes and not the call-and-jump ones.
///
/// A 32-byte probe covered 255 of that corpus's 256 call-only gaps, which is
/// what took the width from 8 to 32 and fixed that regression. It is 128 now,
/// for the reasons at the foot of this comment; the argument that used to
/// close this paragraph - that sparse data reaching the vector search after a
/// few more probes is "nothing against the run it is about to cross" - stays
/// RETRACTED. It is not nothing: crossing a sparse run at 128 costs up to 12%,
/// and that cost is measured rather than argued. What changed is not the cost
/// but whether anything on this path ever pays it.
///
/// **32 IS MEASURABLY A BAD WIDTH, ON BOTH ARCHITECTURES** (16 Sep 2026,
/// claim `rars-auto-x86-scan-probe-16sep`). This comment used to say that
/// wider probes were rejected because they lose on sparse data, citing a
/// sweep over trigger-free runs; that sweep's corpus used a FIXED STRIDE,
/// which pins every `memchr` call at one alignment - and at a DIFFERENT
/// alignment for the 8-byte arm than for every wider one - and is worth a
/// factor of 2.4 to the baseline on its own. Re-drawn with GEOMETRIC gaps of
/// the same mean, on an M3 Ultra and on an x86 part, 32 is the worst or
/// second-worst arm on nearly every readable row of both: 64 or 128 wins for
/// dense and real-binary inputs, 8 or 16 wins past a mean gap of about 256,
/// and 256 is past the crossover everywhere. The retracted sweep and the
/// redraw are in nzbfast
/// `research/rarbench-2026-09-16/specc-e8fix/16sep-probe-width-sparse.txt`
/// and `research/AUTO-X86-SCAN-PROBE-2026-09-16.md`.
///
/// **The callers of THIS constant have now been measured too, and 32 lost
/// there as well** (16 Sep 2026, claim `rars-x86-probe-bytes-apply-path-16sep`,
/// nzbfast `research/X86-PROBE-BYTES-APPLY-PATH-2026-09-16.md`). They are the
/// filter-application path, which skips five bytes past each trigger and
/// converts as it goes, so its gaps are the chooser's minus four and its
/// per-trigger work is much larger - large enough that the scan might not have
/// been its bottleneck at all, which would have been a finding of its own. It
/// is: `benches/address_filters.rs`'s probe-width leg, on four real Windows
/// PEs and on geometric-gap synthetics, puts 64 at 1.02-1.13x of 32 and 128 at
/// 1.05-1.18x on every real-binary row of BOTH architectures, and 32 is never
/// the best arm on any of them.
///
/// **128 rather than 64, and what decided it is the block census the previous
/// paragraph was waiting on** (16 Sep 2026, claim
/// `rars-probe-width-rar3-decode-block-gaps-16sep`, nzbfast
/// `research/X86-PROBE-BYTES-APPLY-PATH-2026-09-16.md`). 128 is the better arm
/// on every real-binary row of both architectures and 64 is the safer one only
/// at the sparse end: past a median trigger gap of about 180 bytes the ordering
/// inverts, where 128's worst row of the sweep is 0.88x against 64's 0.95x. So
/// the question was never which arm is faster, it was whether a block this path
/// is GIVEN can be sparse. It cannot, on the read path any more than the write
/// one. Censused as a DECODE receives them - `examples/x86_block_census.rs`,
/// 102 archives written by real RAR 7.23 over real x86-64 and i386 binaries and
/// over 196 MB of non-code data, 3,150 blocks, 201 MB of filtered bytes, plus a
/// wild RAR 3.x archive of a real Windows application - **98.4% of filtered
/// bytes sit in blocks whose median trigger gap is 64 bytes or less**, the
/// byte-weighted p90 of that median is 38 and its p99 is 83. Not one byte of
/// non-code data was filtered at all: the encoder's own detector never fired on
/// text, PDFs, tarballs or high-entropy data, so the sparse block the maximin
/// reading was protecting against is not in the population.
///
/// **The one way to reach the sparse end is `-mce+`**, RAR's switch for
/// applying the x86 filter to all processed data whatever its detector thinks,
/// which its own manual introduces under "improper use of this switch". Forced
/// that way over the same non-code corpus, 30% of filtered bytes land in blocks
/// past a median gap of 180 and those blocks pay the 0.88x. That cost is
/// accepted deliberately and it is worth naming why: an archive built that way
/// is one where the filter was already a mistake, half of those bytes are in
/// blocks with fewer than two triggers - one long crossing, where the probe
/// width is a rounding error against the vector search - and it buys 3 to 9
/// points on every archive anybody actually makes.
const X86_PROBE_BYTES: usize = 128;

/// The first trigger at or after `start` that has a whole operand after it.
///
/// The crate's ONE x86 trigger scan since 16 Sep 2026. `src/fast.rs` carried a
/// second one - `next_x86_opcode`, taking a runtime `cmp_mask` and an explicit
/// end bound - which went straight to `memchr` on every call with no probe at
/// all; the RAR writer's `x86_filter_scan::auto_x86_filter_ranges` was its last
/// caller and now calls this, so that file is gone. The two differed only in
/// how they were parameterised: `cmp_mask` was `0xff` or `0xfe` and nothing
/// else, which is `JUMP`, and the end bound was always `data.len() - 4`, which
/// is what this computes. Neither difference was load-bearing, so there is
/// nothing here for a future lane to re-derive.
#[inline(always)]
pub(crate) fn next_x86_trigger<const JUMP: bool>(data: &[u8], start: usize) -> Option<usize> {
    let candidates = data.get(start..data.len().saturating_sub(4))?;
    // In code the next opcode is usually close: a word-at-a-time probe over
    // the first `X86_PROBE_BYTES` settles that before paying for a vector
    // search call, which is what sparse data needs instead.
    let mut probed = 0;
    while probed < X86_PROBE_BYTES {
        let rest = candidates.get(probed..)?;
        let Some(word) = rest.first_chunk::<8>() else {
            // Fewer than eight bytes left to look at.
            return rest
                .iter()
                .position(|&byte| is_x86_trigger::<JUMP>(byte))
                .map(|index| start + probed + index);
        };
        let hits = x86_trigger_bits::<JUMP>(u64::from_le_bytes(*word));
        if hits != 0 {
            return Some(start + probed + (hits.trailing_zeros() / 8) as usize);
        }
        probed += 8;
    }
    let rest = candidates.get(probed..)?;
    let found = if JUMP {
        memchr::memchr2(0xe8, 0xe9, rest)
    } else {
        memchr::memchr(0xe8, rest)
    };
    found.map(|index| start + probed + index)
}

#[inline(always)]
fn is_x86_trigger<const JUMP: bool>(byte: u8) -> bool {
    if JUMP {
        byte | 1 == 0xe9
    } else {
        byte == 0xe8
    }
}

/// Bit 7 of byte `i` of the result is set when byte `i` of `word` (little
/// endian) is a trigger. The lowest set bit is exact; a borrow can also set
/// bits above a real hit, but the caller reads only the lowest.
#[inline(always)]
fn x86_trigger_bits<const JUMP: bool>(word: u64) -> u64 {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    // Setting bit 0 everywhere folds 0xE8 onto 0xE9, so one comparison
    // covers both opcodes.
    let (folded, pattern) = if JUMP {
        (word | ONES, 0xe9 * ONES)
    } else {
        (word, 0xe8 * ONES)
    };
    let zero_where_trigger = folded ^ pattern;
    zero_where_trigger.wrapping_sub(ONES) & !zero_where_trigger & HIGHS
}

// ---------------------------------------------------------------------------
// ARM
// ---------------------------------------------------------------------------

/// Words are taken at multiples of four from the start of the block. A word
/// whose top byte is 0xEB (branch with link, condition "always") carries a
/// 24-bit offset counted in words; the encoder adds the word's own index
/// (the file offset in words), the decoder subtracts it. Trailing bytes that
/// do not fill a word are left alone.
#[inline(never)]
fn arm_pass<const ENCODE: bool>(data: &mut [u8], file_offset: u32) {
    // Only the index modulo 2^24 matters, so dividing the offset first and
    // then counting words (with 32-bit wrapping) gives the same field.
    let first_index = file_offset >> 2;
    // `chunks_exact_mut` leaves the trailing bytes out; every chunk it yields
    // is a whole word, so `first_chunk_mut` never misses one.
    for (index, chunk) in data.chunks_exact_mut(4).enumerate() {
        let Some(word) = chunk.first_chunk_mut::<4>() else {
            continue;
        };
        let value = u32::from_le_bytes(*word);
        let target = first_index.wrapping_add(index as u32);
        let shift = if ENCODE {
            target
        } else {
            target.wrapping_neg()
        };
        let moved = (value & 0xff00_0000) | (value.wrapping_add(shift) & 0x00ff_ffff);
        // Every word is written back, rewritten or not, so the loop has no
        // branch for the compiler to keep.
        *word = if value >> 24 == 0xeb { moved } else { value }.to_le_bytes();
    }
}

// ---------------------------------------------------------------------------
// IA-64
// ---------------------------------------------------------------------------

/// The 20-bit immediate field of an instruction slot.
const IA64_FIELD: u32 = 0x000f_ffff;

/// Which of a bundle's three instruction slots may hold a branch, by
/// template (bits 1-4 of the bundle's first byte). Three bits per template,
/// bit `j` for slot `j`, packed so the lookup is a shift and not a branch.
const IA64_BRANCH_SLOTS: u64 = ia64_slots(0x8, 0b100)
    | ia64_slots(0x9, 0b110)
    | ia64_slots(0xb, 0b111)
    | ia64_slots(0xc, 0b100)
    | ia64_slots(0xe, 0b100);

const fn ia64_slots(template: u32, slots: u64) -> u64 {
    slots << (3 * template)
}

/// Bundles are 16 bytes, aligned to the start of the block, and one is
/// processed only when at least six more bytes follow it. In each branch
/// slot whose 4-bit major opcode is 5, the 20-bit immediate is moved by the
/// bundle's index (the file offset in bundles), modulo 2^20.
#[inline(never)]
fn ia64_pass<const ENCODE: bool>(data: &mut [u8], file_offset: u32) {
    // `P + 22 <= n` for `P = 16k` admits exactly `(n - 6) / 16` bundles.
    let count = data.len().saturating_sub(6) / 16;
    let Some(region) = data.get_mut(..count * 16) else {
        return;
    };
    let first_index = file_offset >> 4;
    for (index, chunk) in region.chunks_exact_mut(16).enumerate() {
        let Some(bundle) = chunk.first_chunk_mut::<16>() else {
            continue;
        };
        let target = first_index.wrapping_add(index as u32);
        let shift = if ENCODE {
            target
        } else {
            target.wrapping_neg()
        };
        *bundle = ia64_bundle(u128::from_le_bytes(*bundle), shift).to_le_bytes();
    }
}

/// One bundle, read as a little-endian 128-bit integer.
///
/// Slot `j` starts at byte `2 + 5j` with its fields shifted up by `j + 2`
/// bits inside that byte-aligned word, so its immediate starts at bit
/// `8(2 + 5j) + j + 2 = 18 + 41j` and its major opcode 24 bits above that.
/// No write reaches the template, an opcode, or another slot's field, so
/// the three slots are independent.
#[inline(always)]
fn ia64_bundle(bundle: u128, shift: u32) -> u128 {
    let template = (bundle >> 1) as u32 & 0xf;
    let slots = (IA64_BRANCH_SLOTS >> (3 * template)) as u32;
    let mut out = bundle;
    for slot in 0..3 {
        let field_at = 18 + 41 * slot;
        let opcode = (bundle >> (field_at + 24)) as u32 & 0xf;
        // All ones over the field when this slot is a branch, zero otherwise:
        // chosen by masking rather than a test, so random templates cost the
        // processor no mispredicted branches.
        let branch = (slots >> slot) & u32::from(opcode == 5) & 1;
        let select = 0u32.wrapping_sub(branch) & IA64_FIELD;
        let field = (bundle >> field_at) as u32 & IA64_FIELD;
        let moved = field.wrapping_add(shift) & IA64_FIELD;
        out ^= u128::from((field ^ moved) & select) << field_at;
    }
    out
}

// ---------------------------------------------------------------------------
// Entry points for the benches and fuzz targets, which can reach only public
// items. Not part of the crate's API.
// ---------------------------------------------------------------------------

/// A census of the filter blocks a DECODE receives, for the lane that has to
/// decide `X86_PROBE_BYTES` on evidence rather than on the write path's
/// structure.
///
/// The write path's blocks are dense by construction - the RAR 5 writer's
/// range chooser picks a range BECAUSE its triggers cluster - but a decode
/// applies the filter wherever the archive says, and the archive was written
/// by somebody else's encoder. This records, per block and as the
/// application path itself walks it, the block's length and the quantiles of
/// its trigger-to-trigger gaps, so a round can say whether a foreign encoder
/// ever hands the decoder a sparse block.
///
/// Off unless `enable()` is called, and gated behind `bench-internals` so no
/// shipped build carries the test or the lock.
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod census {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// One filter block as the decoder received it.
    #[derive(Debug, Clone, Copy)]
    pub struct Block {
        /// The block's length in bytes.
        pub len: usize,
        /// Whether jumps count as triggers as well as calls.
        pub jump: bool,
        /// RAR 5 rather than RAR 3.
        pub rar5: bool,
        /// Triggers the application path visited in this block.
        pub triggers: usize,
        /// Trigger-to-trigger gap quantiles, in bytes. Zero when the block
        /// holds fewer than two triggers. This is the measure
        /// `benches/address_filters.rs` reports, so it is what the probe-width
        /// tables' "median gap" columns compare against.
        pub p50: usize,
        pub p90: usize,
        pub max: usize,
        /// The same quantiles over every distance the SCAN crosses, which is
        /// the interior gaps plus the run before the first trigger and the run
        /// after the last one. A block with no trigger at all crosses its whole
        /// length once and is maximally sparse, which the interior measure
        /// cannot say - it reports zero, the same as a block whose triggers are
        /// adjacent. The probe is paid per scan, so this is the measure that
        /// decides the constant.
        pub scan_p50: usize,
        pub scan_p90: usize,
        pub scan_max: usize,
    }

    static ON: AtomicBool = AtomicBool::new(false);
    static BLOCKS: Mutex<Vec<Block>> = Mutex::new(Vec::new());

    /// Starts recording, and drops anything already recorded.
    pub fn enable() {
        if let Ok(mut blocks) = BLOCKS.lock() {
            blocks.clear();
        }
        ON.store(true, Ordering::Relaxed);
    }

    /// Stops recording and returns what was recorded.
    pub fn take() -> Vec<Block> {
        ON.store(false, Ordering::Relaxed);
        BLOCKS
            .lock()
            .map(|mut blocks| std::mem::take(&mut *blocks))
            .unwrap_or_default()
    }

    pub(super) fn enabled() -> bool {
        ON.load(Ordering::Relaxed)
    }

    /// Walks `data` exactly as `visit_x86_operands` does - trigger, then
    /// resume five bytes on - so the gaps recorded are the distances the
    /// probe actually has to cross.
    pub(super) fn record<const JUMP: bool>(data: &[u8], rar5: bool) {
        let mut gaps: Vec<usize> = Vec::new();
        let mut scans: Vec<usize> = Vec::new();
        let mut start = 0;
        let mut previous: Option<usize> = None;
        let mut triggers = 0;
        while let Some(position) = super::next_x86_trigger::<JUMP>(data, start) {
            triggers += 1;
            if let Some(last) = previous {
                gaps.push(position - last);
            }
            scans.push(position.saturating_sub(start));
            previous = Some(position);
            start = position + 5;
        }
        // The last scan finds nothing and crosses the rest of the block.
        scans.push(data.len().saturating_sub(start));
        gaps.sort_unstable();
        scans.sort_unstable();
        let at = |sorted: &[usize], q: f64| {
            sorted
                .get(((sorted.len() as f64) * q) as usize)
                .copied()
                .unwrap_or(0)
        };
        let block = Block {
            len: data.len(),
            jump: JUMP,
            rar5,
            triggers,
            p50: at(&gaps, 0.5),
            p90: at(&gaps, 0.9),
            max: gaps.last().copied().unwrap_or(0),
            scan_p50: at(&scans, 0.5),
            scan_p90: at(&scans, 0.9),
            scan_max: scans.last().copied().unwrap_or(0),
        };
        if let Ok(mut blocks) = BLOCKS.lock() {
            blocks.push(block);
        }
    }
}

#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod harness {
    use super::{Direction, X86Format, X86Opcodes};

    fn direction(encode: bool) -> Direction {
        if encode {
            Direction::Encode
        } else {
            Direction::Decode
        }
    }

    pub fn x86(data: &mut [u8], file_offset: u32, encode: bool, jump: bool, rar5: bool) {
        let opcodes = if jump {
            X86Opcodes::CallAndJump
        } else {
            X86Opcodes::Call
        };
        let format = if rar5 {
            X86Format::Rar5
        } else {
            X86Format::Rar3
        };
        super::x86(data, file_offset, direction(encode), opcodes, format);
    }

    pub fn arm(data: &mut [u8], file_offset: u32, encode: bool) {
        super::arm(data, file_offset, direction(encode));
    }

    pub fn ia64(data: &mut [u8], file_offset: u32, encode: bool) {
        super::ia64(data, file_offset, direction(encode));
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;
    use crate::codec::rar29::{
        RAR3_E8E9_FILTER_BYTECODE, RAR3_E8_FILTER_BYTECODE, RAR3_ITANIUM_FILTER_BYTECODE,
    };
    use crate::codec::rarvm::{Invocation, Program};
    use std::sync::OnceLock;
    use Direction::{Decode, Encode};
    use X86Format::{Rar3, Rar5};
    use X86Opcodes::{Call, CallAndJump};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Kind {
        X86(X86Opcodes, X86Format),
        Arm,
        Ia64,
    }
    use Kind::{Arm, Ia64, X86};

    const KINDS: [Kind; 6] = [
        X86(Call, Rar5),
        X86(CallAndJump, Rar5),
        X86(Call, Rar3),
        X86(CallAndJump, Rar3),
        Arm,
        Ia64,
    ];
    const ALL_X86: &[Kind] = &[
        X86(Call, Rar5),
        X86(CallAndJump, Rar5),
        X86(Call, Rar3),
        X86(CallAndJump, Rar3),
    ];
    const RAR5_X86: &[Kind] = &[X86(Call, Rar5), X86(CallAndJump, Rar5)];
    const RAR3_X86: &[Kind] = &[X86(Call, Rar3), X86(CallAndJump, Rar3)];
    const CALL_ONLY: &[Kind] = &[X86(Call, Rar5), X86(Call, Rar3)];
    const CALL_AND_JUMP: &[Kind] = &[X86(CallAndJump, Rar5), X86(CallAndJump, Rar3)];

    fn apply(kind: Kind, direction: Direction, data: &mut [u8], file_offset: u32) {
        match kind {
            X86(opcodes, format) => x86(data, file_offset, direction, opcodes, format),
            Arm => arm(data, file_offset, direction),
            Ia64 => ia64(data, file_offset, direction),
        }
    }

    fn opposite(direction: Direction) -> Direction {
        match direction {
            Decode => Encode,
            Encode => Decode,
        }
    }

    /// The RAR 3 standard programs as every archive carries them, parsed once:
    /// E8, E8E9, IA-64.
    fn vm_programs() -> &'static [Program; 3] {
        static PROGRAMS: OnceLock<[Program; 3]> = OnceLock::new();
        PROGRAMS.get_or_init(|| {
            [
                RAR3_E8_FILTER_BYTECODE,
                RAR3_E8E9_FILTER_BYTECODE,
                RAR3_ITANIUM_FILTER_BYTECODE,
            ]
            .map(|code| Program::parse(code).unwrap())
        })
    }

    /// Runs a standard program the way the RAR 3 decoder would for a filter
    /// with no register overrides.
    fn vm_execute(program: &Program, input: &[u8], file_offset: u32) -> Vec<u8> {
        program
            .execute(Invocation {
                input,
                regs: [0, 0, 0, 0x3c000, input.len() as u32, 0, 0],
                global_data: &[],
                file_offset: u64::from(file_offset),
                exec_count: 0,
            })
            .unwrap()
            .output
    }

    /// O2: the RAR 3 standard x86 and IA-64 programs on the crate's own VM,
    /// for blocks the VM accepts. Decode only.
    ///
    /// IA-64 was left out until 15 Sep 2026, when two VM faults were fixed
    /// (static data placed under the system globals, and a subroutine RET
    /// ending the program); the VM had run the IA-64 program as the identity.
    ///
    /// The IA-64 bytecode's loop bound is one bundle wider than this module's:
    /// for `n > 21` it rewrites every bundle at `pos <= n - 21`, where this
    /// module (like RAR 7.23, which extracts rars-written IA-64 archives
    /// byte-identical) stops at `pos < n - 21`. They differ only when `n - 21`
    /// is a multiple of 16. In that case the program runs on all but the last
    /// byte: a bundle reads no byte past its offset 18, so that moves the bound
    /// by exactly the one bundle and nothing else.
    fn vm_decode(kind: Kind, input: &[u8], file_offset: u32) -> Option<Vec<u8>> {
        let (program, held_back) = match kind {
            X86(Call, Rar3) => (&vm_programs()[0], 0),
            X86(CallAndJump, Rar3) => (&vm_programs()[1], 0),
            Ia64 => {
                let wider = input.len() > 21 && (input.len() - 21).is_multiple_of(16);
                (&vm_programs()[2], usize::from(wider))
            }
            _ => return None,
        };
        if input.len() > 0x3c000 || input.len() < held_back {
            return None;
        }
        let (body, tail) = input.split_at(input.len() - held_back);
        let mut output = vm_execute(program, body, file_offset);
        output.extend_from_slice(tail);
        Some(output)
    }

    /// Whether decode and encode must be inverses for this block: always,
    /// except RAR 3 x86 once an operand's offset can pass 2^31.
    fn inverse_expected(kind: Kind, file_offset: u32, len: usize) -> bool {
        match kind {
            X86(_, Rar3) => u64::from(file_offset) + len as u64 <= 1 << 31,
            _ => true,
        }
    }

    fn hex_window(bytes: &[u8], at: usize) -> String {
        let lo = at.saturating_sub(8).min(bytes.len());
        let hi = (at + 8).min(bytes.len());
        bytes[lo..hi]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn assert_same(context: &str, what: &str, input: &[u8], got: &[u8], want: &[u8]) {
        if got == want {
            return;
        }
        let at = got
            .iter()
            .zip(want)
            .position(|(a, b)| a != b)
            .unwrap_or(got.len().min(want.len()));
        panic!(
            "{context}: {what}: n={} (got {} bytes, want {}), first difference at {at}\n\
             input {}\n  got {}\n want {}",
            input.len(),
            got.len(),
            want.len(),
            hex_window(input, at),
            hex_window(got, at),
            hex_window(want, at),
        );
    }

    fn trigger_positions(kind: Kind, data: &[u8]) -> Vec<usize> {
        let mut copy = data.to_vec();
        let mut positions = Vec::new();
        match kind {
            X86(Call, _) => visit_x86_operands::<false>(&mut copy, |p, _| positions.push(p)),
            X86(CallAndJump, _) => visit_x86_operands::<true>(&mut copy, |p, _| positions.push(p)),
            _ => {}
        }
        positions
    }

    /// Every check that applies to one block: new == O2 for the RAR 3 x86
    /// decodes the VM accepts, round trips where they must hold, and x86
    /// scan-position invariance. Until the legacy oracle O1 was deleted (15
    /// Sep 2026, after this differential and 30-minute fuzz runs per transform
    /// were green) it also held every entry point to O1 in both directions.
    fn check_case(context: &str, kind: Kind, file_offset: u32, input: &[u8]) {
        let context = format!("{context} {kind:?} F={file_offset:#010x}");
        for direction in [Decode, Encode] {
            let context = format!("{context} {direction:?}");
            let mut new = input.to_vec();
            apply(kind, direction, &mut new, file_offset);
            if direction == Decode {
                if let Some(vm) = vm_decode(kind, input, file_offset) {
                    assert_same(&context, "new vs O2 (VM)", input, &new, &vm);
                }
            }
            if inverse_expected(kind, file_offset, input.len()) {
                let mut back = new.clone();
                apply(kind, opposite(direction), &mut back, file_offset);
                assert_same(&context, "round trip", input, &back, input);
            }
            if let X86(..) = kind {
                let before = trigger_positions(kind, input);
                assert_eq!(
                    before,
                    trigger_positions(kind, &new),
                    "{context}: trigger positions moved"
                );
                let mut in_operand = vec![false; input.len()];
                for &p in &before {
                    in_operand[p + 1..p + 5].fill(true);
                }
                for (i, inside) in in_operand.iter().enumerate() {
                    assert!(
                        *inside || new[i] == input[i],
                        "{context}: byte {i} outside every operand changed"
                    );
                }
            }
        }
    }

    // --- deterministic randomness -----------------------------------------

    /// xorshift64*, so failures reproduce and the tests add no dependency.
    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
        fn byte(&mut self) -> u8 {
            (self.next() >> 56) as u8
        }
        fn fill(&mut self, buf: &mut [u8]) {
            for byte in buf {
                *byte = self.byte();
            }
        }
        fn pick<T: Copy>(&mut self, items: &[T]) -> T {
            items[self.below(items.len() as u64) as usize]
        }
    }

    fn edge_offsets() -> Vec<u32> {
        let mut edges = vec![0, 1, 2, 3, 4, 15, 16, 17];
        edges.extend((1u32 << 24) - 6..=(1u32 << 24) + 6);
        edges.extend((1u32 << 31) - 6..=(1u32 << 31) + 6);
        edges.extend(u32::MAX - 39..=u32::MAX);
        edges
    }

    fn draw_offset(rng: &mut Rng, edges: &[u32]) -> u32 {
        if rng.below(2) == 0 {
            rng.pick(edges)
        } else {
            rng.next() as u32
        }
    }

    /// The operand offset a position sees, for building boundary operands.
    fn operand_offset(format: X86Format, file_offset: u32, position: usize) -> u32 {
        let offset = file_offset.wrapping_add(position as u32).wrapping_add(1);
        match format {
            Rar5 => offset & (WINDOW - 1),
            Rar3 => offset,
        }
    }

    fn boundary_operands(offset: u32) -> [u32; 15] {
        let neg = offset.wrapping_neg();
        [
            0,
            1,
            WINDOW - 1,
            WINDOW,
            (1 << 31) - 1,
            1 << 31,
            u32::MAX,
            neg,
            neg.wrapping_sub(1),
            WINDOW.wrapping_sub(offset),
            WINDOW.wrapping_sub(offset).wrapping_sub(1),
            offset,
            offset.wrapping_sub(1),
            WINDOW.wrapping_add(offset),
            WINDOW.wrapping_add(offset).wrapping_sub(1),
        ]
    }

    // --- 6.2 hand vectors ---------------------------------------------------

    fn hex(text: &str) -> Vec<u8> {
        text.split_whitespace()
            .map(|pair| u8::from_str_radix(pair, 16).unwrap())
            .collect()
    }

    /// A zero buffer of `len` bytes with hex runs written at the given indices.
    fn patched(len: usize, edits: &[(usize, &str)]) -> Vec<u8> {
        let mut out = vec![0; len];
        for &(at, bytes) in edits {
            let bytes = hex(bytes);
            out[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        out
    }

    struct Vector {
        name: &'static str,
        kinds: &'static [Kind],
        file_offset: u32,
        input: Vec<u8>,
        decoded: Vec<u8>,
        encoded: Vec<u8>,
        inverse: bool,
    }

    fn row(
        name: &'static str,
        kinds: &'static [Kind],
        file_offset: u32,
        input: &str,
        decoded: &str,
        encoded: &str,
    ) -> Vector {
        let input = hex(input);
        let pick = |text: &str| {
            if text == "=" {
                input.clone()
            } else {
                hex(text)
            }
        };
        Vector {
            name,
            kinds,
            file_offset,
            decoded: pick(decoded),
            encoded: pick(encoded),
            input,
            inverse: true,
        }
    }

    fn non_inverse(mut vector: Vector) -> Vector {
        vector.inverse = false;
        vector
    }

    fn x86_vectors() -> Vec<Vector> {
        let mut v = vec![
            row(
                "X1",
                ALL_X86,
                0,
                "e8 10 00 00 00",
                "e8 0f 00 00 00",
                "e8 11 00 00 00",
            ),
            row(
                "X2",
                ALL_X86,
                0x10,
                "e8 ff ff ff ff",
                "e8 ff ff ff 00",
                "e8 10 00 00 00",
            ),
            row("X3", ALL_X86, 0x10, "e8 00 00 00 80", "=", "="),
            row("X4", ALL_X86, 0x10, "e8 00 00 00 01", "=", "="),
            row(
                "X5",
                ALL_X86,
                0x10,
                "e8 ff ff ff 00",
                "e8 ee ff ff 00",
                "e8 ff ff ff ff",
            ),
            row(
                "X6",
                ALL_X86,
                0,
                "e8 e8 00 00 00 e8 05 00 00 00",
                "e8 e7 00 00 00 e8 ff ff ff ff",
                "e8 e9 00 00 00 e8 0b 00 00 00",
            ),
            row("X7", ALL_X86, 0, "90 90 e8 01 02 03", "=", "="),
            row(
                "X8",
                ALL_X86,
                0x1000,
                "90 90 90 e8 10 00 00 00",
                "90 90 90 e8 0c f0 ff ff",
                "90 90 90 e8 14 10 00 00",
            ),
            row(
                "X9",
                RAR5_X86,
                0x0110_0000,
                "e8 08 0c 10 00",
                "e8 07 0c 00 00",
                "e8 09 0c 20 00",
            ),
            row(
                "X9/RAR3",
                RAR3_X86,
                0x0110_0000,
                "e8 08 0c 10 00",
                "e8 07 0c 00 ff",
                "e8 08 0c 10 ff",
            ),
            row("X10", CALL_ONLY, 0, "e9 20 00 00 00", "=", "="),
            row("X11", ALL_X86, 0, "e8 e8 e8 e8 e8 e8 e8 e8 e8 e8", "=", "="),
            row(
                "X12",
                RAR5_X86,
                0xffff_fff0,
                "e8 00 00 00 00",
                "e8 0f 00 00 ff",
                "e8 f1 ff ff 00",
            ),
            non_inverse(row(
                "X12/RAR3",
                RAR3_X86,
                0xffff_fff0,
                "e8 00 00 00 00",
                "e8 0f 00 00 00",
                "=",
            )),
            non_inverse(row(
                "Z1",
                RAR3_X86,
                0x8000_0000,
                "e8 ff ff ff 00",
                "e8 fe ff ff 80",
                "=",
            )),
            row(
                "Y1",
                CALL_AND_JUMP,
                0x100,
                "e9 20 00 00 00",
                "e9 1f ff ff ff",
                "e9 21 01 00 00",
            ),
            row(
                "Y2",
                CALL_AND_JUMP,
                0,
                "e9 e8 00 00 00 e8 05 00 00 00",
                "e9 e7 00 00 00 e8 ff ff ff ff",
                "e9 e9 00 00 00 e8 0b 00 00 00",
            ),
            row(
                "Y3",
                CALL_AND_JUMP,
                0,
                "e8 e9 00 00 00 e9 05 00 00 00",
                "e8 e8 00 00 00 e9 ff ff ff ff",
                "e8 ea 00 00 00 e9 0b 00 00 00",
            ),
            row(
                "Y4",
                CALL_AND_JUMP,
                0,
                "ea 10 00 00 00 e7 10 00 00 00",
                "=",
                "=",
            ),
        ];
        for (input, f) in [
            ("", 0),
            ("e8", 0x10),
            ("e8 ff", 0x0100_0000),
            ("e8 00 00", 0xffff_fff0),
            ("e8 ff ff ff", 0x8000_0000),
        ] {
            v.push(row("X13", ALL_X86, f, input, "=", "="));
        }
        v
    }

    fn arm_vectors() -> Vec<Vector> {
        const ARM: &[Kind] = &[Arm];
        let mut v = vec![
            row(
                "A1",
                ARM,
                0xffff_fffc,
                "04 00 00 eb 08 00 00 eb",
                "05 00 00 eb 08 00 00 eb",
                "03 00 00 eb 08 00 00 eb",
            ),
            row(
                "A2",
                ARM,
                0x100,
                "00 10 00 eb 00 10 00 ea 00 10 00 eb 11 22",
                "c0 0f 00 eb 00 10 00 ea be 0f 00 eb 11 22",
                "40 10 00 eb 00 10 00 ea 42 10 00 eb 11 22",
            ),
            row(
                "A3",
                ARM,
                3,
                "00 00 00 eb 00 00 00 eb",
                "00 00 00 eb ff ff ff eb",
                "00 00 00 eb 01 00 00 eb",
            ),
            row(
                "A4",
                ARM,
                8,
                "01 02 03 eb aa bb eb",
                "ff 01 03 eb aa bb eb",
                "03 02 03 eb aa bb eb",
            ),
            row(
                "A5",
                ARM,
                0,
                "eb eb eb 00 05 00 00 eb",
                "eb eb eb 00 04 00 00 eb",
                "eb eb eb 00 06 00 00 eb",
            ),
        ];
        for (input, f) in [("", 0), ("eb", 4), ("eb eb", 0xffff_ffff), ("00 00 eb", 8)] {
            v.push(row("A6", ARM, f, input, "=", "="));
        }
        v
    }

    fn ia64_vector(
        name: &'static str,
        file_offset: u32,
        input: Vec<u8>,
        decoded: Vec<u8>,
        encoded: Vec<u8>,
    ) -> Vector {
        Vector {
            name,
            kinds: &[Ia64],
            file_offset,
            input,
            decoded,
            encoded,
            inverse: true,
        }
    }

    fn ia64_vectors() -> Vec<Vector> {
        let i1 = "16 00 00 00 00 14 00 00 00 00 28 00 00 00 00 50 00 00 00 00 00 00";
        let with_template = |template: &str| {
            let mut bytes = hex(i1);
            bytes[0] = hex(template)[0];
            bytes
        };
        let i8 = patched(21, &[(0, "16 00 00 00 00 14")]);
        let i9 = patched(22, &[(0, "16 00 00 00 00 14")]);
        let i10 = patched(32, &[(0, "16"), (5, "14"), (16, "16"), (21, "14")]);
        let i11 = patched(38, &[(0, "16"), (5, "14"), (16, "16"), (21, "14")]);
        let edit = |base: &[u8], edits: &[(usize, &str)]| {
            let mut out = base.to_vec();
            for &(at, bytes) in edits {
                let bytes = hex(bytes);
                out[at..at + bytes.len()].copy_from_slice(&bytes);
            }
            out
        };
        vec![
            ia64_vector(
                "I1",
                0x10,
                hex(i1),
                hex("16 00 fc ff 3f 14 00 f8 ff 7f 28 00 f0 ff ff 50 00 00 00 00 00 00"),
                hex("16 00 04 00 00 14 00 08 00 00 28 00 10 00 00 50 00 00 00 00 00 00"),
            ),
            ia64_vector(
                "I2",
                0x20,
                with_template("10"),
                edit(&with_template("10"), &[(12, "e0 ff ff")]),
                edit(&with_template("10"), &[(12, "20 00 00")]),
            ),
            ia64_vector(
                "I3",
                0x30,
                hex("12 00 fc ff 3f 14 00 08 00 00 28 00 10 00 00 50 00 00 00 00 00 00"),
                hex("12 00 fc ff 3f 14 00 f0 ff 7f 28 00 e0 ff ff 50 00 00 00 00 00 00"),
                hex("12 00 fc ff 3f 14 00 20 00 00 28 00 40 00 00 50 00 00 00 00 00 00"),
            ),
            ia64_vector(
                "I4",
                0x10,
                with_template("14"),
                with_template("14"),
                with_template("14"),
            ),
            ia64_vector(
                "I5",
                0x10,
                hex("17 00 00 00 00 10 00 00 00 00 28 00 00 00 00 50 00 00 00 00 00 00"),
                hex("17 00 00 00 00 10 00 f8 ff 7f 28 00 f0 ff ff 50 00 00 00 00 00 00"),
                hex("17 00 00 00 00 10 00 08 00 00 28 00 10 00 00 50 00 00 00 00 00 00"),
            ),
            ia64_vector(
                "I6",
                0x10,
                patched(22, &[(0, "18"), (15, "50")]),
                patched(22, &[(0, "18"), (12, "f0 ff ff 50")]),
                patched(22, &[(0, "18"), (12, "10 00 00 50")]),
            ),
            ia64_vector(
                "I7",
                0x10,
                patched(22, &[(0, "1c"), (12, "0f 00 f0 5f")]),
                patched(22, &[(0, "1c"), (12, "ff ff ef 5f")]),
                patched(22, &[(0, "1c"), (12, "1f 00 f0 5f")]),
            ),
            ia64_vector("I8", 0x10, i8.clone(), i8.clone(), i8),
            ia64_vector(
                "I9",
                0x10,
                i9.clone(),
                edit(&i9, &[(2, "fc ff 3f")]),
                edit(&i9, &[(2, "04 00 00")]),
            ),
            ia64_vector(
                "I10",
                0x10,
                i10.clone(),
                edit(&i10, &[(2, "fc ff 3f")]),
                edit(&i10, &[(2, "04 00 00")]),
            ),
            ia64_vector(
                "I11",
                0x10,
                i11.clone(),
                edit(&i11, &[(2, "fc ff 3f"), (18, "f8 ff 3f")]),
                edit(&i11, &[(2, "04 00 00"), (18, "08 00 00")]),
            ),
            ia64_vector(
                "I12",
                0xffff_ffff,
                i11.clone(),
                edit(&i11, &[(2, "04 00 00")]),
                edit(&i11, &[(2, "fc ff 3f")]),
            ),
            ia64_vector(
                "I13",
                0x1f,
                i9.clone(),
                edit(&i9, &[(2, "fc ff 3f")]),
                edit(&i9, &[(2, "04 00 00")]),
            ),
        ]
    }

    #[test]
    fn hand_vectors_give_the_specified_bytes_in_both_directions() {
        let vectors = x86_vectors()
            .into_iter()
            .chain(arm_vectors())
            .chain(ia64_vectors());
        let mut checked = 0;
        for vector in vectors {
            for &kind in vector.kinds {
                let f = vector.file_offset;
                let context = format!("{} {kind:?} F={f:#010x}", vector.name);
                let mut decoded = vector.input.clone();
                apply(kind, Decode, &mut decoded, f);
                assert_same(&context, "decode", &vector.input, &decoded, &vector.decoded);
                let mut encoded = vector.input.clone();
                apply(kind, Encode, &mut encoded, f);
                assert_same(&context, "encode", &vector.input, &encoded, &vector.encoded);
                if vector.inverse {
                    apply(kind, Encode, &mut decoded, f);
                    assert_same(
                        &context,
                        "encode(decode)",
                        &vector.input,
                        &decoded,
                        &vector.input,
                    );
                    apply(kind, Decode, &mut encoded, f);
                    assert_same(
                        &context,
                        "decode(encode)",
                        &vector.input,
                        &encoded,
                        &vector.input,
                    );
                }
                // The rows derived from the equations were confirmed against
                // O1 before its deletion; RAR 3 x86 decodes still meet O2.
                check_case(vector.name, kind, f, &vector.input);
                checked += 1;
            }
        }
        assert!(checked > 60, "only {checked} vector applications ran");
    }

    /// Z1 is a byte-exactness vector, not a round-trip one: RAR 3 x86 past
    /// 2 GiB is not an inverse pair, and must stay that way. Nobody "fixes"
    /// it silently in the transform - the decode side has to agree with
    /// every other RAR 3 reader. SPEC C Part 7 item 1 settled the writer
    /// policy on 16 Sep 2026 instead: `split_large_filter` clips an x86
    /// filter block so it can never reach this region.
    #[test]
    fn rar3_x86_past_two_gib_stays_non_inverse() {
        for opcodes in [Call, CallAndJump] {
            let input = hex("e8 ff ff ff 00");
            let mut encoded = input.clone();
            x86(&mut encoded, 0x8000_0000, Encode, opcodes, Rar3);
            assert_eq!(encoded, input, "{opcodes:?}: encode leaves Z1 unchanged");
            let mut decoded = encoded;
            x86(&mut decoded, 0x8000_0000, Decode, opcodes, Rar3);
            assert_eq!(decoded, hex("e8 fe ff ff 80"), "{opcodes:?}");
            assert_ne!(
                decoded, input,
                "{opcodes:?}: decode(encode(Z1)) must differ"
            );
        }
    }

    /// The trigger scan probes `X86_PROBE_BYTES` a word at a time and then
    /// hands the rest to a vector search, so it has a seam at every multiple
    /// of eight and one at the handover. A trigger sitting on any of them
    /// must still be the one found, and found first.
    #[test]
    fn the_scan_finds_a_trigger_at_every_probe_seam() {
        for jump in [false, true] {
            for opcode in [0xe8u8, 0xe9] {
                if !jump && opcode == 0xe9 {
                    continue;
                }
                for distance in 0..X86_PROBE_BYTES + 24 {
                    let mut data = vec![0x90u8; distance + 64];
                    data[distance] = opcode;
                    let mut seen = Vec::new();
                    if jump {
                        visit_x86_operands::<true>(&mut data, |at, _| seen.push(at));
                    } else {
                        visit_x86_operands::<false>(&mut data, |at, _| seen.push(at));
                    }
                    assert_eq!(
                        seen.first().copied(),
                        Some(distance),
                        "jump {jump} opcode {opcode:#x} at {distance}"
                    );
                }
            }
        }
    }

    // --- 6.3 differential and property tests --------------------------------

    #[test]
    fn random_short_buffers_round_trip_and_match_the_vm() {
        let seed = 0x5eed_0001;
        let mut rng = Rng::new(seed);
        let edges = edge_offsets();
        let mut buf = Vec::new();
        for case in 0..20_000 {
            let len = rng.below(301) as usize;
            buf.resize(len, 0);
            rng.fill(&mut buf);
            let f = draw_offset(&mut rng, &edges);
            for kind in KINDS {
                check_case(&format!("seed {seed:#x} case {case}"), kind, f, &buf);
            }
        }
    }

    #[test]
    fn random_long_buffers_round_trip_and_match_the_vm() {
        let seed = 0x5eed_0002;
        let mut rng = Rng::new(seed);
        let edges = edge_offsets();
        let lengths = [4095, 4096, 4097, 65535, 65536, 65537, 0x3ffff, 1 << 20];
        for case in 0..200 {
            let mut buf = vec![0; lengths[case % lengths.len()]];
            rng.fill(&mut buf);
            let f = draw_offset(&mut rng, &edges);
            for kind in KINDS {
                check_case(&format!("seed {seed:#x} case {case}"), kind, f, &buf);
            }
        }
    }

    /// Lengths around every lane the implementation uses: the 8-byte x86
    /// probe, the 4-byte ARM word, the 16-byte IA-64 bundle, and the widths
    /// a vector search or an auto-vectorised loop may take.
    fn adversarial_lengths() -> Vec<usize> {
        let mut lengths: Vec<usize> = (0..=130).collect();
        for lane in [4, 8, 16, 32, 64] {
            for k in 1..=4 {
                for d in 1..=5 {
                    lengths.push(lane * k + d);
                    lengths.push(lane * k - d.min(lane * k));
                }
            }
        }
        lengths.sort_unstable();
        lengths.dedup();
        lengths
    }

    fn adversarial_buffers(rng: &mut Rng, len: usize, file_offset: u32) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let random = |rng: &mut Rng| {
            let mut buf = vec![0; len];
            rng.fill(&mut buf);
            buf
        };
        // x86
        out.push(vec![0xe8; len]);
        out.push(vec![0xe9; len]);
        out.push(
            (0..len)
                .map(|i| if i % 2 == 0 { 0xe8 } else { 0xe9 })
                .collect(),
        );
        out.push(
            (0..len)
                .map(|_| rng.pick(&[0xe8, 0xe9, 0x00, 0xff, 0x01, 0xfe]))
                .collect(),
        );
        for k in 1..=6 {
            let mut buf = random(rng);
            for i in (0..len).step_by(k) {
                buf[i] = 0xe8;
            }
            out.push(buf);
        }
        for (format, jump) in [(Rar5, false), (Rar5, true), (Rar3, false), (Rar3, true)] {
            let mut buf = vec![0x90; len];
            let mut p = 0;
            while p + 5 <= len {
                buf[p] = if jump && rng.below(2) == 1 {
                    0xe9
                } else {
                    0xe8
                };
                let operand = rng.pick(&boundary_operands(operand_offset(format, file_offset, p)));
                buf[p + 1..p + 5].copy_from_slice(&operand.to_le_bytes());
                p += 5 + rng.below(3) as usize;
            }
            out.push(buf);
        }
        // ARM
        let mut words = random(rng);
        for i in (3..len).step_by(4) {
            words[i] = 0xeb;
        }
        out.push(words);
        out.push(vec![0xeb; len]);
        let mut scattered = random(rng);
        for word in scattered.chunks_mut(4) {
            let at = rng.below(4) as usize;
            if at < word.len() {
                word[at] = 0xeb;
            }
        }
        out.push(scattered);
        // IA-64
        for template in [0x16, 0x17, 0x12, 0x10, 0x18, 0x1c] {
            let mut buf = random(rng);
            for bundle in buf.chunks_mut(16) {
                bundle[0] = template;
                for (at, shift) in [(5, 2), (10, 3), (15, 4)] {
                    if at < bundle.len() {
                        bundle[at] = (bundle[at] & !(0xf << shift)) | (5 << shift);
                    }
                }
            }
            out.push(buf);
        }
        out.push(vec![0x16; len]);
        let mut templates = random(rng);
        for bundle in templates.chunks_mut(16) {
            bundle[0] = rng.below(0x20) as u8;
        }
        out.push(templates);
        out
    }

    #[test]
    fn trigger_dense_buffers_round_trip_and_match_the_vm() {
        let seed = 0x5eed_0003;
        let mut rng = Rng::new(seed);
        let edges = edge_offsets();
        for len in adversarial_lengths() {
            for round in 0..3 {
                let f = draw_offset(&mut rng, &edges);
                for (pattern, buf) in adversarial_buffers(&mut rng, len, f).iter().enumerate() {
                    for kind in KINDS {
                        let context =
                            format!("seed {seed:#x} len {len} round {round} pattern {pattern}");
                        check_case(&context, kind, f, buf);
                    }
                }
            }
        }
    }

    #[test]
    fn exhaustive_small_x86_operands() {
        let edges = edge_offsets();
        for &f in &edges {
            for format in [Rar5, Rar3] {
                for operand in boundary_operands(operand_offset(format, f, 0)) {
                    for opcode in [0xe8, 0xe9] {
                        let mut buf = vec![opcode];
                        buf.extend_from_slice(&operand.to_le_bytes());
                        for &kind in ALL_X86 {
                            check_case("exhaustive x86", kind, f, &buf);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exhaustive_small_arm_words() {
        let mut rng = Rng::new(0x5eed_0004);
        let mut random = [0u8; 8];
        rng.fill(&mut random);
        let bases = [[0u8; 8], [0xff; 8], [0x80; 8], random];
        let offsets = (0..=64u32).chain(u32::MAX - 63..=u32::MAX);
        for f in offsets {
            for base in bases {
                for b3 in [0xea, 0xeb, 0xec] {
                    for b7 in [0xea, 0xeb, 0xec] {
                        let mut buf = base;
                        buf[3] = b3;
                        buf[7] = b7;
                        check_case("exhaustive arm", Arm, f, &buf);
                    }
                }
            }
        }
    }

    #[test]
    fn exhaustive_small_ia64_bundles() {
        let mut rng = Rng::new(0x5eed_0005);
        let mut base = [0u8; 22];
        rng.fill(&mut base);
        for (at, shift) in [(5, 2), (10, 3), (15, 4)] {
            base[at] = (base[at] & !(0xf << shift)) | (5 << shift);
        }
        for f in [0, 0x10, 0x1f, u32::MAX] {
            for template in 0..=255u8 {
                for (at, shift) in [(5, 2), (10, 3), (15, 4)] {
                    for nibble in 0..16u8 {
                        let mut buf = base;
                        buf[0] = template;
                        buf[at] = (buf[at] & !(0xf << shift)) | (nibble << shift);
                        check_case("exhaustive ia64", Ia64, f, &buf);
                    }
                }
            }
        }
    }
}
