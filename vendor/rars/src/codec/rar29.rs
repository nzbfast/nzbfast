use super::filters::{self, DeltaErrorMessages, FilterOp};
use super::huffman;
use super::ppmd::{PpmdByteReader, PpmdDecoder, PpmdEncoder};
use super::rarvm;
use super::{Error, Result};
use crate::crc32::crc32;
use std::io::{Read, Write};
use std::ops::Range;

const MAIN_COUNT: usize = 299;
const OFFSET_COUNT: usize = 60;
const LOW_OFFSET_COUNT: usize = 17;
const LENGTH_COUNT: usize = 28;
const LEVEL_COUNT: usize = 20;
const TABLE_COUNT: usize = MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT + LENGTH_COUNT;
const MAX_HISTORY: usize = 4 * 1024 * 1024;
const STREAM_CHUNK: usize = 1024 * 1024;
const MAX_VM_FILTER_BLOCK_SIZE: usize = 128 * 1024;
// nzbfast: ceiling on a DECODED RAR 3 VM filter block, which the wire
// declares as a bare u32 with no cap of its own
// (`MAX_VM_FILTER_BLOCK_SIZE` above bounds only what the ENCODER emits).
//
// A filter holds output back: `safe_flush_end` will not flush past a
// filter's start until its end is decoded, and `trim_history` keeps
// `keep_from <= flushed`, so nothing drains either. A crafted member
// declaring `block_start = 0` and a 2 GiB block therefore grew
// `self.output` to the whole member's output, and `filtered_range` then
// copied that block again for the VM - about 4 GiB of peak from a few MB
// of packed input, with no analogue of RAR5's `add_filter` bail.
//
// 8 MiB is RAR5's `STREAM_FILTER_HOLD_LIMIT`, kept deliberately
// identical. It is enormous headroom for RAR 3: a real filter block runs
// inside RARVM memory, whose global address is 0x3c000 (~240 KiB, the
// value regs[3] is seeded with below), and unrar itself declines to
// filter a block larger than that.
const MAX_VM_FILTER_HOLD: usize = 8 * 1024 * 1024;
// nzbfast: the packed-input window `decode_member_from_reader` holds, and
// the margin below which it refuses to begin a decode excursion.
// (nzbfast-local change, 16 Sep 2026; re-apply on the next rars re-sync,
// see `vendor/rars/VENDORING.md`.)
//
// Until 2026-09-16 that entry point drained the whole packed member into
// the bit reader before decoding a byte, so an 8 GB -m3 RAR4 member cost
// its packed size in heap whatever any budget said. It now refills from
// the reader as it decodes, and `compact()` drops what has been consumed,
// so the retained input is `STREAM_INPUT_WINDOW` plus whatever tail the
// member carries past its last decoded byte.
//
// The bit reader has no mid-symbol rollback: a `NeedMoreInput` raised
// part-way through a symbol has already consumed bits and mutated
// decoder state, and resuming from there is a corrupt-output bug, which
// is worse than the allocation. So the refill is PROACTIVE - the decoder
// pauses at a clean symbol boundary while more input can still arrive,
// and never starts an excursion that could outrun the buffer. The margin
// must therefore exceed the input any single excursion can consume:
//
//   * `read_tables`: 2 bits + 20 x 8 (level lengths) + TABLE_COUNT (404)
//     symbols of at most 15 + 7 bits = under 1.2 KiB.
//   * one `decode_lz` outer iteration past the literal burst: a main
//     symbol (<= 15 bits) plus its arm. The widest arm is 257,
//     `read_vm_code`, whose length field is a bare 16-bit count read
//     BEFORE `MAX_VM_CODE_SIZE` is checked, so it reads at most
//     65535 + 3 bytes. Every other arm is under 16 bytes.
//   * `Ppmd::decode_init` out of `read_tables`: a header byte and the
//     range coder's four-byte prime.
//
// 128 KiB clears the worst of those (64 KiB + slop) by 2x. The literal
// burst loop needs no margin of its own: it stops on a failed `peek_bits`,
// which consumes nothing, so draining the window inside it is safe.
//
// PPMd blocks are NOT streamed. A PPMd symbol's input cost is bounded
// only by the model's escape chain, and `read_vm_code_ppmd` can spend
// 65539 symbols, so no margin this side of tens of megabytes is provable.
// `decode_until` therefore absorbs the rest of the reader the moment a
// block selects PPMd and decodes it exactly as before - the old peak, on
// a shape that is rare in the wild and was never better than this.
const STREAM_INPUT_WINDOW: usize = 1024 * 1024;
const STREAM_INPUT_MARGIN: usize = 128 * 1024;
// The standard AUDIO bytecode uses separate input/output regions inside RARVM
// memory. Keep generated blocks below the overlap boundary accepted by period
// decoders.
const MAX_VM_DELTA_FILTER_BLOCK_SIZE: usize = 120_000;
const MAX_VM_AUDIO_FILTER_BLOCK_SIZE: usize = 120_000;
const MAX_VM_GLOBAL_DATA: usize = 0x2000;
const MAX_VM_CODE_SIZE: usize = 64 * 1024;
const MAX_VM_PROGRAMS: usize = 8192;
const MAX_VM_FILTERS: usize = 8192;

const LENGTH_BASES: [usize; LENGTH_COUNT] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LENGTH_BITS: [u8; LENGTH_COUNT] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
const OFFSET_BASES: [usize; OFFSET_COUNT] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160,
];
const OFFSET_BITS: [u8; OFFSET_COUNT] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];
const SHORT_BASES: [usize; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];
const MAX_ENCODER_MATCH_OFFSET: usize = 1024 * 1024;
const MAX_ENCODER_MATCH_LENGTH: usize = 258;
const MATCH_HASH_BUCKETS: usize = 4096;
const MAX_MATCH_CANDIDATES: usize = 256;
const MAX_PPMD_MATCH_LENGTH: usize = 255;
const MIN_PPMD_MATCH_LENGTH: usize = 32;
const MAX_PPMD_REPEAT_LENGTH: usize = 259;

// RAR 3.x standard filters are stored as RARVM bytecode in the compressed
// stream. RAR15_40_FORMAT_SPECIFICATION.md §20 and FILTER_TRANSFORMS.md §9
// define these blobs by byte length plus CRC32 fingerprint; keep the bytes
// verbatim so writer output and reader recognition use the same wire identity.
const RAR3_E8_FILTER_BYTECODE: &[u8] = &[
    0x97, 0x1b, 0x01, 0x28, 0x07, 0x06, 0x98, 0x08, 0x00, 0x00, 0x00, 0xd1, 0x3a, 0x10, 0x15, 0x92,
    0xec, 0x50, 0xcb, 0x99, 0x20, 0xb9, 0x25, 0xf0, 0x29, 0x19, 0x15, 0x53, 0x03, 0x12, 0xae, 0x51,
    0x10, 0x35, 0x59, 0x2b, 0x60, 0x04, 0x15, 0x6d, 0x40, 0x66, 0xab, 0x02, 0x34, 0x49, 0x04, 0x36,
    0x02, 0x52, 0x3e, 0x97, 0x00,
];
const RAR3_E8E9_FILTER_BYTECODE: &[u8] = &[
    0x84, 0x1b, 0x01, 0x28, 0x11, 0x10, 0x69, 0x80, 0x80, 0x00, 0x00, 0x0d, 0x13, 0xa1, 0x01, 0xc6,
    0x89, 0xd2, 0x80, 0xac, 0x97, 0x62, 0x85, 0x5c, 0xc9, 0x05, 0xc9, 0x2f, 0x81, 0x48, 0xc8, 0xaa,
    0x98, 0x18, 0x95, 0x72, 0x88, 0x81, 0xaa, 0xc9, 0x5b, 0x00, 0x20, 0xab, 0x6a, 0x03, 0x35, 0x58,
    0x11, 0xa2, 0x48, 0x21, 0xb0, 0x12, 0x91, 0xf4, 0xb8,
];
const RAR3_DELTA_FILTER_BYTECODE: &[u8] = &[
    0x2f, 0x01, 0x9a, 0x41, 0x80, 0xec, 0x27, 0x48, 0x2f, 0x09, 0x76, 0x6d, 0xd3, 0xea, 0x41, 0x5b,
    0x59, 0x44, 0xe8, 0x17, 0x5c, 0xe1, 0x6c, 0x91, 0x4c, 0x4e, 0x3f, 0x77, 0x00,
];
pub(crate) const RAR3_ITANIUM_FILTER_BYTECODE: &[u8] = &[
    0x46, 0x9e, 0x08, 0x08, 0x0c, 0x0c, 0x00, 0x00, 0x0e, 0x0e, 0x08, 0x08, 0x00, 0x00, 0x08, 0x08,
    0x00, 0x00, 0x6c, 0x11, 0x5a, 0x04, 0xac, 0x0c, 0xc4, 0xcc, 0x5c, 0x08, 0x18, 0x46, 0x24, 0x08,
    0xf9, 0xa0, 0x44, 0x25, 0x12, 0x12, 0x45, 0x85, 0x99, 0x0c, 0x14, 0x00, 0x26, 0x25, 0x58, 0x99,
    0x90, 0x03, 0x38, 0x1a, 0x08, 0xdc, 0x02, 0x30, 0x0c, 0x4e, 0xd1, 0x1d, 0x89, 0xa1, 0xe2, 0xd0,
    0x55, 0x11, 0x33, 0x60, 0x8c, 0x5a, 0x23, 0x06, 0xde, 0x06, 0x18, 0x00, 0x7f, 0xff, 0xfc, 0x4d,
    0xcc, 0x19, 0x17, 0xb3, 0x06, 0xc4, 0x44, 0xb2, 0x32, 0x5a, 0x44, 0xc4, 0xa6, 0x01, 0xf4, 0x24,
    0x88, 0x83, 0x38, 0xcc, 0xc4, 0x11, 0x09, 0x87, 0xa6, 0xe0, 0x46, 0x02, 0xb2, 0x24, 0x03, 0xe2,
    0xa0, 0x32, 0x54, 0x83, 0x52, 0xc5, 0xb1, 0x70,
];
const RAR3_RGB_FILTER_BYTECODE: &[u8] = &[
    0xc5, 0x01, 0x9a, 0x41, 0x95, 0xc9, 0xa6, 0x4d, 0xba, 0x4b, 0x14, 0x0a, 0xf4, 0x9b, 0x80, 0x4c,
    0x00, 0x15, 0xa6, 0xa8, 0x07, 0x26, 0x2a, 0xc9, 0xc4, 0x8b, 0x86, 0x62, 0x32, 0x0f, 0x86, 0x64,
    0x24, 0x06, 0x66, 0x71, 0x19, 0x98, 0xcc, 0x43, 0x33, 0x31, 0x99, 0x00, 0x66, 0x88, 0x33, 0x30,
    0xcc, 0xd1, 0x0e, 0x98, 0x0b, 0x33, 0x34, 0x40, 0x0c, 0xd1, 0x46, 0x66, 0x19, 0x9a, 0x28, 0xcc,
    0x49, 0x80, 0xb3, 0x33, 0x45, 0x00, 0xcd, 0x18, 0x66, 0x61, 0x99, 0xa3, 0x0c, 0xc8, 0x98, 0x0b,
    0x33, 0x34, 0x60, 0x4c, 0xd1, 0x06, 0x68, 0xa5, 0x20, 0x62, 0x66, 0x88, 0x33, 0x46, 0x28, 0x05,
    0x0f, 0x32, 0x0c, 0x4c, 0xd1, 0x46, 0x68, 0xc5, 0x00, 0x41, 0xe4, 0x8f, 0xc8, 0x85, 0x5e, 0x02,
    0x7c, 0xc9, 0x26, 0x81, 0x83, 0xb0, 0x9d, 0xc2, 0xde, 0x9c, 0x78, 0xac, 0xd6, 0x68, 0xb4, 0x0e,
    0x71, 0xdb, 0xb2, 0x49, 0x38, 0x6e, 0x02, 0x2a, 0x2c, 0x41, 0x2b, 0x10, 0x98, 0x82, 0x49, 0x03,
    0x14, 0xf4, 0xe1, 0x97, 0x00,
];
const RAR3_AUDIO_FILTER_BYTECODE: &[u8] = &[
    0x47, 0x01, 0x9a, 0x41, 0x95, 0xe5, 0x72, 0x0d, 0xc2, 0x64, 0x82, 0x74, 0x93, 0x24, 0xb1, 0x40,
    0x06, 0xd8, 0x38, 0x44, 0x00, 0xa8, 0x01, 0x34, 0x11, 0xdc, 0xa1, 0xba, 0x01, 0x99, 0x0c, 0xc4,
    0x03, 0x31, 0x19, 0xa4, 0x06, 0x66, 0x22, 0x60, 0x4d, 0x9a, 0x40, 0x0d, 0x66, 0x8e, 0x60, 0xd0,
    0x30, 0x40, 0x18, 0x26, 0xc1, 0xc8, 0xf6, 0xe6, 0x26, 0x13, 0x78, 0x92, 0x08, 0xe8, 0x50, 0xbc,
    0x5a, 0x07, 0xc6, 0xe9, 0xf5, 0x20, 0xa9, 0xa0, 0xed, 0x37, 0x33, 0x47, 0x39, 0x66, 0x90, 0x70,
    0x19, 0xa3, 0x9b, 0xcf, 0x25, 0x83, 0x80, 0xc1, 0xbd, 0x30, 0x16, 0x6e, 0x23, 0x34, 0x93, 0x81,
    0x16, 0x09, 0xb0, 0x50, 0x18, 0x3b, 0x4d, 0xc8, 0x4c, 0x05, 0x9b, 0x88, 0xc5, 0x28, 0xe0, 0x76,
    0x93, 0x90, 0x98, 0x0b, 0x37, 0x11, 0x8a, 0x59, 0xc4, 0x80, 0x42, 0x48, 0x43, 0xa9, 0x47, 0xee,
    0x43, 0x34, 0x60, 0x47, 0xd4, 0x4a, 0x0d, 0xbb, 0xd3, 0x59, 0xa4, 0x86, 0xee, 0x05, 0x09, 0x40,
    0x26, 0xc9, 0x34, 0x24, 0x76, 0xa0, 0x30, 0x6a, 0x20, 0xea, 0x02, 0x20, 0x04, 0xa0, 0x41, 0x50,
    0x9e, 0x50, 0x3f, 0xe6, 0xe1, 0x28, 0x94, 0x46, 0x01, 0xbd, 0x8b, 0x40, 0xf0, 0x68, 0x11, 0x36,
    0xc9, 0xa1, 0x92, 0x38, 0x11, 0x41, 0x9c, 0xa8, 0x95, 0x10, 0xee, 0x50, 0x66, 0x2b, 0x00, 0x20,
    0x95, 0x11, 0x04, 0x02, 0x62, 0xac, 0x66, 0x8c, 0x6a, 0xca, 0x26, 0x40, 0xb2, 0x67, 0x1b, 0x4b,
    0x26, 0xcc, 0x64, 0x8a, 0x62, 0x71, 0xa2, 0xb8,
];

pub fn unpack29_decode(input: &[u8], output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = Unpack29::new();
    decoder.decode_non_solid_member(input, output_size)
}

pub fn unpack29_encode_literals(input: &[u8]) -> Result<Vec<u8>> {
    encode_member(input, &[])
}

pub fn unpack29_encode_literals_with_options(
    input: &[u8],
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member_with_options(input, &[], options)
}

pub(crate) fn unpack29_encode_literals_with_options_and_progress(
    input: &[u8],
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_member_with_options_and_progress(input, &[], options, progress)
}

pub fn unpack29_encode_ppmd_literals(input: &[u8]) -> Result<Vec<u8>> {
    encode_ppmd_member(input, false, &[])
}

pub fn unpack29_encode_ppmd(input: &[u8]) -> Result<Vec<u8>> {
    encode_ppmd_member(input, true, &[])
}

pub fn unpack29_encode_ppmd_with_filter(input: &[u8], filter: Rar29FilterSpec) -> Result<Vec<u8>> {
    encode_ppmd_filtered_member(input, filter, true)
}

pub fn unpack29_encode_ppmd_literals_with_filter(
    input: &[u8],
    filter: Rar29FilterSpec,
) -> Result<Vec<u8>> {
    encode_ppmd_filtered_member(input, filter, false)
}

fn encode_ppmd_filtered_member(
    input: &[u8],
    filter: Rar29FilterSpec,
    lz_escapes: bool,
) -> Result<Vec<u8>> {
    let filters = split_large_filter(input.len(), filter)?;
    let filtered = filtered_members(input, &filters)?;
    let records = encoded_filter_records(&filtered.records)?;
    encode_ppmd_member(&filtered.data, lz_escapes, &records)
}

fn filtered_members(input: &[u8], filters: &[Rar29FilterSpec]) -> Result<FilteredMembers> {
    let mut data = input.to_vec();
    let mut records = Vec::with_capacity(filters.len());
    for filter in filters {
        let filtered = filtered_member(input, filter)?;
        let range = filtered.block_start..filtered.block_start + filtered.block_size;
        data[range.clone()].copy_from_slice(&filtered.data[range]);
        records.push(OwnedVmFilterRecord {
            block_start: filtered.block_start,
            block_size: filtered.block_size,
            init_regs: filtered.init_regs,
            code: filtered.code,
        });
    }
    Ok(FilteredMembers { data, records })
}

struct FilteredMembers {
    data: Vec<u8>,
    records: Vec<OwnedVmFilterRecord>,
}

/// The furthest a RAR 3 x86 filter block may end, in member-relative bytes.
///
/// SPEC C Part 3.2: the RAR 3 x86 transform forms `o = F + p + 1` with no
/// reduction, where `F` is the block's member-relative start and `p` the
/// position of the trigger byte inside it. Encode is the inverse of decode
/// only while `o <= 2^31`; past that the pair is not invertible for every
/// operand value, and the transform must not be "repaired", because its
/// decode side has to agree with every other RAR 3 reader.
///
/// A block `[s, e)` reaches at most `o = e - 4`, because a trigger byte
/// needs four operand bytes behind it and so sits at most at `e - 5`.
const MAX_RAR3_X86_FILTER_END: usize = (1 << 31) + 4;

/// The shortest x86 block that can convert anything: one trigger byte and
/// its four operand bytes.
const MIN_RAR3_X86_FILTER_LEN: usize = 5;

const RAR3_X86_PAST_BOUNDARY: &str =
    "RAR 2.9 x86 filter range reaches past the 2 GiB round-trip boundary";

fn split_large_filter(input_len: usize, filter: Rar29FilterSpec) -> Result<Vec<Rar29FilterSpec>> {
    let range = filter.range.clone().unwrap_or(0..input_len);
    if range.start >= range.end || range.end > input_len {
        return Err(Error::InvalidData("RAR 2.9 VM filter range is invalid"));
    }

    // SPEC C Part 7 item 1, settled 16 Sep 2026: the writer gives up the
    // coverage it cannot encode reversibly rather than refusing the member.
    // The safe side of a large member is still filtered in full; only the
    // tail past 2 GiB goes out unfiltered, which costs ratio and never
    // correctness. Refusing was the spec's other option and was rejected:
    // `FilterPolicy::Auto` offers a whole-member x86 filter for every
    // member it compresses, so a refusal here would turn every RAR 2.9
    // write of a member over 2 GiB into a hard error.
    let mut clipped = false;
    let range = if matches!(filter.kind, Rar29FilterKind::E8 | Rar29FilterKind::E8E9) {
        let end = range.end.min(MAX_RAR3_X86_FILTER_END);
        clipped = end != range.end;
        if end.saturating_sub(range.start) < MIN_RAR3_X86_FILTER_LEN {
            // Nothing left that a filter record could convert.
            return Ok(Vec::new());
        }
        range.start..end
    } else {
        range
    };

    let chunk_size = match filter.kind {
        Rar29FilterKind::Delta { channels } => {
            if channels == 0 || channels > MAX_VM_DELTA_FILTER_BLOCK_SIZE {
                return Err(Error::InvalidData(
                    "RAR 2.9 VM filter channel count is invalid",
                ));
            }
            MAX_VM_DELTA_FILTER_BLOCK_SIZE - (MAX_VM_DELTA_FILTER_BLOCK_SIZE % channels)
        }
        Rar29FilterKind::Audio { channels } => {
            if channels == 0 || channels > MAX_VM_AUDIO_FILTER_BLOCK_SIZE {
                return Err(Error::InvalidData(
                    "RAR 2.9 VM filter channel count is invalid",
                ));
            }
            MAX_VM_AUDIO_FILTER_BLOCK_SIZE - (MAX_VM_AUDIO_FILTER_BLOCK_SIZE % channels)
        }
        Rar29FilterKind::Rgb { width, .. } => {
            if width == 0 || width > MAX_VM_FILTER_BLOCK_SIZE {
                return Err(Error::InvalidData(
                    "RAR 2.9 RGB filter scanline width is invalid",
                ));
            }
            MAX_VM_FILTER_BLOCK_SIZE - (MAX_VM_FILTER_BLOCK_SIZE % width)
        }
        Rar29FilterKind::E8 | Rar29FilterKind::E8E9 | Rar29FilterKind::Itanium => {
            MAX_VM_FILTER_BLOCK_SIZE
        }
    };
    if range.len() <= chunk_size {
        return Ok(vec![if clipped {
            Rar29FilterSpec::range(filter.kind, range)
        } else {
            filter
        }]);
    }
    if chunk_size == 0 {
        return Err(Error::InvalidData(
            "RAR 2.9 VM filter chunk size is invalid",
        ));
    }

    let mut filters = Vec::new();
    let mut start = range.start;
    while start < range.end {
        let end = (start + chunk_size).min(range.end);
        filters.push(Rar29FilterSpec::range(filter.kind, start..end));
        start = end;
    }
    Ok(filters)
}

struct OwnedVmFilterRecord {
    block_start: usize,
    block_size: usize,
    init_regs: Vec<(usize, u32)>,
    code: &'static [u8],
}

fn encode_ppmd_member(
    input: &[u8],
    lz_escapes: bool,
    initial_filters: &[Vec<u8>],
) -> Result<Vec<u8>> {
    encode_ppmd_block(input, lz_escapes, initial_filters)
}

fn encode_ppmd_block(
    input: &[u8],
    lz_escapes: bool,
    initial_filters: &[Vec<u8>],
) -> Result<Vec<u8>> {
    const PPMD_ORDER: usize = 8;
    const PPMD_DICTIONARY_MB: u8 = 25;
    const PPMD_ESC: u8 = 2;

    let mut out = Vec::new();
    out.push(0x80 | 0x20 | ((PPMD_ORDER as u8) - 1));
    out.push(PPMD_DICTIONARY_MB - 1);
    let mut encoder = PpmdEncoder::new(PPMD_ORDER, PPMD_ESC, usize::from(PPMD_DICTIONARY_MB))?;
    for record in initial_filters {
        encoder.encode_vm_filter_record(record)?;
    }
    for token in encode_ppmd_tokens(input, lz_escapes) {
        match token {
            PpmdEncodeToken::Literal(byte) => encoder.encode_literal(byte)?,
            PpmdEncodeToken::RepeatOffsetOne { length } => {
                encoder.encode_repeat_offset_one(length)?
            }
            PpmdEncodeToken::Match { offset, length } => encoder.encode_match(offset, length)?,
        }
    }
    out.extend_from_slice(&encoder.finish()?);
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PpmdEncodeToken {
    Literal(u8),
    RepeatOffsetOne { length: usize },
    Match { offset: usize, length: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rar29FilterSpec {
    pub kind: Rar29FilterKind,
    pub range: Option<Range<usize>>,
}

impl Rar29FilterSpec {
    pub fn whole(kind: Rar29FilterKind) -> Self {
        Self { kind, range: None }
    }

    pub fn range(kind: Rar29FilterKind, range: Range<usize>) -> Self {
        Self {
            kind,
            range: Some(range),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rar29FilterKind {
    E8,
    E8E9,
    Delta { channels: usize },
    Itanium,
    Rgb { width: usize, pos_r: usize },
    Audio { channels: usize },
}

struct FilteredMember {
    data: Vec<u8>,
    block_start: usize,
    block_size: usize,
    init_regs: Vec<(usize, u32)>,
    code: &'static [u8],
}

fn filtered_member(input: &[u8], filter: &Rar29FilterSpec) -> Result<FilteredMember> {
    let range = filter.range.clone().unwrap_or(0..input.len());
    if matches!(filter.kind, Rar29FilterKind::E8 | Rar29FilterKind::E8E9)
        && range.end > MAX_RAR3_X86_FILTER_END
    {
        // `split_large_filter` is the only way in and clips this away, so
        // reaching here is a writer bug rather than bad caller input. Refuse
        // rather than emit a record that will not round trip. Checked before
        // the length arm below so the two cannot be confused.
        return Err(Error::InvalidData(RAR3_X86_PAST_BOUNDARY));
    }
    if range.start >= range.end || range.end > input.len() {
        return Err(Error::InvalidData("RAR 2.9 VM filter range is invalid"));
    }
    let mut filtered = input.to_vec();
    let (init_regs, code): (Vec<(usize, u32)>, &'static [u8]) = match filter.kind {
        Rar29FilterKind::E8 => {
            filters::encode_in_place(
                FilterOp::E8,
                &mut filtered[range.clone()],
                range.start as u32,
                rar29_delta_messages(),
            )?;
            (Vec::new(), RAR3_E8_FILTER_BYTECODE)
        }
        Rar29FilterKind::E8E9 => {
            filters::encode_in_place(
                FilterOp::E8E9,
                &mut filtered[range.clone()],
                range.start as u32,
                rar29_delta_messages(),
            )?;
            (Vec::new(), RAR3_E8E9_FILTER_BYTECODE)
        }
        Rar29FilterKind::Delta { channels } => {
            filters::encode_in_place(
                FilterOp::Delta { channels },
                &mut filtered[range.clone()],
                0,
                rar29_delta_messages(),
            )?;
            (vec![(0, channels as u32)], RAR3_DELTA_FILTER_BYTECODE)
        }
        Rar29FilterKind::Itanium => {
            itanium_encode(&mut filtered[range.clone()], range.start as u32);
            (Vec::new(), RAR3_ITANIUM_FILTER_BYTECODE)
        }
        Rar29FilterKind::Rgb { width, pos_r } => {
            filtered[range.clone()].copy_from_slice(&rgb_encode(
                &input[range.clone()],
                width,
                pos_r,
            )?);
            let init_regs = if pos_r == 0 {
                vec![(0, width as u32 + 3)]
            } else {
                vec![(0, width as u32 + 3), (1, pos_r as u32)]
            };
            (init_regs, RAR3_RGB_FILTER_BYTECODE)
        }
        Rar29FilterKind::Audio { channels } => {
            filtered[range.clone()]
                .copy_from_slice(&audio_encode(&input[range.clone()], channels)?);
            (vec![(0, channels as u32)], RAR3_AUDIO_FILTER_BYTECODE)
        }
    };
    Ok(FilteredMember {
        data: filtered,
        block_start: range.start,
        block_size: range.end - range.start,
        init_regs,
        code,
    })
}

fn rar29_delta_messages() -> DeltaErrorMessages {
    DeltaErrorMessages {
        invalid_channels: "RAR 2.9 DELTA filter channel count is invalid",
        zero_channels: "RAR 2.9 DELTA filter has zero channels",
        truncated_source: "RAR 2.9 DELTA filter source is truncated",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncodeOptions {
    pub max_match_candidates: usize,
    pub lazy_matching: bool,
    pub lazy_lookahead: usize,
    pub max_match_distance: usize,
    pub block_size: Option<usize>,
}

impl EncodeOptions {
    pub const fn new(max_match_candidates: usize) -> Self {
        Self {
            max_match_candidates,
            lazy_matching: false,
            lazy_lookahead: 1,
            max_match_distance: MAX_ENCODER_MATCH_OFFSET,
            block_size: None,
        }
    }

    pub const fn with_lazy_matching(mut self, enabled: bool) -> Self {
        self.lazy_matching = enabled;
        self
    }

    pub const fn with_lazy_lookahead(mut self, bytes: usize) -> Self {
        self.lazy_lookahead = bytes;
        self
    }

    pub const fn with_max_match_distance(mut self, distance: usize) -> Self {
        self.max_match_distance = distance;
        self
    }

    pub const fn with_block_size(mut self, bytes: usize) -> Self {
        self.block_size = Some(bytes);
        self
    }
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self::new(MAX_MATCH_CANDIDATES)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Unpack29Encoder {
    history: Vec<u8>,
    options: EncodeOptions,
}

impl Unpack29Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: EncodeOptions) -> Self {
        Self {
            history: Vec::new(),
            options,
        }
    }

    pub fn encode_member(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let packed = encode_member_with_options(input, &self.history, self.options)?;
        self.remember(input);
        Ok(packed)
    }

    pub(crate) fn encode_member_with_progress(
        &mut self,
        input: &[u8],
        progress: &mut dyn FnMut(usize) -> bool,
    ) -> Result<Vec<u8>> {
        let packed =
            encode_member_with_options_and_progress(input, &self.history, self.options, progress)?;
        self.remember(input);
        Ok(packed)
    }

    pub fn encode_member_with_filter(
        &mut self,
        input: &[u8],
        filter: Rar29FilterSpec,
    ) -> Result<Vec<u8>> {
        let filters = split_large_filter(input.len(), filter)?;
        let filtered = filtered_members(input, &filters)?;
        let records = encoded_filter_records(&filtered.records)?;
        let packed = encode_member_with_initial_filters(
            &filtered.data,
            &self.history,
            &records,
            self.options,
        )?;
        self.remember(input);
        Ok(packed)
    }

    pub fn encode_member_with_filters(
        &mut self,
        input: &[u8],
        filters: &[Rar29FilterSpec],
    ) -> Result<Vec<u8>> {
        let mut split_filters = Vec::new();
        for filter in filters {
            split_filters.extend(split_large_filter(input.len(), filter.clone())?);
        }
        let filtered = filtered_members(input, &split_filters)?;
        let records = encoded_filter_records(&filtered.records)?;
        let packed = encode_member_with_initial_filters(
            &filtered.data,
            &self.history,
            &records,
            self.options,
        )?;
        self.remember(input);
        Ok(packed)
    }

    fn remember(&mut self, input: &[u8]) {
        self.history.extend_from_slice(input);
        let keep_from = self.history.len().saturating_sub(MAX_HISTORY);
        if keep_from != 0 {
            self.history.drain(..keep_from);
        }
    }
}

fn encode_member(input: &[u8], history: &[u8]) -> Result<Vec<u8>> {
    encode_member_with_options(input, history, EncodeOptions::default())
}

fn encode_member_with_options(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member_with_options_impl(input, history, options, None)
}

fn encode_member_with_options_and_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_member_with_options_impl(input, history, options, Some(progress))
}

fn encode_member_with_options_impl(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    if let Some(block_size) = options.block_size.filter(|&size| size != 0) {
        if input.len() > block_size {
            return encode_member_blocks(input, history, options, block_size, progress);
        }
    }
    encode_member_inner(input, history, &[], options, progress)
}

fn encode_member_blocks(
    input: &[u8],
    history: &[u8],
    mut options: EncodeOptions,
    block_size: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    options.block_size = None;
    let mut out = Vec::new();
    let mut local_history = history[history.len().saturating_sub(MAX_HISTORY)..].to_vec();
    let mut completed = 0usize;
    for chunk in input.chunks(block_size) {
        let mut chunk_progress = |position: usize| {
            progress
                .as_deref_mut()
                .is_none_or(|report| report(completed.saturating_add(position)))
        };
        out.extend_from_slice(&encode_member_inner(
            chunk,
            &local_history,
            &[],
            options,
            Some(&mut chunk_progress),
        )?);
        completed = completed.saturating_add(chunk.len());
        local_history.extend_from_slice(chunk);
        let keep_from = local_history.len().saturating_sub(MAX_HISTORY);
        if keep_from != 0 {
            local_history.drain(..keep_from);
        }
    }
    Ok(out)
}

fn encode_member_with_initial_filters(
    input: &[u8],
    history: &[u8],
    filters: &[Vec<u8>],
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member_inner(input, history, filters, options, None)
}

fn encode_member_inner(
    input: &[u8],
    history: &[u8],
    initial_filters: &[Vec<u8>],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let tokens = encode_tokens_with_progress(input, history, options, progress)?;
    let mut main_frequencies = vec![0usize; MAIN_COUNT];
    let mut offset_frequencies = vec![0usize; OFFSET_COUNT];
    let mut low_offset_frequencies = vec![0usize; LOW_OFFSET_COUNT];
    let mut length_frequencies = vec![0usize; LENGTH_COUNT];
    main_frequencies[257] += initial_filters.len();
    let mut match_state = EncoderMatchState::default();
    for token in &tokens {
        match *token {
            EncodeToken::Literal(byte) => {
                main_frequencies[byte as usize] += 1;
            }
            EncodeToken::Match { length, offset } => {
                match match_state.encode_match(length, offset)? {
                    EncodedMatch::LastLengthRepeat => {
                        main_frequencies[258] += 1;
                    }
                    EncodedMatch::RepeatOffset {
                        index, length_slot, ..
                    } => {
                        main_frequencies[259 + index] += 1;
                        length_frequencies[length_slot] += 1;
                    }
                    EncodedMatch::Fresh {
                        length_slot,
                        offset_slot,
                        offset_extra,
                        ..
                    } => {
                        main_frequencies[271 + length_slot] += 1;
                        offset_frequencies[offset_slot] += 1;
                        if offset_slot > 9 {
                            low_offset_frequencies[offset_extra & 0x0f] += 1;
                        }
                    }
                }
                match_state.remember(length, offset);
            }
        }
    }
    main_frequencies[256] += 1;

    let mut table_lengths = [0u8; TABLE_COUNT];
    if low_offset_frequencies
        .iter()
        .all(|&frequency| frequency == 0)
    {
        low_offset_frequencies[0] = 1;
    }
    let main_lengths = huffman::lengths_for_frequencies(&main_frequencies, 15);
    let offset_lengths = huffman::lengths_for_frequencies(&offset_frequencies, 15);
    let low_offset_lengths = huffman::lengths_for_frequencies(&low_offset_frequencies, 15);
    let length_lengths = huffman::lengths_for_frequencies(&length_frequencies, 15);
    table_lengths[..MAIN_COUNT].copy_from_slice(&main_lengths);
    table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT].copy_from_slice(&offset_lengths);
    table_lengths[MAIN_COUNT + OFFSET_COUNT..MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT]
        .copy_from_slice(&low_offset_lengths);
    table_lengths[MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT..].copy_from_slice(&length_lengths);

    let level_tokens = encode_table_level_tokens(&table_lengths);
    let level_lengths = level_code_lengths(&level_tokens);
    let level_codes = canonical_codes(&level_lengths)?;
    let main_codes = canonical_codes(&table_lengths[..MAIN_COUNT])?;

    let mut bits = BitWriter::default();
    bits.write_bit(false); // LZ block.
    bits.write_bit(false); // do not keep previous tables.
    for &len in &level_lengths {
        bits.write_bits(len as u32, 4);
    }
    for token in level_tokens {
        let code = level_codes[token.symbol].ok_or(Error::InvalidData(
            "RAR 2.9 encoder missing level Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
        if token.extra_bits != 0 {
            bits.write_bits(token.extra_value as u32, token.extra_bits);
        }
    }
    let offset_codes = canonical_codes(&table_lengths[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT])?;
    let low_offset_codes = canonical_codes(
        &table_lengths[MAIN_COUNT + OFFSET_COUNT..MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT],
    )?;
    let length_codes =
        canonical_codes(&table_lengths[MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT..])?;
    for filter in initial_filters {
        let code = main_codes[257].ok_or(Error::InvalidData(
            "RAR 2.9 encoder missing VM filter Huffman code",
        ))?;
        bits.write_bits(code.code as u32, code.len);
        for &byte in filter {
            bits.write_bits(u32::from(byte), 8);
        }
    }
    let mut match_state = EncoderMatchState::default();
    for token in tokens {
        match token {
            EncodeToken::Literal(byte) => {
                let code = main_codes[byte as usize].ok_or(Error::InvalidData(
                    "RAR 2.9 encoder missing literal Huffman code",
                ))?;
                bits.write_bits(code.code as u32, code.len);
            }
            EncodeToken::Match { length, offset } => {
                match match_state.encode_match(length, offset)? {
                    EncodedMatch::LastLengthRepeat => {
                        let code = main_codes[258].ok_or(Error::InvalidData(
                            "RAR 2.9 encoder missing last-length repeat Huffman code",
                        ))?;
                        bits.write_bits(code.code as u32, code.len);
                    }
                    EncodedMatch::RepeatOffset {
                        index,
                        length_slot,
                        length_extra,
                    } => {
                        let code = main_codes[259 + index].ok_or(Error::InvalidData(
                            "RAR 2.9 encoder missing repeat-offset Huffman code",
                        ))?;
                        bits.write_bits(code.code as u32, code.len);
                        let length_code = length_codes[length_slot].ok_or(Error::InvalidData(
                            "RAR 2.9 encoder missing repeat length Huffman code",
                        ))?;
                        bits.write_bits(length_code.code as u32, length_code.len);
                        if LENGTH_BITS[length_slot] != 0 {
                            bits.write_bits(length_extra as u32, LENGTH_BITS[length_slot]);
                        }
                    }
                    EncodedMatch::Fresh {
                        length_slot,
                        length_extra,
                        offset_slot,
                        offset_extra,
                    } => {
                        let code = main_codes[271 + length_slot].ok_or(Error::InvalidData(
                            "RAR 2.9 encoder missing match Huffman code",
                        ))?;
                        bits.write_bits(code.code as u32, code.len);
                        if LENGTH_BITS[length_slot] != 0 {
                            bits.write_bits(length_extra as u32, LENGTH_BITS[length_slot]);
                        }
                        let offset = offset_codes[offset_slot].ok_or(Error::InvalidData(
                            "RAR 2.9 encoder missing offset Huffman code",
                        ))?;
                        bits.write_bits(offset.code as u32, offset.len);
                        if offset_slot > 9 {
                            let offset_bits = OFFSET_BITS[offset_slot];
                            if offset_bits > 4 {
                                bits.write_bits((offset_extra >> 4) as u32, offset_bits - 4);
                            }
                            let low_offset =
                                low_offset_codes[offset_extra & 0x0f].ok_or(Error::InvalidData(
                                    "RAR 2.9 encoder missing low-offset Huffman code",
                                ))?;
                            bits.write_bits(low_offset.code as u32, low_offset.len);
                        } else if OFFSET_BITS[offset_slot] != 0 {
                            bits.write_bits(offset_extra as u32, OFFSET_BITS[offset_slot]);
                        }
                    }
                }
                match_state.remember(length, offset);
            }
        }
    }
    let end = main_codes[256].ok_or(Error::InvalidData(
        "RAR 2.9 encoder missing end-of-block Huffman code",
    ))?;
    bits.write_bits(end.code as u32, end.len);
    bits.write_bit(true); // end member, no following table.
    Ok(bits.finish())
}

fn encoded_filter_records(filters: &[OwnedVmFilterRecord]) -> Result<Vec<Vec<u8>>> {
    let mut programs: Vec<&'static [u8]> = Vec::new();
    let mut records = Vec::with_capacity(filters.len());
    for filter in filters {
        let existing = (filter.code != RAR3_AUDIO_FILTER_BYTECODE)
            .then(|| programs.iter().position(|&code| code == filter.code))
            .flatten();
        let (program_selector, include_code) = match existing {
            Some(index) => (
                u32::try_from(index + 1)
                    .map_err(|_| Error::InvalidData("RAR 2.9 VM program index overflows"))?,
                false,
            ),
            None => {
                let selector = if programs.is_empty() {
                    0
                } else {
                    u32::try_from(programs.len() + 1)
                        .map_err(|_| Error::InvalidData("RAR 2.9 VM program index overflows"))?
                };
                programs.push(filter.code);
                (selector, true)
            }
        };
        records.push(encode_vm_filter_record_inner(
            VmFilterRecord {
                block_start: filter.block_start,
                block_size: filter.block_size,
                init_regs: &filter.init_regs,
                code: filter.code,
            },
            program_selector,
            include_code,
        )?);
    }
    Ok(records)
}

#[derive(Debug, Clone, Copy)]
struct VmFilterRecord<'a> {
    block_start: usize,
    block_size: usize,
    init_regs: &'a [(usize, u32)],
    code: &'a [u8],
}

fn encode_vm_filter_record_inner(
    record: VmFilterRecord<'_>,
    program_selector: u32,
    include_code: bool,
) -> Result<Vec<u8>> {
    if record.block_size == 0 {
        return Err(Error::InvalidData("RAR 2.9 VM filter block is empty"));
    }
    if include_code && record.code.is_empty() {
        return Err(Error::InvalidData("RAR 2.9 VM filter bytecode is empty"));
    }

    let mut body = BitWriter::default();
    body.write_encoded_u32(program_selector);
    body.write_encoded_u32(
        u32::try_from(record.block_start)
            .map_err(|_| Error::InvalidData("RAR 2.9 VM block start overflows"))?,
    );
    body.write_encoded_u32(
        u32::try_from(record.block_size)
            .map_err(|_| Error::InvalidData("RAR 2.9 VM block size overflows"))?,
    );
    if !record.init_regs.is_empty() {
        let mut mask = 0u32;
        for &(index, _) in record.init_regs {
            if index >= 7 {
                return Err(Error::InvalidData(
                    "RAR 2.9 VM init register index is invalid",
                ));
            }
            mask |= 1 << index;
        }
        body.write_bits(mask, 7);
        for index in 0..7 {
            if let Some((_, value)) = record.init_regs.iter().find(|(reg, _)| *reg == index) {
                body.write_encoded_u32(*value);
            }
        }
    }
    if include_code {
        body.write_encoded_u32(
            u32::try_from(record.code.len())
                .map_err(|_| Error::InvalidData("RAR 2.9 VM code size overflows"))?,
        );
        for &byte in record.code {
            body.write_bits(u32::from(byte), 8);
        }
    }
    let body = body.finish();

    let mut out = Vec::new();
    let mut first = 0x80 | 0x20;
    if !record.init_regs.is_empty() {
        first |= 0x10;
    }
    match body.len() {
        1..=6 => first |= (body.len() as u8) - 1,
        7..=262 => {
            first |= 6;
            out.push((body.len() - 7) as u8);
        }
        263..=65535 => {
            first |= 7;
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        _ => return Err(Error::InvalidData("RAR 2.9 VM filter record is too large")),
    }
    out.insert(0, first);
    out.extend_from_slice(&body);
    Ok(out)
}

fn rgb_encode(data: &[u8], width: usize, pos_r: usize) -> Result<Vec<u8>> {
    if data.len() < 3 || width == 0 || !width.is_multiple_of(3) || width > data.len() || pos_r > 2 {
        return Err(Error::InvalidData(
            "RAR 2.9 RGB filter parameters are invalid",
        ));
    }
    let mut work = data.to_vec();
    for i in (pos_r..work.len().saturating_sub(2)).step_by(3) {
        let green = work[i + 1];
        work[i] = work[i].wrapping_sub(green);
        work[i + 2] = work[i + 2].wrapping_sub(green);
    }

    let mut out = Vec::with_capacity(data.len());
    for channel in 0..3 {
        let mut prev = 0u8;
        let mut i = channel;
        while i < work.len() {
            let predicted = if i >= width + 3 {
                rgb_predict(prev, work[i - width], work[i - width - 3])
            } else {
                prev
            };
            let byte = work[i];
            out.push(predicted.wrapping_sub(byte));
            prev = byte;
            i += 3;
        }
    }
    Ok(out)
}

fn audio_encode(data: &[u8], channels: usize) -> Result<Vec<u8>> {
    if channels == 0 || channels > 32 {
        return Err(Error::InvalidData(
            "RAR 2.9 AUDIO filter channel count is invalid",
        ));
    }
    let mut out = Vec::with_capacity(data.len());
    for channel in 0..channels {
        let mut prev_byte = 0u32;
        let mut prev_delta = 0i32;
        let mut d1 = 0i32;
        let mut d2 = 0i32;
        let mut k1 = 0i32;
        let mut k2 = 0i32;
        let mut k3 = 0i32;
        let mut dif = [0u32; 7];
        let mut byte_count = 0usize;
        let mut i = channel;
        while i < data.len() {
            let d3 = d2;
            d2 = prev_delta - d1;
            d1 = prev_delta;
            let predicted = ((8 * prev_byte as i32 + k1 * d1 + k2 * d2 + k3 * d3) >> 3) & 0xff;
            let decoded = data[i];
            let encoded = (predicted as u8).wrapping_sub(decoded);
            out.push(encoded);
            prev_delta = decoded.wrapping_sub(prev_byte as u8) as i8 as i32;
            prev_byte = decoded as u32;
            let d = (encoded as i8 as i32) << 3;
            dif[0] += d.unsigned_abs();
            dif[1] += (d - d1).unsigned_abs();
            dif[2] += (d + d1).unsigned_abs();
            dif[3] += (d - d2).unsigned_abs();
            dif[4] += (d + d2).unsigned_abs();
            dif[5] += (d - d3).unsigned_abs();
            dif[6] += (d + d3).unsigned_abs();
            if byte_count & 0x1f == 0 {
                let mut min = dif[0];
                let mut min_index = 0usize;
                dif[0] = 0;
                for (index, value) in dif.iter_mut().enumerate().skip(1) {
                    if *value < min {
                        min = *value;
                        min_index = index;
                    }
                    *value = 0;
                }
                match min_index {
                    1 if k1 >= -16 => k1 -= 1,
                    2 if k1 < 16 => k1 += 1,
                    3 if k2 >= -16 => k2 -= 1,
                    4 if k2 < 16 => k2 += 1,
                    5 if k3 >= -16 => k3 -= 1,
                    6 if k3 < 16 => k3 += 1,
                    _ => {}
                }
            }
            byte_count += 1;
            i += channels;
        }
    }
    Ok(out)
}

fn itanium_encode(data: &mut [u8], file_offset: u32) {
    if data.len() <= 21 {
        return;
    }
    let base_offset = file_offset >> 4;
    let block_count = (data.len() - 21).div_ceil(16);
    for block in 0..block_count {
        let pos = block * 16;
        let file_offset = base_offset.wrapping_add(block as u32);
        let mut mask = (0x334b_0000u32 >> (data[pos] & 0x1e)) & 3;
        if mask != 0 {
            mask += 1;
            while mask <= 4 {
                let p = pos + (mask as usize * 5 - 8);
                if ((data[p + 3] >> mask) & 15) == 5 {
                    let raw = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                    let mut value = raw >> mask;
                    value = value.wrapping_add(file_offset) & 0x000f_ffff;
                    let raw = (raw & !(0x000f_ffff << mask)) | (value << mask);
                    data[p..p + 4].copy_from_slice(&raw.to_le_bytes());
                }
                mask += 1;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum EncodeToken {
    Literal(u8),
    Match { length: usize, offset: usize },
}

#[derive(Debug, Clone, Copy, Default)]
struct EncoderMatchState {
    old_offsets: [usize; 4],
    last_offset: usize,
    last_length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodedMatch {
    LastLengthRepeat,
    RepeatOffset {
        index: usize,
        length_slot: usize,
        length_extra: usize,
    },
    Fresh {
        length_slot: usize,
        length_extra: usize,
        offset_slot: usize,
        offset_extra: usize,
    },
}

impl EncoderMatchState {
    fn encode_match(&self, length: usize, offset: usize) -> Result<EncodedMatch> {
        if offset == self.last_offset && length == self.last_length && self.last_length != 0 {
            return Ok(EncodedMatch::LastLengthRepeat);
        }
        if let Some(index) = self
            .old_offsets
            .iter()
            .position(|&old_offset| old_offset == offset && old_offset != 0)
        {
            let (length_slot, length_extra) = length_slot_for_repeat_match(length)?;
            return Ok(EncodedMatch::RepeatOffset {
                index,
                length_slot,
                length_extra,
            });
        }
        let encoded_length =
            length
                .checked_sub(match_length_adjustment(offset))
                .ok_or(Error::InvalidData(
                    "RAR 2.9 adjusted match length underflows",
                ))?;
        let (length_slot, length_extra) = length_slot_for_match(encoded_length)?;
        let (offset_slot, offset_extra) = offset_slot_for_match(offset)?;
        Ok(EncodedMatch::Fresh {
            length_slot,
            length_extra,
            offset_slot,
            offset_extra,
        })
    }

    fn remember(&mut self, length: usize, offset: usize) {
        if offset == self.last_offset && length == self.last_length && self.last_length != 0 {
            return;
        }
        if let Some(index) = self
            .old_offsets
            .iter()
            .position(|&old_offset| old_offset == offset)
        {
            self.old_offsets[..=index].rotate_right(1);
        } else {
            self.old_offsets.rotate_right(1);
            self.old_offsets[0] = offset;
        }
        self.last_offset = offset;
        self.last_length = length;
    }
}

#[cfg(test)]
fn encode_tokens(input: &[u8], history: &[u8], options: EncodeOptions) -> Vec<EncodeToken> {
    encode_tokens_with_progress(input, history, options, None)
        .expect("encoding without cancellation cannot be cancelled")
}

fn encode_tokens_with_progress(
    input: &[u8],
    history: &[u8],
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<EncodeToken>> {
    let mut tokens = Vec::new();
    let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
    let history = &history[history.len().saturating_sub(options.max_match_distance)..];
    let mut combined = Vec::with_capacity(history.len() + input.len());
    combined.extend_from_slice(history);
    combined.extend_from_slice(input);
    for history_pos in 0..history.len().saturating_sub(2) {
        insert_match_position(&combined, history_pos, &mut buckets);
    }

    let mut pos = history.len();
    let end = combined.len();
    let mut state = EncoderMatchState::default();
    let mut next_report = 0usize;
    while pos < end {
        if let Some(candidate) = best_match(&combined, pos, end, &buckets, options, &state) {
            if should_lazy_emit_literal(&combined, pos, end, &buckets, options, &state, candidate) {
                tokens.push(EncodeToken::Literal(combined[pos]));
                insert_match_position(&combined, pos, &mut buckets);
                pos += 1;
                continue;
            }
            let MatchCandidate { length, offset, .. } = candidate;
            tokens.push(EncodeToken::Match { length, offset });
            state.remember(length, offset);
            for history_pos in pos..pos + length {
                insert_match_position(&combined, history_pos, &mut buckets);
            }
            pos += length;
        } else {
            tokens.push(EncodeToken::Literal(combined[pos]));
            insert_match_position(&combined, pos, &mut buckets);
            pos += 1;
        }
        let consumed = pos.saturating_sub(history.len());
        if consumed >= next_report {
            if progress
                .as_deref_mut()
                .is_some_and(|report| !report(consumed))
            {
                return Err(Error::Cancelled);
            }
            next_report = consumed.saturating_add(1024 * 1024);
        }
    }
    if progress.is_some_and(|report| !report(input.len())) {
        return Err(Error::Cancelled);
    }
    Ok(tokens)
}

fn should_lazy_emit_literal(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &[Vec<usize>],
    options: EncodeOptions,
    state: &EncoderMatchState,
    current: MatchCandidate,
) -> bool {
    if !options.lazy_matching || pos + 1 >= end {
        return false;
    }
    let lookahead = options.lazy_lookahead.max(1);
    (1..=lookahead)
        .take_while(|offset| pos + offset < end)
        .any(|offset| {
            best_match(input, pos + offset, end, buckets, options, state).is_some_and(|next| {
                let skipped_literal_score = offset as isize * 8;
                next.score > current.score + skipped_literal_score
            })
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MatchCandidate {
    length: usize,
    offset: usize,
    score: isize,
}

fn encode_ppmd_tokens(input: &[u8], lz_escapes: bool) -> Vec<PpmdEncodeToken> {
    if !lz_escapes {
        return input
            .iter()
            .copied()
            .map(PpmdEncodeToken::Literal)
            .collect();
    }

    let mut tokens = Vec::new();
    let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
    let mut pos = 0usize;
    while pos < input.len() {
        if let Some(length) = ppmd_offset_one_repeat(input, pos) {
            tokens.push(PpmdEncodeToken::RepeatOffsetOne { length });
            for history_pos in pos..pos + length {
                insert_match_position(input, history_pos, &mut buckets);
            }
            pos += length;
            continue;
        }

        if let Some((length, offset)) = best_ppmd_match(input, pos, &buckets) {
            tokens.push(PpmdEncodeToken::Match { offset, length });
            for history_pos in pos..pos + length {
                insert_match_position(input, history_pos, &mut buckets);
            }
            pos += length;
            continue;
        }

        tokens.push(PpmdEncodeToken::Literal(input[pos]));
        insert_match_position(input, pos, &mut buckets);
        pos += 1;
    }
    tokens
}

fn ppmd_offset_one_repeat(input: &[u8], pos: usize) -> Option<usize> {
    if pos == 0 || input[pos] != input[pos - 1] {
        return None;
    }
    let mut length = 0usize;
    while pos + length < input.len()
        && input[pos + length] == input[pos - 1]
        && length < MAX_PPMD_REPEAT_LENGTH
    {
        length += 1;
    }
    (length >= 4).then_some(length)
}

fn best_ppmd_match(input: &[u8], pos: usize, buckets: &[Vec<usize>]) -> Option<(usize, usize)> {
    let max_offset = pos.min(0x1000001).min(MAX_ENCODER_MATCH_OFFSET);
    let max_length = (input.len() - pos).min(MAX_PPMD_MATCH_LENGTH);
    if max_offset < 2 || max_length < MIN_PPMD_MATCH_LENGTH || pos + 2 >= input.len() {
        return None;
    }
    let bucket = &buckets[match_hash(input, pos)];
    let mut best = None;
    let mut checked = 0usize;
    for &candidate in bucket.iter().rev() {
        if candidate >= pos {
            continue;
        }
        let offset = pos - candidate;
        if offset > max_offset {
            break;
        }
        if offset < 2 {
            continue;
        }
        checked += 1;
        let mut length = 0usize;
        while length < max_length && input[pos + length] == input[pos + length - offset] {
            length += 1;
        }
        if length >= MIN_PPMD_MATCH_LENGTH
            && best.is_none_or(|(best_length, best_offset)| {
                length > best_length || (length == best_length && offset < best_offset)
            })
        {
            best = Some((length, offset));
            if length == max_length {
                break;
            }
        }
        if checked >= MAX_MATCH_CANDIDATES {
            break;
        }
    }
    best
}

fn best_match(
    input: &[u8],
    pos: usize,
    end: usize,
    buckets: &[Vec<usize>],
    options: EncodeOptions,
    state: &EncoderMatchState,
) -> Option<MatchCandidate> {
    let max_offset = pos.min(options.max_match_distance);
    let max_length = (end - pos).min(MAX_ENCODER_MATCH_LENGTH);
    if options.max_match_candidates == 0
        || max_offset == 0
        || max_length < 4
        || pos + 2 >= input.len()
    {
        return None;
    }
    let bucket = &buckets[match_hash(input, pos)];
    let mut best = None;
    let mut checked = 0usize;
    for offset in state.old_offsets {
        if offset == 0 || offset > max_offset {
            continue;
        }
        let length = match_length(input, pos, offset, max_length);
        consider_match_candidate(&mut best, state, length, offset);
    }
    for &candidate in bucket.iter().rev() {
        if candidate >= pos {
            continue;
        }
        let offset = pos - candidate;
        if offset > max_offset {
            break;
        }
        checked += 1;
        let length = match_length(input, pos, offset, max_length);
        consider_match_candidate(&mut best, state, length, offset);
        if best.is_some_and(|candidate| candidate.length == max_length) {
            break;
        }
        if checked >= options.max_match_candidates {
            break;
        }
    }
    best
}

fn match_length(input: &[u8], pos: usize, offset: usize, max_length: usize) -> usize {
    super::fast::match_length(input, pos, offset, max_length)
}

fn consider_match_candidate(
    best: &mut Option<MatchCandidate>,
    state: &EncoderMatchState,
    length: usize,
    offset: usize,
) {
    if length < 4 {
        return;
    }
    let Ok(cost) = estimated_match_cost(state, length, offset) else {
        return;
    };
    let score = (length as isize * 8) - cost as isize;
    let candidate = MatchCandidate {
        length,
        offset,
        score,
    };
    if best.is_none_or(|best| {
        candidate.score > best.score
            || (candidate.score == best.score
                && (candidate.length > best.length
                    || (candidate.length == best.length && candidate.offset < best.offset)))
    }) {
        *best = Some(candidate);
    }
}

fn estimated_match_cost(state: &EncoderMatchState, length: usize, offset: usize) -> Result<usize> {
    match state.encode_match(length, offset)? {
        EncodedMatch::LastLengthRepeat => Ok(2),
        EncodedMatch::RepeatOffset { length_slot, .. } => {
            Ok(5 + usize::from(LENGTH_BITS[length_slot]))
        }
        EncodedMatch::Fresh {
            length_slot,
            offset_slot,
            ..
        } => {
            let low_offset_cost = usize::from(offset_slot > 9) * 4;
            Ok(8 + usize::from(LENGTH_BITS[length_slot])
                + usize::from(OFFSET_BITS[offset_slot])
                + low_offset_cost)
        }
    }
}

fn match_length_adjustment(offset: usize) -> usize {
    usize::from(offset >= 0x2000) + usize::from(offset >= 0x40000)
}

fn insert_match_position(input: &[u8], pos: usize, buckets: &mut [Vec<usize>]) {
    if pos + 2 < input.len() {
        buckets[match_hash(input, pos)].push(pos);
    }
}

fn match_hash(input: &[u8], pos: usize) -> usize {
    let value =
        ((input[pos] as usize) << 8) ^ ((input[pos + 1] as usize) << 4) ^ input[pos + 2] as usize;
    value & (MATCH_HASH_BUCKETS - 1)
}

fn length_slot_for_match(length: usize) -> Result<(usize, usize)> {
    if length < 3 {
        return Err(Error::InvalidData("RAR 2.9 match length is too short"));
    }
    let adjusted = length - 3;
    for (slot, &base) in LENGTH_BASES.iter().enumerate() {
        let extra_bits = LENGTH_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData("RAR 2.9 match length is too long"))
}

fn length_slot_for_repeat_match(length: usize) -> Result<(usize, usize)> {
    if length < 2 {
        return Err(Error::InvalidData(
            "RAR 2.9 repeat match length is too short",
        ));
    }
    let adjusted = length - 2;
    for (slot, &base) in LENGTH_BASES.iter().enumerate() {
        let extra_bits = LENGTH_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData(
        "RAR 2.9 repeat match length is too long",
    ))
}

fn offset_slot_for_match(offset: usize) -> Result<(usize, usize)> {
    if offset == 0 {
        return Err(Error::InvalidData("RAR 2.9 match offset is zero"));
    }
    let adjusted = offset - 1;
    for (slot, &base) in OFFSET_BASES.iter().enumerate() {
        let extra_bits = OFFSET_BITS[slot];
        let max = base
            + if extra_bits == 0 {
                0
            } else {
                (1usize << extra_bits) - 1
            };
        if adjusted >= base && adjusted <= max {
            return Ok((slot, adjusted - base));
        }
    }
    Err(Error::InvalidData("RAR 2.9 match offset is too large"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LevelToken {
    symbol: usize,
    extra_bits: u8,
    extra_value: u8,
}

impl LevelToken {
    const fn plain(symbol: usize) -> Self {
        Self {
            symbol,
            extra_bits: 0,
            extra_value: 0,
        }
    }

    const fn repeat_previous_short(count: usize) -> Self {
        Self {
            symbol: 16,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn repeat_previous_long(count: usize) -> Self {
        Self {
            symbol: 17,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }

    const fn zero_run_short(count: usize) -> Self {
        Self {
            symbol: 18,
            extra_bits: 3,
            extra_value: (count - 3) as u8,
        }
    }

    const fn zero_run_long(count: usize) -> Self {
        Self {
            symbol: 19,
            extra_bits: 7,
            extra_value: (count - 11) as u8,
        }
    }
}

fn encode_table_level_tokens(lengths: &[u8; TABLE_COUNT]) -> Vec<LevelToken> {
    encode_level_tokens(lengths)
}

fn encode_level_tokens(lengths: &[u8]) -> Vec<LevelToken> {
    let mut tokens = Vec::new();
    let mut pos = 0usize;
    let mut previous = None;
    while pos < lengths.len() {
        let value = lengths[pos];
        let mut run = 1usize;
        while pos + run < lengths.len() && lengths[pos + run] == value {
            run += 1;
        }

        if value == 0 {
            emit_zero_level_run(&mut tokens, run);
            previous = Some(0);
            pos += run;
            continue;
        }

        if previous == Some(value) && run >= 3 {
            emit_repeat_level_run(&mut tokens, run);
            pos += run;
            continue;
        }

        tokens.push(LevelToken::plain(value as usize));
        previous = Some(value);
        pos += 1;
    }
    tokens
}

fn emit_repeat_level_run(tokens: &mut Vec<LevelToken>, mut run: usize) {
    while run != 0 {
        if run >= 11 {
            let mut chunk = run.min(138);
            if matches!(run - chunk, 1 | 2) && chunk >= 14 {
                chunk -= 3;
            }
            tokens.push(LevelToken::repeat_previous_long(chunk));
            run -= chunk;
        } else if run >= 3 {
            let chunk = run.min(10);
            tokens.push(LevelToken::repeat_previous_short(chunk));
            run -= chunk;
        } else {
            break;
        }
    }
}

fn emit_zero_level_run(tokens: &mut Vec<LevelToken>, mut run: usize) {
    while run != 0 {
        if run >= 11 {
            let mut chunk = run.min(138);
            if matches!(run - chunk, 1 | 2) && chunk >= 14 {
                chunk -= 3;
            }
            tokens.push(LevelToken::zero_run_long(chunk));
            run -= chunk;
        } else if run >= 3 {
            let chunk = run.min(10);
            tokens.push(LevelToken::zero_run_short(chunk));
            run -= chunk;
        } else {
            tokens.extend(std::iter::repeat_n(LevelToken::plain(0), run));
            break;
        }
    }
}

fn level_code_lengths(tokens: &[LevelToken]) -> [u8; LEVEL_COUNT] {
    let mut lengths = [0u8; LEVEL_COUNT];
    let mut used = [false; LEVEL_COUNT];
    for token in tokens {
        used[token.symbol] = true;
    }
    let used_count = used.iter().filter(|&&used| used).count();
    let len = huffman::bits_for_symbol_count(used_count);
    for (symbol, is_used) in used.into_iter().enumerate() {
        if is_used {
            lengths[symbol] = len;
        }
    }
    lengths
}

#[derive(Debug, Clone, Copy)]
struct HuffmanCode {
    code: u16,
    len: u8,
}

fn canonical_codes(lengths: &[u8]) -> Result<Vec<Option<HuffmanCode>>> {
    let mut count = [0u16; 16];
    for &len in lengths {
        if len > 15 {
            return Err(Error::InvalidData("RAR 2.9 Huffman length is too large"));
        }
        if len != 0 {
            count[len as usize] += 1;
        }
    }
    // Encoder side stays strict about oversubscription - we never emit a
    // table that claims more code space than exists. An incomplete one is
    // fine and normal here (a single used symbol gets a 1-bit code).
    if canonical_shape(&count) == CanonicalShape::Oversubscribed {
        return Err(Error::InvalidData("RAR 2.9 oversubscribed Huffman table"));
    }

    let mut next_code = [0u16; 16];
    let mut code = 0u16;
    for len in 1..=15 {
        code = (code + count[len - 1]) << 1;
        next_code[len] = code;
    }

    let mut codes = vec![None; lengths.len()];
    for (symbol, &len) in lengths.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let code = next_code[len as usize];
        next_code[len as usize] += 1;
        codes[symbol] = Some(HuffmanCode { code, len });
    }
    Ok(codes)
}

#[derive(Debug, Clone)]
pub struct Unpack29 {
    bits: BitReader,
    levels: [u8; TABLE_COUNT],
    main: Huffman,
    offsets: Huffman,
    low_offsets: Huffman,
    lengths: Huffman,
    old_offsets: [usize; 4],
    last_offset: usize,
    last_length: usize,
    last_low_offset: usize,
    low_offset_repeats: usize,
    pending_match: Option<(usize, usize)>,
    in_lz_block: bool,
    block_mode: BlockMode,
    ppmd: PpmdDecoder,
    ppmd_esc: u8,
    filters: Vec<VmFilter>,
    programs: Vec<VmProgram>,
    last_filter: usize,
    base_offset: usize,
    output: Vec<u8>,
    /// Refill the packed input from the reader as decoding proceeds
    /// (`decode_member_from_reader` only; the slice entry points own their
    /// whole input already and clear it).
    stream_refill: bool,
    /// The reader has answered 0 - nothing more can arrive, so a short
    /// buffer is a truncated member rather than a reason to pause.
    stream_eof: bool,
    /// A block selected PPMd, which is not streamable; the caller must
    /// absorb the rest of the reader before decoding continues.
    stream_needs_full: bool,
    /// Unread packed bytes the refill aims to hold. Must stay above
    /// `stream_margin`, or a refill could never clear the pause it just
    /// took; `set_stream_bounds` is the only thing that moves it and only
    /// tests call it.
    stream_window: usize,
    /// Packed bytes below which no decode excursion may start.
    stream_margin: usize,
}

/// See `Unpack29::state_digest`.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rar29State {
    current_pos: usize,
    consumed_bits: usize,
    in_lz_block: bool,
    block_mode: BlockMode,
    levels: u32,
    old_offsets: [usize; 4],
    last_offset: usize,
    last_length: usize,
    last_low_offset: usize,
    low_offset_repeats: usize,
    pending_match: Option<(usize, usize)>,
    last_filter: usize,
    filters: usize,
    programs: usize,
    history_len: usize,
    history: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockMode {
    Lz,
    Ppmd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LzBlockEnd {
    SameFileNewTable,
    NewFileKeepTables,
    NewFileNewTables,
}

#[derive(Debug, Clone)]
struct VmFilter {
    program: usize,
    start: usize,
    size: usize,
    regs: [u32; 7],
    global_data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct VmProgram {
    kind: VmProgramKind,
    block_size: usize,
    exec_count: u32,
    globals: Vec<u8>,
}

#[derive(Debug, Clone)]
enum VmProgramKind {
    Standard(StandardFilter),
    Generic(rarvm::Program),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandardFilter {
    E8,
    E8E9,
    Itanium,
    Delta,
    Rgb,
    Audio,
}

impl Unpack29 {
    pub fn new() -> Self {
        Self {
            bits: BitReader::new(),
            levels: [0; TABLE_COUNT],
            main: Huffman::empty(),
            offsets: Huffman::empty(),
            low_offsets: Huffman::empty(),
            lengths: Huffman::empty(),
            old_offsets: [0; 4],
            last_offset: 0,
            last_length: 0,
            last_low_offset: 0,
            low_offset_repeats: 0,
            pending_match: None,
            in_lz_block: false,
            block_mode: BlockMode::Lz,
            ppmd: PpmdDecoder::new(),
            ppmd_esc: 2,
            filters: Vec::new(),
            programs: Vec::new(),
            last_filter: 0,
            base_offset: 0,
            output: Vec::new(),
            stream_refill: false,
            stream_eof: false,
            stream_needs_full: false,
            stream_window: STREAM_INPUT_WINDOW,
            stream_margin: STREAM_INPUT_MARGIN,
        }
    }

    /// Shrink the refill window so a small member crosses it many times.
    ///
    /// Sound only when no excursion in the member under test can consume
    /// `margin` bytes - i.e. the member declares no VM filter, since
    /// `read_vm_code` alone can spend 64 KiB (see `STREAM_INPUT_MARGIN`).
    /// Every caller asserts `filters` stayed empty.
    #[cfg(test)]
    fn set_stream_bounds(&mut self, window: usize, margin: usize) {
        assert!(window > margin, "a refill must be able to clear the pause");
        self.stream_window = window;
        self.stream_margin = margin;
    }

    /// High-water mark of packed input retained for the member being
    /// decoded, in bytes. Reset by each `decode_member*` entry point that
    /// installs a fresh bit reader; the streaming bound is asserted
    /// against it.
    pub fn peak_packed_input(&self) -> usize {
        self.bits.peak_input
    }

    /// Everything a LATER member can read out of this decoder, reduced to
    /// a comparable value.
    ///
    /// Byte-identical output is not evidence on its own: a shared model
    /// can be wrong in a band nothing reads and every output byte still
    /// matches (the rar15 census recorded exactly that, 1.25 M steps on a
    /// wrong state with identical bytes). So this covers the carried
    /// state - the Huffman levels, the offset and length memory, the
    /// pending match, the filter and program tables, the block cursor -
    /// plus the retained history a solid successor matches against, and
    /// the absolute count of bits consumed off the packed stream.
    ///
    /// `base_offset` and `output.len()` are deliberately NOT in it: the
    /// buffered and streaming paths flush in different-sized spans, so
    /// `trim_history` fires at different moments and the retained length
    /// legitimately differs. The history is compared over its last
    /// `MAX_HISTORY` bytes instead, which is the part either path
    /// guarantees and the only part a successor can reach.
    #[cfg(test)]
    fn state_digest(&self) -> Rar29State {
        let retained = self.output.len().min(MAX_HISTORY);
        Rar29State {
            current_pos: self.current_pos(),
            consumed_bits: self.bits.absolute_position(),
            in_lz_block: self.in_lz_block,
            block_mode: self.block_mode,
            levels: crc32(&self.levels),
            old_offsets: self.old_offsets,
            last_offset: self.last_offset,
            last_length: self.last_length,
            last_low_offset: self.last_low_offset,
            low_offset_repeats: self.low_offset_repeats,
            pending_match: self.pending_match,
            last_filter: self.last_filter,
            filters: self.filters.len(),
            programs: self.programs.len(),
            history_len: retained,
            history: crc32(&self.output[self.output.len() - retained..]),
        }
    }

    pub fn reset_non_solid(&mut self) {
        *self = Self::new();
    }

    pub fn decode_non_solid_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        self.reset_non_solid();
        self.decode_member(input, output_size)
    }

    pub fn decode_non_solid_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.reset_non_solid();
        self.decode_member_to(input, output_size, out)
    }

    pub fn decode_non_solid_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.reset_non_solid();
        self.decode_member_from_reader(input, output_size, out)
    }

    pub fn decode_member(&mut self, input: &[u8], output_size: usize) -> Result<Vec<u8>> {
        self.stream_refill = false;
        let start = self.current_pos();
        let target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.9 output size overflows"))?;
        if !input.is_empty() {
            self.bits = BitReader::new();
        }
        self.bits.append(input);
        self.decode_until(target).map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 2.9 bitstream is truncated"),
            error => error,
        })?;
        self.finish_member().map_err(|error| match error {
            Error::NeedMoreInput => Error::InvalidData("RAR 2.9 bitstream is truncated"),
            error => error,
        })?;
        let out = self.filtered_range(start, target, start)?;
        self.trim_history(target, target);
        Ok(out)
    }

    pub fn decode_member_to(
        &mut self,
        input: &[u8],
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.stream_refill = false;
        let start = self.current_pos();
        let final_target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.9 output size overflows"))?;
        if !input.is_empty() {
            self.bits = BitReader::new();
        }
        self.bits.append(input);

        let mut flushed = start;
        let mut target = start.saturating_add(STREAM_CHUNK).min(final_target);
        while flushed < final_target {
            self.decode_until(target)?;
            let safe_end = self.safe_flush_end(flushed, target, final_target)?;
            if safe_end <= flushed {
                if target == final_target {
                    return Err(Error::InvalidData(
                        "RAR 2.9 VM filter extends beyond output",
                    ));
                }
                target = self
                    .current_pos()
                    .saturating_add(STREAM_CHUNK)
                    .min(final_target);
                continue;
            }

            if self.range_has_filters(flushed, safe_end) {
                let decoded = self.filtered_range(flushed, safe_end, start)?;
                out.write_all(&decoded)
                    .map_err(|_| Error::InvalidData("RAR 2.9 output write failed"))?;
            } else {
                // Common case: no VM filter in this span — write straight
                // from the retained window, no per-chunk buffer.
                out.write_all(self.raw_range(flushed, safe_end)?)
                    .map_err(|_| Error::InvalidData("RAR 2.9 output write failed"))?;
            }
            flushed = safe_end;
            self.trim_history(flushed, self.current_pos());
            target = self
                .current_pos()
                .saturating_add(STREAM_CHUNK)
                .min(final_target);
        }
        self.finish_member()?;
        Ok(())
    }

    pub fn decode_member_from_reader(
        &mut self,
        input: &mut impl Read,
        output_size: usize,
        out: &mut impl Write,
    ) -> Result<()> {
        self.bits = BitReader::new();
        self.stream_refill = true;
        self.stream_eof = false;
        self.stream_needs_full = false;
        let start = self.current_pos();
        let final_target = start
            .checked_add(output_size)
            .ok_or(Error::InvalidData("RAR 2.9 output size overflows"))?;
        let mut flushed = start;
        let mut target = start.saturating_add(STREAM_CHUNK).min(final_target);
        // Fill the window rather than the member: see STREAM_INPUT_WINDOW.
        // The reader is still drained to EOF by `stream_finish` below, so
        // callers that read the decoder's position out of a chained reader
        // (the chase's consumption watermark) see what they always saw.
        let primed = self.stream_fill(input)?;
        // Empty members in solid mode still carry their own block init bytes
        // (typically the (esc, 0) end-of-block marker + 4-byte range coder
        // flush). When output_size is zero, decode_until skips its loop body
        // and never reads tables, so do the init here so finish_member can
        // observe the block end.
        if final_target == start && !self.in_lz_block && primed != 0 {
            self.read_tables().map_err(|error| match error {
                Error::NeedMoreInput => Error::InvalidData("RAR 2.9 bitstream is truncated"),
                error => error,
            })?;
            self.in_lz_block = true;
        }

        while flushed < final_target {
            self.stream_fill(input)?;
            self.decode_until(target).map_err(|error| match error {
                Error::NeedMoreInput => Error::InvalidData("RAR 2.9 bitstream is truncated"),
                error => error,
            })?;
            if self.stream_needs_full {
                // A PPMd block: absorb the rest and decode it buffered.
                self.stream_absorb_rest(input)?;
                continue;
            }

            // `decode_until` may stop short of `target` when the window ran
            // low, so flush against what was actually decoded - never
            // against the goal.
            let decoded = self.current_pos().min(target);
            let stalled_on_input = decoded < target && self.stream_refill && !self.stream_eof;
            if decoded > flushed {
                let safe_end = self.safe_flush_end(flushed, decoded, final_target)?;
                if safe_end > flushed {
                    if self.range_has_filters(flushed, safe_end) {
                        let filtered = self.filtered_range(flushed, safe_end, start)?;
                        out.write_all(&filtered)
                            .map_err(|_| Error::InvalidData("RAR 2.9 output write failed"))?;
                    } else {
                        // Common case: no VM filter in this span — write
                        // straight from the retained window, no per-chunk
                        // buffer.
                        out.write_all(self.raw_range(flushed, safe_end)?)
                            .map_err(|_| Error::InvalidData("RAR 2.9 output write failed"))?;
                    }
                    flushed = safe_end;
                    self.trim_history(flushed, self.current_pos());
                    target = self
                        .current_pos()
                        .saturating_add(STREAM_CHUNK)
                        .min(final_target);
                    continue;
                }
            }

            if stalled_on_input {
                // Nothing flushable yet and more input can still arrive:
                // top the window up and decode on. Each turn either reads a
                // byte or sets `stream_eof`, so this cannot spin.
                continue;
            }
            if target == final_target {
                return Err(Error::InvalidData(
                    "RAR 2.9 VM filter extends beyond output",
                ));
            }
            target = self
                .current_pos()
                .saturating_add(STREAM_CHUNK)
                .min(final_target);
        }
        self.stream_finish(input)?;
        self.finish_member()?;
        self.stream_refill = false;
        Ok(())
    }

    /// Top the packed-input window back up to `STREAM_INPUT_WINDOW`
    /// unread bytes. Returns the bytes read this call.
    fn stream_fill(&mut self, input: &mut impl Read) -> Result<usize> {
        if !self.stream_refill || self.stream_eof {
            return Ok(0);
        }
        if self.bits.available_bits() >= self.stream_window * 8 {
            return Ok(0);
        }
        let (read, eof) = self
            .bits
            .fill_from_reader(input, self.stream_window)
            .map_err(|_| Error::InvalidData("RAR 2.9 input read failed"))?;
        if eof {
            self.stream_eof = true;
        }
        Ok(read)
    }

    /// Absorb everything the reader still holds and stop streaming. Used
    /// for the two shapes the window cannot serve: a PPMd block, and the
    /// member tail `finish_member` walks (which `remaining_bits_are_zero`
    /// reads whole). For a well-formed member the tail is a handful of
    /// padding bytes; for a crafted one it is the packed size, which is
    /// exactly what this path cost before.
    fn stream_absorb_rest(&mut self, input: &mut impl Read) -> Result<()> {
        self.bits
            .append_from_reader(input)
            .map_err(|_| Error::InvalidData("RAR 2.9 input read failed"))?;
        self.stream_refill = false;
        self.stream_eof = true;
        self.stream_needs_full = false;
        Ok(())
    }

    fn stream_finish(&mut self, input: &mut impl Read) -> Result<()> {
        if !self.stream_refill || self.stream_eof {
            return Ok(());
        }
        self.stream_absorb_rest(input)
    }

    /// True while a decode excursion could outrun the buffer: streaming,
    /// more input can still arrive, and less than the margin is held.
    fn stream_low(&self) -> bool {
        self.stream_refill
            && !self.stream_eof
            && self.bits.available_bits() < self.stream_margin * 8
    }

    fn decode_until(&mut self, target: usize) -> Result<()> {
        while self.current_pos() < target {
            // Never begin an excursion the window cannot cover; the caller
            // refills and comes straight back. Placed at the loop top so a
            // pause returned by `decode_lz` leaves here too rather than
            // re-entering it on the same empty buffer.
            if self.stream_low() {
                return Ok(());
            }
            self.drain_pending_match(target)?;
            if self.current_pos() >= target {
                break;
            }
            if !self.in_lz_block {
                self.read_tables()?;
                self.in_lz_block = true;
            }
            match self.block_mode {
                BlockMode::Lz => self.decode_lz(target)?,
                BlockMode::Ppmd => {
                    // Not streamable - see STREAM_INPUT_MARGIN. The test is
                    // here rather than after `read_tables` because a solid
                    // member can OPEN inside a PPMd block the previous one
                    // started.
                    if self.stream_refill {
                        self.stream_needs_full = true;
                        return Ok(());
                    }
                    self.decode_ppmd(target)?
                }
            }
        }
        Ok(())
    }

    fn read_tables(&mut self) -> Result<()> {
        self.bits.align_byte();
        if self.bits.peek_bit()? != 0 {
            let first_byte = self.bits.read_bits(8)? as u8;
            self.ppmd
                .decode_init(first_byte, &mut self.bits, &mut self.ppmd_esc)?;
            self.block_mode = BlockMode::Ppmd;
            return Ok(());
        }
        self.bits.read_bit()?;
        self.block_mode = BlockMode::Lz;
        let keep_tables = self.bits.read_bit()? != 0;
        self.last_low_offset = 0;
        self.low_offset_repeats = 0;
        if !keep_tables {
            self.levels = [0; TABLE_COUNT];
        }

        let level_lengths = Self::read_level_lengths(&mut self.bits)?;
        let level_decoder = Huffman::from_lengths(&level_lengths)?;
        let mut new_levels = [0u8; TABLE_COUNT];
        let mut pos = 0usize;
        while pos < TABLE_COUNT {
            let symbol = level_decoder.decode(&mut self.bits)?;
            match symbol {
                0..=15 => {
                    new_levels[pos] = (self.levels[pos].wrapping_add(symbol as u8)) & 0x0f;
                    pos += 1;
                }
                16 => {
                    if pos == 0 {
                        return Err(Error::InvalidData("RAR 2.9 table repeat at start"));
                    }
                    let count = 3 + self.bits.read_bits(3)? as usize;
                    let value = new_levels[pos - 1];
                    fill_levels(&mut new_levels, &mut pos, count, value)?;
                }
                17 => {
                    if pos == 0 {
                        return Err(Error::InvalidData("RAR 2.9 long table repeat at start"));
                    }
                    let count = 11 + self.bits.read_bits(7)? as usize;
                    let value = new_levels[pos - 1];
                    fill_levels(&mut new_levels, &mut pos, count, value)?;
                }
                18 => {
                    let count = 3 + self.bits.read_bits(3)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
                19 => {
                    let count = 11 + self.bits.read_bits(7)? as usize;
                    fill_levels(&mut new_levels, &mut pos, count, 0)?;
                }
                _ => return Err(Error::InvalidData("RAR 2.9 invalid level symbol")),
            }
        }

        self.levels = new_levels;
        self.main = Huffman::from_lengths(&self.levels[..MAIN_COUNT])?;
        self.offsets = Huffman::from_lengths(&self.levels[MAIN_COUNT..MAIN_COUNT + OFFSET_COUNT])?;
        self.low_offsets = Huffman::from_lengths(
            &self.levels[MAIN_COUNT + OFFSET_COUNT..MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT],
        )?;
        self.lengths =
            Huffman::from_lengths(&self.levels[MAIN_COUNT + OFFSET_COUNT + LOW_OFFSET_COUNT..])?;
        Ok(())
    }

    fn read_level_lengths(bits: &mut BitReader) -> Result<[u8; LEVEL_COUNT]> {
        let mut lengths = [0u8; LEVEL_COUNT];
        let mut pos = 0usize;
        while pos < LEVEL_COUNT {
            let value = bits.read_bits(4)? as u8;
            if value == 15 {
                let zero_count = bits.read_bits(4)? as usize;
                if zero_count == 0 {
                    lengths[pos] = 15;
                    pos += 1;
                } else {
                    pos = pos.saturating_add(zero_count + 2).min(LEVEL_COUNT);
                }
            } else {
                lengths[pos] = value;
                pos += 1;
            }
        }
        Ok(lengths)
    }

    fn decode_lz(&mut self, output_size: usize) -> Result<()> {
        while self.current_pos() < output_size {
            // Literal burst on the LUT fast path: literals dominate most
            // streams, and the generic `decode()` pays its empty-table and
            // fallback checks per symbol. Mirrors the RAR 5 burst loops;
            // LUT misses (long codes) and the sub-15-bit tail fall through
            // to the generic path below, which handles them identically.
            // An `empty()` table has no LUT at all - the generic path owns
            // that error.
            while !self.main.lut.is_empty() && self.current_pos() < output_size {
                let Ok(peek) = self.bits.peek_bits(15) else {
                    break;
                };
                let entry = self.main.lut[(peek >> (15 - HUFF29_LUT_BITS)) as usize];
                if entry == 0 || (entry >> 8) > 255 {
                    break;
                }
                self.bits.consume((entry & 0xff) as u8);
                self.output.push((entry >> 8) as u8);
            }
            if self.current_pos() >= output_size {
                break;
            }
            // The burst above stops on a failed peek, which consumes
            // nothing, so it may leave the window all but empty. This is
            // the boundary that matters: everything below can consume up to
            // `read_vm_code`'s 64 KiB and has no way back.
            if self.stream_low() {
                return Ok(());
            }
            let symbol = self.main.decode(&mut self.bits)?;
            match symbol {
                0..=255 => self.output.push(symbol as u8),
                256 => {
                    self.read_end_of_block()?;
                    return Ok(());
                }
                257 => {
                    self.read_vm_code()?;
                }
                258 => {
                    if self.last_length != 0 {
                        self.copy_match(self.last_length, self.last_offset, output_size)?;
                    }
                }
                259..=262 => {
                    let index = symbol - 259;
                    let offset = self.old_offsets[index];
                    let length_slot = self.lengths.decode(&mut self.bits)?;
                    if length_slot >= LENGTH_COUNT {
                        return Err(Error::InvalidData("RAR 2.9 invalid repeat length slot"));
                    }
                    let mut length = LENGTH_BASES[length_slot] + 2;
                    if LENGTH_BITS[length_slot] != 0 {
                        length += self.bits.read_bits(LENGTH_BITS[length_slot])? as usize;
                    }
                    self.rotate_old_offset(index);
                    self.last_offset = offset;
                    self.last_length = length;
                    self.copy_match(length, offset, output_size)?;
                }
                263..=270 => {
                    let index = symbol - 263;
                    let mut offset = SHORT_BASES[index] + 1;
                    if SHORT_BITS[index] != 0 {
                        offset += self.bits.read_bits(SHORT_BITS[index])? as usize;
                    }
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.last_length = 2;
                    self.copy_match(2, offset, output_size)?;
                }
                271..=298 => {
                    let length_slot = symbol - 271;
                    let mut length = LENGTH_BASES[length_slot] + 3;
                    if LENGTH_BITS[length_slot] != 0 {
                        length += self.bits.read_bits(LENGTH_BITS[length_slot])? as usize;
                    }
                    let offset = self.read_offset()?;
                    if offset >= 0x2000 {
                        length += 1;
                    }
                    if offset >= 0x40000 {
                        length += 1;
                    }
                    self.push_old_offset(offset);
                    self.last_offset = offset;
                    self.last_length = length;
                    self.copy_match(length, offset, output_size)?;
                }
                _ => return Err(Error::InvalidData("RAR 2.9 invalid main symbol")),
            }
        }
        Ok(())
    }

    fn decode_ppmd(&mut self, output_size: usize) -> Result<()> {
        while self.current_pos() < output_size {
            let Some(symbol) = self.ppmd.decode_symbol(&mut self.bits)? else {
                return Ok(());
            };
            if symbol != self.ppmd_esc {
                self.output.push(symbol);
                continue;
            }

            let Some(next) = self.ppmd.decode_symbol(&mut self.bits)? else {
                return Ok(());
            };
            match next {
                0 => {
                    self.in_lz_block = false;
                    return Ok(());
                }
                1 | 6..=u8::MAX => self.output.push(self.ppmd_esc),
                2 => {
                    self.in_lz_block = false;
                    return Ok(());
                }
                3 => {
                    self.read_vm_code_ppmd()?;
                }
                4 => {
                    let mut offset = 0usize;
                    for _ in 0..3 {
                        offset = (offset << 8) | self.read_ppmd_required_byte()? as usize;
                    }
                    offset += 2;
                    let length = self.read_ppmd_required_byte()? as usize + 32;
                    self.copy_match(length, offset, output_size)?;
                }
                5 => {
                    let length = self.read_ppmd_required_byte()? as usize + 4;
                    self.copy_match(length, 1, output_size)?;
                }
            }
        }
        Ok(())
    }

    fn read_ppmd_required_byte(&mut self) -> Result<u8> {
        self.ppmd
            .decode_symbol(&mut self.bits)?
            .ok_or(Error::InvalidData("RAR 2.9 PPMd stream ended early"))
    }

    fn finish_ppmd_member(&mut self) -> Result<()> {
        if self.block_mode != BlockMode::Ppmd {
            return Ok(());
        }
        let Some(symbol) = self.ppmd.decode_symbol(&mut self.bits)? else {
            return Ok(());
        };
        if symbol != self.ppmd_esc {
            return Err(Error::InvalidData("RAR 2.9 PPMd member has trailing data"));
        }
        let Some(next) = self.ppmd.decode_symbol(&mut self.bits)? else {
            return Ok(());
        };
        match next {
            2 => {
                self.in_lz_block = false;
                Ok(())
            }
            0 => {
                self.in_lz_block = false;
                Ok(())
            }
            _ => Err(Error::InvalidData("RAR 2.9 PPMd member has trailing data")),
        }
    }

    fn finish_member(&mut self) -> Result<()> {
        match self.block_mode {
            BlockMode::Lz => self.finish_lz_member(),
            BlockMode::Ppmd => self.finish_ppmd_member(),
        }
    }

    fn finish_lz_member(&mut self) -> Result<()> {
        loop {
            if !self.in_lz_block {
                return Ok(());
            }
            let symbol = self.main.decode(&mut self.bits)?;
            if symbol != 256 {
                return Err(Error::InvalidData("RAR 2.9 LZ member has trailing data"));
            }
            match self.read_end_of_block()? {
                LzBlockEnd::SameFileNewTable => {
                    if self.bits.remaining_bits_are_zero() {
                        return Ok(());
                    }
                    if let Err(error) = self.read_tables() {
                        if error == Error::NeedMoreInput {
                            return Ok(());
                        }
                        return Err(error);
                    }
                    self.in_lz_block = true;
                }
                LzBlockEnd::NewFileKeepTables | LzBlockEnd::NewFileNewTables => return Ok(()),
            }
        }
    }

    fn read_end_of_block(&mut self) -> Result<LzBlockEnd> {
        if self.bits.read_bit()? != 0 {
            self.in_lz_block = false;
            return Ok(LzBlockEnd::SameFileNewTable);
        }
        if self.bits.read_bit()? != 0 {
            self.in_lz_block = false;
            Ok(LzBlockEnd::NewFileNewTables)
        } else {
            self.in_lz_block = true;
            Ok(LzBlockEnd::NewFileKeepTables)
        }
    }

    fn read_offset(&mut self) -> Result<usize> {
        let slot = self.offsets.decode(&mut self.bits)?;
        if slot >= OFFSET_COUNT {
            return Err(Error::InvalidData("RAR 2.9 invalid offset slot"));
        }
        let mut offset = OFFSET_BASES[slot] + 1;
        let extra_bits = OFFSET_BITS[slot];
        if extra_bits != 0 {
            if slot > 9 {
                if extra_bits > 4 {
                    offset += (self.bits.read_bits(extra_bits - 4)? as usize) << 4;
                }
                if self.low_offset_repeats > 0 {
                    self.low_offset_repeats -= 1;
                    offset += self.last_low_offset;
                } else {
                    let low = self.low_offsets.decode(&mut self.bits)?;
                    if low == 16 {
                        self.low_offset_repeats = 15;
                        offset += self.last_low_offset;
                    } else if low < 16 {
                        self.last_low_offset = low;
                        offset += low;
                    } else {
                        return Err(Error::InvalidData("RAR 2.9 invalid low offset symbol"));
                    }
                }
            } else {
                offset += self.bits.read_bits(extra_bits)? as usize;
            }
        }
        Ok(offset)
    }

    fn read_vm_code(&mut self) -> Result<()> {
        let first_byte = self.bits.read_bits(8)?;
        let mut len = (first_byte & 7) + 1;
        if len == 7 {
            len = self.bits.read_bits(8)? + 7;
        } else if len == 8 {
            len = self.bits.read_bits(16)?;
        }
        let mut data = Vec::with_capacity(len as usize);
        for _ in 0..len {
            data.push(self.bits.read_bits(8)? as u8);
        }

        self.parse_vm_code(first_byte, data)
    }

    fn read_vm_code_ppmd(&mut self) -> Result<()> {
        let first_byte = u32::from(self.read_ppmd_required_byte()?);
        let mut len = (first_byte & 7) + 1;
        if len == 7 {
            len = u32::from(self.read_ppmd_required_byte()?) + 7;
        } else if len == 8 {
            len = (u32::from(self.read_ppmd_required_byte()?) << 8)
                | u32::from(self.read_ppmd_required_byte()?);
        }
        let mut data = Vec::with_capacity(len as usize);
        for _ in 0..len {
            data.push(self.read_ppmd_required_byte()?);
        }

        self.parse_vm_code(first_byte, data)
    }

    fn parse_vm_code(&mut self, first_byte: u32, data: Vec<u8>) -> Result<()> {
        let mut vm = BitReader::from_bytes(&data);
        let program_index = if first_byte & 0x80 != 0 {
            let value = vm.read_encoded_u32()?;
            if value == 0 {
                self.filters.clear();
                self.programs.clear();
                0
            } else {
                usize::try_from(value - 1)
                    .map_err(|_| Error::InvalidData("RAR 2.9 VM program index overflows"))?
            }
        } else {
            self.last_filter
        };
        if program_index > self.programs.len() {
            return Err(Error::InvalidData("RAR 2.9 VM program index is invalid"));
        }
        self.last_filter = program_index;
        let new_program = program_index == self.programs.len();

        let mut block_start = vm.read_encoded_u32()? as usize;
        if first_byte & 0x40 != 0 {
            block_start += 258;
        }
        block_start = self
            .current_pos()
            .checked_add(block_start)
            .ok_or(Error::InvalidData("RAR 2.9 VM block start overflows"))?;

        let mut block_size = self
            .programs
            .get(program_index)
            .map(|program| program.block_size)
            .unwrap_or(0);
        if first_byte & 0x20 != 0 {
            block_size = vm.read_encoded_u32()? as usize;
        }
        // nzbfast: refuse the declaration itself - see MAX_VM_FILTER_HOLD.
        // Checked here rather than at use, because the block is held from
        // the moment the filter is RECORDED, and a reuse of a stored
        // program (the `else` arm below) re-declares it just as freely.
        if block_size > MAX_VM_FILTER_HOLD {
            return Err(Error::InvalidData(
                "RAR 2.9 VM filter block is too large to hold",
            ));
        }

        let mut regs = [0u32; 7];
        regs[3] = 0x3c000;
        regs[4] = block_size as u32;
        if let Some(program) = self.programs.get(program_index) {
            regs[5] = program.exec_count;
        }
        if first_byte & 0x10 != 0 {
            let mask = vm.read_bits(7)?;
            for (index, reg) in regs.iter_mut().enumerate() {
                if mask & (1 << index) != 0 {
                    *reg = vm.read_encoded_u32()?;
                }
            }
        }

        if new_program {
            if self.programs.len() >= MAX_VM_PROGRAMS {
                return Err(Error::InvalidData("RAR 2.9 VM program limit exceeded"));
            }
            let code_size = vm.read_encoded_u32()? as usize;
            if code_size == 0 {
                return Err(Error::InvalidData("RAR 2.9 VM code is empty"));
            }
            if code_size > MAX_VM_CODE_SIZE {
                return Err(Error::InvalidData("RAR 2.9 VM code is too large"));
            }
            let mut code = Vec::with_capacity(code_size);
            for _ in 0..code_size {
                code.push(vm.read_bits(8)? as u8);
            }
            let kind = identify_standard_filter(&code)
                .map(VmProgramKind::Standard)
                .map_or_else(
                    || rarvm::Program::parse(&code).map(VmProgramKind::Generic),
                    Ok,
                )?;
            self.programs.push(VmProgram {
                kind,
                block_size,
                exec_count: 0,
                globals: Vec::new(),
            });
        } else if let Some(program) = self.programs.get_mut(program_index) {
            program.exec_count = program.exec_count.wrapping_add(1);
            program.block_size = block_size;
        }

        let mut global_data = Vec::new();
        if first_byte & 0x08 != 0 {
            let data_size = vm.read_encoded_u32()? as usize;
            global_data.reserve(data_size.min(MAX_VM_GLOBAL_DATA));
            for _ in 0..data_size {
                let byte = vm.read_bits(8)? as u8;
                if global_data.len() < MAX_VM_GLOBAL_DATA {
                    global_data.push(byte);
                }
            }
        }

        if self.filters.len() >= MAX_VM_FILTERS {
            return Err(Error::InvalidData("RAR 2.9 VM filter limit exceeded"));
        }
        self.filters.push(VmFilter {
            program: program_index,
            start: block_start,
            size: block_size,
            regs,
            global_data,
        });
        Ok(())
    }

    /// Does any complete VM filter block lie inside `[start, end)`? Mirrors
    /// the selection rule in `filtered_range`.
    fn range_has_filters(&self, start: usize, end: usize) -> bool {
        self.filters
            .iter()
            // nzbfast: `saturating_add`, as in `filtered_range` and
            // `trim_history`. `block_start` is `current_pos()` plus a
            // wire u32 and `block_size` is a wire u32, so on a 32-bit
            // target the sum overflows - and the BUFFERED decode path
            // reaches here without the checked `safe_flush_end` that
            // covers the streaming one. Saturating is also the right
            // answer: a filter whose end runs past the address space
            // cannot be inside any range, which is what `<= end` then
            // says.
            .any(|filter| filter.start >= start && filter.start.saturating_add(filter.size) <= end)
    }

    fn filtered_range(&mut self, start: usize, end: usize, member_start: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(end - start);
        let mut pos = start;
        let filters: Vec<_> = self
            .filters
            .iter()
            .enumerate()
            .filter_map(|(index, filter)| {
                // Saturating for the reason at `range_has_filters`.
                (filter.start >= start && filter.start.saturating_add(filter.size) <= end)
                    .then_some(index)
            })
            .collect();
        for filter_index in filters {
            let (program_index, filter_start, filter_size, regs, global_data) = {
                let filter = self
                    .filters
                    .get(filter_index)
                    .ok_or(Error::InvalidData("RAR 2.9 VM filter is missing"))?;
                (
                    filter.program,
                    filter.start,
                    filter.size,
                    filter.regs,
                    filter.global_data.clone(),
                )
            };
            if filter_start < pos {
                continue;
            }
            out.extend_from_slice(self.raw_range(pos, filter_start)?);
            let mut block = self
                .raw_range(filter_start, filter_start.saturating_add(filter_size))?
                .to_vec();
            let file_offset = filter_start
                .checked_sub(member_start)
                .ok_or(Error::InvalidData("RAR 2.9 VM filter starts before file"))?
                as u32;
            let program = self
                .programs
                .get_mut(program_index)
                .ok_or(Error::InvalidData("RAR 2.9 VM program is missing"))?;
            match &program.kind {
                VmProgramKind::Standard(standard) => {
                    apply_standard_filter(*standard, &mut block, file_offset, &regs)?
                }
                VmProgramKind::Generic(generic) => {
                    let globals = if global_data.is_empty() {
                        program.globals.as_slice()
                    } else {
                        global_data.as_slice()
                    };
                    let result = generic.execute(rarvm::Invocation {
                        input: &block,
                        regs,
                        global_data: globals,
                        file_offset: file_offset as u64,
                        exec_count: program.exec_count,
                    })?;
                    program.globals = result.globals;
                    block = result.output;
                }
            }
            out.extend_from_slice(&block);
            pos = filter_start.saturating_add(filter_size);
        }
        out.extend_from_slice(self.raw_range(pos, end)?);
        Ok(out)
    }

    fn safe_flush_end(&self, start: usize, end: usize, final_target: usize) -> Result<usize> {
        let current = self.current_pos();
        let mut safe_end = end;
        for filter in &self.filters {
            let filter_end = filter
                .start
                .checked_add(filter.size)
                .ok_or(Error::InvalidData("RAR 2.9 VM filter size overflows"))?;
            if filter.start >= safe_end || filter_end <= start {
                continue;
            }
            if filter_end > final_target {
                return Err(Error::InvalidData(
                    "RAR 2.9 VM filter extends beyond output",
                ));
            }
            if filter_end > current {
                safe_end = safe_end.min(filter.start);
            }
        }
        Ok(safe_end)
    }

    fn copy_match(&mut self, length: usize, offset: usize, output_size: usize) -> Result<()> {
        // The bitstream normally encodes match distances as offset+1, so zero
        // is not emitted for fresh matches. Keep the legacy decoder boundary
        // tolerant here: a zero internal offset behaves as distance one.
        let offset = if offset == 0 { 1 } else { offset };
        let current = self.current_pos();
        if offset > current || offset > self.output.len() {
            return Err(Error::InvalidData("RAR 2.9 match distance is out of range"));
        }
        let copy_len = length.min(output_size.saturating_sub(current));
        if copy_len < length {
            self.pending_match = Some((length - copy_len, offset));
        }
        if offset == 1 {
            let byte = *self
                .output
                .last()
                .ok_or(Error::InvalidData("RAR 2.9 match distance is out of range"))?;
            self.output.resize(self.output.len() + copy_len, byte);
            return Ok(());
        }

        // Short matches are most matches, and `extend_from_within` pays a
        // memmove libcall and a capacity check per call for a few bytes of
        // copy. At a distance of at least 16 every 16-byte stride reads bytes
        // that are already final, so the window grows by a fixed 80 bytes (a
        // constant-size store the compiler inlines), the match is copied in
        // 16-byte strides, and the slack past it is dropped - the shape of
        // rar50's `flat_stride_copy`. (nzbfast-local change, 14 Sep 2026;
        // see VENDORING.md.)
        if copy_len <= 64 && offset >= 16 {
            let start = self.output.len();
            self.output.extend_from_slice(&[0u8; 80]);
            let mut done = 0;
            while done < copy_len {
                let src = start + done - offset;
                self.output.copy_within(src..src + 16, start + done);
                done += 16;
            }
            self.output.truncate(start + copy_len);
            return Ok(());
        }

        // A short-period overlap is periodic. After copying one complete
        // period, the usable periodic span has doubled, so grow the source run
        // geometrically instead of issuing one tiny extend per original
        // distance. Long periods already copy cache-line-sized runs and keep
        // the simple path below.
        const PERIOD_DOUBLE_CEILING: usize = 4096;
        if copy_len > offset && offset <= PERIOD_DOUBLE_CEILING {
            let mut remaining = copy_len;
            let mut period = offset;
            while remaining > 0 {
                let run = remaining.min(period);
                let src_start = self.output.len() - period;
                self.output.extend_from_within(src_start..src_start + run);
                remaining -= run;
                if run == period && period * 2 <= PERIOD_DOUBLE_CEILING {
                    period *= 2;
                }
            }
            return Ok(());
        }

        // Chunked self-referential copy: runs capped at the match offset
        // reproduce the byte-loop's overlap periodicity.
        let mut remaining = copy_len;
        while remaining > 0 {
            let src_start = self.output.len() - offset;
            let run = remaining.min(offset);
            self.output.extend_from_within(src_start..src_start + run);
            remaining -= run;
        }
        Ok(())
    }

    fn drain_pending_match(&mut self, output_size: usize) -> Result<()> {
        let Some((length, offset)) = self.pending_match.take() else {
            return Ok(());
        };
        self.copy_match(length, offset, output_size)
    }

    fn push_old_offset(&mut self, offset: usize) {
        self.old_offsets[3] = self.old_offsets[2];
        self.old_offsets[2] = self.old_offsets[1];
        self.old_offsets[1] = self.old_offsets[0];
        self.old_offsets[0] = offset;
    }

    fn rotate_old_offset(&mut self, index: usize) {
        let value = self.old_offsets[index];
        for i in (1..=index).rev() {
            self.old_offsets[i] = self.old_offsets[i - 1];
        }
        self.old_offsets[0] = value;
    }

    fn current_pos(&self) -> usize {
        self.base_offset + self.output.len()
    }

    fn raw_range(&self, start: usize, end: usize) -> Result<&[u8]> {
        if start < self.base_offset || end < start {
            return Err(Error::InvalidData(
                "RAR 2.9 retained history is unavailable",
            ));
        }
        let rel_start = start - self.base_offset;
        let rel_end = end - self.base_offset;
        self.output
            .get(rel_start..rel_end)
            .ok_or(Error::InvalidData(
                "RAR 2.9 retained history is unavailable",
            ))
    }

    fn trim_history(&mut self, flushed_pos: usize, current_pos: usize) {
        let keep_from = current_pos.saturating_sub(MAX_HISTORY);
        let keep_from = keep_from.min(flushed_pos);
        if keep_from <= self.base_offset {
            return;
        }
        let drain = keep_from - self.base_offset;
        // Hysteresis: draining memmoves the whole retained window, so let
        // trimmable data accumulate instead of paying that per chunk. Memory
        // stays bounded at MAX_HISTORY + this slack (drain cost amortizes to
        // MAX_HISTORY bytes moved per 2*MAX_HISTORY decoded).
        if drain < 2 * MAX_HISTORY {
            return;
        }
        self.output.drain(..drain);
        self.base_offset = keep_from;
        self.filters
            // Saturating for the reason at `range_has_filters`; a
            // filter whose end overflows is certainly past the base.
            .retain(|filter| filter.start.saturating_add(filter.size) > self.base_offset);
    }
}

impl Default for Unpack29 {
    fn default() -> Self {
        Self::new()
    }
}

fn fill_levels(levels: &mut [u8], pos: &mut usize, count: usize, value: u8) -> Result<()> {
    let end = pos
        .checked_add(count)
        .ok_or(Error::InvalidData("RAR 2.9 table run overflows"))?;
    let end = end.min(levels.len());
    for item in &mut levels[*pos..end] {
        *item = value;
    }
    *pos = end;
    Ok(())
}

#[derive(Debug, Clone)]
struct Huffman {
    symbols: Vec<HuffmanSymbol>,
    first_code: [u16; 16],
    first_index: [usize; 16],
    counts: [u16; 16],
    // Primary decode LUT: top HUFF29_LUT_BITS of the stream -> packed
    // (symbol << 8) | code_len; 0 means longer-than-LUT or invalid.
    lut: Vec<u32>,
    // Present whenever the strict canonical form is not COMPLETE, which
    // is exactly when unrar's own table answers a field this one cannot.
    // Two ways in. Oversubscribed or all-zero length tables (old WinRAR
    // 2.x encoders really emitted the first; the second is what a
    // damaged stream degenerates into) have no strict form at all, so
    // `symbols` and `lut` stay empty and the twin owns the whole code
    // space - which also keeps the burst fast paths, gated on a
    // non-empty LUT, off those tables. An UNDERsubscribed table does
    // have a strict form and keeps it, LUT and all, because it decodes
    // its reachable codes exactly like unrar; only the hole (fields no
    // canonical code covers) is answered from the twin. That split
    // matters: incomplete tables are common in real archives - the
    // small length/offset alphabets routinely carry a single 1-bit code
    // - and routing them all through the twin would cost the LUT for
    // shapes that never decode a byte differently.
    tolerant: Option<Box<TolerantHuffman>>,
}

/// Bit-exact port of unrar's MakeDecodeTables/DecodeNumber pair, which
/// never validates subscription at all - it builds a decode table from
/// whatever lengths it is handed. Oversubscribed: the left-aligned upper
/// limits are 32-bit, so an oversubscribed length saturates past 0xffff
/// and every wider code becomes unreachable (truncation, not an error).
/// Undersubscribed: the limits stop below 0xffff, so fields above the
/// last one fall out of the length search at 15 bits, and the position
/// they compute lands in the zero-filled tail of the alphabet list.
/// All-zero: every limit is 0, so every field resolves the same way, to
/// alphabet entry 0 with 15 bits consumed. Out-of-range positions clamp
/// to slot 0 throughout, as upstream does for damaged archives. Built
/// whenever the strict canonical form is not complete; the member CRC
/// still gates the output, so genuinely corrupt streams keep failing.
#[derive(Debug, Clone)]
struct TolerantHuffman {
    // decode_len[len]: left-aligned (16-bit field space) upper limit for
    // codes of `len` bits, cumulative, monotone; [0] = 0.
    decode_len: [u32; 16],
    // decode_pos[len]: first index in `decode_num` for codes of `len` bits.
    decode_pos: [usize; 16],
    // Alphabet numbers ordered by (code length, appearance order).
    decode_num: Vec<u16>,
}

const HUFF29_LUT_BITS: usize = 12;

#[derive(Debug, Clone)]
struct HuffmanSymbol {
    code: u16,
    len: u8,
    symbol: usize,
}

impl Huffman {
    fn empty() -> Self {
        Self {
            symbols: Vec::new(),
            first_code: [0; 16],
            first_index: [0; 16],
            counts: [0; 16],
            lut: Vec::new(),
            tolerant: None,
        }
    }

    fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let mut count = [0u16; 16];
        for &len in lengths {
            if len > 15 {
                return Err(Error::InvalidData("RAR 2.9 Huffman length is too large"));
            }
            if len != 0 {
                count[len as usize] += 1;
            }
        }
        let shape = canonical_shape(&count);
        if shape == CanonicalShape::Oversubscribed || count.iter().all(|&value| value == 0) {
            // No strict table to build: the lengths either claim more code
            // space than exists, or claim none at all. unrar builds a
            // working table for both shapes and decodes every field from
            // it, so hand the whole code space to the twin. The one shape
            // with no unrar answer to copy is an empty alphabet - upstream
            // reads its DecodeNum out of bounds there - so that one keeps
            // erroring when a symbol is asked for.
            if lengths.is_empty() {
                return Ok(Self::empty());
            }
            let mut table = Self::empty();
            table.tolerant = Some(Box::new(TolerantHuffman::from_lengths(lengths, &count)));
            return Ok(table);
        }

        let mut first_code = [0u16; 16];
        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code + count[len - 1]) << 1;
            first_code[len] = code;
            next_code[len] = code;
        }

        let mut first_index = [0usize; 16];
        let mut index = 0usize;
        for len in 1..=15 {
            first_index[len] = index;
            index += usize::from(count[len]);
        }

        let mut symbols = Vec::new();
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            symbols.push(HuffmanSymbol { code, len, symbol });
        }
        symbols.sort_by_key(|item| (item.len, item.code, item.symbol));
        let mut lut = vec![0u32; 1 << HUFF29_LUT_BITS];
        for item in &symbols {
            let len = usize::from(item.len);
            if len <= HUFF29_LUT_BITS {
                let shift = HUFF29_LUT_BITS - len;
                let start = usize::from(item.code) << shift;
                let entry = ((item.symbol as u32) << 8) | u32::from(item.len);
                lut[start..start + (1 << shift)].fill(entry);
            }
        }
        Ok(Self {
            symbols,
            first_code,
            first_index,
            counts: count,
            lut,
            // Complete: every field decodes strictly, so there is nothing
            // for a twin to answer. Incomplete: the reachable codes decode
            // strictly (and keep the LUT), the hole goes to the twin.
            tolerant: match shape {
                CanonicalShape::Complete => None,
                _ => Some(Box::new(TolerantHuffman::from_lengths(lengths, &count))),
            },
        })
    }

    fn decode(&self, bits: &mut BitReader) -> Result<usize> {
        if self.symbols.is_empty() {
            // Oversubscribed or all-zero lengths: the twin owns the whole
            // code space. Without one there is nothing to decode from.
            return match &self.tolerant {
                Some(tolerant) => tolerant.decode(bits),
                None => Err(Error::InvalidData("RAR 2.9 empty Huffman table")),
            };
        }
        if let Ok(peek) = bits.peek_bits(15) {
            let entry = self.lut[(peek >> (15 - HUFF29_LUT_BITS)) as usize];
            if entry != 0 {
                bits.consume((entry & 0xff) as u8);
                return Ok((entry >> 8) as usize);
            }
            for len in (HUFF29_LUT_BITS + 1)..=15 {
                let count = self.counts[len];
                if count != 0 {
                    let code = (peek >> (15 - len)) as u16;
                    let offset = code.wrapping_sub(self.first_code[len]);
                    if offset < count {
                        bits.consume(len as u8);
                        let index = self.first_index[len] + usize::from(offset);
                        return Ok(self.symbols[index].symbol);
                    }
                }
            }
            return self.decode_hole(bits);
        }
        match &self.tolerant {
            // Sub-15-bit tail of an incomplete table. The twin resolves the
            // code length from buffered bits alone and consumes nothing
            // when the answer needs bits that have not arrived, which the
            // bit-by-bit walk below cannot do - and it agrees with the walk
            // on every code the walk can complete.
            Some(tolerant) => tolerant.decode(bits),
            None => self.decode_slow(bits),
        }
    }

    // A field no canonical code covers. A complete table has none; an
    // incomplete one has a hole, and unrar reads the hole as a 15-bit code
    // whose position lands in the zero-filled tail of the alphabet list (or
    // clamps to slot 0 past its end) rather than failing. Nothing has been
    // consumed at this point, so the twin sees the same bits.
    fn decode_hole(&self, bits: &mut BitReader) -> Result<usize> {
        match &self.tolerant {
            Some(tolerant) => tolerant.decode(bits),
            None => Err(Error::InvalidData("RAR 2.9 invalid Huffman code")),
        }
    }

    // Bit-by-bit canonical walk for the input tail, where fewer than 15
    // peekable bits remain but a shorter valid code may still complete.
    fn decode_slow(&self, bits: &mut BitReader) -> Result<usize> {
        let mut code = 0u16;
        for len in 1..=15 {
            code = (code << 1) | bits.read_bit()? as u16;
            let count = self.counts[len];
            if count != 0 {
                let first = self.first_code[len];
                let offset = code.wrapping_sub(first);
                if offset < count {
                    let index = self.first_index[len] + usize::from(offset);
                    return Ok(self.symbols[index].symbol);
                }
            }
        }
        Err(Error::InvalidData("RAR 2.9 invalid Huffman code"))
    }
}

impl TolerantHuffman {
    fn from_lengths(lengths: &[u8], count: &[u16; 16]) -> Self {
        let mut decode_len = [0u32; 16];
        let mut decode_pos = [0usize; 16];
        let mut upper_limit = 0u32;
        for len in 1..16 {
            upper_limit += u32::from(count[len]);
            decode_len[len] = upper_limit << (16 - len);
            upper_limit *= 2;
            decode_pos[len] = decode_pos[len - 1] + usize::from(count[len - 1]);
        }

        // Alphabet-order walk, exactly like upstream: within a length,
        // symbols keep their order of appearance. No sort by code - with
        // an oversubscribed table the canonical codes wrap, and a sort
        // keyed on them would reorder the list.
        let mut decode_num = vec![0u16; lengths.len()];
        let mut next_pos = decode_pos;
        for (symbol, &len) in lengths.iter().enumerate() {
            if len != 0 {
                decode_num[next_pos[len as usize]] = symbol as u16;
                next_pos[len as usize] += 1;
            }
        }
        Self {
            decode_len,
            decode_pos,
            decode_num,
        }
    }

    fn decode(&self, bits: &mut BitReader) -> Result<usize> {
        // Left-aligned 16-bit field with bit 0 clear (upstream masks with
        // 0xfffe). Near the input tail, fewer than 15 bits may be
        // buffered; the padded low bits never decide a comparison,
        // because `decode_len[len]` is zero below bit 16-len, so the
        // outcome at each length depends only on the top `len` real bits.
        let avail = bits.available_bits().min(15);
        if avail == 0 {
            return Err(Error::NeedMoreInput);
        }
        let field = bits.peek_bits(avail as u8)? << (16 - avail);

        let mut code_len = 15usize;
        for len in 1..15 {
            if field < self.decode_len[len] {
                code_len = len;
                break;
            }
        }
        if code_len > avail {
            return Err(Error::NeedMoreInput);
        }
        bits.consume(code_len as u8);

        let dist = (field - self.decode_len[code_len - 1]) >> (16 - code_len);
        let mut pos = self.decode_pos[code_len] + dist as usize;
        // Out-of-bounds guard for damaged streams, as upstream: clamp to
        // slot 0. The member CRC rejects the garbage output downstream.
        if pos >= self.decode_num.len() {
            pos = 0;
        }
        Ok(usize::from(self.decode_num[pos]))
    }
}

/// Shape of the strict canonical table a set of code lengths implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanonicalShape {
    /// The lengths use the code space exactly: every 15-bit field decodes.
    Complete,
    /// The lengths leave code space unused, so the strict table has a hole
    /// that unrar's table still answers.
    Incomplete,
    /// The lengths claim more code space than exists, so no strict table
    /// can be built.
    Oversubscribed,
}

/// Walk the Kraft budget: one code of length 1 costs half the space, and
/// each extra bit halves the cost again. `available` is the number of
/// length-`len` slots still free after placing every shorter code.
fn canonical_shape(count: &[u16; 16]) -> CanonicalShape {
    let mut available = 1i32;
    for &len_count in count.iter().skip(1) {
        available = (available << 1) - i32::from(len_count);
        if available < 0 {
            return CanonicalShape::Oversubscribed;
        }
    }
    if available == 0 {
        CanonicalShape::Complete
    } else {
        CanonicalShape::Incomplete
    }
}

/// MSB-first bit reader over an owned, appendable buffer, with a 64-bit
/// cache (same design as rar50's slice-based reader). `cache` holds the
/// next `cache_bits` unconsumed bits MSB-aligned; bits below the valid
/// region are garbage that the next refill re-ORs with identical values
/// (whole-byte advance). The cache stays valid across `append` (end-only
/// pushes never touch cached bytes) and `compact` (drains only fully
/// consumed bytes strictly before the first cached byte, with `byte_pos`
/// re-indexed in lockstep).
#[derive(Debug, Clone)]
struct BitReader {
    input: Vec<u8>,
    byte_pos: usize,
    cache: u64,
    cache_bits: u32,
    /// High-water mark of `input.len()`, which is what the streaming
    /// bound is asserted against.
    peak_input: usize,
    /// Bits `compact()` has dropped off the front. `position()` is
    /// relative to the buffer, which compaction moves, so this is what
    /// makes an absolute consumed-bit count available - and that count is
    /// the state check the streaming path is held to.
    drained_bits: usize,
}

impl BitReader {
    fn new() -> Self {
        Self {
            input: Vec::new(),
            byte_pos: 0,
            cache: 0,
            cache_bits: 0,
            peak_input: 0,
            drained_bits: 0,
        }
    }

    fn from_bytes(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            byte_pos: 0,
            cache: 0,
            cache_bits: 0,
            peak_input: input.len(),
            drained_bits: 0,
        }
    }

    /// Bits consumed since the reader was created, across compactions.
    #[cfg(test)]
    fn absolute_position(&self) -> usize {
        self.drained_bits + self.position()
    }

    /// Absolute position in bits from the start of the buffer.
    #[inline]
    fn position(&self) -> usize {
        self.byte_pos * 8 - self.cache_bits as usize
    }

    #[inline]
    fn refill(&mut self) {
        if self.byte_pos + 8 <= self.input.len() {
            let word =
                u64::from_be_bytes(self.input[self.byte_pos..self.byte_pos + 8].try_into().unwrap());
            self.cache |= word >> self.cache_bits;
            let whole = (64 - self.cache_bits) & !7;
            self.byte_pos += (whole / 8) as usize;
            self.cache_bits += whole;
        } else {
            while self.cache_bits <= 56 && self.byte_pos < self.input.len() {
                self.cache |= u64::from(self.input[self.byte_pos]) << (56 - self.cache_bits);
                self.byte_pos += 1;
                self.cache_bits += 8;
            }
        }
    }

    #[inline]
    fn consume(&mut self, count: u8) {
        debug_assert!(u32::from(count) <= self.cache_bits);
        self.cache <<= count;
        self.cache_bits -= u32::from(count);
    }

    fn append(&mut self, input: &[u8]) {
        self.compact();
        self.input.extend_from_slice(input);
        self.peak_input = self.peak_input.max(self.input.len());
    }

    /// Append the reader's remaining bytes directly into the buffer,
    /// avoiding an intermediate staging Vec. Returns the byte count read.
    fn append_from_reader(&mut self, input: &mut impl std::io::Read) -> std::io::Result<usize> {
        self.compact();
        let read = input.read_to_end(&mut self.input)?;
        self.peak_input = self.peak_input.max(self.input.len());
        Ok(read)
    }

    /// Drop what has been consumed, then read until `want` unread bytes are
    /// buffered or the reader answers 0. Returns `(bytes read, hit EOF)`.
    ///
    /// This is the whole memory story: the buffer holds the window and
    /// nothing else, because `compact()` runs first every time.
    fn fill_from_reader(
        &mut self,
        input: &mut impl std::io::Read,
        want: usize,
    ) -> std::io::Result<(usize, bool)> {
        self.compact();
        let mut read = 0usize;
        let mut eof = false;
        while self.input.len() - self.byte_pos < want {
            let need = want - (self.input.len() - self.byte_pos);
            let at = self.input.len();
            self.input.resize(at + need, 0);
            let got = match input.read(&mut self.input[at..]) {
                Ok(got) => got,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    self.input.truncate(at);
                    continue;
                }
                Err(error) => {
                    self.input.truncate(at);
                    return Err(error);
                }
            };
            self.input.truncate(at + got);
            if got == 0 {
                eof = true;
                break;
            }
            read += got;
        }
        self.peak_input = self.peak_input.max(self.input.len());
        Ok((read, eof))
    }

    fn compact(&mut self) {
        let bytes = self.position() / 8;
        if bytes == 0 {
            return;
        }
        self.input.drain(..bytes);
        self.byte_pos -= bytes;
        self.drained_bits += bytes * 8;
    }

    fn align_byte(&mut self) {
        // position() % 8 == (8 - cache_bits % 8) % 8, so the bits to skip
        // are exactly cache_bits % 8 — always in cache, never needs input.
        let partial = (self.cache_bits % 8) as u8;
        if partial != 0 {
            self.consume(partial);
        }
    }

    /// Bits buffered and not yet consumed (cache plus unread input).
    #[inline]
    fn available_bits(&self) -> usize {
        (self.input.len() - self.byte_pos) * 8 + self.cache_bits as usize
    }

    fn peek_bit(&mut self) -> Result<u8> {
        self.peek_bits(1).map(|value| value as u8)
    }

    fn read_bit(&mut self) -> Result<u8> {
        self.read_bits(1).map(|value| value as u8)
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        let value = self.peek_bits(count)?;
        self.consume(count);
        Ok(value)
    }

    fn remaining_bits_are_zero(&self) -> bool {
        let position = self.position();
        let full_bytes = position / 8;
        let bit_offset = position % 8;
        let Some((&first, rest)) = self
            .input
            .get(full_bytes)
            .zip(self.input.get(full_bytes + 1..))
        else {
            return true;
        };
        if bit_offset != 0 && first << bit_offset != 0 {
            return false;
        }
        if bit_offset == 0 && first != 0 {
            return false;
        }
        rest.iter().all(|&byte| byte == 0)
    }

    /// Peek without consuming; a failed peek never moves `position()`.
    fn peek_bits(&mut self, count: u8) -> Result<u32> {
        if count > 24 {
            return Err(Error::InvalidData("RAR 2.9 bit read is too wide"));
        }
        if count == 0 {
            return Ok(0);
        }
        let count = u32::from(count);
        if self.cache_bits < count {
            self.refill();
            if self.cache_bits < count {
                return Err(Error::NeedMoreInput);
            }
        }
        Ok((self.cache >> (64 - count)) as u32)
    }

    fn read_encoded_u32(&mut self) -> Result<u32> {
        match self.read_bits(2)? {
            0 => self.read_bits(4),
            1 => {
                let high = self.read_bits(8)?;
                if high >= 16 {
                    Ok(high)
                } else {
                    Ok(0xffff_ff00 | (high << 4) | self.read_bits(4)?)
                }
            }
            2 => self.read_bits(16),
            _ => Ok((self.read_bits(16)? << 16) | self.read_bits(16)?),
        }
    }
}

impl PpmdByteReader for BitReader {
    fn read_ppmd_byte(&mut self) -> Result<u8> {
        self.read_bits(8).map(|value| value as u8)
    }
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn write_bits(&mut self, value: u32, count: u8) {
        for shift in (0..count).rev() {
            self.write_bit(((value >> shift) & 1) != 0);
        }
    }

    fn write_encoded_u32(&mut self, value: u32) {
        if value < 16 {
            self.write_bits(0, 2);
            self.write_bits(value, 4);
        } else if value < 256 {
            self.write_bits(1, 2);
            self.write_bits(value, 8);
        } else if value <= 0xffff {
            self.write_bits(2, 2);
            self.write_bits(value, 16);
        } else {
            self.write_bits(3, 2);
            self.write_bits(value >> 16, 16);
            self.write_bits(value & 0xffff, 16);
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if self.bit_pos.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit {
            let shift = 7 - (self.bit_pos % 8);
            *self.bytes.last_mut().unwrap() |= 1 << shift;
        }
        self.bit_pos += 1;
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn identify_standard_filter(code: &[u8]) -> Option<StandardFilter> {
    if code.iter().fold(0u8, |acc, &byte| acc ^ byte) != 0 {
        return None;
    }
    match (code.len(), crc32(code)) {
        (53, 0xad57_6887) => Some(StandardFilter::E8),
        (57, 0x3cd7_e57e) => Some(StandardFilter::E8E9),
        (120, 0x3769_893f) => Some(StandardFilter::Itanium),
        (29, 0x0e06_077d) => Some(StandardFilter::Delta),
        (149, 0x1c2c_5dc8) => Some(StandardFilter::Rgb),
        (216, 0xbc85_e701) => Some(StandardFilter::Audio),
        _ => None,
    }
}

fn apply_standard_filter(
    filter: StandardFilter,
    data: &mut Vec<u8>,
    file_offset: u32,
    regs: &[u32; 7],
) -> Result<()> {
    match filter {
        StandardFilter::E8 => {
            filters::decode_in_place(FilterOp::E8, data, file_offset, rar29_delta_messages())?
        }
        StandardFilter::E8E9 => {
            filters::decode_in_place(FilterOp::E8E9, data, file_offset, rar29_delta_messages())?
        }
        StandardFilter::Itanium => itanium_decode(data, file_offset),
        StandardFilter::Delta => {
            let channels = regs[0] as usize;
            if channels == 0 {
                return Err(Error::InvalidData("RAR 2.9 DELTA filter has zero channels"));
            }
            filters::decode_in_place(
                FilterOp::Delta { channels },
                data,
                0,
                rar29_delta_messages(),
            )?;
        }
        StandardFilter::Rgb => {
            if regs[0] < 3 || regs[1] > 2 {
                return Err(Error::InvalidData(
                    "RAR 2.9 RGB filter parameters are invalid",
                ));
            }
            let width = regs[0] as usize - 3;
            let pos_r = regs[1] as usize;
            *data = rgb_decode(data, width, pos_r)?;
        }
        StandardFilter::Audio => {
            let channels = regs[0] as usize;
            if channels == 0 {
                return Err(Error::InvalidData("RAR 2.9 AUDIO filter has zero channels"));
            }
            *data = audio_decode(data, channels)?;
        }
    }
    Ok(())
}

fn itanium_decode(data: &mut [u8], file_offset: u32) {
    if data.len() <= 21 {
        return;
    }
    let base_offset = file_offset >> 4;
    // Each 16-byte Itanium bundle can inspect a 4-byte instruction field that
    // starts up to 13 bytes into the bundle. Keeping a 21-byte tail prevents
    // decoding a partial final bundle.
    let block_count = (data.len() - 21).div_ceil(16);
    for block in 0..block_count {
        let pos = block * 16;
        let file_offset = base_offset.wrapping_add(block as u32);
        let mut mask = (0x334b_0000u32 >> (data[pos] & 0x1e)) & 3;
        if mask != 0 {
            mask += 1;
            while mask <= 4 {
                let p = pos + (mask as usize * 5 - 8);
                if ((data[p + 3] >> mask) & 15) == 5 {
                    let raw = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                    let mut value = raw >> mask;
                    value = value.wrapping_sub(file_offset) & 0x000f_ffff;
                    let raw = (raw & !(0x000f_ffff << mask)) | (value << mask);
                    data[p..p + 4].copy_from_slice(&raw.to_le_bytes());
                }
                mask += 1;
            }
        }
    }
}

fn rgb_decode(data: &[u8], width: usize, pos_r: usize) -> Result<Vec<u8>> {
    if data.len() < 3 || width == 0 || !width.is_multiple_of(3) || width > data.len() || pos_r > 2 {
        return Err(Error::InvalidData(
            "RAR 2.9 RGB filter parameters are invalid",
        ));
    }
    let mut out = vec![0u8; data.len()];
    let mut src = 0usize;
    for channel in 0..3 {
        let mut prev = 0u8;
        let mut i = channel;
        while i < data.len() {
            let predicted = if i >= width + 3 {
                rgb_predict(prev, out[i - width], out[i - width - 3])
            } else {
                prev
            };
            let encoded = *data
                .get(src)
                .ok_or(Error::InvalidData("RAR 2.9 RGB filter source is truncated"))?;
            prev = predicted.wrapping_sub(encoded);
            out[i] = prev;
            src += 1;
            i += 3;
        }
    }
    for i in (pos_r..data.len().saturating_sub(2)).step_by(3) {
        let green = out[i + 1];
        out[i] = out[i].wrapping_add(green);
        out[i + 2] = out[i + 2].wrapping_add(green);
    }
    Ok(out)
}

fn rgb_predict(prev: u8, upper: u8, upper_left: u8) -> u8 {
    let predicted = i32::from(prev) + i32::from(upper) - i32::from(upper_left);
    let pa = (predicted - i32::from(prev)).abs();
    let pb = (predicted - i32::from(upper)).abs();
    let pc = (predicted - i32::from(upper_left)).abs();
    if pa <= pb && pa <= pc {
        prev
    } else if pb <= pc {
        upper
    } else {
        upper_left
    }
}

fn audio_decode(data: &[u8], channels: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; data.len()];
    let mut src = 0usize;
    for channel in 0..channels {
        let mut prev_byte = 0u32;
        let mut prev_delta = 0i32;
        let mut d1 = 0i32;
        let mut d2 = 0i32;
        let mut k1 = 0i32;
        let mut k2 = 0i32;
        let mut k3 = 0i32;
        let mut dif = [0u32; 7];
        let mut byte_count = 0usize;
        let mut i = channel;
        while i < data.len() {
            let d3 = d2;
            d2 = prev_delta - d1;
            d1 = prev_delta;
            let predicted = ((8 * prev_byte as i32 + k1 * d1 + k2 * d2 + k3 * d3) >> 3) & 0xff;
            let encoded = *data.get(src).ok_or(Error::InvalidData(
                "RAR 2.9 AUDIO filter source is truncated",
            ))?;
            src += 1;
            let decoded = (predicted as u8).wrapping_sub(encoded);
            out[i] = decoded;
            prev_delta = decoded.wrapping_sub(prev_byte as u8) as i8 as i32;
            prev_byte = decoded as u32;
            let d = (encoded as i8 as i32) << 3;
            dif[0] += d.unsigned_abs();
            dif[1] += (d - d1).unsigned_abs();
            dif[2] += (d + d1).unsigned_abs();
            dif[3] += (d - d2).unsigned_abs();
            dif[4] += (d + d2).unsigned_abs();
            dif[5] += (d - d3).unsigned_abs();
            dif[6] += (d + d3).unsigned_abs();
            if byte_count & 0x1f == 0 {
                let mut min = dif[0];
                let mut min_index = 0usize;
                dif[0] = 0;
                for (index, value) in dif.iter_mut().enumerate().skip(1) {
                    if *value < min {
                        min = *value;
                        min_index = index;
                    }
                    *value = 0;
                }
                match min_index {
                    1 if k1 >= -16 => k1 -= 1,
                    2 if k1 < 16 => k1 += 1,
                    3 if k2 >= -16 => k2 -= 1,
                    4 if k2 < 16 => k2 += 1,
                    5 if k3 >= -16 => k3 -= 1,
                    6 if k3 < 16 => k3 += 1,
                    _ => {}
                }
            }
            byte_count += 1;
            i += channels;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {

    #[test]
    fn cached_reader_survives_append_after_partial_consume() {
        // Exercises the refill re-OR invariant across append/compact: the
        // owned-buffer property rar50's slice reader never had to prove.
        let data: Vec<u8> = (0u16..64).map(|i| (i.wrapping_mul(37) >> 1) as u8).collect();
        let mut incremental = super::BitReader::new();
        incremental.append(&data[..7]);
        let mut reference = super::BitReader::from_bytes(&data);
        // Consume an odd number of bits, then append more mid-stream.
        for step in [3u8, 11, 1, 7] {
            assert_eq!(
                incremental.read_bits(step).unwrap(),
                reference.read_bits(step).unwrap()
            );
        }
        incremental.append(&data[7..]);
        let mut step = 1u8;
        while let Ok(expected) = reference.read_bits(step) {
            assert_eq!(incremental.read_bits(step).unwrap(), expected);
            step = step % 24 + 1;
        }
        // Positions are buffer-relative and append() compacts, so compare
        // exhaustion instead: both readers must fail the next read.
        assert!(incremental.read_bits(step).is_err());
    }

    // SPEC C Part 3.2 / Part 7 item 1. The RAR 3 x86 filter computes
    // `o = F + p + 1` with no reduction, where `F` is the block's
    // member-relative start and `p` the position of the trigger byte.
    // Encode and decode are exact inverses only while `o <= 2^31`; past
    // that the pair is not invertible for every operand value, and the
    // transform must not be "repaired", because its decode side has to
    // match what other RAR 3 readers do. So the writer must not plan a
    // block that can reach the region at all.
    //
    // The largest `o` a block `[s, e)` can produce is `e - 4`: the
    // trigger byte sits at most at `e - 5` and `o = F + p + 1`.
    const TWO_GIB: usize = 1 << 31;

    #[test]
    fn the_block_the_planner_gives_up_is_the_one_that_does_not_round_trip() {
        // Why the clip is where it is, stated at the writer's own entry
        // point. 128 KiB divides 2 GiB exactly, so before the guard the
        // whole-member planner put a block start on 0x8000_0000 itself.
        let first_unsafe_start = TWO_GIB;
        assert_eq!(first_unsafe_start % MAX_VM_FILTER_BLOCK_SIZE, 0);

        let file_offset = u32::try_from(first_unsafe_start).unwrap();
        let original = [0xe8u8, 0xff, 0xff, 0xff, 0x00];

        let mut encoded = original.to_vec();
        filters::encode_in_place(
            FilterOp::E8,
            &mut encoded,
            file_offset,
            rar29_delta_messages(),
        )
        .unwrap();
        assert_eq!(
            encoded, original,
            "neither encode arm holds, so it is a no-op"
        );

        let mut decoded = encoded.clone();
        filters::decode_in_place(
            FilterOp::E8,
            &mut decoded,
            file_offset,
            rar29_delta_messages(),
        )
        .unwrap();
        assert_ne!(
            decoded, original,
            "a record covering this block would not round trip"
        );
    }

    #[test]
    fn filtered_member_refuses_an_x86_range_past_the_boundary() {
        // Defence in depth: `split_large_filter` is the only way in and
        // clips, so this arm answers a writer bug, not caller input. The
        // buffer is a stub - the check runs before it is read.
        let member = vec![0u8; 64];
        let result = super::filtered_member(
            &member,
            &Rar29FilterSpec::range(Rar29FilterKind::E8, 0..TWO_GIB + 8),
        );
        let err = match result {
            Ok(_) => panic!("an x86 range past the boundary must be refused"),
            Err(err) => err,
        };
        assert!(
            matches!(err, Error::InvalidData(message) if message == RAR3_X86_PAST_BOUNDARY),
            "the boundary arm answers, not the length arm"
        );
    }

    #[test]
    fn split_large_filter_clips_x86_coverage_at_the_two_gib_boundary() {
        // A member big enough that a whole-member x86 filter would
        // otherwise plan blocks on both sides of the boundary. The
        // 128 KiB chunking divides 2 GiB exactly, so the unguarded
        // planner put a block start on 0x8000_0000 itself - the `F` of
        // the non-inverse vector above.
        let member_len = TWO_GIB + 4 * 1024 * 1024;
        for kind in [Rar29FilterKind::E8, Rar29FilterKind::E8E9] {
            let filters = split_large_filter(member_len, Rar29FilterSpec::whole(kind)).unwrap();
            let last = filters.last().expect("coverage below the boundary is kept");
            let last_end = last.range.clone().unwrap().end;
            assert!(
                last_end <= TWO_GIB + 4,
                "{kind:?} planned a block ending at {last_end}, past the inverse boundary"
            );
            for filter in &filters {
                let range = filter.range.clone().unwrap();
                assert!(
                    range.end.saturating_sub(4) <= TWO_GIB,
                    "{kind:?} block {range:?} can reach an operand offset past 2^31"
                );
            }
            // The safe side is still covered in full: the planner only
            // gives up the tail it cannot encode reversibly.
            assert_eq!(filters.first().unwrap().range.clone().unwrap().start, 0);
            assert!(last_end >= TWO_GIB - MAX_VM_FILTER_BLOCK_SIZE);
        }
    }

    #[test]
    fn split_large_filter_drops_an_x86_range_that_lies_wholly_past_two_gib() {
        let member_len = TWO_GIB + 4 * 1024 * 1024;
        let filters = split_large_filter(
            member_len,
            Rar29FilterSpec::range(Rar29FilterKind::E8, TWO_GIB + 16..member_len),
        )
        .unwrap();
        assert!(
            filters.is_empty(),
            "nothing in this range can be filtered reversibly, so no record is emitted"
        );
    }

    #[test]
    fn split_large_filter_leaves_non_x86_kinds_and_small_members_alone() {
        // The clip is an x86 writer policy, not a size rule: a member
        // under the boundary is planned exactly as before, and the
        // kinds that do not take a file offset are never clipped.
        let filters =
            split_large_filter(300 * 1024, Rar29FilterSpec::whole(Rar29FilterKind::E8)).unwrap();
        assert_eq!(filters.len(), 3);
        assert_eq!(
            filters.last().unwrap().range.clone().unwrap().end,
            300 * 1024
        );

        let member_len = TWO_GIB + 4 * 1024 * 1024;
        let delta = split_large_filter(
            member_len,
            Rar29FilterSpec::whole(Rar29FilterKind::Delta { channels: 3 }),
        )
        .unwrap();
        assert_eq!(
            delta.last().unwrap().range.clone().unwrap().end,
            member_len,
            "the delta filter reads no file offset, so the boundary does not apply"
        );
    }

    #[test]
    fn cached_reader_align_and_compact_at_all_phases() {
        for phase in 0u8..8 {
            let data: Vec<u8> = (0u16..32).map(|i| (i * 29 + 5) as u8).collect();
            let mut bits = super::BitReader::from_bytes(&data);
            if phase != 0 {
                bits.read_bits(phase).unwrap();
            }
            bits.align_byte();
            assert_eq!(bits.position() % 8, 0, "phase {phase}");
            let expected_pos = if phase == 0 { 0 } else { 8 };
            assert_eq!(bits.position(), expected_pos, "phase {phase}");
            bits.compact();
            assert_eq!(
                bits.read_bits(8).unwrap() as u8,
                data[expected_pos / 8],
                "phase {phase}"
            );
        }
    }

    #[test]
    fn cached_reader_remaining_bits_are_zero_sees_cached_bits() {
        let mut bits = super::BitReader::from_bytes(&[0xff, 0x00, 0x00]);
        bits.read_bits(8).unwrap();
        assert!(bits.remaining_bits_are_zero());
        let mut bits = super::BitReader::from_bytes(&[0xff, 0x80, 0x00]);
        bits.read_bits(8).unwrap();
        assert!(!bits.remaining_bits_are_zero());
        // Mid-byte: bits below the current position must be ignored.
        let mut bits = super::BitReader::from_bytes(&[0b1010_0000]);
        bits.read_bits(3).unwrap();
        assert!(bits.remaining_bits_are_zero());
    }
    use super::rarvm::{Instruction, Opcode, Operand, Program};
    use std::ops::Range;

    use super::{
        apply_standard_filter, audio_encode, best_match, encode_ppmd_tokens,
        encode_table_level_tokens, encode_tokens, encoded_filter_records, filters,
        insert_match_position, itanium_decode, itanium_encode, rar29_delta_messages,
        should_lazy_emit_literal, split_large_filter,
        unpack29_decode, unpack29_encode_literals, unpack29_encode_ppmd,
        unpack29_encode_ppmd_literals, unpack29_encode_ppmd_with_filter, BitReader, BitWriter,
        EncodeOptions, EncodeToken, EncoderMatchState, Error, FilterOp, Huffman, LevelToken,
        OwnedVmFilterRecord, PpmdEncodeToken, Rar29FilterKind, Rar29FilterSpec, Result,
        BlockMode, Rar29State, StandardFilter, Unpack29, Unpack29Encoder, VmFilter, VmProgram,
        VmProgramKind, MAIN_COUNT,
        MATCH_HASH_BUCKETS, MAX_MATCH_CANDIDATES, MAX_VM_AUDIO_FILTER_BLOCK_SIZE,
        MAX_VM_DELTA_FILTER_BLOCK_SIZE, MAX_VM_FILTER_BLOCK_SIZE, RAR3_AUDIO_FILTER_BYTECODE,
        STREAM_INPUT_MARGIN, STREAM_INPUT_WINDOW,
        RAR3_DELTA_FILTER_BYTECODE, RAR3_RGB_FILTER_BYTECODE, RAR3_X86_PAST_BOUNDARY, TABLE_COUNT,
    };

    const COMPRESSED_TEXT: &[u8] = &[
        0x09, 0x10, 0x10, 0x93, 0xe4, 0xce, 0x7f, 0xa2, 0xba, 0x80, 0x46, 0x16, 0x82, 0x63, 0xe9,
        0x9a, 0x19, 0xe4, 0x10, 0xe0, 0x41, 0x3d, 0x16, 0xfc, 0x4d, 0xfa, 0x6f, 0xf2, 0x5c, 0xae,
        0x32, 0x86, 0xc9, 0x95, 0x9d, 0xf1, 0x04, 0xa4, 0xe8, 0x92, 0x8f, 0x12, 0xd7, 0xe7, 0xba,
        0xcb, 0x26, 0xf1, 0x97, 0xac, 0x7c, 0x5f, 0xfd, 0xa0, 0x00, 0x1f, 0x77, 0x50,
    ];

    #[test]
    fn decodes_rar29_lz_member() {
        assert_eq!(
            unpack29_decode(COMPRESSED_TEXT, 2400).unwrap(),
            expected_text()
        );
    }

    #[test]
    fn tolerates_oversubscribed_rar29_huffman_tables() {
        // Old WinRAR 2.x encoders emit these; unrar truncates instead of
        // erroring, and so do we (via the tolerant fallback table).
        let table = Huffman::from_lengths(&[1, 1, 1]).unwrap();
        assert!(table.tolerant.is_some());

        // counts[1] = 3 saturates the 1-bit limit past 0xffff, so every
        // bit field decodes as one of the two reachable 1-bit codes and
        // the third symbol is unreachable, exactly as unrar behaves.
        let mut bits = BitReader::from_bytes(&[0b0100_0000, 0]);
        assert_eq!(table.decode(&mut bits).unwrap(), 0);
        assert_eq!(bits.position(), 1);
        assert_eq!(table.decode(&mut bits).unwrap(), 1);
        assert_eq!(bits.position(), 2);
    }

    #[test]
    fn oversubscribed_low_offset_shape_from_the_field_decodes_as_unrar() {
        // The exact 17-symbol low-offset table shape from the 11 Aug soak
        // set (Rapala WII): two 1-bit codes up front, then 15 junk
        // lengths. unrar resolves every field at 1 bit; the junk symbols
        // are unreachable.
        let lengths: [u8; 17] = [1, 1, 3, 3, 4, 5, 6, 6, 7, 8, 9, 11, 12, 12, 14, 14, 14];
        let table = Huffman::from_lengths(&lengths).unwrap();
        assert!(table.tolerant.is_some());
        for pattern in 0u16..=0xff {
            let mut bits = BitReader::from_bytes(&[pattern as u8, 0]);
            let symbol = table.decode(&mut bits).unwrap();
            assert_eq!(bits.position(), 1);
            assert_eq!(symbol, usize::from(pattern >> 7));
        }
    }

    #[test]
    fn tolerant_decode_matches_strict_for_the_reachable_code_space() {
        // A complete table plus one phantom max-length entry (the classic
        // junk-tail shape) must decode the real code space bit-for-bit
        // like the strict table without the phantom.
        let valid: [u8; 6] = [2, 2, 3, 3, 3, 3];
        let mut padded = [0u8; 7];
        padded[..6].copy_from_slice(&valid);
        padded[6] = 15;

        let strict = Huffman::from_lengths(&valid).unwrap();
        let tolerant = Huffman::from_lengths(&padded).unwrap();
        assert!(strict.tolerant.is_none());
        assert!(tolerant.tolerant.is_some());

        for pattern in 0u16..=0xffff {
            let input = pattern.to_be_bytes();
            let mut strict_bits = BitReader::from_bytes(&input);
            let mut tolerant_bits = BitReader::from_bytes(&input);
            let strict_symbol = strict.decode(&mut strict_bits).unwrap();
            let tolerant_symbol = tolerant.decode(&mut tolerant_bits).unwrap();
            assert_eq!(strict_symbol, tolerant_symbol, "pattern {pattern:#06x}");
            assert_eq!(
                strict_bits.position(),
                tolerant_bits.position(),
                "pattern {pattern:#06x}"
            );
        }
    }

    // Decode one 16-bit field from a fresh reader: (symbol, bits consumed).
    // unrar always has 16 bits in hand at this point, so two bytes is the
    // whole field it would see.
    fn decode_field(table: &Huffman, pattern: u16) -> (usize, usize) {
        let input = pattern.to_be_bytes();
        let mut bits = BitReader::from_bytes(&input);
        let symbol = table.decode(&mut bits).unwrap();
        (symbol, bits.position())
    }

    #[test]
    fn undersubscribed_rar29_huffman_tables_answer_the_hole_as_unrar() {
        // Lengths that leave code space unused. Strict construction is
        // happy with these (nothing is oversubscribed) but has no code for
        // fields at or above 0xa000, where unrar still answers: its length
        // search falls out at 15 bits and the position it computes lands in
        // the zero-filled tail of the alphabet list, or clamps to slot 0
        // past its end. Expectations transcribed from unrar 7.20's
        // MakeDecodeTables/DecodeNumber run over this exact table.
        let lengths: [u8; 8] = [0, 2, 2, 3, 0, 0, 0, 0];
        let table = Huffman::from_lengths(&lengths).unwrap();

        // The strict table survives - this shape keeps the LUT and the
        // burst path, and only borrows the twin for the hole.
        assert!(!table.symbols.is_empty());
        assert!(!table.lut.is_empty());
        assert!(table.tolerant.is_some());

        for pattern in 0u16..=0xffff {
            let field = pattern & 0xfffe;
            let expected = match field {
                0x0000..=0x3fff => (1, 2),
                0x4000..=0x7fff => (2, 2),
                0x8000..=0x9fff => (3, 3),
                // The hole. Position 3 + (field - 0xa000) / 2 reads the
                // zero-filled tail while it stays inside the 8-entry
                // alphabet, then clamps to slot 0 - which holds symbol 1,
                // the first 2-bit code, not symbol 0.
                0xa000..=0xa009 => (0, 15),
                _ => (1, 15),
            };
            assert_eq!(
                decode_field(&table, pattern),
                expected,
                "field {field:#06x}"
            );
        }
    }

    #[test]
    fn single_one_bit_code_rar29_table_decodes_as_unrar() {
        // The commonest incomplete shape in real archives: one used symbol
        // in a small alphabet, so half the code space is a hole.
        let table = Huffman::from_lengths(&[0, 1, 0, 0]).unwrap();
        assert!(table.tolerant.is_some());

        for pattern in 0u16..=0xffff {
            let field = pattern & 0xfffe;
            let expected = match field {
                0x0000..=0x7fff => (1, 1),
                0x8000..=0x8005 => (0, 15),
                _ => (1, 15),
            };
            assert_eq!(
                decode_field(&table, pattern),
                expected,
                "field {field:#06x}"
            );
        }
    }

    #[test]
    fn all_zero_rar29_huffman_table_decodes_as_unrar() {
        // What a damaged stream degenerates into. unrar builds a table here
        // too: every limit is zero, so every field falls out of the length
        // search at 15 bits and reads alphabet entry 0. rars used to return
        // an empty table and then hard-error the first time a symbol was
        // asked for.
        let table = Huffman::from_lengths(&[0u8; 20]).unwrap();
        assert!(table.symbols.is_empty());
        assert!(table.tolerant.is_some());

        for pattern in 0u16..=0xffff {
            assert_eq!(
                decode_field(&table, pattern),
                (0, 15),
                "pattern {pattern:#06x}"
            );
        }
    }

    #[test]
    fn an_empty_alphabet_still_refuses_to_decode() {
        // The one shape with no unrar answer to copy: upstream reads its
        // decode table out of bounds. No table, no symbols.
        let table = Huffman::from_lengths(&[]).unwrap();
        assert!(table.tolerant.is_none());
        let mut bits = BitReader::from_bytes(&[0xff, 0xff]);
        assert!(table.decode(&mut bits).is_err());
    }

    #[test]
    fn complete_rar29_tables_keep_the_strict_path_alone() {
        // No hole, so no twin: the gate must not drag complete tables onto
        // the tolerant path.
        for lengths in [&[1u8, 1][..], &[2, 2, 2, 2][..], &[1, 2, 3, 3][..]] {
            let table = Huffman::from_lengths(lengths).unwrap();
            assert!(table.tolerant.is_none(), "lengths {lengths:?}");
            assert!(!table.lut.is_empty(), "lengths {lengths:?}");
        }
    }

    #[test]
    fn literal_encoder_round_trips_rar29_lz_blocks() {
        let input = b"literal-only RAR 2.9 baseline\nwith repeated text literal-only\n";
        let packed = unpack29_encode_literals(input).unwrap();

        assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn multi_block_lz_encoding_round_trips_large_repeated_documents() {
        let seed = b"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\n\
<HTML><BODY><P>RAR29 repeated document body with enough structured text to \
exercise LZSS block table selection.</P></BODY></HTML>\n"
            .repeat(96);
        let input = seed.repeat(180);
        let single =
            super::encode_member_with_options(&input, &[], EncodeOptions::new(96)).unwrap();
        let blocked = super::encode_member_with_options(
            &input,
            &[],
            EncodeOptions::new(96).with_block_size(1024 * 1024),
        )
        .unwrap();

        assert_eq!(unpack29_decode(&single, input.len()).unwrap(), input);
        assert_eq!(unpack29_decode(&blocked, input.len()).unwrap(), input);
        assert!(blocked.len() < input.len());
    }

    #[test]
    fn table_level_encoder_uses_rar29_run_symbols() {
        let mut lengths = [0u8; TABLE_COUNT];
        lengths[..4].fill(5);
        lengths[8..21].fill(0);

        let tokens = encode_table_level_tokens(&lengths);

        assert!(tokens.contains(&LevelToken::repeat_previous_short(3)));
        assert!(tokens.iter().any(|token| token.symbol == 19));
    }

    #[test]
    fn lazy_lz_parser_defers_short_match_for_longer_next_match() {
        let input = b"abcdXbcdYYYYYYYYYYYYabcdYYYYYYYYYYYY";
        let greedy = encode_tokens(input, &[], EncodeOptions::new(MAX_MATCH_CANDIDATES));
        let lazy = encode_tokens(
            input,
            &[],
            EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
        );
        let packed = Unpack29Encoder::with_options(
            EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
        )
        .encode_member(input)
        .unwrap();

        assert!(greedy
            .iter()
            .any(|token| matches!(token, EncodeToken::Match { length: 4, .. })));
        assert!(lazy
            .iter()
            .any(|token| matches!(token, EncodeToken::Match { length, .. } if *length > 8)));
        assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn lazy_lz_parser_uses_match_cost_not_only_match_length() {
        let pos = 300_000usize;
        let mut input = vec![0u8; pos + 16];
        input[100..106].copy_from_slice(b"BCDEFG");
        input[106] = b'!';
        input[pos - 10..pos - 5].copy_from_slice(b"ABCD!");
        input[pos..pos + 7].copy_from_slice(b"ABCDEFG");
        let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
        insert_match_position(&input, 100, &mut buckets);
        insert_match_position(&input, pos - 10, &mut buckets);

        let current = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::new(MAX_MATCH_CANDIDATES),
            &EncoderMatchState::default(),
        )
        .unwrap();
        let next = best_match(
            &input,
            pos + 1,
            input.len(),
            &buckets,
            EncodeOptions::new(MAX_MATCH_CANDIDATES),
            &EncoderMatchState::default(),
        )
        .unwrap();

        assert_eq!(current.length, 4);
        assert_eq!(current.offset, 10);
        assert_eq!(next.length, 6);
        assert!(next.offset > 0x40000);
        assert!(!should_lazy_emit_literal(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::new(MAX_MATCH_CANDIDATES).with_lazy_matching(true),
            &EncoderMatchState::default(),
            current,
        ));
    }

    #[test]
    fn lazy_lz_parser_uses_bounded_cost_lookahead() {
        let pos = 160;
        let mut input: Vec<u8> = (0..240u16)
            .map(|value| value.wrapping_mul(91) as u8)
            .collect();
        input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
        input[pos - 80..pos - 64].copy_from_slice(b"CDEFGHIJKLMNOPQR");
        input[pos..pos + 18].copy_from_slice(b"ABCDEFGHIJKLMNOPQR");

        let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
        for candidate in 0..pos {
            insert_match_position(&input, candidate, &mut buckets);
        }
        let current = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &EncoderMatchState::default(),
        )
        .unwrap();

        assert_eq!((current.length, current.offset), (8, 30));
        assert!(!should_lazy_emit_literal(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default()
                .with_lazy_matching(true)
                .with_lazy_lookahead(1),
            &EncoderMatchState::default(),
            current,
        ));
        assert!(should_lazy_emit_literal(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default()
                .with_lazy_matching(true)
                .with_lazy_lookahead(2),
            &EncoderMatchState::default(),
            current,
        ));
    }

    #[test]
    fn match_state_encodes_last_length_and_repeat_offset_symbols() {
        let mut state = EncoderMatchState::default();
        assert!(matches!(
            state.encode_match(12, 64).unwrap(),
            super::EncodedMatch::Fresh { .. }
        ));
        state.remember(12, 64);

        assert_eq!(
            state.encode_match(12, 64).unwrap(),
            super::EncodedMatch::LastLengthRepeat
        );
        assert!(matches!(
            state.encode_match(9, 64).unwrap(),
            super::EncodedMatch::RepeatOffset { index: 0, .. }
        ));
    }

    #[test]
    fn cost_aware_match_selection_prefers_repeat_offset_token() {
        let pos = 600usize;
        let mut input: Vec<u8> = (0..pos + 16)
            .map(|index| (index as u8).wrapping_mul(37))
            .collect();
        input[pos - 30..pos - 22].copy_from_slice(b"ABCDEFGH");
        input[pos - 512..pos - 503].copy_from_slice(b"ABCDEFGHI");
        input[pos..pos + 9].copy_from_slice(b"ABCDEFGHI");
        input[pos - 22] = 0x11;
        input[pos - 503] = 0x22;
        input[pos + 9] = 0x33;
        let mut buckets = vec![Vec::new(); MATCH_HASH_BUCKETS];
        insert_match_position(&input, pos - 30, &mut buckets);
        insert_match_position(&input, pos - 512, &mut buckets);

        let fresh = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &EncoderMatchState::default(),
        )
        .unwrap();
        let repeat = best_match(
            &input,
            pos,
            input.len(),
            &buckets,
            EncodeOptions::default(),
            &EncoderMatchState {
                old_offsets: [30, 0, 0, 0],
                last_offset: 0,
                last_length: 0,
            },
        )
        .unwrap();

        assert_eq!((fresh.length, fresh.offset), (9, 512));
        assert_eq!((repeat.length, repeat.offset), (8, 30));
    }

    #[test]
    fn match_finder_respects_configured_maximum_distance() {
        let phrase = b"rar29 bounded dictionary phrase";
        let mut input = Vec::new();
        input.extend_from_slice(phrase);
        input.extend(std::iter::repeat_n(0u8, 256 * 1024));
        input.extend_from_slice(phrase);

        let bounded = encode_tokens(
            &input,
            &[],
            EncodeOptions::new(MAX_MATCH_CANDIDATES).with_max_match_distance(128 * 1024),
        );
        let unbounded = encode_tokens(
            &input,
            &[],
            EncodeOptions::new(MAX_MATCH_CANDIDATES).with_max_match_distance(1024 * 1024),
        );

        assert!(!bounded.iter().any(
            |token| matches!(token, EncodeToken::Match { offset, .. } if *offset > 128 * 1024)
        ));
        assert!(unbounded.iter().any(
            |token| matches!(token, EncodeToken::Match { offset, .. } if *offset > 128 * 1024)
        ));
    }

    #[test]
    fn lz_encoder_uses_weighted_rar29_huffman_tables() {
        let mut input = Vec::new();
        for byte in 0u8..120 {
            input.push(b'A');
            input.push(byte);
        }
        let packed = Unpack29Encoder::new().encode_member(&input).unwrap();
        let mut decoder = Unpack29::new();
        decoder.bits.append(&packed);
        decoder.read_tables().unwrap();
        let main_lengths = &decoder.levels[..MAIN_COUNT];
        let nonzero_lengths = main_lengths
            .iter()
            .copied()
            .filter(|&length| length != 0)
            .collect::<std::collections::BTreeSet<_>>();

        assert!(nonzero_lengths.len() > 1);
        assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn copy_match_treats_zero_offset_as_distance_one() {
        let mut decoder = Unpack29::new();
        decoder.output.push(b'Z');

        decoder.copy_match(4, 0, 5).unwrap();

        assert_eq!(decoder.output, b"ZZZZZ");
    }

    #[test]
    fn copy_match_period_doubling_matches_bytewise_oracle() {
        for distance in [1, 2, 3, 7, 64, 4096, 4097] {
            for length in [1, distance - 1, distance, distance + 1, 10_003] {
                let seed: Vec<u8> = (0..distance)
                    .map(|index| ((index * 37 + 11) % 251) as u8)
                    .collect();
                let mut expected = seed.clone();
                for _ in 0..length {
                    let byte = expected[expected.len() - distance];
                    expected.push(byte);
                }

                let mut decoder = Unpack29::new();
                decoder.output = seed;
                decoder
                    .copy_match(length, distance, distance + length)
                    .unwrap();
                assert_eq!(
                    decoder.output, expected,
                    "distance={distance} length={length}"
                );
            }
        }
    }

    /// The 16-byte stride path (distance 16 and up, length 64 and down)
    /// against the byte loop, at every stride edge and every overlap the
    /// strides can meet, with window content after the match so a stride
    /// that scribbled past its end would show.
    #[test]
    fn copy_match_short_stride_path_matches_bytewise_oracle() {
        for distance in [16usize, 17, 31, 32, 33, 47, 48, 63, 64, 65, 1000] {
            for length in 2..=64usize {
                let seed: Vec<u8> = (0..distance + 5)
                    .map(|index| ((index * 53 + 7) % 251) as u8)
                    .collect();
                let mut expected = seed.clone();
                for _ in 0..length {
                    let byte = expected[expected.len() - distance];
                    expected.push(byte);
                }
                expected.push(0xEE);

                let mut decoder = Unpack29::new();
                decoder.output = seed.clone();
                decoder
                    .copy_match(length, distance, seed.len() + length)
                    .unwrap();
                decoder.output.push(0xEE);
                assert_eq!(decoder.output, expected, "distance={distance} length={length}");
            }
        }
    }

    #[test]
    fn copy_match_period_doubling_preserves_pending_remainder() {
        let mut decoder = Unpack29::new();
        decoder.output.extend_from_slice(b"abc");

        decoder.copy_match(20, 3, 10).unwrap();
        assert_eq!(decoder.output, b"abcabcabca");
        assert_eq!(decoder.pending_match, Some((13, 3)));

        decoder.drain_pending_match(23).unwrap();
        assert_eq!(decoder.output, b"abcabcabcabcabcabcabcab");
        assert_eq!(decoder.pending_match, None);
    }

    #[test]
    fn ppmd_literal_encoder_round_trips_rar29_ppmd_blocks() {
        let mut input = b"rar29 ppmd literal text payload alpha beta gamma\n".repeat(64);
        input.extend_from_slice(&[2, 2, 2, b'e', b's', b'c']);
        let packed = unpack29_encode_ppmd_literals(&input).unwrap();

        assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
        assert_ne!(packed.first().copied(), Some(0));
    }

    #[test]
    fn ppmd_encoder_advertises_period_compatible_model_for_external_decoders() {
        let packed = unpack29_encode_ppmd(b"rar29 ppmd dictionary header").unwrap();

        assert_eq!(packed[0], 0xa7);
        assert_eq!(packed[1], 24);
    }

    #[test]
    fn ppmd_encoder_emits_offset_one_repeat_escapes() {
        let input = b"seed "
            .iter()
            .copied()
            .chain(std::iter::repeat_n(b'Z', 512))
            .collect::<Vec<_>>();
        let tokens = encode_ppmd_tokens(&input, true);
        let packed = unpack29_encode_ppmd(&input).unwrap();

        assert!(tokens.iter().any(
            |token| matches!(token, PpmdEncodeToken::RepeatOffsetOne { length } if *length >= 4)
        ));
        assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn ppmd_encoder_emits_distance_match_escapes() {
        let phrase = b"repeated phrase for rar29 ppmd distance escape 4 ";
        let mut input = Vec::new();
        input.extend_from_slice(phrase);
        input.extend_from_slice(b"middle bytes make the repeat distance greater than one ");
        input.extend_from_slice(phrase);
        input.extend_from_slice(phrase);
        input.extend_from_slice(b"tail");
        let tokens = encode_ppmd_tokens(&input, true);
        let packed = unpack29_encode_ppmd(&input).unwrap();

        assert!(tokens
            .iter()
            .any(|token| matches!(token, PpmdEncodeToken::Match { offset, length } if *offset > 1 && *length >= 32)));
        assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn ppmd_distance_match_lengths_stay_period_decoder_compatible() {
        let phrase = b"<html><body>RAR PPMd LZSS conversion phrase</body></html>\n";
        let mut input = Vec::new();
        for _ in 0..200 {
            input.extend_from_slice(phrase);
        }
        let tokens = encode_ppmd_tokens(&input, true);

        assert!(tokens.iter().any(
            |token| matches!(token, PpmdEncodeToken::Match { offset, length } if *offset > 1 && *length >= 32)
        ));
        assert!(!tokens
            .iter()
            .any(|token| matches!(token, PpmdEncodeToken::Match { length, .. } if *length > 255)));
    }

    #[test]
    fn ppmd_encoder_emits_embedded_vm_filter_escape() {
        let input = b"\xe8\0\0\0\0rar29 ppmd embedded e8 filter payload\n".repeat(16);
        let packed =
            unpack29_encode_ppmd_with_filter(&input, Rar29FilterSpec::whole(Rar29FilterKind::E8))
                .unwrap();
        let plain_ppmd = unpack29_encode_ppmd(&input).unwrap();
        let filtered_lz = Unpack29Encoder::new()
            .encode_member_with_filter(&input, Rar29FilterSpec::whole(Rar29FilterKind::E8))
            .unwrap();

        assert!(packed.len() != plain_ppmd.len() || packed.len() != filtered_lz.len());
        assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    }

    fn encode_with_filter(input: &[u8], kind: Rar29FilterKind) -> Result<Vec<u8>> {
        Unpack29Encoder::new().encode_member_with_filter(input, Rar29FilterSpec::whole(kind))
    }

    fn encode_with_filter_range(
        input: &[u8],
        kind: Rar29FilterKind,
        range: Range<usize>,
    ) -> Result<Vec<u8>> {
        Unpack29Encoder::new().encode_member_with_filter(input, Rar29FilterSpec::range(kind, range))
    }

    fn encode_with_filter_ranges(
        input: &[u8],
        kind: Rar29FilterKind,
        ranges: Vec<Range<usize>>,
    ) -> Result<Vec<u8>> {
        let filters: Vec<_> = ranges
            .into_iter()
            .map(|range| Rar29FilterSpec::range(kind, range))
            .collect();
        Unpack29Encoder::new().encode_member_with_filters(input, &filters)
    }

    #[test]
    fn encoder_emits_rar29_offset_one_matches_for_repeated_bytes() {
        let input = b"Z".repeat(1024);
        let packed = unpack29_encode_literals(&input).unwrap();

        assert!(packed.len() < input.len() / 4);
        assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_emits_rar29_dictionary_matches_for_repeated_sequences() {
        let input = b"abc123xyz-".repeat(128);
        let packed = unpack29_encode_literals(&input).unwrap();

        assert!(packed.len() < input.len() / 2);
        assert_eq!(unpack29_decode(&packed, input.len()).unwrap(), input);
    }

    #[test]
    fn encoder_finds_rar29_matches_beyond_near_offsets() {
        let phrase = b"long-distance repeated phrase for rar29 low-offset coding.";
        let mut input = Vec::new();
        input.extend_from_slice(phrase);
        input.extend(std::iter::repeat_n(0, 300 * 1024));
        input.extend_from_slice(phrase);
        input.extend_from_slice(phrase);
        let tokens = encode_tokens(&input, &[], EncodeOptions::default());
        let packed = unpack29_encode_literals(&input).unwrap();

        assert!(tokens.iter().any(|token| matches!(
            token,
            EncodeToken::Match { offset, .. } if *offset > 0x40000
        )));
        assert!(packed.len() < input.len());
        let decoded = unpack29_decode(&packed, input.len()).unwrap();
        assert!(
            decoded == input,
            "RAR 2.9 long-distance match round-trip failed"
        );
    }

    #[test]
    fn encoder_emits_rar29_e8_vm_filter_record() {
        let input = b"\xe8\0\0\0\0rar29 e8 filter writer payload\n".repeat(8);
        let packed = encode_with_filter(&input, Rar29FilterKind::E8).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert!(
            decoded == input,
            "RAR 2.9 multi-filter E8 round-trip failed"
        );
    }

    #[test]
    fn encoder_emits_rar29_e8e9_vm_filter_record() {
        let input = b"\xe9\0\0\0\0rar29 e8e9 filter writer payload\n".repeat(8);
        let packed = encode_with_filter(&input, Rar29FilterKind::E8E9).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_rar29_segmented_e8_vm_filter_record() {
        let mut input = b"prefix data that should not be x86 filtered ".to_vec();
        let start = input.len();
        input.extend_from_slice(b"\xe8\0\0\0\0segmented e8 filtered payload\n");
        let end = input.len();
        input.extend_from_slice(b" suffix data that should also remain raw");
        let packed = encode_with_filter_range(&input, Rar29FilterKind::E8, start..end).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_rar29_multiple_e8_vm_filter_records() {
        let mut input = vec![0x41u8; 80_000];
        for cluster_start in [8_000, 60_000] {
            for index in 0..8 {
                let pos = cluster_start + index * 64;
                input[pos] = 0xe8;
                input[pos + 1..pos + 5].copy_from_slice(&(0x2000u32 + index as u32).to_le_bytes());
            }
        }

        let packed = encode_with_filter_ranges(
            &input,
            Rar29FilterKind::E8,
            vec![8_000..8_512, 60_000..60_512],
        )
        .unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_rar29_segmented_e8e9_vm_filter_record() {
        let mut input = b"prefix data that should not be x86 filtered ".to_vec();
        let start = input.len();
        input.extend_from_slice(b"\xe9\0\0\0\0segmented e8e9 filtered payload\n");
        let end = input.len();
        input.extend_from_slice(b" suffix data that should also remain raw");
        let packed = encode_with_filter_range(&input, Rar29FilterKind::E8E9, start..end).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_rar29_delta_vm_filter_record() {
        let input: Vec<u8> = (0..192).map(|index| (index * 13 + 7) as u8).collect();
        let packed = encode_with_filter(&input, Rar29FilterKind::Delta { channels: 3 }).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_rar29_segmented_delta_vm_filter_record() {
        let mut input = b"prefix bytes before delta segment ".to_vec();
        let start = input.len();
        input.extend((0..192).map(|index| (index * 13 + 7) as u8));
        let end = input.len();
        input.extend_from_slice(b" suffix bytes after delta segment");
        let packed =
            encode_with_filter_range(&input, Rar29FilterKind::Delta { channels: 3 }, start..end)
                .unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_rar29_itanium_vm_filter_record() {
        let mut input = vec![0u8; 48];
        input[16] = 22;
        input[21] = 20;
        input.extend_from_slice(b"rar29 itanium filter writer payload\n");
        let packed = encode_with_filter(&input, Rar29FilterKind::Itanium).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_rar29_segmented_itanium_vm_filter_record() {
        let mut input = b"prefix bytes before itanium segment ".to_vec();
        let start = input.len();
        input.extend_from_slice(&[0; 48]);
        input[start + 16] = 22;
        input[start + 21] = 20;
        input.extend_from_slice(b"rar29 segmented itanium filter writer payload\n");
        let end = input.len();
        input.extend_from_slice(b" suffix bytes after itanium segment");
        let packed =
            encode_with_filter_range(&input, Rar29FilterKind::Itanium, start..end).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_rar29_rgb_vm_filter_record() {
        let width = 12;
        let input: Vec<u8> = (0..96).map(|index| (index * 29 + 11) as u8).collect();
        let packed = encode_with_filter(&input, Rar29FilterKind::Rgb { width, pos_r: 0 }).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_rar29_segmented_rgb_vm_filter_record() {
        let width = 12;
        let mut input = b"prefix bytes before rgb segment ".to_vec();
        let start = input.len();
        input.extend((0..96).map(|index| (index * 29 + 11) as u8));
        let end = input.len();
        input.extend_from_slice(b" suffix bytes after rgb segment");
        let packed =
            encode_with_filter_range(&input, Rar29FilterKind::Rgb { width, pos_r: 0 }, start..end)
                .unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_rejects_rar29_rgb_filter_with_unaligned_scanline_width() {
        let input: Vec<u8> = (0..96).map(|index| (index * 29 + 11) as u8).collect();
        assert!(encode_with_filter(&input, Rar29FilterKind::Rgb { width: 8, pos_r: 0 }).is_err());
    }

    #[test]
    fn encoder_emits_rar29_audio_vm_filter_record() {
        let input: Vec<u8> = (0..160)
            .map(|index| (index * 7 + index / 3) as u8)
            .collect();
        let packed = encode_with_filter(&input, Rar29FilterKind::Audio { channels: 2 }).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn audio_filter_bytecode_matches_builtin_transform() {
        let channels = 2;
        let input: Vec<u8> = (0..MAX_VM_AUDIO_FILTER_BLOCK_SIZE)
            .map(|index| (index * 7 + index / channels + index / 257) as u8)
            .collect();
        let encoded = audio_encode(&input, channels).unwrap();
        let program = Program::parse(RAR3_AUDIO_FILTER_BYTECODE).unwrap();
        let result = program
            .execute(super::rarvm::Invocation {
                input: &encoded,
                regs: [channels as u32, 0, 0, 0, 0, 0, 0],
                global_data: &[],
                file_offset: 0,
                exec_count: 0,
            })
            .unwrap();

        assert_eq!(result.output, input);
    }

    #[test]
    fn delta_filter_bytecode_matches_builtin_transform() {
        for channels in [1usize, 3, 4] {
            let input: Vec<u8> = (0..4099)
                .map(|index| (index * 5 + index / channels + index / 131) as u8)
                .collect();
            let mut encoded = input.clone();
            super::filters::encode_in_place(
                super::FilterOp::Delta { channels },
                &mut encoded,
                0,
                super::rar29_delta_messages(),
            )
            .unwrap();
            assert_ne!(encoded, input);
            let mut native = encoded.clone();
            let regs = [channels as u32, 0, 0, 0, 0, 0, 0];
            apply_standard_filter(StandardFilter::Delta, &mut native, 0, &regs).unwrap();
            let result = Program::parse(RAR3_DELTA_FILTER_BYTECODE)
                .unwrap()
                .execute(super::rarvm::Invocation {
                    input: &encoded,
                    regs,
                    global_data: &[],
                    file_offset: 0,
                    exec_count: 0,
                })
                .unwrap();

            assert_eq!(native, input, "channels={channels}");
            assert_eq!(result.output, input, "channels={channels}");
        }
    }

    #[test]
    fn rgb_filter_bytecode_matches_builtin_transform() {
        for (width, pos_r) in [(3usize, 0usize), (12, 1), (30, 2)] {
            let input: Vec<u8> = (0..3000)
                .map(|index| (index * 3 + index / width + index / 97) as u8)
                .collect();
            let encoded = super::rgb_encode(&input, width, pos_r).unwrap();
            assert_ne!(encoded, input);
            let mut native = encoded.clone();
            let regs = [width as u32 + 3, pos_r as u32, 0, 0, 0, 0, 0];
            apply_standard_filter(StandardFilter::Rgb, &mut native, 0, &regs).unwrap();
            let result = Program::parse(RAR3_RGB_FILTER_BYTECODE)
                .unwrap()
                .execute(super::rarvm::Invocation {
                    input: &encoded,
                    regs,
                    global_data: &[],
                    file_offset: 0,
                    exec_count: 0,
                })
                .unwrap();

            assert_eq!(native, input, "width={width} pos_r={pos_r}");
            assert_eq!(result.output, input, "width={width} pos_r={pos_r}");
        }
    }

    #[test]
    fn large_audio_filters_are_split_into_rarvm_safe_blocks() {
        let filters = split_large_filter(
            MAX_VM_FILTER_BLOCK_SIZE * 2 + 123,
            Rar29FilterSpec::whole(Rar29FilterKind::Audio { channels: 4 }),
        )
        .unwrap();

        assert_eq!(filters.len(), 3);
        assert_eq!(filters[0].range, Some(0..MAX_VM_AUDIO_FILTER_BLOCK_SIZE));
        assert_eq!(
            filters[1].range,
            Some(MAX_VM_AUDIO_FILTER_BLOCK_SIZE..MAX_VM_AUDIO_FILTER_BLOCK_SIZE * 2)
        );
        assert_eq!(
            filters[2].range,
            Some(MAX_VM_AUDIO_FILTER_BLOCK_SIZE * 2..MAX_VM_FILTER_BLOCK_SIZE * 2 + 123)
        );
    }

    #[test]
    fn large_delta_filters_are_split_into_rarvm_safe_blocks() {
        let filters = split_large_filter(
            MAX_VM_FILTER_BLOCK_SIZE * 2 + 123,
            Rar29FilterSpec::whole(Rar29FilterKind::Delta { channels: 4 }),
        )
        .unwrap();

        assert_eq!(filters.len(), 3);
        assert_eq!(filters[0].range, Some(0..MAX_VM_DELTA_FILTER_BLOCK_SIZE));
        assert_eq!(
            filters[1].range,
            Some(MAX_VM_DELTA_FILTER_BLOCK_SIZE..MAX_VM_DELTA_FILTER_BLOCK_SIZE * 2)
        );
        assert_eq!(
            filters[2].range,
            Some(MAX_VM_DELTA_FILTER_BLOCK_SIZE * 2..MAX_VM_FILTER_BLOCK_SIZE * 2 + 123)
        );
    }

    #[test]
    fn segmented_audio_filters_redeclare_program_state() {
        let filters = [
            OwnedVmFilterRecord {
                block_start: 0,
                block_size: MAX_VM_AUDIO_FILTER_BLOCK_SIZE,
                init_regs: vec![(0, 4)],
                code: RAR3_AUDIO_FILTER_BYTECODE,
            },
            OwnedVmFilterRecord {
                block_start: MAX_VM_AUDIO_FILTER_BLOCK_SIZE,
                block_size: 4096,
                init_regs: vec![(0, 4)],
                code: RAR3_AUDIO_FILTER_BYTECODE,
            },
        ];
        let records = encoded_filter_records(&filters).unwrap();

        assert_vm_filter_declares_program(&records[0], 0);
        assert_vm_filter_declares_program(&records[1], 2);
    }

    #[test]
    fn encoder_emits_rar29_segmented_audio_vm_filter_record() {
        let mut input = b"prefix bytes before audio segment ".to_vec();
        let start = input.len();
        input.extend((0..160).map(|index| (index * 7 + index / 3) as u8));
        let end = input.len();
        input.extend_from_slice(b" suffix bytes after audio segment");
        let packed =
            encode_with_filter_range(&input, Rar29FilterKind::Audio { channels: 2 }, start..end)
                .unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_multiple_rar29_audio_vm_filter_records_for_large_ranges() {
        let input: Vec<u8> = (0..(MAX_VM_AUDIO_FILTER_BLOCK_SIZE * 2 + 64))
            .map(|index| (index * 7 + index / 3 + index / 257) as u8)
            .collect();
        let packed = encode_with_filter(&input, Rar29FilterKind::Audio { channels: 4 }).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    #[test]
    fn encoder_emits_multiple_rar29_delta_vm_filter_records_for_large_ranges() {
        let input: Vec<u8> = (0..(MAX_VM_DELTA_FILTER_BLOCK_SIZE * 2 + 64))
            .map(|index| (index * 11 + index / 5 + index / 251) as u8)
            .collect();
        let packed = encode_with_filter(&input, Rar29FilterKind::Delta { channels: 4 }).unwrap();
        let decoded = unpack29_decode(&packed, input.len()).unwrap();

        assert_eq!(decoded, input);
    }

    fn assert_vm_filter_declares_program(record: &[u8], expected_selector: u32) {
        let first = record[0];
        assert_ne!(first & 0x80, 0);
        assert_ne!(first & 0x20, 0);
        assert_ne!(first & 0x10, 0);
        let inline_len = match first & 7 {
            len @ 0..=5 => len as usize + 1,
            6 => usize::from(record[1]) + 7,
            _ => u16::from_be_bytes([record[1], record[2]]) as usize,
        };
        let body_start = match first & 7 {
            0..=5 => 1,
            6 => 2,
            _ => 3,
        };
        let body = &record[body_start..body_start + inline_len];
        let mut bits = BitReader::from_bytes(body);
        assert_eq!(bits.read_encoded_u32().unwrap(), expected_selector);
        let _block_start = bits.read_encoded_u32().unwrap();
        let _block_size = bits.read_encoded_u32().unwrap();
        let mask = bits.read_bits(7).unwrap();
        for index in 0..7 {
            if mask & (1 << index) != 0 {
                let _ = bits.read_encoded_u32().unwrap();
            }
        }
        assert_eq!(
            bits.read_encoded_u32().unwrap() as usize,
            RAR3_AUDIO_FILTER_BYTECODE.len()
        );
    }

    #[test]
    fn solid_encoder_emits_rar29_matches_against_previous_member_history() {
        let first = b"solid rar29 shared phrase alpha beta gamma ".repeat(4);
        let second = b"solid rar29 shared phrase alpha beta gamma ".repeat(2);
        let independent = unpack29_encode_literals(&second).unwrap();
        let mut encoder = Unpack29Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(&second).unwrap();

        assert!(second_packed.len() < independent.len());
        let mut decoder = Unpack29::new();
        assert_eq!(
            decoder.decode_member(&first_packed, first.len()).unwrap(),
            first
        );
        assert_eq!(
            decoder.decode_member(&second_packed, second.len()).unwrap(),
            second
        );
    }

    // --- mid-stream refill (item 10 of the 16 Sep 2026 sweep) ---------
    //
    // `decode_member_from_reader` used to drain the whole packed member
    // into the bit reader before decoding a byte. These hold the refill
    // that replaced it to the buffered path it has to be identical to,
    // in OUTPUT and in carried STATE, and hold its retained input to the
    // window.

    /// A reader that hands out at most `chunk` bytes per call, so the
    /// refill never gets what it asked for in one go.
    struct ChunkyReader<'a> {
        input: &'a [u8],
        chunk: usize,
    }

    impl std::io::Read for ChunkyReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let len = self.input.len().min(out.len()).min(self.chunk);
            out[..len].copy_from_slice(&self.input[..len]);
            self.input = &self.input[len..];
            Ok(len)
        }
    }

    /// Mixed literal/match content that does not collapse under LZ, so the
    /// packed member is big enough to cross a refill window several times.
    fn refill_corpus(bytes: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(bytes + 8192);
        let mut x = 0x1234_5678u32;
        while data.len() < bytes {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            data.extend_from_slice(&x.to_le_bytes());
            if x % 97 == 0 {
                let end = data.len();
                let at = end.saturating_sub(4096);
                data.extend_from_within(at..end);
            }
        }
        data
    }

    fn decode_buffered(packed: &[u8], size: usize) -> (Vec<u8>, Rar29State) {
        let mut decoder = Unpack29::new();
        let mut out = Vec::new();
        decoder.decode_member_to(packed, size, &mut out).unwrap();
        let state = decoder.state_digest();
        (out, state)
    }

    fn decode_streamed(
        packed: &[u8],
        size: usize,
        bounds: Option<(usize, usize)>,
        chunk: usize,
    ) -> (Vec<u8>, Rar29State, usize) {
        let mut decoder = Unpack29::new();
        if let Some((window, margin)) = bounds {
            decoder.set_stream_bounds(window, margin);
        }
        let mut reader = ChunkyReader {
            input: packed,
            chunk,
        };
        let mut out = Vec::new();
        decoder
            .decode_member_from_reader(&mut reader, size, &mut out)
            .unwrap();
        assert!(
            decoder.filters.is_empty(),
            "the shrunken margin is only sound for a member with no VM filter"
        );
        let state = decoder.state_digest();
        let peak = decoder.peak_packed_input();
        (out, state, peak)
    }

    #[test]
    fn streaming_refill_matches_the_buffered_decode_in_bytes_and_in_state() {
        let data = refill_corpus(2 * 1024 * 1024);
        let packed = Unpack29Encoder::new().encode_member(&data).unwrap();
        // Many refills: a 32 KiB window over a ~240 KiB packed member.
        let window = 32 * 1024;
        let margin = 8 * 1024;
        assert!(packed.len() > 6 * window, "packed {}", packed.len());

        let (buffered, buffered_state) = decode_buffered(&packed, data.len());
        let (streamed, streamed_state, peak) =
            decode_streamed(&packed, data.len(), Some((window, margin)), 7000);

        assert_eq!(buffered, data);
        assert_eq!(streamed, buffered);
        assert_eq!(streamed_state, buffered_state);
        assert!(
            peak <= window + margin + 4096,
            "retained {peak} packed bytes against a {window} byte window"
        );
    }

    #[test]
    fn streaming_refill_holds_the_window_at_the_shipped_bounds() {
        // The knobbed tests above prove the boundary; this one proves the
        // SHIPPED constants bound a member whose packed size is past them,
        // with no knob in the way.
        let data = refill_corpus(12 * 1024 * 1024);
        let packed = Unpack29Encoder::new().encode_member(&data).unwrap();
        assert!(
            packed.len() > STREAM_INPUT_WINDOW + STREAM_INPUT_MARGIN,
            "packed {} does not cross the shipped window",
            packed.len()
        );

        let (buffered, buffered_state) = decode_buffered(&packed, data.len());
        let (streamed, streamed_state, peak) =
            decode_streamed(&packed, data.len(), None, usize::MAX);

        assert_eq!(streamed, buffered);
        assert_eq!(streamed_state, buffered_state);
        assert!(
            peak <= STREAM_INPUT_WINDOW + STREAM_INPUT_MARGIN + 4096,
            "retained {peak} of {} packed bytes",
            packed.len()
        );
    }

    #[test]
    fn the_state_digest_sees_a_decoder_that_stopped_somewhere_else() {
        // A negative control for the check above: a digest that cannot
        // tell two states apart proves nothing when it matches. Same
        // output prefix, different carried state.
        let data = refill_corpus(256 * 1024);
        let packed = Unpack29Encoder::new().encode_member(&data).unwrap();
        let (_, whole) = decode_buffered(&packed, data.len());

        let mut decoder = Unpack29::new();
        let mut out = Vec::new();
        decoder
            .decode_member_to(&packed, data.len(), &mut out)
            .unwrap();
        let same = decoder.state_digest();
        assert_eq!(same, whole);

        let mut partial = Unpack29::new();
        let mut short = Vec::new();
        partial
            .decode_member_to(&packed, data.len() - 4096, &mut short)
            .unwrap_err();
        let stopped = partial.state_digest();
        assert_ne!(stopped, whole);
        assert_ne!(stopped.consumed_bits, whole.consumed_bits);
        assert_ne!(stopped.history, whole.history);
    }

    #[test]
    fn streaming_refill_carries_solid_history_into_the_next_member() {
        // The state that a refill boundary could plausibly corrupt is the
        // state a LATER member reads. Decode two solid members both ways
        // and compare after each.
        let first = refill_corpus(1024 * 1024);
        let mut second = first[4096..8192].repeat(48);
        second.extend_from_slice(&refill_corpus(64 * 1024));
        let mut encoder = Unpack29Encoder::new();
        let first_packed = encoder.encode_member(&first).unwrap();
        let second_packed = encoder.encode_member(&second).unwrap();

        let mut buffered = Unpack29::new();
        let mut buffered_out = Vec::new();
        buffered
            .decode_member_to(&first_packed, first.len(), &mut buffered_out)
            .unwrap();
        let buffered_between = buffered.state_digest();
        buffered
            .decode_member_to(&second_packed, second.len(), &mut buffered_out)
            .unwrap();

        let mut streamed = Unpack29::new();
        streamed.set_stream_bounds(32 * 1024, 8 * 1024);
        let mut streamed_out = Vec::new();
        streamed
            .decode_member_from_reader(
                &mut ChunkyReader {
                    input: &first_packed,
                    chunk: 5000,
                },
                first.len(),
                &mut streamed_out,
            )
            .unwrap();
        assert_eq!(streamed.state_digest(), buffered_between);
        streamed.set_stream_bounds(32 * 1024, 8 * 1024);
        streamed
            .decode_member_from_reader(
                &mut ChunkyReader {
                    input: &second_packed,
                    chunk: 5000,
                },
                second.len(),
                &mut streamed_out,
            )
            .unwrap();

        let mut whole = first.clone();
        whole.extend_from_slice(&second);
        assert_eq!(buffered_out, whole);
        assert_eq!(streamed_out, buffered_out);
        assert_eq!(streamed.state_digest(), buffered.state_digest());
        assert!(streamed.filters.is_empty());
    }

    #[test]
    fn streaming_refill_decodes_a_filtered_member_at_the_shipped_margin() {
        // A VM filter is the one excursion the margin is sized for
        // (`read_vm_code` reads its length before `MAX_VM_CODE_SIZE` is
        // checked), and `filtered_range` is the one flush the streaming
        // loop reaches differently. No knob here: the shipped margin is
        // the claim under test.
        let data = refill_corpus(18 * 1024 * 1024);
        let packed = encode_with_filter(&data, Rar29FilterKind::E8).unwrap();
        assert!(
            packed.len() > STREAM_INPUT_WINDOW,
            "packed {} does not cross the shipped window",
            packed.len()
        );

        let mut buffered = Unpack29::new();
        let mut buffered_out = Vec::new();
        buffered
            .decode_member_to(&packed, data.len(), &mut buffered_out)
            .unwrap();

        let mut streamed = Unpack29::new();
        let mut streamed_out = Vec::new();
        streamed
            .decode_member_from_reader(
                &mut ChunkyReader {
                    input: &packed,
                    chunk: 100_000,
                },
                data.len(),
                &mut streamed_out,
            )
            .unwrap();

        assert_eq!(streamed_out, buffered_out);
        assert_eq!(streamed.state_digest(), buffered.state_digest());
        assert!(
            streamed.peak_packed_input()
                <= STREAM_INPUT_WINDOW + STREAM_INPUT_MARGIN + 4096,
            "retained {} of {} packed bytes",
            streamed.peak_packed_input(),
            packed.len()
        );
    }

    #[test]
    fn a_ppmd_block_falls_back_to_buffering_and_decodes_identically() {
        let mut input = b"rar29 ppmd literal text payload alpha beta gamma\n".repeat(64);
        input.extend_from_slice(&[2, 2, 2, b'e', b's', b'c']);
        let packed = unpack29_encode_ppmd_literals(&input).unwrap();

        let mut buffered = Unpack29::new();
        let mut buffered_out = Vec::new();
        buffered
            .decode_member_to(&packed, input.len(), &mut buffered_out)
            .unwrap();

        let mut streamed = Unpack29::new();
        let mut streamed_out = Vec::new();
        streamed
            .decode_member_from_reader(
                &mut ChunkyReader {
                    input: &packed,
                    chunk: 3,
                },
                input.len(),
                &mut streamed_out,
            )
            .unwrap();

        assert_eq!(buffered_out, input);
        assert_eq!(streamed_out, buffered_out);
        assert_eq!(streamed.state_digest(), buffered.state_digest());
        assert_eq!(streamed.block_mode, BlockMode::Ppmd);
        // The fallback is what makes it correct: streaming is off by the
        // end, because PPMd cannot be paused at a provable boundary.
        assert!(!streamed.stream_refill);
    }

    #[test]
    fn a_truncated_streamed_member_is_refused_rather_than_padded() {
        let data = refill_corpus(512 * 1024);
        let packed = Unpack29Encoder::new().encode_member(&data).unwrap();
        let cut = &packed[..packed.len() / 2];

        let mut decoder = Unpack29::new();
        decoder.set_stream_bounds(32 * 1024, 8 * 1024);
        let mut out = Vec::new();
        let error = decoder
            .decode_member_from_reader(
                &mut ChunkyReader {
                    input: cut,
                    chunk: 1000,
                },
                data.len(),
                &mut out,
            )
            .unwrap_err();

        assert_eq!(
            error,
            Error::InvalidData("RAR 2.9 bitstream is truncated"),
            "a short reader must read as truncation, never as EOF padding"
        );
    }

    #[test]
    fn the_streamed_reader_is_still_drained_to_eof() {
        // The chase publishes its consumption watermark off this reader,
        // so the member must leave it where `read_to_end` used to.
        struct CountingReader<'a> {
            input: &'a [u8],
            eof_reads: usize,
        }

        impl std::io::Read for CountingReader<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.input.is_empty() {
                    self.eof_reads += 1;
                    return Ok(0);
                }
                let len = self.input.len().min(out.len()).min(1024);
                out[..len].copy_from_slice(&self.input[..len]);
                self.input = &self.input[len..];
                Ok(len)
            }
        }

        let data = refill_corpus(512 * 1024);
        let mut packed = Unpack29Encoder::new().encode_member(&data).unwrap();
        // Trailing filler past the member, exactly what read_to_end used
        // to swallow.
        packed.extend_from_slice(&[0u8; 8192]);

        let mut decoder = Unpack29::new();
        decoder.set_stream_bounds(32 * 1024, 8 * 1024);
        let mut reader = CountingReader {
            input: &packed,
            eof_reads: 0,
        };
        let mut out = Vec::new();
        decoder
            .decode_member_from_reader(&mut reader, data.len(), &mut out)
            .unwrap();

        assert_eq!(out, data);
        assert!(reader.input.is_empty(), "the reader was left unread");
        assert!(reader.eof_reads >= 1);
    }

    #[test]
    fn decode_member_from_reader_accepts_incremental_input() {
        struct TinyReader<'a> {
            input: &'a [u8],
        }

        impl std::io::Read for TinyReader<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.input.is_empty() {
                    return Ok(0);
                }
                let len = self.input.len().min(out.len()).min(3);
                out[..len].copy_from_slice(&self.input[..len]);
                self.input = &self.input[len..];
                Ok(len)
            }
        }

        let mut decoder = Unpack29::new();
        let mut reader = TinyReader {
            input: COMPRESSED_TEXT,
        };
        let mut output = Vec::new();
        decoder
            .decode_member_from_reader(&mut reader, 2400, &mut output)
            .unwrap();

        assert_eq!(output, expected_text());
    }

    #[test]
    fn decode_non_solid_member_resets_reusable_decoder_state() {
        let mut decoder = Unpack29::new();
        decoder.output.extend_from_slice(b"stale history");
        decoder.filters.push(VmFilter {
            program: 0,
            start: 0,
            size: 1,
            regs: [0; 7],
            global_data: vec![1, 2, 3],
        });

        let output = decoder
            .decode_non_solid_member(COMPRESSED_TEXT, 2400)
            .unwrap();

        assert_eq!(output, expected_text());
        assert!(decoder.filters.is_empty());
    }

    #[test]
    fn e8_filter_uses_member_relative_offset_in_solid_stream() {
        let mut decoder = Unpack29::new();
        let member_start = 1000usize;
        let filter_start = member_start + 100;
        decoder.output.resize(filter_start + 8, 0);
        decoder.output[filter_start] = 0xe8;

        let call_operand_pos = 1u32;
        let member_relative_filter_start = (filter_start - member_start) as u32;
        let decoded_addr = 0x2000u32;
        let encoded_addr = decoded_addr
            .wrapping_add(member_relative_filter_start)
            .wrapping_add(call_operand_pos);
        decoder.output[filter_start + 1..filter_start + 5]
            .copy_from_slice(&encoded_addr.to_le_bytes());
        decoder.programs.push(VmProgram {
            kind: VmProgramKind::Standard(StandardFilter::E8),
            block_size: 5,
            exec_count: 0,
            globals: Vec::new(),
        });
        decoder.filters.push(VmFilter {
            program: 0,
            start: filter_start,
            size: 5,
            regs: [0; 7],
            global_data: Vec::new(),
        });

        let filtered = decoder
            .filtered_range(member_start, filter_start + 5, member_start)
            .unwrap();
        let operand =
            u32::from_le_bytes([filtered[101], filtered[102], filtered[103], filtered[104]]);

        assert_eq!(operand, decoded_addr);
    }

    #[test]
    fn generic_vm_filter_executes_from_filtered_range() {
        let mut decoder = Unpack29::new();
        decoder.output.extend_from_slice(&[0x11, 0x22, 0x33]);
        decoder.programs.push(VmProgram {
            kind: VmProgramKind::Generic(Program {
                static_data: Vec::new(),
                instructions: vec![
                    Instruction {
                        opcode: Opcode::Mov,
                        byte_mode: true,
                        operands: vec![Operand::Absolute(0), Operand::Immediate(0x44)],
                    },
                    Instruction {
                        opcode: Opcode::Ret,
                        byte_mode: false,
                        operands: Vec::new(),
                    },
                ],
            }),
            block_size: 3,
            exec_count: 0,
            globals: Vec::new(),
        });
        decoder.filters.push(VmFilter {
            program: 0,
            start: 0,
            size: 3,
            regs: [0; 7],
            global_data: Vec::new(),
        });

        let filtered = decoder.filtered_range(0, 3, 0).unwrap();

        assert_eq!(filtered, [0x44, 0x22, 0x33]);
    }

    #[test]
    fn standard_filters_reject_malformed_delta_and_rgb_registers() {
        let mut delta = vec![0; 32];
        let mut delta_regs = [0; 7];
        delta_regs[0] = 33;
        assert_eq!(
            apply_standard_filter(StandardFilter::Delta, &mut delta, 0, &delta_regs),
            Err(Error::InvalidData(
                "RAR 2.9 DELTA filter channel count is invalid"
            ))
        );

        let mut rgb = vec![0; 32];
        let mut rgb_regs = [0; 7];
        rgb_regs[0] = 2;
        assert_eq!(
            apply_standard_filter(StandardFilter::Rgb, &mut rgb, 0, &rgb_regs),
            Err(Error::InvalidData(
                "RAR 2.9 RGB filter parameters are invalid"
            ))
        );
        rgb_regs[0] = 15;
        rgb_regs[1] = 3;
        assert_eq!(
            apply_standard_filter(StandardFilter::Rgb, &mut rgb, 0, &rgb_regs),
            Err(Error::InvalidData(
                "RAR 2.9 RGB filter parameters are invalid"
            ))
        );
    }

    #[test]
    fn vm_encoded_u32_accepts_32_bit_form() {
        let mut bits = super::BitReader::from_bytes(&[0xff; 5]);

        assert_eq!(bits.read_encoded_u32().unwrap(), 0xffff_ffff);
    }

    #[test]
    fn vm_global_data_size_does_not_reserve_untrusted_declared_size() {
        let mut decoder = Unpack29::new();
        decoder.programs.push(VmProgram {
            kind: VmProgramKind::Standard(StandardFilter::E8),
            block_size: 1,
            exec_count: 0,
            globals: Vec::new(),
        });

        let mut data = BitWriter::default();
        data.write_encoded_u32(1);
        data.write_encoded_u32(0);
        data.write_encoded_u32(u32::MAX);

        assert_eq!(
            decoder.parse_vm_code(0x80 | 0x08, data.finish()),
            Err(Error::NeedMoreInput)
        );
    }

    /// nzbfast: a RAR 3 VM filter block is declared as a bare u32 on the
    /// wire, and a filter HOLDS output: `safe_flush_end` will not flush
    /// past a filter's start until its end is decoded, and `trim_history`
    /// keeps `keep_from <= flushed`, so nothing drains either. A member
    /// declaring `block_start = 0` and a 2 GiB block grew `self.output`
    /// to the whole member's output, and `filtered_range` then copied
    /// that block AGAIN for the VM: about 4 GiB of peak from a few MB of
    /// packed input. RAR5 refuses the equivalent in `add_filter`; RAR3
    /// had no bail and no buffered fallback.
    ///
    /// NEGATIVE CONTROL, run: remove the `MAX_VM_FILTER_HOLD` check from
    /// `parse_vm_code` and this test fails with `Ok(())`.
    #[test]
    fn vm_filter_block_size_is_capped_before_it_can_hold_the_member() {
        let oversized = |declared: u32| {
            let mut decoder = Unpack29::new();
            let mut data = BitWriter::default();
            data.write_encoded_u32(0); // program index (0 = a fresh one)
            data.write_encoded_u32(0); // block start
            data.write_encoded_u32(declared); // block size
            // 0x80: new program; 0x20: the block size is declared here.
            decoder.parse_vm_code(0x80 | 0x20, data.finish())
        };

        assert_eq!(
            oversized((super::MAX_VM_FILTER_HOLD + 1) as u32),
            Err(Error::InvalidData(
                "RAR 2.9 VM filter block is too large to hold"
            ))
        );
        assert_eq!(
            oversized(u32::MAX),
            Err(Error::InvalidData(
                "RAR 2.9 VM filter block is too large to hold"
            ))
        );
        // A block at the ceiling is NOT refused for its size - it runs on
        // into the code-size parse and fails there for want of input, so
        // the cap is what it says and not a lower one.
        assert_ne!(
            oversized(super::MAX_VM_FILTER_HOLD as u32),
            Err(Error::InvalidData(
                "RAR 2.9 VM filter block is too large to hold"
            ))
        );
        // And a real filter block, which lives inside RARVM memory
        // (0x3c000), is nowhere near it.
        assert_ne!(
            oversized(0x3c000),
            Err(Error::InvalidData(
                "RAR 2.9 VM filter block is too large to hold"
            ))
        );
    }

    #[test]
    fn vm_code_size_is_capped_before_allocation() {
        let mut decoder = Unpack29::new();
        let mut data = BitWriter::default();
        data.write_encoded_u32(0);
        data.write_encoded_u32(1);
        data.write_encoded_u32((super::MAX_VM_CODE_SIZE + 1) as u32);

        assert_eq!(
            decoder.parse_vm_code(0x80, data.finish()),
            Err(Error::InvalidData("RAR 2.9 VM code is too large"))
        );
    }

    #[test]
    fn vm_program_and_filter_counts_are_capped() {
        let mut decoder = Unpack29::new();
        decoder
            .programs
            .resize_with(super::MAX_VM_PROGRAMS, || VmProgram {
                kind: VmProgramKind::Standard(StandardFilter::E8),
                block_size: 1,
                exec_count: 0,
                globals: Vec::new(),
            });

        let mut new_program = BitWriter::default();
        new_program.write_encoded_u32((super::MAX_VM_PROGRAMS + 1) as u32);
        new_program.write_encoded_u32(1);
        new_program.write_encoded_u32(1);
        new_program.write_bits(0, 8);
        assert_eq!(
            decoder.parse_vm_code(0x80, new_program.finish()),
            Err(Error::InvalidData("RAR 2.9 VM program limit exceeded"))
        );

        decoder.programs.truncate(1);
        decoder.last_filter = 0;
        decoder
            .filters
            .resize_with(super::MAX_VM_FILTERS, || VmFilter {
                program: 0,
                start: 0,
                size: 1,
                regs: [0; 7],
                global_data: Vec::new(),
            });
        let mut reused_program = BitWriter::default();
        reused_program.write_encoded_u32(0);
        assert_eq!(
            decoder.parse_vm_code(0, reused_program.finish()),
            Err(Error::InvalidData("RAR 2.9 VM filter limit exceeded"))
        );
    }

    #[test]
    fn itanium_filter_round_trips_with_high_file_offset() {
        let mut data = vec![0u8; 64];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = index as u8;
        }
        data[0] = 0;
        data[7] = 5 << 3;
        let original = data.clone();

        itanium_encode(&mut data, u32::MAX);
        itanium_decode(&mut data, u32::MAX);

        assert_eq!(data, original);
    }

    fn expected_text() -> Vec<u8> {
        "Hello, RAR 3.x fixture world.\n".repeat(80).into_bytes()
    }
}

