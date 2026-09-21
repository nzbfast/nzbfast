use super::address_filters::{self, Direction, X86Format, X86Opcodes};
use super::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterOp {
    E8,
    E8E9,
    Delta { channels: usize },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeltaErrorMessages {
    pub invalid_channels: &'static str,
    pub zero_channels: &'static str,
    pub truncated_source: &'static str,
}

#[cfg(test)]
pub(crate) fn encode(op: FilterOp, data: &[u8], file_offset: u32) -> Result<Vec<u8>> {
    encode_with_messages(op, data, file_offset, DeltaErrorMessages::generic())
}

#[cfg(test)]
pub(crate) fn encode_with_messages(
    op: FilterOp,
    data: &[u8],
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<Vec<u8>> {
    match op {
        FilterOp::E8 | FilterOp::E8E9 => {
            let mut out = data.to_vec();
            address_filters::x86(
                &mut out,
                file_offset,
                Direction::Encode,
                rar3_x86_opcodes(op),
                X86Format::Rar3,
            );
            Ok(out)
        }
        FilterOp::Delta { channels } => delta_encode(data, channels, messages),
    }
}

pub(crate) fn encode_in_place(
    op: FilterOp,
    data: &mut [u8],
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<()> {
    match op {
        FilterOp::E8 | FilterOp::E8E9 => address_filters::x86(
            data,
            file_offset,
            Direction::Encode,
            rar3_x86_opcodes(op),
            X86Format::Rar3,
        ),
        // nzbfast-local change, 5 Sep 2026 — no transpose or scratch is
        // needed for a single channel. See VENDORING.md.
        FilterOp::Delta { channels: 1 } => delta_encode_one_channel(data),
        FilterOp::Delta { channels } => {
            let encoded = delta_encode(data, channels, messages)?;
            data.copy_from_slice(&encoded);
        }
    }
    Ok(())
}

pub(crate) fn decode_in_place(
    op: FilterOp,
    data: &mut Vec<u8>,
    file_offset: u32,
    messages: DeltaErrorMessages,
) -> Result<()> {
    match op {
        FilterOp::E8 | FilterOp::E8E9 => address_filters::x86(
            data,
            file_offset,
            Direction::Decode,
            rar3_x86_opcodes(op),
            X86Format::Rar3,
        ),
        FilterOp::Delta { channels } => {
            *data = delta_decode(data, channels, messages)?;
        }
    }
    Ok(())
}

/// The RAR 3 standard x86 programs: E8 converts calls, E8E9 calls and jumps.
fn rar3_x86_opcodes(op: FilterOp) -> X86Opcodes {
    if op == FilterOp::E8E9 {
        X86Opcodes::CallAndJump
    } else {
        X86Opcodes::Call
    }
}

/// The allocating shape, for the RAR 2.9 filter path and the tests: one
/// fresh buffer per call. The RAR 5 decoders take [`delta_decode_into`].
pub(crate) fn delta_decode(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    delta_decode_into(data, channels, messages, &mut out)?;
    Ok(out)
}

/// Delta-decode `data` into `out`, whose initialized length is grown or
/// truncated to `data.len()` and then fully rewritten. The decode cannot
/// run in place - it walks the source serially and the destination by a
/// stride of `channels`, so a byte it has yet to read may already have
/// been overwritten - but the buffer it needs does not have to be a fresh
/// one. Every RAR 5 filter block used to allocate and zero its own; the
/// decoders now carry one across the whole member. Keeping the initialized
/// prefix also avoids zero-filling
/// bytes that the channel reconstruction immediately overwrites.
/// Common channel counts reconstruct contiguous output rows from separate
/// source planes. Other counts validate each contiguous source slice and use
/// a strided destination iterator without loop-carried source/destination indexes.
/// (nzbfast-local change, 20 Aug, 3 Sep and 5 Sep 2026 - re-apply on the next
/// rars re-sync, see vendor/rars/VENDORING.md.)
pub(crate) fn delta_decode_into(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
    out: &mut Vec<u8>,
) -> Result<()> {
    if channels == 0 {
        return Err(Error::InvalidData(messages.zero_channels));
    }
    if channels > 32 {
        return Err(Error::InvalidData(messages.invalid_channels));
    }
    if out.len() < data.len() {
        out.resize(data.len(), 0);
    } else {
        out.truncate(data.len());
    }
    match channels {
        2 => {
            delta_rows::<2>(data, out);
            return Ok(());
        }
        3 => {
            delta_rows::<3>(data, out);
            return Ok(());
        }
        4 => {
            delta_rows::<4>(data, out);
            return Ok(());
        }
        _ => {}
    }
    let mut encoded = data;
    for channel in 0..channels.min(out.len()) {
        let count = (out.len() - channel).div_ceil(channels);
        let channel_data = encoded
            .get(..count)
            .ok_or(Error::InvalidData(messages.truncated_source))?;
        let mut prev = 0u8;
        for (dest, &byte) in out[channel..]
            .iter_mut()
            .step_by(channels)
            .zip(channel_data)
        {
            prev = prev.wrapping_sub(byte);
            *dest = prev;
        }
        encoded = &encoded[count..];
    }
    debug_assert!(encoded.is_empty());
    Ok(())
}

// nzbfast-local change, 5 Sep 2026 — reconstruct common channel counts
// a row at a time. Independent channel accumulators shorten the dependency
// chain while contiguous output stores avoid revisiting each cache line.
// Keep the generic channel-major path for other counts; see VENDORING.md.
fn delta_rows<const N: usize>(data: &[u8], out: &mut [u8]) {
    // The first len % N planes contain one extra byte. Splitting by these
    // exact counts keeps both full rows and a partial final row in bounds.
    let mut encoded = data;
    let mut planes = [&[][..]; N];
    for (channel, plane) in planes.iter_mut().enumerate() {
        let count = data.len() / N + usize::from(channel < data.len() % N);
        (*plane, encoded) = encoded.split_at(count);
    }
    let mut prev = [0u8; N];
    let mut rows = out.chunks_exact_mut(N);
    for (row, dest) in rows.by_ref().enumerate() {
        for channel in 0..N {
            prev[channel] = prev[channel].wrapping_sub(planes[channel][row]);
            dest[channel] = prev[channel];
        }
    }
    for (channel, dest) in rows.into_remainder().iter_mut().enumerate() {
        *dest = prev[channel].wrapping_sub(planes[channel][data.len() / N]);
    }
}

// Keep this vectorizable loop out of the shared filter dispatcher. Inlining
// it regressed multi-channel encoding in the measured release build.
#[inline(never)]
fn delta_encode_one_channel(data: &mut [u8]) {
    let mut prev = 0u8;
    for byte in data {
        let current = *byte;
        *byte = prev.wrapping_sub(current);
        prev = current;
    }
}

pub(crate) fn delta_encode(
    data: &[u8],
    channels: usize,
    messages: DeltaErrorMessages,
) -> Result<Vec<u8>> {
    if channels == 0 || channels > 32 {
        return Err(Error::InvalidData(messages.invalid_channels));
    }
    let mut out = Vec::with_capacity(data.len());
    for channel in 0..channels {
        let mut prev = 0u8;
        let mut src = channel;
        while src < data.len() {
            let byte = data[src];
            out.push(prev.wrapping_sub(byte));
            prev = byte;
            src += channels;
        }
    }
    Ok(out)
}

impl DeltaErrorMessages {
    #[cfg(test)]
    pub(crate) const fn generic() -> Self {
        Self {
            invalid_channels: "DELTA filter channel count is invalid",
            zero_channels: "DELTA filter has zero channels",
            truncated_source: "DELTA filter source is truncated",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_single_channel_in_place_matches_scalar_at_vector_boundaries() {
        for len in (0..=129).chain([255, 256, 257, 4095, 4096, 4097, 65539]) {
            let data: Vec<u8> = (0..len).map(|i| ((i * 179 + i / 3) & 255) as u8).collect();
            let mut prev = 0u8;
            let expected: Vec<u8> = data
                .iter()
                .map(|&byte| {
                    let encoded = prev.wrapping_sub(byte);
                    prev = byte;
                    encoded
                })
                .collect();
            let mut actual = data.clone();
            encode_in_place(
                FilterOp::Delta { channels: 1 },
                &mut actual,
                0,
                DeltaErrorMessages::generic(),
            )
            .unwrap();
            assert_eq!(actual, expected);
            let mut decoded = Vec::new();
            delta_decode_into(&actual, 1, DeltaErrorMessages::generic(), &mut decoded).unwrap();
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn delta_rows_match_scalar_through_partial_rows_and_reused_buffers() {
        let mut scratch = vec![0xa5; 1000];
        for channels in 1..=32 {
            for len in (0..=129).chain([255, 256, 257, 4095, 4096, 4097, 65539]) {
                let data: Vec<u8> = (0..len).map(|i| ((i * 179 + i / 3) & 255) as u8).collect();
                let expected = reference_delta_decode(&data, channels);
                delta_decode_into(&data, channels, DeltaErrorMessages::generic(), &mut scratch)
                    .unwrap();
                assert_eq!(scratch, expected, "channels={channels}, len={len}");
            }
        }
        for channels in [0, 33, usize::MAX] {
            let before = scratch.clone();
            assert!(delta_decode_into(
                &[1, 2, 3],
                channels,
                DeltaErrorMessages::generic(),
                &mut scratch
            )
            .is_err());
            assert_eq!(scratch, before);
        }
    }

    fn x86_sample() -> Vec<u8> {
        let mut data = b"prefix ".to_vec();
        data.extend_from_slice(&[0xe8, 0x10, 0x20, 0x00, 0x00]);
        data.extend_from_slice(b" middle ");
        data.extend_from_slice(&[0xe9, 0xf0, 0xff, 0xff, 0xff]);
        data.extend_from_slice(b" suffix");
        data
    }

    fn reference_delta_decode(data: &[u8], channels: usize) -> Vec<u8> {
        let mut out = vec![0; data.len()];
        let mut src = 0usize;
        for channel in 0..channels {
            let mut prev = 0u8;
            let mut dest = channel;
            while dest < out.len() {
                prev = prev.wrapping_sub(data[src]);
                out[dest] = prev;
                src += 1;
                dest += channels;
            }
        }
        out
    }

    #[test]
    fn e8_transform_round_trips_representative_bytes() {
        let input = x86_sample();
        let mut filtered = encode(FilterOp::E8, &input, 4096).unwrap();

        decode_in_place(
            FilterOp::E8,
            &mut filtered,
            4096,
            DeltaErrorMessages::generic(),
        )
        .unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn e8e9_transform_round_trips_representative_bytes() {
        let input = x86_sample();
        let mut filtered = encode(FilterOp::E8E9, &input, 8192).unwrap();

        decode_in_place(
            FilterOp::E8E9,
            &mut filtered,
            8192,
            DeltaErrorMessages::generic(),
        )
        .unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn delta_transform_round_trips_interleaved_channels() {
        let input = b"abcdefghijklmnopqrstuvwxyz0123456789".repeat(3);
        let mut filtered = encode(FilterOp::Delta { channels: 3 }, &input, 0).unwrap();

        decode_in_place(
            FilterOp::Delta { channels: 3 },
            &mut filtered,
            0,
            DeltaErrorMessages::generic(),
        )
        .unwrap();

        assert_eq!(filtered, input);
    }

    #[test]
    fn delta_decode_rejects_channel_counts_above_writer_limit() {
        let mut filtered = vec![0; 64];

        assert_eq!(
            decode_in_place(
                FilterOp::Delta { channels: 33 },
                &mut filtered,
                0,
                DeltaErrorMessages::generic(),
            ),
            Err(Error::InvalidData("DELTA filter channel count is invalid"))
        );
    }

    /// The scratch-reusing decode must be byte-identical to an independent
    /// scalar reconstruction, INCLUDING when the buffer it is handed is
    /// longer than the block and full of somebody else's bytes - which is
    /// exactly what the second and every later block of a member sees.
    #[test]
    fn delta_decode_into_matches_scalar_on_a_dirty_buffer() {
        let mut scratch = Vec::new();
        for channels in 1..=32usize {
            for len in [0usize, 1, 5, 31, 64, 257, 4096] {
                // Deterministic pseudo-random bytes: a filter block is
                // arbitrary compressed output, not a pattern.
                let data: Vec<u8> = (0..len)
                    .map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8)
                    .collect();
                let expected = reference_delta_decode(&data, channels);
                // Exercise growth, exact reuse, and truncation. All
                // initialized bytes are dirty so a decode that failed to
                // rewrite even one byte would read back the stale one.
                for initial_len in [len.saturating_sub(1), len, len + 997] {
                    scratch.clear();
                    scratch.resize(initial_len, 0xa5);
                    delta_decode_into(&data, channels, DeltaErrorMessages::generic(), &mut scratch)
                        .unwrap();
                    assert_eq!(
                        scratch, expected,
                        "channels={channels} len={len} initial_len={initial_len}"
                    );
                }
            }
        }
    }

    #[test]
    fn encode_in_place_matches_allocating_encode() {
        let input = x86_sample();
        let expected = encode(FilterOp::E8E9, &input, 1234).unwrap();
        let mut actual = input;

        encode_in_place(
            FilterOp::E8E9,
            &mut actual,
            1234,
            DeltaErrorMessages::generic(),
        )
        .unwrap();

        assert_eq!(actual, expected);
    }
}
