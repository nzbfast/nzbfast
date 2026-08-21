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
        FilterOp::E8 => {
            let mut out = data.to_vec();
            e8e9_encode(&mut out, file_offset, false);
            Ok(out)
        }
        FilterOp::E8E9 => {
            let mut out = data.to_vec();
            e8e9_encode(&mut out, file_offset, true);
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
        FilterOp::E8 => e8e9_encode(data, file_offset, false),
        FilterOp::E8E9 => e8e9_encode(data, file_offset, true),
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
        FilterOp::E8 => e8e9_decode(data, file_offset, false),
        FilterOp::E8E9 => e8e9_decode(data, file_offset, true),
        FilterOp::Delta { channels } => {
            *data = delta_decode(data, channels, messages)?;
        }
    }
    Ok(())
}

pub(crate) fn e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask) {
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32);
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let new_addr = if addr < 0x0100_0000 {
            Some(addr.wrapping_sub(offset))
        } else if addr & 0x8000_0000 != 0 && addr.wrapping_add(offset) & 0x8000_0000 == 0 {
            Some(addr.wrapping_add(0x0100_0000))
        } else {
            None
        };
        if let Some(value) = new_addr {
            data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
        }
        opcode_pos = pos + 5;
    }
}

pub(crate) fn e8e9_encode(data: &mut [u8], file_offset: u32, include_e9: bool) {
    if data.len() <= 4 {
        return;
    }
    let cmp_mask = if include_e9 { 0xfe } else { 0xff };
    let opcode_limit = data.len() - 4;
    let mut opcode_pos = 0usize;
    while let Some(pos) = super::fast::next_x86_opcode(data, opcode_pos, opcode_limit, cmp_mask) {
        let cur_pos = pos + 1;
        let offset = file_offset.wrapping_add(cur_pos as u32);
        let addr = u32::from_le_bytes([
            data[cur_pos],
            data[cur_pos + 1],
            data[cur_pos + 2],
            data[cur_pos + 3],
        ]);
        let candidate = addr.wrapping_add(offset);
        if candidate < 0x0100_0000 {
            data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
        } else {
            let candidate = addr.wrapping_sub(0x0100_0000);
            if candidate & 0x8000_0000 != 0 && candidate.wrapping_add(offset) & 0x8000_0000 == 0 {
                data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
            }
        }
        opcode_pos = pos + 5;
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

/// Delta-decode `data` into `out`, which is resized to `data.len()` and
/// fully rewritten. The decode cannot run in place - it walks the source
/// serially and the destination by a stride of `channels`, so a byte it
/// has yet to read may already have been overwritten - but the buffer it
/// needs does not have to be a fresh one. Every RAR 5 filter block used
/// to allocate and zero its own; the decoders now carry one across the
/// whole member. (nzbfast-local change, 20 Aug 2026 - re-apply on the
/// next rars re-sync, see vendor/rars/VENDORING.md.)
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
    out.clear();
    out.resize(data.len(), 0);
    let mut src = 0usize;
    for channel in 0..channels {
        let mut prev = 0u8;
        let mut dest = channel;
        while dest < out.len() {
            let byte = *data
                .get(src)
                .ok_or(Error::InvalidData(messages.truncated_source))?;
            prev = prev.wrapping_sub(byte);
            out[dest] = prev;
            src += 1;
            dest += channels;
        }
    }
    Ok(())
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

    fn x86_sample() -> Vec<u8> {
        let mut data = b"prefix ".to_vec();
        data.extend_from_slice(&[0xe8, 0x10, 0x20, 0x00, 0x00]);
        data.extend_from_slice(b" middle ");
        data.extend_from_slice(&[0xe9, 0xf0, 0xff, 0xff, 0xff]);
        data.extend_from_slice(b" suffix");
        data
    }

    fn reference_e8e9_encode(data: &mut [u8], file_offset: u32, include_e9: bool) {
        if data.len() <= 4 {
            return;
        }
        let cmp_mask = if include_e9 { 0xfe } else { 0xff };
        let mut cur_pos = 0usize;
        while cur_pos < data.len() - 4 {
            cur_pos += 1;
            let opcode = data[cur_pos - 1];
            if opcode & cmp_mask == 0xe8 {
                let offset = file_offset.wrapping_add(cur_pos as u32);
                let addr = u32::from_le_bytes([
                    data[cur_pos],
                    data[cur_pos + 1],
                    data[cur_pos + 2],
                    data[cur_pos + 3],
                ]);
                let candidate = addr.wrapping_add(offset);
                if candidate < 0x0100_0000 {
                    data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
                } else {
                    let candidate = addr.wrapping_sub(0x0100_0000);
                    if candidate & 0x8000_0000 != 0
                        && candidate.wrapping_add(offset) & 0x8000_0000 == 0
                    {
                        data[cur_pos..cur_pos + 4].copy_from_slice(&candidate.to_le_bytes());
                    }
                }
                cur_pos += 4;
            }
        }
    }

    fn reference_e8e9_decode(data: &mut [u8], file_offset: u32, include_e9: bool) {
        if data.len() <= 4 {
            return;
        }
        let cmp_mask = if include_e9 { 0xfe } else { 0xff };
        let mut cur_pos = 0usize;
        while cur_pos < data.len() - 4 {
            cur_pos += 1;
            let opcode = data[cur_pos - 1];
            if opcode & cmp_mask == 0xe8 {
                let offset = file_offset.wrapping_add(cur_pos as u32);
                let addr = u32::from_le_bytes([
                    data[cur_pos],
                    data[cur_pos + 1],
                    data[cur_pos + 2],
                    data[cur_pos + 3],
                ]);
                let new_addr = if addr < 0x0100_0000 {
                    Some(addr.wrapping_sub(offset))
                } else if addr & 0x8000_0000 != 0 && addr.wrapping_add(offset) & 0x8000_0000 == 0 {
                    Some(addr.wrapping_add(0x0100_0000))
                } else {
                    None
                };
                if let Some(value) = new_addr {
                    data[cur_pos..cur_pos + 4].copy_from_slice(&value.to_le_bytes());
                }
                cur_pos += 4;
            }
        }
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
    fn e8e9_transform_matches_scalar_at_lane_boundaries_and_skips_payloads() {
        let mut input = vec![0x41u8; 104];
        for (pos, address) in [
            (0usize, 0x0000_00e8u32),
            (31, 0x0000_0100),
            (36, 0x0000_0200),
            (64, 0x0000_0300),
            (96, 0xffff_ff00),
        ] {
            input[pos] = if pos == 36 { 0xe9 } else { 0xe8 };
            input[pos + 1..pos + 5].copy_from_slice(&address.to_le_bytes());
        }
        input[32] = 0xe8;
        input[65] = 0xe9;

        for &include_e9 in &[false, true] {
            let mut expected = input.clone();
            let mut actual = input.clone();
            reference_e8e9_encode(&mut expected, 0x1000, include_e9);
            e8e9_encode(&mut actual, 0x1000, include_e9);
            assert_eq!(actual, expected);

            reference_e8e9_decode(&mut expected, 0x1000, include_e9);
            e8e9_decode(&mut actual, 0x1000, include_e9);
            assert_eq!(actual, expected);
            assert_eq!(actual, input);
        }
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

    /// The scratch-reusing decode must be byte-identical to the
    /// allocating one, INCLUDING when the buffer it is handed is longer
    /// than the block and full of somebody else's bytes - which is
    /// exactly what the second and every later block of a member sees.
    #[test]
    fn delta_decode_into_matches_the_allocating_decode_on_a_dirty_buffer() {
        let mut scratch = Vec::new();
        for channels in 1..=8usize {
            for len in [0usize, 1, 5, 31, 64, 257, 4096] {
                // Deterministic pseudo-random bytes: a filter block is
                // arbitrary compressed output, not a pattern.
                let data: Vec<u8> = (0..len)
                    .map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8)
                    .collect();
                let expected = delta_decode(&data, channels, DeltaErrorMessages::generic());
                // Leave the previous block's answer (and then some) in
                // the buffer, so a decode that failed to rewrite every
                // byte would read back the stale one.
                scratch.clear();
                scratch.resize(len + 997, 0xa5);
                let actual =
                    delta_decode_into(&data, channels, DeltaErrorMessages::generic(), &mut scratch)
                        .map(|()| scratch.clone());
                assert_eq!(actual, expected, "channels={channels} len={len}");
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
