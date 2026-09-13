//! Lab-only postprocessor for ordinary unencrypted RAR5 archives.
//! Remove a table description only when all four Huffman length arrays are
//! identical to the preceding block's. Token bits and repeat state are unchanged.
use rars::codec::rar50::{encode_compressed_block, parse_compressed_block, read_table_lengths};
use rars::rar50::{Archive, Block};
use std::{fs, path::Path};

fn vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 128 {
        out.push(value as u8 | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn member(input: &[u8], version: u8) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut previous = None;
    let mut pos = 0;
    let mut reused = 0;
    loop {
        let block = parse_compressed_block(&input[pos..]).expect("compressed block");
        let payload = &input[pos + block.payload.start..pos + block.payload.end];
        let mut replacement = None;
        if block.header.has_tables {
            let (lengths, table_bits) = read_table_lengths(payload, version).expect("tables");
            assert!(table_bits <= block.header.payload_bits);
            if previous.as_ref() == Some(&lengths) {
                let bits = block.header.payload_bits - table_bits;
                let mut shifted = vec![0; bits.div_ceil(8)];
                // Shift whole bytes, retaining the original MSB-first bit order.
                for (i, byte) in shifted.iter_mut().enumerate() {
                    let start = table_bits + i * 8;
                    let shift = start % 8;
                    *byte = payload[start / 8] << shift;
                    if shift != 0 && start / 8 + 1 < payload.len() {
                        *byte |= payload[start / 8 + 1] >> (8 - shift);
                    }
                }
                if bits % 8 != 0 {
                    *shifted.last_mut().unwrap() &= 0xff << (8 - bits % 8);
                }
                let candidate =
                    encode_compressed_block(&shifted, bits, false, block.header.is_last)
                        .expect("reused-table block");
                if candidate.len() < block.payload.end {
                    replacement = Some(candidate);
                    reused += 1;
                }
            }
            previous = Some(lengths);
        } else {
            assert!(previous.is_some(), "member must begin with its own tables");
        }
        if let Some(bytes) = replacement {
            out.extend(bytes);
        } else {
            out.extend_from_slice(&input[pos..pos + block.payload.end]);
        }
        pos += block.payload.end;
        if block.header.is_last {
            break;
        }
    }
    assert_eq!(pos, input.len(), "trailing compressed payload");
    (out, reused)
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "ratio_table_reuse INPUT.rar OUTPUT.rar");
    assert!(!Path::new(&args[2]).exists(), "output already exists");
    let input = fs::read(&args[1]).unwrap();
    let parsed = Archive::parse(&input).expect("archive headers");
    assert_eq!(parsed.sfx_offset, 0);
    assert!(!parsed.main.is_volume() && !parsed.main.has_recovery_record());
    assert!(
        parsed.main.locator().is_none(),
        "archive-relative locator unsupported"
    );
    let mut out = input[..parsed.main.block.data_range.end].to_vec();
    let mut reused = 0;
    for entry in &parsed.blocks {
        match entry {
            Block::File(file) => {
                assert!(!file.encrypted && file.redirection.is_none());
                assert_eq!(file.block.flags & (8 | 16), 0, "split member unsupported");
                let data = &input[file.block.data_range.clone()];
                if (file.compression_info >> 7) & 7 == 0 {
                    out.extend_from_slice(&input[file.block.offset..file.block.data_range.end]);
                    continue;
                }
                let (packed, count) = member(data, (file.compression_info & 63) as u8);
                reused += count;
                if count == 0 {
                    out.extend_from_slice(&input[file.block.offset..file.block.data_range.end]);
                    continue;
                }
                let mut body = Vec::new();
                vint(&mut body, file.block.header_type);
                vint(&mut body, file.block.flags);
                if let Some(size) = file.block.extra_area_size {
                    vint(&mut body, size);
                }
                assert!(file.block.data_size.is_some());
                vint(&mut body, packed.len() as u64);
                // Preserve every type-specific and extra field, including file CRC.
                body.extend_from_slice(
                    &input[file.block.header_range.start..file.block.data_range.start],
                );
                let mut header = Vec::new();
                vint(&mut header, body.len() as u64);
                header.extend(body);
                out.extend(rars::crc32::crc32(&header).to_le_bytes());
                out.extend(header);
                out.extend(packed);
            }
            Block::End(header) => {
                out.extend_from_slice(&input[header.offset..header.data_range.end])
            }
            _ => panic!("only ordinary file and end blocks are supported"),
        }
    }
    assert!(out.len() <= input.len());
    fs::write(&args[2], &out).unwrap();
    println!(
        "before={} after={} saved={} reused_tables={reused}",
        input.len(),
        out.len(),
        input.len() - out.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use rars::codec::rar50::{decode_lz, encode_literal_only};

    #[test]
    fn repeated_tables_preserve_every_payload_alignment_and_are_idempotent() {
        let mut alignments = std::collections::BTreeSet::new();
        for length in 1..130 {
            let data: Vec<_> = (0..length).map(|i| (i % 19) as u8).collect();
            let encoded = encode_literal_only(&data, 0).unwrap();
            let parsed = parse_compressed_block(&encoded).unwrap();
            alignments.insert(parsed.header.payload_bits % 8);
            let first = encode_compressed_block(
                &encoded[parsed.payload.clone()],
                parsed.header.payload_bits,
                true,
                false,
            )
            .unwrap();
            let input = [first.as_slice(), first.as_slice(), encoded.as_slice()].concat();
            let (out, count) = member(&input, 0);
            assert_eq!(count, 2);
            assert!(out.len() < input.len());
            assert_eq!(decode_lz(&out, 0, data.len() * 3).unwrap(), data.repeat(3));
            let (again, count) = member(&out, 0);
            assert_eq!(count, 0);
            assert_eq!(out, again);
        }
        assert_eq!(alignments.len(), 8);
    }

    #[test]
    fn different_tables_are_preserved_byte_for_byte() {
        let first = encode_literal_only(b"aaa", 0).unwrap();
        let parsed = parse_compressed_block(&first).unwrap();
        let first = encode_compressed_block(
            &first[parsed.payload],
            parsed.header.payload_bits,
            true,
            false,
        )
        .unwrap();
        let last = encode_literal_only(b"xyz", 0).unwrap();
        let input = [first, last].concat();
        let (out, count) = member(&input, 0);
        assert_eq!(count, 0);
        assert_eq!(out, input);
        assert_eq!(decode_lz(&out, 0, 6).unwrap(), b"aaaxyz");
    }
}
