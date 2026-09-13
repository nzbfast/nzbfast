//! The PAR2 packet builders the creator streams through: the in-place
//! packet appender, the recovery-packet digest, the balanced volume
//! seals and the recovery packet writer. Split out of `par2gen.rs` on
//! 5 Sep 2026 when the seals landed and the file crossed its ceiling.

use super::*;

/// Append one PAR2 packet directly to its destination: magic , length ,
/// MD5(set_id,type,body) , set_id , type , body. The body must already be
/// padded to a multiple of 4; the length field counts the whole packet
/// including its 64-byte head. Building the body IN PLACE matters for the
/// recovery packets: a slice can be many MiB, and the volume writer used to
/// copy it into a body, then into a packet, then into the final volume
/// buffer.
pub(super) fn append_packet(
    out: &mut Vec<u8>,
    set_id: &[u8; 16],
    ptype: &[u8; 16],
    body_len: usize,
    append_body: impl FnOnce(&mut Vec<u8>),
) {
    debug_assert_eq!(body_len % 4, 0, "PAR2 packet bodies are 4-aligned");
    let start = out.len();
    out.reserve(64 + body_len);
    out.extend_from_slice(crate::par2::MAGIC);
    out.extend_from_slice(&(64 + body_len as u64).to_le_bytes());
    // The digest precedes the bytes it covers, so leave its slot empty,
    // append the body once, then seal straight over the destination.
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(set_id);
    out.extend_from_slice(ptype);
    append_body(out);
    assert_eq!(
        out.len(),
        start + 64 + body_len,
        "PAR2 packet builder appended the wrong body length"
    );
    let end = out.len();
    let digest: [u8; 16] = Md5::digest(&out[start + 32..end]).into();
    out[start + 16..start + 32].copy_from_slice(&digest);
}

/// Seal and stream one recovery packet without materializing its
/// block-sized body or packet. `slice` already lives in the GF accumulator;
/// hashing and writing it there removes the final accumulator -> volume copy
/// that [`append_packet`] alone still leaves.
pub(super) fn recovery_digest(set_id: &[u8; 16], exponent: u32, slice: &[u8]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(set_id);
    md5.update(TYPE_RECVSLIC);
    md5.update(exponent.to_le_bytes());
    md5.update(slice);
    md5.finalize().into()
}

// Research-only: balance packet seals independently of unequal output volumes.
pub(super) fn prepare_recovery_seals(
    set_id: &[u8; 16],
    first: usize,
    slices: &[Vec<u16>],
    lanes: bool,
) -> Vec<[u8; 16]> {
    let mut out = vec![[0; 16]; slices.len()];
    let groups = slices.len().div_ceil(8);
    let requested = std::env::var("NZBFAST_PAR2GEN_SEAL_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&v| v > 0);
    let workers = requested
        .unwrap_or_else(crate::mem::cpu_workers)
        .clamp(1, 64)
        .min(groups.max(1));
    let per_worker = groups.div_ceil(workers).max(1) * 8;
    std::thread::scope(|scope| {
        for (wi, dst) in out.chunks_mut(per_worker).enumerate() {
            let base = wi * per_worker;
            scope.spawn(move || {
                for (gi, batch) in dst.chunks_mut(8).enumerate() {
                    let start = base + gi * 8;
                    let src = &slices[start..start + batch.len()];
                    if lanes && src.iter().all(|v| v.len() * 2 >= 28) {
                        let mut md5 = crate::md5fast::multi::Md5Lanes::new();
                        let mut prefix = [[0u8; 64]; 8];
                        for (j, row) in src.iter().enumerate() {
                            prefix[j][..16].copy_from_slice(set_id);
                            prefix[j][16..32].copy_from_slice(TYPE_RECVSLIC);
                            prefix[j][32..36]
                                .copy_from_slice(&((first + start + j) as u32).to_le_bytes());
                            prefix[j][36..]
                                .copy_from_slice(&crate::gf16::words_as_bytes(row)[..28]);
                        }
                        let mut chunks: [&[u8]; 8] = [&[]; 8];
                        for j in 0..src.len() {
                            chunks[j] = &prefix[j];
                        }
                        md5.update(chunks);
                        for (j, row) in src.iter().enumerate() {
                            chunks[j] = &crate::gf16::words_as_bytes(row)[28..];
                        }
                        md5.update(chunks);
                        for (j, d) in batch.iter_mut().enumerate() {
                            *d = md5.finalize(j);
                        }
                    } else {
                        for (j, d) in batch.iter_mut().enumerate() {
                            *d = recovery_digest(
                                set_id,
                                (first + start + j) as u32,
                                crate::gf16::words_as_bytes(&src[j]),
                            );
                        }
                    }
                }
            });
        }
    });
    out
}

pub(super) fn write_recovery_packet(
    out: &mut impl std::io::Write,
    set_id: &[u8; 16],
    exponent: u32,
    slice: &[u8],
    sealed: Option<&[u8; 16]>,
) -> std::io::Result<()> {
    debug_assert_eq!(slice.len() % 4, 0, "PAR2 recovery slices are 4-aligned");
    let digest = sealed
        .copied()
        .unwrap_or_else(|| recovery_digest(set_id, exponent, slice));
    let exponent = exponent.to_le_bytes();

    // The exponent is the first four bytes of the body, so one small header
    // write followed by the accumulator bytes is the complete packet.
    let mut header = [0u8; 68];
    header[..8].copy_from_slice(crate::par2::MAGIC);
    header[8..16].copy_from_slice(&(68 + slice.len() as u64).to_le_bytes());
    header[16..32].copy_from_slice(&digest);
    header[32..48].copy_from_slice(set_id);
    header[48..64].copy_from_slice(TYPE_RECVSLIC);
    header[64..68].copy_from_slice(&exponent);
    out.write_all(&header)?;
    out.write_all(slice)
}
