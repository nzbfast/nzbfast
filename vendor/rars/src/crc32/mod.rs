//! Shared RAR CRC-32 primitives.

mod pmull;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32 {
    value: u32,
}

impl Crc32 {
    pub const fn new() -> Self {
        Self { value: 0xffff_ffff }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.value = update_raw(self.value, input);
    }

    pub fn update_zeroes(&mut self, len: u64) {
        let mut matrix = zero_byte_matrix();
        let mut count = len;
        while count != 0 {
            if count & 1 != 0 {
                self.value = gf2_matrix_times(&matrix, self.value);
            }
            count >>= 1;
            if count != 0 {
                matrix = gf2_matrix_square(&matrix);
            }
        }
    }

    pub const fn finish(self) -> u32 {
        !self.value
    }

    /// Folds in `other`: the checksum, from a fresh [`Crc32::new`], of the
    /// `len` bytes that come straight after everything this one has seen.
    /// It is what lets the pieces of one stream be checksummed apart and
    /// joined in order.
    pub fn combine(&mut self, other: Crc32, len: u64) {
        let mut joined = crc32fast::Hasher::new_with_initial(!self.value);
        joined.combine(&crc32fast::Hasher::new_with_initial_len(!other.value, len));
        self.value = !joined.finalize();
    }

    /// [`Self::update`] over `pieces` in order, each piece on a thread of its
    /// own when there are several and they are large enough to pay for it.
    ///
    /// CRC32 is one stream, so one checksum is one core however many the box
    /// has. Measured 14 Sep 2026 on the dev Mac (M3 Ultra): 9.8 GB/s for one
    /// stream, 25 GB/s for 4 MiB cut four ways and joined with
    /// [`Self::combine`], a thread spawned per piece included. That single
    /// stream was half the CPU of `rarfast t` on a stored or a text archive,
    /// and the whole of its gap to the reference unrar.
    pub fn update_pieces(&mut self, pieces: &[&[u8]]) {
        #[cfg(feature = "parallel")]
        if pieces.len() > 1
            && pieces.iter().map(|piece| piece.len()).sum::<usize>() >= PARALLEL_PIECES_MIN_BYTES
        {
            std::thread::scope(|scope| {
                let rest: Vec<_> = pieces[1..]
                    .iter()
                    .map(|piece| {
                        scope.spawn(move || {
                            let mut part = Crc32::new();
                            part.update(piece);
                            part
                        })
                    })
                    .collect();
                self.update(pieces[0]);
                for (handle, piece) in rest.into_iter().zip(&pieces[1..]) {
                    let part = handle.join().expect("CRC32 piece thread panicked");
                    self.combine(part, piece.len() as u64);
                }
            });
            return;
        }
        for piece in pieces {
            self.update(piece);
        }
    }
}

/// Below this many bytes in all, [`Crc32::update_pieces`] hashes on the
/// calling thread: two 1 MiB pieces already ran 11.4 GB/s against 9.8 for
/// one stream, and anything smaller is spawn cost for nothing.
#[cfg(feature = "parallel")]
const PARALLEL_PIECES_MIN_BYTES: usize = 2 << 20;

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn crc32(input: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(input);
    crc.finish()
}

pub fn crc32_raw(input: &[u8]) -> u32 {
    update_raw(0xffff_ffff, input)
}

pub fn table_entry(index: u8) -> u32 {
    TABLE[index as usize]
}

// `crc` here is the raw (pre-inverted) CRC state; crc32fast's
// `new_with_initial` takes and `finalize` returns *finished* checksums,
// so bridge with a complement on each side. A CPU with the folded kernel
// (`pmull`) never reaches crc32fast here.
fn update_raw(crc: u32, input: &[u8]) -> u32 {
    if let Some(folded) = pmull::update(crc, input) {
        return folded;
    }
    let mut hasher = crc32fast::Hasher::new_with_initial(!crc);
    hasher.update(input);
    !hasher.finalize()
}

fn zero_byte_matrix() -> [u32; 32] {
    let mut matrix = [0; 32];
    for (bit, slot) in matrix.iter_mut().enumerate() {
        let mut value = 1u32 << bit;
        let index = value as u8;
        value = (value >> 8) ^ table_entry(index);
        *slot = value;
    }
    matrix
}

fn gf2_matrix_times(matrix: &[u32; 32], mut vector: u32) -> u32 {
    let mut sum = 0;
    let mut index = 0;
    while vector != 0 {
        if vector & 1 != 0 {
            sum ^= matrix[index];
        }
        vector >>= 1;
        index += 1;
    }
    sum
}

fn gf2_matrix_square(matrix: &[u32; 32]) -> [u32; 32] {
    let mut square = [0; 32];
    for (index, slot) in square.iter_mut().enumerate() {
        *slot = gf2_matrix_times(matrix, matrix[index]);
    }
    square
}

const TABLES: [[u32; 256]; 8] = crc32_tables();
const TABLE: [u32; 256] = TABLES[0];

const fn crc32_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            let mask = 0u32.wrapping_sub(value & 1);
            value = (value >> 1) ^ (0xedb8_8320 & mask);
            bit += 1;
        }
        tables[0][i] = value;
        i += 1;
    }

    let mut table = 1;
    while table < 8 {
        let mut i = 0;
        while i < 256 {
            let previous = tables[table - 1][i];
            tables[table][i] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            i += 1;
        }
        table += 1;
    }
    tables
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn raw_crc_matches_unfinalized_seeded_rar15_value() {
        assert_eq!(crc32_raw(b"password"), 0xca3d_b92a);
    }

    #[test]
    fn combined_and_pieced_checksums_match_one_stream() {
        let data = deterministic_bytes(9_000_001);
        let whole = crc32(&data);
        for cut in [0usize, 1, 4096, 1 << 20, 4_500_000, data.len()] {
            let (left, right) = data.split_at(cut);
            let mut joined = Crc32::new();
            joined.update(left);
            let mut tail = Crc32::new();
            tail.update(right);
            joined.combine(tail, right.len() as u64);
            assert_eq!(joined.finish(), whole, "cut at {cut}");
        }
        for sizes in [
            vec![data.len()],
            vec![1 << 20; 8],
            vec![0, 3, 2 << 20, 1, 4 << 20],
            vec![3_000_000, 3_000_000, 3_000_001],
        ] {
            let mut at = 0;
            let mut pieces = Vec::new();
            for size in sizes {
                let end = (at + size).min(data.len());
                pieces.push(&data[at..end]);
                at = end;
            }
            let mut pieced = Crc32::new();
            pieced.update(b"prefix");
            pieced.update_pieces(&pieces);
            let covered = &data[..at];
            let mut expected = Crc32::new();
            expected.update(b"prefix");
            expected.update(covered);
            assert_eq!(pieced.finish(), expected.finish());
        }
    }

    #[test]
    fn update_zeroes_matches_byte_update() {
        let mut skipped = Crc32::new();
        skipped.update(b"prefix");
        skipped.update_zeroes(1024);
        skipped.update(b"suffix");

        let mut bytewise = Crc32::new();
        bytewise.update(b"prefix");
        bytewise.update(&[0; 1024]);
        bytewise.update(b"suffix");

        assert_eq!(skipped.finish(), bytewise.finish());
    }

    fn reference_crc32(input: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &byte in input {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !crc
    }

    fn deterministic_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((state >> 24) as u8);
        }
        out
    }

    #[test]
    fn crc32_matches_bitwise_reference_across_chunk_boundaries() {
        for len in 0..=257 {
            let input = deterministic_bytes(len);
            assert_eq!(crc32(&input), reference_crc32(&input), "len {len}");
        }

        for len in [1024, 4095, 4096, 4097, 65_536] {
            let input = deterministic_bytes(len);
            assert_eq!(crc32(&input), reference_crc32(&input), "len {len}");
        }
    }

    #[test]
    fn table_entry_matches_bitwise_generation() {
        assert_eq!(table_entry(0), 0);
        assert_eq!(table_entry(1), 0x7707_3096);
        assert_eq!(table_entry(0xff), 0x2d02_ef8d);
    }
}
