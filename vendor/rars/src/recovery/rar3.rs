/// The most symbols a Reed-Solomon codeword over GF(2^8) can hold: the field
/// has 255 nonzero elements and a codeword needs a distinct one per position.
/// The parity count is bounded by the same figure.
const SYMBOL_LIMIT: usize = 255;

/// The low byte of `x^8 + x^4 + x^3 + x^2 + 1`: what a bit shifted out of the
/// top of a byte folds back in as.
const BYTE_FIELD_REDUCTION: u8 = 0x1d;

/// `a^(i mod 255)` for the primitive element `a = 2`, for every `i` in `0..512`.
///
/// A product indexes it with the sum of two logarithms, each at most 254. The
/// table is 512 entries rather than the 509 that needs because two `u8`
/// logarithms widened and summed are at most 510, which the compiler can see
/// is in bounds, so the lookup carries no bounds check.
static BYTE_EXP: [u8; 512] = byte_exp_table();

/// The discrete logarithm base `a` of every nonzero byte. Entry 0 is never
/// read: every lookup handles a zero operand before indexing.
static BYTE_LOG: [u8; 256] = byte_log_table(&BYTE_EXP);

const fn byte_exp_table() -> [u8; 512] {
    let mut table = [0u8; 512];
    let mut value: u8 = 1;
    let mut index = 0;
    while index < SYMBOL_LIMIT {
        table[index] = value;
        let carry = value & 0x80 != 0;
        value <<= 1;
        if carry {
            value ^= BYTE_FIELD_REDUCTION;
        }
        index += 1;
    }
    while index < table.len() {
        table[index] = table[index - SYMBOL_LIMIT];
        index += 1;
    }
    table
}

const fn byte_log_table(exp: &[u8; 512]) -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < SYMBOL_LIMIT {
        table[exp[index] as usize] = index as u8;
        index += 1;
    }
    table
}

/// `value * a^power`, for any `power` a `u8` holds.
#[inline]
fn byte_mul_by_power(value: u8, power: u8) -> u8 {
    if value == 0 {
        return 0;
    }
    BYTE_EXP[usize::from(BYTE_LOG[usize::from(value)]) + usize::from(power)]
}

/// The field product of two bytes.
#[inline]
fn byte_mul(left: u8, right: u8) -> u8 {
    if right == 0 {
        return 0;
    }
    byte_mul_by_power(left, BYTE_LOG[usize::from(right)])
}

/// `numerator / denominator` for a nonzero denominator.
#[inline]
fn byte_div(numerator: u8, denominator: u8) -> u8 {
    // `a^-k = a^(255 - k)`, and a logarithm is at most 254.
    byte_mul_by_power(
        numerator,
        (SYMBOL_LIMIT as u8) - BYTE_LOG[usize::from(denominator)],
    )
}

/// Evaluate a polynomial, lowest power first, at `a^power`.
#[inline]
fn byte_poly_at(coefficients: &[u8], power: u8) -> u8 {
    coefficients.iter().rev().fold(0, |value, &coefficient| {
        byte_mul_by_power(value, power) ^ coefficient
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidParitySize,
    InvalidCodewordSize,
    TooManyErasures,
    DecodeFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParitySize => f.write_str("RAR 3 recovery parity size is invalid"),
            Self::InvalidCodewordSize => f.write_str("RAR 3 recovery codeword size is invalid"),
            Self::TooManyErasures => {
                f.write_str("RAR 3 recovery data cannot repair this many erasures")
            }
            Self::DecodeFailed => f.write_str("RAR 3 recovery decode failed"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// The Reed-Solomon code RAR 3 `.rev` sets carry, over GF(2^8).
///
/// A codeword is `k` data symbols followed by `p` parity symbols, at most 255
/// in all, and slice index 0 is the coefficient of the highest power of `x`.
/// The generator's roots are `a^1 ..= a^p`, so a codeword is exactly a symbol
/// sequence whose polynomial vanishes at each of them. The field tables are
/// compile-time data, so a coder is nothing but its parity count.
#[derive(Debug, Clone)]
pub(crate) struct ByteFieldCoder {
    parity: usize,
}

impl ByteFieldCoder {
    /// A coder with `parity` check symbols, `1 ..= 255`.
    pub(crate) fn new(parity: usize) -> Result<Self> {
        if parity == 0 || parity > SYMBOL_LIMIT {
            return Err(Error::InvalidParitySize);
        }
        Ok(Self { parity })
    }

    /// The generator `(x + a^1)(x + a^2)...(x + a^p)` below its leading 1,
    /// lowest power first.
    #[cfg(test)]
    fn generator(&self) -> Vec<u8> {
        let mut product = vec![0u8; self.parity + 1];
        product[0] = 1;
        for root_power in 1..=self.parity {
            // Multiply the degree `root_power - 1` product by `(x + root)`.
            let power = root_power as u8;
            for degree in (1..=root_power).rev() {
                product[degree] = product[degree - 1] ^ byte_mul_by_power(product[degree], power);
            }
            product[0] = byte_mul_by_power(product[0], power);
        }
        product.truncate(self.parity);
        product
    }

    /// Systematic parity for `data`, highest power first: the remainder of
    /// `data(x) * x^p` divided by the generator.
    #[cfg(test)]
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        let generator = self.generator();
        let mut remainder = vec![0u8; self.parity];
        for &symbol in data {
            // The coefficient shifted up to `x^p`, which the generator folds
            // back as `g_(p-1) x^(p-1) + ... + g_0`.
            let feedback = symbol ^ remainder[0];
            remainder.copy_within(1.., 0);
            remainder[self.parity - 1] = 0;
            for (slot, &coefficient) in remainder.iter_mut().zip(generator.iter().rev()) {
                *slot ^= byte_mul(feedback, coefficient);
            }
        }
        remainder
    }

    /// Repair the symbols at `erasures` in place.
    ///
    /// Erasure decoding only: the caller names every corrupt position and
    /// nothing else is searched for. A codeword whose polynomial already
    /// vanishes at every root is left untouched whatever `erasures` says. On
    /// success every position, data and parity, holds its corrected value;
    /// on any error the codeword is unchanged. Works in fixed stack scratch.
    pub(crate) fn correct_erasures(&self, codeword: &mut [u8], erasures: &[usize]) -> Result<()> {
        let len = codeword.len();
        if len == 0 || len > SYMBOL_LIMIT {
            return Err(Error::InvalidCodewordSize);
        }
        let parity = self.parity;

        // S_m = C(a^(m+1)), by Horner from slice index 0, the top power.
        let mut syndromes = [0u8; SYMBOL_LIMIT];
        let mut clean = true;
        for (index, syndrome) in syndromes[..parity].iter_mut().enumerate() {
            let power = (index + 1) as u8;
            *syndrome = codeword
                .iter()
                .fold(0, |value, &symbol| byte_mul_by_power(value, power) ^ symbol);
            clean &= *syndrome == 0;
        }
        if clean {
            return Ok(());
        }
        if erasures.is_empty() {
            return Err(Error::DecodeFailed);
        }
        if erasures.len() > parity {
            return Err(Error::TooManyErasures);
        }
        let mut erased = [false; SYMBOL_LIMIT];
        for &position in erasures {
            if position >= len {
                return Err(Error::InvalidCodewordSize);
            }
            // A repeated position is a double root: no Forney denominator.
            if std::mem::replace(&mut erased[position], true) {
                return Err(Error::DecodeFailed);
            }
        }

        // The erasure locator, the product of `(1 + X_e x)` with
        // `X_e = a^(len - 1 - e)`, lowest power first.
        let count = erasures.len();
        let mut locator = [0u8; SYMBOL_LIMIT + 1];
        locator[0] = 1;
        for (degree, &position) in erasures.iter().enumerate() {
            let power = (len - 1 - position) as u8;
            for index in (1..=degree + 1).rev() {
                locator[index] ^= byte_mul_by_power(locator[index - 1], power);
            }
        }
        let locator = &locator[..=count];

        // The evaluator, `S(x) * L(x) mod x^p`.
        let mut evaluator = [0u8; SYMBOL_LIMIT];
        for (index, slot) in evaluator[..parity].iter_mut().enumerate() {
            *slot = (0..=index.min(count)).fold(0, |value, term| {
                value ^ byte_mul(locator[term], syndromes[index - term])
            });
        }
        let evaluator = &evaluator[..parity];

        // Forney: with roots starting at `a^1`, the error at `e` is
        // `evaluator(X_e^-1) / locator'(X_e^-1)`. Each position's root is
        // computed from the position itself, so every field element is
        // visited at most once and `a^0` never aliases `a^255`.
        let mut corrections = [0u8; SYMBOL_LIMIT];
        for (correction, &position) in corrections.iter_mut().zip(erasures) {
            let root = (SYMBOL_LIMIT - (len - 1 - position)) as u8;
            if byte_poly_at(locator, root) != 0 {
                return Err(Error::DecodeFailed);
            }
            // The formal derivative keeps the odd-degree terms, each one
            // power lower: a polynomial in `x^2` evaluated at `root^2`.
            let root_squared = ((usize::from(root) * 2) % SYMBOL_LIMIT) as u8;
            let denominator = locator
                .iter()
                .skip(1)
                .step_by(2)
                .rev()
                .fold(0, |value, &coefficient| {
                    byte_mul_by_power(value, root_squared) ^ coefficient
                });
            if denominator == 0 {
                return Err(Error::DecodeFailed);
            }
            *correction = byte_div(byte_poly_at(evaluator, root), denominator);
        }
        for (&correction, &position) in corrections.iter().zip(erasures) {
            codeword[position] ^= correction;
        }
        Ok(())
    }

    /// `table[v]` is `coefficient * v` for every byte `v`, so a bulk multiply
    /// is one load per byte.
    pub(crate) fn mul_table(&self, coefficient: u8) -> [u8; 256] {
        let mut table = [0u8; 256];
        if coefficient == 0 {
            return table;
        }
        let power = BYTE_LOG[usize::from(coefficient)];
        for (value, slot) in table.iter_mut().enumerate().skip(1) {
            *slot = byte_mul_by_power(value as u8, power);
        }
        table
    }
}

/// Bytes of one output volume rebuilt per pass, so the destination slice stays
/// in cache while every source volume streams past it.
const RECONSTRUCT_CHUNK: usize = 64 * 1024;

/// Fold work - bytes of one rebuilt volume times the surviving volumes
/// folded into it - below which that volume is rebuilt on the calling
/// thread, for a host of `threads` threads.
///
/// Like the RAR 5 repair folds this is work PER THREAD (see
/// `recovery/rar5.rs`: a flat byte gate derived on a 20-thread box was a
/// LOSS on a 32-thread one), but the constant is an order smaller, because
/// this kernel is slower per byte - a table load per byte against the RAR 5
/// fold's SIMD shuffle - so the same bytes buy far more work to amortise a
/// dispatch against. Measured 15 Sep 2026 with the fork's fold (whole
/// sources four to a pass), serial build against parallel, cold process and
/// warm pool. On an M1 Ultra (20 threads): 1 MiB of work 1.01-1.61x the
/// serial time, 2 MiB 0.63-0.98x, 3 MiB 0.49-0.78x, 8 MiB 0.31-0.46x. On an
/// M3 Ultra (32 threads): 2 MiB 1.12x cold, 3 MiB 0.49-0.82x, 4 MiB
/// 0.40-0.69x. 128 KiB a thread wins on both (2.5 MiB at 20 threads, 4 MiB
/// at 32), floored at the 2 MiB the 20-thread box measured. This tree folds whole
/// sources four to a pass; nzbfast's vendored copy folds one byte at a time,
/// which costs more per byte, so the team pays at least as early there. See the host repo's
/// `research/RARFAST-BENCH-2026-09-14.md` section 14 (nzbfast-local change,
/// 15 Sep 2026; see VENDORING.md).
#[cfg(feature = "parallel")]
fn reconstruct_team_min_work_for(threads: usize) -> usize {
    const FLOOR: usize = 2 << 20;
    const PER_THREAD: usize = 128 << 10;
    FLOOR.max(threads.saturating_mul(PER_THREAD))
}

/// Whether rebuilding `volume_len` bytes from `sources` live tables is
/// enough work to repay a rayon team on this host.
#[cfg(feature = "parallel")]
fn reconstruct_on_team(volume_len: usize, sources: usize) -> bool {
    volume_len.saturating_mul(sources)
        >= reconstruct_team_min_work_for(crate::recovery::rar5::fold_team_threads())
}

/// Derive the erasure-correction coefficients once for a fixed erasure set.
///
/// `correct_erasures` is linear in the codeword, and everything it derives
/// from the erasure positions alone -- locator, roots, Forney denominators --
/// is identical at every byte offset. The whole decode therefore collapses to
/// a fixed matrix: the value recovered at erased position `e` is the XOR over
/// known positions `k` of `matrix[e][k] * codeword[k]`.
///
/// The coefficients are read out of `correct_erasures` itself, by decoding
/// unit codewords, so the bulk path cannot drift from the reference decoder.
/// A unit codeword always has non-zero syndromes, so no probe can take the
/// clean-codeword early return and silently yield an all-zero column.
fn erasure_correction_matrix(
    coder: &ByteFieldCoder,
    codeword_len: usize,
    erasures: &[usize],
    known: &[(usize, &[u8])],
) -> Result<Vec<Vec<u8>>> {
    let mut matrix = vec![vec![0u8; codeword_len]; erasures.len()];
    let mut probe = vec![0u8; codeword_len];
    for &(position, _) in known {
        probe.iter_mut().for_each(|byte| *byte = 0);
        probe[position] = 1;
        // Distinct, non-empty erasures always give a full root set and
        // non-zero denominators, so a probe failure means the erasure set
        // itself is undecodable -- exactly what the serial loop reported.
        coder.correct_erasures(&mut probe, erasures)?;
        for (row, &erasure) in matrix.iter_mut().zip(erasures) {
            row[position] = probe[erasure];
        }
    }
    Ok(matrix)
}

pub fn reconstruct_data_volumes(
    data_volumes: &[Option<&[u8]>],
    recovery_count: usize,
    recovery_volumes: &[(usize, &[u8])],
) -> Result<Vec<Vec<u8>>> {
    if data_volumes.is_empty() || data_volumes.len() + recovery_count > SYMBOL_LIMIT {
        return Err(Error::InvalidCodewordSize);
    }
    if recovery_volumes.is_empty() || recovery_count == 0 || recovery_count > SYMBOL_LIMIT {
        return Err(Error::InvalidParitySize);
    }
    let shard_len = recovery_volumes[0].1.len();
    if recovery_volumes
        .iter()
        .any(|&(index, data)| index >= recovery_count || data.len() != shard_len)
    {
        return Err(Error::InvalidCodewordSize);
    }
    if data_volumes
        .iter()
        .flatten()
        .any(|data| data.len() > shard_len)
    {
        return Err(Error::InvalidCodewordSize);
    }

    let mut recovery_by_index = vec![None; recovery_count];
    for &(index, data) in recovery_volumes {
        if recovery_by_index[index].replace(data).is_some() {
            return Err(Error::InvalidCodewordSize);
        }
    }

    let missing_data: Vec<_> = data_volumes
        .iter()
        .enumerate()
        .filter_map(|(index, data)| data.is_none().then_some(index))
        .collect();
    if missing_data.is_empty() {
        return Ok(data_volumes
            .iter()
            .map(|data| {
                let mut out = vec![0; shard_len];
                if let Some(data) = data {
                    out[..data.len()].copy_from_slice(data);
                }
                out
            })
            .collect());
    }

    let missing_recovery: Vec<_> = recovery_by_index
        .iter()
        .enumerate()
        .filter_map(|(index, data)| data.is_none().then_some(data_volumes.len() + index))
        .collect();
    let mut erasures = missing_data.clone();
    erasures.extend(missing_recovery);
    if erasures.len() > recovery_count {
        return Err(Error::TooManyErasures);
    }

    let coder = ByteFieldCoder::new(recovery_count)?;
    let mut out: Vec<Vec<u8>> = data_volumes
        .iter()
        .map(|data| {
            let mut shard = vec![0; shard_len];
            if let Some(data) = data {
                shard[..data.len()].copy_from_slice(data);
            }
            shard
        })
        .collect();

    // Every surviving symbol of the codeword, in codeword order: the data
    // volumes we still have, then the recovery volumes we still have.
    let mut known: Vec<(usize, &[u8])> = Vec::with_capacity(data_volumes.len() + recovery_count);
    for (index, data) in data_volumes.iter().enumerate() {
        if let Some(data) = data {
            known.push((index, data));
        }
    }
    for (index, data) in recovery_by_index.iter().enumerate() {
        if let Some(data) = data {
            known.push((data_volumes.len() + index, data));
        }
    }

    let codeword_len = data_volumes.len() + recovery_count;
    // No fallback path: every erasure set that reaches here derives its
    // coefficients. The erasures are distinct and inside the codeword (the
    // data indices are unique, the recovery ones are offset past them, and
    // the count is bounded above by `recovery_count` a few lines up), so the
    // locator carries exactly one simple root per erasure, all of them inside
    // the scanned range and each with a non-zero Forney denominator. An error
    // here would mean one of those held false, which is worth surfacing
    // rather than papering over. Until the root-scan alias fix (TODO 17e) it
    // could hold false for a full-length 255-symbol codeword, and the
    // original per-byte Forney loop stayed on as a fallback for exactly that
    // case; it now lives in the test module as the differential oracle.
    // (nzbfast-local change, 22 Aug 2026 - re-apply on the next rars
    // re-sync, and only on top of the root-scan fix, see
    // vendor/rars/VENDORING.md.)
    let matrix = erasure_correction_matrix(&coder, codeword_len, &erasures, &known)?;

    // One multiply-by-constant table per (rebuilt volume, surviving volume).
    // `erasures` starts with `missing_data`, so matrix row `i` is the
    // correction for `missing_data[i]`; the missing recovery rows that follow
    // are never read back, since recovery volumes are not outputs.
    let tables: Vec<Vec<Option<[u8; 256]>>> = (0..missing_data.len())
        .map(|row| {
            known
                .iter()
                .map(|&(position, _)| {
                    let coefficient = matrix[row][position];
                    (coefficient != 0).then(|| coder.mul_table(coefficient))
                })
                .collect()
        })
        .collect();

    // Accumulate one chunk of one rebuilt volume: every surviving volume's
    // matching bytes, each scaled by its coefficient and folded in. The
    // destination stays in cache while the sources stream past it, and the
    // sources that cover the whole chunk are folded four to a pass, so the
    // destination is rewritten a quarter as often. Still one table load per
    // source byte.
    let fold_chunk = |destination: &mut [u8], row: usize, start: usize| {
        let end = start + destination.len();
        let mut whole: [(&[u8; 256], &[u8]); SYMBOL_LIMIT] = [(&[0; 256], &[]); SYMBOL_LIMIT];
        let mut whole_count = 0;
        for (slot, &(_, data)) in known.iter().enumerate() {
            let Some(table) = &tables[row][slot] else {
                continue;
            };
            // A volume shorter than the shard reads as zero past its end, and
            // `table[0]` is zero, so the tail contributes nothing.
            let available = data.len().min(end);
            if available <= start {
                continue;
            }
            if available == end {
                whole[whole_count] = (table, &data[start..end]);
                whole_count += 1;
                continue;
            }
            for (byte, &symbol) in destination.iter_mut().zip(&data[start..available]) {
                *byte ^= table[usize::from(symbol)];
            }
        }
        let mut quads = whole[..whole_count].chunks_exact(4);
        for quad in &mut quads {
            let [(t0, s0), (t1, s1), (t2, s2), (t3, s3)] = [quad[0], quad[1], quad[2], quad[3]];
            for ((((byte, &b0), &b1), &b2), &b3) in
                destination.iter_mut().zip(s0).zip(s1).zip(s2).zip(s3)
            {
                *byte ^= t0[usize::from(b0)]
                    ^ t1[usize::from(b1)]
                    ^ t2[usize::from(b2)]
                    ^ t3[usize::from(b3)];
            }
        }
        for &(table, source) in quads.remainder() {
            for (byte, &symbol) in destination.iter_mut().zip(source) {
                *byte ^= table[usize::from(symbol)];
            }
        }
    };

    for (row, &target) in missing_data.iter().enumerate() {
        // `out[target]` starts zeroed: a missing volume contributed no bytes
        // to the copy above, so this accumulates the correction in place.
        // Chunks touch disjoint output and only read shared input.
        #[cfg(feature = "parallel")]
        if reconstruct_on_team(out[target].len(), tables[row].iter().flatten().count()) {
            use rayon::prelude::*;
            out[target]
                .par_chunks_mut(RECONSTRUCT_CHUNK)
                .enumerate()
                .for_each(|(index, destination)| {
                    fold_chunk(destination, row, index * RECONSTRUCT_CHUNK);
                });
            continue;
        }
        for (index, destination) in out[target].chunks_mut(RECONSTRUCT_CHUNK).enumerate() {
            fold_chunk(destination, row, index * RECONSTRUCT_CHUNK);
        }
    }

    Ok(out)
}

/// One 512-byte sector of a RAR 3.x embedded recovery record.
///
/// The unit is the format's, not a tuning choice: the record stores one
/// 16-bit tag per sector and one parity sector per group, and
/// `rar15_40`'s repair path reads both at this stride.
pub const RECOVERY_SECTOR_LEN: usize = 512;

/// The geometry of one embedded ("Protect+") recovery record.
///
/// A RAR 3.x record protects the archive bytes that PRECEDE it, padded
/// with zeros to a whole number of sectors. It stores a CRC tag per
/// protected sector, which is how a damaged sector is located, then
/// `parity_sectors` XOR sectors, sector `k` folding every protected
/// sector whose index is congruent to `k` modulo `parity_sectors`. One
/// damaged sector per congruence class is therefore recoverable, and a
/// second one in the same class is not - which is the whole reason the
/// percentage matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewSubRecoveryPlan {
    /// Sectors the record covers; the last one may be partial and is
    /// zero-padded for both the tag and the XOR.
    pub protected_sectors: usize,
    /// XOR sectors written after the tag table.
    pub parity_sectors: usize,
}

impl NewSubRecoveryPlan {
    /// Bytes the record's data area occupies: the tag table, then the
    /// parity sectors.
    pub const fn data_len(self) -> usize {
        self.protected_sectors * 2 + self.parity_sectors * RECOVERY_SECTOR_LEN
    }
}

/// Sizes a record covering `protected_len` bytes at `percent` redundancy.
///
/// `percent` is the share of the PROTECTED SECTOR COUNT spent on parity,
/// floored, with a floor of one sector so a caller that asked for a
/// record always gets one. That is the same rule the RAR 5 planner uses
/// (`recovery::rar5::plan_inline_recovery`), deliberately: the two
/// generations then answer one `recovery_record_pct` the same way, which
/// is what a catalog row comparing them needs. It is NOT bit-identical
/// to what `rar` itself picks - measured on one 200,059-byte archive,
/// `rar 7.23` chose 4/8/12/19/39/78/117/195 parity sectors for
/// 1/2/3/5/10/20/30/50 percent against this rule's 3/7/11/19/39/78/117/195,
/// so it rounds rather than floors and shades the estimate by a sector or
/// two at the bottom of the range. Nothing reads the ratio back: `rar`
/// and this crate's own repair path both derive the geometry from the
/// stored counts.
pub fn plan_newsub_recovery(protected_len: usize, percent: u32) -> Result<NewSubRecoveryPlan> {
    let protected_sectors = protected_len.div_ceil(RECOVERY_SECTOR_LEN);
    if protected_sectors == 0 {
        return Err(Error::InvalidCodewordSize);
    }
    let percent = percent.min(100) as usize;
    if percent == 0 {
        return Err(Error::InvalidParitySize);
    }
    let parity_sectors = (protected_sectors * percent / 100)
        .max(1)
        .min(protected_sectors);
    Ok(NewSubRecoveryPlan {
        protected_sectors,
        parity_sectors,
    })
}

/// Builds the record's data area over `protected`.
///
/// `protected` is the archive prefix the record will sit after, exactly:
/// a byte more or less shifts every sector and the record repairs
/// nothing. The tag is `!crc32(sector) & 0xffff`, which is the form
/// `rar15_40`'s repair path checks against and the form `rar` writes.
pub fn build_newsub_recovery_data(protected: &[u8], plan: NewSubRecoveryPlan) -> Vec<u8> {
    let mut out = vec![0u8; plan.data_len()];
    let (tags, parity) = out.split_at_mut(plan.protected_sectors * 2);
    for index in 0..plan.protected_sectors {
        let sector = padded_sector(protected, index);
        let tag = (!crate::crc32::crc32(&sector) & 0xffff) as u16;
        tags[index * 2..index * 2 + 2].copy_from_slice(&tag.to_le_bytes());
        let slot = index % plan.parity_sectors;
        let row = &mut parity[slot * RECOVERY_SECTOR_LEN..(slot + 1) * RECOVERY_SECTOR_LEN];
        for (out_byte, byte) in row.iter_mut().zip(sector) {
            *out_byte ^= byte;
        }
    }
    out
}

/// Sector `index` of the protected prefix, zero-padded past its end.
fn padded_sector(protected: &[u8], index: usize) -> [u8; RECOVERY_SECTOR_LEN] {
    let mut sector = [0u8; RECOVERY_SECTOR_LEN];
    let start = index * RECOVERY_SECTOR_LEN;
    if start < protected.len() {
        let end = (start + RECOVERY_SECTOR_LEN).min(protected.len());
        sector[..end - start].copy_from_slice(&protected[start..end]);
    }
    sector
}

#[cfg(test)]
mod tests {
    use super::{
        build_newsub_recovery_data, byte_mul, plan_newsub_recovery, reconstruct_data_volumes,
        ByteFieldCoder, Error, BYTE_EXP, BYTE_LOG, RECOVERY_SECTOR_LEN, SYMBOL_LIMIT,
    };

    #[test]
    fn a_newsub_plan_covers_every_byte_and_spends_the_percent_on_parity() {
        // A partial trailing sector still counts: the record pads it.
        let plan = plan_newsub_recovery(1025, 10).unwrap();
        assert_eq!(plan.protected_sectors, 3);
        assert_eq!(plan.parity_sectors, 1);
        assert_eq!(plan.data_len(), 3 * 2 + RECOVERY_SECTOR_LEN);

        // 391 sectors is the geometry `rar 7.23` was measured on; it
        // rounds where this floors, so 5 percent agrees at 19 and 1
        // percent does not (rar picked 4).
        assert_eq!(plan_newsub_recovery(200_059, 5).unwrap().parity_sectors, 19);
        assert_eq!(plan_newsub_recovery(200_059, 1).unwrap().parity_sectors, 3);

        // The floor of one parity sector: a caller that asked for a
        // record gets one rather than a header describing nothing.
        assert!(plan_newsub_recovery(200_059, 0).is_err());
        assert_eq!(
            plan_newsub_recovery(200_059, 100).unwrap().parity_sectors,
            391
        );
        assert_eq!(plan_newsub_recovery(1, 1).unwrap().parity_sectors, 1);
        // Nothing to protect is a refusal, not an empty record.
        assert!(plan_newsub_recovery(0, 10).is_err());
    }

    #[test]
    fn newsub_recovery_data_tags_every_sector_and_folds_it_into_its_group() {
        let protected: Vec<u8> = (0..2600u32).map(|byte| (byte % 251) as u8).collect();
        let plan = plan_newsub_recovery(protected.len(), 40).unwrap();
        assert_eq!(plan.protected_sectors, 6);
        assert_eq!(plan.parity_sectors, 2);
        let data = build_newsub_recovery_data(&protected, plan);
        assert_eq!(data.len(), plan.data_len());

        let (tags, parity) = data.split_at(plan.protected_sectors * 2);
        let mut padded = protected.clone();
        padded.resize(plan.protected_sectors * RECOVERY_SECTOR_LEN, 0);
        for index in 0..plan.protected_sectors {
            let sector = &padded[index * RECOVERY_SECTOR_LEN..(index + 1) * RECOVERY_SECTOR_LEN];
            // The tag `rar` writes and this crate's repair path checks:
            // the low half of the complement of the sector's CRC32.
            let expected = (!crate::crc32::crc32(sector) & 0xffff) as u16;
            assert_eq!(
                u16::from_le_bytes(tags[index * 2..index * 2 + 2].try_into().unwrap()),
                expected,
                "sector {index}"
            );
        }
        for slot in 0..plan.parity_sectors {
            let mut fold = vec![0u8; RECOVERY_SECTOR_LEN];
            for index in (slot..plan.protected_sectors).step_by(plan.parity_sectors) {
                for (out, byte) in fold
                    .iter_mut()
                    .zip(&padded[index * RECOVERY_SECTOR_LEN..(index + 1) * RECOVERY_SECTOR_LEN])
                {
                    *out ^= byte;
                }
            }
            assert_eq!(
                &parity[slot * RECOVERY_SECTOR_LEN..(slot + 1) * RECOVERY_SECTOR_LEN],
                &fold[..],
                "parity slot {slot}"
            );
        }
    }

    /// Solve the full Forney decode once per byte offset.
    ///
    /// This is the original reconstruction loop, quadratic in the volume count
    /// and allocating about half a dozen vectors per output byte. It shipped as
    /// production's fallback while a full-length codeword could defeat the root
    /// scan; with that fixed it is kept here, and only here, as the differential
    /// oracle the bulk matrix path is checked against.
    fn reconstruct_per_symbol(
        data_volumes: &[Option<&[u8]>],
        recovery_by_index: &[Option<&[u8]>],
        coder: &ByteFieldCoder,
        erasures: &[usize],
        missing_data: &[usize],
        shard_len: usize,
        mut out: Vec<Vec<u8>>,
    ) -> super::Result<Vec<Vec<u8>>> {
        for offset in 0..shard_len {
            let mut codeword = vec![0; data_volumes.len() + recovery_by_index.len()];
            for (index, data) in data_volumes.iter().enumerate() {
                if let Some(data) = data {
                    codeword[index] = data.get(offset).copied().unwrap_or(0);
                }
            }
            for (index, data) in recovery_by_index.iter().enumerate() {
                if let Some(data) = data {
                    codeword[data_volumes.len() + index] = data[offset];
                }
            }
            coder.correct_erasures(&mut codeword, erasures)?;
            for &index in missing_data {
                out[index][offset] = codeword[index];
            }
        }
        Ok(out)
    }

    /// Drive the original per-byte Forney loop directly, as the differential
    /// reference the bulk matrix path must agree with byte for byte.
    fn reconstruct_reference(
        data_volumes: &[Option<&[u8]>],
        recovery_count: usize,
        recovery_volumes: &[(usize, &[u8])],
    ) -> super::Result<Vec<Vec<u8>>> {
        let shard_len = recovery_volumes[0].1.len();
        let mut recovery_by_index = vec![None; recovery_count];
        for &(index, data) in recovery_volumes {
            recovery_by_index[index] = Some(data);
        }
        let missing_data: Vec<_> = data_volumes
            .iter()
            .enumerate()
            .filter_map(|(index, data)| data.is_none().then_some(index))
            .collect();
        let missing_recovery: Vec<_> = recovery_by_index
            .iter()
            .enumerate()
            .filter_map(|(index, data)| data.is_none().then_some(data_volumes.len() + index))
            .collect();
        let mut erasures = missing_data.clone();
        erasures.extend(missing_recovery);

        let coder = ByteFieldCoder::new(recovery_count)?;
        let out: Vec<Vec<u8>> = data_volumes
            .iter()
            .map(|data| {
                let mut shard = vec![0; shard_len];
                if let Some(data) = data {
                    shard[..data.len()].copy_from_slice(data);
                }
                shard
            })
            .collect();
        reconstruct_per_symbol(
            data_volumes,
            &recovery_by_index,
            &coder,
            &erasures,
            &missing_data,
            shard_len,
            out,
        )
    }

    /// Build the correction matrix the same way `reconstruct_data_volumes`
    /// does, so a test can tell whether production took the matrix path or
    /// the per-byte fallback.
    fn correction_matrix_for(
        data_volumes: &[Option<&[u8]>],
        recovery_count: usize,
        recovery_volumes: &[(usize, &[u8])],
    ) -> super::Result<Vec<Vec<u8>>> {
        let mut recovery_by_index = vec![None; recovery_count];
        for &(index, data) in recovery_volumes {
            recovery_by_index[index] = Some(data);
        }
        let mut erasures: Vec<usize> = data_volumes
            .iter()
            .enumerate()
            .filter_map(|(index, data)| data.is_none().then_some(index))
            .collect();
        erasures.extend(
            recovery_by_index
                .iter()
                .enumerate()
                .filter_map(|(index, data)| data.is_none().then_some(data_volumes.len() + index)),
        );
        let mut known: Vec<(usize, &[u8])> = Vec::new();
        for (index, data) in data_volumes.iter().enumerate() {
            if let Some(data) = data {
                known.push((index, data));
            }
        }
        for (index, data) in recovery_by_index.iter().enumerate() {
            if let Some(data) = data {
                known.push((data_volumes.len() + index, data));
            }
        }
        super::erasure_correction_matrix(
            &ByteFieldCoder::new(recovery_count)?,
            data_volumes.len() + recovery_count,
            &erasures,
            &known,
        )
    }

    /// Column-wise RS(255) parity over the same generator `ByteFieldCoder` builds,
    /// i.e. the shape a real .rev set carries.
    fn encode_columns(data: &[Vec<u8>], recovery_count: usize, shard_len: usize) -> Vec<Vec<u8>> {
        let coder = ByteFieldCoder::new(recovery_count).unwrap();
        let mut parity = vec![vec![0u8; shard_len]; recovery_count];
        for offset in 0..shard_len {
            let column: Vec<u8> = data
                .iter()
                .map(|shard| shard.get(offset).copied().unwrap_or(0))
                .collect();
            for (row, byte) in parity.iter_mut().zip(coder.encode(&column)) {
                row[offset] = byte;
            }
        }
        parity
    }

    fn pseudorandom(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as u8
            })
            .collect()
    }

    /// The bulk matrix path must reproduce the per-byte Forney decode exactly,
    /// across volume counts, erasure counts, ragged final volumes, shards that
    /// straddle the chunking boundary, and all-zero input.
    #[test]
    fn bulk_reconstruction_matches_per_byte_reference() {
        let chunk = super::RECONSTRUCT_CHUNK;
        let cases: &[(usize, usize, usize, usize)] = &[
            // (data volumes, recovery count, missing data, shard length)
            (3, 2, 1, 12),
            (3, 2, 2, 257),
            (8, 4, 4, 1000),
            (16, 3, 1, chunk - 1),
            (16, 3, 1, chunk),
            (16, 3, 2, chunk + 1),
            (16, 3, 3, 2 * chunk + 37),
            (50, 5, 5, 4096),
            (1, 1, 1, 64),
            (200, 55, 2, 512),
        ];
        for &(volumes, recovery_count, missing, shard_len) in cases {
            let mut data: Vec<Vec<u8>> = (0..volumes)
                .map(|index| pseudorandom(shard_len, 0x9e37 + index as u64))
                .collect();
            // Ragged tail: real sets end on a short volume.
            if shard_len > 3 {
                data[volumes - 1].truncate(shard_len - 3);
            }
            let parity = encode_columns(&data, recovery_count, shard_len);

            let mut present: Vec<Option<&[u8]>> =
                data.iter().map(|shard| Some(shard.as_slice())).collect();
            for slot in present.iter_mut().take(missing) {
                *slot = None;
            }
            let recovery: Vec<(usize, &[u8])> = (0..missing)
                .map(|index| (index, parity[index].as_slice()))
                .collect();

            // Production falls back to the per-byte loop when (and only when)
            // the coefficients cannot be derived, so this pins which path the
            // case below actually took -- without it, a case that quietly fell
            // back would compare the reference against itself and pass. Every
            // decodable erasure set derives, including the full-length
            // 255-symbol codeword since the root-scan alias fix.
            let took_matrix_path =
                correction_matrix_for(&present, recovery_count, &recovery).is_ok();
            assert!(
                took_matrix_path,
                "unexpected fallback for {volumes}+{recovery_count}, {missing} missing"
            );

            let fast = reconstruct_data_volumes(&present, recovery_count, &recovery);
            let reference = reconstruct_reference(&present, recovery_count, &recovery);
            // Success or failure, the two paths must answer identically.
            assert_eq!(
                fast, reference,
                "fast path diverged for {volumes}+{recovery_count}, {missing} missing, {shard_len} B"
            );
            let Ok(fast) = fast else {
                continue;
            };
            // And where it succeeds it must rebuild the original bytes.
            for index in 0..missing {
                assert_eq!(
                    &fast[index][..data[index].len()],
                    data[index].as_slice(),
                    "wrong bytes for volume {index} of {volumes}+{recovery_count}"
                );
            }
        }
    }

    /// A run of zero bytes makes the codeword self-consistent, which the
    /// per-byte decoder handled by an early return. The matrix path must land
    /// on the same zeros rather than diverging there.
    #[test]
    fn all_zero_shards_reconstruct_as_zero() {
        let data: Vec<Vec<u8>> = vec![vec![0u8; 300]; 6];
        let parity = encode_columns(&data, 3, 300);
        let mut present: Vec<Option<&[u8]>> =
            data.iter().map(|shard| Some(shard.as_slice())).collect();
        present[2] = None;
        let recovery = [(0usize, parity[0].as_slice())];

        let fast = reconstruct_data_volumes(&present, 3, &recovery).unwrap();
        let reference = reconstruct_reference(&present, 3, &recovery).unwrap();

        assert_eq!(fast, reference);
        assert!(fast[2].iter().all(|&byte| byte == 0));
    }

    /// Recovery volumes may themselves be missing; they count against the
    /// erasure budget but are never emitted.
    #[test]
    fn missing_recovery_volumes_count_as_erasures() {
        let data: Vec<Vec<u8>> = (0..5).map(|i| pseudorandom(600, 0x5151 + i)).collect();
        let parity = encode_columns(&data, 4, 600);
        let mut present: Vec<Option<&[u8]>> =
            data.iter().map(|shard| Some(shard.as_slice())).collect();
        present[1] = None;
        present[4] = None;
        // Only recovery rows 1 and 3 survive: rows 0 and 2 are erasures too.
        let recovery = [(1usize, parity[1].as_slice()), (3usize, parity[3].as_slice())];

        let fast = reconstruct_data_volumes(&present, 4, &recovery).unwrap();
        let reference = reconstruct_reference(&present, 4, &recovery).unwrap();

        assert_eq!(fast, reference);
        assert_eq!(fast[1], data[1]);
        assert_eq!(fast[4], data[4]);
    }

    #[test]
    fn max_parity_bound_is_unchanged() {
        assert_eq!(SYMBOL_LIMIT, 255);
    }

    /// Full-length codeword, last position erased: root 0 and root 255 are
    /// aliases in the Chien scan (exponents are taken mod 255), and before
    /// the range clamp the scan recorded the same true root twice -- the
    /// valid loc 0 plus the impossible loc 255 -- and refused to repair.
    #[test]
    fn full_length_codeword_repairs_last_position() {
        let data_count = 250;
        let recovery_count = 5;
        assert_eq!(data_count + recovery_count, SYMBOL_LIMIT);
        let coder = ByteFieldCoder::new(recovery_count).unwrap();

        let data = pseudorandom(data_count, 0xC0DE);
        let parity = coder.encode(&data);
        let mut codeword: Vec<u8> = data.clone();
        codeword.extend_from_slice(&parity);

        // Erase the last data symbol (position 254 of the codeword is parity;
        // exercise both the last data position and the very last position).
        for &erased in &[data_count - 1, SYMBOL_LIMIT - 1] {
            let mut damaged = codeword.clone();
            damaged[erased] = damaged[erased].wrapping_add(1);
            coder.correct_erasures(&mut damaged, &[erased]).unwrap();
            assert_eq!(damaged, codeword, "position {erased} did not repair");
        }

        // And the bulk volume path over the same full-length geometry.
        let shard_len = 400;
        let volumes: Vec<Vec<u8>> = (0..data_count)
            .map(|index| pseudorandom(shard_len, 0xFEED + index as u64))
            .collect();
        let volume_parity = encode_columns(&volumes, recovery_count, shard_len);
        let mut present: Vec<Option<&[u8]>> =
            volumes.iter().map(|shard| Some(shard.as_slice())).collect();
        present[data_count - 1] = None;
        let recovery = [(0usize, volume_parity[0].as_slice())];

        let rebuilt = reconstruct_data_volumes(&present, recovery_count, &recovery).unwrap();
        assert_eq!(rebuilt[data_count - 1], volumes[data_count - 1]);
    }

    /// The per-byte loop above shipped as production's fallback for exactly
    /// one reason: while a full-length codeword scanned alpha^0 twice, its
    /// erasure sets could not derive coefficients, and the bulk path had to
    /// stand aside rather than answer differently from the decoder. With the
    /// root range fixed the fallback is gone, so the claim that replaced it
    /// has to hold: every erasure set that gets past the argument checks
    /// derives. Sweep the full-length geometries, where the alias lived, at
    /// erasure counts up to the whole parity budget - including the sets
    /// that erase the last data volume, whose root is the aliased one.
    #[test]
    fn no_full_length_erasure_set_needs_a_per_byte_fallback() {
        let shard_len = 8;
        for &(data_count, recovery_count) in &[(200usize, 55usize), (250, 5), (128, 127)] {
            assert_eq!(data_count + recovery_count, SYMBOL_LIMIT);
            let volumes: Vec<Vec<u8>> = (0..data_count)
                .map(|index| pseudorandom(shard_len, 0xA11A + index as u64))
                .collect();
            let parity = encode_columns(&volumes, recovery_count, shard_len);

            for missing in [1usize, recovery_count] {
                // The last `missing` data volumes are gone, and only the
                // first `missing` recovery volumes survive - so the erasure
                // set is the full parity budget, data and recovery together.
                let mut present: Vec<Option<&[u8]>> =
                    volumes.iter().map(|shard| Some(shard.as_slice())).collect();
                for slot in present.iter_mut().rev().take(missing) {
                    *slot = None;
                }
                let recovery: Vec<(usize, &[u8])> = (0..missing)
                    .map(|index| (index, parity[index].as_slice()))
                    .collect();

                assert!(
                    correction_matrix_for(&present, recovery_count, &recovery).is_ok(),
                    "fallback needed for {data_count}+{recovery_count}, {missing} missing"
                );
                let rebuilt = reconstruct_data_volumes(&present, recovery_count, &recovery)
                    .expect("full-length reconstruction");
                for index in (data_count - missing)..data_count {
                    assert_eq!(
                        rebuilt[index], volumes[index],
                        "wrong bytes for volume {index} of {data_count}+{recovery_count}"
                    );
                }
            }
        }
    }

    #[test]
    fn rs8_generator_polynomial_is_pinned() {
        let coder = ByteFieldCoder::new(11).unwrap();
        assert_eq!(
            coder.generator(),
            vec![97, 180, 203, 151, 195, 196, 219, 7, 113, 50, 69]
        );
    }

    #[test]
    fn rs8_reconstructs_single_erased_data_symbol() {
        let coder = ByteFieldCoder::new(4).unwrap();
        let data = b"rar recovery data";
        let parity = coder.encode(data);
        let mut codeword = [data.as_slice(), parity.as_slice()].concat();
        let original = codeword.clone();
        codeword[3] ^= 0xa5;

        coder.correct_erasures(&mut codeword, &[3]).unwrap();

        assert_eq!(codeword, original);
    }

    #[test]
    fn rs8_reconstructs_multiple_erased_symbols_including_parity() {
        let coder = ByteFieldCoder::new(5).unwrap();
        let data = b"rar3-rs8";
        let parity = coder.encode(data);
        let mut codeword = [data.as_slice(), parity.as_slice()].concat();
        let original = codeword.clone();
        codeword[1] = 0;
        codeword[7] = 0;
        codeword[10] = 0;

        coder.correct_erasures(&mut codeword, &[1, 7, 10]).unwrap();

        assert_eq!(codeword, original);
    }

    #[test]
    fn rs8_rejects_more_erasures_than_parity_symbols() {
        let coder = ByteFieldCoder::new(2).unwrap();
        let mut codeword = b"abcde".to_vec();

        assert_eq!(
            coder.correct_erasures(&mut codeword, &[0, 1, 2]),
            Err(Error::TooManyErasures)
        );
    }

    /// The rebuild's team gate sits where 15 Sep 2026 measured the crossover
    /// (VENDORING.md), and a set just under it and one at it rebuild the same
    /// bytes as the volumes they lost.
    #[test]
    fn rev3_rebuild_starts_a_team_only_from_the_measured_crossover() {
        #[cfg(feature = "parallel")]
        {
            for (threads, work) in [(1usize, 2 << 20), (16, 2 << 20), (20, 2560 << 10), (32, 4 << 20), (64, 8 << 20)] {
                assert_eq!(
                    super::reconstruct_team_min_work_for(threads),
                    work,
                    "RAR 3 gate at {threads} threads"
                );
            }
            crate::recovery::rar5::with_fold_team_threads(32, || {
                assert!(!super::reconstruct_on_team(128 << 10, 16));
                assert!(!super::reconstruct_on_team((4 << 20) - 1, 1));
                assert!(super::reconstruct_on_team(256 << 10, 16));
                assert!(super::reconstruct_on_team(usize::MAX, 2));
            });
            crate::recovery::rar5::with_fold_team_threads(2, || {
                assert!(!super::reconstruct_on_team(64 << 10, 16));
                assert!(super::reconstruct_on_team(128 << 10, 16));
            });
        }
        // 16 volumes, one lost: 15 survivors plus one recovery volume fold
        // into the rebuilt one.
        for shard in [64 << 10, 128 << 10] {
            let volumes: Vec<Vec<u8>> = (0..16)
                .map(|index| pseudorandom(shard, 0x7E3 + index as u64))
                .collect();
            let parity = encode_columns(&volumes, 3, shard);
            let mut present: Vec<Option<&[u8]>> = volumes
                .iter()
                .map(|volume| Some(volume.as_slice()))
                .collect();
            present[9] = None;
            let rebuilt =
                reconstruct_data_volumes(&present, 3, &[(1, parity[1].as_slice())]).unwrap();
            assert!(rebuilt[9] == volumes[9], "rebuild of {shard}-byte volumes");
        }
    }

    #[test]
    fn rev3_reconstructs_missing_data_volume_from_recovery_volume() {
        let data = [
            b"volume-one".as_slice(),
            b"volume-two".as_slice(),
            b"volume-three".as_slice(),
        ];
        let recovery_count = 2;
        let coder = ByteFieldCoder::new(recovery_count).unwrap();
        let shard_len = data.iter().map(|shard| shard.len()).max().unwrap();
        let mut recovery = vec![vec![0; shard_len]; recovery_count];
        for offset in 0..shard_len {
            let column: Vec<_> = data
                .iter()
                .map(|shard| shard.get(offset).copied().unwrap_or(0))
                .collect();
            let encoded = coder.encode(&column);
            for (row, byte) in recovery.iter_mut().zip(encoded) {
                row[offset] = byte;
            }
        }

        let repaired = reconstruct_data_volumes(
            &[Some(data[0]), None, Some(data[2])],
            recovery_count,
            &[(0, recovery[0].as_slice())],
        )
        .unwrap();

        assert_eq!(&repaired[1][..data[1].len()], data[1]);
    }

    /// Bitwise multiply straight from the field definition, sharing nothing
    /// with the tables.
    fn bitwise_byte_mul(mut left: u8, mut right: u8) -> u8 {
        let mut product = 0;
        while right != 0 {
            if right & 1 != 0 {
                product ^= left;
            }
            let carry = left & 0x80 != 0;
            left <<= 1;
            if carry {
                left ^= 0x1d;
            }
            right >>= 1;
        }
        product
    }

    #[test]
    fn byte_field_tables_match_the_field_definition() {
        assert_eq!(BYTE_EXP[0], 1);
        for index in 1..BYTE_EXP.len() {
            let shifted = u16::from(BYTE_EXP[index - 1]) << 1;
            let expected = if shifted > 0xff {
                shifted ^ 0x11d
            } else {
                shifted
            };
            assert_eq!(u16::from(BYTE_EXP[index]), expected, "exponent {index}");
        }
        assert_eq!(BYTE_EXP[255], 1, "a^255 is a^0");
        for power in 0..SYMBOL_LIMIT {
            assert_eq!(usize::from(BYTE_LOG[usize::from(BYTE_EXP[power])]), power);
        }
        for value in 1..=255u8 {
            assert_eq!(BYTE_EXP[usize::from(BYTE_LOG[usize::from(value)])], value);
        }
        assert_eq!(byte_mul(2, 2), 4);
        let coder = ByteFieldCoder::new(1).unwrap();
        for coefficient in 0..=255u8 {
            let table = coder.mul_table(coefficient);
            for value in 0..=255u8 {
                let expected = bitwise_byte_mul(coefficient, value);
                assert_eq!(table[usize::from(value)], expected);
                assert_eq!(byte_mul(coefficient, value), expected);
            }
        }
    }

    #[test]
    fn parity_counts_outside_one_to_255_are_refused() {
        assert_eq!(
            ByteFieldCoder::new(0).unwrap_err(),
            Error::InvalidParitySize
        );
        assert_eq!(
            ByteFieldCoder::new(256).unwrap_err(),
            Error::InvalidParitySize
        );
        assert!(ByteFieldCoder::new(1).is_ok());
        assert!(ByteFieldCoder::new(255).is_ok());
    }

    /// Whatever the erasure list, a codeword that is already consistent is
    /// left exactly as it was.
    #[test]
    fn a_clean_codeword_is_left_alone_whatever_the_erasure_list() {
        let coder = ByteFieldCoder::new(4).unwrap();
        let data = pseudorandom(20, 7);
        let original = [data.as_slice(), &coder.encode(&data)].concat();
        for erasures in [&[][..], &[0, 5, 23][..], &[0, 1, 2, 3, 4, 5][..]] {
            let mut codeword = original.clone();
            coder.correct_erasures(&mut codeword, erasures).unwrap();
            assert_eq!(codeword, original, "erasures {erasures:?}");
        }
        let mut zeros = vec![0u8; 24];
        coder.correct_erasures(&mut zeros, &[3]).unwrap();
        assert!(zeros.iter().all(|&byte| byte == 0));
    }

    /// Requests the decoder cannot honour are refused by name and leave the
    /// codeword untouched, never a guessed repair.
    #[test]
    fn malformed_decode_requests_are_refused_and_change_nothing() {
        let coder = ByteFieldCoder::new(3).unwrap();
        let data = b"adversarial";
        let clean = [data.as_slice(), &coder.encode(data)].concat();
        let mut damaged = clean.clone();
        damaged[2] ^= 0x40;

        let refusals: [(&[usize], Error); 4] = [
            (&[clean.len()], Error::InvalidCodewordSize),
            (&[], Error::DecodeFailed),
            (&[2, 2], Error::DecodeFailed),
            (&[0, 1, 2, 3], Error::TooManyErasures),
        ];
        for (erasures, error) in refusals {
            let mut codeword = damaged.clone();
            assert_eq!(coder.correct_erasures(&mut codeword, erasures), Err(error));
            assert_eq!(codeword, damaged, "erasures {erasures:?}");
        }
        assert_eq!(
            coder.correct_erasures(&mut [], &[]),
            Err(Error::InvalidCodewordSize)
        );
        let mut long = vec![1u8; SYMBOL_LIMIT + 1];
        assert_eq!(
            coder.correct_erasures(&mut long, &[0]),
            Err(Error::InvalidCodewordSize)
        );
        let mut codeword = damaged.clone();
        coder.correct_erasures(&mut codeword, &[2]).unwrap();
        assert_eq!(codeword, clean);
    }

    /// Every erasure pattern of every size on short codewords, including
    /// full-length ones, where the last position's root is `a^0`.
    #[test]
    fn every_erasure_subset_up_to_the_budget_repairs_the_codeword() {
        for &(data_len, parity) in &[(5usize, 3usize), (1, 4), (250, 5), (252, 3)] {
            let coder = ByteFieldCoder::new(parity).unwrap();
            let data = pseudorandom(data_len, 0xE7A5 + data_len as u64);
            let clean = [data.as_slice(), &coder.encode(&data)].concat();
            let len = clean.len();
            // Small codewords try every subset; long ones every subset of the
            // first and last few positions.
            let candidates: Vec<usize> = if len <= 8 {
                (0..len).collect()
            } else {
                (0..3).chain(len - 5..len).collect()
            };
            for mask in 1u32..(1 << candidates.len()) {
                let erasures: Vec<usize> = candidates
                    .iter()
                    .enumerate()
                    .filter(|&(bit, _)| mask & (1 << bit) != 0)
                    .map(|(_, &position)| position)
                    .collect();
                let mut codeword = clean.clone();
                for &position in &erasures {
                    codeword[position] ^= 0x5a;
                }
                let result = coder.correct_erasures(&mut codeword, &erasures);
                if erasures.len() > parity {
                    assert_eq!(result, Err(Error::TooManyErasures));
                } else {
                    result.unwrap();
                    assert_eq!(codeword, clean, "{data_len}+{parity} erasures {erasures:?}");
                }
            }
        }
    }

    /// Random geometries and erasure patterns under, at and past the parity
    /// budget, through the volume path: every decodable set rebuilds the
    /// original volumes and agrees with the per-byte loop, and one erasure
    /// too many is refused by name.
    #[test]
    fn random_erasure_patterns_rebuild_or_refuse() {
        let mut state = 0x5EED_CAFE_u64;
        let mut next = move |bound: usize| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((state >> 33) as usize) % bound
        };
        let (mut at_limit, mut past_limit) = (0, 0);
        for round in 0..80u64 {
            let recovery_count = 1 + next(12);
            let data_count = if round % 8 == 0 {
                SYMBOL_LIMIT - recovery_count
            } else {
                1 + next(40)
            };
            let shard_len = 1 + next(if data_count > 100 { 16 } else { 300 });
            let mut volumes: Vec<Vec<u8>> = (0..data_count)
                .map(|index| pseudorandom(shard_len, round * 1000 + index as u64))
                .collect();
            let ragged = 1 + next(shard_len);
            volumes[data_count - 1].truncate(ragged);
            let parity = encode_columns(&volumes, recovery_count, shard_len);

            // Distinct random picks: a partial shuffle of each index range.
            let mut data_order: Vec<usize> = (0..data_count).collect();
            let mut recovery_order: Vec<usize> = (0..recovery_count).collect();
            for order in [&mut data_order, &mut recovery_order] {
                for slot in 0..order.len() {
                    let pick = slot + next(order.len() - slot);
                    order.swap(slot, pick);
                }
            }
            let wanted = 1 + next(recovery_count + 1);
            let missing_data = (1 + next(wanted)).min(data_count);
            // At least one recovery volume must survive to name the shard length.
            let missing_recovery = (wanted - missing_data.min(wanted)).min(recovery_count - 1);
            let erasures = missing_data + missing_recovery;

            let mut present: Vec<Option<&[u8]>> =
                volumes.iter().map(|shard| Some(shard.as_slice())).collect();
            for &index in &data_order[..missing_data] {
                present[index] = None;
            }
            let recovery: Vec<(usize, &[u8])> = recovery_order[missing_recovery..]
                .iter()
                .map(|&index| (index, parity[index].as_slice()))
                .collect();

            let rebuilt = reconstruct_data_volumes(&present, recovery_count, &recovery);
            if erasures > recovery_count {
                past_limit += 1;
                assert_eq!(rebuilt, Err(Error::TooManyErasures), "round {round}");
                continue;
            }
            at_limit += usize::from(erasures == recovery_count);
            let rebuilt = rebuilt.unwrap_or_else(|error| panic!("round {round}: {error}"));
            assert_eq!(
                Ok(&rebuilt),
                reconstruct_reference(&present, recovery_count, &recovery).as_ref(),
                "round {round}"
            );
            for (index, volume) in volumes.iter().enumerate() {
                assert_eq!(
                    &rebuilt[index][..volume.len()],
                    volume.as_slice(),
                    "round {round}"
                );
                assert!(rebuilt[index][volume.len()..].iter().all(|&byte| byte == 0));
            }
        }
        assert!(
            at_limit > 0 && past_limit > 0,
            "{at_limit} at, {past_limit} past"
        );
    }

    /// The 64 MiB repair the clean-room spec measures: 16 data volumes of
    /// 4 MiB, 3 recovery volumes, one data volume missing. Timing only; run
    /// in release with `--ignored --nocapture` and read the best of seven.
    #[test]
    #[ignore = "timing harness, run by hand in release"]
    fn rev3_repair_64mib_throughput() {
        const SHARD: usize = 4 * 1024 * 1024;
        let volumes: Vec<Vec<u8>> = (0..16)
            .map(|index| pseudorandom(SHARD, 0xB3AC + index as u64))
            .collect();
        let parity = encode_columns(&volumes, 3, SHARD);
        let mut present: Vec<Option<&[u8]>> =
            volumes.iter().map(|shard| Some(shard.as_slice())).collect();
        present[5] = None;
        let recovery = [(0usize, parity[0].as_slice())];

        let mut best = f64::MAX;
        for _ in 0..7 {
            let start = std::time::Instant::now();
            let rebuilt = reconstruct_data_volumes(&present, 3, &recovery).unwrap();
            best = best.min(start.elapsed().as_secs_f64());
            assert_eq!(rebuilt[5], volumes[5]);
        }
        println!(
            "rev3 64 MiB repair: best {:.2} ms, {:.0} MiB/s",
            best * 1e3,
            64.0 / best
        );
    }
}
