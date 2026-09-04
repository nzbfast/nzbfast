const MAX_PARITY: usize = 255;
const MAX_POLYNOMIAL: usize = 512;
const PRIMITIVE_POLYNOMIAL: u16 = 0x11d;

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

#[derive(Debug, Clone)]
pub(crate) struct RSCoder8 {
    parity_size: usize,
    gf_exp: [u8; MAX_POLYNOMIAL],
    gf_log: [u16; MAX_PARITY + 1],
    generator: Vec<u8>,
}

impl RSCoder8 {
    pub(crate) fn new(parity_size: usize) -> Result<Self> {
        if parity_size == 0 || parity_size > MAX_PARITY {
            return Err(Error::InvalidParitySize);
        }
        let mut coder = Self {
            parity_size,
            gf_exp: [0; MAX_POLYNOMIAL],
            gf_log: [0; MAX_PARITY + 1],
            generator: vec![0; parity_size],
        };
        coder.init_field();
        coder.init_generator();
        Ok(coder)
    }

    #[cfg(test)]
    fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut shift = vec![0u8; self.parity_size + 1];
        for &byte in data {
            let feedback = byte ^ shift[self.parity_size - 1];
            for index in (1..self.parity_size).rev() {
                shift[index] = shift[index - 1] ^ self.mul(self.generator[index], feedback);
            }
            shift[0] = self.mul(self.generator[0], feedback);
        }
        (0..self.parity_size)
            .map(|index| shift[self.parity_size - index - 1])
            .collect()
    }

    pub(crate) fn correct_erasures(&self, codeword: &mut [u8], erasures: &[usize]) -> Result<()> {
        if codeword.is_empty() || codeword.len() > MAX_PARITY {
            return Err(Error::InvalidCodewordSize);
        }
        if erasures.len() > self.parity_size {
            return Err(Error::TooManyErasures);
        }
        if erasures.iter().any(|&index| index >= codeword.len()) {
            return Err(Error::InvalidCodewordSize);
        }

        let mut syndromes = vec![0u8; self.parity_size];
        let mut all_zero = true;
        for (index, syndrome) in syndromes.iter_mut().enumerate() {
            let factor = self.gf_exp[index + 1];
            let mut sum = 0;
            for &byte in codeword.iter() {
                sum = byte ^ self.mul(factor, sum);
            }
            *syndrome = sum;
            all_zero &= sum == 0;
        }
        if all_zero {
            return Ok(());
        }
        if erasures.is_empty() {
            return Err(Error::DecodeFailed);
        }

        let mut locator = vec![0u8; self.parity_size + 1];
        locator[0] = 1;
        for &erasure in erasures {
            let multiplier = self.gf_exp[codeword.len() - erasure - 1];
            for index in (1..=self.parity_size).rev() {
                locator[index] ^= self.mul(multiplier, locator[index - 1]);
            }
        }

        let mut error_locs = Vec::new();
        let mut denominators = Vec::new();
        // Exponents are taken mod MAX_PARITY, so root 0 and root MAX_PARITY
        // evaluate identically. A full-length codeword would scan both and
        // record the same true root twice -- once as the valid loc 0 and once
        // as the impossible loc MAX_PARITY, failing the decode. Start at 1 so
        // alpha^0 is scanned exactly once; shorter codewords already do.
        for root in (MAX_PARITY - codeword.len()).max(1)..=MAX_PARITY {
            let mut sum = 0;
            for (power, &coefficient) in locator.iter().enumerate() {
                sum ^= self.mul(self.gf_exp[(power * root) % MAX_PARITY], coefficient);
            }
            if sum == 0 {
                let loc = MAX_PARITY - root;
                error_locs.push(loc);
                let mut denominator = 0;
                for index in (1..=self.parity_size).step_by(2) {
                    denominator ^= self.mul(
                        locator[index],
                        self.gf_exp[(root * (index - 1)) % MAX_PARITY],
                    );
                }
                denominators.push(denominator);
            }
        }
        if error_locs.is_empty() || error_locs.len() > self.parity_size {
            return Err(Error::DecodeFailed);
        }

        let evaluator = self.multiply_polynomials(&locator, &syndromes);
        for (&loc, &denominator) in error_locs.iter().zip(&denominators) {
            if denominator == 0 {
                return Err(Error::DecodeFailed);
            }
            let data_pos = codeword
                .len()
                .checked_sub(loc + 1)
                .ok_or(Error::DecodeFailed)?;
            let dloc = MAX_PARITY - loc;
            let mut numerator = 0;
            for (index, &coefficient) in evaluator.iter().enumerate() {
                numerator ^= self.mul(coefficient, self.gf_exp[(dloc * index) % MAX_PARITY]);
            }
            let correction = self.mul(
                numerator,
                self.gf_exp[MAX_PARITY - usize::from(self.gf_log[denominator as usize])],
            );
            codeword[data_pos] ^= correction;
        }
        Ok(())
    }

    fn init_field(&mut self) {
        let mut value = 1u16;
        for index in 0..MAX_PARITY {
            self.gf_log[value as usize] = index as u16;
            self.gf_exp[index] = value as u8;
            value <<= 1;
            if value > 0xff {
                value ^= PRIMITIVE_POLYNOMIAL;
            }
        }
        for index in MAX_PARITY..MAX_POLYNOMIAL {
            self.gf_exp[index] = self.gf_exp[index - MAX_PARITY];
        }
    }

    fn init_generator(&mut self) {
        let mut current = vec![0u8; self.parity_size];
        current[0] = 1;
        for index in 1..=self.parity_size {
            let mut factor = vec![0u8; self.parity_size];
            factor[0] = self.gf_exp[index];
            if self.parity_size > 1 {
                factor[1] = 1;
            }
            self.generator = self.multiply_polynomials(&factor, &current);
            current.clone_from(&self.generator);
        }
    }

    fn multiply_polynomials(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; self.parity_size];
        for left_index in 0..self.parity_size {
            if left.get(left_index).copied().unwrap_or(0) == 0 {
                continue;
            }
            for right_index in 0..(self.parity_size - left_index) {
                out[left_index + right_index] ^= self.mul(
                    left[left_index],
                    right.get(right_index).copied().unwrap_or(0),
                );
            }
        }
        out
    }

    fn mul(&self, left: u8, right: u8) -> u8 {
        if left == 0 || right == 0 {
            0
        } else {
            self.gf_exp[usize::from(self.gf_log[left as usize] + self.gf_log[right as usize])]
        }
    }

    /// Multiply-by-constant lookup, so bulk reconstruction costs one indexed
    /// load per byte instead of two log lookups, an add, and a branch.
    fn mul_table(&self, coefficient: u8) -> [u8; 256] {
        let mut table = [0u8; 256];
        for (value, slot) in table.iter_mut().enumerate() {
            *slot = self.mul(coefficient, value as u8);
        }
        table
    }
}

/// Bytes of one output volume rebuilt per pass, so the destination slice stays
/// in cache while every source volume streams past it.
const RECONSTRUCT_CHUNK: usize = 64 * 1024;

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
    coder: &RSCoder8,
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
    if data_volumes.is_empty() || data_volumes.len() + recovery_count > MAX_PARITY {
        return Err(Error::InvalidCodewordSize);
    }
    if recovery_volumes.is_empty() || recovery_count == 0 || recovery_count > MAX_PARITY {
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

    let coder = RSCoder8::new(recovery_count)?;
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
    // destination stays in cache while the sources stream past it.
    let fold_chunk = |destination: &mut [u8], row: usize, start: usize| {
        let end = start + destination.len();
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
            for (byte, &symbol) in destination.iter_mut().zip(&data[start..available]) {
                *byte ^= table[usize::from(symbol)];
            }
        }
    };

    for (row, &target) in missing_data.iter().enumerate() {
        // `out[target]` starts zeroed: a missing volume contributed no bytes
        // to the copy above, so this accumulates the correction in place.
        // Chunks touch disjoint output and only read shared input.
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            out[target]
                .par_chunks_mut(RECONSTRUCT_CHUNK)
                .enumerate()
                .for_each(|(index, destination)| {
                    fold_chunk(destination, row, index * RECONSTRUCT_CHUNK);
                });
        }
        #[cfg(not(feature = "parallel"))]
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
        build_newsub_recovery_data, plan_newsub_recovery, reconstruct_data_volumes, Error,
        RSCoder8, MAX_PARITY, RECOVERY_SECTOR_LEN,
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
        assert_eq!(plan_newsub_recovery(200_059, 0).is_err(), true);
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
        coder: &RSCoder8,
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

        let coder = RSCoder8::new(recovery_count)?;
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
            &RSCoder8::new(recovery_count)?,
            data_volumes.len() + recovery_count,
            &erasures,
            &known,
        )
    }

    /// Column-wise RS(255) parity over the same generator `RSCoder8` builds,
    /// i.e. the shape a real .rev set carries.
    fn encode_columns(data: &[Vec<u8>], recovery_count: usize, shard_len: usize) -> Vec<Vec<u8>> {
        let coder = RSCoder8::new(recovery_count).unwrap();
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
        assert_eq!(MAX_PARITY, 255);
    }

    /// Full-length codeword, last position erased: root 0 and root 255 are
    /// aliases in the Chien scan (exponents are taken mod 255), and before
    /// the range clamp the scan recorded the same true root twice -- the
    /// valid loc 0 plus the impossible loc 255 -- and refused to repair.
    #[test]
    fn full_length_codeword_repairs_last_position() {
        let data_count = 250;
        let recovery_count = 5;
        assert_eq!(data_count + recovery_count, MAX_PARITY);
        let coder = RSCoder8::new(recovery_count).unwrap();

        let data = pseudorandom(data_count, 0xC0DE);
        let parity = coder.encode(&data);
        let mut codeword: Vec<u8> = data.clone();
        codeword.extend_from_slice(&parity);

        // Erase the last data symbol (position 254 of the codeword is parity;
        // exercise both the last data position and the very last position).
        for &erased in &[data_count - 1, MAX_PARITY - 1] {
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
            assert_eq!(data_count + recovery_count, MAX_PARITY);
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
    fn rs8_encoder_matches_unrar_generator_shape() {
        let coder = RSCoder8::new(11).unwrap();
        assert_eq!(
            coder.generator,
            vec![97, 180, 203, 151, 195, 196, 219, 7, 113, 50, 69]
        );
    }

    #[test]
    fn rs8_reconstructs_single_erased_data_symbol() {
        let coder = RSCoder8::new(4).unwrap();
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
        let coder = RSCoder8::new(5).unwrap();
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
        let coder = RSCoder8::new(2).unwrap();
        let mut codeword = b"abcde".to_vec();

        assert_eq!(
            coder.correct_erasures(&mut codeword, &[0, 1, 2]),
            Err(Error::TooManyErasures)
        );
    }

    #[test]
    fn rev3_reconstructs_missing_data_volume_from_recovery_volume() {
        let data = [
            b"volume-one".as_slice(),
            b"volume-two".as_slice(),
            b"volume-three".as_slice(),
        ];
        let recovery_count = 2;
        let coder = RSCoder8::new(recovery_count).unwrap();
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
}
