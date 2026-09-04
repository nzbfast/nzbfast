const CRC64_XZ_POLY: u64 = 0xc96c_5795_d787_0f42;
const CRC64_XZ_INIT: u64 = 0xffff_ffff_ffff_ffff;
pub(crate) const FIELD_SIZE: usize = 65_535;
const FIELD_MASK: u32 = 0xffff;
const PRIMITIVE_POLYNOMIAL: u32 = 0x1100b;
const ZERO_LOG_SENTINEL: u32 = (FIELD_SIZE * 2) as u32;
const MAX_WINRAR602_DATA_SHARDS: u64 = 200;
const KIB: u64 = 1024;
const RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE: u64 = 0x48;
/// What a *declared* shard grid is allowed to cost before any of it is backed
/// by real bytes. A REV volume states its data-volume count in a `u16`, and the
/// metadata table for the maximum 65,535 slots still fits under the 1 MiB
/// header cap, so a sub-2 MiB `.rev` can ask reconstruction for 65,535
/// payload-sized buffers. Both bounds sit above any recovery set a machine
/// could serve anyway: reconstruction below holds the whole grid in RAM, so
/// past the byte bound it cannot run inside any sane memory budget - raising
/// the numbers is not the fix, stripe reconstruction is.
pub(crate) const MAX_RECONSTRUCTION_SHARDS: usize = 4_096;
const MAX_RECONSTRUCTION_BYTES: u64 = 8 * KIB * KIB * KIB;
/// Ceiling on a striped plan's `damaged * data_count` encoder cells (u16s),
/// i.e. 64 MB of matrix at 32M cells. The striped path holds only the
/// selected rows, so `data_count` alone costs nothing grid-shaped any more -
/// a 100 GB release split into 15 MB volumes is ~6,800 data volumes and must
/// plan - but a crafted header can still pair a wide slot count with a huge
/// damage list, and rows * columns is what that declaration actually
/// allocates. Any real repair is tens of damaged volumes against tens of
/// thousands of slots at most, orders of magnitude under this line.
const MAX_STRIPE_PLAN_CELLS: usize = 32 * 1024 * 1024;
/// Most parity one recovery record stores. A data shard is `group_count`
/// bytes, so once the protected region passes `data_shards * this` - about
/// 13 MB - a shard's parity row no longer fits one record and is split across
/// several, consecutive in the file. Below that there is exactly one group,
/// which is why every small archive repaired and every real one did not.
const RAR5_RECOVERY_PARITY_PER_RECORD_MAX: u64 = 64 * KIB;

use crate::write_progress::ProgressReporter;
use crate::{WriteOperation, WriteProgressEvent};

fn shared_gf16() -> &'static Gf16 {
    static GF16: std::sync::OnceLock<Gf16> = std::sync::OnceLock::new();
    GF16.get_or_init(Gf16::new)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    BadRecoveryChunk,
    OddShardSize,
    PlanOverflow,
    PrefixExceedsPlan,
    ReconstructionTooLarge,
    TooManyDamagedShards,
    ShardSizeMismatch,
    TooManyShards,
    SingularElement,
    /// The repair is arithmetically possible but the CALLER's budget cannot
    /// fund even a minimum stripe. Distinct from `ReconstructionTooLarge`,
    /// which is this crate's own ceiling on a whole-grid reconstruct: this
    /// one is answered by giving the repair a wider budget.
    RepairTooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRecoveryChunk => f.write_str("RAR 5 recovery chunk is invalid"),
            Self::OddShardSize => f.write_str("RAR 5 recovery shard size is odd"),
            Self::PlanOverflow => f.write_str("RAR 5 recovery plan overflows"),
            Self::PrefixExceedsPlan => {
                f.write_str("RAR 5 recovery prefix exceeds planned shard capacity")
            }
            Self::ReconstructionTooLarge => {
                f.write_str("RAR 5 recovery shard grid exceeds the reconstruction budget")
            }
            Self::TooManyDamagedShards => {
                f.write_str("RAR 5 recovery data cannot repair this many damaged shards")
            }
            Self::ShardSizeMismatch => f.write_str("RAR 5 recovery shard sizes differ"),
            Self::TooManyShards => f.write_str("RAR 5 recovery shard count is invalid"),
            Self::SingularElement => f.write_str("RAR 5 recovery matrix is singular"),
            Self::RepairTooLarge => {
                f.write_str("RAR 5 recovery needs more working memory than the budget allows")
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct InlineRecoveryPlan {
    pub data_shards: u64,
    pub recovery_shards: u64,
    pub group_count: u64,
    pub header_size: u64,
    pub shard_size: u64,
}

impl InlineRecoveryPlan {
    pub fn payload_size(self) -> Result<u64> {
        self.recovery_shards
            .checked_mul(self.shard_size)
            .ok_or(Error::PlanOverflow)
    }
}

pub fn plan_inline_recovery(
    archive_size: u64,
    recovery_percent: u64,
) -> Result<InlineRecoveryPlan> {
    let pct = recovery_percent.min(100);
    let data_shards = if archive_size >= 200 * KIB {
        MAX_WINRAR602_DATA_SHARDS
    } else {
        archive_size.div_ceil(KIB).max(1)
    };
    let mut recovery_shards = (2 * pct * data_shards) / 200;
    recovery_shards = recovery_shards.min(data_shards);
    if recovery_shards == 0 && archive_size < 200 * KIB {
        recovery_shards = 1;
    }
    let mut group_count = archive_size.div_ceil(data_shards);
    group_count += group_count & 1;
    let header_size = data_shards
        .checked_mul(8)
        .and_then(|value| value.checked_add(RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE))
        .ok_or(Error::PlanOverflow)?;
    // A shard's parity row is stored as one record per group, each with its
    // own header, so the shard's on-disk span is every header plus the row.
    // This used to assume a single record, which is the same number only
    // below ~13 MB.
    let shard_size = group_count
        .div_ceil(RAR5_RECOVERY_PARITY_PER_RECORD_MAX)
        .max(1)
        .checked_mul(header_size)
        .and_then(|headers| headers.checked_add(group_count))
        .ok_or(Error::PlanOverflow)?;

    Ok(InlineRecoveryPlan {
        data_shards,
        recovery_shards,
        group_count,
        header_size,
        shard_size,
    })
}

/// One storage group: the slice `[offset, offset + len)` of EVERY data shard.
///
/// The recovery grid is not divided by group - the Reed-Solomon code still
/// runs column-wise over all `data_shards` for the whole `group_count` - but
/// the parity and the shard CRCs are STORED per group, so a group is the unit
/// both are read and repaired in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryGroup {
    pub offset: u64,
    pub len: u64,
}

/// The groups `plan` splits each data shard into, in file order.
///
/// Derived entirely from `group_count`, so no record is ever trusted to say
/// which group it belongs to - only checked against this layout.
pub fn recovery_groups(plan: InlineRecoveryPlan) -> Result<Vec<RecoveryGroup>> {
    if plan.group_count == 0 {
        return Err(Error::BadRecoveryChunk);
    }
    let count = plan.group_count.div_ceil(RAR5_RECOVERY_PARITY_PER_RECORD_MAX);
    let count_usize = usize::try_from(count).map_err(|_| Error::PlanOverflow)?;
    let mut groups = Vec::with_capacity(count_usize);
    for index in 0..count {
        let offset = index
            .checked_mul(RAR5_RECOVERY_PARITY_PER_RECORD_MAX)
            .ok_or(Error::PlanOverflow)?;
        let len = RAR5_RECOVERY_PARITY_PER_RECORD_MAX.min(plan.group_count - offset);
        groups.push(RecoveryGroup { offset, len });
    }
    Ok(groups)
}

/// Bytes one recovery shard occupies on disk, its record headers included.
pub fn shard_record_span(plan: InlineRecoveryPlan) -> Result<u64> {
    let groups = recovery_groups(plan)?;
    (groups.len() as u64)
        .checked_mul(plan.header_size)
        .and_then(|headers| headers.checked_add(plan.group_count))
        .ok_or(Error::PlanOverflow)
}

/// The prefix range group `group` covers inside data shard `shard`.
///
/// Clamped to `protected_size`: the last shard of the last group runs off the
/// end of the protected region and is zero-padded for the code's purposes,
/// but only the real bytes are ever read or written back.
fn group_shard_range(
    plan: InlineRecoveryPlan,
    group: RecoveryGroup,
    shard: usize,
    protected_size: u64,
) -> Result<std::ops::Range<usize>> {
    let start = (shard as u64)
        .checked_mul(plan.group_count)
        .and_then(|base| base.checked_add(group.offset))
        .ok_or(Error::PlanOverflow)?
        .min(protected_size);
    let end = start.saturating_add(group.len).min(protected_size);
    Ok(usize::try_from(start).map_err(|_| Error::PlanOverflow)?
        ..usize::try_from(end).map_err(|_| Error::PlanOverflow)?)
}

/// Assigns records to groups from where they sit in the file.
///
/// `records` is `(record_offset, shard_index, parity_len)`; the result is the
/// group index of each, or `None` for a record that does not land on a group
/// boundary or whose parity is not that group's length.
///
/// Position is COMPUTED, not counted: record `(shard_index, k)` sits at
/// `base + shard_index * shard_size + Σ_{j<k}(header_size + len_j)`. Counting
/// records as they are discovered would shift every record after a damaged
/// one into the wrong group and repair it against another group's parity -
/// silent corruption rather than a failed repair.
///
/// `area_floor` is the lowest offset the recovery area can possibly start at,
/// in the same coordinates as `records`: the end of the protected prefix when
/// the offsets are file-absolute, and 0 when they are relative to a recovery
/// buffer. It is what usually resolves the ambiguity described below.
pub fn assign_recovery_groups(
    plan: InlineRecoveryPlan,
    records: &[(u64, usize, u64)],
    area_floor: u64,
) -> Result<Vec<Option<usize>>> {
    let groups = recovery_groups(plan)?;
    let span = shard_record_span(plan)?;
    let mut boundaries = Vec::with_capacity(groups.len());
    let mut cursor = 0u64;
    for group in &groups {
        boundaries.push(cursor);
        cursor = cursor
            .checked_add(plan.header_size)
            .and_then(|value| value.checked_add(group.len))
            .ok_or(Error::PlanOverflow)?;
    }

    // The recovery area starts where shard 0's group 0 record does. Every
    // record knows its own shard_index, so each implies a base; the smallest
    // is the true one, since no record can precede group 0 of its own shard.
    let base = records
        .iter()
        .filter_map(|&(offset, shard_index, _)| {
            offset.checked_sub((shard_index as u64).checked_mul(span)?)
        })
        .min()
        .ok_or(Error::BadRecoveryChunk)?;

    let assign = |anchor: u64| -> Vec<Option<usize>> {
        records
            .iter()
            .map(|&(offset, shard_index, parity_len)| {
                let shard_base = (shard_index as u64)
                    .checked_mul(span)
                    .and_then(|value| anchor.checked_add(value))?;
                let within = offset.checked_sub(shard_base)?;
                let index = boundaries.iter().position(|&value| value == within)?;
                (groups[index].len == parity_len).then_some(index)
            })
            .collect()
    };
    let assigned = assign(base);

    // The base above is inferred from the earliest SURVIVING record, and a
    // record only survives if its CRC64 checks out. If every group-0 record
    // in the set is damaged, the first survivors are group-1 records, the
    // inferred base shifts forward by exactly one record boundary, and those
    // records are assigned to group 0. Nothing downstream can tell: in a set
    // of two or more FULL groups the parity lengths are equal, so the length
    // check above passes, and the repair then compares group 1's CRC table
    // against group 0's data, calls group 0 damaged, and rebuilds group 0's
    // ranges out of group 1's parity. With enough surviving rows to fund it
    // (a 100% recovery record is the clear case) both the buffered and the
    // streaming API return success having written the wrong bytes.
    //
    // Verifying the rebuilt shards afterwards does not catch it - they match
    // the table the repair used. So the ambiguity is settled here, before any
    // parity is applied: if shifting the base back by whole boundaries is
    // equally consistent with every surviving record, the layout is genuinely
    // undecidable and this fails closed. A healthy set is never ambiguous -
    // the last group's records pin it, since they cannot shift any further.
    let explained = |assignment: &[Option<usize>]| assignment.iter().filter(|g| g.is_some()).count();
    let here = explained(&assigned);
    if here > 0 {
        for shift in boundaries.iter().skip(1) {
            let Some(alternative) = base.checked_sub(*shift) else {
                break;
            };
            if alternative < area_floor {
                // The recovery area cannot start before the data it protects,
                // so this shift and every larger one are ruled out.
                break;
            }
            // An earlier base that accounts for at least as many surviving
            // records as this one is not distinguishable from it. A healthy
            // set is never in that position: shifting the whole layout back
            // pushes the LAST group's records off the end of the group table,
            // so the alternative always explains strictly fewer.
            if explained(&assign(alternative)) >= here {
                return Err(Error::BadRecoveryChunk);
            }
        }
    }
    Ok(assigned)
}

/// Places each found record in the group whose parity it carries.
fn group_records<'a>(
    found: &'a [FoundInlineRecoveryChunk],
    plan: InlineRecoveryPlan,
    area_floor: u64,
) -> Result<Vec<Vec<&'a InlineRecoveryChunk>>> {
    let groups = recovery_groups(plan)?;
    let records: Vec<(u64, usize, u64)> = found
        .iter()
        .map(|entry| {
            (
                entry.offset as u64,
                entry.chunk.shard_index,
                entry.chunk.parity.len() as u64,
            )
        })
        .collect();
    let assigned = assign_recovery_groups(plan, &records, area_floor)?;

    let mut by_group: Vec<Vec<&InlineRecoveryChunk>> = vec![Vec::new(); groups.len()];
    for (entry, group) in found.iter().zip(assigned) {
        if let Some(index) = group {
            by_group[index].push(&entry.chunk);
        }
    }
    Ok(by_group)
}

pub fn crc64_xz(data: &[u8]) -> u64 {
    crc64_update(data, CRC64_XZ_INIT) ^ CRC64_XZ_INIT
}

/// Seed for an incremental [`crc64_xz`]; the running state is finalized by
/// XOR-ing this value back out.
pub const CRC64_XZ_SEED: u64 = CRC64_XZ_INIT;

/// Slice-by-8 tables: table 0 is the classic one-byte table and table `n`
/// advances a state byte through `n` additional zero bytes, so eight input
/// bytes fold with eight independent lookups per iteration. Stored as eight
/// flat arrays rather than one nested one so each lookup is a single
/// bounds-checked index even in unoptimized builds.
const CRC64_TABLES: [[u64; 256]; 8] = build_crc64_table();
const CRC64_TABLE_0: [u64; 256] = CRC64_TABLES[0];
const CRC64_TABLE_1: [u64; 256] = CRC64_TABLES[1];
const CRC64_TABLE_2: [u64; 256] = CRC64_TABLES[2];
const CRC64_TABLE_3: [u64; 256] = CRC64_TABLES[3];
const CRC64_TABLE_4: [u64; 256] = CRC64_TABLES[4];
const CRC64_TABLE_5: [u64; 256] = CRC64_TABLES[5];
const CRC64_TABLE_6: [u64; 256] = CRC64_TABLES[6];
const CRC64_TABLE_7: [u64; 256] = CRC64_TABLES[7];

const fn build_crc64_table() -> [[u64; 256]; 8] {
    let mut table = [[0u64; 256]; 8];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u64;
        let mut bit = 0;
        while bit < 8 {
            let mask = 0u64.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC64_XZ_POLY & mask);
            bit += 1;
        }
        table[0][index] = crc;
        index += 1;
    }
    let mut slice = 1;
    while slice < 8 {
        let mut index = 0;
        while index < 256 {
            let previous = table[slice - 1][index];
            table[slice][index] = (previous >> 8) ^ table[0][(previous & 0xff) as usize];
            index += 1;
        }
        slice += 1;
    }
    table
}

/// Folds `data` into a running CRC64 state.
///
/// Public so the streaming paths can hash a multi-gigabyte volume through a
/// fixed buffer: the whole-slice helpers ([`crc64_xz`], [`crc64_rar_state`])
/// would need the volume resident to be called at all. Seed with
/// [`CRC64_XZ_SEED`] for the XZ variant, or 0 for the RAR shard state.
pub fn crc64_update(data: &[u8], initial: u64) -> u64 {
    let mut crc = initial;
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        // Destructure instead of `try_into` and index each slice-by table
        // directly: this keeps the loop cheap even in unoptimized builds,
        // where the generic conversion and nested-array indexing cost more
        // than the fold itself (a debug-build wall-clock guard in the test
        // suite watches exactly that).
        let [b0, b1, b2, b3, b4, b5, b6, b7] = *chunk else {
            unreachable!("chunks_exact(8) yields 8-byte chunks");
        };
        let low = (crc as u32).to_le_bytes();
        let high = ((crc >> 32) as u32).to_le_bytes();
        crc = CRC64_TABLE_7[usize::from(b0 ^ low[0])]
            ^ CRC64_TABLE_6[usize::from(b1 ^ low[1])]
            ^ CRC64_TABLE_5[usize::from(b2 ^ low[2])]
            ^ CRC64_TABLE_4[usize::from(b3 ^ low[3])]
            ^ CRC64_TABLE_3[usize::from(b4 ^ high[0])]
            ^ CRC64_TABLE_2[usize::from(b5 ^ high[1])]
            ^ CRC64_TABLE_1[usize::from(b6 ^ high[2])]
            ^ CRC64_TABLE_0[usize::from(b7 ^ high[3])];
    }
    for &byte in chunks.remainder() {
        crc = (crc >> 8) ^ CRC64_TABLE_0[usize::from((crc as u8) ^ byte)];
    }
    crc
}

/// The original bit-serial fold, kept as the differential reference for the
/// table implementation.
#[cfg(test)]
fn crc64_update_bitwise(data: &[u8], initial: u64) -> u64 {
    let mut crc = initial;
    for &byte in data {
        crc ^= byte as u64;
        for _ in 0..8 {
            let mask = 0u64.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC64_XZ_POLY & mask);
        }
    }
    crc
}

pub fn crc64_rar_state(data: &[u8]) -> u64 {
    crc64_update(data, 0)
}

pub fn split_prefix_shard_ranges(
    prefix_len: usize,
    plan: InlineRecoveryPlan,
) -> Result<Vec<std::ops::Range<usize>>> {
    let data_shards = usize::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
    let group_count = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
    let capacity = data_shards
        .checked_mul(group_count)
        .ok_or(Error::PlanOverflow)?;
    if prefix_len > capacity {
        return Err(Error::PrefixExceedsPlan);
    }

    let mut ranges = Vec::with_capacity(data_shards);
    for shard_index in 0..data_shards {
        let start = shard_index
            .checked_mul(group_count)
            .ok_or(Error::PlanOverflow)?;
        let end = start.saturating_add(group_count).min(prefix_len);
        ranges.push(start..end);
    }
    Ok(ranges)
}

pub fn split_prefix_shards(prefix: &[u8], plan: InlineRecoveryPlan) -> Result<Vec<Vec<u8>>> {
    let group_count = usize::try_from(plan.group_count).map_err(|_| Error::PlanOverflow)?;
    let ranges = split_prefix_shard_ranges(prefix.len(), plan)?;
    let mut shards = Vec::with_capacity(ranges.len());
    for range in ranges {
        let mut shard = vec![0u8; group_count];
        if range.start < range.end {
            shard[..range.end - range.start].copy_from_slice(&prefix[range]);
        }
        shards.push(shard);
    }
    Ok(shards)
}

pub fn encode_inline_recovery_parity(
    archive_prefix: &[u8],
    recovery_percent: u64,
) -> Result<(InlineRecoveryPlan, Vec<Vec<u8>>)> {
    encode_inline_recovery_parity_with_progress(archive_prefix, recovery_percent, None, 1)
}

fn encode_inline_recovery_parity_with_progress(
    archive_prefix: &[u8],
    recovery_percent: u64,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<(InlineRecoveryPlan, Vec<Vec<u8>>)> {
    let plan = plan_inline_recovery(archive_prefix.len() as u64, recovery_percent)?;
    let shards = split_prefix_shards(archive_prefix, plan)?;
    let shard_refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
    let total_bytes = plan.payload_size()?;
    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationStarted {
            operation: WriteOperation::Recovery,
            total_bytes: Some(total_bytes),
            total_entries: None,
            pass,
        });
    }
    let parity = encode_parity_shards_with_progress(
        &shard_refs,
        usize::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?,
        |completed| {
            if let Some(progress) = progress {
                progress.report(WriteProgressEvent::Advanced {
                    operation: WriteOperation::Recovery,
                    completed_bytes: completed,
                    total_bytes,
                    pass,
                });
            }
        },
    )?;
    if let Some(progress) = progress {
        progress.report(WriteProgressEvent::OperationFinished {
            operation: WriteOperation::Recovery,
            total_bytes: Some(total_bytes),
            total_entries: None,
            pass,
        });
    }
    Ok((plan, parity))
}

pub fn build_structural_inline_recovery_data(
    archive_prefix: &[u8],
    recovery_percent: u64,
) -> Result<Vec<u8>> {
    build_structural_inline_recovery_data_with_progress(archive_prefix, recovery_percent, None, 1)
}

pub(crate) fn build_structural_inline_recovery_data_with_progress(
    archive_prefix: &[u8],
    recovery_percent: u64,
    progress: Option<ProgressReporter<'_>>,
    pass: usize,
) -> Result<Vec<u8>> {
    let (plan, parity) = encode_inline_recovery_parity_with_progress(
        archive_prefix,
        recovery_percent,
        progress,
        pass,
    )?;
    let shard_ranges = split_prefix_shard_ranges(archive_prefix.len(), plan)?;
    let total_len = usize::try_from(plan.payload_size()?).map_err(|_| Error::PlanOverflow)?;
    let header_size = usize::try_from(plan.header_size).map_err(|_| Error::PlanOverflow)?;
    let shard_size = usize::try_from(plan.shard_size).map_err(|_| Error::PlanOverflow)?;
    let data_shards = usize::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
    let recovery_shards = usize::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
    let header_size_u32 = u32::try_from(plan.header_size).map_err(|_| Error::PlanOverflow)?;
    let data_shards_u16 = u16::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
    let recovery_shards_u16 =
        u16::try_from(plan.recovery_shards).map_err(|_| Error::PlanOverflow)?;
    let chunk_data_extent = shard_ranges.last().map_or(0usize, std::ops::Range::len);
    let chunk_data_extent_u32 =
        u32::try_from(chunk_data_extent).map_err(|_| Error::PlanOverflow)?;
    // One record per (recovery shard, group), laid out shard-index-major:
    // every group of shard 0, then every group of shard 1. Writing a single
    // record carrying the whole parity row is what RARLab's own reader will
    // not accept above one group, and it is what our reader now rejects too.
    let groups = if plan.group_count == 0 {
        vec![RecoveryGroup { offset: 0, len: 0 }]
    } else {
        recovery_groups(plan)?
    };

    // Each group carries the CRC table for ITS OWN slice of every data shard,
    // which is what makes per-group damage detection possible on the way back
    // in.
    let mut states_by_group: Vec<Vec<u64>> = Vec::with_capacity(groups.len());
    for group in &groups {
        let mut states = Vec::with_capacity(data_shards);
        for shard in 0..data_shards {
            let range = group_shard_range(plan, *group, shard, archive_prefix.len() as u64)?;
            states.push(crc64_rar_state(&archive_prefix[range]));
        }
        states_by_group.push(states);
    }

    // The trailing state is shared: every record of a group carries the CRC of
    // SHARD 0's parity for that group, not its own. Splitting a row into
    // records does not change that - it only makes the shared value per-group.
    let mut final_state_by_group: Vec<u64> = Vec::with_capacity(groups.len());
    for group in &groups {
        let offset = usize::try_from(group.offset).map_err(|_| Error::PlanOverflow)?;
        let len = usize::try_from(group.len).map_err(|_| Error::PlanOverflow)?;
        final_state_by_group.push(
            parity
                .first()
                .and_then(|payload| payload.get(offset..offset + len))
                .map(crc64_rar_state)
                .unwrap_or(0),
        );
    }

    let mut out = Vec::with_capacity(total_len);
    for (shard_index, payload) in parity.iter().enumerate() {
        if payload.len() as u64 != plan.group_count {
            return Err(Error::PlanOverflow);
        }
        for ((group, states), final_state) in groups
            .iter()
            .zip(&states_by_group)
            .zip(&final_state_by_group)
        {
            let group_offset = usize::try_from(group.offset).map_err(|_| Error::PlanOverflow)?;
            let group_len = usize::try_from(group.len).map_err(|_| Error::PlanOverflow)?;
            let slice = payload
                .get(group_offset..group_offset + group_len)
                .ok_or(Error::PlanOverflow)?;
            let record_size = header_size
                .checked_add(group_len)
                .ok_or(Error::PlanOverflow)?;
            let record_size_u32 = u32::try_from(record_size).map_err(|_| Error::PlanOverflow)?;

            let chunk_start = out.len();
            out.extend_from_slice(b"{RB}");
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&record_size_u32.to_le_bytes());
            out.extend_from_slice(&header_size_u32.to_le_bytes());
            out.push(1);
            out.push(1);
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&chunk_data_extent_u32.to_le_bytes());
            out.extend_from_slice(&(archive_prefix.len() as u64).to_le_bytes());
            out.extend_from_slice(&plan.group_count.to_le_bytes());
            out.extend_from_slice(&plan.shard_size.to_le_bytes());
            out.extend_from_slice(&data_shards_u16.to_le_bytes());
            out.extend_from_slice(&recovery_shards_u16.to_le_bytes());
            out.extend_from_slice(
                &u16::try_from(shard_index)
                    .map_err(|_| Error::PlanOverflow)?
                    .to_le_bytes(),
            );
            for &state in states {
                out.extend_from_slice(&state.to_le_bytes());
            }
            out.extend_from_slice(&final_state.to_le_bytes());
            if out.len() - chunk_start != header_size {
                return Err(Error::PlanOverflow);
            }
            out.extend_from_slice(slice);
            if out.len() - chunk_start != record_size {
                return Err(Error::PlanOverflow);
            }

            let chunk_end = chunk_start
                .checked_add(record_size)
                .ok_or(Error::PlanOverflow)?;
            let crc_start = chunk_start.checked_add(0x0c).ok_or(Error::PlanOverflow)?;
            let crc = crc64_xz(out.get(crc_start..chunk_end).ok_or(Error::PlanOverflow)?);
            let crc_field_start = chunk_start.checked_add(0x04).ok_or(Error::PlanOverflow)?;
            let crc_field_end = chunk_start.checked_add(0x0c).ok_or(Error::PlanOverflow)?;
            out.get_mut(crc_field_start..crc_field_end)
                .ok_or(Error::PlanOverflow)?
                .copy_from_slice(&crc.to_le_bytes());
        }
        if out.len() - shard_index * shard_size != shard_size {
            return Err(Error::PlanOverflow);
        }
    }
    if out.len() != total_len {
        return Err(Error::PlanOverflow);
    }
    debug_assert_eq!(parity.len(), recovery_shards);
    debug_assert!(states_by_group.iter().all(|states| states.len() == data_shards));
    Ok(out)
}

#[derive(Debug, Clone)]
struct InlineRecoveryChunk {
    plan: InlineRecoveryPlan,
    /// This record's own size on disk, which is the discovery stride.
    /// Distinct from `plan.shard_size`, which spans every record of one
    /// recovery shard - the same number only when there is a single group.
    record_size: u64,
    protected_size: u64,
    shard_index: usize,
    /// CRC64 state per data shard for THIS RECORD'S GROUP's slice, not for
    /// the whole shard. Records of different groups carry different tables.
    data_shard_states: Vec<u64>,
    parity: Vec<u8>,
}

#[derive(Debug, Clone)]
struct FoundInlineRecoveryChunk {
    offset: usize,
    chunk: InlineRecoveryChunk,
}

pub fn repair_inline_recovery_prefix(
    archive_prefix: &[u8],
    recovery_data: &[u8],
) -> Result<Vec<u8>> {
    let found = find_inline_recovery_chunks(recovery_data)?;
    // Offsets are relative to `recovery_data`, so the area starts at 0.
    repair_prefix_with_chunks(archive_prefix, &found, 0)
}

/// Repairs `archive_prefix` one storage group at a time.
///
/// A group is the unit because everything the repair needs is stored per
/// group: the parity rows and the data-shard CRC table both describe a
/// group's slice of each shard, never the whole shard. Checking one group's
/// table against a whole shard - what this did before - reports all 200
/// shards damaged the moment an archive has more than one group.
///
/// Groups are also independent, which is worth having on its own: damage
/// confined to one group is repaired using that group's parity alone, so a
/// set that would be beyond the recovery shard count taken as a whole is
/// still repairable when the damage is spread across groups.
fn repair_prefix_with_chunks(
    archive_prefix: &[u8],
    found: &[FoundInlineRecoveryChunk],
    area_floor: u64,
) -> Result<Vec<u8>> {
    let first = found.first().ok_or(Error::BadRecoveryChunk)?;
    let plan = first.chunk.plan;
    let protected_size = archive_prefix.len() as u64;
    if first.chunk.protected_size != protected_size {
        return Err(Error::BadRecoveryChunk);
    }
    if found
        .iter()
        .any(|entry| entry.chunk.plan != plan || entry.chunk.protected_size != protected_size)
    {
        return Err(Error::BadRecoveryChunk);
    }

    let data_shards = usize::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
    let groups = recovery_groups(plan)?;
    let by_group = group_records(found, plan, area_floor)?;

    let mut repaired = archive_prefix.to_vec();
    for (group, rows) in groups.iter().zip(&by_group) {
        let Some(reference) = rows.first() else {
            // No surviving parity for this group. Nothing can be done for it
            // here; if its data is damaged the caller's own verification is
            // what reports the archive still broken.
            continue;
        };
        if reference.data_shard_states.len() != data_shards {
            return Err(Error::BadRecoveryChunk);
        }
        // Every record of one group carries the same table. Disagreement is
        // an inconsistent set rather than a damaged one, and repairing on
        // either table would be a guess.
        if rows
            .iter()
            .any(|row| row.data_shard_states != reference.data_shard_states)
        {
            return Err(Error::BadRecoveryChunk);
        }

        let mut ranges = Vec::with_capacity(data_shards);
        for shard in 0..data_shards {
            ranges.push(group_shard_range(plan, *group, shard, protected_size)?);
        }
        let damaged: Vec<usize> = ranges
            .iter()
            .enumerate()
            .filter_map(|(index, range)| {
                (crc64_rar_state(&repaired[range.clone()])
                    != reference.data_shard_states[index])
                    .then_some(index)
            })
            .collect();
        if damaged.is_empty() {
            continue;
        }
        if damaged.len() > rows.len() {
            return Err(Error::TooManyDamagedShards);
        }

        let group_len = usize::try_from(group.len).map_err(|_| Error::PlanOverflow)?;
        let mut shards: Vec<Vec<u8>> = ranges
            .iter()
            .map(|range| {
                let mut shard = vec![0u8; group_len];
                shard[..range.len()].copy_from_slice(&repaired[range.clone()]);
                shard
            })
            .collect();
        let recovery_rows: Vec<_> = rows[..damaged.len()]
            .iter()
            .map(|row| (row.shard_index, row.parity.as_slice()))
            .collect();
        recover_damaged_shards(&mut shards, &damaged, &recovery_rows)?;

        for &index in &damaged {
            let range = ranges[index].clone();
            if range.is_empty() {
                continue;
            }
            repaired[range.clone()].copy_from_slice(&shards[index][..range.len()]);
        }
    }
    debug_assert_eq!(repaired.len(), archive_prefix.len());
    Ok(repaired)
}

/// Repair damaged RAR5 inline-recovery data shards without materializing the
/// whole protected prefix.
///
/// `read_range` receives byte ranges relative to the protected prefix and must
/// return the current bytes for each requested range. The returned pairs contain
/// only the damaged prefix ranges that need to be written back, in ascending
/// order and never overlapping, which is what lets a caller stream the repaired
/// file out in one pass.
///
/// Group-by-group, for the same reason [`repair_prefix_with_chunks`] is: the
/// parity rows and the CRC table both describe ONE GROUP's slice of each data
/// shard. This used to take the first record's table for the whole set and
/// stride by `plan.group_count` - a whole shard - so on any archive with more
/// than one group (over ~13 MB) every shard's CRC disagreed and the repair
/// reported damage it could not fund. The daemon reaches the streaming path
/// instead, so the cost here was a missed repair, never wrong bytes.
pub fn repair_inline_recovery_prefix_shards<F>(
    protected_size: usize,
    recovery_data: &[u8],
    mut read_range: F,
) -> Result<Vec<(std::ops::Range<usize>, Vec<u8>)>>
where
    F: FnMut(std::ops::Range<usize>) -> Result<Vec<u8>>,
{
    // Found, not parsed: which group a record carries the parity for is
    // decided by where it sits in the file, so its offset has to survive to
    // here. Compacting the records first would shift every survivor after a
    // CRC-failed one into the wrong group.
    let found = find_inline_recovery_chunks(recovery_data)?;
    let first = found.first().ok_or(Error::BadRecoveryChunk)?;
    let plan = first.chunk.plan;
    let protected = protected_size as u64;
    if first.chunk.protected_size != protected {
        return Err(Error::BadRecoveryChunk);
    }
    if found
        .iter()
        .any(|entry| entry.chunk.plan != plan || entry.chunk.protected_size != protected)
    {
        return Err(Error::BadRecoveryChunk);
    }

    let data_shards = usize::try_from(plan.data_shards).map_err(|_| Error::PlanOverflow)?;
    let groups = recovery_groups(plan)?;
    let by_group = group_records(&found, plan, 0)?;

    let mut patches: Vec<(std::ops::Range<usize>, Vec<u8>)> = Vec::new();
    for (group, rows) in groups.iter().zip(&by_group) {
        let Some(reference) = rows.first() else {
            // No surviving parity for this group, so nothing here can repair
            // it. The caller's own verification is what reports the file still
            // broken.
            continue;
        };
        if reference.data_shard_states.len() != data_shards {
            return Err(Error::BadRecoveryChunk);
        }
        // Every record of one group carries the same table. Disagreement is an
        // inconsistent set rather than a damaged one, and repairing on either
        // table would be a guess.
        if rows
            .iter()
            .any(|row| row.data_shard_states != reference.data_shard_states)
        {
            return Err(Error::BadRecoveryChunk);
        }
        // The GF16 kernel walks two-byte symbols, so an odd shard length would
        // read one past the end. Group lengths come from an even `group_count`
        // capped at 64 KiB, so this only fires on a forged plan.
        let shard_len = usize::try_from(group.len).map_err(|_| Error::PlanOverflow)?;
        if !shard_len.is_multiple_of(2) {
            return Err(Error::OddShardSize);
        }

        let mut ranges = Vec::with_capacity(data_shards);
        for shard in 0..data_shards {
            ranges.push(group_shard_range(plan, *group, shard, protected)?);
        }
        let mut damaged = Vec::new();
        for (index, range) in ranges.iter().enumerate() {
            let state = if range.is_empty() {
                0
            } else {
                let shard = read_range(range.clone())?;
                if shard.len() != range.len() {
                    return Err(Error::ShardSizeMismatch);
                }
                crc64_rar_state(&shard)
            };
            if state != reference.data_shard_states[index] {
                damaged.push(index);
            }
        }
        if damaged.is_empty() {
            continue;
        }
        if damaged.len() > rows.len() {
            return Err(Error::TooManyDamagedShards);
        }

        let recovery_rows: Vec<_> = rows[..damaged.len()]
            .iter()
            .map(|row| (row.shard_index, row.parity.as_slice()))
            .collect();
        if recovery_rows
            .iter()
            .any(|(_, parity)| parity.len() != shard_len)
        {
            return Err(Error::ShardSizeMismatch);
        }
        let repaired = solve_damaged_group_shards(
            plan,
            &ranges,
            shard_len,
            &damaged,
            &recovery_rows,
            &mut read_range,
        )?;
        for (&index, data) in damaged.iter().zip(repaired) {
            if ranges[index].is_empty() {
                continue;
            }
            patches.push((ranges[index].clone(), data));
        }
    }

    // Groups are walked outermost, so the patches come out shard-minor within
    // each group rather than in file order. Sorting is what keeps the caller's
    // single forward pass valid; the ranges are disjoint slices of the prefix,
    // so the order is total.
    patches.sort_by_key(|(range, _)| range.start);
    Ok(patches)
}

/// Solves one group's damaged shards from that group's parity rows, reading
/// the surviving shards through `read_range` rather than holding them.
///
/// `ranges` is every data shard's slice of this group, `shard_len` the group's
/// padded shard length. Returns one buffer per entry of `damaged`, trimmed to
/// the real (unpadded) bytes of that shard's range.
fn solve_damaged_group_shards<F>(
    plan: InlineRecoveryPlan,
    ranges: &[std::ops::Range<usize>],
    shard_len: usize,
    damaged: &[usize],
    recovery_rows: &[(usize, &[u8])],
    read_range: &mut F,
) -> Result<Vec<Vec<u8>>>
where
    F: FnMut(std::ops::Range<usize>) -> Result<Vec<u8>>,
{
    // Defence in depth: `parse_inline_recovery_chunk` refuses these counts
    // before a plan exists, but the whole encoder grid below is sized from
    // them and this kernel serves every in-memory repair entry point, so it
    // refuses on its own account rather than trusting its callers (the same
    // lesson `recover_damaged_shards` already learned).
    if ranges.len() > MAX_RECONSTRUCTION_SHARDS
        || plan.recovery_shards > MAX_RECONSTRUCTION_SHARDS as u64
    {
        return Err(Error::ReconstructionTooLarge);
    }
    let matrix = make_encoder_matrix(ranges.len(), plan.recovery_shards as usize)?;
    let equations: Vec<Vec<u16>> = recovery_rows
        .iter()
        .map(|&(row_index, _)| {
            damaged
                .iter()
                .map(|&data_index| matrix[row_index][data_index])
                .collect()
        })
        .collect();
    let gf = shared_gf16();
    let inverse = invert_linear_system_matrix(gf, &equations)?;
    let word_count = shard_len / 2;
    let mut rhs_by_row = recovery_rows
        .iter()
        .map(|(_, parity)| {
            parity
                .chunks_exact(2)
                .map(|word| u16::from_le_bytes([word[0], word[1]]))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let damaged_lookup = damaged_lookup(ranges.len(), damaged)?;

    for (data_index, range) in ranges.iter().enumerate() {
        if damaged_lookup[data_index] {
            continue;
        }
        let shard = read_padded_prefix_shard(range.clone(), shard_len, read_range)?;
        for (row_index, rhs) in rhs_by_row.iter_mut().enumerate() {
            let coeff = matrix[recovery_rows[row_index].0][data_index];
            if coeff == 0 {
                continue;
            }
            for (word_index, word) in shard.chunks_exact(2).enumerate() {
                let data_symbol = u16::from_le_bytes([word[0], word[1]]);
                rhs[word_index] ^= gf.mul(coeff, data_symbol);
            }
        }
    }

    let mut repaired = damaged
        .iter()
        .map(|&index| vec![0; ranges[index].len()])
        .collect::<Vec<_>>();
    for word_index in 0..word_count {
        let rhs = rhs_by_row
            .iter()
            .map(|row| row[word_index])
            .collect::<Vec<_>>();
        let solved = apply_inverse_matrix(gf, &inverse, &rhs)?;
        for (output, &symbol) in repaired.iter_mut().zip(&solved) {
            let byte_offset = word_index * 2;
            if byte_offset < output.len() {
                let bytes = symbol.to_le_bytes();
                let take = (output.len() - byte_offset).min(2);
                output[byte_offset..byte_offset + take].copy_from_slice(&bytes[..take]);
            }
        }
    }
    Ok(repaired)
}

fn damaged_lookup(data_count: usize, damaged: &[usize]) -> Result<Vec<bool>> {
    let mut lookup = vec![false; data_count];
    for &index in damaged {
        if index >= data_count {
            return Err(Error::TooManyDamagedShards);
        }
        lookup[index] = true;
    }
    Ok(lookup)
}

fn read_padded_prefix_shard<F>(
    range: std::ops::Range<usize>,
    shard_len: usize,
    read_range: &mut F,
) -> Result<Vec<u8>>
where
    F: FnMut(std::ops::Range<usize>) -> Result<Vec<u8>>,
{
    let mut shard = vec![0; shard_len];
    let bytes = read_range(range)?;
    if bytes.len() > shard_len {
        return Err(Error::ShardSizeMismatch);
    }
    shard[..bytes.len()].copy_from_slice(&bytes);
    Ok(shard)
}

pub fn repair_inline_recovery_archive(input: &[u8]) -> Result<Vec<u8>> {
    let chunks = find_inline_recovery_chunks(input)?;
    let first = chunks.first().ok_or(Error::BadRecoveryChunk)?;
    let protected_size =
        usize::try_from(first.chunk.protected_size).map_err(|_| Error::PlanOverflow)?;
    if protected_size > input.len() {
        return Err(Error::BadRecoveryChunk);
    }
    // The chunks go straight to the repair with the offsets they were found
    // at. Copying them into a packed buffer first would close the gaps left
    // by any record that failed its CRC, and record position is what decides
    // which group a record belongs to - a compacted buffer would silently
    // shift survivors into the wrong group.
    // Whole-archive offsets: the recovery area sits after the protected
    // prefix, which is the floor that resolves an ambiguous base.
    let repaired_prefix =
        repair_prefix_with_chunks(&input[..protected_size], &chunks, protected_size as u64)?;
    if repaired_prefix == input[..protected_size] {
        return Ok(input.to_vec());
    }
    let mut repaired = input.to_vec();
    repaired[..protected_size].copy_from_slice(&repaired_prefix);
    Ok(repaired)
}

fn find_inline_recovery_chunks(input: &[u8]) -> Result<Vec<FoundInlineRecoveryChunk>> {
    // Budget on total bytes CRC64'd, for the same reason nzbkit's PAR2 packet
    // scanner does: a rejected candidate resumes at start + 1, and validating
    // a candidate hashes everything from its marker to its declared end. So
    // `{RB}` cells sprinkled every few bytes, each declaring a record reaching
    // near EOF, re-hash almost the same span once per byte - O(n^2), and this
    // CRC64 is the bitwise one at 8 rounds per byte. A 16 MiB damaged volume
    // becomes terabytes of hashing, i.e. an unkillable job, from a file that
    // arrived straight off the wire.
    //
    // A legitimate set hashes each record exactly once and sums to about one
    // pass over the input, so 4x leaves ample headroom.
    let budget = (input.len() as u64).saturating_mul(4).max(16 * 1024 * 1024);
    let mut hashed: u64 = 0;
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    while let Some(relative) = find_recovery_marker(&input[offset..]) {
        let start = offset + relative;
        if hashed > budget {
            // Hostile framing, not a real (even badly damaged) archive. Stop
            // with whatever verified so far; the caller then reports an
            // unrepairable volume instead of burning hours.
            break;
        }
        if let Ok(chunk) = parse_inline_recovery_chunk(&input[start..], &mut hashed) {
            // Stride by THIS RECORD, not by the shard's whole span. Striding
            // by the span skipped every record of every group after the
            // first, so a multi-group set was found one-group-deep and then
            // rejected for not adding up.
            let record_size = usize::try_from(chunk.record_size).map_err(|_| Error::PlanOverflow)?;
            if record_size > 0 && input.len().saturating_sub(start) >= record_size {
                chunks.push(FoundInlineRecoveryChunk {
                    offset: start,
                    chunk,
                });
                offset = start + record_size;
                continue;
            }
        }
        offset = start + 1;
    }
    if chunks.is_empty() {
        return Err(Error::BadRecoveryChunk);
    }
    Ok(chunks)
}

fn find_recovery_marker(input: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    while offset + 4 <= input.len() {
        let relative = input[offset..].iter().position(|&byte| byte == b'{')?;
        offset += relative;
        if input.get(offset..offset + 4) == Some(b"{RB}") {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

fn append_inline_recovery_chunk(
    input: &[u8],
    found: &FoundInlineRecoveryChunk,
    out: &mut Vec<u8>,
) -> Result<()> {
    let record_size =
        usize::try_from(found.chunk.record_size).map_err(|_| Error::PlanOverflow)?;
    let start = found.offset;
    let end = start.checked_add(record_size).ok_or(Error::PlanOverflow)?;
    out.extend_from_slice(input.get(start..end).ok_or(Error::BadRecoveryChunk)?);
    Ok(())
}

/// Rebuild every data shard, filling `None` slots from the recovery rows.
///
/// The whole grid is held in memory, so the slot count and the total byte size
/// are checked against `MAX_RECONSTRUCTION_SHARDS` and
/// `MAX_RECONSTRUCTION_BYTES` - and the missing slots against the number of
/// distinct recovery rows - before anything is allocated. Callers pass counts
/// straight out of an attacker-supplied header, so a grid that cannot be
/// afforded, or cannot be repaired, must be refused rather than reserved.
pub fn reconstruct_data_shards(
    data_shards: &[Option<&[u8]>],
    recovery_shards: &[(usize, &[u8])],
) -> Result<Vec<Vec<u8>>> {
    if data_shards.is_empty() {
        return Err(Error::TooManyShards);
    }
    let shard_len = recovery_shards
        .first()
        .map(|(_, shard)| shard.len())
        .or_else(|| data_shards.iter().flatten().map(|shard| shard.len()).max())
        .ok_or(Error::TooManyDamagedShards)?;
    if !shard_len.is_multiple_of(2) {
        return Err(Error::OddShardSize);
    }
    if recovery_shards
        .iter()
        .any(|(_, shard)| shard.len() != shard_len)
    {
        return Err(Error::ShardSizeMismatch);
    }

    // Everything below is sized from a *declared* slot count, so the
    // declaration has to be both affordable and useful before the first buffer
    // is reserved. The row bound matters as much as the slot bound: the encoder
    // matrix is (highest row + 1) x slots, so a single volume numbered near the
    // u16 ceiling sizes an allocation of its own.
    if data_shards.len() > MAX_RECONSTRUCTION_SHARDS
        || recovery_shards
            .iter()
            .any(|(row, _)| *row >= MAX_RECONSTRUCTION_SHARDS)
    {
        return Err(Error::ReconstructionTooLarge);
    }
    let total_bytes = (data_shards.len() as u64)
        .checked_mul(shard_len as u64)
        .ok_or(Error::PlanOverflow)?;
    if total_bytes > MAX_RECONSTRUCTION_BYTES {
        return Err(Error::ReconstructionTooLarge);
    }

    // A missing slot is only recoverable from an independent recovery row, so
    // more missing slots than distinct rows cannot be repaired however much is
    // allocated for the attempt - and the allocation is what a hostile volume
    // is really asking for. Duplicate rows restate one equation, so they add no
    // repair capacity and are dropped rather than counted.
    let mut seen_rows = std::collections::HashSet::with_capacity(recovery_shards.len());
    let distinct_rows: Vec<(usize, &[u8])> = recovery_shards
        .iter()
        .copied()
        .filter(|(row, _)| seen_rows.insert(*row))
        .collect();
    let missing_count = data_shards.iter().filter(|shard| shard.is_none()).count();
    if missing_count > distinct_rows.len() {
        return Err(Error::TooManyDamagedShards);
    }

    let mut out = Vec::with_capacity(data_shards.len());
    let mut missing = Vec::with_capacity(missing_count);
    for (index, shard) in data_shards.iter().enumerate() {
        let mut padded = vec![0; shard_len];
        if let Some(shard) = shard {
            if shard.len() > shard_len {
                return Err(Error::ShardSizeMismatch);
            }
            padded[..shard.len()].copy_from_slice(shard);
        } else {
            missing.push(index);
        }
        out.push(padded);
    }
    if missing.is_empty() {
        return Ok(out);
    }
    recover_damaged_shards(&mut out, &missing, &distinct_rows[..missing.len()])?;
    Ok(out)
}

/// `hashed` accumulates the bytes this scan has CRC64'd, so the caller can
/// stop a hostile file from driving quadratic hashing (see
/// `find_inline_recovery_chunks`).
fn parse_inline_recovery_chunk(input: &[u8], hashed: &mut u64) -> Result<InlineRecoveryChunk> {
    if input.len() < 0x48 || &input[..4] != b"{RB}" {
        return Err(Error::BadRecoveryChunk);
    }
    let total_size = read_u32(input, 0x0c)? as u64;
    let header_size = read_u32(input, 0x10)? as u64;
    if header_size < RAR5_RECOVERY_CHUNK_FIXED_HEADER_SIZE || header_size > total_size {
        return Err(Error::BadRecoveryChunk);
    }
    let total_size_usize = usize::try_from(total_size).map_err(|_| Error::PlanOverflow)?;
    let header_size_usize = usize::try_from(header_size).map_err(|_| Error::PlanOverflow)?;
    if input.len() < total_size_usize {
        return Err(Error::BadRecoveryChunk);
    }
    let expected_crc = read_u64(input, 0x04)?;
    *hashed = hashed.saturating_add((total_size_usize - 0x0c) as u64);
    let actual_crc = crc64_xz(&input[0x0c..total_size_usize]);
    if actual_crc != expected_crc {
        return Err(Error::BadRecoveryChunk);
    }
    if input[0x14] != 1 || input[0x15] != 1 {
        return Err(Error::BadRecoveryChunk);
    }

    let protected_size = read_u64(input, 0x22)?;
    let group_count = read_u64(input, 0x2a)?;
    let shard_size = read_u64(input, 0x32)?;
    let data_shards = u16::from_le_bytes(input[0x3a..0x3c].try_into().unwrap()) as u64;
    let recovery_shards = u16::from_le_bytes(input[0x3c..0x3e].try_into().unwrap()) as u64;
    let shard_index = u16::from_le_bytes(input[0x3e..0x40].try_into().unwrap()) as usize;
    let plan = InlineRecoveryPlan {
        data_shards,
        recovery_shards,
        group_count,
        header_size,
        shard_size,
    };
    if shard_index >= recovery_shards as usize
        || header_size_usize != 0x48 + data_shards as usize * 8
        || total_size_usize < header_size_usize
    {
        return Err(Error::BadRecoveryChunk);
    }
    // Shard counts past the reconstruction cap describe a grid no plan can
    // ever act on, so the record dies here at parse time - the same rule the
    // streaming scanner's `read_chunk_at` applies. Real WinRAR writes at most
    // 200 data shards; only a crafted record asks for more, and letting one
    // through meant `solve_damaged_group_shards` sized a multi-GiB encoder
    // matrix from a ~262 KB file on the in-memory repair path.
    if data_shards > MAX_RECONSTRUCTION_SHARDS as u64
        || recovery_shards > MAX_RECONSTRUCTION_SHARDS as u64
    {
        return Err(Error::BadRecoveryChunk);
    }

    let mut data_shard_states = Vec::with_capacity(data_shards as usize);
    let mut pos = 0x40;
    for _ in 0..data_shards {
        data_shard_states.push(read_u64(input, pos)?);
        pos += 8;
    }
    let _final_state = read_u64(input, pos)?;
    let parity = input[header_size_usize..total_size_usize].to_vec();
    // Everything above proves the record is self-consistent; this proves the
    // PLAN it declares is one we can afford to act on. `split_prefix_shards`
    // allocates data_shards * group_count bytes, and both fields come off the
    // wire - data_shards is a u16 and group_count only had to match this
    // record's own parity length, so a ~16 MiB crafted volume can ask for
    // ~1 TB. Rust's allocation failure is an abort, so that is the whole
    // daemon, reached by downloading a file.
    //
    // A real plan (see `plan_inline_recovery`) sets
    // group_count = ceil(protected/data_shards) rounded up to even, whose
    // capacity is therefore always inside protected_size + 2*data_shards.
    // Holding the record to its own format's arithmetic pins the allocation
    // to the size of the file we are already holding.
    //
    // The even-group_count half also closes the GF16 indexing hole: the
    // recovery kernel walks 2-byte symbols, so an odd shard length reads one
    // past the end. `repair_inline_recovery_prefix_shards` checked for that,
    // but `repair_inline_recovery_archive` (the raw-scan path a damaged
    // download actually takes) went through `repair_inline_recovery_prefix`,
    // which did not - an odd group_count there was a panic.
    if data_shards == 0 || group_count == 0 || !group_count.is_multiple_of(2) {
        return Err(Error::BadRecoveryChunk);
    }
    let capacity = data_shards
        .checked_mul(group_count)
        .ok_or(Error::PlanOverflow)?;
    let max_capacity = protected_size
        .checked_add(data_shards.saturating_mul(2))
        .ok_or(Error::PlanOverflow)?;
    if capacity < protected_size || capacity > max_capacity {
        return Err(Error::BadRecoveryChunk);
    }

    // This record holds one group's parity, not the whole row: the row is
    // `group_count` bytes and a record stores at most 64 KiB of it. What ties
    // the record to the layout is the declared `shard_size`, which must span
    // exactly one header per group plus the whole row - so a record cannot
    // claim a group geometry the rest of the set does not share.
    //
    // The parity length itself is checked against the specific group the
    // record lands in (`group_records`), which needs its file offset and so
    // cannot happen here. Bounding it now keeps a crafted header from
    // declaring a record larger than any group could ever be.
    let parity_len = parity.len() as u64;
    if parity_len == 0
        || parity_len > RAR5_RECOVERY_PARITY_PER_RECORD_MAX
        || parity_len > group_count
        || shard_size != shard_record_span(plan)?
    {
        return Err(Error::BadRecoveryChunk);
    }

    Ok(InlineRecoveryChunk {
        plan,
        record_size: total_size,
        protected_size,
        shard_index,
        data_shard_states,
        parity,
    })
}

fn recover_damaged_shards(
    data_shards: &mut [Vec<u8>],
    damaged: &[usize],
    recovery_shards: &[(usize, &[u8])],
) -> Result<()> {
    // Defence in depth for the GF16 symbol walk below, which reads
    // parity[w], parity[w + 1] and shard[w], shard[w + 1] for even w. Every
    // caller is supposed to have validated the plan, but one of them did not
    // and a malformed download turned into a panic, so the kernel now refuses
    // rather than trusting its callers.
    let shard_len = data_shards.first().ok_or(Error::TooManyShards)?.len();
    if shard_len == 0 || !shard_len.is_multiple_of(2) {
        return Err(Error::OddShardSize);
    }
    if data_shards.iter().any(|shard| shard.len() != shard_len)
        || recovery_shards
            .iter()
            .any(|(_, parity)| parity.len() < shard_len)
    {
        return Err(Error::ShardSizeMismatch);
    }

    let data_count = data_shards.len();
    let mut damaged_lookup = vec![false; data_count];
    for &data_index in damaged {
        if data_index >= data_count {
            return Err(Error::TooManyDamagedShards);
        }
        damaged_lookup[data_index] = true;
    }

    let recovery_count = recovery_shards
        .iter()
        .map(|(row, _)| row + 1)
        .max()
        .ok_or(Error::TooManyDamagedShards)?;
    let matrix = make_encoder_matrix(data_count, recovery_count)?;
    let gf = shared_gf16();
    let equations: Vec<Vec<u16>> = recovery_shards
        .iter()
        .map(|&(row_index, _)| {
            damaged
                .iter()
                .map(|&data_index| matrix[row_index][data_index])
                .collect()
        })
        .collect();
    let inverse = invert_linear_system_matrix(gf, &equations)?;

    // The per-word solve is linear in the codeword, so it collapses to one
    // fixed coefficient per (rebuilt shard, surviving source):
    //
    //   rebuilt_i = XOR_j inverse[i][j] * parity_j
    //             ^ XOR_k (XOR_j inverse[i][j] * matrix[row_j][k]) * shard_k
    //
    // which turns the kernel from two heap allocations and a strided
    // column-major walk per 2-byte symbol into a table-driven row-major fold
    // (the same shape `recovery/rar3.rs` uses, lifted to GF(2^16)).
    let sources: Vec<&[u8]> = recovery_shards
        .iter()
        .map(|&(_, parity)| &parity[..shard_len])
        .chain(
            data_shards
                .iter()
                .enumerate()
                .filter(|&(data_index, _)| !damaged_lookup[data_index])
                .map(|(_, shard)| shard.as_slice()),
        )
        .collect();
    let intact: Vec<usize> = (0..data_count)
        .filter(|&data_index| !damaged_lookup[data_index])
        .collect();

    let mut rebuilt = vec![vec![0u8; shard_len]; damaged.len()];
    for (inverse_row, rebuilt_row) in inverse.iter().zip(rebuilt.iter_mut()) {
        // Combined coefficient per source, tables built per output row so the
        // resident table set stays bounded by the source count, not the grid.
        let tables: Vec<Option<Gf16MulTable>> = sources
            .iter()
            .enumerate()
            .map(|(slot, _)| {
                let coefficient = if slot < recovery_shards.len() {
                    inverse_row[slot]
                } else {
                    let data_index = intact[slot - recovery_shards.len()];
                    recovery_shards
                        .iter()
                        .zip(inverse_row)
                        .fold(0u16, |sum, (&(row_index, _), &weight)| {
                            sum ^ gf.mul(weight, matrix[row_index][data_index])
                        })
                };
                (coefficient != 0).then(|| Gf16MulTable::new(gf, coefficient))
            })
            .collect();

        let fold_chunk = |destination: &mut [u8], start: usize| {
            for (source, table) in sources.iter().zip(&tables) {
                let Some(table) = table else {
                    continue;
                };
                table.fold_into(destination, &source[start..start + destination.len()]);
            }
        };

        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            rebuilt_row
                .par_chunks_mut(RECOVER_FOLD_CHUNK)
                .enumerate()
                .for_each(|(index, destination)| {
                    fold_chunk(destination, index * RECOVER_FOLD_CHUNK);
                });
        }
        #[cfg(not(feature = "parallel"))]
        for (index, destination) in rebuilt_row.chunks_mut(RECOVER_FOLD_CHUNK).enumerate() {
            fold_chunk(destination, index * RECOVER_FOLD_CHUNK);
        }
    }

    for (&data_index, rebuilt_row) in damaged.iter().zip(rebuilt) {
        data_shards[data_index] = rebuilt_row;
    }
    Ok(())
}

/// One chunk of a table-driven fold; even so chunk starts stay on symbol
/// boundaries. 64 KiB keeps the destination L2-resident while sources stream.
const RECOVER_FOLD_CHUNK: usize = 64 * 1024;

/// Multiply-by-constant over GF(2^16), split into low-byte and high-byte
/// halves: `c * x == lo[x & 0xff] ^ hi[x >> 8]`, since multiplication
/// distributes over XOR and `x = (x & 0xff) ^ ((x >> 8) << 8)`. 1 KiB per
/// coefficient, so a fold reads two small tables instead of the log/exp
/// tables' three dependent loads and a branch per symbol.
struct Gf16MulTable {
    lo: [u16; 256],
    hi: [u16; 256],
}

impl Gf16MulTable {
    fn new(gf: &Gf16, coefficient: u16) -> Self {
        let mut lo = [0u16; 256];
        let mut hi = [0u16; 256];
        for byte in 0..256u16 {
            lo[byte as usize] = gf.mul(coefficient, byte);
            hi[byte as usize] = gf.mul(coefficient, byte << 8);
        }
        Self { lo, hi }
    }

    /// XORs `coefficient * source` into `destination`, both little-endian
    /// 2-byte symbol streams of equal, even length.
    fn fold_into(&self, destination: &mut [u8], source: &[u8]) {
        for (destination, source) in destination.chunks_exact_mut(2).zip(source.chunks_exact(2)) {
            let product =
                self.lo[usize::from(source[0])] ^ self.hi[usize::from(source[1])];
            destination[0] ^= (product & 0xff) as u8;
            destination[1] ^= (product >> 8) as u8;
        }
    }
}

fn invert_linear_system_matrix(gf: &Gf16, matrix: &[Vec<u16>]) -> Result<Vec<Vec<u16>>> {
    let n = matrix.len();
    if matrix.len() != n || matrix.iter().any(|row| row.len() != n) {
        return Err(Error::BadRecoveryChunk);
    }
    let mut matrix = matrix.to_vec();
    let mut inverse = vec![vec![0u16; n]; n];
    for (row, inverse_row) in inverse.iter_mut().enumerate() {
        inverse_row[row] = 1;
    }

    for col in 0..n {
        let pivot = (col..n)
            .find(|&row| matrix[row][col] != 0)
            .ok_or(Error::SingularElement)?;
        matrix.swap(col, pivot);
        inverse.swap(col, pivot);
        let inv = gf.inv(matrix[col][col])?;
        for value in &mut matrix[col] {
            *value = gf.mul(*value, inv);
        }
        for value in &mut inverse[col] {
            *value = gf.mul(*value, inv);
        }

        let pivot_matrix_row = matrix[col].clone();
        let pivot_inverse_row = inverse[col].clone();
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            if factor == 0 {
                continue;
            }
            for (value, pivot) in matrix[row]
                .iter_mut()
                .zip(pivot_matrix_row.iter().copied())
                .skip(col)
            {
                *value ^= gf.mul(factor, pivot);
            }
            for (value, pivot) in inverse[row]
                .iter_mut()
                .zip(pivot_inverse_row.iter().copied())
            {
                *value ^= gf.mul(factor, pivot);
            }
        }
    }
    Ok(inverse)
}

fn apply_inverse_matrix(gf: &Gf16, inverse: &[Vec<u16>], rhs: &[u16]) -> Result<Vec<u16>> {
    if inverse.len() != rhs.len() || inverse.iter().any(|row| row.len() != rhs.len()) {
        return Err(Error::BadRecoveryChunk);
    }
    Ok(inverse
        .iter()
        .map(|row| {
            row.iter()
                .zip(rhs)
                .fold(0u16, |sum, (&coefficient, &value)| {
                    sum ^ gf.mul(coefficient, value)
                })
        })
        .collect())
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32> {
    input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(Error::BadRecoveryChunk)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64> {
    input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(Error::BadRecoveryChunk)
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Gf16 {
    exp: Box<[u16]>,
    log: Box<[u32]>,
}

impl Gf16 {
    pub fn new() -> Self {
        let mut exp = vec![0u16; FIELD_SIZE * 4 + 1];
        let mut log = vec![0u32; FIELD_SIZE + 1];
        let mut value = 1u32;
        for power in 0..FIELD_SIZE {
            log[value as usize] = power as u32;
            exp[power] = value as u16;
            exp[power + FIELD_SIZE] = value as u16;
            value <<= 1;
            if value > FIELD_MASK {
                value ^= PRIMITIVE_POLYNOMIAL;
            }
        }
        log[0] = ZERO_LOG_SENTINEL;
        Self {
            exp: exp.into_boxed_slice(),
            log: log.into_boxed_slice(),
        }
    }

    pub fn add(&self, left: u16, right: u16) -> u16 {
        left ^ right
    }

    pub fn mul(&self, left: u16, right: u16) -> u16 {
        if left == 0 || right == 0 {
            return 0;
        }
        let index = self.log[left as usize] + self.log[right as usize];
        self.exp[index as usize]
    }

    pub fn inv(&self, value: u16) -> Result<u16> {
        if value == 0 {
            return Err(Error::SingularElement);
        }
        let index = FIELD_SIZE as u32 - self.log[value as usize];
        Ok(self.exp[index as usize])
    }

    pub fn div(&self, numerator: u16, denominator: u16) -> Result<u16> {
        Ok(self.mul(numerator, self.inv(denominator)?))
    }
}

impl Default for Gf16 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn make_encoder_matrix(data_shards: usize, recovery_shards: usize) -> Result<Vec<Vec<u16>>> {
    if data_shards == 0 || recovery_shards == 0 || data_shards + recovery_shards > FIELD_SIZE {
        return Err(Error::TooManyShards);
    }
    let gf = shared_gf16();
    let mut matrix = vec![vec![0u16; data_shards]; recovery_shards];
    for (i, row) in matrix.iter_mut().enumerate() {
        for (j, cell) in row.iter_mut().enumerate() {
            let denominator = ((i + data_shards) ^ j) as u16;
            *cell = gf.inv(denominator)?;
        }
    }
    Ok(matrix)
}

pub fn encode_parity_shards(data: &[&[u8]], recovery_shards: usize) -> Result<Vec<Vec<u8>>> {
    encode_parity_shards_with_progress(data, recovery_shards, |_| {})
}

fn encode_parity_shards_with_progress(
    data: &[&[u8]],
    recovery_shards: usize,
    mut progress: impl FnMut(u64),
) -> Result<Vec<Vec<u8>>> {
    let Some(first) = data.first() else {
        return Err(Error::TooManyShards);
    };
    if !first.len().is_multiple_of(2) {
        return Err(Error::OddShardSize);
    }
    if data.iter().any(|shard| shard.len() != first.len()) {
        return Err(Error::ShardSizeMismatch);
    }

    let matrix = make_encoder_matrix(data.len(), recovery_shards)?;
    let gf = shared_gf16();
    let mut parity = vec![vec![0u8; first.len()]; recovery_shards];
    for (recovery_index, row) in matrix.iter().enumerate() {
        // Same table-driven fold as `recover_damaged_shards`: one
        // multiply-by-constant table per data shard, row-major accumulation.
        let tables: Vec<Option<Gf16MulTable>> = row
            .iter()
            .map(|&coefficient| (coefficient != 0).then(|| Gf16MulTable::new(gf, coefficient)))
            .collect();
        let parity_row = &mut parity[recovery_index];

        let fold_chunk = |destination: &mut [u8], start: usize| {
            for (shard, table) in data.iter().zip(&tables) {
                let Some(table) = table else {
                    continue;
                };
                table.fold_into(destination, &shard[start..start + destination.len()]);
            }
        };

        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            parity_row
                .par_chunks_mut(RECOVER_FOLD_CHUNK)
                .enumerate()
                .for_each(|(index, destination)| {
                    fold_chunk(destination, index * RECOVER_FOLD_CHUNK);
                });
        }
        #[cfg(not(feature = "parallel"))]
        for (index, destination) in parity_row.chunks_mut(RECOVER_FOLD_CHUNK).enumerate() {
            fold_chunk(destination, index * RECOVER_FOLD_CHUNK);
        }
        progress(((recovery_index + 1) * first.len()) as u64);
    }
    Ok(parity)
}

/// Folds one data shard's stripe into a batch of parity rows, in place.
///
/// This is [`encode_parity_shards`] taken apart so a caller can encode a
/// code word it cannot hold: `matrix` is the rows of the encoder matrix
/// this batch covers, `data_index` says which column `stripe` is, and
/// `parity` accumulates across calls. The caller zeroes `parity` at the
/// start of a stripe and folds every data shard into it before writing.
///
/// `len` is how much of each buffer this stripe uses, so the last stripe
/// of a code word can be shorter than the buffers. It must be even: a
/// stripe boundary inside a 2-byte symbol would corrupt the fold, and
/// the writer's window is chosen even for exactly that reason.
///
/// The multiply tables are built per call rather than cached, which
/// costs 512 field multiplies per row and is nothing beside folding the
/// stripe itself. Caching them would make the working set scale with the
/// data volume count, which is the thing the striping exists to avoid.
pub fn fold_stripe_into_parity(
    matrix: &[Vec<u16>],
    data_index: usize,
    stripe: &[u8],
    parity: &mut [Vec<u8>],
    len: usize,
) -> Result<()> {
    if matrix.len() != parity.len() {
        return Err(Error::BadRecoveryChunk);
    }
    if !len.is_multiple_of(2) {
        return Err(Error::OddShardSize);
    }
    if stripe.len() < len || parity.iter().any(|row| row.len() < len) {
        return Err(Error::ShardSizeMismatch);
    }
    let gf = shared_gf16();
    for (row, destination) in matrix.iter().zip(parity.iter_mut()) {
        let Some(&coefficient) = row.get(data_index) else {
            return Err(Error::BadRecoveryChunk);
        };
        if coefficient == 0 {
            continue;
        }
        let table = Gf16MulTable::new(gf, coefficient);
        for (offset, chunk) in destination[..len]
            .chunks_mut(RECOVER_FOLD_CHUNK)
            .enumerate()
        {
            let start = offset * RECOVER_FOLD_CHUNK;
            table.fold_into(chunk, &stripe[start..start + chunk.len()]);
        }
    }
    Ok(())
}

/// The original per-symbol encode, kept as the differential reference for the
/// table-driven fold.
#[cfg(test)]
fn encode_parity_shards_reference(data: &[&[u8]], recovery_shards: usize) -> Result<Vec<Vec<u8>>> {
    let first = data.first().ok_or(Error::TooManyShards)?;
    let matrix = make_encoder_matrix(data.len(), recovery_shards)?;
    let gf = shared_gf16();
    let mut parity = vec![vec![0u8; first.len()]; recovery_shards];
    for (recovery_index, row) in matrix.iter().enumerate() {
        for word_offset in (0..first.len()).step_by(2) {
            let mut symbol = 0u16;
            for (data_index, shard) in data.iter().enumerate() {
                let data_symbol = u16::from_le_bytes([shard[word_offset], shard[word_offset + 1]]);
                symbol ^= gf.mul(row[data_index], data_symbol);
            }
            parity[recovery_index][word_offset..word_offset + 2]
                .copy_from_slice(&symbol.to_le_bytes());
        }
    }
    Ok(parity)
}

/// The original per-word solve, kept as the differential reference for the
/// table-driven `recover_damaged_shards`.
#[cfg(test)]
fn recover_damaged_shards_reference(
    data_shards: &mut [Vec<u8>],
    damaged: &[usize],
    recovery_shards: &[(usize, &[u8])],
) -> Result<()> {
    let shard_len = data_shards.first().ok_or(Error::TooManyShards)?.len();
    let data_count = data_shards.len();
    let mut damaged_lookup = vec![false; data_count];
    for &data_index in damaged {
        damaged_lookup[data_index] = true;
    }
    let recovery_count = recovery_shards
        .iter()
        .map(|(row, _)| row + 1)
        .max()
        .ok_or(Error::TooManyDamagedShards)?;
    let matrix = make_encoder_matrix(data_count, recovery_count)?;
    let gf = shared_gf16();
    let equations: Vec<Vec<u16>> = recovery_shards
        .iter()
        .map(|&(row_index, _)| {
            damaged
                .iter()
                .map(|&data_index| matrix[row_index][data_index])
                .collect()
        })
        .collect();
    let inverse = invert_linear_system_matrix(gf, &equations)?;

    for word_offset in (0..shard_len).step_by(2) {
        let mut rhs = Vec::with_capacity(recovery_shards.len());
        for &(row_index, parity) in recovery_shards {
            let mut value = u16::from_le_bytes([parity[word_offset], parity[word_offset + 1]]);
            for (data_index, shard) in data_shards.iter().enumerate() {
                if damaged_lookup[data_index] {
                    continue;
                }
                let data_symbol = u16::from_le_bytes([shard[word_offset], shard[word_offset + 1]]);
                value ^= gf.mul(matrix[row_index][data_index], data_symbol);
            }
            rhs.push(value);
        }
        let solved = apply_inverse_matrix(gf, &inverse, &rhs)?;
        for (&data_index, &symbol) in damaged.iter().zip(&solved) {
            data_shards[data_index][word_offset..word_offset + 2]
                .copy_from_slice(&symbol.to_le_bytes());
        }
    }
    Ok(())
}

/// Smallest stripe worth running: below this the per-stripe seek and
/// matrix-solve overhead dominates, and a budget that cannot afford even
/// this much is better reported than crawled through.
///
/// Deliberately low. The working set scales with the DAMAGE count, so a
/// badly damaged set (100 missing shards out of 200) divides the budget a
/// hundred ways; a higher floor here would refuse repairs that are perfectly
/// affordable, just fine-grained. 8 KiB still amortizes the per-stripe solve
/// and keeps each pass over the set sequential enough for the page cache.
pub const MIN_STRIPE_LEN: usize = 8 * 1024;

/// A validated plan for reconstructing damaged shards a stripe at a time.
///
/// The whole-grid APIs ([`reconstruct_data_shards`],
/// [`repair_inline_recovery_prefix_shards`]) hold every shard resident: their
/// working set is `data_count * shard_len` regardless of how little is
/// actually damaged, which for a 60x1 GB volume set with one missing volume
/// is over 120 GB. Reed-Solomon over GF(2^16) solves each 2-byte symbol
/// column independently, so the same reconstruction can run over a bounded
/// window of every shard at once. Working memory then depends on the stripe
/// and the DAMAGE count, never on the size of the set:
///
/// `(2 * damaged + 1) * stripe_len` - one right-hand-side row and one output
/// row per damaged shard, plus a single read buffer.
///
/// The plan itself (the selected encoder rows and the system's inverse) is
/// `O(damaged * data_count)` 16-bit cells and is built once, outside the
/// stripe loop.
#[derive(Debug, Clone)]
pub struct StripeRepairPlan {
    data_count: usize,
    shard_len: usize,
    damaged: Vec<usize>,
    damaged_lookup: Vec<bool>,
    // One encoder row per selected recovery equation, in `rows` order -
    // indexed by SLOT, not by recovery-row number. Only these rows are ever
    // read back, so the full recovery_count x data_count grid is never
    // materialized (see `new`).
    matrix: Vec<Vec<u16>>,
    inverse: Vec<Vec<u16>>,
}

impl StripeRepairPlan {
    /// Validates the geometry and inverts the linear system.
    ///
    /// `damaged` lists the data-shard indices to rebuild; `rows` lists the
    /// recovery-row index backing each equation, in the order the recovery
    /// sources will be read. Exactly one row per damaged shard is required -
    /// a square system - and both lists must be free of duplicates, since a
    /// repeated row is one equation counted twice and makes the system
    /// singular.
    pub fn new(
        data_count: usize,
        recovery_count: usize,
        shard_len: usize,
        damaged: &[usize],
        rows: &[usize],
    ) -> Result<Self> {
        if data_count == 0 {
            return Err(Error::TooManyShards);
        }
        // Both counts come raw off the wire, and what is sized from them must
        // be refused before anything is reserved - but they no longer cost
        // the same thing. Since the rows-only rewrite the matrix is
        // `damaged * data_count` cells and the inversion is
        // `O(damaged^3)`, so the hard cap belongs on `recovery_count` (which
        // bounds `rows`, and through the square-system requirement `damaged`
        // too), NOT on `data_count`: a legitimate `.rev` set over a 100 GB
        // release in 15 MB volumes declares ~6,800 data volumes, and capping
        // the slot count refused repairs this crate used to perform. The
        // slot count is bounded only by the field itself, exactly as
        // `make_encoder_matrix` bounds it; what a wide-and-damaged crafted
        // header can still ask for is policed by the cell budget below.
        if recovery_count > MAX_RECONSTRUCTION_SHARDS {
            return Err(Error::ReconstructionTooLarge);
        }
        if data_count
            .checked_add(recovery_count)
            .is_none_or(|total| total > FIELD_SIZE)
        {
            return Err(Error::TooManyShards);
        }
        if shard_len == 0 || !shard_len.is_multiple_of(2) {
            return Err(Error::OddShardSize);
        }
        if damaged.is_empty() || damaged.len() != rows.len() {
            return Err(Error::TooManyDamagedShards);
        }
        if damaged.len() > data_count {
            return Err(Error::TooManyDamagedShards);
        }
        let damaged_lookup = damaged_lookup(data_count, damaged)?;
        if damaged_lookup.iter().filter(|hit| **hit).count() != damaged.len() {
            return Err(Error::TooManyDamagedShards);
        }
        let mut seen = rows.to_vec();
        seen.sort_unstable();
        seen.dedup();
        if seen.len() != rows.len() {
            return Err(Error::TooManyDamagedShards);
        }
        if rows.iter().any(|row| *row >= recovery_count) {
            return Err(Error::TooManyShards);
        }
        // What the plan actually allocates is `damaged * data_count` matrix
        // cells (`damaged` itself is already <= MAX_RECONSTRUCTION_SHARDS via
        // the recovery cap, which also bounds the O(damaged^3) inversion), so
        // that product is what gets a budget. Only a crafted header pairing
        // thousands of damaged shards with a u16-scale slot count reaches it.
        if damaged
            .len()
            .checked_mul(data_count)
            .is_none_or(|cells| cells > MAX_STRIPE_PLAN_CELLS)
        {
            return Err(Error::ReconstructionTooLarge);
        }

        // Only the selected rows, never the whole grid: the stripe loop reads
        // the matrix per equation and nowhere else, so building the full
        // recovery_count x data_count Cauchy matrix cost recovery_count /
        // rows.len() times the memory the repair uses. Each cell is exactly
        // what `make_encoder_matrix` computes for that (row, column).
        let gf = shared_gf16();
        let mut matrix = Vec::with_capacity(rows.len());
        for &row in rows {
            let mut cells = vec![0u16; data_count];
            for (column, cell) in cells.iter_mut().enumerate() {
                let denominator = ((row + data_count) ^ column) as u16;
                *cell = gf.inv(denominator)?;
            }
            matrix.push(cells);
        }
        let equations: Vec<Vec<u16>> = matrix
            .iter()
            .map(|cells| damaged.iter().map(|&data| cells[data]).collect())
            .collect();
        let inverse = invert_linear_system_matrix(gf, &equations)?;
        Ok(Self {
            data_count,
            shard_len,
            damaged: damaged.to_vec(),
            damaged_lookup,
            matrix,
            inverse,
        })
    }

    /// Data-shard indices this plan rebuilds, in output-slot order.
    pub fn damaged(&self) -> &[usize] {
        &self.damaged
    }

    /// Padded shard length every source and sink is addressed against.
    pub fn shard_len(&self) -> usize {
        self.shard_len
    }

    /// Bytes [`repair_shards_striped`] reserves for a given stripe: one
    /// right-hand-side row and one output row per damaged shard, plus a
    /// single read buffer. Independent of `data_count` and `shard_len`, which
    /// is the whole point of the striped path.
    pub fn working_bytes(&self, stripe_len: usize) -> u64 {
        (2 * self.damaged.len() as u64 + 1) * stripe_len as u64
    }

    /// Largest stripe whose working set fits `budget` bytes, rounded to an
    /// even length and never longer than a whole shard.
    ///
    /// `RepairTooLarge` when the budget cannot even hold [`MIN_STRIPE_LEN`]
    /// per row - the caller's cue to report an unsupported repair rather
    /// than grind through 2-byte stripes.
    pub fn stripe_len_for_budget(&self, budget: u64) -> Result<usize> {
        let rows = (2 * self.damaged.len() + 1) as u64;
        let stripe = budget / rows;
        let stripe = usize::try_from(stripe).unwrap_or(usize::MAX);
        if stripe < MIN_STRIPE_LEN.min(self.shard_len) {
            return Err(Error::RepairTooLarge);
        }
        Ok((stripe & !1).min(self.shard_len).max(2))
    }
}

/// Reconstructs the planned damaged shards in bounded stripes.
///
/// - `read_data(index, offset, buf)` fills `buf` with data shard `index`
///   starting at `offset`, ZERO-PADDING any part of the window that lies
///   past the shard's real content (short trailing shards are padded to
///   `shard_len` in the code word, exactly as the whole-grid path pads them).
/// - `read_recovery(slot, offset, buf)` fills `buf` from the recovery source
///   backing equation `slot` - the same order as the `rows` given to
///   [`StripeRepairPlan::new`].
/// - `write_damaged(slot, offset, bytes)` receives each rebuilt stripe for
///   damaged shard `plan.damaged()[slot]`, in ascending offset order, so a
///   sink can append straight to a file without buffering the shard.
///
/// Never allocates per stripe: all buffers are reserved once up front.
pub fn repair_shards_striped<D, R, W>(
    plan: &StripeRepairPlan,
    stripe_len: usize,
    mut read_data: D,
    mut read_recovery: R,
    mut write_damaged: W,
) -> Result<()>
where
    D: FnMut(usize, usize, &mut [u8]) -> Result<()>,
    R: FnMut(usize, usize, &mut [u8]) -> Result<()>,
    W: FnMut(usize, usize, &[u8]) -> Result<()>,
{
    if stripe_len == 0 || !stripe_len.is_multiple_of(2) {
        return Err(Error::OddShardSize);
    }
    let gf = shared_gf16();
    let damaged_count = plan.damaged.len();

    // The per-word solve is linear in the codeword, so it collapses to one
    // fixed coefficient per (rebuilt shard, surviving source), exactly as
    // `recover_damaged_shards` derives:
    //
    //   rebuilt_i = XOR_j inverse[i][j] * parity_j
    //             ^ XOR_k (XOR_j inverse[i][j] * matrix[j][k]) * shard_k
    //
    // The previous shape here - a scalar `gf.mul` per 2-byte symbol to
    // subtract every intact shard into an rhs, then a column-major inverse
    // solve per word - ran the `.rev` rebuild at ~48 MB/s where the inline
    // recovery path's table fold does 6x that before parallelism. Combined
    // data coefficients first; damaged columns stay zero because those
    // shards are never read.
    let mut combined = vec![vec![0u16; plan.data_count]; damaged_count];
    for (inverse_row, combined_row) in plan.inverse.iter().zip(combined.iter_mut()) {
        for (&weight, matrix_row) in inverse_row.iter().zip(&plan.matrix) {
            if weight == 0 {
                continue;
            }
            for (cell, &coeff) in combined_row.iter_mut().zip(matrix_row.iter()) {
                *cell ^= gf.mul(weight, coeff);
            }
        }
    }

    // One source window resident at a time, folded into every output row
    // through that source's per-output tables. Chunked so the destination
    // stays L2-resident; parallel per chunk when the feature allows, because
    // with a single damaged shard the chunk axis is the only parallelism
    // there is.
    fn fold_source_into(out: &mut [Vec<u8>], tables: &[Option<Gf16MulTable>], window: &[u8]) {
        for (destination, table) in out.iter_mut().zip(tables) {
            let Some(table) = table else {
                continue;
            };
            let destination = &mut destination[..window.len()];
            #[cfg(feature = "parallel")]
            {
                use rayon::prelude::*;
                destination
                    .par_chunks_mut(RECOVER_FOLD_CHUNK)
                    .zip(window.par_chunks(RECOVER_FOLD_CHUNK))
                    .for_each(|(destination, source)| table.fold_into(destination, source));
            }
            #[cfg(not(feature = "parallel"))]
            for (destination, source) in destination
                .chunks_mut(RECOVER_FOLD_CHUNK)
                .zip(window.chunks(RECOVER_FOLD_CHUNK))
            {
                table.fold_into(destination, source);
            }
        }
    }

    let mut scratch = vec![0u8; stripe_len];
    let mut out = vec![vec![0u8; stripe_len]; damaged_count];
    // Tables live inline in the Vec (1 KiB each), so clearing and refilling
    // per source allocates nothing after the first stripe.
    let mut tables: Vec<Option<Gf16MulTable>> = Vec::with_capacity(damaged_count);

    let mut offset = 0usize;
    while offset < plan.shard_len {
        let len = stripe_len.min(plan.shard_len - offset);
        for row in out.iter_mut() {
            row[..len].fill(0);
        }

        // Each recovery row's parity enters through the inverse directly.
        for slot in 0..damaged_count {
            read_recovery(slot, offset, &mut scratch[..len])?;
            tables.clear();
            tables.extend(plan.inverse.iter().map(|row| {
                let coeff = row[slot];
                (coeff != 0).then(|| Gf16MulTable::new(gf, coeff))
            }));
            fold_source_into(&mut out, &tables, &scratch[..len]);
        }

        // Every intact shard enters through its combined coefficient. One
        // pass over the set per stripe: the same total I/O the whole-grid
        // path does, spread so that only one shard's window is resident at
        // a time.
        for data_index in 0..plan.data_count {
            if plan.damaged_lookup[data_index] {
                continue;
            }
            if combined.iter().all(|row| row[data_index] == 0) {
                continue;
            }
            read_data(data_index, offset, &mut scratch[..len])?;
            tables.clear();
            tables.extend(combined.iter().map(|row| {
                let coeff = row[data_index];
                (coeff != 0).then(|| Gf16MulTable::new(gf, coeff))
            }));
            fold_source_into(&mut out, &tables, &scratch[..len]);
        }

        for (slot, shard) in out.iter().enumerate() {
            write_damaged(slot, offset, &shard[..len])?;
        }
        offset += len;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_inverse_matrix, assign_recovery_groups, build_structural_inline_recovery_data,
        crc64_rar_state, RAR5_RECOVERY_PARITY_PER_RECORD_MAX,
        crc64_update, crc64_update_bitwise, crc64_xz, CRC64_XZ_SEED,
        encode_inline_recovery_parity, encode_parity_shards, invert_linear_system_matrix,
        find_inline_recovery_chunks, make_encoder_matrix, parse_inline_recovery_chunk,
        plan_inline_recovery,
        reconstruct_data_shards, recover_damaged_shards, recover_damaged_shards_reference,
        recovery_groups,
        repair_inline_recovery_archive,
        repair_inline_recovery_prefix, repair_inline_recovery_prefix_shards,
        repair_shards_striped, shared_gf16, shard_record_span, solve_damaged_group_shards,
        split_prefix_shard_ranges, split_prefix_shards,
        Error, Gf16, InlineRecoveryPlan, StripeRepairPlan, FIELD_SIZE,
        MAX_RECONSTRUCTION_SHARDS, MAX_WINRAR602_DATA_SHARDS,
    };

    #[test]
    fn rar5_inline_recovery_plan_matches_fixture_formula_examples() {
        assert_eq!(
            plan_inline_recovery(65_681, 5).unwrap(),
            InlineRecoveryPlan {
                data_shards: 65,
                recovery_shards: 3,
                group_count: 1012,
                header_size: 592,
                shard_size: 1604,
            }
        );
        assert_eq!(
            plan_inline_recovery(65_681, 20).unwrap(),
            InlineRecoveryPlan {
                data_shards: 65,
                recovery_shards: 13,
                group_count: 1012,
                header_size: 592,
                shard_size: 1604,
            }
        );
    }

    #[test]
    fn rar5_inline_recovery_plan_handles_clamps_and_large_prefixes() {
        assert_eq!(
            plan_inline_recovery(0, 0).unwrap(),
            InlineRecoveryPlan {
                data_shards: 1,
                recovery_shards: 1,
                group_count: 0,
                header_size: 80,
                shard_size: 80,
            }
        );
        assert_eq!(
            plan_inline_recovery(200 * 1024, 1000).unwrap(),
            InlineRecoveryPlan {
                data_shards: 200,
                recovery_shards: 200,
                group_count: 1024,
                header_size: 1672,
                shard_size: 2696,
            }
        );
    }

    #[test]
    fn rar5_inline_recovery_plan_keeps_fixed_header_above_64k_groups() {
        let boundary = MAX_WINRAR602_DATA_SHARDS * 0x10000;
        assert_eq!(
            plan_inline_recovery(boundary, 1).unwrap(),
            InlineRecoveryPlan {
                data_shards: 200,
                recovery_shards: 2,
                group_count: 65_536,
                header_size: 1672,
                shard_size: 67_208,
            }
        );
        // One byte past the boundary is the first archive whose parity row no
        // longer fits a single 64 KiB record, so the shard's span gains a
        // second header: 2 * 1672 + 65_538. The old expectation here (67_210,
        // one header) is what the format ceiling was made of - WinRAR's own
        // 16 MB archives declare 2 * 1672 + 83_888 = 87_232 for the same
        // reason, which is what pins this number.
        assert_eq!(
            plan_inline_recovery(boundary + 1, 1).unwrap(),
            InlineRecoveryPlan {
                data_shards: 200,
                recovery_shards: 2,
                group_count: 65_538,
                header_size: 1672,
                shard_size: 68_882,
            }
        );
    }

    #[test]
    fn gf16_matches_rar5_polynomial_wrap() {
        let gf = Gf16::new();

        assert_eq!(gf.mul(0x8000, 2), 0x100b);
        assert_eq!(gf.mul(0, 0x1234), 0);
        assert_eq!(gf.mul(0x1234, 0), 0);
        assert_eq!(gf.mul(0, 0), 0);
        assert_eq!(gf.mul(1, 0x1234), 0x1234);
    }

    #[test]
    fn shared_gf16_reuses_field_tables() {
        let first = shared_gf16() as *const Gf16;
        let second = shared_gf16() as *const Gf16;

        assert_eq!(first, second);
        assert_eq!(shared_gf16().mul(0x8000, 2), 0x100b);
    }

    #[test]
    fn crc64_xz_matches_reference_vectors() {
        assert_eq!(crc64_xz(b""), 0);
        assert_eq!(crc64_xz(b"123456789"), 0x995d_c9bb_df19_39fa);
        assert_eq!(crc64_xz(b"testtesttest"), 0x7b1c_2d23_0ede_b436);
    }

    #[test]
    fn raw_crc64_state_matches_reference_vector() {
        assert_eq!(crc64_rar_state(b""), 0);
        assert_eq!(crc64_rar_state(b"te\x80st"), 0xb5db_f958_3a6e_ed4a);
    }

    /// The table-driven fold must reproduce the per-word solve exactly:
    /// across damage patterns, non-contiguous recovery rows, shard lengths
    /// that straddle the fold-chunk boundary, and all-zero coefficients.
    #[test]
    fn bulk_recover_matches_per_word_reference() {
        let chunk = super::RECOVER_FOLD_CHUNK;
        let cases: &[(usize, &[usize], &[usize], usize)] = &[
            // (data shards, damaged indices, recovery rows, shard length)
            (4, &[1], &[0], 8),
            (4, &[0, 3], &[0, 1], 500),
            (10, &[2, 5, 9], &[1, 3, 7], 1024),
            (1, &[0], &[0], 2),
            (30, &[0, 15, 29], &[0, 1, 2], chunk - 2),
            (30, &[7], &[4], chunk),
            (30, &[7, 8], &[2, 6], chunk + 38),
            (30, &[7, 8, 9], &[0, 5, 11], 2 * chunk + 66),
        ];
        for &(data_count, damaged, rows, shard_len) in cases {
            let originals: Vec<Vec<u8>> = (0..data_count)
                .map(|index| {
                    (0..shard_len)
                        .map(|offset| {
                            ((offset as u64)
                                .wrapping_mul(0x9E3779B97F4A7C15)
                                .wrapping_add(index as u64 * 0x1234567)
                                >> 29) as u8
                        })
                        .collect()
                })
                .collect();
            let data_refs: Vec<&[u8]> = originals.iter().map(Vec::as_slice).collect();
            let recovery_count = rows.iter().max().unwrap() + 1;
            let parity = encode_parity_shards(&data_refs, recovery_count).unwrap();
            let recovery: Vec<(usize, &[u8])> =
                rows.iter().map(|&row| (row, parity[row].as_slice())).collect();

            let damage = |shards: &mut [Vec<u8>]| {
                for &index in damaged {
                    shards[index].fill(0xAA);
                }
            };
            let mut fast = originals.clone();
            damage(&mut fast);
            let mut reference = originals.clone();
            damage(&mut reference);

            let fast_result = recover_damaged_shards(&mut fast, damaged, &recovery);
            let reference_result =
                recover_damaged_shards_reference(&mut reference, damaged, &recovery);
            assert_eq!(fast_result.is_ok(), reference_result.is_ok());
            assert_eq!(
                fast, reference,
                "kernels diverged: {data_count} shards, {damaged:?} damaged, rows {rows:?}, len {shard_len}"
            );
            if fast_result.is_ok() {
                assert_eq!(fast, originals, "repair did not restore the originals");
            }
        }
    }

    /// The table-driven encoder must match the per-symbol encoder bit for bit.
    #[test]
    fn bulk_encode_matches_per_symbol_reference() {
        for &(data_count, recovery_count, shard_len) in
            &[(1usize, 1usize, 2usize), (5, 3, 998), (12, 7, 70_000)]
        {
            let shards: Vec<Vec<u8>> = (0..data_count)
                .map(|index| {
                    (0..shard_len)
                        .map(|offset| (offset.wrapping_mul(31).wrapping_add(index * 97) >> 3) as u8)
                        .collect()
                })
                .collect();
            let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
            assert_eq!(
                encode_parity_shards(&refs, recovery_count).unwrap(),
                super::encode_parity_shards_reference(&refs, recovery_count).unwrap(),
                "{data_count}+{recovery_count} at {shard_len} B"
            );
        }
    }

    /// The slice-by-8 tables must match the bit-serial fold at every length
    /// around the 8-byte chunk boundary and from any running state.
    #[test]
    fn crc64_table_fold_matches_bitwise_reference() {
        let data: Vec<u8> = (0u32..4096).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 255, 256, 1024, 4096] {
            for seed in [0u64, CRC64_XZ_SEED, 0x0123_4567_89ab_cdef] {
                assert_eq!(
                    crc64_update(&data[..len], seed),
                    crc64_update_bitwise(&data[..len], seed),
                    "diverged at len {len}, seed {seed:#x}"
                );
            }
        }
        // Incremental folding across an arbitrary split must equal one pass.
        let split = crc64_update(&data[1000..], crc64_update(&data[..1000], CRC64_XZ_SEED));
        assert_eq!(split, crc64_update(&data, CRC64_XZ_SEED));
    }

    #[test]
    fn rar5_prefix_split_produces_even_padded_data_shards() {
        let plan = InlineRecoveryPlan {
            data_shards: 3,
            recovery_shards: 1,
            group_count: 4,
            header_size: 96,
            shard_size: 100,
        };
        let shards = split_prefix_shards(b"abcdefghij", plan).unwrap();

        assert_eq!(
            shards,
            vec![b"abcd".to_vec(), b"efgh".to_vec(), b"ij\0\0".to_vec()]
        );
    }

    #[test]
    fn rar5_prefix_split_rejects_prefix_larger_than_plan_capacity() {
        let plan = InlineRecoveryPlan {
            data_shards: 2,
            recovery_shards: 1,
            group_count: 2,
            header_size: 88,
            shard_size: 90,
        };

        assert_eq!(
            split_prefix_shards(b"abcde", plan),
            Err(Error::PrefixExceedsPlan)
        );
    }

    #[test]
    fn gf16_inverse_round_trips_nonzero_elements() {
        let gf = Gf16::new();

        for value in [1, 2, 3, 0x100b, 0x8000, 0xffff] {
            let inverse = gf.inv(value).unwrap();
            assert_eq!(gf.mul(value, inverse), 1);
        }
        assert_eq!(gf.inv(0), Err(Error::SingularElement));
    }

    #[test]
    fn rar5_cauchy_encoder_matrix_uses_inverse_xor_denominators() {
        let gf = Gf16::new();
        let matrix = make_encoder_matrix(3, 2).unwrap();

        assert_eq!(matrix.len(), 2);
        assert_eq!(matrix[0].len(), 3);
        for (i, row) in matrix.iter().enumerate() {
            for (j, &cell) in row.iter().enumerate() {
                let denominator = ((i + 3) ^ j) as u16;
                assert_eq!(gf.mul(cell, denominator), 1);
            }
        }
    }

    #[test]
    fn rar5_cauchy_encoder_matrix_rejects_impossible_shard_counts() {
        assert_eq!(make_encoder_matrix(0, 1), Err(Error::TooManyShards));
        assert_eq!(make_encoder_matrix(1, 0), Err(Error::TooManyShards));
        assert_eq!(make_encoder_matrix(65535, 1), Err(Error::TooManyShards));
    }

    #[test]
    fn rar5_recovery_inverse_matrix_solves_reused_equations() {
        let gf = shared_gf16();
        let equations = vec![vec![3, 5], vec![7, 11]];
        let expected = [0x1234, 0xabcd];
        let rhs = equations
            .iter()
            .map(|row| gf.mul(row[0], expected[0]) ^ gf.mul(row[1], expected[1]))
            .collect::<Vec<_>>();

        let inverse = invert_linear_system_matrix(gf, &equations).unwrap();
        let solved = apply_inverse_matrix(gf, &inverse, &rhs).unwrap();

        assert_eq!(solved, expected);
    }

    #[test]
    fn rar5_parity_encoder_generates_systematic_recovery_shards() {
        let first = [1, 0, 2, 0, 3, 0, 4, 0];
        let parity = encode_parity_shards(&[&first], 1).unwrap();

        assert_eq!(parity, [first.to_vec()]);
    }

    #[test]
    fn rar5_parity_encoder_applies_cauchy_matrix_coefficients() {
        let gf = Gf16::new();
        let first = [1, 0, 2, 0];
        let second = [3, 0, 4, 0];
        let matrix = make_encoder_matrix(2, 2).unwrap();
        let parity = encode_parity_shards(&[&first, &second], 2).unwrap();

        for recovery_index in 0..2 {
            for word_index in 0..2 {
                let offset = word_index * 2;
                let left = u16::from_le_bytes([first[offset], first[offset + 1]]);
                let right = u16::from_le_bytes([second[offset], second[offset + 1]]);
                let expected = gf.mul(matrix[recovery_index][0], left)
                    ^ gf.mul(matrix[recovery_index][1], right);
                assert_eq!(
                    u16::from_le_bytes([
                        parity[recovery_index][offset],
                        parity[recovery_index][offset + 1],
                    ]),
                    expected
                );
            }
        }
    }

    #[test]
    fn rar5_inline_recovery_parity_splits_and_encodes_prefix() {
        let prefix = b"RAR5 inline recovery parity payload input";
        let (plan, parity) = encode_inline_recovery_parity(prefix, 10).unwrap();

        assert_eq!(plan, plan_inline_recovery(prefix.len() as u64, 10).unwrap());
        assert_eq!(parity.len(), plan.recovery_shards as usize);
        assert!(parity
            .iter()
            .all(|shard| shard.len() == plan.group_count as usize));

        let data_shards = split_prefix_shards(prefix, plan).unwrap();
        let shard_refs: Vec<&[u8]> = data_shards.iter().map(Vec::as_slice).collect();
        assert_eq!(
            parity,
            encode_parity_shards(&shard_refs, plan.recovery_shards as usize).unwrap()
        );
    }

    #[test]
    fn rar5_structural_inline_recovery_data_writes_chunks_and_crc64() {
        let prefix = b"RAR5 structural inline recovery data";
        let (plan, parity) = encode_inline_recovery_parity(prefix, 10).unwrap();
        let data = build_structural_inline_recovery_data(prefix, 10).unwrap();

        assert_eq!(data.len(), plan.payload_size().unwrap() as usize);
        for (shard_index, payload) in parity.iter().enumerate() {
            let chunk_start = shard_index * plan.shard_size as usize;
            let chunk = &data[chunk_start..chunk_start + plan.shard_size as usize];
            assert_eq!(&chunk[..4], b"{RB}");
            assert_eq!(
                u64::from_le_bytes(chunk[4..12].try_into().unwrap()),
                crc64_xz(&chunk[0x0c..])
            );
            assert_eq!(
                u32::from_le_bytes(chunk[0x0c..0x10].try_into().unwrap()) as u64,
                plan.shard_size
            );
            assert_eq!(
                u32::from_le_bytes(chunk[0x10..0x14].try_into().unwrap()) as u64,
                plan.header_size
            );
            assert_eq!(chunk[0x14], 1);
            assert_eq!(chunk[0x15], 1);
            assert_eq!(
                u64::from_le_bytes(chunk[0x22..0x2a].try_into().unwrap()),
                prefix.len() as u64
            );
            assert_eq!(
                u16::from_le_bytes(chunk[0x3e..0x40].try_into().unwrap()) as usize,
                shard_index
            );
            let shard_ranges = split_prefix_shard_ranges(prefix.len(), plan).unwrap();
            assert_eq!(
                u32::from_le_bytes(chunk[0x1e..0x22].try_into().unwrap()) as usize,
                shard_ranges.last().unwrap().len()
            );
            for (data_index, range) in shard_ranges.iter().enumerate() {
                let state_offset = 0x40 + data_index * 8;
                assert_eq!(
                    u64::from_le_bytes(chunk[state_offset..state_offset + 8].try_into().unwrap()),
                    crc64_rar_state(&prefix[range.clone()])
                );
            }
            assert_eq!(&chunk[plan.header_size as usize..], payload);
        }
    }

    #[test]
    fn rar5_structural_inline_recovery_round_trips_above_64k_groups() {
        let prefix_len = (MAX_WINRAR602_DATA_SHARDS * 0x10000 + 1) as usize;
        let prefix: Vec<u8> = (0..prefix_len).map(|index| index as u8).collect();
        let plan = plan_inline_recovery(prefix.len() as u64, 1).unwrap();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 1).unwrap();

        assert_eq!(plan.header_size, 1672);
        assert_eq!(plan.group_count, 65_538);
        assert_eq!(recovery_data.len(), plan.payload_size().unwrap() as usize);

        // Two groups here (65_536 + 2), so a shard is TWO records, not one.
        let groups = recovery_groups(plan).unwrap();
        assert_eq!(
            groups.iter().map(|group| group.len).collect::<Vec<_>>(),
            vec![65_536, 2]
        );
        for shard_index in 0..plan.recovery_shards as usize {
            let mut cursor = shard_index * plan.shard_size as usize;
            for group in &groups {
                let record_size = plan.header_size as usize + group.len as usize;
                let chunk = &recovery_data[cursor..cursor + record_size];
                assert_eq!(
                    u32::from_le_bytes(chunk[0x0c..0x10].try_into().unwrap()) as usize,
                    record_size,
                    "a record declares its own size, not the shard's span"
                );
                assert_eq!(
                    u32::from_le_bytes(chunk[0x10..0x14].try_into().unwrap()) as u64,
                    plan.header_size
                );
                assert_eq!(
                    u64::from_le_bytes(chunk[0x32..0x3a].try_into().unwrap()),
                    plan.shard_size,
                    "every record still declares the shard's whole span"
                );
                assert_eq!(
                    u16::from_le_bytes(chunk[0x3e..0x40].try_into().unwrap()) as usize,
                    shard_index
                );
                assert_eq!(
                    u64::from_le_bytes(chunk[0x04..0x0c].try_into().unwrap()),
                    crc64_xz(&chunk[0x0c..])
                );
                cursor += record_size;
            }
            assert_eq!(cursor, (shard_index + 1) * plan.shard_size as usize);
        }

        assert_eq!(
            repair_inline_recovery_prefix(&prefix, &recovery_data).unwrap(),
            prefix
        );
        let mut damaged = prefix.clone();
        damaged[0] ^= 0xff;
        assert_eq!(
            repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap(),
            prefix
        );
    }

    #[test]
    fn rar5_structural_inline_recovery_uses_shared_final_state() {
        let prefix: Vec<u8> = (0..(256 * 1024)).map(|index| index as u8).collect();
        let (plan, parity) = encode_inline_recovery_parity(&prefix, 20).unwrap();
        assert!(plan.recovery_shards > 1);
        let data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let expected = crc64_rar_state(&parity[0]);

        for shard_index in 0..plan.recovery_shards as usize {
            let chunk_start = shard_index * plan.shard_size as usize;
            let final_state_offset = chunk_start + 0x40 + plan.data_shards as usize * 8;
            assert_eq!(
                u64::from_le_bytes(
                    data[final_state_offset..final_state_offset + 8]
                        .try_into()
                        .unwrap()
                ),
                expected
            );
        }
    }

    #[test]
    fn rar5_parity_encoder_rejects_invalid_shard_shapes() {
        assert_eq!(encode_parity_shards(&[], 1), Err(Error::TooManyShards));
        assert_eq!(
            encode_parity_shards(&[&[1, 2, 3]], 1),
            Err(Error::OddShardSize)
        );
        assert_eq!(
            encode_parity_shards(&[&[1, 2], &[3, 4, 5, 6]], 1),
            Err(Error::ShardSizeMismatch)
        );
    }

    #[test]
    fn rar5_inline_recovery_repairs_single_damaged_data_shard() {
        let prefix: Vec<u8> = (0..32_000).map(|index| (index * 17) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut damaged = prefix.clone();
        damaged[1500..1537].fill(0xa5);

        let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

        assert_eq!(repaired, prefix);
    }

    #[test]
    fn rar5_inline_recovery_skips_damaged_recovery_chunks_if_enough_survive() {
        let prefix: Vec<u8> = (0..32_000).map(|index| (index * 13) as u8).collect();
        let mut recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        recovery_data[0x48] ^= 0xff;
        let mut damaged = prefix.clone();
        damaged[1024..1300].fill(0xa5);

        let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

        assert_eq!(repaired, prefix);
    }

    #[test]
    fn rar5_inline_recovery_repairs_multiple_damaged_data_shards() {
        let prefix: Vec<u8> = (0..128_000).map(|index| (index * 31) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut damaged = prefix.clone();
        damaged[100..500].fill(0x11);
        damaged[4_000..4_400].fill(0x22);
        damaged[9_000..9_400].fill(0x33);

        let repaired = repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap();

        assert_eq!(repaired, prefix);
    }

    #[test]
    fn rar5_inline_recovery_returns_only_repaired_shard_ranges() {
        let prefix: Vec<u8> = (0..128_000).map(|index| (index * 29) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut damaged = prefix.clone();
        damaged[100..500].fill(0x11);
        damaged[9_000..9_400].fill(0x33);

        let repaired_shards =
            repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
                Ok(damaged[range].to_vec())
            })
            .unwrap();
        assert!(!repaired_shards.is_empty());

        let mut repaired = damaged;
        for (range, data) in repaired_shards {
            assert_eq!(range.len(), data.len());
            repaired[range].copy_from_slice(&data);
        }

        assert_eq!(repaired, prefix);
    }

    /// The buffered shard api ACROSS GROUPS, damaged outside the first one.
    ///
    /// A group is at most 200 x 64 KiB, so anything under ~13 MB has exactly
    /// one and every earlier test of this api sat inside it. With two groups
    /// the second one's CRC table is a different table: taking the first
    /// record's for the whole set called all 200 shards damaged and the repair
    /// failed for want of parity it did not need.
    #[test]
    fn rar5_inline_recovery_shards_repair_damage_in_a_later_group() {
        // 200 * 64 KiB is exactly one group, so a little past it is two.
        let prefix_len = (MAX_WINRAR602_DATA_SHARDS * 0x10000) as usize + 300_000;
        let prefix: Vec<u8> = (0..prefix_len).map(|index| (index * 7) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 10).unwrap();

        let plan = plan_inline_recovery(prefix.len() as u64, 10).unwrap();
        let groups = recovery_groups(plan).unwrap();
        assert!(
            groups.len() >= 2,
            "this test is pointless with a single group"
        );
        assert!(prefix.len() as u64 > 13_107_200, "must exceed one group");

        // One shard in the LAST group and, on a different shard, one in the
        // first: the two groups have to be solved independently for both to
        // come back.
        let last = *groups.last().unwrap();
        let late_hit = 3 * plan.group_count as usize + last.offset as usize + 128;
        let early_hit = 11 * plan.group_count as usize + 64;
        assert!(late_hit < prefix.len() && early_hit < prefix.len());
        let mut damaged = prefix.clone();
        damaged[late_hit..late_hit + 512].fill(0x5a);
        damaged[early_hit..early_hit + 512].fill(0xa5);

        let patches = repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
            Ok(damaged[range].to_vec())
        })
        .unwrap();
        assert!(!patches.is_empty(), "the damage must be found at all");

        // The caller streams these out in one forward pass, so they must be
        // ascending and disjoint.
        let mut cursor = 0usize;
        for (range, data) in &patches {
            assert_eq!(range.len(), data.len());
            assert!(
                range.start >= cursor,
                "patches must be ascending and disjoint: {range:?} after {cursor}"
            );
            cursor = range.end;
        }

        let mut repaired = damaged;
        for (range, data) in patches {
            repaired[range].copy_from_slice(&data);
        }
        assert_eq!(
            repaired, prefix,
            "a multi-group buffered repair must be byte-exact"
        );
    }

    /// The same shape with NO damage: a multi-group archive must come back
    /// with nothing to patch. Before the per-group fix this reported every
    /// shard of every group past the first as damaged.
    #[test]
    fn rar5_inline_recovery_shards_report_a_clean_multi_group_prefix_as_clean() {
        let prefix_len = (MAX_WINRAR602_DATA_SHARDS * 0x10000) as usize + 300_000;
        let prefix: Vec<u8> = (0..prefix_len).map(|index| (index * 7) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 10).unwrap();
        assert!(recovery_groups(plan_inline_recovery(prefix.len() as u64, 10).unwrap())
            .unwrap()
            .len()
            >= 2);

        let patches = repair_inline_recovery_prefix_shards(prefix.len(), &recovery_data, |range| {
            Ok(prefix[range].to_vec())
        })
        .unwrap();

        assert!(patches.is_empty(), "an intact prefix needs no patches");
    }

    #[test]
    fn rar5_inline_recovery_archive_scans_chunks_and_repairs_prefix() {
        let prefix: Vec<u8> = (0..32_000).map(|index| (index * 13) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut archive = prefix.clone();
        archive.extend_from_slice(b"service header bytes before chunks");
        archive.extend_from_slice(&recovery_data);
        archive.extend_from_slice(b"end bytes");
        let mut damaged = archive.clone();
        damaged[256..320].fill(0x5a);

        let repaired = repair_inline_recovery_archive(&damaged).unwrap();

        assert_eq!(repaired, archive);
    }

    #[test]
    fn rar5_inline_recovery_archive_accepts_healthy_archive() {
        let prefix: Vec<u8> = (0..32_000).map(|index| (index * 17) as u8).collect();
        let recovery_data = build_structural_inline_recovery_data(&prefix, 20).unwrap();
        let mut archive = prefix.clone();
        archive.extend_from_slice(b"service header bytes before chunks");
        archive.extend_from_slice(&recovery_data);
        archive.extend_from_slice(b"end bytes");

        let repaired = repair_inline_recovery_archive(&archive).unwrap();

        assert_eq!(repaired, archive);
    }

    #[test]
    fn rar5_inline_recovery_rejects_unrepairable_damage_count() {
        let prefix = b"small prefix with only one parity shard".repeat(100);
        let recovery_data = build_structural_inline_recovery_data(&prefix, 1).unwrap();
        let mut damaged = prefix.clone();
        damaged[0] ^= 0xff;
        damaged[1024] ^= 0xff;

        assert_eq!(
            repair_inline_recovery_prefix(&damaged, &recovery_data),
            Err(Error::TooManyDamagedShards)
        );
    }

    /// Build a CRC-valid `{RB}` record with arbitrary plan fields, so the
    /// hostile-input tests below never have to construct (or allocate) the
    /// enormous thing the record merely *claims*.
    fn forged_record(
        protected_size: u64,
        group_count: u64,
        data_shards: u16,
        parity_len: usize,
    ) -> Vec<u8> {
        let header_size = 0x48usize + data_shards as usize * 8;
        let total_size = header_size + parity_len;
        let mut rec = vec![0u8; total_size];
        rec[..4].copy_from_slice(b"{RB}");
        rec[0x0c..0x10].copy_from_slice(&(total_size as u32).to_le_bytes());
        rec[0x10..0x14].copy_from_slice(&(header_size as u32).to_le_bytes());
        rec[0x14] = 1;
        rec[0x15] = 1;
        rec[0x22..0x2a].copy_from_slice(&protected_size.to_le_bytes());
        rec[0x2a..0x32].copy_from_slice(&group_count.to_le_bytes());
        rec[0x32..0x3a].copy_from_slice(&(total_size as u64).to_le_bytes());
        rec[0x3a..0x3c].copy_from_slice(&data_shards.to_le_bytes());
        rec[0x3c..0x3e].copy_from_slice(&1u16.to_le_bytes());
        rec[0x3e..0x40].copy_from_slice(&0u16.to_le_bytes());
        let crc = crc64_xz(&rec[0x0c..]);
        rec[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());
        rec
    }

    /// A record's plan sizes an allocation, so it has to be affordable before
    /// anything acts on it. data_shards is a u16 and group_count only had to
    /// match this record's own parity length, so a ~590 KB file could declare
    /// a 4.29 GB shard grid; Rust answers allocation failure with abort, so
    /// that is the daemon killed by a downloaded file.
    #[test]
    fn rar5_inline_recovery_rejects_a_plan_larger_than_the_file() {
        let record = forged_record(4096, 65_536, 65_535, 65_536);
        assert_eq!(65_535u64 * 65_536, 4_294_901_760, "the plan claims 4.29 GB");
        assert!(record.len() < 700 * 1024, "but the fixture stays tiny");

        let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
        archive.extend_from_slice(&record);

        assert_eq!(
            repair_inline_recovery_archive(&archive),
            Err(Error::BadRecoveryChunk)
        );
    }

    /// Geometry read off real WinRAR 7.23 output (`rar a -ma5 -m0 -rr5p`).
    ///
    /// These are the numbers the format ceiling was hiding: below one group
    /// the old single-record arithmetic agreed with RARLab by accident, and
    /// above it every field but `group_count` disagreed. Pinning measured
    /// archives here is what stops the layout drifting back to a guess -
    /// every recovery test besides this one round-trips our own writer, so
    /// nothing else in the suite would notice.
    #[test]
    fn rar5_plan_matches_real_winrar_geometry() {
        // 16 MB archive: two groups, 65_536 + 18_352.
        let plan = plan_inline_recovery(16_777_374, 5).unwrap();
        assert_eq!(plan.data_shards, 200);
        assert_eq!(plan.recovery_shards, 10);
        assert_eq!(plan.group_count, 83_888);
        assert_eq!(plan.header_size, 1_672);
        assert_eq!(plan.shard_size, 87_232);
        assert_eq!(
            recovery_groups(plan)
                .unwrap()
                .iter()
                .map(|group| group.len)
                .collect::<Vec<_>>(),
            vec![65_536, 18_352]
        );

        // 128 MB archive: eleven groups, ten full and a short tail.
        let plan = plan_inline_recovery(134_217_886, 5).unwrap();
        assert_eq!(plan.group_count, 671_090);
        assert_eq!(plan.shard_size, 689_482);
        let groups = recovery_groups(plan).unwrap();
        assert_eq!(groups.len(), 11);
        assert!(groups[..10].iter().all(|group| group.len == 65_536));
        assert_eq!(groups[10].len, 671_090 - 10 * 65_536);
        assert_eq!(
            groups.iter().map(|group| group.len).sum::<u64>(),
            plan.group_count,
            "a shard's groups must tile its whole parity row"
        );
    }

    /// A two-full-group plan: both groups carry 64 KiB of parity, so parity
    /// length cannot tell one from the other.
    fn two_full_group_plan() -> InlineRecoveryPlan {
        let plan = InlineRecoveryPlan {
            data_shards: 4,
            recovery_shards: 4,
            group_count: 2 * RAR5_RECOVERY_PARITY_PER_RECORD_MAX,
            header_size: 0x48 + 4 * 8,
            shard_size: 0,
        };
        let plan = InlineRecoveryPlan {
            shard_size: shard_record_span(plan).unwrap(),
            ..plan
        };
        assert_eq!(recovery_groups(plan).unwrap().len(), 2);
        plan
    }

    /// Records as they sit in the file: shard-index-major, every group of
    /// shard 0, then every group of shard 1, starting at `base`.
    fn laid_out_records(plan: InlineRecoveryPlan, base: u64) -> Vec<(u64, usize, u64)> {
        let groups = recovery_groups(plan).unwrap();
        let span = shard_record_span(plan).unwrap();
        let mut records = Vec::new();
        for shard in 0..plan.recovery_shards as usize {
            let mut cursor = base + shard as u64 * span;
            for group in &groups {
                records.push((cursor, shard, group.len));
                cursor += plan.header_size + group.len;
            }
        }
        records
    }

    /// The recovery-area base is inferred from the earliest SURVIVING record.
    /// Lose every group-0 record to CRC damage and the group-1 records look
    /// exactly like group-0 records one boundary further on - same offset
    /// arithmetic, same parity length. Assigning them to group 0 would repair
    /// group 0's ranges out of group 1's parity and return success, so an
    /// undecidable layout has to fail closed instead.
    #[test]
    fn rar5_recovery_base_refuses_an_ambiguous_layout() {
        let plan = two_full_group_plan();
        // Far enough in that an earlier base is arithmetically possible -
        // otherwise the guard has nothing to weigh.
        let base = 200_000;
        let all = laid_out_records(plan, base);

        // Healthy: every record present, every group correctly identified.
        let assigned = assign_recovery_groups(plan, &all, 0).unwrap();
        assert_eq!(
            assigned,
            (0..plan.recovery_shards as usize)
                .flat_map(|_| [Some(0), Some(1)])
                .collect::<Vec<_>>()
        );

        // Every group-0 record CRC-damaged (so absent), every group-1 record
        // intact: the base is no longer decidable from what survived.
        let survivors: Vec<_> = all.iter().copied().skip(1).step_by(2).collect();
        assert_eq!(survivors.len(), plan.recovery_shards as usize);
        assert_eq!(
            assign_recovery_groups(plan, &survivors, 0),
            Err(Error::BadRecoveryChunk),
            "assigning the survivors to group 0 would rebuild it from the wrong parity"
        );

        // The floor settles it when the caller knows one: with no room for a
        // record before them, the survivors can only BE group 0 - which is
        // also the ordinary healthy case, where the recovery area starts
        // immediately after the data it protects.
        let assigned = assign_recovery_groups(plan, &survivors, base + 1).unwrap();
        assert!(assigned.iter().all(|group| *group == Some(0)));

        // Losing only SOME group-0 records leaves the base pinned, and every
        // survivor keeps its true group.
        let mut partial = all.clone();
        partial.remove(2); // shard 1's group-0 record
        let assigned = assign_recovery_groups(plan, &partial, 0).unwrap();
        assert_eq!(assigned[0], Some(0));
        assert_eq!(assigned[1], Some(1));
        assert_eq!(assigned[2], Some(1));
    }

    /// The guard must stay silent on healthy sets, including the ordinary
    /// shape: several full groups and a short tail.
    #[test]
    fn rar5_recovery_base_accepts_a_healthy_three_group_set() {
        let plan = InlineRecoveryPlan {
            data_shards: 4,
            recovery_shards: 4,
            group_count: 2 * RAR5_RECOVERY_PARITY_PER_RECORD_MAX + 4096,
            header_size: 0x48 + 4 * 8,
            shard_size: 0,
        };
        let plan = InlineRecoveryPlan {
            shard_size: shard_record_span(plan).unwrap(),
            ..plan
        };
        assert_eq!(recovery_groups(plan).unwrap().len(), 3);
        let all = laid_out_records(plan, 200_000);
        let assigned = assign_recovery_groups(plan, &all, 0).unwrap();
        assert!(assigned.chunks(3).all(|shard| shard == [Some(0), Some(1), Some(2)]));

        // Damage that takes out records WITHIN a group leaves the base pinned
        // by the survivors of the others.
        let survivors: Vec<_> = all
            .iter()
            .copied()
            .enumerate()
            .filter(|(index, _)| *index != 4 && *index != 8)
            .map(|(_, record)| record)
            .collect();
        let assigned = assign_recovery_groups(plan, &survivors, 0).unwrap();
        assert_eq!(assigned[..3], [Some(0), Some(1), Some(2)]);
    }

    /// Damage in a group OTHER than the first, which is the case the old
    /// single-group reader could not even see.
    #[test]
    fn rar5_repairs_damage_in_a_later_group() {
        // Three groups: 65_536 * 2 + a tail.
        let prefix_len = (MAX_WINRAR602_DATA_SHARDS * 0x10000 * 2 + 4096) as usize;
        let prefix: Vec<u8> = (0..prefix_len).map(|index| (index * 7) as u8).collect();
        let plan = plan_inline_recovery(prefix.len() as u64, 5).unwrap();
        let groups = recovery_groups(plan).unwrap();
        assert!(groups.len() >= 3, "need a multi-group archive to mean anything");

        let recovery_data = build_structural_inline_recovery_data(&prefix, 5).unwrap();
        assert_eq!(
            repair_inline_recovery_prefix(&prefix, &recovery_data).unwrap(),
            prefix,
            "an undamaged prefix must come back untouched"
        );

        // One byte inside the LAST group of data shard 3.
        let last = *groups.last().unwrap();
        let hit = (3 * plan.group_count + last.offset) as usize + 5;
        assert!(hit < prefix.len());
        let mut damaged = prefix.clone();
        damaged[hit] ^= 0xff;
        assert_eq!(
            repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap(),
            prefix
        );

        // And damage in two different groups at once, which only works
        // because each group is solved against its own parity.
        let mut damaged = prefix.clone();
        damaged[hit] ^= 0xff;
        damaged[(1 * plan.group_count + groups[1].offset) as usize + 9] ^= 0xff;
        assert_eq!(
            repair_inline_recovery_prefix(&damaged, &recovery_data).unwrap(),
            prefix
        );
    }

    /// The plan bound is derived from the format's own arithmetic, so it must
    /// not creep down onto legitimate archives: this is the widest real plan
    /// (group_count rounded up to even is what makes capacity exceed the
    /// protected size at all).
    #[test]
    fn rar5_inline_recovery_plan_bound_accepts_the_widest_real_archive() {
        let prefix_len = (MAX_WINRAR602_DATA_SHARDS * 0x10000 + 1) as usize;
        let prefix: Vec<u8> = (0..prefix_len).map(|index| index as u8).collect();
        let plan = plan_inline_recovery(prefix.len() as u64, 1).unwrap();
        let capacity = plan.data_shards * plan.group_count;
        assert!(
            capacity > prefix.len() as u64,
            "the even-rounding overshoot is what the bound has to allow"
        );
        assert!(capacity <= prefix.len() as u64 + 2 * plan.data_shards);

        let recovery_data = build_structural_inline_recovery_data(&prefix, 1).unwrap();
        assert!(find_inline_recovery_chunks(&recovery_data).is_ok());
    }

    /// The GF16 kernel walks two-byte symbols, so an odd shard length reads
    /// one past the end. `repair_inline_recovery_prefix_shards` guarded that,
    /// but the raw-scan path a damaged download actually takes goes through
    /// `repair_inline_recovery_prefix`, which did not: a downloaded file could
    /// panic the process.
    #[test]
    fn rar5_inline_recovery_rejects_odd_group_count_without_panicking() {
        for group_count in [1u64, 3, 5, 65_535] {
            let record = forged_record(group_count * 2, group_count, 2, group_count as usize);
            let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
            archive.extend_from_slice(&record);
            assert_eq!(
                repair_inline_recovery_archive(&archive),
                Err(Error::BadRecoveryChunk),
                "odd group_count {group_count} must be refused, not indexed past"
            );
        }
    }

    /// Even with every caller validated, the kernel refuses odd/short input
    /// itself - the panic above happened because one caller was trusted.
    #[test]
    fn rar5_recover_damaged_shards_refuses_odd_and_short_rows() {
        let mut odd = vec![vec![0u8; 3], vec![0u8; 3]];
        let parity = vec![0u8; 3];
        assert_eq!(
            recover_damaged_shards(&mut odd, &[0], &[(0, parity.as_slice())]),
            Err(Error::OddShardSize)
        );

        let mut ragged = vec![vec![0u8; 4], vec![0u8; 6]];
        let parity = vec![0u8; 4];
        assert_eq!(
            recover_damaged_shards(&mut ragged, &[0], &[(0, parity.as_slice())]),
            Err(Error::ShardSizeMismatch)
        );

        let mut even = vec![vec![0u8; 4], vec![0u8; 4]];
        let short = vec![0u8; 2];
        assert_eq!(
            recover_damaged_shards(&mut even, &[0], &[(0, short.as_slice())]),
            Err(Error::ShardSizeMismatch)
        );
    }

    /// Rejected candidates resume at start + 1 and each one CRC64s to its
    /// declared end, so overlapping markers re-hash almost the same span every
    /// byte. Without a budget a 4 MiB volume is ~110 GB of bitwise CRC - an
    /// unkillable job from a file that arrived off the wire.
    #[test]
    fn rar5_inline_recovery_scan_is_not_quadratic_on_dense_markers() {
        let len = 4 * 1024 * 1024;
        let mut hostile = vec![0x41u8; len];
        hostile[..8].copy_from_slice(b"Rar!\x1a\x07\x01\x00");
        let mut planted = 0;
        let mut pos = 8;
        while pos + 0x48 < len {
            hostile[pos..pos + 4].copy_from_slice(b"{RB}");
            // Reach to EOF so each candidate asks for a full-suffix hash, and
            // leave the stored CRC as junk so it is always rejected.
            hostile[pos + 0x0c..pos + 0x10]
                .copy_from_slice(&((len - pos) as u32).to_le_bytes());
            hostile[pos + 0x10..pos + 0x14].copy_from_slice(&0x48u32.to_le_bytes());
            planted += 1;
            pos += 80;
        }
        assert!(planted > 50_000, "{planted} markers is not a dense fixture");

        let started = std::time::Instant::now();
        let result = repair_inline_recovery_archive(&hostile);
        let elapsed = started.elapsed();

        assert!(result.is_err(), "junk must not repair");
        assert!(
            elapsed.as_secs() < 5,
            "scan took {elapsed:?} - the hash budget is not bounding it"
        );
    }

    #[test]
    fn rar5_reconstruct_data_shards_repairs_missing_shards_from_parity() {
        let first = b"abcdefgh".to_vec();
        let second = b"ijklmnop".to_vec();
        let third = b"qrstuvwx".to_vec();
        let refs = [first.as_slice(), second.as_slice(), third.as_slice()];
        let parity = encode_parity_shards(&refs, 2).unwrap();

        let reconstructed = reconstruct_data_shards(
            &[Some(&first), None, Some(&third)],
            &[(0, parity[0].as_slice())],
        )
        .unwrap();

        assert_eq!(reconstructed[0], first);
        assert_eq!(reconstructed[1], second);
        assert_eq!(reconstructed[2], third);
    }

    #[test]
    fn rar5_reconstruct_data_shards_repairs_multiple_missing_shards() {
        let first = b"abcdefgh".to_vec();
        let second = b"ijklmnop".to_vec();
        let third = b"qrstuvwx".to_vec();
        let refs = [first.as_slice(), second.as_slice(), third.as_slice()];
        let parity = encode_parity_shards(&refs, 2).unwrap();

        let reconstructed = reconstruct_data_shards(
            &[None, Some(&second), None],
            &[(0, parity[0].as_slice()), (1, parity[1].as_slice())],
        )
        .unwrap();

        assert_eq!(reconstructed[0], first);
        assert_eq!(reconstructed[1], second);
        assert_eq!(reconstructed[2], third);
    }

    /// One buffer is padded per declared slot, so feasibility has to be settled
    /// before the padding starts: a slot is only recoverable from an
    /// independent recovery row, and reserving the grid to discover there are
    /// not enough rows is exactly the allocation a hostile volume wants.
    #[test]
    fn rar5_reconstruct_refuses_more_missing_slots_than_recovery_rows() {
        let parity = vec![0u8; 8];
        assert_eq!(
            reconstruct_data_shards(&[None, None], &[(0, parity.as_slice())]),
            Err(Error::TooManyDamagedShards)
        );

        // Two copies of one row restate one equation - no extra repair
        // capacity, so they must not license a second missing slot.
        assert_eq!(
            reconstruct_data_shards(
                &[None, None],
                &[(0, parity.as_slice()), (0, parity.as_slice())]
            ),
            Err(Error::TooManyDamagedShards)
        );
    }

    /// The slot count comes from a `u16` in a header that costs 12 bytes per
    /// slot to declare, so it is never a safe multiplier for a payload-sized
    /// allocation. Both bounds are checked while the grid is still notional.
    #[test]
    fn rar5_reconstruct_refuses_a_grid_beyond_the_allocation_bounds() {
        let parity = vec![0u8; 2];
        let too_many: Vec<Option<&[u8]>> = vec![None; MAX_RECONSTRUCTION_SHARDS + 1];
        assert_eq!(
            reconstruct_data_shards(&too_many, &[(0, parity.as_slice())]),
            Err(Error::ReconstructionTooLarge)
        );

        // Within the slot bound, but the payload size puts the grid just over
        // the byte bound.
        let wide_parity = vec![0u8; 2 * 1024 * 1024 + 2];
        let slots: Vec<Option<&[u8]>> = vec![None; MAX_RECONSTRUCTION_SHARDS];
        assert_eq!(
            reconstruct_data_shards(&slots, &[(0, wide_parity.as_slice())]),
            Err(Error::ReconstructionTooLarge)
        );

        // A row numbered near the u16 ceiling sizes the encoder matrix, which
        // is (highest row + 1) x slots even when only one row was supplied.
        assert_eq!(
            reconstruct_data_shards(
                &[None, Some(parity.as_slice())],
                &[(MAX_RECONSTRUCTION_SHARDS, parity.as_slice())]
            ),
            Err(Error::ReconstructionTooLarge)
        );
    }

    /// Shard bytes generated on demand instead of stored, so a test can
    /// address a volume far larger than it could hold. Every shard is a
    /// single repeated 16-bit symbol, which makes each recovery row a single
    /// repeated symbol too - the GF math stays real while both sides of it
    /// remain computable in O(data_count) rather than O(shard_len).
    struct ConstantShards {
        symbols: Vec<u16>,
        /// Largest single window any callback was asked for.
        peak_window: std::cell::Cell<usize>,
    }

    impl ConstantShards {
        fn new(data_count: usize) -> Self {
            Self {
                // Distinct non-zero symbols: an all-zero set would make the
                // parity trivially zero and prove nothing about the solve.
                symbols: (0..data_count).map(|i| (i as u16) * 7 + 3).collect(),
                peak_window: std::cell::Cell::new(0),
            }
        }

        fn parity_symbol(&self, row: usize) -> u16 {
            let gf = shared_gf16();
            let matrix = make_encoder_matrix(self.symbols.len(), row + 1).unwrap();
            self.symbols
                .iter()
                .enumerate()
                .fold(0u16, |sum, (index, &symbol)| {
                    sum ^ gf.mul(matrix[row][index], symbol)
                })
        }

        fn fill(&self, symbol: u16, buf: &mut [u8]) {
            self.peak_window.set(self.peak_window.get().max(buf.len()));
            for word in buf.chunks_exact_mut(2) {
                word.copy_from_slice(&symbol.to_le_bytes());
            }
        }
    }

    #[test]
    fn rar5_striped_repair_matches_the_whole_grid_result() {
        // Same inputs through both kernels: the striped path must be a
        // memory shape change, not a different reconstruction.
        let shards: Vec<Vec<u8>> = (0..6)
            .map(|i| (0..64).map(|b| (i * 31 + b * 7) as u8).collect())
            .collect();
        let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
        let parity = encode_parity_shards(&refs, 3).unwrap();

        for damaged in [vec![2usize], vec![0, 5], vec![1, 3, 4]] {
            let rows: Vec<usize> = (0..damaged.len()).collect();
            let mut available: Vec<Option<&[u8]>> =
                refs.iter().map(|shard| Some(*shard)).collect();
            for &index in &damaged {
                available[index] = None;
            }
            let recovery: Vec<(usize, &[u8])> =
                rows.iter().map(|&r| (r, parity[r].as_slice())).collect();
            let expected = reconstruct_data_shards(&available, &recovery).unwrap();

            let plan = StripeRepairPlan::new(shards.len(), 3, 64, &damaged, &rows).unwrap();
            let mut rebuilt = vec![vec![0u8; 64]; damaged.len()];
            // A stripe that does not divide the shard exercises the short
            // trailing window.
            repair_shards_striped(
                &plan,
                20,
                |index, offset, buf| {
                    buf.copy_from_slice(&shards[index][offset..offset + buf.len()]);
                    Ok(())
                },
                |slot, offset, buf| {
                    buf.copy_from_slice(&parity[rows[slot]][offset..offset + buf.len()]);
                    Ok(())
                },
                |slot, offset, bytes| {
                    rebuilt[slot][offset..offset + bytes.len()].copy_from_slice(bytes);
                    Ok(())
                },
            )
            .unwrap();

            for (slot, &index) in plan.damaged().iter().enumerate() {
                assert_eq!(rebuilt[slot], shards[index], "damaged set {damaged:?}");
                assert_eq!(rebuilt[slot], expected[index]);
            }
        }
    }

    #[test]
    fn rar5_striped_repair_agrees_with_the_whole_grid_at_every_stripe_size() {
        // The stripe length is the parameter most likely to hide an off-by-one:
        // it interacts with the short trailing stripe, the 2-byte symbol walk,
        // and the per-stripe rhs reset. Sweep it against the whole-grid oracle
        // rather than trusting one hand-picked value - including a stripe
        // larger than the shard, one exactly equal to it, the 2-byte minimum,
        // and several that do not divide it.
        for &shard_len in &[2usize, 8, 64, 66, 128, 250] {
            let shards: Vec<Vec<u8>> = (0..5)
                .map(|i| {
                    (0..shard_len)
                        .map(|b| (i * 97 + b * 31 + 5) as u8)
                        .collect()
                })
                .collect();
            let refs: Vec<&[u8]> = shards.iter().map(Vec::as_slice).collect();
            let parity = encode_parity_shards(&refs, 2).unwrap();

            for &damaged_index in &[0usize, 2, 4] {
                let damaged = vec![damaged_index];
                let rows = vec![0usize];
                let mut available: Vec<Option<&[u8]>> =
                    refs.iter().map(|s| Some(*s)).collect();
                available[damaged_index] = None;
                let expected = reconstruct_data_shards(
                    &available,
                    &[(0, parity[0].as_slice())],
                )
                .unwrap();

                let plan =
                    StripeRepairPlan::new(shards.len(), 2, shard_len, &damaged, &rows).unwrap();
                for &stripe in &[2usize, 4, 6, 64, shard_len, shard_len + 2, shard_len * 3] {
                    if stripe == 0 || !stripe.is_multiple_of(2) {
                        continue;
                    }
                    let mut rebuilt = vec![0u8; shard_len];
                    repair_shards_striped(
                        &plan,
                        stripe,
                        |index, offset, buf| {
                            buf.copy_from_slice(&shards[index][offset..offset + buf.len()]);
                            Ok(())
                        },
                        |_, offset, buf| {
                            buf.copy_from_slice(&parity[0][offset..offset + buf.len()]);
                            Ok(())
                        },
                        |_, offset, bytes| {
                            rebuilt[offset..offset + bytes.len()].copy_from_slice(bytes);
                            Ok(())
                        },
                    )
                    .unwrap();
                    assert_eq!(
                        rebuilt, shards[damaged_index],
                        "shard_len {shard_len}, damaged {damaged_index}, stripe {stripe}"
                    );
                    assert_eq!(rebuilt, expected[damaged_index]);
                }
            }
        }
    }

    #[test]
    fn rar5_striped_repair_holds_its_window_inside_a_small_ceiling() {
        // 4 MiB shards repaired inside a 128 KiB ceiling: the point is that
        // no callback is ever handed more than one stripe, and that the
        // reserved working set matches the documented formula rather than
        // scaling with the set.
        const SHARD_LEN: usize = 4 << 20;
        const BUDGET: u64 = 128 << 10;
        let source = ConstantShards::new(8);
        let damaged = vec![3usize];
        let rows = vec![0usize];
        let plan = StripeRepairPlan::new(8, 1, SHARD_LEN, &damaged, &rows).unwrap();
        let stripe = plan.stripe_len_for_budget(BUDGET).unwrap();
        assert!(plan.working_bytes(stripe) <= BUDGET);
        assert!(stripe < SHARD_LEN, "a 4 MiB shard must take several stripes");

        let parity = source.parity_symbol(0);
        let expected = source.symbols[3];
        let mut written = 0usize;
        repair_shards_striped(
            &plan,
            stripe,
            |index, _, buf| {
                assert!(buf.len() <= stripe);
                source.fill(source.symbols[index], buf);
                Ok(())
            },
            |_, _, buf| {
                source.fill(parity, buf);
                Ok(())
            },
            |_, offset, bytes| {
                assert_eq!(offset, written, "stripes arrive in ascending order");
                assert!(bytes.len() <= stripe);
                assert!(
                    bytes
                        .chunks_exact(2)
                        .all(|w| u16::from_le_bytes([w[0], w[1]]) == expected),
                    "rebuilt stripe at {offset} does not match the missing shard"
                );
                written += bytes.len();
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(written, SHARD_LEN, "the whole shard was rebuilt");
        assert!(source.peak_window.get() <= stripe);
    }

    // 64-bit only, and the reason is the property under test rather than
    // the test's convenience: `StripeRepairPlan` measures a shard in
    // `usize`, so on a 32-bit host (armv7) a 20 GiB shard is not a plan
    // that comes out badly sized - it is a plan that cannot be built.
    // Both production callers already refuse it there, at
    // `usize::try_from(shard_len) -> RecoveryError::PlanOverflow`
    // (rar50.rs `repair_volume_set`, recovery/stream.rs `repair_stream`),
    // so the 32-bit answer is a clean decline. Written as `20 << 30` in a
    // 32-bit `usize` the constant is silently ZERO, which is how this
    // read as an `OddShardSize` failure rather than as "not applicable".
    // The striping arithmetic itself is pinned for 32-bit by
    // `rar5_striped_plan_budgets_the_largest_shard_a_32_bit_host_can_hold`.
    #[cfg(not(target_pointer_width = "32"))]
    #[test]
    fn rar5_striped_plan_budgets_a_multi_gigabyte_volume_without_allocating_it() {
        // A 20 GiB declared volume: planning and budgeting must depend on
        // the damage count alone, never on the size of the set. Nothing here
        // touches a byte of shard data, which is exactly why a volume this
        // size can be planned at all.
        const SHARD_LEN: usize = 20 << 30;
        let damaged = vec![11usize];
        let rows = vec![0usize];
        let plan = StripeRepairPlan::new(60, 1, SHARD_LEN, &damaged, &rows).unwrap();

        let stripe = plan.stripe_len_for_budget(64 << 20).unwrap();
        assert!(plan.working_bytes(stripe) <= 64 << 20);
        assert!(
            stripe <= 64 << 20,
            "the stripe is bounded by the budget, not by the 20 GiB shard"
        );
        // A 60x1 GB set with one missing volume - finding 10's own example -
        // now needs a stripe, not the >120 GB the whole-grid path wanted.
        let small = StripeRepairPlan::new(60, 1, 1 << 30, &damaged, &rows).unwrap();
        assert!(small.working_bytes(small.stripe_len_for_budget(8 << 20).unwrap()) <= 8 << 20);

        // A budget too small to run on is a clean refusal, not a crawl.
        assert_eq!(
            plan.stripe_len_for_budget(1024),
            Err(Error::RepairTooLarge)
        );
    }

    /// The 32-bit twin of the test above: the same "the stripe is bounded
    /// by the budget, not by the shard" property, at the largest shard a
    /// 32-bit host can actually express. Without this, armv7 would carry
    /// no coverage of the striping arithmetic at scale at all.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn rar5_striped_plan_budgets_the_largest_shard_a_32_bit_host_can_hold() {
        const SHARD_LEN: usize = 3 << 30; // 3 GiB, and it fits
        let damaged = vec![11usize];
        let rows = vec![0usize];
        let plan = StripeRepairPlan::new(60, 1, SHARD_LEN, &damaged, &rows).unwrap();

        let stripe = plan.stripe_len_for_budget(64 << 20).unwrap();
        assert!(plan.working_bytes(stripe) <= 64 << 20);
        assert!(
            stripe <= 64 << 20,
            "the stripe is bounded by the budget, not by the 3 GiB shard"
        );
        assert_eq!(
            plan.stripe_len_for_budget(1024),
            Err(Error::RepairTooLarge)
        );
    }

    #[test]
    fn rar5_striped_plan_rejects_a_system_it_cannot_solve() {
        // Two missing shards backed by the same recovery row is one equation
        // counted twice - singular, and refused at plan time rather than
        // producing confident garbage.
        let err = |damaged: &[usize], rows: &[usize], shard_len: usize, recovery: usize| {
            StripeRepairPlan::new(6, recovery, shard_len, damaged, rows).unwrap_err()
        };
        assert_eq!(err(&[1, 2], &[0, 0], 64, 3), Error::TooManyDamagedShards);
        // More damage than equations.
        assert_eq!(err(&[1, 2], &[0], 64, 3), Error::TooManyDamagedShards);
        // A duplicated damaged index would silently shrink the system.
        assert_eq!(err(&[1, 1], &[0, 1], 64, 3), Error::TooManyDamagedShards);
        // An odd shard length would walk a 2-byte symbol off the end.
        assert_eq!(err(&[1], &[0], 63, 3), Error::OddShardSize);
        // A row beyond the declared recovery count.
        assert_eq!(err(&[1], &[3], 64, 1), Error::TooManyShards);
    }

    #[test]
    fn rar5_striped_plan_refuses_a_wire_scale_grid() {
        // Hostile declarations arrive raw off the wire as u16s. Every one of
        // these refusals must come before anything is sized from the
        // declaration, so together they also have to be instant.
        let started = std::time::Instant::now();
        // 32768 recovery shards is past the hard recovery cap.
        assert_eq!(
            StripeRepairPlan::new(32_767, 32_768, 4096, &[7], &[0]).unwrap_err(),
            Error::ReconstructionTooLarge
        );
        assert_eq!(
            StripeRepairPlan::new(8, MAX_RECONSTRUCTION_SHARDS + 1, 4096, &[7], &[0])
                .unwrap_err(),
            Error::ReconstructionTooLarge
        );
        // The two counts together cannot exceed the GF(2^16) code word.
        assert_eq!(
            StripeRepairPlan::new(FIELD_SIZE, 4096, 4096, &[7], &[0]).unwrap_err(),
            Error::TooManyShards
        );
        // A wide slot count paired with a huge damage list blows the cell
        // budget: 4096 damaged rows x 61439 slots is ~252M matrix cells.
        let damaged: Vec<usize> = (0..MAX_RECONSTRUCTION_SHARDS).collect();
        let rows: Vec<usize> = (0..MAX_RECONSTRUCTION_SHARDS).collect();
        assert_eq!(
            StripeRepairPlan::new(
                FIELD_SIZE - MAX_RECONSTRUCTION_SHARDS,
                MAX_RECONSTRUCTION_SHARDS,
                4096,
                &damaged,
                &rows
            )
            .unwrap_err(),
            Error::ReconstructionTooLarge
        );
        assert!(
            started.elapsed().as_millis() < 500,
            "a refused grid must not be built first"
        );
        // The caps sit far above anything real. WinRAR tops out at 200 data
        // shards per inline record, and a plan that size must still build -
        // as must the `.rev` shape the old data_count cap wrongly refused: a
        // 100 GB release in 15 MB volumes is ~6,800 data volumes, more than
        // MAX_RECONSTRUCTION_SHARDS, and it repaired before that cap landed.
        StripeRepairPlan::new(200, 10, 4096, &[7], &[0]).unwrap();
        StripeRepairPlan::new(6_800, 5, 4096, &[7, 11], &[0, 3]).unwrap();
    }

    /// Builds the ~262 KB record that used to sail through the in-memory
    /// parser: internally consistent in every field the parser checks -
    /// sizes, version bytes, CRC64, capacity arithmetic, record span - while
    /// declaring a 32767 x 32768 grid, which is ~2 GiB of encoder matrix the
    /// moment `solve_damaged_group_shards` acts on it.
    fn wire_scale_consistent_record() -> Vec<u8> {
        let data_shards: u64 = 32_767;
        let recovery_shards: u64 = 32_768;
        let group_count: u64 = 2;
        let header_size = 0x48 + data_shards * 8;
        let total_size = header_size + group_count;
        let protected_size = data_shards * group_count;
        let plan = InlineRecoveryPlan {
            data_shards,
            recovery_shards,
            group_count,
            header_size,
            shard_size: 0,
        };
        let shard_size = shard_record_span(plan).unwrap();

        let mut record = vec![0u8; total_size as usize];
        record[..4].copy_from_slice(b"{RB}");
        record[0x0c..0x10].copy_from_slice(&(total_size as u32).to_le_bytes());
        record[0x10..0x14].copy_from_slice(&(header_size as u32).to_le_bytes());
        record[0x14] = 1;
        record[0x15] = 1;
        record[0x22..0x2a].copy_from_slice(&protected_size.to_le_bytes());
        record[0x2a..0x32].copy_from_slice(&group_count.to_le_bytes());
        record[0x32..0x3a].copy_from_slice(&shard_size.to_le_bytes());
        record[0x3a..0x3c].copy_from_slice(&(data_shards as u16).to_le_bytes());
        record[0x3c..0x3e].copy_from_slice(&(recovery_shards as u16).to_le_bytes());
        let crc = crc64_xz(&record[0x0c..]);
        record[0x04..0x0c].copy_from_slice(&crc.to_le_bytes());
        record
    }

    /// The in-memory scan's twin of the streaming scanner's shard-count cap.
    /// `read_chunk_at` gained the cap; `parse_inline_recovery_chunk` - the
    /// parser behind `ArchiveReader::repair_recovery()` - did not, so the
    /// public in-memory repair path still accepted the grid the streaming
    /// path refused.
    #[test]
    fn rar5_inline_parse_rejects_a_wire_scale_grid() {
        let record = wire_scale_consistent_record();
        assert!(record.len() < 300 * 1024, "the fixture stays tiny");
        let started = std::time::Instant::now();
        let mut hashed = 0u64;
        assert_eq!(
            parse_inline_recovery_chunk(&record, &mut hashed).unwrap_err(),
            Error::BadRecoveryChunk
        );
        assert!(
            started.elapsed().as_millis() < 500,
            "the refusal must not size anything first"
        );
    }

    /// Defence in depth for the same grid: even handed a pre-parsed plan,
    /// the group solver must refuse to size the encoder matrix from it.
    #[test]
    fn rar5_group_solver_refuses_a_wire_scale_grid() {
        let plan = InlineRecoveryPlan {
            data_shards: 32_767,
            recovery_shards: 32_768,
            group_count: 2,
            header_size: 0x48 + 32_767 * 8,
            shard_size: 0,
        };
        let ranges = vec![0..0usize; 32_767];
        let parity = [0u8; 2];
        let rows = [(0usize, &parity[..])];
        let started = std::time::Instant::now();
        let result = solve_damaged_group_shards(plan, &ranges, 2, &[0], &rows, &mut |_| {
            Ok(Vec::new())
        });
        assert_eq!(result.unwrap_err(), Error::ReconstructionTooLarge);
        assert!(
            started.elapsed().as_millis() < 500,
            "the refusal must not size anything first"
        );
    }
}
